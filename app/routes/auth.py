"""Login, logout and password change with lockout and per-IP rate limiting."""
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash

from ..bootstrap import validate_password
from ..extensions import db
from ..models import User, utcnow
from ..security import audit

bp = Blueprint("auth", __name__)

_DUMMY_HASH = generate_password_hash("timing-equalizer-not-a-password")
_ip_lock = threading.Lock()
_ip_attempts = defaultdict(deque)
_IP_WINDOW_SECONDS = 900


def _ip_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    with _ip_lock:
        attempts = _ip_attempts[ip]
        while attempts and now - attempts[0] > _IP_WINDOW_SECONDS:
            attempts.popleft()
        return len(attempts) >= current_app.config["LOGIN_IP_MAX_ATTEMPTS"]


def _record_ip_failure(ip: str) -> None:
    with _ip_lock:
        _ip_attempts[ip].append(time.monotonic())


def _safe_next(target: str) -> str:
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("dashboard.index")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        username = (request.form.get("username") or "").strip()[:64]
        password = request.form.get("password") or ""
        if _ip_rate_limited(ip):
            audit("auth.rate_limited", details={"username": username})
            flash("Too many login attempts from your address. Try again later.", "danger")
            return render_template("login.html"), 429

        user = User.query.filter_by(username=username).first()
        now = utcnow()
        if user and user.locked_until and user.locked_until > now:
            _record_ip_failure(ip)
            flash("Account temporarily locked after repeated failures. Try again later.", "danger")
            audit("auth.locked", "user", user.id, {"username": username})
            return render_template("login.html"), 403

        valid = user.check_password(password) if user else _check_dummy(password)
        if user and valid and user.is_active:
            user.failed_logins = 0
            user.locked_until = None
            user.last_login_at = now
            db.session.commit()
            session.clear()
            session.permanent = True
            login_user(user, remember=False)
            audit("auth.login", "user", user.id, user=user)
            return redirect(_safe_next(request.args.get("next", "")))

        _record_ip_failure(ip)
        if user:
            user.failed_logins = (user.failed_logins or 0) + 1
            if user.failed_logins >= current_app.config["LOGIN_MAX_ATTEMPTS"]:
                user.locked_until = now + timedelta(minutes=current_app.config["LOGIN_LOCKOUT_MINUTES"])
                user.failed_logins = 0
            db.session.commit()
        audit("auth.failed", "user", user.id if user else None, {"username": username}, user=None)
        flash("Invalid username or password.", "danger")
        return render_template("login.html"), 401
    return render_template("login.html")


def _check_dummy(password: str) -> bool:
    from werkzeug.security import check_password_hash
    check_password_hash(_DUMMY_HASH, password)  # equalize timing for unknown users
    return False


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("auth.logout", "user", current_user.id)
    logout_user()
    session.clear()
    flash("Signed out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password") or ""
        new = request.form.get("new_password") or ""
        confirm = request.form.get("confirm_password") or ""
        if not current_user.check_password(current):
            flash("Current password is incorrect.", "danger")
        elif new != confirm:
            flash("New passwords do not match.", "danger")
        else:
            try:
                validate_password(new)
            except ValueError as exc:
                flash(str(exc), "danger")
            else:
                current_user.set_password(new)
                db.session.commit()
                audit("auth.password_changed", "user", current_user.id)
                flash("Password updated.", "success")
                return redirect(url_for("dashboard.index"))
    return render_template("change_password.html")
