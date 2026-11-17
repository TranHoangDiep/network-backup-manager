"""Admin area: application settings, backup policies (schedules), users, audit log."""
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..bootstrap import validate_password
from ..extensions import db
from ..models import ROLE_ADMIN, ROLES, AuditLog, BackupPolicy, Role, User
from ..security import audit, permission_required
from ..services.backup_service import enqueue_policy_backups
from ..services.notification_service import send_email, send_webhook
from ..services.scheduler_service import WEEKDAYS, validate_cron
from ..services.settings_service import GROUPS, SCHEMA, get_all, is_secret_set, update_from_form
from ..validators import USERNAME_RE, ValidationError, clean_name, parse_int, parse_timezone

bp = Blueprint("settings", __name__, url_prefix="/settings")

SCHEDULE_TYPES = {"6h": "Every 6 hours", "12h": "Every 12 hours", "daily": "Daily", "weekly": "Weekly",
                  "cron": "Custom cron expression"}


# ------------------------------------------------------------ settings ---
@bp.route("/", methods=["GET", "POST"])
@login_required
@permission_required("settings.manage")
def general():
    if request.method == "POST":
        changed, errors = update_from_form(request.form)
        if errors:
            for error in errors:
                flash(error, "danger")
        else:
            audit("settings.update", details={"changed": changed})
            flash(f"Settings saved ({len(changed)} changed). The worker applies them within a few seconds.",
                  "success")
            return redirect(url_for("settings.general"))
    return render_template("settings.html", schema=SCHEMA, groups=GROUPS, values=get_all(),
                           secret_set={k: is_secret_set(k) for k, s in SCHEMA.items() if s[0] == "secret"})


@bp.route("/notifications/test", methods=["POST"])
@login_required
@permission_required("settings.manage")
def test_notification():
    body = f"Test notification requested by {current_user.username}."
    for name, sender in (("Email", lambda: send_email(f"[{current_app.config['APP_SHORT_NAME']}] Test notification", body)),
                         ("Webhook", lambda: send_webhook("test", "Test notification", body, {}))):
        try:
            sent = sender()
            flash(f"{name}: {'sent' if sent else 'not configured'}", "success" if sent else "secondary")
        except Exception as exc:
            flash(f"{name} failed: {exc}", "danger")
    audit("settings.notification_test")
    return redirect(url_for("settings.general"))


# ------------------------------------------------------------ policies ---
@bp.route("/policies")
@login_required
@permission_required("policy.manage")
def policies():
    items = BackupPolicy.query.order_by(BackupPolicy.name).all()
    return render_template("policies.html", policies=items, usage={p.id: p.devices.count() for p in items})


def _clean_policy(form, current_id=None):
    errors, out = [], {}

    def take(key, func, *args):
        try:
            out[key] = func(*args)
        except ValidationError as exc:
            errors.append(str(exc))

    take("name", clean_name, form.get("name"), "Policy name")
    take("timezone", parse_timezone, form.get("timezone"))
    take("hour", parse_int, form.get("hour", 0), "Hour", 0, 23)
    take("minute", parse_int, form.get("minute", 0), "Minute", 0, 59)
    out["schedule_type"] = form.get("schedule_type")
    if out["schedule_type"] not in SCHEDULE_TYPES:
        errors.append("Invalid schedule type")
    out["day_of_week"] = form.get("day_of_week", "sun")
    if out["day_of_week"] not in WEEKDAYS:
        errors.append("Invalid day of week")
    out["cron_expression"] = (form.get("cron_expression") or "").strip() or None
    if out["schedule_type"] == "cron":
        try:
            validate_cron(out["cron_expression"] or "", out.get("timezone", "UTC"))
        except Exception as exc:
            errors.append(f"Invalid cron expression (minute hour day month weekday): {exc}")
    types = [t for t in ("running", "startup") if form.get(f"type_{t}")]
    if "running" not in types:
        types.insert(0, "running")
    out["config_types"] = ",".join(types)
    retention = (form.get("retention_days") or "").strip()
    if retention:
        take("retention_days", parse_int, retention, "Retention days", 1, 3650)
    else:
        out["retention_days"] = None
    out["enabled"] = bool(form.get("enabled"))
    if "name" in out and BackupPolicy.query.filter(BackupPolicy.name == out["name"],
                                                   BackupPolicy.id != (current_id or 0)).first():
        errors.append("A policy with this name already exists")
    return out, errors


@bp.route("/policies/new", methods=["GET", "POST"])
@bp.route("/policies/<int:policy_id>/edit", methods=["GET", "POST"])
@login_required
@permission_required("policy.manage")
def edit_policy(policy_id=None):
    policy = db.session.get(BackupPolicy, policy_id) if policy_id else None
    if policy_id and policy is None:
        abort(404)
    if request.method == "POST":
        values, errors = _clean_policy(request.form, policy_id)
        if not errors:
            policy = policy or BackupPolicy()
            for key, value in values.items():
                setattr(policy, key, value)
            db.session.add(policy)
            db.session.commit()
            audit("policy.update" if policy_id else "policy.create", "policy", policy.id, values)
            flash("Policy saved. The scheduler reloads schedules within one minute.", "success")
            return redirect(url_for("settings.policies"))
        for error in errors:
            flash(error, "danger")
        return render_template("policy_form.html", policy=policy, form=request.form,
                               schedule_types=SCHEDULE_TYPES, weekdays=WEEKDAYS), 400
    if policy:
        form = {c: getattr(policy, c) for c in ("name", "schedule_type", "hour", "minute", "day_of_week",
                                                "cron_expression", "timezone", "retention_days")}
        form["enabled"] = "on" if policy.enabled else ""
        for t in policy.config_type_list:
            form[f"type_{t}"] = "on"
    else:
        from flask import current_app
        form = {"schedule_type": "daily", "hour": 2, "minute": 0, "day_of_week": "sun", "enabled": "on",
                "timezone": current_app.config["APP_TIMEZONE"], "type_running": "on", "type_startup": "on"}
    return render_template("policy_form.html", policy=policy, form=form, schedule_types=SCHEDULE_TYPES,
                           weekdays=WEEKDAYS)


@bp.route("/policies/<int:policy_id>/run", methods=["POST"])
@login_required
@permission_required("policy.manage")
def run_policy(policy_id):
    policy = db.session.get(BackupPolicy, policy_id)
    if policy is None:
        abort(404)
    count = enqueue_policy_backups(policy.id)
    audit("policy.run_now", "policy", policy.id, {"queued": count})
    flash(f"Queued {count} backup job(s) for policy '{policy.name}'.", "info")
    return redirect(url_for("backups.jobs"))


@bp.route("/policies/<int:policy_id>/delete", methods=["POST"])
@login_required
@permission_required("policy.manage")
def delete_policy(policy_id):
    policy = db.session.get(BackupPolicy, policy_id)
    if policy is None:
        abort(404)
    if policy.devices.count():
        flash("Policy is assigned to devices. Reassign them first.", "warning")
        return redirect(url_for("settings.policies"))
    name = policy.name
    db.session.delete(policy)
    db.session.commit()
    audit("policy.delete", "policy", policy_id, {"name": name})
    flash("Policy deleted.", "success")
    return redirect(url_for("settings.policies"))


# --------------------------------------------------------------- users ---
@bp.route("/users")
@login_required
@permission_required("user.manage")
def users():
    return render_template("users.html", users=User.query.order_by(User.username).all())


def _active_admin_count(exclude_id=None) -> int:
    query = User.query.join(Role).filter(Role.name == ROLE_ADMIN, User.active.is_(True))
    if exclude_id:
        query = query.filter(User.id != exclude_id)
    return query.count()


@bp.route("/users/new", methods=["GET", "POST"])
@bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@permission_required("user.manage")
def edit_user(user_id=None):
    user = db.session.get(User, user_id) if user_id else None
    if user_id and user is None:
        abort(404)
    if request.method == "POST":
        errors = []
        username = (request.form.get("username") or "").strip()
        role = Role.query.filter_by(name=request.form.get("role")).first()
        password = request.form.get("password") or ""
        active = bool(request.form.get("active"))
        if not USERNAME_RE.match(username):
            errors.append("Username: 2-64 characters, letters, digits, . _ -")
        elif User.query.filter(User.username == username, User.id != (user_id or 0)).first():
            errors.append("Username already exists")
        if role is None:
            errors.append("Invalid role")
        if not user_id or password:
            try:
                validate_password(password)
            except ValueError as exc:
                errors.append(str(exc))
        if user and user.has_role(ROLE_ADMIN) and (role is None or role.name != ROLE_ADMIN or not active) \
                and _active_admin_count(exclude_id=user.id) == 0:
            errors.append("At least one active administrator must remain")
        if not errors:
            user = user or User()
            user.username, user.role, user.active = username, role, active
            user.can_download = bool(request.form.get("can_download"))
            if password:
                user.set_password(password)
                user.failed_logins, user.locked_until = 0, None
            db.session.add(user)
            db.session.commit()
            audit("user.update" if user_id else "user.create", "user", user.id,
                  {"username": user.username, "role": role.name, "active": active,
                   "can_download": user.can_download, "password_changed": bool(password)})
            flash("User saved.", "success")
            return redirect(url_for("settings.users"))
        for error in errors:
            flash(error, "danger")
        return render_template("user_form.html", user=user, form=request.form, roles=ROLES), 400
    form = ({"username": user.username, "role": user.role_name, "active": "on" if user.active else "",
             "can_download": "on" if user.can_download else ""} if user else {"role": "viewer", "active": "on"})
    return render_template("user_form.html", user=user, form=form, roles=ROLES)


@bp.route("/users/<int:user_id>/unlock", methods=["POST"])
@login_required
@permission_required("user.manage")
def unlock_user(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    user.failed_logins, user.locked_until = 0, None
    db.session.commit()
    audit("user.unlock", "user", user.id)
    flash("Account unlocked.", "success")
    return redirect(url_for("settings.users"))


# --------------------------------------------------------------- audit ---
@bp.route("/audit")
@login_required
@permission_required("audit.view")
def audit_logs():
    query = AuditLog.query
    action = (request.args.get("action") or "").strip()
    if action:
        query = query.filter(AuditLog.action.like(f"{action}%"))
    page = query.order_by(AuditLog.created_at.desc()).paginate(
        page=request.args.get("page", 1, type=int), per_page=100, error_out=False)
    return render_template("audit_logs.html", page=page, action=action)
