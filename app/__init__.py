"""Flask application factory."""
import logging
import os
from datetime import timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from flask import Flask, render_template, request
from flask_wtf.csrf import CSRFError

from .config import Config
from .extensions import csrf, db, login_manager, migrate
from .logging_setup import setup_logging

log = logging.getLogger(__name__)


def _derive_paths(cfg) -> None:
    data = Path(cfg["DATA_DIR"])
    cfg["DATA_DIR"] = data
    defaults = {
        "BACKUP_DIR": data / "backups",
        "LOG_DIR": data / "logs",
        "TMP_DIR": data / "tmp",
        "CERT_DIR": data / "certs",
        "SCHEDULER_LOCK_FILE": data / "scheduler.lock",
        "SCHEDULER_HEARTBEAT_FILE": data / "scheduler.heartbeat",
        "SECRET_KEY_FILE": Path(cfg["KEY_FILE"]).parent / "flask_secret.key",
    }
    for key, value in defaults.items():
        cfg[key] = Path(cfg[key]) if cfg.get(key) else value
    if not cfg.get("SQLALCHEMY_DATABASE_URI"):
        db_path = data / "db" / "nbm.sqlite3"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        cfg["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"


def _load_secret_key(app) -> None:
    if app.config.get("SECRET_KEY"):
        return
    path = Path(app.config["SECRET_KEY_FILE"])
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write(os.urandom(48).hex())
        except FileExistsError:
            pass
    app.config["SECRET_KEY"] = path.read_text().strip()


def create_app(overrides: dict = None, process_role: str = "web") -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)
    _derive_paths(app.config)
    for key in ("DATA_DIR", "BACKUP_DIR", "LOG_DIR", "TMP_DIR", "CERT_DIR"):
        Path(app.config[key]).mkdir(parents=True, exist_ok=True)
    os.chmod(app.config["TMP_DIR"], 0o700)
    _load_secret_key(app)

    if not app.config.get("TESTING"):
        setup_logging(app.config["LOG_DIR"], f"{process_role}.log", app.config["LOG_LEVEL"])

    db.init_app(app)
    migrate.init_app(app, db, render_as_batch=True)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"
    login_manager.session_protection = "strong"

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        user = db.session.get(User, int(user_id)) if str(user_id).isdigit() else None
        return user if user and user.is_active else None

    if app.config.get("TRUST_PROXY"):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    _register_blueprints(app)
    _register_template_helpers(app)
    _register_error_handlers(app)
    _register_security_headers(app)

    from .bootstrap import register_cli
    register_cli(app)
    return app


def _register_blueprints(app) -> None:
    from .routes.auth import bp as auth_bp
    from .routes.backups import bp as backups_bp
    from .routes.credentials import bp as credentials_bp
    from .routes.dashboard import bp as dashboard_bp
    from .routes.devices import bp as devices_bp
    from .routes.settings import bp as settings_bp
    from .routes.sites import bp as sites_bp

    for blueprint in (auth_bp, dashboard_bp, devices_bp, sites_bp, credentials_bp, backups_bp, settings_bp):
        app.register_blueprint(blueprint)


def _register_template_helpers(app) -> None:
    from flask_login import current_user

    from .drivers import PLATFORMS, VENDORS
    from .models import DEVICE_ROLES
    from .security import has_permission

    tz = ZoneInfo(app.config["APP_TIMEZONE"])

    @app.template_filter("localdt")
    def localdt(value, fmt="%Y-%m-%d %H:%M:%S"):
        if not value:
            return "-"
        return value.replace(tzinfo=timezone.utc).astimezone(tz).strftime(fmt)

    @app.template_filter("filesize")
    def filesize(value):
        if value is None:
            return "-"
        for unit in ("B", "KB", "MB"):
            if value < 1024:
                return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
            value /= 1024
        return f"{value:.1f} GB"

    badge_map = {
        "success": "success", "partial": "warning", "failed": "danger", "interrupted": "secondary",
        "queued": "info", "running": "primary", "skipped": "secondary", "cancelled": "secondary",
        "active": "success", "inactive": "secondary",
    }

    # Globals (not context processors) so imported macros can use them too.
    app.jinja_env.globals["badge"] = lambda status: badge_map.get(status or "", "light")
    app.jinja_env.globals["request"] = request

    @app.context_processor
    def inject_helpers():
        return {
            "can": lambda perm: has_permission(current_user, perm),
            "PLATFORMS": PLATFORMS,
            "VENDORS": VENDORS,
            "DEVICE_ROLES": DEVICE_ROLES,
            "APP_TZ": app.config["APP_TIMEZONE"],
            "USE_CDN": app.config["USE_CDN_ASSETS"],
            "PW_MIN": app.config["PASSWORD_MIN_LENGTH"],
            "APP_NAME": app.config["APP_NAME"],
            "APP_SHORT_NAME": app.config["APP_SHORT_NAME"],
        }


def _register_error_handlers(app) -> None:
    @app.errorhandler(CSRFError)
    def csrf_error(err):
        return render_template("error.html", code=400, message="Form expired or invalid CSRF token. Reload and retry."), 400

    for code, message in ((403, "You do not have permission to access this resource."),
                          (404, "Page not found."),
                          (413, "Upload too large.")):
        app.register_error_handler(code, lambda err, c=code, m=message: (
            render_template("error.html", code=c, message=m), c))

    @app.errorhandler(500)
    def server_error(err):
        log.exception("Unhandled error on %s", request.path)
        return render_template("error.html", code=500, message="Internal server error."), 500


def _register_security_headers(app) -> None:
    csp = ("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
           "style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net; "
           "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'")

    @app.after_request
    def headers(resp):
        resp.headers.setdefault("Content-Security-Policy", csp)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if request.endpoint and not request.endpoint.startswith("static"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp
