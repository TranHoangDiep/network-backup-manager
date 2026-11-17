"""Application configuration loaded from environment variables.

Only non-secret defaults live here. Secrets (Flask SECRET_KEY, Fernet key)
are loaded from files outside the database; see app/__init__.py and
app/services/credential_service.py.
"""
import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    value = os.environ.get(name)
    try:
        return int(value) if value not in (None, "") else default
    except ValueError:
        return default


class Config:
    # --- Paths -----------------------------------------------------------
    DATA_DIR = Path(os.environ.get("NBM_DATA_DIR", BASE_DIR / "data"))
    KEY_FILE = Path(os.environ.get("NBM_KEY_FILE", BASE_DIR / "keys" / "fernet.key"))
    # Derived in create_app() when left as None
    BACKUP_DIR = None
    LOG_DIR = os.environ.get("NBM_LOG_DIR") or None
    TMP_DIR = None
    CERT_DIR = None
    SECRET_KEY_FILE = None
    SCHEDULER_LOCK_FILE = None
    SCHEDULER_HEARTBEAT_FILE = None

    # --- Flask / security --------------------------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY") or None
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or None
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"timeout": 15, "check_same_thread": False}}
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", True)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_NAME = "nbm_session"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=_int("SESSION_LIFETIME_MINUTES", 480))
    SESSION_REFRESH_EACH_REQUEST = True
    REMEMBER_COOKIE_DURATION = timedelta(seconds=0)
    WTF_CSRF_TIME_LIMIT = None  # token bound to session lifetime
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # CSV uploads

    PASSWORD_MIN_LENGTH = _int("PASSWORD_MIN_LENGTH", 12)
    LOGIN_MAX_ATTEMPTS = _int("LOGIN_MAX_ATTEMPTS", 5)
    LOGIN_LOCKOUT_MINUTES = _int("LOGIN_LOCKOUT_MINUTES", 15)
    LOGIN_IP_MAX_ATTEMPTS = _int("LOGIN_IP_MAX_ATTEMPTS", 30)

    TRUST_PROXY = _bool("TRUST_PROXY", False)
    USE_CDN_ASSETS = _bool("USE_CDN_ASSETS", True)

    # --- Network egress restrictions --------------------------------------
    # Workers refuse to connect to anything outside these networks/ports.
    ALLOWED_MGMT_NETWORKS = os.environ.get(
        "ALLOWED_MGMT_NETWORKS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    )
    ALLOWED_PORTS = os.environ.get("ALLOWED_PORTS", "22,443,8443,10443")
    SSH_STRICT_HOST_KEY = _bool("SSH_STRICT_HOST_KEY", True)

    # --- Scheduler / workers ----------------------------------------------
    APP_TIMEZONE = os.environ.get("APP_TIMEZONE", "Asia/Ho_Chi_Minh")
    MAX_CONCURRENCY_HARD_LIMIT = _int("MAX_CONCURRENCY_HARD_LIMIT", 20)
    JOB_POLL_SECONDS = _int("JOB_POLL_SECONDS", 2)

    # --- Bootstrap admin (only used when no user exists) -------------------
    INITIAL_ADMIN_USERNAME = os.environ.get("INITIAL_ADMIN_USERNAME", "admin")
    INITIAL_ADMIN_PASSWORD = os.environ.get("INITIAL_ADMIN_PASSWORD") or None

    # Branding: full name (login page, footer, title) and short name (navbar, email subject)
    APP_NAME = os.environ.get("APP_NAME", "Network Config Backup")
    APP_SHORT_NAME = os.environ.get("APP_SHORT_NAME", "Config Backup")

    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
    TESTING = False
