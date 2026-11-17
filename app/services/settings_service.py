"""Typed application settings stored in the application_settings table."""
from ..extensions import db
from ..models import ApplicationSetting, utcnow
from ..validators import ValidationError
from .credential_service import decrypt_str, encrypt_str

# key: (type, default, min, max, label, group)
SCHEMA = {
    "max_concurrency": ("int", 5, 1, 20, "Maximum concurrent backup jobs", "Backup engine"),
    "retry_max_attempts": ("int", 3, 1, 10, "Maximum attempts per backup job (including the first)", "Backup engine"),
    "retry_backoff_seconds": ("int", 60, 5, 3600, "Retry backoff base (seconds, doubles per attempt)", "Backup engine"),
    "job_timeout_seconds": ("int", 900, 60, 7200, "Hard job timeout (seconds)", "Backup engine"),
    "ssh_conn_timeout": ("int", 15, 3, 120, "SSH/API connect timeout (seconds)", "Backup engine"),
    "ssh_read_timeout": ("int", 120, 10, 900, "SSH command read timeout (seconds)", "Backup engine"),
    "api_timeout": ("int", 60, 5, 600, "REST API read timeout (seconds)", "Backup engine"),
    "retention_firewall": ("int", 180, 1, 3650, "Firewall", "Retention (days)"),
    "retention_core_switch": ("int", 180, 1, 3650, "Core Switch", "Retention (days)"),
    "retention_access_switch": ("int", 90, 1, 3650, "Access Switch", "Retention (days)"),
    "retention_router": ("int", 180, 1, 3650, "Router", "Retention (days)"),
    "stale_backup_hours": ("int", 48, 1, 2160, "Alert when no successful backup within (hours)", "Notifications"),
    "notify_on_failure": ("bool", True, None, None, "Backup failed after retries", "Notifications"),
    "notify_on_unreachable": ("bool", True, None, None, "Device unreachable", "Notifications"),
    "notify_on_change": ("bool", True, None, None, "Configuration change detected", "Notifications"),
    "notify_on_stale": ("bool", True, None, None, "No recent successful backup", "Notifications"),
    "smtp_host": ("str", "", None, 255, "SMTP host", "SMTP email"),
    "smtp_port": ("int", 587, 1, 65535, "SMTP port", "SMTP email"),
    "smtp_security": ("choice:starttls,ssl,none", "starttls", None, None, "SMTP security", "SMTP email"),
    "smtp_username": ("str", "", None, 255, "SMTP username", "SMTP email"),
    "smtp_password": ("secret", "", None, 255, "SMTP password", "SMTP email"),
    "smtp_from": ("str", "", None, 255, "From address", "SMTP email"),
    "notify_emails": ("str", "", None, 1000, "Recipients (comma separated)", "SMTP email"),
    "webhook_url": ("str", "", None, 1000, "Webhook URL (HTTPS, JSON POST)", "Webhook"),
}

GROUPS = []
for _key, _spec in SCHEMA.items():
    if _spec[5] not in GROUPS:
        GROUPS.append(_spec[5])


def _convert(key: str, raw):
    kind, default = SCHEMA[key][0], SCHEMA[key][1]
    if raw is None:
        return default
    if kind == "int":
        try:
            return int(raw)
        except ValueError:
            return default
    if kind == "bool":
        return str(raw).lower() in ("1", "true", "yes", "on")
    return raw


def get_setting(key: str):
    row = db.session.get(ApplicationSetting, key)
    if row is None:
        return SCHEMA[key][1]
    if SCHEMA[key][0] == "secret":
        return decrypt_str(row.value) if row.value else ""
    return _convert(key, row.value)


def get_all() -> dict:
    return {key: get_setting(key) for key in SCHEMA}


def is_secret_set(key: str) -> bool:
    row = db.session.get(ApplicationSetting, key)
    return bool(row and row.value)


def _store(key: str, value: str, secret: bool = False) -> None:
    row = db.session.get(ApplicationSetting, key)
    if row is None:
        row = ApplicationSetting(key=key)
        db.session.add(row)
    row.value = value
    row.is_secret = secret
    row.updated_at = utcnow()


def validate_value(key: str, raw):
    kind, _default, minimum, maximum, label, _group = SCHEMA[key]
    if kind == "int":
        try:
            value = int(str(raw).strip())
        except ValueError:
            raise ValidationError(f"{label}: must be an integer") from None
        if not minimum <= value <= maximum:
            raise ValidationError(f"{label}: must be between {minimum} and {maximum}")
        return str(value)
    if kind == "bool":
        return "true" if raw in (True, "on", "true", "1", "yes") else "false"
    if kind.startswith("choice:"):
        if raw not in kind.split(":", 1)[1].split(","):
            raise ValidationError(f"{label}: invalid choice")
        return raw
    value = (raw or "").strip()
    if maximum and len(value) > maximum:
        raise ValidationError(f"{label}: at most {maximum} characters")
    if key == "webhook_url" and value and not value.startswith("https://"):
        raise ValidationError("Webhook URL must start with https://")
    return value


def set_setting(key: str, raw) -> None:
    value = validate_value(key, raw)
    if SCHEMA[key][0] == "secret":
        _store(key, encrypt_str(value) if value else None, secret=True)
    else:
        _store(key, value)


def update_from_form(form) -> tuple:
    """Validate and apply all settings from a submitted form. Secrets left blank are kept."""
    errors, changed = [], []
    pending = {}
    for key, spec in SCHEMA.items():
        kind = spec[0]
        if kind == "bool":
            raw = "on" if form.get(key) else ""
        elif kind == "secret":
            if form.get(f"{key}__clear"):
                pending[key] = ""
                continue
            raw = form.get(key, "")
            if not raw:
                continue
        else:
            raw = form.get(key, "")
        try:
            validate_value(key, raw)
            pending[key] = raw
        except ValidationError as exc:
            errors.append(str(exc))
    if errors:
        return [], errors
    for key, raw in pending.items():
        before = get_setting(key)
        set_setting(key, raw)
        if get_setting(key) != before:
            changed.append(key)
    db.session.commit()
    return changed, []


# Internal (non-form) key/value state such as scheduler heartbeat.
def get_state(key: str, default=None):
    row = db.session.get(ApplicationSetting, f"state:{key}")
    return row.value if row else default


def set_state(key: str, value: str, commit: bool = True) -> None:
    _store(f"state:{key}", value)
    if commit:
        db.session.commit()
