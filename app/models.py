"""SQLAlchemy models.

All timestamps are stored as naive UTC datetimes. Secrets are stored only as
Fernet tokens (columns ending in ``_enc``). Configuration contents are never
stored in the database; ``BackupVersion.file_path`` points to an encrypted file.
"""
from datetime import datetime, timezone

from flask_login import UserMixin
from sqlalchemy import Index, text
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db

ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_VIEWER = "viewer"
ROLES = {
    ROLE_ADMIN: "Full access: devices, credentials, schedules, users, downloads",
    ROLE_OPERATOR: "View devices, run backups, view history and masked configs",
    ROLE_VIEWER: "Dashboards and backup status only",
}

DEVICE_ROLES = {
    "firewall": "Firewall",
    "core_switch": "Core Switch",
    "access_switch": "Access Switch",
    "router": "Router",
}

JOB_ACTIVE_STATUSES = ("queued", "running")
JOB_TERMINAL_STATUSES = ("success", "partial", "failed", "interrupted", "cancelled")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class TimestampMixin:
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False)
    description = db.Column(db.String(255))


class User(UserMixin, TimestampMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False, index=True)
    active = db.Column(db.Boolean, nullable=False, default=True)
    can_download = db.Column(db.Boolean, nullable=False, default=False)
    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime)
    last_login_at = db.Column(db.DateTime)

    role = db.relationship("Role", lazy="joined")

    @property
    def is_active(self) -> bool:  # Flask-Login
        return bool(self.active)

    @property
    def role_name(self) -> str:
        return self.role.name if self.role else ""

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def has_role(self, *names: str) -> bool:
        return self.role_name in names


class Site(TimestampMixin, db.Model):
    __tablename__ = "sites"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(255))
    mgmt_subnet = db.Column(db.String(64))
    timezone = db.Column(db.String(64), nullable=False, default="UTC")
    status = db.Column(db.String(16), nullable=False, default="active")

    devices = db.relationship("Device", back_populates="site", lazy="dynamic")


class Credential(TimestampMixin, db.Model):
    """Reusable credential profile. Secret columns hold Fernet tokens only."""

    __tablename__ = "credentials"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    cred_type = db.Column(db.String(8), nullable=False)  # ssh | api
    description = db.Column(db.String(255))
    username = db.Column(db.String(128))
    password_enc = db.Column(db.Text)
    private_key_enc = db.Column(db.Text)
    key_passphrase_enc = db.Column(db.Text)
    enable_password_enc = db.Column(db.Text)
    api_token_enc = db.Column(db.Text)
    api_port = db.Column(db.Integer, nullable=False, default=443)
    verify_tls = db.Column(db.Boolean, nullable=False, default=True)
    ca_cert_pem = db.Column(db.Text)  # public CA certificate, not secret
    rotated_at = db.Column(db.DateTime)

    devices = db.relationship("Device", back_populates="credential", lazy="dynamic")

    @property
    def secret_flags(self) -> dict:
        return {
            "password": bool(self.password_enc),
            "private_key": bool(self.private_key_enc),
            "key_passphrase": bool(self.key_passphrase_enc),
            "enable_password": bool(self.enable_password_enc),
            "api_token": bool(self.api_token_enc),
        }


class BackupPolicy(TimestampMixin, db.Model):
    __tablename__ = "backup_policies"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    schedule_type = db.Column(db.String(16), nullable=False, default="daily")  # 6h|12h|daily|weekly|cron
    hour = db.Column(db.Integer, nullable=False, default=2)
    minute = db.Column(db.Integer, nullable=False, default=0)
    day_of_week = db.Column(db.String(8), nullable=False, default="sun")
    cron_expression = db.Column(db.String(128))
    timezone = db.Column(db.String(64), nullable=False, default="UTC")
    config_types = db.Column(db.String(64), nullable=False, default="running,startup")
    retention_days = db.Column(db.Integer)  # overrides per-role default when set
    enabled = db.Column(db.Boolean, nullable=False, default=True)

    devices = db.relationship("Device", back_populates="policy", lazy="dynamic")

    @property
    def config_type_list(self) -> list:
        return [c.strip() for c in (self.config_types or "").split(",") if c.strip()]

    def describe(self) -> str:
        hm = f"{self.hour:02d}:{self.minute:02d}"
        return {
            "6h": f"Every 6 hours (minute {self.minute:02d})",
            "12h": f"Every 12 hours (minute {self.minute:02d})",
            "daily": f"Daily at {hm}",
            "weekly": f"Weekly on {self.day_of_week} at {hm}",
            "cron": f"Cron: {self.cron_expression}",
        }.get(self.schedule_type, self.schedule_type) + f" ({self.timezone})"


class Device(TimestampMixin, db.Model):
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    hostname = db.Column(db.String(253))
    mgmt_ip = db.Column(db.String(45), nullable=False, index=True)
    site_id = db.Column(db.Integer, db.ForeignKey("sites.id", ondelete="RESTRICT"), nullable=False, index=True)
    vendor = db.Column(db.String(32), nullable=False)
    platform = db.Column(db.String(32), nullable=False)
    connection_method = db.Column(db.String(8), nullable=False, default="ssh")  # ssh | api
    port = db.Column(db.Integer)
    credential_id = db.Column(db.Integer, db.ForeignKey("credentials.id", ondelete="RESTRICT"), index=True)
    policy_id = db.Column(db.Integer, db.ForeignKey("backup_policies.id", ondelete="SET NULL"), index=True)
    device_role = db.Column(db.String(32), nullable=False, default="access_switch")
    vdom = db.Column(db.String(32))
    description = db.Column(db.String(500))
    enabled = db.Column(db.Boolean, nullable=False, default=True)

    # Trusted SSH host key (public data) and a pending key awaiting admin approval
    ssh_host_key_type = db.Column(db.String(64))
    ssh_host_key_b64 = db.Column(db.Text)
    pending_host_key_type = db.Column(db.String(64))
    pending_host_key_b64 = db.Column(db.Text)

    reachable = db.Column(db.Boolean)
    last_seen_at = db.Column(db.DateTime)
    last_backup_at = db.Column(db.DateTime)
    last_backup_status = db.Column(db.String(16))
    last_success_at = db.Column(db.DateTime)
    last_error = db.Column(db.Text)

    site = db.relationship("Site", back_populates="devices")
    credential = db.relationship("Credential", back_populates="devices")
    policy = db.relationship("BackupPolicy", back_populates="devices")
    jobs = db.relationship("BackupJob", back_populates="device", lazy="dynamic",
                           cascade="all, delete-orphan", passive_deletes=True)
    versions = db.relationship("BackupVersion", back_populates="device", lazy="dynamic",
                               cascade="all, delete-orphan", passive_deletes=True)

    def effective_port(self) -> int:
        if self.port:
            return self.port
        if self.connection_method == "api":
            return (self.credential.api_port if self.credential else None) or 443
        return 22


class BackupJob(db.Model):
    """One execution request (backup or connection test) for a device."""

    __tablename__ = "backup_jobs"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    job_type = db.Column(db.String(16), nullable=False, default="backup")  # backup | test
    trigger = db.Column(db.String(16), nullable=False, default="manual")  # manual | scheduled
    status = db.Column(db.String(16), nullable=False, default="queued", index=True)
    requested_by_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"))
    attempt = db.Column(db.Integer, nullable=False, default=0)
    max_attempts = db.Column(db.Integer, nullable=False, default=1)
    next_attempt_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    message = db.Column(db.Text)
    result_json = db.Column(db.Text)

    device = db.relationship("Device", back_populates="jobs")
    requested_by = db.relationship("User")

    __table_args__ = (
        # At most one queued/running job per device: DB-level overlap protection.
        Index("uq_backup_jobs_active_device", "device_id", unique=True,
              sqlite_where=text("status IN ('queued', 'running')")),
    )

    @property
    def is_active(self) -> bool:
        return self.status in JOB_ACTIVE_STATUSES


class BackupVersion(db.Model):
    """History record for every backup execution and config type.

    Unchanged results reference the previous encrypted file, so no duplicate
    files are created while every execution is still recorded.
    """

    __tablename__ = "backup_versions"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    job_id = db.Column(db.Integer, db.ForeignKey("backup_jobs.id", ondelete="SET NULL"), index=True)
    config_type = db.Column(db.String(16), nullable=False, default="running")
    backup_method = db.Column(db.String(8), nullable=False)
    status = db.Column(db.String(16), nullable=False)  # success | failed | skipped
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    config_hash = db.Column(db.String(64))  # SHA-256 of the stored plaintext
    normalized_hash = db.Column(db.String(64))  # SHA-256 after removing dynamic lines
    changed = db.Column(db.Boolean, nullable=False, default=False)
    change_summary = db.Column(db.String(64))
    file_path = db.Column(db.String(255), index=True)  # relative to BACKUP_DIR
    file_size = db.Column(db.Integer)
    error_message = db.Column(db.Text)

    device = db.relationship("Device", back_populates="versions")
    job = db.relationship("BackupJob")

    __table_args__ = (
        Index("ix_backup_versions_device_type_time", "device_id", "config_type", "created_at"),
    )


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), index=True)
    username = db.Column(db.String(64))
    action = db.Column(db.String(64), nullable=False, index=True)
    target_type = db.Column(db.String(32))
    target_id = db.Column(db.String(64))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    user = db.relationship("User")


class ApplicationSetting(db.Model):
    __tablename__ = "application_settings"
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text)
    is_secret = db.Column(db.Boolean, nullable=False, default=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)
