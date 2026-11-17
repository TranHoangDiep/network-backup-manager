"""Database seeding and Flask CLI commands (flask --app run:app <command>)."""
import datetime as dt
import getpass
import ipaddress
import os
from pathlib import Path

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from flask import current_app

from .extensions import db
from .models import ROLE_ADMIN, ROLES, BackupPolicy, Role, User

MIN_PASSWORD_LENGTH = 12


def seed_defaults() -> None:
    for name, description in ROLES.items():
        if not Role.query.filter_by(name=name).first():
            db.session.add(Role(name=name, description=description))
    if BackupPolicy.query.count() == 0:
        tz = current_app.config["APP_TIMEZONE"]
        db.session.add_all([
            BackupPolicy(name="Daily 02:00", schedule_type="daily", hour=2, minute=0, timezone=tz),
            BackupPolicy(name="Every 6 hours", schedule_type="6h", minute=15, timezone=tz),
            BackupPolicy(name="Weekly Sunday 03:00", schedule_type="weekly", day_of_week="sun",
                         hour=3, minute=0, timezone=tz),
        ])
    db.session.commit()


def min_password_length() -> int:
    try:
        return max(1, int(current_app.config.get("PASSWORD_MIN_LENGTH", MIN_PASSWORD_LENGTH)))
    except (TypeError, ValueError, RuntimeError):
        return MIN_PASSWORD_LENGTH


def validate_password(password: str) -> None:
    minimum = min_password_length()
    if len(password or "") < minimum:
        raise ValueError(f"Password must be at least {minimum} characters")


def create_user(username: str, password: str, role: str = ROLE_ADMIN, can_download: bool = True) -> User:
    validate_password(password)
    role_obj = Role.query.filter_by(name=role).one()
    user = User(username=username, role=role_obj, can_download=can_download, active=True)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def generate_self_signed_cert(cert_path: Path, key_path: Path, common_name: str) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    alt_names = [x509.DNSName(common_name), x509.DNSName("localhost"),
                 x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    key_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def register_cli(app) -> None:
    @app.cli.command("init-app")
    def init_app_command():
        """Create the encryption key (if missing), seed roles/policies and the initial admin."""
        from .services.credential_service import ensure_key_file
        if ensure_key_file(app.config["KEY_FILE"]):
            click.echo(f"Generated encryption key {app.config['KEY_FILE']} - back it up securely.")
        seed_defaults()
        if User.query.count() == 0:
            password = app.config.get("INITIAL_ADMIN_PASSWORD")
            username = app.config.get("INITIAL_ADMIN_USERNAME") or "admin"
            if password:
                create_user(username, password, ROLE_ADMIN)
                click.echo(f"Created initial admin '{username}'. Remove INITIAL_ADMIN_PASSWORD from .env now.")
            else:
                click.echo("No users exist. Run: flask --app run:app create-admin --username admin")
        click.echo("Initialization complete.")

    @app.cli.command("create-admin")
    @click.option("--username", required=True)
    def create_admin_command(username):
        """Create an admin user (password prompted, never echoed)."""
        if User.query.filter_by(username=username).first():
            raise click.ClickException("User already exists")
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Confirm: "):
            raise click.ClickException("Passwords do not match")
        try:
            create_user(username, password, ROLE_ADMIN)
        except ValueError as exc:
            raise click.ClickException(str(exc))
        click.echo(f"Admin '{username}' created.")

    @app.cli.command("reset-password")
    @click.option("--username", required=True)
    def reset_password_command(username):
        """Reset a user's password and unlock the account."""
        user = User.query.filter_by(username=username).first()
        if not user:
            raise click.ClickException("No such user")
        password = getpass.getpass("New password: ")
        try:
            validate_password(password)
        except ValueError as exc:
            raise click.ClickException(str(exc))
        user.set_password(password)
        user.failed_logins = 0
        user.locked_until = None
        db.session.commit()
        click.echo("Password updated.")

    @app.cli.command("rotate-key")
    @click.option("--drop-old", is_flag=True, help="Remove previous keys after re-encryption")
    def rotate_key_command(drop_old):
        """Rotate the Fernet key and re-encrypt credentials, secret settings and backups.
        Stop the scheduler container before running this."""
        from .services.credential_service import rotate_encryption_key
        click.echo(f"Re-encrypted: {rotate_encryption_key(drop_old=drop_old)}")

    @app.cli.command("gen-cert")
    @click.option("--cn", default=lambda: os.environ.get("TLS_COMMON_NAME", "config-backup.local"))
    @click.option("--force", is_flag=True)
    def gen_cert_command(cn, force):
        """Create a self-signed TLS certificate if none exists."""
        cert = Path(os.environ.get("TLS_CERT_FILE", app.config["CERT_DIR"] / "server.crt"))
        key = Path(os.environ.get("TLS_KEY_FILE", app.config["CERT_DIR"] / "server.key"))
        if cert.exists() and key.exists() and not force:
            click.echo(f"Certificate {cert} exists; leaving it unchanged.")
            return
        generate_self_signed_cert(cert, key, cn)
        click.echo(f"Self-signed certificate written to {cert} (CN={cn}). Replace with a CA-signed one for production.")

    @app.cli.command("run-retention")
    def run_retention_command():
        """Run backup retention cleanup now."""
        from .security import audit
        from .services.retention_service import run_retention
        stats = run_retention()
        audit("retention.run", details=stats)
        click.echo(stats)
