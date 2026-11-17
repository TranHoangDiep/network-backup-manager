"""Fernet encryption for credentials, secret settings and backup files.

The key file lives outside the database (default keys/fernet.key, mode 0600).
It may contain several keys, one per line: the first encrypts, all decrypt
(MultiFernet). This enables key rotation without downtime.
"""
import logging
import os
import stat
import threading
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from flask import current_app

from ..drivers.base import DeviceCredential

log = logging.getLogger(__name__)

SECRET_FIELDS = ("password", "private_key", "key_passphrase", "enable_password", "api_token")


class CryptoError(Exception):
    pass


def ensure_key_file(path) -> bool:
    """Create the key file if missing. Returns True if a new key was generated."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    created = False
    if not path.exists():
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(Fernet.generate_key() + b"\n")
            created = True
            log.warning("Generated a new encryption key at %s. BACK IT UP: without it, credentials "
                        "and backups cannot be decrypted.", path)
        except FileExistsError:
            pass
    enforce_key_permissions(path)
    return created


def enforce_key_permissions(path) -> None:
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        os.chmod(path, 0o600)
        log.warning("Tightened permissions on %s from %o to 600", path, mode)


def read_keys(path) -> list:
    path = Path(path)
    if not path.exists():
        raise CryptoError(f"Encryption key file {path} not found. Run 'flask init-app' or restore the key backup.")
    keys = [line.strip() for line in path.read_bytes().splitlines()
            if line.strip() and not line.strip().startswith(b"#")]
    if not keys:
        raise CryptoError(f"Encryption key file {path} is empty")
    return keys


_cache_lock = threading.Lock()
_cache: dict = {}


def get_fernet(path=None) -> MultiFernet:
    path = Path(path or current_app.config["KEY_FILE"])
    mtime = path.stat().st_mtime_ns if path.exists() else None
    with _cache_lock:
        cached = _cache.get(str(path))
        if cached and cached[0] == mtime:
            return cached[1]
        try:
            fernet = MultiFernet([Fernet(k) for k in read_keys(path)])
        except ValueError:
            raise CryptoError(f"Encryption key file {path} contains an invalid Fernet key") from None
        _cache[str(path)] = (mtime, fernet)
        return fernet


def encrypt_str(value: str):
    if not value:
        return None
    return get_fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_str(token) -> str:
    if not token:
        return ""
    try:
        return get_fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken:
        raise CryptoError("Unable to decrypt secret: wrong or missing encryption key") from None


def encrypt_bytes(data: bytes) -> bytes:
    return get_fernet().encrypt(data)


def decrypt_bytes(token: bytes) -> bytes:
    try:
        return get_fernet().decrypt(token)
    except InvalidToken:
        raise CryptoError("Unable to decrypt backup file: wrong key or corrupted file") from None


def load_credential(cred) -> DeviceCredential:
    """Decrypt a Credential model into memory. Never persist or log the result."""
    return DeviceCredential(
        username=cred.username or "",
        password=decrypt_str(cred.password_enc),
        private_key=decrypt_str(cred.private_key_enc),
        key_passphrase=decrypt_str(cred.key_passphrase_enc),
        enable_password=decrypt_str(cred.enable_password_enc),
        api_token=decrypt_str(cred.api_token_enc),
        api_port=cred.api_port or 443,
        verify_tls=bool(cred.verify_tls),
        ca_cert_pem=cred.ca_cert_pem or "",
    )


def set_secret(cred, field: str, value: str, clear: bool = False) -> bool:
    """Update one secret column. Empty value keeps the existing secret."""
    if field not in SECRET_FIELDS:
        raise ValueError(field)
    column = f"{field}_enc"
    if clear:
        changed = getattr(cred, column) is not None
        setattr(cred, column, None)
        return changed
    if value:
        setattr(cred, column, encrypt_str(value))
        return True
    return False


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def rotate_encryption_key(drop_old: bool = False) -> dict:
    """Generate a new primary key and re-encrypt all secrets and backup files.

    Step 1 prepends the new key (old keys still decrypt). Step 2 re-encrypts
    data. With drop_old=True, old keys are removed afterwards.
    """
    from ..extensions import db
    from ..models import ApplicationSetting, BackupVersion, Credential
    from .storage_service import get_storage, storage_lock

    key_path = Path(current_app.config["KEY_FILE"])
    old_keys = read_keys(key_path)
    new_key = Fernet.generate_key()
    _atomic_write(key_path, b"\n".join([new_key] + old_keys) + b"\n")
    fernet = get_fernet(key_path)
    stats = {"credentials": 0, "settings": 0, "files": 0}

    with storage_lock:
        for cred in Credential.query.all():
            for field in SECRET_FIELDS:
                token = getattr(cred, f"{field}_enc")
                if token:
                    setattr(cred, f"{field}_enc", fernet.rotate(token.encode()).decode())
            stats["credentials"] += 1
        for setting in ApplicationSetting.query.filter_by(is_secret=True).all():
            if setting.value:
                setting.value = fernet.rotate(setting.value.encode()).decode()
                stats["settings"] += 1
        db.session.commit()

        storage = get_storage()
        paths = {p for (p,) in db.session.query(BackupVersion.file_path).filter(BackupVersion.file_path.isnot(None))}
        for rel in paths:
            full = storage.resolve(rel)
            if full.exists():
                _atomic_write(full, fernet.rotate(full.read_bytes()))
                stats["files"] += 1

    if drop_old:
        _atomic_write(key_path, new_key + b"\n")
    log.warning("Encryption key rotated: %s (old keys %s)", stats, "dropped" if drop_old else "retained")
    return stats
