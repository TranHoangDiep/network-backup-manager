"""Encrypted backup file storage on the local filesystem.

Paths are built only from integer IDs, a whitelisted config type and a UTC
timestamp, never from device-supplied names:
    <BACKUP_DIR>/<site_id>/<device_id>/<config_type>/<YYYY-mm-dd_HHMMSS>.cfg.enc
"""
import os
import threading
import uuid
from pathlib import Path, PurePosixPath

from flask import current_app

from .credential_service import decrypt_bytes, encrypt_bytes

CONFIG_TYPES = ("running", "startup")

# Serializes file creation/deletion between backup workers and retention.
storage_lock = threading.RLock()


class StorageError(Exception):
    pass


class StorageService:
    def __init__(self, base_dir):
        self.base = Path(base_dir).resolve()
        self.base.mkdir(parents=True, exist_ok=True)

    def new_relative_path(self, site_id: int, device_id: int, config_type: str, when) -> str:
        if config_type not in CONFIG_TYPES:
            raise StorageError(f"Invalid config type {config_type!r}")
        directory = PurePosixPath(str(int(site_id)), str(int(device_id)), config_type)
        stamp = when.strftime("%Y-%m-%d_%H%M%S")
        candidate = directory / f"{stamp}.cfg.enc"
        counter = 1
        while (self.base / candidate).exists():
            candidate = directory / f"{stamp}_{counter}.cfg.enc"
            counter += 1
        return candidate.as_posix()

    def resolve(self, relative: str) -> Path:
        """Map a stored relative path to an absolute path inside base, rejecting traversal."""
        if not relative or not isinstance(relative, str):
            raise StorageError("Empty path")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or "\\" in relative or ".." in pure.parts or "\x00" in relative:
            raise StorageError("Invalid backup path")
        full = (self.base / pure).resolve()
        if self.base not in full.parents:
            raise StorageError("Backup path escapes the storage directory")
        return full

    def write(self, relative: str, plaintext: bytes) -> int:
        full = self.resolve(relative)
        full.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        token = encrypt_bytes(plaintext)
        tmp = full.with_name(f".{full.name}.{uuid.uuid4().hex}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(token)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, full)
        finally:
            if tmp.exists():
                tmp.unlink()
        return len(plaintext)

    def read(self, relative: str) -> bytes:
        full = self.resolve(relative)
        if not full.is_file():
            raise StorageError("Backup file is missing on disk")
        return decrypt_bytes(full.read_bytes())

    def read_text(self, relative: str) -> str:
        return self.read(relative).decode("utf-8", errors="surrogateescape")

    def exists(self, relative: str) -> bool:
        try:
            return self.resolve(relative).is_file()
        except StorageError:
            return False

    def delete(self, relative: str) -> bool:
        full = self.resolve(relative)
        if full.is_file():
            full.unlink()
            self._prune_empty_dirs(full.parent)
            return True
        return False

    def _prune_empty_dirs(self, directory: Path) -> None:
        while directory != self.base and self.base in directory.parents:
            try:
                directory.rmdir()
            except OSError:
                return
            directory = directory.parent


def get_storage() -> StorageService:
    return StorageService(current_app.config["BACKUP_DIR"])
