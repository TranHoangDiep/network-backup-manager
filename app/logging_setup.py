"""Rotating file logging with secret redaction.

Two layers of redaction:
1. Regex patterns for common secret shapes (password=..., Bearer tokens, PEM keys).
2. Exact values of credentials decrypted at runtime (registered by the worker
   for the duration of a job), so they can never leak through exception text.
"""
import logging
import re
import sys
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "<redacted-private-key>"),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-~+/=]+"), r"\1 ***"),
    (re.compile(r"(?i)\b(access_token|api[_-]?key|token|password|passwd|secret|passphrase)"
                r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1\2***"),
]

_secret_lock = threading.Lock()
_secret_values: dict = {}  # value -> refcount


def register_secrets(values) -> None:
    with _secret_lock:
        for value in values:
            if value and len(value) >= 4:
                _secret_values[value] = _secret_values.get(value, 0) + 1


def unregister_secrets(values) -> None:
    with _secret_lock:
        for value in values:
            if value in _secret_values:
                _secret_values[value] -= 1
                if _secret_values[value] <= 0:
                    del _secret_values[value]


def redact(message: str) -> str:
    with _secret_lock:
        values = sorted(_secret_values, key=len, reverse=True)
    for value in values:
        message = message.replace(value, "***")
    for pattern, replacement in _PATTERNS:
        message = pattern.sub(replacement, message)
    return message


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # malformed format args; keep record as-is
            return True
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        record.msg = redact(message)
        record.args = None
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


_configured = set()


def setup_logging(log_dir, filename: str, level: str = "INFO", console: bool = True) -> None:
    key = (str(log_dir), filename)
    if key in _configured:
        return
    _configured.add(key)

    Path(log_dir).mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(process)d:%(threadName)s] %(name)s: %(message)s")
    redactor = RedactingFilter()

    root = logging.getLogger()
    root.setLevel(level)

    file_handler = RotatingFileHandler(Path(log_dir) / filename, maxBytes=10 * 1024 * 1024,
                                       backupCount=10, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.addFilter(redactor)
    root.addHandler(file_handler)

    if console:
        stream = logging.StreamHandler(sys.stdout)
        stream.setFormatter(formatter)
        stream.addFilter(redactor)
        root.addHandler(stream)

    # Third-party libraries can be chatty and may echo session data at DEBUG.
    for noisy in ("paramiko", "netmiko", "httpx", "httpcore", "apscheduler.executors"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
