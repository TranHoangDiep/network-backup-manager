"""Driver contract shared by all vendor drivers.

A driver receives a connection target, an in-memory decrypted credential and
options. It returns validated configuration text and never writes to disk
(except a short-lived known_hosts file containing public host keys).
Drivers must be read-only: they only execute 'show'-style commands or
read-only REST endpoints.
"""
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------- errors ---
class DriverError(Exception):
    """Base driver failure. ``retryable`` decides whether the job is retried."""

    retryable = False
    category = "error"


class AuthenticationError(DriverError):
    category = "auth"


class PermissionDeniedError(DriverError):
    category = "permission"


class ConnectionTimeoutError(DriverError):
    retryable = True
    category = "timeout"


class ConnectionFailedError(DriverError):
    retryable = True
    category = "connection"


class TLSVerificationError(DriverError):
    category = "tls"


class HostKeyError(DriverError):
    category = "hostkey"

    def __init__(self, message: str, mismatch: bool = False):
        super().__init__(message)
        self.mismatch = mismatch


class IncompleteConfigError(DriverError):
    """Output was empty, truncated, or a CLI/API error instead of a config."""

    retryable = True
    category = "incomplete"


class UnsupportedError(DriverError):
    category = "unsupported"


# ------------------------------------------------------------ data types ---
@dataclass
class DeviceCredential:
    """Decrypted credential, held in memory only for the duration of a job."""

    username: str = ""
    password: str = ""
    private_key: str = ""
    key_passphrase: str = ""
    enable_password: str = ""
    api_token: str = ""
    api_port: int = 443
    verify_tls: bool = True
    ca_cert_pem: str = ""

    def secret_values(self) -> list:
        return [v for v in (self.password, self.private_key, self.key_passphrase,
                            self.enable_password, self.api_token) if v]

    def __repr__(self) -> str:  # never print secrets
        return f"DeviceCredential(username={self.username!r}, secrets=***)"

    __str__ = __repr__


@dataclass
class ConnectionTarget:
    name: str
    host: str
    port: int
    platform: str
    vdom: str = ""
    host_key_type: str = ""
    host_key_b64: str = ""


@dataclass
class DriverOptions:
    conn_timeout: int = 15
    read_timeout: int = 120
    api_timeout: int = 60
    strict_host_key: bool = True
    tmp_dir: str = "/tmp"


@dataclass
class ConfigResult:
    config_type: str
    content: Optional[str]
    status: str = "success"  # success | skipped | failed
    message: str = ""
    meta: dict = field(default_factory=dict)


@dataclass
class TestResult:
    __test__ = False  # not a pytest test class
    ok: bool
    message: str
    details: dict = field(default_factory=dict)


# ---------------------------------------------------------------- driver ---
class BaseDriver(ABC):
    vendor = ""
    method = ""  # ssh | api
    platforms: tuple = ()
    config_types: tuple = ("running",)  # first entry is the primary type
    label = ""

    def __init__(self, target: ConnectionTarget, credential: DeviceCredential, options: DriverOptions):
        self.target = target
        self.credential = credential
        self.options = options

    @property
    def primary_config_type(self) -> str:
        return self.config_types[0]

    @abstractmethod
    def test_connection(self) -> TestResult:
        ...

    @abstractmethod
    def fetch_configs(self, config_types: list) -> list:
        """Return a list of ConfigResult. Raise DriverError on fatal failure."""


# --------------------------------------------------------------- helpers ---
def non_empty_lines(text: str) -> list:
    return [line for line in text.splitlines() if line.strip()]


def assert_no_cli_error(text: str, markers: list, head_lines: int = 10) -> None:
    """CLI errors appear at the top of short outputs; only scan the head to
    avoid false positives from banners or descriptions inside the config."""
    head = "\n".join(non_empty_lines(text)[:head_lines])
    for marker in markers:
        if re.search(marker, head, re.I):
            first = non_empty_lines(text)[0] if text.strip() else ""
            raise IncompleteConfigError(f"Device returned an error instead of a configuration: {first[:200]}")


def assert_min_length(text: str, minimum: int = 64) -> None:
    if len(text.strip()) < minimum:
        raise IncompleteConfigError(f"Configuration output is empty or too short ({len(text.strip())} bytes)")


def assert_no_pager(text: str) -> None:
    if re.search(r"--\s*More\s*--", text):
        raise IncompleteConfigError("Output contains a pager prompt (--More--); terminal paging was not disabled")
