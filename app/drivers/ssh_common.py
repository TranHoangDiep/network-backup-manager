"""Netmiko-based SSH driver foundation: host-key pinning, key auth, error mapping."""
import base64
import hashlib
import io
import logging
import os
import socket
import tempfile
from contextlib import contextmanager

import paramiko
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException, ReadTimeout

from .base import (AuthenticationError, BaseDriver, ConfigResult, ConnectionFailedError,
                   ConnectionTimeoutError, DriverError, HostKeyError, IncompleteConfigError,
                   TestResult)

log = logging.getLogger(__name__)


def known_hosts_name(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def host_key_fingerprint(key_b64: str) -> str:
    digest = hashlib.sha256(base64.b64decode(key_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def scan_host_key(host: str, port: int, timeout: int) -> dict:
    """Fetch the server host key without authenticating (for admin approval)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (socket.timeout, TimeoutError):
        raise ConnectionTimeoutError(f"TCP connection to {host}:{port} timed out") from None
    except OSError as exc:
        raise ConnectionFailedError(f"TCP connection to {host}:{port} failed: {exc}") from None
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        b64 = key.get_base64()
        return {"type": key.get_name(), "b64": b64, "fingerprint": host_key_fingerprint(b64)}
    except paramiko.SSHException as exc:
        raise ConnectionFailedError(f"SSH handshake failed: {exc}") from None
    finally:
        transport.close()


def load_private_key(pem: str, passphrase: str = ""):
    for key_class in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return key_class.from_private_key(io.StringIO(pem), password=passphrase or None)
        except (paramiko.SSHException, ValueError, TypeError):
            continue
    raise AuthenticationError("SSH private key is invalid, unsupported, or the passphrase is wrong")


class NetmikoDriver(BaseDriver):
    method = "ssh"
    netmiko_device_type = None  # defaults to target.platform
    connection_class = None     # optional custom Netmiko class
    commands: dict = {}

    # ------------------------------------------------------- connection ---
    def _connect_kwargs(self) -> dict:
        cred = self.credential
        kwargs = {
            "device_type": self.netmiko_device_type or self.target.platform,
            "host": self.target.host,
            "port": self.target.port,
            "username": cred.username,
            "password": cred.password or "",
            "secret": cred.enable_password or "",
            "conn_timeout": self.options.conn_timeout,
            "auth_timeout": self.options.conn_timeout,
            "banner_timeout": self.options.conn_timeout,
            "timeout": self.options.read_timeout,
            "fast_cli": False,
            "use_keys": False,
            "allow_agent": False,
            "system_host_keys": False,
        }
        if cred.private_key:
            kwargs["pkey"] = load_private_key(cred.private_key, cred.key_passphrase)
            kwargs["use_keys"] = True
        return kwargs

    def _open(self, kwargs: dict):
        if self.connection_class is not None:
            return self.connection_class(**kwargs)
        return ConnectHandler(**kwargs)

    @contextmanager
    def connect(self):
        kwargs = self._connect_kwargs()
        known_hosts_path = None
        if self.options.strict_host_key:
            if not self.target.host_key_b64:
                raise HostKeyError("No trusted SSH host key for this device. Run 'Test Connection' "
                                   "and have an administrator verify and trust the fingerprint.")
            fd, known_hosts_path = tempfile.mkstemp(prefix="known_hosts_", dir=self.options.tmp_dir)
            with os.fdopen(fd, "w") as handle:
                handle.write(f"{known_hosts_name(self.target.host, self.target.port)} "
                             f"{self.target.host_key_type} {self.target.host_key_b64}\n")
            kwargs.update(ssh_strict=True, alt_host_keys=True, alt_key_file=known_hosts_path)
        else:
            log.warning("SSH host key verification disabled (SSH_STRICT_HOST_KEY=false) for %s", self.target.name)
            kwargs.update(ssh_strict=False, alt_host_keys=False)

        conn = None
        try:
            conn = self._open(kwargs)
            yield conn
        except DriverError:
            raise
        except Exception as exc:  # map library exceptions to driver errors
            raise self.map_exception(exc) from None
        finally:
            if conn is not None:
                try:
                    conn.disconnect()
                except Exception:
                    pass
            if known_hosts_path:
                try:
                    os.unlink(known_hosts_path)
                except OSError:
                    pass

    def map_exception(self, exc: Exception) -> DriverError:
        text = str(exc).strip().splitlines()[0][:300] if str(exc).strip() else type(exc).__name__
        if isinstance(exc, (NetmikoAuthenticationException, paramiko.AuthenticationException)):
            return AuthenticationError("SSH authentication failed (check username, password or key)")
        if isinstance(exc, (NetmikoTimeoutException, ReadTimeout, socket.timeout, TimeoutError)):
            return ConnectionTimeoutError(f"SSH timeout: {text}")
        if isinstance(exc, paramiko.BadHostKeyException):
            return HostKeyError("SSH HOST KEY MISMATCH: the device presented a different key than the "
                                "trusted one. Possible device replacement or man-in-the-middle.", mismatch=True)
        if isinstance(exc, paramiko.SSHException):
            if "known_hosts" in str(exc):
                return HostKeyError("SSH host key is not trusted for this address")
            return ConnectionFailedError(f"SSH error: {text}")
        if isinstance(exc, OSError):
            return ConnectionFailedError(f"Connection failed: {text}")
        return DriverError(f"Unexpected SSH error ({type(exc).__name__}): {text}")

    # ------------------------------------------------------------ hooks ---
    def prepare_session(self, conn) -> None:
        """Privilege checks etc. Must not change device configuration."""

    def validate_output(self, config_type: str, output: str) -> ConfigResult:
        raise NotImplementedError

    def send_show(self, conn, command: str) -> str:
        return conn.send_command(command, read_timeout=self.options.read_timeout)

    # ------------------------------------------------------- operations ---
    def test_connection(self) -> TestResult:
        if self.options.strict_host_key and not self.target.host_key_b64:
            key = scan_host_key(self.target.host, self.target.port, self.options.conn_timeout)
            return TestResult(False, f"SSH reachable, but the host key is not trusted yet. "
                                     f"Fingerprint {key['type']} {key['fingerprint']}. "
                                     f"Verify it on the device console and trust it.",
                              {"host_key_pending": key})
        try:
            with self.connect() as conn:
                prompt = conn.find_prompt()
                self.prepare_session(conn)
                return TestResult(True, f"SSH login successful. Prompt: {prompt}", {"prompt": prompt})
        except HostKeyError as exc:
            if exc.mismatch:
                key = scan_host_key(self.target.host, self.target.port, self.options.conn_timeout)
                return TestResult(False, f"{exc} New fingerprint: {key['type']} {key['fingerprint']}",
                                  {"host_key_pending": key, "host_key_mismatch": True})
            raise

    def fetch_configs(self, config_types: list) -> list:
        results = []
        with self.connect() as conn:
            self.prepare_session(conn)
            for config_type in config_types:
                command = self.commands[config_type]
                output = self.send_show(conn, command)
                try:
                    results.append(self.validate_output(config_type, output))
                except IncompleteConfigError as exc:
                    if config_type == self.primary_config_type:
                        raise
                    results.append(ConfigResult(config_type, None, "failed", str(exc)))
        return results
