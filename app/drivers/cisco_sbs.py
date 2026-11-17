"""Cisco Small Business / Business (CBS250/350, SG300/350...) backup driver.

These switches accept the SSH session without authenticating and ask for
'User Name:' / 'Password:' inside the CLI, so Netmiko's normal SSH password
login fails with "authentication failed" even with correct credentials.
This driver sends no password at the SSH layer and answers the CLI prompts.
ponytail: if the switch has `ip ssh password-auth` enabled it authenticates at the
SSH layer instead; this driver does not support that mode (use platform Cisco IOS).
"""
import re

import paramiko
from netmiko.cisco import CiscoS300SSH
from netmiko.exceptions import NetmikoAuthenticationException

from .base import (ConfigResult, IncompleteConfigError, assert_min_length, assert_no_cli_error,
                   assert_no_pager, non_empty_lines)
from .cisco_ios import CiscoIOSDriver

SBS_ERROR_MARKERS = [
    r"^%\s*Invalid input",
    r"^%\s*Unrecognized command",
    r"^%\s*Incomplete command",
    r"^%\s*Ambiguous command",
    r"^%\s*Access denied",
]


class _NoAuthClient(paramiko.SSHClient):
    """SSH client that only does 'none' authentication (paramiko refuses to without a password)."""

    def _auth(self, username, *args, **kwargs):
        self._transport.auth_none(username)


class CiscoSBSSH(CiscoS300SSH):
    def _get_ssh_client_instance(self):
        return _NoAuthClient()

    def special_login_handler(self, delay_factor: float = 1.0) -> None:
        self.read_until_pattern(pattern=r"User Name:", read_timeout=15)
        self.write_channel(self.username + self.RETURN)
        self.read_until_pattern(pattern=r"Password:", read_timeout=15)
        self.write_channel(self.password + self.RETURN)
        # A rejected login shows 'User Name:' again instead of a prompt.
        out = self.read_until_pattern(pattern=r"[>#]\s*$|User Name:", read_timeout=15)
        if out.rstrip().endswith("User Name:"):
            self.paramiko_cleanup()
            raise NetmikoAuthenticationException("Authentication to device failed (rejected at the CLI login).")


class CiscoSBSDriver(CiscoIOSDriver):
    platforms = ("cisco_sbs",)
    label = "Cisco Small Business (SSH)"
    netmiko_device_type = "cisco_s300"
    connection_class = CiscoSBSSH

    def validate_output(self, config_type: str, output: str) -> ConfigResult:
        text = output or ""
        assert_no_cli_error(text, SBS_ERROR_MARKERS)
        assert_no_pager(text)
        assert_min_length(text)
        # ponytail: this OS has no 'end' trailer, so truncation is only caught by the header/hostname checks.
        if non_empty_lines(text)[0].strip() != "config-file-header":
            raise IncompleteConfigError(f"{config_type} configuration does not start with 'config-file-header'")
        if not re.search(r"^hostname\s+\S+", text, re.M):
            raise IncompleteConfigError(f"{config_type} configuration has no 'hostname' line")
        if not text.endswith("\n"):
            text += "\n"
        return ConfigResult(config_type, text, "success")
