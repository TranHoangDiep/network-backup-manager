"""Cisco IOS / IOS-XE backup driver (Netmiko device types cisco_ios, cisco_xe).

Netmiko's session preparation sends 'terminal width 511' and 'terminal length 0'.
Both are session-only settings and do not modify the device configuration.

Privilege: 'show running-config' at privilege < 15 only displays the commands
the user is allowed to configure (a silently partial config), so this driver
requires privileged EXEC mode ('#'), entering it with the enable secret if needed.
"""
import re

from netmiko.exceptions import ReadTimeout

from .base import (ConfigResult, IncompleteConfigError, PermissionDeniedError, assert_min_length,
                   assert_no_cli_error, assert_no_pager, non_empty_lines)
from .ssh_common import NetmikoDriver

IOS_ERROR_MARKERS = [
    r"^%\s*Invalid input",
    r"^%\s*Incomplete command",
    r"^%\s*Ambiguous command",
    r"^%\s*Unknown command",
    r"^%\s*Authorization failed",
    r"Command authorization failed",
    r"^%\s*Access denied",
    r"^%\s*Permission denied",
]

STARTUP_MISSING = re.compile(
    r"startup-config is not present|%\s*Error opening nvram:/?startup-config|"
    r"Non-Volatile memory is not present|%\s*Non-volatile configuration memory is not present", re.I)


class CiscoIOSDriver(NetmikoDriver):
    vendor = "cisco"
    platforms = ("cisco_ios", "cisco_xe")
    config_types = ("running", "startup")
    label = "Cisco IOS/IOS-XE (SSH)"
    commands = {"running": "show running-config", "startup": "show startup-config"}

    def prepare_session(self, conn) -> None:
        if conn.check_enable_mode():
            return
        if not self.credential.enable_password:
            raise PermissionDeniedError(
                "Session is not in privileged EXEC mode (#) and no enable password is configured. "
                "Use a privilege-15 account or set an enable password in the credential profile.")
        try:
            conn.enable()
        except (ValueError, ReadTimeout):
            raise PermissionDeniedError("Failed to enter enable mode (check the enable password)") from None
        if not conn.check_enable_mode():
            raise PermissionDeniedError("Enable mode was not reached after sending the enable password")

    def validate_output(self, config_type: str, output: str) -> ConfigResult:
        text = output or ""
        if config_type == "startup" and STARTUP_MISSING.search(text[:500]):
            return ConfigResult(config_type, None, "skipped", "Startup configuration is not present on the device")
        assert_no_cli_error(text, IOS_ERROR_MARKERS)
        assert_no_pager(text)
        assert_min_length(text)
        lines = non_empty_lines(text)
        if lines[-1].strip() != "end":
            raise IncompleteConfigError(f"{config_type} configuration does not end with 'end' (truncated output?)")
        if not re.search(r"^(hostname|version)\s+\S+", text, re.M):
            raise IncompleteConfigError(f"{config_type} configuration has no 'hostname' or 'version' line")
        if not text.endswith("\n"):
            text += "\n"
        return ConfigResult(config_type, text, "success")
