"""Cisco NX-OS backup driver (Netmiko device type cisco_nxos).

NX-OS has no enable mode; the account's role (network-admin or network-operator)
determines what is visible. Netmiko sends 'terminal length 0' and
'terminal width 511' (session-only). NX-OS configs do not end with 'end', so
completeness is checked via the '!Command:'/'version'/'hostname' markers.
"""
import re

from .base import (ConfigResult, IncompleteConfigError, assert_min_length, assert_no_cli_error,
                   assert_no_pager)
from .ssh_common import NetmikoDriver

NXOS_ERROR_MARKERS = [
    r"^%\s*Invalid command",
    r"^%\s*Invalid parameter",
    r"^%\s*Incomplete command",
    r"^%\s*Permission denied",
    r"Syntax error while parsing",
    r"^%\s*Invalid input",
]

STARTUP_MISSING = re.compile(r"(startup-config|startup configuration).{0,40}(not present|does not exist|not found)", re.I)


class CiscoNXOSDriver(NetmikoDriver):
    vendor = "cisco"
    platforms = ("cisco_nxos",)
    config_types = ("running", "startup")
    label = "Cisco NX-OS (SSH)"
    commands = {"running": "show running-config", "startup": "show startup-config"}

    def validate_output(self, config_type: str, output: str) -> ConfigResult:
        text = output or ""
        if config_type == "startup" and STARTUP_MISSING.search(text[:500]):
            return ConfigResult(config_type, None, "skipped", "Startup configuration is not present on the device")
        assert_no_cli_error(text, NXOS_ERROR_MARKERS)
        assert_no_pager(text)
        assert_min_length(text)
        if not re.search(r"^version\s+\S+", text, re.M):
            raise IncompleteConfigError(f"{config_type} configuration has no 'version' line")
        if not re.search(r"^(hostname|switchname)\s+\S+", text, re.M):
            raise IncompleteConfigError(f"{config_type} configuration has no 'hostname'/'switchname' line")
        if not text.endswith("\n"):
            text += "\n"
        return ConfigResult(config_type, text, "success")
