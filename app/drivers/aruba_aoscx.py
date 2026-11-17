"""Aruba AOS-CX backup driver (experimental; Netmiko device type aruba_aoscx).

Validated only against sample output shapes. Run the integration checklist
in README before relying on it in production.
"""
import re

from .base import (ConfigResult, IncompleteConfigError, assert_min_length, assert_no_cli_error,
                   assert_no_pager)
from .ssh_common import NetmikoDriver

AOSCX_ERROR_MARKERS = [r"Invalid input", r"%\s*Command incomplete", r"Permission denied", r"Unknown command"]


class ArubaAOSCXDriver(NetmikoDriver):
    vendor = "aruba"
    platforms = ("aruba_aoscx",)
    config_types = ("running", "startup")
    label = "Aruba AOS-CX (SSH, experimental)"
    commands = {"running": "show running-config", "startup": "show startup-config"}

    def validate_output(self, config_type: str, output: str) -> ConfigResult:
        text = output or ""
        assert_no_cli_error(text, AOSCX_ERROR_MARKERS)
        assert_no_pager(text)
        assert_min_length(text, 32)
        if not re.search(r"^(hostname\s+\S+|!Version\s+)", text, re.M):
            raise IncompleteConfigError(f"{config_type} configuration has no 'hostname' or '!Version' line")
        if not text.endswith("\n"):
            text += "\n"
        return ConfigResult(config_type, text, "success")
