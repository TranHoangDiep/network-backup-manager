"""Fortinet FortiOS SSH backup driver (alternative to the REST API driver).

Read-only behavior: stock Netmiko FortinetSSH changes 'config system console /
set output standard' to disable paging and reverts it on logout. That is a
configuration change, so this driver uses a subclass that never touches the
console setting. If the device console output mode is 'more', the backup
fails with a clear message. One-time device prerequisite:

    config system console
        set output standard
    end

Scope: the SSH driver runs 'show' at the top level, which returns the full
configuration (global and all VDOMs the account can read). Per-VDOM scope is
supported only by the REST API driver.
"""
from netmiko.fortinet.fortinet_ssh import FortinetSSH

from .base import (ConfigResult, IncompleteConfigError, UnsupportedError, assert_min_length,
                   assert_no_cli_error, assert_no_pager, non_empty_lines)
from .ssh_common import NetmikoDriver

PAGING_MESSAGE = ("FortiGate console output mode is 'more' (paging). This tool will not change device "
                  "configuration; set 'config system console / set output standard / end' once on the "
                  "device, or use the REST API driver.")

FORTI_ERROR_MARKERS = [
    r"Command fail",
    r"Unknown action",
    r"command parse error",
    r"Permission denied",
    r"^-\d+\s*$",
]


class ReadOnlyFortinetSSH(FortinetSSH):
    """FortinetSSH variant that never modifies 'config system console'."""

    def disable_paging(self, *args, **kwargs) -> str:
        if self._output_mode != "standard":
            raise ValueError(PAGING_MESSAGE)
        return ""

    def cleanup(self, command: str = "exit") -> None:
        # Nothing was changed, so nothing must be restored.
        self._original_output_mode = "standard"
        return super().cleanup(command=command)


class FortinetSSHDriver(NetmikoDriver):
    vendor = "fortinet"
    platforms = ("fortinet",)
    config_types = ("running",)
    label = "Fortinet FortiOS (SSH)"
    netmiko_device_type = "fortinet"
    connection_class = ReadOnlyFortinetSSH
    commands = {"running": "show"}

    def map_exception(self, exc):
        if isinstance(exc, ValueError) and "output mode" in str(exc):
            return UnsupportedError(PAGING_MESSAGE)
        return super().map_exception(exc)

    def validate_output(self, config_type: str, output: str) -> ConfigResult:
        text = output or ""
        assert_no_cli_error(text, FORTI_ERROR_MARKERS)
        assert_no_pager(text)
        assert_min_length(text)
        if "config system global" not in text and "config global" not in text:
            raise IncompleteConfigError("FortiOS output has no 'config system global' section")
        if non_empty_lines(text)[-1].strip() != "end":
            raise IncompleteConfigError("FortiOS configuration does not end with 'end' (truncated output?)")
        if not text.endswith("\n"):
            text += "\n"
        return ConfigResult(config_type, text, "success")
