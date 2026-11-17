"""Driver registry. Add a vendor by writing a BaseDriver subclass and
registering it in PLATFORMS below."""
from .aruba_aoscx import ArubaAOSCXDriver
from .base import UnsupportedError
from .cisco_ios import CiscoIOSDriver
from .cisco_nxos import CiscoNXOSDriver
from .fortinet_api import FortinetAPIDriver
from .fortinet_ssh import FortinetSSHDriver

VENDORS = {"cisco": "Cisco", "fortinet": "Fortinet", "aruba": "Aruba"}

PLATFORMS = {
    "cisco_ios": {"vendor": "cisco", "label": "Cisco IOS", "methods": {"ssh": CiscoIOSDriver}},
    "cisco_xe": {"vendor": "cisco", "label": "Cisco IOS-XE", "methods": {"ssh": CiscoIOSDriver}},
    "cisco_nxos": {"vendor": "cisco", "label": "Cisco NX-OS", "methods": {"ssh": CiscoNXOSDriver}},
    "fortinet": {"vendor": "fortinet", "label": "Fortinet FortiOS",
                 "methods": {"api": FortinetAPIDriver, "ssh": FortinetSSHDriver}},
    "aruba_aoscx": {"vendor": "aruba", "label": "Aruba AOS-CX (experimental)",
                    "methods": {"ssh": ArubaAOSCXDriver}},
}


def get_driver_class(platform: str, method: str):
    entry = PLATFORMS.get(platform)
    if entry is None:
        raise UnsupportedError(f"Unsupported platform '{platform}'")
    driver = entry["methods"].get(method)
    if driver is None:
        raise UnsupportedError(f"Platform '{platform}' does not support connection method '{method}'")
    return driver


def is_compatible(vendor: str, platform: str, method: str) -> bool:
    entry = PLATFORMS.get(platform)
    return bool(entry and entry["vendor"] == vendor and method in entry["methods"])
