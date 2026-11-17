"""Input validation and destination (egress) policy checks."""
import ipaddress
import re
from zoneinfo import ZoneInfo, available_timezones

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()\-]{0,63}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{1,63}$")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")
VDOM_RE = re.compile(r"^[A-Za-z0-9_\-]{1,31}$")
SSH_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@\\\-]{1,128}$")


class ValidationError(ValueError):
    pass


def clean_name(value, field: str = "Name") -> str:
    value = (value or "").strip()
    if not NAME_RE.match(value):
        raise ValidationError(f"{field} must be 1-64 characters: letters, digits, space, . _ - ( )")
    return value


def clean_text(value, field: str, max_len: int = 255, required: bool = False) -> str:
    value = (value or "").strip()
    if required and not value:
        raise ValidationError(f"{field} is required")
    if len(value) > max_len:
        raise ValidationError(f"{field} must be at most {max_len} characters")
    return value


def clean_hostname(value) -> str:
    value = (value or "").strip()
    if value and not HOSTNAME_RE.match(value):
        raise ValidationError("Hostname is not a valid DNS name")
    return value


def parse_ip(value) -> str:
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        raise ValidationError("Management IP is not a valid IPv4/IPv6 address") from None
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_reserved:
        raise ValidationError("Management IP must be a unicast, non-loopback, non-link-local address")
    return str(ip)


def parse_port(value, required: bool = False):
    value = str(value or "").strip()
    if not value:
        if required:
            raise ValidationError("Port is required")
        return None
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise ValidationError("Port must be an integer between 1 and 65535")
    return int(value)


def parse_int(value, field: str, minimum: int, maximum: int) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValidationError(f"{field} must be an integer") from None
    if not minimum <= number <= maximum:
        raise ValidationError(f"{field} must be between {minimum} and {maximum}")
    return number


def parse_cidr(value) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        raise ValidationError(f"'{value}' is not a valid network (CIDR)") from None


_TIMEZONES = None


def parse_timezone(value) -> str:
    global _TIMEZONES
    if _TIMEZONES is None:
        _TIMEZONES = available_timezones()
    value = (value or "").strip() or "UTC"
    if value not in _TIMEZONES and value != "UTC":
        raise ValidationError(f"Unknown timezone '{value}'")
    ZoneInfo(value)
    return value


def parse_networks(csv_value: str) -> list:
    networks = []
    for item in (csv_value or "").split(","):
        item = item.strip()
        if item:
            networks.append(ipaddress.ip_network(item, strict=False))
    return networks


def parse_ports(csv_value: str) -> set:
    return {int(p) for p in (csv_value or "").split(",") if p.strip().isdigit()}


def check_destination_allowed(ip: str, port: int, site_subnet, allowed_networks: list, allowed_ports: set) -> None:
    """Raise ValidationError if a worker must not connect to ip:port."""
    address = ipaddress.ip_address(ip)
    if not allowed_networks:
        raise ValidationError("ALLOWED_MGMT_NETWORKS is empty; no destination is permitted")
    if not any(address.version == net.version and address in net for net in allowed_networks):
        raise ValidationError(f"{ip} is outside the authorized management networks (ALLOWED_MGMT_NETWORKS)")
    if site_subnet:
        subnet = ipaddress.ip_network(site_subnet, strict=False)
        if address.version != subnet.version or address not in subnet:
            raise ValidationError(f"{ip} is outside the site management subnet {subnet}")
    if allowed_ports and port not in allowed_ports:
        raise ValidationError(f"Port {port} is not in ALLOWED_PORTS ({', '.join(map(str, sorted(allowed_ports)))})")


def destination_policy(config) -> tuple:
    return parse_networks(config["ALLOWED_MGMT_NETWORKS"]), parse_ports(config["ALLOWED_PORTS"])
