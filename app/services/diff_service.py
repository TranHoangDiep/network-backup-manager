"""Vendor-aware normalization, secret masking, hashing and line diffs.

Raw files are never modified: normalization and masking operate on copies
in memory, for change detection and for display only.
"""
import difflib
import hashlib
import re

_DYNAMIC_LINES = {
    "cisco": [
        r"^! Last configuration change at",
        r"^! NVRAM config last updated at",
        r"^! No configuration change since last restart",
        r"^ntp clock-period\s",
        r"^Building configuration",
        r"^Current configuration\s*:",
        r"^Using \d+ out of \d+ bytes",
    ],
    "nxos": [
        r"^!Command:",
        r"^!Time:",
        r"^!Running configuration last done at:",
        r"^!Startup config saved at:",
    ],
    "fortinet": [
        r"^#config-version=",
        r"^#conf_file_ver=",
        r"^#buildno=",
        r"^#global_vdom=",
    ],
    "aruba": [
        r"^Current configuration:",
    ],
}
_DYNAMIC_RE = {family: re.compile("|".join(patterns)) for family, patterns in _DYNAMIC_LINES.items()}

# FortiOS re-encrypts stored secrets with a random salt on every export, so
# 'set password ENC xxx' changes on every backup without any real change.
_FORTI_ENC_RE = re.compile(r"(\bENC\s+)\S+")


def platform_family(platform: str) -> str:
    if platform == "cisco_nxos":
        return "nxos"
    if platform.startswith("cisco"):
        return "cisco"
    if platform.startswith("fortinet"):
        return "fortinet"
    if platform.startswith("aruba"):
        return "aruba"
    return platform


def normalize(content: str, platform: str) -> str:
    family = platform_family(platform)
    dynamic = _DYNAMIC_RE.get(family)
    lines = []
    for line in content.splitlines():
        if dynamic is not None and dynamic.search(line):
            continue
        if family == "fortinet":
            line = _FORTI_ENC_RE.sub(r"\1<encrypted>", line)
        lines.append(line.rstrip())
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalized_hash(content: str, platform: str) -> str:
    return sha256_bytes(normalize(content, platform).encode("utf-8", errors="surrogateescape"))


# ------------------------------------------------------------- masking ---
_MASK = "<masked>"
_LINE_MASKS = [
    # Cisco: enable secret 9 ..., username x privilege 15 secret 9 ..., password 7 ...
    re.compile(r"^(\s*(?:enable\s+)?(?:secret|password)\s+(?:\d+\s+)?)\S.*$", re.I),
    re.compile(r"^(\s*username\s+\S+.*?\s(?:secret|password)\s+(?:\d+\s+)?)\S.*$", re.I),
    re.compile(r"^(\s*snmp-server\s+community\s+)\S+(.*)$", re.I),
    re.compile(r"^(\s*snmp-server\s+user\s+\S+.*?\sauth\s+\S+\s+)\S.*$", re.I),
    re.compile(r"^(\s*(?:key-string|pre-shared-key|authentication-key|ip ospf message-digest-key\s+\d+\s+md5)"
               r"\s+(?:\d+\s+)?)\S.*$", re.I),
    re.compile(r"^(\s*(?:tacacs-server|radius-server)\s+(?:host\s+\S+\s+)?key\s+(?:\d+\s+)?)\S.*$", re.I),
    re.compile(r"^(\s*(?:server-private\s+\S+\s+)?key\s+(?:\d+\s+)?)\S+\s*$", re.I),
    re.compile(r"^(\s*crypto isakmp key\s+(?:\d+\s+)?)\S+(.*)$", re.I),
    re.compile(r"^(\s*(?:psk|wpa-psk|ascii)\s+)\S.*$", re.I),
    # FortiOS: set <anything with password/secret/psk/...> value
    re.compile(r"^(\s*set\s+[\w-]*(?:password|passwd|secret|psk|pwd|passphrase|private-key|api-key|community|"
               r"key-string)[\w-]*\s+).*$", re.I),
    re.compile(r"^(\s*set\s+key\s+).*$", re.I),
]
_ENC_RE = re.compile(r"\bENC\s+\S+")
_PEM_RE = re.compile(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.S)


def mask_sensitive(content: str) -> str:
    content = _PEM_RE.sub("<masked certificate/key block>", content)
    out = []
    for line in content.splitlines():
        for pattern in _LINE_MASKS:
            if pattern.match(line):
                line = pattern.sub(lambda m: m.group(1) + _MASK, line)
                break
        out.append(_ENC_RE.sub("ENC " + _MASK, line))
    return "\n".join(out) + ("\n" if content.endswith("\n") else "")


# ---------------------------------------------------------------- diff ---
def build_diff(old: str, new: str, context: int = 3, full: bool = False) -> dict:
    a, b = old.splitlines(), new.splitlines()
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    rows, added, removed = [], 0, 0
    groups = [matcher.get_opcodes()] if full else list(matcher.get_grouped_opcodes(context))
    for index, group in enumerate(groups):
        if index > 0 or (group and (group[0][1] > 0 or group[0][3] > 0) and not full):
            rows.append({"kind": "skip", "old_no": None, "new_no": None, "text": "..."})
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                for offset in range(i2 - i1):
                    rows.append({"kind": "equal", "old_no": i1 + offset + 1, "new_no": j1 + offset + 1,
                                 "text": a[i1 + offset]})
                continue
            if tag in ("delete", "replace"):
                for i in range(i1, i2):
                    rows.append({"kind": "del", "old_no": i + 1, "new_no": None, "text": a[i]})
                    removed += 1
            if tag in ("insert", "replace"):
                for j in range(j1, j2):
                    rows.append({"kind": "add", "old_no": None, "new_no": j + 1, "text": b[j]})
                    added += 1
    return {"rows": rows, "added": added, "removed": removed, "identical": added == 0 and removed == 0}


def diff_stats(old: str, new: str) -> tuple:
    result = build_diff(old, new, context=0)
    return result["added"], result["removed"]
