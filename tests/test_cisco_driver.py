import os

import pytest
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from app.drivers import ssh_common
from app.drivers.base import (AuthenticationError, ConnectionTarget, ConnectionTimeoutError, DeviceCredential,
                              DriverOptions, HostKeyError, IncompleteConfigError, PermissionDeniedError)
from app.drivers.cisco_ios import CiscoIOSDriver
from app.drivers.cisco_nxos import CiscoNXOSDriver
from app.drivers.cisco_sbs import CiscoSBSDriver, CiscoSBSSH, _NoAuthClient

from .conftest import CISCO_RUNNING

NXOS_RUNNING = """!Command: show running-config
!Running configuration last done at: Sun Nov 15 01:00:00 2026
!Time: Sun Nov 15 02:00:00 2026

version 10.3(4a) Bios:version 05.47
hostname N9K-01
feature ssh
interface Ethernet1/1
  description uplink
"""


class FakeConn:
    def __init__(self, outputs, enabled=True, secret=""):
        self.outputs, self.enabled, self.secret, self.sent, self.closed = outputs, enabled, secret, [], False

    def find_prompt(self):
        return "CORE-SW-01#" if self.enabled else "CORE-SW-01>"

    def check_enable_mode(self):
        return self.enabled

    def enable(self):
        if self.secret != "enable-456":
            raise ValueError("Failed to enter enable mode")
        self.enabled = True

    def send_command(self, command, read_timeout=None):
        self.sent.append(command)
        value = self.outputs[command]
        if isinstance(value, Exception):
            raise value
        return value

    def disconnect(self):
        self.closed = True


@pytest.fixture
def connect(monkeypatch):
    state = {}

    def install(outputs=None, enabled=True, raises=None):
        def fake_connect(**kwargs):
            state["kwargs"] = kwargs
            state["known_hosts"] = open(kwargs["alt_key_file"]).read() if kwargs.get("alt_key_file") else None
            if raises:
                raise raises
            state["conn"] = FakeConn(outputs or {}, enabled=enabled, secret=kwargs.get("secret", ""))
            return state["conn"]
        monkeypatch.setattr(ssh_common, "ConnectHandler", fake_connect)
        return state
    return install


def make_driver(cls=CiscoIOSDriver, enable_password="", host_key=True, tmp_path="/tmp"):
    target = ConnectionTarget(name="CORE-SW-01", host="10.10.10.2", port=22, platform="cisco_xe",
                              host_key_type="ssh-ed25519" if host_key else "",
                              host_key_b64="AAAAC3NzaC1lZDI1NTE5AAAAIFake" if host_key else "")
    cred = DeviceCredential(username="netbackup", password="pw", enable_password=enable_password)
    return cls(target, cred, DriverOptions(tmp_dir=str(tmp_path)))


def test_cisco_backup_running_and_startup(connect, tmp_path):
    state = connect({"show running-config": CISCO_RUNNING, "show startup-config": CISCO_RUNNING})
    results = make_driver(tmp_path=tmp_path).fetch_configs(["running", "startup"])
    assert [r.status for r in results] == ["success", "success"]
    assert results[0].content == CISCO_RUNNING
    kwargs = state["kwargs"]
    assert kwargs["ssh_strict"] is True and kwargs["system_host_keys"] is False and kwargs["allow_agent"] is False
    assert state["known_hosts"].startswith("10.10.10.2 ssh-ed25519 ")
    assert not os.path.exists(kwargs["alt_key_file"])  # temp known_hosts cleaned up
    assert state["conn"].closed
    assert state["conn"].sent == ["show running-config", "show startup-config"]  # read-only commands only


def test_startup_missing_is_skipped(connect, tmp_path):
    connect({"show running-config": CISCO_RUNNING, "show startup-config": "startup-config is not present"})
    results = make_driver(tmp_path=tmp_path).fetch_configs(["running", "startup"])
    assert results[1].status == "skipped"


def test_cli_error_not_saved(connect, tmp_path):
    connect({"show running-config": "                ^\n% Invalid input detected at '^' marker.\n"})
    with pytest.raises(IncompleteConfigError):
        make_driver(tmp_path=tmp_path).fetch_configs(["running"])


def test_truncated_config_rejected(connect, tmp_path):
    truncated = CISCO_RUNNING.replace("\nend\n", "\ninterface Gi1/0/2\n")
    connect({"show running-config": truncated})
    with pytest.raises(IncompleteConfigError, match="end"):
        make_driver(tmp_path=tmp_path).fetch_configs(["running"])


def test_empty_output_rejected(connect, tmp_path):
    connect({"show running-config": ""})
    with pytest.raises(IncompleteConfigError):
        make_driver(tmp_path=tmp_path).fetch_configs(["running"])


def test_secondary_failure_is_partial(connect, tmp_path):
    connect({"show running-config": CISCO_RUNNING, "show startup-config": "% Permission denied"})
    results = make_driver(tmp_path=tmp_path).fetch_configs(["running", "startup"])
    assert results[0].status == "success" and results[1].status == "failed"


def test_enable_mode_with_secret(connect, tmp_path):
    connect({"show running-config": CISCO_RUNNING}, enabled=False)
    results = make_driver(enable_password="enable-456", tmp_path=tmp_path).fetch_configs(["running"])
    assert results[0].status == "success"


def test_unprivileged_without_enable_password(connect, tmp_path):
    connect({"show running-config": CISCO_RUNNING}, enabled=False)
    with pytest.raises(PermissionDeniedError):
        make_driver(tmp_path=tmp_path).fetch_configs(["running"])


def test_wrong_enable_password(connect, tmp_path):
    connect({"show running-config": CISCO_RUNNING}, enabled=False)
    with pytest.raises(PermissionDeniedError):
        make_driver(enable_password="wrong", tmp_path=tmp_path).fetch_configs(["running"])


def test_invalid_credentials(connect, tmp_path):
    connect(raises=NetmikoAuthenticationException("Authentication to device failed."))
    with pytest.raises(AuthenticationError) as info:
        make_driver(tmp_path=tmp_path).fetch_configs(["running"])
    assert not info.value.retryable


def test_connection_timeout_is_retryable(connect, tmp_path):
    connect(raises=NetmikoTimeoutException("TCP connection to device failed."))
    with pytest.raises(ConnectionTimeoutError) as info:
        make_driver(tmp_path=tmp_path).fetch_configs(["running"])
    assert info.value.retryable


def test_untrusted_host_key_blocks_connection(connect, tmp_path):
    state = connect({"show running-config": CISCO_RUNNING})
    with pytest.raises(HostKeyError):
        make_driver(host_key=False, tmp_path=tmp_path).fetch_configs(["running"])
    assert "kwargs" not in state  # never connected


def test_unknown_host_key_from_paramiko(connect, tmp_path):
    import paramiko
    connect(raises=paramiko.SSHException("Server '10.10.10.2' not found in known_hosts"))
    with pytest.raises(HostKeyError):
        make_driver(tmp_path=tmp_path).fetch_configs(["running"])


def test_test_connection_scans_unknown_key(monkeypatch, tmp_path):
    monkeypatch.setattr(ssh_common, "scan_host_key", lambda host, port, timeout: {
        "type": "ssh-ed25519", "b64": "AAAAkey", "fingerprint": "SHA256:abc"})
    result = make_driver(host_key=False, tmp_path=tmp_path).test_connection()
    assert not result.ok and result.details["host_key_pending"]["fingerprint"] == "SHA256:abc"


def test_nxos_backup(connect, tmp_path):
    connect({"show running-config": NXOS_RUNNING})
    results = make_driver(CiscoNXOSDriver, tmp_path=tmp_path).fetch_configs(["running"])
    assert results[0].status == "success"


def test_nxos_permission_error(connect, tmp_path):
    connect({"show running-config": "% Permission denied for the role"})
    with pytest.raises(IncompleteConfigError):
        make_driver(CiscoNXOSDriver, tmp_path=tmp_path).fetch_configs(["running"])


def test_fortinet_ssh_never_changes_console(monkeypatch):
    from app.drivers.fortinet_ssh import ReadOnlyFortinetSSH
    conn = ReadOnlyFortinetSSH.__new__(ReadOnlyFortinetSSH)
    conn._output_mode = "more"
    with pytest.raises(ValueError, match="output mode"):
        conn.disable_paging()
    conn._output_mode = "standard"
    assert conn.disable_paging() == ""


SBS_RUNNING = """config-file-header
SW-01
v4.1.3.36 / RLSB4.1.3_951_191_247
CLI v1.0
set system mode switch
!
hostname SW-01
!
interface gigabitethernet1
 description uplink
exit
ip default-gateway 10.4.24.254
"""


def test_sbs_accepts_config_without_end_trailer(tmp_path):
    result = make_driver(CiscoSBSDriver, tmp_path=tmp_path).validate_output("running", SBS_RUNNING)
    assert result.status == "success" and result.content == SBS_RUNNING


def test_sbs_rejects_ios_style_or_truncated_output(tmp_path):
    driver = make_driver(CiscoSBSDriver, tmp_path=tmp_path)
    with pytest.raises(IncompleteConfigError, match="config-file-header"):
        driver.validate_output("running", CISCO_RUNNING)  # valid IOS config, wrong OS
    with pytest.raises(IncompleteConfigError, match="hostname"):
        driver.validate_output("running", SBS_RUNNING.replace("hostname SW-01", ""))
    with pytest.raises(IncompleteConfigError):
        driver.validate_output("running", "% Unrecognized command\n")


def test_sbs_ssh_layer_uses_no_password_auth():
    assert isinstance(CiscoSBSSH._get_ssh_client_instance(None), _NoAuthClient)


def test_legacy_ssh_rsa_host_key_enabled_last():
    import paramiko
    assert paramiko.Transport._preferred_keys[-1] == "ssh-rsa" and "ssh-rsa" in paramiko.RSAKey.HASHES
    assert paramiko.Transport._preferred_keys.index("rsa-sha2-512") < paramiko.Transport._preferred_keys.index("ssh-rsa")


def test_legacy_group14_sha1_kex_enabled_last():
    import paramiko
    kex = paramiko.Transport._preferred_kex
    assert kex[-1] == "diffie-hellman-group14-sha1" and "diffie-hellman-group14-sha256" in kex
    assert "diffie-hellman-group14-sha1" in paramiko.Transport._kex_info
