import io

from app.extensions import db
from app.models import AuditLog, BackupVersion, Device, utcnow
from app.services.storage_service import get_storage

from .conftest import login


def form(sample, **overrides):
    data = {"name": "SW-HN-01", "hostname": "sw-hn-01.example.local", "mgmt_ip": "10.10.20.2",
            "site_id": sample["site"].id, "vendor": "cisco", "platform": "cisco_ios", "connection_method": "ssh",
            "port": "", "credential_id": sample["ssh"].id, "policy_id": "", "device_role": "access_switch",
            "vdom": "", "description": "Access switch", "enabled": "on"}
    data.update(overrides)
    return data


def test_create_device(client, sample):
    login(client, "admin")
    resp = client.post("/devices/new", data=form(sample))
    assert resp.status_code == 302
    device = Device.query.filter_by(name="SW-HN-01").one()
    assert device.mgmt_ip == "10.10.20.2" and device.enabled and device.effective_port() == 22
    assert AuditLog.query.filter_by(action="device.create").count() == 1


def test_device_list_and_detail(client, sample):
    login(client, "viewer")
    assert b"CORE-SW-01" in client.get("/devices/").data
    assert client.get(f"/devices/{sample['cisco'].id}").status_code == 200


def test_validation_errors(client, sample):
    login(client, "admin")
    cases = [
        {"mgmt_ip": "999.1.1.1"},                                    # invalid IP
        {"mgmt_ip": "127.0.0.1"},                                    # loopback
        {"mgmt_ip": "192.168.1.1"},                                  # outside ALLOWED_MGMT_NETWORKS
        {"mgmt_ip": "10.99.0.1"},                                    # outside site subnet
        {"port": "2222"},                                            # port not allowed
        {"port": "70000"},
        {"connection_method": "api", "credential_id": sample["api"].id},  # cisco has no API driver
        {"vendor": "fortinet"},                                      # vendor/platform mismatch
        {"credential_id": sample["api"].id},                         # API profile on SSH device
        {"name": "CORE-SW-01"},                                      # duplicate
        {"name": "../etc"},                                          # invalid name
        {"vdom": "root"},                                            # VDOM only for Fortinet API
    ]
    for overrides in cases:
        resp = client.post("/devices/new", data=form(sample, **overrides))
        assert resp.status_code == 400, overrides
    assert Device.query.count() == 2


def test_fortinet_api_device_with_vdom(client, sample):
    login(client, "admin")
    resp = client.post("/devices/new", data=form(sample, name="FG-HN-01", vendor="fortinet", platform="fortinet",
                                                 connection_method="api", credential_id=sample["api"].id,
                                                 device_role="firewall", vdom="root"))
    assert resp.status_code == 302
    device = Device.query.filter_by(name="FG-HN-01").one()
    assert device.effective_port() == 443 and device.vdom == "root"


def test_edit_ip_resets_host_key(client, sample):
    login(client, "admin")
    device = sample["cisco"]
    data = form(sample, name=device.name, mgmt_ip="10.10.10.3", platform="cisco_xe", device_role="core_switch")
    assert client.post(f"/devices/{device.id}/edit", data=data).status_code == 302
    db.session.refresh(device)
    assert device.mgmt_ip == "10.10.10.3" and device.ssh_host_key_b64 is None


def test_toggle_and_delete(client, sample):
    login(client, "admin")
    device = sample["cisco"]
    storage = get_storage()
    path = storage.new_relative_path(device.site_id, device.id, "running", utcnow())
    storage.write(path, b"hostname x\nend\n")
    db.session.add(BackupVersion(device_id=device.id, config_type="running", backup_method="ssh",
                                 status="success", file_path=path))
    db.session.commit()
    client.post(f"/devices/{device.id}/toggle")
    db.session.refresh(device)
    assert device.enabled is False
    assert client.post(f"/devices/{device.id}/delete", data={"confirm_name": "wrong"}).status_code == 302
    assert db.session.get(Device, device.id) is not None
    device_id = device.id
    client.post(f"/devices/{device_id}/delete", data={"confirm_name": "CORE-SW-01"})
    db.session.expire_all()
    assert db.session.get(Device, device_id) is None
    assert BackupVersion.query.filter_by(device_id=device_id).count() == 0
    assert not storage.exists(path)


def test_trust_host_key_requires_matching_fingerprint(client, sample):
    from app.drivers.ssh_common import host_key_fingerprint
    login(client, "admin")
    device = sample["cisco"]
    device.pending_host_key_type, device.pending_host_key_b64 = "ssh-rsa", "AAAAB3NzaC1yc2EAAAADAQABAAABAQC7"
    db.session.commit()
    client.post(f"/devices/{device.id}/hostkey/trust", data={"fingerprint": "SHA256:wrong"})
    db.session.refresh(device)
    assert device.ssh_host_key_type == "ssh-ed25519"
    fp = host_key_fingerprint("AAAAB3NzaC1yc2EAAAADAQABAAABAQC7")
    client.post(f"/devices/{device.id}/hostkey/trust", data={"fingerprint": fp})
    db.session.refresh(device)
    assert device.ssh_host_key_type == "ssh-rsa" and device.pending_host_key_b64 is None


CSV_HEADER = "name,hostname,mgmt_ip,site,vendor,platform,connection_method,port,credential,policy,device_role,vdom,description,enabled\n"


def upload(client, text):
    return client.post("/devices/import", data={"file": (io.BytesIO(text.encode()), "devices.csv")},
                       content_type="multipart/form-data")


def test_csv_import(client, sample):
    login(client, "admin")
    text = CSV_HEADER + (
        "SW-A,,10.10.30.1,HCM-DC,cisco,cisco_ios,ssh,22,Cisco SSH,Daily 02:00,access_switch,,,true\n"
        "FG-B,,10.10.30.2,HCM-DC,fortinet,fortinet,api,,FortiGate API,,firewall,root,,\n")
    assert upload(client, text).status_code == 302
    assert Device.query.filter(Device.name.in_(["SW-A", "FG-B"])).count() == 2
    assert Device.query.filter_by(name="SW-A").one().policy.name == "Daily 02:00"


def test_csv_import_all_or_nothing(client, sample):
    login(client, "admin")
    text = CSV_HEADER + (
        "SW-A,,10.10.30.1,HCM-DC,cisco,cisco_ios,ssh,22,Cisco SSH,,access_switch,,,true\n"
        "SW-B,,8.8.8.8,HCM-DC,cisco,cisco_ios,ssh,22,Cisco SSH,,access_switch,,,true\n"
        "SW-C,,10.10.30.3,NOPE,cisco,cisco_ios,ssh,22,Cisco SSH,,access_switch,,,true\n")
    resp = upload(client, text)
    assert resp.status_code == 400 and b"Row 3" in resp.data and b"Row 4" in resp.data
    assert Device.query.filter(Device.name.like("SW-%")).count() == 0


def test_backup_now_does_not_block(client, sample):
    login(client, "operator")
    resp = client.post(f"/devices/{sample['cisco'].id}/backup")
    assert resp.status_code == 302 and "job=" in resp.headers["Location"]
    second = client.post(f"/devices/{sample['cisco'].id}/backup", follow_redirects=True)
    assert b"already queued" in second.data
    status = client.get("/jobs/1.json").get_json()
    assert status["status"] == "queued" and status["active"] is True
