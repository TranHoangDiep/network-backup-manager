import pytest

from app.extensions import db
from app.models import BackupVersion, User, utcnow
from app.services.diff_service import build_diff, mask_sensitive, normalize, normalized_hash
from app.services.storage_service import StorageError, get_storage

from .conftest import CISCO_RUNNING, FORTI_CONFIG, login


def test_cisco_normalization_ignores_dynamic_lines():
    other = CISCO_RUNNING.replace("02:00:01", "09:13:44").replace("1234 bytes", "1240 bytes")
    assert other != CISCO_RUNNING
    assert normalized_hash(other, "cisco_xe") == normalized_hash(CISCO_RUNNING, "cisco_xe")
    assert "Last configuration change" not in normalize(CISCO_RUNNING, "cisco_ios")


def test_fortinet_normalization_ignores_enc_and_header():
    other = FORTI_CONFIG.replace("SH2nlFAKEHASHvalue==", "SH2differentSALT==").replace("1234567", "7654321")
    assert normalized_hash(other, "fortinet") == normalized_hash(FORTI_CONFIG, "fortinet")
    real_change = FORTI_CONFIG.replace('"FG-HCM-01"', '"FG-HCM-02"')
    assert normalized_hash(real_change, "fortinet") != normalized_hash(FORTI_CONFIG, "fortinet")


def test_masking_hides_secrets():
    masked = mask_sensitive(CISCO_RUNNING + FORTI_CONFIG + "crypto isakmp key MyPsk123 address 1.2.3.4\n"
                            "    set psksecret ENC abc\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n")
    for secret in ("$9$abcdefghijklmnop", "$9$qrstuvwxyz", "S3cretCommunity", "SH2nlFAKEHASHvalue", "MyPsk123", "MIIabc"):
        assert secret not in masked
    assert "hostname CORE-SW-01" in masked  # non-sensitive content preserved


def test_build_diff_counts():
    result = build_diff("a\nb\nc\n", "a\nB\nc\nd\n")
    assert result["added"] == 2 and result["removed"] == 1 and not result["identical"]
    kinds = [r["kind"] for r in result["rows"]]
    assert "add" in kinds and "del" in kinds
    assert build_diff("x\n", "x\n")["identical"]


def make_versions(device, contents):
    storage = get_storage()
    versions = []
    for i, content in enumerate(contents):
        when = utcnow().replace(microsecond=0)
        path = storage.new_relative_path(device.site_id, device.id, "running", when)
        storage.write(path, content.encode())
        v = BackupVersion(device_id=device.id, config_type="running", backup_method="ssh", status="success",
                          file_path=path, created_at=when, changed=True)
        db.session.add(v)
        db.session.commit()
        versions.append(v)
    return versions


def test_diff_page_masks_for_operator(client, sample):
    changed = CISCO_RUNNING.replace("description Uplink", "description Core uplink")
    a, b = make_versions(sample["cisco"], [CISCO_RUNNING, changed])
    login(client, "operator")
    page = client.get(f"/backups/diff?device_id={sample['cisco'].id}&a={a.id}&b={b.id}&normalize=1&full=1&raw=1")
    assert page.status_code == 200
    assert b"Core uplink" in page.data
    assert b"S3cretCommunity" not in page.data  # operator never sees raw secrets, even with raw=1
    assert b"diff-add" in page.data and b"diff-del" in page.data


def test_diff_page_raw_for_admin(client, sample):
    a, b = make_versions(sample["cisco"], [CISCO_RUNNING, CISCO_RUNNING + "! extra\n"])
    login(client, "admin")
    page = client.get(f"/backups/diff?device_id={sample['cisco'].id}&a={a.id}&b={b.id}&full=1&raw=1")
    assert b"S3cretCommunity" in page.data


def test_viewer_cannot_view_or_diff(client, sample):
    (a,) = make_versions(sample["cisco"], [CISCO_RUNNING])
    login(client, "viewer")
    assert client.get(f"/backups/{a.id}/view").status_code == 403
    assert client.get(f"/backups/diff?a={a.id}&b={a.id}").status_code == 403
    assert client.get(f"/backups/{a.id}/download").status_code == 403


def test_admin_download_returns_decrypted_attachment(client, sample):
    (a,) = make_versions(sample["cisco"], [CISCO_RUNNING])
    login(client, "admin")
    resp = client.get(f"/backups/{a.id}/download")
    assert resp.status_code == 200 and resp.data == CISCO_RUNNING.encode()
    disposition = resp.headers["Content-Disposition"]
    assert disposition.startswith("attachment;") and "CORE-SW-01_running_" in disposition
    assert resp.headers["Cache-Control"] == "no-store"


def test_operator_download_requires_flag(client, sample):
    (a,) = make_versions(sample["cisco"], [CISCO_RUNNING])
    login(client, "operator")
    assert client.get(f"/backups/{a.id}/download").status_code == 403
    user = User.query.filter_by(username="operator").one()
    user.can_download = True
    db.session.commit()
    assert client.get(f"/backups/{a.id}/download").status_code == 200


def test_download_rejects_tampered_path(client, sample):
    v = BackupVersion(device_id=sample["cisco"].id, config_type="running", backup_method="ssh",
                      status="success", file_path="../../../../etc/passwd")
    db.session.add(v)
    db.session.commit()
    login(client, "admin")
    assert client.get(f"/backups/{v.id}/download").status_code == 410
    assert client.get("/backups/999999/download").status_code == 404


def test_download_filename_sanitized(client, sample):
    sample["cisco"].name = "evil\";name"
    db.session.commit()
    (a,) = make_versions(sample["cisco"], [CISCO_RUNNING])
    login(client, "admin")
    disposition = client.get(f"/backups/{a.id}/download").headers["Content-Disposition"]
    assert '";' not in disposition.split("filename=")[1].strip('"')


@pytest.mark.parametrize("bad", ["../x", "/etc/passwd", "1/2/../../../x", "a\\b", ""])
def test_storage_resolve_rejects_traversal(app, bad):
    with pytest.raises(StorageError):
        get_storage().resolve(bad)


def test_storage_rejects_unknown_config_type(app):
    with pytest.raises(StorageError):
        get_storage().new_relative_path(1, 1, "../../etc", utcnow())
