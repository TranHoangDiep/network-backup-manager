import logging
import os
import stat

import pytest
from cryptography.fernet import Fernet

from app.extensions import db
from app.logging_setup import RedactingFilter, register_secrets, unregister_secrets
from app.models import ApplicationSetting, Credential
from app.services import credential_service as cs
from app.services.settings_service import get_setting, set_setting

from .conftest import login


def test_encrypt_decrypt_roundtrip(app):
    token = cs.encrypt_str("s3cr3t-Password!")
    assert token and "s3cr3t" not in token
    assert cs.decrypt_str(token) == "s3cr3t-Password!"
    assert cs.encrypt_str("") is None
    assert cs.decrypt_str(None) == ""


def test_key_file_permissions(app):
    mode = stat.S_IMODE(os.stat(app.config["KEY_FILE"]).st_mode)
    assert mode == 0o600


def test_wrong_key_raises_crypto_error(app):
    token = cs.encrypt_str("value")
    app.config["KEY_FILE"].write_bytes(Fernet.generate_key() + b"\n")
    with pytest.raises(cs.CryptoError):
        cs.decrypt_str(token)


def test_no_plaintext_in_database(app, sample):
    db_bytes = open(app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", ""), "rb").read()
    wal = app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "") + "-wal"
    if os.path.exists(wal):
        db_bytes += open(wal, "rb").read()
    for secret in (b"ssh-pass-123", b"enable-456", b"tok-ABCDEF123456"):
        assert secret not in db_bytes


def test_load_credential_and_repr_hides_secrets(app, sample):
    cred = cs.load_credential(sample["ssh"])
    assert cred.password == "ssh-pass-123" and cred.enable_password == "enable-456"
    assert "ssh-pass-123" not in repr(cred)


def test_credential_form_never_shows_secret_and_blank_keeps(client, sample):
    login(client, "admin")
    cred = sample["ssh"]
    page = client.get(f"/credentials/{cred.id}/edit").data
    assert b"ssh-pass-123" not in page and b"enable-456" not in page
    old_token = cred.password_enc
    resp = client.post(f"/credentials/{cred.id}/edit", data={
        "name": "Cisco SSH", "cred_type": "ssh", "username": "netbackup", "password": "", "description": ""})
    assert resp.status_code == 302
    db.session.refresh(cred)
    assert cred.password_enc == old_token  # unchanged
    resp = client.post(f"/credentials/{cred.id}/edit", data={
        "name": "Cisco SSH", "cred_type": "ssh", "username": "netbackup", "password": "rotated-pass-789"})
    assert resp.status_code == 302
    db.session.refresh(cred)
    assert cs.decrypt_str(cred.password_enc) == "rotated-pass-789"
    assert cred.rotated_at is not None


def test_api_credential_requires_token(client, app):
    login(client, "admin")
    resp = client.post("/credentials/new", data={"name": "No token", "cred_type": "api", "api_port": "443"})
    assert resp.status_code == 400
    assert Credential.query.filter_by(name="No token").first() is None


def test_secret_setting_is_encrypted(app):
    set_setting("smtp_password", "mail-pass-xyz")
    db.session.commit()
    row = db.session.get(ApplicationSetting, "smtp_password")
    assert row.is_secret and "mail-pass-xyz" not in row.value
    assert get_setting("smtp_password") == "mail-pass-xyz"


def test_key_rotation_keeps_data_decryptable(app, sample):
    from app.services.storage_service import get_storage
    storage = get_storage()
    from app.models import BackupVersion, utcnow
    path = storage.new_relative_path(sample["site"].id, sample["cisco"].id, "running", utcnow())
    storage.write(path, b"hostname X\nend\n")
    db.session.add(BackupVersion(device_id=sample["cisco"].id, config_type="running", backup_method="ssh",
                                 status="success", file_path=path))
    db.session.commit()
    old_token = sample["ssh"].password_enc
    stats = cs.rotate_encryption_key(drop_old=True)
    assert stats["files"] == 1 and stats["credentials"] == 2
    db.session.refresh(sample["ssh"])
    assert sample["ssh"].password_enc != old_token
    assert cs.decrypt_str(sample["ssh"].password_enc) == "ssh-pass-123"
    assert storage.read(path) == b"hostname X\nend\n"
    assert len(cs.read_keys(app.config["KEY_FILE"])) == 1


def test_log_redaction():
    record = logging.LogRecord("t", logging.INFO, __file__, 1,
                               "login password=hunter2 token: abc Authorization: Bearer xyz.123 val=%s",
                               ("mysecretvalue",), None)
    register_secrets(["mysecretvalue"])
    try:
        RedactingFilter().filter(record)
    finally:
        unregister_secrets(["mysecretvalue"])
    message = record.getMessage()
    for leaked in ("hunter2", "xyz.123", "mysecretvalue"):
        assert leaked not in message
