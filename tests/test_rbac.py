import pytest

from app.extensions import db
from app.models import BackupJob, User

from .conftest import PASSWORD, login


def test_anonymous_redirected_to_login(client):
    resp = client.get("/devices/")
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]


def test_healthz_is_public(client):
    assert client.get("/healthz").status_code == 200


@pytest.mark.parametrize("username,path,expected", [
    ("viewer", "/", 200),
    ("viewer", "/devices/", 200),
    ("viewer", "/backups", 200),
    ("viewer", "/credentials/", 403),
    ("viewer", "/devices/new", 403),
    ("viewer", "/settings/", 403),
    ("operator", "/devices/", 200),
    ("operator", "/credentials/", 403),
    ("operator", "/devices/new", 403),
    ("operator", "/settings/users", 403),
    ("admin", "/credentials/", 200),
    ("admin", "/devices/new", 200),
    ("admin", "/settings/", 200),
    ("admin", "/settings/users", 200),
    ("admin", "/settings/policies", 200),
    ("admin", "/settings/audit", 200),
])
def test_page_permissions(client, sample, username, path, expected):
    login(client, username)
    assert client.get(path).status_code == expected


def test_viewer_cannot_run_backup(client, sample):
    login(client, "viewer")
    assert client.post(f"/devices/{sample['cisco'].id}/backup").status_code == 403
    assert BackupJob.query.count() == 0


def test_operator_can_run_backup(client, sample):
    login(client, "operator")
    resp = client.post(f"/devices/{sample['cisco'].id}/backup")
    assert resp.status_code == 302
    job = BackupJob.query.one()
    assert job.status == "queued" and job.trigger == "manual"


def test_operator_cannot_manage_credentials(client, sample):
    login(client, "operator")
    resp = client.post("/credentials/new", data={"name": "x", "cred_type": "api", "api_token": "t", "api_port": "443"})
    assert resp.status_code == 403


def test_login_lockout(client, app):
    for _ in range(app.config["LOGIN_MAX_ATTEMPTS"]):
        client.post("/login", data={"username": "viewer", "password": "wrong-password"})
    user = User.query.filter_by(username="viewer").one()
    db.session.refresh(user)
    assert user.locked_until is not None
    resp = client.post("/login", data={"username": "viewer", "password": PASSWORD})
    assert resp.status_code == 403


def test_open_redirect_blocked(client):
    resp = client.post("/login?next=//evil.example.com", data={"username": "admin", "password": PASSWORD})
    assert resp.status_code == 302 and resp.headers["Location"] == "/"


def test_cannot_remove_last_admin(client):
    login(client, "admin")
    admin = User.query.filter_by(username="admin").one()
    resp = client.post(f"/settings/users/{admin.id}/edit", data={"username": "admin", "role": "viewer", "active": "on"})
    assert resp.status_code == 400
    db.session.refresh(admin)
    assert admin.role_name == "admin"


def test_security_headers(client):
    resp = client.get("/login")
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Frame-Options"] == "DENY"
