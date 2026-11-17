import pytest

from app import create_app
from app.bootstrap import create_user, seed_defaults
from app.extensions import db
from app.models import Credential, Device, Site
from app.services.credential_service import encrypt_str, ensure_key_file

PASSWORD = "correct-horse-battery"

CISCO_RUNNING = """Building configuration...

Current configuration : 1234 bytes
!
! Last configuration change at 02:00:01 UTC Sun Nov 15 2026 by netbackup
!
version 17.9
hostname CORE-SW-01
!
enable secret 9 $9$abcdefghijklmnop
username netbackup privilege 15 secret 9 $9$qrstuvwxyz
!
interface GigabitEthernet1/0/1
 description Uplink
!
snmp-server community S3cretCommunity RO
!
end
"""

FORTI_CONFIG = """#config-version=FG100F-7.06-FW-build3510-241014:opmode=0:vdom=0:user=api
#conf_file_ver=1234567
#buildno=3510
#global_vdom=1
config system global
    set hostname "FG-HCM-01"
end
config system admin
    edit "admin"
        set password ENC SH2nlFAKEHASHvalue==
    next
end
"""


@pytest.fixture
def app(tmp_path):
    key_file = tmp_path / "keys" / "fernet.key"
    application = create_app({
        "TESTING": True,
        "DATA_DIR": tmp_path / "data",
        "KEY_FILE": key_file,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.sqlite3'}",
        "SECRET_KEY": "test-secret",
        "WTF_CSRF_ENABLED": False,
        "SESSION_COOKIE_SECURE": False,
        "ALLOWED_MGMT_NETWORKS": "10.0.0.0/8",
        "ALLOWED_PORTS": "22,443",
        "LOGIN_IP_MAX_ATTEMPTS": 1000,
        "SSH_STRICT_HOST_KEY": True,
    })
    ensure_key_file(key_file)
    with application.app_context():
        db.create_all()
        seed_defaults()
        create_user("admin", PASSWORD, "admin")
        create_user("operator", PASSWORD, "operator", can_download=False)
        create_user("viewer", PASSWORD, "viewer", can_download=False)
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def login(client, username):
    resp = client.post("/login", data={"username": username, "password": PASSWORD})
    assert resp.status_code == 302, resp.data
    return client


@pytest.fixture
def admin_client(client):
    return login(client, "admin")


@pytest.fixture
def sample(app):
    site = Site(name="HCM-DC", mgmt_subnet="10.10.0.0/16", timezone="Asia/Ho_Chi_Minh", status="active")
    ssh = Credential(name="Cisco SSH", cred_type="ssh", username="netbackup",
                     password_enc=encrypt_str("ssh-pass-123"), enable_password_enc=encrypt_str("enable-456"))
    api = Credential(name="FortiGate API", cred_type="api", api_token_enc=encrypt_str("tok-ABCDEF123456"),
                     api_port=443, verify_tls=True)
    db.session.add_all([site, ssh, api])
    db.session.flush()
    cisco = Device(name="CORE-SW-01", mgmt_ip="10.10.10.2", site_id=site.id, vendor="cisco", platform="cisco_xe",
                   connection_method="ssh", credential_id=ssh.id, device_role="core_switch",
                   ssh_host_key_type="ssh-ed25519", ssh_host_key_b64="AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTests000000000000000000000000")
    forti = Device(name="FG-HCM-01", mgmt_ip="10.10.10.1", site_id=site.id, vendor="fortinet", platform="fortinet",
                   connection_method="api", credential_id=api.id, device_role="firewall")
    db.session.add_all([cisco, forti])
    db.session.commit()
    return {"site": site, "ssh": ssh, "api": api, "cisco": cisco, "forti": forti}
