from datetime import timedelta

from app.extensions import db
from app.models import BackupJob, BackupVersion, utcnow
from app.services.retention_service import run_retention
from app.services.storage_service import get_storage


def add_version(device, days_ago, path=None, status="success", content=b"hostname X\nend\n"):
    when = utcnow() - timedelta(days=days_ago)
    storage = get_storage()
    if path is None and status == "success":
        path = storage.new_relative_path(device.site_id, device.id, "running", when)
        storage.write(path, content)
    version = BackupVersion(device_id=device.id, config_type="running", backup_method="ssh", status=status,
                            created_at=when, file_path=path)
    db.session.add(version)
    db.session.commit()
    return version


def test_expired_versions_and_unreferenced_files_deleted(app, sample):
    device = sample["cisco"]
    device.device_role = "access_switch"  # 90 days
    v1 = add_version(device, 200)
    v2 = add_version(device, 100, path=v1.file_path)  # unchanged, shares file
    v3 = add_version(device, 10)
    add_version(device, 95, status="failed")
    path_a, path_b = v1.file_path, v3.file_path
    stats = run_retention()
    assert stats["versions_deleted"] == 3 and stats["files_deleted"] == 1
    remaining = BackupVersion.query.filter_by(device_id=device.id).all()
    assert [v.id for v in remaining] == [v3.id]
    assert not get_storage().exists(path_a) and get_storage().exists(path_b)
    assert v2.id not in [v.id for v in remaining]


def test_last_valid_backup_never_deleted(app, sample):
    only = add_version(sample["cisco"], 400)
    run_retention()
    assert db.session.get(BackupVersion, only.id) is not None
    assert get_storage().exists(only.file_path)


def test_shared_file_kept_while_referenced(app, sample):
    old = add_version(sample["cisco"], 400)
    newer = add_version(sample["cisco"], 5, path=old.file_path)
    run_retention()
    assert db.session.get(BackupVersion, old.id) is None
    assert db.session.get(BackupVersion, newer.id) is not None
    assert get_storage().exists(newer.file_path)


def test_device_with_active_job_skipped(app, sample):
    add_version(sample["cisco"], 400)
    add_version(sample["cisco"], 300)
    db.session.add(BackupJob(device_id=sample["cisco"].id, status="running"))
    db.session.commit()
    stats = run_retention()
    assert stats["devices_skipped"] == 1 and stats["versions_deleted"] == 0


def test_policy_retention_override(app, sample):
    from app.models import BackupPolicy
    policy = BackupPolicy.query.first()
    policy.retention_days = 7
    sample["cisco"].policy_id = policy.id
    db.session.commit()
    old = add_version(sample["cisco"], 10)
    add_version(sample["cisco"], 1)
    run_retention()
    assert db.session.get(BackupVersion, old.id) is None
