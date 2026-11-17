import hashlib
import threading
import time
from datetime import timedelta

import pytest
from sqlalchemy.exc import IntegrityError

from app.drivers.base import (AuthenticationError, BaseDriver, ConfigResult, ConnectionTimeoutError,
                              IncompleteConfigError, TestResult)
from app.extensions import db
from app.models import BackupJob, BackupVersion, utcnow
from app.services import backup_service as bs
from app.services.settings_service import set_setting
from app.services.storage_service import get_storage

from .conftest import CISCO_RUNNING


class FakeDriver(BaseDriver):
    """Configurable stand-in for a real driver (tests only)."""
    vendor, method, platforms, config_types = "cisco", "ssh", ("cisco_xe",), ("running", "startup")
    outputs = []        # queue of: str config | Exception
    startup = None      # optional startup ConfigResult
    gate = None         # optional threading.Event to block on

    def test_connection(self):
        return TestResult(True, "ok")

    def fetch_configs(self, config_types):
        if FakeDriver.gate is not None:
            FakeDriver.gate.wait(5)
        item = FakeDriver.outputs.pop(0)
        if isinstance(item, Exception):
            raise item
        results = [ConfigResult("running", item)]
        if "startup" in config_types:
            results.append(FakeDriver.startup or ConfigResult("startup", None, "skipped", "not present"))
        return results


@pytest.fixture
def fake_driver(monkeypatch):
    FakeDriver.outputs, FakeDriver.startup, FakeDriver.gate = [], None, None
    monkeypatch.setattr(bs, "get_driver_class", lambda platform, method: FakeDriver)
    notifications = []
    monkeypatch.setattr(bs, "notify", lambda event, subject, body, data=None: notifications.append(event))
    FakeDriver.notifications = notifications
    return FakeDriver


def run(device, job_type="backup"):
    job, reason = bs.enqueue_job(device, job_type)
    assert job, reason
    assert bs.claim_job(job.id)
    bs.execute_job(job.id)
    db.session.refresh(job)
    return job


def test_backup_stores_encrypted_file_and_checksum(app, sample, fake_driver):
    fake_driver.outputs = [CISCO_RUNNING]
    job = run(sample["cisco"])
    assert job.status == "success"
    version = BackupVersion.query.filter_by(config_type="running").one()
    assert version.changed and version.change_summary == "initial backup"
    assert version.config_hash == hashlib.sha256(CISCO_RUNNING.encode()).hexdigest()
    path = get_storage().resolve(version.file_path)
    assert version.file_path.startswith(f"{sample['site'].id}/{sample['cisco'].id}/running/")
    raw_disk = path.read_bytes()
    assert b"hostname" not in raw_disk  # encrypted at rest
    assert get_storage().read(version.file_path) == CISCO_RUNNING.encode()
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    skipped = BackupVersion.query.filter_by(config_type="startup").one()
    assert skipped.status == "skipped"
    assert sample["cisco"].last_backup_status == "success" and sample["cisco"].reachable is True


def test_unchanged_config_reuses_file(app, sample, fake_driver):
    second = CISCO_RUNNING.replace("02:00:01", "08:00:05")  # only a dynamic line differs
    fake_driver.outputs = [CISCO_RUNNING, second]
    run(sample["cisco"])
    run(sample["cisco"])
    versions = BackupVersion.query.filter_by(config_type="running").order_by(BackupVersion.id).all()
    assert len(versions) == 2  # every execution recorded
    assert versions[1].changed is False and versions[1].file_path == versions[0].file_path
    files = list(get_storage().base.rglob("*.cfg.enc"))
    assert len(files) == 1  # no duplicate file


def test_changed_config_creates_new_file_and_notifies(app, sample, fake_driver):
    changed = CISCO_RUNNING.replace(" description Uplink\n", " description Uplink\n shutdown\n")
    fake_driver.outputs = [CISCO_RUNNING, changed]
    run(sample["cisco"])
    run(sample["cisco"])
    latest = BackupVersion.query.filter_by(config_type="running").order_by(BackupVersion.id.desc()).first()
    assert latest.changed and latest.change_summary == "+1 / -0 lines"
    assert len(list(get_storage().base.rglob("*.cfg.enc"))) == 2
    assert "config_changed" in fake_driver.notifications


def test_retryable_error_requeues_with_backoff(app, sample, fake_driver):
    set_setting("retry_max_attempts", 2)
    db.session.commit()
    fake_driver.outputs = [ConnectionTimeoutError("timed out"), ConnectionTimeoutError("timed out")]
    job = run(sample["cisco"])
    assert job.status == "queued" and job.attempt == 1 and job.next_attempt_at > utcnow()
    assert sample["cisco"].reachable is False
    assert bs.claim_job(job.id)
    bs.execute_job(job.id)
    db.session.refresh(job)
    assert job.status == "failed" and job.attempt == 2
    failed = BackupVersion.query.filter_by(status="failed").one()
    assert "timed out" in failed.error_message and failed.file_path is None
    assert "backup_failed" in fake_driver.notifications


def test_auth_error_not_retried(app, sample, fake_driver):
    fake_driver.outputs = [AuthenticationError("SSH authentication failed")]
    job = run(sample["cisco"])
    assert job.status == "failed" and job.attempt == 1
    assert sample["cisco"].last_backup_status == "failed"


def test_incomplete_config_never_stored(app, sample, fake_driver):
    set_setting("retry_max_attempts", 1)
    db.session.commit()
    fake_driver.outputs = [IncompleteConfigError("truncated")]
    job = run(sample["cisco"])
    assert job.status == "failed"
    assert list(get_storage().base.rglob("*.cfg.enc")) == []


def test_partial_when_secondary_fails(app, sample, fake_driver):
    fake_driver.outputs = [CISCO_RUNNING]
    fake_driver.startup = ConfigResult("startup", None, "failed", "% Permission denied")
    job = run(sample["cisco"])
    assert job.status == "partial"


def test_destination_outside_allowlist_blocked(app, sample, fake_driver):
    app.config["ALLOWED_MGMT_NETWORKS"] = "192.168.0.0/16"
    fake_driver.outputs = [CISCO_RUNNING]
    job = run(sample["cisco"])
    assert job.status == "failed" and "Destination not allowed" in job.message
    assert fake_driver.outputs == [CISCO_RUNNING]  # driver never called


def test_test_job_stores_pending_host_key(app, sample, monkeypatch):
    class KeyDriver(FakeDriver):
        def test_connection(self):
            return TestResult(False, "untrusted", {"host_key_pending": {"type": "ssh-rsa", "b64": "AAAAB3", "fingerprint": "SHA256:x"}})
    monkeypatch.setattr(bs, "get_driver_class", lambda p, m: KeyDriver)
    job = run(sample["cisco"], "test")
    assert job.status == "failed"
    assert sample["cisco"].pending_host_key_b64 == "AAAAB3"


# ------------------------------------------------- concurrency protection ---
def test_duplicate_enqueue_rejected(app, sample):
    job, _ = bs.enqueue_job(sample["cisco"])
    again, reason = bs.enqueue_job(sample["cisco"])
    assert job and again is None and f"#{job.id}" in reason


def test_db_unique_index_blocks_second_active_job(app, sample):
    db.session.add(BackupJob(device_id=sample["cisco"].id, status="queued"))
    db.session.commit()
    db.session.add(BackupJob(device_id=sample["cisco"].id, status="running"))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
    db.session.add(BackupJob(device_id=sample["cisco"].id, status="success"))  # finished jobs are fine
    db.session.commit()


def test_job_can_only_be_claimed_once(app, sample):
    job, _ = bs.enqueue_job(sample["cisco"])
    assert bs.claim_job(job.id) is True
    assert bs.claim_job(job.id) is False


def test_runner_respects_max_concurrency(app, sample, fake_driver):
    from app.models import Device
    set_setting("max_concurrency", 2)
    db.session.commit()
    devices = [sample["cisco"]]
    for i in range(3):
        d = Device(name=f"SW-{i}", mgmt_ip=f"10.10.20.{i + 1}", site_id=sample["site"].id, vendor="cisco",
                   platform="cisco_xe", connection_method="ssh", credential_id=sample["ssh"].id,
                   device_role="access_switch", ssh_host_key_type="ssh-ed25519", ssh_host_key_b64="AAAA")
        db.session.add(d)
        devices.append(d)
    db.session.commit()
    for d in devices:
        bs.enqueue_job(d)
    fake_driver.gate = threading.Event()
    fake_driver.outputs = [CISCO_RUNNING] * 4
    runner = bs.JobRunner(app, hard_limit=5)
    try:
        assert runner.poll() == 2
        assert runner.poll() == 0  # at capacity
        assert BackupJob.query.filter_by(status="running").count() == 2
        fake_driver.gate.set()
        deadline = time.time() + 10
        while runner.in_flight and time.time() < deadline:
            time.sleep(0.05)
        assert runner.poll() == 2
    finally:
        fake_driver.gate.set()
        runner.executor.shutdown(wait=True)
    db.session.expire_all()
    assert BackupJob.query.filter_by(status="success").count() == 4


def test_watchdog_fails_hung_jobs(app, sample):
    job, _ = bs.enqueue_job(sample["cisco"])
    bs.claim_job(job.id)
    job.started_at = utcnow() - timedelta(hours=2)
    db.session.commit()
    runner = bs.JobRunner(app, hard_limit=1)
    try:
        assert runner.watchdog() == 1
    finally:
        runner.shutdown()
    db.session.refresh(job)
    assert job.status == "failed" and "timeout" in job.message


def test_restart_marks_running_jobs_interrupted(app, sample):
    job, _ = bs.enqueue_job(sample["cisco"])
    bs.claim_job(job.id)
    queued, _ = bs.enqueue_job(sample["forti"])
    assert bs.mark_interrupted_jobs() == 1
    db.session.refresh(job)
    db.session.refresh(queued)
    assert job.status == "interrupted" and queued.status == "queued"
    # device is free again for new jobs
    assert bs.enqueue_job(sample["cisco"])[0] is not None
