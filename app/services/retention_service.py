"""Backup retention cleanup.

Rules:
* Retention days = policy.retention_days if set, else the per-role default.
* The newest successful version per device and config type is always kept.
* Devices with a queued/running job are skipped in this run.
* Metadata rows are deleted and committed first; a file is removed only when
  no remaining version references it (unchanged versions share files).
"""
import logging
from datetime import timedelta

from ..extensions import db
from ..models import BackupJob, BackupVersion, Device, JOB_ACTIVE_STATUSES, utcnow
from .settings_service import get_setting
from .storage_service import StorageError, get_storage, storage_lock

log = logging.getLogger(__name__)

JOB_HISTORY_DAYS = 400


def retention_days_for(device: Device) -> int:
    if device.policy and device.policy.retention_days:
        return device.policy.retention_days
    return get_setting(f"retention_{device.device_role}") if device.device_role else 180


def run_retention(now=None) -> dict:
    now = now or utcnow()
    stats = {"versions_deleted": 0, "files_deleted": 0, "devices_skipped": 0, "jobs_deleted": 0}
    storage = get_storage()
    with storage_lock:
        busy = {d for (d,) in db.session.query(BackupJob.device_id)
                .filter(BackupJob.status.in_(JOB_ACTIVE_STATUSES))}
        candidate_paths = set()
        for device in Device.query.all():
            if device.id in busy:
                stats["devices_skipped"] += 1
                continue
            cutoff = now - timedelta(days=retention_days_for(device))
            keep_ids = set()
            for (config_type,) in (db.session.query(BackupVersion.config_type)
                                   .filter_by(device_id=device.id).distinct()):
                latest = (BackupVersion.query
                          .filter_by(device_id=device.id, config_type=config_type, status="success")
                          .filter(BackupVersion.file_path.isnot(None))
                          .order_by(BackupVersion.created_at.desc(), BackupVersion.id.desc()).first())
                if latest:
                    keep_ids.add(latest.id)
            query = BackupVersion.query.filter(BackupVersion.device_id == device.id,
                                               BackupVersion.created_at < cutoff)
            if keep_ids:
                query = query.filter(BackupVersion.id.notin_(keep_ids))
            expired = query.all()
            for version in expired:
                if version.file_path:
                    candidate_paths.add(version.file_path)
                log.info("Retention: deleting version #%d of %s (%s, %s)", version.id, device.name,
                         version.config_type, version.created_at)
                db.session.delete(version)
                stats["versions_deleted"] += 1

        old_jobs = (BackupJob.query.filter(BackupJob.status.notin_(JOB_ACTIVE_STATUSES),
                                           BackupJob.created_at < now - timedelta(days=JOB_HISTORY_DAYS)))
        stats["jobs_deleted"] = old_jobs.delete(synchronize_session=False)
        db.session.commit()

        referenced = {p for (p,) in db.session.query(BackupVersion.file_path)
                      .filter(BackupVersion.file_path.in_(candidate_paths))} if candidate_paths else set()
        for path in candidate_paths - referenced:
            try:
                if storage.delete(path):
                    stats["files_deleted"] += 1
                    log.info("Retention: deleted file %s", path)
            except (StorageError, OSError) as exc:
                log.error("Retention: could not delete %s: %s", path, exc)
    log.info("Retention run finished: %s", stats)
    return stats
