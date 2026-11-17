"""Backup job queue and execution engine.

Flow: the web process only *enqueues* BackupJob rows (status=queued). The
single scheduler/worker process claims queued jobs atomically, runs them in a
bounded ThreadPoolExecutor and records results. Overlap protection:
  * partial unique index: at most one queued/running job per device (DB level)
  * atomic claim: UPDATE ... WHERE status='queued' (no double execution)
  * the worker caps in-flight jobs at the configured max concurrency
"""
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from flask import current_app
from sqlalchemy import or_, update
from sqlalchemy.exc import IntegrityError

from ..drivers import get_driver_class
from ..drivers.base import (AuthenticationError, ConnectionFailedError, ConnectionTarget,
                            ConnectionTimeoutError, DriverError, DriverOptions, HostKeyError,
                            IncompleteConfigError, PermissionDeniedError)
from ..extensions import db
from ..logging_setup import register_secrets, unregister_secrets
from ..models import JOB_ACTIVE_STATUSES, BackupJob, BackupVersion, Device, utcnow
from ..validators import ValidationError, check_destination_allowed, destination_policy
from .credential_service import CryptoError, load_credential
from .diff_service import diff_stats, normalize, normalized_hash, sha256_bytes
from .notification_service import notify
from .settings_service import get_setting
from .storage_service import get_storage, storage_lock

log = logging.getLogger(__name__)

MAX_BACKOFF_SECONDS = 3600


# ------------------------------------------------------------- helpers ---
def driver_options() -> DriverOptions:
    return DriverOptions(
        conn_timeout=get_setting("ssh_conn_timeout"),
        read_timeout=get_setting("ssh_read_timeout"),
        api_timeout=get_setting("api_timeout"),
        strict_host_key=bool(current_app.config["SSH_STRICT_HOST_KEY"]),
        tmp_dir=str(current_app.config["TMP_DIR"]),
    )


def build_target(device: Device) -> ConnectionTarget:
    return ConnectionTarget(
        name=device.name,
        host=device.mgmt_ip,
        port=device.effective_port(),
        platform=device.platform,
        vdom=device.vdom or "",
        host_key_type=device.ssh_host_key_type or "",
        host_key_b64=device.ssh_host_key_b64 or "",
    )


def validate_device_destination(device: Device) -> None:
    networks, ports = destination_policy(current_app.config)
    subnet = device.site.mgmt_subnet if device.site else None
    check_destination_allowed(device.mgmt_ip, device.effective_port(), subnet, networks, ports)


def config_types_for(device: Device, driver_cls) -> list:
    supported = list(driver_cls.config_types)
    if device.policy:
        wanted = [t for t in device.policy.config_type_list if t in supported]
        if driver_cls.config_types[0] not in wanted:
            wanted.insert(0, driver_cls.config_types[0])
        return wanted
    return supported


def latest_successful_version(device_id: int, config_type: str):
    return (BackupVersion.query
            .filter_by(device_id=device_id, config_type=config_type, status="success")
            .filter(BackupVersion.file_path.isnot(None))
            .order_by(BackupVersion.created_at.desc(), BackupVersion.id.desc())
            .first())


def active_job_for(device_id: int):
    return BackupJob.query.filter(BackupJob.device_id == device_id,
                                  BackupJob.status.in_(JOB_ACTIVE_STATUSES)).first()


# ------------------------------------------------------------- enqueue ---
def enqueue_job(device: Device, job_type: str = "backup", trigger: str = "manual", user=None):
    """Create a queued job. Returns (job, None) or (None, reason)."""
    if job_type not in ("backup", "test"):
        raise ValueError(job_type)
    if trigger == "scheduled" and (not device.enabled or (device.site and device.site.status != "active")):
        return None, "Device or site is disabled"
    existing = active_job_for(device.id)
    if existing:
        return None, f"Job #{existing.id} is already {existing.status} for {device.name}"
    job = BackupJob(device_id=device.id, job_type=job_type, trigger=trigger,
                    requested_by_id=getattr(user, "id", None),
                    max_attempts=get_setting("retry_max_attempts") if job_type == "backup" else 1)
    db.session.add(job)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return None, f"Another job is already queued or running for {device.name}"
    log.info("Queued %s job #%d for %s (%s)", job_type, job.id, device.name, trigger)
    return job, None


def claim_job(job_id: int) -> bool:
    """Atomically move a queued job to running. Returns False if someone else got it."""
    result = db.session.execute(
        update(BackupJob)
        .where(BackupJob.id == job_id, BackupJob.status == "queued")
        .values(status="running", started_at=utcnow(), finished_at=None, attempt=BackupJob.attempt + 1)
    )
    db.session.commit()
    return result.rowcount == 1


def mark_interrupted_jobs() -> int:
    """Called at worker start: jobs left 'running' by a crash/restart are interrupted."""
    now = utcnow()
    jobs = BackupJob.query.filter_by(status="running").all()
    for job in jobs:
        job.status = "interrupted"
        job.finished_at = now
        job.message = (job.message + "\n" if job.message else "") + "Interrupted by worker restart"
        if job.device and job.job_type == "backup":
            job.device.last_backup_status = "interrupted"
    db.session.commit()
    if jobs:
        log.warning("Marked %d running job(s) as interrupted after restart", len(jobs))
    return len(jobs)


# ------------------------------------------------------------- execute ---
def _still_running(job: BackupJob) -> bool:
    db.session.refresh(job)
    return job.status == "running"


def execute_job(job_id: int) -> None:
    """Run one claimed job (status must already be 'running')."""
    job = db.session.get(BackupJob, job_id)
    if job is None or job.status != "running":
        return
    device = job.device
    secrets = []
    try:
        if not device.enabled and job.trigger == "scheduled":
            raise DriverError("Device is disabled")
        validate_device_destination(device)
        if device.credential is None:
            raise DriverError("No credential profile assigned to the device")
        if device.credential.cred_type != device.connection_method:
            raise DriverError("Credential profile type does not match the connection method")
        driver_cls = get_driver_class(device.platform, device.connection_method)
        credential = load_credential(device.credential)
        secrets = credential.secret_values()
        register_secrets(secrets)
        driver = driver_cls(build_target(device), credential, driver_options())
        if job.job_type == "test":
            _run_test(job, device, driver)
        else:
            _run_backup(job, device, driver, config_types_for(device, driver_cls))
    except ValidationError as exc:
        db.session.rollback()
        _finish_failed(job, device, f"Destination not allowed: {exc}", connection_error=False)
    except CryptoError as exc:
        db.session.rollback()
        _finish_failed(job, device, str(exc), connection_error=False)
    except DriverError as exc:
        db.session.rollback()
        _handle_driver_error(job, device, exc)
    except Exception as exc:
        db.session.rollback()
        log.exception("Unexpected error in job #%s", job_id)
        _finish_failed(job, device, f"Internal error ({type(exc).__name__}); see worker log",
                       connection_error=False)
    finally:
        unregister_secrets(secrets)


def _run_test(job: BackupJob, device: Device, driver) -> None:
    result = driver.test_connection()
    if not _still_running(job):
        return
    now = utcnow()
    pending = result.details.get("host_key_pending")
    if pending:
        device.pending_host_key_type = pending["type"]
        device.pending_host_key_b64 = pending["b64"]
    device.reachable = True
    device.last_seen_at = now
    job.status = "success" if result.ok else "failed"
    job.message = result.message
    job.result_json = json.dumps(result.details, default=str)
    job.finished_at = now
    db.session.commit()
    log.info("Test job #%d for %s: %s", job.id, device.name, job.status)


def _run_backup(job: BackupJob, device: Device, driver, config_types: list) -> None:
    results = driver.fetch_configs(config_types)
    if not _still_running(job):
        log.warning("Job #%d finished after being marked %s; discarding result", job.id, job.status)
        return
    now = utcnow()
    storage = get_storage()
    summary, changes, failures = [], [], []
    with storage_lock:
        for result in results:
            version = BackupVersion(device_id=device.id, job_id=job.id, config_type=result.config_type,
                                    backup_method=device.connection_method, created_at=now)
            if result.status != "success":
                version.status = result.status
                version.error_message = result.message
                summary.append(f"{result.config_type}: {result.status} ({result.message})")
                if result.status == "failed":
                    failures.append(result.config_type)
                db.session.add(version)
                continue

            raw = result.content.encode("utf-8", errors="surrogateescape")
            norm_hash = normalized_hash(result.content, device.platform)
            previous = latest_successful_version(device.id, result.config_type)
            version.status = "success"
            version.normalized_hash = norm_hash
            if previous and previous.normalized_hash == norm_hash and storage.exists(previous.file_path):
                version.changed = False
                version.file_path = previous.file_path
                version.file_size = previous.file_size
                version.config_hash = previous.config_hash
                version.change_summary = "unchanged"
            else:
                path = storage.new_relative_path(device.site_id, device.id, result.config_type, now)
                version.file_size = storage.write(path, raw)
                version.file_path = path
                version.config_hash = sha256_bytes(raw)
                version.changed = True
                if previous:
                    try:
                        old_text = storage.read_text(previous.file_path)
                        added, removed = diff_stats(normalize(old_text, device.platform),
                                                    normalize(result.content, device.platform))
                        version.change_summary = f"+{added} / -{removed} lines"
                    except Exception as exc:  # stats are informational only
                        log.warning("Diff stats failed for %s: %s", device.name, exc)
                        version.change_summary = "changed"
                    changes.append((result.config_type, version.change_summary))
                else:
                    version.change_summary = "initial backup"
            summary.append(f"{result.config_type}: {version.change_summary}"
                           + (f" [{result.message}]" if result.message else ""))
            db.session.add(version)

        job.status = "partial" if failures else "success"
        job.message = "; ".join(summary)
        job.finished_at = now
        device.last_backup_at = now
        device.last_backup_status = job.status
        device.last_success_at = now
        device.reachable = True
        device.last_seen_at = now
        device.last_error = None if not failures else job.message
        db.session.commit()

    log.info("Backup job #%d for %s: %s (%s)", job.id, device.name, job.status, job.message)
    for config_type, change in changes:
        notify("config_changed", f"Configuration change on {device.name}",
               f"Device: {device.name} ({device.mgmt_ip})\nSite: {device.site.name}\n"
               f"Config: {config_type}\nChange: {change}\nTime (UTC): {now:%Y-%m-%d %H:%M:%S}",
               {"device": device.name, "config_type": config_type, "change": change})


def _handle_driver_error(job: BackupJob, device: Device, exc: DriverError) -> None:
    if not _still_running(job):
        return
    connection_error = isinstance(exc, (ConnectionTimeoutError, ConnectionFailedError))
    if job.job_type == "backup" and exc.retryable and job.attempt < job.max_attempts:
        delay = min(get_setting("retry_backoff_seconds") * (2 ** (job.attempt - 1)), MAX_BACKOFF_SECONDS)
        job.status = "queued"
        job.next_attempt_at = utcnow() + timedelta(seconds=delay)
        job.message = f"Attempt {job.attempt}/{job.max_attempts} failed: {exc}. Retrying in {delay}s."
        if connection_error:
            device.reachable = False
        db.session.commit()
        log.warning("Job #%d for %s: %s", job.id, device.name, job.message)
        return
    if isinstance(exc, (AuthenticationError, PermissionDeniedError, IncompleteConfigError, HostKeyError)):
        device.reachable = True
    _finish_failed(job, device, str(exc), connection_error=connection_error)


def _finish_failed(job: BackupJob, device: Device, message: str, connection_error: bool) -> None:
    if not _still_running(job):
        return
    now = utcnow()
    was_reachable = device.reachable
    job.status = "failed"
    job.message = message
    job.finished_at = now
    if connection_error:
        device.reachable = False
    if job.job_type == "backup":
        device.last_backup_at = now
        device.last_backup_status = "failed"
        device.last_error = message
        db.session.add(BackupVersion(device_id=device.id, job_id=job.id, config_type="running",
                                     backup_method=device.connection_method, status="failed",
                                     created_at=now, error_message=message))
    db.session.commit()
    log.error("Job #%d (%s) for %s failed: %s", job.id, job.job_type, device.name, message)

    if job.job_type != "backup":
        return
    notify("backup_failed", f"Backup failed: {device.name}",
           f"Device: {device.name} ({device.mgmt_ip})\nSite: {device.site.name}\n"
           f"Attempts: {job.attempt}/{job.max_attempts}\nError: {message}",
           {"device": device.name, "error": message, "job_id": job.id})
    if connection_error and was_reachable is not False:
        notify("unreachable", f"Device unreachable: {device.name}",
               f"Device: {device.name} ({device.mgmt_ip})\nSite: {device.site.name}\nError: {message}",
               {"device": device.name, "error": message})


# ------------------------------------------------------- policy helpers ---
def enqueue_policy_backups(policy_id: int) -> int:
    devices = (Device.query.filter_by(policy_id=policy_id, enabled=True).all())
    count = 0
    for device in devices:
        job, reason = enqueue_job(device, "backup", "scheduled")
        if job:
            count += 1
        else:
            log.info("Skipped scheduled backup for %s: %s", device.name, reason)
    log.info("Policy %s: queued %d backup job(s)", policy_id, count)
    return count


def find_stale_devices(now=None) -> list:
    now = now or utcnow()
    cutoff = now - timedelta(hours=get_setting("stale_backup_hours"))
    return (Device.query.filter(Device.enabled.is_(True))
            .filter(or_(Device.last_success_at.is_(None), Device.last_success_at < cutoff))
            .order_by(Device.name).all())


# ------------------------------------------------------------- runner ---
class JobRunner:
    """Executes queued jobs inside the scheduler/worker process."""

    def __init__(self, app, hard_limit: int = None):
        self.app = app
        self.hard_limit = hard_limit or app.config["MAX_CONCURRENCY_HARD_LIMIT"]
        self.executor = ThreadPoolExecutor(max_workers=self.hard_limit, thread_name_prefix="backup")
        self._lock = threading.Lock()
        self._in_flight = set()

    @property
    def in_flight(self) -> int:
        with self._lock:
            return len(self._in_flight)

    def poll(self) -> int:
        with self.app.app_context():
            limit = min(get_setting("max_concurrency"), self.hard_limit)
            capacity = limit - self.in_flight
            if capacity <= 0:
                return 0
            now = utcnow()
            candidates = (BackupJob.query.filter(BackupJob.status == "queued")
                          .filter(or_(BackupJob.next_attempt_at.is_(None), BackupJob.next_attempt_at <= now))
                          .order_by(BackupJob.created_at, BackupJob.id).limit(capacity).all())
            started = 0
            for job in candidates:
                if claim_job(job.id):
                    with self._lock:
                        self._in_flight.add(job.id)
                    self.executor.submit(self._run, job.id)
                    started += 1
            return started

    def _run(self, job_id: int) -> None:
        try:
            with self.app.app_context():
                execute_job(job_id)
        except Exception:
            log.exception("Job runner crashed on job #%s", job_id)
        finally:
            with self._lock:
                self._in_flight.discard(job_id)

    def watchdog(self) -> int:
        """Fail jobs that exceeded the hard timeout (driver timeouts normally fire first)."""
        with self.app.app_context():
            cutoff = utcnow() - timedelta(seconds=get_setting("job_timeout_seconds"))
            stale = BackupJob.query.filter(BackupJob.status == "running", BackupJob.started_at < cutoff).all()
            for job in stale:
                job.status = "failed"
                job.finished_at = utcnow()
                job.message = "Job exceeded the hard timeout and was abandoned by the watchdog"
                if job.job_type == "backup":
                    job.device.last_backup_status = "failed"
                    job.device.last_error = job.message
                log.error("Watchdog: job #%d for %s timed out", job.id, job.device.name)
            db.session.commit()
            return len(stale)

    def shutdown(self) -> None:
        self.executor.shutdown(wait=False, cancel_futures=True)
