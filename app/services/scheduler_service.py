"""APScheduler orchestration for the dedicated scheduler/worker process.

* A non-blocking exclusive file lock (fcntl) guarantees a single scheduler
  instance; a second process exits immediately.
* Backup policies in SQLite are the source of truth. They are re-synced every
  minute, so schedules survive restarts and UI edits apply without restart.
* Cron triggers (also for 6h/12h) keep run times aligned after restarts.
"""
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path

from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_MISSED
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from zoneinfo import ZoneInfo

from ..models import BackupPolicy, utcnow
from ..security import audit
from .backup_service import JobRunner, enqueue_policy_backups, find_stale_devices, mark_interrupted_jobs
from .notification_service import notify
from .retention_service import run_retention
from .settings_service import get_setting, get_state, set_state

log = logging.getLogger(__name__)

WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


class SchedulerAlreadyRunning(RuntimeError):
    pass


_CRON_DOW_NAMES = ("sun", "mon", "tue", "wed", "thu", "fri", "sat", "sun")


def _convert_cron_dow(field: str) -> str:
    """Convert a standard crontab weekday field (0/7=Sunday) to APScheduler names.

    APScheduler 3 CronTrigger.from_crontab() treats 0 as Monday, which would
    silently shift user schedules by one day; names are unambiguous.
    """
    if field == "*":
        return "*"
    days = []
    for part in field.split(","):
        part = part.strip().lower()
        step = 1
        if "/" in part:
            part, step_text = part.split("/", 1)
            step = int(step_text)
            if step < 1:
                raise ValueError("Invalid weekday step")
        if part in ("*", ""):
            start, end = 0, 6
        elif "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = _dow_number(start_text), _dow_number(end_text)
        else:
            start = end = _dow_number(part)
        if start > end:
            raise ValueError("Weekday range start must not exceed end")
        for number in range(start, end + 1, step):
            name = _CRON_DOW_NAMES[number]
            if name not in days:
                days.append(name)
    return ",".join(days)


def _dow_number(token: str) -> int:
    if token.isdigit() and 0 <= int(token) <= 7:
        return int(token)
    if token[:3] in _CRON_DOW_NAMES:
        return _CRON_DOW_NAMES.index(token[:3])
    raise ValueError(f"Invalid weekday '{token}'")


def cron_trigger(expression: str, tz) -> CronTrigger:
    fields = (expression or "").split()
    if len(fields) != 5:
        raise ValueError("Cron expression must have 5 fields: minute hour day month weekday")
    minute, hour, day, month, dow = fields
    return CronTrigger(minute=minute, hour=hour, day=day, month=month,
                       day_of_week=_convert_cron_dow(dow), timezone=tz)


def build_trigger(policy) -> CronTrigger:
    tz = ZoneInfo(policy.timezone or "UTC")
    kind = policy.schedule_type
    if kind == "6h":
        return CronTrigger(hour="*/6", minute=policy.minute, timezone=tz)
    if kind == "12h":
        return CronTrigger(hour="*/12", minute=policy.minute, timezone=tz)
    if kind == "daily":
        return CronTrigger(hour=policy.hour, minute=policy.minute, timezone=tz)
    if kind == "weekly":
        return CronTrigger(day_of_week=policy.day_of_week, hour=policy.hour, minute=policy.minute, timezone=tz)
    if kind == "cron":
        return cron_trigger(policy.cron_expression, tz)
    raise ValueError(f"Unknown schedule type {kind!r}")


def validate_cron(expression: str, timezone: str = "UTC") -> None:
    cron_trigger(expression, ZoneInfo(timezone))


class SchedulerService:
    def __init__(self, app):
        self.app = app
        self.lock_path = Path(app.config["SCHEDULER_LOCK_FILE"])
        self.heartbeat_path = Path(app.config["SCHEDULER_HEARTBEAT_FILE"])
        self._lock_fd = None
        self._policy_signatures = {}
        self.runner = None
        self.scheduler = None

    # -------------------------------------------------------------- lock ---
    def acquire_lock(self) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise SchedulerAlreadyRunning(f"Another scheduler holds {self.lock_path}") from None
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode())
        self._lock_fd = fd

    def release_lock(self) -> None:
        if self._lock_fd is not None:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            self._lock_fd = None

    # ------------------------------------------------------------ lifecycle ---
    def start(self) -> None:
        self.acquire_lock()
        with self.app.app_context():
            mark_interrupted_jobs()
        self.runner = JobRunner(self.app)
        tz = ZoneInfo(self.app.config["APP_TIMEZONE"])
        self.scheduler = BackgroundScheduler(timezone=tz, job_defaults={
            "coalesce": True, "max_instances": 1, "misfire_grace_time": 900})
        self.scheduler.add_listener(self._on_job_event, EVENT_JOB_ERROR | EVENT_JOB_MISSED)
        poll = self.app.config["JOB_POLL_SECONDS"]
        self.scheduler.add_job(self.runner.poll, "interval", seconds=poll, id="poll-jobs")
        self.scheduler.add_job(self.runner.watchdog, "interval", seconds=60, id="watchdog")
        self.scheduler.add_job(self.sync_policies, "interval", seconds=60, id="sync-policies")
        self.scheduler.add_job(self._heartbeat, "interval", seconds=30, id="heartbeat")
        self.scheduler.add_job(self._retention, CronTrigger(hour=3, minute=30, timezone=tz), id="retention")
        self.scheduler.add_job(self._stale_check, "interval", hours=1, id="stale-check")
        self.scheduler.start()
        self._heartbeat()
        self.sync_policies()
        log.info("Scheduler started (pid %s)", os.getpid())

    def shutdown(self) -> None:
        if self.scheduler:
            self.scheduler.shutdown(wait=False)
        if self.runner:
            self.runner.shutdown()
        self.release_lock()
        log.info("Scheduler stopped")

    # ------------------------------------------------------------- jobs ---
    @staticmethod
    def _signature(policy) -> str:
        data = [policy.schedule_type, policy.hour, policy.minute, policy.day_of_week,
                policy.cron_expression, policy.timezone, policy.enabled]
        return hashlib.sha256(json.dumps(data, default=str).encode()).hexdigest()

    def sync_policies(self) -> None:
        with self.app.app_context():
            wanted = {}
            for policy in BackupPolicy.query.all():
                if policy.enabled:
                    wanted[f"policy-{policy.id}"] = policy
            for job_id in list(self._policy_signatures):
                if job_id not in wanted:
                    self.scheduler.remove_job(job_id)
                    del self._policy_signatures[job_id]
                    log.info("Removed schedule %s", job_id)
            for job_id, policy in wanted.items():
                signature = self._signature(policy)
                if self._policy_signatures.get(job_id) == signature:
                    continue
                try:
                    trigger = build_trigger(policy)
                except Exception as exc:
                    log.error("Invalid schedule for policy %s: %s", policy.name, exc)
                    continue
                self.scheduler.add_job(self._run_policy, trigger, args=[policy.id], id=job_id,
                                       replace_existing=True, name=policy.name)
                self._policy_signatures[job_id] = signature
                log.info("Scheduled policy '%s': %s, next run %s", policy.name, policy.describe(),
                         getattr(self.scheduler.get_job(job_id), "next_run_time", None))

    def _run_policy(self, policy_id: int) -> None:
        with self.app.app_context():
            enqueue_policy_backups(policy_id)

    def _retention(self) -> None:
        with self.app.app_context():
            stats = run_retention()
            audit("retention.run", details=stats)

    def _stale_check(self) -> None:
        with self.app.app_context():
            stale = find_stale_devices()
            if not stale:
                return
            last = get_state("last_stale_notification_at")
            now = utcnow()
            if last and (now - _parse_dt(last)).total_seconds() < 86400:
                return
            hours = get_setting("stale_backup_hours")
            body = "\n".join(f"- {d.name} ({d.mgmt_ip}) last success: {d.last_success_at or 'never'}"
                             for d in stale)
            notify("stale_backup", f"{len(stale)} device(s) without a successful backup in {hours}h",
                   body, {"devices": [d.name for d in stale]})
            set_state("last_stale_notification_at", now.isoformat())

    def _heartbeat(self) -> None:
        now = utcnow()
        self.heartbeat_path.write_text(now.isoformat())
        with self.app.app_context():
            set_state("scheduler_heartbeat", now.isoformat())

    def _on_job_event(self, event) -> None:
        kind = "error" if event.code == EVENT_JOB_ERROR else "missed"
        log.error("Scheduler job %s %s: %s", event.job_id, kind, getattr(event, "exception", ""))
        try:
            with self.app.app_context():
                audit(f"scheduler.{kind}", "scheduler_job", event.job_id,
                      {"error": str(getattr(event, "exception", "") or "")[:500]})
        except Exception:
            log.exception("Failed to record scheduler event")


def _parse_dt(value: str):
    from datetime import datetime
    return datetime.fromisoformat(value)
