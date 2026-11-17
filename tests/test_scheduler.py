from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from app.extensions import db
from app.models import BackupJob, BackupPolicy
from app.services.backup_service import claim_job, enqueue_job
from app.services.scheduler_service import SchedulerAlreadyRunning, SchedulerService, build_trigger, validate_cron


def policy(**kwargs):
    defaults = {"name": "p", "schedule_type": "daily", "hour": 2, "minute": 0, "day_of_week": "sun",
                "timezone": "Asia/Ho_Chi_Minh"}
    defaults.update(kwargs)
    return BackupPolicy(**defaults)


def next_fire(trigger, now):
    return trigger.get_next_fire_time(None, now)


def test_daily_trigger_is_timezone_aware():
    tz = ZoneInfo("Asia/Ho_Chi_Minh")
    fire = next_fire(build_trigger(policy()), datetime(2026, 11, 15, 1, 0, tzinfo=tz))
    assert (fire.hour, fire.minute) == (2, 0) and fire.utcoffset().total_seconds() == 7 * 3600


@pytest.mark.parametrize("kind,expected_hours", [("6h", {0, 6, 12, 18}), ("12h", {0, 12})])
def test_interval_triggers(kind, expected_hours):
    trigger = build_trigger(policy(schedule_type=kind, minute=15))
    now = datetime(2026, 11, 15, 0, 0, tzinfo=ZoneInfo("Asia/Ho_Chi_Minh"))
    hours = set()
    for _ in range(8):
        now = next_fire(trigger, now)
        hours.add(now.hour)
        assert now.minute == 15
        now = now.replace(minute=16)
    assert hours == expected_hours


def test_weekly_and_cron_triggers():
    tz = ZoneInfo("UTC")
    weekly = next_fire(build_trigger(policy(schedule_type="weekly", day_of_week="sun", hour=3, timezone="UTC")),
                       datetime(2026, 11, 16, tzinfo=tz))
    assert weekly.weekday() == 6 and weekly.hour == 3
    cron = next_fire(build_trigger(policy(schedule_type="cron", cron_expression="30 1 * * 1-5", timezone="UTC")),
                     datetime(2026, 11, 14, tzinfo=tz))  # Saturday -> Monday
    assert cron.weekday() == 0 and (cron.hour, cron.minute) == (1, 30)
    with pytest.raises(ValueError):
        validate_cron("not a cron")
    sunday = next_fire(build_trigger(policy(schedule_type="cron", cron_expression="0 4 * * 0", timezone="UTC")),
                       datetime(2026, 11, 16, tzinfo=tz))
    assert sunday.weekday() == 6  # standard cron: 0 = Sunday
    also_sunday = next_fire(build_trigger(policy(schedule_type="cron", cron_expression="0 4 * * 7", timezone="UTC")),
                            datetime(2026, 11, 16, tzinfo=tz))
    assert also_sunday == sunday


def test_single_scheduler_instance(app):
    first, second = SchedulerService(app), SchedulerService(app)
    first.acquire_lock()
    try:
        with pytest.raises(SchedulerAlreadyRunning):
            second.acquire_lock()
    finally:
        first.release_lock()
    second.acquire_lock()
    second.release_lock()


def test_start_marks_interrupted_and_loads_policies(app, sample):
    job, _ = enqueue_job(sample["cisco"])
    claim_job(job.id)
    service = SchedulerService(app)
    service.start()
    try:
        db.session.refresh(job)
        assert job.status == "interrupted"
        policy_ids = {j.id for j in service.scheduler.get_jobs() if j.id.startswith("policy-")}
        assert policy_ids == {f"policy-{p.id}" for p in BackupPolicy.query.filter_by(enabled=True)}
        # Disabling a policy removes its schedule on the next sync
        p = BackupPolicy.query.first()
        p.enabled = False
        db.session.commit()
        service.sync_policies()
        assert service.scheduler.get_job(f"policy-{p.id}") is None
        assert service.heartbeat_path.exists()
    finally:
        service.shutdown()


def test_policy_run_enqueues_only_enabled_devices(app, sample):
    from app.services.backup_service import enqueue_policy_backups
    p = BackupPolicy.query.first()
    sample["cisco"].policy_id = p.id
    sample["forti"].policy_id = p.id
    sample["forti"].enabled = False
    db.session.commit()
    assert enqueue_policy_backups(p.id) == 1
    assert enqueue_policy_backups(p.id) == 0  # already queued: no duplicate
    job = BackupJob.query.one()
    assert job.trigger == "scheduled" and job.device_id == sample["cisco"].id
