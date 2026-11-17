"""Dashboard and health endpoint."""
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, render_template
from flask_login import login_required
from sqlalchemy import func, text

from ..extensions import db
from ..models import BackupJob, BackupVersion, Device, utcnow
from ..security import permission_required
from ..services.backup_service import find_stale_devices
from ..services.settings_service import get_setting, get_state

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
@permission_required("dashboard.view")
def index():
    now = utcnow()
    since = now - timedelta(hours=24)
    enabled = Device.query.filter_by(enabled=True)
    job_counts = dict(db.session.query(BackupJob.status, func.count(BackupJob.id))
                      .filter(BackupJob.job_type == "backup", BackupJob.created_at >= since)
                      .group_by(BackupJob.status).all())
    heartbeat = get_state("scheduler_heartbeat")
    heartbeat_age = None
    if heartbeat:
        heartbeat_age = int((now - datetime.fromisoformat(heartbeat)).total_seconds())
    stats = {
        "total": Device.query.count(),
        "enabled": enabled.count(),
        "online": enabled.filter(Device.reachable.is_(True)).count(),
        "offline": enabled.filter(Device.reachable.is_(False)).count(),
        "unknown": enabled.filter(Device.reachable.is_(None)).count(),
        "success_24h": job_counts.get("success", 0) + job_counts.get("partial", 0),
        "failed_24h": job_counts.get("failed", 0),
        "active_jobs": BackupJob.query.filter(BackupJob.status.in_(("queued", "running"))).count(),
        "last_backup": db.session.query(func.max(BackupVersion.created_at))
                                 .filter(BackupVersion.status == "success").scalar(),
        "stale_hours": get_setting("stale_backup_hours"),
        "heartbeat_age": heartbeat_age,
    }
    recent_changes = (BackupVersion.query.filter_by(status="success", changed=True)
                      .order_by(BackupVersion.created_at.desc()).limit(10).all())
    recent_jobs = BackupJob.query.order_by(BackupJob.created_at.desc()).limit(15).all()
    return render_template("dashboard.html", stats=stats, stale=find_stale_devices(now)[:20],
                           recent_changes=recent_changes, recent_jobs=recent_jobs)


@bp.route("/healthz")
def healthz():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify(status="ok")
    except Exception:
        return jsonify(status="error"), 503
