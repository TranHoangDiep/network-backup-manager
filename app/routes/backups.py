"""Backup history, job status, secure download, config view and diff."""
import re

from flask import Blueprint, Response, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..extensions import db
from ..models import BackupJob, BackupVersion, Device
from ..security import audit, has_permission, permission_required
from ..services.credential_service import CryptoError
from ..services.diff_service import build_diff, mask_sensitive, normalize
from ..services.storage_service import StorageError, get_storage

bp = Blueprint("backups", __name__)

PER_PAGE = 50


@bp.route("/backups")
@login_required
@permission_required("history.view")
def history():
    query = BackupVersion.query.join(Device)
    device_id = request.args.get("device_id", type=int)
    if device_id:
        query = query.filter(BackupVersion.device_id == device_id)
    status = request.args.get("status")
    if status in ("success", "failed", "skipped"):
        query = query.filter(BackupVersion.status == status)
    if request.args.get("changed") == "1":
        query = query.filter(BackupVersion.changed.is_(True))
    config_type = request.args.get("config_type")
    if config_type in ("running", "startup"):
        query = query.filter(BackupVersion.config_type == config_type)
    page = query.order_by(BackupVersion.created_at.desc(), BackupVersion.id.desc()).paginate(
        page=request.args.get("page", 1, type=int), per_page=PER_PAGE, error_out=False)
    device = db.session.get(Device, device_id) if device_id else None
    return render_template("backup_history.html", page=page, device=device, filters=request.args,
                           devices=Device.query.order_by(Device.name).all())


@bp.route("/jobs")
@login_required
@permission_required("history.view")
def jobs():
    query = BackupJob.query
    status = request.args.get("status")
    if status:
        query = query.filter(BackupJob.status == status)
    page = query.order_by(BackupJob.created_at.desc()).paginate(
        page=request.args.get("page", 1, type=int), per_page=PER_PAGE, error_out=False)
    return render_template("jobs.html", page=page, filters=request.args)


@bp.route("/jobs/<int:job_id>.json")
@login_required
@permission_required("history.view")
def job_status(job_id):
    job = db.session.get(BackupJob, job_id)
    if job is None:
        abort(404)
    return jsonify(id=job.id, status=job.status, job_type=job.job_type, attempt=job.attempt,
                   max_attempts=job.max_attempts, message=job.message or "",
                   active=job.is_active, device_id=job.device_id)


def _version_or_404(version_id: int) -> BackupVersion:
    version = db.session.get(BackupVersion, version_id)
    if version is None or version.status != "success" or not version.file_path:
        abort(404)
    return version


def _read(version: BackupVersion) -> str:
    try:
        return get_storage().read_text(version.file_path)
    except (StorageError, CryptoError) as exc:
        abort(Response(f"Backup file unavailable: {exc}", status=410))


@bp.route("/backups/<int:version_id>/download")
@login_required
@permission_required("backup.download")
def download(version_id):
    version = _version_or_404(version_id)
    try:
        data = get_storage().read(version.file_path)
    except (StorageError, CryptoError) as exc:
        abort(Response(f"Backup file unavailable: {exc}", status=410))
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", version.device.name)[:64] or f"device{version.device_id}"
    filename = f"{safe_name}_{version.config_type}_{version.created_at:%Y%m%d_%H%M%S}.cfg"
    audit("backup.download", "backup_version", version.id,
          {"device": version.device.name, "config_type": version.config_type})
    return Response(data, mimetype="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    })


@bp.route("/backups/<int:version_id>/view")
@login_required
@permission_required("config.view")
def view(version_id):
    version = _version_or_404(version_id)
    raw_allowed = has_permission(current_user, "config.view_raw")
    content = _read(version)
    masked = not (raw_allowed and request.args.get("raw") == "1")
    if masked:
        content = mask_sensitive(content)
    audit("backup.view", "backup_version", version.id, {"masked": masked})
    return render_template("config_view.html", version=version, lines=content.splitlines(),
                           masked=masked, raw_allowed=raw_allowed)


@bp.route("/backups/diff")
@login_required
@permission_required("config.view")
def diff():
    a_id, b_id = request.args.get("a", type=int), request.args.get("b", type=int)
    device_id = request.args.get("device_id", type=int)
    if not (a_id and b_id):
        device = db.session.get(Device, device_id) if device_id else None
        if device is None:
            flash("Choose a device and two backup versions to compare.", "info")
            return redirect(url_for("backups.history"))
        versions = (device.versions.filter_by(status="success").order_by(BackupVersion.created_at.desc())
                    .limit(200).all())
        return render_template("config_diff.html", device=device, versions=versions, result=None)

    old, new = _version_or_404(a_id), _version_or_404(b_id)
    if old.device_id != new.device_id:
        abort(400)
    if old.created_at > new.created_at:
        old, new = new, old
    old_text, new_text = _read(old), _read(new)
    normalized = request.args.get("normalize") == "1"
    if normalized:
        old_text, new_text = normalize(old_text, old.device.platform), normalize(new_text, new.device.platform)
    raw_allowed = has_permission(current_user, "config.view_raw")
    masked = not (raw_allowed and request.args.get("raw") == "1")
    if masked:
        old_text, new_text = mask_sensitive(old_text), mask_sensitive(new_text)
    result = build_diff(old_text, new_text, context=3, full=request.args.get("full") == "1")
    audit("backup.diff", "device", old.device_id, {"a": old.id, "b": new.id, "masked": masked})
    versions = (old.device.versions.filter_by(status="success").order_by(BackupVersion.created_at.desc())
                .limit(200).all())
    return render_template("config_diff.html", device=old.device, versions=versions, result=result,
                           old=old, new=new, masked=masked, raw_allowed=raw_allowed, normalized=normalized)
