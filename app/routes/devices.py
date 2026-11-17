"""Device inventory: CRUD, CSV import, test connection, manual backup, host keys."""
import csv
import io

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..drivers import PLATFORMS, VENDORS, is_compatible
from ..drivers.ssh_common import host_key_fingerprint
from ..extensions import db
from ..models import DEVICE_ROLES, BackupJob, BackupPolicy, BackupVersion, Credential, Device, Site
from ..security import audit, permission_required
from ..services.backup_service import active_job_for, enqueue_job
from ..services.storage_service import get_storage, storage_lock
from ..validators import (VDOM_RE, ValidationError, check_destination_allowed, clean_hostname, clean_name,
                          clean_text, destination_policy, parse_ip, parse_port)

bp = Blueprint("devices", __name__, url_prefix="/devices")

CSV_FIELDS = ["name", "hostname", "mgmt_ip", "site", "vendor", "platform", "connection_method", "port",
              "credential", "policy", "device_role", "vdom", "description", "enabled"]
MAX_CSV_ROWS = 1000


def clean_device(raw: dict, site, credential, policy, current_id=None) -> tuple:
    """Validate raw device fields. Returns (values, errors)."""
    errors, out = [], {}

    def take(key, func, *args):
        try:
            out[key] = func(*args)
        except ValidationError as exc:
            errors.append(str(exc))

    take("name", clean_name, raw.get("name"), "Device name")
    take("hostname", clean_hostname, raw.get("hostname"))
    take("mgmt_ip", parse_ip, raw.get("mgmt_ip"))
    take("port", parse_port, raw.get("port"))
    take("description", clean_text, raw.get("description"), "Description", 500)

    vendor = (raw.get("vendor") or "").strip().lower()
    platform = (raw.get("platform") or "").strip().lower()
    method = (raw.get("connection_method") or "").strip().lower()
    role = (raw.get("device_role") or "").strip().lower()
    vdom = (raw.get("vdom") or "").strip()
    if vendor not in VENDORS:
        errors.append("Unknown vendor")
    elif platform not in PLATFORMS:
        errors.append("Unknown platform")
    elif not is_compatible(vendor, platform, method):
        errors.append(f"No driver supports {vendor}/{platform} over '{method or '?'}'")
    if role not in DEVICE_ROLES:
        errors.append("Unknown device role")
    if vdom:
        if platform != "fortinet" or method != "api":
            errors.append("VDOM scope is only supported by the Fortinet REST API driver")
        elif not VDOM_RE.match(vdom):
            errors.append("Invalid VDOM name")
    if site is None:
        errors.append("Site is required")
    if credential is None:
        errors.append("Credential profile is required")
    elif credential.cred_type != method:
        errors.append(f"Credential profile '{credential.name}' is a {credential.cred_type.upper()} profile; "
                      f"it cannot be used with {method.upper() or '?'}")

    out.update(vendor=vendor, platform=platform, connection_method=method, device_role=role,
               vdom=vdom or None, site_id=getattr(site, "id", None),
               credential_id=getattr(credential, "id", None), policy_id=getattr(policy, "id", None))
    raw_enabled = raw.get("enabled", "")
    out["enabled"] = str(raw_enabled).strip().lower() in ("1", "true", "yes", "on", "y")

    if "name" in out:
        clash = Device.query.filter(Device.name == out["name"], Device.id != (current_id or 0)).first()
        if clash:
            errors.append(f"A device named '{out['name']}' already exists")

    if not errors:
        port = out["port"] or (credential.api_port if method == "api" else 22)
        networks, ports = destination_policy(current_app.config)
        try:
            check_destination_allowed(out["mgmt_ip"], port, site.mgmt_subnet, networks, ports)
        except ValidationError as exc:
            errors.append(str(exc))
    return out, errors


def _form_lookups(form) -> tuple:
    def get(model, key):
        value = form.get(key, "")
        return db.session.get(model, int(value)) if str(value).isdigit() else None
    return get(Site, "site_id"), get(Credential, "credential_id"), get(BackupPolicy, "policy_id")


def _apply(device: Device, values: dict) -> bool:
    """Set attributes; returns True if the network destination changed."""
    destination_changed = device.id is not None and (
        device.mgmt_ip != values["mgmt_ip"] or device.port != values["port"])
    for key, value in values.items():
        setattr(device, key, value)
    if destination_changed:
        # A trusted host key is bound to the old address; require re-verification.
        device.ssh_host_key_type = device.ssh_host_key_b64 = None
        device.pending_host_key_type = device.pending_host_key_b64 = None
    return destination_changed


def _form_context(device=None, form=None):
    return {
        "device": device,
        "form": form or {},
        "sites": Site.query.order_by(Site.name).all(),
        "credentials": Credential.query.order_by(Credential.name).all(),
        "policies": BackupPolicy.query.order_by(BackupPolicy.name).all(),
    }


def _get_device(device_id: int) -> Device:
    device = db.session.get(Device, device_id)
    if device is None:
        abort(404)
    return device


# ---------------------------------------------------------------- views ---
@bp.route("/")
@login_required
@permission_required("device.view")
def index():
    query = Device.query.join(Site)
    q = (request.args.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        query = query.filter(db.or_(Device.name.ilike(like), Device.mgmt_ip.ilike(like),
                                    Device.hostname.ilike(like)))
    site_id = request.args.get("site_id", type=int)
    if site_id:
        query = query.filter(Device.site_id == site_id)
    vendor = request.args.get("vendor")
    if vendor in VENDORS:
        query = query.filter(Device.vendor == vendor)
    status = request.args.get("status")
    if status == "failed":
        query = query.filter(Device.last_backup_status == "failed")
    elif status == "offline":
        query = query.filter(Device.reachable.is_(False))
    elif status == "disabled":
        query = query.filter(Device.enabled.is_(False))
    devices = query.order_by(Site.name, Device.name).all()
    active = {j.device_id: j for j in BackupJob.query.filter(BackupJob.status.in_(("queued", "running")))}
    return render_template("devices.html", devices=devices, active=active,
                           sites=Site.query.order_by(Site.name).all(), filters=request.args)


@bp.route("/new", methods=["GET", "POST"])
@login_required
@permission_required("device.manage")
def create():
    if request.method == "POST":
        site, credential, policy = _form_lookups(request.form)
        values, errors = clean_device(request.form, site, credential, policy)
        if not errors:
            device = Device()
            _apply(device, values)
            db.session.add(device)
            db.session.commit()
            audit("device.create", "device", device.id, {"name": device.name, "ip": device.mgmt_ip})
            flash(f"Device {device.name} created. Run 'Test Connection' to verify access.", "success")
            return redirect(url_for("devices.detail", device_id=device.id))
        for error in errors:
            flash(error, "danger")
        return render_template("device_form.html", **_form_context(form=request.form)), 400
    return render_template("device_form.html", **_form_context(form={"enabled": "on"}))


@bp.route("/<int:device_id>/edit", methods=["GET", "POST"])
@login_required
@permission_required("device.manage")
def edit(device_id):
    device = _get_device(device_id)
    if request.method == "POST":
        site, credential, policy = _form_lookups(request.form)
        values, errors = clean_device(request.form, site, credential, policy, current_id=device.id)
        if not errors:
            reset = _apply(device, values)
            db.session.commit()
            audit("device.update", "device", device.id, {"name": device.name, "hostkey_reset": reset})
            flash("Device updated." + (" Management address changed: SSH host key must be re-verified."
                                       if reset else ""), "success")
            return redirect(url_for("devices.detail", device_id=device.id))
        for error in errors:
            flash(error, "danger")
        return render_template("device_form.html", **_form_context(device, request.form)), 400
    form = {c: getattr(device, c) for c in ("name", "hostname", "mgmt_ip", "site_id", "vendor", "platform",
                                            "connection_method", "port", "credential_id", "policy_id",
                                            "device_role", "vdom", "description")}
    form["enabled"] = "on" if device.enabled else ""
    return render_template("device_form.html", **_form_context(device, form))


@bp.route("/<int:device_id>")
@login_required
@permission_required("device.view")
def detail(device_id):
    device = _get_device(device_id)
    jobs = device.jobs.order_by(BackupJob.created_at.desc()).limit(15).all()
    versions = device.versions.order_by(BackupVersion.created_at.desc()).limit(15).all()
    trusted_fp = host_key_fingerprint(device.ssh_host_key_b64) if device.ssh_host_key_b64 else None
    pending_fp = host_key_fingerprint(device.pending_host_key_b64) if device.pending_host_key_b64 else None
    return render_template("device_detail.html", device=device, jobs=jobs, versions=versions,
                           trusted_fp=trusted_fp, pending_fp=pending_fp,
                           watch_job=request.args.get("job", type=int))


def _enqueue(device_id: int, job_type: str):
    device = _get_device(device_id)
    if not device.enabled:
        flash("Device is disabled.", "warning")
        return redirect(url_for("devices.detail", device_id=device.id))
    job, reason = enqueue_job(device, job_type, "manual", current_user)
    if job is None:
        flash(reason, "warning")
        return redirect(url_for("devices.detail", device_id=device.id))
    audit(f"job.{job_type}_requested", "device", device.id, {"job_id": job.id, "name": device.name})
    flash(f"{'Backup' if job_type == 'backup' else 'Connection test'} job #{job.id} queued.", "info")
    return redirect(url_for("devices.detail", device_id=device.id, job=job.id))


@bp.route("/<int:device_id>/backup", methods=["POST"])
@login_required
@permission_required("backup.run")
def backup_now(device_id):
    return _enqueue(device_id, "backup")


@bp.route("/<int:device_id>/test", methods=["POST"])
@login_required
@permission_required("backup.run")
def test_connection(device_id):
    return _enqueue(device_id, "test")


@bp.route("/<int:device_id>/hostkey/trust", methods=["POST"])
@login_required
@permission_required("hostkey.manage")
def trust_host_key(device_id):
    device = _get_device(device_id)
    if not device.pending_host_key_b64:
        flash("No pending host key. Run 'Test Connection' first.", "warning")
        return redirect(url_for("devices.detail", device_id=device.id))
    expected = request.form.get("fingerprint", "")
    fingerprint = host_key_fingerprint(device.pending_host_key_b64)
    if expected != fingerprint:
        flash("Pending host key changed since the page was loaded. Review it again.", "danger")
        return redirect(url_for("devices.detail", device_id=device.id))
    previous = host_key_fingerprint(device.ssh_host_key_b64) if device.ssh_host_key_b64 else None
    device.ssh_host_key_type, device.ssh_host_key_b64 = device.pending_host_key_type, device.pending_host_key_b64
    device.pending_host_key_type = device.pending_host_key_b64 = None
    db.session.commit()
    audit("device.hostkey_trusted", "device", device.id, {"fingerprint": fingerprint, "previous": previous})
    flash(f"Host key {fingerprint} trusted.", "success")
    return redirect(url_for("devices.detail", device_id=device.id))


@bp.route("/<int:device_id>/hostkey/forget", methods=["POST"])
@login_required
@permission_required("hostkey.manage")
def forget_host_key(device_id):
    device = _get_device(device_id)
    device.ssh_host_key_type = device.ssh_host_key_b64 = None
    device.pending_host_key_type = device.pending_host_key_b64 = None
    db.session.commit()
    audit("device.hostkey_removed", "device", device.id)
    flash("SSH host key removed. Run 'Test Connection' to fetch it again.", "info")
    return redirect(url_for("devices.detail", device_id=device.id))


@bp.route("/<int:device_id>/toggle", methods=["POST"])
@login_required
@permission_required("device.manage")
def toggle(device_id):
    device = _get_device(device_id)
    device.enabled = not device.enabled
    db.session.commit()
    audit("device.enable" if device.enabled else "device.disable", "device", device.id, {"name": device.name})
    flash(f"Device {'enabled' if device.enabled else 'disabled'}.", "info")
    return redirect(url_for("devices.detail", device_id=device.id))


@bp.route("/<int:device_id>/delete", methods=["POST"])
@login_required
@permission_required("device.manage")
def delete(device_id):
    device = _get_device(device_id)
    if active_job_for(device.id):
        flash("Device has a queued or running job. Try again when it finishes.", "warning")
        return redirect(url_for("devices.detail", device_id=device.id))
    if request.form.get("confirm_name") != device.name:
        flash("Type the device name to confirm deletion.", "danger")
        return redirect(url_for("devices.detail", device_id=device.id))
    storage = get_storage()
    with storage_lock:
        paths = {p for (p,) in db.session.query(BackupVersion.file_path)
                 .filter(BackupVersion.device_id == device.id, BackupVersion.file_path.isnot(None))}
        name = device.name
        db.session.delete(device)
        db.session.commit()
        for path in paths:
            try:
                storage.delete(path)
            except Exception as exc:
                current_app.logger.error("Could not delete %s: %s", path, exc)
    audit("device.delete", "device", device_id, {"name": name, "files_deleted": len(paths)})
    flash(f"Device {name} and its {len(paths)} backup file(s) deleted.", "success")
    return redirect(url_for("devices.index"))


# ------------------------------------------------------------ CSV import ---
@bp.route("/import/template.csv")
@login_required
@permission_required("device.manage")
def import_template():
    sample = io.StringIO()
    writer = csv.writer(sample)
    writer.writerow(CSV_FIELDS)
    writer.writerow(["FG-HCM-01", "fg-hcm-01.example.local", "10.10.10.1", "HCM-DC", "fortinet", "fortinet", "api",
                     "443", "FortiGate API", "Daily 02:00", "firewall", "", "HCM edge firewall", "true"])
    writer.writerow(["CORE-SW-01", "", "10.10.10.2", "HCM-DC", "cisco", "cisco_xe", "ssh", "22", "Cisco SSH",
                     "Daily 02:00", "core_switch", "", "", "true"])
    return Response(sample.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=device_import_template.csv"})


@bp.route("/import", methods=["GET", "POST"])
@login_required
@permission_required("device.manage")
def import_csv():
    if request.method == "GET":
        return render_template("device_import.html", errors=[], fields=CSV_FIELDS)
    upload = request.files.get("file")
    if not upload or not upload.filename:
        flash("Choose a CSV file.", "warning")
        return render_template("device_import.html", errors=[], fields=CSV_FIELDS), 400
    try:
        text = upload.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        flash("CSV must be UTF-8 encoded.", "danger")
        return render_template("device_import.html", errors=[], fields=CSV_FIELDS), 400
    reader = csv.DictReader(io.StringIO(text))
    missing = {"name", "mgmt_ip", "site", "vendor", "platform", "connection_method", "credential",
               "device_role"} - set(reader.fieldnames or [])
    if missing:
        flash(f"CSV is missing columns: {', '.join(sorted(missing))}", "danger")
        return render_template("device_import.html", errors=[], fields=CSV_FIELDS), 400

    sites = {s.name: s for s in Site.query.all()}
    creds = {c.name: c for c in Credential.query.all()}
    policies = {p.name: p for p in BackupPolicy.query.all()}
    rows, errors, names = [], [], set()
    for number, row in enumerate(reader, start=2):
        if number - 1 > MAX_CSV_ROWS:
            errors.append(f"More than {MAX_CSV_ROWS} rows; split the file")
            break
        row = {k: (v or "").strip() for k, v in row.items() if k}
        row.setdefault("enabled", "true")
        if row["enabled"] == "":
            row["enabled"] = "true"
        policy = policies.get(row.get("policy", "")) if row.get("policy") else None
        if row.get("policy") and policy is None:
            errors.append(f"Row {number}: unknown policy '{row['policy']}'")
        values, row_errors = clean_device(row, sites.get(row.get("site")), creds.get(row.get("credential")), policy)
        if row.get("site") and row["site"] not in sites:
            row_errors.append(f"unknown site '{row['site']}'")
        if values.get("name") in names:
            row_errors.append("duplicate name within file")
        names.add(values.get("name"))
        errors.extend(f"Row {number}: {e}" for e in row_errors)
        rows.append(values)
    if errors or not rows:
        if not rows and not errors:
            errors.append("CSV contains no device rows")
        return render_template("device_import.html", errors=errors, fields=CSV_FIELDS), 400
    for values in rows:
        device = Device()
        _apply(device, values)
        db.session.add(device)
    db.session.commit()
    audit("device.import", details={"count": len(rows)})
    flash(f"Imported {len(rows)} device(s). Run 'Test Connection' on SSH devices to trust host keys.", "success")
    return redirect(url_for("devices.index"))
