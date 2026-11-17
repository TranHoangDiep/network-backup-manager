"""Credential profiles (admin only). Secrets are write-only from the UI."""
import ssl

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import login_required

from ..drivers.ssh_common import load_private_key
from ..drivers.base import AuthenticationError
from ..extensions import db
from ..models import Credential, utcnow
from ..security import audit, permission_required
from ..services.credential_service import set_secret
from ..validators import SSH_USERNAME_RE, ValidationError, clean_name, clean_text, parse_port

bp = Blueprint("credentials", __name__, url_prefix="/credentials")

MAX_SECRET_LEN = 16384


def _clean(form, cred: Credential) -> list:
    """Validate and apply the form to ``cred``. Returns errors; secrets stay untouched on error."""
    errors = []
    try:
        name = clean_name(form.get("name"), "Profile name")
        if Credential.query.filter(Credential.name == name, Credential.id != (cred.id or 0)).first():
            errors.append("A profile with this name already exists")
    except ValidationError as exc:
        errors.append(str(exc))
        name = None
    cred_type = form.get("cred_type")
    if cred.id and cred_type != cred.cred_type and cred.devices.count():
        errors.append("Cannot change the type of a profile that is assigned to devices")
    if cred_type not in ("ssh", "api"):
        errors.append("Type must be SSH or API")
    try:
        description = clean_text(form.get("description"), "Description", 255)
    except ValidationError as exc:
        errors.append(str(exc))
        description = ""

    secrets = {f: form.get(f, "") for f in ("password", "private_key", "key_passphrase",
                                            "enable_password", "api_token")}
    for field, value in secrets.items():
        if len(value) > MAX_SECRET_LEN:
            errors.append(f"{field} is too long")
    clears = {f: bool(form.get(f"clear_{f}")) for f in secrets}

    username = (form.get("username") or "").strip()
    api_port, ca_pem, verify_tls = 443, None, True
    if cred_type == "ssh":
        if not SSH_USERNAME_RE.match(username):
            errors.append("SSH username is required (letters, digits, . _ - @ \\)")
        has_password = (secrets["password"] or cred.password_enc) and not clears["password"]
        has_key = (secrets["private_key"] or cred.private_key_enc) and not clears["private_key"]
        if not has_password and not has_key:
            errors.append("SSH profile needs a password or a private key")
        if secrets["private_key"]:
            try:
                load_private_key(secrets["private_key"], secrets["key_passphrase"])
            except AuthenticationError as exc:
                errors.append(str(exc))
    elif cred_type == "api":
        username = ""
        if not (secrets["api_token"] or cred.api_token_enc) or clears["api_token"]:
            errors.append("API profile needs an API token")
        try:
            api_port = parse_port(form.get("api_port"), required=True)
        except ValidationError as exc:
            errors.append(str(exc))
        verify_tls = bool(form.get("verify_tls"))
        ca_pem = (form.get("ca_cert_pem") or "").strip() or None
        if ca_pem:
            if "PRIVATE KEY" in ca_pem:
                errors.append("CA certificate field must not contain a private key")
            else:
                try:
                    ssl.create_default_context(cadata=ca_pem)
                except (ssl.SSLError, ValueError):
                    errors.append("CA certificate is not valid PEM")
    if errors:
        return errors

    cred.name, cred.cred_type, cred.description = name, cred_type, description
    cred.username, cred.api_port, cred.verify_tls, cred.ca_cert_pem = username, api_port, verify_tls, ca_pem
    rotated = False
    for field, value in secrets.items():
        allowed = (field in ("password", "private_key", "key_passphrase", "enable_password")) == (cred_type == "ssh")
        if not allowed:
            rotated |= set_secret(cred, field, "", clear=True)
        else:
            rotated |= set_secret(cred, field, value, clear=clears[field])
    if rotated:
        cred.rotated_at = utcnow()
    return []


@bp.route("/")
@login_required
@permission_required("credential.manage")
def index():
    creds = Credential.query.order_by(Credential.name).all()
    usage = {c.id: c.devices.count() for c in creds}
    return render_template("credentials.html", credentials=creds, usage=usage)


@bp.route("/new", methods=["GET", "POST"])
@bp.route("/<int:cred_id>/edit", methods=["GET", "POST"])
@login_required
@permission_required("credential.manage")
def edit(cred_id=None):
    cred = db.session.get(Credential, cred_id) if cred_id else Credential(cred_type="ssh", verify_tls=True, api_port=443)
    if cred is None:
        abort(404)
    if request.method == "POST":
        errors = _clean(request.form, cred)
        if not errors:
            db.session.add(cred)
            db.session.commit()
            audit("credential.update" if cred_id else "credential.create", "credential", cred.id,
                  {"name": cred.name, "type": cred.cred_type, "secrets_set": cred.secret_flags,
                   "verify_tls": cred.verify_tls})
            flash("Credential profile saved. Secret values are encrypted and cannot be displayed.", "success")
            return redirect(url_for("credentials.index"))
        db.session.rollback()
        for error in errors:
            flash(error, "danger")
        form = {k: v for k, v in request.form.items() if k not in
                ("password", "private_key", "key_passphrase", "enable_password", "api_token")}
        return render_template("credential_form.html", cred=cred if cred_id else None, form=form), 400
    form = {"name": cred.name or "", "cred_type": cred.cred_type, "description": cred.description or "",
            "username": cred.username or "", "api_port": cred.api_port, "ca_cert_pem": cred.ca_cert_pem or "",
            "verify_tls": "on" if cred.verify_tls else ""}
    return render_template("credential_form.html", cred=cred if cred_id else None, form=form)


@bp.route("/<int:cred_id>/delete", methods=["POST"])
@login_required
@permission_required("credential.manage")
def delete(cred_id):
    cred = db.session.get(Credential, cred_id)
    if cred is None:
        abort(404)
    if cred.devices.count():
        flash("Profile is assigned to devices and cannot be deleted.", "warning")
        return redirect(url_for("credentials.index"))
    name = cred.name
    db.session.delete(cred)
    db.session.commit()
    audit("credential.delete", "credential", cred_id, {"name": name})
    flash("Credential profile deleted.", "success")
    return redirect(url_for("credentials.index"))
