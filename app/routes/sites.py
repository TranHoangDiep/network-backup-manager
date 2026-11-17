"""Site management."""
import ipaddress

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import login_required

from ..extensions import db
from ..models import Device, Site
from ..security import audit, permission_required
from ..validators import ValidationError, clean_name, clean_text, parse_cidr, parse_timezone

bp = Blueprint("sites", __name__, url_prefix="/sites")


def _clean(form, current_id=None):
    errors, out = [], {}
    checks = (("name", clean_name, (form.get("name"), "Site name")),
              ("description", clean_text, (form.get("description"), "Description", 255)),
              ("mgmt_subnet", parse_cidr, (form.get("mgmt_subnet"),)),
              ("timezone", parse_timezone, (form.get("timezone"),)))
    for key, func, args in checks:
        try:
            out[key] = func(*args)
        except ValidationError as exc:
            errors.append(str(exc))
    out["status"] = "active" if form.get("status") == "active" else "inactive"
    if "name" in out and Site.query.filter(Site.name == out["name"], Site.id != (current_id or 0)).first():
        errors.append("A site with this name already exists")
    if current_id and out.get("mgmt_subnet"):
        subnet = ipaddress.ip_network(out["mgmt_subnet"])
        outside = [d.name for d in Device.query.filter_by(site_id=current_id)
                   if ipaddress.ip_address(d.mgmt_ip) not in subnet]
        if outside:
            errors.append(f"Devices outside the new subnet: {', '.join(outside[:10])}")
    return out, errors


@bp.route("/")
@login_required
@permission_required("device.view")
def index():
    sites = Site.query.order_by(Site.name).all()
    counts = {s.id: s.devices.count() for s in sites}
    return render_template("sites.html", sites=sites, counts=counts)


@bp.route("/new", methods=["GET", "POST"])
@bp.route("/<int:site_id>/edit", methods=["GET", "POST"])
@login_required
@permission_required("site.manage")
def edit(site_id=None):
    site = db.session.get(Site, site_id) if site_id else None
    if site_id and site is None:
        abort(404)
    if request.method == "POST":
        values, errors = _clean(request.form, site_id)
        if not errors:
            site = site or Site()
            values["mgmt_subnet"] = values["mgmt_subnet"] or None
            for key, value in values.items():
                setattr(site, key, value)
            db.session.add(site)
            db.session.commit()
            audit("site.update" if site_id else "site.create", "site", site.id, {"name": site.name})
            flash("Site saved.", "success")
            return redirect(url_for("sites.index"))
        for error in errors:
            flash(error, "danger")
        return render_template("site_form.html", site=site, form=request.form), 400
    form = ({"name": site.name, "description": site.description, "mgmt_subnet": site.mgmt_subnet,
             "timezone": site.timezone, "status": site.status} if site else {"status": "active", "timezone": "UTC"})
    return render_template("site_form.html", site=site, form=form)


@bp.route("/<int:site_id>/delete", methods=["POST"])
@login_required
@permission_required("site.manage")
def delete(site_id):
    site = db.session.get(Site, site_id)
    if site is None:
        abort(404)
    if site.devices.count():
        flash("Site still has devices. Move or delete them first.", "warning")
        return redirect(url_for("sites.index"))
    name = site.name
    db.session.delete(site)
    db.session.commit()
    audit("site.delete", "site", site_id, {"name": name})
    flash("Site deleted.", "success")
    return redirect(url_for("sites.index"))
