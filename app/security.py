"""Role-based access control helpers and audit logging."""
import json
import logging
from functools import wraps

from flask import abort, has_request_context, request
from flask_login import current_user

from .extensions import db
from .models import ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER, AuditLog

log = logging.getLogger(__name__)

ALL_ROLES = {ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER}

PERMISSIONS = {
    "dashboard.view": ALL_ROLES,
    "device.view": ALL_ROLES,
    "history.view": ALL_ROLES,          # metadata only
    "device.manage": {ROLE_ADMIN},
    "site.manage": {ROLE_ADMIN},
    "credential.manage": {ROLE_ADMIN},
    "policy.manage": {ROLE_ADMIN},
    "settings.manage": {ROLE_ADMIN},
    "user.manage": {ROLE_ADMIN},
    "audit.view": {ROLE_ADMIN},
    "hostkey.manage": {ROLE_ADMIN},
    "backup.run": {ROLE_ADMIN, ROLE_OPERATOR},
    "config.view": {ROLE_ADMIN, ROLE_OPERATOR},   # masked for operators
    "config.view_raw": {ROLE_ADMIN},
}


def has_permission(user, permission: str) -> bool:
    if user is None or not getattr(user, "is_authenticated", False) or not user.is_active:
        return False
    role = user.role_name
    if permission == "backup.download":
        return role == ROLE_ADMIN or (role == ROLE_OPERATOR and bool(user.can_download))
    return role in PERMISSIONS.get(permission, set())


def permission_required(permission: str):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                from .extensions import login_manager
                return login_manager.unauthorized()
            if not has_permission(current_user, permission):
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def audit(action: str, target_type: str = None, target_id=None, details: dict = None,
          user=None, commit: bool = True) -> None:
    """Persist an audit entry. Never pass secrets in ``details``."""
    if user is None and has_request_context() and current_user and current_user.is_authenticated:
        user = current_user
    entry = AuditLog(
        user_id=getattr(user, "id", None),
        username=getattr(user, "username", None) or (details or {}).get("username"),
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        details=json.dumps(details, default=str, sort_keys=True) if details else None,
        ip_address=request.remote_addr if has_request_context() else None,
    )
    db.session.add(entry)
    if commit:
        db.session.commit()
    log.info("AUDIT %s user=%s target=%s:%s", action, entry.username, target_type, target_id)
