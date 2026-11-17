"""SMTP email and generic webhook notifications.

Notification bodies contain metadata only (device, status, line counts),
never configuration content or secrets.
"""
import logging
import smtplib
import ssl
from email.message import EmailMessage

import httpx
from flask import current_app

from ..models import utcnow
from .settings_service import get_setting

log = logging.getLogger(__name__)

EVENT_TOGGLES = {
    "backup_failed": "notify_on_failure",
    "unreachable": "notify_on_unreachable",
    "config_changed": "notify_on_change",
    "stale_backup": "notify_on_stale",
}


def notify(event: str, subject: str, body: str, data: dict = None) -> None:
    toggle = EVENT_TOGGLES.get(event)
    if toggle and not get_setting(toggle):
        return
    try:
        send_email(f"[{current_app.config['APP_SHORT_NAME']}] {subject}", body)
    except Exception as exc:
        log.error("Email notification failed for %s: %s", event, exc)
    try:
        send_webhook(event, subject, body, data or {})
    except Exception as exc:
        log.error("Webhook notification failed for %s: %s", event, exc)


def _recipients() -> list:
    return [r.strip() for r in (get_setting("notify_emails") or "").split(",") if r.strip()]


def send_email(subject: str, body: str) -> bool:
    host, recipients = get_setting("smtp_host"), _recipients()
    if not host or not recipients:
        return False
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = get_setting("smtp_from") or get_setting("smtp_username") or "config-backup@localhost"
    message["To"] = ", ".join(recipients)
    message.set_content(body)

    port, security = get_setting("smtp_port"), get_setting("smtp_security")
    context = ssl.create_default_context()
    if security == "ssl":
        server = smtplib.SMTP_SSL(host, port, timeout=15, context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=15)
    with server:
        if security == "starttls":
            server.starttls(context=context)
        username = get_setting("smtp_username")
        if username:
            server.login(username, get_setting("smtp_password"))
        server.send_message(message)
    log.info("Email sent: %s -> %d recipient(s)", subject, len(recipients))
    return True


def send_webhook(event: str, subject: str, body: str, data: dict) -> bool:
    url = get_setting("webhook_url")
    if not url:
        return False
    payload = {"event": event, "subject": subject, "message": body, "data": data,
               "timestamp": utcnow().isoformat() + "Z"}
    with httpx.Client(timeout=10, verify=True, trust_env=False, follow_redirects=False) as client:
        resp = client.post(url, json=payload)
    if resp.status_code >= 300:
        raise RuntimeError(f"Webhook returned HTTP {resp.status_code}")
    log.info("Webhook delivered: %s", event)
    return True
