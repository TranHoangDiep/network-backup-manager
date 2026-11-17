"""Container health checks: `python healthcheck.py web|scheduler`."""
import os
import ssl
import sys
import time
import urllib.request
from pathlib import Path

DATA_DIR = Path(os.environ.get("NBM_DATA_DIR", "/app/data"))


def check_web() -> bool:
    tls = os.environ.get("TLS_ENABLED", "true").lower() == "true"
    port = os.environ.get("WEB_PORT", "8443")
    url = f"{'https' if tls else 'http'}://127.0.0.1:{port}/healthz"
    context = None
    if tls:
        # Loopback probe of our own listener only; the certificate is typically
        # issued for the public hostname, not 127.0.0.1. Device connections
        # always verify certificates.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(url, timeout=5, context=context) as resp:
        return resp.status == 200


def check_scheduler() -> bool:
    heartbeat = DATA_DIR / "scheduler.heartbeat"
    return heartbeat.exists() and time.time() - heartbeat.stat().st_mtime < 120


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "web"
    try:
        ok = check_web() if target == "web" else check_scheduler()
    except Exception as exc:
        print(f"unhealthy: {exc}")
        ok = False
    sys.exit(0 if ok else 1)
