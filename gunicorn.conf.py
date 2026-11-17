"""Gunicorn settings (web container). HTTPS is terminated by gunicorn itself."""
import os

bind = f"0.0.0.0:{os.environ.get('WEB_PORT', '8443')}"
# One worker keeps the in-memory login rate limiter and rotating log file
# consistent; threads handle concurrency for ~10 internal users comfortably.
workers = int(os.environ.get("WEB_WORKERS", "1"))
threads = int(os.environ.get("WEB_THREADS", "8"))
worker_class = "gthread"
timeout = 60
graceful_timeout = 30
accesslog = "-"
errorlog = "-"
access_log_format = '%(h)s "%(r)s" %(s)s %(b)s %(L)ss'
forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1")

if os.environ.get("TLS_ENABLED", "true").lower() == "true":
    certfile = os.environ.get("TLS_CERT_FILE", "/app/data/certs/server.crt")
    keyfile = os.environ.get("TLS_KEY_FILE", "/app/data/certs/server.key")
