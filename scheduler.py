"""Dedicated scheduler/worker process.

Runs APScheduler (backup policies, retention, stale-backup alerts) and the
bounded thread pool that executes queued backup jobs. Exactly one instance
may run; a second instance exits because it cannot take the file lock.
"""
import logging
import signal
import sys
import threading

from app import create_app
from app.services.scheduler_service import SchedulerAlreadyRunning, SchedulerService

log = logging.getLogger("scheduler")


def main() -> int:
    app = create_app(process_role="scheduler")
    service = SchedulerService(app)
    stop = threading.Event()

    def handle_signal(signum, _frame):
        log.info("Received signal %s, shutting down", signum)
        stop.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    try:
        service.start()
    except SchedulerAlreadyRunning as exc:
        log.error("%s; exiting", exc)
        return 1
    try:
        while not stop.wait(1):
            pass
    finally:
        service.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
