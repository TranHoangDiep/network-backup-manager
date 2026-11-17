# Network Configuration Backup Manager

Flask app for backing up configs from about 100 network devices (FortiGate, Cisco IOS/IOS-XE/NX-OS, experimental Aruba AOS-CX) over SSH (Netmiko) or REST API (HTTPX). It runs on one Linux server with Docker Compose.

## Architecture

```
Browser --HTTPS--> web container (gunicorn + Flask)
                     | enqueue BackupJob rows (never runs backups itself)
                     v
                   SQLite (WAL) <---- scheduler container (scheduler.py)
                     ^                  - APScheduler: policies, retention, stale alerts
                     |                  - ThreadPoolExecutor: runs queued jobs (default 5 concurrent)
                     |                  - drivers -> Netmiko (SSH) / HTTPX (FortiOS API)
   data/backups/<site_id>/<device_id>/<running|startup>/<UTC time>.cfg.enc  (Fernet-encrypted)
   keys/fernet.key (encryption key, outside the DB)
```

- **One scheduler only.** An `fcntl` file lock (`data/scheduler.lock`) makes a second scheduler process exit.
- **No overlapping jobs.** A partial unique index allows at most one queued/running job per device. Jobs are claimed with an atomic `UPDATE ... WHERE status='queued'`.
- **Restart handling.** When the worker starts, any job left `running` is marked `interrupted`. Queued jobs continue. Schedules are reloaded from the DB (and re-synced every 60 s).
- **Retries.** Timeouts, connection errors and incomplete output are retried with exponential backoff. Authentication, permission and host-key errors are not retried. A watchdog fails jobs that exceed the hard timeout.

## Project layout

```
app/
  __init__.py  config.py  models.py  extensions.py  security.py  validators.py
  logging_setup.py (rotating logs + secret redaction)  bootstrap.py (CLI)
  routes/      auth dashboard devices sites credentials backups settings
  services/    backup_service scheduler_service credential_service storage_service
               diff_service notification_service retention_service settings_service
  drivers/     base ssh_common cisco_ios cisco_nxos fortinet_api fortinet_ssh aruba_aoscx
  templates/   Bootstrap 5 + Jinja2
  static/      css/app.css js/app.js (no inline JS; strict CSP)
migrations/    Alembic (Flask-Migrate)
tests/         pytest (no real devices needed)
scheduler.py   worker/scheduler process
run.py         WSGI entry (gunicorn run:app)
docker/entrypoint.sh  Dockerfile  docker-compose.yml  gunicorn.conf.py  healthcheck.py
```

## Install (Ubuntu + Docker Compose)

```bash
git clone <repo> network-backup-manager && cd network-backup-manager
cp .env.example .env
# Edit .env: ALLOWED_MGMT_NETWORKS (your VPN management subnets), APP_TIMEZONE,
# TLS_COMMON_NAME, and a temporary INITIAL_ADMIN_PASSWORD (min 12 chars).
mkdir -p data keys && chmod 700 keys
# Linux server: the container runs as uid/gid APP_UID/APP_GID (default 1000).
# Either set APP_UID/APP_GID in .env to your own `id -u`/`id -g`, or:
sudo chown -R 1000:1000 data keys
# macOS (Docker Desktop): do NOT chown to 1000. Docker Desktop writes bind mounts
# as your Mac user, so the folders must stay owned by you:
#   sudo chown -R $(id -u):$(id -g) data keys
docker compose up -d --build
docker compose ps        # both services should become "healthy"
```

Open `https://<server>:8443`, sign in, then **remove `INITIAL_ADMIN_PASSWORD` from `.env`**.

On first start:
- `keys/fernet.key` (mode 600) and `keys/flask_secret.key` are generated. **Back up `fernet.key` right away.** Without it, no credential or backup can be decrypted.
- A self-signed TLS certificate is written to `data/certs/`. For production, replace `server.crt`/`server.key` with a certificate from your internal CA and run `docker compose restart web`.

Admin CLI commands:

```bash
docker compose exec web flask create-admin --username alice
docker compose exec web flask reset-password --username alice
docker compose exec web flask run-retention
docker compose stop scheduler && docker compose exec web flask rotate-key --drop-old && docker compose start scheduler
```

## First-time setup in the UI

1. **Sites**: create sites (e.g. `HCM-DC 10.10.0.0/16`). A device IP must be inside its site subnet.
2. **Credentials** (admin only): create SSH profiles (username + password or private key, optional enable password) and API profiles (FortiGate token, port, TLS verification, optional CA PEM). Secrets are write-only. Leaving a field blank keeps the stored value, and entering a new value rotates it.
3. **Admin → Schedules**: three default policies are created (Daily 02:00, Every 6h, Weekly). The options are 6h, 12h, daily, weekly or a 5-field cron expression where 0/7 = Sunday. Each policy has its own timezone.
4. **Devices**: add devices manually or via **Import CSV** (all-or-nothing, template downloadable).
5. For each SSH device, click **Test Connection**. The worker fetches the SSH host key and shows its SHA-256 fingerprint. Verify it on the device console and click **Trust this key**. SSH backups are blocked until a key is trusted. If the device later presents a different key, backups fail with a *HOST KEY MISMATCH* error.
6. **Backup Now** queues a job. The page polls job status and does not block.

## Roles

| Role | Permissions |
|---|---|
| admin | everything: devices, sites, credentials, schedules, settings, users, audit log, raw configs, downloads |
| operator | view devices/history, run backups and tests, view configs/diffs **with secrets masked**, download only if the user has "can download" |
| viewer | dashboard, device list, backup status/history metadata only; no config content |

Login protection: account lockout after 5 failures for 15 min, plus a per-IP rate limit. Sessions expire after 8 h, cookies are Secure/HttpOnly/SameSite, CSRF protection covers all forms, and every sensitive action is written to the audit log.

## Vendor behavior and firmware assumptions

**Cisco IOS / IOS-XE** (`cisco_ios`, `cisco_xe`): runs `show running-config` and `show startup-config`. Netmiko sends `terminal length 0` and `terminal width 511`, which are session-only settings. Privileged EXEC (`#`) is **required**, because at privilege < 15 `show running-config` returns a silently partial config. The driver enters enable mode with the enable password if one is set. A config is accepted only if it has no `% Invalid/Authorization` errors and no `--More--`, ends with `end`, and contains `hostname` or `version`. A missing startup-config is recorded as `skipped`.

**Cisco Small Business / Business** (`cisco_sbs`, CBS250/350, SG300/350): these switches authenticate inside the CLI (`User Name:` / `Password:`) instead of at the SSH layer, so use this platform, not Cisco IOS. Runs `show running-config` and `show startup-config`. The output starts with `config-file-header` and has no `end` trailer. Needs a privilege-15 account (prompt `#`). Not supported when the switch has `ip ssh password-auth` enabled.

**Cisco NX-OS** (`cisco_nxos`): runs `show running-config` and `show startup-config`. NX-OS output does not end with `end`, so validation checks for `version` and `hostname`/`switchname` lines instead. Use a `network-admin` role; `network-operator` hides some sections.

**FortiGate REST API** (preferred): `/api/v2/monitor/system/config/backup` with `scope=global`, or `scope=vdom&vdom=X` when a VDOM is set on the device.
- FortiOS **< 7.6.0 uses GET; 7.6.0+ requires POST** (GET returns 405). The driver reads the version from `/api/v2/monitor/system/status`, tries the expected method first, and switches to the other method only on HTTP 405.
- The token is always sent as `Authorization: Bearer`. FortiOS 7.4.5+ rejects `access_token` in the URL.
- 401 means a bad/expired token or that this server is not in the API user's *trusthost*. 403 means insufficient profile/VDOM permission. JSON or HTML responses are never saved as a config.
- On the FortiGate, create a REST API admin with trusthost = this server's VPN source IP. Fortinet documents `super_admin` for full backups; restricted profiles may produce 403 or partial output.
- TLS is verified by default. If the FortiGate uses a self-signed cert, paste its certificate or the issuing CA into the credential profile's CA field instead of disabling verification.
- Check the method and parameters against FNDN for your exact build. Treat this as an assumption.

**FortiGate SSH** (alternative): runs `show` at the top level, which returns the full config including VDOMs. Stock Netmiko changes `config system console / set output standard` to disable paging and reverts it afterwards. That is a config change, so this driver **does not do it**. Set the console output mode once on the device yourself:
```
config system console
    set output standard
end
```

**Aruba AOS-CX**: experimental and only validated against sample output. Test it on a device before relying on it.

**Adding a vendor**: subclass `BaseDriver` (or `NetmikoDriver`), implement `test_connection` / `fetch_configs` with validation, and register it in `app/drivers/__init__.py:PLATFORMS`.

## Change detection, diff, retention

- Every execution creates a `backup_versions` row, including unchanged runs.
- `config_hash` is the SHA-256 of the raw file. `normalized_hash` is the SHA-256 after removing dynamic lines (Cisco `! Last configuration change`, `ntp clock-period`; NX-OS `!Time:`; FortiOS `#config-version`, `#conf_file_ver` and the random-salted `ENC ...` values). A changed `normalized_hash` means a new encrypted file. Otherwise the row points at the previous file, so no duplicate files are created.
- The diff page uses difflib: green = added, red = removed. Dynamic lines can optionally be ignored. Secrets are masked for operators, and admins can toggle "Unmasked". Raw files are never modified.
- Retention defaults: firewall 180 d, core switch 180 d, access switch 90 d, router 180 d (Settings). A policy can override this. The newest successful version per device and config type is **never** deleted. Devices with active jobs are skipped. A file is removed only when no remaining row references it. Retention runs daily at 03:30, and every deletion is logged.

## Network egress restrictions

Before connecting, the worker checks the device IP against `ALLOWED_MGMT_NETWORKS` **and** the site subnet, and checks the port against `ALLOWED_PORTS`. Loopback, link-local, multicast and reserved addresses are rejected when the device is saved. The check runs in the form and again in the worker. The UI cannot run arbitrary commands or push configuration; drivers only run show commands and read-only API calls.

## Notifications

Configured under Admin → Settings: SMTP (STARTTLS/SSL) and an optional HTTPS webhook (JSON POST). Notifications are sent for: a backup failing after all retries, a device becoming unreachable, a config change, and devices without a successful backup within N hours (at most once per day). Messages contain metadata only, never config content.

## Backup and restore of this application

The SQLite DB, the encrypted backup files and the key **must be backed up together**. Files without the key are unreadable, and a DB without its files has dangling references.

```bash
# Backup (consistent: stop scheduler so no job writes mid-copy)
docker compose stop scheduler
docker compose exec web python -c "import sqlite3; s=sqlite3.connect('/app/data/db/nbm.sqlite3'); d=sqlite3.connect('/app/data/db/snapshot.sqlite3'); s.backup(d); d.close()"
tar czf nbm-data-$(date +%F).tgz --exclude=data/db/nbm.sqlite3* data/
tar czf nbm-keys-$(date +%F).tgz keys/      # store SEPARATELY (password vault / offline media)
docker compose start scheduler
rm data/db/snapshot.sqlite3
```

```bash
# Restore
docker compose down
tar xzf nbm-data-YYYY-MM-DD.tgz && tar xzf nbm-keys-YYYY-MM-DD.tgz
mv data/db/snapshot.sqlite3 data/db/nbm.sqlite3
sudo chown -R 1000:1000 data keys && chmod 600 keys/*
docker compose up -d
```

After a restore, check the result: sign in, open a recent backup's **view** page (this confirms decryption works), and run **Backup Now** on one device. Test the restore procedure periodically.

## Development and tests

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
# local run (HTTP, dev only):
export NBM_DATA_DIR=./data NBM_KEY_FILE=./keys/fernet.key SESSION_COOKIE_SECURE=false INITIAL_ADMIN_PASSWORD='change-me-please'
flask --app run:app db upgrade && flask --app run:app init-app
python run.py            # terminal 1
python scheduler.py      # terminal 2
```

The tests cover: device CRUD/validation/CSV, credential encryption and key rotation, RBAC, Cisco/NX-OS drivers with mocked Netmiko, FortiOS API with `httpx.MockTransport` (GET/POST/405 fallback, 401/403, JSON/HTML bodies, truncation, timeout), checksum and unchanged detection, diff and masking, retention, concurrency (unique index, atomic claim, max concurrency, watchdog), scheduler lock/restart, and secure download/path traversal.

After changing models: `flask --app run:app db migrate -m "msg"` then `db upgrade`.

## Integration testing with real devices

Use a lab device or a maintenance window, with read-only accounts.

1. **Cisco IOS/XE**: create `username netbackup privilege 15 secret ...` (or a lower privilege plus enable secret). Add the device, run Test Connection, verify and trust the fingerprint (`show ip ssh` / `show crypto key mypubkey rsa`), then Backup Now. Check that `running` and `startup` succeed. Run it again and expect `unchanged`. Change a description, back up again, and expect `+1/-1` in the diff. Revert the change.
2. **NX-OS**: same steps with a `network-admin` role account.
3. **FortiGate API**: `config system api-user` with trusthost = this server and an appropriate profile. Test Connection should show the FortiOS version and serial. Back up and confirm in the job message which HTTP method was used (GET below 7.6, POST from 7.6). Check the negative cases: a wrong token should give 401 and a removed trusthost should give 401/403.
4. **FortiGate SSH**: confirm `get system console` shows `output: standard`, then run a backup.
5. **Failure cases**: a wrong password should fail with no retry; a firewall-blocked port should give a timeout with retries; a device IP outside the allow-list should show "Destination not allowed".
6. **Restart**: run `docker compose restart scheduler` during a backup. The job should become `interrupted` and new jobs should still work.
