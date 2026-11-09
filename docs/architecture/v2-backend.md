# LinSec360 v2 backend

This document describes the FastAPI + PostgreSQL backend used by the LinSec360
React application.

## What exists

- `backend/` — FastAPI application, SQLAlchemy 2.0 models, Pydantic v2 schemas.
- PostgreSQL schema managed by Alembic (`backend/alembic/`).
- Redis + RQ deployment queue with an in-process thread fallback for local dev.
- Session authentication, CSRF protection, RBAC, hashed API tokens, login rate
  limiting, and an audit log.
- DB-backed playbooks, generated Ansible inventories, and deployment logs.
- Deployment cancellation, retry, event timeline, and SSE log streaming.
- SSH host enrollment with out-of-band fingerprint verification, optional
  password-based key installation, and pinned host keys.
- Wazuh agents/alerts/vulnerabilities, OpenSCAP scans, Uyuni systems/errata,
  native live-patch state, hardening drift, and KPI snapshots.
- Alert acknowledgement and Wazuh active response.
- Scheduled operations, maintenance windows, and orphan cleanup.
- Hashed API tokens for non-browser clients.
- `/api/v1` endpoints for all of the above.
- `docker-compose.v2.yml` for the API, worker, PostgreSQL, Redis, Wazuh, and an
  optional Uyuni profile.
- 70 backend tests in `backend/tests/`.

## Architecture

```text
Browser / API client
  -> FastAPI (backend/main.py)
       -> services/ (hosts, playbooks, deployments, KPIs, audit,
                     wazuh, oscap, uyuni, livepatch, hardening, alerts)
       -> SQLAlchemy -> PostgreSQL
       -> RQ queue -> Redis
                         -> worker -> ansible-playbook -> managed hosts
       -> Wazuh API / Indexer (alerts, agents, vulnerabilities)
       -> Uyuni API (systems, channels, errata)
```

The worker writes inventories and materialized playbooks to private runtime
directories, and logs to `LINSEC_LOG_DIR`. The database is the source of truth
for hosts and playbooks; files on disk are disposable runtime artifacts.

## Quick start with Docker Compose

1. Copy the new values from `.env.example` into `.env` and set:

```dotenv
POSTGRES_PASSWORD=<strong-password>
LINSEC_SECRET_KEY=<openssl rand -hex 32>
LINSEC_BOOTSTRAP_ADMIN_USERNAME=admin
LINSEC_BOOTSTRAP_ADMIN_PASSWORD=<strong-password>
LINSEC_API_PORT=8080
```

2. Ensure `./.ssh/id_ed25519` exists and is readable by the container UID
   (`LINSEC_UID`, default `1000`). The worker mounts `./.ssh` read-only at
   `/opt/linsec/.ssh`; Ansible uses that key.

3. Start the stack:

```bash
docker compose -f docker-compose.v2.yml up --build
```

4. Open:

- API: `http://localhost:8080`
- OpenAPI docs: `http://localhost:8080/api/docs`
- Health: `http://localhost:8080/health`
- Readiness: `http://localhost:8080/ready`

The API container runs `alembic upgrade head` before starting Uvicorn. The
worker starts only after the API is healthy. On the first startup the bootstrap
admin is created from `LINSEC_BOOTSTRAP_ADMIN_PASSWORD`; change it immediately
after login.

## Local development without Docker

```bash
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements-dev.txt

export LINSEC_SECRET_KEY="$(openssl rand -hex 32)"
export LINSEC_DATABASE_URL="sqlite:///./var/linsec.db"
export LINSEC_BOOTSTRAP_ADMIN_PASSWORD="change-me-now-123"
export LINSEC_AUTO_CREATE_TABLES=false

.venv/bin/alembic -c backend/alembic.ini upgrade head
.venv/bin/uvicorn backend.main:app --reload --port 8000
```

Open `http://localhost:8000/api/docs`.

To create the admin without the bootstrap environment variable:

```bash
.venv/bin/python -m backend.cli create-admin
```

Useful CLI commands:

```bash
python -m backend.cli create-admin --username admin --role admin
python -m backend.cli reset-password --username admin
python -m backend.cli seed-playbooks
python -m backend.cli create-tables   # dev only; prefer Alembic
```

### PostgreSQL instead of SQLite

```bash
export LINSEC_DATABASE_URL="postgresql+psycopg://linsec:password@localhost:5432/linsec"
.venv/bin/alembic -c backend/alembic.ini upgrade head
.venv/bin/uvicorn backend.main:app --reload --port 8000
```

### Queue mode

With `LINSEC_REDIS_URL` empty, deployments run in a bounded thread pool inside
the API process. This is convenient for development but jobs do not survive a
restart. For durable jobs, run Redis and a worker:

```bash
export LINSEC_REDIS_URL="redis://localhost:6379/0"
rq worker deployments --url "$LINSEC_REDIS_URL" --path .
```

The API enqueues `backend.workers.deployment_worker.run_deployment`; the worker
materializes the playbook, generates the inventory, runs `ansible-playbook`,
and records status, host status, events, and the log file.

## Authentication and CSRF

`POST /api/v1/auth/login` accepts JSON:

```bash
curl -c cookies.txt -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"change-me-now-123"}'
```

The response sets:

- `linsec_session` — HttpOnly, SameSite=Lax session cookie.
- `linsec_csrf` — readable CSRF cookie.

Every mutating request (`POST`, `PUT`, `PATCH`, `DELETE`) must echo the CSRF
value in `X-CSRF-Token`. Login is exempt. Logout requires the header.

```bash
csrf=$(awk '$6 == "linsec_csrf" {print $7}' cookies.txt)

curl -b cookies.txt -H "X-CSRF-Token: $csrf" \
  -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/hosts \
  -d '{"name":"web01","ip":"10.0.0.10","environment":"production","security_level":"high","groups":["web"]}'
```

Roles:

| Role | Capabilities |
|---|---|
| `admin` | All reads and writes, user/admin operations, delete hosts/playbooks |
| `operator` | Read, create/update hosts and playbooks, create deployments |
| `auditor` | Read, including audit log |
| `viewer` | Read-only |

## API v1

```text
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
GET    /api/v1/auth/me

GET    /api/v1/auth/tokens
POST   /api/v1/auth/tokens
DELETE /api/v1/auth/tokens/:id

GET    /api/v1/hosts
POST   /api/v1/hosts
POST   /api/v1/hosts/import
POST   /api/v1/hosts/ssh/fingerprint
POST   /api/v1/hosts/enroll
GET    /api/v1/hosts/ssh/public-key
GET    /api/v1/hosts/:id
GET    /api/v1/hosts/:id/posture
PATCH  /api/v1/hosts/:id
DELETE /api/v1/hosts/:id
POST   /api/v1/hosts/:id/ssh/test
POST   /api/v1/hosts/:id/ssh/accept-fingerprint

GET    /api/v1/playbooks
POST   /api/v1/playbooks
POST   /api/v1/playbooks/validate
GET    /api/v1/playbooks/:filename
PUT    /api/v1/playbooks/:filename
DELETE /api/v1/playbooks/:filename

GET    /api/v1/deployments
POST   /api/v1/deployments
GET    /api/v1/deployments/:id
GET    /api/v1/deployments/:id/events
GET    /api/v1/deployments/:id/events/stream
GET    /api/v1/deployments/:id/log
POST   /api/v1/deployments/:id/cancel
POST   /api/v1/deployments/:id/retry

GET    /api/v1/kpis/overview
GET    /api/v1/kpis/history

GET    /api/v1/audit

GET    /api/v1/agents
GET    /api/v1/agents/summary
POST   /api/v1/agents/sync

GET    /api/v1/alerts
GET    /api/v1/alerts/summary
POST   /api/v1/alerts/sync
POST   /api/v1/alerts/:id/ack
POST   /api/v1/alerts/:id/active-response

GET    /api/v1/compliance/scans
POST   /api/v1/compliance/scans
GET    /api/v1/compliance/scans/:id
GET    /api/v1/compliance/scans/export
GET    /api/v1/compliance/profiles
GET    /api/v1/compliance/summary

GET    /api/v1/patching/findings
GET    /api/v1/patching/summary
POST   /api/v1/patching/findings/:id/resolve
GET    /api/v1/patching/uyuni
GET    /api/v1/patching/livepatch
POST   /api/v1/patching/uyuni/sync
POST   /api/v1/patching/livepatch
POST   /api/v1/patching/wazuh/sync

GET    /api/v1/hardening/baseline
GET    /api/v1/hardening/checks
GET    /api/v1/hardening/summary
POST   /api/v1/hardening/results

GET    /api/v1/integrations/status
POST   /api/v1/integrations/wazuh/test
POST   /api/v1/integrations/wazuh/sync
POST   /api/v1/integrations/uyuni/test
POST   /api/v1/integrations/ansible/test

GET    /api/v1/operations/schedules
POST   /api/v1/operations/schedules
DELETE /api/v1/operations/schedules/:id
POST   /api/v1/operations/schedules/run-due
GET    /api/v1/operations/maintenance
POST   /api/v1/operations/maintenance
POST   /api/v1/operations/cleanup-orphans

GET    /health
GET    /ready
```

Environments and groups are created implicitly from validated host payloads.
Dedicated CRUD endpoints come with the SPA.

### SSH host enrollment

The UI first calls `POST /api/v1/hosts/ssh/fingerprint` without credentials.
An operator compares the displayed fingerprint with a trusted source, then
submits the host details, password, and verified fingerprint to
`POST /api/v1/hosts/enroll`. The API rescans the key and refuses to send the
password unless the fingerprint still matches. Password authentication is
tested before the host is added; a failed test leaves the inventory unchanged.

After a successful test, the host is added and the public Ansible key is
installed in a FastAPI background task. The password is not persisted or sent
to the job queue, and is passed to `sshpass` through a pipe rather than its
arguments. SSH uses strict host-key checking with a temporary pinned
`known_hosts` file. Enrollment requires HTTPS; plain HTTP is accepted only for
the localhost UI. The UI supports CSV batches of up to 25 hosts: it scans each
host key without credentials, requires the operator to compare and enter each
fingerprint, then submits credentials one host at a time. Passwords are cleared
from the UI after the attempt and never stored in the database. Once key
installation is confirmed, the selected allowlisted playbook is queued for
hosts that passed the key-authentication check. Failed hosts are excluded from
the deployment and shown with their reason.
The short-lived installation task runs in the API process, so an API restart
during provisioning requires the operator to retry the enrollment.

## KPI semantics

`GET /api/v1/kpis/overview` returns each metric as `{value, status, source}`.
`value` is `null` unless the underlying source has data. `status` is one of:

- `ok` — a real value was computed.
- `unknown` — the source is not configured, unreachable, or has no rows yet.
- `stale` — reserved for values whose source has aged out (not currently
  produced by the default aggregation).

Sources and thresholds:

| Metric | Source | Unknown when |
|---|---|---|
| `hosts_total`, `hosts_secured`, `hosts_deploying`, `active_deployments` | `database` | never; counts default to 0 |
| `deployment_success_rate` | `database` | no succeeded/failed deployment in the last 30 days |
| `open_vulnerabilities`, `open_critical_vulnerabilities`, `open_high_vulnerabilities` | `wazuh` | no `PatchFinding` rows have been synchronized |
| `patch_coverage`, `reboot_required` | `uyuni` | no patch rows or no hosts |
| `compliance_score` | `openscap` | no completed scan with a score |
| `agent_coverage`, `disconnected_agents` | `wazuh` | no host has an `agent_id` |
| `kernel_exposure_days` | `livepatch` | no live-patch record has an operator-supplied `exposure_days` |
| `hardening_drift`, `selinux_non_compliant` | `hardening` | no hardening checks have been ingested |
| `alerts_by_severity` | `wazuh` | `null` until alerts are synchronized |

`GET /api/v1/kpis/history?metric=compliance_score&days=30` returns persisted
snapshots used for trend charts. Snapshots are captured by the operations
scheduler (`POST /api/v1/operations/schedules/run-due` or a configured
schedule) and retain their original status and source.

No synthetic or estimated security values are ever returned.

## Frontend (React SPA)

`web/` is a Vite + React 19 + TypeScript single-page application.

- TanStack Query for server state, React Router for navigation.
- Recharts for compliance trends and posture visuals.
- lucide-react icons.
- All requests use `credentials: 'include'` and the `X-CSRF-Token` header from
  the readable `linsec_csrf` cookie.
- Vite proxies `/api` to `http://localhost:8080` in development; nginx serves
  the production build and proxies `/api` in the Docker image.

Pages: Overview, Hosts, Host detail, Deployments, Deployment detail, Playbooks,
Compliance, Patching, Detection, Audit, and Settings.

The Overview combines KPI cards, a 30-day compliance area chart, a posture
ring, alert-severity bars, and recent hosts/deployments. Every metric that the
API reports as `unknown` or `stale` is rendered as `—` with its status badge;
the UI never substitutes placeholder security numbers. Detection and Settings
show explicit "source not configured" states when Wazuh or Uyuni are absent.

```bash
cd web
npm install
npm run dev     # http://localhost:5173
npm run lint    # oxlint
npm run build   # tsc -b && vite build
```

The current bundle is a single ~755 kB chunk (~221 kB gzip). Code splitting
per route is the next frontend optimisation; it does not affect behaviour.

## End-to-end validation

The compose stack was smoke-tested with PostgreSQL 16, Redis 7, RQ 3.0, and
ansible-core 2.18:

- `alembic upgrade head` ran against Postgres before the API started.
- Login, host creation, playbook creation, and deployment creation succeeded.
- The worker picked up the queued job, generated the inventory, ran the
  playbook, streamed the log, marked the deployment `succeeded`, and marked the
  host `secured`.

The worker image installs `ansible-core`, not the full `ansible` package. It
therefore uses `backend/ansible.cfg` with `stdout_callback = default`.

## Operational notes

- Playbooks are stored in PostgreSQL and materialized to
  `LINSEC_PLAYBOOK_DIR` with mode `0600` before execution.
- Bundled playbooks are seeded from `LINSEC_BUNDLED_PLAYBOOKS_DIR`, which is
  separate from the runtime directory. Deleting a playbook therefore cannot
  resurrect it on restart.
- Inventories are generated from the DB at `LINSEC_INVENTORY_DIR/<environment>/hosts.yml`
  with mode `0600`; deployments always pass `--limit` for the selected hosts.
- The worker injects `linsec_config_dir` and `linsec_artifact_dir` into every
  deployment and sets `ANSIBLE_ROLES_PATH` from `LINSEC_TASKENGINE_DIR`, so
  hardening, SELinux, OpenSCAP, Wazuh, and live-patch assets are found even
  when playbooks are materialized elsewhere.
- `LINSEC_CONFIG_DIR` (default `config/`) holds the hardening baseline,
  SELinux policy, OpenSCAP profiles, and helper scripts. OpenSCAP and hardening
  paths can be overridden with `LINSEC_OPENSCAP_PROFILE_DIR` and
  `LINSEC_HARDENING_BASELINE_PATH`.
- Generated reports and scan artifacts are written below
  `LINSEC_ARTIFACT_DIR` (default `var/artifacts/`) with owner-only
  permissions.
- Deployment logs are written to `LINSEC_LOG_DIR/deploy-<uuid>.log`; the log
  endpoint refuses paths outside that directory.
- Passwords are hashed with Argon2id. Sessions are revocable rows in
  `user_sessions`; logout marks the session revoked.
- Set `LINSEC_COOKIE_SECURE=true` and terminate TLS in front of the API when
  `LINSEC_ENVIRONMENT=production`; the settings validator enforces this.

## Database migrations

```bash
alembic -c backend/alembic.ini upgrade head
alembic -c backend/alembic.ini downgrade -1
alembic -c backend/alembic.ini revision --autogenerate -m "describe change"
```

The initial migration is `backend/alembic/versions/7e7c7e049d26_initial_schema.py`.
It has been verified with upgrade → downgrade → upgrade on SQLite and with
upgrade on PostgreSQL 16.

## Tests

```bash
python3 -m pytest backend/tests -q
```

GitHub Actions runs the backend suite with Ruff and mypy on every push and pull
request through `.github/workflows/ci.yml`.

The current suite has **70 passing tests**. It covers auth/CSRF/RBAC, API
tokens, host CRUD and validation, CSV import, SSH fingerprint/enrollment
guards, playbook CRUD and YAML validation, inventory generation and file
permissions, KPI unknowns and counts, deployment creation, worker
success/failure, alert acknowledgement, and log retrieval. It uses a temporary
SQLite database per test and never touches the real database.

## Not implemented yet

- Account lockout and OIDC single sign-on.
- Durable scheduled jobs in a dedicated scheduler process (due schedules are
  currently run by an explicit API call).
- TLS termination and nginx gateway hardening as a first-class deployment
  artifact; the compose stack currently exposes the API directly.
- Production secret manager integration (Vault, SOPS, or cloud KMS).
- Structured telemetry, distributed tracing, and metrics export.
- Frontend route-level code splitting and a component test suite.
- Automatic Yum/DNF repository provisioning for Uyuni beyond registration and
  errata synchronization.
