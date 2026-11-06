# LinSec360 v1 backend

This document describes the FastAPI + PostgreSQL backend used by the LinSec360
React application.

## What exists

- `backend/` — FastAPI application, SQLAlchemy 2.0 models, Pydantic v2 schemas.
- PostgreSQL schema managed by Alembic (`backend/alembic/`).
- Redis + RQ deployment queue with an in-process thread fallback for local dev.
- Session authentication, CSRF protection, RBAC, hashed API tokens, login rate
  limiting, and an audit log.
- DB-backed playbooks, generated Ansible inventories, and deployment logs.
- Deployment cancellation, retry, and SSE log streaming.
- Wazuh agents/alerts/vulnerabilities, OpenSCAP scans, Uyuni systems/errata,
  native live-patch state, hardening drift, and KPI snapshots.
- `/api/v1` endpoints for all of the above.
- `docker-compose.v2.yml` for PostgreSQL + Redis + API + worker.
- 44 backend tests in `backend/tests/`.

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

## API v1 implemented today

```text
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
GET    /api/v1/auth/me

GET    /api/v1/hosts
POST   /api/v1/hosts
GET    /api/v1/hosts/:id
PATCH  /api/v1/hosts/:id
DELETE /api/v1/hosts/:id

GET    /api/v1/playbooks
POST   /api/v1/playbooks
GET    /api/v1/playbooks/:filename
PUT    /api/v1/playbooks/:filename
DELETE /api/v1/playbooks/:filename

GET    /api/v1/deployments
POST   /api/v1/deployments
GET    /api/v1/deployments/:id
GET    /api/v1/deployments/:id/events
GET    /api/v1/deployments/:id/log

GET    /api/v1/kpis/overview
GET    /api/v1/audit
GET    /health
GET    /ready
```

Environments and groups are created implicitly from validated host payloads.
Dedicated CRUD endpoints come with the SPA.

## KPI semantics

`/api/v1/kpis/overview` returns each metric with `value`, `status`, and
`source`.

- DB-derived metrics return `status: "ok"`.
- `deployment_success_rate` is `unknown` until at least one deployment has
  finished in the last 30 days.
- `open_vulnerabilities` is `unknown` with `source: "wazuh"` until the Wazuh
  client is implemented.
- `compliance_score` is `unknown` with `source: "openscap"` until OpenSCAP
  ingestion is implemented.

No synthetic values are returned.

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
.venv/bin/pytest backend/tests -q
```

GitHub Actions runs the backend suite with Ruff and mypy on every push and pull
request through `.github/workflows/ci.yml`.

The suite covers auth/CSRF/RBAC, host CRUD and validation, playbook CRUD and
YAML validation, inventory generation and file permissions, KPI unknowns and
counts, deployment creation, worker success/failure, and log retrieval. It uses
a temporary SQLite database per test and never touches the real database.

## Not implemented yet

- React SPA and visual dashboards.
- Account lockout and OIDC single sign-on.
- Per-environment concurrency locks and orphan cleanup.
- Scheduled compliance and Uyuni jobs.
- KernelCare and additional OpenUBA integrations.
- TLS/nginx gateway and production secret manager.
- TLS/nginx gateway and production secret manager.
