# LinSec360 — implementation plan (post-MVP → working product)

Status: planning  
Scope: turn the current Wazuh + Flask + Ansible prototype into a maintained,
multi-layer Linux security platform with a real UI, real KPIs, and auditable
operations.

Assumptions:

- Single-tenant, on-premise or private-cloud deployment.
- Linux targets only (the Ansible layer may still skip non-Linux hosts).
- Wazuh 4.12 remains the telemetry, SIEM, and behavioral-analytics backend.
- Uyuni is the patch/repository control plane; native kernel live-patching uses
  the free `klp` bricks instead of commercial KernelCare.
- Small team (1–3 engineers); estimates below are relative and assume one
  full-time engineer unless stated otherwise.
- Existing domain code (services/repositories/Ansible runner) is worth keeping;
  the raw `sqlite3` data layer and the current frontend are not.

---

## 1. Target architecture

```text
┌──────────────────────────────── Browser ────────────────────────────────┐
│ React + TypeScript SPA (Vite)                                           │
│  Dashboard · Hosts · Deployments · Compliance · Patching · Alerts       │
│  Settings · Audit · Users                                               │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │ HTTPS  /api/v1/*  +  /events (SSE)
┌───────────────────────────────▼─────────────────────────────────────────┐
│ nginx (TLS termination, static SPA, reverse proxy, rate limiting)       │
└───────────────────────────────┬─────────────────────────────────────────┘
┌───────────────────────────────▼─────────────────────────────────────────┐
│ FastAPI (uvicorn/gunicorn)                                              │
│  api/v1 · auth/RBAC · Pydantic v2 contracts · audit · KPIs              │
│  services: hosts, deployments, wazuh, oscap, uyuni, kpi, audit         │
│  repositories → PostgreSQL (SQLAlchemy 2.0 + Alembic)                   │
└───────┬───────────────────┬───────────────────────┬─────────────────────┘
        │                   │                       │
        ▼                   ▼                       ▼
  Redis + RQ worker     Wazuh API / Indexer     Uyuni API / CLI
  ansible-runner        (alerts, agents, vulns, (repos, patch jobs,
                        SCA, dashboards)         klp live-patch state)
        │
        ▼
  Ansible playbooks/roles
  hardening · patching · OpenSCAP · SELinux · Uyuni/klp · Wazuh agents
```

Key decisions:

1. **FastAPI (approved).** The product is API-first, so use a typed framework:
   Pydantic v2 contracts, dependency-injected RBAC, and an OpenAPI schema that
   generates the TypeScript client for the React app. The legacy Flask app is
   frozen during the transition and removed after UI parity.
2. **PostgreSQL + SQLAlchemy 2.0 + Alembic (approved).** SQLite is fine for
   tests, not for concurrent job state, KPI history, or audit trails.
3. **Redis + RQ for jobs.** Replace ad-hoc threads; support retries, timeouts,
   cancellation, concurrency limits, and multiple workers.
4. **New React SPA.** The current UI is a prototype. A typed SPA is the right
   foundation for dashboards, filters, and real-time updates.
5. **One API contract.** All UI data goes through `/api/v1`; the SPA never reads
   files or Wazuh directly.
6. **No synthetic KPIs.** A KPI is either derived from a real source and stored
   with provenance, or it is shown as “not configured”.
7. **Uyuni replaces KernelCare; OpenUBA is not deployed.** Uyuni is the only new
   external component. KernelCare is dropped because it is commercial. Wazuh
   Dashboard/Indexer already provides supervision, correlation, and behavioral
   analytics, so no separate OpenUBA stack is added.

---

## 2. Frontend plan

### Recommended stack

| Concern | Choice |
|---|---|
| Framework | React 19 + TypeScript |
| Build | Vite |
| Routing | React Router v7 |
| Server state | TanStack Query v5 |
| Forms | React Hook Form + Zod |
| Styling | Tailwind CSS v4 + shadcn/ui (Radix) |
| Icons | lucide-react |
| Charts | Recharts (simple) / ECharts (dense security charts) |
| Tables | TanStack Table |
| Real-time | Server-Sent Events (existing `/events`, upgraded) |
| Tests | Vitest + React Testing Library + Playwright |
| Lint/format | ESLint + Prettier |

### Why a SPA (and not Next.js)

- No SEO or server-rendered marketing content is needed.
- The app is a stateful internal console behind authentication.
- Static assets + nginx is simpler and cheaper to operate than a Node server.
- Vite’s dev proxy keeps `/api` and `/events` painless.
- If SSR is ever needed, the same React code can move to Next.js later.

### Information architecture

1. **Overview** — health, coverage, compliance score, open criticals, patch
   status, active deployments, recent alerts.
2. **Hosts** — inventory, per-host posture, groups, environments, last scan,
   agent status; host detail drawer with hardening/SELinux/patch/compliance tabs.
3. **Deployments** — run history, live log streaming, filter by status/host,
   retry/cancel, duration, success rate.
4. **Compliance** — OpenSCAP scans, profile selection, score trend, failed rules.
5. **Patching** — pending CVEs, Uyuni patch runs, klp live-patch state, reboot
   queue.
6. **Detection** — Wazuh alerts, severity, agent health, active-response actions.
7. **Settings** — Wazuh connection, environments, playbook allowlist, maintenance
   windows, retention, notification channels, secrets are write-only.
8. **Audit & Users** — audit trail, roles, sessions.

### UI principles

- Dense but calm: tables + summary cards, no decorative dashboards.
- Every number is clickable through to the underlying records.
- Explicit empty/unknown states (“Wazuh not configured”), never fake values.
- Destructive actions require confirmation and are audited.
- Keyboard-first navigation for operators.
- Dark and light themes; WCAG AA contrast.

### Frontend milestones

- **F1** — shell, auth, routing, design tokens, API client, error boundary.
- **F2** — overview + hosts + deployments (parity with current UI).
- **F3** — compliance + patching + detection views.
- **F4** — settings, audit, users, reports/export.
- **F5** — Playwright E2E, accessibility pass, performance budget.

---

## 3. Backend plan

### 3.1 Structure (approved baseline)

The new backend lives in `backend/` and runs beside the frozen legacy `app/`
until the React UI reaches parity. After cutover, `app/`, `__web_ui_legacy/`,
and the legacy `ansible` compose service are deleted.

```text
backend/
  main.py                # FastAPI factory + lifespan
  config.py              # pydantic-settings, validated env
  db.py                  # engine, session factory, session_scope
  models.py              # SQLAlchemy 2.0 models
  schemas.py             # Pydantic v2 request/response models
  security.py            # hashing, JWT sessions, RBAC, CSRF
  api/
    deps.py
    auth.py  hosts.py  groups.py  environments.py
    playbooks.py  deployments.py  kpis.py
    compliance.py  patching.py  alerts.py
    settings.py  users.py  audit.py
    health.py
  services/
    ansible_service.py     # command building, execution, log capture
    inventory_service.py   # generate inventory YAML from DB
    playbook_service.py    # DB source of truth + materialize to disk
    deployment_service.py  # lifecycle + queue enqueue
    wazuh_service.py       # API + indexer client (httpx, async)
    oscap_service.py       # scan + result ingestion
    uyuni_service.py       # systems, channels, errata, patch jobs
    livepatch_service.py   # klp state and kernel exposure
    hardening_service.py   # baseline + drift
    kpi_service.py         # definitions + snapshots
    audit_service.py
    auth_service.py
  workers/
    deployment_worker.py
    scan_worker.py
  alembic/
    env.py
    versions/
  tests/
```

Rules: routers validate and delegate; services hold domain logic; models own
persistence; no DB calls from routes or Ansible code.

### 3.2 Data model (core tables)

| Table | Purpose |
|---|---|
| `users`, `roles`, `user_roles`, `sessions` | auth + RBAC |
| `environments` | name, description, default inventory path |
| `host_groups` | group metadata (replaces comma-separated column) |
| `hosts` | name, ip, environment, status, agent_id, os, last_seen |
| `host_group_members` | host ↔ group |
| `playbooks` | filename, checksum, owner, allowlisted |
| `deployments` | job_id, playbook, environment, status, timings, requested_by |
| `deployment_targets` | deployment ↔ host |
| `deployment_events` | structured log lines/state transitions |
| `kpi_snapshots` | metric, scope, value, source, captured_at |
| `compliance_scans` | host, profile, started/finished, score, artifact path |
| `compliance_findings` | scan ↔ rule, result, severity, remediation |
| `patch_runs` | host, scope, status, source (`uyuni`/ansible), timings |
| `patch_findings` | host, package, current/fixed version, CVE, errata, severity |
| `uyuni_systems` | host, Uyuni system id, channels, last sync |
| `livepatch_status` | host, kernel, klp patch state, exposure days |
| `hardening_checks` | host, control, expected/actual, status |
| `alerts` | normalized Wazuh alerts (retention-limited) |
| `incidents` | correlated alerts + lifecycle (optional v1.1) |
| `audit_log` | actor, action, target, before/after, request_id, ip, time |
| `settings` | non-secret config; secrets live in a secret store |

Use UUIDs for jobs, integer PKs elsewhere. Every table gets `created_at` /
`updated_at`; destructive operations are soft-deleted or audited.

### 3.3 API surface (v1)

```text
POST   /api/v1/auth/login            POST /api/v1/auth/logout
GET    /api/v1/auth/me
GET    /api/v1/overview
GET    /api/v1/hosts                 POST /api/v1/hosts
GET    /api/v1/hosts/:id             PATCH /api/v1/hosts/:id
DELETE /api/v1/hosts/:id
GET    /api/v1/hosts/:id/posture
GET    /api/v1/environments          POST/PATCH/DELETE
GET    /api/v1/groups                POST/PATCH/DELETE
GET    /api/v1/playbooks             POST /api/v1/playbooks
GET    /api/v1/playbooks/:name       PUT/DELETE
GET    /api/v1/deployments           POST /api/v1/deployments
GET    /api/v1/deployments/:id
POST   /api/v1/deployments/:id/cancel
POST   /api/v1/deployments/:id/retry
GET    /api/v1/deployments/:id/log   (streaming, authenticated)
GET    /api/v1/kpis?scope=&range=
GET    /api/v1/compliance/scans      POST /api/v1/compliance/scans
GET    /api/v1/compliance/scans/:id
GET    /api/v1/patching/findings     POST /api/v1/patching/runs
GET    /api/v1/patching/uyuni        GET /api/v1/patching/livepatch
GET    /api/v1/alerts                POST /api/v1/alerts/:id/ack
GET    /api/v1/agents                GET /api/v1/agents/summary
GET    /api/v1/settings              PUT /api/v1/settings
GET    /api/v1/audit
GET    /api/v1/users                 POST/PATCH/DELETE
GET    /api/v1/health                GET /api/v1/ready
GET    /api/v1/events                (SSE)
```

Conventions: JSON only, ISO-8601 UTC timestamps, cursor pagination, stable error
codes (`{code, message, details, request_id}`), 4xx for validation, 409 for state
conflicts.

### 3.4 Auth and authorization

- Server-side sessions (HttpOnly, Secure, SameSite=Lax) stored in Redis.
- CSRF token required for state-changing requests.
- Roles: `admin`, `operator`, `auditor`, `viewer`.
- Permission matrix enforced in a decorator + service layer, not only in UI.
- Optional OIDC (Authentik/Keycloak) as the identity provider for enterprises.
- Rate-limit login and expensive actions; lockout after repeated failures.
- API tokens (scoped, hashed at rest) for automation.

### 3.5 Jobs and Ansible execution

- Enqueue deployments in Redis/RQ; worker picks up.
- Per-environment concurrency lock; global concurrency limit.
- Timeouts, retries with backoff, cancellation, and orphan cleanup.
- Stream logs to Redis and persist structured events.
- Build commands from validated inputs only; always apply `--limit` for targets.
- Keep `become` explicit; store privilege policy per playbook.
- Record actor, checksum, inventory hash, and Ansible version per run.

### 3.6 Configuration

- `pydantic-settings` validates every env var at startup; fail fast.
- Secrets from Docker secrets, Vault, or the platform secret store.
- Settings UI can edit non-secrets; secrets are write-only and never returned.
- Wazuh and Uyuni connection test endpoints (`/settings/wazuh/test`,
  `/settings/uyuni/test`).

### 3.7 Implemented foundation (2026-11-06)

The first Phase-1 slice is in `backend/` and covered by 31 backend tests:

- FastAPI app factory, Pydantic v2 settings, structured error envelope.
- SQLAlchemy 2.0 models for users, sessions, environments, groups, hosts,
  playbooks, deployments, deployment targets/events, KPI snapshots, audit log.
- Alembic baseline migration, verified upgrade/downgrade on SQLite.
- Revocable server-side sessions stored in PostgreSQL; JWT in an HttpOnly
  cookie; double-submit CSRF for all mutating API calls.
- Roles `admin`, `operator`, `auditor`, `viewer` enforced with dependencies.
- `/api/v1`: auth, hosts, playbooks, deployments, logs, events, KPI overview,
  audit. Hosts/groups/environments are created from validated host payloads.
- Playbooks are DB-backed and materialized to a private runtime directory;
  bundled playbooks are seeded from a separate read-only directory.
- Inventories are generated from the DB; deployments always pass `--limit`.
- Redis/RQ queue abstraction with an in-process fallback for development.
- `docker-compose.v2.yml` for PostgreSQL + Redis + API + worker.

Deliberate deviations from the target in this slice:

- Sessions are in PostgreSQL, not Redis. This removes a dependency for auth and
  is easy to move later; revocation already works.
- Login rate limiting, API tokens, OIDC, cancellation/retry, and SSE streaming
  are not implemented yet.
- The React SPA and Wazuh/OpenSCAP/KernelCare clients are still pending.

---

## 4. Layer implementation

### 4.1 Hardening

- New `taskengine/roles/hardening` with check-mode support:
  - SSH: root login, password auth, ciphers/MACs/KEX, idle timeout.
  - Kernel/sysctl: network and memory hardening, ASLR.
  - auditd: immutable rules, key coverage for identity/privilege/network.
  - PAM/login: password quality, lockout, umask.
  - Services/packages: disable legacy services, remove risky packages.
- SELinux: mode (enforcing/permissive/disabled), booleans, policy modules;
  collect `sestatus`, `getenforce`, `semanage boolean -l`.
- Persist per-control results → drift score; show on host detail and overview.
- Provide “check”, “apply”, and “remediate selected controls only”.

### 4.2 Patching / KernelCare

- KernelCare: install agent, license from secret, verify `kcarectl --info`,
  track kernel version vs patched state, surface exposure days.
- Package patching: CVE-driven runs using Wazuh vulnerability data; allow
  security-only vs full upgrade.
- Maintenance windows, reboot gating, pre/post health checks, rollback notes.
- Patch compliance KPI: pending, applied, failed, reboot required.

### 4.3 OpenSCAP compliance

- Real profiles under `config/openscap/profiles/` (CIS Ubuntu/RHEL baseline).
- Playbook: install `openscap-scanner`, run `oscap xccdf eval`, fetch ARF/OVAL.
- Ingest results: score, per-rule pass/fail, severity, remediation text.
- Store artifacts, checksum them, retain per policy.
- Compliance view: trend, worst hosts, top failed rules, export CSV/JSON.

### 4.4 Detection / response (Wazuh)

- Deploy agents via a real playbook using the vendored role, with manager
  address/port and enrollment mode as variables.
- Read agents, alerts, vulnerabilities, and SCA through the Wazuh API and
  indexer; cache and back off on failure.
- Normalize alerts into the platform; map severities.
- Enable active response (firewall-drop, disable-account) behind an allowlist;
  require explicit operator confirmation for destructive actions.
- Agent health KPI: connected, disconnected, never connected, outdated.

### 4.5 OpenUBA

- Deploy OpenUBA as an optional Compose profile.
- Feed normalized audit/Wazuh events; store anomaly scores against hosts.
- Surface anomalies as a detection source; link to incidents in a later release.

---

## 5. Supervision and KPI model

Every KPI stores: definition, scope, value, source, timestamp, and whether it is
`ok`, `unknown`, or `stale`. Never show a synthetic value.

| KPI | Definition | Source |
|---|---|---|
| Agent coverage | connected agents / hosts | Wazuh |
| Disconnected agents | count, age | Wazuh |
| Compliance score | passed rules / evaluated rules | OpenSCAP |
| Worst hosts | lowest score | OpenSCAP |
| Open critical/high vulns | count by severity | Wazuh |
| MTTR | mean time from first seen to resolved | Wazuh + platform |
| Patch coverage | hosts with no pending security patches / hosts | Patching |
| Reboot required | count | Patching |
| Kernel exposure | days since vulnerable kernel released | KernelCare |
| Hardening drift | hosts with failed controls | Hardening |
| SELinux non-compliant | hosts not enforcing | SELinux |
| Deployment success rate | succeeded / finished in range | Platform |
| Deployment duration | p50/p95 | Platform |
| Alert volume | by severity, by host | Wazuh |
| MTTD / MTTR incidents | detection/response time | Platform |

Delivery:

- `kpi_snapshots` written by a scheduled job and on state changes.
- Retention policy per metric (e.g. raw 30 days, hourly 1 year).
- Overview shows current + trend; host detail shows per-host history.
- Reports: scheduled PDF/CSV export.

---

## 6. Infrastructure and operations

### Compose profiles

- `core`: api, web, postgres, redis, worker, nginx.
- `wazuh`: manager, indexer, dashboard (existing).
- `openuba`: optional analytics stack.
- `dev`: sqlite + mock Wazuh adapter, no TLS.

### Production requirements

- PostgreSQL backups (daily + PITR), restore drills.
- Redis persistence for job state.
- TLS everywhere; HSTS; secure cookies.
- Containers run non-root, read-only root FS where possible; no Docker socket.
- Resource limits and healthchecks on every service.
- Log rotation and centralized logs.
- Prometheus metrics + OpenTelemetry traces; Sentry optional.
- Blue/green or rolling upgrade path for API/worker.

### CI/CD

- Backend: `ruff`, `mypy`, `pytest` (unit + integration), coverage gate.
- Frontend: `eslint`, `tsc --noEmit`, `vitest`, Playwright, build.
- Docker build + Trivy scan; SBOM.
- Migration check (`alembic upgrade head` on a scratch DB).
- Deploy to staging, run smoke tests, then promote.

---

## 7. Sequencing and effort

| Phase | Scope | Exit criteria | Effort |
|---|---|---|---|
| 0 | Phase-0 fixes (targeting, form, persistence) | UI changes survive restart; selected hosts respected | 2–3 days |
| 1 | Foundation: settings, Postgres/Alembic, sessions/RBAC, `/api/v1`, audit | Login works; all writes audited; migrations run | 2–3 weeks |
| 2 | Jobs: RQ/Redis, retries, cancel, log streaming | Deployments survive restart; cancel/retry work | 1–2 weeks |
| 3 | Frontend shell + parity (overview/hosts/deployments) | New UI replaces old one with no feature loss | 3–4 weeks |
| 4 | Wazuh integration + detection KPIs | Real agent/alert/vuln data in UI | 2 weeks |
| 5 | Hardening + SELinux | Baseline apply/check/drift on a test host | 2–3 weeks |
| 6 | OpenSCAP compliance | Real scan + score + findings view | 2–3 weeks |
| 7 | Patching + KernelCare | Patch runs + kernel exposure KPI | 2–3 weeks |
| 8 | Remaining UI (compliance/patching/settings/audit) + reports | Full operator workflow | 3 weeks |
| 9 | OpenUBA + anomalies | Anomaly source visible in detection | 2–3 weeks |
| 10 | Production hardening, E2E, docs, runbooks | Staging sign-off + DR drill | 2–3 weeks |

Total: roughly **18–26 person-weeks**. With two engineers in parallel
(backend/infra and frontend), expect **10–14 calendar weeks** plus hardening
buffer.

Suggested order of attack if only one engineer: **1 → 2 → 4 → 3 → 5 → 6 → 7 → 8 → 9 → 10**.
Ship backend contracts first so the SPA is built against stable APIs.

---

## 8. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Wazuh API version drift | Pin 4.12, wrap the client, contract tests |
| Ansible privilege escalation | Explicit `become` policy, allowlisted playbooks, audit |
| Secrets in UI logs | Write-only secret fields, redaction in logs/errors |
| KernelCare licensing/offline | Feature flag; surface “not configured” instead of failing |
| OpenUBA maturity | Optional profile; isolate failures from core KPIs |
| Scope creep across five layers | Phase gates; each phase has a demo + exit criteria |
| Data volume from alerts | Retention + aggregation; store summaries, not raw firehose |
| SQLite → Postgres migration | Alembic from day one; migration test in CI |
| UI rewrite stalling delivery | Build parity first, then new views; keep old UI until cutover |

---

## 9. Immediate next steps (this sprint)

- [x] Session auth, RBAC, CSRF, and audit logging in the new backend.
- [x] PostgreSQL + SQLAlchemy + Alembic baseline.
- [x] `/api/v1` for auth, hosts, playbooks, deployments, KPIs, and audit.
- [x] Redis/RQ deployment queue (in-process fallback for local development).
- [x] Explicit unknown KPI states (`open_vulnerabilities`, `compliance_score`).
- [ ] Scaffold `web/` with Vite + React + TS + Tailwind + shadcn and build the
      Overview/Hosts/Deployments parity views against `/api/v1`.
- [ ] Add login rate limiting, API tokens, and cancellation/retry.
- [ ] Add SSE deployment log streaming and KPI history charts.
- [ ] Add CI (pytest + ruff + mypy + tsc + vitest) before Wazuh integration.
- [ ] Freeze/retire the legacy Flask UI only after React parity is verified.
