# LinSec360 implementation roadmap

This roadmap turns the five-layer scope (hardening, patching, detection/response,
orchestration, supervision) into ordered, testable work. It reflects the current
state of the repository, not the target marketing description.

## Current state (baseline)

| Layer | State | Notes |
|---|---|---|
| Orchestration | Functional MVP + v1 backend | Legacy Flask runner still exists; new FastAPI service has auth, RBAC, DB-backed playbooks, generated inventories, and RQ/thread queue |
| Supervision | Foundation | New `/api/v1/kpis/overview` reports DB metrics and explicit unknowns; history/trends pending |
| Detection/response | Partially deployed | Wazuh stack runs, but agents are not deployed by any playbook and the app never reads Wazuh |
| Patching | Basic | `system-update.yml` and `disk-cleanup.yml` only; Uyuni + klp not integrated |
| Hardening | Not implemented | SELinux/audit config files are empty; no baseline role |
| OpenSCAP | Not implemented | Profile/report files are empty placeholders |
| Uyuni | Not implemented | Replacement for KernelCare: repos, patch jobs, and klp live-patch state |
| Analytics | Covered by Wazuh | No OpenUBA deployment; correlation/behavioral views come from Wazuh Dashboard/Indexer |

Scope rule: Uyuni is the only new external component. KernelCare is removed
because it is commercial. OpenUBA is not deployed; Wazuh Dashboard/Indexer is
the supervision/SIEM and behavioral-analytics layer.

## Implemented v1 backend foundation (2026-11-06)

- [x] FastAPI + Pydantic v2 app factory in `backend/`.
- [x] PostgreSQL/SQLAlchemy 2.0 models + Alembic baseline.
- [x] HttpOnly session cookies, server-side revocation, CSRF, RBAC, audit log.
- [x] `/api/v1` auth, hosts, playbooks, deployments/logs/events, KPIs, audit.
- [x] DB-backed playbooks with validated filenames and private materialization.
- [x] Inventory generated from the DB; `--limit` always applied to targets.
- [x] Redis/RQ queue with an in-process dev fallback; migration + worker in
      `docker-compose.v2.yml`.
- [x] Compose smoke test on PostgreSQL 16 + Redis 7 + RQ 3.0 + ansible-core
      2.18: a queued deployment ran end to end and updated host/deployment state.
- [x] No synthetic KPIs: `open_vulnerabilities` and `compliance_score` are
      returned as `unknown` until real sources are connected; the legacy UI now
      shows `—` for vulnerabilities instead of a fabricated count.
- [ ] React SPA parity for Overview/Hosts/Deployments.
- [ ] Login rate limiting, API tokens, cancel/retry, SSE log streaming.
- [ ] Retire the legacy Flask app after UI parity.

## Phase 0 — make the existing product trustworthy (in progress)

- [x] Align the host form security-level values with backend validation.
- [x] Apply `--limit` so deploying selected hosts/groups targets only those hosts.
- [x] Persist SQLite DB, inventories, and playbooks across container recreation.
- [x] Add authentication, RBAC, and CSRF to the new FastAPI API.
- [x] Remove fabricated `vulnerabilities_count` from the new KPI endpoint.
- [x] Count `queued` jobs in "active deployments" in the new KPI endpoint.
- [ ] Retire the legacy Flask UI/API (still reachable until parity).
- [ ] Fix `deploy.sh`, `backup.sh`, and the empty `restore.sh`.
- [ ] Add `pytest` to a dev requirements file and run tests in CI.

**Done when:** no KPI is synthetic, only authorized users can act, and UI changes
survive a `docker compose down && up`.

## Phase 1 — Wazuh integration (supervision + detection)

- [ ] Add a Wazuh API client (`WAZUH_API_URL`, `WAZUH_API_USERNAME`,
      `WAZUH_API_PASSWORD` from the environment; never hardcoded).
- [ ] Expose read-only endpoints: agents, agent coverage, alerts by severity,
      vulnerability summary, SCA summary.
- [ ] Store KPI snapshots in the DB for trend/history instead of reading live only.
- [ ] Deploy agents from a real playbook that applies
      `taskengine/roles/wazuh/ansible-wazuh-agent`, with the manager address as a
      variable.
- [ ] Enable and document active-response (firewall-drop, disable-account) with an
      explicit allowlist.

**Done when:** the dashboard shows real agent, alert, vulnerability, and SCA data
with no manual Wazuh navigation required.

## Phase 2 — hardening layer

- [ ] Create `taskengine/roles/hardening` with: SSH baseline, sysctl, auditd rules,
      login/umask/password policy, package baseline, file permissions.
- [ ] Implement SELinux management (mode, booleans, policy) from
      `config/selinux/`; support `--check` / diff mode and drift reporting.
- [ ] Add a `hardening.yml` playbook with `--check` support and per-host results.
- [ ] Persist hardening results and expose a drift/score view.

**Done when:** a host can be hardened, re-checked, and reported as compliant or
drifted, with SELinux state visible.

## Phase 3 — compliance (OpenSCAP)

- [ ] Populate real profiles under `config/openscap/profiles/` (CIS Ubuntu/RHEL).
- [ ] Add a playbook that installs `openscap-scanner`, runs `oscap xccdf eval`,
      and retrieves ARF/OVAL results.
- [ ] Parse results into per-rule pass/fail plus an aggregate compliance score.
- [ ] Add a compliance view and export (CSV/JSON).

**Done when:** a scan produces a real score and rule-level findings stored in the
platform.

## Phase 4 — patching layer (Uyuni + klp)

- [ ] Integrate Uyuni as the patch/repository control plane: system registration,
      channel/repository assignment, package and errata inventory.
- [ ] Schedule and track traditional patch runs from Uyuni; map them to
      LinSec360 deployments and audit events.
- [ ] Surface free native kernel live-patching state (klp) per host, including
      current kernel, live-patch availability, and exposure days.
- [ ] Drive patching from CVE data (Wazuh vulnerability detection) rather than
      "update everything".
- [ ] Add maintenance windows, reboot gating, and pre/post health checks.
- [ ] Track patch compliance: pending, applied, failed, reboot required.

**Done when:** package and kernel exposure are measurable from Uyuni/klp and
patch runs are auditable.

## Phase 5 — supervision and KPI model

Define and track, per host and globally:

- agent coverage and disconnected agents
- compliance score and failed rules (OpenSCAP)
- open critical/high vulnerabilities and mean time to remediate
- patch coverage, reboot-required hosts, kernel exposure days (Uyuni + klp)
- hardening drift count (SELinux/audit/SSH)
- deployment success rate, duration, and failure reasons
- alert volume by severity and mean time to detect/respond

- [ ] Add time-series storage and retention.
- [ ] Add dashboards, filters, and scheduled reports.
- [ ] Add an immutable audit log for every action.

## Phase 6 — supervision analytics (Wazuh)

No separate analytics platform is deployed. Wazuh Dashboard/Indexer already
provides correlation and behavioral views; this phase hardens and extends it.

- [ ] Add correlation rules and dashboards for authentication, privilege
      escalation, process execution, and file-integrity events.
- [ ] Surface Wazuh anomalies and alerts in the LinSec360 host/incident views.
- [ ] Track mean time to detect/respond from Wazuh alert and active-response
      records.
- [ ] Document retention, index templates, and alert tuning.

## Phase 7 — production readiness

- [x] PostgreSQL schema, Alembic migrations, queue-backed worker (RQ), and a
      development thread fallback.
- [ ] Retries, cancellation, per-environment concurrency, and orphan cleanup.
- [ ] Secrets manager, TLS everywhere, least-privilege containers.
- [ ] Backup/restore drills, HA, upgrade path, and observability (metrics/traces).

## Working rules

- Every change gets a test; fixes start from a failing test.
- One source of truth per behavior.
- No synthetic data in security KPIs.
- Keep routes thin; business logic in services, DB access in repositories.
