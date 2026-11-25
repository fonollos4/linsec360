# LinSec360 implementation roadmap

This roadmap turns the five-layer scope (hardening, patching, detection/response,
orchestration, supervision) into ordered, testable work. It reflects the current
state of the repository, not the target marketing description.

## Current state (baseline)

| Layer | State | Notes |
|---|---|---|
| Orchestration | Implemented | FastAPI service with auth/RBAC, DB-backed playbooks, generated inventories, RQ/thread queue, cancel/retry/SSE, and a working Ansible role/config path. |
| Supervision | Implemented core | `/api/v1/kpis/overview` and `/api/v1/kpis/history` combine and expose DB, Wazuh, OpenSCAP, hardening, and live-patch sources; snapshots are stored. Trend charts and reports remain. |
| Detection/response | Implemented | Agent playbook, Wazuh API/indexer sync, alert storage/acknowledgement, vulnerability KPIs, and active-response configuration guards. |
| Patching | Implemented (native) | `taskengine/roles/patching_option2` uses `dnf-automatic`, `unattended-upgrades`, optional Ubuntu Pro livepatch, and a Wazuh status check; reboots stay manual. |
| Hardening | Implemented | `taskengine/roles/hardening` and `taskengine/roles/hardening_mac` cover the shared baseline, SELinux/AppArmor, auditd/systemd/PAM/SSH/sysctl controls, check mode and drift ingestion. |
| OpenSCAP | Implemented | CIS Ubuntu/RHEL tailoring profiles, `taskengine/roles/hardening_openscap` with before/after XML+HTML reports, filtered remediation, ARF parsing, rule-level findings and aggregate score. |
| Uyuni | Retired | Removed from Compose, runtime config, worker extra vars and UI. Legacy backend modules and patching endpoints remain dormant for import compatibility. |
| Live patching | Implemented | Native `klp` via `/sys/kernel/livepatch`, with Ubuntu Pro `canonical-livepatch`/`kpatch` fallbacks; exposure days stay unknown unless supplied. |
| Analytics | Covered by Wazuh | No OpenUBA deployment; correlation/behavioral views come from Wazuh Dashboard/Indexer. |

Scope rule: KernelCare and Uyuni are retired. Native distribution patching and
live-patching are the supported path. OpenUBA is not deployed; Wazuh
Dashboard/Indexer is the supervision/SIEM and behavioral-analytics layer.

## Next functional product implementation

The remaining product gap is not infrastructure coverage but operator workflow.
Backend services exist for hosts, deployments, Wazuh, OpenSCAP, patching,
live-patching, alerts and audit, but each area must be exposed as a complete
actionable web workflow.

- [ ] Complete host CRUD and unified per-host posture.
- [ ] Complete playbook selection, check mode, approval and live deployment detail.
- [ ] Add Wazuh synchronization, incident detail and operator-confirmed response.
- [ ] Complete OpenSCAP launch, profile selection, comparison and remediation.
- [ ] Validate Wazuh patch findings and native update status in operator workflows.
- [ ] Complete patch preview, approval, execution and reboot verification.
- [ ] Correlate Wazuh alerts, CVEs, OpenSCAP drift and patch findings.
- [ ] Add scheduling and maintenance-window enforcement in operator workflows.
- [ ] Add immutable workflow evidence for detection, action and verification.
- [ ] Add an end-to-end test for alert → proposal → approval → Ansible → verification.

The target workflow and integration decisions are documented in
[`product-security-workflow.md`](architecture/product-security-workflow.md).

## Implemented backend foundation (2026-11-06)

- [x] FastAPI + Pydantic v2 app factory in `backend/`.
- [x] PostgreSQL/SQLAlchemy 2.0 models + Alembic migrations.
- [x] HttpOnly session cookies, server-side revocation, CSRF, RBAC, audit log.
- [x] `/api/v1` auth, tokens, hosts, playbooks, deployments/logs/events, KPIs,
      audit, agents, alerts, compliance, patching, hardening, integrations.
- [x] DB-backed playbooks with validated filenames and private materialization.
- [x] Inventory generated from the DB; `--limit` always applied to targets.
- [x] Redis/RQ queue with an in-process dev fallback; migration + worker in
      `docker-compose.v2.yml`.
- [x] Compose smoke test on PostgreSQL 16 + Redis 7 + RQ 3.0 + ansible-core
      2.18: a queued deployment ran end to end and updated host/deployment state.
- [x] No synthetic KPIs: unconnected sources return `unknown`; integrations
      return `503 integration_not_configured` rather than fabricated data.
- [x] Login rate limiting, hashed API tokens, deployment cancel/retry, and SSE
      log streaming.
- [x] React SPA parity for Overview/Hosts/Deployments.
- [x] Retire the legacy Flask app and UI.

## Phase 0 — make the existing product trustworthy

- [x] Align the host form security-level values with backend validation.
- [x] Apply `--limit` so deploying selected hosts/groups targets only those hosts.
- [x] Persist DB, inventories, and playbooks across container recreation.
- [x] Add authentication, RBAC, and CSRF to the FastAPI API.
- [x] Remove fabricated `vulnerabilities_count` from the KPI endpoint.
- [x] Count `queued` jobs in "active deployments".
- [x] Fix `deploy.sh`, `backup.sh`, and `restore.sh`.
- [x] Add `pytest` to a dev requirements file and run tests in CI.
- [x] Retire the legacy Flask UI/API.

**Done when:** no KPI is synthetic, only authorized users can act, and UI changes
survive a `docker compose down && up`.

## Phase 1 — Wazuh integration (supervision + detection)

- [x] Wazuh API client (`LINSEC_WAZUH_API_*` from the environment; never
      hardcoded).
- [x] Read-only endpoints: agents, agent coverage, alerts by severity,
      vulnerability summary.
- [x] Store KPI snapshots in the DB for trend/history.
- [x] Deploy agents from `wazuh-agent.yml` using
      `taskengine/roles/wazuh/ansible-wazuh-agent`, with the manager address as a
      variable.
- [x] Normalize alerts, store them, and expose acknowledgement.
- [x] Finish and document active-response tuning (firewall-drop, disable-account)
      with an explicit allowlist and operator confirmation.
- [x] Add Wazuh Manager, Indexer, and Dashboard services to the V2 Compose
      stack with generated certificates and private runtime configuration.

**Done when:** the dashboard shows real agent, alert, vulnerability, and SCA data
with no manual Wazuh navigation required.

## Phase 2 — hardening layer

- [x] `taskengine/roles/hardening` with SSH baseline, sysctl, auditd rules,
      login/password policy, package baseline, and service checks.
- [x] SELinux management (mode, booleans, policy) from `config/selinux/` with
      `--check` / diff mode and drift reporting.
- [x] `hardening.yml` with per-host JSON reports, plus the OpenSCAP scan /
  remediate / verify workflow that reports per-host compliance.
- [x] Persist hardening results and expose drift/score views.

**Done when:** a host can be hardened, re-checked, and reported as compliant or
drifted, with SELinux state visible.

## Phase 3 — compliance (OpenSCAP)

- [x] CIS Ubuntu/RHEL tailoring profiles under `config/openscap/profiles/`.
- [x] `openscap-scan.yml` installs the scanner, runs `oscap xccdf eval`, and
      retrieves ARF/OVAL results.
- [x] Parse results into per-rule pass/fail plus an aggregate compliance score.
- [x] Compliance endpoints, summaries, and HTML report templates.
- [x] CSV/JSON export endpoint for compliance scans.
- [x] Scheduled scans.

**Done when:** a scan produces a real score and rule-level findings stored in the
platform.

## Phase 4 — patching layer (native updates + livepatch)

- [x] `taskengine/roles/patching_option2` configures `dnf-automatic` in security
      mode with `apply_updates = yes` and `dnf-automatic.timer` on RedHat-family
      hosts.
- [x] Debian-family hosts use `unattended-upgrades` and
      `apt-daily-upgrade.timer`; no reboot is forced during working hours.
- [x] Ubuntu Pro livepatch uses the vaulted `ubuntu_pro_token` variable and
      `pro enable livepatch --assume-yes` only when needed.
- [x] `taskengine/roles/cleanup_uyuni` removes the retired Salt/Uyuni footprint
      while guaranteeing that SSH stays reachable.
- [x] CVE-driven findings from Wazuh and the Wazuh patching status command.
- [x] Track patch compliance: pending, applied, failed, reboot required.

See [`taskengine-automation.md`](architecture/taskengine-automation.md) for the
full baseline and verification commands.

**Done when:** native security updates are enabled and auditable through Wazuh,
SSH remains reachable, and reboots are never forced during working hours.

## Phase 5 — supervision and KPI model

Define and track, per host and globally:

- agent coverage and disconnected agents
- compliance score and failed rules (OpenSCAP)
- open critical/high vulnerabilities and mean time to remediate
- patch coverage, reboot-required hosts, kernel exposure days (native updates + klp/livepatch)
- hardening drift count (SELinux/audit/SSH)
- deployment success rate, duration, and failure reasons
- alert volume by severity and mean time to detect/respond

- [x] Add snapshot storage and retention settings.
- [x] Add KPI history API with metric, period, and limit filters.
- [x] Add trend dashboards; scheduled reports remain an operator-export feature pending a report scheduler.
- [x] Add an immutable audit log for every action.

## Phase 6 — supervision analytics (Wazuh)

No separate analytics platform is deployed. Wazuh Dashboard/Indexer already
provides correlation and behavioral views; this phase hardens and extends it.

- [ ] Add correlation rules and dashboards for authentication, privilege
      escalation, process execution, and file-integrity events.
- [x] Surface Wazuh alerts in the LinSec360 host/incident views.
- [x] Track mean time to detect/respond from Wazuh alert and active-response
      records.
- [x] Document retention, index templates, and alert tuning.

## Phase 7 — production readiness

- [x] PostgreSQL schema, Alembic migrations, queue-backed worker (RQ), and a
      development thread fallback.
- [x] Retries, cancellation, and SSE streaming.
- [x] Backup/restore scripts with checksums, retention, and safe restore.
- [x] Per-environment concurrency locks and orphan cleanup.
- [ ] Secrets manager, TLS everywhere, least-privilege containers.
- [ ] Restore drills, HA, and upgrade path.
- [x] Basic Prometheus observability endpoint and React SPA/nginx gateway.
- [ ] Production TLS certificates and secrets manager integration.

## Working rules

- Every change gets a test; fixes start from a failing test.
- One source of truth per behavior.
- No synthetic data in security KPIs.
- Keep routes thin; business logic in services, DB access in repositories.
