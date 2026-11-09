# Product security workflow

## Product goal

LinSec360 is an operator console for continuous Linux security operations. It
combines inventory, detection, vulnerability management, compliance, patching,
orchestration and audit into one controlled workflow.

The product is not a replacement for Wazuh Dashboard, Uyuni or Ansible:

| Component | Product responsibility |
|---|---|
| Wazuh | Linux agents, detection events, vulnerability telemetry, behavioral analytics |
| Uyuni | Repositories, systems, channels, errata and patch activation |
| OpenSCAP | Independent compliance evaluation and rule-level evidence |
| SELinux / system hardening | Local configuration and drift evaluation |
| Native live patching | Kernel live-patch state without a commercial subscription |
| Ansible | Check-mode previews and auditable remediation execution |
| FastAPI | Authorization, validation, correlation, job state and audit |
| React | Operator navigation and execution controls |
| PostgreSQL | Durable source of truth for normalized findings and job history |
| Redis/RQ | Durable and cancellable security automation jobs |

KernelCare and OpenUBA are deliberately excluded. Uyuni replaces KernelCare.
Wazuh Indexer and Dashboard provide the native correlation, search and
behavioral-analysis layer previously associated with OpenUBA.

## Recommended operational loop

```text
Wazuh detects a signal or Uyuni/OpenSCAP reports drift
                    |
                    v
LinSec360 synchronizes and normalizes the source data
                    |
                    v
Resolve the source agent/system to a LinSec360 host
                    |
                    v
Correlate alerts, vulnerabilities, patch findings and compliance drift
                    |
                    v
Create or update an actionable incident
                    |
                    v
Generate an allowlisted remediation proposal
                    |
                    v
Preview with Ansible --check when supported
                    |
                    v
Validate environment, maintenance window and operator permissions
                    |
                    v
Execute one validated playbook through Redis/RQ
                    |
                    v
Verify using Wazuh, OpenSCAP and Uyuni/native live-patch data
                    |
                    v
Resolve, retain or escalate the incident with an immutable audit record
```

Human approval is required initially for all critical actions. Automatic
execution must start only for explicitly allowlisted low-risk actions, with a
global concurrency limit and circuit breaker.

## Functional web surfaces

### Overview

- connected/disconnected Wazuh agents
- open critical and high findings
- average and worst-host OpenSCAP scores
- patch and reboot queues
- hardening drift
- active deployments
- recent incidents and audit activity

Every metric must show its source and use `unknown` or `not configured` instead
of a synthetic zero.

### Hosts

Each host detail page must provide:

- host identity, environment, group and operating system
- Wazuh agent ID, status and last keepalive
- compliance score and failed controls
- vulnerabilities and patch findings
- SELinux and hardening drift
- Uyuni system registration, channels and errata
- native live-patch state
- deployment history
- guarded actions for check, apply and remediation

The web UI must support create, edit, delete, environment assignment and
posture refresh before host workflows are considered complete.

### Incidents and detection

Alerts must be presented as correlated incidents, not only raw events. The
operator must be able to:

- synchronize agents and alerts
- filter by host, severity, rule, MITRE technique and date
- acknowledge or assign an alert
- associate it with a host and existing finding
- preview the recommended action
- approve an allowlisted active response
- follow the resulting deployment
- verify closure evidence

Initial allowed active responses are limited to explicit commands such as
`firewall-drop` and `disable-account`. Arbitrary command execution is prohibited.

### Compliance

The compliance workflow must include profile selection, host/group targeting,
check or real scan mode, live job status, rule-level results, scan comparison,
CSV/JSON/HTML export, remediation launch and scheduled recurring scans.

### Patching

The patching workflow must distinguish:

- vulnerability from Wazuh
- package or errata finding from Uyuni
- native package patching fallback
- live-patch capability
- reboot requirement
- post-patch verification

A package/patch run must show its preview, impact, maintenance window, approval,
deployment status and verification result.

### Deployments

A deployment form must select hosts/groups, playbook, mode and parameters from
allowlists. It must display check-mode preview, block disruptive actions outside
a maintenance window, expose live logs/events, support cancel/retry and require
actor/target/evidence in the audit record.

### Settings and audit

Settings must manage integration state, environment configuration, playbook
allowlists, maintenance windows, threshold policy, response allowlists, retention
and notification configuration. Secrets must be write-only.

Audit must record actor, source finding/alert, action, approval, targets,
playbook/checksum, mode, result, verification and request metadata.

## Uyuni integration direction

Uyuni is an external control plane and should initially be deployed and operated
separately from the LinSec360 web containers.

The current [Uyuni client](/home/olougbegnon/linsec360/backend/services/uyuni_service.py)
is a REST-shaped client, while Uyuni/SUSE Manager commonly exposes system and
errata operations through XML-RPC. The current protocol assumptions must not be
treated as production-compatible until contract tests are added against a real
Uyuni server.

Required next integration work:

1. Deploy or connect a real Uyuni instance.
2. Confirm the exact supported XML-RPC or REST gateway.
3. Replace the generic HTTP assumptions with a pinned protocol adapter.
4. Add authenticated connection, organization and TLS tests.
5. Synchronize systems, channels and relevant errata.
6. Map Uyuni systems by hostname or registered ID to LinSec360 hosts.
7. Add patch preview, approval and execution.
8. Verify applied errata and reboot state after the deployment.

A future Compose profile may include Uyuni containers, but only after supported
Uyuni container deployment, persistent storage, TLS and licensing/repository
requirements have been validated. Uyuni must not be added merely as an
unconfigured placeholder service.

## API documentation assessment (2026-11-06)

### Wazuh

The public Wazuh API documentation and getting-started documentation are
accessible at:

- https://documentation.wazuh.com/current/user-manual/api/getting-started.html
- https://documentation.wazuh.com/current/user-manual/api/reference.html

The integration can use these documented areas:

- `POST /security/user/authenticate`
- agent listing and agent status
- active response (`PUT /active-response`)
- vulnerability and SCA data through the API or normalized Indexer searches

The existing Wazuh API version and manager edition must be pinned. Requests and
payload schemas require contract tests because API additions and response shapes
change between releases.

### Uyuni/SUSE Manager

The Uyuni project documentation site and repository are public:

- https://www.uyuni-project.org/uyuni-docs/en/uyuni/index.html
- https://github.com/uyuni-project/uyuni
- https://documentation.suse.com/suma/

The main protocol is XML-RPC for the traditional Spacewalk/SUSE Manager API; the
integration must verify the exact server endpoints and supported method names.
No complete public Uyuni REST OpenAPI contract was available during this review
that directly matches the currently implemented `/auth/login`,
`/system/listSystems` and `/system/getRelevantErrata` assumptions.

The implementation therefore currently has client code and unit-level
normalization, but it has not yet been confirmed against a real Uyuni server.
It must not be described as fully integrated until a live contract test passes.

## Implementation phases

1. **Functional host workflow** — CRUD, detail posture, synchronization controls.
2. **Detection workflow** — incident detail, acknowledgement, proposal and
   operator-confirmed active response.
3. **Deployment workflow** — host targeting, check mode, live events, cancel/retry.
4. **Compliance workflow** — scan launch, profiles, rule detail and comparison.
5. **Patching workflow** — Uyuni contract, preview, approval and verification.
6. **Unified incident workflow** — alert/Vulnerability/CVE/OpenSCAP correlation.
7. **Reports and supervision** — KPI history, exports and schedules.
8. **Controlled automation** — allowlisted automatic actions after end-to-end drills.

## Exit criteria

The functional loop is complete when an operator can:

1. see a real Wazuh agent alert on a real LinSec360 host,
2. inspect correlated compliance and patch posture,
3. preview an allowlisted remediation,
4. approve and execute it through Ansible,
5. receive live deployment evidence,
6. verify the remediated state,
7. resolve or retain the incident,
8. retrieve a complete immutable audit trail.
