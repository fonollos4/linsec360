# LinSec360 Refactoring guide

This document is the concrete refactoring plan for the next agents working on this repository. It is intentionally practical: it describes what to change, why it matters, and in what order to do it.

The objective is not to add more complexity. The objective is to reduce accidental complexity and make the codebase understandable, scalable, and easier to operate.

---

## 1. Why this refactor is needed

The project already has a valid idea: a Flask dashboard that manages Linux hosts, inventories, Ansible playbooks, and Wazuh monitoring. That foundation is useful.

However, the current implementation mixes responsibilities in a way that makes future changes risky:

- routes handle business logic
- services are duplicated
- database access is embedded in the app layer
- inventory logic is intertwined with deployment logic
- scripts and app config are partially hardcoded
- secrets are not centralized
- background work is not strongly modeled

This makes the app less safe to extend and harder for new contributors to understand.

The goal of the refactor is to make the project behave like an operational platform, not a demo application.

---

## 2. Refactoring principles

All work must follow these rules:

### 2.1 One source of truth
If the same behavior exists in two places, consolidate it.

Current problem:
- deployment behavior exists in `app/services.py` and in `app/services/deployment_service.py`

Rule:
- the authoritative implementation must be unique
- all callers must import that single implementation

### 2.2 Keep routing thin
Routes should validate input and delegate to services.

Bad pattern:
- route directly reads/writes database and stock inventory files

Good pattern:
- route calls a service method like `HostService.create_host(payload)`

### 2.3 Separate layers clearly
Each module should have a single responsibility.

Recommended boundaries:

- `app/` → app factory, config, bootstrap
- `app/api/` → request/response handlers
- `app/services/` → orchestration and business logic
- `app/repositories/` → SQLite access
- `app/models/` → data objects
- `app/validators/` → validation logic
- `app/tasks/` → background jobs / workers
- `app/utils/` → logging, filesystem helpers, common utilities

### 2.4 Use explicit state
Do not store hidden job status in global variables when a database or job registry can represent the state more cleanly.

### 2.5 Prefer readability
Do not introduce abstraction for abstraction's sake. If a method is understandable in a few lines, keep it simple.

---

## 3. Refactoring target structure

The code should eventually resemble the following layout:

```text
app/
  __init__.py
  app.py
  config.py
  cli.py
  api/
    __init__.py
    hosts.py
    playbooks.py
    deployments.py
    stats.py
  services/
    __init__.py
    host_service.py
    inventory_service.py
    playbook_service.py
    deployment_service.py
    stats_service.py
    event_service.py
  repositories/
    __init__.py
    host_repository.py
    stats_repository.py
  models/
    __init__.py
    host.py
    stats.py
  validators/
    __init__.py
    host_validator.py
    playbook_validator.py
  tasks/
    __init__.py
    deployment_worker.py
  utils/
    __init__.py
    logging.py
    filesystem.py
```

### Keep the existing project layout only if needed for compatibility
If the repo is still in transition, do not build a giant rewrite in one patch. Instead:

- create the new service/repository structure,
- redirect callers to it,
- remove the duplicate logic once behavior is validated.

---

## 4. Architectural cleanup plan

## Phase 1: Remove duplication and define the canonical service layer

### Goal
Eliminate multiple implementations of the same behavior.

### Tasks

1. Pick the canonical location for deployment logic.
   - Recommended: `app/services/deployment_service.py`
2. Move the business logic from `app/services.py` into that canonical service.
3. Remove or deprecate duplicate code in the root-level module.
4. Ensure all routes import from the same service.
5. Do not keep two implementations that compete with each other.

### Validation
- Run the app and confirm `/deploy` still works.
- Confirm host statuses update as expected.
- Confirm deployment logs are still created.

### Rule
After this phase, there should be no second deployment implementation in the repo.

---

## Phase 2: Split shared logic from web layer logic

### Goal
Make the Flask layer responsible only for HTTP concerns.

### Tasks

- Move database interaction out of route functions.
- Create repository classes for host and stats queries.
- Create service classes for domain logic and orchestration.
- Keep route functions thin and validation-oriented.

### Example
Instead of this:

```python
@app.route('/hosts')
def list_hosts():
    db = get_db()
    hosts = db.execute('SELECT * FROM hosts').fetchall()
    return jsonify([dict(host) for host in hosts])
```

Use this pattern:

```python
@app.route('/hosts')
def list_hosts():
    hosts = host_service.list_hosts()
    return jsonify(hosts)
```

And the service does the DB work through repositories.

---

## Phase 3: Introduce repository layer

### Goal
Centralize SQLite data access.

### New responsibilities

- `HostRepository` handles all host table access
- `StatsRepository` handles stats reads/writes
- service layer orchestrates business actions

### Pattern

```python
class HostRepository:
    def list_all(self):
        ...

    def create(self, host_data):
        ...

    def delete(self, host_id):
        ...

    def update_status(self, host_names, status):
        ...
```

### Why
This reduces hidden coupling between route code and database structure.

---

## Phase 4: make configuration explicit and secure

### Goal
Remove hardcoded runtime assumptions.

### Tasks

- Replace hardcoded paths with environment-driven settings.
- Centralize config in one settings object.
- Use `.env` or a real secrets manager for local/dev usage only.
- Move credentials out of source files.
- Ensure generated directories are created with safe permissions.

The Flask configuration supports `FLASK_SECRET`, `LINSEC_DB_PATH`,
`LINSEC_ANSIBLE_DIR`, `LINSEC_INVENTORY_DIR`, `LINSEC_PLAYBOOKS_DIR`, and
`LINSEC_LOG_DIR`; `LINSEC_LOG_API_TOKEN` optionally enables authenticated
deployment-log retrieval. When no database path is supplied, the database
remains in the Flask instance directory. Set `FLASK_SECRET` to a unique secret
outside local development.

### Preferred pattern

```python
import os

class Settings:
    SECRET_KEY = os.environ.get("FLASK_SECRET", "development-secret")
    DATABASE_PATH = os.environ.get("LINSEC_DB_PATH", "/var/lib/linsec/linsec.db")
    INVENTORY_DIR = os.environ.get("LINSEC_INVENTORY_DIR", "/opt/linsec/taskengine/inventories")
    LOG_DIR = os.environ.get("LINSEC_LOG_DIR", "/opt/linsec/logs")
    PLAYBOOKS_DIR = os.environ.get("LINSEC_PLAYBOOKS_DIR", "/opt/linsec/taskengine/playbooks")
```

### Explicit rule
No credentials, passwords, APIs, or hostnames should be committed in code.

---

## Phase 5: normalize validation logic

### Goal
Use a single validation layer for all user-managed inputs.

### Tasks

- Validate IP addresses in one place.
- Validate playbook names in one place.
- Validate inventory/environment names before writing files.
- Reject invalid filenames and paths.
- Sanitize strings before touching disk.

### Good pattern

```python
class HostValidator:
    @staticmethod
    def validate_ip(ip):
        ...

    @staticmethod
    def validate_host_name(name):
        ...
```

### Rule
No untrusted input should reach an Ansible inventory or a filesystem path without validation.

---

## Phase 6: create structured background task handling

### Goal
Make long-running jobs explicit and monitorable.

### Current state
The app uses threads directly in deployment logic. That is acceptable for small prototypes, but not for scale.

### Better model
Use one of the following:

- a job registry with explicit state
- a queue worker system such as Celery or RQ
- a lightweight task abstraction for job state tracking

### Required job metadata
Each job should store:

- id
- environment
- playbook
- target hosts
- status
- created_at
- started_at
- finished_at
- logs path
- error message

### Rule
Background jobs must be traceable and introspectable.

---

## Phase 7: improve logs and observability

### Goal
Make deployments observable and debuggable.

### Required improvements

- structured log entries
- timestamped deployment logs
- environment metadata in logs
- playbook name and target host names in logs
- clear HTTP status and failure information
- `/health` endpoint
- readiness endpoint for dependencies

### Example log record

```python
logger.info(
    "deployment_started",
    extra={
        "environment": environment,
        "playbook": playbook,
        "hosts": target_hosts,
    },
)
```

### Rule
Do not log opaque single-line strings without context.

---

## Phase 8: clean up the frontend boundary

### Goal
Make the UI easier to maintain.

### Existing problems
The frontend script in `app/static/js/script.js` mixes:

- DOM updates
- API calls
- state tracking
- SSE handling
- notifications
- rendering logic

### Better structure
Split the client-side code into:

- API client functions
- state management
- rendering functions
- notification helpers
- deployment target logic

### Result
The frontend should be easier to reason about and less likely to break when the app changes.

---

## 5. Testing strategy to introduce

The repository needs a real test pyramid.

### Unit tests
Write tests for:

- IP validation
- playbook filename validation
- inventory generation rules
- status transitions
- database update logic

### Integration tests
Write tests for:

- SQLite operations with temp database
- Ansible inventory file generation
- playbook file creation/update/delete

### End-to-end tests
Write tests for:

- `/deploy` route
- status changes
- SSE updates
- deployment log creation

### TDD rule
Every bug fix should start with a failing test.

---

## 6. Security and operational hardening

Security automation must be stricter than a typical web app.

### Required rules

- never commit secrets
- validate all inputs at the boundary
- sanitize playbook and filename paths before writing
- restrict permissions for generated files and directories
- avoid running privileged actions without explicit checks
- ensure SSH and inventory generation are based on validated data only
- secure Docker and Wazuh defaults

### Required follow-up

- health checks for Docker services
- TLS/certificate validation workflow
- clearer SSH trust configuration
- explicit least-privilege patterns for automation

---

## 7. Safe migration sequence

Do not rewrite everything in one commit.

### Recommended order

1. Define config object and environment loading
2. Consolidate deployment logic into one service
3. Add repository layer for host and stats access
4. Move business logic out of routes
5. Add validations and sanitization
6. Add tests for current behavior
7. Improve logging and monitoring
8. Refactor frontend structure
9. Harden security and operational workflows

## 8. Implemented refactor foundations

The application now validates host, environment, group, IP, security-level, and
playbook inputs before database or filesystem operations. Inventory writes use
private temporary files and atomic replacement; generated inventory and
playbook files are restricted to owner access.

Host, stats, and deployment-job SQL is owned by repositories. Deployment jobs
are persisted in SQLite with queued/running/succeeded/failed state, timestamps,
target hosts, error details, and an internal log path. The HTTP API exposes
`/health`, `/ready`, `/deployments`, `/deployments/<job_id>`, and a bounded
`/deployments/<job_id>/log` endpoint. Background workers run in a Flask
application context so database access and logging work outside the request
thread.

The dashboard client is split between `static/js/api.js` for HTTP requests,
`static/js/state.js` for page state, `static/js/deployment.js` for target
selection, `static/js/render.js` for DOM rendering,
`static/js/notifications.js` for notifications, and `static/js/script.js` for
interaction and SSE wiring. User-provided text is rendered as text rather than
HTML.

Wazuh demo credentials have been removed from Compose and mounted config
files. Compose now requires credentials in an ignored root `.env`; run
`python3 config/scripts/render-wazuh-config.py` before manual Compose startup.
The renderer requires precomputed bcrypt hashes and writes runtime config
files beneath the ignored, owner-only `config/wazuh/generated/` directory. The deployment
script runs this renderer automatically.
Deployment log retrieval is disabled unless `LINSEC_LOG_API_TOKEN` is set;
when enabled it requires a Bearer token and only serves logs from the configured
log directory.

The Ansible image no longer grants unrestricted `NOPASSWD:ALL`; its runtime
user can invoke only a fixed root-owned SSH key initialization helper. The
deployment script validates environment and batch-size arguments before using
them in inventory or Ansible commands.

Run the focused Python suite with `python -m pytest -q tests`; it covers
validation, repository persistence, inventory/playbook filesystem behavior,
deployment worker completion, routes, and SSE context handling. The
application and client modules can be syntax-checked with
`python -m compileall -q app tests` and `node --check` on the JavaScript files.

This reduces risk and preserves stable behavior while improving architecture.

---

## 8. Refactoring checklist for every patch

Before any merge, verify:

- [ ] there is one source of truth for the behavior
- [ ] the change is documented in code
- [ ] input validation is present
- [ ] no secrets are hardcoded
- [ ] logs are meaningful
- [ ] exceptions are handled explicitly
- [ ] the code remains understandable to a new contributor
- [ ] tests exist for the behavior
- [ ] there is no duplicated pattern left behind
- [ ] the scope is minimal and focused

---

## 9. Recommended next concrete tasks

For the next working session, the agent should focus on the following, in order:

1. centralize deployment logic in a single service
2. remove duplicate code from `app/services.py`
3. move database interactions into repositories
4. reduce route-side logic
5. add validation and security checks
6. add a minimal failing test around deployment flow
7. document the new service contracts

---

## 10. Final target state

The repo should evolve toward a clean operational flow like this:

```text
Browser UI
  -> Flask API
    -> Service layer
      -> Repository layer
      -> Ansible orchestration
      -> Inventory manager
      -> Wazuh integration
      -> Database / logging / monitoring
```

That structure is predictable, easier to debug, easier to extend, and much safer for production-like operations.

---

## 11. Final guidance to future agents

- Keep changes narrow and explicit.
- Avoid introducing new abstraction layers without value.
- Prefer readability and clarity over cleverness.
- Do not duplicate behavior.
- Make bug fixes and features testable.
- Treat this as an operational platform, not just a small demo.
- When in doubt, simplify.

The purpose is not to add more code. The purpose is to create the right code in a form that humans can understand, maintain, and operate confidently.
