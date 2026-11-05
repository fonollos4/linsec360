# LinSec360 engineering and maintainability guide

This document defines how future agents and contributors should evolve the project so it remains scalable, understandable, and easy to maintain.

## 1. Mission and scope

LinSec360 is a Linux security orchestration platform that combines:

- a Flask web dashboard
- Ansible-based deployment automation
- inventory management for environments
- Wazuh monitoring integration
- operational logging and deployment tracking

The platform should be easy to reason about, safe to deploy, and straightforward to extend without creating hidden coupling between the UI, deployment logic, configuration, and automation engine.

---

## 2. Assessment of the current stack

The current implementation has a solid foundation, but it does not yet fully follow the best practices expected for a maintainable production-grade platform.

### What is good

- The project separates concerns at a broad level: Flask app, database, services, and Ansible inventory.
- It adopts a dashboard-oriented workflow for managing infrastructure.
- It uses Docker Compose for the Wazuh control plane.
- It includes Ansible automation and inventory patterns rather than hardcoded shell logic only.
- It supports status tracking and deployment lifecycle management.

### What should be improved

1. Service boundaries are not consistently defined.
   - The same logic exists in both `app/services.py` and the package under `app/services/`.
   - This creates ambiguity about which implementation is authoritative.

2. There is too much hardcoded configuration.
   - Paths, credentials, and environment assumptions are spread across code and scripts.
   - Secrets should be externalized using environment variables or secret managers.

3. The platform mixes concerns.
   - UI logic, API logic, deployment orchestration, DB access, and Ansible execution are all loosely interwoven.
   - This should be split into clearer application layers.

4. Testing is not structured enough.
   - There is no clear test strategy for API behavior, deployment execution, inventory generation, or regression prevention.

5. Observability is limited.
   - Deployment logs exist, but structured telemetry, tracing, and health endpoints are missing.

6. Security posture needs tightening.
   - Default credentials and secrets should not remain in code or templates.
   - TLS/cert generation, container security, and least privilege should be explicitly designed.

7. The codebase is not yet easy for new contributors to follow.
   - Naming is partly inconsistent.
   - Some modules are duplicated or contain both business logic and orchestration logic.

### Best-practice verdict

The stack is promising and useful, but it is best described as a functional prototype or internal platform, not yet a production-grade, maintainable security automation system.

The main objective of future work should be to reduce accidental complexity and improve architectural clarity.

---

## 3. Design principles for all future work

### Principle 1: keep the architecture explicit

Do not allow the repository to grow without strict layering.

Suggested boundaries:

- `app/` → Flask application, routing, request validation, app factory
- `app/api/` → REST endpoints and request schemas
- `app/services/` → domain logic and orchestration
- `app/models/` → data structures and DB mapping logic
- `app/repositories/` → database access
- `app/validators/` → input validation
- `app/tasks/` → background job or orchestration adapters
- `app/config/` → environment and settings management

### Principle 2: prefer one source of truth

If the same behavior is implemented in more than one place, it must be consolidated.

Current repo issue:

- deployment behavior is duplicated between `app/services.py` and `app/services/deployment_service.py`

Rule:

- only one implementation should own deployment logic
- the rest should import and use it

### Principle 3: minimize hidden state

Avoid mutating globals without traceability.

Prefer:

- explicit service instances
- injectable configuration objects
- context-aware database sessions
- explicit job state tracking

### Principle 4: maintain readability over cleverness

Avoid overengineering or deeply nested logic.

A code path should be understandable by a new developer in under 10 minutes.

### Principle 5: make all automation reproducible

All actions should be scriptable and repeatable.

That includes:

- deployment steps
- backups
- restores
- inventory refresh
- certificate rotation
- SSH trust configuration

---

## 4. Code standards

### Python and Flask

- Use a clear application factory pattern.
- Keep route handlers thin; they should validate and delegate.
- Put domain operations in service classes or functions.
- Avoid writing DB logic directly inside routes.
- Centralize config in one settings object.
- Use environment variables for runtime configuration.
- Use `logging` instead of ad hoc prints.

### Package organization

Prefer this structure:

```text
app/
  __init__.py
  app.py
  config.py
  cli.py
  api/
    __init__.py
    routes.py
  services/
    __init__.py
    deployment_service.py
    host_service.py
    inventory_service.py
    playbook_service.py
    stats_service.py
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
  tasks/
    __init__.py
    deployment_worker.py
  utils/
    __init__.py
    logging.py
```

### Avoid

- duplicating logic in root-level modules and service packages
- large single-file services containing all logic
- direct secret values in source files
- silent failures in deployment and inventory workflows

---

## 5. Configuration and secrets management

### Required rules

- Secrets must never be committed in source control.
- Any credential used by Docker, Wazuh, Ansible, or SSH must be read from environment or a secret store.
- Use `.env` or a secret manager for local dev only, and never commit those files.
- Replace hardcoded passwords like default admin or Wazuh credentials with environment-driven configuration.

### Preferred pattern

```python
import os

class Settings:
    SECRET_KEY = os.environ.get("FLASK_SECRET", "development-secret")
    DATABASE_PATH = os.environ.get("LINSEC_DB_PATH", "/var/lib/linsec/linsec.db")
    INVENTORY_DIR = os.environ.get("LINSEC_INVENTORY_DIR", "/opt/linsec/taskengine/inventories")
    LOG_DIR = os.environ.get("LINSEC_LOG_DIR", "/opt/linsec/logs")
```

Do not hardcode environment-specific values like IPs, hostnames, or security credentials in application logic.

---

## 6. Security best practices

The platform is security-focused, so it must follow stricter rules than typical apps.

### Required practices

- Validate all user inputs at the API boundary.
- Sanitize filenames and playbook names before writing to disk.
- Use secure defaults for Ansible and Wazuh configuration.
- Restrict filesystem permissions for generated inventory and logs.
- Ensure the app does not allow arbitrary file writes from unsanitized input.
- Avoid running privileged operations without explicit checks.
- Use least privilege when interacting with Docker, SSH, and remote hosts.

### Additional recommendations

- add health checks for Docker services
- verify TLS/cert rotation and trust chains
- add a secure secrets lifecycle for Wazuh and Ansible credentials
- ensure SSH config is generated from validated inventory only

---

## 7. Testing strategy

The project should follow a test pyramid:

### Unit tests

- input validation
- inventory generation rules
- playbook filename validation
- status transitions
- database update logic

### Integration tests

- create a temp SQLite DB and validate operations
- generate inventory files and confirm expected YAML
- execute a lightweight local Ansible command against a test inventory

### End-to-end tests

- trigger deployment job through the Flask API
- verify status changes and deployment logs
- validate SSE updates to the frontend

### Test rule

Every fix should include a failing test before the implementation is considered correct.

---

## 8. Operational reliability

### Logging

Use structured logs with:

- timestamp
- environment
- host or group target
- playbook name
- action outcome
- error message

Avoid writing raw, opaque text with no context.

### Background jobs

If the task is long-running, use:

- a queue system such as Celery or RQ, or
- a job manager abstraction, or
- at minimum explicit worker threads with job state tracking

Do not run ad hoc background threads with hidden state and no monitoring if the project grows.

### Health and status

Provide:

- `/health` endpoint
- readiness checks
- deployment status summaries
- log retrieval endpoint
- job execution history

---

## 9. Frontend and API quality

### API rules

- Use JSON responses consistently.
- Keep status codes meaningful.
- Return machine-readable errors.
- Validate payloads before writing to database or inventory.

### Frontend rules

- Keep JS logic simple and maintainable.
- Avoid large inline HTML generation where possible.
- Prefer explicit render functions over repeated DOM patching.
- Separate state management from UI rendering.

The current UI already demonstrates the right intent, but it should be refactored to use a cleaner state model and reusable DOM rendering helpers.

---

## 10. Maintainability checklist for every change

Before merging a change, verify:

- [ ] There is a single source of truth for the behavior
- [ ] The change is documented in the relevant module
- [ ] Input validation is correct
- [ ] Secrets are not committed or hardcoded
- [ ] Logging is meaningful
- [ ] Exceptions are handled explicitly
- [ ] The code remains readable by a new contributor
- [ ] The change has tests
- [ ] The change does not duplicate existing patterns
- [ ] The scope of the change is minimal and focused

---

## 11. Refactor directions for this repo

The following should be prioritized:

1. Eliminate duplicate service logic.
2. Standardize config and environment loading.
3. Move DB access into repositories.
4. Split API endpoints from business logic.
5. Add a real test suite.
6. Add structured logging and deployment metadata.
7. Replace hardcoded default secret values.
8. Add health endpoints and clearer job/state tracking.
9. Cleanly separate Wazuh, inventory, and app concerns.
10. Reduce reliance on ad hoc shell scripts for critical operations.

---

## 12. Recommended future architecture

The long-term architecture should resemble this:

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

This creates a predictable flow and makes future expansion easier.

---

## 13. Final guidance to agents

When working on this repository:

- Keep changes narrow and explicit.
- Do not add new abstraction layers without clear value.
- Prefer simple, readable patterns over clever code.
- Follow a single responsibility principle for each module.
- Make bug fixes and features testable.
- Treat the platform as an operational system, not just a demo application.
- When in doubt, simplify.

The goal is not to build more code. The goal is to build the correct code in a way that humans can understand and operate confidently.
