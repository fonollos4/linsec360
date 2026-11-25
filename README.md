# LinSec360

LinSec360 is a Linux security orchestration platform built around a FastAPI
backend, React UI, PostgreSQL, Redis/RQ, Ansible automation, and the Wazuh
control plane. The complete supported deployment is defined by
[`docker-compose.v2.yml`](docker-compose.v2.yml).

Additional project documentation is indexed in [docs/INDEX.md](docs/INDEX.md).

## Current deployment model

- Uyuni/Salt is **no longer part of the stack**. It was removed from Compose,
  runtime configuration, deployment worker, and the UI. Legacy API/model fields
  may still exist for compatibility, but no Uyuni container or profile is
  started.
- All automation lives under [`taskengine/`](taskengine/): playbooks, roles,
  inventories, and `ansible.cfg`. Do not add root-level `playbooks/`, `roles/`,
  `inventories/`, or `ansible.cfg`.
- SSH host fingerprints are **not scanned, pinned, or compared**. An administrator
  must provision a service account (default `linsec-ansible`) on every target and
  install the matching public key before onboarding the host.
- The UI provides bulk host import, fleet filtering, grouped actions, an
  authenticated WebSocket terminal, and OpenSCAP/patching controls. See
  [docs/architecture/ui-enrichment.md](docs/architecture/ui-enrichment.md).

## Deploy production and development automatically

Run every command from the repository root. The supported entry point handles
the entire lifecycle: environment files, secrets, TLS SANs, Wazuh certificates
and private configuration, the Ansible SSH key, Compose project isolation,
startup, Wazuh user synchronization, and IP-based health checks.

```bash
# Production: HTTPS UI on port 8444, API on port 8080
./config/scripts/deploy-stack.sh production

# Development: HTTP UI on port 8081, API on port 8082
./config/scripts/deploy-stack.sh development
```

The command is idempotent. On the first run it creates `.env` for production or
`.env.development` for development from `.env.example`, generates all missing
secrets, and leaves existing secrets unchanged. This includes
`LINSEC_INGEST_API_TOKEN`: Ansible playbooks use it to write OpenSCAP, hardening,
livepatch and patch results back to the API. Only its SHA-256 hash is stored in
the database, so back up the plaintext value from the environment file; losing
it breaks result ingestion until a new token is configured and provisioned. It
detects the primary server IP with `hostname -I`; override it with `--server-ip <IP>` or
`LINSEC_SERVER_IP=<IP>`. Every published port is bound to `0.0.0.0`, CORS
origins include the server IP and hostname, and the API receives
`LINSEC_WAZUH_MANAGER_ADDRESS=<server IP>` so agents can reach Wazuh.

Useful options:

```bash
# Recreate every container after a full rebuild
./config/scripts/deploy-stack.sh production --force-recreate

# Start quickly with previously built images
./config/scripts/deploy-stack.sh development --no-build
```

`LINSEC_FORCE_RECREATE=1` is equivalent to `--force-recreate`.

### URL and port map

The script prints the final URLs and waits for both the API and UI health
endpoints. Replace `<IP>` with the address of the server.

| Service | Production | Development |
| --- | --- | --- |
| LinSec360 UI | `https://<IP>:8444` | `http://<IP>:8081` |
| API health | `http://<IP>:8080/health` | `http://<IP>:8082/health` |
| Wazuh Dashboard | `https://<IP>:443` | `https://<IP>:444` |
| Wazuh Indexer | `<IP>:9200` | `<IP>:9201` |
| Wazuh Manager API | `<IP>:55000` | `<IP>:55001` |
| Wazuh agent/enrollment | `<IP>:1514` / `<IP>:1515` | `<IP>:1516` / `<IP>:1517` |
| Wazuh syslog (UDP) | `<IP>:514` | `<IP>:515` |
| Compose project | `linsec360` | `linsec360-dev` |
| Environment file | `.env` | `.env.development` |
| Docker network | `172.30.0.0/16` | `172.31.0.0/16` |

Production and development use different Compose projects, PostgreSQL/Redis
volumes, generated Wazuh configuration, Wazuh certificates, UI certificates,
and ports. They can run at the same time without colliding. The generated TLS
certificate for production includes the detected server IP; if an older
certificate does not include it, the script moves the old pair aside with a
timestamp suffix and generates a replacement.

Prerequisites:

- Docker Engine with the Compose plugin, Python 3, `openssl`, and `curl`
- Wazuh Indexer memory limit:

  ```bash
  sudo sysctl -w vm.max_map_count=262144
  ```

The script warns but does not change kernel settings. It also generates the
Ansible service-account key in `./.ssh` when absent. Install the printed public
key in the `linsec-ansible` account on every managed host; no fingerprint scan,
pin, or comparison is performed.

`LINSEC_BOOTSTRAP_ADMIN_PASSWORD` is used **only when the database has no
users**. Changing it later does not change an existing `admin` password; use
the reset procedure below.

### Manual reference (fallback only)

The deploy script performs these steps in order. Use them only for debugging or
a custom deployment:

```bash
cp .env.example .env                 # or .env.development
chmod 600 .env
python3 config/scripts/init-wazuh-env.py --env-file .env
python3 config/scripts/update-env.py --env-file .env \
  LINSEC_BIND_ADDRESS=0.0.0.0 LINSEC_WAZUH_MANAGER_ADDRESS=<IP> \
  LINSEC_INGEST_API_URL=http://api:8000 \
  LINSEC_INGEST_API_TOKEN='linsec_<generated-secret>'
python3 config/scripts/render-wazuh-config.py \
  --env-file .env --output-dir "$PWD/config/wazuh/generated"
docker compose -p linsec360 -f docker-compose.v2.yml --env-file .env \
  up -d --build --remove-orphans
python3 config/scripts/sync-wazuh-users.py --env-file .env \
  --cert-dir "$PWD/config/wazuh/indexer_ssl_certs"
```

Wazuh indexer certificates are generated only when
`config/wazuh/indexer_ssl_certs/root-ca.pem` is absent:

```bash
docker compose -p linsec360-certs-production \
  -f generate-indexer-certs.yml run --rm generator
```

Do not rerun the certificate generator after certificates exist.

### Verify Ansible automation

The API and worker images include `ansible-core 2.18`, `openssh-client`, and the
collections from `taskengine/requirements.yml`:

```bash
docker compose -p linsec360 -f docker-compose.v2.yml --env-file .env \
  exec api ansible-playbook --version
docker compose -p linsec360 -f docker-compose.v2.yml --env-file .env \
  exec api ansible-playbook --syntax-check \
  -i /opt/linsec/taskengine/inventories/production/hosts.yml \
  /opt/linsec/taskengine/playbooks/site.yml
docker compose -p linsec360 -f docker-compose.v2.yml --env-file .env \
  exec api ansible-playbook --syntax-check \
  -i /opt/linsec/taskengine/inventories/production/hosts.yml \
  /opt/linsec/taskengine/playbooks/verify.yml
```

Replace the project, env file, and inventory with the development values to
check that stack. The supported bundled library is:

- `site.yml` — baseline hardening
- `verify.yml` — baseline verification
- `openscap-scan.yml` — OpenSCAP baseline scan
- `openscap-remediate.yml` — filtered OpenSCAP remediation and after-scan ingestion
- `compliance-verify.yml` — after-scan verification and ingestion
- `hardening.yml` — hardening controls
- `patch-security.yml` — targeted native package/CVE patching
- `patch-verify.yml` — post-patch verification and result ingestion
- `livepatch-check.yml` — native kernel live-patch state
- `wazuh-agent.yml` — agent deployment
- `connectivity.yml` — connectivity check

The obsolete `site-legacy.yml`, `system-audit.yml`, `hardening-audit.yml`,
`system-update.yml`, and `disk-cleanup.yml` playbooks were removed. On startup,
the API synchronizes the bundled library from `taskengine/playbooks`: bundled
rows are refreshed or removed with their source files, while operator-created
playbooks are preserved. Inventories generated from the database are
authoritative for deployments; the files under `taskengine/inventories/` are
examples for local/syntax runs only.

### Wazuh manager address for agents

The deploy script sets `LINSEC_WAZUH_MANAGER_ADDRESS` to the detected server IP.
The Settings page resolves configured service hostnames to IP addresses from the
API container and summarizes the Web UI, API, database, Redis, and Wazuh
Manager/API/Indexer/Dashboard. Recreate the API and worker after changing this
setting manually.

### Vulnerability source

Wazuh 4.12 no longer exposes `/vulnerability/{agent_id}/inventory` on the
Manager API. LinSec360 reads state documents from
`wazuh-states-vulnerabilities-*` through the Wazuh Indexer API, using
`LINSEC_WAZUH_INDEXER_URL`, `LINSEC_WAZUH_INDEXER_USERNAME`, and
`LINSEC_WAZUH_INDEXER_PASSWORD` (or their runtime-equivalent settings). The
previous 404 from `https://wazuh.manager:55000/vulnerability/002/inventory`
therefore cannot occur with the current integration.

## Host onboarding and terminal

- Add a host from the UI with name/alias, IPv4, environment, groups, SSH user,
  port, and an optional SSH key reference. **Tester la connexion** checks SSH via
  the service account and detects the distribution with Ansible.
- Bulk import accepts CSV with headers
  (`name,ip,environment,groups,ansible_user,ansible_port,ssh_key_reference`),
  JSON, or pasted `hostname,ip,ssh_user,group,environment` lines. Invalid and
  selected rows are previewed before import.
- The **Déployer après ajout** option queues the first allowlisted playbook
  (`site.yml` when available).
- The terminal button opens `WS /api/v1/hosts/{id}/terminal/ws`. Access requires
  an authenticated session or Bearer token with role `admin` or `operator`;
  openings and closures are written to the audit log. The nginx location in
  `web/snippets/linsec-locations.conf` handles the WebSocket upgrade.
- Long running deployments are tracked from `/deployments`, its SSE feed, and
  detailed logs. The UI refreshes compliance, patch, KPI and host state when a
  job reaches a terminal status.
- The Compliance page provides the three-step OpenSCAP flow: scan, remediate,
  verify. The selected profile is passed to every step. Remediation excludes
  SSH-cutting rules and does not open Wazuh ports `1514`/`1515`; reports are
  written under `/var/log/linsec360/` on the target.
- The Patching page lets the operator select individual findings for a host,
  apply targeted packages with `patch-security.yml`, then verify with
  `patch-verify.yml`. Reboots remain manual unless `patch_reboot_allowed=true`
  is explicitly supplied as an extra variable.

There is no fingerprint approval screen. Legacy fingerprint endpoints remain
importable for compatibility but are not used by the UI, connection tests, or
the deployment worker.

## Development checks

```bash
python3 -m pytest backend/tests -q
npm run build --prefix web
npm run lint --prefix web
git diff --check
docker compose -f docker-compose.v2.yml --env-file .env config --quiet
docker compose -f docker-compose.v2.yml --env-file .env.development config --quiet
```

## Reset the LinSec360 web administration password

`LINSEC_BOOTSTRAP_ADMIN_PASSWORD` is used only when the database has no users.
Changing this value in `.env` does not update an existing `admin` account.

Reset the existing account directly from the running API container:

```bash
docker compose -p linsec360 -f docker-compose.v2.yml --env-file .env exec api \
  python -m backend.cli reset-password --username admin
```

Enter a password of at least 12 characters at the secure prompt. The command
updates the Argon2 password hash stored in PostgreSQL and revokes every active
LinSec360 session for that user. Do not pass the password with `--password` in
shell scripts or terminal history.

After the reset, update the bootstrap value in `.env` so a database
reinitialization uses the same password:

```dotenv
LINSEC_BOOTSTRAP_ADMIN_USERNAME=admin
LINSEC_BOOTSTRAP_ADMIN_PASSWORD='<the-new-secret>'
```

Keep `.env` mode `0600`, do not commit the password, and restart the API if the
new bootstrap value must also be available to the running configuration:

```bash
chmod 600 .env
docker compose -p linsec360 -f docker-compose.v2.yml --env-file .env \
  up -d --force-recreate api
```

For a completely new database:

```bash
docker compose -p linsec360 -f docker-compose.v2.yml --env-file .env stop api
docker volume rm linsec360_linsec_postgres
./config/scripts/deploy-stack.sh production --force-recreate
```

This deletes all LinSec360 users, deployment history, and application data; use
it only for a disposable test database. In production, never delete the
PostgreSQL volume. Use the CLI reset above, restrict it to approved operators,
revoke old browser sessions, store the secret in an approved secret manager, and
verify HTTPS/proxy cookies before reopening access.

## Remove a previous deployment before a fresh install

Use this only when you intentionally want to erase the existing stack data. It
permanently deletes the LinSec360 PostgreSQL database, Redis state, Wazuh
indexes and configuration data, and application logs/artifacts stored in Compose
volumes. Back up anything that must be retained first.

Verify the project and services:

```bash
docker compose -p linsec360 -f docker-compose.v2.yml --env-file .env ps --all
```

Stop and remove the production containers, orphan containers, and all
Compose-managed volumes:

```bash
docker compose -p linsec360 -f docker-compose.v2.yml --env-file .env \
  down --volumes --remove-orphans
```

This does not delete `.env`, source files, bind-mounted configuration, or TLS
certificates. Keep those files for the reinstall and change/regenerate secrets
separately only when required. Do not run a global `docker system prune` or
manually remove unrelated Docker volumes. Use `linsec360-dev` and
`.env.development` only if the disposable stack is the development one.

Reinstall with the normal automated entry point:

```bash
./config/scripts/deploy-stack.sh production --force-recreate
```

## Reset Wazuh test data and security users

This procedure is intended for disposable test environments. It removes the
indexer's persisted OpenSearch security state and alerts, then initializes the
Wazuh users from the current values and bcrypt hashes in `.env`.

```bash
docker compose -p linsec360 -f docker-compose.v2.yml --env-file .env down
docker volume rm linsec360_wazuh-indexer-data
python3 config/scripts/render-wazuh-config.py --env-file .env \
  --output-dir "$PWD/config/wazuh/generated"
./config/scripts/deploy-stack.sh production --force-recreate
```

If a different Compose project was used, determine the actual volume name first:

```bash
docker volume ls --format '{{.Name}}' | grep 'wazuh-indexer-data'
docker compose -p <project> -f docker-compose.v2.yml --env-file <env-file> down
docker volume rm <volume-from-the-command-above>
```

Do not use `docker compose down -v` unless every LinSec360 and Wazuh data volume
is intentionally disposable. In production, take an approved backup or snapshot
first and rotate/synchronize Wazuh security users through the Security API
without removing the index volume.
