# LinSec360

LinSec360 is a Linux security orchestration platform. The repository currently
contains two stacks during a controlled transition:

- **Legacy Wazuh/Flask stack** — `docker-compose.yml`, documented below.
- **New FastAPI + PostgreSQL backend** — `backend/`, with auth/RBAC, DB-backed
  playbooks, generated inventories, and a Redis/RQ deployment worker. See
  [`docs/V2_BACKEND.md`](docs/V2_BACKEND.md) for setup and the `/api/v1`
  contract. Start it with:

  ```bash
  docker compose -f docker-compose.v2.yml up --build
  ```

The legacy stack remains the default until the React UI reaches parity. Do not
remove it yet.

---

# Deploy Wazuh Docker in single node configuration

This deployment is defined in `docker-compose.yml` with one Wazuh manager,
one Wazuh indexer, and one Wazuh dashboard container.

Before deploying, copy `.env.example` to `.env`, run `chmod 600 .env`, and set
unique values for the Wazuh admin, dashboard, and API passwords. Generate a
bcrypt hash for each of the admin and dashboard passwords with the Wazuh
Indexer `hash.sh` tool. Set the corresponding `WAZUH_ADMIN_PASSWORD_HASH` and
`WAZUH_DASHBOARD_PASSWORD_HASH` entries. Do not commit `.env`.
Use single quotes in `.env` for values containing `$`, `#`, or spaces.
Set `FLASK_SECRET` to a separate random value (for example, from
`openssl rand -hex 32`).
To enable authenticated deployment-log access, set `LINSEC_LOG_API_TOKEN` to
a randomly generated value; log requests require a `Bearer` authorization
header. Leave it empty to keep the log endpoint disabled.

For automated deployment, the script renders private runtime Wazuh
configuration, generates certificates, and starts the services:

```
$ ./config/scripts/deploy.sh
```

For manual Compose use, first render the private runtime configuration:

```
$ python3 config/scripts/render-wazuh-config.py
```

Then continue with the following steps:

1) Increase max_map_count on your host (Linux). This command must be run with root permissions:
```
$ sysctl -w vm.max_map_count=262144
```
2) Run the certificate creation script:
```
$ docker compose -f generate-indexer-certs.yml run --rm generator
```
3) Start the environment with Docker Compose:

- In the foregroud:
```
$ docker compose up --build
```
- In the background:
```
$ docker compose up --build -d
```

The environment takes about 1 minute to get up (depending on your Docker host) for the first time since Wazuh Indexer must be started for the first time and the indexes and index patterns must be generated.
