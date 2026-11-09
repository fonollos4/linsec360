# Uyuni deployment decision for LinSec360

## Official deployment model

Uyuni is a control plane that is significantly larger than a single application
container. The official Uyuni documentation supports:

- containerized Uyuni Server deployment on openSUSE Tumbleweed with Podman,
  `mgradm`, and `mgrctl`;
- persistent storage under `/var/lib/containers/storage/volumes`;
- Kubernetes deployment through the official Uyuni server and proxy Helm charts;
- multi-container server components, including PostgreSQL and an XML-RPC gateway.

Official references:

- [Uyuni server container deployment](https://www.uyuni-project.org/uyuni-docs/en/uyuni/installation-and-upgrade/container-deployment/uyuni/server-deployment-uyuni.html)
- [Uyuni containers and volumes](https://www.uyuni-project.org/uyuni-docs/en/uyuni/installation-and-upgrade/container-management/containers.html)
- [Uyuni server Helm chart](https://github.com/uyuni-project/uyuni/tree/master/containers/server-helm)
- [Uyuni source repository](https://github.com/uyuni-project/uyuni)

## LinSec360 integration decision

LinSec360 includes an optional Uyuni profile in `docker-compose.v2.yml`.
The profile runs the official Uyuni server image and its official PostgreSQL
image as separate services:

- `uyuni` is the XML-RPC, Salt and web control plane;
- `uyuni-db` provides persistent PostgreSQL storage;
- FastAPI receives credentials and connects to `http://uyuni/rpc/api`.

This remains an official multi-component deployment; it is not a simulation and
not an application-only placeholder. Uyuni's profile requires privileged
container support and sufficient CPU, memory and storage. For production,
operators should still review Uyuni's documented host and network prerequisites.

## Deploy with Docker Compose

1. Copy and protect `.env`.
2. Set every `UYUNI_*_PASSWORD` variable, especially `UYUNI_ADMIN_PASSWORD`,
   `UYUNI_POSTGRES_PASSWORD`, `UYUNI_DB_PASSWORD` and
   `UYUNI_REPORT_DB_PASSWORD`.
3. Choose a DNS-resolvable FQDN and expose the public ports.
4. Start Uyuni and then the remaining stack:

```bash
docker compose -f docker-compose.v2.yml --profile uyuni up -d --build
```

Uyuni web access is available on the configured HTTP and HTTPS ports
(`8081` and `8443` by default). After initialization, verify the XML-RPC
connection from LinSec360 under **Paramètres > Intégrations**, then synchronize
systems and errata from **Correctifs**.

## Required LinSec360 settings

```dotenv
LINSEC_UYUNI_API_URL=https://uyuni.example.internal/rpc/api
LINSEC_UYUNI_USERNAME=
LINSEC_UYUNI_PASSWORD=
LINSEC_UYUNI_VERIFY_TLS=true
LINSEC_UYUNI_TIMEOUT_SECONDS=30
```

`LINSEC_UYUNI_API_URL` must point directly to the XML-RPC gateway, usually
`https://uyuni.example.internal/rpc/api`. LinSec360 uses XML-RPC methods
including `auth.login`, `system.listSystems`, `system.getChannels`, and
`system.getRelevantErrata`.

The `/api/v1/integrations` pages report Uyuni as `not configured`, `reachable`,
or `unavailable`; they must not report success without an actual connection.
