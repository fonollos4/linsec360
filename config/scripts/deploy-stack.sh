#!/usr/bin/env bash
# Deploy or redeploy the LinSec360 production or development stack.
#
# Usage:
#   config/scripts/deploy-stack.sh [production|development] [options]
#
# Options:
#   --no-build       Reuse existing images instead of rebuilding them.
#   --force-recreate Recreate every container even when its configuration is unchanged.
#   --server-ip IP   Override automatic server IP detection.
#   -h, --help       Show this help.
#
# The script creates .env (production) or .env.development (development) from
# .env.example when needed, initializes missing secrets, configures every
# published port for the server IP, generates missing certificates, renders the
# private Wazuh configuration, starts the matching Compose project, and waits
# for the IP-based health endpoints. Environment variables LINSEC_SERVER_IP and
# LINSEC_FORCE_RECREATE=1 are also accepted.

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPOSITORY_ROOT"

COMPOSE_FILE="$REPOSITORY_ROOT/docker-compose.v2.yml"
CERT_GENERATOR_FILE="$REPOSITORY_ROOT/generate-indexer-certs.yml"
ENVIRONMENT="production"
BUILD_IMAGE=1
FORCE_RECREATE="${LINSEC_FORCE_RECREATE:-0}"
SERVER_IP="${LINSEC_SERVER_IP:-}"

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
}

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

absolute_path() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *) printf '%s/%s\n' "$REPOSITORY_ROOT" "$1" ;;
    esac
}

detect_server_ip() {
    local candidate
    for candidate in $(hostname -I 2>/dev/null || true); do
        case "$candidate" in
            127.*|172.17.*|172.30.*) continue ;;
        esac
        if [[ "$candidate" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    candidate="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ { for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }')"
    if [[ -n "$candidate" ]]; then
        printf '%s\n' "$candidate"
        return 0
    fi
    return 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        production|development)
            ENVIRONMENT="$1"
            ;;
        --no-build)
            BUILD_IMAGE=0
            ;;
        --force-recreate)
            FORCE_RECREATE=1
            ;;
        --server-ip)
            shift
            [[ $# -gt 0 ]] || fail "--server-ip requires an IPv4 address"
            SERVER_IP="$1"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
    shift
done

if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP="$(detect_server_ip)" || \
        fail "could not detect the server IP; use --server-ip or LINSEC_SERVER_IP"
fi
HOSTNAME="$(hostname -f 2>/dev/null || hostname)"

case "$ENVIRONMENT" in
    production)
        ENV_FILE_REL=".env"
        PROJECT="linsec360"
        API_PORT=8080
        WEB_PORT=80
        HTTPS_PORT=8444
        WAZUH_DASHBOARD_PORT=443
        WAZUH_INDEXER_PORT=9200
        WAZUH_API_PORT=55000
        WAZUH_MANAGER_PORT=1514
        WAZUH_ENROLLMENT_PORT=1515
        WAZUH_SYSLOG_PORT=514
        TLS_ENABLED=true
        COOKIE_SECURE=true
        TLS_DIR_REL="./config/tls"
        WAZUH_CERT_DIR_REL="./config/wazuh/indexer_ssl_certs"
        WAZUH_GENERATED_DIR_REL="./config/wazuh/generated"
        DOCKER_SUBNET="172.30.0.0/16"
        UI_URL="https://$SERVER_IP:$HTTPS_PORT"
        UI_HEALTH_URL="$UI_URL/health"
        ;;
    development)
        ENV_FILE_REL=".env.development"
        PROJECT="linsec360-dev"
        API_PORT=8082
        WEB_PORT=8081
        HTTPS_PORT=8445
        WAZUH_DASHBOARD_PORT=444
        WAZUH_INDEXER_PORT=9201
        WAZUH_API_PORT=55001
        WAZUH_MANAGER_PORT=1516
        WAZUH_ENROLLMENT_PORT=1517
        WAZUH_SYSLOG_PORT=515
        TLS_ENABLED=false
        COOKIE_SECURE=false
        TLS_DIR_REL="./config/tls-development"
        WAZUH_CERT_DIR_REL="./config/wazuh/indexer_ssl_certs-development"
        WAZUH_GENERATED_DIR_REL="./config/wazuh/generated-development"
        DOCKER_SUBNET="172.31.0.0/16"
        UI_URL="http://$SERVER_IP:$WEB_PORT"
        UI_HEALTH_URL="$UI_URL/health"
        ;;
esac

ENV_FILE="$REPOSITORY_ROOT/$ENV_FILE_REL"
TLS_DIR="$(absolute_path "$TLS_DIR_REL")"
WAZUH_CERT_DIR="$(absolute_path "$WAZUH_CERT_DIR_REL")"
WAZUH_GENERATED_DIR="$(absolute_path "$WAZUH_GENERATED_DIR_REL")"

if [[ "$TLS_ENABLED" == "true" ]]; then
    CORS_ORIGINS="[\"http://$SERVER_IP:$WEB_PORT\",\"https://$SERVER_IP:$HTTPS_PORT\",\"http://$HOSTNAME:$WEB_PORT\",\"https://$HOSTNAME:$HTTPS_PORT\",\"http://localhost:5173\"]"
else
    CORS_ORIGINS="[\"http://$SERVER_IP:$WEB_PORT\",\"http://$SERVER_IP:$API_PORT\",\"http://$HOSTNAME:$WEB_PORT\",\"http://$HOSTNAME:$API_PORT\",\"http://localhost:5173\"]"
fi

if [[ ! -f "$ENV_FILE" ]]; then
    [[ -f "$REPOSITORY_ROOT/.env.example" ]] || fail ".env.example is missing"
    cp "$REPOSITORY_ROOT/.env.example" "$ENV_FILE"
    echo "Created $ENV_FILE_REL from .env.example"
fi
chmod 600 "$ENV_FILE"

if ! grep -Eq '^LINSEC_INGEST_API_TOKEN=.+' "$ENV_FILE"; then
    ingest_token="linsec_$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
    python3 "$REPOSITORY_ROOT/config/scripts/update-env.py" \
        --env-file "$ENV_FILE" \
        "LINSEC_INGEST_API_TOKEN=$ingest_token"
    echo "Initialized LINSEC_INGEST_API_TOKEN in $ENV_FILE_REL (back it up)"
fi

python3 "$REPOSITORY_ROOT/config/scripts/update-env.py" \
    --env-file "$ENV_FILE" \
    "LINSEC_ENVIRONMENT=$ENVIRONMENT" \
    "LINSEC_BIND_ADDRESS=0.0.0.0" \
    "LINSEC_INGEST_API_URL=http://api:8000" \
    "LINSEC_TLS_HOSTS=$HOSTNAME,$SERVER_IP,localhost,127.0.0.1" \
    "LINSEC_CORS_ORIGINS=$CORS_ORIGINS" \
    "LINSEC_WAZUH_MANAGER_ADDRESS=$SERVER_IP" \
    "LINSEC_API_PORT=$API_PORT" \
    "LINSEC_WEB_PORT=$WEB_PORT" \
    "LINSEC_HTTPS_PORT=$HTTPS_PORT" \
    "LINSEC_TLS_ENABLED=$TLS_ENABLED" \
    "LINSEC_COOKIE_SECURE=$COOKIE_SECURE" \
    "LINSEC_TLS_DIR=$TLS_DIR_REL" \
    "LINSEC_WAZUH_CERT_DIR=$WAZUH_CERT_DIR_REL" \
    "LINSEC_WAZUH_GENERATED_DIR=$WAZUH_GENERATED_DIR_REL" \
    "LINSEC_DOCKER_SUBNET=$DOCKER_SUBNET" \
    "WAZUH_DASHBOARD_PORT=$WAZUH_DASHBOARD_PORT" \
    "WAZUH_INDEXER_PORT=$WAZUH_INDEXER_PORT" \
    "WAZUH_API_PORT=$WAZUH_API_PORT" \
    "WAZUH_MANAGER_PORT=$WAZUH_MANAGER_PORT" \
    "WAZUH_MANAGER_ENROLLMENT_PORT=$WAZUH_ENROLLMENT_PORT" \
    "WAZUH_SYSLOG_PORT=$WAZUH_SYSLOG_PORT"

python3 "$REPOSITORY_ROOT/config/scripts/init-wazuh-env.py" --env-file "$ENV_FILE"

if [[ ! -f "$REPOSITORY_ROOT/.ssh/id_ed25519" ]]; then
    "$REPOSITORY_ROOT/config/scripts/generate-ansible-key.sh"
fi

mkdir -p "$WAZUH_CERT_DIR" "$WAZUH_GENERATED_DIR"
# Existing bind-mounted directories may have been created by a container as
# root; never fail the deployment only because the host user cannot chmod them.
chmod 700 "$WAZUH_CERT_DIR" "$WAZUH_GENERATED_DIR" 2>/dev/null || true

python3 "$REPOSITORY_ROOT/config/scripts/render-wazuh-config.py" \
    --env-file "$ENV_FILE" \
    --output-dir "$WAZUH_GENERATED_DIR"

if [[ ! -f "$WAZUH_CERT_DIR/root-ca.pem" ]]; then
    echo "Generating Wazuh indexer certificates for $ENVIRONMENT"
    LINSEC_WAZUH_CERT_DIR="$WAZUH_CERT_DIR" \
        docker compose -p "linsec360-certs-$ENVIRONMENT" \
        -f "$CERT_GENERATOR_FILE" run --rm generator
fi

if [[ "$TLS_ENABLED" == "true" ]]; then
    mkdir -p "$TLS_DIR"
    chmod 700 "$TLS_DIR" 2>/dev/null || true
    cert_file="$TLS_DIR/fullchain.pem"
    key_file="$TLS_DIR/privkey.pem"
    cert_has_ip=false
    if [[ -f "$cert_file" ]] && \
       openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -Fq "IP Address:$SERVER_IP"; then
        cert_has_ip=true
    fi
    if [[ ! -f "$cert_file" || ! -f "$key_file" || "$cert_has_ip" != "true" ]]; then
        backup_suffix="$(date +%Y%m%d-%H%M%S)"
        [[ ! -f "$cert_file" ]] || mv "$cert_file" "$cert_file.bak.$backup_suffix"
        [[ ! -f "$key_file" ]] || mv "$key_file" "$key_file.bak.$backup_suffix"
        echo "Generating UI TLS certificate for $SERVER_IP"
        LINSEC_TLS_DIR="$TLS_DIR" \
        LINSEC_TLS_HOSTS="$HOSTNAME,$SERVER_IP,localhost,127.0.0.1" \
            "$REPOSITORY_ROOT/config/scripts/generate-linsec-tls.sh"
    fi
fi

map_count="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
if [[ "$map_count" -lt 262144 ]]; then
    echo "WARNING: vm.max_map_count=$map_count; Wazuh Indexer requires at least 262144" >&2
    echo "WARNING: run: sudo sysctl -w vm.max_map_count=262144" >&2
fi

UP_ARGS=(-d --remove-orphans)
[[ "$BUILD_IMAGE" == "1" ]] && UP_ARGS+=(--build)
[[ "$FORCE_RECREATE" == "1" ]] && UP_ARGS+=(--force-recreate)

echo "Starting $ENVIRONMENT stack (project $PROJECT) from $ENV_FILE_REL"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" \
    up "${UP_ARGS[@]}"

# internal_users.yml is only imported when the security index is created. Keep
# existing installations in sync with the current passwords after every deploy.
python3 "$REPOSITORY_ROOT/config/scripts/sync-wazuh-users.py" \
    --env-file "$ENV_FILE" \
    --cert-dir "$WAZUH_CERT_DIR" \
    --indexer-url "https://127.0.0.1:$WAZUH_INDEXER_PORT"

wait_for_url() {
    local url="$1"
    local attempts="${2:-60}"
    local attempt
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if curl -fsSLk --max-time 5 "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    echo "ERROR: $url did not become ready after $((attempts * 2))s" >&2
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" \
        logs --tail=60 >&2 || true
    return 1
}

wait_for_url "http://$SERVER_IP:$API_PORT/health"
wait_for_url "$UI_HEALTH_URL"

echo
echo "$ENVIRONMENT deployment is ready on $SERVER_IP"
echo "  UI:              $UI_URL"
echo "  API health:      http://$SERVER_IP:$API_PORT/health"
echo "  Wazuh dashboard: https://$SERVER_IP:$WAZUH_DASHBOARD_PORT"
echo
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps
