#!/usr/bin/env bash
# LinSec360 deployment entry point.
#
# Usage:
#   config/scripts/deploy.sh [environment] [batch] [--with-hardening]
#
# Environment variables:
#   LINSEC_STACK=legacy|v2       Which compose stack to start (default: legacy)
#   LINSEC_COMPOSE_FILE=<path>   Override the compose file
#   WAZUH_MANAGER_HOST=<ip>      Manager address agents enroll with
#   WAZUH_MANAGER_API_USER       Wazuh API user for inventory checks
#
# Secrets must come from .env or the platform secret store. This script never
# writes credentials to disk or to the deployment log.

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPOSITORY_ROOT"

ENVIRONMENT="${1:-production}"
BATCH_SIZE="${2:-20%}"
WITH_HARDENING="${3:-}"
STACK="${LINSEC_STACK:-legacy}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="${LINSEC_LOG_DIR:-$REPOSITORY_ROOT/logs}"
LOG_FILE="$LOG_DIR/deployment-$TIMESTAMP.log"
WAZUH_MANAGER_HOST="${WAZUH_MANAGER_HOST:-127.0.0.1}"
WAZUH_MANAGER_API_USER="${WAZUH_MANAGER_API_USER:-wazuh-wui}"

if [[ ! "$ENVIRONMENT" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]]; then
    echo "Invalid environment name: $ENVIRONMENT" >&2
    exit 2
fi

if [[ ! "$BATCH_SIZE" =~ ^([1-9][0-9]?|100)%?$ ]]; then
    echo "Batch size must be an integer from 1 to 100, optionally followed by %." >&2
    exit 2
fi

case "$STACK" in
    legacy) DEFAULT_COMPOSE_FILE="docker-compose.yml" ;;
    v2) DEFAULT_COMPOSE_FILE="docker-compose.v2.yml" ;;
    *) echo "LINSEC_STACK must be 'legacy' or 'v2'" >&2; exit 2 ;;
esac
COMPOSE_FILE="${LINSEC_COMPOSE_FILE:-$REPOSITORY_ROOT/$DEFAULT_COMPOSE_FILE}"

if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo "Compose file not found: $COMPOSE_FILE" >&2
    exit 2
fi

if [[ ! -f "$REPOSITORY_ROOT/.env" ]]; then
    echo "Missing .env. Copy .env.example and fill the required secrets." >&2
    exit 2
fi

mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR"

log() {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG_FILE"
}

compose() {
    docker compose -f "$COMPOSE_FILE" "$@"
}

check_prerequisites() {
    log "Checking prerequisites"
    command -v docker >/dev/null || { echo "Docker is required." >&2; exit 1; }
    docker compose version >/dev/null || { echo "Docker Compose v2 is required." >&2; exit 1; }
    command -v python3 >/dev/null || { echo "python3 is required." >&2; exit 1; }
    log "Prerequisites check passed"
}

restore_secrets() {
    # The renderer reads Wazuh secrets from the environment. Source .env without
    # echoing it so values never reach the deployment log.
    set -a
    # shellcheck disable=SC1091
    source "$REPOSITORY_ROOT/.env"
    set +a

    if [[ -z "${WAZUH_API_PASSWORD:-}" && -z "${WAZUH_ADMIN_PASSWORD:-}" ]]; then
        log "WARNING: no Wazuh API/admin password is set; integrations stay unknown"
    fi
    export WAZUH_MANAGER_HOST
}

render_configuration() {
    log "Rendering Wazuh configuration"
    python3 config/scripts/render-wazuh-config.py >>"$LOG_FILE" 2>&1
}

generate_certificates() {
    if [[ -f config/wazuh/indexer_ssl_certs/root-ca.pem ]]; then
        log "TLS certificates already present"
        return
    fi
    log "Generating TLS certificates"
    docker compose -f "$REPOSITORY_ROOT/generate-indexer-certs.yml" run --rm generator >>"$LOG_FILE" 2>&1
}

wait_for_health() {
    local service="$1"
    local timeout="${2:-180}"
    local elapsed=0
    log "Waiting for $service to become healthy (timeout ${timeout}s)"
    while (( elapsed < timeout )); do
        if compose ps --format json "$service" 2>/dev/null | grep -q '"Health":"healthy"'; then
            log "$service is healthy"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    log "ERROR: $service did not become healthy within ${timeout}s"
    return 1
}

deploy_control_plane() {
    log "Starting the $STACK control plane from $COMPOSE_FILE"
    compose up -d --remove-orphans >>"$LOG_FILE" 2>&1
    wait_for_health wazuh.manager 240 || true
    compose exec -T wazuh.manager /var/ossec/bin/wazuh-control status >>"$LOG_FILE" 2>&1 || {
        log "ERROR: Wazuh manager is not running"
        return 1
    }
    log "Control plane started"
}

deploy_agents() {
    log "Deploying Wazuh agents to $ENVIRONMENT (batch $BATCH_SIZE)"
    if ! compose ps --services --filter status=running | grep -qx ansible; then
        log "No ansible service in this stack; skipping in-container agent deployment"
        return 0
    fi
    compose exec -T ansible ansible-playbook \
        -i "/opt/linsec/taskengine/inventories/$ENVIRONMENT/hosts.yml" \
        /opt/linsec/taskengine/playbooks/wazuh-agent.yml \
        --extra-vars "wazuh_manager_address=$WAZUH_MANAGER_HOST" \
        --extra-vars "batch_size=$BATCH_SIZE" \
        >>"$LOG_FILE" 2>&1

    if [[ "$WITH_HARDENING" == "--with-hardening" ]]; then
        log "Applying the hardening baseline"
        compose exec -T ansible ansible-playbook \
            -i "/opt/linsec/taskengine/inventories/$ENVIRONMENT/hosts.yml" \
            /opt/linsec/taskengine/playbooks/hardening.yml \
            --extra-vars "batch_size=$BATCH_SIZE" \
            >>"$LOG_FILE" 2>&1
    fi
}

validate_deployment() {
    log "Validating deployment"
    compose exec -T wazuh.manager /var/ossec/bin/agent_control -l >>"$LOG_FILE" 2>&1 || true
    compose exec -T ansible ansible \
        -i "/opt/linsec/taskengine/inventories/$ENVIRONMENT/hosts.yml" \
        all -m ping >>"$LOG_FILE" 2>&1 || {
        log "WARNING: connectivity check failed for one or more hosts"
    }
    log "Validation finished"
}

main() {
    log "LinSec360 deployment started (environment=$ENVIRONMENT, stack=$STACK)"
    check_prerequisites
    restore_secrets
    render_configuration
    generate_certificates
    deploy_control_plane
    deploy_agents
    validate_deployment
    log "LinSec360 deployment completed"
    log "API: http://localhost:${LINSEC_API_PORT:-8080}"
    log "Deployment log: $LOG_FILE"
}

main "$@"
