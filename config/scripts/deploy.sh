#!/bin/bash
# scripts/deploy.sh

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPOSITORY_ROOT"

# Configuration
ENVIRONMENT=${1:-production}  
BATCH_SIZE=${2:-20%}
LOG_FILE="deployment-$(date +%Y%m%d-%H%M%S).log"

if [[ ! "$ENVIRONMENT" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]]; then
    echo "Invalid environment name: $ENVIRONMENT" >&2
    exit 1
fi

if [[ ! "$BATCH_SIZE" =~ ^([1-9][0-9]?|100)%?$ ]]; then
    echo "Batch size must be an integer from 1 to 100, optionally followed by %." >&2
    exit 1
fi

echo "Starting LinSec360 deployment for environment: $ENVIRONMENT"

# Vérification des prérequis
check_prerequisites() {
    echo "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        echo "Docker is required but not installed."
        exit 1
    fi
    
    if ! docker compose version &> /dev/null; then
        echo "Docker Compose is required but not installed."
        exit 1
    fi
    
    echo "Prerequisites check passed."
}

# Déploiement du plan de contrôle
deploy_control_plane() {
    echo "Deploying control plane..."

    python3 config/scripts/render-wazuh-config.py
    
    # Génération des certificats SSL
    docker compose -f generate-indexer-certs.yml run --rm generator
    
    # Démarrage des services
    docker compose up -d
    
    # Attente que les services soient prêts
    echo "Waiting for services to be ready..."
    sleep 60
    
    # Vérification de la santé des services
    docker compose exec wazuh-manager /var/ossec/bin/wazuh-control status
    
    echo "Control plane deployment completed."
}

# Déploiement des agents
deploy_agents() {
    echo "Deploying agents to $ENVIRONMENT environment..."
    
    docker compose exec ansible ansible-playbook \
        -i "/opt/linsec/taskengine/inventories/$ENVIRONMENT/hosts.yml" \
        /opt/linsec/taskengine/playbooks/site.yml \
        --extra-vars "batch_size=$BATCH_SIZE" \
        --vault-password-file /opt/linsec/taskengine/.vault_pass \
        | tee -a "$LOG_FILE"
    
    echo "Agent deployment completed."
}

# Validation post-déploiement
validate_deployment() {
    echo "Validating deployment..."
    
    # Vérification des agents connectés
    CONNECTED_AGENTS=$(
        docker compose exec wazuh.manager /var/ossec/bin/agent_control -l |
            grep -c "is available" || true
    )
    echo "Connected agents: $CONNECTED_AGENTS"
    
    # Tests de connectivité
    docker compose exec ansible ansible \
        -i "/opt/linsec/taskengine/inventories/$ENVIRONMENT/hosts.yml" \
        all -m ping
    
    echo "Deployment validation completed."
}

# Exécution du déploiement
main() {
    check_prerequisites
    deploy_control_plane
    deploy_agents
    validate_deployment
    
    echo "LinSec360 deployment completed successfully!"
    echo "Dashboard accessible at: https://$(hostname):443"
    echo "Deployment log: $LOG_FILE"
}

main "$@"