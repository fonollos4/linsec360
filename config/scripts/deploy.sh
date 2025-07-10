#!/bin/bash
# scripts/deploy.sh

set -euo pipefail

# Configuration
ENVIRONMENT=${1:-production}  
BATCH_SIZE=${2:-20%}
LOG_FILE="deployment-$(date +%Y%m%d-%H%M%S).log"

echo "Starting LinSec360 deployment for environment: $ENVIRONMENT"

# Vérification des prérequis
check_prerequisites() {
    echo "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        echo "Docker is required but not installed."
        exit 1
    fi
    
    if ! command -v docker compose &> /dev/null; then
        echo "Docker Compose is required but not installed."
        exit 1
    fi
    
    echo "Prerequisites check passed."
}

# Déploiement du plan de contrôle
deploy_control_plane() {
    echo "Deploying control plane..."
    
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
    
    docker compose exec ansible-control ansible-playbook \
        -i inventories/$ENVIRONMENT/hosts.yml \
        playbooks/site.yml \
        --extra-vars "batch_size=$BATCH_SIZE" \
        --vault-password-file /ansible/.vault_pass \
        | tee -a $LOG_FILE
    
    echo "Agent deployment completed."
}

# Validation post-déploiement
validate_deployment() {
    echo "Validating deployment..."
    
    # Vérification des agents connectés
    CONNECTED_AGENTS=$(docker compose exec wazuh-manager /var/ossec/bin/agent_control -l | grep -c "is available")
    echo "Connected agents: $CONNECTED_AGENTS"
    
    # Tests de connectivité
    docker compose exec ansible-control ansible \
        -i inventories/$ENVIRONMENT/hosts.yml \
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