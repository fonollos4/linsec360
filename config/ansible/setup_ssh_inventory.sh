#!/bin/bash

# LinSec Inventory SSH Setup Script
# Automated SSH configuration for all hosts in LinSec inventory
# Usage: ./setup_ssh_inventory.sh [environment] [--dry-run]

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINSEC_DIR="$(dirname "$SCRIPT_DIR")"
ANSIBLE_DIR="$LINSEC_DIR/ansible"
INVENTORY_DIR="$ANSIBLE_DIR/inventories"
SSH_CONFIG_FILE="$HOME/.ssh/config"
LOG_FILE="/var/log/linsec-ssh-setup.log"
TEMP_DIR="/tmp/linsec-ssh-setup-$$"

# Default values
DEFAULT_ENVIRONMENT="production"
DRY_RUN=false
BATCH_SIZE=5
MAX_RETRIES=3
CONNECTION_TIMEOUT=30

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Progress tracking
declare -A HOST_STATUS
declare -A HOST_IPS
declare -A HOST_GROUPS
TOTAL_HOSTS=0
PROCESSED_HOSTS=0
SUCCESS_HOSTS=0
FAILED_HOSTS=0

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}ERROR: $1${NC}" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}SUCCESS: $1${NC}" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}INFO: $1${NC}" | tee -a "$LOG_FILE"
}

# Progress bar function
show_progress() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local filled=$((width * current / total))
    local empty=$((width - filled))
    
    printf "\rProgress: ["
    printf "%${filled}s" | tr ' ' '='
    printf "%${empty}s" | tr ' ' '-'
    printf "] %d%% (%d/%d)" "$percentage" "$current" "$total"
}

# Parse command line arguments
parse_arguments() {
    ENVIRONMENT="${1:-$DEFAULT_ENVIRONMENT}"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --batch-size)
                BATCH_SIZE="$2"
                shift 2
                ;;
            --timeout)
                CONNECTION_TIMEOUT="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                ENVIRONMENT="$1"
                shift
                ;;
        esac
    done
}

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [environment] [options]

Options:
    --dry-run           Show what would be done without executing
    --batch-size NUM    Number of hosts to process in parallel (default: 5)
    --timeout NUM       SSH connection timeout in seconds (default: 30)
    --help              Show this help message

Environments:
$(ls -1 "$INVENTORY_DIR" 2>/dev/null | grep -v "group_vars\|host_vars" | sed 's/^/    /' || echo "    No environments found")

Examples:
    $0 production                    # Setup SSH for production environment
    $0 staging --dry-run             # Preview changes for staging
    $0 production --batch-size 10    # Process 10 hosts in parallel
EOF
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if running as non-root user
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root"
        exit 1
    fi
    
    # Check required commands
    local required_commands=("ssh" "ssh-keygen" "openssl" "ansible" "ansible-inventory" "expect" "python3")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Required command '$cmd' is not installed"
            exit 1
        fi
    done
    
    # Check SSH key exists
    if [[ ! -f "$HOME/.ssh/id_rsa.pub" && ! -f "$HOME/.ssh/id_ed25519.pub" ]]; then
        warning "No SSH key found. Generating new ED25519 key..."
        ssh-keygen -t ed25519 -f "$HOME/.ssh/id_ed25519" -N "" -C "linsec-$(whoami)@$(hostname)"
    fi
    
    # Check LinSec directory structure
    if [[ ! -d "$INVENTORY_DIR" ]]; then
        error "LinSec inventory directory not found: $INVENTORY_DIR"
        exit 1
    fi
    
    # Check inventory file exists
    local inventory_file="$INVENTORY_DIR/$ENVIRONMENT/hosts.yml"
    if [[ ! -f "$inventory_file" ]]; then
        error "Inventory file not found: $inventory_file"
        exit 1
    fi
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
    
    success "Prerequisites check passed"
}

# Get SSH public key
get_ssh_key() {
    if [[ -f "$HOME/.ssh/id_ed25519.pub" ]]; then
        cat "$HOME/.ssh/id_ed25519.pub"
    elif [[ -f "$HOME/.ssh/id_rsa.pub" ]]; then
        cat "$HOME/.ssh/id_rsa.pub"
    else
        error "No SSH public key found"
        exit 1
    fi
}

# Parse inventory and extract host information
parse_inventory() {
    log "Parsing inventory for environment: $ENVIRONMENT"
    
    local inventory_file="$INVENTORY_DIR/$ENVIRONMENT/hosts.yml"
    
    # Use ansible-inventory to get all hosts with their variables
    local inventory_json
    inventory_json=$(ansible-inventory -i "$inventory_file" --list)
    
    # Extract host information using Python
    python3 << EOF
import json
import sys

try:
    inventory = json.loads('''$inventory_json''')
    
    # Get all hosts
    all_hosts = inventory.get('_meta', {}).get('hostvars', {})
    
    if not all_hosts:
        print("No hosts found in inventory")
        sys.exit(1)
    
    # Extract host information
    for hostname, vars in all_hosts.items():
        if hostname == 'localhost':
            continue
            
        ansible_host = vars.get('ansible_host', hostname)
        
        # Find which group this host belongs to
        group = 'unknown'
        for group_name, group_data in inventory.items():
            if group_name.startswith('_'):
                continue
            if isinstance(group_data, dict) and hostname in group_data.get('hosts', []):
                group = group_name
                break
        
        print(f"{hostname}|{ansible_host}|{group}")
        
except Exception as e:
    print(f"Error parsing inventory: {e}")
    sys.exit(1)
EOF
}

# Load inventory hosts
load_inventory_hosts() {
    log "Loading inventory hosts..."
    
    local host_info
    host_info=$(parse_inventory)
    
    if [[ -z "$host_info" ]]; then
        error "No hosts found in inventory"
        exit 1
    fi
    
    # Parse host information
    while IFS='|' read -r hostname ip group; do
        if [[ -n "$hostname" && "$hostname" != "localhost" ]]; then
            HOST_IPS["$hostname"]="$ip"
            HOST_GROUPS["$hostname"]="$group"
            HOST_STATUS["$hostname"]="pending"
            ((TOTAL_HOSTS++))
        fi
    done <<< "$host_info"
    
    info "Found $TOTAL_HOSTS hosts in inventory"
    
    # Display hosts
    echo
    echo "Hosts to configure:"
    printf "%-20s %-15s %-15s\n" "HOSTNAME" "IP ADDRESS" "GROUP"
    printf "%-20s %-15s %-15s\n" "--------" "----------" "-----"
    for hostname in "${!HOST_IPS[@]}"; do
        printf "%-20s %-15s %-15s\n" "$hostname" "${HOST_IPS[$hostname]}" "${HOST_GROUPS[$hostname]}"
    done
    echo
}

# Get credentials for SSH setup
get_credentials() {
    if [[ "$DRY_RUN" == "true" ]]; then
        return 0
    fi
    
    echo "=== SSH Setup Credentials ==="
    echo
    echo "This script will configure SSH key authentication for all hosts in the inventory."
    echo "Initial SSH connection requires password authentication."
    echo
    
    # Get common root password
    read -s -p "Enter common root password for initial setup: " COMMON_ROOT_PASS
    echo
    
    # Option to use different passwords for specific hosts
    read -p "Do some hosts have different root passwords? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "You'll be prompted for individual passwords during setup."
        USE_INDIVIDUAL_PASSWORDS=true
    else
        USE_INDIVIDUAL_PASSWORDS=false
    fi
    
    echo
}

# Test host connectivity
test_connectivity() {
    local hostname=$1
    local ip=$2
    
    # Test ping
    if ! ping -c 1 -W 3 "$ip" &>/dev/null; then
        return 1
    fi
    
    # Test SSH port
    if ! timeout 5 bash -c "cat < /dev/null > /dev/tcp/$ip/22" 2>/dev/null; then
        return 1
    fi
    
    return 0
}

# Configure SSH for a single host
configure_host_ssh() {
    local hostname=$1
    local ip=$2
    local retry_count=0
    
    log "Configuring SSH for $hostname ($ip)..."
    
    # Test connectivity first
    if ! test_connectivity "$hostname" "$ip"; then
        error "Host $hostname ($ip) is not reachable"
        HOST_STATUS["$hostname"]="failed"
        return 1
    fi
    
    local ssh_key
    ssh_key=$(get_ssh_key)
    
    local new_root_pass
    new_root_pass=$(openssl rand -base64 32)
    
    # Get password for this host
    local host_password="$COMMON_ROOT_PASS"
    if [[ "$USE_INDIVIDUAL_PASSWORDS" == "true" ]]; then
        read -s -p "Enter root password for $hostname: " host_password
        echo
    fi
    
    # Create expect script
    local expect_script="$TEMP_DIR/ssh_setup_${hostname}.exp"
    cat > "$expect_script" << EOF
#!/usr/bin/expect -f
set timeout $CONNECTION_TIMEOUT
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=$CONNECTION_TIMEOUT root@$ip
expect {
    "password:" {
        send "$host_password\\r"
        exp_continue
    }
    "# " {
        # Create SSH directory and add key
        send "mkdir -p /root/.ssh && chmod 700 /root/.ssh\\r"
        expect "# "
        send "echo '$ssh_key' >> /root/.ssh/authorized_keys\\r"
        expect "# "
        send "chmod 600 /root/.ssh/authorized_keys\\r"
        expect "# "
        
        # Backup and configure SSH
        send "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.\\$(date +%Y%m%d)\\r"
        expect "# "
        send "sed -i 's/#\\\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config\\r"
        expect "# "
        send "sed -i 's/#\\\\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config\\r"
        expect "# "
        send "sed -i 's/#\\\\?AuthorizedKeysFile.*/AuthorizedKeysFile .ssh\\/authorized_keys/' /etc/ssh/sshd_config\\r"
        expect "# "
        
        # Restart SSH service
        send "systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || service sshd restart\\r"
        expect "# "
        
        # Change root password
        send "echo 'root:$new_root_pass' | chpasswd\\r"
        expect "# "
        
        # Ensure Python is available for Ansible
        send "which python3 && ln -sf \\$(which python3) /usr/bin/python 2>/dev/null || true\\r"
        expect "# "
        
        # Install basic packages if needed
        send "command -v curl || (apt-get update && apt-get install -y curl) || (yum install -y curl) || true\\r"
        expect "# "
        
        send "exit\\r"
        expect eof
    }
    "Permission denied" {
        puts "Permission denied for $hostname"
        exit 1
    }
    "Connection refused" {
        puts "Connection refused for $hostname"
        exit 1
    }
    timeout {
        puts "Connection timeout for $hostname"
        exit 1
    }
}
EOF
    
    chmod +x "$expect_script"
    
    # Execute SSH configuration with retries
    while [[ $retry_count -lt $MAX_RETRIES ]]; do
        if expect "$expect_script" > "$TEMP_DIR/${hostname}_setup.log" 2>&1; then
            # Test SSH key authentication
            if ssh -o PasswordAuthentication=no -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$ip" "echo 'SSH key authentication successful'" &>/dev/null; then
                success "SSH configured successfully for $hostname"
                HOST_STATUS["$hostname"]="success"
                
                # Store new root password securely
                echo "$hostname:$new_root_pass" >> "$TEMP_DIR/new_passwords.txt"
                chmod 600 "$TEMP_DIR/new_passwords.txt"
                
                # Update SSH config
                update_ssh_config_entry "$hostname" "$ip"
                
                return 0
            else
                warning "SSH key authentication test failed for $hostname (attempt $((retry_count + 1)))"
            fi
        else
            warning "SSH setup failed for $hostname (attempt $((retry_count + 1)))"
        fi
        
        ((retry_count++))
        if [[ $retry_count -lt $MAX_RETRIES ]]; then
            sleep 5
        fi
    done
    
    error "Failed to configure SSH for $hostname after $MAX_RETRIES attempts"
    HOST_STATUS["$hostname"]="failed"
    return 1
}

# Update SSH config for a single host
update_ssh_config_entry() {
    local hostname=$1
    local ip=$2
    
    # Remove existing entry if present
    if grep -q "Host $hostname" "$SSH_CONFIG_FILE" 2>/dev/null; then
        # Create temp file without the existing entry
        awk "
            /^Host $hostname\$/ { skip=1; next }
            /^Host / && skip { skip=0 }
            !skip { print }
        " "$SSH_CONFIG_FILE" > "$SSH_CONFIG_FILE.tmp"
        mv "$SSH_CONFIG_FILE.tmp" "$SSH_CONFIG_FILE"
    fi
    
    # Add new entry
    cat >> "$SSH_CONFIG_FILE" << EOF

Host $hostname
    HostName $ip
    User root
    IdentityFile ~/.ssh/id_ed25519
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
    ConnectTimeout 10
EOF
}

# Process hosts in batches
process_hosts() {
    log "Processing hosts in batches of $BATCH_SIZE..."
    
    local batch_count=0
    local pids=()
    
    for hostname in "${!HOST_IPS[@]}"; do
        if [[ "$DRY_RUN" == "true" ]]; then
            info "[DRY RUN] Would configure SSH for $hostname (${HOST_IPS[$hostname]})"
            HOST_STATUS["$hostname"]="success"
            ((PROCESSED_HOSTS++))
            ((SUCCESS_HOSTS++))
        else
            # Process host in background
            configure_host_ssh "$hostname" "${HOST_IPS[$hostname]}" &
            pids+=($!)
            ((batch_count++))
            
            # Wait for batch to complete
            if [[ $batch_count -ge $BATCH_SIZE ]]; then
                for pid in "${pids[@]}"; do
                    wait "$pid"
                done
                pids=()
                batch_count=0
            fi
        fi
        
        ((PROCESSED_HOSTS++))
        show_progress "$PROCESSED_HOSTS" "$TOTAL_HOSTS"
    done
    
    # Wait for remaining processes
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    echo # New line after progress bar
}

# Test Ansible connectivity for all hosts
test_ansible_connectivity() {
    log "Testing Ansible connectivity for all hosts..."
    
    local inventory_file="$INVENTORY_DIR/$ENVIRONMENT/hosts.yml"
    local failed_hosts=()
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY RUN] Would test Ansible connectivity"
        return 0
    fi
    
    # Test all hosts
    for hostname in "${!HOST_IPS[@]}"; do
        if [[ "${HOST_STATUS[$hostname]}" == "success" ]]; then
            if ansible -i "$inventory_file" "$hostname" -m ping -o &>/dev/null; then
                success "Ansible connectivity verified for $hostname"
            else
                error "Ansible connectivity failed for $hostname"
                failed_hosts+=("$hostname")
                HOST_STATUS["$hostname"]="ansible_failed"
            fi
        fi
    done
    
    if [[ ${#failed_hosts[@]} -gt 0 ]]; then
        warning "Ansible connectivity failed for: ${failed_hosts[*]}"
    fi
}

# Generate final report
generate_report() {
    log "Generating final report..."
    
    # Count results
    SUCCESS_HOSTS=0
    FAILED_HOSTS=0
    
    for hostname in "${!HOST_STATUS[@]}"; do
        case "${HOST_STATUS[$hostname]}" in
            "success")
                ((SUCCESS_HOSTS++))
                ;;
            "failed"|"ansible_failed")
                ((FAILED_HOSTS++))
                ;;
        esac
    done
    
    cat << EOF

=== LinSec SSH Setup Report ===
Environment: $ENVIRONMENT
Total Hosts: $TOTAL_HOSTS
Successful: $SUCCESS_HOSTS
Failed: $FAILED_HOSTS

EOF
    
    # Successful hosts
    if [[ $SUCCESS_HOSTS -gt 0 ]]; then
        echo "✅ Successfully configured hosts:"
        printf "%-20s %-15s %-15s\n" "HOSTNAME" "IP ADDRESS" "GROUP"
        printf "%-20s %-15s %-15s\n" "--------" "----------" "-----"
        for hostname in "${!HOST_STATUS[@]}"; do
            if [[ "${HOST_STATUS[$hostname]}" == "success" ]]; then
                printf "%-20s %-15s %-15s\n" "$hostname" "${HOST_IPS[$hostname]}" "${HOST_GROUPS[$hostname]}"
            fi
        done
        echo
    fi
    
    # Failed hosts
    if [[ $FAILED_HOSTS -gt 0 ]]; then
        echo "❌ Failed to configure hosts:"
        printf "%-20s %-15s %-15s %-10s\n" "HOSTNAME" "IP ADDRESS" "GROUP" "STATUS"
        printf "%-20s %-15s %-15s %-10s\n" "--------" "----------" "-----" "------"
        for hostname in "${!HOST_STATUS[@]}"; do
            if [[ "${HOST_STATUS[$hostname]}" =~ ^(failed|ansible_failed)$ ]]; then
                printf "%-20s %-15s %-15s %-10s\n" "$hostname" "${HOST_IPS[$hostname]}" "${HOST_GROUPS[$hostname]}" "${HOST_STATUS[$hostname]}"
            fi
        done
        echo
    fi
    
    # Next steps
    if [[ $SUCCESS_HOSTS -gt 0 ]]; then
        cat << EOF
Next steps:
1. Deploy LinSec components:
   cd $LINSEC_DIR
   ./scripts/deploy.sh $ENVIRONMENT

2. Test SSH connections:
   ssh <hostname>

3. Verify Ansible connectivity:
   ansible -i inventories/$ENVIRONMENT/hosts.yml all -m ping

Files created:
- Log file: $LOG_FILE
- SSH config: $SSH_CONFIG_FILE
- New passwords: $TEMP_DIR/new_passwords.txt (keep secure!)

EOF
    fi
}

# Cleanup function
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        # Keep important files
        if [[ -f "$TEMP_DIR/new_passwords.txt" ]]; then
            cp "$TEMP_DIR/new_passwords.txt" "$HOME/.linsec_passwords_$(date +%Y%m%d_%H%M%S).txt"
            chmod 600 "$HOME/.linsec_passwords_$(date +%Y%m%d_%H%M%S).txt"
            warning "New root passwords saved to $HOME/.linsec_passwords_$(date +%Y%m%d_%H%M%S).txt"
        fi
        
        # Clean temporary files
        rm -rf "$TEMP_DIR"
    fi
}

# Main execution
main() {
    log "Starting LinSec inventory SSH setup..."
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    parse_arguments "$@"
    check_prerequisites
    load_inventory_hosts
    get_credentials
    process_hosts
    test_ansible_connectivity
    generate_report
    
    if [[ $SUCCESS_HOSTS -eq $TOTAL_HOSTS ]]; then
        success "All hosts configured successfully!"
        exit 0
    elif [[ $SUCCESS_HOSTS -gt 0 ]]; then
        warning "Partial success: $SUCCESS_HOSTS/$TOTAL_HOSTS hosts configured"
        exit 1
    else
        error "No hosts were configured successfully"
        exit 1
    fi
}

# Execute main function
main "$@"