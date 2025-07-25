#!/bin/bash
set -euo pipefail

# Define where to store SSH keys for linsecagent
SSH_DIR="/opt/linsec/.ssh"

# Ensure the SSH directory exists
if [ ! -d "$SSH_DIR" ]; then
  mkdir -p "$SSH_DIR"
  chown linsecagent:linsecagent "$SSH_DIR"
  chmod 700 "$SSH_DIR"
fi

# Generate SSH keys if not present
if [ ! -f "$SSH_DIR/id_ed25519" ]; then
  echo "Generating SSH key pair for linsecagent..."
  sudo ssh-keygen -t ed25519 -N "" -f "$SSH_DIR/id_ed25519"
  sudo chown linsecagent:linsecagent "$SSH_DIR/id_ed25519" "$SSH_DIR/id_ed25519.pub"
  sudo chmod 600 "$SSH_DIR/id_ed25519"
  sudo chmod 644 "$SSH_DIR/id_ed25519.pub"
  echo "Public key:"
  cat "$SSH_DIR/id_ed25519.pub"
fi

# Generate Ansible vault password if needed
if [ ! -f "/opt/linsec/taskengine/.vault_pass" ]; then
  echo "Generating Ansible Vault password..."
  openssl rand -base64 32 > /opt/linsec/taskengine/.vault_pass
  chmod 600 /opt/linsec/taskengine/.vault_pass
fi

# Start the Flask app with Gunicorn
exec gunicorn "app:create_app()" \
  --bind 0.0.0.0:5000 \
  --workers 4 \
  --access-logfile /opt/linsec/logs/access.log