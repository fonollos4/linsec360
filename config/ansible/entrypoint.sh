#!/bin/bash
set -euo pipefail

# Generate SSH keys if not present
if [ ! -f "/root/.ssh/id_ed25519" ]; then
  echo "Generating SSH key pair..."
  ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519
  echo "Public key:"
  cat /root/.ssh/id_ed25519.pub
fi

# Generate Ansible vault password if needed
if [ ! -f "/ansible/.vault_pass" ]; then
  echo "Generating Ansible Vault password..."
  openssl rand -base64 32 > /ansible/.vault_pass
  chmod 600 /ansible/.vault_pass
fi

# Fix permissions for mounted volumes
chmod -R 755 /ansible
find /ansible -type d -exec chmod 755 {} \;
find /ansible -type f -exec chmod 644 {} \;

# Execute command
exec "$@"