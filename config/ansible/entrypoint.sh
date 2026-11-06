#!/bin/bash
set -euo pipefail

# Define where to store SSH keys for linsecagent
SSH_DIR="/opt/linsec/.ssh"

sudo -n /usr/local/sbin/linsec360-init-ssh
echo "Public key:"
cat "$SSH_DIR/id_ed25519.pub"

# Generate Ansible vault password if needed
if [ ! -f "/opt/linsec/taskengine/.vault_pass" ]; then
  echo "Generating Ansible Vault password..."
  openssl rand -base64 32 > /opt/linsec/taskengine/.vault_pass
  chmod 600 /opt/linsec/taskengine/.vault_pass
fi

# Initialize the SQLite database on first boot. The instance directory is
# volume-mounted, so the database created at image build time may be hidden.
if [ ! -f "/opt/linsec/app/instance/linsec.db" ]; then
  echo "Initializing LinSec360 database..."
  (cd /opt/linsec/app && flask --app 'app:create_app()' init-db)
fi

# Start the Flask app with Gunicorn
exec gunicorn "app:create_app()" \
  --bind 0.0.0.0:5000 \
  --workers 4 \
  --access-logfile - \
  --error-logfile -