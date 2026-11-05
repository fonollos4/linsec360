#!/bin/bash
set -euo pipefail

SSH_DIR="/opt/linsec/.ssh"
PRIVATE_KEY="$SSH_DIR/id_ed25519"
PUBLIC_KEY="$SSH_DIR/id_ed25519.pub"
LOG_DIR="/opt/linsec/logs"

if [ -L "$SSH_DIR" ]; then
    echo "SSH directory must not be a symbolic link." >&2
    exit 1
fi

mkdir -p "$SSH_DIR"
if [ -L "$PRIVATE_KEY" ] || [ -L "$PUBLIC_KEY" ]; then
    echo "SSH key files must not be symbolic links." >&2
    exit 1
fi

if [ ! -e "$PRIVATE_KEY" ] && [ ! -e "$PUBLIC_KEY" ]; then
    ssh-keygen -q -t ed25519 -N "" -f "$PRIVATE_KEY"
elif [ ! -f "$PRIVATE_KEY" ] || [ ! -f "$PUBLIC_KEY" ]; then
    echo "SSH key pair is incomplete." >&2
    exit 1
fi

chown linsecagent:linsecagent "$PRIVATE_KEY" "$PUBLIC_KEY"
chmod 600 "$PRIVATE_KEY"
chmod 644 "$PUBLIC_KEY"
chown linsecagent:linsecagent "$SSH_DIR"
chmod 700 "$SSH_DIR"

if [ -L "$LOG_DIR" ]; then
    echo "Log directory must not be a symbolic link." >&2
    exit 1
fi
mkdir -p "$LOG_DIR"

chown -R linsecagent:linsecagent "$LOG_DIR"
find "$LOG_DIR" -type d -exec chmod 0775 {} +
find "$LOG_DIR" -type f -exec chmod 0664 {} +

# Ensure Gunicorn can create and append to its access log if it is configured
# to use a file-backed log.
touch "$LOG_DIR/access.log"
touch "$LOG_DIR/error.log"
chown linsecagent:linsecagent "$LOG_DIR/access.log" "$LOG_DIR/error.log"
chmod 0664 "$LOG_DIR/access.log" "$LOG_DIR/error.log"
