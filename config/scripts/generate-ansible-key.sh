#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
key_dir=${LINSEC_SSH_KEY_DIR:-"$repo_root/.ssh"}
case "$key_dir" in
    /*) ;;
    *) key_dir="$repo_root/$key_dir" ;;
esac
private_key="$key_dir/id_ed25519"
public_key="$private_key.pub"

if [ -e "$private_key" ] || [ -e "$public_key" ]; then
    printf 'Refusing to overwrite an existing Ansible SSH key: %s\n' "$private_key" >&2
    exit 1
fi

mkdir -p "$key_dir"
chmod 700 "$key_dir"
ssh-keygen -q -t ed25519 -a 64 -N '' -C linsec-ansible -f "$private_key"
chmod 600 "$private_key"
chmod 644 "$public_key"

printf 'Ansible SSH key created at %s\n' "$private_key"
printf 'Public key (safe to share): %s\n' "$public_key"
