#!/usr/bin/env bash
# LinSec360 backup.
#
# Creates a single, checksummed archive containing:
#   - the application database (SQLite file or PostgreSQL custom dump)
#   - the versioned configuration under config/
#   - the Ansible task engine (inventories, playbooks, roles)
#   - optionally /var/ossec from the running Wazuh manager container
#
# Usage:
#   config/scripts/backup.sh [--with-wazuh|--no-wazuh]
#
# Environment:
#   LINSEC_BACKUP_DIR            Destination directory (default /var/backups/linsec360)
#   LINSEC_BACKUP_RETENTION_DAYS Delete archives older than N days (default 14)
#   LINSEC_DATABASE_URL          sqlite:///... or postgresql+psycopg://...
#   LINSEC_BACKUP_INCLUDE_ENV    Set to 1 to include .env (contains secrets)
#   LINSEC_COMPOSE_FILE          Compose file used to reach wazuh.manager
#
# Backups contain credentials and private keys. The archive is created with mode
# 0600 and the directory with 0700; store it on encrypted media and copy it off
# the host.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

BACKUP_DIR="${LINSEC_BACKUP_DIR:-/var/backups/linsec360}"
RETENTION_DAYS="${LINSEC_BACKUP_RETENTION_DAYS:-14}"
INCLUDE_WAZUH="${LINSEC_BACKUP_WAZUH:-auto}"
INCLUDE_ENV="${LINSEC_BACKUP_INCLUDE_ENV:-0}"
COMPOSE_FILE="${LINSEC_COMPOSE_FILE:-$REPO_ROOT/docker-compose.yml}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STAGING="$BACKUP_DIR/linsec360-$TIMESTAMP"
ARCHIVE="$BACKUP_DIR/linsec360-$TIMESTAMP.tar.gz"

log() {
    printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"
}

usage() {
    cat <<'EOF'
Usage: config/scripts/backup.sh [--with-wazuh|--no-wazuh]

  --with-wazuh  Always try to back up the Wazuh manager data.
  --no-wazuh    Never back up Wazuh data.
  -h, --help    Show this help.

Default (auto) backs up Wazuh only when the manager container is running.
EOF
}

while (($#)); do
    case "$1" in
        --with-wazuh) INCLUDE_WAZUH=yes ;;
        --no-wazuh) INCLUDE_WAZUH=no ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if [[ ! "$RETENTION_DAYS" =~ ^[0-9]+$ ]]; then
    echo "LINSEC_BACKUP_RETENTION_DAYS must be a non-negative integer" >&2
    exit 2
fi

cleanup() {
    if [[ -d "$STAGING" ]]; then
        rm -rf "$STAGING"
    fi
}
trap cleanup EXIT

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
mkdir -p "$STAGING"

manifest_items=()

record_item() {
    manifest_items+=("$1")
}

compose() {
    docker compose -f "$COMPOSE_FILE" "$@"
}

backup_env() {
    if [[ "$INCLUDE_ENV" != "1" ]]; then
        log "Skipping .env (set LINSEC_BACKUP_INCLUDE_ENV=1 to include secrets)"
        return 0
    fi
    if [[ -f "$REPO_ROOT/.env" ]]; then
        cp -p "$REPO_ROOT/.env" "$STAGING/env"
        chmod 600 "$STAGING/env"
        record_item "env"
        log "Backed up .env"
    fi
}

backup_database() {
    local url="${LINSEC_DATABASE_URL:-}"
    if [[ -z "$url" ]]; then
        local legacy="$REPO_ROOT/app/instance/linsec.db"
        local modern="$REPO_ROOT/var/linsec.db"
        if [[ -f "$legacy" ]]; then
            url="sqlite:///$legacy"
        elif [[ -f "$modern" ]]; then
            url="sqlite:///$modern"
        fi
    fi

    if [[ -z "$url" ]]; then
        log "WARNING: no database configured; database backup skipped"
        return 0
    fi

    case "$url" in
        sqlite:///*)
            local source="${url#sqlite:///}"
            # sqlite:////absolute/path keeps its leading slash after the strip.
            if [[ "$url" == "sqlite:////"* ]]; then
                source="/${url#sqlite:////}"
            fi
            if [[ ! -f "$source" ]]; then
                log "WARNING: SQLite database not found at $source; skipped"
                return 0
            fi
            mkdir -p "$STAGING/database"
            if command -v sqlite3 >/dev/null 2>&1; then
                sqlite3 "$source" ".backup '$STAGING/database/linsec.db'"
            else
                cp --preserve=mode,timestamps "$source" "$STAGING/database/linsec.db"
            fi
            chmod 600 "$STAGING/database/linsec.db"
            record_item "database/linsec.db"
            log "Backed up SQLite database ($source)"
            ;;
        postgresql* | postgres*)
            local pgurl="${url/postgresql+psycopg/postgresql}"
            mkdir -p "$STAGING/database"
            if command -v pg_dump >/dev/null 2>&1; then
                pg_dump --no-owner --no-privileges --format=custom \
                    --file "$STAGING/database/linsec.dump" "$pgurl"
                chmod 600 "$STAGING/database/linsec.dump"
                record_item "database/linsec.dump"
                log "Backed up PostgreSQL database with pg_dump"
            elif command -v docker >/dev/null 2>&1 &&
                compose ps -q postgres >/dev/null 2>&1 &&
                [[ -n "$(compose ps -q postgres)" ]]; then
                compose exec -T postgres pg_dump -U linsec -d linsec \
                    --no-owner --no-privileges --format=custom \
                    >"$STAGING/database/linsec.dump"
                chmod 600 "$STAGING/database/linsec.dump"
                record_item "database/linsec.dump"
                log "Backed up PostgreSQL database through the compose container"
            else
                log "WARNING: pg_dump is unavailable; database backup skipped"
            fi
            ;;
        *)
            log "WARNING: unsupported database URL scheme; database backup skipped"
            ;;
    esac

    if [[ ! -s "$STAGING/database/linsec.db" && ! -s "$STAGING/database/linsec.dump" ]]; then
        rmdir "$STAGING/database" 2>/dev/null || true
    fi
}

backup_repository_data() {
    local paths=()
    [[ -d "$REPO_ROOT/config" ]] && paths+=("config")
    [[ -d "$REPO_ROOT/taskengine" ]] && paths+=("taskengine")
    [[ -d "$REPO_ROOT/docs" ]] && paths+=("docs")
    [[ -f "$REPO_ROOT/.env.example" ]] && paths+=(".env.example")

    if ((${#paths[@]} == 0)); then
        log "WARNING: no configuration or task engine directory found"
        return 0
    fi

    tar -C "$REPO_ROOT" -czf "$STAGING/linsec-files.tar.gz" "${paths[@]}"
    chmod 600 "$STAGING/linsec-files.tar.gz"
    record_item "linsec-files.tar.gz"
    log "Backed up repository data: ${paths[*]}"
}

wazuh_running() {
    command -v docker >/dev/null 2>&1 || return 1
    [[ -f "$COMPOSE_FILE" ]] || return 1
    local container
    container="$(compose ps -q wazuh.manager 2>/dev/null || true)"
    [[ -n "$container" ]]
}

backup_wazuh() {
    if [[ "$INCLUDE_WAZUH" == "no" ]]; then
        log "Wazuh backup disabled"
        return 0
    fi
    if ! wazuh_running; then
        if [[ "$INCLUDE_WAZUH" == "yes" ]]; then
            log "WARNING: wazuh.manager is not running; Wazuh backup skipped"
        else
            log "Wazuh manager is not running; Wazuh backup skipped"
        fi
        return 0
    fi

    log "Backing up Wazuh manager data"
    # etc/ holds local configuration and keys; queue/ holds agent state.
    compose exec -T wazuh.manager \
        tar -czf - -C /var/ossec etc queue >"$STAGING/wazuh-ossec.tar.gz"
    chmod 600 "$STAGING/wazuh-ossec.tar.gz"
    record_item "wazuh-ossec.tar.gz"
    log "Backed up /var/ossec/etc and /var/ossec/queue"
}

write_manifest() {
    local items_json=""
    local item
    local database_scheme="none"
    for item in "${manifest_items[@]}"; do
        items_json+="${items_json:+, }\"$item\""
    done

    if [[ -n "${LINSEC_DATABASE_URL:-}" ]]; then
        database_scheme="${LINSEC_DATABASE_URL%%:*}"
    fi

    cat >"$STAGING/manifest.json" <<EOF
{
  "format": 1,
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$(hostname -f 2>/dev/null || hostname)",
  "repository": "$REPO_ROOT",
  "database_url_scheme": "$database_scheme"
}
EOF
    # Keep the manifest valid JSON without requiring jq.
    if command -v jq >/dev/null 2>&1; then
        jq --argjson items "[$items_json]" '. + {items: $items}' \
            "$STAGING/manifest.json" >"$STAGING/manifest.json.tmp"
        mv "$STAGING/manifest.json.tmp" "$STAGING/manifest.json"
    fi
    chmod 600 "$STAGING/manifest.json"
}

write_checksums() {
    (
        cd "$STAGING"
        find . -type f ! -name SHA256SUMS -print0 |
            sort -z |
            xargs -0 sha256sum >SHA256SUMS
        chmod 600 SHA256SUMS
    )
}

create_archive() {
    tar -czf "$ARCHIVE" -C "$BACKUP_DIR" "$(basename "$STAGING")"
    chmod 600 "$ARCHIVE"

    if ! tar -tzf "$ARCHIVE" >/dev/null 2>&1; then
        echo "Backup archive failed integrity check: $ARCHIVE" >&2
        rm -f "$ARCHIVE"
        exit 1
    fi
}

prune_old_backups() {
    if ((RETENTION_DAYS == 0)); then
        log "Retention is 0 days; old backups are not pruned"
        return 0
    fi
    local deleted
    deleted="$(
        find "$BACKUP_DIR" -maxdepth 1 -type f \
            -name 'linsec360-*.tar.gz' -mtime +"$RETENTION_DAYS" -print -delete
    )"
    if [[ -n "$deleted" ]]; then
        log "Pruned archives older than $RETENTION_DAYS days:"
        printf '%s\n' "$deleted"
    fi
}

main() {
    log "Starting backup into $BACKUP_DIR"
    backup_database
    backup_repository_data
    backup_wazuh
    backup_env
    write_manifest
    write_checksums
    create_archive

    local size
    size="$(du -h "$ARCHIVE" | cut -f1)"
    log "Backup completed: $ARCHIVE ($size)"
    log "Contents: ${manifest_items[*]:-none}"
    prune_old_backups
}

main "$@"
