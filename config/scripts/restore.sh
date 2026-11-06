#!/usr/bin/env bash
# LinSec360 restore.
#
# Restores an archive created by config/scripts/backup.sh. The archive is
# verified before anything is changed, and existing data is moved aside to a
# timestamped .pre-restore-* path so the operation can be rolled back.
#
# Usage:
#   config/scripts/restore.sh <archive> [options]
#
# Options:
#   --yes              Required for destructive restore operations.
#   --no-files         Do not restore config/ and taskengine/.
#   --no-database      Do not restore the database.
#   --with-wazuh       Also restore the Wazuh manager data. Stops the manager.
#
# Environment:
#   LINSEC_RESTORE_DB_PATH        Explicit SQLite destination path.
#   LINSEC_DATABASE_URL           Used to locate the SQLite/PostgreSQL target.
#   LINSEC_RESTORE_NO_SAFETY_BACKUP=1  Skip the automatic pre-restore backup.
#   LINSEC_COMPOSE_FILE           Compose file used for PostgreSQL/Wazuh.
#
# Restoring PostgreSQL requires pg_restore and connection credentials (PGPASSWORD
# or a .pgpass file). Restoring Wazuh requires the manager image to be available.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="${LINSEC_COMPOSE_FILE:-$REPO_ROOT/docker-compose.yml}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

ARCHIVE=""
CONFIRMED=0
RESTORE_FILES=1
RESTORE_DATABASE=1
RESTORE_WAZUH=0

log() {
    printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"
}

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: config/scripts/restore.sh <archive> [--yes] [--no-files] [--no-database] [--with-wazuh]

  --yes           Confirm the destructive restore. Required.
  --no-files      Restore only the database.
  --no-database   Restore only the files (config/ and taskengine/).
  --with-wazuh    Restore /var/ossec data into the Wazuh manager.
  -h, --help      Show this help.
EOF
}

while (($#)); do
    case "$1" in
        --yes) CONFIRMED=1 ;;
        --no-files) RESTORE_FILES=0 ;;
        --no-database) RESTORE_DATABASE=0 ;;
        --with-wazuh) RESTORE_WAZUH=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        -*)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            [[ -z "$ARCHIVE" ]] || fail "only one archive may be restored at a time"
            ARCHIVE="$1"
            ;;
    esac
    shift
done

[[ -n "$ARCHIVE" ]] || {
    usage >&2
    exit 2
}
[[ -f "$ARCHIVE" ]] || fail "archive not found: $ARCHIVE"
[[ -r "$ARCHIVE" ]] || fail "archive is not readable: $ARCHIVE"

if ((CONFIRMED == 0)); then
    fail "destructive restore requires --yes"
fi

EXTRACT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/linsec-restore-XXXXXXXX")"
cleanup() {
    rm -rf "$EXTRACT_DIR"
}
trap cleanup EXIT

log "Validating archive structure"
while IFS= read -r entry; do
    case "$entry" in
        /*) fail "archive contains an absolute path: $entry" ;;
    esac
    case "/$entry/" in
        */../*) fail "archive contains a parent-directory path: $entry" ;;
    esac
done < <(tar -tzf "$ARCHIVE")

log "Extracting archive to a temporary directory"
tar -xzf "$ARCHIVE" -C "$EXTRACT_DIR"

STAGE_ROOT="$(find "$EXTRACT_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
[[ -n "$STAGE_ROOT" ]] || fail "archive does not contain a backup directory"

if [[ -f "$STAGE_ROOT/SHA256SUMS" ]]; then
    log "Verifying checksums"
    (
        cd "$STAGE_ROOT"
        sha256sum -c SHA256SUMS >/dev/null
    ) || fail "checksum verification failed; refusing to restore"
else
    log "WARNING: archive has no SHA256SUMS file"
fi

if [[ -f "$STAGE_ROOT/manifest.json" ]]; then
    log "Archive manifest:"
    sed 's/^/    /' "$STAGE_ROOT/manifest.json"
fi

safety_backup() {
    if [[ "${LINSEC_RESTORE_NO_SAFETY_BACKUP:-0}" == "1" ]]; then
        log "Safety backup explicitly disabled"
        return 0
    fi
    if [[ ! -x "$SCRIPT_DIR/backup.sh" ]]; then
        log "WARNING: backup.sh is not executable; no safety backup was taken"
        return 0
    fi
    local safety_dir
    safety_dir="$(cd "$(dirname "$ARCHIVE")" && pwd)/pre-restore"
    log "Creating a safety backup in $safety_dir"
    if ! LINSEC_BACKUP_DIR="$safety_dir" LINSEC_BACKUP_RETENTION_DAYS=0 \
        "$SCRIPT_DIR/backup.sh" --no-wazuh; then
        log "WARNING: safety backup failed; continuing after explicit --yes"
    fi
}

sqlite_target() {
    local url="${LINSEC_DATABASE_URL:-}"
    if [[ -n "${LINSEC_RESTORE_DB_PATH:-}" ]]; then
        printf '%s' "$LINSEC_RESTORE_DB_PATH"
        return 0
    fi
    case "$url" in
        sqlite:////*)
            printf '/%s' "${url#sqlite:////}"
            ;;
        sqlite:///*)
            printf '%s' "${url#sqlite:///}"
            ;;
        *)
            if [[ -d "$REPO_ROOT/app/instance" ]]; then
                printf '%s' "$REPO_ROOT/app/instance/linsec.db"
            else
                printf '%s' "$REPO_ROOT/var/linsec.db"
            fi
            ;;
    esac
}

restore_sqlite() {
    local source="$1"
    local target
    target="$(sqlite_target)"
    mkdir -p "$(dirname "$target")"
    if [[ -f "$target" ]]; then
        mv "$target" "$target.pre-restore-$TIMESTAMP"
        log "Moved existing database to $target.pre-restore-$TIMESTAMP"
    fi
    cp --preserve=mode,timestamps "$source" "$target"
    chmod 600 "$target"
    log "Restored SQLite database to $target"
}

restore_postgres() {
    local source="$1"
    local url="${LINSEC_DATABASE_URL:-}"
    [[ -n "$url" ]] || fail "LINSEC_DATABASE_URL is required to restore PostgreSQL"

    local pgurl="${url/postgresql+psycopg/postgresql}"
    if command -v pg_restore >/dev/null 2>&1; then
        pg_restore --clean --if-exists --no-owner --no-privileges \
            --dbname "$pgurl" "$source"
        log "Restored PostgreSQL database with pg_restore"
        return 0
    fi

    if command -v docker >/dev/null 2>&1 &&
        docker compose -f "$COMPOSE_FILE" ps -q postgres >/dev/null 2>&1 &&
        [[ -n "$(docker compose -f "$COMPOSE_FILE" ps -q postgres)" ]]; then
        docker compose -f "$COMPOSE_FILE" exec -T postgres \
            pg_restore -U linsec -d linsec --clean --if-exists \
            --no-owner --no-privileges <"$source"
        log "Restored PostgreSQL database through the compose container"
        return 0
    fi

    fail "pg_restore is unavailable and no PostgreSQL container is running"
}

restore_database() {
    local sqlite_file="$STAGE_ROOT/database/linsec.db"
    local pg_file="$STAGE_ROOT/database/linsec.dump"

    if [[ -f "$sqlite_file" ]]; then
        restore_sqlite "$sqlite_file"
    elif [[ -f "$pg_file" ]]; then
        restore_postgres "$pg_file"
    else
        log "Archive has no database; database restore skipped"
    fi
}

restore_files() {
    local files_archive="$STAGE_ROOT/linsec-files.tar.gz"
    if [[ ! -f "$files_archive" ]]; then
        log "Archive has no repository files; file restore skipped"
        return 0
    fi

    local -a entries=()
    while IFS= read -r entry; do
        entries+=("$entry")
    done < <(tar -tzf "$files_archive" | awk -F/ '{print $1}' | sort -u)

    local entry
    for entry in "${entries[@]}"; do
        case "$entry" in
            "" | . | ..) continue ;;
            # Only operational data is moved aside. Docs and the env example
            # are safe to overwrite and stay under version control.
            config | taskengine) ;;
            *) continue ;;
        esac
        if [[ -e "$REPO_ROOT/$entry" ]]; then
            mv "$REPO_ROOT/$entry" "$REPO_ROOT/$entry.pre-restore-$TIMESTAMP"
            log "Moved existing $entry to $entry.pre-restore-$TIMESTAMP"
        fi
    done

    tar -xzf "$files_archive" -C "$REPO_ROOT"
    log "Restored repository files: ${entries[*]}"
}

restore_wazuh() {
    local wazuh_archive="$STAGE_ROOT/wazuh-ossec.tar.gz"
    if [[ ! -f "$wazuh_archive" ]]; then
        log "Archive has no Wazuh data; Wazuh restore skipped"
        return 0
    fi
    command -v docker >/dev/null 2>&1 ||
        fail "docker is required to restore Wazuh data"
    [[ -f "$COMPOSE_FILE" ]] || fail "compose file not found: $COMPOSE_FILE"

    local compose=(docker compose -f "$COMPOSE_FILE")
    log "Stopping the Wazuh manager"
    "${compose[@]}" stop wazuh.manager

    log "Restoring /var/ossec data"
    "${compose[@]}" run --rm --no-deps -T --entrypoint tar \
        wazuh.manager -xzf - -C /var/ossec <"$wazuh_archive"

    log "Starting the Wazuh manager"
    "${compose[@]}" up -d wazuh.manager
    log "Wazuh data restored"
}

main() {
    log "Restoring $ARCHIVE"
    safety_backup

    ((RESTORE_DATABASE == 1)) && restore_database
    ((RESTORE_FILES == 1)) && restore_files
    ((RESTORE_WAZUH == 1)) && restore_wazuh

    log "Restore completed"
    log "Re-run 'alembic upgrade head' if the archive predates the current schema"
}

main "$@"
