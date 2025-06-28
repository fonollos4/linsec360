#!/bin/bash
# scripts/backup.sh

BACKUP_DIR="/opt/linsec360-backups"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_NAME="linsec360-backup-$TIMESTAMP"

mkdir -p "$BACKUP_DIR/$BACKUP_NAME"

# Sauvegarde des volumes Docker
docker-compose exec wazuh-manager tar czf /tmp/wazuh-data.tar.gz /var/ossec
docker cp $(docker-compose ps -q wazuh-manager):/tmp/wazuh-data.tar.gz "$BACKUP_DIR/$BACKUP_NAME/"

# Sauvegarde de la configuration
cp -r config/ "$BACKUP_DIR/$BACKUP_NAME/"
cp -r ansible/ "$BACKUP_DIR/$BACKUP_NAME/"

# Compression finale
tar czf "$BACKUP_DIR/$BACKUP_NAME.tar.gz" -C "$BACKUP_DIR" "$BACKUP_NAME"
rm -rf "$BACKUP_DIR/$BACKUP_NAME"

echo "Backup completed: $BACKUP_DIR/$BACKUP_NAME.tar.gz"