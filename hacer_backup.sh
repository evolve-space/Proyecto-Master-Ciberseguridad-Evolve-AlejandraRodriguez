#!/bin/bash
# Noctua Predictive — Backup simple de datos criticos
FECHA=$(date +%Y%m%d_%H%M)
DESTINO="/root/asoar/backups"
mkdir -p "$DESTINO"

tar -czf "$DESTINO/noctua_backup_$FECHA.tar.gz" \
    /root/asoar/*.py \
    /root/asoar/*.json \
    /root/asoar/.env \
    /root/asoar/models/ \
    /var/ossec/etc/rules/suricata_custom_rules.xml \
    2>/dev/null

echo "Backup creado: $DESTINO/noctua_backup_$FECHA.tar.gz"
ls -lh "$DESTINO/noctua_backup_$FECHA.tar.gz"

# Mantener solo los ultimos 7 backups
cd "$DESTINO" && ls -t noctua_backup_*.tar.gz | tail -n +8 | xargs -r rm --
