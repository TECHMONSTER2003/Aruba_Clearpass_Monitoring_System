#!/usr/bin/env bash
# CPPM Monitor backup: MySQL dump + ticket files + /etc/cppmmon (env + Fernet key).
# Run as root (systemd timer cppmmon-backup.timer, daily). Keeps the newest $KEEP archives.
#
#   sudo /opt/cppmmon/tools/backup.sh            # → /var/backups/cppmmon/cppmmon-YYYYmmdd-HHMMSS.tar.gz
#
# Restore (on a host installed with deploy/install.sh, services stopped):
#   tar -xzf cppmmon-*.tar.gz -C /tmp/restore
#   cp -a /tmp/restore/etc/cppmmon/. /etc/cppmmon/             # env + secret.key (needed to decrypt node credentials)
#   gunzip -c /tmp/restore/cppmmon.sql.gz | mysql cppmmon
#   cp -a /tmp/restore/tickets/. /var/lib/cppmmon/tickets/ && chown -R cppmmon:cppmmon /var/lib/cppmmon/tickets
#   systemctl start 'cppmmon-*'
set -Eeuo pipefail
DEST=${CPPMMON_BACKUP_DIR:-/var/backups/cppmmon}
KEEP=${CPPMMON_BACKUP_KEEP:-14}
STAMP=$(date -u +%Y%m%d-%H%M%S)
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
install -d -m 0750 -o root -g cppmmon "$DEST"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
umask 027

DB=$(grep -E '^CPPMMON_DB_URL=' /etc/cppmmon/cppmmon.env | cut -d= -f2-)
if [[ "$DB" == mysql* ]]; then
  mysqldump --single-transaction --routines --no-tablespaces -uroot cppmmon | gzip -9 > "$WORK/cppmmon.sql.gz"
else
  cp "${DB#sqlite:///}" "$WORK/cppmmon.db"
fi
mkdir -p "$WORK/etc" "$WORK/tickets"
cp -a /etc/cppmmon "$WORK/etc/"
cp -a /var/lib/cppmmon/tickets/. "$WORK/tickets/" 2>/dev/null || true
OUT="$DEST/cppmmon-$STAMP.tar.gz"
tar -C "$WORK" -czf "$OUT" .
chown root:cppmmon "$OUT"; chmod 0640 "$OUT"
ls -1t "$DEST"/cppmmon-*.tar.gz | tail -n +$((KEEP + 1)) | xargs -r rm -f
echo "backup written: $OUT ($(du -h "$OUT" | cut -f1))"
