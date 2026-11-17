#!/usr/bin/env bash
# CPPM Monitor installer. Idempotent: safe to re-run for upgrades.
#
#   sudo ./deploy/install.sh                 # full install / upgrade
#   sudo ./deploy/install.sh --no-packages   # skip apt/dnf step
#   sudo ./deploy/install.sh --prepare-only  # packages, user, dirs, venv, DB, env; no units/migrations
#
# Never stops/disables foreign services, never drops databases, never disables
# SELinux/firewalls. Secrets are generated once and never printed.
set -Eeuo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR=/opt/cppmmon
ETC_DIR=/etc/cppmmon
DATA_DIR=/var/lib/cppmmon
LOG_DIR=/var/log/cppmmon
SVC_USER=cppmmon
ENV_FILE="$ETC_DIR/cppmmon.env"
KEY_FILE="$ETC_DIR/secret.key"
UNITS=(cppmmon-receiver cppmmon-poller cppmmon-engine cppmmon-web)

DO_PACKAGES=1
PREPARE_ONLY=0
for a in "$@"; do
  case "$a" in
    --no-packages) DO_PACKAGES=0 ;;
    --prepare-only) PREPARE_ONLY=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;34m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO: $BASH_COMMAND"' ERR

[[ $EUID -eq 0 ]] || die "run as root (sudo)"
. /etc/os-release

# ------------------------------------------------------------- packages
pick_python() {
  for p in python3.13 python3.12 python3.11; do
    command -v "$p" >/dev/null 2>&1 && { echo "$(command -v "$p")"; return; }
  done
  return 1
}

if [[ $DO_PACKAGES -eq 1 ]]; then
  if command -v apt-get >/dev/null; then
    log "installing OS packages (apt)"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3-venv python3-dev build-essential mysql-server snmp fping rsync tzdata >/dev/null
  elif command -v dnf >/dev/null; then
    log "installing OS packages (dnf)"
    dnf install -y -q python3.11 python3.11-pip python3.11-devel gcc mysql-server net-snmp-utils fping rsync >/dev/null
  else
    die "no apt-get or dnf found"
  fi
fi
PY="$(pick_python)" || die "Python 3.11+ not found"
log "python: $PY ($("$PY" --version))"

# ---------------------------------------------------- unprivileged ICMP
# icmplib runs with privileged=False (no CAP_NET_RAW in the units). Allow ICMP
# echo sockets for all groups; approved option (a), Phase 1, 2026-11-17.
SYSCTL_FILE=/etc/sysctl.d/60-cppmmon-ping.conf
if [[ ! -f "$SYSCTL_FILE" ]]; then
  log "enabling unprivileged ICMP ($SYSCTL_FILE)"
  printf '%s\n' '# cppmmon: allow unprivileged ICMP echo sockets (icmplib privileged=False)' \
                'net.ipv4.ping_group_range = 0 2147483647' > "$SYSCTL_FILE"
  sysctl -q -p "$SYSCTL_FILE"
fi

# ------------------------------------------------------- user and dirs
if ! id "$SVC_USER" >/dev/null 2>&1; then
  log "creating system user $SVC_USER"
  useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi
install -d -m 0755 -o root -g root "$APP_DIR"
install -d -m 0750 -o root -g "$SVC_USER" "$ETC_DIR"
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR" "$DATA_DIR/spool" "$DATA_DIR/tickets" "$LOG_DIR"

# ------------------------------------------------------------ code + venv
log "syncing code to $APP_DIR"
rsync -a --delete \
  --exclude 'venv/' --exclude '.git/' --exclude '__pycache__/' --exclude '*.pyc' \
  --exclude '.pytest_cache/' --exclude 'requirements.lock' \
  "$SRC_DIR/" "$APP_DIR/"
chown -R root:root "$APP_DIR"
chmod -R u=rwX,go=rX "$APP_DIR"

if [[ ! -x "$APP_DIR/venv/bin/python" ]]; then
  log "creating venv"
  "$PY" -m venv "$APP_DIR/venv"
fi
log "installing Python dependencies"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements-dev.txt"
"$APP_DIR/venv/bin/pip" freeze --exclude-editable > "$APP_DIR/requirements.lock"
SITE="$("$APP_DIR/venv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
echo "$APP_DIR" > "$SITE/cppmmon.pth"

# ---------------------------------------------------------------- secrets
if [[ ! -s "$KEY_FILE" ]]; then
  log "generating Fernet key $KEY_FILE"
  umask 027
  "$APP_DIR/venv/bin/python" -c 'from cryptography.fernet import Fernet; import sys; sys.stdout.write(Fernet.generate_key().decode())' > "$KEY_FILE"
fi
chown root:"$SVC_USER" "$KEY_FILE"; chmod 0640 "$KEY_FILE"

# ---------------------------------------------------------------- database
rand() { "$APP_DIR/venv/bin/python" -c 'import secrets; print(secrets.token_urlsafe(32))'; }

if [[ ! -s "$ENV_FILE" ]]; then
  DB_URL=""
  if systemctl list-unit-files mysql.service >/dev/null 2>&1 && command -v mysql >/dev/null; then
    systemctl enable --now mysql >/dev/null 2>&1 || true
    if systemctl is-active --quiet mysql; then
      log "creating MySQL database + user (cppmmon)"
      DBPW="$(rand)"
      mysql --protocol=socket -uroot <<SQL
CREATE DATABASE IF NOT EXISTS cppmmon CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER IF NOT EXISTS 'cppmmon'@'localhost' IDENTIFIED BY '${DBPW}';
CREATE USER IF NOT EXISTS 'cppmmon'@'127.0.0.1' IDENTIFIED BY '${DBPW}';
ALTER USER 'cppmmon'@'localhost' IDENTIFIED BY '${DBPW}';
ALTER USER 'cppmmon'@'127.0.0.1' IDENTIFIED BY '${DBPW}';
GRANT ALL PRIVILEGES ON cppmmon.* TO 'cppmmon'@'localhost';
GRANT ALL PRIVILEGES ON cppmmon.* TO 'cppmmon'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL
      DB_URL="mysql+pymysql://cppmmon:${DBPW}@127.0.0.1:3306/cppmmon?charset=utf8mb4"
    fi
  fi
  if [[ -z "$DB_URL" ]]; then
    warn "MySQL unavailable: falling back to SQLite (LAB-ONLY deviation, see CLAUDE.md §1)"
    DB_URL="sqlite:///$DATA_DIR/cppmmon.db"
  fi
  log "writing $ENV_FILE (secrets generated, not printed)"
  umask 027
  sed -e "s#^CPPMMON_DB_URL=.*#CPPMMON_DB_URL=${DB_URL}#" \
      -e "s#^CPPMMON_WEB_SECRET=.*#CPPMMON_WEB_SECRET=$(rand)#" \
      -e '/^# CPPMMON_DB_URL=sqlite/d' \
      "$SRC_DIR/deploy/cppmmon.env.example" > "$ENV_FILE"
else
  log "$ENV_FILE exists, keeping it"
fi
chown root:"$SVC_USER" "$ENV_FILE"; chmod 0640 "$ENV_FILE"

# Admin CLI wrapper (runs as the service user so it can read the env + key)
cat > /usr/local/bin/cppmmon-admin <<'EOF'
#!/bin/sh
# cppmmon-admin: CPPM Monitor operator CLI
cd /opt/cppmmon || exit 1
if [ "$(id -un)" = "cppmmon" ]; then exec /opt/cppmmon/venv/bin/python -m cppmmon.cli "$@"; fi
exec sudo -u cppmmon /opt/cppmmon/venv/bin/python -m cppmmon.cli "$@"
EOF
chmod 0755 /usr/local/bin/cppmmon-admin

if [[ $PREPARE_ONLY -eq 1 ]]; then
  log "prepare-only: done"
  exit 0
fi

# -------------------------------------------------------------- migrations
ls "$APP_DIR"/cppmmon/db/migrations/versions/*.py >/dev/null 2>&1 \
  || die "no Alembic revisions found in cppmmon/db/migrations/versions"
log "applying migrations"
( cd "$APP_DIR" && sudo -u "$SVC_USER" "$APP_DIR/venv/bin/alembic" upgrade head )
log "seeding trap catalog (adds missing OIDs only; never overwrites imported entries)"
( cd "$APP_DIR" && sudo -u "$SVC_USER" "$APP_DIR/venv/bin/python" -m cppmmon.cli catalog-import "$APP_DIR/catalog/cppm_traps.yaml" --seed )

# ------------------------------------------------------- port conflicts
cfg_port() { grep -E "^$1=" "$ENV_FILE" | cut -d= -f2; }
TRAP_PORT="$(cfg_port CPPMMON_RECEIVER_TRAP_PORT)"; SYSLOG_PORT="$(cfg_port CPPMMON_RECEIVER_SYSLOG_PORT)"
conflict="$(ss -H -lunpt "( sport = :$TRAP_PORT or sport = :$SYSLOG_PORT )" 2>/dev/null; ss -H -ltnp "( sport = :$SYSLOG_PORT or sport = :8070 )" 2>/dev/null)"
if [[ -n "$conflict" ]] && ! grep -q 'python' <<<"$conflict" && ! grep -q 'gunicorn' <<<"$conflict"; then
  echo "$conflict" >&2
  die "a port needed by cppmmon is held by another process (shown above). Not touching it — decide and re-run."
fi

# -------------------------------------------------------------- systemd
log "installing systemd units"
install -m 0644 "$APP_DIR"/deploy/systemd/*.service "$APP_DIR"/deploy/systemd/*.timer /etc/systemd/system/
systemctl daemon-reload
for u in "${UNITS[@]}"; do
  systemctl enable "$u" >/dev/null 2>&1
  systemctl restart "$u"
done
systemctl enable --now cppmmon-maintenance.timer >/dev/null 2>&1
systemctl start cppmmon-maintenance.service || warn "maintenance one-shot failed (see journalctl -u cppmmon-maintenance)"
systemctl enable --now cppmmon-backup.timer >/dev/null 2>&1
install -d -m 0750 -o root -g "$SVC_USER" /var/backups/cppmmon

# -------------------------------------------------------------- firewall
if systemctl is-active --quiet firewalld; then
  log "opening firewalld ports"
  for p in 162/udp 514/udp 514/tcp 8070/tcp; do firewall-cmd -q --permanent --add-port="$p"; done
  firewall-cmd -q --reload
elif command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
  log "opening ufw ports"
  for p in 162/udp 514/udp 514/tcp 8070/tcp; do ufw allow "$p" >/dev/null; done
else
  log "no active host firewall (firewalld/ufw inactive): no rules added"
fi

log "done. Create the first admin with:  sudo cppmmon-admin create-user <name> --role admin"
