#!/usr/bin/env bash
# Send sample CPPM-style syslog (CEF, LEEF, standard key=value, plain) over UDP and TCP.
#
#   tools/simulate_syslog.sh [-t <host>] [-p <port>]
#
# These are synthetic shapes for exercising the receiver. Phase 5 parsers are
# built against REAL lab captures (tests/fixtures/syslog/), not these.
set -euo pipefail
HOST=127.0.0.1
PORT=514
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t) HOST="$2"; shift 2 ;;
    -p) PORT="$2"; shift 2 ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

samples=(
  "CEF:0|Aruba Networks|ClearPass|6.14.1.372486|SystemEvents|Radius server|5|rt=Nov 17 2026 14:00:00 IST cat=System Events msg=SIMULATED service stopped Level=ERROR Source=Radius server"
  "CEF:0|Aruba Networks|ClearPass|6.14.1.372486|AuditRecords|Service updated|3|rt=Nov 17 2026 14:00:01 IST suser=admin act=MODIFY cat=Service msg=SIMULATED audit change"
  "LEEF:1.0|Aruba Networks|ClearPass|6.14|SystemEvents|devTime=Nov 17 2026 14:00:02	cat=System Events	Level=WARN	msg=SIMULATED leef sample"
  "Timestamp=2026-11-17 14:00:03+05:30, Source=Policy server, Level=INFO, Category=Logged out, Action=None, Description=SIMULATED standard format"
  "SIMULATED plain message without a payload format"
)

n=0
for msg in "${samples[@]}"; do
  logger -n "$HOST" -P "$PORT" -d -t CPPM_SIM -p local0.info -- "$msg"   # UDP, RFC 5424 header
  logger -n "$HOST" -P "$PORT" -T -t CPPM_SIM -p local0.warning --octet-count -- "$msg"  # TCP, octet-counted
  n=$((n + 2))
done
logger -n "$HOST" -P "$PORT" -T -t CPPM_SIM --rfc3164 -- "SIMULATED rfc3164 over TCP (LF framing)"
n=$((n + 1))
echo "sent $n syslog message(s) to $HOST:$PORT (UDP + TCP)"
