#!/usr/bin/env bash
# Send every catalog trap (plus one unknown OID) to the receiver with snmptrap (net-snmp).
#
#   tools/simulate_traps.sh -c <trap_community> [-t <host[:port]>] [-n <cppmNodeIp>] [-f catalog.yaml] [--only 1017,1018]
#
# The trap community must match a node's "Trap community", and the sender must be a
# registered node: either the UDP source IP, or the cppmNodeIp varbind (-n) if the
# source is not a node. Without that, traps are stored but no events are created.
set -euo pipefail

TARGET="127.0.0.1:162"
COMM=""
NODE_IP=""
ONLY=""
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG="$HERE/catalog/cppm_traps.yaml"
PY="${PYTHON:-/opt/cppmmon/venv/bin/python}"
[[ -x "$PY" ]] || PY=python3

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c) COMM="$2"; shift 2 ;;
    -t) TARGET="$2"; shift 2 ;;
    -n) NODE_IP="$2"; shift 2 ;;
    -f) CATALOG="$2"; shift 2 ;;
    --only) ONLY="$2"; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[[ -n "$COMM" ]] || { echo "error: -c <trap_community> is required" >&2; exit 2; }
command -v snmptrap >/dev/null || { echo "error: snmptrap not found (apt install snmp)" >&2; exit 2; }

B=1.3.6.1.4.1.14823.1.6.1.1.200.100
mapfile -t OIDS < <("$PY" - "$CATALOG" "$ONLY" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
only = {x.strip() for x in sys.argv[2].split(",") if x.strip()}
for t in doc.get("traps", []):
    oid = str(t["oid"])
    if not only or oid.rsplit(".", 1)[-1] in only:
        print(f"{oid}|{t['name']}")
if not only:
    print("1.3.6.1.4.1.14823.1.6.1.1.200.9999|(unknown OID test)")
PY
)

sent=0
for line in "${OIDS[@]}"; do
  oid="${line%%|*}"; name="${line#*|}"
  vbs=()
  [[ -n "$NODE_IP" ]] && vbs+=("$B.2" a "$NODE_IP")
  case "${oid##*.}" in
    1017|1018|1019) vbs+=("$B.17" s "Radius server") ;;
    1001|1002) vbs+=("$B.4" s "Access" "$B.6" i 25 "$B.7" i 25) ;;
    1003) vbs+=("$B.5" s "HTTPS(RSA)" "$B.8" i 21) ;;
    1004) vbs+=("$B.9" i 2048 "$B.14" s "MB") ;;
    1005) vbs+=("$B.10" i 512 "$B.14" s "MB") ;;
    1006|1007|1008|1009|1010) vbs+=("$B.3" a "192.0.2.11" "$B.11" i 20) ;;
    1014|1015) vbs+=("$B.15" s "cppm-patch-sim.bin" "$B.16" s "Success") ;;
    1016) vbs+=("$B.4" s "Access" "$B.12" i 25 "$B.13" i 23) ;;
    1021) vbs+=("$B.37" s "92%") ;;
    1023) vbs+=("$B.19" s "Access" "$B.20" i 3) ;;
  esac
  vbs+=("$B.35" s "SIMULATED by cppmmon tools/simulate_traps.sh: $name")
  snmptrap -v 2c -c "$COMM" "$TARGET" '' "$oid" "${vbs[@]}"
  printf '  sent %-44s %s\n' "$oid" "$name"
  sent=$((sent + 1))
  sleep 0.2
done
echo "sent $sent trap(s) to $TARGET"
