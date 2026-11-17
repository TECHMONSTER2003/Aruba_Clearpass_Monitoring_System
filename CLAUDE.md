# CLAUDE.md — CPPM Monitor (build and deploy instructions for Claude Code)

You are building and deploying a **production-grade prototype** that monitors Aruba ClearPass Policy Manager (CPPM). It does proactive polling (SNMP/REST/ICMP with a dashboard) and reactive alerting (SNMP traps and syslog turned into ServiceNow-ready ticket text files).

**Read `docs/DESIGN.md` fully before writing any code.** It is the source of truth for architecture, KPIs, OIDs, data model and alert logic. If this file and DESIGN.md disagree, DESIGN.md wins. Report the conflict.

Scope is **CPPM only**. Do not build anything for Cisco ISE.

---

## 0. Working rules (non-negotiable)

1. **Work phase by phase (§5). After each phase, STOP and report**: what you built, the commands you ran, verification output, and anything unresolved. Wait for the user's "go" before starting the next phase. Never batch phases.
2. **Never guess environment facts.** Detect them (OS, Python version, sudo, ports in use, SELinux, firewalld, DB availability) and report them.
3. **No destructive actions without asking**: no stopping or disabling existing services (e.g. `snmptrapd`, `rsyslog` listeners), no dropping DBs, no `rm -rf` outside the project, no disabling SELinux or firewalld.
4. **Secrets:** never hardcode or log credentials, community strings or API secrets. Never echo them back in your reports.
5. If a CPPM REST endpoint path differs on the lab version, check `https://<cppm>/api-docs` (Swagger). Adapt it and record the difference in `docs/API_NOTES.md`.
6. Every module has structured logging and explicit error handling. No bare `except:`. No silent `pass`.
7. Prefer small, well-named modules over clever code. Type hints everywhere. Docstrings on public functions.

---

## 1. Environment

| Item | Value |
|---|---|
| Target host | Linux VM reachable by SSH (details given by the user at session start) |
| Install path | `/opt/cppmmon` (code), `/etc/cppmmon` (config + secret key, 0750/0640), `/var/lib/cppmmon` (spool, tickets), `/var/log/cppmmon` (logs) |
| Service user | `cppmmon` (system user, no login shell) |
| Web UI | `0.0.0.0:8070` |
| Receivers | SNMP trap UDP/162, syslog UDP/514 + TCP/514 |
| Lab CPPM | IP, SNMP and API credentials are **entered via the UI**, not in files |

### Preflight (Phase 0, report the results as a table)
```bash
cat /etc/os-release; uname -r
python3 --version; ls /usr/bin/python3.1*
sudo -n true && echo SUDO_OK || echo NO_SUDO
ss -lunpt | grep -E ':(162|514)\b'; ss -ltnp | grep -E ':(514|8070|3306)\b'
getenforce 2>/dev/null; systemctl is-active firewalld
systemctl is-active mysqld mariadb 2>/dev/null
which snmpget snmptrap logger fping 2>/dev/null
df -h /opt /var; free -m; nproc
```
Decision rules:
- **Python:** use 3.11+. On RHEL 8/9: `dnf install python3.11 python3.11-pip` (needs sudo).
- **DB:** MySQL 8 (team standard). If there's no sudo and no MySQL, fall back to SQLite (WAL mode) via the same SQLAlchemy URL. Report this clearly as a lab-only deviation.
- **Privileged ports:** systemd `AmbientCapabilities=CAP_NET_BIND_SERVICE` on `cppmmon-receiver` only. If systemd caps are not possible, use ports 1162/1514 plus a firewalld `forward-port` rule, and report it.
- **Port conflicts:** if 162 or 514 is already bound, show which process holds it and **ask** before changing anything.

---

## 2. Tech stack (pin versions in `requirements.txt` and record the exact resolved versions in your report)

| Layer | Choice |
|---|---|
| Language | Python 3.11+ |
| Web | Flask 3.x, Flask-Login, Jinja2, gunicorn (2 workers, gthread) |
| Frontend | Server-rendered Jinja + HTMX + Chart.js. **Vendor the JS files into `static/vendor/`** (no CDN at runtime) |
| DB | SQLAlchemy 2.x (Core + ORM), Alembic migrations, PyMySQL driver |
| SNMP | **pysnmp 7.x (lextudio, asyncio API)**: `pysnmp.hlapi.v3arch.asyncio` for polling, `pysnmp.entity.rfc3413.ntfrcv` with the asyncio dgram transport for the trap receiver |
| REST | httpx (async), with a token cache |
| ICMP | `icmplib` (unprivileged mode). If the kernel `net.ipv4.ping_group_range` blocks it, fall back to `fping` via subprocess |
| Templates | Jinja2 (also used for ticket text) |
| Crypto | `cryptography.Fernet`. Key in `/etc/cppmmon/secret.key` (0640 root:cppmmon) |
| Config | `/etc/cppmmon/cppmmon.env` read by pydantic-settings |
| Logging | stdlib `logging` with a JSON formatter to `/var/log/cppmmon/<service>.log`, rotated (TimedRotatingFileHandler, 14 days) + journald |
| Tests | pytest, pytest-asyncio. Tests for parsers, delta/reset logic, the alert state machine and ticket rendering |

Do **not** add Redis, Kafka, Celery, Docker or a TSDB (see DESIGN ADR-001/002).

---

## 3. Repository layout

```
cppmmon/
├── CLAUDE.md
├── docs/
│   ├── DESIGN.md
│   ├── API_NOTES.md              # you create: verified REST paths/payloads on the lab version
│   └── RUNBOOK.md                # you create: install, ops, troubleshooting
├── catalog/
│   └── cppm_traps.yaml           # seed trap + varbind catalog (user's trap DB overrides via import)
├── cppmmon/
│   ├── __init__.py
│   ├── config.py                 # pydantic-settings
│   ├── logging_setup.py
│   ├── crypto.py                 # Fernet encrypt/decrypt helpers
│   ├── db/
│   │   ├── models.py             # SQLAlchemy models = DESIGN §6
│   │   ├── session.py
│   │   └── migrations/           # alembic
│   ├── catalog/loader.py         # YAML/CSV import, validation, upsert, diff preview
│   ├── collectors/
│   │   ├── snmp_client.py        # async GET/GETBULK/WALK wrapper, v2c + v3, per-OID result parsing
│   │   ├── cppm_snmp.py          # index discovery, system table, policy/radius/tacacs tables, UCD, hrStorage, IF-MIB
│   │   ├── cppm_api.py           # OAuth token cache, cluster/server, services, certs, licenses, endpoint count
│   │   └── icmp.py
│   ├── receiver/
│   │   ├── main.py               # entrypoint: runs trap + syslog listeners in one asyncio loop
│   │   ├── traps.py              # pysnmp ntfrcv; community check; decode via catalog; persist raw + event
│   │   ├── syslog.py             # UDP + TCP (LF and RFC6587 octet-counting) listeners
│   │   ├── syslog_parsers.py     # plugin chain: cef, leef, cppm_std(key=value), rfc5424, rfc3164, raw
│   │   └── spool.py              # JSONL spool on DB failure + idempotent replay
│   ├── poller/
│   │   ├── main.py               # scheduler: per-node jobs with jitter + semaphores
│   │   ├── jobs.py               # job definitions/intervals (DESIGN §4.3)
│   │   ├── deltas.py             # counter delta/reset/wrap logic
│   │   └── thresholds.py         # sustain window + hysteresis → events
│   ├── engine/
│   │   ├── main.py               # outbox consumer loop (SKIP LOCKED, batch 500)
│   │   ├── rules.py              # event → alert decision, severity overrides, clear pairing
│   │   ├── correlation.py        # node-down suppression, flap guard, cluster grouping
│   │   └── tickets.py            # TicketSink interface + FileTicketSink (DESIGN §8)
│   ├── web/
│   │   ├── app.py                # Flask factory
│   │   ├── auth.py
│   │   ├── routes/               # nodes, dashboard, node_detail, traps, syslog, alerts, tickets, catalog, thresholds, health
│   │   ├── templates/
│   │   └── static/vendor/        # htmx.min.js, chart.umd.min.js (vendored)
│   └── jobs/maintenance.py       # retention + 5-min rollups (systemd timer)
├── deploy/
│   ├── install.sh                # idempotent: user, dirs, venv, deps, DB, migrations, units, firewall
│   ├── cppmmon.env.example
│   └── systemd/
│       ├── cppmmon-receiver.service
│       ├── cppmmon-poller.service
│       ├── cppmmon-engine.service
│       ├── cppmmon-web.service
│       ├── cppmmon-maintenance.service
│       └── cppmmon-maintenance.timer
├── tools/
│   ├── simulate_traps.sh         # sends every catalog trap via snmptrap to the receiver
│   ├── simulate_syslog.sh        # sends CEF/LEEF/std samples via logger
│   └── cppm_probe.py             # CLI: test one CPPM (ICMP/SNMP/API) from the shell
├── tests/
└── requirements.txt
```

---

## 4. Implementation specifics you must get right

### 4.1 SNMP (see DESIGN §2.1)
- `cppmSystemTable` is a **table**. Discover the index by GETting `…1.1.1.1.1.4.{1,0,2,3,4,5}` in **one PDU**. The first non-`NoSuchInstance` value wins. Cache it in `node_state.sys_index`. If none match, walk `…1.1.1.1.1.4`.
- **Parse results per OID, never by position.** One missing OID must not shift other values.
- Memory and disk are **bytes**. RAM% = `(total - available) / total`, using UCD `memAvailReal` (KB) when present. Otherwise fall back to CPPM free memory and flag `mem_source=cppm_free`.
- CPU% from UCD raw ticks (`ssCpuRawUser/System/Idle/Wait/Nice/Kernel/Interrupt`). Compute the delta between consecutive polls. The first poll only stores state.
- Walk the policy/radius/tacacs tables (string-indexed by hostname) with GETBULK.
- Daily auth counters reset at 00:00. A negative delta means a reset: use the current value as the delta. If `sysUpTime` also decreased, emit a `node.reboot` event.
- Timeouts: 3 s, retries 2. Semaphore: 50 concurrent SNMP sessions.

### 4.2 REST API (see DESIGN §2.3)
- `POST /api/oauth` with `grant_type=client_credentials`. Cache the token per node and refresh at 80% of `expires_in`. On 401, refresh once, then retry once. On a second 401, set the node API state to `auth_failed`.
- Endpoint list in DESIGN §2.3. **Verify each one on the lab CPPM first** and write the confirmed paths and sample responses (credentials/PII redacted) to `docs/API_NOTES.md`.
- A 404 for a given endpoint means that KPI is `unsupported` for that node. Log it once per node per endpoint, not every cycle.
- Endpoint count: use `calculate_count=true&limit=1` and read `count`. **Never page through all endpoints.**
- TLS verification is a per-node toggle (lab CPPMs are usually self-signed). The UI shows a warning when it is off.

### 4.3 Trap receiver
- One asyncio loop hosts both the trap and syslog listeners. **The callback does no blocking I/O.** Push to an `asyncio.Queue` and have a writer task batch-insert to the DB every 200 ms or 500 rows, whichever comes first.
- Communities: accept any community configured on any registered node (`trap_community`). Count others as `community_ok=false` and still store them for troubleshooting, without creating events.
- Sender resolution: UDP source IP → `nodes.ip`. If unmatched, try the `cppmNodeIp` varbind. If still unmatched, set `node_id=NULL` ("Unregistered sender").
- Decode the trap OID and varbinds via the catalog. **Unknown OIDs are stored and emitted as `UNKNOWN_TRAP` (info). Never drop them.**
- If the DB write fails, append to `/var/lib/cppmmon/spool/*.jsonl` and replay on recovery, idempotent by `sha1(src|ts|payload)`.

### 4.4 Syslog receiver
- UDP/514 and TCP/514 (supports both LF and RFC6587 octet-counted framing). Max message size 64 KB, truncated with a flag.
- **Phase 2 stores raw messages only**, plus an RFC3164/5424 header parse. Parsers (CEF/LEEF/CPPM-standard key=value) are Phase 5, built against **real samples captured from the lab** and saved under `tests/fixtures/syslog/`.
- Store the detected format in `raw_syslog.fmt`.

### 4.5 Engine (DESIGN §7)
- Consume `events WHERE processed=0 ORDER BY id LIMIT 500 FOR UPDATE SKIP LOCKED` (on SQLite, use a single consumer and plain SELECT).
- Implement exactly: dedup key, one open alert per key, clear pairing (`clear_oid` + `clear_match_field`), hysteresis clears from the poller, flap guard (more than 3 open/close cycles in 30 min), node-down suppression, maintenance window, and severity → priority mapping.
- **The engine is the only writer of `alerts` and `tickets`.**

### 4.6 Ticket sink (DESIGN §8)
- `TicketSink` ABC with `create/update/resolve`. Implement `FileTicketSink` only.
- Path: `/var/lib/cppmmon/tickets/YYYY/MM/DD/CPPM-YYYYMMDD-NNNN.txt` (NNNN is a daily sequence held in the DB, never a filesystem count).
- The ticket body follows the DESIGN §8 template exactly. Updates and resolutions **append** to the same file.
- Every lifecycle change also appends one JSON line to `/var/lib/cppmmon/tickets/alerts.log`.
- Write atomically: write to `*.tmp`, fsync, then rename.

### 4.7 Web UI (DESIGN §9)
- Login is required. Create the first admin with `cppmmon-admin create-user` (a CLI). There are no default passwords.
- **Nodes page:** form fields are name, IP, SNMP version (v2c community | v3 user/auth proto/auth key/priv proto/priv key), trap community, API enabled, client id, client secret and TLS verify. Secret fields are **write-only** (never rendered back, shown as `••••` with a "replace" option).
- **Test connection button** runs the ICMP, SNMP (sysName + CPPM index discovery + hostname) and API (token + version) checks and shows a per-check pass/fail, latency and error text.
- Dashboard tiles and charts as in DESIGN §9. Auto-refresh every 30 s via HTMX polling.
- Health page: receiver packets/s and drops, spool backlog, engine lag (age of the oldest unprocessed event), and the last run plus duration of each poller job.
- CSRF protection on all forms.

### 4.8 systemd units
- All units: `User=cppmmon`, `Restart=always`, `RestartSec=5`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/cppmmon /var/log/cppmmon`, `EnvironmentFile=/etc/cppmmon/cppmmon.env`.
- Receiver only: `AmbientCapabilities=CAP_NET_BIND_SERVICE` and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`.
- Web: `gunicorn -w 2 -k gthread -b 0.0.0.0:8070 'cppmmon.web.app:create_app()'`.
- Maintenance timer: hourly rollups, daily retention (values in DESIGN §6).
- firewalld (if active): open `162/udp`, `514/udp`, `514/tcp`, `8070/tcp`. Do not open 3306.

---

## 5. Phases (STOP and report after each)

### Phase 0: Preflight and skeleton
Run the preflight. Create the repo layout, venv, `requirements.txt`, config, logging, DB models + Alembic initial migration, `install.sh`, the systemd units (services can be stubs that log "started"), the firewall rules, and the login page.
**Verify:** `systemctl status cppmmon-*` shows all units active. `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8070/login` returns 200. `ss -lunpt` shows the receiver on 162/514.

### Phase 1: Node onboarding and test connection
Nodes CRUD with encrypted credentials, `cppm_probe.py` CLI, and the Test Connection button.
**Verify:** the user adds the lab CPPM in the UI. All three checks pass, or the report gives the exact error and the CPPM-side fix (e.g. "enable SNMP under Server Configuration → System Monitor", "API client lacks operator profile").

### Phase 2: Receivers (traps + raw syslog)
Trap listener, catalog loader (seed `catalog/cppm_traps.yaml`), the raw syslog listener, Live Traps and Live Syslog pages, `tools/simulate_traps.sh`, and `tools/simulate_syslog.sh`.
Example simulation (service stop, then start):
```bash
snmptrap -v2c -c <trap_comm> <monitor_ip>:162 '' 1.3.6.1.4.1.14823.1.6.1.1.200.1017 \
  1.3.6.1.4.1.14823.1.6.1.1.200.100.17 s "Radius server" \
  1.3.6.1.4.1.14823.1.6.1.1.200.100.35 s "Radius server stopped"
snmptrap -v2c -c <trap_comm> <monitor_ip>:162 '' 1.3.6.1.4.1.14823.1.6.1.1.200.1018 \
  1.3.6.1.4.1.14823.1.6.1.1.200.100.17 s "Radius server"
logger -n <monitor_ip> -P 514 -d "CEF:0|Aruba|ClearPass|6.12|SystemEvents|Test|5|msg=hello"
```
Then give the user the **CPPM-side configuration steps**: SNMP trap receiver (Server Configuration → SNMP/System Monitor), Syslog Target + Export Filters (System Events + Audit Records, CEF), and ask them to trigger real events (e.g. restart a non-critical service in the lab).
**Verify:** all seed traps from the simulation appear decoded. An unknown OID shows as UNKNOWN_TRAP. Real CPPM traps and syslog appear. Save 20+ real syslog lines to `tests/fixtures/syslog/` (credentials/PII redacted).

### Phase 3: Poller and dashboard
SNMP, REST and ICMP jobs per DESIGN §3 and §4.3, deltas, metrics writes, dashboard tiles, and node detail charts.
**Verify:** the lab node shows live CPU/Mem/Disk/auth/services/certs/license. Cross-check one value of each against the CPPM UI and report it (e.g. "Disk 41.2% vs CPPM System Monitor 41%").

### Phase 4: Engine and file tickets
Rules, correlation, thresholds UI, the ticket sink, and the Alerts and Tickets pages.
**Verify:** (a) simulated 1017 → one ticket file; repeated 1017 → no new ticket, occurrences incremented; 1018 → the same ticket marked RESOLVED. (b) temporarily lower the CPU threshold → ticket after the sustain window → restore the threshold → cleared via hysteresis. (c) block ICMP+SNMP to the node (or use a wrong IP node) → NODE DOWN ticket, other alerts for that node suppressed. Show the ticket file contents in your report.

### Phase 5: Syslog parsing and rules
Build the CEF/LEEF/CPPM-standard parsers against the captured fixtures, with unit tests. Propose syslog→event rules from the real samples (e.g. System Events Level=ERROR), **show the proposal to the user before enabling it**, then implement.

### Phase 6: Hardening
Retention + rollups, health page completion, SNMPv3 trap support (engineID config), `docs/RUNBOOK.md`, and a backup script for DB + tickets. Run a 24–48 h soak and report memory per process and the engine-lag trend.

---

## 6. Trap database from the user
The user will provide a trap database (CSV/YAML/XLSX). When it arrives:
1. Map its columns to the import schema in DESIGN §6.4. Show the mapping table to the user before importing.
2. Import it via `catalog/loader.py` (upsert by OID) with a diff preview: added / changed / unchanged.
3. Never delete seed entries that the user's DB doesn't mention. Flag them in the report instead.

---

## 7. Definition of done (prototype demo)
- From a browser at `http://<vm>:8070`: log in, add the lab CPPM, Test Connection is all green, and the dashboard shows live KPIs.
- Real CPPM traps and syslog appear live.
- A real or simulated incident produces a correctly formatted ticket `.txt`. Its clear event resolves the same ticket.
- All services survive `systemctl restart` of any other service. The receiver survives a DB stop (spool fills, then replays).
- `pytest` passes. `docs/RUNBOOK.md` and `docs/API_NOTES.md` exist.

## 8. Reporting format (end of every phase)
```
PHASE n — <name> — DONE | BLOCKED
Built: <files/modules>
Commands run: <key commands>
Verification: <command → actual output excerpt>
Deviations from DESIGN.md: <none | list + reason>
Open issues / needs from user: <list>
Next phase preview: <1–3 lines>
```
