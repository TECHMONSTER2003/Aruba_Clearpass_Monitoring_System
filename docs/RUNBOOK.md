# CPPM Monitor: runbook

Operating guide for the CPPM Monitor (`cppmmon`) **1.0.0-rc1** (UAT release candidate, 2026-11-17).
Covers Phases 0–4 and Phase 6 hardening (rollups, retention, backup, Health). Phase 5 (syslog parsing and rules) is pending; see `UAT_PLAN.md` §5.
UAT test cases: [UAT_PLAN.md](UAT_PLAN.md). Release notes: [../CHANGELOG.md](../CHANGELOG.md).

- Architecture and rationale: [DESIGN.md](DESIGN.md)
- Verified CPPM API/SNMP/trap behaviour: [API_NOTES.md](API_NOTES.md)
- Where the build differs from DESIGN.md: [DEVIATIONS.md](DEVIATIONS.md)

---

## 1. At a glance

```text
CPPM nodes ──SNMP traps :162/udp──▶ cppmmon-receiver ──▶ raw_traps + events ─┐   REACTIVE (pushed by CPPM)
           ──syslog :514/udp+tcp──▶                  ──▶ raw_syslog          │
           ◀─ICMP / SNMP / REST─── cppmmon-poller   ──▶ metrics + events ────┤   POLLED (monitor asks)
                                                                            ▼
                                   cppmmon-engine  ◀── events outbox (MySQL)
                                        │  dedup · clear pairing · suppression · flap guard
                                        ▼
                         alerts (DB) + tickets/YYYY/MM/DD/CPPM-*.txt + tickets/alerts.log
                                        ▲
                     cppmmon-web :8070 (UI) — never writes alerts/tickets directly
```

| Item | Value |
|---|---|
| UI | `http://<monitor-vm>:8070` |
| Database | MySQL 8, `cppmmon` DB on 127.0.0.1 only |
| Time | Stored in UTC, shown in IST (`CPPMMON_DISPLAY_TZ`) |

## 2. Polled vs reactive: what comes from where

The design principle (revised 2026-11-17): **CPPM pushes what it can, and the monitor polls only what CPPM cannot push.** Polling has a cost on both sides (every SNMP request is processed, and was even DEBUG-logged, by CPPM), so reactive signals are primary wherever they exist.

### 2.1 Polled metrics (the monitor asks CPPM)

| Job | Interval | Protocol | Metrics / data | Alerts it can raise |
|---|---|---|---|---|
| `icmp` | 30 s | ICMP | `icmp_rtt_ms`, `icmp_loss_pct` | part of **NODE DOWN** (with SNMP) |
| `snmp_system` | 60 s | SNMP GET (1 PDU) | `cpu_pct` (UCD ticks), `mem_pct` (excl. cache), `disk_pct` (CPPM-MIB), `load1/5/15`, `uptime_s` (cppmSystemUptime), `auth_per_min`, `auth_fail_per_min`, `auth_fail_pct`, `auth_success_pct_today`, cluster size, hostname/version/model/role | CPU, Memory, Disk, Auth failure %, **Reboot detected**, **Cluster node count drop**, NODE DOWN / Degraded |
| `snmp_auth` | **5 min** | SNMP walk | `auth_src_req_per_min`, `auth_src_fail_per_min` per auth source (AD/LDAP/…) | Auth-source failure spike |
| `snmp_storage_if` | 5 min | SNMP walk | `disk_mount_pct` per mount, `if_in_bps`/`if_out_bps`, `if_errors_per_min`, `if_oper_up` per NIC | Mount full, Interface errors |
| `rest_services` | **15 min** (backstop); **2 min while a service alert is open** on the node | REST | service state per service | Service down/up (**reactive traps are primary**, see 2.2). The fast re-check exists because CPPM does not always send a "started" trap |
| `rest_endpoints` | 15 min | REST | `endpoints_total` | — (trend) |
| `rest_inventory` | 1 h | REST | cluster members, role, replication status, cluster identity, `cluster_servers` | Role change, Replication not ENABLED |
| `rest_certs_licenses` | 6 h | REST | **only the installed RADIUS and HTTPS(RSA) server certificates** (`cert_days_left`), license usage + type/activation/expiry (`license_pct`) | Certificate expiry (≤30 d Medium, ≤7 d High, expired Critical), License ≥90 % / ≥100 % |

- Every interval is jittered ±10%. SNMP sessions are capped at 50, REST at 20.
- **Poll now** (Dashboard → *Poll all now*; Nodes / Overview / Licenses → *Poll now*) runs **every** job above immediately. The 6-hour certificate/licence job is included.
- Certificate scope is set by `CPPMMON_CERT_MONITOR_SERVICES` (default `RADIUS,HTTPS(RSA)`). HTTPS(ECC), RadSec, Database and the trust list are **not polled**.

### 2.2 Reactive alerts (CPPM pushes; no polling)

| Signal | Source | OID / message | Alert | Clears on |
|---|---|---|---|---|
| Service stopped / started / restarted | SNMP trap (CPPM-MIB) | `…200.1017` / `1018` / `1019`, `cppmServiceName` = unit (e.g. `cpass-tacacs-server`) | **service.down**: High for RADIUS/TACACS/Policy/DB/replication/Domain services, else Medium | 1018/1019 for the same service |
| Service health watchdog | SNMP trap (DISMAN-EVENT-MIB, CPPM's built-in net-snmp monitor) | `1.3.6.1.2.1.88.2.0.2/.3` with `extNames`/`extOutput`, e.g. `TACACS+ Server [ cpass-tacacs-server ] is stopped` | **service.down** (same alert as 1017); covers ~20 checks incl. **`Domain Server [cpass-domain-server@<DOMAIN>]`** (AD domain service), postgresql, httpd | Watchdog trap reporting "is running" |
| Memory / disk / load watchdog | same DISMAN traps (`mteHotTrigger` = memory, dskTable, laTable) | `memSwapErrorMsg`, `dskErrorMsg`, … | `watchdog.<trigger>` Medium | Watchdog trap reporting OK |
| Certificate expiry (**any** cert CPPM flags) | SNMP trap | `…200.1003` `cppmNodeCertExpiry` | Medium; High at ≤7 days | — (manual or renewal) |
| License expiry / activation / usage / overrun | SNMP trap | `…1001`, `1002`, `1016` (≥90%), `1023` | Medium / High | 1016 below 85% |
| Low disk / low memory / high CPU | SNMP trap | `…1004`, `1005`, `1021` | Medium | — |
| Cluster events | SNMP trap | `…1007` removed, `1008` promoted, `1009` disabled, `1010` out of sync | High (cluster-wide: one ticket per cluster) | — |
| Config reset / restore | SNMP trap | `…1012` / `1013` | High / Medium | — |
| Core dump, license overrun | SNMP trap | `…1022`, `1023` | High | — |
| Reboot | SNMP trap | `coldStart` (High), `warmStart` (Medium) | — | — |
| Link up/down, SNMP agent start/stop | SNMP trap | `1.3.6.1.6.3.1.1.5.3/.4`, `1.3.6.1.4.1.8072.4.0.x` | **log only** (Live Traps): CPPM link traps carry only ifIndex and fire for docker bridges | — |
| Unknown OID | SNMP trap | anything not in the catalog | stored as `UNKNOWN_TRAP`, log only | — |
| Raw syslog | Syslog 514 | everything CPPM forwards | stored + searchable (Live Syslog). **No alerts yet** | — |
| System Events / Audit Records: AD/LDAP unreachable, trusted-root expiry, … | Syslog (CEF Export Filters) | to be captured from the lab | **Phase 5**: rules proposed from real samples, enabled after approval | Phase 5 |

**One alert per service.** The 1017 trap, the watchdog trap and the 15-minute REST poll all key on the service's **unit name** (`<node>|service.down|cpass-tacacs-server`). The first signal opens the alert and ticket; later signals add *occurrences*. Any "running/started" signal resolves it.

**AD/LDAP reachability:**
- CPPM has **no trap** for auth-source reachability.
- Event-driven coverage today: the **Domain Server watchdog** (AD join/winbind service), plus the 5-minute auth-source failure counters (polled).
- DC/LDAP reachability itself comes from **System Events syslog** (Phase 5). That needs the CEF Export Filter, and failures appear when a **real authentication** uses the source (the UI *Test connection* button only shows in Apache access logs).

## 3. CPPM configuration checklist (everything the monitor needs)

Do this on **every** CPPM node unless marked *cluster-wide*. Navigation is for CPPM 6.14.

| # | What | Where in CPPM | Set to | Needed for |
|---|---|---|---|---|
| 1 | SNMP agent (polling) | Administration › Server Manager › Server Configuration › *server* › **System Monitor** (SNMP) | v2c community (or v3 user), allow the monitor IP | `snmp_*` jobs, Test Connection |
| 2 | SNMP trap receiver | same page, trap destination | Host **&lt;monitor-ip&gt;**, UDP **162**, community = the node's *Trap community* in the monitor | all reactive traps (2.2) |
| 3 | Service traps / watchdog | System Monitor (same page) | keep the built-in service/process monitors enabled (they produce the DISMAN watchdog traps) | service.down, Domain Server |
| 4 | REST API client (*cluster-wide*) | Guest › Administration › API Services › **API Clients** | grant **Client credentials**, operator profile with **read-only** API access | `rest_*` jobs, Discover cluster, Test Connection |
| 5 | Allow the monitor's source IP | Server Configuration › *server* › Network › **Restrict Access** (if used), plus any firewall in front | permit <monitor-ip> to TCP 443 and UDP 161 | REST + SNMP (otherwise HTTP 403 HTML page / SNMP timeout) |
| 6 | Syslog target | Administration › External Servers › **Syslog Targets** | <monitor-ip>, port 514, UDP (or TCP) | all syslog |
| 7 | **Syslog Export Filters** (*cluster-wide*) | Administration › External Servers › **Syslog Export Filters** | Filter A: Export Template **System Events**, Format **CEF**, target from #6. Filter B: **Audit Records**, **CEF** | Phase 5 alerts (AD/LDAP failures, trusted-root expiry, admin/audit) |
| 8 | Log level of *Async network services* | Administration › Server Manager › Log Configuration › *server* › Service Log Configuration | **INFO** (not DEBUG/WARN) | stops clear-text SNMP communities and request dumps in syslog, cuts syslog volume |
| 9 | NTP | Server Configuration › *server* › System Time | same NTP as the monitor | correct timestamps/correlation |


## 4. Layout on the VM

| Path | Owner / mode | Contents |
|---|---|---|
| `/opt/cppmmon` | root 0755 | code, `venv/`, `requirements.lock` |
| `/etc/cppmmon/cppmmon.env` | root:cppmmon 0640 | DB URL, web secret, ports, tunables (generated once; install never overwrites) |
| `/etc/cppmmon/secret.key` | root:cppmmon 0640 | Fernet key for node credentials. **Back it up** |
| `/var/lib/cppmmon/tickets/` | cppmmon 0750 | ticket `.txt` files + `alerts.log` |
| `/var/lib/cppmmon/spool/` | cppmmon 0750 | JSONL buffer while the DB is down (auto-replayed) |
| `/var/lib/cppmmon/uploads/` | cppmmon 0750 | staged catalog uploads (deleted after 1 h) |
| `/var/lib/cppmmon/sim_trap_community` | cppmmon 0600 | community of the `SIM-MONITOR-VM` simulation node |
| `/var/log/cppmmon/<service>.log` | cppmmon 0750 | JSON logs, daily rotation, 14 days |
| `/etc/sysctl.d/60-cppmmon-ping.conf` | root | unprivileged ICMP (`ping_group_range = 0 2147483647`) |

## 5. Install, upgrade, users

```bash
sudo ./deploy/install.sh                 # idempotent; --no-packages skips apt/dnf
sudo cppmmon-admin create-user <name> --role admin     # no default password exists
```

`install.sh` does the following:
1. OS packages.
2. Service user and directories.
3. venv.
4. Fernet key.
5. MySQL DB and user.
6. Env file.
7. ICMP sysctl.
8. Alembic migrations.
9. **Trap catalog seed** (adds missing OIDs only, never overwrites).
10. systemd units.
11. Firewall rules, only if firewalld/ufw is active.

It stops if 162/514/8070 are held by another process.

Roles: `admin` (everything), `operator` (nodes, Test, Poll now, Discover, Resolve, Thresholds), `viewer` (read-only).
`cppmmon-admin list-users | create-user | set-password <name> | catalog-import <file> [--apply|--seed]`

## 6. Services

| Unit | Role | Notes |
|---|---|---|
| `cppmmon-receiver` | traps 162/udp, syslog 514/udp+tcp | Only unit with `CAP_NET_BIND_SERVICE`. Survives DB outages (spool). Masks credentials in syslog. Suppresses repeats |
| `cppmmon-poller` | polled jobs (§2.1) + thresholds + Poll now | Picks up node/threshold edits within 60 s, Poll-now requests within ~2 s |
| `cppmmon-engine` | events → alerts → tickets | Single writer of alerts and tickets |
| `cppmmon-web` | UI :8070 | `/healthz` unauthenticated |
| `cppmmon-maintenance.timer` | hourly: 5-min rollups, retention, monitor disk check | "inactive (dead)" between runs is normal |
| `cppmmon-backup.timer` | daily 02:30: `tools/backup.sh` → `/var/backups/cppmmon/cppmmon-*.tar.gz` (DB dump + tickets + `/etc/cppmmon` incl. key), newest 14 kept | restore steps are in the script header |

```bash
systemctl status 'cppmmon-*'
journalctl -u cppmmon-engine -f
tail -f /var/log/cppmmon/poller.log | jq -c '{ts,level,msg,node_id,job}'
```

## 7. UI pages

| Page | Use it for |
|---|---|
| **Dashboard** | Tiles per node (status, role, version, uptime, CPU/Mem/Disk, auth, endpoints, RTT, key services, cert, license, open alerts). Refreshes every 30 s. **Poll all now**. *Discover members* banner when a cluster has unmonitored members |
| **Nodes** | Add/edit/delete, **Poll now**, Overview, Settings & Test, **Discover** |
| Node **Overview** | Charts 1 h–7 d, services, the 2 monitored certificates, licenses (detailed), interfaces/mounts, auth sources, open alerts, recent traps/syslog. **Poll now**, **Discover cluster** |
| **Alerts** | Filter by state. **Resolve**, **Resolve selected**, **Resolve all shown** |
| **Tickets** | List, text view + Copy, `.txt` download |
| **Licenses** | Per node: application, used/licensed with bar, type, activated, added, expiry. **Poll now** per node |
| **Live Traps** / **Live Syslog** | Live tails with filters; click a row for details |
| **Trap Catalog** | Decoding table; admins import CSV/YAML with diff preview |
| **Thresholds** | Edit polled-metric rules (§10) |
| **Health** | Ingest rates, engine lag, spool backlog, monitor disk; service heartbeats; receiver counters (decode errors, rejected community, suppressed, masked, drops, DB errors/spool/replay); engine counters; poller job table (runs, failures, last/max ms, last error); largest tables; last maintenance and latest backup. Refreshes every 15 s |

## 8. Onboarding nodes

1. **Nodes → Add node**: name, management IP, SNMP, trap community, REST API (Client credentials recommended; Password grant also supported). **Run test** checks ICMP, SNMP and API with CPPM-side hints. Secrets are write-only and encrypted.
2. **Discover the rest of the cluster**: Overview → **Discover cluster**. This reads `/api/cluster/server`. Tick the unmonitored members and copy SNMP / API / trap-community settings from the source node.
3. **Polling enabled** off pauses polling; traps/syslog are still matched. **Maintenance until** (IST) records alerts as *suppressed (maintenance)* with no tickets.
4. **Deleting a node** resolves its open alerts (children before NODE DOWN) through the engine.
5. CLI probe: `sudo -u cppmmon /opt/cppmmon/venv/bin/python /opt/cppmmon/tools/cppm_probe.py --node <name-or-ip>` (`--json`; exit 0 = all passed).

## 9. Alerts and tickets

- **Dedup key** `node | type | instance`. Cluster-wide types key on the cluster (publisher UUID). Service alerts key on the **unit** name, so trap, watchdog and REST share one alert.
- **One open alert per key.** Repeats increase *occurrences* and add `RE-OCCUR` to the ticket at most every 30 min. A higher severity adds `ESCALATE`.
- **Clear**: pairing trap (1018/1019), watchdog "is running", REST "Running", or a polled metric back past its clear value. The alert becomes *cleared*, the ticket *RESOLVED*, and a RESOLVED line is appended.
- **NODE DOWN** (ICMP **and** SNMP failing 3 consecutive cycles) suppresses that node's other alerts. On recovery, still-active ones become normal alerts with their own tickets. **Degraded**: ICMP OK, SNMP + API failing.
- **Flap guard**: more than 3 open/close cycles in 30 min → `FLAPPING:` with severity +1. Clears are held until 30 min of quiet.
- **Manual resolve** (single, selected, all shown) queues an internal clear for the engine; the ticket gets `RESOLVED manually resolved by <user>`.
- **Severity → priority**: Critical P1 (1/1) · High P2 (2/2) · Medium P3 (3/3) · Low/Info no ticket.
- **Ticket files**: `/var/lib/cppmmon/tickets/YYYY/MM/DD/CPPM-YYYYMMDD-NNNN.txt`, DESIGN §8 layout, atomic writes. Lifecycle JSON lines go to `tickets/alerts.log` (`opened`, `reoccurred`, `escalated`, `suppressed`, `cleared`).

## 10. Threshold rules (polled metrics only)

| Rule | Metric | Warning → Medium | Critical → High | Clear | Sustain |
|---|---|---|---|---|---|
| cpu | cpu_pct | > 85 | > 95 | < 75 | 300 s |
| mem | mem_pct | > 85 | > 95 | < 75 | 300 s |
| disk | disk_pct | > 80 | > 90 | < 75 | 0 |
| disk_mount | disk_mount_pct | > 85 | > 95 | < 80 | 0 |
| auth_fail | auth_fail_pct (≥ 20 auths/interval) | > 30 | > 60 | < 20 | 600 s |
| auth_src_fail | auth_src_fail_per_min | > 20 | — | < 5 | 300 s |
| license | license_pct | ≥ 90 | ≥ 100 | < 85 | 0 |
| cert | cert_days_left (RADIUS, HTTPS(RSA)) | ≤ 30 | ≤ 7 | > 30 | 0 (expired → **Critical**) |
| if_errors | if_errors_per_min | > 10 | — | < 1 | 300 s |
| trust_cert | — | **disabled** (trust list not polled) | | | |

## 11. Syslog handling

- Stored raw with the parsed header (host, app, facility, severity, device timestamp) and detected format (`cef`, `leef`, `rfc5424`, `rfc3164`, `raw`). Field parsing and alert rules are Phase 5.
- TCP accepts LF and RFC 6587 framing. Messages over 64 KB are truncated and flagged.
- **Credential masking** before storage: `community=`, `password=`, `secret=`, pysnmp `payload [..]` and similar become `***`.
- **Repeat suppression**: the same normalised message from the same source is stored once per `CPPMMON_SYSLOG_REPEAT_WINDOW_S` (60 s), followed by one `[cppmmon] N repeat(s) … suppressed` row.

## 12. Retention (hourly timer)

| Data | Kept |
|---|---|
| raw_syslog | 30 days |
| raw_traps | 90 days |
| events (processed) | 30 days |
| metrics (raw) | 7 days, and only once rolled up |
| metrics_5m (avg/min/max per 5 min) | 90 days |
| alerts, tickets | forever |
| backups | newest 14 daily archives |

The same hourly run raises an internal **`monitor.disk_low`** alert (Medium, ticketed) when the monitor's data disk passes **85%** used, and clears it below 80%.

## 13. Simulation and tests

| Tool | Use |
|---|---|
| `SIM-MONITOR-VM` node | polling paused; monitor VM IP; random trap community in `/var/lib/cppmmon/sim_trap_community` |
| `tools/simulate_traps.sh -c <comm> -t <host:port> [--only 1017,1018] [-n <cppmNodeIp>]` | sends catalog traps plus one unknown OID |
| `tools/simulate_syslog.sh -t <host>` | CEF/LEEF/standard/plain over UDP and TCP |
| `pytest` | `sudo -u cppmmon bash -c 'cd /opt/cppmmon && venv/bin/python -m pytest -q'` (91 tests) |

## 14. Configuration reference (`/etc/cppmmon/cppmmon.env`)

| Variable | Default | Purpose |
|---|---|---|
| `CPPMMON_DB_URL` / `CPPMMON_WEB_SECRET` | generated | secrets |
| `CPPMMON_WEB_SESSION_HOURS` / `_COOKIE_SECURE` | 8 / false | session |
| `CPPMMON_RECEIVER_TRAP_PORT` / `_SYSLOG_PORT` | 162 / 514 | receiver ports |
| `CPPMMON_SYSLOG_REPEAT_WINDOW_S` | 60 | repeat suppression (0 = off) |
| `CPPMMON_CERT_MONITOR_SERVICES` | `RADIUS,HTTPS(RSA)` | server certificates polled |
| `CPPMMON_RETAIN_*_DAYS` | §12 | retention |
| `CPPMMON_DISPLAY_TZ` | Asia/Kolkata | display zone |
| `CPPMMON_TICKET_ASSIGNMENT_GROUP` / `_CALLER` | Network Operations / CPPM-Monitor (automation) | ticket fields |
| `CPPMMON_LOG_LEVEL` | INFO | logging |

After editing: `sudo systemctl restart 'cppmmon-*'`.

## 15. Troubleshooting

| Symptom | Check / fix |
|---|---|
| A service shows stopped although it was started | (a) CPPM may send **no** "started" trap: the monitor then confirms the start through the REST re-check, every 2 min while the alert is open, or immediately with **Poll now**. (b) Check the **source IP** of any start trap in Live Traps: in the lab, a start trap for TACACS came from **.195** while .196 was still stopped. Check *Services Control* on the right server |
| Test Connection: ICMP fails, SNMP/API OK | ICMP filtered; status still **Up** |
| SNMP "No SNMP response" | §3 #1 and #5 |
| SNMP "cppmSystemTable has no instances" | not a CPPM, or the SNMP view excludes `.1.3.6.1.4.1.14823` |
| API "HTTP 403 Forbidden (HTML error page)" | source-IP restriction or firewall (§3 #5), not credentials |
| API `invalid_client` / `invalid_grant` / `unauthorized_client` | client ID/secret, user/password, or grant type mismatch |
| Traps visible but no alerts | Live Traps → *Rejected community* (set the node's Trap community) or *Unregistered* (sender is not a node) |
| Watchdog/traps show as UNKNOWN_TRAP | catalog not seeded: `sudo cppmmon-admin catalog-import /opt/cppmmon/catalog/cppm_traps.yaml --seed` |
| No CEF syslog | §3 #7 (Export Filters) not configured or not targeting the monitor |
| Huge syslog volume from `cppm.async-netd` | §3 #8 log level |
| Alert won't clear | FLAPPING (clears after 30 min quiet) or resolve manually |
| Engine lag (Health) | `journalctl -u cppmmon-engine`; failed events have `processed=2` |
| DB down | receiver spools and replays; poller/engine retry |

## 17. Production cutover checklist

| # | Item | Notes |
|---|---|---|
| 1 | **VM sizing** | 2 vCPU / 4 GB RAM is enough for a few clusters. **Disk: ≥ 50 GB for /var** (the lab VM's 11 GB root has ~1.8 GB free). Use UAT's measured syslog volume and DB growth (Health → Storage) for the final size. Syslog volume is the main driver |
| 2 | OS | Ubuntu 22.04/24.04 or RHEL 8/9, Python 3.11+, MySQL 8 local. `sudo` for install |
| 3 | Install | Copy the release tarball, verify SHA-256, extract, `sudo ./deploy/install.sh`, create admin users (no defaults) |
| 4 | Network | Monitor → CPPM: ICMP, UDP 161, TCP 443. CPPM → monitor: UDP 162, UDP/TCP 514. Users → monitor: TCP 8070 (or 443 via proxy) |
| 5 | HTTPS | Put nginx (or the corporate proxy) with a certificate in front of :8070, then set `CPPMMON_WEB_COOKIE_SECURE=true` |
| 6 | CPPM side | Apply RUNBOOK §3 on **every** production node: SNMP, trap destination, read-only API client, syslog target, Export Filters, Async network services at INFO |
| 7 | Nodes | Add one publisher, then **Discover cluster**; Run test on each; set *Site* names |
| 8 | Tickets | Set `CPPMMON_TICKET_ASSIGNMENT_GROUP` for production; agree who reads `/var/lib/cppmmon/tickets` until the ServiceNow API sink exists |
| 9 | Backups | Confirm `cppmmon-backup.timer`. **Copy `/var/backups/cppmmon` off the VM** (it contains the Fernet key) |
| 10 | Credentials | Use production-only SNMP communities / API clients; never reuse lab values |
| 11 | Acceptance | Re-run UAT-03, -06, -10/11, -14 against production nodes before go-live |
