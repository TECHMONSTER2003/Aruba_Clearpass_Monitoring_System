# Deviations from DESIGN.md / CLAUDE.md

DESIGN.md remains the source of truth. This file records every place the build differs from it, and why.
Each entry was reported at the end of its phase. Newest last.

| # | Phase | Area | DESIGN / CLAUDE says | Built | Why |
|---|---|---|---|---|---|
| 1 | 0 | Repo layout | `docs/DESIGN.md`, `catalog/cppm_traps.yaml` | Files moved there from the folder root | Match CLAUDE.md §3 |
| 2 | 0 | Schema | §6 columns | **Additive only**: `raw_*.dedup_hash` (spool idempotency), `raw_syslog.truncated`, `node_state.api_state/last_test/last_test_at`, `alerts.flapping/parent_alert_id/suppress_reason/clear_pending_at/last_update_note_at/attributes`, `trap_catalog.dedup_field`, tables `ticket_seq`, `service_heartbeat` | Needed by rules DESIGN itself describes (spool replay, flap guard, suppression, daily ticket sequence, Health page) |
| 3 | 0 | Dev tools | — | pytest installed in the production venv | Tests run on the VM |
| 4 | 0 | Firewall | open ports in firewalld | No rules added | Neither firewalld nor ufw is active on the VM (rule followed: only if active) |
| 5 | 1 | ICMP | icmplib unprivileged, fping fallback | Plus `/etc/sysctl.d/60-cppmmon-ping.conf` | VM had `ping_group_range = 1 0`; option (a) approved by the user |
| 6 | 1 | REST auth | OAuth `client_credentials` | Also supports the `password` grant (`api_grant_type`, `api_username`, `api_password_enc`) | The lab's existing API client is a public password-grant client |
| 7 | 1 | CPPM-MIB OID | `…1.1.1.1.1.<col>.<idx>` | `1.3.6.1.4.1.14823.1.6.1.1.1.1.1.<col>.<idx>` | The "…" prefix is `1.3.6.1.4.1.14823.1.6`. First build had one extra `.1`; fixed and pinned by a test |
| 8 | 1 | Nodes | — | "Polling enabled" toggle; paused nodes still match traps/syslog | Needed for the simulation node and temporary pauses |
| 9 | 2 | Trap receiver | `pysnmp.entity.rfc3413.ntfrcv` | Raw decode with the pysnmp proto API + pyasn1 | ntfrcv silently drops traps with an unknown community, but CLAUDE §4.3 requires storing them with `community_ok=false`; raw decode also gives the source IP directly. v3 traps stay Phase 6 |
| 10 | 2 | Trap catalog | `clear_oid` single value | `clear_oid` TEXT, comma-separated | Seed YAML clears 1017 with 1018 **or** 1019 |
| 11 | 2 | Catalog import | upsert by OID | Upsert touches **only columns present in the file**; seed mode never overwrites | A partial CSV must not blank templates/clear pairs |
| 12 | 2 | Syslog | store every message | **Repeat suppression** (same source + normalised body, once per 60 s window + summary row; `CPPMMON_SYSLOG_REPEAT_WINDOW_S`) | Lab CPPM bursts ~44 msg/s of one line (≈2.6 GB/day) on a VM with 1.9 GB free |
| 13 | 2 | Retention | Phase 6 | Brought forward for raw_syslog / raw_traps / events | Same disk risk |
| 14 | 2 | Syslog header | RFC 3164/5424 | Also accepts BSD headers with an ISO-8601 timestamp | That is what CPPM 6.14 sends |
| 15 | 3 | policyServerTable | string-indexed by hostname, walk | Instance `.0`, single GET | Observed on 6.14.1 |
| 16 | 3 | Memory % | "free excludes cache; pair with memAvailReal" | used = total − free − buffers − cached (UCD); CPPM-MIB free as fallback | On 6.14 `memAvailReal` is free memory and CPPM-MIB "free" already includes cache |
| 17 | 3 | Disk % | CPPM-MIB + hrStorage | `disk_pct` from CPPM-MIB (all partitions); hrStorage per mount separately | hrStorage only exposes `/` (29 GB of 168 GB) |
| 18 | 3 | Reboot detection | sysUpTime / cppmSystemUptime decrease | **cppmSystemUptime only** (+120 s tolerance) | sysUpTime resets whenever the SNMP agent restarts (seen in the lab) |
| 19 | 3 | Interfaces | ifIn/OutOctets | 32-bit counters with wrap handling | No `ifHC*` on CPPM |
| 20 | 3 | Service alerts | "not running → High" | Critical services alert whenever stopped; others only on a running → stopped transition | Some services (e.g. Ingress logger) are stopped by design and would alert forever |
| 21 | 3 | Certificates | trust-list expiry | Only **enabled** trust-list CAs, separate rule capped at Medium; server cert expired → Critical | 51 trust entries, mostly disabled defaults |
| 22 | 3 | /api/session | active sessions KPI | Unsupported | HTTP 500 unless Insight is enabled |
| 23 | 4 | Cluster grouping | "keyed by cluster" | Cluster identity = publisher `server_uuid` from `/api/cluster/server` | CPPM exposes no cluster ID |
| 24 | 4 | Info-severity traps | alert, no ticket | No alert at all (log only, visible in Live Traps) | Matches §7.7 "log only" and keeps the Alerts page actionable |
| 25 | 4 | Manual resolve | — | UI inserts an internal clear event; the engine applies it | Keeps "engine is the only writer of alerts and tickets" |
| 26 | 4 | Poison events | — | A failing event is marked `processed=2` and skipped | One bad event must not block the queue |
| 27 | 4+ | Cluster discovery | not in DESIGN | `/nodes/<id>/discover` from `/api/cluster/server`, copying encrypted credentials; dashboard banner from the hourly member count | User request: subscribers had to be added by hand |
| 29 | 4+ | Syslog storage | store raw | **Credential masking before storage** (`community=`, `password=`, `secret=`, pysnmp `payload [..]`, …) | CPPM .195 `async-netd` at DEBUG logs SNMP requests with the community in clear text |
| 28 | 4+ | Bulk resolve | not in DESIGN | Resolve selected / Resolve all shown; children cleared before NODE DOWN parents | User request |
| 30 | 4+ | Polling vs reactive | REST services 2 min, auth tables 60 s | REST services **15 min** (backstop), auth-source walk **5 min** | User decision: prefer CPPM-pushed signals; polling costs CPU on both sides |
| 31 | 4+ | Trap catalog | 22 CPPM-MIB traps + std | **+ DISMAN watchdog** (`mteTriggerFired/Rising/Falling`), linkUp/linkDown, net-snmp agent start/stop/restart, and 25 varbind names (DISMAN, UCD ext/mem/dsk/la/pr, IF-MIB) | CPPM 6.14 pushes ~20 service/process health checks this way (incl. AD Domain Server) |
| 32 | 4+ | Watchdog classification | — | Classified by `extOutput` text / `mteHotValue`, **not** by Rising/Falling | Direction observed to be unreliable in the lab |
| 33 | 4+ | Service alerts | per-signal alerts | **One `service.down` alert per service unit** for trap 1017/1018/1019, watchdog and REST poll | One service stop produced 2–3 alerts before; real 1017 traps carry the unit name |
| 34 | 4+ | Varbind naming | — | Table varbinds named without the instance index (`extNames.14` → `extNames`); the full OID is kept in the list | Lets catalog rules use table columns as dedup fields |
| 35 | 4+ | Certificates | server certs + trust list (§3) | Polled: **only installed RADIUS + HTTPS(RSA)** (`CPPMMON_CERT_MONITOR_SERVICES`). Trust list and other server certs: only via CPPM's own trap 1003 / syslog. `trust_cert` rule disabled | User scope decision |
| 36 | 4+ | Licenses | `licenses` app/total/used | + `license_type`, `activated`, `added_on`, computed `expires_at` (from `/api/application-license`); per-node **Licenses** page | User request |
| 37 | 4+ | Poll now | not in DESIGN | `poll_requests` table; the poller wakes every job for the node(s) within ~2 s | User request |
| 38 | 4+ | Link traps | — | linkDown/linkUp **log-only** | CPPM link traps carry only ifIndex and fire for docker bridges |
| 40 | 6 | Adaptive service polling | fixed interval | REST services every **2 min while a service.down alert is open** for the node, 15 min otherwise | CPPM sent no "started" trap when TACACS was started on .196 (lab, 16:0x IST) |
| 41 | 6 | Rollups | nightly job | Hourly (same maintenance timer); raw metrics purged only after roll-up | Simpler, smaller batches |
| 42 | 6 | Monitor self-check | ticket-write failure alert | Plus `monitor.disk_low` internal alert (85% / 80%) | Lab VM disk at 78% |
| 43 | 6 | Backup | "backup script for DB + tickets" | Plus `/etc/cppmmon` (env + Fernet key), daily systemd timer, 14 kept | Without the key, restored credentials cannot be decrypted |
| 44 | 6 | SNMPv3 traps | Phase 6 | **Not implemented** in 1.0.0-rc1 | Lab and target estate use v2c traps; listed as a known limitation |
| 45 | 5 | Syslog parsers/rules | Phase 5 | **Not in 1.0.0-rc1** | No CEF received yet; CLAUDE.md requires real samples + user approval |
| 39 | 4+ | Node deletion | — | Deleting a node queues engine clears for its open alerts | An orphaned NODE DOWN stayed open after a node was deleted |
