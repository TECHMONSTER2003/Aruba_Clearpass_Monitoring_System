# CPPM Monitor 1.0.0-rc1: UAT plan

Release: **cppmmon 1.0.0-rc1** (see `CHANGELOG.md`). Operating details: `docs/RUNBOOK.md`.
Each case lists the steps and the expected result. Record **Pass / Fail / Notes**. A *Fail* on any **Critical** case blocks production.

## 1. Pre-requisites (complete before testing)

| # | Item | Check |
|---|---|---|
| P1 | Monitor VM per RUNBOOK §17 sizing; `deploy/install.sh` completed; `systemctl status 'cppmmon-*'` all active | |
| P2 | Admin account created with `sudo cppmmon-admin create-user <name> --role admin`; one operator and one viewer for role tests | |
| P3 | **On every CPPM node**: SNMP agent + **trap destination** = monitor IP:162 with the node's trap community (RUNBOOK §3 #1–#3) | |
| P4 | REST API client (client credentials, read-only profile) and the monitor IP allowed (RUNBOOK §3 #4–#5) | |
| P5 | Syslog target = monitor IP:514 on **every node** | |
| P6 | *Async network services* log level INFO on every node, **service restarted** so it takes effect (RUNBOOK §3 #8) | |
| P7 | (For Phase 5 readiness only) Syslog Export Filters System Events + Audit Records in **CEF** (RUNBOOK §3 #7) | |

## 2. Test cases

| ID | Pri | Area | Steps | Expected result |
|---|---|---|---|---|
| UAT-01 | Critical | Access | Open `http://<vm>:8070`, log in with the admin account | Login page shown. No default password works. Session lasts 8 h |
| UAT-02 | High | Roles | Log in as viewer; try Add node, Resolve, Thresholds save | All edit actions hidden or HTTP 403. Pages viewable |
| UAT-03 | Critical | Onboarding | Nodes → Add node (publisher) → **Run test** | ICMP, SNMP, API all pass with latency and hostname/version shown |
| UAT-04 | High | Onboarding | Overview → **Discover cluster** → add the subscribers (copy creds) → Run test on each | All members listed with role and replication; added nodes poll within 60 s |
| UAT-05 | High | Security | Edit a node; view page source | No community, secret or password is ever shown (only "stored") |
| UAT-06 | Critical | KPIs | Compare the dashboard tile with CPPM (Dashboard / System Monitor / Server Manager) | CPU ±10 pts, Memory ±5 pts (monitor excludes cache), Disk ±1 pt, Uptime, Version, Role, Endpoints, License used/total, RADIUS/TACACS state all match |
| UAT-07 | High | KPIs | Overview → Certificates | Only RADIUS and HTTPS(RSA) listed, with correct expiry dates/days |
| UAT-08 | High | Licenses | Licenses page | Per node: application, used/licensed, type, activated, added, expiry match CPPM *Licensing* |
| UAT-09 | High | Poll now | Change something visible in CPPM (e.g. stop a non-critical service), press **Poll now** on that node | Values/state refresh within ~30 s |
| UAT-10 | Critical | Reactive | CPPM Services Control on a **subscriber**: stop *Stats collection service* (non-critical) | Within seconds: trap in Live Traps → **one** Medium alert + **P3** ticket file |
| UAT-11 | Critical | Reactive | Start that service again | Alert cleared and ticket RESOLVED within 2 min (trap, or adaptive re-check if CPPM sends no start trap) |
| UAT-12 | Critical | Reactive | Stop **RADIUS** (or TACACS) on a subscriber for 3 min, then start | **One** High alert + **P2** ticket (trap, watchdog and REST merge: occurrences > 1, still one ticket); resolved after start |
| UAT-13 | High | Reactive | Reboot a subscriber | coldStart trap → High alert; "Reboot detected" from uptime; NODE DOWN only if down for more than 3 poll cycles; all clear/resolve after it is back (coldStart: resolve manually) |
| UAT-14 | Critical | Node down | Block ICMP + SNMP from the monitor to one node (ACL), or power off a test node | After about 3 min: **NODE DOWN P1** ticket. Any other alert for that node shows *suppressed (node down)*. Restore → resolved |
| UAT-15 | High | Maintenance | Set *Maintenance until* on a node, then repeat UAT-10 | Alert recorded as *suppressed (maintenance)*, **no ticket** |
| UAT-16 | High | Thresholds | Thresholds → set cpu warning to 1 (clear 0.5), wait 6 min; then restore 85/95/75 | P3 ticket after the 300 s sustain; RESOLVED ("back to normal") after restore |
| UAT-17 | High | Tickets | Open a ticket, download `.txt`, compare with DESIGN §8 | All fields present (CI, Priority, Impact/Urgency, Description, Evidence, Recommended Action, UPDATES). Daily numbering `CPPM-YYYYMMDD-NNNN` |
| UAT-18 | Medium | Resolve | Alerts → tick 2 → *Resolve selected*; then *Resolve all shown* | Alerts cleared; tickets get `RESOLVED manually resolved by <user>` |
| UAT-19 | Medium | Traps | `tools/simulate_traps.sh` against the monitor with the SIM community (RUNBOOK §13) | All catalog traps decoded; unknown OID shown as UNKNOWN_TRAP; wrong community shown as *Rejected* with no alert |
| UAT-20 | Medium | Syslog | Live Syslog during UAT-10..12 | CPPM messages visible with node, format and severity; communities/passwords masked as `***` |
| UAT-21 | High | Resilience | `sudo systemctl restart cppmmon-<each>` one at a time during UAT-10 | No lost traps; UI recovers; no duplicate tickets |
| UAT-22 | Critical | Resilience | `sudo systemctl stop mysql`; send traps (UAT-19); start mysql | Health shows spool backlog; after start, traps replay into Live Traps, no duplicates |
| UAT-23 | High | Backup | `sudo systemctl start cppmmon-backup`; restore to a scratch VM per `tools/backup.sh` header | Archive in `/var/backups/cppmmon`; restored instance shows nodes and tickets and decrypts credentials |
| UAT-24 | Medium | Health | Health page | Services Running; ingest rates; engine lag < 10 s; poller jobs with 0 or few failures; disk and backup shown |
| UAT-25 | Medium | Soak | Leave running 24–48 h | No service restarts (`systemctl status`), steady memory (`ps -o pid,rss,cmd -u cppmmon`), engine lag stays low, disk growth as expected |

## 3. Data to collect during UAT
- Per node: syslog messages/min (Health), trap count, DB size growth per day (Health → Storage). These size the production VM disk.
- Any CPPM trap seen as UNKNOWN_TRAP (Live Traps → *Unknown OIDs*): send the OID to the team for the catalog.
- **CEF samples** once P7 is active (for Phase 5).

## 4. Exit criteria
All **Critical** cases pass. High cases pass, or each has an accepted workaround. Soak shows no memory growth or engine lag.

## 5. Known limitations in 1.0.0-rc1 (not defects)
1. Syslog-based alerting (Phase 5) is not included. Syslog is stored and searchable only.
2. AD/LDAP **domain-controller reachability** alerts depend on Phase 5 (System Events). Covered now: AD *Domain Server* service watchdog (trap), auth-source failure counters (5-min poll).
3. CPPM may not send a "service started" trap. Recovery is detected by the 2-min adaptive re-check instead of instantly.
4. coldStart/warmStart/reboot alerts have no automatic clear: resolve them after verification.
5. Link up/down traps are log-only (CPPM sends only ifIndex, including docker bridges).
6. SNMPv3 **traps** are not supported (v2c traps; v3 polling works).
7. HTTP only on :8070. Production should front it with HTTPS (RUNBOOK §17).
