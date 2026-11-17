# Changelog

## 1.0.0-rc1 (2026-11-17): UAT release candidate

First release candidate of the CPPM Monitor for UAT. Built and verified against a 3-node lab ClearPass 6.14.1 cluster
(one publisher, two subscribers).

### Monitoring
- **Polled** (ICMP / SNMP / REST): CPU, memory, disk, load, uptime and reboot detection, auth rate and failure %, per-auth-source failures, interface throughput and errors, endpoint count, cluster role and replication, service states (15-min backstop, 2 min while a service alert is open), **RADIUS + HTTPS(RSA) server certificates**, licenses (usage, type, activation, expiry).
- **Reactive** (CPPM pushes): all CPPM-MIB traps (service stop/start/restart, cert/license expiry, low disk/memory, high CPU, cluster events, config reset/restore, core dump, license overrun), CPPM's built-in **service watchdog** traps (DISMAN) including the AD *Domain Server* service, coldStart/warmStart, link/agent traps (log-only), unknown OIDs (log-only). Raw syslog (UDP/TCP 514) stored and searchable.
- Multi-signal **NODE DOWN** (ICMP + SNMP, 3 cycles) with suppression of the node's other alerts; *Degraded* when only management fails.

### Alerting and tickets
- Alert engine: dedup, one alert per service across trap/watchdog/REST signals, clear pairing, hysteresis thresholds, flap guard, maintenance windows, cluster-wide grouping, severity → P1/P2/P3.
- ServiceNow-ready **ticket files** (DESIGN §8 layout) with in-place updates and resolution; `alerts.log` audit trail.
- Manual, selected and bulk resolve (engine stays the single writer).

### UI (light/dark theme)
Dashboard (Poll all now, discovery banner) · Nodes (add/test/Poll now/Discover cluster/maintenance/pause) · Node overview (charts 1 h–7 d) · Alerts · Tickets · Licenses · Live Traps · Live Syslog · Trap Catalog (import with diff preview) · Thresholds · Health.

### Operations
- systemd services (receiver, poller, engine, web), hourly maintenance (5-min rollups, retention), **daily backup** (DB + tickets + config/key, 14 kept).
- Receiver spools to disk when MySQL is down and replays idempotently. Syslog repeat suppression and credential masking.
- Monitor self-check: alert when the VM disk passes 85%.
- 91 automated tests.

### Known limitations (see docs/UAT_PLAN.md §5)
- **Syslog parsing and syslog-based alerts (Phase 5) are not in this release.** They need CPPM *Syslog Export Filters* (CEF) to be active and rules approved from real samples. Syslog is stored and searchable only.
- AD/LDAP **DC reachability** depends on Phase 5 (System Events). This release covers the AD *Domain Server* service (trap) and auth-source failure counters (polled).
- SNMPv3 traps are not supported (v2c traps; SNMPv3 polling is supported).
- CPPM does not always send a "service started" trap; the 2-min adaptive re-check covers it.
