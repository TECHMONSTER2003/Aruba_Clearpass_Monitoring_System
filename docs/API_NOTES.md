# CPPM: verified notes (lab)

Lab node `cppm-pub` (192.0.2.10): ClearPass **6.14.1.372486**, model CLABV (VM), Publisher, 3-node cluster, cumulative patch 1 for 6.14.0. Verified from the monitor VM on 2026-11-17 with `tools/cppm_probe.py` and the UI Test Connection. Credentials and tokens are redacted.

## REST API

| Endpoint (DESIGN §2.3) | Lab result | Notes |
|---|---|---|
| `POST /api/oauth` | **200**, `expires_in` 28800 (8 h) | `client_credentials` works with a confidential client. Also supports `password` (public client, no secret) and `refresh_token` (Swagger enum). ~450 ms. |
| `GET /api/cppm-version` | **200** | Fields: `app_major_version`, `app_minor_version`, `app_service_release`, `app_build_number`, `hardware_version` ("CLABV"), `fips_enabled`, `eval_license`, `cloud_mode` |
| `GET /api/server/version` | **200** | `cppm_version`, `guest_version`, `installed_patches[] {name, description, installed}` |
| `GET /api/cluster/server` | **200** | `_embedded.items[]`: `server_uuid`, `management_ip`, `is_publisher`, `replication_status` ("ENABLED"), `last_replication_timestamp`. Lab cluster: .195 publisher, .194 and .196 subscribers. Cluster identity = publisher UUID |
| `GET /api/server/service/{server_uuid}` | **200** | A **map** keyed by systemd unit (not a list): `{unit: {display_name, description, state: Running/Stopped, is_running}}`. Lab: "Ingress logger service" Stopped by design, all key services Running |
| `GET /api/server-cert` | **200** | Items have `service_name`, `subject`, `issued_by`, `expiry_date` ("Mar 12, 2027 17:10:44 IST"), `validity`, `cert_file` (PEM). Expiry is read from the PEM; the string is the fallback. **Lab: HTTPS(ECC) expired 2026-02-20** |
| `GET /api/cert-trust-list` | **200**, `count` 51 | Items: `id`, `enabled`, `cert_usage[]`, `cert_file` (PEM only, no expiry field). Paged by 100; only `enabled` entries are evaluated. Lab: 23 enabled, one expired ("Hewlett Packard Enterprise Private SSL CA") |
| `GET /api/application-license` | **200** | Keys only (`license_key` redacted), no usage |
| `GET /api/application-license/summary` | **200** | `items[]`: `license_type`, `licensed_count`, `used_count`. **Used for license %** |
| `GET /api/endpoint?calculate_count=true&limit=1` | **200**, `count` 4835 | Only `count` is read |
| `GET /api/session` | **500** "enable Insight" | Needs Insight on at least one node. Treated as **unsupported** (logged once per node) |

Monitor-side note: a CPPM that blocks the monitor's source IP answers `POST /api/oauth` with **HTTP 403 and an HPE HTML error page** (seen on `cppm.example.com`). This is classified as `ip_restricted`, with its own hint.

Error bodies seen or expected: OAuth failures return 400/401 with `error` = `invalid_client` / `invalid_grant` / `unauthorized_client`. `cppm_api.py` classifies on those strings.

## SNMP (CPPM-MIB)

- **DESIGN's `…` prefix is `1.3.6.1.4.1.14823.1.6`.** `cppmSystemEntry` = `1.3.6.1.4.1.14823.1.6.1.1.1.1.1.<col>.<idx>`. Phase 1 first shipped with one extra `.1`, and the regression test now pins the correct OID.
- **Instance index on this lab node: `0`.** Index 1 is absent, so discovery picks 0.
- Column layout observed (index 0):

| Col | Value seen | Meaning |
|---|---|---|
| 1 | CLABV | model |
| 2 | "None" | serial, a literal placeholder on VMs (normalised to null) |
| 3 | 6.14.1.372486 | version |
| 4 | cppm-pub.example.com | hostname (also sysName) |
| 5 | Publisher | node type |
| 6 | default | (zone / cluster name) |
| 7 | 3 | cluster node count |
| 8 / 9 | 192.0.2.10 / MAC | management IP / MAC |
| 10 / 11 | 127.0.0.1 / MAC | data port IP / MAC (data port not configured) |
| 12 / 13 | 8589934592 / 3555672064 | memory total / free, **bytes** (8 GiB) |
| 14 / 15 | 168528976896 / 90946159616 | disk total / free, **bytes** |
| 16 | 8 | CPUs |
| 17 | 1191397 | **cppmSystemUptime, seconds** (~13.8 d) |
| 18 | 0 | (undocumented; to identify in Phase 3) |

- **Reboot detection must use col 17, not `sysUpTime`.** `sysUpTime` read 2077 s (the SNMP agent restarted) while the system had been up ~13.8 days. A `sysUpTime` drop alone means the agent restarted, not the node.
- A full GETBULK walk of `…1.6.1.1` with 25 repetitions, a 3 s timeout and 2 retries timed out. Phase 3 table walks therefore walk per table.

### Other tables (verified 2026-11-17)

| Table | OID | Layout on 6.14.1 |
|---|---|---|
| policyServerTable | `…1.6.1.1.2.3.1.<col>.0` | **Index `.0`**, not hostname-indexed as DESIGN assumed. Cols 14/15/16 = auth success/failure/total, 17/18/19 = daily success/failed/total |
| radiusServerTable | `…2.1.1.<1-5>.0` | 5 counters, all 0 in the lab (semantics unconfirmed, not used) |
| radiusServerAuthTable | `…2.2.1.<col>.<n>` | Col 1 index, col 2 source name (20 sources incl. CORP-AD-LDAP, Microsoft Entra). Cols 3–6 are **assumed** success/failure/total/time. All 0 in the lab, so this needs confirming under real auth load |
| tacacsAuthTable | `…2.7.1.<1-7>.0` | 7 counters (unconfirmed semantics, not used yet) |
| networkTrafficTable | `…3.1.1.<col>.<n>` | Per-service port traffic (col 2 name, col 3 port, col 4 bytes); not used |
| UCD CPU | `.2021.11.50–53.0` | User/Nice/System/Idle present. **Wait/Kernel/Interrupt absent** |
| UCD memory | `.2021.4.5/6/14/15.0` | KB. **`memAvailReal` is *free* memory here** (241 MB of 8 GB), so used% = total − free − buffers − cached. CPPM-MIB "free" (col 13) already includes cache on 6.14, contrary to DESIGN §2.1 |
| hrStorage | `.25.2.3.1` | Only `/` (29 GB) and swap. CPPM-MIB disk (168 GB) covers all partitions, so `disk_pct` uses CPPM-MIB and per-mount % comes from hrStorage |
| IF-MIB | `.2.2.1` | lo, eth0, eth1, docker0, br-*, veth*. **No `ifHC*` 64-bit counters**: 32-bit octets with wrap handling; lo/docker/bridges skipped |

### CPPM built-in watchdog traps (DISMAN-EVENT-MIB), observed 2026-11-17
CPPM's net-snmp agent pushes `mteTriggerRising` (`1.3.6.1.2.1.88.2.0.2`) / `mteTriggerFalling` (`…0.3`) without being polled.
- Varbinds: `mteHotTrigger` (`88.2.1.1.0`, e.g. `extTable`, `memory`), `mteHotOID` (`88.2.1.4.0`, e.g. `2021.8.1.100.<n>` = extResult), `mteHotValue` (`88.2.1.5.0`), `extNames.<n>` (`2021.8.1.2.<n>`, check name), `extOutput.<n>` (`2021.8.1.101.<n>`, text).
- Checks seen on SEC/TRI: radius, tacacs, policy, dbcn, dbwrite, replication, statsd, system-auxiliary, vip, zone-cache, fias, postgresql, postgresql_logdb, crond, httpd, swap, and **`cpass-domain-server@<DOMAIN>.service` ("Domain Server")**, the per-AD-domain service.
- **The Rising/Falling direction is not reliable on its own**: a Falling trap carried `httpd is inactive (dead)`, and a Rising one carried `… is running`. Classify on `mteHotValue` / the `extOutput` text ("is stopped", "inactive", "dead", "failed").
- CPPM-MIB has **no auth-source / AD-reachability trap**. The Domain Server check covers the AD domain service process, not DC reachability.

### CPPM-MIB service traps as actually sent (2026-11-17)
- `cppmServiceName` carries the **systemd unit** (`cpass-tacacs-server`), not the display name ("TACACS+ server"). `cppmTrapMessage` = "cpass-tacacs-server service is stopped".
- Each trap carries every varbind **twice**: once with a NULL value at the column OID (`…100.17`) and once with the real value at `…100.17.0`.
- A start (1018) for a service on a subscriber can arrive **from the publisher's IP** when the service is controlled from the publisher UI. In the lab, TACACS was stopped on .195 and .196 and started only on .195.
- `/api/application-license` items: `product_name`, `license_type` (Permanent/…), `user_count`, `duration` + `duration_units`, `license_added_on`, `activation_status`. Expiry is computed as added_on + duration when duration > 0.
- An auth source "Test connection" in the CPPM UI produces **no** trap and **no** System Event, only Apache access-log lines (`authSources.*`, `ldapBrowser.closeConnection`).
- `/api/auth-source/{id}`: server address in `cppm_primary_auth_source_connection_details.host_name` / `connection_port`; backups in `cppm_auth_source_connection_backups`. Lab directory sources: CORP-AD (AD), POC-AD (AD), CORP-AD-LDAP (LDAP). `/api/ad-domain/{server_uuid}` lists joined domains (CORP.EXAMPLE.COM, POC.EXAMPLE.COM).

### Traps and syslog observed from the lab node
- **Security:** the publisher's (.195) `cppm.async-netd` runs at **DEBUG** and logs every incoming SNMP request, **including the community in clear text**. The receiver masks it before storage (since 2026-11-17 15:10 IST). The bursts of ~44 msg/s were this debug output of the monitor's own SNMP walks.
- Real trap: `cppmLowDiskSpace` (v2c, community accepted) with **every varbind sent twice**. The decoder keeps both raw; named lookup collapses them.
- Syslog (OS forward, before Export Filters): BSD header with an **ISO-8601 timestamp** `<142>2026-11-17T13:39:44+05:30 <ip> cppm.<app>[pid]: …`. Bursts of ~44 msg/s of `cppm.async-netd … WARN Skipping Ingress Events` (Ingress logger service stopped). The receiver suppresses repeats per 60 s window.
