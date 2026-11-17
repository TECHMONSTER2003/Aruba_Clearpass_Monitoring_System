"""Threshold evaluation with sustain window + hysteresis → poll events (DESIGN §3, §7.3).

State per (node, rule, instance):
  * value breaches warn/crit → start the sustain timer; once sustained, emit an
    open event at that level (escalation warn → crit emits again, no downgrade);
  * value returns past ``clear_value`` → emit a clear event (if open) and reset;
  * between clear and warn → hold (hysteresis: no flapping on the boundary).
Open state is seeded from open alerts at startup so a poller restart never
loses a pending clear.
"""
from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select

from cppmmon.db.models import Alert, Threshold
from cppmmon.db.session import session_scope

log = logging.getLogger(__name__)

# DESIGN §3 defaults. Editable later in the Thresholds UI (Phase 4).
DEFAULT_RULES: list[dict[str, Any]] = [
    dict(rule_id="cpu", metric="cpu_pct", op=">", warn_value=85, crit_value=95, clear_value=75, sustain_s=300,
         severity_warn="medium", severity_crit="high"),
    dict(rule_id="mem", metric="mem_pct", op=">", warn_value=85, crit_value=95, clear_value=75, sustain_s=300,
         severity_warn="medium", severity_crit="high"),
    dict(rule_id="disk", metric="disk_pct", op=">", warn_value=80, crit_value=90, clear_value=75, sustain_s=0,
         severity_warn="medium", severity_crit="high"),
    dict(rule_id="disk_mount", metric="disk_mount_pct", op=">", warn_value=85, crit_value=95, clear_value=80, sustain_s=0,
         severity_warn="medium", severity_crit="high"),
    dict(rule_id="auth_fail", metric="auth_fail_pct", op=">", warn_value=30, crit_value=60, clear_value=20, sustain_s=600,
         severity_warn="medium", severity_crit="high"),
    dict(rule_id="auth_src_fail", metric="auth_src_fail_per_min", op=">", warn_value=20, crit_value=None, clear_value=5,
         sustain_s=300, severity_warn="medium", severity_crit="high"),
    dict(rule_id="license", metric="license_pct", op=">=", warn_value=90, crit_value=100, clear_value=85, sustain_s=0,
         severity_warn="medium", severity_crit="high"),
    dict(rule_id="cert", metric="cert_days_left", op="<=", warn_value=30, crit_value=7, clear_value=30, sustain_s=0,
         severity_warn="medium", severity_crit="high"),
    dict(rule_id="if_errors", metric="if_errors_per_min", op=">", warn_value=10, crit_value=None, clear_value=1, sustain_s=300,
         severity_warn="medium", severity_crit="high"),
    # Trust-list CAs are no longer polled (scope change 2026-11-17): CPPM's own expiry traps/syslog cover them.
]
# Metrics whose open/clear must not depend on raw volume: auth_fail_pct is only
# evaluated when the interval had at least this many authentications.
MIN_AUTH_VOLUME = 20
UNITS = {"cpu_pct": "%", "mem_pct": "%", "disk_pct": "%", "disk_mount_pct": "%", "auth_fail_pct": "%",
         "license_pct": "%", "cert_days_left": " days", "trust_cert_days_left": " days",
         "auth_src_fail_per_min": "/min", "if_errors_per_min": "/min"}
LABELS = {"cpu": "CPU", "mem": "Memory", "disk": "Disk", "disk_mount": "Disk", "auth_fail": "Auth failure rate",
          "auth_src_fail": "Auth source failures", "license": "License usage", "cert": "Certificate expiry",
          "trust_cert": "Trusted CA expiry", "if_errors": "Interface errors"}


def seed_rules() -> int:
    """Insert missing default rules (never overwrites edited ones). Returns rows added."""
    with session_scope() as s:
        have = set(s.scalars(select(Threshold.rule_id)))
        new = [Threshold(**r, instance_glob="*", enabled=True) for r in DEFAULT_RULES if r["rule_id"] not in have]
        s.add_all(new)
        return len(new)


def _breach(op: str, v: float, t: float | None) -> bool:
    if t is None:
        return False
    return {">": v > t, ">=": v >= t, "<": v < t, "<=": v <= t}[op]


def _cleared(op: str, v: float, clear: float | None, warn: float | None) -> bool:
    ref = clear if clear is not None else warn
    if ref is None:
        return True
    return v < ref if op in (">", ">=") else v > ref


@dataclass
class _State:
    since: datetime | None = None
    active: str | None = None  # None | "warn" | "crit"


@dataclass
class Evaluator:
    rules: list[Threshold] = field(default_factory=list)
    state: dict[tuple[int, str, str], _State] = field(default_factory=dict)

    def load(self) -> None:
        """(Re)load enabled rules and seed open state from open threshold alerts."""
        with session_scope() as s:
            self.rules = list(s.scalars(select(Threshold).where(Threshold.enabled.is_(True))))
            for a in s.scalars(select(Alert).where(Alert.state == "open", Alert.rule_id.like("threshold.%"))):
                parts = a.dedup_key.split("|", 2)
                if len(parts) == 3 and a.node_id is not None:
                    st = self.state.setdefault((a.node_id, parts[1].removeprefix("threshold."), parts[2]), _State())
                    st.active = st.active or ("crit" if a.severity in ("high", "critical") else "warn")

    def evaluate(self, node_id: int, node_name: str, metric: str, instance: str, value: float | None,
                 now: datetime, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Return poll events (open/clear) for one sample."""
        if value is None:
            return []
        events: list[dict[str, Any]] = []
        for r in self.rules:
            if r.metric != metric or not fnmatch.fnmatch(instance or "", r.instance_glob or "*"):
                continue
            key = (node_id, r.rule_id, instance or "")
            st = self.state.setdefault(key, _State())
            level = "crit" if _breach(r.op, value, r.crit_value) else ("warn" if _breach(r.op, value, r.warn_value) else None)
            if metric == "cert_days_left" and value < 0:
                level = "expired"
            if level:
                st.since = st.since or now
                sustained = (now - st.since).total_seconds() >= (r.sustain_s or 0)
                rank = {"warn": 1, "crit": 2, "expired": 3}
                if sustained and rank[level] > rank.get(st.active or "", 0):
                    st.active = level
                    sev = "critical" if level == "expired" else (r.severity_crit if level == "crit" else r.severity_warn)
                    thr = r.crit_value if level == "crit" else r.warn_value
                    events.append(self._event(node_id, node_name, r, instance, value, thr, level, sev, False, now, context))
            else:
                st.since = None
                if st.active and _cleared(r.op, value, r.clear_value, r.warn_value):
                    events.append(self._event(node_id, node_name, r, instance, value, r.clear_value, "clear", "info", True, now, context))
                    st.active = None
        return events

    @staticmethod
    def _event(node_id: int, node_name: str, r: Threshold, instance: str, value: float, thr: float | None, level: str,
               sev: str, is_clear: bool, now: datetime, context: dict[str, Any] | None) -> dict[str, Any]:
        unit = UNITS.get(r.metric, "")
        label = LABELS.get(r.rule_id, r.metric)
        what = f"{label}{' ' + instance if instance else ''}"
        if level == "expired" or (not is_clear and r.metric.endswith("days_left") and value < 0):
            title = f"[CPPM][{sev.upper()}] {what} EXPIRED on {node_name} ({-value:.0f} days ago)"
        elif is_clear:
            title = f"{what} back to normal on {node_name}: {value:.1f}{unit}"
        else:
            sustain = f", sustained {r.sustain_s // 60} min" if r.sustain_s else ""
            title = f"[CPPM][{sev.upper()}] {what} {value:.1f}{unit} on {node_name} (threshold {r.op} {thr:g}{unit}{sustain})"
        return {
            "ts": now, "node_id": node_id, "source": "poll", "event_type": f"threshold.{r.rule_id}", "severity": sev,
            "is_clear": is_clear, "dedup_instance": (instance or "")[:128], "processed": 0,
            "attributes": {"metric": r.metric, "value": round(value, 2), "threshold": thr, "op": r.op, "level": level,
                           "rule_id": r.rule_id, "title": title, "unit": unit, **(context or {})},
        }
