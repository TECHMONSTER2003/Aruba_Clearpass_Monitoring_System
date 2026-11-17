"""Trap catalog import: YAML/CSV → validated rows → diff preview → upsert (DESIGN §6.4).

Rules (CLAUDE.md §6): upsert by OID, never delete entries the import does not
mention (they are reported as ``untouched``), seed imports never overwrite.
"""
from __future__ import annotations

import csv
import io
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from cppmmon.db.models import SEVERITIES, TrapCatalog, VarbindCatalog

log = logging.getLogger(__name__)

OID_RE = re.compile(r"^\d+(\.\d+)+$")
FIELDS = (
    "name", "category", "alarm_type", "severity", "create_ticket", "clear_oid", "clear_match_field",
    "dedup_field", "title_tpl", "description_tpl", "recommended_action", "source_ref",
)
_TRUE = {"1", "true", "yes", "y", "on"}


class CatalogError(ValueError):
    """The uploaded catalog cannot be parsed at all."""


@dataclass
class ParsedCatalog:
    traps: dict[str, dict[str, Any]] = field(default_factory=dict)  # oid → fields
    varbinds: dict[str, str] = field(default_factory=dict)  # oid prefix → name
    errors: list[str] = field(default_factory=list)  # per-row problems (row skipped)


@dataclass
class CatalogDiff:
    added: list[dict[str, Any]] = field(default_factory=list)
    changed: list[dict[str, Any]] = field(default_factory=list)  # {"oid", "name", "fields": {f: (old, new)}}
    unchanged: list[str] = field(default_factory=list)
    untouched: list[dict[str, str]] = field(default_factory=list)  # in DB, not in upload (kept)
    vb_added: list[str] = field(default_factory=list)
    vb_changed: list[str] = field(default_factory=list)


def _norm_oid(oid: Any) -> str:
    return str(oid or "").strip().lstrip(".")


def _norm_clear(v: Any) -> str | None:
    if v is None or v == "":
        return None
    items = v if isinstance(v, list) else re.split(r"[,\s;]+", str(v))
    out = [_norm_oid(x) for x in items if _norm_oid(x)]
    return ",".join(out) or None


def _row(raw: dict[str, Any], where: str, errors: list[str]) -> tuple[str, dict[str, Any]] | None:
    oid = _norm_oid(raw.get("oid"))
    if not OID_RE.match(oid):
        errors.append(f"{where}: invalid OID {raw.get('oid')!r}")
        return None
    name = str(raw.get("name") or "").strip()
    if not name:
        errors.append(f"{where}: OID {oid} has no name")
        return None
    sev = str(raw.get("severity") or "info").strip().lower()
    if sev not in SEVERITIES:
        errors.append(f"{where}: OID {oid} severity {sev!r} not in {SEVERITIES}")
        return None
    ct = raw.get("create_ticket")
    clear = _norm_clear(raw.get("clear_oid"))
    if clear and not all(OID_RE.match(c) for c in clear.split(",")):
        errors.append(f"{where}: OID {oid} has an invalid clear_oid")
        return None
    out: dict[str, Any] = {
        "name": name[:128],
        "category": (str(raw["category"]).strip() or None) if raw.get("category") else None,
        "alarm_type": (str(raw["alarm_type"]).strip() or None) if raw.get("alarm_type") else None,
        "severity": sev,
        "create_ticket": ct if isinstance(ct, bool) else str(ct or "").strip().lower() in _TRUE,
        "clear_oid": clear,
        "clear_match_field": (str(raw.get("clear_match_field") or "").strip() or None),
        "dedup_field": (str(raw.get("dedup_field") or "").strip() or None),
        "title_tpl": raw.get("title_tpl") or None,
        "description_tpl": raw.get("description_tpl") or None,
        "recommended_action": raw.get("recommended_action") or None,
        "source_ref": (str(raw.get("source_ref") or "").strip() or None),
    }
    # Only fields the source actually carries are compared/updated on existing OIDs,
    # so a CSV with a few columns never blanks the others.
    out["_present"] = sorted(f for f in FIELDS if f in raw)
    return oid, out


def _present(new: dict[str, Any]) -> list[str]:
    return list(new.get("_present") or FIELDS)


def _row_values(new: dict[str, Any]) -> dict[str, Any]:
    return {f: new[f] for f in FIELDS}


def parse(content: bytes, filename: str) -> ParsedCatalog:
    """Parse YAML (seed format: ``varbinds`` map + ``traps`` list) or CSV (DESIGN §6.4 columns)."""
    pc = ParsedCatalog()
    text = content.decode("utf-8-sig", errors="replace")
    lower = filename.lower()
    if lower.endswith((".yaml", ".yml")):
        try:
            doc = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise CatalogError(f"YAML parse error: {exc}") from exc
        if not isinstance(doc, dict):
            raise CatalogError("YAML root must be a mapping with 'traps' (and optional 'varbinds')")
        for prefix, name in (doc.get("varbinds") or {}).items():
            p = _norm_oid(prefix)
            if OID_RE.match(p) and name:
                pc.varbinds[p] = str(name)
            else:
                pc.errors.append(f"varbinds: invalid entry {prefix!r}")
        for i, raw in enumerate(doc.get("traps") or [], 1):
            if not isinstance(raw, dict):
                pc.errors.append(f"traps[{i}]: not a mapping")
                continue
            r = _row(raw, f"traps[{i}]", pc.errors)
            if r:
                pc.traps[r[0]] = r[1]
    elif lower.endswith(".csv"):
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames or "oid" not in [f.strip().lower() for f in reader.fieldnames]:
            raise CatalogError("CSV needs a header row with at least 'oid' and 'name'")
        for i, raw in enumerate(reader, 2):
            norm = {(k or "").strip().lower(): (v.strip() if isinstance(v, str) else v) for k, v in raw.items()}
            if norm.get("kind") == "varbind":
                p = _norm_oid(norm.get("oid"))
                if OID_RE.match(p) and norm.get("name"):
                    pc.varbinds[p] = norm["name"]
                continue
            r = _row(norm, f"line {i}", pc.errors)
            if r:
                pc.traps[r[0]] = r[1]
    else:
        raise CatalogError("Unsupported file type: use .yaml/.yml or .csv")
    if not pc.traps and not pc.varbinds:
        raise CatalogError("No valid trap or varbind entries found")
    return pc


def diff(session: Session, pc: ParsedCatalog) -> CatalogDiff:
    """Compare a parsed upload with the DB (read-only)."""
    d = CatalogDiff()
    current = {t.oid: t for t in session.scalars(select(TrapCatalog))}
    for oid, new in sorted(pc.traps.items()):
        cur = current.get(oid)
        if cur is None:
            d.added.append({"oid": oid, **_row_values(new)})
            continue
        changes = {f: (getattr(cur, f), new[f]) for f in _present(new) if (getattr(cur, f) or None) != (new[f] or None)}
        if changes:
            d.changed.append({"oid": oid, "name": new["name"], "fields": changes})
        else:
            d.unchanged.append(oid)
    d.untouched = [{"oid": o, "name": t.name} for o, t in sorted(current.items()) if o not in pc.traps]
    vbs = {v.oid_prefix: v.name for v in session.scalars(select(VarbindCatalog))}
    for p, n in pc.varbinds.items():
        if p not in vbs:
            d.vb_added.append(p)
        elif vbs[p] != n:
            d.vb_changed.append(p)
    return d


def apply(session: Session, pc: ParsedCatalog, seed: bool = False) -> dict[str, int]:
    """Upsert. ``seed=True`` only inserts OIDs not already present (never overwrites)."""
    counts = {"added": 0, "updated": 0, "skipped": 0, "vb_added": 0, "vb_updated": 0}
    current = {t.oid: t for t in session.scalars(select(TrapCatalog))}
    for oid, new in pc.traps.items():
        cur = current.get(oid)
        if cur is None:
            session.add(TrapCatalog(oid=oid, **_row_values(new)))
            counts["added"] += 1
        elif seed:
            counts["skipped"] += 1
        else:
            changed = False
            for f in _present(new):
                if (getattr(cur, f) or None) != (new[f] or None):
                    setattr(cur, f, new[f])
                    changed = True
            counts["updated" if changed else "skipped"] += 1
    vbs = {v.oid_prefix: v for v in session.scalars(select(VarbindCatalog))}
    for p, n in pc.varbinds.items():
        if p not in vbs:
            session.add(VarbindCatalog(oid_prefix=p, name=n))
            counts["vb_added"] += 1
        elif not seed and vbs[p].name != n:
            vbs[p].name = n
            counts["vb_updated"] += 1
    log.info("catalog applied", extra={"seed": seed, **counts})
    return counts
