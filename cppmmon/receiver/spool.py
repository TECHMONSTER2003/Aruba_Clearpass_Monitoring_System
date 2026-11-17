"""JSONL spool used while the DB is unavailable; replayed in order once it is back."""
from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cppmmon.receiver.persist import to_json_line

log = logging.getLogger(__name__)


class Spool:
    """Append-only JSONL files under ``directory``, rotated at ``max_bytes``."""

    def __init__(self, directory: Path, max_bytes: int = 100 * 1024 * 1024) -> None:
        self.dir = directory
        self.max = max_bytes
        self._current: Path | None = None
        self._lock = threading.Lock()  # append and replay run in different worker threads
        self.dir.mkdir(parents=True, exist_ok=True)

    def _target(self) -> Path:
        if self._current is None or not self._current.exists() or self._current.stat().st_size >= self.max:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
            self._current = self.dir / f"spool-{stamp}-{os.getpid()}.jsonl"
        return self._current

    def append(self, records: list[dict[str, Any]]) -> None:
        """Append records and fsync (blocking; call from a worker thread)."""
        with self._lock:
            path = self._target()
            with path.open("a", encoding="utf-8") as fh:
                for r in records:
                    fh.write(to_json_line(r) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    def files(self) -> list[Path]:
        """Spool files, oldest first."""
        return sorted(self.dir.glob("spool-*.jsonl"))

    def backlog(self) -> tuple[int, int]:
        """(file count, total bytes) for the Health page."""
        fs = self.files()
        return len(fs), sum(f.stat().st_size for f in fs)

    def replay(self, persist: Callable[[list[dict[str, Any]]], Any], batch: int = 500) -> int:
        """Replay every spool file in order. Stops (raising) at the first DB failure.

        Each file is deleted only after all of its records were persisted; a
        partial failure re-plays that file later, which is safe because inserts
        are idempotent by dedup_hash.
        """
        total = 0
        for path in self.files():
            with self._lock:
                if path == self._current:
                    self._current = None  # anything spooled from now on goes to a new file
            records: list[dict[str, Any]] = []
            bad = 0
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        bad += 1
            if bad:
                log.error("spool lines unreadable, skipped", extra={"file": path.name, "lines": bad})
            for i in range(0, len(records), batch):
                persist(records[i:i + batch])
            path.unlink()
            total += len(records)
            log.info("spool file replayed", extra={"file": path.name, "records": len(records)})
        return total
