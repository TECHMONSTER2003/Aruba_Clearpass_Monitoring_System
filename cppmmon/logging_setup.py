"""Structured JSON logging to /var/log/cppmmon/<service>.log plus stderr (journald)."""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

_RESERVED = set(vars(logging.makeLogRecord({})).keys()) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """Render a record as one JSON object; ``extra={...}`` fields are merged in."""

    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "service": self.service,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging(service: str, log_dir: Path | None = None, level: str = "INFO") -> logging.Logger:
    """Configure root logging for ``service`` and return its logger.

    The file handler is skipped (with a warning on stderr) if the directory is
    not writable, so tests and ad-hoc CLI runs still work.
    """
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)
    fmt = JsonFormatter(service)

    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(fmt)
    root.addHandler(stream)

    if log_dir is not None:
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            fh = TimedRotatingFileHandler(log_dir / f"{service}.log", when="midnight", backupCount=14, utc=True)
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError as exc:
            root.warning("file logging disabled", extra={"log_dir": str(log_dir), "error": str(exc)})

    # httpx logs every request at INFO; keep only its warnings.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    return logging.getLogger(f"cppmmon.{service}")
