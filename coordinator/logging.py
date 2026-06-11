# shared/logging.py
"""
Structured JSON logging with correlation ID propagation.
Every log entry is a JSON object — machine-parseable, searchable.
"""

import logging
import json
import uuid
import time
import sys
from contextvars import ContextVar
from typing import Optional

# Correlation ID propagated through async context
_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
_event_window_id: ContextVar[str] = ContextVar("event_window_id", default="")


def set_correlation_id(cid: Optional[str] = None) -> str:
    cid = cid or str(uuid.uuid4())[:12]
    _correlation_id.set(cid)
    return cid


def set_event_window_id(wid: str):
    _event_window_id.set(wid)


class StructuredFormatter(logging.Formatter):
    """JSON log formatter with platform-specific fields."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "module": record.name,
            "msg": record.getMessage(),
            "correlation_id": _correlation_id.get(""),
            "event_window": _event_window_id.get(""),
        }
        # Merge extra fields
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            entry.update(record.extra)
        # Include exception info
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry)


class PlatformLogger:
    """Logger wrapper that accepts structured kwargs."""

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)

    def info(self, msg: str, **kwargs):
        self.logger.info(msg, extra={"extra": kwargs})

    def warning(self, msg: str, **kwargs):
        self.logger.warning(msg, extra={"extra": kwargs})

    def error(self, msg: str, **kwargs):
        self.logger.error(msg, extra={"extra": kwargs})

    def critical(self, msg: str, **kwargs):
        self.logger.critical(msg, extra={"extra": kwargs})

    def debug(self, msg: str, **kwargs):
        self.logger.debug(msg, extra={"extra": kwargs})


def get_logger(name: str) -> PlatformLogger:
    return PlatformLogger(name)


def setup_logging(level: str = "INFO"):
    """Call once at startup to configure all logging."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredFormatter())
    logging.root.handlers = [handler]
    logging.root.setLevel(getattr(logging, level.upper(), logging.INFO))
