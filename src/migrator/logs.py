"""Structured JSON logging.  Secrets are redacted; full paths are allowed."""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone

_SECRET_ENV_HINTS = ("API_KEY", "DATABASE_URL", "DSN", "PASSWORD", "TOKEN")
_DSN_PASSWORD = re.compile(r"(postgres(?:ql)?://[^:/@\s]+:)([^@\s]+)(@)")


def _secret_values() -> list[str]:
    vals = []
    for k, v in os.environ.items():
        if v and len(v) >= 6 and any(h in k.upper() for h in _SECRET_ENV_HINTS):
            vals.append(v)
    return sorted(vals, key=len, reverse=True)


def redact(text: str) -> str:
    text = _DSN_PASSWORD.sub(r"\1***\3", text)
    for v in _secret_values():
        text = text.replace(v, "***")
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "run_id": getattr(record, "run_id", None),
            "trace_id": getattr(record, "trace_id", None),
            "operation_id": getattr(record, "operation_id", None),
            "component": record.name.removeprefix("migrator."),
            "message": redact(record.getMessage()),
        }
        if record.exc_info:
            entry["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps({k: v for k, v in entry.items() if v is not None}, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger("migrator")
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())
    root.propagate = False


class _Adapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):  # merge per-call extras with bound context
        extra = dict(self.extra or {})
        extra.update(kwargs.get("extra") or {})
        kwargs["extra"] = extra
        return msg, kwargs


def get_logger(component: str, **context) -> logging.LoggerAdapter:
    return _Adapter(logging.getLogger(f"migrator.{component}"),
                    {k: str(v) for k, v in context.items() if v is not None})
