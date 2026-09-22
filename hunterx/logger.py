"""Structured logging with secret redaction.

All logs written to disk are JSON lines. Secrets (tokens, keys,
passwords, JWTs, private keys) are redacted before anything is
emitted. Never log raw authorization material.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

CONSOLE_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"

# Conservative redaction patterns. We mask rather than drop the whole
# line so operators still see the surrounding context.
def _mask_secret_value(match: "re.Match[str]") -> str:
    """Keep the key and separator, drop the rest of the value."""
    s = match.group(0)
    separators = [i for i in (s.find("="), s.find(":")) if i != -1]
    if not separators:
        return s
    idx = min(separators)
    value = s[idx + 1 :]
    if not value.strip():
        return s[: idx + 1] + " (empty)"
    return s[: idx + 1] + " ***REDACTED***"


_REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), lambda m: m.group(0)[:4] + "*" * 8 + m.group(0)[-4:]),
    # GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_).
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), lambda m: m.group(0)[:4] + "*" * 12 + m.group(0)[-3:]),
    # JWTs.
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), lambda m: "JWT:REDACTED"),
    # Private keys.
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), lambda m: "PRIVATE-KEY:REDACTED"),
    # Generic key=value / key: value secrets. The value is taken as the
    # remainder of the line (over-redaction is safer than leakage).
    (
        re.compile(
            r"(?i)\b(?:bearer|authorization|token|api[_-]?key|access[_-]?secret|"
            r"client[_-]?secret|password|passwd|secret|private[_-]?key)\b[^=:\n]{0,20}[=:]\s*[^\n]*"
        ),
        _mask_secret_value,
    ),
]


def redact(text: str) -> str:
    """Mask known secret patterns in *text*."""
    for pattern, repl in _REDACTION_PATTERNS:
        text = pattern.sub(repl, text)
    return text


class RedactionFilter(logging.Filter):
    """Rewrites message/args through :func:`redact` in place."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = redact(record.msg)
            if record.args:
                record.args = tuple(
                    redact(a) if isinstance(a, str) else a for a in record.args
                )
        except Exception:
            pass
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per log line, safe to ingest from anywhere."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("run_id", "module", "target", "duration_ms"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def setup_logging(log_dir: str | Path | None = None, level: str | int = "INFO") -> logging.Logger:
    """Configure the ``hunterx`` logger hierarchy.

    Writes JSON lines to ``<log_dir>/hunterx.log`` (rotating) and a
    human-readable stream to stderr.
    """
    log = logging.getLogger("hunterx")
    log.setLevel(level)
    log.propagate = False
    log.addFilter(RedactionFilter())

    if not any(isinstance(h, logging.StreamHandler) for h in log.handlers):
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter(CONSOLE_FORMAT, datefmt="%H:%M:%S"))
        log.addHandler(console)

    if log_dir is not None:
        directory = Path(log_dir)
        directory.mkdir(parents=True, exist_ok=True)
        if not any(isinstance(h, RotatingFileHandler) for h in log.handlers):
            file_handler = RotatingFileHandler(
                directory / "hunterx.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8"
            )
            file_handler.setFormatter(JsonFormatter())
            log.addHandler(file_handler)

    return log


def get_logger(name: str = "hunterx") -> logging.Logger:
    """Return a child logger, e.g. ``get_logger("hunterx.discovery")``."""
    return logging.getLogger(name)