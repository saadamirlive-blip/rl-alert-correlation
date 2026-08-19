"""
Log4j-style structured logging for the collector pipeline.

This is deliberately modeled on the parts of Log4j/Log4j2 that make
operational logs useful in a multi-threaded pipeline like the log
collector's:

  * named, hierarchical loggers per component  (collector.suricata,
    collector.apache_access, collector.writer, ...)  -- like Log4j Loggers
  * two appenders per logger tree:
      - a console appender using a PatternLayout-style line
        (timestamp [thread] LEVEL logger - message)
      - a rotating file appender (Log4j RollingFileAppender equivalent)
        that always writes structured JSON, one record per line, so the
        operational log itself can be grepped/loaded with pandas later
  * an MDC (Mapped Diagnostic Context) equivalent: `log_context(...)` binds
    key/value pairs (e.g. run_id) to every log record emitted from the
    current thread/task for the duration of a `with` block, the same way
    Log4j's ThreadContext/MDC lets you tag a whole request's log lines
    without threading the value through every call site.

This module only covers the pipeline's own operational logs (startup,
parse errors, throughput, exceptions) -- the alert *data* itself still goes
through collector/schema.py into SQLite, not through this logger.
"""
from __future__ import annotations

import contextvars
import json
import logging
import logging.handlers
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# --- MDC (Mapped Diagnostic Context) ---------------------------------------
_context: "contextvars.ContextVar[dict]" = contextvars.ContextVar("log_context", default={})


def set_context(**kwargs) -> contextvars.Token:
    ctx = dict(_context.get())
    ctx.update(kwargs)
    return _context.set(ctx)


def clear_context(token: Optional[contextvars.Token] = None) -> None:
    if token is not None:
        _context.reset(token)
    else:
        _context.set({})


@contextmanager
def log_context(**kwargs):
    """MDC-style scoped context, e.g.:

        with log_context(run_id=run_id):
            logger.info("stage started")   # every record in this block
                                            # carries {"context": {"run_id": ...}}
    """
    token = set_context(**kwargs)
    try:
        yield
    finally:
        clear_context(token)


class _ContextFilter(logging.Filter):
    """Injects the current MDC into every LogRecord as `record.mdc`."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.mdc = _context.get()
        return True


# --- Formatters (Log4j "Layouts") -------------------------------------------
_RESERVED_ATTRS = set(vars(logging.makeLogRecord({})).keys()) | {"message", "asctime", "mdc"}


def _iso_ts(record: logging.LogRecord) -> str:
    return (
        datetime.fromtimestamp(record.created, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _extra_fields(record: logging.LogRecord) -> dict:
    return {k: v for k, v in record.__dict__.items() if k not in _RESERVED_ATTRS and not k.startswith("_")}


class JsonLayout(logging.Formatter):
    """Log4j2 JsonTemplateLayout equivalent: one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": _iso_ts(record),
            "level": record.levelname,
            "logger": record.name,
            "thread": record.threadName,
            "message": record.getMessage(),
        }
        mdc = getattr(record, "mdc", None)
        if mdc:
            payload["context"] = mdc
        extras = _extra_fields(record)
        if extras:
            payload["data"] = extras
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class PatternLayout(logging.Formatter):
    """Log4j PatternLayout equivalent for interactive console use:

        2026-08-18T12:34:56.789Z [tail-suricata] INFO  collector.suricata - alert ingested {'run_id': 'a1b2c3'}
    """

    def format(self, record: logging.LogRecord) -> str:
        line = (
            f"{_iso_ts(record)} [{record.threadName}] {record.levelname:<5s} "
            f"{record.name} - {record.getMessage()}"
        )
        extras = _extra_fields(record)
        if extras:
            line += f" {extras}"
        mdc = getattr(record, "mdc", None)
        if mdc:
            line += f" {mdc}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


# --- Configuration entry point ----------------------------------------------
def configure_logging(
    component: str,
    log_file: Path,
    level: int = logging.INFO,
    console_json: bool = False,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
) -> logging.Logger:
    """Configure the root logger with a console appender (human-readable by
    default) and a rotating JSON file appender, then return a logger for
    `component`. Safe to call once at process startup (e.g. in each
    script's `main()`).
    """
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    context_filter = _ContextFilter()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(JsonLayout() if console_json else PatternLayout())
    console_handler.addFilter(context_filter)
    root.addHandler(console_handler)

    log_file.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count
    )
    file_handler.setFormatter(JsonLayout())
    file_handler.addFilter(context_filter)
    root.addHandler(file_handler)

    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return logging.getLogger(component)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
