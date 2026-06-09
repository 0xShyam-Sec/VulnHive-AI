"""Structlog configuration with three sinks: rich console, JSONL file, Redis pubsub.

Call configure_logging(...) once per scan; call get_logger() everywhere else.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import structlog
from rich.console import Console

_RICH_CONSOLE = Console(stderr=False)


class _RichRenderer:
    """structlog processor that pretty-prints to a rich Console."""

    LEVEL_STYLES = {
        "debug":    "dim",
        "info":     "cyan",
        "warning":  "yellow",
        "error":    "red",
        "critical": "red bold",
    }

    def __call__(self, _logger, method_name: str, event_dict: dict) -> str:
        level = event_dict.pop("level", method_name)
        event = event_dict.pop("event", "")
        style = self.LEVEL_STYLES.get(level, "white")
        extras = " ".join(f"[dim]{k}=[/dim]{v}" for k, v in event_dict.items() if k not in ("timestamp",))
        _RICH_CONSOLE.print(f"[{style}]{level.upper():<8}[/] {event}  {extras}")
        return ""


class _RedisSink:
    """structlog processor that publishes log records to a Redis channel.

    Channel: scan:<scan_id>:logs   (skipped if scan_id is None).
    """

    def __init__(self, redis_client, scan_id: Optional[int]):
        self._r = redis_client
        self._scan_id = scan_id

    def __call__(self, _logger, _method_name: str, event_dict: dict) -> dict:
        if self._r is not None and self._scan_id is not None:
            try:
                self._r.publish(f"scan:{self._scan_id}:logs", json.dumps(event_dict, default=str))
            except Exception as e:
                _RICH_CONSOLE.print(f"[dim]redis_sink_publish_failed: {e}[/dim]")
        return event_dict


class _FileSink:
    """structlog processor that appends each record as one JSON line."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path

    def __call__(self, _logger, _method_name: str, event_dict: dict) -> dict:
        try:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event_dict, default=str) + "\n")
        except Exception as e:
            _RICH_CONSOLE.print(f"[dim]file_sink_write_failed: {e}[/dim]")
        return event_dict


def configure_logging(scan_id: Optional[int], log_dir: Optional[Path], redis_client=None) -> None:
    """Wire structlog. Idempotent within a process."""
    processors: list = [
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
    ]
    if log_dir is not None:
        log_dir = Path(log_dir)
        sid = scan_id if scan_id is not None else "global"
        processors.append(_FileSink(log_dir / f"scan_{sid}.jsonl"))
    if redis_client is not None:
        processors.append(_RedisSink(redis_client, scan_id))
    processors.append(_RichRenderer())   # final renderer; must be last

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        cache_logger_on_first_use=False,
    )


def get_logger():
    return structlog.get_logger()
