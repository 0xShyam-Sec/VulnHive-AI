"""Error taxonomy for the scan pipeline.

Three classes of failure:
- Fatal:           scan cannot continue (Ollama unreachable, DB write fails)
- ProducerFatal:   one producer failed; others continue
- Soft (logged via ctx.record_error, no exception class needed)
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field, asdict
from typing import Optional


class FatalError(Exception):
    """Scan cannot continue. Propagates up; runner stops."""


class ProducerFatalError(Exception):
    """One producer failed. Caught by safe_run; scan continues."""

    def __init__(self, producer: str, message: str):
        super().__init__(f"{producer}: {message}")
        self.producer = producer


@dataclass
class ScanError:
    scan_id: int
    producer: str
    phase: str
    kind: str                                  # producer_fatal | target_soft | recoverable | fatal
    error: str
    traceback: Optional[str] = None
    affected_target: Optional[str] = None
    created_at: str = field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)
