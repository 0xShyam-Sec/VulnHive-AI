"""Producer abstraction. Every source of findings — vuln agents, discovery
modules, importers, the browser crawler — wraps as a FindingProducer.

The runner orchestrates producers; everything downstream (dedup, persistence,
SSE) sees the same Finding shape regardless of source.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator, Optional

from engine.errors import ScanError
from engine.finding_model import Finding


@dataclass
class ScanContext:
    """Carries everything a producer needs to do its job + emit telemetry."""

    scan_id: int
    target: str
    db_path: Optional[Path]
    auth_config: dict = field(default_factory=dict)
    llm_backend: str = "ollama"
    redis_client: object = None
    errors: list[ScanError] = field(default_factory=list)
    progress_snapshot: dict = field(default_factory=dict)

    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def cancel(self) -> None:
        self._cancel.set()

    def record_error(self, err: ScanError) -> None:
        self.errors.append(err)
        if self.db_path is not None:
            try:
                from dashboard.repository import save_scan_error
                save_scan_error(self.db_path, err)
            except Exception as e:
                # Observability must never crash the scan.
                import sys
                print(f"[scan_error_persist_failed] {e}", file=sys.stderr)

    def progress(self, producer: str, current: int, total: int,
                 last: str = "", finished: bool = False) -> None:
        snap = {
            "producer": producer,
            "current": current,
            "total": total,
            "last": last,
            "finished": finished,
        }
        self.progress_snapshot[producer] = snap
        if self.redis_client is not None:
            try:
                import json
                self.redis_client.publish(
                    f"scan:{self.scan_id}:progress",
                    json.dumps(snap),
                )
            except Exception as e:
                import sys
                print(f"[progress_publish_failed] {e}", file=sys.stderr)


class FindingProducer(ABC):
    """Abstract base for everything that yields findings."""

    name: str = "abstract"
    phase: str = "attack"

    @abstractmethod
    async def produce(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        """Yield Finding objects as they're discovered. Async generator."""
        if False:
            yield
