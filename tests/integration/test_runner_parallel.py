import asyncio
import time
from pathlib import Path

import pytest

from engine.finding_model import Confidence, Finding, Severity
from engine.producer import FindingProducer
from engine.runner import run_scan


class _SlowProducer(FindingProducer):
    """Sleeps 1s, then yields one finding. If 3 of these run concurrently,
    elapsed must be < 2s — otherwise we're still sequential."""

    def __init__(self, name: str):
        self.name = name
        self.phase = "attack"

    async def produce(self, ctx):
        await asyncio.sleep(1.0)
        yield Finding(
            scan_id=ctx.scan_id, rule_id=f"{self.name}-rule", vuln_type="x",
            title=self.name, severity=Severity.low, confidence=Confidence.medium,
        )


@pytest.mark.asyncio
async def test_three_producers_run_concurrently(tmp_path: Path):
    db = tmp_path / "t.db"
    import sqlite3
    sqlite3.connect(db).executescript(
        "CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT);"
        "INSERT INTO scans (id, target) VALUES (1, 'x');"
    )
    from dashboard.migrations.runner import run_migration_001_up
    run_migration_001_up(db)

    producers = [_SlowProducer(f"p{i}") for i in range(3)]

    start = time.monotonic()
    result = await run_scan(scan_id=1, target="x", producers=producers, db_path=db)
    elapsed = time.monotonic() - start

    assert elapsed < 2.0, f"expected concurrent execution (<2s), got {elapsed:.2f}s"
    assert len(result["findings"]) == 3
