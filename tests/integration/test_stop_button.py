import asyncio
from pathlib import Path

import pytest

from engine.finding_model import Confidence, Finding, Severity
from engine.producer import FindingProducer


class _LongProducer(FindingProducer):
    """Yields 20 findings, sleeping 0.1s between each. Honors ctx.cancelled."""

    name = "long"
    phase = "attack"

    async def produce(self, ctx):
        for i in range(20):
            if ctx.cancelled:
                return
            await asyncio.sleep(0.1)
            yield Finding(
                scan_id=ctx.scan_id, rule_id="long", vuln_type="x",
                title=f"finding-{i}", severity=Severity.low,
                confidence=Confidence.medium,
            )


@pytest.mark.asyncio
async def test_cancel_via_on_ctx_callback_stops_producer(tmp_path: Path):
    """Caller can capture the live ScanContext via on_ctx, then cancel it."""
    import sqlite3
    db = tmp_path / "t.db"
    sqlite3.connect(db).executescript(
        "CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT);"
        "INSERT INTO scans (id, target) VALUES (1, 'x');"
    )
    from dashboard.migrations.runner import run_migration_001_up
    run_migration_001_up(db)

    from engine.runner import run_scan
    ctx_holder = {}

    # Schedule a cancel after ~0.25s (≈ 2-3 iterations).
    async def cancel_soon():
        await asyncio.sleep(0.25)
        ctx = ctx_holder.get("ctx")
        if ctx is not None:
            ctx.cancel()

    canceller = asyncio.create_task(cancel_soon())
    result = await run_scan(
        scan_id=1, target="x",
        producers=[_LongProducer()],
        db_path=db,
        on_ctx=lambda c: ctx_holder.__setitem__("ctx", c),
    )
    await canceller

    # Producer was cancelled, so it yielded fewer than the 20 max
    assert len(result["findings"]) < 10, f"expected <10 findings after cancel, got {len(result['findings'])}"


@pytest.mark.asyncio
async def test_run_scan_accepts_on_ctx_callback():
    """on_ctx must be called with the ScanContext before producers start."""
    from engine.runner import run_scan

    captured = []

    class _NullProducer(FindingProducer):
        name = "null"
        phase = "recon"
        async def produce(self, ctx):
            if False:
                yield

    await run_scan(
        scan_id=99, target="x",
        producers=[_NullProducer()],
        db_path=None,
        on_ctx=lambda c: captured.append(c.scan_id),
    )
    assert captured == [99]
