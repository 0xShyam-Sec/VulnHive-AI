import json

import pytest


class _FakeRedis:
    def __init__(self):
        self.published = []

    def publish(self, channel, payload):
        self.published.append((channel, payload))


@pytest.mark.asyncio
async def test_ctx_progress_publishes_event():
    from engine.producer import ScanContext
    r = _FakeRedis()
    ctx = ScanContext(scan_id=42, target="x", db_path=None, redis_client=r)
    ctx.progress("sqli_agent", 3, 10, last="probing /search")
    assert any(c == "scan:42:progress" for c, _ in r.published)
    _, payload = r.published[-1]
    snap = json.loads(payload)
    assert snap["producer"] == "sqli_agent"
    assert snap["current"] == 3
    assert snap["total"] == 10


@pytest.mark.asyncio
async def test_heartbeat_event_fires_every_n_ticks():
    """The runner schedules a heartbeat task that publishes periodically."""
    from engine.runner import _emit_heartbeat
    r = _FakeRedis()
    await _emit_heartbeat(scan_id=7, redis_client=r, every=0.05, total_ticks=3)
    channels = [c for c, _ in r.published]
    assert channels.count("scan:7:heartbeat") == 3
