import json

import pytest

from engine.errors import ScanError


class _FakeRedis:
    def __init__(self):
        self.published = []

    def publish(self, c, p):
        self.published.append((c, p))


@pytest.mark.asyncio
async def test_record_error_also_publishes_to_redis():
    from engine.producer import ScanContext

    r = _FakeRedis()
    ctx = ScanContext(scan_id=5, target="x", db_path=None, redis_client=r)
    ctx.record_error(ScanError(
        scan_id=5, producer="nuclei", phase="discovery",
        kind="producer_fatal", error="binary missing"))
    channels = [c for c, _ in r.published]
    assert "scan:5:errors" in channels
    _, payload = next((c, p) for c, p in r.published if c == "scan:5:errors")
    record = json.loads(payload)
    assert record["producer"] == "nuclei"
    assert record["kind"] == "producer_fatal"
