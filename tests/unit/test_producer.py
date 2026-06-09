import pytest

from engine.errors import ScanError
from engine.finding_model import Confidence, Finding, Severity
from engine.producer import FindingProducer, ScanContext


class _FakeProducer(FindingProducer):
    name = "fake"
    phase = "attack"

    async def produce(self, ctx):
        yield Finding(
            scan_id=ctx.scan_id, rule_id="fake-rule", vuln_type="x",
            title="X", severity=Severity.low, confidence=Confidence.medium,
        )


@pytest.mark.asyncio
async def test_producer_yields_findings():
    ctx = ScanContext(scan_id=1, target="http://x", db_path=None)
    p = _FakeProducer()
    findings = [f async for f in p.produce(ctx)]
    assert len(findings) == 1
    assert findings[0].rule_id == "fake-rule"


def test_ctx_records_errors_and_progress():
    ctx = ScanContext(scan_id=1, target="http://x", db_path=None)
    ctx.record_error(ScanError(
        scan_id=1, producer="p", phase="attack", kind="producer_fatal", error="boom",
    ))
    assert len(ctx.errors) == 1

    ctx.progress(producer="p", current=2, total=10, last="probing /search")
    assert ctx.progress_snapshot["p"]["current"] == 2
    assert ctx.progress_snapshot["p"]["total"] == 10


def test_ctx_cancelled_flag():
    ctx = ScanContext(scan_id=1, target="http://x", db_path=None)
    assert ctx.cancelled is False
    ctx.cancel()
    assert ctx.cancelled is True
