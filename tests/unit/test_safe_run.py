import pytest

from engine.errors import FatalError
from engine.finding_model import Confidence, Finding, Severity
from engine.producer import FindingProducer, ScanContext
from engine.safe_run import safe_produce


class _GoodProducer(FindingProducer):
    name = "good"
    phase = "attack"

    async def produce(self, ctx):
        yield Finding(
            scan_id=ctx.scan_id, rule_id="g-rule", vuln_type="x",
            title="X", severity=Severity.low, confidence=Confidence.medium,
        )


class _CrashingProducer(FindingProducer):
    name = "crash"
    phase = "attack"

    async def produce(self, ctx):
        raise RuntimeError("boom")
        yield                                        # pragma: no cover


class _FatalProducer(FindingProducer):
    name = "fatal"
    phase = "attack"

    async def produce(self, ctx):
        raise FatalError("ollama down")
        yield                                        # pragma: no cover


@pytest.mark.asyncio
async def test_good_producer_yields_normally():
    ctx = ScanContext(scan_id=1, target="x", db_path=None)
    findings = [f async for f in safe_produce(_GoodProducer(), ctx)]
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_crashing_producer_records_scan_error_and_continues():
    ctx = ScanContext(scan_id=1, target="x", db_path=None)
    findings = [f async for f in safe_produce(_CrashingProducer(), ctx)]
    assert findings == []
    assert len(ctx.errors) == 1
    assert ctx.errors[0].producer == "crash"
    assert ctx.errors[0].kind == "producer_fatal"
    assert "boom" in ctx.errors[0].error


@pytest.mark.asyncio
async def test_fatal_error_propagates():
    ctx = ScanContext(scan_id=1, target="x", db_path=None)
    with pytest.raises(FatalError):
        async for _ in safe_produce(_FatalProducer(), ctx):
            pass
