from pathlib import Path

import pytest

from engine.producer import ScanContext
from engine.producers.nuclei import NucleiProducer


@pytest.mark.asyncio
async def test_nuclei_producer_parses_jsonl():
    sample = Path(__file__).parent.parent / "fixtures" / "recordings" / "nuclei_sample.jsonl"
    ctx = ScanContext(scan_id=1, target="http://target.test", db_path=None)
    producer = NucleiProducer(jsonl_path=sample)

    findings = [f async for f in producer.produce(ctx)]
    assert len(findings) == 2

    rules = {f.rule_id for f in findings}
    assert "nuclei:CVE-2024-1234" in rules
    assert "nuclei:missing-csp-header" in rules

    rce = next(f for f in findings if f.rule_id == "nuclei:CVE-2024-1234")
    assert rce.cwe == 78
    assert rce.severity.value == "critical"
    assert rce.confidence.value == "high"
    assert "CVE-2024-1234" in rce.references_json.get("cve_ids", [])
