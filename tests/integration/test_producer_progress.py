import json

import pytest


class _FakeRedis:
    def __init__(self):
        self.published = []
    def publish(self, channel, payload):
        self.published.append((channel, payload))


@pytest.mark.asyncio
async def test_nuclei_producer_emits_progress_per_line(tmp_path):
    """The Nuclei producer must call ctx.progress(...) as it walks the JSONL."""
    from engine.producer import ScanContext
    from engine.producers.nuclei import NucleiProducer

    # Build a sample JSONL with 3 entries.
    sample = tmp_path / "n.jsonl"
    sample.write_text("\n".join([
        json.dumps({"template-id": f"rule-{i}",
                    "info": {"name": f"r{i}", "severity": "low"},
                    "matched-at": f"http://x/{i}"})
        for i in range(3)
    ]))

    r = _FakeRedis()
    ctx = ScanContext(scan_id=99, target="http://x", db_path=None, redis_client=r)
    producer = NucleiProducer(jsonl_path=sample)
    findings = [f async for f in producer.produce(ctx)]
    assert len(findings) == 3

    # ctx.progress(...) for nuclei should have produced at least one event on the
    # scan:99:progress channel (start + completion at minimum).
    progress_events = [p for c, p in r.published if c == "scan:99:progress"]
    assert progress_events, "NucleiProducer did not emit any progress events"
    # The producer must have emitted at LEAST one event whose producer field is "nuclei".
    decoded = [json.loads(p) for p in progress_events]
    assert any(d["producer"] == "nuclei" for d in decoded)


@pytest.mark.asyncio
async def test_vuln_agent_producer_emits_progress(monkeypatch, tmp_path):
    """VulnAgentProducer must emit ctx.progress events."""
    import json
    from engine.producer import ScanContext
    from engine.producers.vuln_agent import VulnAgentProducer

    class _StubAgent:
        vuln_type = "sqli"
        agent_name = "sqli_agent"
        def __init__(self, llm_backend="ollama"): pass
        def run(self, _msg):
            return [
                {"vuln_type": "sqli", "url": "http://x/q", "method": "GET",
                 "param_name": "id", "payload": "1'", "evidence": "MySQL err",
                 "severity": "high", "validated": 1, "source": "sqli_agent"},
                {"vuln_type": "sqli", "url": "http://x/r", "method": "GET",
                 "param_name": "id", "payload": "2'", "evidence": "Pg err",
                 "severity": "high", "validated": 1, "source": "sqli_agent"},
            ]

    r = _FakeRedis()
    ctx = ScanContext(scan_id=7, target="http://x", db_path=None, redis_client=r)
    p = VulnAgentProducer(_StubAgent, vuln_type="sqli", agent_name="sqli_agent")
    findings = [f async for f in p.produce(ctx)]
    assert len(findings) == 2

    progress_events = [json.loads(p) for c, p in r.published
                       if c == "scan:7:progress"]
    assert progress_events, "VulnAgentProducer did not emit progress"
    # At least one event marked finished=True
    assert any(e.get("finished") for e in progress_events)
