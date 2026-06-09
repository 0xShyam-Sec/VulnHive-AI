import pytest

from engine.producer import ScanContext


@pytest.mark.asyncio
async def test_playwright_emits_auth_required_finding_per_endpoint(monkeypatch):
    """When the underlying crawler discovers endpoints tagged auth_required,
    the producer must yield an 'idor_target' Finding for each."""
    from engine.producers import playwright_crawler as mod
    from engine.scan_state import Endpoint

    async def _fake_run(ctx, _state, _cfg):
        # Simulate the wrapped crawler populating endpoints — use the real
        # Endpoint shape from engine.scan_state (auth_required is a bool field).
        return [
            Endpoint(url="http://x/api/users/1", method="GET", auth_required=True),
            Endpoint(url="http://x/api/orders/42", method="GET", auth_required=True),
            Endpoint(url="http://x/", method="GET", auth_required=False),
        ]

    monkeypatch.setattr(mod, "_run_underlying_crawler", _fake_run)

    ctx = ScanContext(scan_id=1, target="http://x", db_path=None)
    findings = [f async for f in mod.PlaywrightProducer().produce(ctx)]

    assert len(findings) == 2
    assert all(f.vuln_type == "idor_target" for f in findings)
    urls = {f.references_json["_primary_instance"]["url"] for f in findings}
    assert urls == {"http://x/api/users/1", "http://x/api/orders/42"}
