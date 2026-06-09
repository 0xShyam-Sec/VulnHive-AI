import threading
import time

import pytest

from engine.producer import ScanContext
from engine.producers.passive_recon import PassiveReconProducer


@pytest.fixture(scope="module")
def mock_target():
    """Spin up the mock Flask target on a random local port."""
    from tests.fixtures.mock_target.app import app
    import werkzeug.serving as ws

    server = ws.make_server("127.0.0.1", 8765, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    yield "http://127.0.0.1:8765"
    server.shutdown()


@pytest.mark.asyncio
async def test_passive_recon_finds_missing_headers(mock_target):
    ctx = ScanContext(scan_id=1, target=mock_target, db_path=None)
    findings = [f async for f in PassiveReconProducer().produce(ctx)]
    types = {f.vuln_type for f in findings}
    assert "missing_security_header" in types or "headers" in types
