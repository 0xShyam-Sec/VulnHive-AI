
import pytest

from engine.errors import FatalError, ProducerFatalError, ScanError


def test_fatal_error_is_exception():
    with pytest.raises(FatalError):
        raise FatalError("ollama unreachable")


def test_producer_fatal_carries_producer_name():
    err = ProducerFatalError("nuclei", "binary missing")
    assert err.producer == "nuclei"
    assert "binary missing" in str(err)


def test_scan_error_serializes_to_dict():
    e = ScanError(
        scan_id=42,
        producer="sqli_agent",
        phase="attack",
        kind="producer_fatal",
        error="LLM returned empty 3 times",
        traceback=None,
        affected_target="http://app.test/login",
    )
    d = e.to_dict()
    assert d["scan_id"] == 42
    assert d["producer"] == "sqli_agent"
    assert d["kind"] == "producer_fatal"
    assert "created_at" in d
