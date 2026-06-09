"""Verify that _resolve_producers_for_mode honours the config['mode'] field."""
import sys
import types
from unittest import mock


def _import_worker():
    """Import dashboard.worker with redis stubbed out (not installed in CI)."""
    if "dashboard.worker" in sys.modules:
        return sys.modules["dashboard.worker"]

    # Stub the redis package so the top-level `import redis as redis_client` succeeds.
    fake_redis_mod = types.ModuleType("redis")
    fake_redis_instance = mock.MagicMock()
    fake_redis_mod.Redis = mock.MagicMock(return_value=fake_redis_instance)

    with mock.patch.dict(sys.modules, {"redis": fake_redis_mod}):
        import dashboard.worker as worker_mod  # noqa: PLC0415
    return worker_mod


worker = _import_worker()


def test_worker_resolves_full_mode_to_full_producer_set():
    producers = worker._resolve_producers_for_mode({"mode": "full"})
    names = {p.name for p in producers}
    assert "nmap" in names


def test_worker_resolves_multi_agent_to_multi_agent_set_and_NOT_nmap():
    producers = worker._resolve_producers_for_mode({"mode": "multi-agent"})
    names = {p.name for p in producers}
    assert "nmap" not in names
    assert "nuclei" in names


def test_worker_unknown_mode_falls_back_to_multi_agent():
    producers = worker._resolve_producers_for_mode({"mode": "bogus"})
    names = {p.name for p in producers}
    assert "nuclei" in names
