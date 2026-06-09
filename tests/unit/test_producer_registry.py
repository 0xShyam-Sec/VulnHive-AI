import pytest

from engine.modes import ALL_VULN_AGENTS
from engine.producers.registry import (
    PRODUCER_FACTORIES,
    build_producer,
    build_producers,
)


def test_every_vuln_agent_is_registered():
    for name in ALL_VULN_AGENTS:
        assert name in PRODUCER_FACTORIES, f"missing producer factory for {name!r}"


def test_importers_and_recon_are_registered():
    for name in ("passive_recon", "playwright_crawler", "nuclei", "nmap", "shodan",
                 "waf_detector"):
        assert name in PRODUCER_FACTORIES


def test_unknown_name_raises_keyerror():
    with pytest.raises(KeyError):
        build_producer("not-a-producer")


def test_build_producers_for_multi_agent_returns_list():
    producers = build_producers("multi-agent")
    names = {p.name for p in producers}
    assert "passive_recon" in names
    assert "nuclei" in names
    # The vuln-agent producers are named after the agent class's agent_name,
    # which uses the actual class agent_name attribute (e.g., "SQLiAgent").
    # Verify by checking that there are >= 25 producers in multi-agent (the count of vuln agents).
    assert len(producers) >= 25
