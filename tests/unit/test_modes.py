import pytest

from engine.modes import MODE_PRODUCERS, build_producer_names, list_modes


def test_multi_agent_includes_nuclei():
    assert "nuclei" in MODE_PRODUCERS["multi-agent"]


def test_multi_agent_includes_passive_recon_and_playwright():
    assert "passive_recon" in MODE_PRODUCERS["multi-agent"]
    assert "playwright_crawler" in MODE_PRODUCERS["multi-agent"]


def test_full_is_superset_of_multi_agent():
    full = set(MODE_PRODUCERS["full"])
    ma = set(MODE_PRODUCERS["multi-agent"])
    assert ma.issubset(full)
    assert "nmap" in full
    assert "shodan" in full
    assert "systematic" in full


def test_unknown_mode_raises():
    with pytest.raises(KeyError):
        build_producer_names("not-a-mode")


def test_list_modes_contains_all_expected():
    modes = list_modes()
    assert {"fast", "multi-agent", "full", "browser", "api"}.issubset(set(modes))
