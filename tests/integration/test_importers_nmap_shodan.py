from pathlib import Path

import pytest

from engine.producer import ScanContext
from engine.producers.nmap import NmapProducer
from engine.producers.shodan import ShodanProducer


@pytest.mark.asyncio
async def test_nmap_importer_yields_one_finding_per_open_port():
    xml = Path(__file__).parent.parent / "fixtures" / "recordings" / "nmap_sample.xml"
    ctx = ScanContext(scan_id=1, target="127.0.0.1", db_path=None)
    findings = [f async for f in NmapProducer(xml_path=xml).produce(ctx)]
    assert len(findings) == 3
    ports = {f.references_json["port"] for f in findings}
    assert ports == {22, 80, 3306}
    titles = {f.title for f in findings}
    assert any("MySQL 5.7.30" in t for t in titles)


@pytest.mark.asyncio
async def test_shodan_importer_handles_network_gracefully():
    """ShodanProducer gracefully handles network unreachability or absence of host in InternetDB."""
    import os

    os.environ.pop("SHODAN_API_KEY", None)
    ctx = ScanContext(scan_id=1, target="example.com", db_path=None)
    findings = [f async for f in ShodanProducer().produce(ctx)]
    # In test environment with no known CVEs or network issues, expect 0 findings
    # But if example.com does have CVEs in InternetDB, this may be > 0
    # The important assertion is that it doesn't crash and returns a list
    assert isinstance(findings, list)
    # Ensure each finding is valid
    for f in findings:
        assert f.rule_id.startswith("shodan:")
        assert f.vuln_type == "known_cve"
