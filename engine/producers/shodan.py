"""Importer: query Shodan InternetDB (free, no key needed) for known CVEs on the target host.

InternetDB endpoint: https://internetdb.shodan.io/<ip>
"""

from __future__ import annotations

import socket
import urllib.parse
from typing import AsyncIterator

from engine.classification import classify
from engine.finding_model import Confidence, Finding, Severity
from engine.logging_setup import get_logger
from engine.producer import FindingProducer, ScanContext
from engine.runner import attach_instance

_log = get_logger()


class ShodanProducer(FindingProducer):
    name = "shodan"
    phase = "discovery"

    async def produce(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        host = urllib.parse.urlparse(ctx.target).hostname or ctx.target
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            _log.warning("shodan_dns_failed", host=host, error=str(e))
            return

        import httpx
        url = f"https://internetdb.shodan.io/{ip}"
        async with httpx.AsyncClient(timeout=15) as client:
            try:
                resp = await client.get(url)
            except httpx.HTTPError as e:
                _log.warning("shodan_request_failed", error=str(e))
                return
        if resp.status_code != 200:
            return

        data = resp.json()
        for cve in (data.get("vulns") or []):
            if ctx.cancelled:
                break
            rule_id = f"shodan:{cve}"
            cwe_default, cvss_default = classify("cmdi")
            f = Finding(
                scan_id=ctx.scan_id,
                rule_id=rule_id,
                vuln_type="known_cve",
                title=f"Known CVE on host: {cve}",
                cwe=cwe_default,
                cvss=cvss_default,
                severity=Severity.high,
                confidence=Confidence.high,
                primary_evidence=f"Shodan InternetDB reports {cve} affects {ip}",
                references_json={"cve_id": cve, "ip": ip, "host": host},
            )
            yield attach_instance(
                f,
                url=ctx.target,
                evidence_raw=f.primary_evidence,
                source_tool="shodan",
            )
