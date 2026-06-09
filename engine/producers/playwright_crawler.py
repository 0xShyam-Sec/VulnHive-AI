"""Playwright-based crawler that now ALSO emits Findings, not just endpoints.

For every endpoint tagged auth_required (via the bool field or the 'auth_required'
tag string), we yield a low-confidence 'idor_target' Finding — it's a test target,
not a confirmed vulnerability, but the user gets to see them in the dashboard for
follow-up.
"""

from __future__ import annotations

from typing import AsyncIterator

from engine.classification import classify
from engine.finding_model import Confidence, Finding, Severity
from engine.logging_setup import get_logger
from engine.producer import FindingProducer, ScanContext
from engine.runner import attach_instance

_log = get_logger()


async def _run_underlying_crawler(ctx: ScanContext, state, cfg) -> list:
    """Invoke the legacy Playwright crawl. Overridden in tests via monkeypatch.

    The real entry point is ``discover_with_playwright`` (an async function) in
    ``discovery.playwright_crawler``.  We call it directly and then return the
    endpoints that were added to *state*.
    """
    from discovery.playwright_crawler import discover_with_playwright

    await discover_with_playwright(ctx.target, cfg, state)
    return list(getattr(state, "endpoints", []))


class PlaywrightProducer(FindingProducer):
    name = "playwright_crawler"
    phase = "recon"

    async def produce(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        from engine.config import ScanConfig
        from engine.scan_state import ScanState

        cfg = ScanConfig(target=ctx.target)
        state = ScanState()

        try:
            endpoints = await _run_underlying_crawler(ctx, state, cfg)
        except Exception as e:
            _log.warning("playwright_crawl_failed", error=str(e))
            return

        cwe, cvss = classify("idor")

        for ep in endpoints:
            if ctx.cancelled:
                break

            # Support both the bool field and the tag-string convention so that
            # tests can supply either form without friction.
            auth_req_bool = bool(getattr(ep, "auth_required", False))
            tags = set(getattr(ep, "tags", None) or ())
            auth_req_tag = "auth_required" in tags

            if not (auth_req_bool or auth_req_tag):
                continue

            url = getattr(ep, "url", "")
            method = getattr(ep, "method", "GET")
            f = Finding(
                scan_id=ctx.scan_id,
                rule_id="playwright:idor_target",
                vuln_type="idor_target",
                title=f"Authenticated endpoint (IDOR candidate): {url}",
                cwe=cwe,
                cvss=cvss,
                severity=Severity.info,
                confidence=Confidence.low,
                primary_evidence=f"Crawler observed {method} {url} requires authentication",
                references_json={"discovered_by": "playwright_crawler"},
            )
            yield attach_instance(
                f,
                url=url,
                method=method,
                evidence_raw=f.primary_evidence,
                source_tool="playwright_crawler",
            )
