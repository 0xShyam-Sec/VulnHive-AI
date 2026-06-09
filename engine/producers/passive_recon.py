"""Wrap the existing discovery.passive_recon module into a FindingProducer.

The legacy code already populates a ScanState with finding dicts. We invoke it,
then convert each dict via the legacy adapter and yield Findings.

Adaptation note: discovery.passive_recon emits vuln_type values with per-header
suffixes, e.g. ``missing_security_header_x_frame_options``. We normalise these
to the canonical ``missing_security_header`` type so downstream classification
(CWE-693, CVSS 4.3) and deduplication keying work correctly.
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator

from engine.classification import classify
from engine.finding_model import (
    Confidence,
    Finding,
    from_legacy_dict,
)
from engine.producer import FindingProducer, ScanContext
from engine.runner import attach_instance


def _normalise_vuln_type(raw: str) -> str:
    """Collapse per-header suffixes back to the canonical vuln_type.

    ``missing_security_header_x_frame_options`` → ``missing_security_header``
    ``missing_security_header_strict_transport_security`` → ``missing_security_header``
    All other types pass through unchanged.
    """
    if raw.startswith("missing_security_header_"):
        return "missing_security_header"
    return raw


class PassiveReconProducer(FindingProducer):
    name = "passive_recon"
    phase = "recon"

    async def produce(self, ctx: ScanContext) -> AsyncIterator[Finding]:  # type: ignore[override]
        # Lazy imports: pulling these at module top-level slows test collection.
        from discovery.passive_recon import run_passive_recon
        from engine.scan_state import ScanState, Endpoint
        from engine.config import ScanConfig

        cfg = ScanConfig(target=ctx.target)
        state = ScanState()
        state.add_endpoint(Endpoint(url=ctx.target, method="GET"))

        # The legacy function is synchronous + side-effects state.findings.
        # Run it on the loop executor so we don't block the event loop.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, run_passive_recon, ctx.target, cfg, state)

        all_findings = list(state.findings)
        total = len(all_findings)
        ctx.progress(producer=self.name, current=0, total=total, last="starting")
        for idx, d in enumerate(all_findings):
            if ctx.cancelled:
                break

            # Normalise the vuln_type before conversion so classification and
            # deduplication keys are consistent.
            normalised = _normalise_vuln_type(d.get("vuln_type", "unknown") or "unknown")
            d_normalised = {**d, "vuln_type": normalised}

            finding, instance = from_legacy_dict({
                **d_normalised,
                "scan_id": ctx.scan_id,
                "source": "passive_recon",
            })

            if finding.cwe is None or finding.cvss is None:
                cwe_default, cvss_default = classify(finding.vuln_type)
                finding.cwe = finding.cwe or cwe_default
                finding.cvss = finding.cvss or cvss_default

            if finding.confidence == Confidence.medium:
                finding.confidence = Confidence.high

            ctx.progress(producer=self.name, current=idx + 1, total=total,
                         last=instance.url or "")
            yield attach_instance(
                finding,
                url=instance.url,
                method=instance.method,
                param_name=instance.param_name,
                payload=instance.payload,
                evidence_raw=instance.evidence_raw,
                source_tool="passive_recon",
            )
        ctx.progress(producer=self.name, current=total, total=total, finished=True)
