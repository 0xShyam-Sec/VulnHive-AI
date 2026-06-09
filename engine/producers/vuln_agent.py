"""Generic adapter: turn any existing agent class into a FindingProducer.

The contract we depend on:
- Agent has `vuln_type` and `agent_name` (or we accept them via constructor)
- Agent has a `run(user_message: str) -> list[dict]` method that returns
  legacy-shape finding dicts.

The wrapper:
- Calls agent.run() in a thread (the legacy methods are sync + blocking)
- For each returned dict, builds a Finding via from_legacy_dict
- Sets confidence based on the dict's `validated` flag (1 → confirmed, 0 → medium)
- Populates cwe/cvss from engine.classification if absent
- Attaches the dict's url/method/param/payload/evidence as the Instance
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator, Type

from engine.classification import classify
from engine.finding_model import (
    Confidence,
    Finding,
    from_legacy_dict,
)
from engine.logging_setup import get_logger
from engine.producer import FindingProducer, ScanContext
from engine.runner import attach_instance

_log = get_logger()


def _confidence_from_legacy(dict_: dict) -> Confidence:
    """Legacy `validated` flag → new confidence enum.

    validated=1 + has payload + has evidence → confirmed (deterministic proof)
    validated=1 (heuristic match)            → high
    validated=0                              → medium (LLM opinion, untested)
    """
    if dict_.get("validated", 0) == 1:
        if dict_.get("payload") and dict_.get("evidence"):
            return Confidence.confirmed
        return Confidence.high
    return Confidence.medium


class VulnAgentProducer(FindingProducer):
    """Adapter for legacy vuln agents in `agents/vuln/*.py`."""

    phase = "attack"

    def __init__(self, agent_class: Type, vuln_type: str, agent_name: str):
        self.agent_class = agent_class
        self.vuln_type = vuln_type
        self.agent_name = agent_name
        self.name = agent_name

    async def produce(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        loop = asyncio.get_running_loop()
        try:
            agent = self.agent_class(llm_backend=ctx.llm_backend)
        except Exception as e:
            _log.error("agent_init_failed", agent=self.agent_name, error=str(e))
            return

        try:
            user_msg = f"Test the target: {ctx.target}"
            results = await loop.run_in_executor(None, agent.run, user_msg)
        except Exception as e:
            _log.error("agent_run_failed", agent=self.agent_name, error=str(e))
            return

        results = results or []
        total = len(results)
        ctx.progress(producer=self.name, current=0, total=total, last="starting")
        for idx, d in enumerate(results):
            if ctx.cancelled:
                break

            d = {
                **d,
                "scan_id": ctx.scan_id,
                "source": self.agent_name,
                "vuln_type": d.get("vuln_type") or self.vuln_type,
            }

            finding, instance = from_legacy_dict(d)
            finding.rule_id = f"{self.agent_name}:{finding.vuln_type}"
            finding.confidence = _confidence_from_legacy(d)

            cwe_default, cvss_default = classify(finding.vuln_type)
            finding.cwe = finding.cwe or cwe_default
            finding.cvss = finding.cvss or cvss_default

            ctx.progress(producer=self.name, current=idx + 1, total=total,
                         last=instance.url or "")
            yield attach_instance(
                finding,
                url=instance.url or ctx.target,
                method=instance.method,
                param_name=instance.param_name,
                payload=instance.payload,
                evidence_raw=instance.evidence_raw,
                source_tool=self.agent_name,
            )
        ctx.progress(producer=self.name, current=total, total=total, finished=True)
