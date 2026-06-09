"""Importer: parse Nuclei JSONL output and yield Findings.

Two operating modes:
- jsonl_path=<file>: parse a pre-recorded JSONL (used by tests + offline replays)
- jsonl_path=None:   shell out to `nuclei -target ... -jsonl -o /tmp/...` (live scan)
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import AsyncIterator, Optional

from engine.classification import classify
from engine.finding_model import Confidence, Finding, Severity
from engine.logging_setup import get_logger
from engine.producer import FindingProducer, ScanContext
from engine.runner import attach_instance


_log = get_logger()

_SEVERITY_MAP = {
    "critical": Severity.critical,
    "high":     Severity.high,
    "medium":   Severity.medium,
    "low":      Severity.low,
    "info":     Severity.info,
    "unknown":  Severity.info,
}

_CWE_RE = re.compile(r"CWE[-_:]?(\d+)", re.I)


def _row_to_finding(scan_id: int, row: dict) -> Finding:
    info = row.get("info", {}) or {}
    classification = info.get("classification", {}) or {}

    cwe_ids = classification.get("cwe-id") or []
    cve_ids = classification.get("cve-id") or []

    cwe_int: Optional[int] = None
    for cwe in cwe_ids:
        m = _CWE_RE.search(str(cwe))
        if m:
            cwe_int = int(m.group(1))
            break

    severity = _SEVERITY_MAP.get((info.get("severity") or "info").lower(), Severity.info)
    template_id = row.get("template-id", "unknown")
    vuln_type = "nuclei_match"
    title = info.get("name") or template_id

    cvss = classification.get("cvss-score")
    if cvss is None:
        _, cvss = classify(vuln_type)
    cvss = float(cvss) if cvss is not None else None

    references_json: dict = {
        "nuclei_template_id": template_id,
        "cve_ids": list(cve_ids),
    }

    return Finding(
        scan_id=scan_id,
        rule_id=f"nuclei:{template_id}",
        vuln_type=vuln_type,
        title=title,
        cwe=cwe_int,
        cvss=cvss,
        severity=severity,
        confidence=Confidence.high,
        primary_evidence=info.get("description", "") or info.get("matcher-name", "") or "",
        references_json=references_json,
    )


class NucleiProducer(FindingProducer):
    name = "nuclei"
    phase = "discovery"

    def __init__(self, jsonl_path: Optional[Path] = None,
                 nuclei_bin: str = "nuclei"):
        self.jsonl_path = Path(jsonl_path) if jsonl_path else None
        self.nuclei_bin = nuclei_bin

    async def produce(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        if self.jsonl_path is None:
            self.jsonl_path = await self._run_live(ctx)

        if self.jsonl_path is None or not self.jsonl_path.exists():
            return

        for line in self.jsonl_path.read_text().splitlines():
            line = line.strip()
            if not line or ctx.cancelled:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                _log.warning("nuclei_parse_failed", line_excerpt=line[:60], error=str(e))
                continue
            f = _row_to_finding(ctx.scan_id, row)
            yield attach_instance(
                f,
                url=row.get("matched-at") or row.get("host") or ctx.target,
                method="GET",
                evidence_raw=json.dumps(row)[:500],
                source_tool="nuclei",
            )

    async def _run_live(self, ctx: ScanContext) -> Optional[Path]:
        out = Path(tempfile.mktemp(suffix=".jsonl", prefix="nuclei-"))
        cmd = [self.nuclei_bin, "-u", ctx.target, "-jsonl", "-o", str(out),
               "-silent", "-timeout", "10", "-rate-limit", "150"]
        loop = asyncio.get_running_loop()
        try:
            proc = await loop.run_in_executor(None,
                lambda: subprocess.run(cmd, capture_output=True, timeout=900))
            if proc.returncode != 0:
                _log.warning("nuclei_returned_nonzero", code=proc.returncode,
                             stderr=proc.stderr.decode(errors="replace")[:200])
            return out if out.exists() else None
        except FileNotFoundError:
            _log.warning("nuclei_binary_missing", bin=self.nuclei_bin)
            return None
        except Exception as e:
            _log.warning("nuclei_invocation_failed", error=str(e))
            return None
