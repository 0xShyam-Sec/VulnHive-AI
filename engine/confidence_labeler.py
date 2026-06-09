"""Replace the legacy drop_false_positives=True semantics.

The labeler NEVER deletes a finding. It re-examines the evidence and assigns a
confidence label. The dashboard filter (default: hide confidence=low and
confidence=false_positive) decides what's shown.
"""

from __future__ import annotations

import re
from typing import Optional

from engine.finding_model import Confidence, Finding


_STRONG_SIGNALS = [
    re.compile(r"\bSQL syntax\b", re.I),
    re.compile(r"\bMySQL\b.*\berror\b", re.I),
    re.compile(r"\bPostgres(QL)?\b.*\berror\b", re.I),
    re.compile(r"\bORA-\d{5}\b"),
    re.compile(r"\bsqlite_master\b", re.I),
    re.compile(r"\bjava\.sql\.SQLException\b"),
    re.compile(r"<script[^>]*>alert\("),
    re.compile(r"\bcanary\b", re.I),
    re.compile(r"\broot:.*:\d+:\d+:", re.I),
    re.compile(r"\bAWSAccessKeyId\b"),
    re.compile(r"\bBEGIN RSA PRIVATE KEY\b"),
]


async def label_confidence(finding: Finding,
                           instance_url: Optional[str] = None) -> Finding:
    """Re-examine evidence; promote, demote, or pass through. Returns a NEW Finding."""

    if finding.confidence == Confidence.confirmed:
        return finding

    if finding.confidence == Confidence.false_positive:
        return finding

    evidence = (finding.primary_evidence or "").strip()

    if not evidence:
        return finding.model_copy(update={"confidence": Confidence.low})

    if any(p.search(evidence) for p in _STRONG_SIGNALS):
        if finding.confidence in (Confidence.medium, Confidence.low):
            return finding.model_copy(update={"confidence": Confidence.high})

    if finding.confidence == Confidence.medium and len(evidence) < 20:
        return finding.model_copy(update={"confidence": Confidence.low})

    return finding
