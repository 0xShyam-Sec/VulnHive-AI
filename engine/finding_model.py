"""Canonical Finding and FindingInstance models.

Findings represent a logical vulnerability. FindingInstances represent each
affected (url, method, param) tuple. Multi-endpoint issues stay as one Finding
with many Instances — fixes the over-aggressive dedup in the legacy flat shape.
"""

from __future__ import annotations

import datetime as _dt
import re
import uuid
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high     = "high"
    medium   = "medium"
    low      = "low"
    info     = "info"


class Confidence(str, Enum):
    confirmed      = "confirmed"
    high           = "high"
    medium         = "medium"
    low            = "low"
    false_positive = "false_positive"


class Status(str, Enum):
    active         = "active"
    duplicate      = "duplicate"
    out_of_scope   = "out_of_scope"
    risk_accepted  = "risk_accepted"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


class Finding(BaseModel):
    id: str = Field(default_factory=_new_id)
    scan_id: int
    rule_id: str
    vuln_type: str
    title: str
    cwe: Optional[int] = None
    cvss: Optional[float] = None
    severity: Severity
    confidence: Confidence
    status: Status = Status.active
    verified: bool = False
    false_p: bool = False
    nb_occurrences: int = 1
    primary_evidence: str = ""
    remediation: str = ""
    references_json: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=_now_iso)
    updated_at: str = Field(default_factory=_now_iso)


class FindingInstance(BaseModel):
    id: str = Field(default_factory=_new_id)
    finding_id: str
    url: str
    method: str = "GET"
    param_name: Optional[str] = None
    payload: Optional[str] = None
    evidence_raw: str = ""
    request: Optional[str] = None
    response_excerpt: Optional[str] = None
    source_tool: str = "unknown"
    source_module: Optional[str] = None
    created_at: str = Field(default_factory=_now_iso)


_CWE_RE = re.compile(r"CWE[-_:]?(\d+)")


def _parse_cwe(raw: Any) -> Optional[int]:
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw
    m = _CWE_RE.search(str(raw))
    return int(m.group(1)) if m else None


def from_legacy_dict(d: dict[str, Any]) -> tuple[Finding, FindingInstance]:
    """Convert one row from the legacy `findings` table or in-memory dict shape."""
    validated = bool(d.get("validated", 0))
    severity_raw = (d.get("severity") or "medium").lower()
    severity = Severity(severity_raw) if severity_raw in Severity._value2member_map_ else Severity.medium
    confidence = Confidence.high if validated else Confidence.medium

    vuln_type = d.get("vuln_type", "unknown") or "unknown"
    rule_id = f"{vuln_type}-legacy"
    title = d.get("title") or vuln_type.replace("_", " ").title()

    finding = Finding(
        scan_id=int(d.get("scan_id", 0)),
        rule_id=rule_id,
        vuln_type=vuln_type,
        title=title,
        cwe=_parse_cwe(d.get("cwe")),
        cvss=float(d["cvss"]) if d.get("cvss") not in (None, "") else None,
        severity=severity,
        confidence=confidence,
        primary_evidence=d.get("evidence", "") or "",
    )
    instance = FindingInstance(
        finding_id=finding.id,
        url=d.get("url", "") or "",
        method=(d.get("method") or "GET").upper(),
        param_name=d.get("param_name") or None,
        payload=d.get("payload") or None,
        evidence_raw=d.get("evidence", "") or "",
        source_tool=d.get("source") or "unknown",
    )
    return finding, instance


def to_legacy_dict(finding: Finding, instance: FindingInstance) -> dict[str, Any]:
    """Render a (Finding, Instance) pair into the dict shape legacy callers expect."""
    return {
        "scan_id": finding.scan_id,
        "vuln_type": finding.vuln_type,
        "url": instance.url,
        "method": instance.method,
        "param_name": instance.param_name,
        "payload": instance.payload,
        "evidence": instance.evidence_raw or finding.primary_evidence,
        "source": instance.source_tool,
        "severity": finding.severity.value,
        "validated": 1 if finding.confidence in (Confidence.confirmed, Confidence.high) else 0,
        "cwe": f"CWE-{finding.cwe}" if finding.cwe else None,
        "cvss": finding.cvss,
        "confidence": finding.confidence.value,
    }
