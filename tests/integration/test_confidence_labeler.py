import pytest

from engine.confidence_labeler import label_confidence
from engine.finding_model import Confidence, Finding, Severity


def _f(confidence=Confidence.medium, payload=None, evidence=""):
    return Finding(
        scan_id=1, rule_id="x", vuln_type="sqli", title="SQL Injection",
        severity=Severity.high, confidence=confidence,
        primary_evidence=evidence,
    )


@pytest.mark.asyncio
async def test_confirmed_stays_confirmed():
    f = _f(confidence=Confidence.confirmed, evidence="MySQL error stack trace")
    out = await label_confidence(f, instance_url=None)
    assert out.confidence == Confidence.confirmed


@pytest.mark.asyncio
async def test_medium_with_strong_evidence_promotes_to_high():
    f = _f(confidence=Confidence.medium, evidence="MySQL syntax error near 'OR 1=1'")
    out = await label_confidence(f, instance_url=None)
    assert out.confidence == Confidence.high


@pytest.mark.asyncio
async def test_medium_with_no_evidence_demotes_to_low():
    f = _f(confidence=Confidence.medium, evidence="")
    out = await label_confidence(f, instance_url=None)
    assert out.confidence == Confidence.low


@pytest.mark.asyncio
async def test_nothing_is_ever_deleted():
    """A FP-marked finding stays in the pipeline; only its confidence changes."""
    f = _f(confidence=Confidence.false_positive)
    out = await label_confidence(f, instance_url=None)
    assert out is not None
    assert out.confidence == Confidence.false_positive
