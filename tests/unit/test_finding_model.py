from engine.finding_model import (
    Confidence,
    Finding,
    FindingInstance,
    Severity,
    Status,
    from_legacy_dict,
    to_legacy_dict,
)


def test_finding_minimum_fields():
    f = Finding(
        scan_id=1,
        rule_id="sqli-error-based",
        vuln_type="sqli",
        title="SQL Injection (error-based)",
        severity=Severity.high,
        confidence=Confidence.confirmed,
    )
    assert f.status == Status.active
    assert f.verified is False
    assert f.false_p is False
    assert f.nb_occurrences == 1


def test_finding_instance_links_to_finding():
    fi = FindingInstance(
        finding_id="abc",
        url="http://app.test/login",
        method="POST",
        param_name="username",
        payload="1' OR 1=1--",
        evidence_raw="MySQL syntax error: …",
        source_tool="sqli_agent",
    )
    assert fi.finding_id == "abc"
    assert fi.method == "POST"


def test_legacy_dict_roundtrip_high_confidence():
    legacy = {
        "scan_id": 7,
        "vuln_type": "sqli",
        "url": "http://app.test/q",
        "method": "GET",
        "param_name": "id",
        "payload": "1'",
        "evidence": "MySQL error",
        "source": "sqli_agent",
        "severity": "high",
        "validated": 1,
        "cwe": "CWE-89",
        "cvss": 9.8,
    }
    finding, instance = from_legacy_dict(legacy)
    assert finding.vuln_type == "sqli"
    assert finding.confidence == Confidence.high   # validated=1 → high
    assert finding.cvss == 9.8
    assert finding.cwe == 89
    assert instance.url == "http://app.test/q"
    assert instance.source_tool == "sqli_agent"

    rt = to_legacy_dict(finding, instance)
    assert rt["vuln_type"] == "sqli"
    assert rt["url"] == "http://app.test/q"
    assert rt["payload"] == "1'"


def test_legacy_dict_unvalidated_becomes_medium():
    legacy = {"scan_id": 1, "vuln_type": "headers", "url": "http://a", "validated": 0}
    finding, _ = from_legacy_dict(legacy)
    assert finding.confidence == Confidence.medium
