from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from engine.finding_model import (
    Confidence,
    Finding,
    FindingInstance,
    Severity,
    Status,
)


TEMPLATES = Path("dashboard/templates")


def _render(name: str, **ctx) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)))
    return env.get_template(name).render(**ctx)


def test_modal_renders_with_finding_and_instances():
    f = Finding(
        scan_id=1, rule_id="sqli", vuln_type="sqli",
        title="SQL Injection", cwe=89, cvss=9.8,
        severity=Severity.high, confidence=Confidence.confirmed,
        primary_evidence="MySQL error",
        status=Status.active,
    )
    instances = [
        FindingInstance(
            finding_id=f.id, url="http://app.test/login",
            method="POST", param_name="username", payload="1' OR 1=1--",
            source_tool="sqli_agent",
        ),
    ]
    html = _render("partials/finding_detail_modal.html", f=f, instances=instances)
    assert "Overview" in html
    assert "Evidence" in html
    assert "Affected (1)" in html
    assert "Remediation" in html
    assert "References" in html
    assert "CWE-89" in html
    assert "9.8" in html
    assert "MySQL error" in html
    assert "1&#39; OR 1=1--" in html or "1' OR 1=1--" in html


def test_modal_renders_with_no_instances():
    f = Finding(
        scan_id=1, rule_id="x", vuln_type="x", title="X",
        severity=Severity.low, confidence=Confidence.medium,
    )
    html = _render("partials/finding_detail_modal.html", f=f, instances=[])
    assert "Affected (0)" in html
    assert "No instance records." in html
