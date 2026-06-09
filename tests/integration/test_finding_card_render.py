from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from engine.finding_model import Confidence, Finding, Severity


TEMPLATES = Path("dashboard/templates")


def _render(name: str, **ctx) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)))
    return env.get_template(name).render(**ctx)


def test_card_shows_cwe_cvss_payload_confidence():
    f = Finding(
        scan_id=1, rule_id="sqli", vuln_type="sqli",
        title="SQL Injection (error-based)",
        cwe=89, cvss=9.8,
        severity=Severity.critical, confidence=Confidence.confirmed,
        primary_evidence="MySQL syntax error near 'OR 1=1'",
        nb_occurrences=3,
    )
    primary = {
        "url": "http://app.com/login",
        "method": "POST",
        "param_name": "username",
        "payload": "1' OR 1=1--",
        "source_tool": "sqli_agent",
    }
    html = _render("partials/finding_card.html", f=f, primary=primary)

    assert "CWE-89" in html
    assert "9.8" in html
    assert "Critical" in html or "critical" in html
    assert "Confirmed" in html or "confirmed" in html
    assert "1&#39; OR 1=1--" in html or "1' OR 1=1--" in html
    assert "3 affected" in html
    assert "sqli_agent" in html
