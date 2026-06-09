"""End-to-end: scan DVWA via the CLI and assert on the report JSON.

Skipped unless `DVWA_AVAILABLE=1` env var is set. CI workflow exports this
after `docker-compose up -d dvwa` finishes warming up.
"""

import json
import os
import subprocess

import pytest


pytestmark = pytest.mark.e2e


@pytest.mark.skipif(os.environ.get("DVWA_AVAILABLE") != "1",
                    reason="DVWA not running; set DVWA_AVAILABLE=1 to enable")
def test_dvwa_scan_produces_known_finding_classes(tmp_path):
    """A multi-agent scan against DVWA must produce:
    - ≥ 30 findings
    - Core vuln types (sqli/xss/missing_security_header)
    - At least one confirmed-confidence finding
    - All non-info findings carry a CWE
    """
    result = subprocess.run([
        "./venv/bin/python", "main.py",
        "--target", "http://localhost:8080",
        "--mode", "multi-agent",
        "--auth-type", "form",
        "--login-url", "http://localhost:8080/login.php",
        "--username", "admin",
        "--password", "password",
        "--llm", "ollama",
        "--report-dir", str(tmp_path),
    ], capture_output=True, timeout=900)

    assert result.returncode == 0, f"CLI failed: {result.stderr.decode()[:400]}"

    # find the produced JSON report (main.py names it scan_*.json or similar)
    jsons = list(tmp_path.glob("*.json"))
    assert jsons, f"no JSON report produced; tmp dir contains: {list(tmp_path.iterdir())}"

    findings = json.loads(jsons[0].read_text()).get("findings", [])

    types = {f.get("vuln_type") for f in findings}
    assert "sqli" in types or "xss" in types or "reflected_xss" in types, \
        f"expected core vuln types, got {sorted(types)[:20]}"
    assert any("header" in (t or "") for t in types), \
        f"expected header findings, got {sorted(types)[:20]}"
    assert any(f.get("confidence") in ("confirmed", "high") for f in findings), \
        "expected at least one high-confidence finding"
    assert all((f.get("cwe") is not None) for f in findings if f.get("vuln_type") not in (None, "info")), \
        "all non-info findings must have a CWE"
    assert len(findings) >= 30, \
        f"demo floor is 30 findings on DVWA multi-agent scan; got {len(findings)}"
