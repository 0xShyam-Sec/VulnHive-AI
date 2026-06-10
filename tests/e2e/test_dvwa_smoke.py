"""End-to-end: scan DVWA via the CLI and assert on the report JSON.

This test is meant to run **locally before a demo**, not in CI. It requires:
- DVWA running on http://localhost:8080
- Ollama with qwen3:14b pulled and running on http://localhost:11434

Skipped unless BOTH `DVWA_AVAILABLE=1` AND `OLLAMA_AVAILABLE=1` are set.
A GitHub Actions runner can't realistically host qwen3:14b (9 GB model,
runners have ~7 GB RAM), so this test does not run in default CI.

To run locally:
    docker compose up -d            # DVWA at :8080
    ollama serve &                   # if not already
    DVWA_AVAILABLE=1 OLLAMA_AVAILABLE=1 \\
        ./venv/bin/pytest tests/e2e -v -m e2e
"""

import json
import os
import subprocess
import sys

import pytest


pytestmark = pytest.mark.e2e


_e2e_enabled = (
    os.environ.get("DVWA_AVAILABLE") == "1"
    and os.environ.get("OLLAMA_AVAILABLE") == "1"
)


@pytest.mark.skipif(not _e2e_enabled,
                    reason="needs DVWA_AVAILABLE=1 AND OLLAMA_AVAILABLE=1")
def test_dvwa_scan_produces_known_finding_classes(tmp_path):
    """A multi-agent scan against DVWA must produce:
    - ≥ 30 findings
    - Core vuln types (sqli/xss/missing_security_header)
    - At least one confirmed-confidence finding
    - All non-info findings carry a CWE
    """
    result = subprocess.run([
        sys.executable, "main.py",
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
