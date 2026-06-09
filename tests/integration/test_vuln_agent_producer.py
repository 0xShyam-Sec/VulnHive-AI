import pytest

from engine.producer import ScanContext
from engine.producers.vuln_agent import VulnAgentProducer


class _StubAgent:
    """Stand-in for agents.vuln.sqli.SqliAgent etc."""

    vuln_type = "sqli"
    agent_name = "sqli_agent"

    def __init__(self, llm_backend="ollama"):
        self.llm_backend = llm_backend

    def run(self, _user_message):
        return [
            {
                "vuln_type": "sqli",
                "url": "http://x/q",
                "method": "GET",
                "param_name": "id",
                "payload": "1'",
                "evidence": "MySQL syntax error: …",
                "severity": "high",
                "validated": 1,        # → confidence=confirmed by wrapper
                "source": "sqli_agent",
            }
        ]


@pytest.mark.asyncio
async def test_vuln_agent_wrapper_yields_finding_from_agent_dict():
    ctx = ScanContext(scan_id=1, target="http://x", db_path=None)
    p = VulnAgentProducer(_StubAgent, vuln_type="sqli", agent_name="sqli_agent")
    findings = [f async for f in p.produce(ctx)]
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "sqli"
    assert f.cwe == 89
    assert f.cvss == 9.8
    assert f.confidence.value == "confirmed"
    assert f.rule_id == "sqli_agent:sqli"
