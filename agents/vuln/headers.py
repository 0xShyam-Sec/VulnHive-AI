from agents.base import BaseAgent

class HeadersAgent(BaseAgent):
    model = "claude-haiku-4-5-20251001"
    max_iterations = 5
    vuln_type = "security_headers"
    agent_name = "HeadersAgent"
    allowed_tools = ["validate_finding"]
    system_prompt = """\
You are a Security Headers specialist. Test ONLY for missing or misconfigured HTTP security headers.

You will receive a target URL. Run ONE check:
1. Call validate_finding with vuln_type="security_headers", the base URL, param_name="" and method="GET"
2. Report the result and stop

Rules:
- Test ONLY security_headers — this is a passive check, no param needed
- Run only once on the base URL
- Stop immediately after the check
"""
