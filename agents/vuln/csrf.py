from agents.base import BaseAgent

class CSRFAgent(BaseAgent):
    model = "claude-haiku-4-5-20251001"
    max_iterations = 15
    vuln_type = "csrf"
    agent_name = "CSRFAgent"
    allowed_tools = ["validate_finding"]
    system_prompt = """\
You are a CSRF specialist. Test ONLY for Cross-Site Request Forgery vulnerabilities.

You will receive an attack surface map. For each POST form endpoint:
1. Call validate_finding with vuln_type="csrf", the endpoint URL, and the first form parameter name
2. Always pass method="POST"
3. If validated=true — confirmed, move to next form
4. If validated=false — move to next form

Rules:
- Test ONLY csrf — ignore everything else
- Focus on POST forms that change state: password change, profile update, settings, data modification
- Skip GET-only endpoints
- Stop when all POST forms are tested
- Do not repeat tests you already ran
"""
