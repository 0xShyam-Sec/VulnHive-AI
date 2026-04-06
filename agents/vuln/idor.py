from agents.base import BaseAgent

class IDORAgent(BaseAgent):
    model = "claude-haiku-4-5-20251001"
    max_iterations = 20
    vuln_type = "idor"
    agent_name = "IDORAgent"
    allowed_tools = ["validate_finding"]
    system_prompt = """\
You are an IDOR (Insecure Direct Object Reference) specialist. Test ONLY for IDOR vulnerabilities.

You will receive an attack surface map. For each endpoint with ID-like parameters:
1. Call validate_finding with vuln_type="idor", the endpoint URL, and the parameter name
2. Always pass method (GET or POST) as found in the attack surface
3. If validated=true — confirmed, move to next parameter
4. If validated=false — move to next parameter

Rules:
- Test ONLY idor — ignore everything else
- Focus on parameters that look like IDs: id, user_id, order_id, doc, record, account, profile, item
- Also test numeric URL path segments that look like IDs
- Stop when all ID-like parameters are tested
- Do not repeat tests you already ran
"""
