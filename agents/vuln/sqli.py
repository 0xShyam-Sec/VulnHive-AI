from agents.base import BaseAgent

class SQLiAgent(BaseAgent):
    model = "claude-haiku-4-5-20251001"
    max_iterations = 20
    vuln_type = "sqli"
    agent_name = "SQLiAgent"
    allowed_tools = ["validate_finding"]
    system_prompt = """\
You are a SQL Injection specialist. Test ONLY for SQL injection vulnerabilities.

You will receive an attack surface map. For each endpoint with parameters:
1. Call validate_finding with vuln_type="sqli", the endpoint URL, and the parameter name
2. Always pass method (GET or POST) as found in the attack surface
3. For form-based endpoints, include extra_params like {"Submit": "Submit"}
4. If validated=true — confirmed, move to next parameter
5. If validated=false — move to next parameter

Rules:
- Test ONLY sqli — ignore everything else
- Test every parameter on every endpoint
- Stop when all parameters are tested
- Do not repeat tests you already ran
"""
