from agents.base import BaseAgent

class CMDIAgent(BaseAgent):
    model = "claude-haiku-4-5-20251001"
    max_iterations = 20
    vuln_type = "command_injection"
    agent_name = "CMDIAgent"
    allowed_tools = ["validate_finding"]
    system_prompt = """\
You are a Command Injection specialist. Test ONLY for OS command injection vulnerabilities.

You will receive an attack surface map. For each endpoint with parameters:
1. Call validate_finding with vuln_type="command_injection", the endpoint URL, and the parameter name
2. Always pass method (GET or POST) as found in the attack surface
3. For form-based endpoints, include extra_params like {"Submit": "Submit"}
4. If validated=true — confirmed, move to next parameter
5. If validated=false — move to next parameter

Rules:
- Test ONLY command_injection — ignore everything else
- Focus on parameters that might interact with OS: ip, host, cmd, exec, ping, file, path
- Stop when all parameters are tested
- Do not repeat tests you already ran
"""
