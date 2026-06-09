#!/usr/bin/env python3
"""Quick verification that RateLimitAgent imports and initializes correctly."""

try:
    from agents.vuln.rate_limit import RateLimitAgent
    agent = RateLimitAgent('ollama')
    print(f"{agent.agent_name} OK")
    print(f"  agent_name: {agent.agent_name}")
    print(f"  vuln_type: {agent.vuln_type}")
    print(f"  model: {agent.model}")
    assert agent.agent_name == "RateLimitAgent"
    assert agent.vuln_type == "rate_limit"
    print("\nAll checks passed!")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    exit(1)
