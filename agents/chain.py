"""
ChainAnalyzer — uses Claude Sonnet to reason about exploit chains
from a list of confirmed findings.
"""

import json
import re
import os
from rich.console import Console

console = Console()


class ChainAnalyzer:
    model = "claude-sonnet-4-6"

    def __init__(self):
        import anthropic
        self.client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

    SYSTEM_PROMPT = """\
You are an exploit chain analyst. Given a list of confirmed vulnerabilities from a penetration test,
identify which ones can be realistically combined into multi-step attack chains.

For each chain found, output a JSON object with:
- name: short chain name (e.g. "XSS + CSRF = Account Takeover")
- steps: array of vuln types used in order
- description: 2-3 sentence explanation of the attack flow
- impact: combined impact (e.g. "Full account takeover for any authenticated user")
- severity: "Critical", "High", or "Medium"

Only include chains that are technically feasible given the evidence.
Output ONLY a valid JSON array. No extra text.

Example:
[
  {
    "name": "XSS + CSRF = Account Takeover",
    "steps": ["xss", "csrf"],
    "description": "Attacker injects XSS payload that auto-submits the CSRF-vulnerable password change form, changing the victim's password without interaction.",
    "impact": "Full account takeover for any authenticated user who visits attacker-controlled content.",
    "severity": "Critical"
  }
]

If no meaningful chains exist, output: []
"""

    def analyze(self, findings: list) -> list:
        if not findings:
            return []

        msg = (
            f"Confirmed findings ({len(findings)} total):\n"
            f"{json.dumps(findings, indent=2, default=str)[:8000]}"
        )

        try:
            import anthropic
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2048,
                system=self.SYSTEM_PROMPT,
                messages=[{"role": "user", "content": msg}],
            )
        except anthropic.APIError as e:
            console.print(f"  [red]ChainAnalyzer API error: {e}[/]")
            return []

        text = " ".join(
            b.text for b in response.content if hasattr(b, "text")
        ).strip()

        try:
            match = re.search(r'\[.*\]', text, re.DOTALL)
            if match:
                return json.loads(match.group())
        except (json.JSONDecodeError, AttributeError):
            pass

        return []
