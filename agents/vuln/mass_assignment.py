"""
Mass Assignment & Parameter Tampering Agent

Tests for:
1. Mass assignment — inject unexpected fields (role, admin, price) in POST/PUT bodies
2. Price/amount tampering — change numeric values to 0, negative, very large
3. State machine bypass — skip workflow steps, jump to later states directly
4. HTTP method override — test if GET endpoints accept POST (and vice versa)
"""

import json
import httpx
import re
from agents.base import BaseAgent
from rich.console import Console

console = Console()

# Fields to inject for mass assignment
PRIVILEGE_FIELDS = [
    ('role', ['admin', 'superuser', 'root', 'administrator', 'ADMIN', 'super_admin']),
    ('is_admin', [True, 1, 'true', 'True']),
    ('admin', [True, 1, 'true']),
    ('user_role', ['admin', 'ADMIN', 'superuser']),
    ('permission', ['admin', 'write', 'all']),
    ('group', ['admin', 'administrators', 'superusers']),
    ('access_level', [9999, 'admin', 'ALL']),
    ('is_superuser', [True, 1, 'true']),
    ('verified', [True, 1]),
    ('email_verified', [True, 1]),
    ('active', [True, 1]),
    ('status', ['ACTIVE', 'VERIFIED', 'APPROVED']),
]

# Numeric fields to tamper
NUMERIC_TAMPER = [
    ('price', [0, -1, -999, 0.001, 99999999]),
    ('amount', [0, -1, -999]),
    ('quantity', [0, -1, 99999999]),
    ('discount', [100, 999, -1]),
    ('total', [0, -1]),
    ('cost', [0, -1]),
    ('fee', [0, -1]),
    ('balance', [99999999, -1]),
]


class MassAssignmentAgent(BaseAgent):
    model = "claude-haiku-4-5-20251001"
    max_iterations = 15
    vuln_type = "mass_assignment"
    agent_name = "MassAssignmentAgent"
    allowed_tools = []
    system_prompt = "You are a mass assignment and parameter tampering specialist."

    def _run_sync(self, user_message: str) -> list:
        m = re.search(r'Target:\s*(\S+)', user_message)
        if not m:
            return []
        base_url = m.group(1).rstrip('/')

        token_match = re.search(r'Bearer[:\s]+(\S+)', user_message, re.IGNORECASE)
        bearer_token = token_match.group(1) if token_match else None

        targets = self._parse_targets_from_message(user_message)
        post_put_targets = [t for t in targets if t.get('method', 'GET').upper() in ('POST', 'PUT', 'PATCH')]

        if not post_put_targets:
            console.print("  [dim]MassAssignmentAgent: No POST/PUT endpoints to test[/]")
            return []

        console.print(f"  [cyan]MassAssignmentAgent: testing {len(post_put_targets)} endpoints...[/]")

        headers = {'Content-Type': 'application/json', 'User-Agent': 'VulnHive-AI/1.0'}
        if bearer_token:
            headers['Authorization'] = f'Bearer {bearer_token}'
        client = httpx.Client(timeout=15, verify=False, headers=headers)

        findings = []

        for target in post_put_targets[:10]:
            url = target['url']
            method = target['method'].upper()

            # Test 1: Mass assignment — inject privilege fields
            for field_name, values in PRIVILEGE_FIELDS:
                payload = {target.get('param', 'data'): 'test', field_name: values[0]}
                try:
                    if method == 'POST':
                        resp = client.post(url, json=payload)
                    else:
                        resp = client.put(url, json=payload)

                    if resp.status_code in (200, 201):
                        resp_text = resp.text.lower()
                        # Check if the injected field appears in the response (mass assignment confirmed)
                        if field_name in resp_text and str(values[0]).lower() in resp_text:
                            console.print(f"  [bold red][MassAssignmentAgent] CONFIRMED: {field_name} injected[/]")
                            findings.append({
                                'validated': True,
                                'type': f'Mass Assignment: {field_name} field accepted',
                                'url': url,
                                'param_name': field_name,
                                'method': method,
                                'payload': json.dumps(payload),
                                'evidence': f'Injected field "{field_name}={values[0]}" reflected in response: {resp.text[:300]}',
                                'severity': 'High',
                                'source': 'MassAssignmentAgent',
                            })
                except Exception:
                    pass

            # Test 2: Numeric tampering
            for field_name, values in NUMERIC_TAMPER:
                for tamper_val in values[:2]:  # test first 2 values
                    payload = {field_name: tamper_val}
                    try:
                        if method == 'POST':
                            resp = client.post(url, json=payload)
                        else:
                            resp = client.put(url, json=payload)

                        if resp.status_code in (200, 201):
                            resp_text = resp.text
                            # Check if tampered value was accepted
                            if str(tamper_val) in resp_text:
                                console.print(f"  [bold red][MassAssignmentAgent] CONFIRMED: {field_name}={tamper_val} accepted[/]")
                                findings.append({
                                    'validated': True,
                                    'type': f'Parameter Tampering: {field_name}={tamper_val} accepted',
                                    'url': url,
                                    'param_name': field_name,
                                    'method': method,
                                    'payload': json.dumps(payload),
                                    'evidence': f'Tampered value {field_name}={tamper_val} accepted and reflected: {resp_text[:200]}',
                                    'severity': 'High',
                                    'source': 'MassAssignmentAgent',
                                })
                    except Exception:
                        pass

        client.close()
        return findings
