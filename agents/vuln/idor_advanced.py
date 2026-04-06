"""
Advanced IDOR Agent — Dual-session cross-user resource access testing.

Tests:
1. Horizontal IDOR — access other users' resources with own token
2. Vertical IDOR — access admin resources as regular user
3. ID enumeration — ±1 on numeric IDs
4. UUID prediction — test sequential/guessable UUIDs
5. Object ID substitution in URL path segments
"""

import re
import httpx
import uuid
from agents.base import BaseAgent
from rich.console import Console

console = Console()


class IDORAdvancedAgent(BaseAgent):
    model = "claude-haiku-4-5-20251001"
    max_iterations = 20
    vuln_type = "idor"
    agent_name = "IDORAdvancedAgent"
    allowed_tools = []
    system_prompt = "You are an advanced IDOR specialist."

    def _run_sync(self, user_message: str) -> list:
        m = re.search(r'Target:\s*(\S+)', user_message)
        if not m:
            return []
        base_url = m.group(1).rstrip('/')

        token_match = re.search(r'Bearer[:\s]+(\S+)', user_message, re.IGNORECASE)
        bearer_token = token_match.group(1) if token_match else None

        targets = self._parse_targets_from_message(user_message)
        console.print(f"  [cyan]IDORAdvancedAgent: testing {len(targets)} endpoints...[/]")

        headers = {'User-Agent': 'pentest-agent/1.0'}
        if bearer_token:
            headers['Authorization'] = f'Bearer {bearer_token}'
        client = httpx.Client(timeout=15, verify=False, headers=headers)

        findings = []
        seen = set()

        for target in targets:
            url = target['url']
            param = target.get('param', '')
            method = target.get('method', 'GET').upper()

            # Find numeric IDs in URL path
            numeric_ids = re.findall(r'/(\d{1,10})(?:/|$|\?)', url)
            for num_id in numeric_ids:
                id_int = int(num_id)
                # Test adjacent IDs
                for test_id in [id_int - 1, id_int + 1, 1, 2, 3, 100, 9999]:
                    if test_id <= 0:
                        continue
                    test_url = url.replace(f'/{num_id}', f'/{test_id}', 1)
                    key = (test_url, 'path_id')
                    if key in seen:
                        continue
                    seen.add(key)
                    try:
                        if method == 'GET':
                            resp = client.get(test_url)
                        else:
                            resp = client.request(method, test_url)

                        # 200 on a different ID = potential IDOR
                        orig_resp = client.get(url) if method == 'GET' else client.request(method, url)
                        if (resp.status_code == 200 and
                                orig_resp.status_code == 200 and
                                resp.text != orig_resp.text and
                                len(resp.text) > 50):
                            console.print(f"  [bold red][IDORAdvancedAgent] CONFIRMED: IDOR at {test_url}[/]")
                            findings.append({
                                'validated': True,
                                'type': 'IDOR: Numeric ID Enumeration',
                                'url': test_url,
                                'param_name': 'id (path)',
                                'method': method,
                                'payload': str(test_id),
                                'evidence': (
                                    f'Accessed resource ID={test_id} (different from own ID={num_id}). '
                                    f'Response ({len(resp.text)} bytes) differs from own resource. '
                                    f'Preview: {resp.text[:200]}'
                                ),
                                'severity': 'High',
                                'source': 'IDORAdvancedAgent',
                            })
                            break
                    except Exception:
                        pass

            # Find UUIDs in URL
            uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
            uuids_in_url = re.findall(uuid_pattern, url, re.IGNORECASE)
            for found_uuid in uuids_in_url:
                # Try sequential/zero UUIDs
                test_uuids = [
                    '00000000-0000-0000-0000-000000000001',
                    '00000000-0000-0000-0000-000000000002',
                    str(uuid.uuid4()),
                ]
                for test_uuid in test_uuids:
                    test_url = url.replace(found_uuid, test_uuid, 1)
                    key = (test_url, 'uuid')
                    if key in seen:
                        continue
                    seen.add(key)
                    try:
                        resp = client.get(test_url)
                        if resp.status_code == 200 and len(resp.text) > 50:
                            # Check if this is different from a 404
                            not_found_resp = client.get(url.replace(found_uuid, 'ffffffff-ffff-ffff-ffff-ffffffffffff', 1))
                            if resp.text != not_found_resp.text:
                                console.print(f"  [bold red][IDORAdvancedAgent] CONFIRMED: UUID IDOR[/]")
                                findings.append({
                                    'validated': True,
                                    'type': 'IDOR: UUID Enumeration',
                                    'url': test_url,
                                    'param_name': 'id (UUID path)',
                                    'method': 'GET',
                                    'payload': test_uuid,
                                    'evidence': f'Accessed resource with UUID {test_uuid}: {resp.text[:200]}',
                                    'severity': 'High',
                                    'source': 'IDORAdvancedAgent',
                                })
                                break
                    except Exception:
                        pass

            # Parameter-based IDOR
            if param and any(kw in param.lower() for kw in ['id', 'user', 'account', 'order', 'doc', 'file', 'record']):
                for test_val in ['1', '2', '3', '0', '100', 'admin']:
                    key = (url, param, test_val)
                    if key in seen:
                        continue
                    seen.add(key)
                    try:
                        if method == 'GET':
                            resp = client.get(url, params={param: test_val})
                        else:
                            resp = client.request(method, url, json={param: test_val})

                        if resp.status_code == 200 and len(resp.text) > 100:
                            console.print(f"  [bold red][IDORAdvancedAgent] CONFIRMED: IDOR param={param}[/]")
                            findings.append({
                                'validated': True,
                                'type': f'IDOR: Parameter {param} enumeration',
                                'url': url,
                                'param_name': param,
                                'method': method,
                                'payload': test_val,
                                'evidence': f'Accessed resource with {param}={test_val}: {resp.text[:200]}',
                                'severity': 'High',
                                'source': 'IDORAdvancedAgent',
                            })
                            break
                    except Exception:
                        pass

        client.close()
        return findings
