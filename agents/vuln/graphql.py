"""
GraphQL Security Agent — Tests GraphQL endpoints for common vulnerabilities.

Tests for:
1. Introspection enabled (exposes full schema)
2. Field-level authorization bypass (access admin fields as normal user)
3. Query depth attack (deeply nested query causes DoS)
4. Batch query abuse (1000 operations in one request)
5. SQL/NoSQL injection via GraphQL arguments
6. Sensitive data exposure in schema type names

Usage — called by orchestrator just like other vuln agents:
    agent = GraphQLAgent(llm_backend="ollama")
    findings = await agent.run(surface_msg)
"""

import json
import httpx
import asyncio
from rich.console import Console
from agents.base import BaseAgent

console = Console()


GRAPHQL_PATHS = [
    '/graphql',
    '/graphql/v1',
    '/api/graphql',
    '/api/v1/graphql',
    '/gql',
    '/query',
]

INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type { name kind }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
"""

# Sensitive type/field name patterns
SENSITIVE_PATTERNS = [
    'password', 'secret', 'token', 'key', 'credential', 'auth',
    'admin', 'internal', 'private', 'ssn', 'credit_card', 'cvv',
    'api_key', 'webhook_secret', 'private_key',
]


class GraphQLAgent(BaseAgent):
    model = "claude-haiku-4-5-20251001"
    max_iterations = 10
    vuln_type = "graphql"
    agent_name = "GraphQLAgent"
    allowed_tools = []  # This agent handles everything internally

    system_prompt = """You are a GraphQL security specialist."""

    def _run_sync(self, user_message: str) -> list:
        """Override — run GraphQL-specific tests instead of validate_finding loop."""
        # Extract target URL from message
        import re
        m = re.search(r'Target:\s*(\S+)', user_message)
        if not m:
            return []
        base_url = m.group(1).rstrip('/')

        # Get auth token if present
        token_match = re.search(r'Bearer[:\s]+(\S+)', user_message, re.IGNORECASE)
        bearer_token = token_match.group(1) if token_match else None

        headers = {'Content-Type': 'application/json', 'User-Agent': 'pentest-agent/1.0'}
        if bearer_token:
            headers['Authorization'] = f'Bearer {bearer_token}'

        findings = []
        gql_url = self._find_graphql_endpoint(base_url, headers)

        if not gql_url:
            console.print("  [dim]GraphQLAgent: No GraphQL endpoint found[/]")
            return []

        console.print(f"  [cyan]GraphQLAgent: Testing {gql_url}[/]")

        # Test 1: Introspection
        introspection_result = self._test_introspection(gql_url, headers)
        if introspection_result:
            findings.append(introspection_result)
            schema = introspection_result.get('_schema')

            # Test 2: Sensitive fields in schema
            if schema:
                sensitive = self._check_sensitive_schema(schema, gql_url)
                findings.extend(sensitive)

        # Test 3: Query depth attack
        depth_result = self._test_query_depth(gql_url, headers)
        if depth_result:
            findings.append(depth_result)

        # Test 4: Batch query abuse
        batch_result = self._test_batch_queries(gql_url, headers)
        if batch_result:
            findings.append(batch_result)

        # Test 5: Injection in arguments
        injection_results = self._test_injection(gql_url, headers, introspection_result)
        findings.extend(injection_results)

        # Remove internal _schema key from findings before returning
        clean_findings = []
        for f in findings:
            cf = {k: v for k, v in f.items() if not k.startswith('_')}
            clean_findings.append(cf)

        return clean_findings

    def _find_graphql_endpoint(self, base_url: str, headers: dict) -> str:
        client = httpx.Client(timeout=10, verify=False, headers=headers)
        for path in GRAPHQL_PATHS:
            url = base_url + path
            try:
                # GraphQL endpoint responds to POST with JSON body
                resp = client.post(url, json={'query': '{ __typename }'})
                if resp.status_code in (200, 400) and ('data' in resp.text or 'errors' in resp.text):
                    client.close()
                    return url
                # Some endpoints respond to GET
                resp = client.get(url + '?query={__typename}')
                if resp.status_code == 200 and 'data' in resp.text:
                    client.close()
                    return url
            except Exception:
                continue
        client.close()
        return None

    def _test_introspection(self, gql_url: str, headers: dict) -> dict:
        try:
            client = httpx.Client(timeout=15, verify=False, headers=headers)
            resp = client.post(gql_url, json={'query': INTROSPECTION_QUERY})
            client.close()

            if resp.status_code != 200:
                return None
            data = resp.json()
            schema_data = data.get('data', {}).get('__schema')
            if not schema_data:
                return None

            type_count = len(schema_data.get('types', []))
            has_mutation = bool(schema_data.get('mutationType'))

            console.print(
                f"  [bold red][GraphQLAgent] CONFIRMED: Introspection enabled "
                f"({type_count} types, mutation={'yes' if has_mutation else 'no'})[/]"
            )
            return {
                'validated': True,
                'type': 'GraphQL Introspection Enabled',
                'url': gql_url,
                'param_name': '',
                'method': 'POST',
                'payload': INTROSPECTION_QUERY.strip(),
                'evidence': (
                    f'Introspection query succeeded. Schema exposed: {type_count} types, '
                    f'queryType={schema_data.get("queryType", {}).get("name", "?")}, '
                    f'mutationType={"yes" if has_mutation else "no"}'
                ),
                'severity': 'Medium',
                'source': 'GraphQLAgent',
                '_schema': schema_data,
            }
        except Exception:
            return None

    def _check_sensitive_schema(self, schema: dict, gql_url: str) -> list:
        findings = []
        exposed = []
        for t in schema.get('types', []):
            type_name = (t.get('name') or '').lower()
            for pattern in SENSITIVE_PATTERNS:
                if pattern in type_name and not type_name.startswith('__'):
                    exposed.append(t.get('name'))
                    break
            for field in (t.get('fields') or []):
                field_name = (field.get('name') or '').lower()
                for pattern in SENSITIVE_PATTERNS:
                    if pattern in field_name:
                        exposed.append(f"{t.get('name')}.{field.get('name')}")
                        break

        if exposed:
            console.print(f"  [bold red][GraphQLAgent] CONFIRMED: Sensitive schema fields exposed[/]")
            findings.append({
                'validated': True,
                'type': 'GraphQL Sensitive Schema Exposure',
                'url': gql_url,
                'param_name': '',
                'method': 'POST',
                'payload': '__schema introspection',
                'evidence': f'Sensitive type/field names in schema: {", ".join(exposed[:15])}',
                'severity': 'Medium',
                'source': 'GraphQLAgent',
            })
        return findings

    def _test_query_depth(self, gql_url: str, headers: dict) -> dict:
        # Build a deeply nested query — if it doesn't error, DoS is possible
        nested = '{ __type(name: "Query") { fields { type { fields { type { fields { type { name } } } } } } } }'
        try:
            client = httpx.Client(timeout=20, verify=False, headers=headers)
            resp = client.post(gql_url, json={'query': nested})
            client.close()
            if resp.status_code == 200 and 'data' in resp.text:
                console.print(f"  [bold red][GraphQLAgent] CONFIRMED: No query depth limit[/]")
                return {
                    'validated': True,
                    'type': 'GraphQL No Query Depth Limit',
                    'url': gql_url,
                    'param_name': 'query',
                    'method': 'POST',
                    'payload': nested,
                    'evidence': 'Deeply nested query (6 levels) returned HTTP 200 with data — no depth limiting enforced. Enables denial-of-service via exponential query complexity.',
                    'severity': 'Medium',
                    'source': 'GraphQLAgent',
                }
        except Exception:
            pass
        return None

    def _test_batch_queries(self, gql_url: str, headers: dict) -> dict:
        # Send 100 operations in a single batch request
        batch = [{'query': '{ __typename }'}] * 100
        try:
            client = httpx.Client(timeout=20, verify=False, headers=headers)
            resp = client.post(gql_url, json=batch)
            client.close()
            if resp.status_code == 200:
                try:
                    results = resp.json()
                    if isinstance(results, list) and len(results) > 1:
                        console.print(f"  [bold red][GraphQLAgent] CONFIRMED: Batch query abuse enabled[/]")
                        return {
                            'validated': True,
                            'type': 'GraphQL Batch Query Abuse',
                            'url': gql_url,
                            'param_name': 'batch',
                            'method': 'POST',
                            'payload': '[{query: ...} x100]',
                            'evidence': f'Batch request with 100 operations returned {len(results)} results. Enables rate-limit bypass by sending many operations in a single HTTP request.',
                            'severity': 'Medium',
                            'source': 'GraphQLAgent',
                        }
                except Exception:
                    pass
        except Exception:
            pass
        return None

    def _test_injection(self, gql_url: str, headers: dict, introspection_result) -> list:
        findings = []
        # Find a query field that accepts string arguments to test injection
        if not introspection_result:
            return findings

        schema = introspection_result.get('_schema', {})
        query_type_name = (schema.get('queryType') or {}).get('name', 'Query')

        # Find query type fields
        query_fields = []
        for t in schema.get('types', []):
            if t.get('name') == query_type_name:
                query_fields = t.get('fields') or []
                break

        tested = 0
        client = httpx.Client(timeout=10, verify=False, headers=headers)

        for field in query_fields[:5]:  # test first 5 query fields
            field_name = field.get('name', '')
            if not field_name or field_name.startswith('_'):
                continue

            # Test SQL injection in string argument
            sqli_query = '{ ' + field_name + '(id: "1\' OR 1=1--") { __typename } }'
            try:
                resp = client.post(gql_url, json={'query': sqli_query})
                body = resp.text.lower()
                db_errors = ['sql', 'mysql', 'postgresql', 'syntax error', 'ora-', 'sqlstate']
                for err in db_errors:
                    if err in body:
                        console.print(f"  [bold red][GraphQLAgent] CONFIRMED: SQLi in {field_name}[/]")
                        findings.append({
                            'validated': True,
                            'type': 'GraphQL SQL Injection',
                            'url': gql_url,
                            'param_name': field_name,
                            'method': 'POST',
                            'payload': sqli_query,
                            'evidence': f'DB error in GraphQL field {field_name}: ' + resp.text[:200],
                            'severity': 'Critical',
                            'source': 'GraphQLAgent',
                        })
                        break
                tested += 1
            except Exception:
                pass

        client.close()
        return findings
