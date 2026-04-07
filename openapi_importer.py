"""
OpenAPI / Swagger Importer — Auto-discovers API specs and converts to test targets.

Probes common OpenAPI paths, parses both OpenAPI 2.0 (Swagger) and 3.0 specs,
and returns a flat list of {url, param, method} test targets for the vuln agents.

Usage:
    from openapi_importer import OpenAPIImporter
    importer = OpenAPIImporter("https://api.target.com", bearer_token="...")
    result = importer.run()
    # result = {
    #   "found": True,
    #   "spec_url": "https://api.target.com/swagger.json",
    #   "version": "2.0",
    #   "endpoints": [...],   # raw endpoint list
    #   "test_targets": [{"url": "...", "param": "...", "method": "..."}, ...],
    # }
"""

import httpx
from urllib.parse import urljoin
from rich.console import Console
from typing import Optional

console = Console()

SPEC_PATHS = [
    '/swagger.json',
    '/swagger.yaml',
    '/openapi.json',
    '/openapi.yaml',
    '/api-docs',
    '/api-docs.json',
    '/api/swagger.json',
    '/api/openapi.json',
    '/api/v1/swagger.json',
    '/api/v2/swagger.json',
    '/api/v3/swagger.json',
    '/v1/api-docs',
    '/v2/api-docs',
    '/v3/api-docs',
    '/docs/swagger.json',
    '/swagger/v1/swagger.json',
    '/swagger/v2/swagger.json',
    '/api/swagger-ui.html',
    '/swagger-ui.html',
    '/redoc',
    '/.well-known/openapi.json',
    '/graphql',       # GraphQL introspection endpoint
    '/graphiql',
]


class OpenAPIImporter:

    def __init__(self, base_url: str, bearer_token: Optional[str] = None,
                 cookies: Optional[dict] = None, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        headers = {'User-Agent': 'VulnHive-AI/1.0'}
        if bearer_token:
            headers['Authorization'] = f'Bearer {bearer_token}'
        self.client = httpx.Client(
            timeout=timeout, follow_redirects=True, verify=False,
            headers=headers, cookies=cookies or {},
        )

    def run(self) -> dict:
        """Discover OpenAPI spec and convert to test targets."""
        console.print(f"  [cyan]OpenAPI probe: {self.base_url}...[/]")

        spec_url, spec_data = self._discover_spec()
        if not spec_data:
            console.print("  [dim]No OpenAPI/Swagger spec found[/]")
            return {'found': False, 'endpoints': [], 'test_targets': []}

        console.print(f"  [green]Spec found: {spec_url}[/]")
        version = self._detect_version(spec_data)

        if version == '2.0':
            endpoints = self._parse_swagger2(spec_data, spec_url)
        else:
            endpoints = self._parse_openapi3(spec_data, spec_url)

        test_targets = self._to_test_targets(endpoints)
        console.print(f"  [bold]{len(endpoints)} endpoints, {len(test_targets)} test targets[/]")

        return {
            'found': True,
            'spec_url': spec_url,
            'version': version,
            'endpoints': endpoints,
            'test_targets': test_targets,
        }

    def _discover_spec(self):
        """Probe all known spec paths and return the first valid one."""
        for path in SPEC_PATHS:
            url = urljoin(self.base_url, path)
            try:
                resp = self.client.get(url)
                if resp.status_code != 200:
                    continue
                ct = resp.headers.get('content-type', '')
                # Try JSON
                if 'json' in ct or resp.text.strip().startswith('{'):
                    try:
                        data = resp.json()
                        if self._looks_like_spec(data):
                            return url, data
                    except Exception:
                        pass
                # Try YAML
                if 'yaml' in ct or path.endswith('.yaml'):
                    try:
                        import yaml
                        data = yaml.safe_load(resp.text)
                        if data and self._looks_like_spec(data):
                            return url, data
                    except ImportError:
                        pass
            except Exception:
                continue
        return None, None

    def _looks_like_spec(self, data: dict) -> bool:
        if not isinstance(data, dict):
            return False
        return (
            'swagger' in data or
            'openapi' in data or
            'paths' in data or
            'info' in data and 'paths' in data
        )

    def _detect_version(self, data: dict) -> str:
        if 'swagger' in data:
            return '2.0'
        openapi_ver = str(data.get('openapi', ''))
        if openapi_ver.startswith('3'):
            return '3.0'
        return '3.0'

    def _parse_swagger2(self, spec: dict, spec_url: str) -> list:
        """Parse OpenAPI 2.0 (Swagger) spec into endpoint list."""
        from urllib.parse import urlparse
        parsed = urlparse(spec_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        base_path = spec.get('basePath', '')
        endpoints = []

        for path, path_item in spec.get('paths', {}).items():
            if not isinstance(path_item, dict):
                continue
            for method, operation in path_item.items():
                if method.lower() not in ('get', 'post', 'put', 'delete', 'patch', 'options'):
                    continue
                if not isinstance(operation, dict):
                    continue

                full_path = base_path.rstrip('/') + path
                full_url = base + full_path
                params = self._extract_params_swagger2(operation, path)

                endpoints.append({
                    'url': full_url,
                    'path': full_path,
                    'method': method.upper(),
                    'params': params,
                    'summary': operation.get('summary', ''),
                    'requires_auth': bool(operation.get('security') or spec.get('security')),
                })

        return endpoints

    def _parse_openapi3(self, spec: dict, spec_url: str) -> list:
        """Parse OpenAPI 3.0 spec into endpoint list."""
        from urllib.parse import urlparse
        parsed = urlparse(spec_url)

        # Try servers list first, fall back to spec URL base
        servers = spec.get('servers', [])
        if servers and isinstance(servers[0], dict):
            base = servers[0].get('url', '').rstrip('/')
            if not base.startswith('http'):
                base = f"{parsed.scheme}://{parsed.netloc}{base}"
        else:
            base = f"{parsed.scheme}://{parsed.netloc}"

        endpoints = []
        for path, path_item in spec.get('paths', {}).items():
            if not isinstance(path_item, dict):
                continue
            for method, operation in path_item.items():
                if method.lower() not in ('get', 'post', 'put', 'delete', 'patch', 'options'):
                    continue
                if not isinstance(operation, dict):
                    continue

                full_url = base.rstrip('/') + path
                params = self._extract_params_openapi3(operation, path, spec)

                endpoints.append({
                    'url': full_url,
                    'path': path,
                    'method': method.upper(),
                    'params': params,
                    'summary': operation.get('summary', ''),
                    'requires_auth': bool(operation.get('security') or spec.get('security')),
                })

        return endpoints

    def _extract_params_swagger2(self, operation: dict, path: str) -> list:
        params = []
        # Path parameters
        for seg in path.split('/'):
            if seg.startswith('{') and seg.endswith('}'):
                params.append({'name': seg[1:-1], 'in': 'path', 'type': 'string'})
        # Operation parameters
        for p in operation.get('parameters', []):
            if isinstance(p, dict) and p.get('name'):
                params.append({
                    'name': p['name'],
                    'in': p.get('in', 'query'),
                    'type': p.get('type', 'string'),
                    'required': p.get('required', False),
                })
        return params

    def _extract_params_openapi3(self, operation: dict, path: str, spec: dict) -> list:
        params = []
        # Path parameters
        for seg in path.split('/'):
            if seg.startswith('{') and seg.endswith('}'):
                params.append({'name': seg[1:-1], 'in': 'path', 'type': 'string'})
        # Operation parameters
        for p in operation.get('parameters', []):
            if isinstance(p, dict):
                if '$ref' in p:
                    p = self._resolve_ref(p['$ref'], spec)
                if p and p.get('name'):
                    schema = p.get('schema', {})
                    params.append({
                        'name': p['name'],
                        'in': p.get('in', 'query'),
                        'type': schema.get('type', 'string') if schema else 'string',
                        'required': p.get('required', False),
                    })
        # Request body params
        req_body = operation.get('requestBody', {})
        if req_body:
            content = req_body.get('content', {})
            for ct, ct_data in content.items():
                schema = ct_data.get('schema', {})
                if '$ref' in schema:
                    schema = self._resolve_ref(schema['$ref'], spec) or {}
                for prop_name in schema.get('properties', {}).keys():
                    params.append({
                        'name': prop_name,
                        'in': 'body',
                        'type': 'string',
                        'required': prop_name in schema.get('required', []),
                    })
        return params

    def _resolve_ref(self, ref: str, spec: dict) -> dict:
        """Resolve a $ref pointer within the spec."""
        try:
            parts = ref.lstrip('#/').split('/')
            node = spec
            for part in parts:
                node = node[part]
            return node
        except (KeyError, TypeError):
            return {}

    def _to_test_targets(self, endpoints: list) -> list:
        """Convert endpoint list to flat {url, param, method} test targets."""
        targets = []
        seen = set()

        for ep in endpoints:
            url = ep['url']
            method = ep['method']

            # Replace path params with test values to make the URL concrete
            concrete_url = url
            for p in ep.get('params', []):
                if p['in'] == 'path':
                    concrete_url = concrete_url.replace(
                        '{' + p['name'] + '}', '1'
                    )

            # One target per query/body parameter
            params_added = False
            for p in ep.get('params', []):
                if p['in'] in ('query', 'body', 'formData'):
                    key = (concrete_url, p['name'], method)
                    if key not in seen:
                        seen.add(key)
                        targets.append({
                            'url': concrete_url,
                            'param': p['name'],
                            'method': method,
                            'source': 'openapi',
                        })
                        params_added = True

            # If no params, add endpoint itself with empty param for passive checks
            if not params_added:
                key = (concrete_url, '', method)
                if key not in seen:
                    seen.add(key)
                    targets.append({
                        'url': concrete_url,
                        'param': '',
                        'method': method,
                        'source': 'openapi',
                    })

        return targets

    def close(self):
        self.client.close()
