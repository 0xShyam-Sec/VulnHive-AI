"""
API Security Scanner — REST and GraphQL vulnerability testing.

Discovers and tests API endpoints that traditional HTML crawlers miss:
  - REST API endpoint discovery (common paths, OpenAPI/Swagger)
  - GraphQL introspection and injection testing
  - Authentication/authorization testing (broken access control)
  - Mass assignment testing
  - Rate limiting detection
  - HTTP method tampering
  - JSON injection
  - CORS misconfiguration
"""

import json
import re
import time
from typing import Optional
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx


@dataclass
class APIEndpoint:
    """A discovered API endpoint."""
    url: str
    method: str
    content_type: str = "application/json"
    params: list = field(default_factory=list)
    auth_required: bool = False
    description: str = ""


@dataclass
class APIFinding:
    """An API security finding."""
    vuln_type: str
    url: str
    method: str
    payload: str
    evidence: str
    severity: str
    details: dict = field(default_factory=dict)


class APIScanner:
    """
    Discovers and tests API endpoints for security vulnerabilities.

    Usage:
        scanner = APIScanner("http://target:3000", cookies={"token": "abc"})
        endpoints = scanner.discover_endpoints()
        findings = scanner.run_all_tests(endpoints)
    """

    def __init__(self, base_url: str, cookies: Optional[dict] = None,
                 headers: Optional[dict] = None, bearer_token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.cookies = cookies or {}
        self.headers = headers or {"Content-Type": "application/json"}
        if bearer_token:
            self.headers["Authorization"] = f"Bearer {bearer_token}"

        self.client = httpx.Client(
            timeout=15, follow_redirects=True, verify=False
        )
        self.no_auth_client = httpx.Client(
            timeout=15, follow_redirects=True, verify=False
        )

    def _request(self, method: str, url: str, auth: bool = True, **kwargs) -> httpx.Response:
        """Make an API request with optional auth."""
        req_headers = dict(self.headers)
        req_headers.update(kwargs.pop("headers", {}) or {})
        req_cookies = dict(self.cookies) if auth else {}
        req_cookies.update(kwargs.pop("cookies", {}) or {})

        # Remove auth header for unauthenticated requests
        if not auth:
            req_headers.pop("Authorization", None)

        return self.client.request(
            method=method, url=url,
            headers=req_headers, cookies=req_cookies,
            **kwargs
        )

    # ── Endpoint Discovery ────────────────────────────────────────

    def discover_endpoints(self) -> list:
        """
        Discover API endpoints using multiple methods:
        1. OpenAPI/Swagger spec parsing
        2. Common API path probing
        3. GraphQL endpoint detection
        """
        endpoints = []

        # Method 1: Try to find and parse OpenAPI/Swagger spec
        swagger_endpoints = self._find_openapi_spec()
        endpoints.extend(swagger_endpoints)

        # Method 2: Probe common API paths
        probed_endpoints = self._probe_common_paths()
        endpoints.extend(probed_endpoints)

        # Method 3: GraphQL introspection
        graphql_endpoints = self._find_graphql()
        endpoints.extend(graphql_endpoints)

        # Deduplicate
        seen = set()
        deduped = []
        for ep in endpoints:
            key = (ep.url, ep.method)
            if key not in seen:
                seen.add(key)
                deduped.append(ep)

        return deduped

    def _find_openapi_spec(self) -> list:
        """Try to find and parse OpenAPI/Swagger specification."""
        endpoints = []
        spec_paths = [
            "/swagger.json", "/api/swagger.json", "/v1/swagger.json",
            "/openapi.json", "/api/openapi.json",
            "/swagger/v1/swagger.json",
            "/api-docs", "/api-docs.json",
            "/docs/api.json", "/api/docs",
            "/.well-known/openapi.json",
        ]

        for path in spec_paths:
            try:
                url = self.base_url + path
                resp = self._request("GET", url)
                if resp.status_code != 200:
                    continue

                spec = resp.json()

                # Parse OpenAPI 3.x or Swagger 2.x
                paths = spec.get("paths", {})
                base_path = spec.get("basePath", "")
                servers = spec.get("servers", [])
                server_url = servers[0]["url"] if servers else ""

                for path_str, methods in paths.items():
                    full_path = base_path + path_str if base_path else path_str
                    if server_url:
                        ep_url = server_url.rstrip("/") + full_path
                    else:
                        ep_url = self.base_url + full_path

                    for method, details in methods.items():
                        if method.lower() in ("get", "post", "put", "delete", "patch"):
                            params = []
                            for param in details.get("parameters", []):
                                params.append(param.get("name", ""))

                            # Also extract request body params
                            req_body = details.get("requestBody", {})
                            content = req_body.get("content", {})
                            for ct, schema_info in content.items():
                                schema = schema_info.get("schema", {})
                                props = schema.get("properties", {})
                                params.extend(props.keys())

                            endpoints.append(APIEndpoint(
                                url=ep_url,
                                method=method.upper(),
                                params=params,
                                description=details.get("summary", ""),
                            ))

                break  # Found a spec, don't try more paths

            except (json.JSONDecodeError, KeyError, Exception):
                continue

        return endpoints

    def _probe_common_paths(self) -> list:
        """Probe common API paths to discover endpoints."""
        endpoints = []

        common_paths = [
            # REST API patterns
            ("/api", "GET"), ("/api/", "GET"),
            ("/api/v1", "GET"), ("/api/v2", "GET"),
            ("/api/users", "GET"), ("/api/user", "GET"),
            ("/api/me", "GET"), ("/api/profile", "GET"),
            ("/api/admin", "GET"), ("/api/config", "GET"),
            ("/api/settings", "GET"), ("/api/status", "GET"),
            ("/api/health", "GET"), ("/api/version", "GET"),
            ("/api/info", "GET"), ("/api/debug", "GET"),
            ("/api/products", "GET"), ("/api/items", "GET"),
            ("/api/orders", "GET"), ("/api/search", "GET"),
            ("/api/login", "POST"), ("/api/register", "POST"),
            ("/api/auth", "POST"), ("/api/token", "POST"),
            # Common REST resources
            ("/users", "GET"), ("/users/1", "GET"),
            ("/admin", "GET"), ("/admin/api", "GET"),
            ("/rest", "GET"), ("/rest/v1", "GET"),
            # Status/debug
            ("/health", "GET"), ("/status", "GET"),
            ("/metrics", "GET"), ("/debug", "GET"),
            ("/env", "GET"), ("/actuator", "GET"),
            ("/actuator/health", "GET"), ("/actuator/env", "GET"),
            ("/.env", "GET"), ("/config", "GET"),
        ]

        for path, method in common_paths:
            try:
                url = self.base_url + path
                resp = self._request(method, url)

                if resp.status_code in (200, 201, 401, 403):
                    content_type = resp.headers.get("content-type", "")

                    # Check if it returns JSON (likely an API)
                    is_api = "json" in content_type or "xml" in content_type

                    # Also check if it returns a short HTML error (might be API with HTML error)
                    if not is_api and resp.status_code in (401, 403):
                        is_api = True

                    if is_api or resp.status_code in (401, 403):
                        endpoints.append(APIEndpoint(
                            url=url,
                            method=method,
                            content_type=content_type,
                            auth_required=resp.status_code in (401, 403),
                            description=f"Discovered via probing (status {resp.status_code})",
                        ))

            except Exception:
                continue

        return endpoints

    def _find_graphql(self) -> list:
        """Discover GraphQL endpoints and extract schema via introspection."""
        endpoints = []
        graphql_paths = [
            "/graphql", "/graphiql", "/api/graphql",
            "/v1/graphql", "/query", "/gql",
        ]

        introspection_query = {
            "query": '{ __schema { types { name fields { name type { name } } } } }'
        }

        for path in graphql_paths:
            try:
                url = self.base_url + path
                resp = self._request("POST", url, json=introspection_query)

                if resp.status_code == 200:
                    data = resp.json()
                    if "data" in data and "__schema" in data.get("data", {}):
                        # GraphQL endpoint found with introspection enabled
                        types = data["data"]["__schema"].get("types", [])
                        for t in types:
                            if not t["name"].startswith("__"):
                                fields = [f["name"] for f in (t.get("fields") or [])]
                                if fields:
                                    endpoints.append(APIEndpoint(
                                        url=url,
                                        method="POST",
                                        content_type="application/json",
                                        params=fields,
                                        description=f"GraphQL type: {t['name']}",
                                    ))
                        break

            except Exception:
                continue

        return endpoints

    # ── Vulnerability Tests ───────────────────────────────────────

    def test_broken_auth(self, endpoints: list) -> list:
        """
        Test for Broken Authentication / Broken Access Control:
        - Access authenticated endpoints without auth
        - Access admin endpoints with user-level auth
        """
        findings = []

        for ep in endpoints:
            try:
                # Test 1: Access without authentication
                resp_no_auth = self._request(ep.method, ep.url, auth=False)

                if resp_no_auth.status_code == 200:
                    # Should this endpoint require auth?
                    sensitive_keywords = ["user", "admin", "profile", "account",
                                         "setting", "order", "private", "secret",
                                         "config", "me", "dashboard"]
                    is_sensitive = any(k in ep.url.lower() for k in sensitive_keywords)

                    if is_sensitive:
                        # Verify it returns real data (not an error page)
                        try:
                            body = resp_no_auth.json()
                            if body and not isinstance(body, str):
                                findings.append(APIFinding(
                                    vuln_type="Broken Access Control",
                                    url=ep.url,
                                    method=ep.method,
                                    payload="Request without authentication",
                                    evidence=f"Endpoint returns data without auth (status 200, {len(resp_no_auth.text)} bytes)",
                                    severity="High",
                                ))
                        except json.JSONDecodeError:
                            pass

            except Exception:
                continue

        return findings

    def test_method_tampering(self, endpoints: list) -> list:
        """
        Test HTTP method tampering — try unexpected methods that might
        bypass authorization or reveal hidden functionality.
        """
        findings = []
        test_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

        for ep in endpoints:
            try:
                # Try methods that weren't intended for this endpoint
                for method in test_methods:
                    if method == ep.method:
                        continue

                    resp = self._request(method, ep.url)

                    # If a different method returns 200 with data, might be an issue
                    if resp.status_code == 200 and len(resp.text) > 50:
                        # Especially interesting for state-changing methods on GET endpoints
                        if ep.method == "GET" and method in ("PUT", "DELETE", "PATCH"):
                            findings.append(APIFinding(
                                vuln_type="HTTP Method Tampering",
                                url=ep.url,
                                method=method,
                                payload=f"{method} request to {ep.method}-only endpoint",
                                evidence=f"{method} returns 200 ({len(resp.text)} bytes) on endpoint intended for {ep.method}",
                                severity="Medium",
                            ))
                            break

                    # OPTIONS revealing allowed methods
                    if method == "OPTIONS" and resp.status_code == 200:
                        allow = resp.headers.get("allow", resp.headers.get("access-control-allow-methods", ""))
                        if allow and ("PUT" in allow or "DELETE" in allow):
                            findings.append(APIFinding(
                                vuln_type="Verbose OPTIONS Response",
                                url=ep.url,
                                method="OPTIONS",
                                payload="OPTIONS request",
                                evidence=f"Allowed methods: {allow}",
                                severity="Low",
                                details={"allowed_methods": allow},
                            ))

            except Exception:
                continue

        return findings

    def test_cors_misconfiguration(self) -> list:
        """Test for CORS misconfiguration that could allow cross-origin attacks."""
        findings = []

        test_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            "null",
        ]

        test_urls = [self.base_url + "/", self.base_url + "/api/"]

        for url in test_urls:
            for origin in test_origins:
                try:
                    resp = self._request("GET", url,
                                         headers={"Origin": origin})

                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "")

                    if acao == origin or acao == "*":
                        severity = "High" if acac.lower() == "true" else "Medium"
                        findings.append(APIFinding(
                            vuln_type="CORS Misconfiguration",
                            url=url,
                            method="GET",
                            payload=f"Origin: {origin}",
                            evidence=f"Server reflects origin: ACAO={acao}, ACAC={acac}",
                            severity=severity,
                            details={
                                "access-control-allow-origin": acao,
                                "access-control-allow-credentials": acac,
                            },
                        ))
                        break  # One finding per URL is enough

                except Exception:
                    continue

        return findings

    def test_json_injection(self, endpoints: list) -> list:
        """Test JSON-based endpoints for injection vulnerabilities."""
        findings = []

        sqli_payloads = [
            {"test": "' OR '1'='1"},
            {"test": "1; DROP TABLE users--"},
            {"id": "1 UNION SELECT * FROM users"},
        ]

        nosql_payloads = [
            {"$gt": ""},
            {"$ne": ""},
            {"$where": "1==1"},
        ]

        for ep in endpoints:
            if ep.method not in ("POST", "PUT", "PATCH"):
                continue

            # Test SQL injection via JSON
            for payload in sqli_payloads:
                try:
                    resp = self._request(ep.method, ep.url, json=payload)
                    error_patterns = [
                        r"SQL syntax", r"mysql", r"postgresql",
                        r"sqlite", r"ORA-\d+", r"SQLSTATE",
                    ]
                    for pattern in error_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            findings.append(APIFinding(
                                vuln_type="SQL Injection (API/JSON)",
                                url=ep.url,
                                method=ep.method,
                                payload=json.dumps(payload),
                                evidence=f"SQL error pattern matched: {pattern}",
                                severity="Critical",
                            ))
                            break
                except Exception:
                    continue

            # Test NoSQL injection
            for payload in nosql_payloads:
                try:
                    # Wrap in a typical query structure
                    body = {"username": payload, "password": "test"}
                    resp = self._request(ep.method, ep.url, json=body)

                    if resp.status_code == 200 and len(resp.text) > 100:
                        try:
                            data = resp.json()
                            if data and "error" not in str(data).lower():
                                findings.append(APIFinding(
                                    vuln_type="NoSQL Injection",
                                    url=ep.url,
                                    method=ep.method,
                                    payload=json.dumps(body),
                                    evidence=f"Server returned data with NoSQL operator payload (status {resp.status_code})",
                                    severity="Critical",
                                ))
                                break
                        except json.JSONDecodeError:
                            pass
                except Exception:
                    continue

        return findings

    def test_mass_assignment(self, endpoints: list) -> list:
        """
        Test for mass assignment — send extra fields that shouldn't be
        user-controllable (role, admin, isAdmin, etc.)
        """
        findings = []
        extra_fields = {
            "role": "admin",
            "isAdmin": True,
            "admin": True,
            "is_staff": True,
            "privilege": "admin",
            "permissions": ["*"],
            "verified": True,
            "active": True,
        }

        for ep in endpoints:
            if ep.method not in ("POST", "PUT", "PATCH"):
                continue

            try:
                # Build a normal-looking request with extra fields
                body = dict(extra_fields)
                # Add some normal fields
                for param in ep.params[:3]:
                    body[param] = "test"

                resp = self._request(ep.method, ep.url, json=body)

                if resp.status_code in (200, 201):
                    try:
                        data = resp.json()
                        # Check if any of our extra fields were reflected back
                        data_str = json.dumps(data).lower()
                        for field_name in extra_fields:
                            if field_name.lower() in data_str:
                                findings.append(APIFinding(
                                    vuln_type="Mass Assignment",
                                    url=ep.url,
                                    method=ep.method,
                                    payload=json.dumps(body),
                                    evidence=f"Field '{field_name}' accepted and reflected in response",
                                    severity="High",
                                ))
                                break
                    except json.JSONDecodeError:
                        pass

            except Exception:
                continue

        return findings

    def test_rate_limiting(self, url: Optional[str] = None) -> list:
        """Test if the API has rate limiting in place."""
        findings = []
        test_url = url or self.base_url + "/api/login"

        try:
            # Send 20 rapid requests
            statuses = []
            for _ in range(20):
                resp = self._request("POST", test_url,
                                     json={"username": "test", "password": "test"})
                statuses.append(resp.status_code)

            # If all return the same status (no 429), rate limiting may be absent
            if 429 not in statuses and len(set(statuses)) <= 2:
                findings.append(APIFinding(
                    vuln_type="Missing Rate Limiting",
                    url=test_url,
                    method="POST",
                    payload="20 rapid requests",
                    evidence=f"No 429 response after 20 rapid requests. Statuses: {set(statuses)}",
                    severity="Medium",
                ))

        except Exception:
            pass

        return findings

    def test_info_disclosure(self, endpoints: list) -> list:
        """Test for information disclosure in API responses."""
        findings = []

        # Check for debug/error info in responses
        for ep in endpoints:
            try:
                resp = self._request(ep.method, ep.url)
                text = resp.text

                checks = [
                    (r"stack\s*trace", "Stack trace exposed"),
                    (r"\"password\"\s*:", "Password field in response"),
                    (r"\"secret\"\s*:", "Secret field in response"),
                    (r"\"api[_-]?key\"\s*:", "API key in response"),
                    (r"\"private[_-]?key\"\s*:", "Private key in response"),
                    (r"\"token\"\s*:\s*\"eyJ", "JWT token in response"),
                    (r"\"debug\"\s*:\s*true", "Debug mode enabled"),
                    (r"internal[_-]?ip|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+", "Internal IP/info leaked"),
                ]

                for pattern, description in checks:
                    if re.search(pattern, text, re.IGNORECASE):
                        findings.append(APIFinding(
                            vuln_type="API Information Disclosure",
                            url=ep.url,
                            method=ep.method,
                            payload="N/A (passive check)",
                            evidence=description,
                            severity="Medium",
                        ))
                        break  # One finding per endpoint

            except Exception:
                continue

        return findings

    # ── Run All Tests ─────────────────────────────────────────────

    def run_all_tests(self, endpoints: Optional[list] = None) -> list:
        """
        Run all API security tests.

        Args:
            endpoints: List of APIEndpoint objects. If None, discovers them first.

        Returns:
            List of APIFinding objects.
        """
        if endpoints is None:
            endpoints = self.discover_endpoints()

        all_findings = []

        if not endpoints:
            return all_findings

        # Run each test category
        tests = [
            ("Broken Auth/Access Control", lambda: self.test_broken_auth(endpoints)),
            ("HTTP Method Tampering", lambda: self.test_method_tampering(endpoints)),
            ("CORS Misconfiguration", lambda: self.test_cors_misconfiguration()),
            ("JSON Injection", lambda: self.test_json_injection(endpoints)),
            ("Mass Assignment", lambda: self.test_mass_assignment(endpoints)),
            ("Rate Limiting", lambda: self.test_rate_limiting()),
            ("Information Disclosure", lambda: self.test_info_disclosure(endpoints)),
        ]

        for name, test_func in tests:
            try:
                results = test_func()
                all_findings.extend(results)
            except Exception:
                continue

        return all_findings
