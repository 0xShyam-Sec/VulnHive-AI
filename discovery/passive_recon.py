"""Passive reconnaissance — headers, cookies, JWT, directory enumeration, WAF detection."""

import base64
import json
import re
from typing import Optional
from urllib.parse import urljoin

import httpx
from rich.console import Console

from engine.config import ScanConfig
from engine.scan_state import ScanState, Endpoint

console = Console()


def run_passive_recon(target: str, config: ScanConfig, state: ScanState):
    """
    Run passive reconnaissance on target.

    Gathers intelligence without active exploitation:
    - Security headers analysis
    - Cookie security analysis
    - JWT token analysis (if found)
    - Common path probing (40+ paths)
    - WAF detection
    """
    console.print(f"[cyan]Starting passive recon on {target}[/cyan]")

    # Create httpx client
    client = httpx.Client(
        timeout=10,
        follow_redirects=False,
        verify=False,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        },
    )

    try:
        # Probe main target
        try:
            resp = client.get(target)
            _analyze_headers(resp, target, state)
            _analyze_cookies(resp, target, state)
            _check_auth_tokens(resp, target, state)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not reach {target}: {e}[/yellow]")

        # Probe common paths
        _probe_common_paths(target, client, state)

        # Detect WAF
        _detect_waf(target, client, state)

        console.print(f"[green]Passive recon complete[/green]")

    finally:
        client.close()


def _analyze_headers(resp: httpx.Response, url: str, state: ScanState):
    """
    Analyze response headers for security misconfigurations.

    Checks for:
    - Missing security headers (X-Frame-Options, X-Content-Type-Options, etc.)
    - Information leakage headers (Server, X-Powered-By, etc.)
    - CSP with unsafe-inline/unsafe-eval
    - CORS with * and credentials
    """
    headers = resp.headers

    # Security headers that should be present
    security_headers = {
        "x-frame-options": "Clickjacking protection",
        "x-content-type-options": "MIME sniffing protection",
        "strict-transport-security": "HSTS enforcement",
        "content-security-policy": "XSS/injection protection",
        "referrer-policy": "Referrer leakage prevention",
        "permissions-policy": "Feature delegation control",
        "x-xss-protection": "Legacy XSS protection",
    }

    for header, description in security_headers.items():
        if header not in headers:
            finding = {
                "vuln_type": f"missing_security_header_{header.replace('-', '_')}",
                "url": url,
                "method": "GET",
                "param_name": "",
                "payload": "N/A (passive check)",
                "evidence": f"Missing security header: {header}. {description}.",
                "severity": "Medium",
                "source": "passive-recon",
                "validated": True,
            }
            state.add_finding(finding)

    # Information leakage headers
    info_headers = {
        "server": "Server software version",
        "x-powered-by": "Framework/technology",
        "x-aspnet-version": "ASP.NET version",
        "x-aspnetmvc-version": "ASP.NET MVC version",
    }

    for header, description in info_headers.items():
        if header in headers:
            value = headers.get(header, "")
            finding = {
                "vuln_type": "information_disclosure_header",
                "url": url,
                "method": "GET",
                "param_name": "",
                "payload": "N/A (passive check)",
                "evidence": f"Exposed header '{header}: {value}'. {description}.",
                "severity": "Low",
                "source": "passive-recon",
                "validated": True,
            }
            state.add_finding(finding)

    # Analyze CSP
    if "content-security-policy" in headers:
        csp = headers.get("content-security-policy", "")
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            finding = {
                "vuln_type": "weak_content_security_policy",
                "url": url,
                "method": "GET",
                "param_name": "",
                "payload": "N/A (passive check)",
                "evidence": f"CSP allows unsafe directives: {csp[:100]}...",
                "severity": "Medium",
                "source": "passive-recon",
                "validated": True,
            }
            state.add_finding(finding)

    # Analyze CORS
    cors_origin = headers.get("access-control-allow-origin", "")
    if cors_origin == "*":
        # Check if credentials are allowed
        allow_creds = headers.get("access-control-allow-credentials", "").lower() == "true"

        finding = {
            "vuln_type": "cors_misconfiguration",
            "url": url,
            "method": "GET",
            "param_name": "",
            "payload": "N/A (passive check)",
            "evidence": f"CORS allows any origin (*). Credentials allowed: {allow_creds}.",
            "severity": "High" if allow_creds else "Medium",
            "source": "passive-recon",
            "validated": True,
        }
        state.add_finding(finding)


def _analyze_cookies(resp: httpx.Response, url: str, state: ScanState):
    """
    Analyze Set-Cookie headers for security misconfigurations.

    Checks for:
    - Missing HttpOnly flag
    - Missing Secure flag
    - Missing SameSite attribute
    """
    set_cookie_headers = resp.headers.get_list("set-cookie")

    for cookie_header in set_cookie_headers:
        # Parse cookie name
        cookie_name = cookie_header.split("=")[0] if "=" in cookie_header else "unknown"

        has_httponly = "httponly" in cookie_header.lower()
        has_secure = "secure" in cookie_header.lower()
        has_samesite = "samesite" in cookie_header.lower()

        issues = []
        if not has_httponly:
            issues.append("missing HttpOnly")
        if not has_secure:
            issues.append("missing Secure")
        if not has_samesite:
            issues.append("missing SameSite")

        if issues:
            finding = {
                "vuln_type": "insecure_cookie_attributes",
                "url": url,
                "method": "GET",
                "param_name": f"cookie:{cookie_name}",
                "payload": "N/A (passive check)",
                "evidence": f"Cookie '{cookie_name}' has issues: {', '.join(issues)}.",
                "severity": "Medium",
                "source": "passive-recon",
                "validated": True,
            }
            state.add_finding(finding)


def _check_auth_tokens(resp: httpx.Response, url: str, state: ScanState):
    """
    Check for JWT tokens in response headers and cookies.

    Analyzes JWT token structure (header, payload, claims).
    """
    # Check Authorization header in response (uncommon but possible)
    auth_header = resp.headers.get("authorization", "")

    # Check Set-Cookie for auth tokens
    set_cookie_headers = resp.headers.get_list("set-cookie")
    for cookie_header in set_cookie_headers:
        if any(token_name in cookie_header.lower() for token_name in ["jwt", "token", "auth", "session"]):
            # Try to extract the token value
            parts = cookie_header.split("=", 1)
            if len(parts) == 2:
                token_value = parts[1].split(";")[0]
                _analyze_jwt(token_value, state, url)


def _analyze_jwt(token: str, state: ScanState, url: str):
    """
    Decode and analyze JWT token.

    Checks for:
    - Algorithm = "none" (Critical)
    - Algorithm = "HS256" (Medium - may be misused)
    - Weak claims
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return

        # Decode header
        header_pad = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_pad))

        # Decode payload
        payload_pad = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_pad))

        # Store in state
        state.auth_info["jwt"] = {
            "algorithm": header.get("alg"),
            "type": header.get("typ"),
            "claims": payload,
        }

        # Check for algorithm vulnerabilities
        alg = header.get("alg", "").lower()

        if alg == "none":
            finding = {
                "vuln_type": "jwt_algorithm_none",
                "url": url,
                "method": "GET",
                "param_name": "",
                "payload": "N/A (passive check)",
                "evidence": "JWT token uses 'none' algorithm, allowing unsigned tokens.",
                "severity": "Critical",
                "source": "passive-recon",
                "validated": True,
            }
            state.add_finding(finding)

        elif alg == "hs256":
            finding = {
                "vuln_type": "jwt_symmetric_algorithm",
                "url": url,
                "method": "GET",
                "param_name": "",
                "payload": "N/A (passive check)",
                "evidence": "JWT uses HS256 (HMAC). May be vulnerable to key confusion attacks.",
                "severity": "Medium",
                "source": "passive-recon",
                "validated": True,
            }
            state.add_finding(finding)

    except Exception:
        # Silent fail - JWT parsing errors are expected for non-JWT tokens
        pass


def _probe_common_paths(target: str, client: httpx.Client, state: ScanState):
    """
    Probe 40+ common paths for:
    - Sensitive file exposure (.env, .git, backup.sql, etc.)
    - Information disclosure (robots.txt, sitemap.xml, etc.)
    - Accessible admin interfaces
    - API endpoints and documentation
    """

    # Ensure target ends with protocol
    if not target.startswith("http"):
        target = f"http://{target}"

    # Extract base URL (scheme + netloc)
    parts = target.split("/")
    base_url = "/".join(parts[:3])

    paths = [
        "/.env",
        "/.git/config",
        "/.git/HEAD",
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/admin",
        "/api",
        "/api/docs",
        "/api/v1",
        "/swagger.json",
        "/openapi.json",
        "/graphql",
        "/graphiql",
        "/debug",
        "/debug.log",
        "/phpinfo.php",
        "/server-status",
        "/wp-admin",
        "/wp-login.php",
        "/backup.sql",
        "/db.sql",
        "/database.sql",
        "/.DS_Store",
        "/web.config",
        "/web.config.bak",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/beans",
        "/metrics",
        "/prometheus",
        "/console",
        "/h2-console",
        "/v1/api-docs",
        "/v2/api-docs",
        "/docs",
        "/api-docs",
        "/.htaccess",
        "/.htpasswd",
        "/config.php",
        "/admin.php",
        "/login.php",
        "/password.txt",
        "/.aws/credentials",
        "/.ssh/id_rsa",
    ]

    sensitive_files = {
        ".env", ".git", "backup.sql", "db.sql", "database.sql",
        ".DS_Store", "web.config", "config.php", "password.txt",
        "id_rsa", "credentials", "aws/credentials", ".htpasswd",
        "wp-config.php", "config.json", "secrets.json", "debug.log",
    }

    with console.status("[cyan]Probing common paths...[/cyan]"):
        for path in paths:
            url = urljoin(base_url, path)

            try:
                resp = client.get(url)

                # 200, 301, 302, 403 indicate path exists
                if resp.status_code in [200, 301, 302, 403]:
                    endpoint = Endpoint(
                        url=url,
                        method="GET",
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        tags={"discovered"},
                    )
                    state.add_endpoint(endpoint)

                    # Check if it's a sensitive file with 200 response
                    if resp.status_code == 200:
                        filename = path.split("/")[-1]

                        # Check if it's a sensitive file
                        is_sensitive = any(sensitive in filename for sensitive in sensitive_files)
                        is_sensitive = is_sensitive or any(sensitive in path for sensitive in sensitive_files)

                        if is_sensitive:
                            finding = {
                                "vuln_type": "sensitive_file_exposed",
                                "url": url,
                                "method": "GET",
                                "param_name": "",
                                "payload": "N/A (passive check)",
                                "evidence": f"Sensitive file accessible: {path} ({len(resp.text)} bytes).",
                                "severity": "High",
                                "source": "passive-recon",
                                "validated": True,
                            }
                            state.add_finding(finding)

            except Exception:
                # Connection errors, timeouts, etc. — skip
                pass


def _detect_waf(target: str, client: httpx.Client, state: ScanState):
    """
    Detect WAF by sending malicious-looking payloads and analyzing responses.

    Detects:
    - Cloudflare (cf-ray header)
    - AWS WAF (x-amzn-requestid + 403)
    - ModSecurity
    - Akamai
    - Generic 403 block
    """

    if not target.startswith("http"):
        target = f"http://{target}"

    # XSS payload to trigger WAF
    payload = "?test=<script>alert(1)</script>"
    url = target.rstrip("/") + "/" + payload.lstrip("/")

    try:
        resp = client.get(url)
        headers = resp.headers

        waf_detected = None
        waf_type = None

        # Cloudflare
        if "cf-ray" in headers:
            waf_detected = True
            waf_type = "Cloudflare"

        # AWS WAF
        elif "x-amzn-requestid" in headers and resp.status_code == 403:
            waf_detected = True
            waf_type = "AWS WAF"

        # ModSecurity
        elif resp.status_code == 403 and "modsecurity" in resp.text.lower():
            waf_detected = True
            waf_type = "ModSecurity"

        # Akamai
        elif "akamai" in headers.get("via", "").lower() or "akamai" in resp.text.lower():
            waf_detected = True
            waf_type = "Akamai"

        # Generic WAF
        elif resp.status_code == 403:
            waf_detected = True
            waf_type = "Generic WAF"

        if waf_detected:
            state.waf_info["detected"] = True
            state.waf_info["type"] = waf_type

            finding = {
                "vuln_type": "waf_detected",
                "url": target,
                "method": "GET",
                "param_name": "",
                "payload": "N/A (passive check)",
                "evidence": f"{waf_type} detected. Payloads may be blocked or modified.",
                "severity": "Info",
                "source": "passive-recon",
                "validated": True,
            }
            state.add_finding(finding)

            console.print(f"[yellow]WAF detected: {waf_type}[/yellow]")

    except Exception:
        # Connection errors, etc. — skip
        pass
