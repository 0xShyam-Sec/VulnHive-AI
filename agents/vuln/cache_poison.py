"""
CachePoisonAgent — Tests for cache poisoning vulnerabilities via unkeyed header injection.

Vulnerability: Cache Poisoning
- Attacker injects headers that servers cache but don't include in cache keys
- Cached responses returned to other users with injected content
- Can lead to malicious redirects, XSS, malware distribution

Detection strategy:
1. Detect caching — check response headers for Age, X-Cache, X-Cache-Hit, etc.
2. Unkeyed header injection — inject headers that might bypass cache keys
   - X-Forwarded-Host: evil.com (check if reflected in response)
   - X-Original-URL: /injected (check if server processes different URL)
   - X-Forwarded-Scheme: nothttps (check for protocol manipulation)
   - X-Forwarded-Proto: http (redirect manipulation)
3. Verify cache storage — send clean request without injected header
   - If poisoned content appears → cache poisoning confirmed (Critical)
4. Parameter cloaking — try XSS in parameters that caches might strip

Evidence tracked: which header caused injection, what was reflected/cached
Severity: Critical if confirmed cached, High if reflected but unconfirmed
"""

import uuid
import httpx
from urllib.parse import urlparse, urljoin
from rich.console import Console

from agents.base import BaseAgent

console = Console()

REQUEST_TIMEOUT = 10

# Cache detection headers — check if any of these are present
CACHE_HEADERS = [
    "Age",
    "X-Cache",
    "X-Cache-Hit",
    "CF-Cache-Status",
    "X-Varnish",
    "X-Drupal-Cache",
    "X-Proxy-Cache",
]

# Unkeyed header candidates for injection
UNKEYED_HEADERS = [
    ("X-Forwarded-Host", "evil.com"),
    ("X-Original-URL", "/injected"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Forwarded-Proto", "http"),
]


def _is_cache_detected(response_headers: dict) -> bool:
    """Check if response headers indicate caching is enabled."""
    for header in CACHE_HEADERS:
        if header in response_headers:
            return True
    return False


def _make_finding(
    url: str,
    method: str,
    evidence: str,
    severity: str = "Critical",
    param_name: str = "",
) -> dict:
    """Create a cache poisoning finding."""
    return {
        "vuln_type": "cache_poison",
        "url": url,
        "method": method,
        "param_name": param_name,
        "payload": "Unkeyed header injection / cache poisoning",
        "evidence": evidence,
        "severity": severity,
        "source": "CachePoisonAgent",
        "validated": True,
    }


class CachePoisonAgent(BaseAgent):
    model = "claude-haiku-4-5-20251001"
    max_iterations = 10
    vuln_type = "cache_poison"
    agent_name = "CachePoisonAgent"
    allowed_tools = []

    system_prompt = """\
You are a cache poisoning specialist. Test ONLY for cache poisoning vulnerabilities
via unkeyed header injection. Focus on detecting when servers cache responses
without including certain headers in the cache key, allowing attackers to inject
malicious content that gets served to other users."""

    def _deterministic_test(self, endpoint, config, state) -> list:
        """
        Test endpoint for cache poisoning via unkeyed header injection.

        1. Detect if caching is enabled (check response headers)
        2. Try unkeyed header injection (X-Forwarded-Host, X-Original-URL, etc.)
        3. Verify cache poisoning by requesting without the injected header
        4. Try parameter cloaking with XSS payloads

        Args:
            endpoint: Endpoint object with url, method, params
            config: ScanConfig object with auth headers, cookies
            state: ScanState object

        Returns:
            List of finding dicts for confirmed cache poisoning vulnerabilities.
        """
        findings = []
        url = endpoint.url
        method = endpoint.method or "GET"

        # Only test GET/HEAD endpoints (caching is most relevant here)
        if method not in ["GET", "HEAD"]:
            return []

        console.print(f"  [cyan]CachePoisonAgent: testing cache poisoning on {url}[/]")

        # Prepare headers with auth if available
        headers = {"User-Agent": "pentest-agent/1.0"}
        if hasattr(config, "get_auth_headers"):
            headers.update(config.get_auth_headers())
        else:
            if hasattr(config, "auth_headers") and config.auth_headers:
                headers.update(config.auth_headers)
            if hasattr(config, "bearer_token") and config.bearer_token:
                headers["Authorization"] = f"Bearer {config.bearer_token}"

        cookies = config.cookies if hasattr(config, "cookies") else {}

        try:
            with httpx.Client(timeout=REQUEST_TIMEOUT, verify=False) as client:
                # Step 1: Check if caching is detected
                fresh_response = self._get_fresh_response(
                    client, method, url, headers, cookies
                )
                if fresh_response is None:
                    return []

                if not _is_cache_detected(fresh_response.headers):
                    console.print(f"  [dim]CachePoisonAgent: no cache headers detected[/]")
                    return []

                console.print(f"  [green]CachePoisonAgent: cache detected[/]")

                # Step 2: Try unkeyed header injection
                for header_name, header_value in UNKEYED_HEADERS:
                    result = self._test_unkeyed_header(
                        client,
                        method,
                        url,
                        header_name,
                        header_value,
                        headers,
                        cookies,
                    )
                    if result:
                        findings.append(result)
                        console.print(
                            f"  [bold red][CachePoisonAgent] CONFIRMED: "
                            f"Cache poisoning via {header_name}[/]"
                        )
                        return findings  # Found vulnerability, return early

                # Step 3: Try parameter cloaking with XSS
                result = self._test_parameter_cloaking(
                    client, method, url, headers, cookies
                )
                if result:
                    findings.append(result)
                    console.print(
                        f"  [bold red][CachePoisonAgent] CONFIRMED: "
                        f"Cache poisoning via parameter cloaking[/]"
                    )
                    return findings

        except Exception as e:
            console.print(f"  [dim]CachePoisonAgent error: {e}[/]")
            return []

        return findings

    def _get_fresh_response(self, client, method, url, headers, cookies):
        """Send a request with cache-buster to get a fresh response."""
        cache_buster = str(uuid.uuid4())
        separator = "&" if "?" in url else "?"
        busted_url = f"{url}{separator}cb={cache_buster}"

        try:
            if method.upper() == "POST":
                return client.post(busted_url, headers=headers, cookies=cookies)
            else:
                return client.get(busted_url, headers=headers, cookies=cookies)
        except Exception:
            return None

    def _test_unkeyed_header(
        self,
        client,
        method,
        url,
        header_name,
        header_value,
        headers,
        cookies,
    ) -> dict:
        """
        Test unkeyed header injection.

        Send request with injected header, then verify via clean request.
        If poisoned content appears in clean response → confirmed cache poisoning.
        """
        # Get fresh baseline response
        baseline = self._get_fresh_response(client, method, url, headers, cookies)
        if baseline is None:
            return None

        baseline_text = baseline.text
        baseline_headers = dict(baseline.headers)

        # Send request with injected header
        injected_headers = dict(headers)
        injected_headers[header_name] = header_value

        cache_buster = str(uuid.uuid4())
        separator = "&" if "?" in url else "?"
        busted_url = f"{url}{separator}cb={cache_buster}"

        try:
            if method.upper() == "POST":
                injected_resp = client.post(
                    busted_url, headers=injected_headers, cookies=cookies
                )
            else:
                injected_resp = client.get(
                    busted_url, headers=injected_headers, cookies=cookies
                )
        except Exception:
            return None

        injected_text = injected_resp.text

        # Check if injected header value appears in response
        if header_value not in injected_text:
            return None  # Header not reflected, can't test further

        console.print(
            f"    [yellow]Header {header_name} reflected in response[/]"
        )

        # Step 3: Verify cache poisoning
        # Send clean request (no injected header) to see if poisoned content is cached
        clean_cache_buster = str(uuid.uuid4())
        busted_url_clean = f"{url}{separator}cb={clean_cache_buster}"

        try:
            if method.upper() == "POST":
                clean_resp = client.post(busted_url_clean, headers=headers, cookies=cookies)
            else:
                clean_resp = client.get(busted_url_clean, headers=headers, cookies=cookies)
        except Exception:
            return None

        clean_text = clean_resp.text

        # If injected value appears in clean response without the header → cached!
        if header_value in clean_text:
            evidence = (
                f"Header {header_name}: {header_value} injected and reflected. "
                f"Poisoned content appeared in clean request without the header, "
                f"indicating cache poisoning confirmed. "
                f"Reflected value: '{header_value}' found in clean response."
            )
            return _make_finding(
                url=url,
                method=method,
                evidence=evidence,
                severity="Critical",
                param_name=header_name,
            )

        # If still reflected in injected response, it's high risk even if not fully cached
        evidence = (
            f"Header {header_name}: {header_value} reflected in response. "
            f"Injection successful but cache storage unconfirmed. "
            f"Could be cached based on server configuration."
        )
        return _make_finding(
            url=url,
            method=method,
            evidence=evidence,
            severity="High",
            param_name=header_name,
        )

    def _test_parameter_cloaking(
        self, client, method, url, headers, cookies
    ) -> dict:
        """
        Test parameter cloaking with XSS payload.

        Try injecting XSS in parameters that some caches strip, then
        verify if payload appears in cached response.
        """
        xss_payload = "<script>alert('cache-poison')</script>"
        separator = "&" if "?" in url else "?"
        cloak_url = f"{url}{separator}utm_content={xss_payload}&cb={uuid.uuid4()}"

        try:
            if method.upper() == "POST":
                resp = client.post(cloak_url, headers=headers, cookies=cookies)
            else:
                resp = client.get(cloak_url, headers=headers, cookies=cookies)
        except Exception:
            return None

        response_text = resp.text

        # Check if XSS payload appears in response
        if xss_payload not in response_text:
            return None  # Payload not reflected

        # Try clean request to check if cached
        clean_url = f"{url}{separator}cb={uuid.uuid4()}"

        try:
            if method.upper() == "POST":
                clean_resp = client.post(clean_url, headers=headers, cookies=cookies)
            else:
                clean_resp = client.get(clean_url, headers=headers, cookies=cookies)
        except Exception:
            return None

        clean_text = clean_resp.text

        # If XSS appears in clean response → cached
        if xss_payload in clean_text:
            evidence = (
                f"XSS payload in utm_content parameter cached. "
                f"Payload: {xss_payload} appeared in clean request. "
                f"Cache is storing reflected XSS without sanitization."
            )
            return _make_finding(
                url=url,
                method=method,
                evidence=evidence,
                severity="Critical",
                param_name="utm_content",
            )

        # If reflected but not cached, still high risk
        evidence = (
            f"XSS payload in utm_content reflected. "
            f"Parameter cloaking potential: {xss_payload} "
            f"Cache storage unconfirmed but parameter processing unsafe."
        )
        return _make_finding(
            url=url,
            method=method,
            evidence=evidence,
            severity="High",
            param_name="utm_content",
        )
