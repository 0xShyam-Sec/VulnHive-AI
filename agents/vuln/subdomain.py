"""
SubdomainAgent — DNS enumeration and subdomain takeover detection.

Detects:
1. Valid subdomains via DNS enumeration
2. Subdomains with external CNAME targets (GitHub Pages, Heroku, S3, Azure, CloudFront)
3. Subdomain takeover vulnerabilities (unresponsive or "not found" CNAME targets)

Usage — called by DecisionEngine via test_endpoint():
    agent = SubdomainAgent(llm_backend="ollama")
    findings = agent.test_endpoint(endpoint, config, state)
"""

import socket
import re
from urllib.parse import urlparse
from rich.console import Console

import httpx
from agents.base import BaseAgent

console = Console()

# Common subdomains to check
SUBDOMAINS_TO_CHECK = [
    "admin", "api", "dev", "staging", "test", "qa", "beta", "internal",
    "intranet", "vpn", "mail", "smtp", "pop", "imap", "ftp", "ssh", "git",
    "gitlab", "jenkins", "ci", "cd", "deploy", "docker", "k8s", "kubernetes",
    "monitoring", "grafana", "kibana", "elastic", "prometheus", "redis", "db",
    "database", "mysql", "postgres", "mongo", "backup", "bak", "old", "new",
    "v2", "mobile", "app", "cdn", "media", "assets", "static", "files",
    "upload", "download", "auth", "login", "sso", "oauth", "payment",
    "billing", "shop", "store", "portal", "dashboard", "panel", "console",
    "status", "health", "docs", "wiki", "jira", "confluence", "slack", "teams"
]

# CNAME patterns for external services (takeover targets)
TAKEOVER_PATTERNS = {
    "github_pages": (r".*\.github\.io", "GitHub Pages"),
    "herokuapp": (r".*\.herokuapp\.com", "Heroku"),
    "s3": (r".*\.s3[.-](.*\.)?amazonaws\.com", "AWS S3"),
    "azure": (r".*\.azurewebsites\.net", "Azure App Service"),
    "cloudfront": (r".*\.cloudfront\.net", "CloudFront"),
}

# Error messages indicating takeover is possible
TAKEOVER_ERROR_MESSAGES = [
    "no such app",
    "there isn't a github pages site",
    "nosuchbucket",
    "the specified bucket does not exist",
    "invalidbucketname",
    "404",
    "notfound",
    "app not found",
    "site not found",
    "does not exist",
    "not configured",
]


def _extract_base_domain(url: str) -> str:
    """
    Extract base domain from URL.
    E.g., "https://api.example.com/path" → "example.com"
    """
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path

    # Remove port if present
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    # Extract base domain (last two parts, or three if country TLD)
    parts = hostname.split(".")
    if len(parts) < 2:
        return hostname

    # Simple heuristic: if the last part is <= 3 chars, it's likely a country TLD
    if len(parts) >= 3 and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def _resolve_subdomain(subdomain_fqdn: str, timeout: float = 0.5) -> bool:
    """
    Check if a subdomain resolves via DNS.
    Returns True if resolves, False otherwise.
    """
    try:
        socket.getaddrinfo(subdomain_fqdn, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return True
    except (socket.gaierror, socket.timeout):
        return False
    except Exception:
        return False


def _get_cname(subdomain_fqdn: str, timeout: float = 0.5) -> str:
    """
    Get CNAME for a subdomain.
    Returns CNAME string, or empty string if not found.
    """
    try:
        # Try to get CNAME via socket.getfqdn (works on some systems)
        fqdn = socket.getfqdn(subdomain_fqdn)
        if fqdn and fqdn != subdomain_fqdn:
            return fqdn
    except Exception:
        pass

    # Fallback: try DNS query directly using socket
    try:
        result = socket.gethostbyname_ex(subdomain_fqdn)
        # result = (hostname, aliaslist, ipaddrlist)
        if result[1]:  # aliaslist
            return result[1][0]
    except Exception:
        pass

    return ""


def _is_takeover_target(cname: str) -> tuple:
    """
    Check if CNAME matches a known takeover target.
    Returns (True, service_name) if matches, (False, None) otherwise.
    """
    cname_lower = cname.lower()
    for pattern_key, (pattern, service_name) in TAKEOVER_PATTERNS.items():
        if re.match(pattern, cname_lower):
            return True, service_name
    return False, None


def _check_takeover_possible(url: str, timeout: float = 5.0) -> tuple:
    """
    Try HTTP GET to CNAME target to check if subdomain takeover is possible.
    Returns (True, error_message) if takeover likely, (False, "") otherwise.
    """
    try:
        # Try with http and https
        for scheme in ["https", "http"]:
            try:
                response = httpx.get(
                    f"{scheme}://{url}",
                    timeout=timeout,
                    follow_redirects=False,
                    verify=False
                )
                response_text = response.text.lower()

                # Check for takeover indicators
                for error_msg in TAKEOVER_ERROR_MESSAGES:
                    if error_msg in response_text:
                        return True, f"HTTP {response.status_code}: {response_text[:100]}"

            except (httpx.TimeoutException, httpx.ConnectError):
                # Timeout might indicate misconfiguration
                continue
            except Exception:
                continue

        return False, ""
    except Exception:
        return False, ""


def _make_finding(subdomain: str, url: str, severity: str, evidence: str) -> dict:
    """Create a subdomain takeover finding."""
    return {
        "vuln_type": "subdomain_takeover",
        "url": url,
        "subdomain": subdomain,
        "method": "GET",
        "param_name": "",
        "payload": f"Subdomain takeover: {subdomain}",
        "evidence": evidence,
        "severity": severity,
        "source": "SubdomainAgent",
        "validated": True,
    }


class SubdomainAgent(BaseAgent):
    model = "claude-haiku-4-5-20251001"
    max_iterations = 5
    vuln_type = "subdomain"
    agent_name = "SubdomainAgent"
    allowed_tools = []

    system_prompt = """You are a subdomain enumeration and takeover specialist. \
Test ONLY for subdomain discovery and takeover vulnerabilities."""

    # ──────────────────────────────────────────────────────────────────────
    # Core deterministic test — called by BaseAgent.test_endpoint()
    # ──────────────────────────────────────────────────────────────────────

    def _deterministic_test(self, endpoint, config, state) -> list:
        """
        Test for subdomain enumeration and takeover.

        1. Extract base domain from endpoint.url
        2. DNS enumerate common subdomains
        3. For each resolved subdomain, check CNAME
        4. If CNAME points to external service, check if takeover is possible
        5. Add discovered subdomains as new endpoints to state
        6. Return findings for confirmed takeovers
        """
        url = endpoint.url
        base_domain = _extract_base_domain(url)

        console.print(f"  [cyan]SubdomainAgent: enumerating subdomains for {base_domain}[/]")

        findings = []
        discovered_subdomains = []

        # Step 1: DNS enumeration
        console.print(f"  [dim]SubdomainAgent: checking {len(SUBDOMAINS_TO_CHECK)} subdomains...[/]")

        for subdomain in SUBDOMAINS_TO_CHECK:
            subdomain_fqdn = f"{subdomain}.{base_domain}"

            # Check if resolves
            if not _resolve_subdomain(subdomain_fqdn):
                continue

            console.print(f"    [green]✓ {subdomain_fqdn} resolves[/]")
            discovered_subdomains.append(subdomain_fqdn)

            # Step 2: Get CNAME
            cname = _get_cname(subdomain_fqdn)

            # Step 3: Check if CNAME is takeover target
            if cname:
                is_takeover_target, service_name = _is_takeover_target(cname)

                if is_takeover_target:
                    console.print(
                        f"    [yellow]⚠ {subdomain_fqdn} → {cname} ({service_name})[/]"
                    )

                    # Step 4: Check if takeover is possible
                    takeover_possible, error_msg = _check_takeover_possible(
                        subdomain_fqdn, timeout=5.0
                    )

                    if takeover_possible:
                        console.print(
                            f"    [bold red]✗ TAKEOVER POSSIBLE: {subdomain_fqdn}[/]"
                        )

                        finding = _make_finding(
                            subdomain=subdomain_fqdn,
                            url=url,
                            severity="Critical",
                            evidence=(
                                f"Subdomain {subdomain_fqdn} has CNAME pointing to {service_name} "
                                f"({cname}). Target appears unclaimed. {error_msg}"
                            )
                        )
                        findings.append(finding)

        # Step 5: Add discovered subdomains as new endpoints
        if discovered_subdomains and state:
            for subdomain_fqdn in discovered_subdomains:
                # Create endpoint for the discovered subdomain
                try:
                    from engine.scan_state import Endpoint
                    new_endpoint = Endpoint(
                        url=f"https://{subdomain_fqdn}",
                        method="GET",
                        tags={"subdomain_discovered"}
                    )
                    state.add_endpoint(new_endpoint)
                except Exception:
                    pass

        if discovered_subdomains:
            console.print(
                f"  [bold green][SubdomainAgent] Found {len(discovered_subdomains)} "
                f"subdomains, {len(findings)} takeover(s)[/]"
            )

        return findings
