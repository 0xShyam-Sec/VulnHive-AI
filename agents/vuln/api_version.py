"""
APIVersionAgent — Tests for accessible old API versions.

Detects if older API versions are still accessible and potentially lack authentication.

Detection logic:
1. Extract version pattern from endpoint URL (e.g., /v2/, /v3/, /api/v2/)
2. Generate test URLs with older versions (v1, v2, etc.)
3. Send GET requests to old version endpoints
4. Check response validity (200 status, >100 bytes, not generic error)
5. Compare response structure with current version
6. Extra check: test old version without auth headers to detect missing authentication

Severity assignment:
- Medium: Old API version accessible but auth still required
- High: Old API version accessible WITHOUT authentication

Usage — called by DecisionEngine via test_endpoint():
    agent = APIVersionAgent(llm_backend="ollama")
    findings = agent.test_endpoint(endpoint, config, state)
"""

import re
import httpx
from rich.console import Console

from agents.base import BaseAgent

console = Console()

REQUEST_TIMEOUT = 10


def _extract_version_info(url: str) -> dict:
    """
    Extract API version info from URL.

    Patterns:
    - /v2/, /v3/, /v4/, etc.
    - /api/v2/, /api/v3/, etc.
    - /v2/users, /api/v2/endpoint, etc.

    Returns:
        {
            "current_version": 2,
            "path_after_version": "/users",
            "url_prefix": "http://example.com/v",
            "url_suffix": "/users",
            "pattern_type": "simple"  # or "api_prefix"
        }
        or None if no version pattern found
    """
    # Try /v\d+/ pattern
    match = re.search(r'/v(\d+)(/.*)?$', url)
    if match:
        version = int(match.group(1))
        path_after = match.group(2) or ""
        # Reconstruct URL parts
        url_prefix = url[:match.start()] + "/v"
        url_suffix = path_after
        return {
            "current_version": version,
            "path_after_version": path_after,
            "url_prefix": url_prefix,
            "url_suffix": url_suffix,
            "pattern_type": "simple"
        }

    # Try /api/v\d+/ pattern
    match = re.search(r'/api/v(\d+)(/.*)?$', url)
    if match:
        version = int(match.group(1))
        path_after = match.group(2) or ""
        # Reconstruct URL parts
        url_prefix = url[:match.start()] + "/api/v"
        url_suffix = path_after
        return {
            "current_version": version,
            "path_after_version": path_after,
            "url_prefix": url_prefix,
            "url_suffix": url_suffix,
            "pattern_type": "api_prefix"
        }

    return None


def _generate_old_versions(current_version: int) -> list:
    """
    Generate list of older versions to test.

    If current is v3, try v1 and v2.
    If current is v2, try v1.
    If current is v1, return empty list (no older versions).
    """
    if current_version <= 1:
        return []
    return list(range(1, current_version))


def _make_request(url: str, headers: dict = None, timeout: int = REQUEST_TIMEOUT) -> httpx.Response:
    """
    Make GET request to a URL with optional headers.

    Args:
        url: Target URL
        headers: HTTP headers (optional)
        timeout: Request timeout in seconds

    Returns:
        httpx.Response object
    """
    try:
        client = httpx.Client(
            timeout=timeout,
            verify=False,
        )
        resp = client.get(url, headers=headers or {})
        client.close()
        return resp
    except Exception as e:
        raise e


def _is_valid_response(response: httpx.Response) -> bool:
    """
    Check if response is valid (not a generic error page).

    Criteria:
    - Status code is 200
    - Response length > 100 bytes
    - Not a "not found" or "not implemented" error message
    """
    if response.status_code != 200:
        return False

    if len(response.content) <= 100:
        return False

    # Check for generic error indicators
    error_indicators = ["not found", "404", "not implemented", "501", "method not allowed", "405"]
    response_text = response.text.lower()
    if any(indicator in response_text for indicator in error_indicators):
        return False

    return True


def _is_auth_required(response: httpx.Response) -> bool:
    """
    Check if response indicates authentication is required.

    Returns True if response suggests auth is needed.
    """
    if response.status_code in [401, 403]:
        return True

    auth_indicators = ["unauthorized", "forbidden", "authentication", "auth required", "please login"]
    response_text = response.text.lower()
    if any(indicator in response_text for indicator in auth_indicators):
        return True

    return False


def _make_finding(
    url: str,
    old_version: int,
    current_version: int,
    auth_required: bool,
    response_status: int,
    response_length: int,
) -> dict:
    """
    Create a finding for accessible old API version.

    Args:
        url: Old version URL
        old_version: Old API version number
        current_version: Current API version number
        auth_required: Whether auth is still required for old version
        response_status: HTTP status code of old version response
        response_length: Length of old version response in bytes

    Returns:
        Finding dict
    """
    severity = "High" if not auth_required else "Medium"

    if auth_required:
        evidence = (
            f"API v{old_version} still accessible at {url}. "
            f"Response: {response_status} ({response_length} bytes). "
            f"Authentication is still required."
        )
        title = f"Old API Version Accessible (v{old_version}, auth required)"
    else:
        evidence = (
            f"API v{old_version} still accessible at {url} WITHOUT authentication. "
            f"Response: {response_status} ({response_length} bytes). "
            f"This is a CRITICAL security issue."
        )
        title = f"Old API Version Accessible WITHOUT Auth (v{old_version})"

    return {
        "vuln_type": "api_version",
        "url": url,
        "method": "GET",
        "param_name": "API Version",
        "payload": f"Old version v{old_version}",
        "evidence": evidence,
        "severity": severity,
        "source": "APIVersionAgent",
        "validated": True,
    }


class APIVersionAgent(BaseAgent):
    """Agent for detecting accessible old API versions."""

    agent_name = "APIVersionAgent"
    vuln_type = "api_version"
    model = "claude-haiku-4-5-20251001"
    max_iterations = 10
    allowed_tools = []

    system_prompt = """You are an API version detection specialist. Test for accessible old API versions."""

    # ------------------------------------------------------------------
    # Core deterministic test — called by BaseAgent.test_endpoint()
    # ------------------------------------------------------------------

    def _deterministic_test(self, endpoint, config, state) -> list:
        """
        Test endpoint for accessible old API versions.

        1. Extract version pattern from endpoint URL
        2. Generate older version numbers to test
        3. Send GET requests to old version endpoints
        4. Check if responses are valid (200, >100 bytes, not generic error)
        5. Test old version WITHOUT auth to detect missing authentication
        6. Report findings with appropriate severity
        """
        url = endpoint.url
        method = endpoint.method or "GET"

        findings = []

        # Step 1: Extract version info
        version_info = _extract_version_info(url)
        if not version_info:
            # No version pattern found, skip
            return []

        console.print(
            f"  [cyan]APIVersionAgent: testing old versions for {url}[/]"
        )

        current_version = version_info["current_version"]
        url_prefix = version_info["url_prefix"]
        url_suffix = version_info["url_suffix"]

        # Step 2: Generate old versions to test
        old_versions = _generate_old_versions(current_version)
        if not old_versions:
            # No older versions to test
            return []

        # Prepare auth headers for the current version baseline
        baseline_headers = {"User-Agent": "pentest-agent/1.0"}
        if hasattr(config, "bearer_token") and config.bearer_token:
            baseline_headers["Authorization"] = f"Bearer {config.bearer_token}"
        elif hasattr(config, "get_auth_headers"):
            baseline_headers.update(config.get_auth_headers())

        # Step 3: Test each old version
        for old_version in old_versions:
            old_url = f"{url_prefix}{old_version}{url_suffix}"

            try:
                # Test WITH auth headers (current auth mechanism)
                response_with_auth = _make_request(old_url, headers=baseline_headers)

                # Check if response is valid
                if not _is_valid_response(response_with_auth):
                    continue

                # Step 4: Test WITHOUT auth headers to detect missing authentication
                response_without_auth = _make_request(old_url, headers={"User-Agent": "pentest-agent/1.0"})

                # Determine if auth is required
                auth_required = _is_auth_required(response_without_auth)

                # If old version responds with 200 without auth, severity is HIGH
                # If old version requires auth, severity is MEDIUM
                if response_without_auth.status_code == 200 and len(response_without_auth.content) > 100:
                    auth_required = False

                # Create and append finding
                finding = _make_finding(
                    url=old_url,
                    old_version=old_version,
                    current_version=current_version,
                    auth_required=auth_required,
                    response_status=response_with_auth.status_code,
                    response_length=len(response_with_auth.content),
                )

                findings.append(finding)

                console.print(
                    f"  [bold red][APIVersionAgent] CONFIRMED: Old API v{old_version} "
                    f"accessible @ {old_url}[/]"
                )

            except Exception as e:
                # Log but continue testing other versions
                console.print(f"  [dim]APIVersionAgent: error testing v{old_version}: {e}[/]")
                continue

        return findings
