"""
Rate Limit Detection Agent — Tests for missing rate limiting on sensitive endpoints.

Detects missing or weak rate limiting by:
1. Identifying endpoints with interesting paths (login, auth, api, password, token, payment, checkout, signup, register, otp, verify)
2. Sending 30 identical rapid requests to trigger rate limiting
3. Tracking status codes, response times, and response lengths
4. Reporting if all requests succeed with no 429/CAPTCHA/blocking
5. Noting soft throttling if last 10 requests are significantly slower than first 10

Usage — called by DecisionEngine via test_endpoint():
    agent = RateLimitAgent(llm_backend="ollama")
    findings = agent.test_endpoint(endpoint, config, state)
"""

import time
import httpx
from rich.console import Console

from agents.base import BaseAgent

console = Console()

REQUEST_TIMEOUT = 10
INTERESTING_PATHS = [
    "login", "auth", "api", "password", "token", "payment", "checkout",
    "signup", "register", "otp", "verify"
]


def _is_interesting_endpoint(url: str) -> bool:
    """Check if endpoint path contains interesting keywords for rate limiting tests."""
    url_lower = url.lower()
    return any(keyword in url_lower for keyword in INTERESTING_PATHS)


def _make_finding(url: str, method: str, evidence: str, severity: str = "Medium") -> dict:
    """Create a rate limiting finding."""
    return {
        "vuln_type": "rate_limit",
        "url": url,
        "method": method,
        "param_name": "",
        "payload": "Missing rate limiting",
        "evidence": evidence,
        "severity": severity,
        "source": "RateLimitAgent",
        "validated": True,
    }


class RateLimitAgent(BaseAgent):
    model = "claude-haiku-4-5-20251001"
    max_iterations = 10
    vuln_type = "rate_limit"
    agent_name = "RateLimitAgent"
    allowed_tools = []

    system_prompt = """You are a rate limiting specialist. Test ONLY for missing rate limiting on sensitive endpoints."""

    # ------------------------------------------------------------------
    # Core deterministic test — called by BaseAgent.test_endpoint()
    # ------------------------------------------------------------------

    def _deterministic_test(self, endpoint, config, state) -> list:
        """
        Test endpoint for missing rate limiting.

        1. Only test endpoints with interesting paths
        2. Send 30 identical rapid requests
        3. Track: status codes, response times, response lengths
        4. If all 30 succeed (no 429, no CAPTCHA, no block) → finding
        5. If last 10 are significantly slower → note soft throttling
        """
        url = endpoint.url
        method = endpoint.method or "GET"

        # Skip non-interesting endpoints
        if not _is_interesting_endpoint(url):
            return []

        console.print(f"  [cyan]RateLimitAgent: testing rate limiting on {url}[/]")

        findings = []

        # Prepare headers with auth if available
        headers = {"User-Agent": "pentest-agent/1.0"}
        if hasattr(config, "cookies") and config.cookies:
            headers["Cookie"] = config.cookies
        if hasattr(config, "bearer_token") and config.bearer_token:
            headers["Authorization"] = f"Bearer {config.bearer_token}"

        # Send 30 identical rapid requests
        status_codes = {}
        response_times = []
        response_lengths = []
        blocked = False
        captcha_detected = False

        try:
            with httpx.Client(timeout=REQUEST_TIMEOUT, verify=False) as client:
                for i in range(30):
                    try:
                        start_time = time.time()

                        if method.upper() == "POST":
                            resp = client.post(url, headers=headers)
                        else:
                            resp = client.get(url, headers=headers)

                        elapsed = (time.time() - start_time) * 1000  # milliseconds

                        # Track response
                        status_code = resp.status_code
                        status_codes[status_code] = status_codes.get(status_code, 0) + 1
                        response_times.append(elapsed)
                        response_lengths.append(len(resp.content))

                        # Check for rate limiting indicators
                        if status_code == 429:
                            blocked = True
                            break
                        if status_code == 403:
                            # Might be rate limited
                            if "rate" in resp.text.lower() or "too many" in resp.text.lower():
                                blocked = True
                                break
                        if "captcha" in resp.text.lower() or "challenge" in resp.text.lower():
                            captcha_detected = True
                            break

                    except httpx.TimeoutException:
                        # Timeout might indicate rate limiting
                        blocked = True
                        break
                    except Exception:
                        continue
        except Exception:
            return []

        # Analyze results
        if blocked or captcha_detected:
            # Rate limiting is in place
            return []

        # Check if all 30 requests succeeded
        total_requests = sum(status_codes.values())
        if total_requests < 30:
            # Some requests failed, might be rate limited
            return []

        # All 30 succeeded — potential missing rate limiting
        # Check for soft throttling (last 10 significantly slower than first 10)
        soft_throttling = False
        soft_throttling_note = ""

        if len(response_times) >= 20:
            first_10_avg = sum(response_times[:10]) / 10
            last_10_avg = sum(response_times[-10:]) / 10
            if last_10_avg > 2 * first_10_avg:
                soft_throttling = True
                soft_throttling_note = (
                    f" Possible soft throttling detected: "
                    f"first 10 avg={first_10_avg:.1f}ms, last 10 avg={last_10_avg:.1f}ms"
                )

        # Format status code counts
        status_str = ", ".join(f"{code}: {count}" for code, count in sorted(status_codes.items()))
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0

        evidence = (
            f"30/30 requests succeeded without rate limiting. "
            f"Status codes: {status_str}. "
            f"Avg response time: {avg_response_time:.1f}ms"
            f"{soft_throttling_note}"
        )

        finding = _make_finding(
            url=url,
            method=method,
            evidence=evidence,
            severity="Medium"
        )

        console.print(
            f"  [bold red][RateLimitAgent] CONFIRMED: Missing Rate Limiting @ {url}[/]"
        )

        findings.append(finding)
        return findings
