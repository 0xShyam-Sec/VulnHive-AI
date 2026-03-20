"""Execute detected chains end-to-end and verify exploitability."""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin
import httpx
from engine.config import ScanConfig


class ChainVerifier:
    """Verifies exploit chains by attempting end-to-end execution."""

    def __init__(self, config: ScanConfig):
        """Initialize verifier with scan configuration."""
        self.config = config
        self.client = httpx.Client(
            timeout=10,
            follow_redirects=True,
            verify=False,
        )
        self.client.headers.update(config.get_auth_headers())

    def verify_chains(self, chains: List[Dict], findings: List[Dict]) -> List[Dict]:
        """
        Verify each detected chain by attempting end-to-end execution.

        Args:
            chains: List of detected chains from graph_builder.detect_chains()
            findings: List of findings from scanner

        Returns:
            Updated chains list with verification status and evidence.
        """
        for chain in chains:
            chain_name = chain.get("name", "")
            required_types = set(chain.get("required_types", []))

            # Look up findings involved in this chain
            chain_findings = self._collect_findings_for_chain(
                findings, required_types
            )

            if not chain_findings:
                chain["verified"] = False
                chain["verification_status"] = "Verification Failed"
                chain["verification_evidence"] = "No matching findings found"
                continue

            # Route to appropriate verification function
            verifier_method = self._get_verifier_for_chain(chain_name)
            if verifier_method:
                result = verifier_method(chain_findings, chain)
                chain["verified"] = result["verified"]
                chain["verification_status"] = result["status"]
                chain["verification_evidence"] = result["evidence"]
            else:
                # Unknown chain type - mark as theoretical
                chain["verified"] = False
                chain["verification_status"] = "Theoretical Chain"
                chain["verification_evidence"] = "No verification implemented for this chain type"

        return chains

    def _collect_findings_for_chain(
        self, findings: List[Dict], required_types: set
    ) -> Dict[str, List[Dict]]:
        """Collect findings grouped by vulnerability type for a chain."""
        collected = {}
        for vtype in required_types:
            matching = [
                f for f in findings
                if self._normalize_type(f.get("vuln_type", f.get("type", ""))) == vtype
            ]
            collected[vtype] = matching
        return collected

    def _normalize_type(self, vtype: str) -> str:
        """Normalize vulnerability type string."""
        vtype = vtype.lower().strip()
        mapping = {
            "sql injection": "sqli",
            "cross-site scripting": "xss",
            "cross-site request forgery": "csrf",
            "insecure direct object reference": "idor",
            "server-side request forgery": "ssrf",
            "open redirect": "open_redirect",
            "cors misconfiguration": "cors",
            "file upload": "file_upload",
            "weak jwt configuration": "jwt",
            "server-side template injection": "ssti",
            "command injection": "command_injection",
            "path traversal": "path_traversal",
            "missing security headers": "security_headers",
            "sensitive data exposure": "sensitive_data",
            "mass assignment": "mass_assignment",
        }
        for key, val in mapping.items():
            if key in vtype:
                return val
        return vtype

    def _get_verifier_for_chain(self, chain_name: str):
        """Get the verification function for a chain type."""
        chain_name_lower = chain_name.lower()

        # CORS + CSRF chain
        if "cross-origin" in chain_name_lower:
            return self._verify_cors_csrf_chain

        # XSS + CSRF chain
        if "xss to full" in chain_name_lower or "xss worm" in chain_name_lower:
            return self._verify_xss_csrf_chain

        # IDOR + rate limit chain
        if "idor" in chain_name_lower and ("data enumeration" in chain_name_lower or "privilege" in chain_name_lower):
            return self._verify_idor_ratelimit_chain

        # SQLi escalation chain
        if "sql injection" in chain_name_lower:
            return self._verify_sqli_chain

        return None

    def _verify_cors_csrf_chain(self, findings: Dict[str, List[Dict]], chain: Dict) -> Dict[str, Any]:
        """
        Verify CORS + CSRF chain.

        Tests:
        1. Send cross-origin request with Origin header
        2. Check if CORS allows it
        3. Verify CSRF endpoint accepts without token
        """
        evidence_parts = []

        cors_findings = findings.get("cors", [])
        csrf_findings = findings.get("csrf", [])

        if not cors_findings or not csrf_findings:
            return {
                "verified": False,
                "status": "Theoretical Chain",
                "evidence": "Missing CORS or CSRF findings to test",
            }

        cors_target = cors_findings[0].get("url", "")
        csrf_target = csrf_findings[0].get("url", "")

        try:
            # Test CORS
            if cors_target:
                cors_verified = self._test_cors_header(cors_target)
                evidence_parts.append(
                    f"CORS test: {'PASSED' if cors_verified else 'FAILED'}"
                )
                if not cors_verified:
                    return {
                        "verified": False,
                        "status": "Verification Failed",
                        "evidence": "CORS misconfiguration not confirmed",
                    }

            # Test CSRF endpoint accepts without token
            if csrf_target:
                csrf_verified = self._test_csrf_no_token(csrf_target)
                evidence_parts.append(
                    f"CSRF no-token test: {'PASSED' if csrf_verified else 'FAILED'}"
                )
                if not csrf_verified:
                    return {
                        "verified": False,
                        "status": "Verification Failed",
                        "evidence": "CSRF endpoint requires token",
                    }

            return {
                "verified": True,
                "status": "Verified Chain",
                "evidence": " | ".join(evidence_parts),
            }

        except Exception as e:
            return {
                "verified": False,
                "status": "Verification Failed",
                "evidence": f"Error during verification: {str(e)}",
            }

    def _test_cors_header(self, url: str) -> bool:
        """Test if CORS allows cross-origin requests."""
        try:
            resp = self.client.options(
                url,
                headers={"Origin": "http://evil.com"},
            )
            acl_origin = resp.headers.get("Access-Control-Allow-Origin", "")
            return acl_origin == "http://evil.com" or acl_origin == "*"
        except Exception:
            return False

    def _test_csrf_no_token(self, url: str) -> bool:
        """Test if CSRF endpoint accepts requests without CSRF token."""
        try:
            # Try POST without any CSRF token
            resp = self.client.post(url, data={"test": "1"})
            return resp.status_code < 400
        except Exception:
            return False

    def _verify_xss_csrf_chain(self, findings: Dict[str, List[Dict]], chain: Dict) -> Dict[str, Any]:
        """
        Verify XSS + CSRF chain.

        Tests:
        1. Check if XSS endpoint has no CSP blocking inline scripts
        2. Check if CSRF endpoint is same-origin
        3. Verify both vulnerabilities confirmed
        """
        evidence_parts = []

        xss_findings = findings.get("xss", [])
        csrf_findings = findings.get("csrf", [])

        if not xss_findings or not csrf_findings:
            return {
                "verified": False,
                "status": "Theoretical Chain",
                "evidence": "Missing XSS or CSRF findings to test",
            }

        xss_target = xss_findings[0].get("url", "")
        csrf_target = csrf_findings[0].get("url", "")

        try:
            # Check if same origin
            xss_origin = urlparse(xss_target).netloc if xss_target else ""
            csrf_origin = urlparse(csrf_target).netloc if csrf_target else ""

            if xss_origin != csrf_origin:
                return {
                    "verified": False,
                    "status": "Verification Failed",
                    "evidence": "XSS and CSRF endpoints on different origins",
                }

            evidence_parts.append("Same-origin confirmed")

            # Check CSP
            if xss_target:
                no_csp = self._check_no_csp(xss_target)
                evidence_parts.append(f"CSP check: {'PASSED (weak)' if no_csp else 'BLOCKED'}")
                if not no_csp:
                    return {
                        "verified": False,
                        "status": "Verification Failed",
                        "evidence": "CSP blocks inline scripts",
                    }

            # Verify CSRF endpoint
            if csrf_target:
                csrf_no_token = self._test_csrf_no_token(csrf_target)
                evidence_parts.append(f"CSRF no-token: {'PASSED' if csrf_no_token else 'FAILED'}")
                if not csrf_no_token:
                    return {
                        "verified": False,
                        "status": "Verification Failed",
                        "evidence": "CSRF endpoint requires token",
                    }

            return {
                "verified": True,
                "status": "Verified Chain",
                "evidence": " | ".join(evidence_parts),
            }

        except Exception as e:
            return {
                "verified": False,
                "status": "Verification Failed",
                "evidence": f"Error during verification: {str(e)}",
            }

    def _check_no_csp(self, url: str) -> bool:
        """Check if endpoint lacks CSP blocking inline scripts."""
        try:
            resp = self.client.get(url)
            csp = resp.headers.get("Content-Security-Policy", "")
            # If no CSP or CSP allows inline scripts, return True
            if not csp:
                return True
            if "unsafe-inline" in csp:
                return True
            return False
        except Exception:
            return False

    def _verify_idor_ratelimit_chain(self, findings: Dict[str, List[Dict]], chain: Dict) -> Dict[str, Any]:
        """
        Verify IDOR + rate limit chain.

        Tests:
        1. Send 10 requests with incrementing IDs to IDOR endpoint
        2. Check if all return 200 with different data
        3. Verify no 429 rate limit responses
        """
        evidence_parts = []

        idor_findings = findings.get("idor", [])

        if not idor_findings:
            return {
                "verified": False,
                "status": "Theoretical Chain",
                "evidence": "No IDOR findings to test",
            }

        idor_target = idor_findings[0].get("url", "")

        try:
            if not idor_target:
                return {
                    "verified": False,
                    "status": "Verification Failed",
                    "evidence": "No target URL for IDOR endpoint",
                }

            # Extract base URL and ID parameter
            base_url, id_param = self._extract_idor_url_pattern(idor_target)

            if not base_url or not id_param:
                return {
                    "verified": False,
                    "status": "Verification Failed",
                    "evidence": "Could not extract IDOR pattern from URL",
                }

            # Send 10 requests with incrementing IDs
            success_count = 0
            rate_limited = False
            response_hashes = set()

            for i in range(1, 11):
                url = base_url.replace(id_param, str(i))
                try:
                    resp = self.client.get(url)

                    if resp.status_code == 429:
                        rate_limited = True
                        break

                    if resp.status_code == 200:
                        success_count += 1
                        # Hash response to detect different data
                        resp_hash = hash(resp.text[:100])
                        response_hashes.add(resp_hash)

                except Exception:
                    pass

            evidence_parts.append(f"Requests succeeded: {success_count}/10")
            evidence_parts.append(f"Different responses: {len(response_hashes)}")

            if rate_limited:
                evidence_parts.append("Rate limiting: NOT PRESENT (vulnerable)")
            else:
                evidence_parts.append("Rate limiting: NOT DETECTED")

            # Verified if: high success rate, different responses, no rate limiting
            if success_count >= 8 and len(response_hashes) >= 5 and not rate_limited:
                return {
                    "verified": True,
                    "status": "Verified Chain",
                    "evidence": " | ".join(evidence_parts),
                }
            else:
                return {
                    "verified": False,
                    "status": "Verification Failed",
                    "evidence": " | ".join(evidence_parts),
                }

        except Exception as e:
            return {
                "verified": False,
                "status": "Verification Failed",
                "evidence": f"Error during verification: {str(e)}",
            }

    def _extract_idor_url_pattern(self, url: str) -> tuple:
        """Extract base URL and ID parameter from IDOR URL."""
        # Look for common ID patterns: /user/123, /api/users/456, ?id=789, etc.
        patterns = [
            (r"(/\d+)(?:/|$|\?)", r"\1"),  # /123/ or /123 or /123?
            (r"([?&]id=)\d+", r"\1"),  # ?id=123 or &id=123
            (r"([?&]user_id=)\d+", r"\1"),  # ?user_id=123
            (r"([?&]account_id=)\d+", r"\1"),  # ?account_id=123
        ]

        for pattern, replacement in patterns:
            match = re.search(pattern, url)
            if match:
                base = re.sub(pattern, replacement, url)
                id_marker = replacement
                return base, id_marker

        return "", ""

    def _verify_sqli_chain(self, findings: Dict[str, List[Dict]], chain: Dict) -> Dict[str, Any]:
        """
        Verify SQLi escalation chain.

        Tests:
        1. Try UNION SELECT to extract table names
        2. Confirm actual database structure returned
        """
        evidence_parts = []

        sqli_findings = findings.get("sqli", [])

        if not sqli_findings:
            return {
                "verified": False,
                "status": "Theoretical Chain",
                "evidence": "No SQLi findings to test",
            }

        sqli_target = sqli_findings[0].get("url", "")
        sqli_param = sqli_findings[0].get("parameter", "")

        try:
            if not sqli_target:
                return {
                    "verified": False,
                    "status": "Verification Failed",
                    "evidence": "No target URL for SQLi endpoint",
                }

            # Try basic UNION SELECT
            result = self._test_union_select(sqli_target, sqli_param)

            if result["found_tables"]:
                evidence_parts.append(f"Tables found: {', '.join(result['found_tables'][:5])}")
                evidence_parts.append(f"UNION SELECT: SUCCESSFUL")
                return {
                    "verified": True,
                    "status": "Verified Chain",
                    "evidence": " | ".join(evidence_parts),
                }
            else:
                evidence_parts.append("UNION SELECT: NO TABLES EXTRACTED")
                return {
                    "verified": False,
                    "status": "Verification Failed",
                    "evidence": " | ".join(evidence_parts),
                }

        except Exception as e:
            return {
                "verified": False,
                "status": "Verification Failed",
                "evidence": f"Error during verification: {str(e)}",
            }

    def _test_union_select(self, url: str, param: str = "") -> Dict[str, Any]:
        """Test for UNION-based SQLi and extract table names."""
        found_tables = []

        try:
            # Common UNION SELECT payloads for different databases
            payloads = [
                # MySQL/PostgreSQL - extract table names
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT table_name FROM information_schema.tables LIMIT 1--",
                "1 UNION SELECT table_name FROM information_schema.tables--",
                # SQLite
                "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
                "1 UNION SELECT name FROM sqlite_master WHERE type='table'--",
            ]

            for payload in payloads:
                # Build request
                if param:
                    params = {param: payload}
                    resp = self.client.get(url, params=params)
                else:
                    # Try in common parameter names
                    for common_param in ["id", "q", "search", "filter"]:
                        resp = self.client.get(url, params={common_param: payload})
                        if self._contains_table_names(resp.text):
                            found_tables = self._extract_table_names(resp.text)
                            break

                if self._contains_table_names(resp.text):
                    found_tables = self._extract_table_names(resp.text)
                    if found_tables:
                        break

        except Exception:
            pass

        return {"found_tables": found_tables}

    def _contains_table_names(self, response_text: str) -> bool:
        """Check if response contains likely table names."""
        indicators = [
            "users", "accounts", "admin", "products", "orders",
            "customers", "employees", "posts", "comments",
            "information_schema", "mysql", "sqlite_master"
        ]
        response_lower = response_text.lower()
        return any(indicator in response_lower for indicator in indicators)

    def _extract_table_names(self, response_text: str) -> List[str]:
        """Extract table names from response."""
        common_tables = [
            "users", "accounts", "admin", "products", "orders",
            "customers", "employees", "posts", "comments",
            "transactions", "logs", "sessions", "roles"
        ]
        found = []
        response_lower = response_text.lower()
        for table in common_tables:
            if table in response_lower:
                found.append(table)
        return found

    def close(self):
        """Close HTTP client."""
        self.client.close()


def verify_chains(chains: List[Dict], findings: List[Dict], config: ScanConfig) -> List[Dict]:
    """
    Verify detected chains by attempting end-to-end execution.

    Args:
        chains: List of detected chains from graph_builder.detect_chains()
        findings: List of findings from scanner
        config: ScanConfig instance

    Returns:
        Updated chains list with verification status and evidence.
    """
    verifier = ChainVerifier(config)
    try:
        return verifier.verify_chains(chains, findings)
    finally:
        verifier.close()
