"""
Tools that the AI agent can use to interact with target applications.
Each tool is a function + its schema for the LLM's tool-use interface.
"""

from typing import Optional
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from validator import (
    validate_sqli, validate_xss, validate_command_injection, validate_path_traversal,
    validate_csrf, validate_idor, validate_open_redirect, validate_ssrf,
    validate_security_headers, validate_sensitive_data, validate_xxe,
)
from crawler import crawl_target
from auth import authenticate as _auth_func, get_auth_cookies, get_auth_headers

# Shared HTTP client with reasonable defaults
_client = httpx.Client(timeout=15, follow_redirects=True, verify=False)

# Global session cookies — set after authentication
_session_cookies = {}


# ── Authentication ────────────────────────────────────────────────────

def authenticate(auth_type: str, login_url: Optional[str] = None,
                 username: Optional[str] = None, password: Optional[str] = None,
                 username_field: str = "username", password_field: str = "password",
                 cookies: Optional[dict] = None, bearer_token: Optional[str] = None,
                 success_indicator: Optional[str] = None,
                 extra_fields: Optional[dict] = None) -> dict:
    """
    Authenticate to the target application.
    Supports form login, cookie, basic auth, and bearer token.
    Session cookies/headers are stored for all subsequent requests.
    """
    global _session_cookies

    result = _auth_func(
        auth_type=auth_type,
        login_url=login_url,
        username=username,
        password=password,
        username_field=username_field,
        password_field=password_field,
        cookies=cookies,
        bearer_token=bearer_token,
        success_indicator=success_indicator,
        extra_fields=extra_fields,
    )

    # Store cookies globally for other tools to use
    if result.get("success"):
        auth_cookies = get_auth_cookies()
        if auth_cookies:
            _session_cookies = auth_cookies

        # Auto-detect and set security level to lowest
        # Handles DVWA and similar apps that have a security settings page
        if login_url:
            _try_set_low_security(login_url)

    return result


def _try_set_low_security(login_url: str):
    """
    Auto-detect security level settings pages (like DVWA's security.php)
    and set them to the lowest level for testing.
    """
    global _session_cookies
    from urllib.parse import urljoin
    base_url = login_url.rsplit("/", 1)[0] + "/"

    security_paths = ["security.php", "security_level_set.php", "settings.php"]
    for path in security_paths:
        try:
            sec_url = urljoin(base_url, path)
            resp = _client.get(sec_url, cookies=_session_cookies, headers=_get_headers())
            if resp.status_code != 200:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Look for a form with a security-level select or input
            for form in soup.find_all("form"):
                selects = form.find_all("select")
                for select in selects:
                    name = select.get("name", "").lower()
                    if "security" in name or "level" in name:
                        # Found a security level selector — set to lowest
                        options = select.find_all("option")
                        lowest = None
                        for opt in options:
                            val = opt.get("value", "").lower()
                            if val in ("low", "0", "easy", "beginner"):
                                lowest = opt.get("value", "")
                                break
                        if not lowest and options:
                            lowest = options[0].get("value", "")

                        if lowest:
                            # Build form data
                            form_data = {select.get("name", ""): lowest}
                            # Add CSRF tokens and submit buttons
                            for inp in form.find_all("input"):
                                inp_name = inp.get("name", "")
                                if inp_name:
                                    form_data[inp_name] = inp.get("value", "")
                            for btn in form.find_all(["input", "button"]):
                                if btn.get("type", "").lower() == "submit" and btn.get("name"):
                                    form_data[btn.get("name")] = btn.get("value", "Submit")

                            action = form.get("action", "")
                            full_action = urljoin(sec_url, action) if action else sec_url
                            resp2 = _client.post(full_action, data=form_data,
                                                 cookies=_session_cookies, headers=_get_headers())
                            _session_cookies.update(dict(resp2.cookies))

                            # Also disable PHPIDS if present (DVWA-specific but harmless elsewhere)
                            try:
                                _client.get(urljoin(sec_url, "?phpids=off"),
                                           cookies=_session_cookies, headers=_get_headers())
                            except Exception:
                                pass
                            return
        except Exception:
            continue


def get_session_cookies() -> dict:
    """Return current session cookies."""
    return _session_cookies


def set_session_cookies(cookies: dict):
    """Set session cookies directly (for backward compat)."""
    global _session_cookies
    _session_cookies = cookies


def _get_cookies(cookies: Optional[dict] = None) -> dict:
    """Get cookies: use provided, or fall back to session cookies."""
    if cookies:
        return cookies
    return _session_cookies


def _get_headers() -> dict:
    """Get auth headers (for basic/bearer auth)."""
    return get_auth_headers()


# ── Tool implementations ─────────────────────────────────────────────

def send_http_request(url: str, method: str = "GET", headers: Optional[dict] = None,
                      body: Optional[str] = None, cookies: Optional[dict] = None) -> dict:
    """Send an HTTP request and return status, headers, and body."""
    cookies = _get_cookies(cookies)
    req_headers = dict(_get_headers())
    if headers:
        req_headers.update(headers)
    try:
        response = _client.request(
            method=method.upper(),
            url=url,
            headers=req_headers,
            content=body,
            cookies=cookies,
        )
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:5000],
            "url": str(response.url),
        }
    except Exception as e:
        return {"error": str(e)}


def extract_forms(url: str, cookies: Optional[dict] = None) -> dict:
    """Fetch a page and extract all HTML forms with their inputs."""
    cookies = _get_cookies(cookies)
    try:
        resp = _client.get(url, cookies=cookies, headers=_get_headers())
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            full_action = urljoin(url, action) if action else url
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
            forms.append({
                "action": full_action,
                "method": form.get("method", "GET").upper(),
                "inputs": inputs,
            })
        return {"forms": forms, "count": len(forms)}
    except Exception as e:
        return {"error": str(e)}


def check_response_contains(url: str, method: str = "GET", body: Optional[str] = None,
                            cookies: Optional[dict] = None,
                            search_string: str = "") -> dict:
    """
    Send a request and check if the response contains a specific string.
    Used for DETERMINISTIC VALIDATION.
    """
    cookies = _get_cookies(cookies)
    try:
        resp = _client.request(method=method.upper(), url=url, content=body,
                               cookies=cookies, headers=_get_headers())
        found = search_string in resp.text
        return {
            "found": found,
            "search_string": search_string,
            "status_code": resp.status_code,
            "snippet": resp.text[:2000],
        }
    except Exception as e:
        return {"error": str(e)}


def crawl_links(url: str, cookies: Optional[dict] = None) -> dict:
    """Crawl a page and return all links found (for recon)."""
    cookies = _get_cookies(cookies)
    try:
        resp = _client.get(url, cookies=cookies, headers=_get_headers())
        soup = BeautifulSoup(resp.text, "html.parser")
        links = set()
        for a in soup.find_all("a", href=True):
            full = urljoin(url, a["href"])
            links.add(full)
        return {"links": sorted(links), "count": len(links)}
    except Exception as e:
        return {"error": str(e)}


def scan_target(base_url: str, max_depth: int = 3, max_pages: int = 100,
                cookies: Optional[dict] = None) -> dict:
    """
    Deep-crawl a target website and return a complete attack surface map.
    Returns all pages, forms, parameters, and detected technologies.
    """
    cookies = _get_cookies(cookies)
    try:
        result = crawl_target(
            base_url=base_url,
            cookies=cookies,
            max_depth=max_depth,
            max_pages=max_pages,
        )
        # Re-set security level after crawl — the crawler may have
        # inadvertently changed it by submitting settings forms
        if base_url:
            _try_set_low_security(base_url)
        return result
    except Exception as e:
        return {"error": str(e)}


def validate_finding(vuln_type: str, url: str, method: str = "GET",
                     param_name: str = "", cookies: Optional[dict] = None,
                     extra_params: Optional[dict] = None) -> dict:
    """
    Run DETERMINISTIC VALIDATION on a suspected vulnerability.
    This uses code-based checks (canary strings, regex patterns) — NOT the LLM.
    Returns validated: true/false with evidence.
    """
    cookies = _get_cookies(cookies)
    if extra_params is None:
        extra_params = {}

    # Auto-detect submit buttons and hidden fields from the form
    # This fixes apps like DVWA that require "Submit=Submit" in the request
    if not extra_params:
        try:
            resp = _client.get(url, cookies=cookies, headers=_get_headers())
            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                # Find submit buttons (input type=submit and button type=submit)
                for btn in form.find_all(["input", "button"]):
                    btn_type = btn.get("type", "").lower()
                    btn_name = btn.get("name", "")
                    if btn_type == "submit" and btn_name:
                        extra_params[btn_name] = btn.get("value", "Submit")
                # Find hidden fields (CSRF tokens, etc.) but skip the param we're testing
                for inp in form.find_all("input", {"type": "hidden"}):
                    name = inp.get("name", "")
                    if name and name != param_name:
                        extra_params[name] = inp.get("value", "")
                # Only use the first form that has our param or any submit button
                form_params = [i.get("name", "") for i in form.find_all(["input", "textarea", "select"])]
                if param_name in form_params or extra_params:
                    break
        except Exception:
            pass

    vuln_type_lower = vuln_type.lower()

    if "sql" in vuln_type_lower:
        return validate_sqli(url, method, param_name, "1'", cookies, extra_params)

    elif "xss" in vuln_type_lower or "cross-site scripting" in vuln_type_lower:
        return validate_xss(url, method, param_name, cookies, extra_params)

    elif "command" in vuln_type_lower or "exec" in vuln_type_lower:
        return validate_command_injection(url, method, param_name, cookies, extra_params)

    elif "path" in vuln_type_lower or "traversal" in vuln_type_lower or "lfi" in vuln_type_lower or "file" in vuln_type_lower or "inclusion" in vuln_type_lower:
        return validate_path_traversal(url, method, param_name, cookies, extra_params)

    elif "csrf" in vuln_type_lower:
        return validate_csrf(url, method, param_name, cookies, extra_params)

    elif "idor" in vuln_type_lower or "direct object" in vuln_type_lower:
        return validate_idor(url, method, param_name, cookies, extra_params)

    elif "redirect" in vuln_type_lower:
        return validate_open_redirect(url, method, param_name, cookies, extra_params)

    elif "ssrf" in vuln_type_lower:
        return validate_ssrf(url, method, param_name, cookies, extra_params)

    elif "header" in vuln_type_lower or "security header" in vuln_type_lower:
        return validate_security_headers(url, method, param_name, cookies, extra_params)

    elif "sensitive" in vuln_type_lower or "data exposure" in vuln_type_lower or "leak" in vuln_type_lower:
        return validate_sensitive_data(url, method, param_name, cookies, extra_params)

    elif "xxe" in vuln_type_lower or "xml" in vuln_type_lower:
        return validate_xxe(url, method, param_name, cookies, extra_params)

    else:
        return {"validated": False, "reason": f"Unknown vulnerability type: {vuln_type}"}


# ── Tool schemas ─────────────────────────────────────────────────────

TOOL_SCHEMAS = [
    {
        "name": "authenticate",
        "description": (
            "Authenticate to the target application. Supports form login (auto-detects CSRF tokens), "
            "cookie-based, HTTP Basic, and Bearer token auth. Session is stored for all subsequent requests."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "auth_type": {"type": "string", "enum": ["form", "cookie", "basic", "bearer"],
                              "description": "Authentication method"},
                "login_url": {"type": "string", "description": "Login page URL (for form auth)"},
                "username": {"type": "string", "description": "Username"},
                "password": {"type": "string", "description": "Password"},
                "username_field": {"type": "string", "description": "Form field name for username (auto-detected if omitted)"},
                "password_field": {"type": "string", "description": "Form field name for password (auto-detected if omitted)"},
                "cookies": {"type": "object", "description": "Cookies dict (for cookie auth)"},
                "bearer_token": {"type": "string", "description": "Bearer token (for bearer auth)"},
                "success_indicator": {"type": "string", "description": "String in response that confirms login worked"},
            },
            "required": ["auth_type"],
        },
    },
    {
        "name": "send_http_request",
        "description": "Send an HTTP request to a URL. Returns status code, headers, and body.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The full URL to request"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"], "default": "GET"},
                "headers": {"type": "object", "description": "Optional HTTP headers"},
                "body": {"type": "string", "description": "Optional request body"},
                "cookies": {"type": "object", "description": "Optional cookies"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "extract_forms",
        "description": "Extract all HTML forms from a page with their inputs. Great for finding attack surfaces.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "cookies": {"type": "object"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "check_response_contains",
        "description": "Check if a response contains a specific string. Use for validation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                "body": {"type": "string"},
                "cookies": {"type": "object"},
                "search_string": {"type": "string"},
            },
            "required": ["url", "search_string"],
        },
    },
    {
        "name": "crawl_links",
        "description": "Extract all hyperlinks from a single page. For quick reconnaissance.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "cookies": {"type": "object"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "scan_target",
        "description": (
            "Deep-crawl a website and return a complete attack surface map. "
            "Returns all pages, forms, parameters, and technologies found. "
            "Use this FIRST on any new target to discover what to test."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "The target website URL"},
                "max_depth": {"type": "integer", "description": "How deep to crawl (default 3)", "default": 3},
                "max_pages": {"type": "integer", "description": "Max pages to visit (default 100)", "default": 100},
            },
            "required": ["base_url"],
        },
    },
    {
        "name": "validate_finding",
        "description": (
            "IMPORTANT: Use this to CONFIRM a vulnerability using deterministic code-based checks. "
            "This runs canary-string injection and regex pattern matching — NOT the LLM. "
            "A finding is only real if this returns validated: true. "
            "Supported types: sqli, xss, command_injection, path_traversal, csrf, idor, "
            "open_redirect, ssrf, security_headers, sensitive_data"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "vuln_type": {
                    "type": "string",
                    "description": (
                        "Type: 'sqli', 'xss', 'command_injection', 'path_traversal', "
                        "'csrf', 'idor', 'open_redirect', 'ssrf', 'security_headers', 'sensitive_data'"
                    ),
                },
                "url": {"type": "string", "description": "The vulnerable URL/endpoint"},
                "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                "param_name": {"type": "string", "description": "The parameter name to test"},
                "extra_params": {"type": "object", "description": "Extra form params to include (e.g., Submit buttons)"},
                "cookies": {"type": "object"},
            },
            "required": ["vuln_type", "url", "param_name"],
        },
    },
]


# ── Dispatcher: maps tool name → function ────────────────────────────

TOOL_DISPATCH = {
    "authenticate": authenticate,
    "send_http_request": send_http_request,
    "extract_forms": extract_forms,
    "check_response_contains": check_response_contains,
    "crawl_links": crawl_links,
    "scan_target": scan_target,
    "validate_finding": validate_finding,
}
