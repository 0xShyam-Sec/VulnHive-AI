"""
Session Manager — Keeps sessions alive during long scans.

Features:
  - Auto-detects session expiry (redirect to login, 401/403, login form in response)
  - Re-authenticates transparently when session dies
  - Wraps httpx.Client with session-aware request methods
  - Tracks session health metrics
"""

import time
from typing import Optional, Callable
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup


class SessionManager:
    """
    Wraps HTTP requests with automatic session monitoring and re-authentication.

    Usage:
        sm = SessionManager(
            base_url="http://localhost:8080",
            auth_func=lambda: authenticate(auth_type="form", ...),
            login_url="http://localhost:8080/login.php",
        )
        resp = sm.get("http://localhost:8080/dashboard")
        # If session expired, it re-authenticates and retries automatically
    """

    def __init__(
        self,
        base_url: str,
        auth_func: Optional[Callable] = None,
        login_url: Optional[str] = None,
        cookies: Optional[dict] = None,
        headers: Optional[dict] = None,
        max_retries: int = 2,
        timeout: int = 15,
    ):
        self.base_url = base_url.rstrip("/")
        self.login_url = login_url
        self.login_path = urlparse(login_url).path if login_url else "/login"
        self.auth_func = auth_func
        self.cookies = dict(cookies) if cookies else {}
        self.headers = dict(headers) if headers else {}
        self.max_retries = max_retries

        self.client = httpx.Client(
            timeout=timeout, follow_redirects=True, verify=False
        )
        self.no_redirect_client = httpx.Client(
            timeout=timeout, follow_redirects=False, verify=False
        )

        # Session health tracking
        self.total_requests = 0
        self.reauth_count = 0
        self.last_auth_time = 0.0
        self.session_valid = bool(cookies)

    def _is_session_expired(self, response: httpx.Response) -> bool:
        """
        Detect if the session has expired based on response characteristics.
        Returns True if we need to re-authenticate.
        """
        # Check 1: HTTP 401 Unauthorized or 403 Forbidden
        if response.status_code in (401, 403):
            return True

        # Check 2: Redirected to login page
        final_url = str(response.url)
        if self.login_url and self.login_path in final_url:
            # Make sure we weren't intentionally visiting the login page
            return True

        # Check 3: Response contains a login form (we got bounced to login)
        if response.status_code == 200 and len(response.text) > 100:
            try:
                soup = BeautifulSoup(response.text, "html.parser")
                # Look for password input (login form indicator)
                password_input = soup.find("input", {"type": "password"})
                if password_input:
                    # Make sure the page also has a text/email input (full login form)
                    text_input = soup.find("input", {"type": ["text", "email"]})
                    if text_input:
                        return True
            except Exception:
                pass

        # Check 4: Common session expired messages in response body
        expired_indicators = [
            "session expired", "session has expired", "session timeout",
            "please log in", "please login", "please sign in",
            "you must be logged in", "authentication required",
            "access denied", "not authorized",
        ]
        body_lower = response.text.lower()[:2000]
        for indicator in expired_indicators:
            if indicator in body_lower:
                # Avoid false positive: check that the page is short (error page)
                # or has a login form
                if len(response.text) < 5000:
                    return True

        return False

    def _re_authenticate(self) -> bool:
        """Re-authenticate using the stored auth function."""
        if not self.auth_func:
            return False

        try:
            result = self.auth_func()
            if result.get("success"):
                new_cookies = result.get("cookies", {})
                if new_cookies:
                    self.cookies.update(new_cookies)
                self.session_valid = True
                self.reauth_count += 1
                self.last_auth_time = time.time()
                return True
            return False
        except Exception:
            return False

    def _request(self, method: str, url: str, retries_left: int = None,
                 **kwargs) -> httpx.Response:
        """
        Make an HTTP request with automatic session management.
        If session expires, re-authenticates and retries.
        """
        if retries_left is None:
            retries_left = self.max_retries

        # Merge session cookies/headers with request-specific ones
        req_cookies = dict(self.cookies)
        req_cookies.update(kwargs.pop("cookies", {}) or {})

        req_headers = dict(self.headers)
        req_headers.update(kwargs.pop("headers", {}) or {})

        self.total_requests += 1

        response = self.client.request(
            method=method, url=url,
            cookies=req_cookies, headers=req_headers,
            **kwargs
        )

        # Update cookies from response
        if response.cookies:
            self.cookies.update(dict(response.cookies))

        # Check if session expired
        if self._is_session_expired(response) and retries_left > 0:
            self.session_valid = False
            if self._re_authenticate():
                # Retry the request with new session
                return self._request(
                    method, url, retries_left=retries_left - 1, **kwargs
                )

        return response

    def get(self, url: str, **kwargs) -> httpx.Response:
        """Session-aware GET request."""
        return self._request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        """Session-aware POST request."""
        return self._request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> httpx.Response:
        """Session-aware PUT request."""
        return self._request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> httpx.Response:
        """Session-aware DELETE request."""
        return self._request("DELETE", url, **kwargs)

    def get_no_redirect(self, url: str, **kwargs) -> httpx.Response:
        """GET without following redirects (for redirect testing)."""
        req_cookies = dict(self.cookies)
        req_cookies.update(kwargs.pop("cookies", {}) or {})
        req_headers = dict(self.headers)
        req_headers.update(kwargs.pop("headers", {}) or {})
        return self.no_redirect_client.get(
            url, cookies=req_cookies, headers=req_headers, **kwargs
        )

    def get_stats(self) -> dict:
        """Return session health statistics."""
        return {
            "total_requests": self.total_requests,
            "reauth_count": self.reauth_count,
            "session_valid": self.session_valid,
            "cookies_count": len(self.cookies),
            "last_auth_time": self.last_auth_time,
        }

    def update_cookies(self, cookies: dict):
        """Manually update session cookies."""
        self.cookies.update(cookies)
        self.session_valid = True

    def update_headers(self, headers: dict):
        """Manually update session headers."""
        self.headers.update(headers)
