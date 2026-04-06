"""
Generic Authentication Module — Works with any web app, not just DVWA.

Supports:
  - Form-based login (auto-detects CSRF tokens)
  - Cookie-based (manual session cookies)
  - HTTP Basic Auth
  - Bearer Token (OAuth/JWT)
"""

from typing import Optional
from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup


# Known CSRF token field name patterns
CSRF_PATTERNS = [
    "csrf", "csrftoken", "csrf_token", "_csrf",
    "token", "user_token", "_token",
    "csrfmiddlewaretoken",        # Django
    "authenticity_token",          # Rails
    "__requestverificationtoken",  # ASP.NET
    "anticsrf",
    "xsrf_token", "_xsrf",
]


@dataclass
class AuthConfig:
    """Authentication configuration."""
    auth_type: str = "form"     # form, cookie, basic, bearer

    # Form-based login
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    username_field: str = "username"
    password_field: str = "password"
    extra_fields: dict = field(default_factory=dict)
    success_indicator: Optional[str] = None

    # Cookie-based
    cookies: Optional[dict] = None

    # Basic auth
    basic_username: Optional[str] = None
    basic_password: Optional[str] = None

    # Bearer token
    bearer_token: Optional[str] = None


class Authenticator:
    """
    Generic authenticator that works with any web app.

    Usage:
        auth = Authenticator()
        config = AuthConfig(auth_type="form", login_url="http://target/login",
                           username="admin", password="password")
        result = auth.authenticate(config)
        cookies = auth.get_cookies()
        headers = auth.get_headers()
    """

    def __init__(self):
        self.client = httpx.Client(timeout=15, follow_redirects=True, verify=False)
        self.no_redirect_client = httpx.Client(timeout=15, follow_redirects=False, verify=False)
        self.session_cookies = {}
        self.auth_headers = {}

    def authenticate(self, config: AuthConfig) -> dict:
        """Authenticate using the configured method."""
        auth_type = config.auth_type.lower()

        if auth_type == "form":
            return self._form_login(config)
        elif auth_type == "cookie":
            return self._cookie_auth(config)
        elif auth_type == "basic":
            return self._basic_auth(config)
        elif auth_type == "bearer":
            return self._bearer_auth(config)
        else:
            return {"success": False, "error": f"Unknown auth type: {auth_type}"}

    def _detect_csrf_token(self, soup: BeautifulSoup) -> dict:
        """Auto-detect CSRF token fields in a page."""
        tokens = {}
        for inp in soup.find_all("input", {"type": "hidden"}):
            name = inp.get("name", "").lower()
            for pattern in CSRF_PATTERNS:
                if pattern in name:
                    tokens[inp.get("name", "")] = inp.get("value", "")
                    break
        return tokens

    def _detect_login_form(self, soup: BeautifulSoup) -> Optional[dict]:
        """Auto-detect the login form on a page."""
        for form in soup.find_all("form"):
            inputs = form.find_all(["input", "button"])
            input_names = [i.get("name", "").lower() for i in inputs]
            input_types = [i.get("type", "").lower() for i in inputs]

            has_password = "password" in input_types
            has_text = "text" in input_types or "email" in input_types

            if has_password and has_text:
                action = form.get("action", "")
                method = form.get("method", "POST").upper()

                # Find the username and password field names
                username_field = None
                password_field = None
                for inp in inputs:
                    inp_type = inp.get("type", "text").lower()
                    inp_name = inp.get("name", "")
                    if inp_type == "password" and not password_field:
                        password_field = inp_name
                    elif inp_type in ("text", "email") and not username_field:
                        username_field = inp_name

                return {
                    "action": action,
                    "method": method,
                    "username_field": username_field,
                    "password_field": password_field,
                }
        return None

    def _form_login(self, config: AuthConfig) -> dict:
        """
        Form-based login with auto CSRF token detection.
        Works with DVWA, bWAPP, Juice Shop, WordPress, Django apps, etc.
        """
        if not config.login_url:
            return {"success": False, "error": "login_url is required for form auth"}

        try:
            # Step 1: GET the login page
            resp = self.client.get(config.login_url)
            cookies = dict(resp.cookies)
            soup = BeautifulSoup(resp.text, "html.parser")

            # Step 2: Auto-detect CSRF tokens
            csrf_tokens = self._detect_csrf_token(soup)

            # Step 3: Auto-detect form structure if fields not specified
            username_field = config.username_field
            password_field = config.password_field
            form_info = self._detect_login_form(soup)
            if form_info:
                if not username_field or username_field == "username":
                    username_field = form_info["username_field"] or username_field
                if not password_field or password_field == "password":
                    password_field = form_info["password_field"] or password_field

            # Step 4: Build POST data
            login_data = {
                username_field: config.username or "",
                password_field: config.password or "",
            }
            login_data.update(csrf_tokens)
            login_data.update(config.extra_fields)

            # Also include submit buttons
            for btn in soup.find_all(["input", "button"]):
                btn_type = btn.get("type", "").lower()
                btn_name = btn.get("name", "")
                if btn_type == "submit" and btn_name:
                    login_data[btn_name] = btn.get("value", "Submit")

            # Step 5: POST the login
            resp2 = self.client.post(config.login_url, data=login_data, cookies=cookies)
            cookies.update(dict(resp2.cookies))

            # Step 6: Verify login success
            success = False
            reason = ""

            if config.success_indicator:
                if config.success_indicator in resp2.text:
                    success = True
                    reason = f"Found '{config.success_indicator}' in response"
                else:
                    reason = f"'{config.success_indicator}' not found in response"
            else:
                # Heuristic: check if we got redirected away from login page
                final_url = str(resp2.url)
                if config.login_url not in final_url:
                    success = True
                    reason = f"Redirected to {final_url}"
                # Check if session cookie was set
                elif len(cookies) > 0:
                    success = True
                    reason = "Session cookie received"
                # Check if login form is still present (login failed)
                soup2 = BeautifulSoup(resp2.text, "html.parser")
                if self._detect_login_form(soup2):
                    success = False
                    reason = "Login form still present — credentials likely wrong"

            if success:
                self.session_cookies = cookies

            return {
                "success": success,
                "message": f"Form login {'succeeded' if success else 'failed'}: {reason}",
                "cookies": cookies if success else {},
                "auth_type": "form",
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cookie_auth(self, config: AuthConfig) -> dict:
        """Direct cookie-based authentication."""
        if not config.cookies:
            return {"success": False, "error": "cookies dict is required for cookie auth"}

        self.session_cookies = dict(config.cookies)
        return {
            "success": True,
            "message": "Cookies set directly",
            "cookies": self.session_cookies,
            "auth_type": "cookie",
        }

    def _basic_auth(self, config: AuthConfig) -> dict:
        """HTTP Basic Authentication."""
        import base64
        username = config.basic_username or config.username or ""
        password = config.basic_password or config.password or ""

        if not username:
            return {"success": False, "error": "username is required for basic auth"}

        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.auth_headers["Authorization"] = f"Basic {credentials}"

        return {
            "success": True,
            "message": f"Basic auth configured for user '{username}'",
            "auth_type": "basic",
        }

    def _bearer_auth(self, config: AuthConfig) -> dict:
        """Bearer token authentication (OAuth/JWT)."""
        token = config.bearer_token
        if not token:
            return {"success": False, "error": "bearer_token is required"}

        self.auth_headers["Authorization"] = f"Bearer {token}"

        return {
            "success": True,
            "message": "Bearer token configured",
            "auth_type": "bearer",
        }

    def get_cookies(self) -> dict:
        """Return session cookies for use in requests."""
        return self.session_cookies

    def get_headers(self) -> dict:
        """Return auth headers for use in requests."""
        return self.auth_headers


# Module-level authenticator instance
_authenticator = Authenticator()


def authenticate(auth_type: str, login_url: Optional[str] = None,
                 username: Optional[str] = None, password: Optional[str] = None,
                 username_field: str = "username", password_field: str = "password",
                 cookies: Optional[dict] = None, bearer_token: Optional[str] = None,
                 success_indicator: Optional[str] = None,
                 extra_fields: Optional[dict] = None) -> dict:
    """
    Tool function: Authenticate to the target application.
    This is what the agent calls.
    """
    config = AuthConfig(
        auth_type=auth_type,
        login_url=login_url,
        username=username,
        password=password,
        username_field=username_field,
        password_field=password_field,
        extra_fields=extra_fields or {},
        success_indicator=success_indicator,
        cookies=cookies,
        basic_username=username,
        basic_password=password,
        bearer_token=bearer_token,
    )
    return _authenticator.authenticate(config)


def get_auth_cookies() -> dict:
    """Return current session cookies from the authenticator."""
    return _authenticator.get_cookies()


def get_auth_headers() -> dict:
    """Return current auth headers from the authenticator."""
    return _authenticator.get_headers()
