"""
OAuth / Auth0 / OIDC Auto-Handler — Browser-based authentication for modern SSO flows.

Handles:
- Auth0 (universal login, PKCE)
- Okta hosted login
- Cognito hosted UI
- Generic OAuth2 Authorization Code + PKCE flow
- Multi-step login (client ID → username → password)

Usage:
    from oauth_handler import OAuthHandler
    handler = OAuthHandler("https://app.example.com")

    # Auto-detect and complete login
    result = handler.login(username="user@example.com", password="pass123",
                           client_id="myorg")  # optional, for multi-tenant apps
    # result = {
    #   "success": True,
    #   "access_token": "eyJ...",
    #   "cookies": {"auth0.xxx.is.authenticated": "true", ...},
    #   "provider": "auth0",
    #   "user": {"email": "...", "name": "..."},
    # }
"""

import re
import json
import time
from typing import Optional
from rich.console import Console

console = Console()

# Known OAuth provider detection patterns
PROVIDER_PATTERNS = {
    'auth0': [
        r'auth0\.com',
        r'\.auth0\.com',
        r'isAuth0Available.*true',
        r'auth0-react',
        r'accounts\.[a-z-]+\.com/login',
    ],
    'okta': [
        r'okta\.com',
        r'\.okta\.com',
        r'oktacdn\.com',
    ],
    'cognito': [
        r'cognito',
        r'amazoncognito\.com',
        r'aws.*cognito',
    ],
    'google': [
        r'accounts\.google\.com',
        r'google.*oauth',
    ],
    'azure': [
        r'login\.microsoftonline\.com',
        r'microsoft.*oauth',
    ],
}


class OAuthHandler:
    """
    Handles OAuth/OIDC login flows automatically using Playwright.
    Detects the provider from the app's config/response and completes
    the full authorization code + PKCE flow.
    """

    def __init__(self, base_url: str, timeout: int = 30000):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self._playwright = None
        self._browser = None
        self._context = None

    def detect_provider(self) -> Optional[str]:
        """
        Detect which OAuth provider the app uses without a full browser.
        Checks: HTML source, config API endpoints, response headers.
        """
        import httpx
        client = httpx.Client(timeout=10, verify=False,
                               headers={'User-Agent': 'Mozilla/5.0'})
        try:
            resp = client.get(self.base_url, follow_redirects=True)
            content = resp.text

            # Check common config API endpoints
            for path in ['/v1/config', '/api/config', '/config', '/auth/config']:
                try:
                    cr = client.get(self.base_url.rstrip('/') + path)
                    if cr.status_code == 200:
                        content += cr.text
                except Exception:
                    pass

            for provider, patterns in PROVIDER_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return provider
        except Exception:
            pass
        finally:
            client.close()
        return None

    def login(self, username: str, password: str,
              client_id: Optional[str] = None,
              mfa_code: Optional[str] = None) -> dict:
        """
        Complete full OAuth login flow. Returns access token + cookies.
        Automatically handles multi-step flows (client ID → username → password).
        """
        provider = self.detect_provider()
        console.print(f"  [cyan]OAuthHandler: detected provider={provider or 'generic'}[/]")

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {'success': False, 'error': 'playwright not installed'}

        result = {'success': False, 'provider': provider or 'unknown'}

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()

                # Navigate to app
                page.goto(self.base_url, wait_until='networkidle', timeout=self.timeout)
                time.sleep(2)

                # Step 1: Enter client ID if multi-tenant
                if client_id:
                    self._fill_client_id(page, client_id)
                    time.sleep(2)

                # Step 2: Click LOGIN / Sign In button to trigger OAuth redirect
                self._click_login_button(page)
                time.sleep(3)

                # Step 3: Handle OAuth provider login page
                current_url = page.url
                detected = self._identify_current_provider(current_url)

                if detected == 'auth0' or (provider == 'auth0'):
                    self._complete_auth0_login(page, username, password, client_id)
                elif detected == 'okta' or (provider == 'okta'):
                    self._complete_okta_login(page, username, password)
                elif detected == 'cognito' or (provider == 'cognito'):
                    self._complete_cognito_login(page, username, password)
                else:
                    self._complete_generic_login(page, username, password)

                # Wait for redirect back to app
                time.sleep(5)
                try:
                    page.wait_for_load_state('networkidle', timeout=15000)
                except Exception:
                    pass
                time.sleep(2)

                # Extract tokens and cookies
                tokens = self._extract_tokens(page, context)
                result.update(tokens)
                result['final_url'] = page.url

                if tokens.get('access_token') or tokens.get('cookies'):
                    result['success'] = True
                    console.print(f"  [green]OAuthHandler: Login successful[/]")
                    if tokens.get('user'):
                        console.print(f"  [dim]User: {tokens['user']}[/]")
                else:
                    result['error'] = 'No token found after login'
                    console.print(f"  [yellow]OAuthHandler: Login may have failed — no token extracted[/]")

                context.close()
                browser.close()

        except Exception as e:
            result['error'] = str(e)
            console.print(f"  [red]OAuthHandler error: {e}[/]")

        return result

    def _fill_client_id(self, page, client_id: str):
        """Fill the client/tenant ID field if present (multi-tenant apps)."""
        try:
            # Try common client ID field selectors
            for selector in [
                'input[placeholder*="client" i]',
                'input[placeholder*="tenant" i]',
                'input[placeholder*="organization" i]',
                'input[name*="client" i]',
                'input[name*="tenant" i]',
                'input[type="text"]:first-of-type',
            ]:
                els = page.locator(selector).all()
                if els:
                    els[0].fill(client_id)
                    time.sleep(0.5)
                    # Click continue/next
                    for btn_text in ['CONTINUE', 'Continue', 'Next', 'NEXT', 'Submit']:
                        btns = page.locator(f'text={btn_text}').all()
                        if btns:
                            btns[0].click()
                            time.sleep(2)
                            break
                    return
        except Exception:
            pass
        # Fallback: press Enter
        try:
            page.keyboard.press('Enter')
            time.sleep(2)
        except Exception:
            pass

    def _click_login_button(self, page):
        """Click the main LOGIN/Sign In button."""
        login_texts = ['LOGIN', 'Log in', 'Sign in', 'SIGN IN', 'Log In', 'Continue', 'CONTINUE']
        for text in login_texts:
            try:
                btns = page.locator(f'button:has-text("{text}")').all()
                if btns:
                    btns[0].click()
                    time.sleep(3)
                    return
            except Exception:
                continue
        # Fallback: click first button
        try:
            page.locator('button').first.click()
            time.sleep(3)
        except Exception:
            pass

    def _identify_current_provider(self, url: str) -> Optional[str]:
        """Identify provider from current URL."""
        url_lower = url.lower()
        if 'auth0.com' in url_lower or '/login?state=' in url_lower:
            return 'auth0'
        if 'okta.com' in url_lower or '/login/login.htm' in url_lower:
            return 'okta'
        if 'amazoncognito.com' in url_lower or 'cognito' in url_lower:
            return 'cognito'
        if 'accounts.google.com' in url_lower:
            return 'google'
        if 'login.microsoftonline.com' in url_lower:
            return 'azure'
        return None

    def _complete_auth0_login(self, page, username: str, password: str, client_id: Optional[str] = None):
        """Complete Auth0 Universal Login (supports 1-step and 2-step flows)."""
        try:
            time.sleep(2)
            # Auth0 sometimes pre-fills username from hint, sometimes needs it
            username_selectors = [
                'input[placeholder="User ID"]',
                'input[placeholder*="email" i]',
                'input[placeholder*="username" i]',
                'input[name="username"]',
                'input[name="email"]',
                'input[type="email"]',
                'input[type="text"]:visible',
            ]
            for sel in username_selectors:
                try:
                    els = page.locator(sel).all()
                    if els:
                        els[0].fill(username)
                        time.sleep(0.5)
                        break
                except Exception:
                    continue

            # Check if this is a 2-step flow (username first, then password)
            # Click CONTINUE to advance to password step
            for btn_text in ['CONTINUE', 'Continue', 'Next', 'NEXT']:
                try:
                    btns = page.locator(f'button:has-text("{btn_text}")').all()
                    if btns:
                        btns[0].click()
                        time.sleep(3)
                        break
                except Exception:
                    continue

            # Now fill password
            pw_selectors = [
                'input[type="password"]',
                'input[placeholder*="password" i]',
                'input[name="password"]',
            ]
            for sel in pw_selectors:
                try:
                    els = page.locator(sel).all()
                    if els:
                        els[0].fill(password)
                        time.sleep(0.5)
                        break
                except Exception:
                    continue

            # Click LOGIN/Submit
            for btn_text in ['LOGIN', 'Log in', 'Sign in', 'SIGN IN', 'Continue', 'Submit']:
                try:
                    btns = page.locator(f'button:has-text("{btn_text}")').all()
                    if btns:
                        btns[0].click()
                        time.sleep(5)
                        break
                except Exception:
                    continue

        except Exception as e:
            console.print(f"  [dim]Auth0 login step error: {e}[/]")

    def _complete_okta_login(self, page, username: str, password: str):
        """Complete Okta hosted login."""
        try:
            page.fill('#okta-signin-username', username)
            time.sleep(0.5)
            page.fill('#okta-signin-password', password)
            time.sleep(0.5)
            page.click('#okta-signin-submit')
            time.sleep(5)
        except Exception:
            self._complete_generic_login(page, username, password)

    def _complete_cognito_login(self, page, username: str, password: str):
        """Complete AWS Cognito hosted UI login."""
        try:
            page.fill('input[name="username"]', username)
            time.sleep(0.5)
            page.fill('input[name="password"]', password)
            time.sleep(0.5)
            page.click('input[name="signInSubmitButton"]')
            time.sleep(5)
        except Exception:
            self._complete_generic_login(page, username, password)

    def _complete_generic_login(self, page, username: str, password: str):
        """Generic fallback login — fills first text input then password input."""
        try:
            inputs = page.locator('input[type="text"], input[type="email"]').all()
            if inputs:
                inputs[0].fill(username)
                time.sleep(0.5)
            pw_inputs = page.locator('input[type="password"]').all()
            if pw_inputs:
                pw_inputs[0].fill(password)
                time.sleep(0.5)
            # Submit
            page.keyboard.press('Enter')
            time.sleep(5)
        except Exception:
            pass

    def _extract_tokens(self, page, context) -> dict:
        """Extract access token and session cookies after login."""
        result = {}

        # LocalStorage tokens (Auth0 SPA SDK, Amplify, etc.)
        try:
            storage = page.evaluate(
                '() => { let r={}; for(let k of Object.keys(localStorage)) '
                '{ r[k]=localStorage.getItem(k); } return r; }'
            )
            for key, value in storage.items():
                if 'auth0spajs' in key or 'amplify' in key.lower():
                    try:
                        data = json.loads(value)
                        body = data.get('body', data)
                        if isinstance(body, dict) and 'access_token' in body:
                            result['access_token'] = body['access_token']
                            result['id_token'] = body.get('id_token')
                            result['expires_in'] = body.get('expires_in')
                    except Exception:
                        pass
                elif key.lower() in ('access_token', 'token', 'auth_token', 'bearer_token'):
                    result['access_token'] = value
        except Exception:
            pass

        # Session/Cookie tokens
        try:
            cookies = context.cookies()
            result['cookies'] = {
                c['name']: c['value']
                for c in cookies
                if c['value'] and len(c['value']) > 5
            }
        except Exception:
            result['cookies'] = {}

        # Try to get user info from /userinfo or /session/me
        if result.get('access_token'):
            try:
                import httpx
                r = httpx.get(
                    page.url.split('#')[0].split('?')[0].rstrip('/') + '/session/me',
                    headers={'Authorization': 'Bearer ' + result['access_token']},
                    verify=False, timeout=5
                )
                if r.status_code == 200:
                    user_data = r.json()
                    result['user'] = {
                        'id': user_data.get('id') or user_data.get('sub'),
                        'email': user_data.get('email'),
                        'name': user_data.get('name'),
                    }
            except Exception:
                pass

        return result
