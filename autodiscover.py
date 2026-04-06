"""
Auto-Discovery Engine — Black-box target reconnaissance.

Given just a URL, automatically discovers:
  - Login pages and authentication type
  - Technology stack (server, framework, CMS, language)
  - Form fields (username/password field names)
  - Robots.txt, sitemap.xml, common paths
  - Security headers baseline
  - WAF detection
"""

import re
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
from rich.console import Console

console = Console()


# ── Common login paths to probe ──────────────────────────────────────────
LOGIN_PATHS = [
    "/login", "/login.php", "/login.html", "/login.asp", "/login.aspx",
    "/signin", "/sign-in", "/auth/login", "/user/login", "/users/sign_in",
    "/account/login", "/admin/login", "/admin", "/administrator",
    "/wp-login.php", "/wp-admin",
    "/api/auth/login", "/api/login", "/api/v1/auth/login",
    "/auth", "/authenticate", "/session/new",
    "/portal/login", "/members/login",
    "/index.php?action=login", "/index.php/login",
]

# ── Common sensitive/interesting paths ───────────────────────────────────
INTERESTING_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.env", "/config.php", "/config.yml",
    "/backup", "/debug", "/test", "/info.php", "/phpinfo.php",
    "/.git/HEAD", "/.svn/entries", "/.htaccess", "/web.config",
    "/server-status", "/server-info",
    "/api", "/api/v1", "/api/v2", "/graphql", "/swagger.json",
    "/openapi.json", "/api-docs", "/docs",
    "/admin", "/dashboard", "/panel", "/console",
    "/.well-known/security.txt", "/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
]

# ── WAF signatures ───────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
    "AWS WAF": ["x-amzn-requestid", "awselb"],
    "Akamai": ["akamai", "x-akamai"],
    "Sucuri": ["sucuri", "x-sucuri"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Imperva": ["imperva", "incapsula", "x-iinfo"],
    "F5 BIG-IP": ["bigipserver", "x-wa-info"],
    "Barracuda": ["barra_counter_session"],
    "Fortinet": ["fortigate", "fortiwaf"],
}


class AutoDiscovery:
    """Black-box target reconnaissance engine."""

    def __init__(self, target_url: str, timeout: int = 10):
        self.target = target_url.rstrip("/")
        self.parsed = urlparse(self.target)
        self.client = httpx.Client(
            timeout=timeout, follow_redirects=True, verify=False
        )
        self.no_redirect = httpx.Client(
            timeout=timeout, follow_redirects=False, verify=False
        )
        self.results = {
            "target": self.target,
            "reachable": False,
            "status_code": None,
            "technologies": [],
            "server": None,
            "waf_detected": None,
            "login_pages": [],
            "login_form": None,
            "interesting_paths": [],
            "security_headers": {},
            "robots_txt": None,
            "sitemap_urls": [],
            "cms": None,
            "auth_type_guess": "none",
        }

    def run_all(self) -> dict:
        """Run full auto-discovery. Returns results dict."""
        console.print("  [dim]Checking target reachability...[/]")
        if not self._check_reachable():
            return self.results

        console.print("  [dim]Fingerprinting technology stack...[/]")
        self._fingerprint_tech()

        console.print("  [dim]Detecting WAF...[/]")
        self._detect_waf()

        console.print("  [dim]Checking security headers...[/]")
        self._check_security_headers()

        console.print("  [dim]Scanning for login pages...[/]")
        self._find_login_pages()

        console.print("  [dim]Probing interesting paths...[/]")
        self._probe_interesting_paths()

        console.print("  [dim]Fetching robots.txt & sitemap...[/]")
        self._fetch_robots_sitemap()

        return self.results

    def _check_reachable(self) -> bool:
        """Check if target is reachable."""
        try:
            resp = self.client.get(self.target)
            self.results["reachable"] = True
            self.results["status_code"] = resp.status_code
            self._homepage_resp = resp
            return True
        except Exception as e:
            self.results["reachable"] = False
            self.results["error"] = str(e)
            return False

    def _fingerprint_tech(self):
        """Detect server, framework, CMS from headers and body."""
        resp = self._homepage_resp
        headers = dict(resp.headers)
        body = resp.text.lower()

        # Server header
        server = headers.get("server", "")
        if server:
            self.results["server"] = server
            self.results["technologies"].append(f"Server: {server}")

        # X-Powered-By
        powered = headers.get("x-powered-by", "")
        if powered:
            self.results["technologies"].append(f"Powered-By: {powered}")

        # PHP detection
        if "x-powered-by" in headers and "php" in headers["x-powered-by"].lower():
            self.results["technologies"].append("PHP")
        if any(k.lower() == "phpsessid" for k in resp.cookies.keys()):
            self.results["technologies"].append("PHP (PHPSESSID)")

        # ASP.NET
        if "x-aspnet-version" in headers or "x-aspnetmvc-version" in headers:
            self.results["technologies"].append("ASP.NET")
        if any("asp.net" in k.lower() for k in resp.cookies.keys()):
            self.results["technologies"].append("ASP.NET (cookie)")

        # CMS detection from body
        cms_patterns = {
            "WordPress": ["wp-content", "wp-includes", "wp-json"],
            "Joomla": ["joomla", "/components/com_"],
            "Drupal": ["drupal", "sites/default/files"],
            "Django": ["csrfmiddlewaretoken", "__admin__"],
            "Laravel": ["laravel_session", "laravel"],
            "Express": ["x-powered-by: express"],
            "Rails": ["x-request-id", "_rails"],
            "Spring": ["jsessionid"],
        }
        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                if pattern in body or pattern in str(headers).lower():
                    self.results["cms"] = cms
                    self.results["technologies"].append(f"CMS: {cms}")
                    break
            if self.results["cms"]:
                break

        # Framework hints from cookies
        cookie_frameworks = {
            "JSESSIONID": "Java (Servlet/Spring)",
            "connect.sid": "Node.js (Express)",
            "rack.session": "Ruby (Rack/Rails)",
            "laravel_session": "Laravel",
            "_csrf": "CSRF-protected framework",
        }
        for cookie_name, framework in cookie_frameworks.items():
            if any(cookie_name.lower() in k.lower() for k in resp.cookies.keys()):
                self.results["technologies"].append(framework)

    def _detect_waf(self):
        """Detect WAF by sending a suspicious request and checking response."""
        # Check headers from homepage
        headers_str = str(dict(self._homepage_resp.headers)).lower()
        cookies_str = str(dict(self._homepage_resp.cookies)).lower()

        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig in headers_str or sig in cookies_str:
                    self.results["waf_detected"] = waf_name
                    return

        # Try sending a suspicious payload to trigger WAF
        try:
            test_url = f"{self.target}/?test=<script>alert(1)</script>"
            resp = self.client.get(test_url)
            if resp.status_code in (403, 406, 429, 503):
                self.results["waf_detected"] = "Unknown WAF (blocked test payload)"
            # Check response for WAF indicators
            resp_lower = resp.text.lower()
            if any(w in resp_lower for w in ["blocked", "firewall", "security", "waf"]):
                if resp.status_code != 200 or len(resp.text) < 2000:
                    self.results["waf_detected"] = "Possible WAF (blocked response)"
        except Exception:
            pass

    def _check_security_headers(self):
        """Audit security headers on the homepage."""
        headers = dict(self._homepage_resp.headers)
        headers_lower = {k.lower(): v for k, v in headers.items()}

        security_headers = {
            "Strict-Transport-Security": headers_lower.get("strict-transport-security"),
            "Content-Security-Policy": headers_lower.get("content-security-policy"),
            "X-Frame-Options": headers_lower.get("x-frame-options"),
            "X-Content-Type-Options": headers_lower.get("x-content-type-options"),
            "X-XSS-Protection": headers_lower.get("x-xss-protection"),
            "Referrer-Policy": headers_lower.get("referrer-policy"),
            "Permissions-Policy": headers_lower.get("permissions-policy"),
        }
        self.results["security_headers"] = {
            k: v if v else "MISSING" for k, v in security_headers.items()
        }

    def _find_login_pages(self):
        """Probe common login paths and detect login forms."""
        from bs4 import BeautifulSoup

        found_logins = []

        for path in LOGIN_PATHS:
            url = urljoin(self.target + "/", path.lstrip("/"))
            try:
                resp = self.no_redirect.get(url)
                # Follow one redirect to see where it lands
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if location:
                        if not location.startswith("http"):
                            location = urljoin(url, location)
                        resp = self.client.get(location)
                        url = location

                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    password_inputs = soup.find_all("input", {"type": "password"})
                    if password_inputs:
                        # Found a login form
                        form_info = self._extract_form_details(soup, url)
                        if form_info:
                            found_logins.append(form_info)

            except Exception:
                continue

        # Also check if homepage itself has a login form
        try:
            soup = BeautifulSoup(self._homepage_resp.text, "html.parser")
            if soup.find("input", {"type": "password"}):
                form_info = self._extract_form_details(soup, self.target)
                if form_info:
                    found_logins.append(form_info)
        except Exception:
            pass

        # Deduplicate by URL
        seen_urls = set()
        unique_logins = []
        for login in found_logins:
            if login["url"] not in seen_urls:
                seen_urls.add(login["url"])
                unique_logins.append(login)

        self.results["login_pages"] = unique_logins

        # Pick the best login form
        if unique_logins:
            self.results["login_form"] = unique_logins[0]
            self.results["auth_type_guess"] = "form"

    def _extract_form_details(self, soup, page_url: str) -> Optional[dict]:
        """Extract login form field names and action URL."""
        forms = soup.find_all("form")
        for form in forms:
            password_field = form.find("input", {"type": "password"})
            if not password_field:
                continue

            # Get username field (text, email, or tel input)
            username_field = form.find("input", {"type": ["text", "email", "tel"]})
            # Fallback: any input that's not password, hidden, submit, checkbox, radio
            if not username_field:
                for inp in form.find_all("input"):
                    if inp.get("type", "text") not in ("password", "hidden", "submit",
                                                         "checkbox", "radio", "button"):
                        username_field = inp
                        break

            # Get form action
            action = form.get("action", "")
            if action:
                if not action.startswith("http"):
                    action = urljoin(page_url, action)
            else:
                action = page_url

            # Get form method
            method = form.get("method", "POST").upper()

            # Extract hidden fields
            hidden_fields = {}
            for hidden in form.find_all("input", {"type": "hidden"}):
                name = hidden.get("name")
                value = hidden.get("value", "")
                if name:
                    hidden_fields[name] = value

            return {
                "url": page_url,
                "action": action,
                "method": method,
                "username_field": username_field.get("name", "username") if username_field else "username",
                "password_field": password_field.get("name", "password"),
                "hidden_fields": hidden_fields,
                "has_csrf": bool(hidden_fields),
            }

        return None

    def _probe_interesting_paths(self):
        """Probe for sensitive/interesting paths."""
        found = []
        for path in INTERESTING_PATHS:
            url = urljoin(self.target + "/", path.lstrip("/"))
            try:
                resp = self.client.get(url)
                if resp.status_code == 200 and len(resp.text) > 50:
                    # Skip if it's just the homepage (soft 404)
                    if len(resp.text) != len(self._homepage_resp.text):
                        found.append({
                            "path": path,
                            "url": url,
                            "status": resp.status_code,
                            "size": len(resp.text),
                        })
            except Exception:
                continue

        self.results["interesting_paths"] = found

    def _fetch_robots_sitemap(self):
        """Fetch robots.txt and sitemap.xml for additional paths."""
        # robots.txt
        try:
            resp = self.client.get(urljoin(self.target + "/", "robots.txt"))
            if resp.status_code == 200 and "user-agent" in resp.text.lower():
                self.results["robots_txt"] = resp.text[:2000]
                # Extract disallowed paths
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            self.results["interesting_paths"].append({
                                "path": path,
                                "url": urljoin(self.target + "/", path.lstrip("/")),
                                "status": "from robots.txt",
                                "size": 0,
                            })
        except Exception:
            pass

        # sitemap.xml
        try:
            resp = self.client.get(urljoin(self.target + "/", "sitemap.xml"))
            if resp.status_code == 200 and "<url" in resp.text.lower():
                urls = re.findall(r"<loc>(.*?)</loc>", resp.text, re.IGNORECASE)
                self.results["sitemap_urls"] = urls[:50]
        except Exception:
            pass

    def close(self):
        """Close HTTP clients."""
        self.client.close()
        self.no_redirect.close()
