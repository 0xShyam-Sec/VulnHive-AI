"""
Traffic Recorder — Uses Playwright to record all API calls made by a SPA.

Navigates every page/route of the app while logged in, intercepts all
XHR/fetch requests, and returns a complete API surface map.

Usage:
    from traffic_recorder import TrafficRecorder
    recorder = TrafficRecorder("https://app.example.com",
                                bearer_token="eyJ...",
                                cookies={"session": "..."})
    result = recorder.record(navigate_routes=["#/orders", "#/users", "#/settings"])
    # result = {
    #   "api_calls": [{"method": "GET", "url": "...", "request_body": ..., "response_status": 200}, ...],
    #   "test_targets": [{"url": "...", "param": "...", "method": "..."}, ...],
    #   "unique_endpoints": 47,
    # }
"""

import re
import json
import time
from urllib.parse import urlparse, parse_qs
from typing import Optional
from rich.console import Console

console = Console()


class TrafficRecorder:

    def __init__(self, base_url: str,
                 bearer_token: Optional[str] = None,
                 cookies: Optional[dict] = None,
                 timeout: int = 15000,
                 api_base_patterns: Optional[list] = None):
        self.base_url = base_url.rstrip('/')
        self.bearer_token = bearer_token
        self.cookies = cookies or {}
        self.timeout = timeout
        # Patterns to identify API calls (vs static assets)
        self.api_patterns = api_base_patterns or [
            r'/api/', r'/v\d/', r'/rest/', r'/graphql', r'\.json$',
            r'-api\.', r'api-', r'\.locus-api\.', r'locus-api-',
        ]

    def record(self, navigate_routes: Optional[list] = None,
               wait_per_route: int = 3) -> dict:
        """
        Navigate the app, record all API calls.
        Returns complete list of API calls + test targets.
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {'api_calls': [], 'test_targets': [], 'unique_endpoints': 0,
                    'error': 'playwright not installed'}

        api_calls = []
        recorded_urls = set()

        console.print(f"  [cyan]TrafficRecorder: recording {self.base_url}...[/]")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)

            # Set auth headers/cookies
            if self.cookies:
                context.add_cookies([
                    {'name': k, 'value': v, 'url': self.base_url}
                    for k, v in self.cookies.items()
                ])

            # Intercept all requests to capture API calls
            def on_request(req):
                url = req.url
                if not self._is_api_call(url):
                    return
                if url in recorded_urls:
                    return
                recorded_urls.add(url)
                try:
                    body = req.post_data
                except Exception:
                    body = None
                api_calls.append({
                    'method': req.method,
                    'url': url,
                    'request_body': body,
                    'headers': dict(req.headers),
                })

            def on_response(resp):
                url = resp.url
                for call in api_calls:
                    if call['url'] == url and 'response_status' not in call:
                        call['response_status'] = resp.status
                        try:
                            ct = resp.headers.get('content-type', '')
                            if 'json' in ct and resp.status == 200:
                                call['response_preview'] = resp.text()[:500]
                        except Exception:
                            pass
                        break

            context.on('request', on_request)
            context.on('response', on_response)

            page = context.new_page()

            # Set bearer token via extra HTTP headers if provided
            if self.bearer_token:
                context.set_extra_http_headers({
                    'Authorization': f'Bearer {self.bearer_token}'
                })

            # Navigate to base URL
            try:
                page.goto(self.base_url, wait_until='networkidle', timeout=30000)
                time.sleep(wait_per_route)
            except Exception as e:
                console.print(f"  [dim]Base URL load error: {e}[/]")

            # Navigate to each additional route
            routes = navigate_routes or []
            # Auto-discover routes from the page
            auto_routes = self._discover_routes(page)
            all_routes = list(dict.fromkeys(routes + auto_routes))  # dedupe preserving order

            console.print(f"  [dim]Navigating {len(all_routes)} routes...[/]")

            for route in all_routes[:20]:  # cap at 20 routes
                try:
                    if route.startswith('#'):
                        full_url = self.base_url + '/' + route
                    elif route.startswith('http'):
                        full_url = route
                    else:
                        full_url = self.base_url + route

                    page.goto(full_url, wait_until='networkidle', timeout=self.timeout)
                    time.sleep(wait_per_route)

                    # Interact with the page to trigger more API calls
                    self._interact_with_page(page)
                    time.sleep(1)

                except Exception as e:
                    console.print(f"  [dim]Route {route}: {e}[/]")

            context.close()
            browser.close()

        # Build test targets from recorded calls
        test_targets = self._build_test_targets(api_calls)

        console.print(
            f"  [bold]TrafficRecorder: {len(api_calls)} API calls, "
            f"{len(test_targets)} test targets[/]"
        )

        return {
            'api_calls': api_calls,
            'test_targets': test_targets,
            'unique_endpoints': len(set(c['url'].split('?')[0] for c in api_calls)),
        }

    def _is_api_call(self, url: str) -> bool:
        """Check if a URL looks like an API call (not a static asset)."""
        # Skip static assets
        skip_exts = ('.js', '.css', '.png', '.jpg', '.gif', '.ico', '.woff',
                     '.ttf', '.svg', '.map', '.txt', '.html')
        parsed = urlparse(url)
        path = parsed.path.lower()
        if any(path.endswith(e) for e in skip_exts):
            return False
        # Skip analytics/tracking
        skip_domains = ['google-analytics', 'newrelic', 'nr-data', 'hotjar',
                        'intercom', 'mixpanel', 'segment', 'pendo', 'bam.nr',
                        'fonts.googleapis', 'gstatic']
        if any(d in url.lower() for d in skip_domains):
            return False
        # Must match API patterns OR be a JSON/data endpoint
        for pattern in self.api_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    def _discover_routes(self, page) -> list:
        """Auto-discover navigation routes from the current page."""
        routes = []
        try:
            # Find nav links and menu items
            links = page.locator('a[href], [role="menuitem"], nav a').all()
            for link in links[:50]:
                try:
                    href = link.get_attribute('href') or ''
                    if href and not href.startswith('javascript') and not href.startswith('mailto'):
                        routes.append(href)
                except Exception:
                    pass
        except Exception:
            pass
        return routes

    def _interact_with_page(self, page):
        """Click common UI elements to trigger more API calls."""
        try:
            # Click tabs
            tabs = page.locator('[role="tab"]').all()
            for tab in tabs[:3]:
                try:
                    tab.click()
                    time.sleep(0.5)
                except Exception:
                    pass
            # Click filter/sort buttons
            for selector in ['[data-testid*="filter"]', 'button[aria-label*="filter" i]',
                              '[class*="filter"]', '[class*="sort"]']:
                try:
                    btns = page.locator(selector).all()
                    for btn in btns[:2]:
                        btn.click()
                        time.sleep(0.5)
                except Exception:
                    pass
        except Exception:
            pass

    def _build_test_targets(self, api_calls: list) -> list:
        """Convert recorded API calls to test targets."""
        targets = []
        seen = set()

        for call in api_calls:
            url = call['url']
            method = call['method'].upper()
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # Query parameters
            query_params = parse_qs(parsed.query)
            for param_name in query_params:
                key = (base_url, param_name, method)
                if key not in seen:
                    seen.add(key)
                    targets.append({
                        'url': base_url,
                        'param': param_name,
                        'method': method,
                        'source': 'traffic_recorder',
                    })

            # Request body parameters
            if call.get('request_body'):
                try:
                    body = json.loads(call['request_body'])
                    if isinstance(body, dict):
                        for param_name in body:
                            key = (base_url, param_name, method)
                            if key not in seen:
                                seen.add(key)
                                targets.append({
                                    'url': base_url,
                                    'param': param_name,
                                    'method': method,
                                    'source': 'traffic_recorder',
                                })
                except Exception:
                    pass

            # Endpoint with no params (for passive checks)
            key = (base_url, '', method)
            if key not in seen:
                seen.add(key)
                targets.append({
                    'url': base_url,
                    'param': '',
                    'method': method,
                    'source': 'traffic_recorder',
                })

        return targets
