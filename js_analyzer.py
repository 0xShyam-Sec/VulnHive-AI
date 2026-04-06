"""
JS Bundle Analyzer — Static analysis of JavaScript bundles for pentest recon.

Does three things:
1. Discovers and downloads all JS bundles from the target app
2. Extracts API route patterns hardcoded in the JavaScript
3. Scans for hardcoded secrets (API keys, JWT tokens, AWS credentials, passwords)

Usage:
    from js_analyzer import JSAnalyzer
    analyzer = JSAnalyzer("https://target.com")
    result = analyzer.run()
    # result = {
    #   "endpoints": [{"url": "/api/v1/users", "method": "GET", "source": "bundle.js"}, ...],
    #   "secrets": [{"type": "aws_key", "value": "AKIA...", "file": "main.js", "line": 42}, ...],
    #   "bundles_analyzed": 3,
    # }
"""

import re
import httpx
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from rich.console import Console

console = Console()

# ── Secret patterns ──────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    ("aws_access_key",     r'AKIA[0-9A-Z]{16}'),
    ("aws_secret_key",     r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']'),
    ("jwt_token",          r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    ("google_api_key",     r'AIza[0-9A-Za-z\-_]{35}'),
    ("stripe_key",         r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}'),
    ("github_token",       r'gh[pousr]_[A-Za-z0-9_]{36,}'),
    ("slack_token",        r'xox[baprs]-[0-9A-Za-z\-]{10,}'),
    ("private_key",        r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    ("basic_auth_url",     r'https?://[^:@\s]{3,}:[^@\s]{3,}@[^\s"\']+'),
    ("hardcoded_password", r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']'),
    ("api_key_generic",    r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']'),
    ("bearer_token",       r'(?i)bearer\s+([A-Za-z0-9\-_\.]{20,})'),
    ("sendgrid_key",       r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
    ("twilio_key",         r'SK[0-9a-fA-F]{32}'),
    ("firebase_url",       r'https://[a-z0-9-]+\.firebaseio\.com'),
    ("internal_ip",        r'(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}'),
]

# ── API route patterns ────────────────────────────────────────────────────────

ROUTE_PATTERNS = [
    # axios/fetch/httpx calls: axios.get("/api/v1/users")
    r'(?:axios|fetch|http|request)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*[`"\']([/][^`"\'?\s]{3,})[`"\']',
    # Template literals: `/api/v1/users/${id}`
    r'`(/api/[^`\s$]{3,})',
    # String literals: "/api/v1/users"
    r'["\'](/(?:api|v\d|rest|graphql|gql|internal|private|admin|auth|oauth|service)[^"\'?\s]{2,})["\']',
    # Route definitions: path: "/users/:id"
    r'(?:path|route|url|endpoint|href)\s*:\s*["\']([/][^"\'?\s]{3,})["\']',
    # String concat patterns: baseUrl + "/users"
    r'\+\s*["\'](/[a-zA-Z][^"\'?\s]{3,})["\']',
    # URL builder patterns
    r'url\s*\+?=\s*["\']([/][^"\'?\s]{2,})["\']',
    # ── Framework router patterns ─────────────────────────────────────────
    # React Router: <Route path="/dashboard" />
    r'<Route\s+[^>]*path\s*=\s*["\']([/][^"\'?\s]{2,})["\']',
    # Vue Router: { path: '/users/:id', component: ... }
    r'{\s*path\s*:\s*["\']([/][^"\'?\s]{2,})["\']',
    # Angular: { path: 'admin', ... }  (no leading /)
    r'{\s*path\s*:\s*["\']([a-zA-Z][a-zA-Z0-9/\-:_]{2,})["\']',
    # Next.js API routes: "/api/..." in fetch/getServerSideProps
    r'(?:getServerSideProps|getStaticProps|useSWR|useQuery)\s*\([^)]*["\']([/][^"\'?\s]{3,})["\']',
    # Express-style route handlers: app.get("/api/users", ...)
    r'(?:app|router)\s*\.\s*(?:get|post|put|delete|patch|all|use)\s*\(\s*["\']([/][^"\'?\s]{2,})["\']',
    # GraphQL operation names: query GetUsers { ... }
    r'(?:query|mutation|subscription)\s+([A-Z][a-zA-Z]{2,})\s*[({]',
    # Relative URL paths in string assignments
    r'(?:baseURL|baseUrl|BASE_URL|API_URL|API_BASE)\s*[:=]\s*["\']([/][^"\'?\s]{2,})["\']',
    # window.location / document.location assignments
    r'(?:window|document)\.location(?:\.href)?\s*=\s*["\']([/][^"\'?\s]{3,})["\']',
]

# ── HTTP method indicators ────────────────────────────────────────────────────

METHOD_HINTS = {
    'get': ['get', 'fetch', 'load', 'read', 'list', 'search', 'find'],
    'post': ['post', 'create', 'add', 'insert', 'submit', 'send'],
    'put': ['put', 'update', 'edit', 'modify', 'replace'],
    'patch': ['patch', 'partial'],
    'delete': ['delete', 'remove', 'destroy'],
}


class JSAnalyzer:
    """
    Analyzes JavaScript bundles from a web app for API routes and secrets.
    """

    def __init__(self, base_url: str, timeout: int = 15, max_bundles: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_bundles = max_bundles
        self.client = httpx.Client(
            timeout=timeout, follow_redirects=True, verify=False,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; pentest-agent/1.0)'},
        )

    def run(self) -> dict:
        """
        Full analysis pipeline:
        1. Discover JS bundle URLs from the HTML page
        2. Download each bundle
        3. Extract routes and scan for secrets
        """
        console.print(f"  [cyan]JSAnalyzer: scanning {self.base_url}...[/]")

        bundle_urls = self._discover_bundles()
        console.print(f"  [dim]Found {len(bundle_urls)} JS bundle(s)[/]")

        all_endpoints = []
        all_secrets = []
        bundles_analyzed = 0

        for url in bundle_urls[:self.max_bundles]:
            try:
                content = self._download_bundle(url)
                if not content:
                    continue

                routes = self._extract_routes(content, url)
                secrets = self._scan_secrets(content, url)

                all_endpoints.extend(routes)
                all_secrets.extend(secrets)
                bundles_analyzed += 1

                console.print(
                    f"  [dim]{url.split('/')[-1]}: {len(routes)} routes, {len(secrets)} secrets[/]"
                )
            except Exception as e:
                console.print(f"  [dim]Bundle error {url.split('/')[-1]}: {e}[/]")

        # Deduplicate endpoints by URL path
        seen_paths = set()
        unique_endpoints = []
        for ep in all_endpoints:
            key = (ep['path'], ep.get('method', 'GET'))
            if key not in seen_paths:
                seen_paths.add(key)
                unique_endpoints.append(ep)

        # Deduplicate secrets by value
        seen_vals = set()
        unique_secrets = []
        for s in all_secrets:
            key = s['value'][:30]
            if key not in seen_vals:
                seen_vals.add(key)
                unique_secrets.append(s)

        console.print(
            f"  [bold]JSAnalyzer: {len(unique_endpoints)} unique API paths, "
            f"{len(unique_secrets)} potential secrets[/]"
        )

        return {
            'endpoints': unique_endpoints,
            'secrets': unique_secrets,
            'bundles_analyzed': bundles_analyzed,
            'bundle_urls': bundle_urls[:self.max_bundles],
        }

    def _discover_bundles(self) -> list[str]:
        """Find all JS bundle URLs from the HTML page."""
        bundle_urls = []
        try:
            resp = self.client.get(self.base_url)
            soup = BeautifulSoup(resp.text, 'html.parser')

            for tag in soup.find_all('script', src=True):
                src = tag['src']
                if src.startswith('http'):
                    url = src
                else:
                    url = urljoin(self.base_url, src)

                # Prioritize app bundles, skip CDN/analytics
                skip_domains = ['google', 'facebook', 'twitter', 'analytics',
                                 'newrelic', 'hotjar', 'intercom', 'stripe',
                                 'googleapis', 'gstatic', 'cloudflare']
                if not any(s in url for s in skip_domains):
                    bundle_urls.append(url)

        except Exception as e:
            console.print(f"  [dim]Bundle discovery error: {e}[/]")

        return bundle_urls

    def _download_bundle(self, url: str) -> str:
        """Download a JS bundle, return its text content."""
        resp = self.client.get(url)
        if resp.status_code == 200:
            return resp.text
        return ''

    def _extract_routes(self, js_content: str, source_url: str) -> list[dict]:
        """Extract API route patterns from JS content."""
        routes = []
        filename = source_url.split('/')[-1].split('?')[0]

        for pattern in ROUTE_PATTERNS:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                path = match.strip()
                if not self._is_valid_api_path(path):
                    continue

                # Guess HTTP method from context around the match
                idx = js_content.find(match)
                context = js_content[max(0, idx - 100):idx + 50].lower()
                method = 'GET'
                for m, hints in METHOD_HINTS.items():
                    if any(h in context for h in hints):
                        method = m.upper()
                        break

                routes.append({
                    'path': path,
                    'method': method,
                    'source': filename,
                    'full_url': urljoin(self.base_url, path) if path.startswith('/') else path,
                })

        return routes

    def _scan_secrets(self, js_content: str, source_url: str) -> list[dict]:
        """Scan JS content for hardcoded secrets."""
        secrets = []
        filename = source_url.split('/')[-1].split('?')[0]
        lines = js_content.split('\n')

        for secret_type, pattern in SECRET_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                # Skip minified lines that are too long (likely false positives in compressed data)
                if len(line) > 5000:
                    # Search in chunks
                    for chunk_start in range(0, len(line), 1000):
                        chunk = line[chunk_start:chunk_start + 1000]
                        match = re.search(pattern, chunk)
                        if match:
                            val = match.group(1) if match.lastindex else match.group(0)
                            if not self._is_false_positive(secret_type, val):
                                secrets.append({
                                    'type': secret_type,
                                    'value': val[:120],
                                    'file': filename,
                                    'line': line_num,
                                    'context': chunk[max(0, match.start()-30):match.end()+30],
                                })
                            break
                else:
                    match = re.search(pattern, line)
                    if match:
                        val = match.group(1) if match.lastindex else match.group(0)
                        if not self._is_false_positive(secret_type, val):
                            secrets.append({
                                'type': secret_type,
                                'value': val[:120],
                                'file': filename,
                                'line': line_num,
                                'context': line.strip()[:200],
                            })

        return secrets

    def _is_valid_api_path(self, path: str) -> bool:
        """Filter out non-API paths (CSS, images, template strings, etc.)."""
        if len(path) < 3 or len(path) > 200:
            return False
        # Skip asset paths
        skip_exts = ('.css', '.png', '.jpg', '.svg', '.gif', '.ico', '.woff', '.ttf', '.map')
        if any(path.lower().endswith(e) for e in skip_exts):
            return False
        # Skip template variable paths
        if '${' in path or '#{' in path:
            return False
        # Must look like an API path
        api_indicators = ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql',
                          '/gql', '/admin', '/auth/', '/oauth', '/service/',
                          '/internal/', '/private/', '/user', '/order', '/account',
                          '/client/', '/token', '/session', '/search', '/list']
        return any(ind in path.lower() for ind in api_indicators)

    def _is_false_positive(self, secret_type: str, value: str) -> bool:
        """Filter obvious false positives."""
        if not value or len(value) < 6:
            return True
        # Skip placeholder/example values
        placeholders = ['example', 'placeholder', 'your_key', 'insert_here',
                        'xxxxxxxx', '12345678', 'abcdefgh', 'test', 'demo',
                        'changeme', 'replace_me', 'undefined', 'null', 'none']
        val_lower = value.lower()
        if any(p in val_lower for p in placeholders):
            return True
        # JWT tokens that are clearly test/example
        if secret_type == 'jwt_token' and 'eyJhbGciOiJub25lIn0' in value:
            return True
        return False

    def close(self):
        self.client.close()


# ── JS Crawler — Deep JS discovery across all pages ──────────────────────────

# Common JS asset paths to brute-force
COMMON_JS_PATHS = [
    '/static/js/', '/assets/js/', '/dist/', '/build/',
    '/js/', '/scripts/', '/bundle/', '/chunks/',
    '/static/chunks/', '/_next/static/chunks/',
    '/_next/static/', '/assets/', '/public/js/',
]

# Patterns to find more JS files referenced inside other JS files
JS_REFERENCE_PATTERNS = [
    # Webpack chunk loading: __webpack_require__.e(42).then(...)
    # or: "static/js/" + chunkId + ".chunk.js"
    r'["\']([a-zA-Z0-9/_\-\.]+\.(?:chunk|bundle)?\.?js)["\']',
    # Dynamic imports: import("./pages/Dashboard")
    r'import\s*\(\s*["\']\.?/?([^"\']+)["\']',
    # Source map references: //# sourceMappingURL=main.js.map
    r'sourceMappingURL=([^\s]+\.map)',
    # Webpack manifest entries: "vendors~main": "vendors~main.abc123.js"
    r':\s*["\']([a-zA-Z0-9_\-~.]+\.js)["\']',
]


class JSCrawler:
    """
    Deep JavaScript crawler — discovers ALL .js files across the entire site,
    not just those on the homepage. Fetches, deduplicates, and feeds them into
    JSAnalyzer for endpoint/secret extraction.

    Strategy:
      1. Crawl pages (using existing Crawler results if available) → collect <script src>
      2. For each JS file, look for references to MORE JS files (webpack chunks, dynamic imports)
      3. Brute-force common JS asset directories
      4. Follow source maps for un-minified code (richer endpoint extraction)
      5. Extract inline <script> blocks from HTML pages
      6. Run JSAnalyzer route/secret extraction on everything collected

    Usage:
        from js_analyzer import JSCrawler
        jscrawler = JSCrawler("https://target.com", cookies={"session": "abc"})
        result = jscrawler.run()
        # result["endpoints"]  → list of hidden API paths
        # result["secrets"]    → leaked keys/tokens
        # result["js_files"]   → all .js URLs discovered
    """

    def __init__(
        self,
        base_url: str,
        cookies: dict | None = None,
        headers: dict | None = None,
        timeout: int = 15,
        max_js_files: int = 100,
        max_pages: int = 50,
        crawl_depth: int = 3,
    ):
        self.base_url = base_url.rstrip('/')
        self.base_domain = urlparse(self.base_url).netloc
        self.cookies = cookies or {}
        self.max_js_files = max_js_files
        self.max_pages = max_pages
        self.crawl_depth = crawl_depth

        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            cookies=self.cookies,
            headers=headers or {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                              'AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/120.0.0.0 Safari/537.36',
            },
        )

        self.discovered_js: set[str] = set()  # All unique JS URLs found
        self.downloaded_js: dict[str, str] = {}  # URL → content
        self.visited_pages: set[str] = set()

    def run(self, crawl_result: dict | None = None) -> dict:
        """
        Full deep JS crawling pipeline.

        Args:
            crawl_result: Optional output from crawler.crawl_target() to reuse
                          already-crawled pages instead of re-crawling.
        """
        console.print(f"  [cyan]JSCrawler: deep JS discovery on {self.base_url}...[/]")

        # Phase 1: Collect JS URLs from all crawled pages
        if crawl_result and crawl_result.get('pages'):
            self._collect_from_crawl_result(crawl_result)
        else:
            self._crawl_and_collect()

        console.print(f"  [dim]Phase 1: {len(self.discovered_js)} JS files from page crawl[/]")

        # Phase 2: Brute-force common JS directories
        self._brute_force_js_paths()
        console.print(f"  [dim]Phase 2: {len(self.discovered_js)} JS files after path brute-force[/]")

        # Phase 3: Download JS files and follow references to more JS
        self._download_and_follow_refs()
        console.print(f"  [dim]Phase 3: {len(self.downloaded_js)} JS files downloaded[/]")

        # Phase 4: Extract endpoints and secrets from all JS content
        analyzer = JSAnalyzer(self.base_url)
        all_endpoints = []
        all_secrets = []

        for url, content in self.downloaded_js.items():
            if not content:
                continue
            routes = analyzer._extract_routes(content, url)
            secrets = analyzer._scan_secrets(content, url)
            all_endpoints.extend(routes)
            all_secrets.extend(secrets)

        # Phase 5: Also extract from inline scripts
        inline_endpoints, inline_secrets = self._extract_from_inline_scripts(analyzer)
        all_endpoints.extend(inline_endpoints)
        all_secrets.extend(inline_secrets)

        analyzer.close()

        # Deduplicate
        seen_paths = set()
        unique_endpoints = []
        for ep in all_endpoints:
            key = (ep['path'], ep.get('method', 'GET'))
            if key not in seen_paths:
                seen_paths.add(key)
                unique_endpoints.append(ep)

        seen_vals = set()
        unique_secrets = []
        for s in all_secrets:
            key = s['value'][:30]
            if key not in seen_vals:
                seen_vals.add(key)
                unique_secrets.append(s)

        console.print(
            f"  [bold]JSCrawler: {len(unique_endpoints)} hidden endpoints, "
            f"{len(unique_secrets)} secrets from {len(self.downloaded_js)} JS files[/]"
        )

        return {
            'endpoints': unique_endpoints,
            'secrets': unique_secrets,
            'js_files': sorted(self.discovered_js),
            'js_files_downloaded': len(self.downloaded_js),
            'pages_scanned': len(self.visited_pages),
        }

    # ── Phase 1: Collect JS URLs from crawled pages ──────────────────────

    def _collect_from_crawl_result(self, crawl_result: dict):
        """Extract JS URLs from an existing crawl result (avoids re-crawling)."""
        for page in crawl_result.get('pages', []):
            page_url = page.get('url', '')
            self.visited_pages.add(page_url)

            # Re-fetch the page to parse script tags
            # (crawl_result doesn't store raw HTML)
            try:
                resp = self.client.get(page_url)
                if resp.status_code == 200 and 'text/html' in resp.headers.get('content-type', ''):
                    self._extract_js_from_html(resp.text, page_url)
            except Exception:
                continue

    def _crawl_and_collect(self):
        """Light BFS crawl focused on collecting JS URLs from every page."""
        from collections import deque

        queue = deque([(self.base_url, 0)])
        self.visited_pages.add(self.base_url)

        while queue and len(self.visited_pages) < self.max_pages:
            url, depth = queue.popleft()

            try:
                resp = self.client.get(url)
            except Exception:
                continue

            content_type = resp.headers.get('content-type', '')
            if 'text/html' not in content_type:
                continue

            self._extract_js_from_html(resp.text, url)

            # Follow links if within depth limit
            if depth < self.crawl_depth:
                soup = BeautifulSoup(resp.text, 'html.parser')
                for tag in soup.find_all(['a', 'area'], href=True):
                    href = tag['href'].strip()
                    if href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                        continue
                    full_url = urljoin(url, href)
                    parsed = urlparse(full_url)
                    # Same domain only, skip non-HTML extensions
                    if parsed.netloc != self.base_domain:
                        continue
                    path_lower = parsed.path.lower()
                    if any(path_lower.endswith(e) for e in
                           ('.js', '.css', '.png', '.jpg', '.svg', '.gif',
                            '.ico', '.woff', '.pdf', '.zip')):
                        continue
                    normalized = full_url.split('#')[0]
                    if normalized not in self.visited_pages:
                        self.visited_pages.add(normalized)
                        queue.append((normalized, depth + 1))

    def _extract_js_from_html(self, html: str, page_url: str):
        """Extract all JS URLs from an HTML page (script tags, event handlers, etc.)."""
        soup = BeautifulSoup(html, 'html.parser')

        # <script src="...">
        for tag in soup.find_all('script', src=True):
            src = tag['src']
            js_url = src if src.startswith('http') else urljoin(page_url, src)
            if self._is_same_domain_js(js_url):
                self.discovered_js.add(js_url)

        # <link rel="preload" as="script" href="...">
        for tag in soup.find_all('link', rel=True):
            if 'preload' in tag.get('rel', []) and tag.get('as') == 'script':
                href = tag.get('href', '')
                if href:
                    js_url = href if href.startswith('http') else urljoin(page_url, href)
                    if self._is_same_domain_js(js_url):
                        self.discovered_js.add(js_url)

        # <link rel="modulepreload" href="...">
        for tag in soup.find_all('link', rel=True):
            if 'modulepreload' in tag.get('rel', []):
                href = tag.get('href', '')
                if href:
                    js_url = href if href.startswith('http') else urljoin(page_url, href)
                    if self._is_same_domain_js(js_url):
                        self.discovered_js.add(js_url)

        # Inline script references to JS files in JSON config blocks
        # e.g., Next.js __NEXT_DATA__, Nuxt __NUXT__, webpack manifest
        for tag in soup.find_all('script', src=False):
            text = tag.string or ''
            if not text:
                continue
            # Find JS file paths embedded in inline scripts
            refs = re.findall(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', text)
            for ref in refs:
                if ref.startswith('http'):
                    js_url = ref
                elif ref.startswith('/'):
                    js_url = urljoin(self.base_url, ref)
                elif '/' in ref:
                    js_url = urljoin(page_url, ref)
                else:
                    continue
                if self._is_same_domain_js(js_url):
                    self.discovered_js.add(js_url)

    # ── Phase 2: Brute-force common JS paths ─────────────────────────────

    def _brute_force_js_paths(self):
        """Try common JS asset directories and look for directory listings or known files."""
        for path in COMMON_JS_PATHS:
            url = self.base_url + path
            try:
                resp = self.client.get(url)
                if resp.status_code != 200:
                    continue

                # If we get a directory listing, extract .js files
                if '<a href=' in resp.text.lower():
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    for a in soup.find_all('a', href=True):
                        href = a['href']
                        if href.endswith('.js'):
                            js_url = urljoin(url, href)
                            self.discovered_js.add(js_url)

                # Also check if the path itself contains JS references
                refs = re.findall(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', resp.text)
                for ref in refs:
                    if ref.startswith('http'):
                        js_url = ref
                    elif ref.startswith('/'):
                        js_url = urljoin(self.base_url, ref)
                    else:
                        js_url = urljoin(url, ref)
                    if self._is_same_domain_js(js_url):
                        self.discovered_js.add(js_url)

            except Exception:
                continue

    # ── Phase 3: Download JS and follow references ───────────────────────

    def _download_and_follow_refs(self):
        """Download all discovered JS files and recursively find more JS references."""
        to_download = set(self.discovered_js)
        rounds = 0
        max_rounds = 3  # Prevent infinite loops

        while to_download and rounds < max_rounds:
            rounds += 1
            new_refs = set()

            for js_url in sorted(to_download):
                if len(self.downloaded_js) >= self.max_js_files:
                    break
                if js_url in self.downloaded_js:
                    continue

                try:
                    resp = self.client.get(js_url)
                    if resp.status_code != 200:
                        self.downloaded_js[js_url] = ''
                        continue

                    content = resp.text
                    self.downloaded_js[js_url] = content

                    # Find references to more JS files inside this one
                    for pattern in JS_REFERENCE_PATTERNS:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if match.endswith('.map'):
                                # Source map — resolve and download for richer analysis
                                map_url = urljoin(js_url, match)
                                self._process_source_map(map_url)
                            elif match.endswith('.js') or '.chunk.' in match:
                                ref_url = urljoin(js_url, match)
                                if self._is_same_domain_js(ref_url) and ref_url not in self.downloaded_js:
                                    new_refs.add(ref_url)

                except Exception:
                    self.downloaded_js[js_url] = ''
                    continue

            # Queue newly discovered JS for next round
            self.discovered_js.update(new_refs)
            to_download = new_refs - set(self.downloaded_js.keys())

    def _process_source_map(self, map_url: str):
        """Download a source map and extract the original source code for analysis."""
        if map_url in self.downloaded_js:
            return
        try:
            resp = self.client.get(map_url)
            if resp.status_code != 200:
                return

            import json
            try:
                source_map = json.loads(resp.text)
            except (json.JSONDecodeError, ValueError):
                return

            # Source maps contain "sourcesContent" — the original un-minified code
            sources_content = source_map.get('sourcesContent', [])
            sources_names = source_map.get('sources', [])

            for i, content in enumerate(sources_content):
                if not content or len(content) < 20:
                    continue
                # Use source name as a virtual URL for tracking
                name = sources_names[i] if i < len(sources_names) else f'sourcemap_{i}'
                virtual_url = f"{map_url}::{name}"
                if virtual_url not in self.downloaded_js:
                    self.downloaded_js[virtual_url] = content

        except Exception:
            pass

    # ── Phase 5: Inline scripts ──────────────────────────────────────────

    def _extract_from_inline_scripts(self, analyzer: JSAnalyzer) -> tuple[list, list]:
        """Re-visit cached pages and extract routes/secrets from inline <script> blocks."""
        all_endpoints = []
        all_secrets = []

        for page_url in list(self.visited_pages)[:self.max_pages]:
            try:
                resp = self.client.get(page_url)
                if resp.status_code != 200:
                    continue
                if 'text/html' not in resp.headers.get('content-type', ''):
                    continue

                soup = BeautifulSoup(resp.text, 'html.parser')
                for tag in soup.find_all('script', src=False):
                    text = tag.string or ''
                    if len(text) < 30:
                        continue
                    routes = analyzer._extract_routes(text, page_url)
                    secrets = analyzer._scan_secrets(text, page_url)
                    all_endpoints.extend(routes)
                    all_secrets.extend(secrets)

            except Exception:
                continue

        return all_endpoints, all_secrets

    # ── Helpers ──────────────────────────────────────────────────────────

    def _is_same_domain_js(self, url: str) -> bool:
        """Check if a JS URL belongs to the target domain (skip CDN/third-party)."""
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc != self.base_domain:
            return False
        skip_domains = [
            'google', 'facebook', 'twitter', 'analytics', 'newrelic',
            'hotjar', 'intercom', 'stripe', 'googleapis', 'gstatic',
            'cloudflare', 'cdn.jsdelivr', 'unpkg.com', 'cdnjs.',
        ]
        return not any(s in url for s in skip_domains)

    def close(self):
        self.client.close()
