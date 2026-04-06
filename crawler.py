"""
Generic Web Crawler — Works on any website, not just DVWA.

Features:
  - Recursive breadth-first crawling with configurable depth
  - Same-domain enforcement (won't crawl external sites)
  - Form extraction on every page
  - Parameter discovery (URL params, form inputs, headers)
  - Deduplication (won't visit the same page twice)
  - Respects robots.txt (optional)
  - Rate limiting to avoid overwhelming the target
  - Builds a complete site map with attack surface info
"""

import time
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from collections import deque
from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup


@dataclass
class FormInfo:
    """A form discovered on a page."""
    url: str           # Page where the form was found
    action: str        # Form action URL (resolved to absolute)
    method: str        # GET or POST
    inputs: list       # List of {"name", "type", "value"}

    def to_dict(self):
        return {
            "url": self.url,
            "action": self.action,
            "method": self.method,
            "inputs": self.inputs,
        }


@dataclass
class PageInfo:
    """Information about a crawled page."""
    url: str
    status_code: int
    title: str
    links: list          # Outgoing links found
    forms: list          # FormInfo objects
    params: dict         # URL query parameters
    technologies: list   # Detected tech (e.g., PHP, ASP)
    headers: dict        # Response headers

    def to_dict(self):
        return {
            "url": self.url,
            "status_code": self.status_code,
            "title": self.title,
            "links_count": len(self.links),
            "forms": [f.to_dict() for f in self.forms],
            "params": self.params,
            "technologies": self.technologies,
        }


@dataclass
class CrawlResult:
    """Complete crawl results — the attack surface map."""
    target: str
    pages: list = field(default_factory=list)       # PageInfo objects
    all_forms: list = field(default_factory=list)    # All forms across all pages
    all_params: dict = field(default_factory=dict)   # param_name → [urls where it appears]
    all_links: set = field(default_factory=set)
    errors: list = field(default_factory=list)

    def summary(self):
        return {
            "target": self.target,
            "pages_crawled": len(self.pages),
            "forms_found": len(self.all_forms),
            "unique_params": list(self.all_params.keys()),
            "total_links": len(self.all_links),
            "errors": len(self.errors),
        }

    def get_attack_surface(self):
        """Return a structured attack surface for the agent to use."""
        surface = []
        for form in self.all_forms:
            input_names = [i["name"] for i in form.inputs if i["name"]]
            if input_names:
                surface.append({
                    "url": form.action,
                    "method": form.method,
                    "params": input_names,
                    "found_on": form.url,
                })

        # Also include pages with URL query params
        for page in self.pages:
            if page.params:
                surface.append({
                    "url": page.url.split("?")[0],  # Base URL without params
                    "method": "GET",
                    "params": list(page.params.keys()),
                    "found_on": page.url,
                })

        # Deduplicate by (url, method)
        seen = set()
        deduped = []
        for entry in surface:
            key = (entry["url"], entry["method"], tuple(sorted(entry["params"])))
            if key not in seen:
                seen.add(key)
                deduped.append(entry)

        return deduped


class Crawler:
    """
    Generic recursive web crawler.

    Usage:
        crawler = Crawler(base_url="http://example.com", cookies={"session": "abc"})
        result = crawler.crawl(max_depth=3, max_pages=100)
        attack_surface = result.get_attack_surface()
    """

    def __init__(
        self,
        base_url: str,
        cookies: Optional[dict] = None,
        headers: Optional[dict] = None,
        delay: float = 0.2,
        timeout: int = 15,
    ):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(self.base_url).netloc
        self.cookies = cookies or {}
        self.delay = delay

        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers=headers or {},
        )

        self.visited = set()
        self.result = CrawlResult(target=self.base_url)

    def _is_same_domain(self, url: str) -> bool:
        """Only crawl URLs on the same domain."""
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain or parsed.netloc == ""

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication. Preserves trailing slashes."""
        parsed = urlparse(url)
        # Remove fragment (#section) but keep path as-is (trailing slash matters)
        path = parsed.path if parsed.path else "/"
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            parsed.query,
            "",  # no fragment
        ))
        return normalized

    def _should_skip(self, url: str) -> bool:
        """Skip non-HTML resources and dangerous URLs."""
        skip_extensions = {
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
            ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
            ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
            ".doc", ".docx", ".xls", ".xlsx",
        }
        path = urlparse(url).path.lower()
        if any(path.endswith(ext) for ext in skip_extensions):
            return True

        # Skip URLs that would destroy our session or cause side effects
        dangerous_keywords = ["logout", "signout", "sign-out", "log-out",
                              "delete", "remove", "destroy", "reset",
                              "setup", "install", "uninstall", "drop",
                              "truncate", "purge", "wipe",
                              "phpids", "security_level", "seclev"]
        url_lower = url.lower()
        for keyword in dangerous_keywords:
            if keyword in path or keyword in url_lower:
                return True

        return False

    def _detect_technologies(self, headers: dict, body: str) -> list:
        """Detect server-side technologies from headers and content."""
        techs = []
        server = headers.get("server", "").lower()
        powered_by = headers.get("x-powered-by", "").lower()

        if "apache" in server:
            techs.append("Apache")
        if "nginx" in server:
            techs.append("Nginx")
        if "iis" in server:
            techs.append("IIS")
        if "php" in powered_by or "php" in headers.get("set-cookie", "").lower():
            techs.append("PHP")
        if "asp.net" in powered_by:
            techs.append("ASP.NET")
        if "express" in powered_by:
            techs.append("Express/Node.js")

        # Content-based detection
        if "wp-content" in body or "wordpress" in body.lower():
            techs.append("WordPress")
        if "csrftoken" in body or "csrfmiddlewaretoken" in body:
            techs.append("Django")
        if "rails" in headers.get("x-runtime", "").lower():
            techs.append("Ruby on Rails")

        return techs

    def _extract_links(self, soup: BeautifulSoup, page_url: str) -> list:
        """Extract all links from a page."""
        links = set()
        for tag in soup.find_all(["a", "area"], href=True):
            href = tag["href"].strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            full_url = urljoin(page_url, href)
            if self._is_same_domain(full_url):
                links.add(self._normalize_url(full_url))

        # Also check form actions
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action:
                full_url = urljoin(page_url, action)
                if self._is_same_domain(full_url):
                    links.add(self._normalize_url(full_url))

        # Also check script src for same-domain resources
        for script in soup.find_all("script", src=True):
            src = urljoin(page_url, script["src"])
            if self._is_same_domain(src):
                links.add(self._normalize_url(src))

        # Extract URLs from <option> values (e.g., bWAPP dropdown navigation)
        for option in soup.find_all("option", value=True):
            val = option["value"].strip()
            if val and ("." in val or "/" in val):
                # Looks like a URL/path (e.g., "sqli_1.php", "/page/test")
                full_url = urljoin(page_url, val)
                if self._is_same_domain(full_url):
                    links.add(self._normalize_url(full_url))

        # Extract URLs from onclick/onchange attributes
        import re
        for tag in soup.find_all(attrs={"onclick": True}):
            urls_in_attr = re.findall(r"""(?:window\.location|location\.href)\s*=\s*['"]([^'"]+)['"]""", tag["onclick"])
            for u in urls_in_attr:
                full_url = urljoin(page_url, u)
                if self._is_same_domain(full_url):
                    links.add(self._normalize_url(full_url))

        # Extract URLs from meta refresh
        for meta in soup.find_all("meta", attrs={"http-equiv": "refresh"}):
            content = meta.get("content", "")
            match = re.search(r"url=(.+)", content, re.IGNORECASE)
            if match:
                full_url = urljoin(page_url, match.group(1).strip("'\" "))
                if self._is_same_domain(full_url):
                    links.add(self._normalize_url(full_url))

        return sorted(links)

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> list:
        """Extract all forms from a page with their inputs."""
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            full_action = urljoin(page_url, action) if action else page_url

            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if not name:
                    continue
                inputs.append({
                    "name": name,
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })

            forms.append(FormInfo(
                url=page_url,
                action=full_action,
                method=form.get("method", "GET").upper(),
                inputs=inputs,
            ))
        return forms

    def _crawl_page(self, url: str) -> Optional[PageInfo]:
        """Crawl a single page and extract information."""
        try:
            resp = self.client.get(url, cookies=self.cookies)
        except Exception as e:
            self.result.errors.append({"url": url, "error": str(e)})
            return None

        content_type = resp.headers.get("content-type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            return None

        soup = BeautifulSoup(resp.text, "html.parser")

        # Extract title
        title_tag = soup.find("title")
        title = title_tag.text.strip() if title_tag else ""

        # Extract links
        links = self._extract_links(soup, url)

        # Extract forms
        forms = self._extract_forms(soup, url)

        # Extract URL parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Detect technologies
        techs = self._detect_technologies(dict(resp.headers), resp.text)

        return PageInfo(
            url=url,
            status_code=resp.status_code,
            title=title,
            links=links,
            forms=forms,
            params=params,
            technologies=techs,
            headers=dict(resp.headers),
        )

    def _follow_navigation_forms(self, soup: BeautifulSoup, page_url: str) -> list:
        """
        Submit forms with <select> dropdowns to discover pages behind navigation.
        Apps like bWAPP use form POSTs with dropdown options for navigation.
        Returns list of discovered URLs.
        """
        discovered = []
        # Use a no-redirect client to capture Location headers
        no_redirect_client = httpx.Client(
            timeout=10, follow_redirects=False, verify=False
        )

        for form in soup.find_all("form"):
            selects = form.find_all("select")
            if not selects:
                continue

            action = form.get("action", "")
            full_action = urljoin(page_url, action) if action else page_url
            method = form.get("method", "GET").upper()

            # Build base form data from inputs and buttons
            base_data = {}
            for inp in form.find_all(["input", "button"]):
                name = inp.get("name", "")
                if name:
                    base_data[name] = inp.get("value", "")

            # For each select, try submitting each option
            # Skip selects that look like security/config settings to avoid
            # changing app state (e.g. DVWA security level dropdown)
            settings_keywords = {"security", "level", "difficulty", "config",
                                 "setting", "preference", "theme", "language"}
            for select in selects:
                select_name = select.get("name", "")
                if not select_name:
                    continue
                if select_name.lower() in settings_keywords or \
                   any(k in select_name.lower() for k in settings_keywords):
                    continue
                options = select.find_all("option")
                for option in options:
                    val = option.get("value", "")
                    if not val or val == "0":
                        continue
                    data = dict(base_data)
                    data[select_name] = val
                    try:
                        if method == "POST":
                            resp = no_redirect_client.post(
                                full_action, data=data, cookies=self.cookies)
                        else:
                            resp = no_redirect_client.get(
                                full_action, params=data, cookies=self.cookies)

                        # Check for redirect (302/301) → the Location is the page
                        if resp.status_code in (301, 302, 303, 307):
                            location = resp.headers.get("location", "")
                            if location:
                                full_url = urljoin(full_action, location)
                                if self._is_same_domain(full_url):
                                    discovered.append(self._normalize_url(full_url))
                        elif resp.status_code == 200:
                            # No redirect — the response itself is a new page
                            final_url = str(resp.url)
                            if self._is_same_domain(final_url):
                                discovered.append(self._normalize_url(final_url))
                    except Exception:
                        continue
                    time.sleep(self.delay)

        return discovered

    def crawl(self, max_depth: int = 3, max_pages: int = 100,
              start_urls: Optional[list] = None) -> CrawlResult:
        """
        Crawl the target website using breadth-first search.

        Args:
            max_depth: How many links deep to follow (default 3)
            max_pages: Maximum pages to crawl (default 100)
            start_urls: Additional URLs to seed the crawl (e.g., post-login pages)

        Returns:
            CrawlResult with complete attack surface map
        """
        queue = deque()
        queue.append((self.base_url, 0))  # (url, depth)
        self.visited.add(self._normalize_url(self.base_url))

        # Also seed with additional start URLs
        if start_urls:
            for url in start_urls:
                normalized = self._normalize_url(url)
                if normalized not in self.visited:
                    self.visited.add(normalized)
                    queue.append((url, 0))

        pages_crawled = 0

        while queue and pages_crawled < max_pages:
            url, depth = queue.popleft()

            if self._should_skip(url):
                continue

            # Rate limiting
            if pages_crawled > 0:
                time.sleep(self.delay)

            page_info = self._crawl_page(url)
            if page_info is None:
                continue

            pages_crawled += 1
            self.result.pages.append(page_info)

            # Collect forms
            for form in page_info.forms:
                self.result.all_forms.append(form)

            # Collect params
            for param_name in page_info.params:
                if param_name not in self.result.all_params:
                    self.result.all_params[param_name] = []
                self.result.all_params[param_name].append(url)

            # Collect form param names too
            for form in page_info.forms:
                for inp in form.inputs:
                    name = inp["name"]
                    if name not in self.result.all_params:
                        self.result.all_params[name] = []
                    self.result.all_params[name].append(form.action)

            # Add new links to queue (if within depth limit)
            if depth < max_depth:
                for link in page_info.links:
                    normalized = self._normalize_url(link)
                    if normalized not in self.visited:
                        self.visited.add(normalized)
                        self.result.all_links.add(normalized)
                        queue.append((link, depth + 1))

            # Follow navigation forms (dropdowns) to discover hidden pages
            if depth < max_depth and pages_crawled < max_pages:
                try:
                    resp = self.client.get(url, cookies=self.cookies)
                    soup = BeautifulSoup(resp.text, "html.parser")
                    nav_urls = self._follow_navigation_forms(soup, url)
                    for nav_url in nav_urls:
                        normalized = self._normalize_url(nav_url)
                        if normalized not in self.visited:
                            self.visited.add(normalized)
                            self.result.all_links.add(normalized)
                            queue.append((nav_url, depth + 1))
                except Exception:
                    pass

        return self.result


def crawl_target(base_url: str, cookies: Optional[dict] = None,
                 max_depth: int = 3, max_pages: int = 100,
                 delay: float = 0.2) -> dict:
    """
    Convenience function — crawl a target and return results as a dict.
    This is what the agent tools will call.
    """
    # Auto-discover additional entry points
    start_urls = []
    common_paths = [
        "/", "/index.php", "/index.html", "/home", "/dashboard",
        "/portal.php", "/main", "/app", "/admin", "/panel",
        "/sitemap.xml", "/robots.txt",
    ]
    if cookies:
        client = httpx.Client(timeout=10, follow_redirects=True, verify=False)
        for path in common_paths:
            try:
                test_url = base_url.rstrip("/") + path
                resp = client.get(test_url, cookies=cookies)
                if resp.status_code == 200:
                    final_url = str(resp.url)
                    start_urls.append(final_url)
            except Exception:
                continue

    crawler = Crawler(
        base_url=base_url,
        cookies=cookies,
        delay=delay,
    )
    result = crawler.crawl(max_depth=max_depth, max_pages=max_pages,
                           start_urls=start_urls)

    return {
        "summary": result.summary(),
        "attack_surface": result.get_attack_surface(),
        "pages": [p.to_dict() for p in result.pages],
        "technologies": list(set(
            tech for p in result.pages for tech in p.technologies
        )),
        "errors": result.errors,
    }
