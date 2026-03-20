"""Authenticated Playwright-based crawler that records all API traffic."""
import json
import re
from typing import Optional
from urllib.parse import urlparse, parse_qs, urljoin

from rich.console import Console

from engine.scan_state import ScanState, Endpoint
from engine.config import ScanConfig

console = Console()

try:
    from playwright.async_api import async_playwright, Page, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SKIP_DOMAINS = re.compile(
    r"google-analytics|googletagmanager|facebook|doubleclick|hotjar|segment"
    r"|mixpanel|amplitude|sentry|bugsnag|newrelic|nr-data|pendo|intercom"
    r"|drift|hubspot|cloudflare|cdn",
    re.IGNORECASE,
)

STATIC_EXTENSIONS = re.compile(
    r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)(\?|$)",
    re.IGNORECASE,
)

NAV_CLICK_SELECTORS = [
    "nav a",
    "[role=tab]",
    "[role=menuitem]",
    ".nav-link",
    "button[data-testid*=nav]",
]

AUTH_TOKEN_KEYS = re.compile(
    r"auth|token|session|jwt",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_same_origin(url: str, target: str) -> bool:
    """Return True if url shares the same netloc as target."""
    try:
        return urlparse(url).netloc == urlparse(target).netloc
    except Exception:
        return False


def _should_skip(url: str) -> bool:
    """Return True for analytics/CDN domains or static file requests."""
    if SKIP_DOMAINS.search(url):
        return True
    if STATIC_EXTENSIONS.search(urlparse(url).path):
        return True
    return False


def _url_to_endpoint(url: str, method: str, body: Optional[str], headers: dict) -> Endpoint:
    """Convert a recorded API call into an Endpoint object."""
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())

    body_fields: list = []
    content_type = headers.get("content-type", "")
    if body:
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                body_fields = list(data.keys())
        except (json.JSONDecodeError, ValueError):
            pass

    return Endpoint(
        url=url,
        method=method.upper(),
        params=params,
        body_fields=body_fields,
        content_type=content_type,
        response_headers=headers,
    )


# ---------------------------------------------------------------------------
# Tech-stack detection
# ---------------------------------------------------------------------------


def _detect_tech_stack(state: ScanState, recorded_calls: list) -> None:
    """Inspect recorded call headers and URLs to populate state.tech_stack."""
    for call in recorded_calls:
        headers = call.get("response_headers", {})

        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            state.tech_stack["x-powered-by"] = powered_by
            console.print(f"[cyan][discovery] x-powered-by: {powered_by}[/cyan]")

        server = headers.get("server", "")
        if server:
            state.tech_stack["server"] = server
            console.print(f"[cyan][discovery] server: {server}[/cyan]")

        url = call.get("url", "")
        if re.search(r"/graphql", url, re.IGNORECASE):
            state.tech_stack["graphql"] = True
            console.print("[cyan][discovery] GraphQL endpoint detected[/cyan]")


# ---------------------------------------------------------------------------
# Login helper
# ---------------------------------------------------------------------------


async def _attempt_login(
    page: "Page",
    ctx: "BrowserContext",
    target: str,
    username: str,
    password: str,
    client_id: str,
    config: ScanConfig,
) -> None:
    """Attempt to log in using supplied credentials."""
    try:
        # Step 1: fill client_id if present
        if client_id:
            client_selectors = [
                "input[name=client_id]",
                "input[placeholder*=client]",
                "input[id*=client]",
            ]
            for sel in client_selectors:
                try:
                    el = await page.wait_for_selector(sel, timeout=2000)
                    if el:
                        await el.fill(client_id)
                        await el.press("Enter")
                        await page.wait_for_load_state("networkidle", timeout=5000)
                        break
                except Exception:
                    pass

        # Step 2: click LOGIN / CONTINUE / SIGN IN buttons (pre-username)
        pre_login_buttons = ["LOGIN", "CONTINUE", "SIGN IN", "Log in", "Continue", "Sign in"]
        for label in pre_login_buttons:
            try:
                btn = page.get_by_role("button", name=re.compile(label, re.IGNORECASE))
                if await btn.count() > 0:
                    await btn.first.click()
                    await page.wait_for_load_state("networkidle", timeout=5000)
                    break
            except Exception:
                pass

        # Step 3: fill username
        username_selectors = [
            "input[name=username]",
            "input[name=email]",
            "input[type=email]",
            "input[placeholder*=user]",
            "input[placeholder*=email]",
            "input[placeholder*=User]",
            "input[placeholder*=Email]",
        ]
        for sel in username_selectors:
            try:
                el = await page.wait_for_selector(sel, timeout=2000)
                if el:
                    await el.fill(username)
                    break
            except Exception:
                pass

        # Step 4: click CONTINUE / NEXT / LOGIN
        mid_buttons = ["CONTINUE", "NEXT", "LOGIN", "Continue", "Next", "Log in"]
        for label in mid_buttons:
            try:
                btn = page.get_by_role("button", name=re.compile(label, re.IGNORECASE))
                if await btn.count() > 0:
                    await btn.first.click()
                    await page.wait_for_load_state("networkidle", timeout=5000)
                    break
            except Exception:
                pass

        # Step 5: fill password
        try:
            pwd_el = await page.wait_for_selector("input[type=password]", timeout=5000)
            if pwd_el:
                await pwd_el.fill(password)
        except Exception:
            pass

        # Step 6: click final LOGIN / SIGN IN / CONTINUE
        final_buttons = ["LOGIN", "SIGN IN", "CONTINUE", "Log in", "Sign in", "Continue"]
        for label in final_buttons:
            try:
                btn = page.get_by_role("button", name=re.compile(label, re.IGNORECASE))
                if await btn.count() > 0:
                    await btn.first.click()
                    await page.wait_for_load_state("networkidle", timeout=10000)
                    break
            except Exception:
                pass

        console.print("[green][discovery] Login attempt complete[/green]")

    except Exception as exc:
        console.print(f"[yellow][discovery] Login attempt error: {exc}[/yellow]")


# ---------------------------------------------------------------------------
# Fallback HTTP crawl
# ---------------------------------------------------------------------------


async def _fallback_http_crawl(target: str, config: ScanConfig, state: ScanState) -> None:
    """Simple httpx GET + link extraction when Playwright is unavailable."""
    try:
        import httpx
        from bs4 import BeautifulSoup
    except ImportError:
        console.print("[yellow][discovery] httpx/beautifulsoup4 not available — skipping fallback crawl[/yellow]")
        return

    console.print("[yellow][discovery] Playwright not available — using fallback HTTP crawl[/yellow]")

    headers = config.get_auth_headers()
    visited = set()
    to_visit = [target]

    async with httpx.AsyncClient(verify=False, timeout=15, headers=headers) as client:
        while to_visit:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                resp = await client.get(url)
                endpoint = Endpoint(
                    url=url,
                    method="GET",
                    response_status=resp.status_code,
                    response_headers=dict(resp.headers),
                    content_type=resp.headers.get("content-type", ""),
                )
                state.add_endpoint(endpoint)

                soup = BeautifulSoup(resp.text, "html.parser")
                for tag in soup.find_all("a", href=True):
                    href = urljoin(url, tag["href"])
                    if _is_same_origin(href, target) and href not in visited:
                        to_visit.append(href)
            except Exception as exc:
                console.print(f"[yellow][discovery] Fallback crawl error for {url}: {exc}[/yellow]")

    console.print(f"[green][discovery] Fallback crawl complete — {len(state.endpoints)} endpoints[/green]")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def discover_with_playwright(
    target: str,
    config: ScanConfig,
    state: ScanState,
    username: str = "",
    password: str = "",
    client_id: str = "",
    login_steps=None,
) -> None:
    """
    Launch a headless Chromium browser, record all XHR/fetch traffic, crawl
    navigation links, and populate state.endpoints with discovered API calls.
    """
    if not PLAYWRIGHT_AVAILABLE:
        await _fallback_http_crawl(target, config, state)
        return

    console.print(f"[bold blue][discovery] Starting Playwright crawl → {target}[/bold blue]")

    recorded_calls: list = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        ctx = await browser.new_context(ignore_https_errors=True)
        page = await ctx.new_page()

        # ----------------------------------------------------------------
        # Request interceptor: record XHR / fetch (skip analytics & static)
        # ----------------------------------------------------------------
        async def _on_request(request) -> None:
            url = request.url
            if request.resource_type not in ("xhr", "fetch"):
                return
            if _should_skip(url):
                return
            recorded_calls.append({
                "url": url,
                "method": request.method,
                "post_data": request.post_data,
                "headers": dict(request.headers),
                "response_headers": {},
            })

        async def _on_response(response) -> None:
            url = response.url
            if _should_skip(url):
                return
            # Update the matching recorded call with response headers
            for call in reversed(recorded_calls):
                if call["url"] == url:
                    try:
                        call["response_headers"] = dict(response.headers)
                    except Exception:
                        pass
                    break

        page.on("request", _on_request)
        page.on("response", _on_response)

        # ----------------------------------------------------------------
        # 3. Navigate to target
        # ----------------------------------------------------------------
        try:
            await page.goto(target, wait_until="networkidle", timeout=30000)
        except Exception as exc:
            console.print(f"[yellow][discovery] Initial navigation warning: {exc}[/yellow]")

        # ----------------------------------------------------------------
        # 4. Login if credentials provided
        # ----------------------------------------------------------------
        if username or password or client_id:
            await _attempt_login(page, ctx, target, username, password, client_id, config)

        # ----------------------------------------------------------------
        # 5. Discover navigation links
        # ----------------------------------------------------------------
        discovered_links: list[str] = []
        link_selectors = ["a[href]", "[data-href]", "[routerlink]"]
        for sel in link_selectors:
            try:
                elements = await page.query_selector_all(sel)
                for el in elements:
                    href = await el.get_attribute("href") or \
                           await el.get_attribute("data-href") or \
                           await el.get_attribute("routerlink") or ""
                    if href:
                        full = urljoin(target, href)
                        if _is_same_origin(full, target) and full not in discovered_links:
                            discovered_links.append(full)
            except Exception:
                pass

        # ----------------------------------------------------------------
        # 6. Click nav elements (limit 20)
        # ----------------------------------------------------------------
        clicked = 0
        for sel in NAV_CLICK_SELECTORS:
            if clicked >= 20:
                break
            try:
                elements = await page.query_selector_all(sel)
                for el in elements:
                    if clicked >= 20:
                        break
                    try:
                        await el.click(timeout=2000)
                        await page.wait_for_load_state("networkidle", timeout=5000)
                        clicked += 1
                    except Exception:
                        pass
            except Exception:
                pass

        console.print(f"[cyan][discovery] Clicked {clicked} nav elements[/cyan]")

        # ----------------------------------------------------------------
        # 7. Navigate discovered links (limit 30)
        # ----------------------------------------------------------------
        nav_count = 0
        for link in discovered_links[:30]:
            try:
                await page.goto(link, wait_until="networkidle", timeout=15000)
                nav_count += 1
            except Exception:
                pass

        console.print(f"[cyan][discovery] Navigated {nav_count} links[/cyan]")

        # ----------------------------------------------------------------
        # 8. Scroll 3 times to trigger lazy loading
        # ----------------------------------------------------------------
        for _ in range(3):
            try:
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await page.wait_for_timeout(800)
            except Exception:
                pass

        # ----------------------------------------------------------------
        # 9. Extract SPA routes from JS (hash-based routes)
        # ----------------------------------------------------------------
        try:
            js_content = await page.evaluate("""
                () => {
                    const scripts = Array.from(document.querySelectorAll('script'));
                    return scripts.map(s => s.textContent).join('\\n');
                }
            """)
            hash_routes = re.findall(r'["\'](#/[^"\'\\s]+)["\']', js_content or "")
            for route in hash_routes:
                full = urljoin(target, route)
                if full not in discovered_links:
                    discovered_links.append(full)
        except Exception:
            pass

        # ----------------------------------------------------------------
        # 10. Extract tokens from localStorage
        # ----------------------------------------------------------------
        try:
            local_storage = await page.evaluate("""
                () => {
                    const result = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        result[key] = localStorage.getItem(key);
                    }
                    return result;
                }
            """)
            if local_storage:
                for key, value in local_storage.items():
                    if AUTH_TOKEN_KEYS.search(key):
                        token_value = value
                        # Try to parse JSON and extract access_token
                        try:
                            parsed = json.loads(value)
                            if isinstance(parsed, dict):
                                token_value = parsed.get("access_token", value)
                        except (json.JSONDecodeError, ValueError):
                            pass
                        state.auth_info[key] = token_value
                        console.print(f"[green][discovery] Found token in localStorage: {key}[/green]")
        except Exception:
            pass

        # ----------------------------------------------------------------
        # 11. Collect cookies
        # ----------------------------------------------------------------
        try:
            cookies = await ctx.cookies()
            state.auth_info["cookies"] = {c["name"]: c["value"] for c in cookies}
            console.print(f"[cyan][discovery] Collected {len(cookies)} cookies[/cyan]")
        except Exception:
            pass

        await browser.close()

    # ----------------------------------------------------------------
    # 12. Convert recorded API calls to Endpoint objects
    # ----------------------------------------------------------------
    console.print(f"[cyan][discovery] Converting {len(recorded_calls)} recorded API calls[/cyan]")
    endpoints: list[Endpoint] = []
    for call in recorded_calls:
        try:
            ep = _url_to_endpoint(
                url=call["url"],
                method=call["method"],
                body=call.get("post_data"),
                headers=call.get("response_headers", {}),
            )
            endpoints.append(ep)
        except Exception as exc:
            console.print(f"[yellow][discovery] Endpoint conversion error: {exc}[/yellow]")

    state.add_endpoints(endpoints)
    console.print(f"[bold green][discovery] Added {len(endpoints)} endpoints to state[/bold green]")

    # ----------------------------------------------------------------
    # 13. Detect tech stack
    # ----------------------------------------------------------------
    _detect_tech_stack(state, recorded_calls)

    console.print(
        f"[bold green][discovery] Crawl complete — "
        f"{len(state.endpoints)} total endpoints[/bold green]"
    )
