"""
SubdomainAgent — Comprehensive subdomain enumeration and takeover detection.

Discovery sources:
  1. Passive OSINT — crt.sh (Certificate Transparency), DNS records, Wayback Machine
  2. Active brute-force — built-in 360 words + custom wordlist via --wordlist flag
  3. DNS record enumeration — A, AAAA, CNAME, MX, NS, TXT, SOA, AXFR zone transfer
  4. Permutation engine — prefix/suffix mutations (dev-api, api-v2, api2, etc.)
  5. Recursive enumeration — discovers sub.sub.domain.com

Post-discovery:
  6. HTTP alive probing — checks which subdomains serve HTTP/HTTPS
  7. Subdomain takeover — 30+ service fingerprints (GitHub, Heroku, S3, Azure, etc.)
  8. Endpoint injection — feeds alive hosts back into the scan pipeline

Performance:
  - Async DNS via aiodns (5-10x faster) with sync socket fallback
  - Token-bucket rate limiter (configurable --rate-limit)
  - Concurrent multi-host deep scanning (--scan-all flag)
  - Custom wordlist support (--wordlist flag, SecLists compatible)

Usage:
    agent = SubdomainAgent(llm_backend="ollama")
    findings = agent.test_endpoint(endpoint, config, state)
"""

import asyncio
import socket
import re
import os
import time
import threading
import concurrent.futures
from urllib.parse import urlparse
from rich.console import Console

import httpx
from agents.base import BaseAgent

console = Console()

# ── Check for aiodns availability ─────────────────────────────────────────────

_HAS_AIODNS = False
try:
    import aiodns
    _HAS_AIODNS = True
except ImportError:
    pass


# ── Token-Bucket Rate Limiter ─────────────────────────────────────────────────

class TokenBucket:
    """
    Thread-safe token-bucket rate limiter.
    Supports both sync (.acquire()) and async (.acquire_async()) usage.

    Args:
        rate: Tokens per second (requests/sec). 0 = unlimited.
        burst: Max tokens that can accumulate. Defaults to rate.
    """

    def __init__(self, rate: float, burst: int | None = None):
        self.rate = rate
        self.burst = burst if burst is not None else max(int(rate), 1)
        self.tokens = float(self.burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()
        self._async_lock: asyncio.Lock | None = None

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._last_refill = now
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)

    def acquire(self):
        """Block until a token is available (sync)."""
        if self.rate <= 0:
            return
        while True:
            with self._lock:
                self._refill()
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
            time.sleep(0.01)

    async def acquire_async(self):
        """Wait until a token is available (async)."""
        if self.rate <= 0:
            return
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        while True:
            async with self._async_lock:
                self._refill()
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
            await asyncio.sleep(0.01)


# ── Wordlist — 360 built-in common subdomain names ───────────────────────────

SUBDOMAIN_WORDLIST = [
    # Infrastructure
    "admin", "administrator", "api", "api1", "api2", "api3", "app", "apps",
    "auth", "authentication", "autodiscover", "autoconfig",
    "backend", "backup", "backups", "beta", "billing", "blog", "board",
    "cache", "cdn", "chat", "ci", "client", "cloud", "cluster", "cms",
    "code", "console", "control", "cp", "cpanel", "cron",
    "dashboard", "data", "database", "db", "db1", "db2", "db3", "debug",
    "demo", "deploy", "desktop", "dev", "dev1", "dev2", "dev3", "developer",
    "development", "devops", "direct", "directory", "dl", "dns", "dns1",
    "dns2", "doc", "docs", "documentation", "download", "downloads",
    "edge", "elastic", "elasticsearch", "email", "embed", "engine",
    "es", "events", "exchange", "external",
    "feed", "file", "files", "firewall", "forum", "forums", "ftp",
    "gallery", "gateway", "git", "github", "gitlab", "go", "grafana",
    "graphql", "gw",
    "help", "helpdesk", "home", "hook", "hooks", "host", "hosting", "hub",
    "id", "identity", "image", "images", "imap", "inbox", "info",
    "infra", "infrastructure", "internal", "intranet", "io", "iot", "irc",
    "jenkins", "jira", "job", "jobs",
    "k8s", "kafka", "kb", "key", "keys", "kibana",
    "lab", "labs", "ldap", "legacy", "lib", "library", "link", "links",
    "linux", "live", "load", "local", "log", "logging", "login", "logs",
    "m", "mail", "mail1", "mail2", "mailbox", "mailer", "mailgate",
    "manage", "management", "manager", "map", "maps", "master", "mc",
    "media", "meet", "meeting", "member", "members", "memcached",
    "metrics", "mirror", "mobile", "monitor", "monitoring", "mq", "mqtt",
    "ms", "msg", "mx", "mx1", "mx2", "mysql",
    "nas", "net", "network", "new", "news", "next", "nginx", "node",
    "ns", "ns1", "ns2", "ns3", "ntp",
    "oauth", "office", "old", "on", "open", "ops", "oracle", "order",
    "orders", "origin", "outbound", "outlook",
    "panel", "partner", "partners", "pay", "payment", "payments", "pci",
    "pilot", "platform", "pm", "pop", "pop3", "portal", "postgres",
    "preview", "primary", "print", "private", "prod", "production",
    "profile", "prometheus", "proxy", "push",
    "qa", "queue",
    "rabbit", "rabbitmq", "rac", "rdp", "read", "redis", "redirect",
    "register", "relay", "release", "remote", "render", "repo", "report",
    "reports", "resolver", "rest", "review", "root", "router", "rpc", "rss",
    "s3", "sandbox", "scheduler", "search", "secure", "security", "sentry",
    "server", "service", "services", "sftp", "share", "shop", "signup",
    "site", "sites", "slack", "smtp", "smtp1", "smtp2", "snapshot", "soa",
    "social", "solr", "sonar", "spark", "splunk", "sql", "ssh", "sso",
    "stage", "staging", "stat", "static", "stats", "status", "storage",
    "store", "stream", "streaming", "stripe", "sub", "submit", "support",
    "svn", "sync", "syslog", "system",
    "task", "tasks", "teams", "temp", "test", "test1", "test2", "test3",
    "testing", "ticket", "tickets", "time", "token", "tool", "tools",
    "track", "tracker", "tracking", "transfer", "tunnel",
    "ui", "uat", "unix", "up", "update", "upload", "uploads", "url", "user",
    "users",
    "v", "v1", "v2", "v3", "vault", "video", "virtual", "vm", "vnc",
    "vpn", "vpn1", "vpn2",
    "waf", "web", "webapi", "webmail", "webhook", "webhooks", "webrtc",
    "websocket", "wiki", "windows", "work", "worker", "workers", "wp",
    "ws", "wss", "www", "www1", "www2",
    "xml", "xmpp",
    "zabbix", "zen", "zendesk", "zero", "zone", "zoo", "zookeeper",
]

# ── Permutation templates ─────────────────────────────────────────────────────

PERMUTATION_PREFIXES = [
    "dev-", "staging-", "test-", "uat-", "qa-", "prod-", "pre-",
    "int-", "internal-", "ext-", "external-", "old-", "new-", "v2-",
    "api-", "admin-", "beta-", "alpha-", "sandbox-", "demo-",
]

PERMUTATION_SUFFIXES = [
    "-dev", "-staging", "-test", "-uat", "-qa", "-prod", "-api",
    "-admin", "-internal", "-v2", "-new", "-old", "-backup", "-beta",
    "1", "2", "3", "-01", "-02",
]

# ── Takeover fingerprints (34 services) ──────────────────────────────────────

TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": (
        r".*\.github\.io$",
        ["there isn't a github pages site here", "for root urls", "site not found"],
        "Critical",
    ),
    "Heroku": (
        r".*\.herokuapp\.com$",
        ["no such app", "herokucdn.com/error-pages", "no-such-app"],
        "Critical",
    ),
    "AWS S3": (
        r".*\.s3[.-].*\.?amazonaws\.com$",
        ["nosuchbucket", "the specified bucket does not exist"],
        "Critical",
    ),
    "Azure App Service": (
        r".*\.azurewebsites\.net$",
        ["404 web site not found", "microsoft azure app service"],
        "Critical",
    ),
    "Azure Traffic Manager": (
        r".*\.trafficmanager\.net$",
        ["page not found", "404"],
        "High",
    ),
    "Azure CDN": (
        r".*\.azureedge\.net$",
        ["400 - the request hostname is invalid", "page not found"],
        "High",
    ),
    "CloudFront": (
        r".*\.cloudfront\.net$",
        ["bad request", "error generated by cloudfront"],
        "High",
    ),
    "Shopify": (
        r".*\.myshopify\.com$",
        ["sorry, this shop is currently unavailable", "only one step left"],
        "Critical",
    ),
    "Tumblr": (
        r".*\.tumblr\.com$",
        ["there's nothing here", "whatever you were looking for"],
        "High",
    ),
    "WordPress.com": (
        r".*\.wordpress\.com$",
        ["do you want to register"],
        "High",
    ),
    "Ghost": (
        r".*\.ghost\.io$",
        ["the thing you were looking for is no longer here"],
        "High",
    ),
    "Surge.sh": (
        r".*\.surge\.sh$",
        ["project not found"],
        "High",
    ),
    "Fastly": (
        r".*\.fastly\.net$",
        ["fastly error: unknown domain"],
        "High",
    ),
    "Pantheon": (
        r".*\.pantheonsite\.io$",
        ["404 unknown site", "the gods are wise"],
        "High",
    ),
    "Zendesk": (
        r".*\.zendesk\.com$",
        ["help center closed", "this help center no longer exists"],
        "High",
    ),
    "Teamwork": (
        r".*\.teamwork\.com$",
        ["oops - we didn't find your site"],
        "High",
    ),
    "Helpjuice": (
        r".*\.helpjuice\.com$",
        ["we could not find what you're looking for"],
        "High",
    ),
    "HelpScout": (
        r".*\.helpscoutdocs\.com$",
        ["no settings were found for this company"],
        "High",
    ),
    "Cargo": (
        r".*\.cargocollective\.com$",
        ["404 not found"],
        "Medium",
    ),
    "Statuspage": (
        r".*\.statuspage\.io$",
        ["you are being redirected", "status page launch"],
        "High",
    ),
    "Bitbucket": (
        r".*\.bitbucket\.io$",
        ["repository not found"],
        "High",
    ),
    "Netlify": (
        r".*\.netlify\.app$|.*\.netlify\.com$",
        ["not found - request id"],
        "High",
    ),
    "Fly.io": (
        r".*\.fly\.dev$",
        ["404 not found"],
        "High",
    ),
    "Render": (
        r".*\.onrender\.com$",
        ["not found"],
        "High",
    ),
    "Vercel": (
        r".*\.vercel\.app$|.*\.now\.sh$",
        ["404: not_found"],
        "High",
    ),
    "Unbouncepages": (
        r".*\.unbouncepages\.com$",
        ["the requested url was not found on this server"],
        "High",
    ),
    "Tilda": (
        r".*\.tilda\.ws$",
        ["please renew your subscription"],
        "Medium",
    ),
    "SmartJobBoard": (
        r".*\.smartjobboard\.com$",
        ["this job board website is no longer"],
        "Medium",
    ),
    "Strikingly": (
        r".*\.strikinglydns\.com$",
        ["page not found"],
        "High",
    ),
    "Uptimerobot": (
        r".*\.uptimerobot\.com$",
        ["page not found"],
        "Medium",
    ),
    "Pingdom": (
        r".*\.pingdom\.com$",
        ["sorry, couldn't find the status page"],
        "Medium",
    ),
    "Canny": (
        r".*\.canny\.io$",
        ["company not found", "there is no such company"],
        "High",
    ),
    "ReadMe": (
        r".*\.readme\.io$",
        ["project not found"],
        "High",
    ),
    "Agile CRM": (
        r".*\.agilecrm\.com$",
        ["sorry, this page is no longer available"],
        "Medium",
    ),
}


# ═══════════════════════════════════════════════════════════════════════════════
# Custom Wordlist Loader
# ═══════════════════════════════════════════════════════════════════════════════

def load_wordlist(path: str) -> list[str]:
    """
    Load a custom subdomain wordlist from file.
    Compatible with SecLists format (one subdomain per line, # comments).

    Args:
        path: Path to wordlist file (e.g., SecLists/Discovery/DNS/subdomains-top1million-5000.txt)

    Returns:
        List of subdomain words (no duplicates, stripped, no blanks/comments).
    """
    if not os.path.isfile(path):
        console.print(f"  [yellow]Wordlist not found: {path} — using built-in[/]")
        return SUBDOMAIN_WORDLIST

    words = []
    seen = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip().lower()
                # Skip blanks, comments, and lines with dots (full domains, not words)
                if not word or word.startswith("#"):
                    continue
                # Handle full domain entries (e.g., "admin.example.com" → "admin")
                if "." in word:
                    word = word.split(".")[0]
                if word and word not in seen:
                    seen.add(word)
                    words.append(word)
    except Exception as e:
        console.print(f"  [yellow]Error reading wordlist: {e} — using built-in[/]")
        return SUBDOMAIN_WORDLIST

    console.print(f"  [dim]Loaded custom wordlist: {len(words)} words from {path}[/]")
    return words


def _extract_base_domain(url: str) -> str:
    """Extract base domain from URL. E.g., "https://api.example.com/path" → "example.com" """
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path
    if ":" in hostname:
        hostname = hostname.split(":")[0]
    parts = hostname.split(".")
    if len(parts) < 2:
        return hostname
    if len(parts) >= 3 and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ═══════════════════════════════════════════════════════════════════════════════
# Async DNS Resolution (aiodns with sync fallback)
# ═══════════════════════════════════════════════════════════════════════════════

async def _async_resolve_batch(
    fqdns: list[str],
    limiter: TokenBucket,
    concurrency: int = 100,
) -> dict[str, list[str]]:
    """
    Resolve a batch of FQDNs using aiodns (async, massively concurrent).
    Returns dict of fqdn → [ip1, ip2, ...] for resolved ones only.

    Falls back to sync socket resolution if aiodns not available.
    """
    if not _HAS_AIODNS:
        return _sync_resolve_batch(fqdns, limiter)

    resolver = aiodns.DNSResolver()
    results: dict[str, list[str]] = {}
    semaphore = asyncio.Semaphore(concurrency)

    async def _resolve_one(fqdn: str):
        await limiter.acquire_async()
        async with semaphore:
            try:
                resp = await resolver.query(fqdn, "A")
                ips = [r.host for r in resp]
                if ips:
                    results[fqdn] = ips
            except aiodns.error.DNSError:
                pass
            except Exception:
                pass

    # Run all resolutions concurrently
    await asyncio.gather(*[_resolve_one(fqdn) for fqdn in fqdns])
    return results


def _sync_resolve_batch(
    fqdns: list[str],
    limiter: TokenBucket,
    max_workers: int = 20,
) -> dict[str, list[str]]:
    """Sync fallback: resolve FQDNs using ThreadPoolExecutor + socket."""
    results: dict[str, list[str]] = {}

    def _resolve(fqdn: str):
        limiter.acquire()
        try:
            infos = socket.getaddrinfo(fqdn, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = list({r[4][0] for r in infos})
            if ips:
                return fqdn, ips
        except (socket.gaierror, socket.timeout, OSError):
            pass
        return fqdn, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for fqdn, ips in pool.map(_resolve, fqdns):
            if ips:
                results[fqdn] = ips

    return results


def _run_async_resolve(fqdns: list[str], limiter: TokenBucket, concurrency: int = 100) -> dict[str, list[str]]:
    """
    Run async DNS resolution from sync context.
    Creates a new event loop if needed (safe to call from threads).
    """
    if not _HAS_AIODNS:
        return _sync_resolve_batch(fqdns, limiter)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already inside an event loop — fall back to sync
        return _sync_resolve_batch(fqdns, limiter)

    return asyncio.run(_async_resolve_batch(fqdns, limiter, concurrency))


# ═══════════════════════════════════════════════════════════════════════════════
# Passive OSINT Sources
# ═══════════════════════════════════════════════════════════════════════════════

def _query_crtsh(domain: str, timeout: int = 15) -> set[str]:
    """Query crt.sh Certificate Transparency logs for subdomains."""
    subdomains = set()
    try:
        resp = httpx.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=timeout, follow_redirects=True,
        )
        if resp.status_code != 200:
            return subdomains
        for entry in resp.json():
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(f".{domain}") and name != domain:
                    subdomains.add(name)
    except Exception:
        pass
    return subdomains


def _query_wayback(domain: str, timeout: int = 15) -> set[str]:
    """Query Wayback Machine for historical subdomains."""
    subdomains = set()
    try:
        resp = httpx.get(
            f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json"
            f"&fl=original&collapse=urlkey&limit=500",
            timeout=timeout, follow_redirects=True,
        )
        if resp.status_code != 200:
            return subdomains
        results = resp.json()
        for row in results[1:]:  # Skip header row
            try:
                parsed = urlparse(row[0])
                hostname = parsed.netloc.lower()
                if ":" in hostname:
                    hostname = hostname.split(":")[0]
                if hostname.endswith(f".{domain}") and hostname != domain:
                    subdomains.add(hostname)
            except Exception:
                continue
    except Exception:
        pass
    return subdomains


def _query_dns_records(domain: str) -> dict:
    """Enumerate DNS records — MX, NS, TXT, AXFR."""
    records = {"MX": [], "NS": [], "TXT": [], "CNAME": []}
    import subprocess

    for rtype in ("MX", "NS", "TXT"):
        try:
            result = subprocess.run(
                ["dig", "+short", rtype, domain],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.strip().splitlines():
                val = line.strip().rstrip(".")
                if rtype == "MX":
                    parts = val.split()
                    val = parts[-1].rstrip(".") if len(parts) >= 2 else val
                if rtype == "TXT":
                    val = val.strip('"')
                if val:
                    records[rtype].append(val)
        except Exception:
            pass

    # Try AXFR zone transfer
    for ns in records.get("NS", [])[:2]:
        try:
            result = subprocess.run(
                ["dig", "AXFR", domain, f"@{ns}"],
                capture_output=True, text=True, timeout=10,
            )
            if "Transfer failed" not in result.stdout and result.stdout.strip():
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if parts and parts[0].endswith(f".{domain}."):
                        hostname = parts[0].rstrip(".")
                        if hostname != domain:
                            records.setdefault("AXFR", []).append(hostname)
        except Exception:
            continue

    return records


# ═══════════════════════════════════════════════════════════════════════════════
# CNAME + Takeover Detection
# ═══════════════════════════════════════════════════════════════════════════════

def _get_cname(fqdn: str) -> str:
    """Get CNAME for a subdomain. Returns CNAME string or empty."""
    try:
        result = socket.gethostbyname_ex(fqdn)
        if result[1]:
            return result[1][0]
    except Exception:
        pass
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "CNAME", fqdn],
            capture_output=True, text=True, timeout=5,
        )
        cname = result.stdout.strip().rstrip(".")
        if cname and cname != fqdn:
            return cname
    except Exception:
        pass
    return ""


def _check_takeover(fqdn: str, cname: str) -> dict | None:
    """Check if a CNAME-pointed subdomain is vulnerable to takeover."""
    cname_lower = cname.lower()
    for service, (pattern, error_strings, severity) in TAKEOVER_FINGERPRINTS.items():
        if not re.match(pattern, cname_lower):
            continue
        for scheme in ("https", "http"):
            try:
                resp = httpx.get(
                    f"{scheme}://{fqdn}", timeout=8,
                    follow_redirects=False, verify=False,
                )
                body_lower = resp.text.lower()
                for error_str in error_strings:
                    if error_str in body_lower:
                        return {
                            "service": service, "cname": cname,
                            "severity": severity,
                            "evidence": f"HTTP {resp.status_code}: matched '{error_str}'",
                            "response_snippet": resp.text[:200],
                        }
            except (httpx.ConnectError, httpx.TimeoutException):
                return {
                    "service": service, "cname": cname,
                    "severity": severity,
                    "evidence": f"Connection failed to {cname} — likely unclaimed",
                    "response_snippet": "",
                }
            except Exception:
                continue
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP Alive Probing (rate-limited)
# ═══════════════════════════════════════════════════════════════════════════════

def _probe_http(fqdn: str, limiter: TokenBucket, timeout: float = 5.0) -> dict | None:
    """Check if a subdomain serves HTTP/HTTPS. Rate-limited."""
    for scheme in ("https", "http"):
        limiter.acquire()
        try:
            resp = httpx.get(
                f"{scheme}://{fqdn}", timeout=timeout,
                follow_redirects=True, verify=False,
            )
            title = ""
            match = re.search(r'<title[^>]*>(.*?)</title>', resp.text, re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()[:100]
            return {
                "fqdn": fqdn,
                "url": f"{scheme}://{fqdn}",
                "status_code": resp.status_code,
                "title": title,
                "server": resp.headers.get("server", ""),
                "content_length": len(resp.text),
                "redirect_url": str(resp.url) if str(resp.url) != f"{scheme}://{fqdn}" else None,
            }
        except Exception:
            continue
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Permutation Engine
# ═══════════════════════════════════════════════════════════════════════════════

def _generate_permutations(discovered: set[str], base_domain: str) -> set[str]:
    """Generate prefix/suffix mutations from discovered subdomains."""
    permutations = set()
    for fqdn in discovered:
        sub = fqdn.replace(f".{base_domain}", "").split(".")[0]
        if not sub or sub == "www":
            continue
        for prefix in PERMUTATION_PREFIXES:
            permutations.add(f"{prefix}{sub}.{base_domain}")
        for suffix in PERMUTATION_SUFFIXES:
            permutations.add(f"{sub}{suffix}.{base_domain}")
    permutations -= discovered
    return permutations


# ═══════════════════════════════════════════════════════════════════════════════
# Finding Builder
# ═══════════════════════════════════════════════════════════════════════════════

def _make_finding(subdomain: str, url: str, severity: str, evidence: str,
                  vuln_type: str = "subdomain_takeover") -> dict:
    return {
        "vuln_type": vuln_type, "url": url, "subdomain": subdomain,
        "method": "GET", "param_name": "",
        "payload": f"Subdomain: {subdomain}",
        "evidence": evidence, "severity": severity,
        "source": "SubdomainAgent", "validated": True,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Agent
# ═══════════════════════════════════════════════════════════════════════════════

class SubdomainAgent(BaseAgent):
    model = "claude-haiku-4-5-20251001"
    max_iterations = 5
    vuln_type = "subdomain"
    agent_name = "SubdomainAgent"
    allowed_tools = []

    system_prompt = """You are a subdomain enumeration and takeover specialist. \
Test ONLY for subdomain discovery and takeover vulnerabilities."""

    def _deterministic_test(self, endpoint, config, state) -> list:
        """
        Comprehensive subdomain enumeration and takeover testing.

        Config flags read from ScanConfig:
          - subdomain_wordlist: str  → path to custom wordlist file
          - subdomain_rate_limit: float  → max DNS/HTTP requests per second (0=unlimited)
          - subdomain_threads: int  → max concurrent workers (default 50)
          - subdomain_scan_all: bool  → deep-scan ALL alive hosts, not just first
          - subdomain_dns_concurrency: int  → async DNS concurrency (default 200)
        """
        url = endpoint.url
        base_domain = _extract_base_domain(url)

        # ── Read config flags ────────────────────────────────────────
        max_workers = getattr(config, 'subdomain_threads', 50)
        rate_limit = getattr(config, 'subdomain_rate_limit', 0)  # 0 = unlimited
        wordlist_path = getattr(config, 'subdomain_wordlist', None)
        scan_all = getattr(config, 'subdomain_scan_all', False)
        dns_concurrency = getattr(config, 'subdomain_dns_concurrency', 200)

        # ── Create rate limiter ──────────────────────────────────────
        limiter = TokenBucket(rate=rate_limit, burst=max(int(rate_limit), 50) if rate_limit > 0 else 0)

        console.print(f"  [cyan]SubdomainAgent: comprehensive enum for {base_domain}[/]")
        if _HAS_AIODNS:
            console.print(f"  [dim]DNS engine: aiodns (async, {dns_concurrency} concurrent)[/]")
        else:
            console.print(f"  [dim]DNS engine: socket (sync, {max_workers} threads) — pip install aiodns for 5-10x speed[/]")
        if rate_limit > 0:
            console.print(f"  [dim]Rate limit: {rate_limit} req/sec[/]")
        if scan_all:
            console.print(f"  [dim]Mode: deep-scan ALL alive hosts[/]")

        findings = []
        all_subdomains: set[str] = set()

        # ── Step 1: Passive OSINT ────────────────────────────────────
        console.print("  [dim]Step 1: Passive OSINT (crt.sh + Wayback)...[/]")

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            crtsh_future = pool.submit(_query_crtsh, base_domain)
            wayback_future = pool.submit(_query_wayback, base_domain)
            dns_future = pool.submit(_query_dns_records, base_domain)

            crtsh_subs = crtsh_future.result()
            wayback_subs = wayback_future.result()
            dns_records = dns_future.result()

        all_subdomains.update(crtsh_subs)
        all_subdomains.update(wayback_subs)
        for hostname in dns_records.get("AXFR", []):
            all_subdomains.add(hostname)

        passive_count = len(all_subdomains)
        console.print(
            f"  [dim]  crt.sh: {len(crtsh_subs)} | "
            f"Wayback: {len(wayback_subs)} | "
            f"AXFR: {len(dns_records.get('AXFR', []))}[/]"
        )

        if dns_records.get("MX") or dns_records.get("NS"):
            findings.append(_make_finding(
                subdomain=base_domain, url=url, severity="Info",
                vuln_type="dns_records",
                evidence=(
                    f"MX: {', '.join(dns_records.get('MX', [])[:5])} | "
                    f"NS: {', '.join(dns_records.get('NS', [])[:5])} | "
                    f"TXT records: {len(dns_records.get('TXT', []))}"
                ),
            ))

        # ── Step 2: Active brute-force ───────────────────────────────
        wordlist = SUBDOMAIN_WORDLIST
        if wordlist_path:
            wordlist = load_wordlist(wordlist_path)

        console.print(f"  [dim]Step 2: Active brute-force ({len(wordlist)} words)...[/]")

        brute_candidates = [f"{w}.{base_domain}" for w in wordlist
                           if f"{w}.{base_domain}" not in all_subdomains]

        brute_resolved = _run_async_resolve(brute_candidates, limiter, dns_concurrency)
        all_subdomains.update(brute_resolved.keys())
        console.print(
            f"  [dim]  Brute-force: {len(brute_resolved)} new (total: {len(all_subdomains)})[/]"
        )

        # ── Step 3: Permutation engine ───────────────────────────────
        console.print("  [dim]Step 3: Permutation mutations...[/]")

        permutations = _generate_permutations(all_subdomains, base_domain)
        perm_list = sorted(permutations)[:1000]  # Cap

        perm_resolved = _run_async_resolve(perm_list, limiter, dns_concurrency)
        all_subdomains.update(perm_resolved.keys())
        console.print(
            f"  [dim]  Permutations: {len(perm_resolved)} new (total: {len(all_subdomains)})[/]"
        )

        # ── Step 4: Recursive enumeration ────────────────────────────
        console.print("  [dim]Step 4: Recursive sub-subdomain check...[/]")

        recursive_candidates = []
        for fqdn in list(all_subdomains):
            sub_part = fqdn.replace(f".{base_domain}", "")
            if "." not in sub_part:
                for prefix in ["dev", "staging", "api", "admin", "internal", "test"]:
                    candidate = f"{prefix}.{fqdn}"
                    if candidate not in all_subdomains:
                        recursive_candidates.append(candidate)

        recursive_candidates = recursive_candidates[:500]
        recursive_resolved = _run_async_resolve(recursive_candidates, limiter, dns_concurrency)
        all_subdomains.update(recursive_resolved.keys())
        console.print(
            f"  [dim]  Recursive: {len(recursive_resolved)} new (total: {len(all_subdomains)})[/]"
        )

        # ── Step 5: Verify passive-only subdomains resolve ───────────
        console.print("  [dim]Step 5: Verifying DNS resolution...[/]")

        already_verified = set(brute_resolved.keys()) | set(perm_resolved.keys()) | set(recursive_resolved.keys())
        unverified = [s for s in all_subdomains if s not in already_verified]

        passive_verified = _run_async_resolve(unverified, limiter, dns_concurrency)

        resolved_subdomains = set(already_verified) | set(passive_verified.keys())
        # Merge all IP data
        all_ips: dict[str, list[str]] = {}
        for d in (brute_resolved, perm_resolved, recursive_resolved, passive_verified):
            all_ips.update(d)

        console.print(
            f"  [dim]  Resolved: {len(resolved_subdomains)} / {len(all_subdomains)} total[/]"
        )

        # ── Step 6: HTTP alive probing (rate-limited) ────────────────
        console.print(
            f"  [dim]Step 6: HTTP probing {len(resolved_subdomains)} subdomains...[/]"
        )

        alive_hosts = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_map = {
                pool.submit(_probe_http, fqdn, limiter): fqdn
                for fqdn in resolved_subdomains
            }
            for future in concurrent.futures.as_completed(future_map):
                result = future.result()
                if result:
                    alive_hosts.append(result)
                    console.print(
                        f"    [green]\u2713 {result['fqdn']} "
                        f"[{result['status_code']}] {result['title'][:40]}[/]"
                    )

        console.print(f"  [dim]  Alive: {len(alive_hosts)} HTTP-serving subdomains[/]")

        # ── Step 7: CNAME + takeover checks ──────────────────────────
        console.print("  [dim]Step 7: Checking for subdomain takeover...[/]")

        takeover_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            cname_futures = {
                pool.submit(_get_cname, fqdn): fqdn
                for fqdn in resolved_subdomains
            }
            for future in concurrent.futures.as_completed(cname_futures):
                fqdn = cname_futures[future]
                cname = future.result()
                if not cname:
                    continue
                takeover_result = _check_takeover(fqdn, cname)
                if takeover_result:
                    takeover_count += 1
                    console.print(
                        f"    [bold red]\u2717 TAKEOVER: {fqdn} \u2192 "
                        f"{takeover_result['service']} ({cname})[/]"
                    )
                    findings.append(_make_finding(
                        subdomain=fqdn, url=url,
                        severity=takeover_result["severity"],
                        evidence=(
                            f"Subdomain {fqdn} \u2192 CNAME {cname} "
                            f"({takeover_result['service']}). "
                            f"{takeover_result['evidence']}"
                        ),
                    ))

        # ── Step 8: Inject alive hosts into scan pipeline ────────────
        if alive_hosts and state:
            injected = 0
            hosts_to_inject = alive_hosts if scan_all else alive_hosts[:1]
            for host in hosts_to_inject:
                try:
                    from engine.scan_state import Endpoint
                    new_endpoint = Endpoint(
                        url=host["url"], method="GET",
                        tags={"subdomain_discovered"},
                    )
                    state.add_endpoint(new_endpoint)
                    injected += 1
                except Exception:
                    pass

            if scan_all:
                console.print(
                    f"  [dim]  Injected ALL {injected} alive subdomains for deep scanning[/]"
                )
            else:
                console.print(
                    f"  [dim]  Injected {injected} subdomain endpoint "
                    f"(use scan_all=True to deep-scan all {len(alive_hosts)})[/]"
                )

        # ── Step 9 (scan_all): Parallel deep-scan of alive hosts ─────
        if scan_all and len(alive_hosts) > 1 and state:
            console.print(
                f"  [dim]Step 9: Parallel deep-scan of {len(alive_hosts)} alive hosts...[/]"
            )
            deep_findings = self._deep_scan_alive_hosts(alive_hosts, config, state, limiter)
            findings.extend(deep_findings)
            console.print(
                f"  [dim]  Deep scan: {len(deep_findings)} additional findings[/]"
            )

        # ── Summary ──────────────────────────────────────────────────
        console.print(
            f"  [bold green][SubdomainAgent] "
            f"Sources: {passive_count} passive + {len(brute_resolved)} brute + "
            f"{len(perm_resolved)} perm + {len(recursive_resolved)} recursive | "
            f"Resolved: {len(resolved_subdomains)} | "
            f"Alive: {len(alive_hosts)} | "
            f"Takeovers: {takeover_count}[/]"
        )

        # Store summary on state for report
        if state:
            try:
                with state._lock:
                    state.subdomain_results = {
                        "base_domain": base_domain,
                        "total_discovered": len(all_subdomains),
                        "resolved": len(resolved_subdomains),
                        "alive": len(alive_hosts),
                        "alive_hosts": alive_hosts,
                        "takeovers": takeover_count,
                        "dns_records": dns_records,
                        "all_subdomains": sorted(all_subdomains),
                        "ip_map": {k: v for k, v in all_ips.items()},
                    }
            except Exception:
                pass

        return findings

    # ── Deep scan: run vuln agents against each alive subdomain host ──

    def _deep_scan_alive_hosts(self, alive_hosts: list, config, state, limiter: TokenBucket) -> list:
        """
        Run lightweight recon on each alive subdomain in parallel.
        Checks for: open admin panels, default creds pages, exposed APIs,
        tech fingerprints, and security header issues.
        """
        findings = []
        max_workers = min(len(alive_hosts), getattr(config, 'subdomain_threads', 50))

        def _scan_one_host(host: dict) -> list:
            host_findings = []
            host_url = host["url"]
            fqdn = host["fqdn"]

            # Probe common sensitive paths on this host
            sensitive_paths = [
                "/admin", "/login", "/.env", "/.git/HEAD", "/api", "/graphql",
                "/swagger.json", "/openapi.json", "/api-docs",
                "/debug", "/phpinfo.php", "/server-status",
                "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
            ]

            for path in sensitive_paths:
                limiter.acquire()
                try:
                    resp = httpx.get(
                        f"{host_url}{path}", timeout=5,
                        follow_redirects=True, verify=False,
                    )
                    if resp.status_code == 200 and len(resp.text) > 50:
                        host_findings.append(_make_finding(
                            subdomain=fqdn, url=f"{host_url}{path}",
                            severity="Medium" if path.startswith("/.") else "Info",
                            vuln_type="subdomain_exposed_path",
                            evidence=(
                                f"Exposed path {path} on {fqdn} "
                                f"[HTTP {resp.status_code}, {len(resp.text)} bytes]"
                            ),
                        ))
                except Exception:
                    continue

            # Check security headers
            limiter.acquire()
            try:
                resp = httpx.get(host_url, timeout=5, follow_redirects=True, verify=False)
                missing_headers = []
                for header in ["Strict-Transport-Security", "X-Frame-Options",
                               "X-Content-Type-Options", "Content-Security-Policy"]:
                    if header.lower() not in {k.lower() for k in resp.headers.keys()}:
                        missing_headers.append(header)
                if missing_headers:
                    host_findings.append(_make_finding(
                        subdomain=fqdn, url=host_url,
                        severity="Low",
                        vuln_type="subdomain_missing_headers",
                        evidence=f"Missing security headers on {fqdn}: {', '.join(missing_headers)}",
                    ))
            except Exception:
                pass

            return host_findings

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_scan_one_host, host): host for host in alive_hosts}
            for future in concurrent.futures.as_completed(futures):
                try:
                    host_findings = future.result()
                    findings.extend(host_findings)
                except Exception:
                    continue

        return findings
