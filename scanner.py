"""
Deterministic Scanner — Systematic vulnerability testing without LLM dependency.

The LLM agent is smart but unreliable for coverage — it may skip endpoints,
repeat tests, or use wrong params. This scanner guarantees every parameter
on every form gets tested against every applicable vulnerability type.

Architecture:
  1. Crawl → get attack surface (forms, params, endpoints)
  2. For each endpoint × param × vuln_type → run validator
  3. Collect all confirmed findings
  4. LLM agent is still used for creative exploration AFTER systematic scan

This is what separates a toy from a product.
"""

import time
from typing import Optional
from dataclasses import dataclass, field
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

from session_manager import SessionManager
from crawler import crawl_target
from validator import (
    validate_sqli, validate_xss, validate_command_injection, validate_path_traversal,
    validate_csrf, validate_idor, validate_open_redirect, validate_ssrf,
    validate_security_headers, validate_sensitive_data,
)

console = Console()


# ── Vuln type → applicable param heuristics ──────────────────────────

# Which vuln types to test on which kinds of parameters
PARAM_VULN_MAP = {
    # Injection vulns: test on params that accept user text input
    "sqli": {"input_types": ["text", "search", "hidden", "number", "select"],
             "name_hints": ["id", "user", "name", "search", "query", "q", "item",
                            "cat", "category", "order", "sort", "column", "table",
                            "filter", "where", "select", "limit", "offset"]},

    "xss": {"input_types": ["text", "search", "hidden", "textarea"],
            "name_hints": ["name", "user", "search", "q", "query", "comment",
                           "message", "msg", "text", "title", "desc", "input",
                           "value", "data", "content", "body", "subject"]},

    "command_injection": {"input_types": ["text", "hidden"],
                          "name_hints": ["ip", "host", "ping", "cmd", "command",
                                         "exec", "run", "domain", "address", "target",
                                         "server", "url", "file", "path", "dir"]},

    "path_traversal": {"input_types": ["text", "hidden", "select"],
                       "name_hints": ["file", "path", "page", "include", "template",
                                      "doc", "document", "folder", "dir", "load",
                                      "read", "view", "content", "filename", "lang"]},

    "open_redirect": {"input_types": ["text", "hidden"],
                      "name_hints": ["url", "redirect", "return", "next", "goto",
                                     "dest", "destination", "redir", "return_url",
                                     "continue", "target", "link", "ref", "callback"]},

    "ssrf": {"input_types": ["text", "hidden", "url"],
             "name_hints": ["url", "uri", "link", "src", "source", "fetch",
                            "proxy", "request", "load", "image", "img",
                            "callback", "webhook", "api"]},

    "idor": {"input_types": ["text", "hidden", "number"],
             "name_hints": ["id", "uid", "user_id", "userid", "account",
                            "order_id", "orderid", "doc_id", "profile",
                            "no", "num", "number", "ref", "item_id"]},
}

# These are tested per-form, not per-param
FORM_LEVEL_VULNS = ["csrf"]

# These are tested per-page (passive checks)
PAGE_LEVEL_VULNS = ["security_headers", "sensitive_data"]


@dataclass
class ScanTarget:
    """An endpoint + param to test."""
    url: str
    method: str
    param_name: str
    param_type: str  # input type (text, hidden, etc.)
    form_action: str  # where the form submits to
    extra_params: dict = field(default_factory=dict)


@dataclass
class ScanFinding:
    """A confirmed vulnerability."""
    vuln_type: str
    url: str
    param_name: str
    method: str
    payload: str
    evidence: str
    severity: str
    details: dict = field(default_factory=dict)


def _get_severity(vuln_type: str) -> str:
    """Map vulnerability type to severity level."""
    severity_map = {
        "sqli": "Critical",
        "command_injection": "Critical",
        "path_traversal": "Critical",
        "ssrf": "High",
        "xss": "High",
        "csrf": "Medium",
        "idor": "High",
        "open_redirect": "Medium",
        "security_headers": "Low",
        "sensitive_data": "Medium",
    }
    return severity_map.get(vuln_type, "Medium")


def _should_test_param(param_name: str, param_type: str, vuln_type: str) -> bool:
    """
    Decide if a parameter should be tested for a specific vulnerability type.
    Uses heuristics based on param name and input type to avoid wasting time
    testing Submit buttons for SQLi, etc.
    """
    if not param_name:
        return False

    name_lower = param_name.lower()

    # Skip common non-injectable params
    skip_names = {"submit", "btnsubmit", "btnsign", "btnclear", "btnlogin",
                  "login", "csrf", "token", "user_token", "_token",
                  "csrfmiddlewaretoken", "authenticity_token",
                  "max_file_size", "seclev_submit"}
    if name_lower in skip_names:
        return False

    # Skip params that are clearly submit buttons
    if param_type == "submit":
        return False

    vuln_config = PARAM_VULN_MAP.get(vuln_type)
    if not vuln_config:
        return True  # Unknown vuln type → test everything

    # Check input type compatibility
    if param_type not in vuln_config["input_types"] and param_type != "":
        return False

    # Check name hints — if name matches any hint, definitely test
    name_hints = vuln_config["name_hints"]
    for hint in name_hints:
        if hint in name_lower or name_lower in hint:
            return True

    # For injection vulns, also test params with generic names
    if vuln_type in ("sqli", "xss"):
        # Test most text inputs for SQLi and XSS (they're the most common)
        if param_type in ("text", "textarea", "search", "hidden", ""):
            return True

    return False


def _build_extra_params(form_inputs: list, test_param_name: str) -> dict:
    """Build extra_params dict from form inputs, excluding the param we're testing."""
    extra = {}
    for inp in form_inputs:
        name = inp.get("name", "")
        inp_type = inp.get("type", "text").lower()
        value = inp.get("value", "")

        if not name or name == test_param_name:
            continue

        if inp_type == "submit":
            extra[name] = value or "Submit"
        elif inp_type == "hidden":
            extra[name] = value
        # Don't include other input types — they'll be filled by the validator

    return extra


def run_systematic_scan(
    base_url: str,
    session: SessionManager,
    max_depth: int = 3,
    max_pages: int = 100,
    vuln_types: Optional[list] = None,
    skip_passive: bool = False,
) -> list:
    """
    Run a systematic scan: crawl → test every param × every vuln type.

    Args:
        base_url: Target URL
        session: SessionManager with active session
        max_depth: Crawler depth
        max_pages: Max pages to crawl
        vuln_types: Specific vuln types to test (default: all)
        skip_passive: Skip passive checks (security_headers, sensitive_data)

    Returns:
        List of ScanFinding objects
    """
    findings = []

    if vuln_types is None:
        vuln_types = list(PARAM_VULN_MAP.keys()) + FORM_LEVEL_VULNS + PAGE_LEVEL_VULNS

    # ── Phase 1: Crawl ────────────────────────────────────────────
    console.print("\n[bold blue]Phase 1: Crawling target...[/]")
    crawl_result = crawl_target(
        base_url=base_url,
        cookies=session.cookies,
        max_depth=max_depth,
        max_pages=max_pages,
    )

    attack_surface = crawl_result.get("attack_surface", [])
    pages = crawl_result.get("pages", [])
    summary = crawl_result.get("summary", {})

    console.print(f"  Pages crawled: {summary.get('pages_crawled', 0)}")
    console.print(f"  Forms found: {summary.get('forms_found', 0)}")
    console.print(f"  Unique params: {len(summary.get('unique_params', []))}")
    console.print(f"  Attack surface entries: {len(attack_surface)}")

    # Reset security level after crawl (crawler may have triggered PHPIDS or
    # changed security settings by visiting config pages)
    try:
        from tools import _try_set_low_security
        _try_set_low_security(base_url)
    except Exception:
        pass

    if not attack_surface:
        console.print("[yellow]  No attack surface found. Check authentication.[/]")
        return findings

    # ── Phase 2: Build test matrix ────────────────────────────────
    console.print("\n[bold blue]Phase 2: Building test matrix...[/]")

    test_targets = []
    tested_combos = set()  # (url, param, vuln_type) dedup

    for entry in attack_surface:
        url = entry.get("url", "")
        method = entry.get("method", "GET")
        params = entry.get("params", [])

        # Get full form input details if available
        form_inputs = []
        for page in pages:
            for form in page.get("forms", []):
                if form.get("action", "") == url or form.get("url", "") == url:
                    form_inputs = form.get("inputs", [])
                    break
            if form_inputs:
                break

        for param_name in params:
            # Find the input type for this param
            param_type = ""
            for inp in form_inputs:
                if inp.get("name") == param_name:
                    param_type = inp.get("type", "text").lower()
                    break

            extra_params = _build_extra_params(form_inputs, param_name)

            test_targets.append(ScanTarget(
                url=url,
                method=method,
                param_name=param_name,
                param_type=param_type,
                form_action=url,
                extra_params=extra_params,
            ))

    # Count how many tests we'll run
    total_tests = 0
    for target in test_targets:
        for vt in vuln_types:
            if vt in PAGE_LEVEL_VULNS or vt in FORM_LEVEL_VULNS:
                continue
            if _should_test_param(target.param_name, target.param_type, vt):
                combo = (target.url, target.param_name, vt)
                if combo not in tested_combos:
                    total_tests += 1

    # Add page-level and form-level tests
    page_urls = list(set(p.get("url", "") for p in pages if p.get("url")))
    form_urls = list(set(e.get("url", "") for e in attack_surface))

    if not skip_passive:
        for vt in PAGE_LEVEL_VULNS:
            if vt in vuln_types:
                total_tests += len(page_urls)
    for vt in FORM_LEVEL_VULNS:
        if vt in vuln_types:
            total_tests += len(form_urls)

    console.print(f"  Test targets: {len(test_targets)} endpoint×param combos")
    console.print(f"  Total tests to run: {total_tests}")

    # ── Phase 3: Run tests ────────────────────────────────────────
    console.print("\n[bold blue]Phase 3: Running vulnerability tests...[/]")

    tests_run = 0
    tested_combos.clear()

    cookies = session.cookies

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        console=console,
    ) as progress:
        task = progress.add_task("Testing...", total=total_tests)

        # ── 3a: Parameter-level tests ─────────────────────────────
        for target in test_targets:
            for vt in vuln_types:
                if vt in PAGE_LEVEL_VULNS or vt in FORM_LEVEL_VULNS:
                    continue

                if not _should_test_param(target.param_name, target.param_type, vt):
                    continue

                combo = (target.url, target.param_name, vt)
                if combo in tested_combos:
                    continue
                tested_combos.add(combo)

                progress.update(task,
                    description=f"[cyan]{vt}[/] → {target.param_name}@{target.url[-40:]}")

                result = _run_single_test(
                    vt, target.url, target.method,
                    target.param_name, cookies, target.extra_params
                )

                if result and result.get("validated"):
                    finding = ScanFinding(
                        vuln_type=result.get("type", vt),
                        url=result.get("url", target.url),
                        param_name=target.param_name,
                        method=target.method,
                        payload=str(result.get("payload", "")),
                        evidence=str(result.get("evidence", "")),
                        severity=_get_severity(vt),
                        details=result,
                    )
                    findings.append(finding)
                    console.print(
                        f"\n  [bold red]CONFIRMED:[/] {finding.vuln_type} "
                        f"@ {finding.url} (param: {finding.param_name})"
                    )

                tests_run += 1
                progress.advance(task)

                # Small delay between tests
                time.sleep(0.1)

        # ── 3b: Form-level tests (CSRF) ──────────────────────────
        tested_csrf_urls = set()
        for vt in FORM_LEVEL_VULNS:
            if vt not in vuln_types:
                continue
            for entry in attack_surface:
                url = entry.get("url", "")
                if url in tested_csrf_urls:
                    progress.advance(task)
                    continue
                tested_csrf_urls.add(url)

                method = entry.get("method", "GET")
                progress.update(task, description=f"[cyan]{vt}[/] → {url[-50:]}")

                # For CSRF, pick any state-changing param
                params = entry.get("params", [])
                param_name = params[0] if params else ""

                result = _run_single_test(vt, url, method, param_name, cookies, {})

                if result and result.get("validated"):
                    finding = ScanFinding(
                        vuln_type=result.get("type", vt),
                        url=result.get("url", url),
                        param_name=param_name,
                        method=method,
                        payload=str(result.get("payload", "")),
                        evidence=str(result.get("evidence", "")),
                        severity=_get_severity(vt),
                        details=result,
                    )
                    findings.append(finding)
                    console.print(
                        f"\n  [bold red]CONFIRMED:[/] {finding.vuln_type} @ {finding.url}"
                    )

                tests_run += 1
                progress.advance(task)
                time.sleep(0.1)

        # ── 3c: Page-level tests (headers, sensitive data) ────────
        if not skip_passive:
            tested_page_urls = set()
            for vt in PAGE_LEVEL_VULNS:
                if vt not in vuln_types:
                    continue
                for page_url in page_urls:
                    if page_url in tested_page_urls and vt == "security_headers":
                        # Only check security headers once per unique URL
                        progress.advance(task)
                        continue
                    tested_page_urls.add(page_url)

                    progress.update(task, description=f"[cyan]{vt}[/] → {page_url[-50:]}")

                    result = _run_single_test(vt, page_url, "GET", "", cookies, {})

                    if result and result.get("validated"):
                        # For security headers, only report once (not per-page)
                        if vt == "security_headers":
                            already_found = any(
                                f.vuln_type == "Missing Security Headers" for f in findings
                            )
                            if already_found:
                                progress.advance(task)
                                continue

                        finding = ScanFinding(
                            vuln_type=result.get("type", vt),
                            url=result.get("url", page_url),
                            param_name="",
                            method="GET",
                            payload=str(result.get("payload", "")),
                            evidence=str(result.get("evidence", "")),
                            severity=_get_severity(vt),
                            details=result,
                        )
                        findings.append(finding)
                        console.print(
                            f"\n  [bold red]CONFIRMED:[/] {finding.vuln_type} @ {finding.url}"
                        )

                    tests_run += 1
                    progress.advance(task)
                    time.sleep(0.05)

    # ── Phase 4: Summary ──────────────────────────────────────────
    console.print(f"\n[bold blue]Scan complete.[/] Tests run: {tests_run}, "
                  f"Findings: {len(findings)}")

    if findings:
        _print_findings_table(findings)

    session_stats = session.get_stats()
    if session_stats["reauth_count"] > 0:
        console.print(
            f"\n[dim]Session re-authenticated {session_stats['reauth_count']} time(s) "
            f"during scan.[/]"
        )

    return findings


def _run_single_test(vuln_type: str, url: str, method: str,
                     param_name: str, cookies: dict,
                     extra_params: dict) -> Optional[dict]:
    """Run a single vulnerability test. Returns validator result or None on error."""
    try:
        # Reset validator's HTTP client to avoid cookie contamination
        # (e.g., IDOR tests make unauthenticated requests that accumulate
        #  stale cookies in the client's cookie jar)
        from validator import _reset_client
        _reset_client()
        vt = vuln_type.lower()

        if "sql" in vt:
            return validate_sqli(url, method, param_name, "1'", cookies, extra_params)
        elif "xss" in vt:
            return validate_xss(url, method, param_name, cookies, extra_params)
        elif "command" in vt:
            return validate_command_injection(url, method, param_name, cookies, extra_params)
        elif "path" in vt or "traversal" in vt or "lfi" in vt:
            return validate_path_traversal(url, method, param_name, cookies, extra_params)
        elif "csrf" in vt:
            return validate_csrf(url, method, param_name, cookies, extra_params)
        elif "idor" in vt:
            return validate_idor(url, method, param_name, cookies, extra_params)
        elif "redirect" in vt:
            return validate_open_redirect(url, method, param_name, cookies, extra_params)
        elif "ssrf" in vt:
            return validate_ssrf(url, method, param_name, cookies, extra_params)
        elif "header" in vt:
            return validate_security_headers(url, method, param_name, cookies, extra_params)
        elif "sensitive" in vt:
            return validate_sensitive_data(url, method, param_name, cookies, extra_params)
        else:
            return None
    except Exception:
        return None


def _print_findings_table(findings: list):
    """Print a summary table of all findings."""
    table = Table(title="Confirmed Vulnerabilities", border_style="red")
    table.add_column("#", style="bold", width=3)
    table.add_column("Severity", style="bold")
    table.add_column("Type", style="red bold")
    table.add_column("URL", max_width=50)
    table.add_column("Param")
    table.add_column("Evidence", max_width=50)

    for i, f in enumerate(findings, 1):
        sev_style = {
            "Critical": "bold red",
            "High": "red",
            "Medium": "yellow",
            "Low": "dim",
        }.get(f.severity, "")

        table.add_row(
            str(i),
            f"[{sev_style}]{f.severity}[/]",
            f.vuln_type,
            f.url[-50:],
            f.param_name or "N/A",
            f.evidence[:50],
        )

    console.print(table)
