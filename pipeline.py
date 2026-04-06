"""
Scan Pipeline — Shared scan runners and output formatting.

Used by both main.py (CLI mode) and blackbox.py (interactive mode).
"""

import asyncio
import os
import time
from typing import Optional

from rich.console import Console

console = Console()


# ── Finding format conversion ────────────────────────────────────────────

def findings_to_dicts(findings, source="systematic"):
    """Convert ScanFinding objects to standard finding dicts."""
    return [
        {
            "source": source,
            "vuln_type": f.vuln_type,
            "url": f.url,
            "param_name": f.param_name,
            "method": f.method,
            "payload": f.payload,
            "evidence": f.evidence,
            "severity": f.severity,
        }
        for f in findings
    ]


# ── Scan runners ─────────────────────────────────────────────────────────

def run_systematic(target, session, max_depth=3, max_pages=100):
    """Run the deterministic systematic scanner."""
    console.print(f"\n[bold blue]{'='*60}[/]")
    console.print("[bold blue]SYSTEMATIC SCAN[/]")
    console.print(f"[bold blue]{'='*60}[/]")

    from scanner import run_systematic_scan
    findings = run_systematic_scan(
        base_url=target, session=session,
        max_depth=max_depth, max_pages=max_pages,
    )
    return findings_to_dicts(findings, "systematic")


def run_agent(target, auth_config=None, max_iterations=25, model=None, task=None, llm_backend="ollama"):
    """Run the LLM-powered agent scan."""
    console.print(f"\n[bold green]{'='*60}[/]")
    console.print(f"[bold green]AI AGENT SCAN ({llm_backend.upper()})[/]")
    console.print(f"[bold green]{'='*60}[/]")

    if llm_backend == "ollama":
        try:
            import httpx
            resp = httpx.get("http://localhost:11434/api/tags", timeout=5)
            models = [m["name"] for m in resp.json().get("models", [])]
            if not models:
                console.print("[yellow]Ollama has no models. Skipping agent scan.[/]")
                return []
            console.print(f"[dim]Ollama models: {', '.join(models)}[/dim]")
        except Exception:
            console.print("[yellow]Ollama not running. Skipping agent scan.[/]")
            return []
    elif llm_backend == "anthropic":
        import os
        if not os.environ.get("ANTHROPIC_API_KEY"):
            console.print("[bold red]ANTHROPIC_API_KEY not set. Skipping agent scan.[/]")
            console.print("[dim]Set it with: export ANTHROPIC_API_KEY=sk-ant-...[/]")
            return []

    import agent
    agent.MAX_ITERATIONS = max_iterations
    if model:
        agent.MODEL = model

    task = task or (
        "Perform a comprehensive penetration test on the target application. "
        "Scan for ALL vulnerability types: SQL injection, XSS, command injection, "
        "path traversal, CSRF, IDOR, open redirect, SSRF, missing security headers, "
        "and sensitive data exposure. "
        "For EACH endpoint: extract forms, identify parameters, test payloads, "
        "then call validate_finding to confirm."
    )

    validated = agent.run_agent(target, task, auth_config=auth_config, llm_backend=llm_backend)
    return [
        {
            "source": "agent",
            "vuln_type": f.get("type", "Unknown"),
            "url": f.get("url", ""),
            "param_name": "",
            "method": "",
            "payload": str(f.get("payload", "")),
            "evidence": str(f.get("evidence", "")),
            "severity": "",
        }
        for f in validated
    ]


def run_browser(target, session, headless=True, max_depth=3, max_pages=100):
    """Run Playwright browser-based tests."""
    console.print(f"\n[bold magenta]{'='*60}[/]")
    console.print("[bold magenta]BROWSER TESTING[/]")
    console.print(f"[bold magenta]{'='*60}[/]")

    try:
        from browser import BrowserTester, check_playwright_installed
    except ImportError:
        console.print("[yellow]Playwright not installed. Skipping browser tests.[/]")
        console.print("[dim]Install: pip install playwright && playwright install chromium[/]")
        return []

    if not check_playwright_installed():
        console.print("[yellow]Playwright chromium not available. Skipping.[/]")
        console.print("[dim]Install: playwright install chromium[/]")
        return []

    from crawler import crawl_target
    console.print("  Crawling for attack surface...")
    crawl_result = crawl_target(
        base_url=target, cookies=session.cookies,
        max_depth=max_depth, max_pages=max_pages,
    )
    attack_surface = crawl_result.get("attack_surface", [])
    console.print(f"  Testing {len(attack_surface)} endpoints with browser...")

    tester = BrowserTester(headless=headless)
    try:
        tester.start()
        findings = tester.run_all_tests(
            url=target, attack_surface=attack_surface, cookies=session.cookies,
        )

        spa_data = tester.get_spa_data()
        if spa_data.get("total_routes", 0) > 0 or spa_data.get("total_api_calls", 0) > 0:
            console.print(
                f"  [dim]SPA discovery: {spa_data.get('total_routes', 0)} routes, "
                f"{spa_data.get('total_api_calls', 0)} API calls[/]"
            )

        return findings_to_dicts(findings, "browser")
    except Exception as e:
        console.print(f"[red]Browser test error: {e}[/]")
        return []
    finally:
        tester.stop()


def run_api(target, session, bearer_token=None):
    """Run API security tests."""
    console.print(f"\n[bold cyan]{'='*60}[/]")
    console.print("[bold cyan]API SECURITY SCAN[/]")
    console.print(f"[bold cyan]{'='*60}[/]")

    from api_scanner import APIScanner
    scanner = APIScanner(
        base_url=target, cookies=session.cookies, bearer_token=bearer_token,
    )

    console.print("  Discovering API endpoints...")
    endpoints = scanner.discover_endpoints()
    console.print(f"  Found {len(endpoints)} API endpoints")

    if not endpoints:
        console.print("[dim]  No API endpoints found. Skipping API tests.[/]")
        return []

    for ep in endpoints[:10]:
        console.print(f"    {ep.method} {ep.url} {('[AUTH]' if ep.auth_required else '')}")
    if len(endpoints) > 10:
        console.print(f"    ... and {len(endpoints) - 10} more")

    console.print("  Running API security tests...")
    findings = scanner.run_all_tests(endpoints)
    return findings_to_dicts(findings, "api")


def run_multi_agent(target, auth_config=None, llm_backend="ollama"):
    """Run parallel multi-agent scan using Anthropic API (10 specialist agents simultaneously)."""
    import asyncio
    import os

    console.print(f"\n[bold green]{'='*60}[/]")
    mode = "PARALLEL" if llm_backend == "anthropic" else "SEQUENTIAL"
    console.print(f"[bold green]MULTI-AGENT {mode} SCAN ({llm_backend.upper()})[/]")
    console.print(f"[bold green]10 specialist agents — {mode.lower()}[/]")
    console.print(f"[bold green]{'='*60}[/]")

    if llm_backend == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY"):
        console.print("[bold red]ANTHROPIC_API_KEY not set. Skipping multi-agent scan.[/]")
        console.print("[dim]Set it with: export ANTHROPIC_API_KEY=sk-ant-...[/]")
        return []

    if llm_backend == "ollama":
        try:
            import httpx
            httpx.get("http://localhost:11434/api/tags", timeout=5)
        except Exception:
            console.print("[bold red]Ollama not running. Start it with: ollama serve[/]")
            return []

    from agents.orchestrator import run_multi_agent_scan
    from agents.chain import ChainAnalyzer

    auth_status = (
        "You are authenticated. Session cookies are auto-attached to all requests."
        if auth_config else
        "Not authenticated. If the target requires login, use the authenticate tool first."
    )

    # Authenticate upfront if config provided
    if auth_config:
        from tools import authenticate
        console.print(f"  [cyan]Authenticating ({auth_config.get('auth_type', 'form')})...[/]")
        result = authenticate(**auth_config)
        if result.get("success"):
            console.print(f"  [green]Auth OK[/] — {result['message']}")
        else:
            console.print(f"  [yellow]Auth failed — scanning unauthenticated[/]")

    findings = asyncio.run(run_multi_agent_scan(target, auth_status, llm_backend=llm_backend))

    # CVE + ExploitDB enrichment
    if findings:
        console.print("\n[bold]CVE & Exploit Enrichment (NVD + ExploitDB)...[/]")
        try:
            from enrichment import enrich_findings as _enrich
            findings = _enrich(findings, verbose=True)
            enriched_with_cve = sum(1 for f in findings if f.get("cve_refs"))
            console.print(f"  [green]Enriched {enriched_with_cve}/{len(findings)} findings with CVE data[/]")
        except Exception as e:
            console.print(f"  [yellow]Enrichment skipped: {e}[/]")

    # Exploit chain analysis (Anthropic only — needs reasoning model)
    if findings and llm_backend == "anthropic":
        console.print("\n[bold]Analyzing exploit chains...[/]")
        chains = ChainAnalyzer().analyze(findings)
        if chains:
            console.print(f"  [bold red]{len(chains)} exploit chain(s) identified:[/]")
            for c in chains:
                console.print(f"    [red]▶[/] [{c.get('severity','?')}] {c.get('name','?')}")
                console.print(f"      {c.get('impact','')}")

    return [
        {
            "source": "multi-agent",
            "vuln_type": f.get("type", "Unknown"),
            "url": f.get("url", ""),
            "param_name": f.get("param_name", ""),
            "method": f.get("method", "GET"),
            "payload": str(f.get("payload", "")),
            "evidence": str(f.get("evidence", "")),
            "severity": f.get("severity", "Medium"),
        }
        for f in findings
    ]


def run_exploit_chains(target, findings, session):
    """Run exploit chain engine — proof-of-exploit and vulnerability chaining."""
    console.print(f"\n[bold red]{'='*60}[/]")
    console.print("[bold red]EXPLOIT CHAIN ENGINE[/]")
    console.print(f"[bold red]{'='*60}[/]")

    try:
        from exploit_chain import run_exploit_chains as _run_chains
    except ImportError as e:
        console.print(f"[yellow]Exploit chain engine not available: {e}[/]")
        return None

    try:
        result = _run_chains(
            findings=findings, cookies=session.cookies, base_url=target,
        )
        console.print(f"  Exploited: {result.successful_exploits}/{result.total_findings} vulnerabilities")
        console.print(f"  Chains found: {len(result.chains)}")

        if result.chains:
            console.print("\n  [bold]Attack Chains:[/]")
            for i, chain in enumerate(result.chains[:5], 1):
                name = getattr(chain, 'name', None) or getattr(chain, 'description', f'Chain {i}')
                impact = getattr(chain, 'impact_score', '?')
                console.print(f"    {i}. {name} (impact: {impact})")

        if result.attack_narrative:
            narrative = result.attack_narrative[:500]
            console.print(f"\n  [bold]Narrative:[/]")
            for line in narrative.split('\n'):
                console.print(f"    {line}")
            if len(result.attack_narrative) > 500:
                console.print("    ...")

        return result
    except Exception as e:
        console.print(f"[red]Exploit chain error: {e}[/]")
        return None


def run_adaptive(target, findings, session):
    """Re-test findings with adaptive payload engine for WAF bypass."""
    console.print(f"\n[bold yellow]{'='*60}[/]")
    console.print("[bold yellow]ADAPTIVE PAYLOAD ENGINE[/]")
    console.print(f"[bold yellow]{'='*60}[/]")

    try:
        from payload_engine import PayloadEngine, VulnType
    except ImportError as e:
        console.print(f"[yellow]Payload engine not available: {e}[/]")
        return []

    VULN_MAP = {
        "sqli": VulnType.SQLI, "sql_injection": VulnType.SQLI,
        "xss": VulnType.XSS, "xss_reflected": VulnType.XSS, "xss_stored": VulnType.XSS,
        "command_injection": VulnType.CMDI, "cmdi": VulnType.CMDI,
        "path_traversal": VulnType.PATH_TRAVERSAL, "lfi": VulnType.PATH_TRAVERSAL,
    }

    test_targets = []
    seen = set()
    for f in findings:
        vtype = VULN_MAP.get(f.get("vuln_type", "").lower())
        if not vtype:
            continue
        param = f.get("param_name", "")
        url = f.get("url", "")
        if not param or not url:
            continue
        key = (url, param, vtype)
        if key not in seen:
            seen.add(key)
            test_targets.append({
                "url": url, "param": param, "vuln_type": vtype,
                "method": f.get("method", "GET"),
            })

    if not test_targets:
        console.print("  [dim]No applicable findings for adaptive testing.[/]")
        return []

    console.print(f"  Testing {len(test_targets)} parameter/vuln combos with WAF bypass...")
    engine = PayloadEngine()

    async def _run():
        results = []
        for t in test_targets:
            try:
                result = await engine.test_and_adapt(
                    url=t["url"], param=t["param"], vuln_type=t["vuln_type"],
                    cookies=session.cookies, method=t["method"],
                )
                if result.working_payload:
                    payload_str = result.working_payload.raw
                    technique = result.technique_used.value if result.technique_used else "unknown"
                    evidence = ""
                    for r in result.all_results:
                        if r.success and r.evidence:
                            evidence = r.evidence
                            break
                    results.append({
                        "source": "adaptive",
                        "vuln_type": f"{t['vuln_type'].value}_waf_bypass",
                        "url": t["url"],
                        "param_name": t["param"],
                        "method": t["method"],
                        "payload": payload_str,
                        "evidence": evidence,
                        "severity": "high",
                    })
                    console.print(
                        f"    [green]BYPASS[/] {t['param']} @ {t['url'][:60]} "
                        f"— technique: {technique}"
                    )
            except Exception as e:
                console.print(f"    [dim]Error testing {t['param']}: {e}[/]")
        return results

    try:
        new_findings = asyncio.run(_run())
    except Exception as e:
        console.print(f"[red]Adaptive engine error: {e}[/]")
        new_findings = []

    console.print(f"  Found {len(new_findings)} additional WAF bypass payloads")
    return new_findings


def generate_reports(target, findings, chain_result, elapsed, report_dir):
    """Generate professional HTML and JSON reports."""
    console.print(f"\n[bold white]{'='*60}[/]")
    console.print("[bold white]REPORT GENERATION[/]")
    console.print(f"[bold white]{'='*60}[/]")

    try:
        from report_engine import ReportEngine
    except ImportError as e:
        console.print(f"[yellow]Report engine not available: {e}[/]")
        return

    os.makedirs(report_dir, exist_ok=True)

    exploit_chains = []
    if chain_result and chain_result.chains:
        for chain in chain_result.chains:
            exploit_chains.append({
                "name": getattr(chain, 'name', 'Unknown'),
                "description": getattr(chain, 'description', ''),
                "impact_score": getattr(chain, 'impact_score', 0),
                "steps": getattr(chain, 'steps', []),
            })

    tools_used = []
    sources = {f.get("source") for f in findings}
    if "systematic" in sources: tools_used.append("systematic-scanner")
    if "agent" in sources: tools_used.append("llm-agent")
    if "browser" in sources: tools_used.append("browser-tester")
    if "api" in sources: tools_used.append("api-scanner")
    if "adaptive" in sources: tools_used.append("adaptive-payload-engine")
    if chain_result: tools_used.append("exploit-chain-engine")

    try:
        engine = ReportEngine(
            target=target,
            scan_time=time.strftime("%Y-%m-%d %H:%M:%S"),
            findings=findings,
            exploit_chains=exploit_chains if exploit_chains else None,
            scan_duration=elapsed,
            tools_used=tools_used,
        )
        result = engine.generate_all(report_dir)
        for report_type, path in result.items():
            console.print(f"  {report_type}: {path}")
    except Exception as e:
        console.print(f"[red]Report generation error: {e}[/]")


# ── Output formatting ────────────────────────────────────────────────────

def print_findings_detailed(findings):
    """Print every finding in the full 10-field format."""
    try:
        from report_engine import (
            _classify_finding, _get_remediation_key, _finding_id, REMEDIATION,
        )
        has_report_engine = True
    except ImportError:
        has_report_engine = False

    if not findings:
        return

    severity_colors = {
        "Critical": "bold red", "High": "red", "Medium": "yellow",
        "Low": "green", "Informational": "dim",
    }

    console.print(f"\n[bold]{'='*70}[/]")
    console.print(f"[bold]  DETAILED FINDINGS ({len(findings)} total)[/]")
    console.print(f"[bold]{'='*70}[/]\n")

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "Medium") or "Medium"
        color = severity_colors.get(sev, "white")
        vtype = f.get("vuln_type", "Unknown")

        if has_report_engine:
            fid = _finding_id(f)
            cls = _classify_finding(vtype)
            rk = _get_remediation_key(vtype)
            cwe = f"{cls['cwe']} — {cls['cwe_name']}"
            owasp = f"{cls['owasp']} — {cls['owasp_name']}"
            remediation = REMEDIATION[rk]["description"] if rk and rk in REMEDIATION else "Review and remediate."
        else:
            fid = f"{i:04d}"
            cwe = owasp = remediation = "N/A"

        console.print(f"  [{color}]FINDING #{i} [{sev.upper()}] — {fid}[/{color}]")
        console.print(f"  {'─'*66}")
        console.print(f"  [bold]Vulnerability:[/]  {vtype}")
        console.print(f"  [bold]Severity:[/]       [{color}]{sev}[/{color}]")
        console.print(f"  [bold]URL:[/]            {f.get('url', '')}")
        console.print(f"  [bold]Method:[/]         {f.get('method', '') or 'GET'}")
        console.print(f"  [bold]Parameter:[/]      {f.get('param_name', '') or 'N/A'}")
        console.print(f"  [bold]Payload:[/]        {f.get('payload', '') or 'N/A'}")
        console.print(f"  [bold]Evidence:[/]       {f.get('evidence', '') or 'N/A'}")
        console.print(f"  [bold]CWE:[/]            {cwe}")
        console.print(f"  [bold]OWASP:[/]          {owasp}")
        console.print(f"  [bold]Source:[/]         {f.get('source', 'unknown')}")
        console.print(f"  [bold]Remediation:[/]    {remediation[:120]}{'...' if len(remediation) > 120 else ''}")
        console.print()


def enrich_findings(findings):
    """Enrich findings with classification, remediation, impact for JSON output."""
    try:
        from report_engine import (
            _classify_finding, _get_remediation_key, _finding_id, REMEDIATION,
        )
    except ImportError:
        return findings

    enriched = []
    for f in findings:
        cls = _classify_finding(f.get("vuln_type", ""))
        rk = _get_remediation_key(f.get("vuln_type", ""))
        enriched.append({
            "id": _finding_id(f),
            "vuln_type": f.get("vuln_type", "Unknown"),
            "severity": f.get("severity", "Medium"),
            "url": f.get("url", ""),
            "method": f.get("method", ""),
            "parameter": f.get("param_name", ""),
            "payload": f.get("payload", ""),
            "evidence": f.get("evidence", ""),
            "source": f.get("source", ""),
            "classification": {
                "cwe_id": cls["cwe"],
                "cwe_name": cls["cwe_name"],
                "owasp_id": cls["owasp"],
                "owasp_name": cls["owasp_name"],
                "category": cls["category"],
            },
            "remediation": (
                REMEDIATION[rk]["description"] if rk and rk in REMEDIATION else "Review and fix this vulnerability."
            ),
        })
    return enriched
