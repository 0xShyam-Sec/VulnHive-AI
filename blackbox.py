#!/usr/bin/env python3
"""
Black-Box Pentest — Give a URL, get a full report.

Usage:
    python blackbox.py                               # interactive
    python blackbox.py --url http://target.com       # direct URL
    python blackbox.py --url http://target.com --auto  # fully automated
"""

import argparse
import json
import os
import sys
import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm

from pipeline import (
    run_multi_agent, run_systematic, run_exploit_chains,
    generate_reports, print_findings_detailed, enrich_findings,
)

console = Console()

BANNER = r"""
 ____  _            _    ____
| __ )| | __ _  ___| | _| __ )  _____  __
|  _ \| |/ _` |/ __| |/ /  _ \ / _ \ \/ /
| |_) | | (_| | (__|   <| |_) | (_) >  <
|____/|_|\__,_|\___|_|\_\____/ \___/_/\_\
    VulnHive AI — Black-Box Multi-Agent Mode
"""


def main():
    parser = argparse.ArgumentParser(description="Black-box penetration testing")
    parser.add_argument("--url", default=None, help="Target URL")
    parser.add_argument("--auto", action="store_true", help="Fully automated — skip all prompts")
    parser.add_argument("--output-dir", default="./reports", help="Report output directory")
    parser.add_argument("--llm", choices=["ollama", "anthropic"], default="ollama",
                        help="LLM backend: ollama (default, free/local) or anthropic (Claude API)")
    parser.add_argument("--with-systematic", action="store_true",
                        help="Also run systematic scanner alongside multi-agent")
    args = parser.parse_args()

    console.print(BANNER, style="bold red")

    # ── Step 1: Target URL ───────────────────────────────────────
    target = args.url
    if not target:
        target = Prompt.ask("[bold cyan]Enter target URL[/]")
    if not target.startswith("http"):
        target = "http://" + target
    target = target.rstrip("/")

    console.print(f"\n[bold]Target:[/] {target}\n")

    # ── Step 2: Auto-discovery ───────────────────────────────────
    console.print(Panel("[bold]Phase 1: Auto-Discovery[/]", border_style="blue"))
    from autodiscover import AutoDiscovery
    discovery = AutoDiscovery(target)
    results = discovery.run_all()
    discovery.close()

    if not results["reachable"]:
        console.print(f"[bold red]Target not reachable: {results.get('error', 'Unknown')}[/]")
        sys.exit(1)

    _display_discovery(results)

    # ── Step 3: Authentication ───────────────────────────────────
    auth_config = None

    if results["login_pages"]:
        login = results["login_form"]
        _display_login_info(login)

        do_auth = True if args.auto else Confirm.ask("Authenticate?", default=True)

        if do_auth:
            if args.auto:
                console.print("[yellow]--auto mode: no credentials provided. Skipping auth.[/]")
                console.print("[dim]Pass credentials via --url with auth flags or use interactive mode.[/]")
            else:
                username = Prompt.ask("Username")
                password = Prompt.ask("Password", password=True)
                auth_config = {
                    "auth_type": "form",
                    "login_url": login["url"],
                    "username": username,
                    "password": password,
                    "username_field": login["username_field"],
                    "password_field": login["password_field"],
                }
                from tools import authenticate as tools_authenticate
                console.print("\n[bold cyan]Authenticating...[/]")
                result = tools_authenticate(**auth_config)
                if result.get("success"):
                    console.print(f"[bold green]Auth OK[/] — {result['message']}")
                else:
                    console.print(f"[bold red]Auth failed:[/] {result.get('message', 'Unknown')}")
                    if not Confirm.ask("Continue without auth?", default=True):
                        sys.exit(1)
                    auth_config = None
    else:
        console.print("[dim]No login page detected — scanning unauthenticated.[/]\n")

    # ── Step 4: Scan ─────────────────────────────────────────────
    console.print(Panel("[bold]Phase 2: Multi-Agent Parallel Scan[/]", border_style="red"))
    all_findings = []
    start_time = time.time()

    # Multi-agent is always the primary scan
    all_findings.extend(run_multi_agent(target, auth_config, llm_backend=args.llm))

    # Optional: also run systematic scanner for maximum coverage
    if args.with_systematic:
        from session_manager import SessionManager
        from tools import _get_headers

        session_cookies = {}
        session_headers = {}
        if auth_config:
            from tools import get_session_cookies
            session_cookies = get_session_cookies()
            session_headers = _get_headers()

        def reauth():
            if auth_config:
                from tools import authenticate as ta
                return ta(**auth_config)
            return {"success": False}

        session = SessionManager(
            base_url=target,
            auth_func=reauth if auth_config else None,
            login_url=auth_config.get("login_url") if auth_config else None,
            cookies=session_cookies,
            headers=session_headers,
        )
        all_findings.extend(run_systematic(target, session))

    elapsed = time.time() - start_time

    # ── Step 5: Output ───────────────────────────────────────────
    print_findings_detailed(all_findings)

    console.print()
    console.rule("[bold]Scan Complete")
    console.print(f"  Time: {elapsed:.1f}s | Findings: {len(all_findings)}")

    # ── Step 6: Reports ──────────────────────────────────────────
    if all_findings:
        generate_reports(target, all_findings, None, elapsed, args.output_dir)

    os.makedirs(args.output_dir, exist_ok=True)
    enriched = enrich_findings(all_findings)
    findings_path = os.path.join(args.output_dir, "findings.json")
    with open(findings_path, "w") as f:
        json.dump({
            "target": target,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": elapsed,
            "discovery": {
                "technologies": results["technologies"],
                "waf": results["waf_detected"],
                "login_pages": len(results["login_pages"]),
            },
            "total_findings": len(enriched),
            "findings": enriched,
        }, f, indent=2)
    console.print(f"  Findings JSON: {findings_path}")
    console.print()


# ── Display helpers ───────────────────────────────────────────────────────

def _display_discovery(results):
    console.print()

    if results["technologies"]:
        table = Table(title="Technology Stack", show_header=False, border_style="dim")
        table.add_column("Technology", style="cyan")
        for tech in results["technologies"]:
            table.add_row(tech)
        console.print(table)

    waf = results["waf_detected"]
    console.print(f"  [bold yellow]WAF:[/] {waf}" if waf else "  [dim]WAF: Not detected[/]")

    missing = [k for k, v in results["security_headers"].items() if v == "MISSING"]
    if missing:
        console.print(f"  [yellow]Missing headers:[/] {', '.join(missing)}")

    if results["login_pages"]:
        console.print(f"  [green]Login pages found:[/] {len(results['login_pages'])}")
        for lp in results["login_pages"]:
            console.print(f"    {lp['url']}")

    real_paths = [p for p in results["interesting_paths"] if p.get("status") != "from robots.txt"]
    if real_paths:
        console.print(f"  [cyan]Interesting paths:[/] {len(real_paths)}")
        for p in real_paths[:10]:
            console.print(f"    [{p.get('status', '?')}] {p['path']} ({p.get('size', 0)} bytes)")

    console.print()


def _display_login_info(login):
    console.print(Panel(
        f"[bold]Login URL:[/]       {login['url']}\n"
        f"[bold]Username field:[/]  {login['username_field']}\n"
        f"[bold]Password field:[/]  {login['password_field']}\n"
        f"[bold]CSRF token:[/]      {'Yes' if login['has_csrf'] else 'No'}",
        title="[bold green]Login Page Detected",
        border_style="green",
    ))


if __name__ == "__main__":
    main()
