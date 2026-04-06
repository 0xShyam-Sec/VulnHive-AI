#!/usr/bin/env python3
"""
Pentest Agent v5 — CLI mode.

Usage:
    python main.py --target http://localhost:8080 --auth-type form \
        --login-url http://localhost:8080/login.php \
        --username admin --password password \
        --exploit-chains --report-dir ./reports

    python main.py --target http://localhost:8080 --mode agent
    python main.py --target http://localhost:8080 --mode full --adaptive --report-dir ./reports
"""

import argparse
import json
import sys
import time
from rich.console import Console
from rich.panel import Panel

from pipeline import (
    run_systematic, run_agent, run_browser, run_api, run_multi_agent,
    run_exploit_chains, run_adaptive, generate_reports,
    print_findings_detailed, enrich_findings,
)

console = Console()


def main():
    parser = argparse.ArgumentParser(
        description="AI-powered penetration testing agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Target
    parser.add_argument("--target", required=True, help="Base URL of the target")
    parser.add_argument("--task", default=None, help="Specific task (default: full scan)")
    parser.add_argument("--max-iterations", type=int, default=25, help="Max agent iterations")
    parser.add_argument("--model", default=None, help="Ollama model (default: qwen2.5:14b)")
    parser.add_argument("--llm", choices=["ollama", "anthropic"], default="ollama",
                        help="LLM backend for agent mode: ollama (default, free/local) or anthropic (Claude API)")

    # Scan mode
    parser.add_argument("--mode", choices=["systematic", "agent", "browser", "api", "full", "multi-agent"],
                        default="multi-agent",
                        help="Scan mode: multi-agent (default), systematic, agent, browser, api, full")

    # Crawler settings
    parser.add_argument("--max-depth", type=int, default=3, help="Crawler depth (default: 3)")
    parser.add_argument("--max-pages", type=int, default=100, help="Max pages to crawl (default: 100)")

    # Authentication
    parser.add_argument("--auth-type", choices=["form", "cookie", "basic", "bearer", "none"],
                        default="none", help="Authentication method (default: none)")
    parser.add_argument("--login-url", default=None, help="Login page URL (for form auth)")
    parser.add_argument("--username", default=None, help="Username")
    parser.add_argument("--password", default=None, help="Password")
    parser.add_argument("--username-field", default="username", help="Form field for username")
    parser.add_argument("--password-field", default="password", help="Form field for password")
    parser.add_argument("--cookies", default=None, help="JSON cookies string (for cookie auth)")
    parser.add_argument("--bearer-token", default=None, help="Bearer token (for bearer auth)")
    parser.add_argument("--success-indicator", default=None, help="String confirming login success")

    # Output
    parser.add_argument("--output", default=None, help="Save findings to JSON file")
    parser.add_argument("--report-dir", default=None, help="Generate HTML/JSON reports in this directory")
    parser.add_argument("--no-headless", action="store_true", help="Show browser window during testing")

    # Subdomain enumeration
    parser.add_argument("--wordlist", default=None,
                        help="Custom subdomain wordlist file (SecLists compatible, one word per line)")
    parser.add_argument("--rate-limit", type=float, default=0,
                        help="Max requests/sec for subdomain enum (0=unlimited, default: 0)")
    parser.add_argument("--scan-all", action="store_true",
                        help="Deep-scan ALL alive subdomain hosts in parallel (default: first only)")

    # Engines
    parser.add_argument("--exploit-chains", action="store_true", help="Run exploit chain engine")
    parser.add_argument("--adaptive", action="store_true", help="Use adaptive payload engine (WAF bypass)")

    args = parser.parse_args()

    # ── Build auth config ─────────────────────────────────────────
    auth_config = _build_auth_config(args)

    # ── Display config ────────────────────────────────────────────
    extras = []
    if args.exploit_chains: extras.append("exploit-chains")
    if args.adaptive: extras.append("adaptive-payloads")
    if args.wordlist: extras.append(f"wordlist: {args.wordlist}")
    if args.rate_limit > 0: extras.append(f"rate-limit: {args.rate_limit}/sec")
    if args.scan_all: extras.append("scan-all-subs")
    if args.report_dir: extras.append(f"reports → {args.report_dir}")

    console.print(Panel(
        f"[bold]Target:[/] {args.target}\n"
        f"[bold]Mode:[/] {args.mode}\n"
        f"[bold]Auth:[/] {args.auth_type}\n"
        f"[bold]Depth:[/] {args.max_depth} | Max pages: {args.max_pages}\n"
        f"[bold]Engines:[/] {' | '.join(extras) or 'none'}",
        title="[bold blue]Pentest Agent v5",
        border_style="blue",
    ))

    # ── Authenticate ──────────────────────────────────────────────
    session = _build_session(args, auth_config)

    # ── Run scan pipeline ─────────────────────────────────────────
    all_findings = []
    start_time = time.time()

    if args.mode in ("systematic", "full"):
        all_findings.extend(run_systematic(args.target, session, args.max_depth, args.max_pages))

    if args.mode in ("agent", "full"):
        all_findings.extend(run_agent(args.target, auth_config, args.max_iterations, args.model, args.task, args.llm))

    if args.mode == "multi-agent":
        all_findings.extend(run_multi_agent(args.target, auth_config, llm_backend=args.llm))

    if args.mode in ("browser", "full"):
        all_findings.extend(run_browser(args.target, session, not args.no_headless, args.max_depth, args.max_pages))

    if args.mode in ("api", "full"):
        all_findings.extend(run_api(args.target, session, args.bearer_token))

    if args.adaptive and all_findings:
        all_findings.extend(run_adaptive(args.target, all_findings, session))

    chain_result = None
    if args.exploit_chains and all_findings:
        chain_result = run_exploit_chains(args.target, all_findings, session)

    elapsed = time.time() - start_time

    # ── Output ────────────────────────────────────────────────────
    print_findings_detailed(all_findings)

    console.print()
    console.rule("[bold]Scan Complete")
    console.print(f"  Time: {elapsed:.1f}s")
    console.print(f"  Total findings: {len(all_findings)}")
    if chain_result:
        console.print(f"  Exploit chains: {len(chain_result.chains)}")
        console.print(f"  Successful exploits: {chain_result.successful_exploits}/{chain_result.total_findings}")
    if session.reauth_count > 0:
        console.print(f"  Session re-authentications: {session.reauth_count}")

    if args.output and all_findings:
        enriched = enrich_findings(all_findings)
        with open(args.output, "w") as f:
            json.dump({"scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "total_findings": len(enriched), "findings": enriched}, f, indent=2)
        console.print(f"  Saved to: {args.output}")

    if args.report_dir and all_findings:
        generate_reports(args.target, all_findings, chain_result, elapsed, args.report_dir)

    console.print()


def _build_auth_config(args):
    """Build auth config dict from CLI args."""
    if args.auth_type == "none":
        return None
    config = {"auth_type": args.auth_type}
    if args.login_url: config["login_url"] = args.login_url
    if args.username: config["username"] = args.username
    if args.password: config["password"] = args.password
    if args.username_field != "username": config["username_field"] = args.username_field
    if args.password_field != "password": config["password_field"] = args.password_field
    if args.cookies:
        try:
            config["cookies"] = json.loads(args.cookies)
        except json.JSONDecodeError:
            console.print("[bold red]Error:[/] --cookies must be valid JSON")
            sys.exit(1)
    if args.bearer_token: config["bearer_token"] = args.bearer_token
    if args.success_indicator: config["success_indicator"] = args.success_indicator
    return config


def _build_session(args, auth_config):
    """Authenticate and build SessionManager."""
    from session_manager import SessionManager
    session_cookies = {}
    session_headers = {}

    if auth_config:
        from tools import authenticate as tools_authenticate, _get_headers
        console.print(f"\n[bold cyan]Authenticating ({auth_config['auth_type']})...[/]")
        result = tools_authenticate(**auth_config)
        if result.get("success"):
            console.print(f"[bold green]OK[/] {result['message']}")
            session_cookies = result.get("cookies", {})
            session_headers = _get_headers()
        else:
            console.print(f"[bold red]FAILED:[/] {result.get('message', result.get('error', 'Unknown'))}")
            console.print("[yellow]Continuing without authentication...[/]")

    def reauth_func():
        if auth_config:
            from tools import authenticate as ta
            return ta(**auth_config)
        return {"success": False}

    return SessionManager(
        base_url=args.target,
        auth_func=reauth_func if auth_config else None,
        login_url=auth_config.get("login_url") if auth_config else None,
        cookies=session_cookies,
        headers=session_headers,
    )


if __name__ == "__main__":
    main()
