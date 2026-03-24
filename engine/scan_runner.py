"""Unified scan runner — ties discovery, agents, validation, chains, and reports together."""

import time
from datetime import datetime

from rich.console import Console

from engine.config import ScanConfig
from engine.scan_state import ScanState, Endpoint
from engine.decision_engine import DecisionEngine
from engine.agent_registry import register_all_agents

_console = Console()


def run_scan(
    target,
    username="",
    password="",
    client_id="",
    bearer_token="",
    cookies=None,
    llm_backend="ollama",
    aggressive=False,
) -> dict:
    """
    Execute a full penetration test scan against target.

    Args:
        target: URL of the target application
        username: Optional login username for authenticated scans
        password: Optional login password for authenticated scans
        client_id: Optional client_id for OAuth flows
        bearer_token: Optional Bearer token for authenticated requests
        cookies: Optional dict of cookies to include in requests
        llm_backend: LLM backend to use ("ollama" or "anthropic")
        aggressive: Enable aggressive scanning mode

    Returns:
        dict with keys: findings, chains, state, elapsed, report_paths
    """
    scan_start = time.time()
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    _console.print(f"\n[bold cyan]Pentest Agent — scan started at {scan_time}[/bold cyan]")
    _console.print(f"  Target: {target}")
    _console.print(f"  LLM backend: {llm_backend} | Aggressive: {aggressive}")

    # -----------------------------------------------------------------------
    # 1. Create ScanConfig
    # -----------------------------------------------------------------------
    config = ScanConfig(
        llm_backend=llm_backend,
        aggressive_mode=aggressive,
        bearer_token=bearer_token,
        cookies=cookies or {},
    )

    # -----------------------------------------------------------------------
    # 2. Create ScanState
    # -----------------------------------------------------------------------
    state = ScanState()

    # -----------------------------------------------------------------------
    # 3. Create DecisionEngine
    # -----------------------------------------------------------------------
    engine = DecisionEngine(config, state)

    # -----------------------------------------------------------------------
    # 4. Start CallbackServer (non-fatal)
    # -----------------------------------------------------------------------
    callback_server = None
    try:
        from exploit.callback_server import CallbackServer
        callback_server = CallbackServer()
        callback_server.start()
        _console.print("  [dim]OOB callback server started[/dim]")
    except Exception as exc:
        _console.print(f"  [yellow]CallbackServer unavailable: {exc}[/yellow]")

    # -----------------------------------------------------------------------
    # 5. Register discovery functions
    # -----------------------------------------------------------------------

    # 5a. Playwright crawler
    try:
        from discovery.playwright_crawler import discover_with_playwright

        def _playwright_discovery(t, cfg, st):
            discover_with_playwright(t, cfg, st, username=username, password=password, client_id=client_id)

        engine.register_discovery(_playwright_discovery)
        _console.print("  [dim]Registered: Playwright crawler[/dim]")
    except Exception as exc:
        _console.print(f"  [yellow]Playwright crawler unavailable: {exc}[/yellow]")

    # 5b. Passive recon
    try:
        from discovery.passive_recon import run_passive_recon
        engine.register_discovery(run_passive_recon)
        _console.print("  [dim]Registered: Passive recon[/dim]")
    except Exception as exc:
        _console.print(f"  [yellow]Passive recon unavailable: {exc}[/yellow]")

    # 5c. JS analyzer
    try:
        from js_analyzer import JSAnalyzer

        def _js_discovery(t, cfg, st):
            analyzer = JSAnalyzer(t)
            result = analyzer.run()

            # Add discovered endpoints to state
            for ep_data in result.get("endpoints", []):
                path = ep_data.get("path", "")
                if not path:
                    continue
                # Build absolute URL if path is relative
                if path.startswith("http"):
                    url = path
                else:
                    url = t.rstrip("/") + "/" + path.lstrip("/")
                method = ep_data.get("method", "GET")
                endpoint = Endpoint(url=url, method=method)
                st.add_endpoint(endpoint)

            # Store secrets on state
            secrets = result.get("secrets", [])
            if secrets:
                with st._lock:
                    st.js_secrets.extend(secrets)

            _console.print(
                f"  [dim]JS analysis: {len(result.get('endpoints', []))} endpoints, "
                f"{len(secrets)} secrets[/dim]"
            )

        engine.register_discovery(_js_discovery)
        _console.print("  [dim]Registered: JS analyzer[/dim]")
    except Exception as exc:
        _console.print(f"  [yellow]JS analyzer unavailable: {exc}[/yellow]")

    # -----------------------------------------------------------------------
    # 6. Register all agents
    # -----------------------------------------------------------------------
    try:
        registrations = register_all_agents(engine, config)
        successful = sum(1 for _, _, ok in registrations if ok)
        _console.print(f"  [dim]Registered {successful}/{len(registrations)} vulnerability agents[/dim]")
    except Exception as exc:
        _console.print(f"  [yellow]Agent registration error: {exc}[/yellow]")

    # -----------------------------------------------------------------------
    # 7. Register validator (if LLM available)
    # -----------------------------------------------------------------------
    if config.llm_available:
        try:
            from agents.validator import ValidatorAgent

            validator = ValidatorAgent(llm_backend=llm_backend)

            def _validate(findings, cfg):
                return validator.validate_batch(findings)

            engine.register_validator(_validate)
            _console.print("  [dim]Registered: ValidatorAgent[/dim]")
        except Exception as exc:
            _console.print(f"  [yellow]Validator unavailable: {exc}[/yellow]")
    else:
        _console.print("  [dim]Validator skipped (LLM not available)[/dim]")

    # -----------------------------------------------------------------------
    # 8. Run the OODA scan loop
    # -----------------------------------------------------------------------
    engine.run(target)

    # -----------------------------------------------------------------------
    # 9. Stop callback server
    # -----------------------------------------------------------------------
    if callback_server is not None:
        try:
            callback_server.stop()
            _console.print("  [dim]OOB callback server stopped[/dim]")
        except Exception as exc:
            _console.print(f"  [yellow]CallbackServer stop error: {exc}[/yellow]")

    # -----------------------------------------------------------------------
    # 10. Post-processing
    # -----------------------------------------------------------------------

    # 10a. Chain detection
    try:
        from chain.graph_builder import detect_chains
        chains = detect_chains(state.findings)
        state.chains = chains
        _console.print(f"  Chain detection: {len(chains)} chain(s) found")
    except Exception as exc:
        _console.print(f"  [yellow]Chain detection error: {exc}[/yellow]")
        chains = state.chains

    # 10b. CVE enrichment
    try:
        from enrichment import enrich_findings
        state.findings = enrich_findings(state.findings)
        _console.print(f"  [dim]CVE enrichment complete[/dim]")
    except Exception as exc:
        _console.print(f"  [yellow]CVE enrichment error: {exc}[/yellow]")

    # 10c. Confidence scoring
    try:
        from confidence_scorer import enrich_with_scores
        state.findings = enrich_with_scores(state.findings)
        _console.print(f"  [dim]Confidence scoring complete[/dim]")
    except Exception as exc:
        _console.print(f"  [yellow]Confidence scoring error: {exc}[/yellow]")

    # 10d. Deduplication & Aggregation
    try:
        from engine.deduplicator import deduplicate_findings, get_dedup_stats
        original_count = len(state.findings)
        state.findings = deduplicate_findings(state.findings)
        stats = get_dedup_stats(
            [None] * original_count,  # placeholder for count
            state.findings,
        )
        _console.print(
            f"  [bold]Deduplication: {original_count} → {len(state.findings)} findings "
            f"({stats['reduction_pct']}% noise reduction)[/]"
        )
    except Exception as exc:
        _console.print(f"  [yellow]Deduplication error: {exc}[/yellow]")

    # -----------------------------------------------------------------------
    # 11. Generate reports
    # -----------------------------------------------------------------------
    report_paths = {}
    elapsed = time.time() - scan_start
    try:
        from report_engine import ReportEngine
        report_engine = ReportEngine(
            target=target,
            scan_time=scan_time,
            findings=state.findings,
            exploit_chains=state.chains,
            scan_duration=elapsed,
        )
        report_paths = report_engine.generate_all("reports")
        _console.print(f"  [bold green]Reports generated:[/bold green] {report_paths}")
    except Exception as exc:
        _console.print(f"  [yellow]Report generation error: {exc}[/yellow]")

    # -----------------------------------------------------------------------
    # 12. Return results
    # -----------------------------------------------------------------------
    _console.print(
        f"\n[bold green]Scan finished[/bold green] — "
        f"{len(state.findings)} finding(s), "
        f"{len(state.chains)} chain(s), "
        f"elapsed={elapsed:.1f}s"
    )

    return {
        "findings": state.findings,
        "chains": state.chains,
        "state": state,
        "elapsed": elapsed,
        "report_paths": report_paths,
    }
