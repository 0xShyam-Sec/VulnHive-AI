"""
Orchestrator — coordinates recon + vuln agents + chain analysis.

- Anthropic backend: all agents run in parallel
- Ollama backend: all agents run sequentially (RAM constraint)

Phase 1: Recon (HTML crawl + JS bundle analysis + OpenAPI + traffic recording)
Phase 2: 13 specialist vulnerability agents
"""

import asyncio
import json
from rich.console import Console
from rich.table import Table

from agents.recon import ReconAgent
from agents.vuln.sqli import SQLiAgent
from agents.vuln.xss import XSSAgent
from agents.vuln.cmdi import CMDIAgent
from agents.vuln.path_traversal import PathTraversalAgent
from agents.vuln.csrf import CSRFAgent
from agents.vuln.idor import IDORAgent
from agents.vuln.ssrf import SSRFAgent
from agents.vuln.open_redirect import OpenRedirectAgent
from agents.vuln.headers import HeadersAgent
from agents.vuln.sensitive_data import SensitiveDataAgent

console = Console()

VULN_AGENTS = [
    SQLiAgent,
    XSSAgent,
    CMDIAgent,
    PathTraversalAgent,
    CSRFAgent,
    IDORAgent,
    SSRFAgent,
    OpenRedirectAgent,
    HeadersAgent,
    SensitiveDataAgent,
]

# New agents — loaded conditionally so missing files don't break the scan
def _load_extended_agents():
    extra = []
    try:
        from agents.vuln.graphql import GraphQLAgent
        extra.append(GraphQLAgent)
    except ImportError:
        pass
    try:
        from agents.vuln.mass_assignment import MassAssignmentAgent
        extra.append(MassAssignmentAgent)
    except ImportError:
        pass
    try:
        from agents.vuln.idor_advanced import IDORAdvancedAgent
        extra.append(IDORAdvancedAgent)
    except ImportError:
        pass
    return extra


async def run_multi_agent_scan(target: str, auth_status: str,
                                llm_backend: str = "ollama",
                                bearer_token: str = None,
                                cookies: dict = None) -> list:
    """
    Full multi-agent scan:
    - Ollama: sequential (RAM safe)
    - Anthropic: parallel (fast)
    """
    import re

    # ── Phase 1: Enhanced Recon ───────────────────────────────────
    console.print("\n[bold blue]  Phase 1: Reconnaissance[/]")
    recon = ReconAgent()
    attack_surface = await recon.run_recon(target)

    pages = len(attack_surface.get("pages_visited", []))
    endpoints = len(attack_surface.get("attack_surface", []))
    forms = len(attack_surface.get("forms", []))
    console.print(f"  [dim]HTML crawl: {pages} pages | {endpoints} endpoints | {forms} forms[/]")

    test_targets = attack_surface.get("test_targets", [])

    # ── Phase 1b: Deep JS Crawling — find hidden endpoints in .js files ──
    try:
        from js_analyzer import JSCrawler
        cookies = attack_surface.get("cookies", {})
        jscrawler = JSCrawler(target, cookies=cookies)
        js_result = jscrawler.run()
        jscrawler.close()
        js_endpoints = js_result.get("endpoints", [])
        js_secrets = js_result.get("secrets", [])
        console.print(
            f"  [dim]JS deep crawl: {js_result.get('js_files_downloaded', 0)} JS files | "
            f"{len(js_endpoints)} hidden routes | {len(js_secrets)} potential secrets[/]"
        )
        # Add JS-discovered endpoints to test targets
        for ep in js_endpoints:
            full_url = ep.get("full_url") or ep.get("path", "")
            if full_url:
                key_exists = any(t["url"] == full_url for t in test_targets)
                if not key_exists:
                    test_targets.append({"url": full_url, "param": "", "method": ep.get("method", "GET")})
        # Create findings for any secrets found
        attack_surface["js_secrets"] = js_secrets
        attack_surface["js_files_discovered"] = js_result.get("js_files", [])
    except Exception as e:
        console.print(f"  [dim]JS deep crawl skipped: {e}[/]")

    # ── Phase 1c: OpenAPI / Swagger Discovery ────────────────────
    try:
        from openapi_importer import OpenAPIImporter
        oi = OpenAPIImporter(target, bearer_token=bearer_token, cookies=cookies)
        oi_result = oi.run()
        oi.close()
        if oi_result.get("found"):
            oi_targets = oi_result.get("test_targets", [])
            console.print(
                f"  [dim]OpenAPI: {len(oi_result.get('endpoints',[]))} endpoints | "
                f"{len(oi_targets)} test targets[/]"
            )
            for t in oi_targets:
                test_targets.append(t)
    except Exception as e:
        console.print(f"  [dim]OpenAPI probe skipped: {e}[/]")

    # Deduplicate test targets
    seen_keys = set()
    unique_targets = []
    for t in test_targets:
        k = (t["url"], t.get("param", ""), t.get("method", "GET"))
        if k not in seen_keys:
            seen_keys.add(k)
            unique_targets.append(t)
    test_targets = unique_targets

    console.print(f"  [bold dim]Total test targets: {len(test_targets)}[/]")

    if not test_targets:
        console.print("  [yellow]No testable parameters found.[/]")

    # Format surface message for agents
    targets_text = "\n".join(
        f"  - URL: {t['url']} | param: {t.get('param','') or ''} | method: {t.get('method','GET')}"
        for t in test_targets[:80]
    ) or "  No parameters found — test base URL with empty param_name."

    bearer_line = f"Bearer Token: {bearer_token}" if bearer_token else ""
    surface_msg = (
        f"Target: {target}\n"
        f"Auth: {auth_status}\n"
        f"{bearer_line}\n\n"
        f"Parameters to test:\n{targets_text}\n\n"
        "For each parameter above, call validate_finding with your vuln_type. "
        "Write DONE when all are tested."
    )

    # ── Phase 2: Vuln agents ──────────────────────────────────────
    all_agent_classes = VULN_AGENTS + _load_extended_agents()

    if llm_backend == "anthropic":
        all_findings = await _run_parallel(surface_msg, llm_backend, all_agent_classes)
    else:
        all_findings = await _run_sequential(surface_msg, llm_backend, all_agent_classes)

    # Add JS secrets as findings
    for secret in attack_surface.get("js_secrets", []):
        all_findings.append({
            "validated": True,
            "type": f"Hardcoded Secret in JS: {secret['type']}",
            "url": target,
            "param_name": secret.get("file", ""),
            "method": "GET",
            "payload": "",
            "evidence": f"Found in {secret['file']} line {secret['line']}: {secret['value'][:100]}",
            "severity": "High" if secret["type"] in ("aws_access_key", "private_key", "stripe_key") else "Medium",
            "source": "js-analyzer",
        })

    # Deduplicate
    seen = set()
    unique = []
    for f in all_findings:
        key = (f.get("type", ""), f.get("url", ""), f.get("param_name", ""))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    dupes = len(all_findings) - len(unique)
    console.print(
        f"\n  [bold]Total pre-validation: {len(unique)}[/]"
        + (f" [dim]({dupes} duplicates removed)[/]" if dupes else "")
    )

    # Apply confidence scores
    try:
        from confidence_scorer import enrich_with_scores
        unique = enrich_with_scores(unique)
    except Exception:
        pass

    # ── Phase 3: Adversarial Validation ──────────────────────────
    try:
        from agents.validator import ValidatorAgent
        validator = ValidatorAgent(llm_backend=llm_backend)
        unique = validator.validate_batch(unique, drop_false_positives=True)
    except Exception as e:
        console.print(f"  [yellow]Validation phase skipped: {e}[/]")

    console.print(f"\n  [bold]Final confirmed findings: {len(unique)}[/]")
    return unique


async def _run_parallel(surface_msg: str, llm_backend: str, agent_classes: list) -> list:
    """Run all agents simultaneously — Anthropic only."""
    console.print(f"\n[bold blue]  Phase 2: Parallel agents ({len(agent_classes)} simultaneous)[/]")
    _print_agent_table(llm_backend, agent_classes)

    async def run_one(agent_class):
        agent = agent_class(llm_backend=llm_backend)
        try:
            findings = await agent.run(surface_msg)
            status = f"[green]{len(findings)} finding(s)[/]" if findings else "[dim]0 findings[/]"
            console.print(f"  {agent_class.__name__}: {status}")
            return findings
        except Exception as e:
            console.print(f"  [red]{agent_class.__name__} error: {e}[/]")
            return []

    results = await asyncio.gather(*[run_one(cls) for cls in agent_classes])
    return [f for agent_findings in results for f in agent_findings]


async def _run_sequential(surface_msg: str, llm_backend: str, agent_classes: list) -> list:
    """Run agents one by one — safe for Ollama on limited RAM."""
    console.print(f"\n[bold blue]  Phase 2: Sequential agents ({len(agent_classes)} total)[/]")
    _print_agent_table(llm_backend, agent_classes)

    all_findings = []
    total = len(agent_classes)

    for i, agent_class in enumerate(agent_classes, 1):
        console.print(f"\n  [{i}/{total}] [cyan]{agent_class.__name__}[/]...")
        agent = agent_class(llm_backend=llm_backend)
        try:
            findings = await agent.run(surface_msg)
            status = f"[green]{len(findings)} finding(s)[/]" if findings else "[dim]0 findings[/]"
            console.print(f"  [{i}/{total}] {agent_class.__name__}: {status}")
            all_findings.extend(findings)
        except Exception as e:
            console.print(f"  [red]{agent_class.__name__} error: {e}[/]")

    return all_findings


def _print_agent_table(llm_backend: str, agent_classes: list):
    mode = "Parallel" if llm_backend == "anthropic" else "Sequential"
    model = "Haiku" if llm_backend == "anthropic" else "qwen2.5:14b"

    table = Table(
        title=f"Specialist Agents — {mode} ({model})",
        show_header=True,
        header_style="bold blue",
        border_style="dim",
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("Agent", style="cyan")

    for i, cls in enumerate(agent_classes, 1):
        table.add_row(str(i), cls.__name__)

    console.print(table)
