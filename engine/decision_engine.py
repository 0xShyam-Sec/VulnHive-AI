"""DecisionEngine — OBSERVE→ANALYZE→DECIDE→ACT loop replacing fixed-phase orchestrator."""

import time

from rich.console import Console

from engine.config import ScanConfig
from engine.scan_state import ScanState, LeadItem
from engine.priority_scorer import score_all_endpoints
from engine.reactive_rules import (
    check_finding_triggers,
    check_endpoint_triggers,
    check_state_triggers,
)

# Base vulnerability types seeded for every qualifying endpoint
BASE_VULN_TYPES = [
    "sqli",
    "xss",
    "cmdi",
    "path_traversal",
    "csrf",
    "idor",
    "ssrf",
    "open_redirect",
    "security_headers",
    "sensitive_data",
]

# Injection-class vulns that require params or body_fields to make sense
INJECTION_VULN_TYPES = {"sqli", "xss", "cmdi", "path_traversal", "ssrf"}

_console = Console()


class DecisionEngine:
    """Continuous OODA-loop scan orchestrator."""

    def __init__(self, config: ScanConfig, state: ScanState):
        self.config = config
        self.state = state
        self._discovery_funcs = []
        self._agent_dispatch = {}
        self._validators = []
        self._last_checkpoint = 0.0

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_discovery(self, func):
        """Register a discovery callable: func(target, config, state) -> None."""
        self._discovery_funcs.append(func)

    def register_agent(self, vuln_type: str, func):
        """Register an agent callable for a vuln type: func(endpoint, config, state) -> list[findings]."""
        self._agent_dispatch[vuln_type] = func

    def register_validator(self, func):
        """Register a validation callable: func(findings, config) -> list[findings]."""
        self._validators.append(func)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, target: str):
        """Execute the full OODA scan loop against target."""
        self.state.scan_start_time = time.time()
        self.state.scan_status = "discovering"
        self._last_checkpoint = time.time()

        _console.print(f"\n[bold cyan]{'═' * 3} SCAN ENGINE START: {target} {'═' * 3}[/bold cyan]")

        # Phase 1: Discovery
        self._run_discovery(target)

        # Phase 2: Seed initial leads
        self._seed_initial_leads()

        # Phase 3: State-level reactive triggers (e.g. JWT detected)
        state_leads = check_state_triggers(self.state)
        for lead in state_leads:
            self.state.enqueue_lead(lead)
        if state_leads:
            _console.print(f"  [dim]State triggers enqueued {len(state_leads)} additional lead(s)[/dim]")

        # Phase 4: OODA exploitation loop
        self.state.scan_status = "exploiting"
        _console.print("\n[bold yellow]Phase: Exploit (OODA loop)[/bold yellow]")

        iteration = 0
        while self.state.has_leads():
            lead: LeadItem = self.state.next_lead()
            if lead is None:
                break

            vuln_type = lead.vuln_type
            endpoint = lead.endpoint

            # Skip if already tested
            if self.state.is_tested(endpoint.url, "", vuln_type):
                continue

            # Resolve agent: exact match, then base type (first segment before _)
            agent_func = self._agent_dispatch.get(vuln_type)
            if agent_func is None:
                base_type = vuln_type.split("_")[0]
                agent_func = self._agent_dispatch.get(base_type)

            if agent_func is None:
                self.state.mark_tested(endpoint.url, "", vuln_type)
                continue

            iteration += 1
            _console.print(
                f"  [{iteration}] [green]{vuln_type}[/green] → {endpoint.url} "
                f"(priority={lead.priority:.0f}, depth={lead.depth})"
            )

            # Execute agent
            new_findings = []
            try:
                new_findings = agent_func(endpoint, self.config, self.state) or []
            except Exception as exc:
                _console.print(f"    [red]Agent error ({vuln_type}): {exc}[/red]")

            self.state.mark_tested(endpoint.url, "", vuln_type)

            # Process findings and reactive triggers
            reactive_count = 0
            for finding in new_findings:
                self.state.add_finding(finding)

                # Check finding-level reactive rules
                reactive_leads = check_finding_triggers(finding, self.state)
                for rlead in reactive_leads:
                    rlead.depth = lead.depth + 1
                    if self.state.enqueue_lead(rlead):
                        reactive_count += 1

            if new_findings:
                _console.print(f"    [bold red]Findings: {len(new_findings)}[/bold red]", end="")
                if reactive_count:
                    _console.print(f"  [dim]+ {reactive_count} reactive lead(s) enqueued[/dim]")
                else:
                    _console.print()
            elif reactive_count:
                _console.print(f"    [dim]{reactive_count} reactive lead(s) enqueued[/dim]")

            self._maybe_checkpoint()

        # Phase 5a: Deduplication BEFORE validation (validate 5 findings, not 49)
        try:
            from engine.deduplicator import deduplicate_findings, get_dedup_stats
            original_count = len(self.state.findings)
            deduped = deduplicate_findings(list(self.state.findings))
            stats = get_dedup_stats([None] * original_count, deduped)
            with self.state._lock:
                self.state.findings = deduped
            _console.print(
                f"\n[bold]Deduplication: {original_count} → {len(deduped)} findings "
                f"({stats['reduction_pct']}% noise reduction)[/]"
            )
        except Exception as exc:
            _console.print(f"  [yellow]Deduplication error: {exc}[/yellow]")

        # Phase 5b: Validation (now runs on deduplicated set — much faster)
        self.state.scan_status = "validating"
        _console.print("\n[bold yellow]Phase: Validation[/bold yellow]")
        validated_findings = list(self.state.findings)
        for validator in self._validators:
            try:
                validated_findings = validator(validated_findings, self.config) or validated_findings
            except Exception as exc:
                _console.print(f"  [red]Validator error: {exc}[/red]")

        # Replace findings with validated set
        with self.state._lock:
            self.state.findings = validated_findings

        # Phase 6: Complete
        self.state.scan_status = "complete"
        summary = self.state.summary()
        _console.print(
            f"\n[bold green]Scan complete[/bold green] — "
            f"endpoints={summary['endpoints']}, "
            f"findings={summary['findings']}, "
            f"tested={summary['tested']}"
        )

        self._save_checkpoint()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _run_discovery(self, target: str):
        """Run all registered discovery functions."""
        _console.print("\n[bold yellow]Phase: Discovery[/bold yellow]")
        for func in self._discovery_funcs:
            try:
                func(target, self.config, self.state)
            except Exception as exc:
                _console.print(f"  [red]Discovery error: {exc}[/red]")
        _console.print(f"  Discovered {len(self.state.endpoints)} endpoint(s)")

    def _seed_initial_leads(self):
        """Score endpoints and seed base vuln leads for qualifying endpoints."""
        score_all_endpoints(self.state.endpoints)

        # Check endpoint-level reactive triggers after scoring
        for endpoint in self.state.endpoints:
            ep_leads = check_endpoint_triggers(endpoint, self.state)
            for lead in ep_leads:
                self.state.enqueue_lead(lead)

        seeded = 0
        for endpoint in self.state.endpoints:
            if endpoint.priority_score < 5:
                continue

            has_inputs = bool(endpoint.params or endpoint.body_fields)

            for vuln_type in BASE_VULN_TYPES:
                # Skip injection types when endpoint has no params/body_fields
                if vuln_type in INJECTION_VULN_TYPES and not has_inputs:
                    continue

                lead = LeadItem(
                    priority=endpoint.priority_score,
                    endpoint=endpoint,
                    vuln_type=vuln_type,
                    reason="Initial seed from endpoint scoring",
                    depth=0,
                )
                if self.state.enqueue_lead(lead):
                    seeded += 1

        _console.print(f"  Seeded {seeded} initial lead(s)")

    def _maybe_checkpoint(self):
        """Save checkpoint if enough time has elapsed since last save."""
        now = time.time()
        if now - self._last_checkpoint >= self.config.checkpoint_interval_sec:
            self._save_checkpoint()
            self._last_checkpoint = now

    def _save_checkpoint(self):
        """Persist current state to /tmp/pentest_checkpoint.json."""
        path = "/tmp/pentest_checkpoint.json"
        try:
            self.state.save_checkpoint(path)
            _console.print(f"  [dim]Checkpoint saved → {path}[/dim]")
        except Exception as exc:
            _console.print(f"  [red]Checkpoint save failed: {exc}[/red]")
