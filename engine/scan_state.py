"""Central shared state for all scan components. Thread-safe."""
import json
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from queue import PriorityQueue, Empty
from typing import Optional


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: list = field(default_factory=list)
    body_fields: list = field(default_factory=list)
    content_type: str = ""
    auth_required: bool = False
    response_status: int = 0
    response_headers: dict = field(default_factory=dict)
    priority_score: float = 0.0
    tags: set = field(default_factory=set)

    @property
    def base_url(self):
        return self.url.split("?")[0]

    def __hash__(self):
        return hash((self.base_url, self.method))

    def __eq__(self, other):
        if not isinstance(other, Endpoint):
            return False
        return self.base_url == other.base_url and self.method == other.method


@dataclass
class LeadItem:
    priority: float
    endpoint: Endpoint
    vuln_type: str
    reason: str
    parent_finding_id: str = ""
    depth: int = 0

    def __lt__(self, other):
        # Max-heap: higher priority value = more important
        return self.priority > other.priority


class ScanState:
    """Central shared state for all scan components."""

    def __init__(self):
        self._lock = threading.Lock()
        self.endpoints = []
        self.tech_stack = {}
        self.auth_info = {}
        self.waf_info = {}
        self.filter_profiles = {}
        self.tested = set()
        self.lead_queue = PriorityQueue()
        self.findings = []
        self.chains = []
        self.callback_hits = []
        self.js_secrets = []
        self.depth_tracker = defaultdict(int)
        self.scan_start_time = time.time()
        self.scan_status = "idle"

    # ------------------------------------------------------------------
    # Endpoint management
    # ------------------------------------------------------------------

    def add_endpoint(self, endpoint):
        """Add an endpoint, skipping duplicates."""
        with self._lock:
            if endpoint not in self.endpoints:
                self.endpoints.append(endpoint)

    def add_endpoints(self, endpoints):
        """Batch add endpoints, skipping duplicates."""
        with self._lock:
            for endpoint in endpoints:
                if endpoint not in self.endpoints:
                    self.endpoints.append(endpoint)

    # ------------------------------------------------------------------
    # Finding management
    # ------------------------------------------------------------------

    def add_finding(self, finding):
        """Add a finding."""
        with self._lock:
            self.findings.append(finding)

    def add_findings(self, findings):
        """Batch add findings."""
        with self._lock:
            self.findings.extend(findings)

    # ------------------------------------------------------------------
    # Tested tracking
    # ------------------------------------------------------------------

    def mark_tested(self, url, param, vuln_type):
        """Mark a (base_url, param, vuln_type) tuple as tested."""
        base_url = url.split("?")[0]
        with self._lock:
            self.tested.add((base_url, param, vuln_type))

    def is_tested(self, url, param, vuln_type):
        """Check whether a (base_url, param, vuln_type) combo has been tested."""
        base_url = url.split("?")[0]
        with self._lock:
            return (base_url, param, vuln_type) in self.tested

    # ------------------------------------------------------------------
    # Lead queue
    # ------------------------------------------------------------------

    def enqueue_lead(self, item):
        """Enqueue a LeadItem, enforcing depth and spawn limits.

        Returns True if enqueued, False if rejected.
        Limits:
          - max depth: 3
          - max spawns per (base_url, vuln_type): 10
        """
        if item.depth > 3:
            return False

        tracker_key = (item.endpoint.base_url, item.vuln_type)
        with self._lock:
            if self.depth_tracker[tracker_key] >= 10:
                return False
            self.depth_tracker[tracker_key] += 1

        self.lead_queue.put(item)
        return True

    def next_lead(self):
        """Get the next highest-priority lead, or None if queue is empty."""
        try:
            return self.lead_queue.get_nowait()
        except Empty:
            return None

    def has_leads(self):
        """Return True if there are leads waiting."""
        return not self.lead_queue.empty()

    # ------------------------------------------------------------------
    # Callback hits
    # ------------------------------------------------------------------

    def add_callback_hit(self, token, source_ip, data):
        """Record an out-of-band callback hit."""
        with self._lock:
            self.callback_hits.append({
                "token": token,
                "source_ip": source_ip,
                "data": data,
                "timestamp": time.time(),
            })

    # ------------------------------------------------------------------
    # Checkpoint persistence
    # ------------------------------------------------------------------

    def save_checkpoint(self, path):
        """Serialize state to a JSON file."""
        with self._lock:
            state = {
                "endpoints": [
                    {
                        "url": ep.url,
                        "method": ep.method,
                        "params": ep.params,
                        "body_fields": ep.body_fields,
                        "content_type": ep.content_type,
                        "auth_required": ep.auth_required,
                        "response_status": ep.response_status,
                        "response_headers": ep.response_headers,
                        "priority_score": ep.priority_score,
                        "tags": list(ep.tags),
                    }
                    for ep in self.endpoints
                ],
                "tech_stack": self.tech_stack,
                "auth_info": self.auth_info,
                "waf_info": self.waf_info,
                "filter_profiles": self.filter_profiles,
                "tested": [list(t) for t in self.tested],
                "findings": self.findings,
                "chains": self.chains,
                "callback_hits": self.callback_hits,
                "js_secrets": self.js_secrets,
                "depth_tracker": {
                    json.dumps(list(k)): v
                    for k, v in self.depth_tracker.items()
                },
                "scan_start_time": self.scan_start_time,
                "scan_status": self.scan_status,
            }

        with open(path, "w") as f:
            json.dump(state, f, indent=2)

    @classmethod
    def load_checkpoint(cls, path):
        """Restore state from a JSON checkpoint file."""
        with open(path, "r") as f:
            state = json.load(f)

        instance = cls()
        instance.endpoints = [
            Endpoint(
                url=ep["url"],
                method=ep["method"],
                params=ep["params"],
                body_fields=ep["body_fields"],
                content_type=ep["content_type"],
                auth_required=ep["auth_required"],
                response_status=ep["response_status"],
                response_headers=ep["response_headers"],
                priority_score=ep["priority_score"],
                tags=set(ep["tags"]),
            )
            for ep in state["endpoints"]
        ]
        instance.tech_stack = state.get("tech_stack", {})
        instance.auth_info = state.get("auth_info", {})
        instance.waf_info = state.get("waf_info", {})
        instance.filter_profiles = state.get("filter_profiles", {})
        instance.tested = set(tuple(t) for t in state.get("tested", []))
        instance.findings = state.get("findings", [])
        instance.chains = state.get("chains", [])
        instance.callback_hits = state.get("callback_hits", [])
        instance.js_secrets = state.get("js_secrets", [])
        instance.depth_tracker = defaultdict(int, {
            tuple(json.loads(k)): v
            for k, v in state.get("depth_tracker", {}).items()
        })
        instance.scan_start_time = state.get("scan_start_time", time.time())
        instance.scan_status = state.get("scan_status", "idle")
        return instance

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def summary(self):
        """Return a dict with counts of key state fields."""
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
