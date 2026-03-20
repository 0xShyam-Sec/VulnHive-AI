"""Reactive rules: when one agent finds something, trigger targeted follow-up tests."""

from engine.scan_state import ScanState, Endpoint, LeadItem


# ============================================================================
# Reactive Rules Definition
# ============================================================================

REACTIVE_RULES = [
    {
        "name": "jwt_detected",
        "trigger_field": "auth_info",
        "trigger_condition": lambda state: state.auth_info.get("type") == "jwt",
        "spawn_vuln_types": ["jwt_algorithm", "jwt_claim_tamper", "jwt_expiry"],
        "priority": 85,
        "reason": "JWT token detected in auth_info; escalate to algorithm weakness, claim tampering, expiry checks",
    },
    {
        "name": "403_forbidden",
        "trigger_field": "finding",
        "trigger_condition": lambda finding: "403" in finding.get("evidence", ""),
        "spawn_vuln_types": ["auth_bypass", "path_traversal", "verb_tamper"],
        "priority": 75,
        "reason": "HTTP 403 response found; check for auth bypass via method override, path traversal, or verb tampering",
    },
    {
        "name": "file_upload_endpoint",
        "trigger_field": "endpoint",
        "trigger_condition": lambda endpoint: (
            any(keyword in endpoint.url.lower() for keyword in ["upload", "import", "file", "attach", "media"])
            and endpoint.method in ["POST", "PUT"]
        ),
        "spawn_vuln_types": ["file_upload", "xxe"],
        "priority": 80,
        "reason": "File upload endpoint detected; check for arbitrary upload and XXE injection",
    },
    {
        "name": "sql_error_leaked",
        "trigger_field": "finding",
        "trigger_condition": lambda finding: (
            "sql" in finding.get("vuln_type", "").lower()
            and finding.get("validated", False)
        ),
        "spawn_vuln_types": ["sqli_union_extract", "sqli_blind_boolean", "sqli_time_based"],
        "priority": 90,
        "reason": "SQL injection validated; escalate to union extraction, blind boolean, time-based techniques",
    },
    {
        "name": "cors_misconfigured",
        "trigger_field": "finding",
        "trigger_condition": lambda finding: (
            "cors" in finding.get("vuln_type", "").lower()
            and finding.get("validated", False)
        ),
        "spawn_vuln_types": ["cors_data_theft", "cors_csrf_chain"],
        "priority": 70,
        "reason": "CORS misconfiguration validated; check for data theft and CSRF chaining",
    },
    {
        "name": "idor_confirmed",
        "trigger_field": "finding",
        "trigger_condition": lambda finding: (
            "idor" in finding.get("vuln_type", "").lower()
            and finding.get("validated", False)
        ),
        "spawn_vuln_types": ["idor_mass_enum", "idor_write", "idor_delete"],
        "priority": 85,
        "reason": "IDOR confirmed; escalate to mass enumeration, write, and delete attempts",
    },
    {
        "name": "redirect_found",
        "trigger_field": "finding",
        "trigger_condition": lambda finding: (
            "redirect" in finding.get("vuln_type", "").lower()
            and finding.get("validated", False)
        ),
        "spawn_vuln_types": ["open_redirect_oauth_chain", "ssrf_via_redirect"],
        "priority": 65,
        "reason": "Open redirect confirmed; check for OAuth chaining and SSRF via redirect",
    },
    {
        "name": "graphql_detected",
        "trigger_field": "endpoint",
        "trigger_condition": lambda endpoint: "graphql" in endpoint.url.lower(),
        "spawn_vuln_types": ["graphql_introspection", "graphql_depth", "graphql_batch", "graphql_injection"],
        "priority": 80,
        "reason": "GraphQL endpoint detected; check introspection, depth limits, batch queries, and injection",
    },
    {
        "name": "template_reflection",
        "trigger_field": "finding",
        "trigger_condition": lambda finding: (
            "ssti" in finding.get("vuln_type", "").lower()
            or "{{" in finding.get("evidence", "")
        ),
        "spawn_vuln_types": ["ssti_jinja", "ssti_twig", "ssti_freemarker"],
        "priority": 90,
        "reason": "Server-side template injection detected; test Jinja, Twig, and FreeMarker payloads",
    },
    {
        "name": "xss_confirmed",
        "trigger_field": "finding",
        "trigger_condition": lambda finding: (
            "xss" in finding.get("vuln_type", "").lower()
            and finding.get("validated", False)
        ),
        "spawn_vuln_types": ["xss_stored_check", "xss_dom_check"],
        "priority": 75,
        "reason": "XSS confirmed; escalate to stored XSS and DOM-based XSS checks",
    },
    {
        "name": "websocket_endpoint",
        "trigger_field": "endpoint",
        "trigger_condition": lambda endpoint: (
            endpoint.url.lower().startswith("ws://")
            or endpoint.url.lower().startswith("wss://")
        ),
        "spawn_vuln_types": ["websocket_injection", "websocket_auth_bypass"],
        "priority": 70,
        "reason": "WebSocket endpoint detected; check for injection and auth bypass",
    },
    {
        "name": "versioned_api",
        "trigger_field": "endpoint",
        "trigger_condition": lambda endpoint: any(
            version in endpoint.url for version in ["/v2/", "/v3/", "/v4/", "/v5/"]
        ),
        "spawn_vuln_types": ["api_version_downgrade"],
        "priority": 60,
        "reason": "Versioned API detected; check for version downgrade attacks",
    },
    {
        "name": "payment_endpoint",
        "trigger_field": "endpoint",
        "trigger_condition": lambda endpoint: any(
            keyword in endpoint.url.lower()
            for keyword in ["payment", "checkout", "cart", "order", "price", "billing"]
        ),
        "spawn_vuln_types": ["business_logic", "rate_limit"],
        "priority": 80,
        "reason": "Payment endpoint detected; check business logic flaws and rate limiting",
    },
    {
        "name": "error_verbose",
        "trigger_field": "finding",
        "trigger_condition": lambda finding: (
            "sensitive" in finding.get("vuln_type", "").lower()
            and any(
                trace_term in finding.get("evidence", "").lower()
                for trace_term in ["stack trace", "traceback", "exception", "debug"]
            )
        ),
        "spawn_vuln_types": ["sqli", "ssti", "path_traversal"],
        "priority": 70,
        "reason": "Verbose error with sensitive info detected; check for SQL injection, SSTI, and path traversal",
    },
]


# ============================================================================
# Rule Evaluation Functions
# ============================================================================


def check_finding_triggers(finding: dict, state: ScanState) -> list:
    """
    Evaluate all "finding"-type rules against a single finding.
    Returns list of LeadItem objects to be enqueued.

    Args:
        finding: A finding dict with keys like 'vuln_type', 'evidence', 'url', 'param_name', 'validated'
        state: ScanState for tracking tested vulnerabilities

    Returns:
        List of LeadItem objects to spawn
    """
    leads = []

    for rule in REACTIVE_RULES:
        if rule["trigger_field"] != "finding":
            continue

        try:
            # Evaluate the trigger condition
            if not rule["trigger_condition"](finding):
                continue
        except Exception:
            # Skip rules with evaluation errors
            continue

        # For each endpoint, check if we've already tested this vuln_type
        endpoint_url = finding.get("url", "")
        param_name = finding.get("param_name", "")

        if not endpoint_url:
            continue

        # Get or create an endpoint for this finding
        endpoint = Endpoint(
            url=endpoint_url,
            method=finding.get("method", "GET"),
        )

        # Spawn all vuln_types from this rule
        for vuln_type in rule["spawn_vuln_types"]:
            # Check if already tested
            if state.is_tested(endpoint_url, param_name, vuln_type):
                continue

            # Create and yield a lead
            lead = LeadItem(
                priority=rule["priority"],
                endpoint=endpoint,
                vuln_type=vuln_type,
                reason=rule["reason"],
                parent_finding_id=finding.get("finding_id", ""),
                depth=finding.get("depth", 0) + 1,
            )
            leads.append(lead)

    return leads


def check_endpoint_triggers(endpoint: Endpoint, state: ScanState) -> list:
    """
    Evaluate all "endpoint"-type rules against a single endpoint.
    Returns list of LeadItem objects to be enqueued.

    Args:
        endpoint: An Endpoint object
        state: ScanState for tracking tested vulnerabilities

    Returns:
        List of LeadItem objects to spawn
    """
    leads = []

    for rule in REACTIVE_RULES:
        if rule["trigger_field"] != "endpoint":
            continue

        try:
            # Evaluate the trigger condition
            if not rule["trigger_condition"](endpoint):
                continue
        except Exception:
            # Skip rules with evaluation errors
            continue

        # Spawn all vuln_types from this rule
        for vuln_type in rule["spawn_vuln_types"]:
            # Check if already tested
            if state.is_tested(endpoint.url, "", vuln_type):
                continue

            # Create and yield a lead
            lead = LeadItem(
                priority=rule["priority"],
                endpoint=endpoint,
                vuln_type=vuln_type,
                reason=rule["reason"],
                parent_finding_id="",
                depth=0,
            )
            leads.append(lead)

    return leads


def check_state_triggers(state: ScanState) -> list:
    """
    Evaluate all "auth_info"-type rules against the global state.
    Applies triggers to the top 10 endpoints by priority_score.
    Returns list of LeadItem objects to be enqueued.

    Args:
        state: ScanState with auth_info and endpoints

    Returns:
        List of LeadItem objects to spawn
    """
    leads = []

    for rule in REACTIVE_RULES:
        if rule["trigger_field"] != "auth_info":
            continue

        try:
            # Evaluate the trigger condition
            if not rule["trigger_condition"](state):
                continue
        except Exception:
            # Skip rules with evaluation errors
            continue

        # Get top 10 endpoints by priority_score
        sorted_endpoints = sorted(
            state.endpoints,
            key=lambda ep: ep.priority_score,
            reverse=True,
        )[:10]

        # Spawn vuln_types for each endpoint
        for endpoint in sorted_endpoints:
            for vuln_type in rule["spawn_vuln_types"]:
                # Check if already tested
                if state.is_tested(endpoint.url, "", vuln_type):
                    continue

                # Create and yield a lead
                lead = LeadItem(
                    priority=rule["priority"],
                    endpoint=endpoint,
                    vuln_type=vuln_type,
                    reason=rule["reason"],
                    parent_finding_id="",
                    depth=0,
                )
                leads.append(lead)

    return leads
