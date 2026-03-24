"""
Finding Deduplication & Aggregation Engine.

Groups same-type + same-severity findings into single entries with
endpoint lists. Eliminates report noise from repeated findings like
"Missing Security Headers" appearing 43 times.

Rules:
  1. Group by (normalized_vuln_type, severity)
  2. If multiple endpoints share the same group → merge into ONE finding
  3. Preserve the richest evidence from all merged findings
  4. Track affected_endpoints list on each merged finding
  5. Unique findings (only one endpoint) pass through unchanged
"""

import re
from collections import defaultdict


# ── Vuln type normalization ──────────────────────────────────────────────────
# Maps verbose/variant names to canonical types for grouping

_TYPE_NORMALIZATION = {
    "missing_security_header_x_frame_options": "missing_security_headers",
    "missing_security_header_x_content_type_options": "missing_security_headers",
    "missing_security_header_strict_transport_security": "missing_security_headers",
    "missing_security_header_content_security_policy": "missing_security_headers",
    "missing_security_header_referrer_policy": "missing_security_headers",
    "missing_security_header_permissions_policy": "missing_security_headers",
    "missing_security_header_x_xss_protection": "missing_security_headers",
    "missing security headers": "missing_security_headers",
    "information_disclosure_header": "information_disclosure",
    "insecure_cookie_attributes": "insecure_cookies",
    "sensitive_file_exposed": "sensitive_file_exposure",
    "weak_content_security_policy": "weak_csp",
    "cors_misconfiguration": "cors_misconfiguration",
}

# Types that SHOULD be aggregated (same type on many endpoints = 1 finding)
_AGGREGATABLE_TYPES = {
    "missing_security_headers",
    "information_disclosure",
    "insecure_cookies",
    "weak_csp",
    "rate_limit",
    "cors_misconfiguration",
}

# Types where each endpoint is a distinct finding (never merge)
_NEVER_AGGREGATE = {
    "sqli", "xss", "command_injection", "path_traversal",
    "idor", "ssrf", "ssti", "xxe", "jwt", "file_upload",
    "csrf", "subdomain_takeover", "http_smuggling",
}


def normalize_vuln_type(vt: str) -> str:
    """Normalize a vuln_type string to a canonical grouping key."""
    vt_lower = vt.lower().strip()
    if vt_lower in _TYPE_NORMALIZATION:
        return _TYPE_NORMALIZATION[vt_lower]
    # Strip "missing_security_header_" prefix variants
    if vt_lower.startswith("missing_security_header"):
        return "missing_security_headers"
    return vt_lower


def deduplicate_findings(findings: list) -> list:
    """
    Deduplicate and aggregate findings.

    Same vuln_type + same severity across multiple endpoints → ONE finding
    with an affected_endpoints list.

    Returns: deduplicated list of finding dicts, each with 'affected_endpoints' field.
    """
    if not findings:
        return findings

    # Step 1: Classify each finding
    aggregatable_groups = defaultdict(list)  # (norm_type, severity) → [findings]
    unique_findings = []

    for f in findings:
        vt = f.get("vuln_type", f.get("type", "unknown"))
        norm_type = normalize_vuln_type(vt)
        severity = f.get("severity", "Medium")

        # Check if this type should be aggregated
        if norm_type in _AGGREGATABLE_TYPES:
            key = (norm_type, severity)
            aggregatable_groups[key].append(f)
        elif norm_type in _NEVER_AGGREGATE:
            # Each is unique — pass through
            f["affected_endpoints"] = [f.get("url", "N/A")]
            unique_findings.append(f)
        else:
            # Unknown type — deduplicate by (type, severity, url)
            f["affected_endpoints"] = [f.get("url", "N/A")]
            unique_findings.append(f)

    # Step 2: Merge aggregatable groups
    merged_findings = []
    for (norm_type, severity), group in aggregatable_groups.items():
        merged = _merge_finding_group(norm_type, severity, group)
        merged_findings.append(merged)

    # Step 3: Deduplicate unique findings by (norm_type, url, param)
    seen_unique = set()
    deduped_unique = []
    for f in unique_findings:
        vt = normalize_vuln_type(f.get("vuln_type", ""))
        url = f.get("url", "")
        param = f.get("param_name", "")
        key = (vt, url, param)
        if key not in seen_unique:
            seen_unique.add(key)
            deduped_unique.append(f)

    # Step 4: Combine and sort by severity
    all_findings = merged_findings + deduped_unique
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4, "Info": 5}
    all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "Medium"), 3))

    return all_findings


def _merge_finding_group(norm_type: str, severity: str, group: list) -> dict:
    """
    Merge multiple findings of the same type+severity into one.
    Picks the richest evidence and collects all affected endpoints.
    """
    # Collect all unique endpoints
    endpoints = []
    seen_urls = set()
    for f in group:
        url = f.get("url", "N/A")
        if url not in seen_urls:
            seen_urls.add(url)
            endpoints.append(url)

    # Pick the finding with the richest evidence as the base
    base = max(group, key=lambda f: len(str(f.get("evidence", ""))))

    # Build combined evidence
    all_evidence = set()
    for f in group:
        ev = f.get("evidence", "")
        if ev:
            all_evidence.add(ev)

    # Combine evidence smartly (avoid repetition)
    if norm_type == "missing_security_headers":
        # Extract unique missing header names
        missing_headers = set()
        for ev in all_evidence:
            m = re.findall(r"Missing security header:\s*(\S+)", ev, re.I)
            missing_headers.update(m)
            m2 = re.findall(r"Missing:\s*([^.]+)", ev, re.I)
            for match in m2:
                missing_headers.update(h.strip() for h in match.split(","))
        combined_evidence = "Missing headers: {}".format(", ".join(sorted(missing_headers)))
    else:
        # Take the longest/richest evidence
        combined_evidence = max(all_evidence, key=len) if all_evidence else ""

    # Human-readable display names
    display_names = {
        "missing_security_headers": "Missing Security Headers",
        "information_disclosure": "Information Disclosure via HTTP Headers",
        "insecure_cookies": "Insecure Cookie Configuration",
        "weak_csp": "Weak Content Security Policy",
        "rate_limit": "Missing Rate Limiting",
        "cors_misconfiguration": "CORS Misconfiguration",
    }

    merged = dict(base)
    merged["vuln_type"] = display_names.get(norm_type, norm_type)
    merged["severity"] = severity
    merged["evidence"] = combined_evidence
    merged["affected_endpoints"] = endpoints
    # Keep actual URL when single endpoint; show count when multiple
    if len(endpoints) == 1:
        merged["url"] = endpoints[0]
    else:
        merged["url"] = f"{len(endpoints)} endpoint(s) affected"
    merged["dedup_count"] = len(group)
    merged["dedup_original_count"] = len(group)

    return merged


def get_dedup_stats(original: list, deduped: list) -> dict:
    """Get deduplication statistics."""
    return {
        "original_count": len(original),
        "deduped_count": len(deduped),
        "removed": len(original) - len(deduped),
        "reduction_pct": round(
            (1 - len(deduped) / max(len(original), 1)) * 100, 1
        ),
    }
