"""Build finding relationship graph and detect chains."""

from chain.chain_rules import CHAIN_RULES


def detect_chains(findings: list) -> list:
    """Detect exploit chains from findings using predefined rules."""
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
        if required.issubset(vuln_types):
            chain_findings = []
            for vt in required:
                chain_findings.extend(type_to_findings.get(vt, []))
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
                "findings": [{"vuln_type": f.get("vuln_type", ""), "url": f.get("url", "")} for f in chain_findings[:5]],
            })
    return detected_chains


def _normalize_vuln_type(vt: str) -> str:
    """Normalize vuln type string to match chain rule keys."""
    vt = vt.lower().strip()
    mapping = {
        "sql injection": "sqli", "cross-site scripting": "xss",
        "cross-site scripting (potential)": "xss", "command injection": "command_injection",
        "path traversal": "path_traversal", "cross-site request forgery": "csrf",
        "insecure direct object reference": "idor", "server-side request forgery": "ssrf",
        "open redirect": "open_redirect", "missing security headers": "security_headers",
        "cors misconfiguration": "cors", "sensitive data exposure": "sensitive_data",
        "file upload": "file_upload", "weak jwt configuration": "jwt",
        "server-side template injection": "ssti", "mass assignment": "mass_assignment",
        "hardcoded secret in js": "sensitive_data", "insecure cookie configuration": "security_headers",
        "weak csp policy": "security_headers", "sensitive file exposure": "sensitive_data",
    }
    for key, val in mapping.items():
        if key in vt:
            return val
    return vt
