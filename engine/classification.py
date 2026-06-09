"""CWE + CVSS lookup keyed by vuln_type.

Sourced from report_engine.VULN_CLASSIFICATION (de-duplicated and normalized).
Producers call classify(vuln_type) at emit time so cwe/cvss are never null on a
Finding (the precondition for §7.4 of the spec).
"""

from __future__ import annotations

from typing import Optional


CWE_DEFAULTS: dict[str, int] = {
    "sqli":                         89,
    "blind_sqli":                   89,
    "xss":                          79,
    "reflected_xss":                79,
    "stored_xss":                   79,
    "dom_xss":                      79,
    "csrf":                        352,
    "ssrf":                        918,
    "idor":                        639,
    "idor_advanced":               639,
    "cmdi":                         78,
    "command_injection":            78,
    "ssti":                         94,
    "xxe":                         611,
    "jwt":                         347,
    "path_traversal":               22,
    "file_upload":                 434,
    "graphql":                     200,
    "http_smuggling":              444,
    "headers":                     693,
    "missing_security_header":     693,
    "sensitive_data":              200,
    "mass_assignment":             915,
    "open_redirect":               601,
    "cache_poison":                444,
    "auth_bypass":                 287,
    "business_logic":              840,
    "subdomain":                   200,
    "websocket":                  1385,
    "api_version":                 200,
    "rate_limit":                  799,
    "oauth":                       287,
    "saml":                        287,
    "race_condition":              362,
    "ato":                         287,
    "cloud_misconfig":             732,
    "llm_ai":                      940,
    "cors_misconfiguration":       942,
    "waf_detected":                  0,
}


CVSS_DEFAULTS: dict[str, float] = {
    "sqli":                       9.8,
    "blind_sqli":                 8.6,
    "xss":                        6.1,
    "reflected_xss":              6.1,
    "stored_xss":                 7.4,
    "dom_xss":                    6.1,
    "csrf":                       6.5,
    "ssrf":                       8.6,
    "idor":                       7.5,
    "idor_advanced":              8.1,
    "cmdi":                       9.8,
    "command_injection":          9.8,
    "ssti":                       9.8,
    "xxe":                        8.2,
    "jwt":                        7.5,
    "path_traversal":             7.5,
    "file_upload":                8.8,
    "graphql":                    5.3,
    "http_smuggling":             8.6,
    "headers":                    4.3,
    "missing_security_header":    4.3,
    "sensitive_data":             5.3,
    "mass_assignment":            7.5,
    "open_redirect":              6.1,
    "cache_poison":               7.5,
    "auth_bypass":                9.1,
    "business_logic":             6.5,
    "subdomain":                  3.7,
    "websocket":                  5.3,
    "api_version":                3.1,
    "rate_limit":                 5.3,
    "cors_misconfiguration":      5.3,
    "waf_detected":               0.0,
}


def classify(vuln_type: str) -> tuple[Optional[int], Optional[float]]:
    """Return (cwe, cvss) defaults for a vuln_type. Either may be None for unknown types."""
    key = (vuln_type or "").lower().strip()
    return CWE_DEFAULTS.get(key), CVSS_DEFAULTS.get(key)
