"""Single source of truth: which producers run in each scan mode.

The dashboard worker, the CLI, and the engine runner all consult this table.
Adding a new producer to a mode is a one-line change here.
"""

from __future__ import annotations


ALL_VULN_AGENTS = [
    "sqli", "xss", "csrf", "ssrf", "idor", "idor_advanced",
    "cmdi", "ssti", "xxe", "jwt", "path_traversal", "file_upload",
    "graphql", "http_smuggling", "headers", "sensitive_data",
    "mass_assignment", "open_redirect", "cache_poison", "auth_bypass",
    "business_logic", "subdomain", "websocket", "api_version", "rate_limit",
]

BROWSER_AGENTS = ["xss", "csrf", "open_redirect", "auth_bypass", "idor"]
API_AGENTS     = ["sqli", "idor", "mass_assignment", "jwt", "auth_bypass", "rate_limit",
                  "api_version", "graphql"]


MODE_PRODUCERS: dict[str, list[str]] = {
    "fast": [
        "passive_recon", "headers", "sensitive_data",
    ],
    "multi-agent": [
        "passive_recon", "playwright_crawler", "waf_detector",
        "nuclei",
        *ALL_VULN_AGENTS,
    ],
    "full": [
        "nmap", "nuclei", "shodan",
        "passive_recon", "playwright_crawler", "waf_detector",
        *ALL_VULN_AGENTS,
        "systematic",
    ],
    "browser": [
        "passive_recon", "playwright_crawler",
        *BROWSER_AGENTS,
    ],
    "api": [
        "passive_recon", "openapi_importer",
        *API_AGENTS,
    ],
}


def list_modes() -> list[str]:
    return sorted(MODE_PRODUCERS.keys())


def build_producer_names(mode: str) -> list[str]:
    """Return the producer name list for a given mode. Raises KeyError on unknown."""
    if mode not in MODE_PRODUCERS:
        raise KeyError(f"unknown mode: {mode!r} (known: {sorted(MODE_PRODUCERS)})")
    return list(MODE_PRODUCERS[mode])
