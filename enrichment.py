"""
CVE Enrichment — NVD API + ExploitDB integration.

Auto-enriches confirmed findings with:
  - CVE IDs and CVSS scores from the NVD (National Vulnerability Database)
  - Public exploit references from Exploit-DB

Both APIs are free and require no API key.

Usage:
    from enrichment import enrich_findings
    findings = enrich_findings(findings)
    # Each finding now has: cve_refs, cvss_score, exploit_refs
"""

import time
from typing import Optional

import httpx

# ── Keyword mapping: vuln_type → NVD search terms ───────────────────────────

VULN_KEYWORDS = {
    "sqli":               "sql injection",
    "sql_injection":      "sql injection",
    "xss":                "cross-site scripting xss",
    "xss_reflected":      "reflected cross-site scripting",
    "xss_stored":         "stored cross-site scripting persistent",
    "command_injection":  "os command injection",
    "cmdi":               "os command injection",
    "path_traversal":     "path traversal directory traversal",
    "lfi":                "local file inclusion path traversal",
    "csrf":               "cross-site request forgery csrf",
    "idor":               "insecure direct object reference authorization",
    "ssrf":               "server-side request forgery ssrf",
    "open_redirect":      "open redirect url redirection",
    "missing_headers":    "missing security headers http",
    "sensitive_data":     "sensitive data exposure information disclosure",
}

# ── NVD API ──────────────────────────────────────────────────────────────────

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE = 3
NVD_TIMEOUT = 10

# Simple in-process cache so the same keyword isn't fetched twice per scan
_nvd_cache: dict = {}


def search_nvd(vuln_type: str) -> list[dict]:
    """
    Search NVD for CVEs matching the given vuln_type.

    Returns a list of dicts:
        [{"cve_id": "CVE-2024-…", "cvss_score": 9.8, "cvss_version": "3.1",
          "description": "…", "published": "2024-01-15", "url": "https://nvd.nist.gov/…"},
         …]
    """
    keyword = VULN_KEYWORDS.get(vuln_type.lower(), vuln_type.replace("_", " "))

    if keyword in _nvd_cache:
        return _nvd_cache[keyword]

    try:
        resp = httpx.get(
            NVD_URL,
            params={
                "keywordSearch": keyword,
                "resultsPerPage": NVD_RESULTS_PER_PAGE,
                "cvssV3Severity": "HIGH",          # focus on high/critical
            },
            timeout=NVD_TIMEOUT,
            headers={"User-Agent": "VulnHive-AI/1.0"},
        )
        if resp.status_code != 200:
            _nvd_cache[keyword] = []
            return []

        data = resp.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            published = cve.get("published", "")[:10]

            # Extract best CVSS score available
            cvss_score = None
            cvss_version = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    cvss_data = entries[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_version = key.replace("cvssMetric", "CVSS ")
                    break

            # English description
            description = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    description = d.get("value", "")[:200]
                    break

            results.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "cvss_version": cvss_version,
                "description": description,
                "published": published,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

        _nvd_cache[keyword] = results
        return results

    except Exception:
        _nvd_cache[keyword] = []
        return []


# ── ExploitDB API ────────────────────────────────────────────────────────────

EXPLOITDB_URL = "https://www.exploit-db.com/search"
EXPLOITDB_TIMEOUT = 10
_edb_cache: dict = {}


def search_exploitdb(vuln_type: str) -> list[dict]:
    """
    Search Exploit-DB for public exploits matching the given vuln_type.

    Returns a list of dicts:
        [{"exploit_id": "12345", "title": "…", "type": "webapps",
          "platform": "php", "date": "2024-01-10", "url": "https://exploit-db.com/exploits/12345"},
         …]
    """
    keyword = VULN_KEYWORDS.get(vuln_type.lower(), vuln_type.replace("_", " "))

    if keyword in _edb_cache:
        return _edb_cache[keyword]

    try:
        # ExploitDB uses a DataTables AJAX endpoint — requires specific params + header
        resp = httpx.get(
            EXPLOITDB_URL,
            params={
                "draw": "1",
                "columns[0][data]": "date_published",
                "columns[1][data]": "description",
                "order[0][column]": "0",
                "order[0][dir]": "desc",
                "start": "0",
                "length": "5",
                "search[value]": keyword,
                "search[regex]": "false",
                "type": "",
                "platform": "",
                "action": "search",
            },
            timeout=EXPLOITDB_TIMEOUT,
            headers={
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        if resp.status_code != 200:
            _edb_cache[keyword] = []
            return []

        data = resp.json()
        rows = data.get("data", [])[:3]   # top 3 exploits

        results = []
        for row in rows:
            exploit_id = str(row.get("id", ""))

            # description is sometimes a list [id, title] or a plain string
            raw_desc = row.get("description", "")
            if isinstance(raw_desc, list):
                title = raw_desc[1] if len(raw_desc) > 1 else str(raw_desc[0])
            else:
                title = str(raw_desc)

            platform = row.get("platform_id", row.get("platform", ""))
            if isinstance(platform, dict):
                platform = platform.get("label", "")

            results.append({
                "exploit_id": exploit_id,
                "title": title,
                "platform": str(platform),
                "date": str(row.get("date_published", ""))[:10],
                "url": f"https://www.exploit-db.com/exploits/{exploit_id}",
            })

        _edb_cache[keyword] = results
        return results

    except Exception:
        _edb_cache[keyword] = []
        return []


# ── Enrichment helpers ───────────────────────────────────────────────────────

def _highest_cvss(cve_refs: list[dict]) -> Optional[float]:
    """Return the highest CVSS score from a list of CVE refs, or None."""
    scores = [c["cvss_score"] for c in cve_refs if c.get("cvss_score") is not None]
    return max(scores) if scores else None


def enrich_finding(finding: dict) -> dict:
    """
    Enrich a single finding dict in-place with CVE and exploit data.

    Adds:
        finding["cve_refs"]     — list of CVE dicts from NVD
        finding["exploit_refs"] — list of exploit dicts from ExploitDB
        finding["cvss_score"]   — highest CVSS score found (float or None)
    """
    vuln_type = finding.get("vuln_type", "")
    if not vuln_type:
        finding.setdefault("cve_refs", [])
        finding.setdefault("exploit_refs", [])
        finding.setdefault("cvss_score", None)
        return finding

    cve_refs = search_nvd(vuln_type)
    # Small delay to respect NVD rate limit (5 req/30s without API key)
    time.sleep(0.7)
    exploit_refs = search_exploitdb(vuln_type)

    finding["cve_refs"] = cve_refs
    finding["exploit_refs"] = exploit_refs
    finding["cvss_score"] = _highest_cvss(cve_refs)
    return finding


def enrich_findings(findings: list[dict], verbose: bool = True) -> list[dict]:
    """
    Enrich all findings with NVD CVE data and ExploitDB references.

    Deduplicates API calls — same vuln_type is only fetched once.
    Returns the same list (modified in-place, also returned for chaining).
    """
    if not findings:
        return findings

    # Deduplicate: only call APIs once per unique vuln_type
    seen_types: set = set()
    type_data: dict = {}

    for f in findings:
        vt = f.get("vuln_type", "").lower()
        if vt and vt not in seen_types:
            seen_types.add(vt)
            if verbose:
                from rich.console import Console
                Console().print(f"  [dim]Enriching {vt}...[/dim]")
            cve_refs = search_nvd(vt)
            time.sleep(0.7)   # NVD rate limit
            exploit_refs = search_exploitdb(vt)
            type_data[vt] = {"cve_refs": cve_refs, "exploit_refs": exploit_refs}

    for f in findings:
        vt = f.get("vuln_type", "").lower()
        data = type_data.get(vt, {"cve_refs": [], "exploit_refs": []})
        f["cve_refs"] = data["cve_refs"]
        f["exploit_refs"] = data["exploit_refs"]
        f["cvss_score"] = _highest_cvss(data["cve_refs"])

    return findings
