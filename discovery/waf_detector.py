"""
WAF Detector — Advanced Web Application Firewall fingerprinting.

Detects 25+ WAFs via:
  1. Header fingerprinting — specific headers/values each WAF adds
  2. Cookie fingerprinting — WAF-specific cookies
  3. Error page analysis — trigger WAF with malicious payloads, fingerprint the block page
  4. Response behavior — timing, status codes, body signatures
  5. Bypass strategy mapping — maps detected WAF to known bypass techniques

Results stored on state.waf_info for use by payload_engine and vuln agents.

Usage:
    from discovery.waf_detector import WAFDetector
    detector = WAFDetector("https://target.com")
    result = detector.detect()
    # result = {
    #   "detected": True,
    #   "waf_name": "Cloudflare",
    #   "confidence": "high",
    #   "evidence": [...],
    #   "bypass_hints": [...],
    # }
"""

import re
import time
from urllib.parse import urljoin
from rich.console import Console

import httpx

console = Console()


# ═══════════════════════════════════════════════════════════════════════════════
# WAF Fingerprint Database (25+ WAFs)
# ═══════════════════════════════════════════════════════════════════════════════

WAF_FINGERPRINTS = {
    # ── CDN / Cloud WAFs ─────────────────────────────────────────────────
    "Cloudflare": {
        "headers": {"cf-ray": None, "cf-cache-status": None, "cf-request-id": None},
        "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
        "server": ["cloudflare"],
        "body_signatures": ["attention required! | cloudflare", "ray id:", "cloudflare ray id"],
        "status_on_block": [403, 503],
        "bypass_hints": [
            "Try origin IP bypass (find real IP via DNS history, Shodan, Censys)",
            "Use HTTP/1.0 without Host header",
            "Chunked transfer encoding may bypass body inspection",
            "Unicode normalization: %u003C instead of <",
        ],
    },
    "AWS WAF": {
        "headers": {"x-amzn-requestid": None, "x-amz-apigw-id": None, "x-amzn-trace-id": None},
        "cookies": ["awsalb", "awsalbcors", "aws-waf-token"],
        "server": [],
        "body_signatures": ["request blocked", "aws waf", "automated request"],
        "status_on_block": [403],
        "bypass_hints": [
            "AWS WAF rules are regex-based — try case alternation (sElEcT)",
            "JSON content-type with SQL in values may bypass",
            "Overlong UTF-8 encoding",
            "HTTP parameter pollution (HPP)",
        ],
    },
    "Akamai (Kona/Ghost)": {
        "headers": {"x-akamai-transformed": None, "akamai-grn": None},
        "cookies": ["akamai_", "ak_bmsc", "bm_sz", "bm_sv", "_abck"],
        "server": ["akamaighost", "akamai"],
        "body_signatures": ["access denied", "reference #", "akamai"],
        "status_on_block": [403],
        "bypass_hints": [
            "Akamai inspects first 8KB — pad payload past 8KB boundary",
            "Try null bytes in parameters",
            "HTTP/2 pseudo-headers may bypass",
            "Multipart form-data with boundary manipulation",
        ],
    },
    "Imperva (Incapsula)": {
        "headers": {"x-iinfo": None, "x-cdn": "imperva|incapsula"},
        "cookies": ["visid_incap_", "incap_ses_", "nlbi_", "reese84"],
        "server": [],
        "body_signatures": [
            "powered by incapsula", "incapsula incident id",
            "request unsuccessful", "imperva",
        ],
        "status_on_block": [403],
        "bypass_hints": [
            "Imperva has JS challenge — headless browsers may help",
            "Try X-Forwarded-For spoofing",
            "Double URL encoding",
            "Inline comments in SQL: /*!SELECT*/",
        ],
    },
    "Fastly": {
        "headers": {"x-served-by": None, "x-cache": None, "x-fastly-request-id": None},
        "cookies": [],
        "server": ["fastly"],
        "body_signatures": ["fastly error: unknown domain", "fastly error"],
        "status_on_block": [403, 503],
        "bypass_hints": [
            "Fastly uses VCL — test different Content-Types",
            "Try request smuggling via CL/TE",
        ],
    },
    "Sucuri": {
        "headers": {"x-sucuri-id": None, "x-sucuri-cache": None},
        "cookies": ["sucuri_cloudproxy_"],
        "server": ["sucuri", "sucuri/cloudproxy"],
        "body_signatures": [
            "access denied - sucuri", "sucuri website firewall",
            "cloudproxy", "sucuri cloudproxy",
        ],
        "status_on_block": [403],
        "bypass_hints": [
            "Find origin IP — Sucuri is a reverse proxy",
            "Try XSS payloads without < > (event handlers in existing tags)",
        ],
    },

    # ── Server-level WAFs ────────────────────────────────────────────────
    "ModSecurity (OWASP CRS)": {
        "headers": {"x-modsecurity-error": None, "x-modsecurity-id": None},
        "cookies": [],
        "server": ["mod_security", "modsecurity"],
        "body_signatures": [
            "modsecurity", "mod_security", "not acceptable",
            "this error was generated by mod_security",
            "request denied by modsecurity",
        ],
        "status_on_block": [403, 406, 501],
        "bypass_hints": [
            "CRS paranoia level 1-2: try URL-encoded payloads",
            "Use comments to break SQL keywords: SEL/**/ECT",
            "Try different HTTP methods (PUT instead of POST)",
            "Multipart file upload with payload in filename",
        ],
    },
    "F5 BIG-IP ASM": {
        "headers": {"x-wa-info": None, "x-cnection": None},
        "cookies": ["ts", "bigipserver", "bigipserverpool", "f5_cspm"],
        "server": ["bigip"],
        "body_signatures": [
            "the requested url was rejected",
            "please consult with your administrator",
            "your support id is",
            "big-ip",
        ],
        "status_on_block": [403],
        "bypass_hints": [
            "F5 ASM is signature-based — try polyglot payloads",
            "JSON-formatted payloads may bypass",
            "Try HPP with duplicate parameters",
        ],
    },

    # ── Hosting / Platform WAFs ──────────────────────────────────────────
    "Azure Front Door / WAF": {
        "headers": {"x-azure-ref": None, "x-fd-healthprobe": None, "x-ms-request-id": None},
        "cookies": [],
        "server": [],
        "body_signatures": ["azure front door", "request blocked by azure"],
        "status_on_block": [403, 503],
        "bypass_hints": [
            "Azure WAF uses OWASP CRS — same bypasses as ModSecurity",
            "Try wildcard (*) in CSP header bypass",
        ],
    },
    "Google Cloud Armor": {
        "headers": {},
        "cookies": [],
        "server": ["gws", "gfe"],
        "body_signatures": ["google cloud armor", "request blocked"],
        "status_on_block": [403],
        "bypass_hints": [
            "Cloud Armor is ML-based — try encoding obfuscation",
            "Chunked transfer with partial payloads",
        ],
    },
    "Barracuda WAF": {
        "headers": {"barra_counter_session": None},
        "cookies": ["barra_counter_session", "bNVR_"],
        "server": ["barracuda"],
        "body_signatures": ["barracuda", "barra_counter_session"],
        "status_on_block": [403],
        "bypass_hints": [
            "Barracuda is regex-based — try case mixing",
            "URL encoding tricks",
        ],
    },
    "Fortinet FortiWeb": {
        "headers": {"fortiwafsid": None},
        "cookies": ["cookiesession1", "fortiwafsid"],
        "server": ["fortiweb"],
        "body_signatures": ["fortiweb", "fortigate", ".fgtres"],
        "status_on_block": [403],
        "bypass_hints": [
            "FortiWeb uses anomaly scoring — spread payload across parameters",
            "Try non-standard encodings",
        ],
    },
    "Citrix NetScaler AppFirewall": {
        "headers": {"cneonction": None, "nncoection": None, "ns_af": None},
        "cookies": ["citrix_ns_id", "nsc_", "ns_af"],
        "server": ["netscaler"],
        "body_signatures": ["ns_af_", "appfw", "netscaler"],
        "status_on_block": [302, 403],
        "bypass_hints": [
            "NetScaler has known HPP bypass",
            "Try double-encoding",
        ],
    },
    "Radware AppWall / DefensePro": {
        "headers": {"x-slr-d": None},
        "cookies": ["rdwr_"],
        "server": [],
        "body_signatures": ["radware", "unauthorized activity"],
        "status_on_block": [403],
        "bypass_hints": ["Try IP rotation", "Slowloris-style slow requests"],
    },

    # ── CMS / App-level WAFs ────────────────────────────────────────────
    "Wordfence (WordPress)": {
        "headers": {},
        "cookies": ["wfvt_", "wordfence_"],
        "server": [],
        "body_signatures": [
            "generated by wordfence", "this response was generated by wordfence",
            "your access to this site has been limited",
        ],
        "status_on_block": [403, 503],
        "bypass_hints": [
            "Wordfence Free has no real-time IP blacklisting — rotate IPs",
            "Try WordPress REST API endpoints directly",
        ],
    },
    "Comodo WAF": {
        "headers": {},
        "cookies": [],
        "server": ["comodo"],
        "body_signatures": ["protected by comodo"],
        "status_on_block": [403],
        "bypass_hints": ["Comodo is signature-based — try encoding"],
    },
    "DenyAll": {
        "headers": {},
        "cookies": ["sessioncookie", "denyall"],
        "server": [],
        "body_signatures": ["conditionblocked", "denyall"],
        "status_on_block": [403],
        "bypass_hints": [],
    },
    "SonicWall": {
        "headers": {},
        "cookies": ["sonicwall"],
        "server": ["sonicwall"],
        "body_signatures": ["web site is temporarily unavailable", "sonicwall"],
        "status_on_block": [403],
        "bypass_hints": [],
    },
    "Palo Alto Next-Gen": {
        "headers": {},
        "cookies": [],
        "server": [],
        "body_signatures": ["has been blocked in accordance with company policy"],
        "status_on_block": [403],
        "bypass_hints": ["Next-gen firewalls inspect L7 — try encrypted channels"],
    },
    "Safe3 WAF": {
        "headers": {},
        "cookies": ["safe3_"],
        "server": ["safe3"],
        "body_signatures": ["safe3waf"],
        "status_on_block": [403],
        "bypass_hints": [],
    },
    "WebKnight": {
        "headers": {},
        "cookies": [],
        "server": ["webknight"],
        "body_signatures": ["webknight", "aqtronix"],
        "status_on_block": [403, 999],
        "bypass_hints": ["WebKnight is very old — most modern bypasses work"],
    },
    "Wallarm": {
        "headers": {"x-wallarm-waf-check": None},
        "cookies": [],
        "server": [],
        "body_signatures": ["wallarm", "nginx-wallarm"],
        "status_on_block": [403],
        "bypass_hints": ["Wallarm uses AI — try novel payload structures"],
    },
    "Reblaze": {
        "headers": {"x-rb-req-id": None},
        "cookies": ["rbzid", "rbzsessionid"],
        "server": ["reblaze"],
        "body_signatures": ["reblaze"],
        "status_on_block": [403],
        "bypass_hints": [],
    },
    "StackPath": {
        "headers": {"x-sp-url": None, "x-sp-waf-action": None},
        "cookies": [],
        "server": ["stackpath"],
        "body_signatures": ["stackpath"],
        "status_on_block": [403],
        "bypass_hints": [],
    },
    "Edgecast (Verizon Digital Media)": {
        "headers": {"x-ec-custom-error": None},
        "cookies": [],
        "server": ["ecs", "ecd"],
        "body_signatures": [],
        "status_on_block": [403],
        "bypass_hints": [],
    },
}

# ── Probe payloads — different attack types to trigger different WAF rules ────

TRIGGER_PAYLOADS = [
    # XSS probes
    ("xss_basic", "?test=<script>alert(1)</script>"),
    ("xss_event", "?test=<img/src=x onerror=alert(1)>"),
    ("xss_svg", "?test=<svg/onload=alert(1)>"),
    # SQLi probes
    ("sqli_basic", "?id=1' OR '1'='1"),
    ("sqli_union", "?id=1 UNION SELECT NULL--"),
    # Path traversal
    ("lfi", "?file=../../../etc/passwd"),
    # Command injection
    ("cmdi", "?cmd=;cat /etc/passwd"),
    # General malicious
    ("ua_bot", None),  # Special: uses malicious User-Agent
]


class WAFDetector:
    """
    Advanced WAF detection engine.

    Detection pipeline:
      1. Passive header/cookie fingerprinting on normal response
      2. Active probing — send trigger payloads and fingerprint block pages
      3. Behavioral analysis — compare response times and patterns
      4. Map detected WAF to bypass strategies
    """

    def __init__(self, target_url: str, timeout: int = 10):
        self.target = target_url.rstrip("/")
        self.timeout = timeout
        self.client = httpx.Client(
            timeout=timeout, follow_redirects=True, verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )

    def detect(self) -> dict:
        """
        Run full WAF detection pipeline.

        Returns:
            {
                "detected": bool,
                "waf_name": str | None,
                "waf_names": [str],  # multiple WAFs possible (CDN + app WAF)
                "confidence": "high" | "medium" | "low" | None,
                "evidence": [{"method": str, "detail": str}],
                "bypass_hints": [str],
                "block_behavior": {"status_codes": [int], "block_page_size": int},
                "raw_headers": dict,
            }
        """
        console.print(f"  [cyan]WAF Detector: fingerprinting {self.target}...[/]")

        result = {
            "detected": False,
            "waf_name": None,
            "waf_names": [],
            "confidence": None,
            "evidence": [],
            "bypass_hints": [],
            "block_behavior": {},
            "raw_headers": {},
        }

        # Phase 1: Passive — fingerprint normal response
        baseline = self._get_baseline()
        if not baseline:
            console.print("  [yellow]WAF Detector: target unreachable[/]")
            return result

        result["raw_headers"] = dict(baseline.headers)
        passive_matches = self._passive_fingerprint(baseline)

        # Phase 2: Active — send trigger payloads
        active_matches = self._active_probe(baseline)

        # Phase 3: Combine results
        all_matches: dict[str, list] = {}
        for waf_name, evidence_list in {**passive_matches, **active_matches}.items():
            if waf_name not in all_matches:
                all_matches[waf_name] = []
            all_matches[waf_name].extend(evidence_list)

        if all_matches:
            result["detected"] = True

            # Sort by evidence count (most evidence = primary WAF)
            sorted_wafs = sorted(all_matches.items(), key=lambda x: len(x[1]), reverse=True)
            result["waf_name"] = sorted_wafs[0][0]
            result["waf_names"] = [name for name, _ in sorted_wafs]

            # Confidence based on evidence count
            primary_evidence = len(sorted_wafs[0][1])
            if primary_evidence >= 3:
                result["confidence"] = "high"
            elif primary_evidence >= 2:
                result["confidence"] = "medium"
            else:
                result["confidence"] = "low"

            # Collect all evidence
            for waf_name, evidences in sorted_wafs:
                for ev in evidences:
                    result["evidence"].append({"waf": waf_name, **ev})

            # Collect bypass hints
            for waf_name, _ in sorted_wafs:
                fp = WAF_FINGERPRINTS.get(waf_name, {})
                result["bypass_hints"].extend(fp.get("bypass_hints", []))

            waf_str = " + ".join(result["waf_names"])
            console.print(
                f"  [bold yellow]WAF Detected: {waf_str} "
                f"(confidence: {result['confidence']})[/]"
            )
            if result["bypass_hints"]:
                console.print(f"  [dim]Bypass hints: {len(result['bypass_hints'])} strategies loaded[/]")
        else:
            console.print("  [dim]WAF Detector: no WAF detected[/]")

        return result

    def _get_baseline(self) -> httpx.Response | None:
        """Get baseline response from normal request."""
        try:
            return self.client.get(self.target)
        except Exception:
            return None

    def _passive_fingerprint(self, resp: httpx.Response) -> dict[str, list]:
        """Fingerprint WAF from headers, cookies, and server on a normal response."""
        matches: dict[str, list] = {}
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        cookies = {k.lower(): v for k, v in resp.cookies.items()}
        server = headers.get("server", "")

        for waf_name, fp in WAF_FINGERPRINTS.items():
            evidence = []

            # Header matching
            for header_name, header_pattern in fp.get("headers", {}).items():
                header_name = header_name.lower()
                if header_name in headers:
                    if header_pattern is None:
                        evidence.append({
                            "method": "header",
                            "detail": f"Header '{header_name}' present: {headers[header_name][:80]}",
                        })
                    elif re.search(header_pattern, headers[header_name]):
                        evidence.append({
                            "method": "header",
                            "detail": f"Header '{header_name}' matches pattern: {header_pattern}",
                        })

            # Cookie matching
            for cookie_pattern in fp.get("cookies", []):
                cookie_pattern = cookie_pattern.lower()
                for cookie_name in cookies:
                    if cookie_pattern in cookie_name:
                        evidence.append({
                            "method": "cookie",
                            "detail": f"Cookie '{cookie_name}' matches WAF pattern '{cookie_pattern}'",
                        })
                        break

            # Server header matching
            for server_sig in fp.get("server", []):
                if server_sig.lower() in server:
                    evidence.append({
                        "method": "server",
                        "detail": f"Server header '{server}' matches '{server_sig}'",
                    })

            if evidence:
                matches[waf_name] = evidence

        return matches

    def _active_probe(self, baseline: httpx.Response) -> dict[str, list]:
        """Send malicious payloads and fingerprint block responses."""
        matches: dict[str, list] = {}
        baseline_status = baseline.status_code
        baseline_size = len(baseline.text)
        block_statuses = set()
        block_page_size = 0

        for probe_name, payload_path in TRIGGER_PAYLOADS:
            try:
                if probe_name == "ua_bot":
                    # Send with bot-like User-Agent
                    resp = httpx.get(
                        self.target, timeout=self.timeout,
                        follow_redirects=True, verify=False,
                        headers={"User-Agent": "sqlmap/1.0 (http://sqlmap.org)"},
                    )
                else:
                    url = self.target + payload_path
                    resp = self.client.get(url)

                # Check if we got blocked
                if resp.status_code in (403, 406, 429, 501, 503) and resp.status_code != baseline_status:
                    block_statuses.add(resp.status_code)
                    block_page_size = len(resp.text)
                    body_lower = resp.text.lower()
                    headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}

                    # Fingerprint the block page
                    for waf_name, fp in WAF_FINGERPRINTS.items():
                        for sig in fp.get("body_signatures", []):
                            if sig in body_lower:
                                if waf_name not in matches:
                                    matches[waf_name] = []
                                matches[waf_name].append({
                                    "method": "block_page",
                                    "detail": (
                                        f"Probe '{probe_name}' blocked (HTTP {resp.status_code}), "
                                        f"body matches '{sig}'"
                                    ),
                                })
                                break

                        # Also check block response headers
                        for header_name, _ in fp.get("headers", {}).items():
                            if header_name.lower() in headers_lower:
                                if waf_name not in matches:
                                    matches[waf_name] = []
                                matches[waf_name].append({
                                    "method": "block_header",
                                    "detail": (
                                        f"Probe '{probe_name}' blocked, "
                                        f"header '{header_name}' in block response"
                                    ),
                                })
                                break

                    # If no specific WAF matched but we got blocked
                    if not any(waf in matches for waf in WAF_FINGERPRINTS):
                        if "Generic WAF" not in matches:
                            matches["Generic WAF"] = []
                        matches["Generic WAF"].append({
                            "method": "status_code",
                            "detail": (
                                f"Probe '{probe_name}' returned HTTP {resp.status_code} "
                                f"(baseline was {baseline_status})"
                            ),
                        })

            except Exception:
                continue

        # Store block behavior
        if block_statuses:
            self._block_behavior = {
                "status_codes": sorted(block_statuses),
                "block_page_size": block_page_size,
            }
        else:
            self._block_behavior = {}

        return matches

    def close(self):
        self.client.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Integration helper — run WAF detection and store on ScanState
# ═══════════════════════════════════════════════════════════════════════════════

def run_waf_detection(target: str, config, state) -> dict:
    """
    Discovery function compatible with engine.register_discovery().
    Runs WAF detection and stores results on state.waf_info.
    """
    detector = WAFDetector(target)
    result = detector.detect()
    detector.close()

    # Store on state
    with state._lock:
        state.waf_info = {
            "detected": result["detected"],
            "waf_name": result["waf_name"],
            "waf_names": result["waf_names"],
            "confidence": result["confidence"],
            "evidence": result["evidence"],
            "bypass_hints": result["bypass_hints"],
            "block_behavior": result.get("block_behavior", detector._block_behavior if hasattr(detector, '_block_behavior') else {}),
        }

    # Create informational finding
    if result["detected"]:
        state.add_finding({
            "vuln_type": "waf_detected",
            "url": target,
            "method": "GET",
            "param_name": "",
            "payload": "N/A (recon)",
            "evidence": (
                f"WAF: {' + '.join(result['waf_names'])} "
                f"(confidence: {result['confidence']}). "
                f"Evidence: {len(result['evidence'])} indicators. "
                f"Bypass strategies: {len(result['bypass_hints'])} loaded."
            ),
            "severity": "Info",
            "source": "waf-detector",
            "validated": True,
        })

    return result
