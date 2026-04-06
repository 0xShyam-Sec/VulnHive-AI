"""
WHOIS + DNS Record Enumeration — Deep domain intelligence gathering.

Gathers:
  1. WHOIS data — registrar, creation/expiry dates, nameservers, registrant org
  2. DNS records — A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, PTR
  3. TXT record analysis — SPF configs, DKIM selectors, domain verification tokens
  4. Reverse DNS — PTR records for discovered IPs
  5. Nameserver analysis — NS delegation chain, zone transfer attempt

Usage:
    from discovery.whois_dns import WHOISDNSRecon
    recon = WHOISDNSRecon("example.com")
    result = recon.run()
"""

import re
import subprocess
import socket
from urllib.parse import urlparse
from rich.console import Console

import httpx

console = Console()


# ── Known verification token patterns in TXT records ─────────────────────────

TXT_PATTERNS = {
    "spf": {
        "pattern": r"v=spf1\s+(.+)",
        "description": "SPF (Sender Policy Framework) — authorized mail senders",
        "severity": "Info",
    },
    "dmarc": {
        "pattern": r"v=DMARC1[;\s]+(.+)",
        "description": "DMARC policy — email authentication enforcement",
        "severity": "Info",
    },
    "dkim": {
        "pattern": r"v=DKIM1[;\s]+(.+)",
        "description": "DKIM signing key — email signature verification",
        "severity": "Info",
    },
    "google_verify": {
        "pattern": r"google-site-verification[=:](.+)",
        "description": "Google domain verification token",
        "severity": "Low",
    },
    "facebook_verify": {
        "pattern": r"facebook-domain-verification[=:](.+)",
        "description": "Facebook domain verification token",
        "severity": "Low",
    },
    "microsoft_verify": {
        "pattern": r"MS=ms\d+",
        "description": "Microsoft 365 domain verification token",
        "severity": "Low",
    },
    "docusign_verify": {
        "pattern": r"docusign=[\w-]+",
        "description": "DocuSign domain verification token",
        "severity": "Low",
    },
    "atlassian_verify": {
        "pattern": r"atlassian-domain-verification=[\w]+",
        "description": "Atlassian domain verification token",
        "severity": "Low",
    },
    "globalsign_verify": {
        "pattern": r"globalsign-domain-verification=[\w-]+",
        "description": "GlobalSign domain verification token",
        "severity": "Low",
    },
    "apple_verify": {
        "pattern": r"apple-domain-verification=[\w]+",
        "description": "Apple domain verification token",
        "severity": "Low",
    },
    "zoom_verify": {
        "pattern": r"ZOOM_verify_[\w]+",
        "description": "Zoom domain verification token",
        "severity": "Low",
    },
    "stripe_verify": {
        "pattern": r"stripe-verification=[\w]+",
        "description": "Stripe domain verification token",
        "severity": "Low",
    },
    "aws_ses": {
        "pattern": r"amazonses:[\w]+",
        "description": "AWS SES email verification",
        "severity": "Low",
    },
    "mailgun": {
        "pattern": r"mailgun",
        "description": "Mailgun email service",
        "severity": "Low",
    },
    "sendgrid": {
        "pattern": r"sendgrid",
        "description": "SendGrid email service",
        "severity": "Low",
    },
    "hubspot": {
        "pattern": r"hs-verification=[\w]+",
        "description": "HubSpot domain verification",
        "severity": "Low",
    },
    "have_i_been_pwned": {
        "pattern": r"have-i-been-pwned-verification=[\w]+",
        "description": "Have I Been Pwned verification",
        "severity": "Low",
    },
}

# ── SPF mechanism analysis ───────────────────────────────────────────────────

SPF_ISSUES = {
    "+all": ("SPF allows ALL senders — email spoofing possible", "High"),
    "~all": ("SPF soft-fails unknown senders — spoofing may succeed against permissive receivers", "Medium"),
    "?all": ("SPF neutral on unknown senders — provides no real protection", "Medium"),
    # "-all" is correct/secure — no issue
}


def _extract_domain(url: str) -> str:
    """Extract domain from URL."""
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path
    if ":" in hostname:
        hostname = hostname.split(":")[0]
    return hostname


def _extract_base_domain(hostname: str) -> str:
    """Get base domain (e.g., sub.example.com → example.com)."""
    parts = hostname.split(".")
    if len(parts) < 2:
        return hostname
    if len(parts) >= 3 and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class WHOISDNSRecon:
    """WHOIS and DNS record enumeration engine."""

    def __init__(self, target: str, timeout: int = 10):
        if target.startswith("http"):
            self.hostname = _extract_domain(target)
        else:
            self.hostname = target
        self.base_domain = _extract_base_domain(self.hostname)
        self.timeout = timeout

    def run(self) -> dict:
        """
        Run full WHOIS + DNS recon.

        Returns:
            {
                "domain": str,
                "whois": {...},
                "dns_records": {"A": [...], "MX": [...], ...},
                "txt_analysis": [...],
                "spf_analysis": {...},
                "nameserver_info": {...},
                "findings": [...],
            }
        """
        console.print(f"  [cyan]WHOIS/DNS Recon: {self.base_domain}[/]")

        findings = []
        result = {
            "domain": self.base_domain,
            "whois": {},
            "dns_records": {},
            "txt_analysis": [],
            "spf_analysis": {},
            "nameserver_info": {},
            "findings": findings,
        }

        # Phase 1: WHOIS lookup
        console.print("  [dim]Phase 1: WHOIS lookup...[/]")
        result["whois"] = self._whois_lookup()
        if result["whois"].get("registrar"):
            console.print(
                f"  [dim]  Registrar: {result['whois']['registrar']} | "
                f"Created: {result['whois'].get('creation_date', 'N/A')} | "
                f"Expires: {result['whois'].get('expiry_date', 'N/A')}[/]"
            )

        # Phase 2: DNS record enumeration
        console.print("  [dim]Phase 2: DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA)...[/]")
        result["dns_records"] = self._enumerate_dns()
        for rtype, records in result["dns_records"].items():
            if records:
                console.print(f"  [dim]  {rtype}: {len(records)} record(s)[/]")

        # Phase 3: TXT record analysis
        console.print("  [dim]Phase 3: TXT record deep analysis...[/]")
        txt_analysis = self._analyze_txt_records(result["dns_records"].get("TXT", []))
        result["txt_analysis"] = txt_analysis

        for item in txt_analysis:
            console.print(f"    [dim]{item['type']}: {item['description']}[/]")
            findings.append({
                "vuln_type": "dns_txt_disclosure",
                "url": self.base_domain,
                "method": "DNS",
                "param_name": "",
                "payload": f"TXT: {item['raw'][:100]}",
                "evidence": f"{item['description']}: {item['detail']}",
                "severity": item["severity"],
                "source": "whois-dns-recon",
                "validated": True,
            })

        # Phase 4: SPF analysis
        spf_records = [r for r in result["dns_records"].get("TXT", []) if r.startswith("v=spf1")]
        if spf_records:
            spf_analysis = self._analyze_spf(spf_records[0])
            result["spf_analysis"] = spf_analysis
            if spf_analysis.get("issues"):
                for issue in spf_analysis["issues"]:
                    findings.append({
                        "vuln_type": "spf_misconfiguration",
                        "url": self.base_domain,
                        "method": "DNS",
                        "param_name": "",
                        "payload": f"SPF: {spf_records[0][:100]}",
                        "evidence": issue["detail"],
                        "severity": issue["severity"],
                        "source": "whois-dns-recon",
                        "validated": True,
                    })
                    console.print(
                        f"    [yellow]SPF issue: {issue['detail']}[/]"
                    )

        # Phase 5: DMARC check
        console.print("  [dim]Phase 5: DMARC check...[/]")
        dmarc = self._check_dmarc()
        if dmarc:
            result["dns_records"]["DMARC"] = [dmarc]
            if "p=none" in dmarc:
                findings.append({
                    "vuln_type": "dmarc_policy_none",
                    "url": self.base_domain,
                    "method": "DNS",
                    "param_name": "",
                    "payload": f"DMARC: {dmarc[:100]}",
                    "evidence": "DMARC policy is 'none' — no email spoofing protection enforced",
                    "severity": "Medium",
                    "source": "whois-dns-recon",
                    "validated": True,
                })
                console.print("    [yellow]DMARC policy=none (no enforcement)[/]")
        else:
            findings.append({
                "vuln_type": "dmarc_missing",
                "url": self.base_domain,
                "method": "DNS",
                "param_name": "",
                "payload": "No DMARC record",
                "evidence": "No DMARC record found — domain is vulnerable to email spoofing",
                "severity": "Medium",
                "source": "whois-dns-recon",
                "validated": True,
            })
            console.print("    [yellow]No DMARC record — email spoofing possible[/]")

        # Phase 6: Nameserver analysis
        console.print("  [dim]Phase 6: Nameserver analysis...[/]")
        ns_info = self._analyze_nameservers(result["dns_records"].get("NS", []))
        result["nameserver_info"] = ns_info

        # Phase 7: Reverse DNS on A records
        a_records = result["dns_records"].get("A", [])
        if a_records:
            console.print(f"  [dim]Phase 7: Reverse DNS on {len(a_records)} IP(s)...[/]")
            ptr_records = self._reverse_dns(a_records)
            if ptr_records:
                result["dns_records"]["PTR"] = ptr_records
                console.print(f"  [dim]  PTR: {len(ptr_records)} record(s)[/]")

        # Phase 8: WHOIS findings
        whois = result["whois"]
        if whois.get("expiry_date"):
            try:
                from datetime import datetime
                expiry = whois["expiry_date"]
                # Try to parse common date formats
                for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y"):
                    try:
                        exp_date = datetime.strptime(expiry, fmt)
                        days_left = (exp_date - datetime.now()).days
                        if 0 < days_left < 30:
                            findings.append({
                                "vuln_type": "domain_expiry_soon",
                                "url": self.base_domain,
                                "method": "WHOIS",
                                "param_name": "",
                                "payload": f"Expires: {expiry}",
                                "evidence": f"Domain expires in {days_left} days — risk of domain takeover if not renewed",
                                "severity": "High",
                                "source": "whois-dns-recon",
                                "validated": True,
                            })
                        break
                    except ValueError:
                        continue
            except Exception:
                pass

        console.print(
            f"  [bold green][WHOIS/DNS] "
            f"Records: {sum(len(v) for v in result['dns_records'].values())} | "
            f"TXT tokens: {len(txt_analysis)} | "
            f"Findings: {len(findings)}[/]"
        )

        result["findings"] = findings
        return result

    # ── WHOIS Lookup ─────────────────────────────────────────────────────

    def _whois_lookup(self) -> dict:
        """Run WHOIS lookup and parse key fields."""
        whois_data = {
            "registrar": None,
            "creation_date": None,
            "expiry_date": None,
            "updated_date": None,
            "nameservers": [],
            "registrant_org": None,
            "registrant_country": None,
            "dnssec": None,
            "status": [],
            "raw": "",
        }

        try:
            result = subprocess.run(
                ["whois", self.base_domain],
                capture_output=True, text=True, timeout=15,
            )
            raw = result.stdout
            whois_data["raw"] = raw[:5000]

            # Parse key fields (handles different WHOIS formats)
            patterns = {
                "registrar": [
                    r"Registrar:\s*(.+)",
                    r"registrar:\s*(.+)",
                    r"Sponsoring Registrar:\s*(.+)",
                ],
                "creation_date": [
                    r"Creation Date:\s*(.+)",
                    r"created:\s*(.+)",
                    r"Registration Date:\s*(.+)",
                    r"Created On:\s*(.+)",
                ],
                "expiry_date": [
                    r"(?:Registry |Registrar )?Expir(?:y|ation) Date:\s*(.+)",
                    r"expires:\s*(.+)",
                    r"Expiration Date:\s*(.+)",
                    r"paid-till:\s*(.+)",
                ],
                "updated_date": [
                    r"Updated Date:\s*(.+)",
                    r"last-modified:\s*(.+)",
                    r"Last Updated:\s*(.+)",
                ],
                "registrant_org": [
                    r"Registrant Organization:\s*(.+)",
                    r"org-name:\s*(.+)",
                    r"Registrant:\s*(.+)",
                ],
                "registrant_country": [
                    r"Registrant Country:\s*(.+)",
                    r"country:\s*(.+)",
                ],
                "dnssec": [
                    r"DNSSEC:\s*(.+)",
                    r"dnssec:\s*(.+)",
                ],
            }

            for field, regexes in patterns.items():
                for regex in regexes:
                    match = re.search(regex, raw, re.IGNORECASE)
                    if match:
                        whois_data[field] = match.group(1).strip()
                        break

            # Extract nameservers
            ns_matches = re.findall(r"Name Server:\s*(\S+)", raw, re.IGNORECASE)
            if not ns_matches:
                ns_matches = re.findall(r"nserver:\s*(\S+)", raw, re.IGNORECASE)
            whois_data["nameservers"] = [ns.lower().rstrip(".") for ns in ns_matches]

            # Extract domain status
            status_matches = re.findall(r"(?:Domain )?Status:\s*(\S+)", raw, re.IGNORECASE)
            whois_data["status"] = status_matches[:10]

        except subprocess.TimeoutExpired:
            console.print("  [dim]WHOIS lookup timed out[/]")
        except FileNotFoundError:
            console.print("  [dim]whois command not available[/]")
        except Exception as e:
            console.print(f"  [dim]WHOIS error: {e}[/]")

        return whois_data

    # ── DNS Record Enumeration ───────────────────────────────────────────

    def _enumerate_dns(self) -> dict[str, list[str]]:
        """Enumerate all DNS record types."""
        records: dict[str, list[str]] = {}
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA"]

        for rtype in record_types:
            try:
                result = subprocess.run(
                    ["dig", "+short", rtype, self.base_domain],
                    capture_output=True, text=True, timeout=5,
                )
                lines = []
                for line in result.stdout.strip().splitlines():
                    val = line.strip().rstrip(".")
                    if val:
                        # For MX, strip priority number
                        if rtype == "MX":
                            parts = val.split()
                            val = parts[-1].rstrip(".") if len(parts) >= 2 else val
                        # For TXT, strip outer quotes
                        if rtype == "TXT":
                            val = val.strip('"')
                        lines.append(val)
                if lines:
                    records[rtype] = lines
            except Exception:
                continue

        # Also try AXFR zone transfer on NS records
        for ns in records.get("NS", [])[:2]:
            try:
                result = subprocess.run(
                    ["dig", "AXFR", self.base_domain, f"@{ns}"],
                    capture_output=True, text=True, timeout=10,
                )
                if "Transfer failed" not in result.stdout and "XFR size" in result.stdout:
                    records["AXFR"] = [f"Zone transfer succeeded via {ns}!"]
                    # This is a critical finding
            except Exception:
                continue

        return records

    # ── TXT Record Analysis ──────────────────────────────────────────────

    def _analyze_txt_records(self, txt_records: list[str]) -> list[dict]:
        """Deep analysis of TXT records for tokens, configs, and information leakage."""
        analysis = []

        for record in txt_records:
            record_lower = record.lower()

            for token_name, info in TXT_PATTERNS.items():
                match = re.search(info["pattern"], record, re.IGNORECASE)
                if match:
                    analysis.append({
                        "type": token_name,
                        "description": info["description"],
                        "detail": match.group(0)[:200],
                        "severity": info["severity"],
                        "raw": record[:200],
                    })
                    break
            else:
                # Unknown TXT record — still worth noting
                if len(record) > 10 and not record.startswith("v=spf1"):
                    analysis.append({
                        "type": "unknown_txt",
                        "description": "Unclassified TXT record",
                        "detail": record[:200],
                        "severity": "Info",
                        "raw": record[:200],
                    })

        return analysis

    # ── SPF Analysis ─────────────────────────────────────────────────────

    def _analyze_spf(self, spf_record: str) -> dict:
        """Analyze SPF record for misconfigurations."""
        result = {
            "raw": spf_record,
            "mechanisms": [],
            "includes": [],
            "all_policy": None,
            "issues": [],
            "ip_ranges": [],
        }

        parts = spf_record.split()
        for part in parts:
            part_lower = part.lower()

            # Extract include domains
            if part_lower.startswith("include:"):
                result["includes"].append(part[8:])
                result["mechanisms"].append(part)

            # Extract IP ranges
            elif part_lower.startswith("ip4:") or part_lower.startswith("ip6:"):
                result["ip_ranges"].append(part[4:])
                result["mechanisms"].append(part)

            # Check 'all' policy
            elif part_lower.endswith("all"):
                result["all_policy"] = part
                result["mechanisms"].append(part)

                if part_lower in SPF_ISSUES:
                    detail, severity = SPF_ISSUES[part_lower]
                    result["issues"].append({
                        "detail": detail,
                        "severity": severity,
                    })

            elif part_lower.startswith(("a:", "mx:", "ptr:", "a", "mx")):
                result["mechanisms"].append(part)

        # Check for too many DNS lookups (>10 is a hard fail per RFC 7208)
        dns_lookup_count = len(result["includes"]) + sum(
            1 for m in result["mechanisms"]
            if m.lower().startswith(("a:", "mx:", "ptr:", "exists:", "redirect="))
        )
        if dns_lookup_count > 10:
            result["issues"].append({
                "detail": f"SPF has {dns_lookup_count} DNS lookups (RFC 7208 limit is 10) — may cause permanent failures",
                "severity": "Medium",
            })

        return result

    # ── DMARC Check ──────────────────────────────────────────────────────

    def _check_dmarc(self) -> str | None:
        """Check for DMARC record at _dmarc.domain."""
        try:
            result = subprocess.run(
                ["dig", "+short", "TXT", f"_dmarc.{self.base_domain}"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.strip().splitlines():
                val = line.strip().strip('"')
                if val.lower().startswith("v=dmarc1"):
                    return val
        except Exception:
            pass
        return None

    # ── Nameserver Analysis ──────────────────────────────────────────────

    def _analyze_nameservers(self, ns_records: list[str]) -> dict:
        """Analyze nameservers for hosting info and delegation."""
        info = {
            "nameservers": ns_records,
            "providers": [],
            "all_same_provider": False,
        }

        ns_providers = {
            "cloudflare": "Cloudflare DNS",
            "awsdns": "AWS Route 53",
            "google": "Google Cloud DNS",
            "azure": "Azure DNS",
            "domaincontrol": "GoDaddy",
            "name-services": "GoDaddy",
            "registrar-servers": "Namecheap",
            "hostinger": "Hostinger",
            "digitalocean": "DigitalOcean DNS",
            "linode": "Linode DNS",
            "vultr": "Vultr DNS",
            "hetzner": "Hetzner DNS",
            "ns.dynect": "Oracle Dyn",
            "ultradns": "UltraDNS",
            "dnsmadeeasy": "DNS Made Easy",
        }

        detected = set()
        for ns in ns_records:
            ns_lower = ns.lower()
            for pattern, provider in ns_providers.items():
                if pattern in ns_lower:
                    detected.add(provider)
                    break

        info["providers"] = sorted(detected)
        info["all_same_provider"] = len(detected) <= 1 and len(ns_records) > 0

        return info

    # ── Reverse DNS ──────────────────────────────────────────────────────

    def _reverse_dns(self, ips: list[str]) -> list[dict]:
        """Reverse DNS lookup on IP addresses."""
        ptr_records = []
        for ip in ips[:10]:
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                ptr_records.append({"ip": ip, "hostname": hostname})
            except (socket.herror, socket.gaierror, OSError):
                continue
        return ptr_records


# ═══════════════════════════════════════════════════════════════════════════════
# Integration helper — register as discovery function
# ═══════════════════════════════════════════════════════════════════════════════

def run_whois_dns_recon(target: str, config, state) -> dict:
    """
    Discovery function compatible with engine.register_discovery().
    Runs WHOIS + DNS recon and stores results on state.
    """
    recon = WHOISDNSRecon(target)
    result = recon.run()

    # Store on state
    with state._lock:
        state.whois_dns = {
            "domain": result["domain"],
            "whois": result["whois"],
            "dns_records": result["dns_records"],
            "txt_analysis": result["txt_analysis"],
            "spf_analysis": result["spf_analysis"],
            "nameserver_info": result["nameserver_info"],
        }

    # Add findings to state
    for finding in result.get("findings", []):
        state.add_finding(finding)

    return result
