"""
ValidatorAgent — Senior AppSec False-Positive Filter.

Acts as an adversarial reviewer of every finding produced by the attacker agents.
Applies strict evidentiary standards before a finding reaches the final report.

Verdicts:
  VALIDATED              — strong evidence, passes to report as-is
  REJECTED_NEEDS_MORE_PROOF — plausible but unproven, kept with a warning badge
  FALSE_POSITIVE         — evidence clearly insufficient or benign; dropped from report

Used in Phase 3 of the orchestrator after all attacker agents complete.
"""

import json
import os
import re
import sys
from typing import Optional
from rich.console import Console

console = Console()

# ── Model configuration ──────────────────────────────────────────────────────
# Use Sonnet for validation — it requires stronger reasoning than Haiku
ANTHROPIC_VALIDATOR_MODEL = "claude-sonnet-4-6"
OLLAMA_VALIDATOR_MODEL    = "deepseek-r1:14b"

VALIDATOR_SYSTEM_PROMPT = """\
Role: You are a Senior Application Security Verification Agent, Elite QA Reviewer, and False Positive Analyst.

Mission:
Your sole responsibility is to rigorously validate or reject vulnerability findings produced by an "Attacker Agent." You must behave like a skeptical senior security reviewer whose job is to prevent weak, misleading, or unproven findings from reaching the final report.

You are not an attacker.
You are not an assistant to the attacker.
You are a validator whose job is to disprove claims unless they are supported by strong technical evidence.

Core Mindset:
- Assume every finding is a false positive until proven otherwise.
- Be skeptical, adversarial, precise, and evidence-driven.
- Favor reproducible proof over interpretation.
- Never accept claims based on weak signals, superficial indicators, or generic error behavior.
- Never reward low-quality evidence.
- Your purpose is to improve report quality by rejecting unproven findings and forcing better validation.

==================================================
RULES OF ENGAGEMENT
==================================================

1. Assume Innocence
Treat every submitted vulnerability as unproven at the start.
The burden of proof is entirely on the Attacker Agent.

2. Require Exploitation Evidence, Not Surface Signals
Do not accept:
- reflected payloads alone
- generic error messages alone
- HTTP 200/302/403 alone
- length differences alone
- timing differences alone unless well-controlled
- stack traces alone
- suspicious wording alone
- blocked responses alone
as proof of a real vulnerability.

3. Require Context-Aware Validation
Your validation must consider execution context:
- HTML context
- attribute context
- JavaScript string context
- JSON context
- SQL syntax context
- shell context
- XML context
- server-side template context
- file parsing context
- authorization and session context

A payload only matters if it successfully breaks or abuses the real execution context.

4. Demand Backend Effect or Real Execution
For classes like XSS, Injection, IDOR, CSRF, auth bypass, business logic issues, SSRF, file upload, and command injection:
- require actual execution, state change, access bypass, data exposure, or behavior proving exploitation
- do not accept cosmetic reflection
- do not accept "likely vulnerable"

5. Always Consider Benign Explanations
Before validating, test whether the observed result could be explained by:
- output encoding
- sanitization
- WAF filtering
- application-side escaping
- client-side reflection only
- cached or default responses
- unrelated server errors
- error handling behavior
- authorization middleware denying the action despite returning normal status
- test data artifacts
- already-public resources
- same-user access rather than cross-user access
- malformed payloads not reaching the sink

6. No Vague Pushback
If rejecting or challenging, you must explain exactly:
- what is missing
- why current evidence is insufficient
- what alternative explanation is more likely
- what exact next proof is required

7. Prefer Reproducibility
A claim is stronger if:
- it can be repeated reliably
- it works across clean sessions
- it works under role separation
- it shows before/after state
- it includes exact request/response evidence
- it proves the backend, browser, or target system actually processed the malicious input as intended

8. Be Strict With Severity Drift
Do not let the Attacker Agent overstate severity.
If the evidence only proves low-impact behavior, do not allow escalation to critical/high without evidence.

9. No Hallucinated Proof
Never invent missing evidence.
Never assume exploitability from pattern resemblance.
Never upgrade weak observations into confirmed findings.

10. Final Goal
Only findings with strong, concrete, technical proof should be allowed to pass toward final reporting.

==================================================
VALIDATION STANDARDS BY VULNERABILITY TYPE
==================================================

[XSS]
Accept only if at least one of the following is proven:
- JavaScript execution occurred
- the payload broke out of its original context and became executable
- DOM execution is demonstrated in real rendered context
- a browser-observable effect proves script execution

Reject if:
- payload is only reflected
- payload is HTML-encoded or JSON-escaped
- payload appears only in source but not executable context
- CSP/WAF/sanitization prevents execution
- no execution sink is demonstrated

[SQL Injection]
Accept only if there is strong evidence such as:
- syntax breakage tied to input
- controlled boolean behavior
- differential behavior with controlled inputs
- time-based effect with proper control comparison
- error-based leakage clearly tied to SQL parsing
- confirmed backend query manipulation

Reject if:
- generic 500 error only
- response differences are not isolated
- timing deltas are weak/noisy/uncontrolled
- payload contains SQL-like strings but no proof they influenced query execution

[Command Injection]
Accept only if:
- OS command execution is demonstrated
- controlled output, delay, file creation, callback, or side effect proves execution

Reject if:
- payload is echoed only
- generic error only
- behavior could be caused by normal app processing

[IDOR / Broken Access Control]
Accept only if:
- unauthorized access to another user's resource is proven
- unauthorized modification/deletion/action is proven
- object ownership or role boundary is clearly violated

Reject if:
- resource is public
- same-user resource was accessed
- 200 OK exists but no sensitive data change/access is proven
- attacker did not demonstrate cross-user or cross-role violation

[CSRF]
Accept only if:
- a forged cross-site request successfully triggered a protected state-changing action
- anti-CSRF defenses were absent or bypassed
- backend state change is demonstrated

Reject if:
- only endpoint presence is shown
- no proof of successful action
- SameSite, token, origin, or referer defenses were not actually tested

[SSRF]
Accept only if:
- server-side request behavior is demonstrated
- internal resource access, blind callback, metadata access, or controlled outbound interaction is proven

Reject if:
- user input merely accepts a URL
- no server-side fetch evidence exists
- result could be client-side fetching only

[File Upload]
Accept only if:
- restricted upload validation was bypassed
- uploaded content reached an executable or sensitive processing path
- file was stored, served, or interpreted in a dangerous way

Reject if:
- file upload succeeds but remains inert and safe
- file is renamed/quarantined/sanitized
- no execution or sensitive impact is shown

[Auth Bypass / Session Issues]
Accept only if:
- authentication or authorization controls were actually bypassed
- another user's session or restricted area was accessed without valid permission

Reject if:
- login error differences only
- weak wording in response only
- no successful bypass is demonstrated

[Business Logic Flaws]
Accept only if:
- an application rule was bypassed in a way that changes outcome, privilege, price, workflow, or restricted action
- impact is proven with clear before/after state

Reject if:
- the behavior is odd but not exploitable
- intended behavior is unclear
- no unauthorized advantage is demonstrated

==================================================
VALIDATION STANDARDS — INFRASTRUCTURE/PASSIVE FINDINGS
==================================================

[Missing Security Headers]
Accept (Informational/Low) if:
- specific named headers are absent from a real HTTP response
- direct HTTP request to the server was made

Reject if:
- the test was never sent or evidence is N/A

[CORS Misconfiguration]
Accept if:
- Access-Control-Allow-Origin reflects an attacker origin
- OR Access-Control-Allow-Origin is wildcard AND Access-Control-Allow-Credentials is true
- Evidence must include the actual response header

Reject if:
- wildcard CORS without credentials — this is standard and not exploitable for data theft

[Sensitive Data Exposure]
Accept if:
- concrete sensitive data appears in the response (credentials, keys, PII, internal IPs)
- evidence includes the actual leaked content

Reject if:
- generic 500 error or stack trace shows framework name only
- no sensitive data is demonstrated

[Rate Limiting Missing]
Accept only as Informational — never High/Critical unless combined with another finding.

==================================================
SPECIAL INSTRUCTION FOR PASSIVE-ONLY FINDINGS
==================================================
For findings that are inherently passive checks (security headers, CORS, rate limiting, TLS config,
sensitive data exposure via response inspection), you MUST be significantly more lenient:
- Evidence of "header not present" or "response contains X" IS sufficient.
- Do NOT demand active exploitation proof for passive configuration issues.
- These are valid findings if the observation matches the claimed vulnerability type.

==================================================
OUTPUT FORMAT (you MUST follow this exactly)
==================================================

Verdict: [VALIDATED | REJECTED_NEEDS_MORE_PROOF | FALSE_POSITIVE]

Confidence: [HIGH | MEDIUM | LOW]

Validation Summary:
[2-5 sentences. Clear technical language. Is the claim proven?]

Skepticism Rationale:
[Detailed: why sufficient or insufficient. Reference execution context, authorization context, backend effect, or missing proof. If rejecting, state the most likely benign explanation.]

Weakest Link in the PoC:
[Single most important missing proof or weakest technical point.]

Required Evidence to Validate:
[Exact evidence needed for VALIDATED status. Be concrete. If already VALIDATED, state "Evidence is sufficient."]

Challenge to Attacker Agent:
[Specific next-step instructions. Technical, actionable, targeted to the failure point. If VALIDATED, state "No further action required."]

Notes for Final Report:
[Brief downstream note. Example: "Include as confirmed — evidence is strong." or "Do not include as confirmed. At most classify as Informational pending further proof."]
"""


# ── Parsed verdict dataclass ─────────────────────────────────────────────────

VERDICT_LABELS = {
    "VALIDATED": "Validated",
    "REJECTED_NEEDS_MORE_PROOF": "Needs More Proof",
    "FALSE_POSITIVE": "False Positive",
}

VERDICT_COLORS = {
    "VALIDATED": "#22c55e",
    "REJECTED_NEEDS_MORE_PROOF": "#f59e0b",
    "FALSE_POSITIVE": "#dc2626",
}


def _parse_verdict_response(text: str) -> dict:
    """
    Parse the structured validator output into a dict.
    Robust to minor formatting variations.
    """
    result = {
        "verdict": "REJECTED_NEEDS_MORE_PROOF",
        "confidence": "LOW",
        "validation_summary": "",
        "skepticism_rationale": "",
        "weakest_link": "",
        "required_evidence": "",
        "challenge": "",
        "report_notes": "",
    }

    # Verdict
    m = re.search(r"Verdict:\s*(VALIDATED|REJECTED_NEEDS_MORE_PROOF|FALSE_POSITIVE)", text, re.I)
    if m:
        result["verdict"] = m.group(1).upper()

    # Confidence
    m = re.search(r"Confidence:\s*(HIGH|MEDIUM|LOW)", text, re.I)
    if m:
        result["confidence"] = m.group(1).upper()

    # Extract each labelled section (greedily up to the next section header)
    sections = [
        ("validation_summary",  r"Validation Summary:\s*(.*?)(?=Skepticism Rationale:|Weakest Link|$)"),
        ("skepticism_rationale",r"Skepticism Rationale:\s*(.*?)(?=Weakest Link|Required Evidence|$)"),
        ("weakest_link",        r"Weakest Link[^:]*:\s*(.*?)(?=Required Evidence|Challenge|$)"),
        ("required_evidence",   r"Required Evidence[^:]*:\s*(.*?)(?=Challenge|Notes for Final|$)"),
        ("challenge",           r"Challenge[^:]*:\s*(.*?)(?=Notes for Final|$)"),
        ("report_notes",        r"Notes for Final Report:\s*(.*?)$"),
    ]
    for key, pattern in sections:
        m = re.search(pattern, text, re.DOTALL | re.I)
        if m:
            result[key] = m.group(1).strip()[:1000]

    return result


# ── ValidatorAgent ────────────────────────────────────────────────────────────

class ValidatorAgent:
    """
    Adversarial reviewer — validates findings produced by attacker agents.

    Usage:
        validator = ValidatorAgent(llm_backend="anthropic")
        findings = validator.validate_batch(raw_findings)
        # Returns findings with validation metadata. FALSE_POSITIVEs are filtered out.
    """

    def __init__(self, llm_backend: str = "ollama"):
        self.llm_backend = llm_backend

        if llm_backend == "anthropic":
            try:
                import anthropic
            except ImportError:
                console.print("[bold red]anthropic package not installed.[/]")
                sys.exit(1)
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                console.print("[bold red]ANTHROPIC_API_KEY not set.[/]")
                sys.exit(1)
            self.client = anthropic.Anthropic(api_key=api_key)

    # ── Public interface ──────────────────────────────────────────

    def validate_batch(
        self,
        findings: list,
        drop_false_positives: bool = True,
    ) -> list:
        """
        Validate all findings. Returns enriched list.

        Each finding gets:
            validation_verdict       — VALIDATED | REJECTED_NEEDS_MORE_PROOF | FALSE_POSITIVE
            validation_confidence    — HIGH | MEDIUM | LOW
            validation_summary       — short explanation
            validation_skepticism    — detailed rationale
            validation_weakest_link  — main gap in evidence
            validation_required_evidence
            validation_challenge
            validation_notes

        If drop_false_positives=True (default), FALSE_POSITIVE findings are excluded.
        """
        if not findings:
            return findings

        console.print(
            f"\n[bold blue]  Phase 3: Validation ({len(findings)} findings → validator)[/]"
        )

        validated_count = 0
        needs_proof_count = 0
        fp_count = 0
        results = []

        for i, finding in enumerate(findings, 1):
            vt = finding.get("vuln_type", finding.get("type", "Unknown"))
            url = finding.get("url", "N/A")
            console.print(
                f"  [{i}/{len(findings)}] Reviewing: [cyan]{vt}[/] @ {url[:60]}"
            )

            try:
                enriched = self._validate_one(finding)
            except Exception as e:
                console.print(f"    [yellow]Validator error: {e} — keeping finding as-is[/]")
                finding["validation_verdict"] = "REJECTED_NEEDS_MORE_PROOF"
                finding["validation_confidence"] = "LOW"
                finding["validation_summary"] = "Validator encountered an error; manual review required."
                finding["validation_notes"] = "Automated validation failed."
                enriched = finding

            v = enriched.get("validation_verdict", "REJECTED_NEEDS_MORE_PROOF")
            conf = enriched.get("validation_confidence", "LOW")

            if v == "VALIDATED":
                validated_count += 1
                console.print(f"    [green]VALIDATED[/] ({conf})")
            elif v == "FALSE_POSITIVE":
                fp_count += 1
                console.print(f"    [red]FALSE POSITIVE — dropped[/]")
                if drop_false_positives:
                    continue
            else:
                needs_proof_count += 1
                console.print(f"    [yellow]NEEDS MORE PROOF[/] ({conf})")

            results.append(enriched)

        console.print(
            f"\n  [bold]Validation complete:[/] "
            f"[green]{validated_count} validated[/] | "
            f"[yellow]{needs_proof_count} needs proof[/] | "
            f"[red]{fp_count} false positives dropped[/]"
        )
        return results

    def validate_one(self, finding: dict) -> dict:
        """Public single-finding wrapper (may throw)."""
        return self._validate_one(finding)

    # ── Internal ─────────────────────────────────────────────────

    def _validate_one(self, finding: dict) -> dict:
        """Run LLM validation on a single finding. Returns enriched finding dict."""
        report_xml = self._format_report(finding)

        if self.llm_backend == "anthropic":
            response_text = self._call_anthropic(report_xml)
        else:
            response_text = self._call_ollama(report_xml)

        parsed = _parse_verdict_response(response_text)

        # Attach to finding
        enriched = dict(finding)
        enriched["validation_verdict"]           = parsed["verdict"]
        enriched["validation_confidence"]        = parsed["confidence"]
        enriched["validation_summary"]           = parsed["validation_summary"]
        enriched["validation_skepticism"]        = parsed["skepticism_rationale"]
        enriched["validation_weakest_link"]      = parsed["weakest_link"]
        enriched["validation_required_evidence"] = parsed["required_evidence"]
        enriched["validation_challenge"]         = parsed["challenge"]
        enriched["validation_notes"]             = parsed["report_notes"]
        return enriched

    def _format_report(self, finding: dict) -> str:
        """Serialize a finding dict into the structured <vulnerability_report> XML block."""
        vuln_type  = finding.get("vuln_type", finding.get("type", "Unknown"))
        url        = finding.get("url", "N/A")
        method     = finding.get("method", "N/A")
        param      = finding.get("param_name", "")
        payload    = finding.get("payload", "N/A")
        evidence   = finding.get("evidence", "N/A")
        severity   = finding.get("severity", "Unknown")
        source     = finding.get("source", "N/A")
        conf_score = finding.get("confidence_score", "N/A")
        conf_label = finding.get("confidence_label", "N/A")
        narrative  = finding.get("attack_narrative", "")
        details    = finding.get("details", {})

        details_str = ""
        if isinstance(details, dict) and details:
            try:
                details_str = json.dumps(details, indent=2, default=str)[:800]
            except Exception:
                pass

        return (
            "<vulnerability_report>\n"
            "  <vulnerability_type>{vuln_type}</vulnerability_type>\n"
            "  <target_url>{url}</target_url>\n"
            "  <http_method>{method}</http_method>\n"
            "  <parameter>{param}</parameter>\n"
            "  <payload><![CDATA[{payload}]]></payload>\n"
            "  <evidence><![CDATA[{evidence}]]></evidence>\n"
            "  <severity_claimed>{severity}</severity_claimed>\n"
            "  <source_agent>{source}</source_agent>\n"
            "  <attacker_confidence_score>{conf_score}</attacker_confidence_score>\n"
            "  <attacker_confidence_label>{conf_label}</attacker_confidence_label>\n"
            "  <attacker_narrative><![CDATA[{narrative}]]></attacker_narrative>\n"
            "  <additional_details><![CDATA[{details}]]></additional_details>\n"
            "</vulnerability_report>\n\n"
            "Apply the full validation workflow. Output ONLY in the required format."
        ).format(
            vuln_type=vuln_type, url=url, method=method, param=param,
            payload=payload, evidence=evidence, severity=severity,
            source=source, conf_score=conf_score, conf_label=conf_label,
            narrative=narrative, details=details_str,
        )

    def _call_anthropic(self, report_xml: str) -> str:
        """Single non-streaming Anthropic call — no tool use."""
        try:
            response = self.client.messages.create(
                model=ANTHROPIC_VALIDATOR_MODEL,
                max_tokens=1024,
                system=VALIDATOR_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": report_xml}],
            )
            return response.content[0].text if response.content else ""
        except Exception as e:
            console.print(f"    [red]Anthropic validator call failed: {e}[/]")
            return ""

    def _call_ollama(self, report_xml: str) -> str:
        """Single Ollama chat call — no tool use."""
        import httpx
        try:
            resp = httpx.post(
                "http://localhost:11434/api/chat",
                json={
                    "model": OLLAMA_VALIDATOR_MODEL,
                    "messages": [
                        {"role": "system", "content": VALIDATOR_SYSTEM_PROMPT},
                        {"role": "user", "content": report_xml},
                    ],
                    "stream": False,
                    "options": {
                        "temperature": 0.05,
                        "num_predict": 1024,
                    },
                },
                timeout=120,
            )
            resp.raise_for_status()
            return resp.json().get("message", {}).get("content", "")
        except Exception as e:
            console.print(f"    [red]Ollama validator call failed: {e}[/]")
            return ""
