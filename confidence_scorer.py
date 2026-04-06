"""
Confidence Scorer — Assigns a confidence score (0-100) to each finding.

Score is based on:
- Evidence quality (actual proof vs just error message)
- Payload determinism (canary-based = high, error pattern = medium)
- Validation method used
- Response difference magnitude

Also generates a plain-English attack narrative for each finding.
"""

from typing import Optional


EVIDENCE_KEYWORDS_HIGH = [
    'canary', 'reflected', 'executed', 'confirmed', 'root:x:', '/etc/passwd',
    'union select', 'sleep(', 'user()', 'version()', 'administrator',
    'error in your sql syntax', 'db error', 'access_token', 'CONFIRMED',
]
EVIDENCE_KEYWORDS_MEDIUM = [
    'error', 'exception', 'warning', 'syntax', 'query failed',
    'difference', 'bytes', 'different from', 'length',
]

NARRATIVES = {
    'sqli': (
        "An attacker can inject SQL code into the {param} parameter at {url}. "
        "This allows reading, modifying, or deleting data from the database, "
        "potentially exposing all user records, credentials, and business data."
    ),
    'xss': (
        "An attacker can inject JavaScript into the {param} parameter at {url}. "
        "When a victim visits the page, the script executes in their browser, "
        "enabling session hijacking, credential theft, or malware delivery."
    ),
    'command_injection': (
        "An attacker can inject OS commands via {param} at {url}. "
        "This gives full shell access to the server, enabling data exfiltration, "
        "ransomware deployment, or lateral movement inside the network."
    ),
    'cmdi': (
        "An attacker can inject OS commands via {param} at {url}. "
        "This gives full shell access to the server."
    ),
    'path_traversal': (
        "An attacker can read arbitrary files from the server via {param} at {url}, "
        "including /etc/passwd, application source code, config files with credentials, "
        "and private keys."
    ),
    'idor': (
        "An attacker can access other users' data by changing the {param} value at {url}. "
        "This exposes private records, PII, and potentially allows modifying other accounts."
    ),
    'csrf': (
        "An attacker can trick an authenticated user into making unwanted requests via {url}. "
        "By hosting a malicious page, the attacker can perform actions on behalf of the victim "
        "including changing passwords, transferring funds, or modifying account settings."
    ),
    'ssrf': (
        "An attacker can make the server perform HTTP requests to internal systems via {param} at {url}. "
        "This enables accessing internal services (metadata APIs, Redis, admin panels) "
        "that are not publicly accessible."
    ),
    'open_redirect': (
        "An attacker can redirect users from {url} to a malicious site via {param}. "
        "Used for phishing by sending users a legitimate-looking URL that redirects to attacker infrastructure."
    ),
    'missing_headers': (
        "The application at {url} is missing security headers ({param}). "
        "This makes it easier for attackers to exploit XSS, clickjacking, "
        "and content injection attacks."
    ),
    'sensitive_data': (
        "Sensitive information is exposed at {url}. "
        "This data can be used by attackers for targeted attacks, credential stuffing, "
        "or to understand internal system architecture."
    ),
    'graphql': (
        "The GraphQL endpoint at {url} has a security misconfiguration. "
        "This exposes the full API schema and may allow unauthorized data access."
    ),
    'mass_assignment': (
        "The endpoint {url} accepts unexpected fields ({param}) in the request body. "
        "An attacker can escalate privileges, modify prices, or bypass business logic "
        "by injecting these fields."
    ),
}


def score_finding(finding: dict) -> int:
    """
    Calculate confidence score 0-100 for a finding.
    """
    score = 50  # base score

    evidence = (finding.get('evidence') or '').lower()
    payload = (finding.get('payload') or '').lower()
    vuln_type = (finding.get('vuln_type') or finding.get('type') or '').lower()
    severity = (finding.get('severity') or 'medium').lower()

    # Evidence quality boost
    for kw in EVIDENCE_KEYWORDS_HIGH:
        if kw.lower() in evidence:
            score += 15
            break
    for kw in EVIDENCE_KEYWORDS_MEDIUM:
        if kw.lower() in evidence:
            score += 8
            break

    # Payload quality
    if len(payload) > 10:
        score += 5
    if any(kw in payload for kw in ["'", '"', '<script', ';', '|', '../', 'sleep']):
        score += 10

    # Severity boost
    sev_boosts = {'critical': 20, 'high': 15, 'medium': 5, 'low': 0}
    score += sev_boosts.get(severity, 0)

    # Passive checks get lower score
    passive_types = ['missing_headers', 'sensitive_data']
    if vuln_type in passive_types and not payload:
        score -= 15

    # Cap at 100
    return min(max(score, 10), 100)


def get_confidence_label(score: int) -> str:
    if score >= 85:
        return "Confirmed"
    elif score >= 65:
        return "High Confidence"
    elif score >= 45:
        return "Medium Confidence"
    else:
        return "Low Confidence"


def generate_narrative(finding: dict) -> str:
    """Generate plain-English attack narrative for a finding."""
    vuln_type = (finding.get('vuln_type') or finding.get('type') or '').lower()
    url = finding.get('url', 'the endpoint')
    param = finding.get('param_name') or finding.get('param') or 'a parameter'

    # Find best matching narrative
    for key, template in NARRATIVES.items():
        if key in vuln_type:
            return template.format(url=url, param=param)

    return (
        f"A security vulnerability was identified at {url}. "
        f"An attacker exploiting this could gain unauthorized access or "
        f"compromise application integrity."
    )


def enrich_with_scores(findings: list) -> list:
    """Add confidence_score, confidence_label, and narrative to all findings."""
    for f in findings:
        f['confidence_score'] = score_finding(f)
        f['confidence_label'] = get_confidence_label(f['confidence_score'])
        f['attack_narrative'] = generate_narrative(f)
    return findings
