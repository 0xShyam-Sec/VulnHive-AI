"""
HTML generation utilities for chain visualization sections.
Generates flow diagrams and verification badges for exploit chain reports.
"""


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _get_severity_color(severity: str) -> str:
    """Map severity level to hex color."""
    severity_lower = severity.lower()
    if severity_lower == "critical":
        return "#dc2626"
    elif severity_lower == "high":
        return "#ea580c"
    elif severity_lower == "medium":
        return "#ca8a04"
    else:
        return "#6b7280"  # gray for low/unknown


def _parse_narrative_steps(narrative: str) -> list:
    """Parse narrative string into individual steps.

    Splits on newline and removes numeric prefixes like "1. ", "2. ", etc.
    """
    if not narrative:
        return []

    steps = []
    for line in narrative.split("\n"):
        line = line.strip()
        if not line:
            continue
        # Remove numbering like "1. ", "2. ", etc.
        for i in range(10):
            prefix = f"{i}. "
            if line.startswith(prefix):
                line = line[len(prefix):]
                break
        steps.append(line)

    return steps


def _format_step_with_color(step_text: str, step_num: int, severity: str) -> str:
    """Format a single narrative step with color coding based on severity."""
    color = _get_severity_color(severity)
    escaped_text = _escape_html(step_text)
    return (
        f'<div style="background:#f1f5f9;border:1px solid #e2e8f0;'
        f'border-radius:6px;padding:8px 12px;font-size:12px;">'
        f'<span style="font-weight:700;color:{color};">{step_num}</span> {escaped_text}'
        f'</div>'
    )


def generate_chain_html(chains: list) -> str:
    """Generate HTML for chain visualization sections.

    Args:
        chains: List of chain dictionaries with keys:
            - name: Chain name (str)
            - severity: Severity level (str, e.g., "Critical", "High", "Medium")
            - impact: Impact description (str)
            - narrative: Multi-line narrative string with numbered steps
            - required_types: List of required finding types
            - amplifier_types: List of amplifier finding types
            - finding_count: Number of findings (int)
            - findings: List of finding dicts
            - verified: Whether chain is verified (bool, optional)
            - verification_status: Status string (optional, e.g., "Theoretical Chain")
            - verification_evidence: Evidence text (optional)

    Returns:
        HTML string with formatted chain cards.
    """
    if not chains:
        return ""

    html_parts = []

    for chain in chains:
        name = _escape_html(chain.get("name", "Unnamed Chain"))
        severity = chain.get("severity", "Medium").lower()
        severity_display = severity.capitalize()
        color = _get_severity_color(severity)
        impact = _escape_html(chain.get("impact", "Unknown impact"))

        # Build verification badge
        verification_badge = ""
        is_verified = chain.get("verified", False)
        verification_status = chain.get("verification_status", "")

        if is_verified:
            verification_badge = (
                '<span style="background:#22c55e;color:white;font-size:10px;'
                'font-weight:700;padding:2px 8px;border-radius:3px;">✓ VERIFIED</span>'
            )
        elif verification_status == "Theoretical Chain":
            verification_badge = (
                '<span style="background:#f59e0b;color:white;font-size:10px;'
                'font-weight:700;padding:2px 8px;border-radius:3px;">⚠ THEORETICAL</span>'
            )

        # Parse narrative steps
        narrative = chain.get("narrative", "")
        steps = _parse_narrative_steps(narrative)

        # Build flow diagram
        flow_parts = []
        for i, step_text in enumerate(steps, 1):
            flow_parts.append(_format_step_with_color(step_text, i, severity))
            if i < len(steps):  # Add arrow between steps
                flow_parts.append('<span style="color:#94a3b8;font-size:18px;">→</span>')

        # Add impact box at the end
        flow_parts.append(
            f'<div style="background:#fef2f2;border:1px solid #fecaca;'
            f'border-radius:6px;padding:8px 12px;">'
            f'<strong style="color:#991b1b;">Impact:</strong> {impact}'
            f'</div>'
        )

        flow_html = "\n    ".join(flow_parts)

        # Build involved findings list
        required_types = chain.get("required_types", [])
        amplifier_types = chain.get("amplifier_types", [])

        finding_types_display = " + ".join(_escape_html(str(t)) for t in required_types)

        involved_html = f'<div style="margin-top:12px;font-size:12px;color:#64748b;">Involves: {finding_types_display}'
        if amplifier_types:
            amplifiers_display = ", ".join(_escape_html(str(a)) for a in amplifier_types)
            involved_html += f' (amplified by: {amplifiers_display})'
        involved_html += '</div>'

        # Build verification evidence section if available
        verification_evidence_html = ""
        verification_evidence = chain.get("verification_evidence", "")
        if verification_evidence:
            escaped_evidence = _escape_html(verification_evidence)
            verification_evidence_html = (
                f'<div style="margin-top:12px;padding:10px;background:#f0fdf4;'
                f'border:1px solid #bbf7d0;border-radius:4px;">'
                f'<strong style="color:#166534;">Verification:</strong> {escaped_evidence}'
                f'</div>'
            )

        # Assemble the complete chain card
        badge_html = f'<span class="badge badge-{severity}">{severity_display}</span>'

        card_html = (
            f'<div class="card" style="border-left:4px solid {color};">\n'
            f'  <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">\n'
            f'    {badge_html}\n'
            f'    <h3 style="font-size:16px;">{name}</h3>\n'
        )

        if verification_badge:
            card_html += f'    {verification_badge}\n'

        card_html += (
            f'  </div>\n'
            f'  \n'
            f'  <div style="display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin:16px 0;">\n'
            f'    {flow_html}\n'
            f'  </div>\n'
            f'  \n'
            f'  {involved_html}\n'
        )

        if verification_evidence_html:
            card_html += f'  {verification_evidence_html}\n'

        card_html += '</div>\n'

        html_parts.append(card_html)

    return "\n".join(html_parts)


def generate_chain_summary_html(chains: list) -> str:
    """Generate a summary card for exploit chains.

    Shows total chain count, verified vs theoretical breakdown,
    and highlights the highest severity chain.

    Args:
        chains: List of chain dictionaries (same format as generate_chain_html).

    Returns:
        HTML string with summary card.
    """
    if not chains:
        return (
            '<div class="card">\n'
            '  <h3>Exploit Chains</h3>\n'
            '  <p style="color:#64748b;">No exploit chains detected.</p>\n'
            '</div>'
        )

    total_chains = len(chains)
    verified_count = sum(1 for c in chains if c.get("verified", False))
    theoretical_count = sum(
        1 for c in chains if c.get("verification_status") == "Theoretical Chain"
    )

    # Find highest severity chain
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    highest_chain = max(
        chains,
        key=lambda c: severity_rank.get(c.get("severity", "low").lower(), 0),
        default=None
    )

    highest_severity = ""
    highest_name = ""
    highest_color = ""
    if highest_chain:
        highest_severity = highest_chain.get("severity", "Unknown").upper()
        highest_name = _escape_html(highest_chain.get("name", "Unknown"))
        highest_color = _get_severity_color(highest_severity.lower())

    # Build summary HTML
    summary_html = (
        '<div class="card">\n'
        '  <h3>Exploit Chains Summary</h3>\n'
        '  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:16px 0;">\n'
        f'    <div style="padding:12px;background:#f1f5f9;border-radius:6px;text-align:center;">\n'
        f'      <div style="font-size:24px;font-weight:700;color:#1e293b;">{total_chains}</div>\n'
        f'      <div style="font-size:12px;color:#64748b;margin-top:4px;">Total Chains</div>\n'
        f'    </div>\n'
        f'    <div style="padding:12px;background:#f0fdf4;border-radius:6px;text-align:center;">\n'
        f'      <div style="font-size:24px;font-weight:700;color:#166534;">{verified_count}</div>\n'
        f'      <div style="font-size:12px;color:#64748b;margin-top:4px;">Verified</div>\n'
        f'    </div>\n'
        f'    <div style="padding:12px;background:#fef3c7;border-radius:6px;text-align:center;">\n'
        f'      <div style="font-size:24px;font-weight:700;color:#92400e;">{theoretical_count}</div>\n'
        f'      <div style="font-size:12px;color:#64748b;margin-top:4px;">Theoretical</div>\n'
        f'    </div>\n'
        f'  </div>\n'
    )

    if highest_chain:
        summary_html += (
            f'  <div style="margin-top:16px;padding:12px;background:#fef2f2;'
            f'border:2px solid {highest_color};border-radius:6px;">\n'
            f'    <div style="font-size:12px;color:#64748b;margin-bottom:4px;">Highest Severity</div>\n'
            f'    <div style="display:flex;align-items:center;gap:12px;">\n'
            f'      <span style="background:{highest_color};color:white;font-size:11px;'
            f'font-weight:700;padding:4px 10px;border-radius:4px;">{highest_severity}</span>\n'
            f'      <span style="font-weight:600;color:#1e293b;">{highest_name}</span>\n'
            f'    </div>\n'
            f'  </div>\n'
        )

    summary_html += '</div>'

    return summary_html
