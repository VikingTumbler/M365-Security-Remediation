"""
Executive summary — One-page strategic summary for leadership audiences.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    HAS_JINJA = True
except ImportError:
    HAS_JINJA = False


TEMPLATE_DIR = Path(__file__).parent / "templates"


def export_executive_summary(
    scan_score: Any,
    all_findings: list,
    output_dir: Path,
    scan_id: str,
    tenant_name: str = "Unknown Tenant",
) -> Path:
    """
    Generate a concise executive summary in Markdown.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    filepath = output_dir / f"executive_summary_{scan_id}.md"

    if HAS_JINJA and (TEMPLATE_DIR / "executive_summary.md.j2").exists():
        content = _render_jinja(scan_score, all_findings, scan_id, tenant_name)
    else:
        content = _render_fallback(scan_score, all_findings, scan_id, tenant_name)

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(content)

    return filepath


def _render_jinja(scan_score, findings, scan_id, tenant_name) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape([]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("executive_summary.md.j2")
    return template.render(
        scan_id=scan_id,
        tenant_name=tenant_name,
        generated_utc=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        score=scan_score,
    )


def _render_fallback(scan_score, findings, scan_id, tenant_name) -> str:
    lines = []
    w = lines.append

    w("# Executive Security Summary")
    w("")
    w(f"**Tenant:** {tenant_name}  ")
    w(f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d')}  ")
    w(f"**Classification:** Confidential")
    w("")
    w("---")
    w("")

    # --- Score Box ---
    score = scan_score.overall_score
    rating = scan_score.risk_rating
    w(f"## Security Score: {score:.0f}/100 — {rating}")
    w("")

    # Rating explanation
    if score >= 80:
        w("The tenant security posture is **strong**. Continue maintaining "
          "current controls while addressing the targeted recommendations below.")
    elif score >= 65:
        w("The tenant security posture is **adequate but has notable gaps**. "
          "Priority remediation of critical and high findings is recommended "
          "within 30 days.")
    elif score >= 50:
        w("The tenant security posture is **concerning**. Multiple high-risk "
          "gaps exist that require immediate attention. A remediation sprint "
          "is recommended within 14 days.")
    else:
        w("The tenant security posture is **critically deficient**. Immediate "
          "executive engagement and emergency remediation are required. "
          "Consider engaging incident response resources proactively.")
    w("")

    # --- Key Metrics ---
    w("## Key Metrics")
    w("")
    w(f"| Metric | Count |")
    w(f"|--------|-------|")
    w(f"| Total Findings | {scan_score.total_findings} |")
    w(f"| Critical Findings | {scan_score.critical_findings} |")
    w(f"| High Findings | {scan_score.high_findings} |")
    w(f"| Attack Paths Identified | {len(scan_score.attack_paths)} |")
    w("")

    # --- Domain Heatmap ---
    w("## Domain Risk Heatmap")
    w("")
    w("| Domain | Score | Risk Level |")
    w("|--------|-------|------------|")
    for ds in sorted(scan_score.domain_scores.values(), key=lambda x: x.raw_score):
        if ds.raw_score >= 80:
            risk = "🟢 Low"
        elif ds.raw_score >= 65:
            risk = "🟡 Moderate"
        elif ds.raw_score >= 50:
            risk = "🟠 Elevated"
        else:
            risk = "🔴 Critical"
        w(f"| {ds.display_name} | {ds.raw_score:.0f} | {risk} |")
    w("")

    # --- Top 5 Priorities ---
    w("## Top 5 Remediation Priorities")
    w("")
    for i, weakness in enumerate(scan_score.top_weaknesses[:5], 1):
        w(f"{i}. **{weakness['control']}** ({weakness['severity']}) — "
          f"{weakness.get('risk_explanation', 'See detailed report')[:150]}")
    w("")

    # --- Attack Paths ---
    if scan_score.attack_paths:
        w("## Active Threat Scenarios")
        w("")
        for path in scan_score.attack_paths:
            w(f"- **{path['attack_path']}**: {path['description'][:200]}")
        w("")

    # --- Recommended Timeline ---
    w("## Recommended Action Timeline")
    w("")
    w("| Timeframe | Action |")
    w("|-----------|--------|")
    if scan_score.critical_findings > 0:
        w("| **Immediate (0-7 days)** | Address all critical findings |")
    if scan_score.high_findings > 0:
        w("| **Short-term (7-30 days)** | Remediate high-severity findings |")
    w("| **Medium-term (30-90 days)** | Improve domain maturity levels to 3+ |")
    w("| **Ongoing** | Quarterly re-scan and continuous monitoring |")
    w("")

    w("---")
    w(f"*Scan ID: {scan_id} | Generated by M365 Security Intelligence Engine*")

    return "\n".join(lines)
