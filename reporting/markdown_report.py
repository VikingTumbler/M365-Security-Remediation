"""
Markdown technical report — Full deep-dive report rendered via Jinja2.
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

# Fallback plain-text renderer in case Jinja2 is unavailable
_SEVERITY_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "⚪",
}


def export_markdown(
    scan_score: Any,
    all_findings: list,
    output_dir: Path,
    scan_id: str,
    tenant_name: str = "Unknown Tenant",
) -> Path:
    """
    Generate a comprehensive Markdown technical report.

    Uses Jinja2 template if available, otherwise falls back to
    programmatic Markdown generation.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    filepath = output_dir / f"technical_report_{scan_id}.md"

    if HAS_JINJA and (TEMPLATE_DIR / "technical_report.md.j2").exists():
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
    template = env.get_template("technical_report.md.j2")
    return template.render(
        scan_id=scan_id,
        tenant_name=tenant_name,
        generated_utc=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        score=scan_score,
        findings=findings,
        severity_icons=_SEVERITY_ICONS,
        domain_scores=scan_score.domain_scores,
        attack_paths=scan_score.attack_paths,
        top_weaknesses=scan_score.top_weaknesses,
        framework=scan_score.framework_mapping,
    )


def _render_fallback(scan_score, findings, scan_id, tenant_name) -> str:
    """Programmatic Markdown generation without Jinja2."""
    lines = []
    w = lines.append

    w(f"# M365 Security & IAM Intelligence Report")
    w("")
    w(f"**Tenant:** {tenant_name}  ")
    w(f"**Scan ID:** {scan_id}  ")
    w(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    w(f"**Mode:** READ-ONLY (no tenant modifications)")
    w("")
    w("---")
    w("")

    # --- Executive Score ---
    w("## Overall Security Posture")
    w("")
    w(f"| Metric | Value |")
    w(f"|--------|-------|")
    w(f"| **Overall Score** | **{scan_score.overall_score:.1f} / 100** |")
    w(f"| **Risk Rating** | **{scan_score.risk_rating}** |")
    w(f"| Total Findings | {scan_score.total_findings} |")
    w(f"| Critical | {scan_score.critical_findings} |")
    w(f"| High | {scan_score.high_findings} |")
    w(f"| Attack Paths Triggered | {len(scan_score.attack_paths)} |")
    w("")

    # --- Domain Scores ---
    w("## Domain Scores")
    w("")
    w("| Domain | Score | Weight | Findings | Critical | High | Maturity |")
    w("|--------|-------|--------|----------|----------|------|----------|")
    for ds in scan_score.domain_scores.values():
        w(
            f"| {ds.display_name} | {ds.raw_score:.1f} | {ds.weight:.0%} | "
            f"{ds.finding_count} | {ds.critical_count} | {ds.high_count} | "
            f"{ds.maturity_level:.1f} |"
        )
    w("")

    # --- Top 10 Weaknesses ---
    w("## Top 10 Structural Weaknesses")
    w("")
    for i, weakness in enumerate(scan_score.top_weaknesses[:10], 1):
        icon = _SEVERITY_ICONS.get(weakness.get("severity", "").lower(), "⚪")
        w(f"### {i}. {icon} {weakness['control']} ({weakness['severity']})")
        w("")
        w(f"**Domain:** {weakness['domain']}  ")
        w(f"**Maturity Level:** {weakness.get('maturity_level', 'N/A')}  ")
        w(f"**Impact Score:** {weakness.get('impact_score', 'N/A')}")
        w("")
        if weakness.get("risk_explanation"):
            w(f"> **Risk:** {weakness['risk_explanation']}")
            w("")
        if weakness.get("exploit_scenario"):
            w(f"> **Exploit Scenario:** {weakness['exploit_scenario']}")
            w("")
        if weakness.get("blast_radius"):
            w(f"> **Blast Radius:** {weakness['blast_radius']}")
            w("")

    # --- Attack Path Simulation ---
    w("## Attack Path Simulation")
    w("")
    if scan_score.attack_paths:
        for path in scan_score.attack_paths:
            w(f"### ⚡ {path['attack_path']}")
            w("")
            w(f"**Risk Level:** {path.get('risk_level', 'high').upper()}")
            w("")
            w(f"{path['description']}")
            w("")
            w(f"**Business Impact:** {path['impact']}")
            w("")
            domains = path.get("matched_domains", {})
            if domains:
                w("**Matched Domains:**")
                for d, sevs in domains.items():
                    w(f"  - `{d}`: {', '.join(sevs)}")
                w("")
    else:
        w("No multi-domain attack paths triggered based on current findings.")
        w("")

    # --- "If Breached Today" Impact Summary ---
    w("## 'If Breached Today' Impact Summary")
    w("")
    w(_generate_breach_summary(scan_score, findings))
    w("")

    # --- Control Coverage Matrix ---
    w("## Control Coverage Matrix")
    w("")
    w("| Domain | Findings | Maturity | Gap to Target (3.0) | Status |")
    w("|--------|----------|----------|---------------------|--------|")
    for ds in scan_score.domain_scores.values():
        gap = max(0, 3.0 - ds.maturity_level)
        status = "✅ On Track" if gap <= 0.5 else ("⚠️ Gap" if gap <= 1.5 else "❌ Critical Gap")
        w(f"| {ds.display_name} | {ds.finding_count} | {ds.maturity_level:.1f} | {gap:.1f} | {status} |")
    w("")

    # --- Framework Alignment ---
    w("## Framework Alignment")
    w("")

    # Zero Trust
    zt = scan_score.framework_mapping.zero_trust
    if zt:
        w("### Zero Trust Pillars")
        w("")
        for pillar, mapped_findings in zt.items():
            w(f"- **{pillar.title()}**: {len(mapped_findings)} finding(s)")
        w("")

    # CIS
    cis = scan_score.framework_mapping.cis_benchmark
    if cis:
        w("### CIS M365 Benchmark")
        w("")
        for ref, mapped_findings in sorted(cis.items()):
            w(f"- **{ref}**: {len(mapped_findings)} finding(s)")
        w("")

    # NIST
    nist = scan_score.framework_mapping.nist_families
    if nist:
        w("### NIST 800-53 Families")
        w("")
        for family, mapped_findings in sorted(nist.items()):
            w(f"- **{family}**: {len(mapped_findings)} finding(s)")
        w("")

    # --- Licensing Impact ---
    w("## Licensing Impact Commentary")
    w("")
    w(_generate_licensing_commentary(findings))
    w("")

    # --- All Findings (Detailed) ---
    w("## Detailed Findings")
    w("")
    # Group by domain
    by_domain: dict[str, list] = {}
    for f in findings:
        by_domain.setdefault(f.domain, []).append(f)

    for domain, domain_findings in sorted(by_domain.items()):
        w(f"### {domain.replace('_', ' ').title()}")
        w("")
        # Sort by severity: critical first
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        domain_findings.sort(key=lambda x: sev_order.get((x.severity or "").lower(), 5))

        for f in domain_findings:
            icon = _SEVERITY_ICONS.get((f.severity or "").lower(), "⚪")
            w(f"#### {icon} {f.control_name}")
            w("")
            w(f"| Field | Value |")
            w(f"|-------|-------|")
            w(f"| ID | `{f.id}` |")
            w(f"| Severity | {f.severity} |")
            w(f"| Maturity | {f.maturity_level} |")
            if f.cis_benchmark:
                w(f"| CIS Benchmark | {f.cis_benchmark} |")
            if f.nist_family:
                w(f"| NIST Family | {f.nist_family} |")
            if f.zero_trust_pillar:
                w(f"| Zero Trust Pillar | {f.zero_trust_pillar} |")
            w("")
            w(f"**Detection Logic:** {f.detection_logic}")
            w("")
            if f.evidence:
                w("**Evidence:**")
                w("```json")
                import json
                w(json.dumps(f.evidence, indent=2, default=str))
                w("```")
                w("")
            if f.risk_explanation:
                w(f"> {f.risk_explanation}")
                w("")
            if f.exploit_scenario:
                w(f"**Exploit Scenario:** {f.exploit_scenario}")
                w("")
            if f.blast_radius:
                w(f"**Blast Radius:** {f.blast_radius}")
                w("")

    w("---")
    w(f"*Report generated by M365 Security & IAM Intelligence Engine v1.0.0*")

    return "\n".join(lines)


def _generate_breach_summary(scan_score, findings) -> str:
    """Compose a narrative breach impact summary."""
    critical = scan_score.critical_findings
    high = scan_score.high_findings
    score = scan_score.overall_score
    paths = len(scan_score.attack_paths)

    parts = []
    if score < 50:
        parts.append(
            "**This tenant is at significant risk of compromise.** "
            f"With an overall score of {score:.0f}/100, an attacker who gains "
            "initial access would find multiple escalation paths available."
        )
    elif score < 70:
        parts.append(
            "**This tenant has meaningful security gaps.** "
            f"With an overall score of {score:.0f}/100, an attacker would "
            "encounter some barriers but could likely find escalation opportunities."
        )
    else:
        parts.append(
            f"**This tenant has a reasonable security posture (score: {score:.0f}/100).** "
            "An attacker would face multiple barriers, though specific gaps exist."
        )

    if critical > 0:
        parts.append(
            f"\n\n{critical} critical finding(s) represent immediate exploitable weaknesses "
            "that could be leveraged within hours of initial access."
        )

    if paths > 0:
        parts.append(
            f"\n\n{paths} multi-domain attack path(s) were identified, meaning a breach "
            "in one domain can cascade across others."
        )

    # Specific impacts
    domain_impacts = []
    for ds in scan_score.domain_scores.values():
        if ds.critical_count > 0:
            domain_impacts.append(f"- **{ds.display_name}**: {ds.critical_count} critical weaknesses")
    if domain_impacts:
        parts.append("\n\n**Immediate Risk Areas:**\n" + "\n".join(domain_impacts))

    return "\n".join(parts) if parts else "Breach impact assessment complete."


def _generate_licensing_commentary(findings) -> str:
    """Generate commentary on licensing dependencies discovered in findings."""
    parts = []
    license_keywords = {
        "P2":   "Entra ID P2 (PIM, Identity Protection, risk-based CA)",
        "P1":   "Entra ID P1 (Conditional Access, group-based licensing)",
        "MDE":  "Microsoft Defender for Endpoint",
        "MDO":  "Microsoft Defender for Office 365",
        "MDI":  "Microsoft Defender for Identity",
        "MCAS": "Microsoft Defender for Cloud Apps",
        "Intune": "Microsoft Intune",
    }

    mentioned = set()
    for f in findings:
        text = f"{f.detection_logic} {f.risk_explanation} {f.control_name}".lower()
        for key, desc in license_keywords.items():
            if key.lower() in text and key not in mentioned:
                mentioned.add(key)
                parts.append(f"- **{desc}**: Referenced in finding `{f.control_name}`")

    if parts:
        return (
            "The following licensing tiers are implicated by the findings:\n\n"
            + "\n".join(sorted(parts))
            + "\n\n*Review these license requirements against current entitlements.*"
        )
    return "No specific licensing gaps identified from the current findings."
