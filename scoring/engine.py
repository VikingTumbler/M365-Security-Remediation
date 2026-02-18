"""
Scoring Engine — Computes 0-100 security posture score from analyzer findings.

Scoring model:
  - Each domain starts at 100 points.
  - Findings impose deductions based on severity and maturity gap.
  - Domain scores are weighted per DOMAIN_WEIGHTS and combined into overall score.
  - Attack path simulation identifies chained weaknesses.
"""

from __future__ import annotations

from ..config import DOMAIN_WEIGHTS, SEVERITY_SCORES
from .models import DomainScore, ScanScore
from .frameworks import build_framework_mapping

# ---------------------------------------------------------------------------
# Deduction table — how many points to deduct per finding severity
# ---------------------------------------------------------------------------
SEVERITY_DEDUCTIONS = {
    "critical": 18,
    "high":     10,
    "medium":    5,
    "low":       2,
    "info":      0,
}

# Maturity-based multiplier: lower maturity → bigger deductions
MATURITY_MULTIPLIERS = {
    0: 1.5,   # No controls at all
    1: 1.3,   # Initial / ad hoc
    2: 1.1,   # Developing
    3: 1.0,   # Defined
    4: 0.8,   # Managed
    5: 0.6,   # Optimized
}

# Display names for domains (keys must match DOMAIN_WEIGHTS and analyzer domains)
DOMAIN_DISPLAY = {
    "identity_security":    "Identity & Authentication",
    "conditional_access":   "Conditional Access",
    "privileged_access":    "Privileged Access Management",
    "device_security":      "Device Compliance (Intune)",
    "app_protection":       "Application Security",
    "monitoring_detection": "Monitoring & Detection",
}

# Risk rating thresholds
RISK_THRESHOLDS = [
    (90, "Excellent"),
    (80, "Good"),
    (65, "Moderate"),
    (50, "Concerning"),
    (35, "Poor"),
    ( 0, "Critical"),
]


# ---------------------------------------------------------------------------
# Attack path templates
# ---------------------------------------------------------------------------
ATTACK_PATH_TEMPLATES = [
    {
        "name": "Credential Spray → Lateral Movement",
        "trigger_domains": ["identity", "conditional_access"],
        "trigger_severities": ["critical", "high"],
        "description": (
            "Weak MFA coverage + absent Conditional Access blocking allows "
            "credential spray → initial access → lateral movement via shared "
            "mailbox or delegated permissions."
        ),
        "impact": "Full tenant compromise via privilege escalation chain",
    },
    {
        "name": "Overprivileged App → Data Exfiltration",
        "trigger_domains": ["app", "monitoring"],
        "trigger_severities": ["critical", "high"],
        "description": (
            "Overprivileged application registration with expiring credentials "
            "and no audit monitoring allows silent token theft → Graph API "
            "data exfiltration."
        ),
        "impact": "Mass data exfiltration via Graph API (mail, files, chats)",
    },
    {
        "name": "Standing Privilege → Tenant Takeover",
        "trigger_domains": ["privileged_access", "identity"],
        "trigger_severities": ["critical", "high"],
        "description": (
            "Standing Global Admin without PIM + missing break-glass controls "
            "allows account compromise → full tenant administrative takeover."
        ),
        "impact": "Complete tenant ownership loss",
    },
    {
        "name": "Unmanaged Device → Compliance Bypass",
        "trigger_domains": ["device", "conditional_access"],
        "trigger_severities": ["critical", "high"],
        "description": (
            "Low device enrollment + no device-based Conditional Access allows "
            "access from unmanaged/compromised endpoints."
        ),
        "impact": "Data access from uncontrolled devices, potential malware pivot",
    },
    {
        "name": "Legacy Auth → MFA Bypass",
        "trigger_domains": ["identity", "conditional_access", "monitoring"],
        "trigger_severities": ["critical", "high"],
        "description": (
            "Active legacy authentication protocols bypass MFA enforcement, "
            "allowing password-only access to mailboxes and SharePoint."
        ),
        "impact": "MFA completely bypassed for legacy protocol users",
    },
]


def compute_scores(all_findings: list) -> ScanScore:
    """
    Compute the full tenant security score from merged findings.

    Args:
        all_findings: List of Finding objects from all analyzers.

    Returns:
        ScanScore with overall + domain scores + framework mapping.
    """
    result = ScanScore()
    result.total_findings = len(all_findings)
    result.framework_mapping = build_framework_mapping(all_findings)

    # --- Group findings by domain ---
    domain_findings: dict[str, list] = {}
    for f in all_findings:
        domain_findings.setdefault(f.domain, []).append(f)
        sev = (f.severity or "").lower()
        if sev == "critical":
            result.critical_findings += 1
        elif sev == "high":
            result.high_findings += 1

    # --- Compute per-domain scores ---
    for domain, weight in DOMAIN_WEIGHTS.items():
        ds = DomainScore(
            domain=domain,
            display_name=DOMAIN_DISPLAY.get(domain, domain.replace("_", " ").title()),
            weight=weight,
        )

        findings = domain_findings.get(domain, [])
        ds.finding_count = len(findings)
        total_deduction = 0.0
        maturity_sum = 0.0

        for f in findings:
            sev = (f.severity or "").lower()
            base_deduction = SEVERITY_DEDUCTIONS.get(sev, 0)
            maturity = f.maturity_level if f.maturity_level is not None else 3
            multiplier = MATURITY_MULTIPLIERS.get(maturity, 1.0)
            deduction = base_deduction * multiplier
            total_deduction += deduction
            maturity_sum += maturity

            # Severity counters
            if sev == "critical":
                ds.critical_count += 1
            elif sev == "high":
                ds.high_count += 1
            elif sev == "medium":
                ds.medium_count += 1
            elif sev == "low":
                ds.low_count += 1

        ds.total_deductions = total_deduction
        ds.raw_score = max(0, 100 - total_deduction)
        ds.weighted_score = ds.raw_score * weight
        ds.maturity_level = (maturity_sum / len(findings)) if findings else 5.0

        result.domain_scores[domain] = ds

    # --- Overall weighted score ---
    result.overall_score = sum(ds.weighted_score for ds in result.domain_scores.values())
    # Clamp to [0, 100]
    result.overall_score = max(0, min(100, result.overall_score))

    # --- Risk rating ---
    for threshold, rating in RISK_THRESHOLDS:
        if result.overall_score >= threshold:
            result.risk_rating = rating
            break

    # --- Top 10 weaknesses (sorted by severity weight × maturity gap) ---
    scored_findings = []
    for f in all_findings:
        sev = (f.severity or "").lower()
        sev_weight = SEVERITY_SCORES.get(sev, 0) if hasattr(f, 'severity') else 0
        maturity_gap = 5 - (f.maturity_level if f.maturity_level is not None else 3)
        impact = sev_weight * (1 + maturity_gap * 0.2)
        scored_findings.append((impact, f))

    scored_findings.sort(key=lambda x: x[0], reverse=True)
    for impact, f in scored_findings[:10]:
        result.top_weaknesses.append({
            "finding_id": f.id,
            "control": f.control_name,
            "domain": f.domain,
            "severity": f.severity,
            "maturity_level": f.maturity_level,
            "risk_explanation": f.risk_explanation,
            "exploit_scenario": f.exploit_scenario,
            "blast_radius": f.blast_radius,
            "impact_score": round(impact, 2),
        })

    # --- Attack path simulation ---
    result.attack_paths = _simulate_attack_paths(all_findings)

    return result


def _simulate_attack_paths(findings: list) -> list[dict]:
    """
    Evaluate pre-defined attack path templates against actual findings.
    An attack path fires if ALL trigger domains have at least one finding
    at the required severity levels.
    """
    # Index: domain → set of observed severities
    domain_severities: dict[str, set[str]] = {}
    for f in findings:
        sev = (f.severity or "").lower()
        domain_severities.setdefault(f.domain, set()).add(sev)

    triggered = []
    for template in ATTACK_PATH_TEMPLATES:
        # All trigger domains must have at least one finding at trigger severity
        matched = True
        matched_domains = {}
        for td in template["trigger_domains"]:
            observed = domain_severities.get(td, set())
            overlap = observed & set(template["trigger_severities"])
            if not overlap:
                matched = False
                break
            matched_domains[td] = sorted(overlap)

        if matched:
            triggered.append({
                "attack_path": template["name"],
                "description": template["description"],
                "impact": template["impact"],
                "matched_domains": matched_domains,
                "risk_level": "critical" if "critical" in str(matched_domains) else "high",
            })

    return triggered
