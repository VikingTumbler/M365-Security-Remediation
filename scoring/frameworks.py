"""
Framework alignment — Maps findings to CIS M365 Benchmark, NIST 800-53, and Zero Trust pillars.
"""

from __future__ import annotations

from .models import FrameworkMapping


# ---------------------------------------------------------------------------
# Zero Trust Pillars
# ---------------------------------------------------------------------------
ZERO_TRUST_PILLARS = {
    "identity":     "Verify identity explicitly using strong authentication and least privilege",
    "devices":      "Validate device health and compliance before granting access",
    "applications": "Ensure appropriate in-app permissions and control shadow IT",
    "data":         "Classify, label, and encrypt data; restrict based on policy",
    "infrastructure": "Harden infrastructure, detect anomalies, auto-block risky behavior",
    "networks":     "Segment networks, employ micro-segmentation and threat protection",
}

# ---------------------------------------------------------------------------
# CIS Microsoft 365 Benchmark v3.x control families
# ---------------------------------------------------------------------------
CIS_FAMILIES = {
    "1": "Account / Authentication",
    "2": "Application Permissions",
    "3": "Data Management",
    "4": "Email Security / Exchange Online",
    "5": "Auditing",
    "6": "Storage",
}

# ---------------------------------------------------------------------------
# NIST 800-53 Rev 5 control families (subset relevant to cloud IAM)
# ---------------------------------------------------------------------------
NIST_FAMILIES = {
    "AC":  "Access Control",
    "AU":  "Audit and Accountability",
    "CA":  "Assessment, Authorization, and Monitoring",
    "CM":  "Configuration Management",
    "IA":  "Identification and Authentication",
    "IR":  "Incident Response",
    "PM":  "Program Management",
    "RA":  "Risk Assessment",
    "SA":  "System and Services Acquisition",
    "SC":  "System and Communications Protection",
    "SI":  "System and Information Integrity",
}


def build_framework_mapping(findings: list) -> FrameworkMapping:
    """
    Build framework mapping from a list of Finding objects.
    Groups findings by their declared CIS benchmark reference,
    NIST family, and Zero Trust pillar.
    """
    mapping = FrameworkMapping()

    for finding in findings:
        summary = {
            "id": finding.id,
            "control": finding.control_name,
            "severity": finding.severity,
            "domain": finding.domain,
        }

        # --- Zero Trust ---
        zt_pillar = (finding.zero_trust_pillar or "").strip().lower()
        if zt_pillar and zt_pillar in ZERO_TRUST_PILLARS:
            mapping.zero_trust.setdefault(zt_pillar, []).append(summary)
        elif zt_pillar:
            # Accept pillar even if not in canonical list
            mapping.zero_trust.setdefault(zt_pillar, []).append(summary)

        # --- CIS Benchmark ---
        cis_ref = (finding.cis_benchmark or "").strip()
        if cis_ref:
            mapping.cis_benchmark.setdefault(cis_ref, []).append(summary)

        # --- NIST 800-53 ---
        nist_ref = (finding.nist_family or "").strip()
        if nist_ref:
            mapping.nist_families.setdefault(nist_ref, []).append(summary)

    return mapping
