"""
Privilege & Entitlement Analyzer
Analyzes: privilege creep, admin sprawl, toxic combinations, orphaned assignments,
standing privilege exposure, role overlap index.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from typing import Any

from .base import BaseAnalyzer, Finding

logger = logging.getLogger("m365_security_engine.analyzers.privilege")

# Toxic role pairs
TOXIC_PAIRS = [
    ("Global Administrator", "Exchange Administrator"),
    ("Global Administrator", "SharePoint Administrator"),
    ("Application Administrator", "Cloud Application Administrator"),
    ("User Administrator", "Privileged Role Administrator"),
    ("Global Administrator", "Conditional Access Administrator"),
    ("Application Administrator", "Privileged Role Administrator"),
]

CRITICAL_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Security Administrator",
    "User Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Conditional Access Administrator",
    "Intune Administrator",
}


class PrivilegeAnalyzer(BaseAnalyzer):
    name = "privilege_analyzer"
    domain = "privileged_access"
    description = "Privilege analysis: standing access, role overlap, toxic combos, sprawl"

    def _analyze(self, data: dict[str, Any]):
        privilege = data.get("privilege", {})
        identity = data.get("identity", {})

        role_defs = privilege.get("role_definitions", [])
        assignments = privilege.get("unified_role_assignments", [])
        principal_map = privilege.get("principal_role_map", {})
        admin_consent = privilege.get("admin_consent_policy", {})

        pim_eligible = identity.get("pim_eligible_assignments", [])
        pim_active = identity.get("pim_active_assignments", [])
        users = identity.get("users", [])

        # Build role name lookup
        role_name_map = {r["id"]: r["displayName"] for r in role_defs}

        self._analyze_standing_privilege(assignments, pim_eligible, role_name_map)
        self._analyze_role_overlap(principal_map, role_name_map)
        self._analyze_toxic_combinations(principal_map, role_name_map)
        self._analyze_admin_sprawl(assignments, users)
        self._analyze_orphaned_assignments(assignments, users)
        self._analyze_privilege_creep(principal_map, role_name_map)
        self._analyze_consent_policy(admin_consent)

    def _analyze_standing_privilege(self, assignments: list, eligible: list, role_names: dict):
        """Assess standing vs eligible privilege ratio."""
        total_permanent = len(assignments)
        total_eligible = len(eligible)

        if total_permanent > 0 and total_eligible == 0:
            self.add_finding(
                control_name="100% Standing Privilege (No PIM)",
                detection_logic="All role assignments are permanent; no PIM eligible assignments found",
                evidence={
                    "permanent_assignments": total_permanent,
                    "eligible_assignments": total_eligible,
                },
                severity="high",
                score_impact=20,
                risk_explanation=(
                    "All admin roles are permanently active. PIM (just-in-time access) is not in use. "
                    "Standing privileges maximize blast radius of any admin compromise."
                ),
                exploit_scenario="Compromised admin account has 24/7 full privilege access",
                blast_radius="All permanent admin role scopes",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.3 — Use PIM for admin roles",
                nist_family="AC — Access Control",
                maturity_level=1,
            )
        elif total_permanent > 0 and total_eligible > 0:
            pim_ratio = (total_eligible / (total_permanent + total_eligible)) * 100
            if pim_ratio < 50:
                self.add_finding(
                    control_name="Low PIM Adoption",
                    detection_logic=f"Only {pim_ratio:.0f}% of role assignments are PIM-eligible",
                    evidence={
                        "permanent": total_permanent,
                        "eligible": total_eligible,
                        "pim_coverage_pct": round(pim_ratio, 1),
                    },
                    severity="medium",
                    score_impact=10,
                    risk_explanation="Most admin roles remain permanently assigned despite PIM availability",
                    zero_trust_pillar="Identities",
                    nist_family="AC — Access Control",
                    maturity_level=2,
                )

    def _analyze_role_overlap(self, principal_map: dict, role_names: dict):
        """Compute role overlap index (principals with multiple roles)."""
        multi_role_principals = {
            pid: info for pid, info in principal_map.items()
            if len(info.get("roles", [])) > 1
        }

        if multi_role_principals:
            overlap_details = []
            for pid, info in list(multi_role_principals.items())[:20]:
                names = [role_names.get(r, r) for r in info["roles"]]
                overlap_details.append({
                    "principal": info.get("principalDisplayName"),
                    "type": info.get("principalType"),
                    "roleCount": len(names),
                    "roles": names,
                })

            overlap_index = len(multi_role_principals) / max(len(principal_map), 1) * 100

            self.add_finding(
                control_name="Role Overlap Density",
                detection_logic="Principals holding multiple directory roles simultaneously",
                evidence={
                    "multi_role_principals": len(multi_role_principals),
                    "total_principals": len(principal_map),
                    "overlap_index": round(overlap_index, 1),
                    "top_overlaps": sorted(overlap_details, key=lambda x: x["roleCount"], reverse=True)[:10],
                },
                severity="high" if overlap_index > 30 else "medium",
                score_impact=min(overlap_index * 0.3, 15),
                risk_explanation="Role overlap increases the blast radius when a single principal is compromised",
                exploit_scenario="Single compromised account yields access across multiple admin scopes",
                blast_radius=f"{len(multi_role_principals)} principals with overlapping roles",
                zero_trust_pillar="Identities",
                nist_family="AC — Access Control",
                maturity_level=2,
            )

    def _analyze_toxic_combinations(self, principal_map: dict, role_names: dict):
        """Detect toxic role combination pairs."""
        toxic_found = []

        for pid, info in principal_map.items():
            role_display_names = set(role_names.get(r, r) for r in info.get("roles", []))
            for pair in TOXIC_PAIRS:
                if pair[0] in role_display_names and pair[1] in role_display_names:
                    toxic_found.append({
                        "principal": info.get("principalDisplayName"),
                        "type": info.get("principalType"),
                        "toxic_pair": list(pair),
                        "all_roles": list(role_display_names),
                    })

        if toxic_found:
            self.add_finding(
                control_name="Toxic Role Combinations Detected",
                detection_logic="Principals holding pairs of roles that create dangerous privilege combinations",
                evidence={
                    "toxic_combination_count": len(toxic_found),
                    "details": toxic_found[:15],
                },
                severity="critical" if len(toxic_found) > 3 else "high",
                score_impact=min(len(toxic_found) * 5, 25),
                risk_explanation=(
                    "Toxic role combinations allow a single identity to perform "
                    "operations that should require separation of duties."
                ),
                exploit_scenario=(
                    "GA + Exchange Admin: attacker creates mail flow rules to exfiltrate data "
                    "while having full directory control to cover tracks"
                ),
                blast_radius="Multiple admin scopes controlled by single identity",
                zero_trust_pillar="Identities",
                nist_family="AC — Access Control (Separation of Duties)",
                maturity_level=1,
            )

    def _analyze_admin_sprawl(self, assignments: list, users: list):
        """Measure admin sprawl density."""
        unique_admins = set(a.get("principalId") for a in assignments)
        total_users = len(users)

        if total_users > 0:
            sprawl_pct = (len(unique_admins) / total_users) * 100
            self.add_finding(
                control_name="Admin Sprawl Index",
                detection_logic=f"Unique admin principals / total users = {sprawl_pct:.1f}%",
                evidence={
                    "unique_admin_principals": len(unique_admins),
                    "total_users": total_users,
                    "sprawl_percentage": round(sprawl_pct, 2),
                },
                severity="high" if sprawl_pct > 10 else "medium" if sprawl_pct > 5 else "informational",
                score_impact=min(sprawl_pct, 15),
                risk_explanation=f"{len(unique_admins)} unique admins across {total_users} users",
                zero_trust_pillar="Identities",
                nist_family="AC — Access Control",
                maturity_level=4 if sprawl_pct < 3 else 2,
            )

    def _analyze_orphaned_assignments(self, assignments: list, users: list):
        """Detect role assignments to non-existent or disabled principals."""
        user_ids = {u.get("id") for u in users}
        enabled_ids = {u.get("id") for u in users if u.get("accountEnabled")}

        orphaned = []
        disabled_admin = []
        for a in assignments:
            pid = a.get("principalId")
            if pid and pid not in user_ids and a.get("principalType") in ("user", "User"):
                orphaned.append(a)
            elif pid and pid not in enabled_ids and pid in user_ids:
                disabled_admin.append(a)

        if orphaned:
            self.add_finding(
                control_name="Orphaned Role Assignments",
                detection_logic="Role assignments to principals not found in user directory",
                evidence={
                    "orphaned_count": len(orphaned),
                    "sample": [
                        {"roleDefId": a["roleDefinitionId"], "principalId": a["principalId"]}
                        for a in orphaned[:10]
                    ],
                },
                severity="medium",
                score_impact=min(len(orphaned) * 2, 10),
                risk_explanation="Orphaned role assignments may indicate deleted but not cleaned up references",
                zero_trust_pillar="Identities",
                nist_family="AC — Access Control",
                maturity_level=2,
            )

        if disabled_admin:
            self.add_finding(
                control_name="Disabled Users with Active Role Assignments",
                detection_logic="Disabled user accounts still holding directory role assignments",
                evidence={
                    "count": len(disabled_admin),
                    "sample": [
                        {"principalId": a["principalId"], "role": a.get("roleDefinitionId")}
                        for a in disabled_admin[:10]
                    ],
                },
                severity="medium",
                score_impact=min(len(disabled_admin) * 2, 10),
                risk_explanation="Role assignments on disabled accounts should be removed",
                zero_trust_pillar="Identities",
                nist_family="AC — Access Control",
                maturity_level=2,
            )

    def _analyze_privilege_creep(self, principal_map: dict, role_names: dict):
        """Score privilege creep across all principals."""
        creep_scores = []
        for pid, info in principal_map.items():
            roles = info.get("roles", [])
            display_names = {role_names.get(r, r) for r in roles}
            critical_count = len(display_names & CRITICAL_ROLES)
            total_roles = len(roles)

            creep_score = (critical_count * 3) + total_roles
            if creep_score > 5:
                creep_scores.append({
                    "principal": info.get("principalDisplayName"),
                    "type": info.get("principalType"),
                    "creep_score": creep_score,
                    "critical_roles": critical_count,
                    "total_roles": total_roles,
                })

        if creep_scores:
            creep_scores.sort(key=lambda x: x["creep_score"], reverse=True)
            avg_creep = sum(c["creep_score"] for c in creep_scores) / len(creep_scores)

            self.add_finding(
                control_name="Privilege Creep Scoring",
                detection_logic="Composite score: (critical_roles × 3) + total_roles per principal",
                evidence={
                    "principals_with_creep": len(creep_scores),
                    "average_creep_score": round(avg_creep, 1),
                    "top_creep": creep_scores[:10],
                },
                severity="high" if avg_creep > 10 else "medium",
                score_impact=min(avg_creep * 1.5, 15),
                risk_explanation="High creep scores indicate accumulated privileges beyond operational need",
                zero_trust_pillar="Identities",
                nist_family="AC — Access Control",
                maturity_level=2 if avg_creep < 5 else 1,
            )

    def _analyze_consent_policy(self, policy: dict):
        """Analyze admin consent workflow configuration."""
        if not policy.get("isEnabled"):
            self.add_finding(
                control_name="Admin Consent Workflow Disabled",
                detection_logic="adminConsentRequestPolicy.isEnabled=false",
                evidence=policy,
                severity="medium",
                score_impact=5,
                risk_explanation=(
                    "Without admin consent workflow, users may be blocked from requesting app access, "
                    "or consent may be handled ad-hoc."
                ),
                zero_trust_pillar="Applications",
                nist_family="AC — Access Control",
                maturity_level=2,
            )
