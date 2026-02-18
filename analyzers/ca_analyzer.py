"""
Conditional Access Analyzer
Analyzes: policy coverage, gaps, overlaps, shadow-allow paths, legacy auth,
risk-based policies, admin portal protections, session controls.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import BaseAnalyzer, Finding

logger = logging.getLogger("m365_security_engine.analyzers.ca")


class ConditionalAccessAnalyzer(BaseAnalyzer):
    name = "ca_analyzer"
    domain = "conditional_access"
    description = "Conditional Access policy analysis: gaps, overlaps, exclusions, legacy auth"

    def _analyze(self, data: dict[str, Any]):
        ca_data = data.get("conditional_access", {})
        policies = ca_data.get("ca_policies", [])
        security_defaults = ca_data.get("security_defaults", {})
        auth_methods_policy = ca_data.get("auth_methods_policy", {})
        named_locations = ca_data.get("named_locations", [])

        # Detect whether the collector was blocked by missing permissions
        metadata = ca_data.get("_metadata", {})
        permission_gaps = metadata.get("permission_gaps", [])
        ca_inaccessible = any(
            "conditionalAccess/policies" in gap for gap in permission_gaps
        )
        sd_inaccessible = security_defaults.get("_inaccessible", False)

        if not policies and ca_inaccessible:
            # Could not read policies — report the data gap, NOT a false "no policies" finding
            self.add_finding(
                control_name="Conditional Access Policies Inaccessible",
                detection_logic="Graph API returned 403 for identity/conditionalAccess/policies",
                severity="medium",
                score_impact=5,
                evidence={
                    "permission_gaps": [g for g in permission_gaps if "conditionalAccess" in g],
                    "required_permission": "Policy.Read.All",
                },
                risk_explanation=(
                    "Cannot assess Conditional Access posture. The service principal "
                    "lacks Policy.Read.All permission. Grant this permission and re-scan."
                ),
                blast_radius="Assessment gap — CA posture unknown",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.2 — Conditional Access",
                nist_family="AC — Access Control",
                maturity_level=0,
            )
            return

        sd_enabled = security_defaults.get("isEnabled") if not sd_inaccessible else None

        if not policies and not sd_enabled:
            if sd_inaccessible:
                # Can't confirm security defaults either
                self.add_finding(
                    control_name="Conditional Access & Security Defaults State Unknown",
                    detection_logic=(
                        "Zero CA policies found and security defaults status inaccessible (403)"
                    ),
                    severity="medium",
                    score_impact=5,
                    evidence={"ca_policy_count": 0, "security_defaults_accessible": False},
                    risk_explanation=(
                        "No CA policies were returned and the security defaults endpoint was "
                        "also inaccessible. This may be a permissions gap rather than a real "
                        "absence. Grant Policy.Read.All and re-scan."
                    ),
                    blast_radius="Assessment gap",
                    zero_trust_pillar="Identities",
                    cis_benchmark="CIS 1.2 — Conditional Access",
                    nist_family="AC — Access Control",
                    maturity_level=0,
                )
                return

            self.add_finding(
                control_name="No Conditional Access Policies and Security Defaults Disabled",
                detection_logic="Zero CA policies found and security defaults not enabled",
                severity="critical",
                score_impact=40,
                risk_explanation="Tenant has no access controls beyond basic password authentication",
                exploit_scenario="Any valid credential grants unrestricted access from anywhere",
                blast_radius="Entire tenant — all users, all applications",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.2 — Conditional Access",
                nist_family="AC — Access Control",
                maturity_level=0,
            )
            return

        if security_defaults.get("isEnabled") and policies:
            self.add_finding(
                control_name="Security Defaults Enabled Alongside CA Policies",
                detection_logic="Both security defaults and CA policies are active",
                evidence={"security_defaults_enabled": True, "ca_policy_count": len(policies)},
                severity="medium",
                score_impact=5,
                risk_explanation="Security defaults may interfere with CA policy evaluation",
                zero_trust_pillar="Identities",
                maturity_level=2,
            )

        self._analyze_enabled_policies(policies)
        self._analyze_mfa_coverage(policies)
        self._analyze_legacy_auth(policies)
        self._analyze_exclusions(policies)
        self._analyze_risk_policies(policies)
        self._analyze_device_controls(policies)
        self._analyze_session_controls(policies)
        self._analyze_admin_protection(policies)
        self._analyze_overlap_and_gaps(policies)
        self._analyze_unassigned_policies(policies)

    def _analyze_enabled_policies(self, policies: list):
        """Check for disabled and report-only policies."""
        enabled = [p for p in policies if p.get("state") == "enabled"]
        disabled = [p for p in policies if p.get("state") == "disabled"]
        report_only = [p for p in policies if p.get("state") == "enabledForReportingButNotEnforced"]

        if disabled:
            self.add_finding(
                control_name="Disabled Conditional Access Policies",
                detection_logic="Policies with state=disabled",
                evidence={
                    "disabled_count": len(disabled),
                    "policies": [{"name": p["displayName"], "id": p["id"]} for p in disabled],
                },
                severity="low",
                score_impact=2,
                risk_explanation="Disabled policies may represent intended controls not yet enforced",
                zero_trust_pillar="Identities",
                maturity_level=3,
            )

        self.add_finding(
            control_name="CA Policy Inventory",
            detection_logic="Enumeration of all CA policy states",
            evidence={
                "total": len(policies),
                "enabled": len(enabled),
                "disabled": len(disabled),
                "report_only": len(report_only),
            },
            severity="informational",
            score_impact=0,
            zero_trust_pillar="Identities",
            maturity_level=4 if len(enabled) >= 5 else 2,
        )

    def _analyze_mfa_coverage(self, policies: list):
        """Assess MFA requirements across policies."""
        enabled = [p for p in policies if p.get("state") == "enabled"]
        mfa_policies = [p for p in enabled if p.get("requiresMFA")]
        mfa_all_users = [p for p in mfa_policies if p.get("targetsAllUsers")]
        mfa_all_apps = [p for p in mfa_policies if p.get("targetsAllApps")]

        if not mfa_policies:
            self.add_finding(
                control_name="No MFA Enforcement via Conditional Access",
                detection_logic="No enabled CA policy with 'mfa' in grant controls",
                severity="critical",
                score_impact=30,
                risk_explanation="No CA policy enforces MFA — authentication relies on password alone",
                exploit_scenario="Password spray or phishing grants direct access without MFA challenge",
                blast_radius="All users and applications not protected by MFA",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.2.1 — MFA for all users",
                nist_family="IA — Identification and Authentication",
                maturity_level=0,
            )
        elif not mfa_all_users or not mfa_all_apps:
            # MFA exists but not comprehensive
            self.add_finding(
                control_name="Partial MFA Coverage",
                detection_logic="MFA policies exist but don't target All Users + All Apps",
                evidence={
                    "mfa_policy_count": len(mfa_policies),
                    "targets_all_users": len(mfa_all_users),
                    "targets_all_apps": len(mfa_all_apps),
                    "policies": [p["displayName"] for p in mfa_policies],
                },
                severity="high",
                score_impact=15,
                risk_explanation="Some users or apps may not require MFA, creating gaps",
                exploit_scenario="Attacker targets apps or user segments not covered by MFA policies",
                blast_radius="Users/apps not covered by MFA policies",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.2.1 — MFA for all users",
                nist_family="IA — Identification and Authentication",
                maturity_level=2,
            )

    def _analyze_legacy_auth(self, policies: list):
        """Check for legacy authentication blocking."""
        enabled = [p for p in policies if p.get("state") == "enabled"]

        legacy_block_policies = [
            p for p in enabled
            if p.get("blocksAccess") and p.get("hasLegacyClientBlock")
        ]

        if not legacy_block_policies:
            self.add_finding(
                control_name="Legacy Authentication Not Blocked",
                detection_logic="No enabled CA policy blocks legacy auth (Exchange ActiveSync, etc.)",
                severity="high",
                score_impact=15,
                risk_explanation=(
                    "Legacy authentication protocols (IMAP, POP3, SMTP, ActiveSync) "
                    "do not support MFA and are primary targets for password spray attacks."
                ),
                exploit_scenario="Password spray against IMAP endpoint bypasses all MFA controls",
                blast_radius="All mailboxes accessible via legacy protocols",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.2.2 — Block legacy authentication",
                nist_family="AC — Access Control",
                maturity_level=0,
            )

    def _analyze_exclusions(self, policies: list):
        """Analyze exclusion patterns for shadow-allow paths."""
        enabled = [p for p in policies if p.get("state") == "enabled"]

        all_excluded_users = set()
        all_excluded_groups = set()
        policies_with_exclusions = []

        for p in enabled:
            if p.get("hasExclusions"):
                excluded_users = set(p.get("excludeUsers", []))
                excluded_groups = set(p.get("excludeGroups", []))
                all_excluded_users.update(excluded_users)
                all_excluded_groups.update(excluded_groups)
                policies_with_exclusions.append({
                    "name": p["displayName"],
                    "excludedUsers": list(excluded_users),
                    "excludedGroups": list(excluded_groups),
                })

        if all_excluded_users or all_excluded_groups:
            self.add_finding(
                control_name="CA Policy Exclusion Analysis",
                detection_logic="Aggregated exclusions across all enabled CA policies",
                evidence={
                    "policies_with_exclusions": len(policies_with_exclusions),
                    "unique_excluded_users": len(all_excluded_users),
                    "unique_excluded_groups": len(all_excluded_groups),
                    "detail": policies_with_exclusions[:10],
                },
                severity="medium" if all_excluded_users else "low",
                score_impact=min(len(all_excluded_users) * 2 + len(all_excluded_groups), 15),
                risk_explanation=(
                    "Excluded users/groups bypass CA controls. "
                    "These create shadow-allow paths that attackers can exploit."
                ),
                exploit_scenario="Attacker compromises an excluded account to bypass all CA policies",
                blast_radius=f"{len(all_excluded_users)} users + {len(all_excluded_groups)} groups excluded",
                zero_trust_pillar="Identities",
                nist_family="AC — Access Control",
                maturity_level=2,
            )

    def _analyze_risk_policies(self, policies: list):
        """Check for risk-based Conditional Access policies."""
        enabled = [p for p in policies if p.get("state") == "enabled"]
        risk_policies = [p for p in enabled if p.get("usesRiskSignals")]

        sign_in_risk = [p for p in risk_policies if p.get("signInRiskLevels")]
        user_risk = [p for p in risk_policies if p.get("userRiskLevels")]

        if not sign_in_risk:
            self.add_finding(
                control_name="No Sign-In Risk Policy",
                detection_logic="No enabled CA policy uses signInRiskLevels condition",
                severity="high",
                score_impact=10,
                risk_explanation="Without sign-in risk policies, risky sign-ins are not automatically challenged",
                exploit_scenario="Attacker signs in from compromised infrastructure without additional challenge",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.2.4 — Risk-based Conditional Access",
                nist_family="SI — System and Information Integrity",
                maturity_level=1,
            )

        if not user_risk:
            self.add_finding(
                control_name="No User Risk Policy",
                detection_logic="No enabled CA policy uses userRiskLevels condition",
                severity="high",
                score_impact=10,
                risk_explanation="Compromised users are not automatically required to reset credentials",
                exploit_scenario="User with leaked credentials continues to access resources normally",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.2.4 — Risk-based Conditional Access",
                nist_family="SI — System and Information Integrity",
                maturity_level=1,
            )

    def _analyze_device_controls(self, policies: list):
        """Check device-based CA controls."""
        enabled = [p for p in policies if p.get("state") == "enabled"]

        compliant_device_policies = [p for p in enabled if p.get("requiresCompliantDevice")]
        device_filter_policies = [p for p in enabled if p.get("usesDeviceFilter")]

        if not compliant_device_policies:
            self.add_finding(
                control_name="No Device Compliance Requirement in CA",
                detection_logic="No enabled CA policy requires compliantDevice grant control",
                severity="medium",
                score_impact=8,
                risk_explanation="Resources accessible from non-compliant/unmanaged devices",
                exploit_scenario="Data accessed from compromised personal device",
                zero_trust_pillar="Devices",
                nist_family="AC — Access Control",
                maturity_level=1,
            )

    def _analyze_session_controls(self, policies: list):
        """Evaluate session control configuration."""
        enabled = [p for p in policies if p.get("state") == "enabled"]

        sign_in_frequency = [
            p for p in enabled
            if p.get("signInFrequency") and p["signInFrequency"].get("isEnabled")
        ]

        if not sign_in_frequency:
            self.add_finding(
                control_name="No Sign-In Frequency Controls",
                detection_logic="No CA policy enforces sign-in frequency for sensitive apps",
                severity="low",
                score_impact=3,
                risk_explanation="Users may maintain sessions indefinitely without re-authentication",
                zero_trust_pillar="Identities",
                nist_family="AC — Access Control",
                maturity_level=2,
            )

    def _analyze_admin_protection(self, policies: list):
        """Check if admin roles are specifically targeted by CA policies."""
        enabled = [p for p in policies if p.get("state") == "enabled"]

        admin_targeted = [
            p for p in enabled
            if p.get("includeRoles") and p.get("requiresMFA")
        ]

        if not admin_targeted:
            self.add_finding(
                control_name="No Admin-Specific CA Policy",
                detection_logic="No enabled CA policy targets admin roles with MFA requirement",
                severity="high",
                score_impact=12,
                risk_explanation="Admin accounts not specifically protected by CA — rely on general policies only",
                exploit_scenario="Admin account compromised without elevated MFA requirement",
                blast_radius="All admin portals and capabilities",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.2.3 — MFA for admin roles",
                nist_family="AC — Access Control",
                maturity_level=1,
            )

    def _analyze_overlap_and_gaps(self, policies: list):
        """Detect logical overlaps and potential conflicts."""
        enabled = [p for p in policies if p.get("state") == "enabled"]

        # Check for conflicting grant controls on same scope
        all_users_all_apps = [
            p for p in enabled
            if p.get("targetsAllUsers") and p.get("targetsAllApps")
        ]

        block_and_allow = []
        for p1 in all_users_all_apps:
            for p2 in all_users_all_apps:
                if p1["id"] != p2["id"]:
                    if p1.get("blocksAccess") and p2.get("requiresMFA"):
                        block_and_allow.append({
                            "blocking": p1["displayName"],
                            "allowing": p2["displayName"],
                        })

        if block_and_allow:
            self.add_finding(
                control_name="Potentially Conflicting CA Policies",
                detection_logic="Both block and MFA-require policies target All Users + All Apps",
                evidence={"conflicts": block_and_allow[:5]},
                severity="medium",
                score_impact=5,
                risk_explanation="Conflicting policies may produce unexpected evaluation results",
                zero_trust_pillar="Identities",
                nist_family="AC — Access Control",
                maturity_level=2,
            )

    def _analyze_unassigned_policies(self, policies: list):
        """Detect policies that don't effectively target anyone."""
        empty_target = [
            p for p in policies
            if p.get("state") == "enabled"
            and not p.get("includeUsers")
            and not p.get("includeGroups")
            and not p.get("includeRoles")
        ]

        if empty_target:
            self.add_finding(
                control_name="CA Policies Without User Targeting",
                detection_logic="Enabled policies with no includeUsers, includeGroups, or includeRoles",
                evidence={
                    "count": len(empty_target),
                    "policies": [p["displayName"] for p in empty_target],
                },
                severity="medium",
                score_impact=5,
                risk_explanation="These policies may not be protecting anyone",
                zero_trust_pillar="Identities",
                nist_family="AC — Access Control",
                maturity_level=2,
            )
