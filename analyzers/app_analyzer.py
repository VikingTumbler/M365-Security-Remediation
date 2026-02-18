"""
Application Security Analyzer
Analyzes: overprivileged apps, expiring secrets, OAuth consent exposure,
unused enterprise apps, admin consent risk.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import BaseAnalyzer, Finding

logger = logging.getLogger("m365_security_engine.analyzers.app")

HIGH_RISK_PERMISSIONS = {
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Sites.FullControl.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess",
    "AppRoleAssignment.ReadWrite.All",
}


class AppAnalyzer(BaseAnalyzer):
    name = "app_analyzer"
    domain = "app_protection"
    description = "Application security: overprivileged apps, secrets, OAuth consent"

    def _analyze(self, data: dict[str, Any]):
        apps_data = data.get("applications", {})
        app_regs = apps_data.get("app_registrations", [])
        sps = apps_data.get("service_principals", [])
        oauth_grants = apps_data.get("oauth2_grants", [])
        role_assignments = apps_data.get("app_role_assignments", [])

        if not app_regs and not sps:
            self.add_finding(
                control_name="No Application Data Collected",
                detection_logic="App registration/SP collection returned empty",
                severity="informational",
                score_impact=0,
            )
            return

        self._analyze_expiring_credentials(app_regs)
        self._analyze_overprivileged_apps(app_regs, role_assignments)
        self._analyze_oauth_consent(oauth_grants)
        self._analyze_multi_tenant_apps(app_regs)
        self._analyze_unused_sps(sps)

    def _analyze_expiring_credentials(self, apps: list):
        """Detect apps with expiring or expired credentials."""
        expired = [a for a in apps if a.get("hasExpiredCredentials")]
        expiring = [a for a in apps if a.get("hasExpiringCredentials")]

        if expired:
            self.add_finding(
                control_name="Apps with Expired Credentials",
                detection_logic="App registrations with expired secrets or certificates",
                evidence={
                    "expired_count": len(expired),
                    "apps": [
                        {
                            "name": a["displayName"],
                            "appId": a["appId"],
                            "expired": a["expiredSecrets"],
                        }
                        for a in expired[:15]
                    ],
                },
                severity="high",
                score_impact=min(len(expired) * 2, 15),
                risk_explanation=(
                    f"{len(expired)} apps have expired credentials. "
                    "This may indicate abandoned apps or broken automation."
                ),
                exploit_scenario="Abandoned app with expired creds may still have active permissions",
                blast_radius="Resources accessible by these app registrations",
                zero_trust_pillar="Applications",
                nist_family="IA — Identification and Authentication",
                maturity_level=2,
            )

        if expiring:
            self.add_finding(
                control_name="Apps with Soon-to-Expire Credentials",
                detection_logic="Credentials expiring within 30 days",
                evidence={
                    "expiring_count": len(expiring),
                    "apps": [
                        {
                            "name": a["displayName"],
                            "expiring": a["expiringSecrets"],
                        }
                        for a in expiring[:15]
                    ],
                },
                severity="medium",
                score_impact=min(len(expiring), 8),
                risk_explanation="Credential expiration may cause service outages if not rotated",
                zero_trust_pillar="Applications",
                nist_family="IA — Identification and Authentication",
                maturity_level=3,
            )

    def _analyze_overprivileged_apps(self, apps: list, role_assignments: list):
        """Detect apps with excessive application permissions."""
        high_priv_apps = []
        for a in apps:
            app_perms = a.get("applicationPermissions", [])
            if len(app_perms) > 5:
                high_priv_apps.append({
                    "name": a["displayName"],
                    "appId": a["appId"],
                    "applicationPermissionCount": len(app_perms),
                    "totalPermissions": a["permissionCount"],
                })

        if high_priv_apps:
            self.add_finding(
                control_name="Overprivileged App Registrations",
                detection_logic="Apps with >5 application-level (app-only) permissions",
                evidence={
                    "count": len(high_priv_apps),
                    "apps": sorted(high_priv_apps, key=lambda x: x["applicationPermissionCount"], reverse=True)[:10],
                },
                severity="high" if len(high_priv_apps) > 5 else "medium",
                score_impact=min(len(high_priv_apps) * 3, 15),
                risk_explanation=(
                    "Apps with many application permissions operate with high privilege. "
                    "Compromised app credentials grant broad tenant access."
                ),
                exploit_scenario="Leaked app secret used to read all mail, files, or directory data",
                blast_radius="All data accessible by the app's permissions",
                zero_trust_pillar="Applications",
                cis_benchmark="CIS 3.1 — Minimize app permissions",
                nist_family="AC — Access Control",
                maturity_level=2,
            )

    def _analyze_oauth_consent(self, grants: list):
        """Analyze OAuth2 permission grant patterns."""
        admin_consent_grants = [g for g in grants if g.get("isAdminConsent")]
        user_consent_grants = [g for g in grants if not g.get("isAdminConsent")]

        # Check for broad admin consent scopes
        broad_scopes = []
        for g in admin_consent_grants:
            scope_str = g.get("scope", "")
            scopes = scope_str.strip().split()
            risky = [s for s in scopes if any(h in s for h in [".ReadWrite.", ".All", "FullControl"])]
            if risky:
                broad_scopes.append({
                    "clientId": g["clientId"],
                    "resourceId": g["resourceId"],
                    "riskyScopes": risky,
                })

        if broad_scopes:
            self.add_finding(
                control_name="Broad Admin Consent Grants",
                detection_logic="Admin-consented OAuth2 grants with ReadWrite/All/FullControl scopes",
                evidence={
                    "count": len(broad_scopes),
                    "grants": broad_scopes[:10],
                },
                severity="high",
                score_impact=min(len(broad_scopes) * 3, 15),
                risk_explanation="Admin consent grants apply tenant-wide and bypass per-user consent",
                exploit_scenario="Compromised app with admin-consented broad permissions accesses all user data",
                blast_radius="Tenant-wide data access via consented scopes",
                zero_trust_pillar="Applications",
                nist_family="AC — Access Control",
                maturity_level=2,
            )

        if len(user_consent_grants) > 100:
            self.add_finding(
                control_name="Excessive User Consent Grants",
                detection_logic=f"{len(user_consent_grants)} user-level OAuth consent grants detected",
                evidence={
                    "user_consent_count": len(user_consent_grants),
                    "admin_consent_count": len(admin_consent_grants),
                },
                severity="medium",
                score_impact=5,
                risk_explanation="High volume of user consent grants may indicate illicit consent attack surface",
                zero_trust_pillar="Applications",
                nist_family="AC — Access Control",
                maturity_level=2,
            )

    def _analyze_multi_tenant_apps(self, apps: list):
        """Flag multi-tenant app registrations."""
        multi_tenant = [
            a for a in apps
            if a.get("signInAudience") in (
                "AzureADMultipleOrgs",
                "AzureADandPersonalMicrosoftAccount",
                "PersonalMicrosoftAccount",
            )
        ]

        if multi_tenant:
            self.add_finding(
                control_name="Multi-Tenant App Registrations",
                detection_logic="Apps accepting sign-in from external tenants or personal accounts",
                evidence={
                    "count": len(multi_tenant),
                    "apps": [
                        {"name": a["displayName"], "audience": a["signInAudience"]}
                        for a in multi_tenant[:10]
                    ],
                },
                severity="medium" if len(multi_tenant) > 5 else "low",
                score_impact=min(len(multi_tenant), 8),
                risk_explanation="Multi-tenant apps can be accessed by external identities",
                zero_trust_pillar="Applications",
                nist_family="AC — Access Control",
                maturity_level=3,
            )

    def _analyze_unused_sps(self, sps: list):
        """Flag enterprise apps that appear unused."""
        disabled_sps = [sp for sp in sps if not sp.get("accountEnabled") and not sp.get("isFirstParty")]

        if disabled_sps:
            self.add_finding(
                control_name="Disabled Enterprise Applications",
                detection_logic="Non-Microsoft service principals with accountEnabled=false",
                evidence={
                    "count": len(disabled_sps),
                    "apps": [sp["displayName"] for sp in disabled_sps[:15]],
                },
                severity="low",
                score_impact=2,
                risk_explanation="Disabled enterprise apps may still have permission grants that should be revoked",
                zero_trust_pillar="Applications",
                nist_family="AC — Access Control",
                maturity_level=3,
            )
