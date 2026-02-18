"""
Identity Security Analyzer
Analyzes: MFA posture, dormant accounts, guest exposure, service accounts,
admin role hygiene, break-glass accounts, password policies.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import BaseAnalyzer, Finding

logger = logging.getLogger("m365_security_engine.analyzers.identity")


class IdentityAnalyzer(BaseAnalyzer):
    name = "identity_analyzer"
    domain = "identity_security"
    description = "Identity surface analysis: MFA, dormant, guests, admins, PIM"

    def _analyze(self, data: dict[str, Any]):
        identity = data.get("identity", {})
        users = identity.get("users", [])
        auth_methods = identity.get("user_auth_methods", {})
        groups = identity.get("groups", [])
        roles = identity.get("directory_roles", [])
        role_assignments = identity.get("role_assignments", [])
        risky_users = identity.get("risky_users", [])
        pim_eligible = identity.get("pim_eligible_assignments", [])
        pim_active = identity.get("pim_active_assignments", [])
        domains = identity.get("domains", [])

        if not users:
            self.add_finding(
                control_name="No User Data Collected",
                detection_logic="User collection returned empty",
                severity="informational",
                risk_explanation="Cannot perform identity analysis without user data",
            )
            return

        self._analyze_mfa_posture(users, auth_methods)
        self._analyze_dormant_accounts(users)
        self._analyze_guest_exposure(users)
        self._analyze_service_accounts(users)
        self._analyze_admin_roles(role_assignments, users)
        self._analyze_breakglass(users, role_assignments)
        self._analyze_risky_users(risky_users)
        self._analyze_pim(pim_eligible, pim_active, role_assignments)
        self._analyze_federation(domains)
        self._analyze_groups(groups)
        self._analyze_password_policies(users)

    def _analyze_mfa_posture(self, users: list, auth_methods: dict):
        """Assess MFA registration coverage."""
        enabled_members = [u for u in users if u.get("accountEnabled") and not u.get("isGuest")]
        total = len(enabled_members)
        if total == 0:
            return

        # Check if auth methods collection was blocked by permissions
        # When batch sub-requests return 403, the map is empty but users exist
        users_with_data = sum(
            1 for u in enabled_members if u.get("id") in auth_methods
        )
        if users_with_data == 0 and total > 0:
            # No auth method data for ANY user — almost certainly a permission gap
            self.add_finding(
                control_name="MFA Registration Data Inaccessible",
                detection_logic=(
                    "Authentication methods API returned no data for any user. "
                    "This typically indicates a missing UserAuthenticationMethod.Read.All "
                    "application permission on the service principal."
                ),
                evidence={
                    "total_enabled_members": total,
                    "users_with_auth_data": 0,
                    "required_permission": "UserAuthenticationMethod.Read.All",
                },
                severity="medium",
                score_impact=5,
                risk_explanation=(
                    "Cannot assess MFA registration coverage. Grant the "
                    "UserAuthenticationMethod.Read.All permission and re-scan."
                ),
                blast_radius="Assessment gap — MFA posture unknown",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.1.1 — Ensure MFA is enabled for all users",
                nist_family="IA — Identification and Authentication",
                maturity_level=0,
            )
            return

        weak_mfa_users = []
        no_mfa_users = []

        for user in enabled_members:
            uid = user.get("id")
            methods = auth_methods.get(uid, [])
            method_types = {m.get("type", "") for m in methods}

            strong_methods = {
                "fido2AuthenticationMethod",
                "microsoftAuthenticatorAuthenticationMethod",
                "windowsHelloForBusinessAuthenticationMethod",
                "phoneAuthenticationMethod",
                "softwareOathAuthenticationMethod",
            }

            weak_methods = {
                "smsAuthenticationMethod",
                "emailAuthenticationMethod",
            }

            has_strong = bool(method_types & strong_methods)
            has_weak_only = bool(method_types & weak_methods) and not has_strong
            has_none = not (method_types - {"passwordAuthenticationMethod"})

            if has_none:
                no_mfa_users.append(user.get("userPrincipalName"))
            elif has_weak_only:
                weak_mfa_users.append(user.get("userPrincipalName"))

        no_mfa_pct = (len(no_mfa_users) / total) * 100 if total else 0
        weak_mfa_pct = (len(weak_mfa_users) / total) * 100 if total else 0

        if no_mfa_pct > 0:
            severity = "critical" if no_mfa_pct > 20 else "high" if no_mfa_pct > 5 else "medium"
            self.add_finding(
                control_name="Users Without MFA Registration",
                detection_logic="Users with only password auth method registered (no second factor)",
                evidence={
                    "total_enabled_members": total,
                    "users_without_mfa": len(no_mfa_users),
                    "percentage": round(no_mfa_pct, 1),
                    "sample_users": no_mfa_users[:20],
                },
                severity=severity,
                score_impact=min(no_mfa_pct * 0.5, 30),
                risk_explanation=(
                    f"{len(no_mfa_users)} users ({no_mfa_pct:.1f}%) have no MFA method registered. "
                    "These accounts are vulnerable to password spray and credential stuffing."
                ),
                exploit_scenario=(
                    "Attacker obtains credentials via phishing or password spray. "
                    "Without MFA, direct access is granted to mailbox, Teams, SharePoint."
                ),
                blast_radius=f"Up to {len(no_mfa_users)} user accounts and their associated data",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.1.1 — Ensure MFA is enabled for all users",
                nist_family="IA — Identification and Authentication",
                maturity_level=1 if no_mfa_pct < 10 else 0,
            )

        if weak_mfa_pct > 10:
            self.add_finding(
                control_name="Users with Weak MFA Methods Only",
                detection_logic="Users registered only with SMS or email as second factor",
                evidence={
                    "users_with_weak_mfa_only": len(weak_mfa_users),
                    "percentage": round(weak_mfa_pct, 1),
                    "sample_users": weak_mfa_users[:20],
                },
                severity="medium",
                score_impact=min(weak_mfa_pct * 0.2, 10),
                risk_explanation=(
                    "SMS and email MFA are susceptible to SIM-swap and email compromise attacks."
                ),
                exploit_scenario="SIM-swap attack intercepts SMS OTP codes",
                blast_radius=f"{len(weak_mfa_users)} accounts using weak second factors",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.1.2 — Ensure phishing-resistant MFA",
                nist_family="IA — Identification and Authentication",
                maturity_level=2,
            )

    def _analyze_dormant_accounts(self, users: list):
        """Detect dormant (inactive) accounts."""
        enabled_users = [u for u in users if u.get("accountEnabled")]
        dormant = [u for u in enabled_users if u.get("isDormant")]

        if not dormant:
            return

        dormant_pct = (len(dormant) / len(enabled_users)) * 100 if enabled_users else 0

        self.add_finding(
            control_name="Dormant User Accounts",
            detection_logic="Enabled accounts with no sign-in activity in 90+ days",
            evidence={
                "dormant_count": len(dormant),
                "total_enabled": len(enabled_users),
                "percentage": round(dormant_pct, 1),
                "sample": [
                    {"upn": u["userPrincipalName"], "lastSignIn": u.get("lastSignInDateTime")}
                    for u in dormant[:20]
                ],
            },
            severity="high" if dormant_pct > 15 else "medium",
            score_impact=min(dormant_pct * 0.3, 15),
            risk_explanation=(
                f"{len(dormant)} accounts are enabled but dormant. "
                "Attackers target dormant accounts as they're less likely to trigger user alerts."
            ),
            exploit_scenario="Compromised dormant account used for lateral movement undetected",
            blast_radius=f"{len(dormant)} dormant accounts with potential data access",
            zero_trust_pillar="Identities",
            cis_benchmark="CIS 1.1.5 — Disable dormant accounts",
            nist_family="AC — Access Control",
            maturity_level=2 if dormant_pct < 5 else 1,
        )

    def _analyze_guest_exposure(self, users: list):
        """Analyze guest user posture."""
        guests = [u for u in users if u.get("isGuest")]
        enabled_guests = [g for g in guests if g.get("accountEnabled")]
        dormant_guests = [g for g in enabled_guests if g.get("isDormant")]

        if guests:
            self.add_finding(
                control_name="Guest User Inventory",
                detection_logic="Enumeration of guest (B2B) accounts",
                evidence={
                    "total_guests": len(guests),
                    "enabled_guests": len(enabled_guests),
                    "dormant_guests": len(dormant_guests),
                },
                severity="medium" if dormant_guests else "informational",
                score_impact=min(len(dormant_guests) * 0.5, 10),
                risk_explanation=(
                    f"{len(guests)} guest accounts exist. "
                    f"{len(dormant_guests)} are dormant but still enabled."
                ),
                exploit_scenario="Dormant guest account compromised for external access to tenant data",
                blast_radius="External identity with potential access to shared resources",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.1.6 — Review guest access",
                nist_family="AC — Access Control",
                maturity_level=3 if not dormant_guests else 1,
            )

    def _analyze_service_accounts(self, users: list):
        """Heuristic detection of service accounts."""
        service_patterns = ["svc", "service", "app_", "bot", "automation", "noreply", "scan"]
        service_accounts = []

        for user in users:
            upn = (user.get("userPrincipalName") or "").lower()
            name = (user.get("displayName") or "").lower()
            if any(p in upn or p in name for p in service_patterns):
                service_accounts.append({
                    "upn": user.get("userPrincipalName"),
                    "enabled": user.get("accountEnabled"),
                    "lastSignIn": user.get("lastSignInDateTime"),
                    "hasLicense": user.get("hasLicense"),
                })

        if service_accounts:
            licensed_svc = [s for s in service_accounts if s.get("hasLicense")]
            self.add_finding(
                control_name="Service Account Detection (Heuristic)",
                detection_logic="Pattern matching on UPN/displayName for service-like accounts",
                evidence={
                    "detected_count": len(service_accounts),
                    "licensed_service_accounts": len(licensed_svc),
                    "accounts": service_accounts[:20],
                },
                severity="medium" if licensed_svc else "low",
                score_impact=5 if licensed_svc else 2,
                risk_explanation=(
                    "Service accounts often have weaker monitoring and may lack MFA. "
                    "Licensed service accounts may indicate unnecessary license spend."
                ),
                exploit_scenario="Compromised service account used for persistent access",
                blast_radius="Varies by service account permissions",
                zero_trust_pillar="Identities",
                nist_family="IA — Identification and Authentication",
                maturity_level=2,
            )

    def _analyze_admin_roles(self, role_assignments: list, users: list):
        """Analyze admin role distribution."""
        # Count Global Admins
        ga_assignments = [
            ra for ra in role_assignments
            if ra.get("roleName") == "Global Administrator"
        ]
        ga_users = [ra for ra in ga_assignments if ra.get("principalType") in ("user", "User")]

        if len(ga_users) > 5:
            self.add_finding(
                control_name="Excessive Global Administrators",
                detection_logic="Count of permanent Global Administrator role assignments",
                evidence={
                    "global_admin_count": len(ga_users),
                    "admins": [
                        {"name": ra["principalDisplayName"], "upn": ra.get("principalUpn")}
                        for ra in ga_users
                    ],
                },
                severity="critical" if len(ga_users) > 8 else "high",
                score_impact=min((len(ga_users) - 4) * 3, 20),
                risk_explanation=(
                    f"{len(ga_users)} Global Administrators detected. "
                    "Microsoft recommends 2-4 GAs. Excessive GAs increase attack surface."
                ),
                exploit_scenario="Any compromised GA has full tenant control",
                blast_radius="Entire Microsoft 365 tenant",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.1.3 — Limit Global Admins to fewer than 5",
                nist_family="AC — Access Control",
                maturity_level=1,
            )
        elif len(ga_users) < 2:
            self.add_finding(
                control_name="Insufficient Global Administrators",
                detection_logic="Fewer than 2 Global Administrators (requires break-glass)",
                evidence={"global_admin_count": len(ga_users)},
                severity="high",
                score_impact=10,
                risk_explanation="Fewer than 2 GAs risks lockout if the sole admin is unavailable",
                blast_radius="Potential tenant lockout",
                zero_trust_pillar="Identities",
                nist_family="CP — Contingency Planning",
                maturity_level=1,
            )

        # Admin role density (total admins / total users)
        total_admins = len(set(ra.get("principalId") for ra in role_assignments))
        total_users = len(users)
        if total_users > 0:
            admin_density = (total_admins / total_users) * 100
            if admin_density > 5:
                self.add_finding(
                    control_name="High Admin Density (Admin Sprawl)",
                    detection_logic=f"Admin-to-user ratio: {admin_density:.1f}%",
                    evidence={
                        "total_admins": total_admins,
                        "total_users": total_users,
                        "admin_density_pct": round(admin_density, 1),
                    },
                    severity="high" if admin_density > 10 else "medium",
                    score_impact=min(admin_density, 15),
                    risk_explanation="High admin density increases the attack surface for privilege escalation",
                    exploit_scenario="Large number of admin accounts increases phishing target pool",
                    blast_radius=f"{total_admins} admin accounts across {total_users} users",
                    zero_trust_pillar="Identities",
                    nist_family="AC — Access Control",
                    maturity_level=2,
                )

    def _analyze_breakglass(self, users: list, role_assignments: list):
        """Heuristic detection of break-glass accounts."""
        breakglass_patterns = ["breakglass", "break-glass", "emergency", "bg_admin", "bg-admin"]
        ga_upns = {
            ra.get("principalUpn", "").lower()
            for ra in role_assignments
            if ra.get("roleName") == "Global Administrator"
        }

        detected_bg = []
        for user in users:
            upn = (user.get("userPrincipalName") or "").lower()
            name = (user.get("displayName") or "").lower()
            if any(p in upn or p in name for p in breakglass_patterns):
                detected_bg.append({
                    "upn": user.get("userPrincipalName"),
                    "enabled": user.get("accountEnabled"),
                    "isGlobalAdmin": upn in ga_upns,
                })

        if not detected_bg:
            self.add_finding(
                control_name="No Break-Glass Accounts Detected",
                detection_logic="No accounts matching break-glass naming patterns found as GA",
                evidence={"heuristic": "Pattern-based detection — may exist under non-standard names"},
                severity="high",
                score_impact=10,
                risk_explanation=(
                    "Break-glass accounts provide emergency access when normal admin accounts "
                    "are locked out by CA policies or MFA issues."
                ),
                blast_radius="Potential permanent tenant lockout",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.1.4 — Ensure emergency access accounts",
                nist_family="CP — Contingency Planning",
                maturity_level=0,
            )
        else:
            self.add_finding(
                control_name="Break-Glass Account Presence",
                detection_logic="Accounts matching break-glass naming patterns detected",
                evidence={"accounts": detected_bg},
                severity="informational",
                score_impact=0,
                risk_explanation="Break-glass accounts provide emergency access",
                zero_trust_pillar="Identities",
                maturity_level=4,
            )

    def _analyze_risky_users(self, risky_users: list):
        """Assess risky user signals from Identity Protection."""
        if not risky_users:
            return

        high_risk = [u for u in risky_users if u.get("riskLevel") == "high"]
        medium_risk = [u for u in risky_users if u.get("riskLevel") == "medium"]
        at_risk = [u for u in risky_users if u.get("riskState") == "atRisk"]

        if high_risk:
            self.add_finding(
                control_name="High-Risk Users Detected",
                detection_logic="Identity Protection reports users at high risk level",
                evidence={
                    "high_risk_count": len(high_risk),
                    "at_risk_count": len(at_risk),
                    "sample": [
                        {"upn": u["userPrincipalName"], "riskLevel": u["riskLevel"]}
                        for u in high_risk[:10]
                    ],
                },
                severity="critical",
                score_impact=min(len(high_risk) * 5, 25),
                risk_explanation=f"{len(high_risk)} users flagged as high risk by Identity Protection",
                exploit_scenario="Confirmed or suspected credential compromise",
                blast_radius="Direct access to high-risk user data and resources",
                zero_trust_pillar="Identities",
                nist_family="SI — System and Information Integrity",
                maturity_level=1,
            )

    def _analyze_pim(self, eligible: list, active: list, permanent: list):
        """Assess PIM usage and standing privilege exposure."""
        if not eligible and not active:
            # PIM may not be configured
            permanent_ga = [
                ra for ra in permanent
                if ra.get("roleName") == "Global Administrator"
                and ra.get("assignmentType") == "permanent"
            ]
            if permanent_ga:
                self.add_finding(
                    control_name="Privileged Identity Management Not Detected",
                    detection_logic="No PIM eligible/active assignments found; permanent role assignments exist",
                    evidence={
                        "permanent_ga_count": len(permanent_ga),
                        "note": "PIM requires Entra ID P2 licensing",
                    },
                    severity="high",
                    score_impact=15,
                    risk_explanation=(
                        "Without PIM, all admin roles are permanently assigned. "
                        "Standing privileges increase blast radius of any admin compromise."
                    ),
                    exploit_scenario="Compromised admin has permanent 24/7 access, not time-limited",
                    blast_radius="All permanently-assigned admin roles",
                    zero_trust_pillar="Identities",
                    cis_benchmark="CIS 1.1.7 — Use PIM for admin roles",
                    nist_family="AC — Access Control",
                    maturity_level=1,
                )

    def _analyze_federation(self, domains: list):
        """Check for federated domains (potential bypass risks)."""
        federated = [d for d in domains if d.get("authenticationType") == "Federated"]
        if federated:
            self.add_finding(
                control_name="Federated Domains Detected",
                detection_logic="Domains with authenticationType=Federated",
                evidence={
                    "federated_domains": [d["id"] for d in federated],
                    "count": len(federated),
                },
                severity="informational",
                score_impact=0,
                risk_explanation="Federated domains rely on external IdP security — ensure federation trust is current",
                zero_trust_pillar="Identities",
                nist_family="IA — Identification and Authentication",
                maturity_level=3,
            )

    def _analyze_groups(self, groups: list):
        """Analyze group posture."""
        role_assignable = [g for g in groups if g.get("isAssignableToRole")]
        dynamic = [g for g in groups if g.get("isDynamic")]

        if not role_assignable:
            self.add_finding(
                control_name="No Role-Assignable Groups",
                detection_logic="No groups marked as isAssignableToRole=true",
                evidence={"total_groups": len(groups)},
                severity="informational",
                score_impact=0,
                risk_explanation="Role-assignable groups provide controlled admin role targeting for CA policies",
                zero_trust_pillar="Identities",
                maturity_level=2,
            )

    def _analyze_password_policies(self, users: list):
        """Check for password-never-expires accounts."""
        never_expires = [u for u in users if u.get("passwordNeverExpires") and u.get("accountEnabled")]
        if never_expires:
            self.add_finding(
                control_name="Accounts with Password Never Expires",
                detection_logic="Enabled accounts with DisablePasswordExpiration policy set",
                evidence={
                    "count": len(never_expires),
                    "sample": [u["userPrincipalName"] for u in never_expires[:20]],
                },
                severity="medium" if len(never_expires) > 10 else "low",
                score_impact=min(len(never_expires) * 0.3, 8),
                risk_explanation="Password-never-expires accounts rely entirely on MFA for credential freshness",
                exploit_scenario="Leaked credential remains valid indefinitely without rotation",
                blast_radius=f"{len(never_expires)} accounts",
                zero_trust_pillar="Identities",
                nist_family="IA — Identification and Authentication",
                maturity_level=2,
            )
