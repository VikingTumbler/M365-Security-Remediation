"""
Identity Surface Collector
Enumerates: users, groups, admin roles, domains, tenant info, risky users,
auth methods, PIM configuration, break-glass accounts.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from .base import BaseCollector, CollectorResult

logger = logging.getLogger("m365_security_engine.collectors.identity")


class IdentityCollector(BaseCollector):
    name = "identity"
    description = "Identity surface: users, groups, admin roles, domains, federation, PIM"

    async def collect(self, result: CollectorResult):
        # Run independent collections in parallel
        gather_results = await asyncio.gather(
            self._collect_tenant_info(result),
            self._collect_domains(result),
            self._collect_users(result),
            self._collect_groups(result),
            self._collect_admin_roles(result),
            self._collect_risky_users(result),
            self._collect_pim(result),
            return_exceptions=True,
        )
        task_names = [
            "tenant_info", "domains", "users", "groups",
            "admin_roles", "risky_users", "pim",
        ]
        for name, res in zip(task_names, gather_results):
            if isinstance(res, Exception):
                result.add_warning(f"Sub-collection {name} failed: {type(res).__name__}: {res}")
                logger.warning(f"[identity] {name} exception: {res}")

    # ── Tenant ──────────────────────────────────────────────────────────────

    async def _collect_tenant_info(self, result: CollectorResult):
        """Collect organization/tenant metadata."""
        data = await self.safe_get("organization", result)
        orgs = data.get("value", [])
        if orgs:
            org = orgs[0]
            result.add_data("tenant", {
                "id": org.get("id"),
                "displayName": org.get("displayName"),
                "verifiedDomains": org.get("verifiedDomains", []),
                "technicalNotificationMails": org.get("technicalNotificationMails", []),
                "directorySizeQuota": org.get("directorySizeQuota", {}),
                "createdDateTime": org.get("createdDateTime"),
                "assignedPlans": org.get("assignedPlans", []),
                "provisionedPlans": org.get("provisionedPlans", []),
            })

    # ── Domains ─────────────────────────────────────────────────────────────

    async def _collect_domains(self, result: CollectorResult):
        """Collect all domains and federation status."""
        domains = await self.safe_get_all("domains", result)
        result.add_data("domains", [
            {
                "id": d.get("id"),
                "isDefault": d.get("isDefault"),
                "isVerified": d.get("isVerified"),
                "authenticationType": d.get("authenticationType"),
                "isAdminManaged": d.get("isAdminManaged"),
                "supportedServices": d.get("supportedServices", []),
            }
            for d in domains
        ])

    # ── Users ───────────────────────────────────────────────────────────────

    async def _collect_users(self, result: CollectorResult):
        """
        Collect all users with sign-in activity and key properties.
        Uses streaming for large tenants.
        """
        select_fields = (
            "id,displayName,userPrincipalName,mail,accountEnabled,"
            "userType,createdDateTime,onPremisesSyncEnabled,"
            "onPremisesDistinguishedName,signInActivity,"
            "assignedLicenses,assignedPlans,proxyAddresses,"
            "lastPasswordChangeDateTime,passwordPolicies"
        )

        users = []
        dormant_cutoff = datetime.now(timezone.utc) - timedelta(
            days=self.config.dormant_days_threshold
        )

        async for user in self.safe_get_all_stream(
            "users",
            result,
            params={"$select": select_fields, "$top": "999"},
            beta=True,  # signInActivity requires beta
        ):
            sign_in = user.get("signInActivity", {})
            last_sign_in_str = sign_in.get("lastSignInDateTime")
            last_sign_in = None
            is_dormant = False

            if last_sign_in_str:
                try:
                    last_sign_in = datetime.fromisoformat(
                        last_sign_in_str.replace("Z", "+00:00")
                    )
                    is_dormant = last_sign_in < dormant_cutoff
                except (ValueError, TypeError):
                    pass

            users.append({
                "id": user.get("id"),
                "displayName": user.get("displayName"),
                "userPrincipalName": user.get("userPrincipalName"),
                "mail": user.get("mail"),
                "accountEnabled": user.get("accountEnabled"),
                "userType": user.get("userType", "Member"),
                "createdDateTime": user.get("createdDateTime"),
                "onPremisesSyncEnabled": user.get("onPremisesSyncEnabled"),
                "lastSignInDateTime": last_sign_in_str,
                "lastNonInteractiveSignIn": sign_in.get(
                    "lastNonInteractiveSignInDateTime"
                ),
                "isDormant": is_dormant,
                "isGuest": user.get("userType") == "Guest",
                "isHybrid": bool(user.get("onPremisesSyncEnabled")),
                "licensedServices": [
                    lp.get("servicePlanId")
                    for lp in user.get("assignedPlans", [])
                    if lp.get("capabilityStatus") == "Enabled"
                ],
                "hasLicense": bool(user.get("assignedLicenses")),
                "lastPasswordChange": user.get("lastPasswordChangeDateTime"),
                "passwordNeverExpires": "DisablePasswordExpiration" in (
                    user.get("passwordPolicies") or ""
                ),
            })

        result.add_data("users", users)

        # Collect auth methods for all users (batched)
        await self._collect_auth_methods(result, users)

    async def _collect_auth_methods(self, result: CollectorResult, users: list[dict]):
        """
        Collect authentication methods for users.
        Uses batch requests for efficiency on large tenants.
        """
        auth_methods_map = {}
        user_ids = [u["id"] for u in users if u.get("id")]
        permission_denied_count = 0
        success_count = 0

        # Process in chunks for memory safety
        chunk_size = 20  # Graph $batch limit
        for i in range(0, len(user_ids), chunk_size):
            chunk = user_ids[i:i + chunk_size]
            endpoints = [
                f"/users/{uid}/authentication/methods" for uid in chunk
            ]

            try:
                responses = await self.graph.batch_get(endpoints, beta=True)
                for uid, resp in zip(chunk, responses):
                    if resp.get("_error"):
                        if resp.get("status") == 403:
                            permission_denied_count += 1
                    else:
                        success_count += 1
                        methods = resp.get("value", [])
                        auth_methods_map[uid] = [
                            {
                                "type": m.get("@odata.type", "").split(".")[-1],
                                "id": m.get("id"),
                            }
                            for m in methods
                        ]
            except Exception as e:
                result.add_warning(f"Auth methods batch failed at chunk {i}: {e}")

        if permission_denied_count > 0:
            result.add_warning(
                f"Auth methods: {permission_denied_count}/{len(user_ids)} users "
                f"returned 403 (requires UserAuthenticationMethod.Read.All permission)"
            )
            result.metadata.setdefault("permission_gaps", []).append(
                "users/*/authentication/methods"
            )

        result.add_data("user_auth_methods", auth_methods_map)
        result.add_data("auth_methods_stats", {
            "total_users": len(user_ids),
            "success": success_count,
            "permission_denied": permission_denied_count,
        })

    # ── Groups ──────────────────────────────────────────────────────────────

    async def _collect_groups(self, result: CollectorResult):
        """Collect all groups with nesting and role-assignable flags."""
        select_fields = (
            "id,displayName,groupTypes,mailEnabled,securityEnabled,"
            "membershipRule,isAssignableToRole,createdDateTime,"
            "onPremisesSyncEnabled,description,mail"
        )

        groups = []
        async for group in self.safe_get_all_stream(
            "groups",
            result,
            params={"$select": select_fields, "$top": "999"},
        ):
            groups.append({
                "id": group.get("id"),
                "displayName": group.get("displayName"),
                "groupTypes": group.get("groupTypes", []),
                "mailEnabled": group.get("mailEnabled"),
                "securityEnabled": group.get("securityEnabled"),
                "isAssignableToRole": group.get("isAssignableToRole", False),
                "isDynamic": "DynamicMembership" in group.get("groupTypes", []),
                "isM365Group": "Unified" in group.get("groupTypes", []),
                "onPremisesSyncEnabled": group.get("onPremisesSyncEnabled"),
                "createdDateTime": group.get("createdDateTime"),
                "membershipRule": group.get("membershipRule"),
            })

        result.add_data("groups", groups)

        # Sample nested group depth for role-assignable groups
        role_groups = [g for g in groups if g.get("isAssignableToRole")]
        nesting_data = {}
        for rg in role_groups[:50]:  # Cap at 50 to avoid excessive API calls
            try:
                members = await self.safe_get_all(
                    f"groups/{rg['id']}/transitiveMembers",
                    result,
                    params={"$select": "id", "$top": "999"},
                )
                nested_groups = [
                    m for m in members
                    if m.get("@odata.type") == "#microsoft.graph.group"
                ]
                nesting_data[rg["id"]] = {
                    "total_transitive_members": len(members),
                    "nested_group_count": len(nested_groups),
                }
            except Exception as e:
                result.add_warning(f"Nesting check failed for group {rg['id']}: {e}")

        result.add_data("group_nesting", nesting_data)

    # ── Admin Roles ─────────────────────────────────────────────────────────

    async def _collect_admin_roles(self, result: CollectorResult):
        """Collect directory role definitions and active assignments."""
        # Role definitions
        roles = await self.safe_get_all(
            "directoryRoles", result, skip_top=True,
        )
        result.add_data("directory_roles", [
            {
                "id": r.get("id"),
                "displayName": r.get("displayName"),
                "description": r.get("description"),
                "roleTemplateId": r.get("roleTemplateId"),
            }
            for r in roles
        ])

        # Role assignments (who has what)
        role_assignments = []
        for role in roles:
            role_id = role.get("id")
            if not role_id:
                continue
            members = await self.safe_get_all(
                f"directoryRoles/{role_id}/members",
                result,
                params={"$select": "id,displayName,userPrincipalName"},
                skip_top=True,  # directoryRoles/*/members does not support $top
            )
            for m in members:
                role_assignments.append({
                    "roleId": role_id,
                    "roleName": role.get("displayName"),
                    "principalId": m.get("id"),
                    "principalDisplayName": m.get("displayName"),
                    "principalUpn": m.get("userPrincipalName"),
                    "principalType": m.get("@odata.type", "").split(".")[-1],
                    "assignmentType": "permanent",
                })

        result.add_data("role_assignments", role_assignments)

        # Role definitions (templates) for full catalog
        role_templates = await self.safe_get_all(
            "directoryRoleTemplates",
            result,
            skip_top=True,  # This endpoint does not support $top
        )
        result.add_data("role_templates", [
            {
                "id": rt.get("id"),
                "displayName": rt.get("displayName"),
                "description": rt.get("description"),
            }
            for rt in role_templates
        ])

    # ── Risky Users ─────────────────────────────────────────────────────────

    async def _collect_risky_users(self, result: CollectorResult):
        """Collect risky user signals from Identity Protection."""
        risky_users = await self.safe_get_all(
            "identityProtection/riskyUsers",
            result,
            params={"$top": "500"},  # Max page size is 500 for this endpoint
        )
        result.add_data("risky_users", [
            {
                "id": ru.get("id"),
                "userDisplayName": ru.get("userDisplayName"),
                "userPrincipalName": ru.get("userPrincipalName"),
                "riskLevel": ru.get("riskLevel"),
                "riskState": ru.get("riskState"),
                "riskDetail": ru.get("riskDetail"),
                "riskLastUpdatedDateTime": ru.get("riskLastUpdatedDateTime"),
                "isDeleted": ru.get("isDeleted"),
            }
            for ru in risky_users
        ])

        # Risk detections
        risk_detections = await self.safe_get_all(
            "identityProtection/riskDetections",
            result,
            params={
                "$top": "500",
                "$orderby": "detectedDateTime desc",
            },
        )
        result.add_data("risk_detections", [
            {
                "id": rd.get("id"),
                "riskEventType": rd.get("riskEventType"),
                "riskLevel": rd.get("riskLevel"),
                "riskState": rd.get("riskState"),
                "detectedDateTime": rd.get("detectedDateTime"),
                "userDisplayName": rd.get("userDisplayName"),
                "userPrincipalName": rd.get("userPrincipalName"),
                "ipAddress": rd.get("ipAddress"),
                "location": rd.get("location"),
                "detectionTimingType": rd.get("detectionTimingType"),
            }
            for rd in risk_detections
        ])

    # ── PIM ─────────────────────────────────────────────────────────────────

    async def _collect_pim(self, result: CollectorResult):
        """Collect Privileged Identity Management configuration."""
        # Eligible role assignments
        eligible = await self.safe_get_all(
            "roleManagement/directory/roleEligibilityScheduleInstances",
            result,
            beta=True,
        )
        result.add_data("pim_eligible_assignments", [
            {
                "id": ea.get("id"),
                "roleDefinitionId": ea.get("roleDefinitionId"),
                "principalId": ea.get("principalId"),
                "directoryScopeId": ea.get("directoryScopeId"),
                "startDateTime": ea.get("startDateTime"),
                "endDateTime": ea.get("endDateTime"),
                "memberType": ea.get("memberType"),
                "assignmentType": "eligible",
            }
            for ea in eligible
        ])

        # Active (permanent) scheduled assignments
        active = await self.safe_get_all(
            "roleManagement/directory/roleAssignmentScheduleInstances",
            result,
            beta=True,
        )
        result.add_data("pim_active_assignments", [
            {
                "id": aa.get("id"),
                "roleDefinitionId": aa.get("roleDefinitionId"),
                "principalId": aa.get("principalId"),
                "directoryScopeId": aa.get("directoryScopeId"),
                "startDateTime": aa.get("startDateTime"),
                "endDateTime": aa.get("endDateTime"),
                "memberType": aa.get("memberType"),
                "assignmentType": aa.get("assignmentType"),
            }
            for aa in active
        ])

        # Role management policy (PIM settings per role)
        policies = await self.safe_get_all(
            "policies/roleManagementPolicies",
            result,
            beta=True,
        )
        result.add_data("pim_policies", [
            {
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "scopeId": p.get("scopeId"),
                "scopeType": p.get("scopeType"),
                "isOrganizationDefault": p.get("isOrganizationDefault"),
            }
            for p in policies
        ])
