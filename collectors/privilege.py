"""
Privilege & Entitlement Collector
Focused on standing privilege exposure, role overlap, toxic combinations.
"""

from __future__ import annotations

import asyncio
import logging

from .base import BaseCollector, CollectorResult

logger = logging.getLogger("m365_security_engine.collectors.privilege")


# Toxic role combinations (any principal holding 2+ of these = high risk)
TOXIC_ROLE_COMBINATIONS = [
    {"Global Administrator", "Exchange Administrator"},
    {"Global Administrator", "SharePoint Administrator"},
    {"Application Administrator", "Cloud Application Administrator"},
    {"User Administrator", "Privileged Role Administrator"},
    {"Global Administrator", "Conditional Access Administrator"},
    {"Application Administrator", "Privileged Role Administrator"},
    {"Exchange Administrator", "Compliance Administrator"},
]

# Critical admin roles that should be carefully monitored
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
    "Billing Administrator",
    "Password Administrator",
    "Authentication Administrator",
    "Authentication Policy Administrator",
}


class PrivilegeCollector(BaseCollector):
    name = "privilege"
    description = "Privilege analysis: standing access, role overlap, toxic combos, orphans"

    async def collect(self, result: CollectorResult):
        await asyncio.gather(
            self._collect_role_definitions(result),
            self._collect_all_role_assignments(result),
            self._collect_admin_consent_policy(result),
            return_exceptions=True,
        )

    async def _collect_role_definitions(self, result: CollectorResult):
        """Collect all unified role definitions."""
        roles = await self.safe_get_all(
            "roleManagement/directory/roleDefinitions",
            result,
            skip_top=True,  # This endpoint does not support $top
        )
        result.add_data("role_definitions", [
            {
                "id": r.get("id"),
                "displayName": r.get("displayName"),
                "description": r.get("description"),
                "isBuiltIn": r.get("isBuiltIn"),
                "isEnabled": r.get("isEnabled"),
                "templateId": r.get("templateId"),
                "isCritical": r.get("displayName") in CRITICAL_ROLES,
                "rolePermissions": [
                    {
                        "allowedResourceActions": rp.get("allowedResourceActions", []),
                    }
                    for rp in r.get("rolePermissions", [])
                ],
            }
            for r in roles
        ])

    async def _collect_all_role_assignments(self, result: CollectorResult):
        """
        Collect all directory role assignments (unified API).
        This gives us permanent + PIM-activated assignments.
        """
        assignments = await self.safe_get_all(
            "roleManagement/directory/roleAssignments",
            result,
            params={"$expand": "principal"},
        )

        role_map = {}
        for a in assignments:
            principal = a.get("principal", {})
            role_def_id = a.get("roleDefinitionId")
            principal_id = a.get("principalId")

            entry = {
                "id": a.get("id"),
                "roleDefinitionId": role_def_id,
                "principalId": principal_id,
                "directoryScopeId": a.get("directoryScopeId"),
                "principalDisplayName": principal.get("displayName"),
                "principalType": principal.get("@odata.type", "").split(".")[-1],
                "principalUpn": principal.get("userPrincipalName"),
            }

            # Build a map of principal -> roles for overlap analysis
            if principal_id not in role_map:
                role_map[principal_id] = {
                    "principalDisplayName": principal.get("displayName"),
                    "principalType": principal.get("@odata.type", "").split(".")[-1],
                    "roles": [],
                }
            role_map[principal_id]["roles"].append(role_def_id)

        result.add_data("unified_role_assignments", [
            {
                "id": a.get("id"),
                "roleDefinitionId": a.get("roleDefinitionId"),
                "principalId": a.get("principalId"),
                "directoryScopeId": a.get("directoryScopeId"),
                "principalDisplayName": (a.get("principal") or {}).get("displayName"),
                "principalType": (a.get("principal") or {}).get("@odata.type", "").split(".")[-1],
            }
            for a in assignments
        ])

        result.add_data("principal_role_map", role_map)

    async def _collect_admin_consent_policy(self, result: CollectorResult):
        """Collect admin consent workflow and permission grant policies."""
        # Admin consent settings
        consent_data = await self.safe_get(
            "policies/adminConsentRequestPolicy",
            result,
        )
        result.add_data("admin_consent_policy", {
            "isEnabled": consent_data.get("isEnabled"),
            "notifyReviewers": consent_data.get("notifyReviewers"),
            "remindersEnabled": consent_data.get("remindersEnabled"),
            "requestDurationInDays": consent_data.get("requestDurationInDays"),
            "reviewers": consent_data.get("reviewers", []),
        })

        # Permission grant policies
        grant_policies = await self.safe_get_all(
            "policies/permissionGrantPolicies",
            result,
        )
        result.add_data("permission_grant_policies", [
            {
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "description": p.get("description"),
            }
            for p in grant_policies
        ])
