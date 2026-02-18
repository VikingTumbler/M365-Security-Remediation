"""
Conditional Access Policy Collector
Enumerates: CA policies, named locations, auth strength policies, auth methods policies.
"""

from __future__ import annotations

import asyncio
import logging

from .base import BaseCollector, CollectorResult

logger = logging.getLogger("m365_security_engine.collectors.conditional_access")


class ConditionalAccessCollector(BaseCollector):
    name = "conditional_access"
    description = "Conditional Access policies, named locations, auth strength, session controls"

    async def collect(self, result: CollectorResult):
        gather_results = await asyncio.gather(
            self._collect_ca_policies(result),
            self._collect_named_locations(result),
            self._collect_auth_methods_policy(result),
            self._collect_auth_strengths(result),
            self._collect_security_defaults(result),
            return_exceptions=True,
        )
        # Surface any silently-swallowed exceptions from gather
        task_names = [
            "ca_policies", "named_locations", "auth_methods_policy",
            "auth_strengths", "security_defaults",
        ]
        for name, res in zip(task_names, gather_results):
            if isinstance(res, Exception):
                result.add_warning(f"Sub-collection {name} failed: {type(res).__name__}: {res}")
                logger.warning(f"[conditional_access] {name} exception: {res}")

    async def _collect_ca_policies(self, result: CollectorResult):
        """Collect all Conditional Access policies with full detail."""
        try:
            policies = await self.safe_get_all(
                "identity/conditionalAccess/policies",
                result,
            )
        except Exception as e:
            result.add_warning(f"CA policies endpoint failed: {type(e).__name__}: {e}")
            result.add_data("ca_policies", [])
            return

        ca_policies = []
        for p in policies:
            # Use `or {}` to handle JSON null values (key present but None)
            conditions = p.get("conditions", {}) or {}
            grant_controls = p.get("grantControls", {}) or {}
            session_controls = p.get("sessionControls", {}) or {}

            # Extract user targeting
            users_cond = conditions.get("users", {}) or {}
            include_users = users_cond.get("includeUsers", []) or []
            exclude_users = users_cond.get("excludeUsers", []) or []
            include_groups = users_cond.get("includeGroups", []) or []
            exclude_groups = users_cond.get("excludeGroups", []) or []
            include_roles = users_cond.get("includeRoles", []) or []
            exclude_roles = users_cond.get("excludeRoles", []) or []

            # Extract app targeting
            apps_cond = conditions.get("applications", {}) or {}
            include_apps = apps_cond.get("includeApplications", []) or []
            exclude_apps = apps_cond.get("excludeApplications", []) or []

            # Extract platform conditions
            platforms = conditions.get("platforms", {}) or {}
            include_platforms = platforms.get("includePlatforms", []) or []
            exclude_platforms = platforms.get("excludePlatforms", []) or []

            # Extract device filter
            devices = conditions.get("devices", {}) or {}
            device_filter = devices.get("deviceFilter", {}) or {}

            # Extract location conditions
            locations = conditions.get("locations", {}) or {}
            include_locations = locations.get("includeLocations", []) or []
            exclude_locations = locations.get("excludeLocations", []) or []

            # Client app types
            client_app_types = conditions.get("clientAppTypes", []) or []

            # Sign-in risk and user risk
            sign_in_risk = conditions.get("signInRiskLevels", []) or []
            user_risk = conditions.get("userRiskLevels", []) or []

            ca_policies.append({
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "state": p.get("state"),  # enabled, disabled, enabledForReportingButNotEnforced
                "createdDateTime": p.get("createdDateTime"),
                "modifiedDateTime": p.get("modifiedDateTime"),

                # Conditions
                "includeUsers": include_users,
                "excludeUsers": exclude_users,
                "includeGroups": include_groups,
                "excludeGroups": exclude_groups,
                "includeRoles": include_roles,
                "excludeRoles": exclude_roles,
                "includeApplications": include_apps,
                "excludeApplications": exclude_apps,
                "includeLocations": include_locations,
                "excludeLocations": exclude_locations,
                "includePlatforms": include_platforms,
                "excludePlatforms": exclude_platforms,
                "clientAppTypes": client_app_types,
                "signInRiskLevels": sign_in_risk,
                "userRiskLevels": user_risk,
                "deviceFilter": device_filter,

                # Grant controls
                "grantOperator": grant_controls.get("operator"),
                "grantBuiltInControls": grant_controls.get("builtInControls", []) or [],
                "grantCustomControls": grant_controls.get("customAuthenticationFactors", []) or [],
                "grantTermsOfUse": grant_controls.get("termsOfUse", []) or [],
                "authenticationStrength": grant_controls.get("authenticationStrength", {}) or {},

                # Session controls
                "signInFrequency": session_controls.get("signInFrequency", {}) or {},
                "persistentBrowser": session_controls.get("persistentBrowser", {}) or {},
                "cloudAppSecurity": session_controls.get("cloudAppSecurity", {}) or {},
                "applicationEnforcedRestrictions": session_controls.get(
                    "applicationEnforcedRestrictions", {}
                ) or {},
                "continuousAccessEvaluation": session_controls.get(
                    "continuousAccessEvaluation", {}
                ) or {},

                # Computed flags
                "targetsAllUsers": "All" in include_users,
                "targetsAllApps": "All" in include_apps,
                "hasExclusions": bool(
                    exclude_users or exclude_groups or
                    exclude_apps or exclude_roles
                ),
                "requiresMFA": "mfa" in (grant_controls.get("builtInControls", []) or []),
                "blocksAccess": "block" in (grant_controls.get("builtInControls", []) or []),
                "requiresCompliantDevice": "compliantDevice" in (
                    grant_controls.get("builtInControls", []) or []
                ),
                "requiresDomainJoined": "domainJoinedDevice" in (
                    grant_controls.get("builtInControls", []) or []
                ),
                "hasLegacyClientBlock": "exchangeActiveSync" in client_app_types
                    or "other" in client_app_types,
                "usesRiskSignals": bool(sign_in_risk or user_risk),
                "usesDeviceFilter": bool(device_filter),
            })

        result.add_data("ca_policies", ca_policies)

    async def _collect_named_locations(self, result: CollectorResult):
        """Collect named locations (IP and country)."""
        locations = await self.safe_get_all(
            "identity/conditionalAccess/namedLocations",
            result,
        )
        result.add_data("named_locations", [
            {
                "id": loc.get("id"),
                "displayName": loc.get("displayName"),
                "type": loc.get("@odata.type", "").split(".")[-1],
                "isTrusted": loc.get("isTrusted", False),
                "createdDateTime": loc.get("createdDateTime"),
                "modifiedDateTime": loc.get("modifiedDateTime"),
                "ipRanges": loc.get("ipRanges", []),
                "countriesAndRegions": loc.get("countriesAndRegions", []),
            }
            for loc in locations
        ])

    async def _collect_auth_methods_policy(self, result: CollectorResult):
        """Collect authentication methods policy configuration."""
        data = await self.safe_get(
            "policies/authenticationMethodsPolicy",
            result,
        )

        methods_config = data.get("authenticationMethodConfigurations", [])
        result.add_data("auth_methods_policy", {
            "registrationEnforcement": data.get("registrationEnforcement", {}),
            "policyMigrationState": data.get("policyMigrationState"),
            "methods": [
                {
                    "id": m.get("id"),
                    "state": m.get("state"),
                    "type": m.get("@odata.type", "").split(".")[-1],
                    "includeTargets": m.get("includeTargets", []),
                    "excludeTargets": m.get("excludeTargets", []),
                }
                for m in methods_config
            ],
        })

    async def _collect_auth_strengths(self, result: CollectorResult):
        """Collect authentication strength policies."""
        strengths = await self.safe_get_all(
            "policies/authenticationStrengthPolicies",
            result,
            skip_top=True,  # This endpoint does not support $top
        )
        result.add_data("auth_strength_policies", [
            {
                "id": s.get("id"),
                "displayName": s.get("displayName"),
                "description": s.get("description"),
                "policyType": s.get("policyType"),
                "requirementsSatisfied": s.get("requirementsSatisfied"),
                "allowedCombinations": s.get("allowedCombinations", []),
                "createdDateTime": s.get("createdDateTime"),
                "modifiedDateTime": s.get("modifiedDateTime"),
            }
            for s in strengths
        ])

    async def _collect_security_defaults(self, result: CollectorResult):
        """Check if security defaults are enabled."""
        data = await self.safe_get(
            "policies/identitySecurityDefaultsEnforcementPolicy",
            result,
        )
        if data.get("_forbidden"):
            result.add_data("security_defaults", {"_inaccessible": True})
        else:
            result.add_data("security_defaults", {
                "isEnabled": data.get("isEnabled", False),
                "displayName": data.get("displayName"),
                "description": data.get("description"),
            })
