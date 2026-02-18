"""
Application & Enterprise App Collector
Enumerates: app registrations, service principals, permissions, secrets, OAuth consent.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from .base import BaseCollector, CollectorResult

logger = logging.getLogger("m365_security_engine.collectors.apps")


# High-privilege Graph API permissions that indicate overprivileged apps
HIGH_PRIVILEGE_PERMISSIONS = {
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
    "EntitlementManagement.ReadWrite.All",
    "PrivilegedAccess.ReadWrite.AzureADGroup",
}


class AppCollector(BaseCollector):
    name = "applications"
    description = "App registrations, service principals, permissions, secrets, OAuth consent"

    async def collect(self, result: CollectorResult):
        await asyncio.gather(
            self._collect_app_registrations(result),
            self._collect_service_principals(result),
            self._collect_oauth2_grants(result),
            return_exceptions=True,
        )

    async def _collect_app_registrations(self, result: CollectorResult):
        """Collect all app registrations with credentials and permissions."""
        apps = []
        warning_days = self.config.secret_expiry_warning_days
        now = datetime.now(timezone.utc)
        expiry_cutoff = now + timedelta(days=warning_days)

        async for app in self.safe_get_all_stream(
            "applications",
            result,
            params={
                "$select": "id,appId,displayName,createdDateTime,"
                           "passwordCredentials,keyCredentials,"
                           "requiredResourceAccess,signInAudience,"
                           "api,web,spa",
                "$top": "999",
            },
        ):
            # Analyze credentials
            password_creds = app.get("passwordCredentials", [])
            key_creds = app.get("keyCredentials", [])

            expiring_secrets = []
            expired_secrets = []
            for cred in password_creds + key_creds:
                end_str = cred.get("endDateTime")
                if end_str:
                    try:
                        end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
                        if end_dt < now:
                            expired_secrets.append({
                                "displayName": cred.get("displayName"),
                                "endDateTime": end_str,
                                "type": "password" if cred in password_creds else "certificate",
                            })
                        elif end_dt < expiry_cutoff:
                            expiring_secrets.append({
                                "displayName": cred.get("displayName"),
                                "endDateTime": end_str,
                                "daysUntilExpiry": (end_dt - now).days,
                                "type": "password" if cred in password_creds else "certificate",
                            })
                    except (ValueError, TypeError):
                        pass

            # Analyze required permissions
            required_access = app.get("requiredResourceAccess", [])
            high_priv_permissions = []
            all_permissions = []
            for resource in required_access:
                for perm in resource.get("resourceAccess", []):
                    perm_entry = {
                        "resourceAppId": resource.get("resourceAppId"),
                        "permissionId": perm.get("id"),
                        "type": perm.get("type"),  # Role = Application, Scope = Delegated
                    }
                    all_permissions.append(perm_entry)

            apps.append({
                "id": app.get("id"),
                "appId": app.get("appId"),
                "displayName": app.get("displayName"),
                "createdDateTime": app.get("createdDateTime"),
                "signInAudience": app.get("signInAudience"),
                "secretCount": len(password_creds),
                "certificateCount": len(key_creds),
                "expiringSecrets": expiring_secrets,
                "expiredSecrets": expired_secrets,
                "hasExpiredCredentials": len(expired_secrets) > 0,
                "hasExpiringCredentials": len(expiring_secrets) > 0,
                "permissionCount": len(all_permissions),
                "applicationPermissions": [
                    p for p in all_permissions if p["type"] == "Role"
                ],
                "delegatedPermissions": [
                    p for p in all_permissions if p["type"] == "Scope"
                ],
            })

        result.add_data("app_registrations", apps)

    async def _collect_service_principals(self, result: CollectorResult):
        """Collect enterprise applications (service principals) with permission grants."""
        sps = []
        now = datetime.now(timezone.utc)
        stale_cutoff = now - timedelta(days=self.config.stale_group_days)

        async for sp in self.safe_get_all_stream(
            "servicePrincipals",
            result,
            params={
                "$select": "id,appId,displayName,servicePrincipalType,"
                           "accountEnabled,createdDateTime,appRoles,"
                           "oauth2PermissionScopes,tags,"
                           "appOwnerOrganizationId,signInAudience,"
                           "replyUrls,loginUrl",
                "$top": "999",
            },
        ):
            sps.append({
                "id": sp.get("id"),
                "appId": sp.get("appId"),
                "displayName": sp.get("displayName"),
                "servicePrincipalType": sp.get("servicePrincipalType"),
                "accountEnabled": sp.get("accountEnabled"),
                "createdDateTime": sp.get("createdDateTime"),
                "isFirstParty": sp.get("appOwnerOrganizationId") == "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
                "tags": sp.get("tags", []),
                "signInAudience": sp.get("signInAudience"),
            })

        result.add_data("service_principals", sps)

        # Collect app role assignments (application permissions granted)
        all_role_assignments = []
        # Only check non-Microsoft SPs to avoid excessive calls
        custom_sps = [
            sp for sp in sps
            if not sp.get("isFirstParty") and sp.get("id")
        ]

        for sp in custom_sps[:200]:  # Safety cap
            try:
                assignments = await self.safe_get_all(
                    f"servicePrincipals/{sp['id']}/appRoleAssignments",
                    result,
                )
                for a in assignments:
                    all_role_assignments.append({
                        "servicePrincipalId": sp["id"],
                        "servicePrincipalName": sp.get("displayName"),
                        "resourceId": a.get("resourceId"),
                        "resourceDisplayName": a.get("resourceDisplayName"),
                        "appRoleId": a.get("appRoleId"),
                        "createdDateTime": a.get("createdDateTime"),
                    })
            except Exception:
                pass

        result.add_data("app_role_assignments", all_role_assignments)

    async def _collect_oauth2_grants(self, result: CollectorResult):
        """Collect OAuth2 permission grants (delegated consent)."""
        grants = await self.safe_get_all(
            "oauth2PermissionGrants",
            result,
            params={"$top": "999"},
        )
        result.add_data("oauth2_grants", [
            {
                "id": g.get("id"),
                "clientId": g.get("clientId"),
                "consentType": g.get("consentType"),  # AllPrincipals = admin consent
                "principalId": g.get("principalId"),
                "resourceId": g.get("resourceId"),
                "scope": g.get("scope"),
                "isAdminConsent": g.get("consentType") == "AllPrincipals",
            }
            for g in grants
        ])
