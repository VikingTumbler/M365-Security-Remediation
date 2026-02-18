"""
Intune / Endpoint Management Collector
Enumerates: devices, compliance policies, config profiles, app protection,
enrollment restrictions, update rings, baseline profiles.
"""

from __future__ import annotations

import asyncio
import logging

from .base import BaseCollector, CollectorResult

logger = logging.getLogger("m365_security_engine.collectors.intune")


class IntuneCollector(BaseCollector):
    name = "intune"
    description = "Intune devices, compliance, configuration, app protection, enrollment"

    async def collect(self, result: CollectorResult):
        if not self.config.enable_intune:
            result.add_skipped("intune", "Intune collection disabled in config")
            return

        await asyncio.gather(
            self._collect_managed_devices(result),
            self._collect_compliance_policies(result),
            self._collect_configuration_profiles(result),
            self._collect_app_protection_policies(result),
            self._collect_enrollment_restrictions(result),
            self._collect_update_rings(result),
            self._collect_security_baselines(result),
            self._collect_device_compliance_summary(result),
            return_exceptions=True,
        )

    async def _collect_managed_devices(self, result: CollectorResult):
        """Collect all managed device inventory."""
        devices = []
        async for device in self.safe_get_all_stream(
            "deviceManagement/managedDevices",
            result,
            params={
                "$select": "id,deviceName,managedDeviceOwnerType,"
                           "operatingSystem,osVersion,complianceState,"
                           "isEncrypted,lastSyncDateTime,"
                           "deviceRegistrationState,managementAgent,"
                           "enrolledDateTime,model,manufacturer,"
                           "serialNumber,userDisplayName,"
                           "userPrincipalName,managementState,"
                           "deviceCategoryDisplayName",
                "$top": "999",
            },
        ):
            devices.append({
                "id": device.get("id"),
                "deviceName": device.get("deviceName"),
                "ownerType": device.get("managedDeviceOwnerType"),
                "os": device.get("operatingSystem"),
                "osVersion": device.get("osVersion"),
                "complianceState": device.get("complianceState"),
                "isEncrypted": device.get("isEncrypted"),
                "lastSyncDateTime": device.get("lastSyncDateTime"),
                "registrationState": device.get("deviceRegistrationState"),
                "managementAgent": device.get("managementAgent"),
                "enrolledDateTime": device.get("enrolledDateTime"),
                "model": device.get("model"),
                "manufacturer": device.get("manufacturer"),
                "userPrincipalName": device.get("userPrincipalName"),
                "managementState": device.get("managementState"),
                "category": device.get("deviceCategoryDisplayName"),
            })

        result.add_data("managed_devices", devices)

    async def _collect_compliance_policies(self, result: CollectorResult):
        """Collect device compliance policies."""
        policies = await self.safe_get_all(
            "deviceManagement/deviceCompliancePolicies",
            result,
            params={"$expand": "assignments"},
        )
        compliance_policies = []
        for p in policies:
            assignments = p.get("assignments", [])
            target_groups = []
            for a in assignments:
                target = a.get("target", {})
                target_groups.append({
                    "type": target.get("@odata.type", "").split(".")[-1],
                    "groupId": target.get("groupId"),
                    "deviceAndAppManagementAssignmentFilterId": target.get(
                        "deviceAndAppManagementAssignmentFilterId"
                    ),
                })

            compliance_policies.append({
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "description": p.get("description"),
                "type": p.get("@odata.type", "").split(".")[-1],
                "createdDateTime": p.get("createdDateTime"),
                "lastModifiedDateTime": p.get("lastModifiedDateTime"),
                "version": p.get("version"),
                "assignments": target_groups,
                "isAssigned": len(target_groups) > 0,
                "targetsAllDevices": any(
                    "allDevicesAssignmentTarget" in (t.get("type", ""))
                    for t in target_groups
                ),
            })

        result.add_data("compliance_policies", compliance_policies)

    async def _collect_configuration_profiles(self, result: CollectorResult):
        """Collect device configuration profiles."""
        profiles = await self.safe_get_all(
            "deviceManagement/deviceConfigurations",
            result,
            params={"$expand": "assignments"},
        )
        result.add_data("configuration_profiles", [
            {
                "id": p.get("id"),
                "displayName": p.get("displayName"),
                "description": p.get("description"),
                "type": p.get("@odata.type", "").split(".")[-1],
                "createdDateTime": p.get("createdDateTime"),
                "lastModifiedDateTime": p.get("lastModifiedDateTime"),
                "version": p.get("version"),
                "assignmentCount": len(p.get("assignments", [])),
            }
            for p in profiles
        ])

    async def _collect_app_protection_policies(self, result: CollectorResult):
        """Collect MAM app protection policies (iOS, Android, Windows)."""
        # iOS
        ios_policies = await self.safe_get_all(
            "deviceAppManagement/iosManagedAppProtections",
            result,
            params={"$expand": "assignments"},
        )
        # Android
        android_policies = await self.safe_get_all(
            "deviceAppManagement/androidManagedAppProtections",
            result,
            params={"$expand": "assignments"},
        )
        # Windows (WIP)
        windows_policies = await self.safe_get_all(
            "deviceAppManagement/windowsInformationProtectionPolicies",
            result,
        )

        all_mam = []
        for policies, platform in [
            (ios_policies, "iOS"),
            (android_policies, "Android"),
            (windows_policies, "Windows"),
        ]:
            for p in policies:
                all_mam.append({
                    "id": p.get("id"),
                    "displayName": p.get("displayName"),
                    "platform": platform,
                    "type": p.get("@odata.type", "").split(".")[-1],
                    "createdDateTime": p.get("createdDateTime"),
                    "lastModifiedDateTime": p.get("lastModifiedDateTime"),
                    "pinRequired": p.get("pinRequired"),
                    "minimumPinLength": p.get("minimumPinLength"),
                    "dataBackupBlocked": p.get("dataBackupBlocked"),
                    "managedBrowserToOpenLinksRequired": p.get(
                        "managedBrowserToOpenLinksRequired"
                    ),
                    "encryptAppData": p.get("encryptAppData"),
                    "contactSyncBlocked": p.get("contactSyncBlocked"),
                    "printBlocked": p.get("printBlocked"),
                    "fingerprintBlocked": p.get("fingerprintBlocked"),
                    "assignmentCount": len(p.get("assignments", [])),
                })

        result.add_data("app_protection_policies", all_mam)

    async def _collect_enrollment_restrictions(self, result: CollectorResult):
        """Collect device enrollment restrictions."""
        configs = await self.safe_get_all(
            "deviceManagement/deviceEnrollmentConfigurations",
            result,
        )
        result.add_data("enrollment_restrictions", [
            {
                "id": c.get("id"),
                "displayName": c.get("displayName"),
                "type": c.get("@odata.type", "").split(".")[-1],
                "priority": c.get("priority"),
                "createdDateTime": c.get("createdDateTime"),
                "lastModifiedDateTime": c.get("lastModifiedDateTime"),
                # Platform restrictions
                "platformType": c.get("platformType"),
                "platformBlocked": c.get("platformBlocked"),
                "osMinimumVersion": c.get("osMinimumVersion"),
                "osMaximumVersion": c.get("osMaximumVersion"),
                "personalDeviceEnrollmentBlocked": c.get(
                    "personalDeviceEnrollmentBlocked"
                ),
            }
            for c in configs
        ])

    async def _collect_update_rings(self, result: CollectorResult):
        """Collect Windows Update rings (update policies)."""
        rings = await self.safe_get_all(
            "deviceManagement/deviceConfigurations",
            result,
            params={
                "$filter": "isof('microsoft.graph.windowsUpdateForBusinessConfiguration')",
            },
        )
        result.add_data("update_rings", [
            {
                "id": r.get("id"),
                "displayName": r.get("displayName"),
                "type": r.get("@odata.type", "").split(".")[-1],
                "qualityUpdatesDeferralPeriodInDays": r.get(
                    "qualityUpdatesDeferralPeriodInDays"
                ),
                "featureUpdatesDeferralPeriodInDays": r.get(
                    "featureUpdatesDeferralPeriodInDays"
                ),
                "automaticUpdateMode": r.get("automaticUpdateMode"),
                "installationSchedule": r.get("installationSchedule"),
            }
            for r in rings
        ])

    async def _collect_security_baselines(self, result: CollectorResult):
        """Collect security baseline profiles."""
        # Security baselines are under device management intents (beta)
        intents = await self.safe_get_all(
            "deviceManagement/intents",
            result,
            beta=True,
        )
        result.add_data("security_baselines", [
            {
                "id": i.get("id"),
                "displayName": i.get("displayName"),
                "description": i.get("description"),
                "templateId": i.get("templateId"),
                "isAssigned": i.get("isAssigned"),
                "lastModifiedDateTime": i.get("lastModifiedDateTime"),
            }
            for i in intents
        ])

    async def _collect_device_compliance_summary(self, result: CollectorResult):
        """Collect device compliance overview summary."""
        data = await self.safe_get(
            "deviceManagement/deviceCompliancePolicyDeviceStateSummary",
            result,
        )
        result.add_data("compliance_summary", {
            "inGracePeriodCount": data.get("inGracePeriodCount", 0),
            "compliantDeviceCount": data.get("compliantDeviceCount", 0),
            "notCompliantDeviceCount": data.get("notCompliantDeviceCount", 0),
            "conflictDeviceCount": data.get("conflictDeviceCount", 0),
            "errorDeviceCount": data.get("errorDeviceCount", 0),
            "unknownDeviceCount": data.get("unknownDeviceCount", 0),
            "notApplicableDeviceCount": data.get("notApplicableDeviceCount", 0),
        })
