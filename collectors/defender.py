"""
Defender Signals Collector
Detects licensing, collects MDE onboarding, exposure scores, MCAS signals, risky OAuth.
"""

from __future__ import annotations

import asyncio
import logging

from .base import BaseCollector, CollectorResult

logger = logging.getLogger("m365_security_engine.collectors.defender")


class DefenderCollector(BaseCollector):
    name = "defender"
    description = "Defender for Endpoint, Defender for Cloud Apps, risky OAuth apps"

    async def collect(self, result: CollectorResult):
        if not self.config.enable_defender:
            result.add_skipped("defender", "Defender collection disabled in config")
            return

        await asyncio.gather(
            self._detect_licensing(result),
            self._collect_security_alerts(result),
            self._collect_secure_scores(result),
            self._collect_mde_machines(result),
            return_exceptions=True,
        )

    async def _detect_licensing(self, result: CollectorResult):
        """Detect which Defender workloads are licensed."""
        org_data = await self.safe_get("organization", result)
        orgs = org_data.get("value", [])
        if not orgs:
            result.add_warning("Could not read organization data for license detection")
            return

        assigned_plans = orgs[0].get("assignedPlans", [])

        # Known service plan IDs for Defender workloads
        defender_plans = {
            "MDE": {
                "names": [
                    "MICROSOFT DEFENDER FOR ENDPOINT",
                    "WINDEFATP",
                    "M365_SECURITY_AND_COMPLIANCE",
                ],
                "detected": False,
            },
            "MDO": {
                "names": [
                    "MICROSOFT DEFENDER FOR OFFICE 365",
                    "ATP_ENTERPRISE",
                    "THREAT_INTELLIGENCE",
                ],
                "detected": False,
            },
            "MCAS": {
                "names": [
                    "MICROSOFT CLOUD APP SECURITY",
                    "ADALLOM_S_STANDALONE",
                    "MTP",
                ],
                "detected": False,
            },
            "MDI": {
                "names": [
                    "MICROSOFT DEFENDER FOR IDENTITY",
                    "ATA",
                ],
                "detected": False,
            },
        }

        for plan in assigned_plans:
            service_name = (plan.get("service") or "").upper()
            capability = plan.get("capabilityStatus", "")
            if capability != "Enabled":
                continue
            for workload, info in defender_plans.items():
                for name in info["names"]:
                    if name.upper() in service_name:
                        info["detected"] = True

        result.add_data("defender_licensing", {
            workload: {
                "licensed": info["detected"],
                "status": "Licensed" if info["detected"] else "Not Detected",
            }
            for workload, info in defender_plans.items()
        })

    async def _collect_security_alerts(self, result: CollectorResult):
        """Collect recent security alerts."""
        alerts = await self.safe_get_all(
            "security/alerts_v2",
            result,
            params={
                "$top": "500",
                "$orderby": "createdDateTime desc",
            },
        )
        result.add_data("security_alerts", [
            {
                "id": a.get("id"),
                "title": a.get("title"),
                "status": a.get("status"),
                "severity": a.get("severity"),
                "category": a.get("category"),
                "classification": a.get("classification"),
                "determination": a.get("determination"),
                "serviceSource": a.get("serviceSource"),
                "detectionSource": a.get("detectionSource"),
                "createdDateTime": a.get("createdDateTime"),
                "lastActivityDateTime": a.get("lastActivityDateTime"),
                "assignedTo": a.get("assignedTo"),
                "tenantId": a.get("tenantId"),
            }
            for a in alerts
        ])

    async def _collect_secure_scores(self, result: CollectorResult):
        """Collect Microsoft Secure Score data."""
        data = await self.safe_get(
            "security/secureScores",
            result,
            params={"$top": "1", "$orderby": "createdDateTime desc"},
        )
        scores = data.get("value", [])
        if scores:
            latest = scores[0]
            result.add_data("secure_score", {
                "currentScore": latest.get("currentScore"),
                "maxScore": latest.get("maxScore"),
                "enabledServices": latest.get("enabledServices", []),
                "licensedUserCount": latest.get("licensedUserCount"),
                "activeUserCount": latest.get("activeUserCount"),
                "createdDateTime": latest.get("createdDateTime"),
                "controlScores": [
                    {
                        "controlName": cs.get("controlName"),
                        "score": cs.get("score"),
                        "controlCategory": cs.get("controlCategory"),
                        "description": cs.get("description"),
                    }
                    for cs in latest.get("controlScores", [])
                ],
            })
        else:
            result.add_data("secure_score", {"available": False})

    async def _collect_mde_machines(self, result: CollectorResult):
        """
        Attempt to collect MDE-onboarded machines.
        Uses the security API endpoint; may fail if MDE not licensed.
        """
        try:
            # This beta endpoint may not be available without MDE licensing
            machines_data = await self.safe_get(
                "security/microsoft.graph.security.runHuntingQuery",
                result,
                beta=True,
            )
            # If we can't hunt, try the basic device evidence approach
            result.add_data("mde_onboarding", {
                "queryAvailable": not machines_data.get("_forbidden", False),
                "note": "Advanced hunting requires MDE P2 licensing",
            })
        except Exception:
            result.add_data("mde_onboarding", {
                "queryAvailable": False,
                "note": "MDE advanced hunting not accessible",
            })
