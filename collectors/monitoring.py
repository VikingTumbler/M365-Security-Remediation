"""
Monitoring & Audit Readiness Collector
Enumerates: audit log status, retention, diagnostic settings, alert policies, SIEM connectors.
"""

from __future__ import annotations

import asyncio
import logging

from .base import BaseCollector, CollectorResult

logger = logging.getLogger("m365_security_engine.collectors.monitoring")


class MonitoringCollector(BaseCollector):
    name = "monitoring"
    description = "Audit log status, retention, diagnostics, alert policies, SIEM detection"

    async def collect(self, result: CollectorResult):
        await asyncio.gather(
            self._collect_audit_log_status(result),
            self._collect_diagnostic_settings(result),
            self._collect_alert_rules(result),
            self._collect_sign_in_logs_sample(result),
            self._collect_directory_audit_sample(result),
            return_exceptions=True,
        )

    async def _collect_audit_log_status(self, result: CollectorResult):
        """
        Check unified audit log availability by attempting to read audit logs.
        If accessible, audit logging is enabled.
        """
        try:
            data = await self.safe_get(
                "auditLogs/directoryAudits",
                result,
                params={"$top": "1"},
            )
            has_audit = not data.get("_forbidden", False) and not data.get("_not_found", False)
            result.add_data("audit_log_status", {
                "directoryAuditsAccessible": has_audit,
                "sampleRecordAvailable": bool(data.get("value")),
            })
        except Exception as e:
            result.add_data("audit_log_status", {
                "directoryAuditsAccessible": False,
                "error": str(e),
            })

    async def _collect_diagnostic_settings(self, result: CollectorResult):
        """
        Detect diagnostic settings / log export configuration.
        Graph doesn't directly expose all diagnostic settings, but we can
        check for indicators via organization settings.
        """
        # Check organization-level settings
        org_settings = await self.safe_get(
            "organization",
            result,
        )
        orgs = org_settings.get("value", [])

        # Check for Activity-based log streaming (via subscriptions)
        subscriptions = await self.safe_get_all(
            "subscriptions",
            result,
            skip_top=True,  # This endpoint does not support $top
        )

        # Check for security API connectors
        partner_info = await self.safe_get(
            "security/tiIndicators",
            result,
            params={"$top": "1"},
        )

        result.add_data("diagnostic_settings", {
            "graphSubscriptions": [
                {
                    "id": s.get("id"),
                    "resource": s.get("resource"),
                    "changeType": s.get("changeType"),
                    "notificationUrl": s.get("notificationUrl"),
                    "expirationDateTime": s.get("expirationDateTime"),
                }
                for s in subscriptions
            ],
            "graphSubscriptionCount": len(subscriptions),
            "hasThreatIntelConnector": not partner_info.get("_forbidden", False),
            "note": "Full diagnostic settings require Azure Monitor API access",
        })

    async def _collect_alert_rules(self, result: CollectorResult):
        """Collect security alert rules and policies."""
        # Alert policies from security API
        alerts_data = await self.safe_get(
            "security/alerts_v2",
            result,
            params={"$top": "1"},
        )

        # Check for custom detection rules (if MDE licensed)
        custom_rules = await self.safe_get_all(
            "security/rules/detectionRules",
            result,
            beta=True,
        )

        result.add_data("alert_configuration", {
            "securityAlertsAccessible": not alerts_data.get("_forbidden", False),
            "customDetectionRules": [
                {
                    "id": r.get("id"),
                    "displayName": r.get("displayName"),
                    "isEnabled": r.get("isEnabled"),
                    "schedule": r.get("schedule"),
                    "lastRunDateTime": r.get("lastRunDateTime"),
                }
                for r in custom_rules
            ],
            "customDetectionRuleCount": len(custom_rules),
        })

    async def _collect_sign_in_logs_sample(self, result: CollectorResult):
        """Sample sign-in logs to assess availability and quality."""
        sign_ins = await self.safe_get(
            "auditLogs/signIns",
            result,
            params={
                "$top": "50",
                "$orderby": "createdDateTime desc",
            },
        )
        records = sign_ins.get("value", [])

        # Analyze sign-in patterns from sample
        legacy_auth_count = 0
        mfa_success_count = 0
        risk_sign_ins = 0
        client_apps = set()

        for r in records:
            client_app = r.get("clientAppUsed", "")
            client_apps.add(client_app)

            # Detect legacy auth protocols
            if client_app in (
                "Exchange ActiveSync", "IMAP4", "POP3", "SMTP",
                "Authenticated SMTP", "Other clients",
                "Exchange Online PowerShell", "MAPI Over HTTP",
            ):
                legacy_auth_count += 1

            # MFA check
            mfa_detail = r.get("mfaDetail", {})
            if mfa_detail and mfa_detail.get("authMethod"):
                mfa_success_count += 1

            # Risk
            if r.get("riskLevelDuringSignIn") and r["riskLevelDuringSignIn"] != "none":
                risk_sign_ins += 1

        result.add_data("sign_in_logs_sample", {
            "accessible": not sign_ins.get("_forbidden", False),
            "sampleSize": len(records),
            "legacyAuthCount": legacy_auth_count,
            "mfaSuccessCount": mfa_success_count,
            "riskSignInCount": risk_sign_ins,
            "uniqueClientApps": list(client_apps),
            "hasLegacyAuth": legacy_auth_count > 0,
        })

    async def _collect_directory_audit_sample(self, result: CollectorResult):
        """Sample directory audit logs for retention assessment."""
        audits = await self.safe_get(
            "auditLogs/directoryAudits",
            result,
            params={
                "$top": "10",
                "$orderby": "activityDateTime desc",
            },
        )
        records = audits.get("value", [])

        oldest_record = None
        newest_record = None
        if records:
            newest_record = records[0].get("activityDateTime")
            oldest_record = records[-1].get("activityDateTime")

        result.add_data("directory_audit_sample", {
            "accessible": not audits.get("_forbidden", False),
            "sampleSize": len(records),
            "newestRecord": newest_record,
            "oldestInSample": oldest_record,
            "categories": list(set(
                r.get("category", "Unknown") for r in records
            )),
        })
