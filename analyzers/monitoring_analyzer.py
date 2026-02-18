"""
Monitoring & Detection Analyzer
Analyzes: audit log readiness, retention, SIEM detection, legacy auth signals, alert coverage.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import BaseAnalyzer, Finding

logger = logging.getLogger("m365_security_engine.analyzers.monitoring")


class MonitoringAnalyzer(BaseAnalyzer):
    name = "monitoring_analyzer"
    domain = "monitoring_detection"
    description = "Monitoring & detection readiness: audit logs, retention, SIEM, alerts"

    def _analyze(self, data: dict[str, Any]):
        monitoring = data.get("monitoring", {})
        audit_status = monitoring.get("audit_log_status", {})
        diagnostics = monitoring.get("diagnostic_settings", {})
        alerts_config = monitoring.get("alert_configuration", {})
        sign_in_sample = monitoring.get("sign_in_logs_sample", {})
        audit_sample = monitoring.get("directory_audit_sample", {})

        self._analyze_audit_logs(audit_status, audit_sample)
        self._analyze_sign_in_monitoring(sign_in_sample)
        self._analyze_siem_detection(diagnostics)
        self._analyze_alert_configuration(alerts_config)
        self._analyze_legacy_auth_signals(sign_in_sample)

    def _analyze_audit_logs(self, status: dict, sample: dict):
        """Assess audit log availability and retention."""
        if not status.get("directoryAuditsAccessible"):
            self.add_finding(
                control_name="Directory Audit Logs Not Accessible",
                detection_logic="API call to auditLogs/directoryAudits returned error/forbidden",
                evidence=status,
                severity="critical",
                score_impact=20,
                risk_explanation=(
                    "Audit logs are essential for incident response. "
                    "Without access, security events cannot be investigated."
                ),
                exploit_scenario="Attacker operates without any forensic trail",
                blast_radius="Complete loss of audit visibility",
                zero_trust_pillar="Visibility and Analytics",
                cis_benchmark="CIS 5.1 — Enable audit logging",
                nist_family="AU — Audit and Accountability",
                maturity_level=0,
            )
        else:
            self.add_finding(
                control_name="Audit Log Availability",
                detection_logic="Directory audit logs are accessible",
                evidence={
                    "accessible": True,
                    "sample_categories": sample.get("categories", []),
                    "newest_record": sample.get("newestRecord"),
                },
                severity="informational",
                score_impact=0,
                zero_trust_pillar="Visibility and Analytics",
                nist_family="AU — Audit and Accountability",
                maturity_level=4,
            )

    def _analyze_sign_in_monitoring(self, sample: dict):
        """Assess sign-in log monitoring capability."""
        if not sample.get("accessible"):
            self.add_finding(
                control_name="Sign-In Logs Not Accessible",
                detection_logic="API call to auditLogs/signIns returned error/forbidden",
                severity="high",
                score_impact=15,
                risk_explanation="Cannot monitor sign-in activity or detect suspicious authentication",
                zero_trust_pillar="Visibility and Analytics",
                nist_family="AU — Audit and Accountability",
                maturity_level=0,
            )

    def _analyze_siem_detection(self, diagnostics: dict):
        """Detect SIEM/log export integration."""
        sub_count = diagnostics.get("graphSubscriptionCount", 0)
        has_ti = diagnostics.get("hasThreatIntelConnector", False)

        if sub_count == 0 and not has_ti:
            self.add_finding(
                control_name="No SIEM/Log Export Detected",
                detection_logic="No Graph subscriptions or threat intelligence connectors found",
                evidence={
                    "graphSubscriptions": sub_count,
                    "threatIntelConnector": has_ti,
                    "note": diagnostics.get("note", ""),
                },
                severity="high",
                score_impact=12,
                risk_explanation=(
                    "No SIEM integration detected. Security events are not being forwarded "
                    "to an external monitoring system for correlation and alerting."
                ),
                exploit_scenario="Security events only exist in M365 native logs with limited retention",
                blast_radius="No external security monitoring",
                zero_trust_pillar="Visibility and Analytics",
                cis_benchmark="CIS 5.2 — Centralized log management",
                nist_family="AU — Audit and Accountability",
                maturity_level=1,
            )
        else:
            self.add_finding(
                control_name="SIEM/Log Integration Detected",
                detection_logic="Graph subscriptions or threat intelligence connectors present",
                evidence={
                    "subscriptionCount": sub_count,
                    "hasThreatIntel": has_ti,
                },
                severity="informational",
                score_impact=0,
                zero_trust_pillar="Visibility and Analytics",
                nist_family="AU — Audit and Accountability",
                maturity_level=4,
            )

    def _analyze_alert_configuration(self, config: dict):
        """Assess alert rule coverage."""
        custom_rules = config.get("customDetectionRuleCount", 0)
        alerts_accessible = config.get("securityAlertsAccessible", False)

        if not alerts_accessible:
            self.add_finding(
                control_name="Security Alerts API Not Accessible",
                detection_logic="security/alerts_v2 endpoint returned forbidden",
                severity="medium",
                score_impact=8,
                risk_explanation="Cannot verify security alert coverage",
                zero_trust_pillar="Visibility and Analytics",
                nist_family="SI — System and Information Integrity",
                maturity_level=1,
            )

        if custom_rules == 0:
            self.add_finding(
                control_name="No Custom Detection Rules",
                detection_logic="No custom detection rules found in security API",
                evidence={"note": "Custom rules require MDE P2 or Microsoft 365 Defender"},
                severity="low",
                score_impact=3,
                risk_explanation="No custom detections beyond built-in Microsoft rules",
                zero_trust_pillar="Visibility and Analytics",
                nist_family="SI — System and Information Integrity",
                maturity_level=2,
            )

    def _analyze_legacy_auth_signals(self, sample: dict):
        """Flag legacy auth activity from sign-in log samples."""
        if sample.get("hasLegacyAuth"):
            self.add_finding(
                control_name="Active Legacy Authentication Detected",
                detection_logic="Sign-in log sample contains legacy auth protocol usage",
                evidence={
                    "legacy_auth_count": sample.get("legacyAuthCount", 0),
                    "sample_size": sample.get("sampleSize", 0),
                    "client_apps": sample.get("uniqueClientApps", []),
                },
                severity="high",
                score_impact=10,
                risk_explanation=(
                    "Legacy authentication protocols are actively being used. "
                    "These protocols cannot enforce MFA and are the primary vector for password spray."
                ),
                exploit_scenario="Password spray against IMAP/POP3 succeeds without MFA challenge",
                blast_radius="All accounts using legacy auth protocols",
                zero_trust_pillar="Identities",
                cis_benchmark="CIS 1.2.2 — Block legacy authentication",
                nist_family="AC — Access Control",
                maturity_level=1,
            )
