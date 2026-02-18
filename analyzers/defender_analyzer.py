"""
Defender Signals Analyzer
Analyzes: licensing coverage, security alerts, secure score, MDE onboarding.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import BaseAnalyzer, Finding

logger = logging.getLogger("m365_security_engine.analyzers.defender")


class DefenderAnalyzer(BaseAnalyzer):
    name = "defender_analyzer"
    domain = "device_security"  # Defender findings contribute to device_security domain
    description = "Defender signals analysis: licensing, alerts, secure score"

    def _analyze(self, data: dict[str, Any]):
        defender = data.get("defender", {})
        licensing = defender.get("defender_licensing", {})
        alerts = defender.get("security_alerts", [])
        secure_score = defender.get("secure_score", {})

        self._analyze_licensing(licensing)
        self._analyze_alerts(alerts)
        self._analyze_secure_score(secure_score)

    def _analyze_licensing(self, licensing: dict):
        """Check Defender workload licensing."""
        if not licensing:
            self.add_finding(
                control_name="Defender Licensing Detection Failed",
                detection_logic="Could not determine Defender workload licensing",
                severity="informational",
                score_impact=0,
            )
            return

        unlicensed = [
            workload for workload, info in licensing.items()
            if not info.get("licensed")
        ]

        for workload in unlicensed:
            severity_map = {
                "MDE": ("high", 10, "Defender for Endpoint: no endpoint threat protection"),
                "MDO": ("medium", 5, "Defender for Office 365: no email threat protection"),
                "MCAS": ("medium", 5, "Defender for Cloud Apps: no CASB protection"),
                "MDI": ("medium", 5, "Defender for Identity: no identity threat detection"),
            }
            sev, impact, explanation = severity_map.get(workload, ("low", 2, f"{workload} not detected"))

            self.add_finding(
                control_name=f"{workload} Not Licensed",
                detection_logic=f"Service plan analysis: {workload} workload not detected in tenant licenses",
                evidence={"workload": workload, "licensing": licensing},
                severity=sev,
                score_impact=impact,
                risk_explanation=explanation,
                zero_trust_pillar="Devices" if workload == "MDE" else "Applications",
                nist_family="SI — System and Information Integrity",
                maturity_level=1,
            )

    def _analyze_alerts(self, alerts: list):
        """Analyze security alert patterns."""
        if not alerts:
            self.add_finding(
                control_name="No Security Alerts Found",
                detection_logic="Security alerts API returned empty",
                evidence={"note": "May indicate no alerts or insufficient permissions"},
                severity="informational",
                score_impact=0,
                maturity_level=3,
            )
            return

        high_severity = [a for a in alerts if a.get("severity") in ("high", "critical")]
        unresolved = [a for a in alerts if a.get("status") in ("new", "inProgress")]

        if high_severity:
            self.add_finding(
                control_name="Unresolved High-Severity Security Alerts",
                detection_logic="Alerts with severity=high/critical",
                evidence={
                    "high_severity_count": len(high_severity),
                    "unresolved_count": len(unresolved),
                    "sample": [
                        {
                            "title": a["title"],
                            "severity": a["severity"],
                            "status": a["status"],
                            "source": a.get("serviceSource"),
                        }
                        for a in high_severity[:10]
                    ],
                },
                severity="critical" if len(high_severity) > 5 else "high",
                score_impact=min(len(high_severity) * 3, 20),
                risk_explanation=f"{len(high_severity)} high/critical security alerts detected",
                blast_radius="Scope varies by alert type",
                zero_trust_pillar="Visibility and Analytics",
                nist_family="IR — Incident Response",
                maturity_level=2,
            )

    def _analyze_secure_score(self, score: dict):
        """Analyze Microsoft Secure Score."""
        if not score or not score.get("currentScore"):
            self.add_finding(
                control_name="Secure Score Not Available",
                detection_logic="Microsoft Secure Score data not returned",
                severity="informational",
                score_impact=0,
            )
            return

        current = score["currentScore"]
        maximum = score.get("maxScore", 1)
        pct = (current / maximum) * 100 if maximum else 0

        self.add_finding(
            control_name="Microsoft Secure Score",
            detection_logic=f"Current: {current}/{maximum} ({pct:.1f}%)",
            evidence={
                "currentScore": current,
                "maxScore": maximum,
                "percentage": round(pct, 1),
                "enabledServices": score.get("enabledServices", []),
            },
            severity="high" if pct < 40 else "medium" if pct < 70 else "informational",
            score_impact=max(0, (70 - pct) * 0.2),
            risk_explanation=f"Secure Score is {pct:.0f}% — {'below recommended baseline' if pct < 70 else 'at acceptable level'}",
            zero_trust_pillar="Visibility and Analytics",
            nist_family="CA — Assessment, Authorization, and Monitoring",
            maturity_level=4 if pct > 80 else 3 if pct > 60 else 2,
        )
