"""
Intune / Device Security Analyzer
Analyzes: compliance coverage, OS risk, encryption, MAM vs MDM drift,
update ring exposure, unmanaged devices.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from .base import BaseAnalyzer, Finding

logger = logging.getLogger("m365_security_engine.analyzers.intune")


class IntuneAnalyzer(BaseAnalyzer):
    name = "intune_analyzer"
    domain = "device_security"
    description = "Intune device security analysis: compliance, encryption, OS, MAM/MDM"

    def _analyze(self, data: dict[str, Any]):
        intune = data.get("intune", {})
        devices = intune.get("managed_devices", [])
        compliance_policies = intune.get("compliance_policies", [])
        compliance_summary = intune.get("compliance_summary", {})
        app_protection = intune.get("app_protection_policies", [])
        enrollment = intune.get("enrollment_restrictions", [])
        config_profiles = intune.get("configuration_profiles", [])
        update_rings = intune.get("update_rings", [])
        baselines = intune.get("security_baselines", [])

        if not devices and not compliance_policies:
            self.add_finding(
                control_name="No Intune Data Collected",
                detection_logic="Intune collection returned empty (may not be licensed)",
                severity="high",
                score_impact=20,
                risk_explanation="No endpoint management detected — devices are unmanaged",
                blast_radius="All devices accessing M365 resources",
                zero_trust_pillar="Devices",
                nist_family="CM — Configuration Management",
                maturity_level=0,
            )
            return

        self._analyze_compliance_coverage(devices, compliance_summary)
        self._analyze_os_distribution(devices)
        self._analyze_encryption(devices)
        self._analyze_compliance_policies(compliance_policies, devices)
        self._analyze_mam_mdm(app_protection, devices)
        self._analyze_update_rings(update_rings)
        self._analyze_baselines(baselines)
        self._analyze_enrollment(enrollment)

    def _analyze_compliance_coverage(self, devices: list, summary: dict):
        """Assess overall device compliance posture."""
        total = len(devices)
        if total == 0:
            return

        compliant = [d for d in devices if d.get("complianceState") == "compliant"]
        non_compliant = [d for d in devices if d.get("complianceState") == "noncompliant"]
        unknown = [d for d in devices if d.get("complianceState") in ("unknown", "configManager")]

        compliance_rate = (len(compliant) / total) * 100 if total else 0

        if len(non_compliant) > 0:
            self.add_finding(
                control_name="Non-Compliant Devices",
                detection_logic="Devices with complianceState=noncompliant",
                evidence={
                    "total_devices": total,
                    "compliant": len(compliant),
                    "non_compliant": len(non_compliant),
                    "unknown": len(unknown),
                    "compliance_rate": round(compliance_rate, 1),
                    "summary": summary,
                },
                severity="high" if compliance_rate < 80 else "medium",
                score_impact=max(0, (100 - compliance_rate) * 0.3),
                risk_explanation=(
                    f"{len(non_compliant)} devices are non-compliant. "
                    "Non-compliant devices may lack encryption, updates, or AV protection."
                ),
                exploit_scenario="Data accessed from device without required security controls",
                blast_radius=f"{len(non_compliant)} non-compliant devices",
                zero_trust_pillar="Devices",
                cis_benchmark="CIS 4.1 — Device compliance",
                nist_family="CM — Configuration Management",
                maturity_level=3 if compliance_rate > 90 else 2 if compliance_rate > 70 else 1,
            )

    def _analyze_os_distribution(self, devices: list):
        """Analyze OS distribution for risk signals."""
        os_counter = Counter(d.get("os", "Unknown") for d in devices)
        version_counter = Counter(
            f"{d.get('os', 'Unknown')} {d.get('osVersion', 'Unknown')}"
            for d in devices
        )

        # Detect outdated OS versions (heuristic)
        outdated_windows = [
            d for d in devices
            if d.get("os") == "Windows" and d.get("osVersion", "")
            and self._is_outdated_windows(d.get("osVersion", ""))
        ]

        self.add_finding(
            control_name="OS Distribution Analysis",
            detection_logic="Aggregated OS and version data from managed devices",
            evidence={
                "os_distribution": dict(os_counter),
                "top_versions": dict(version_counter.most_common(10)),
                "outdated_windows_count": len(outdated_windows),
                "total_devices": len(devices),
            },
            severity="medium" if outdated_windows else "informational",
            score_impact=min(len(outdated_windows) * 0.5, 10),
            risk_explanation="Outdated OS versions may lack critical security patches",
            zero_trust_pillar="Devices",
            nist_family="SI — System and Information Integrity",
            maturity_level=3,
        )

    def _is_outdated_windows(self, version: str) -> bool:
        """Heuristic check for outdated Windows versions."""
        try:
            parts = version.split(".")
            major = int(parts[0]) if parts else 0
            build = int(parts[2]) if len(parts) > 2 else 0
            # Windows 10 builds below 19045 (22H2) considered outdated
            if major == 10 and build < 19045:
                return True
            return False
        except (ValueError, IndexError):
            return False

    def _analyze_encryption(self, devices: list):
        """Assess BitLocker/encryption coverage."""
        total = len(devices)
        if not total:
            return

        encrypted = [d for d in devices if d.get("isEncrypted")]
        not_encrypted = [d for d in devices if d.get("isEncrypted") is False]
        unknown_encryption = [d for d in devices if d.get("isEncrypted") is None]

        encryption_rate = (len(encrypted) / total) * 100 if total else 0

        if not_encrypted:
            self.add_finding(
                control_name="Unencrypted Devices",
                detection_logic="Devices where isEncrypted=false",
                evidence={
                    "encrypted": len(encrypted),
                    "not_encrypted": len(not_encrypted),
                    "unknown": len(unknown_encryption),
                    "encryption_rate": round(encryption_rate, 1),
                    "sample_unencrypted": [
                        {"name": d["deviceName"], "os": d.get("os")}
                        for d in not_encrypted[:10]
                    ],
                },
                severity="high" if encryption_rate < 80 else "medium",
                score_impact=max(0, (100 - encryption_rate) * 0.2),
                risk_explanation=f"{len(not_encrypted)} devices lack disk encryption (data at rest risk)",
                exploit_scenario="Lost/stolen device exposes unencrypted data",
                blast_radius=f"{len(not_encrypted)} unencrypted devices",
                zero_trust_pillar="Devices",
                cis_benchmark="CIS 4.2 — BitLocker encryption",
                nist_family="SC — System and Communications Protection",
                maturity_level=3 if encryption_rate > 95 else 2,
            )

    def _analyze_compliance_policies(self, policies: list, devices: list):
        """Check compliance policy assignment coverage."""
        if not policies:
            self.add_finding(
                control_name="No Compliance Policies Defined",
                detection_logic="Zero device compliance policies found",
                severity="critical",
                score_impact=20,
                risk_explanation="No compliance policies means no device health evaluation",
                blast_radius="All managed devices",
                zero_trust_pillar="Devices",
                nist_family="CM — Configuration Management",
                maturity_level=0,
            )
            return

        unassigned = [p for p in policies if not p.get("isAssigned")]
        if unassigned:
            self.add_finding(
                control_name="Unassigned Compliance Policies",
                detection_logic="Compliance policies with no group assignments",
                evidence={
                    "unassigned_count": len(unassigned),
                    "policies": [p["displayName"] for p in unassigned],
                },
                severity="medium",
                score_impact=5,
                risk_explanation="Unassigned compliance policies do not evaluate any devices",
                zero_trust_pillar="Devices",
                nist_family="CM — Configuration Management",
                maturity_level=2,
            )

    def _analyze_mam_mdm(self, app_protection: list, devices: list):
        """Assess MAM vs MDM coverage drift."""
        mam_platforms = set(p.get("platform") for p in app_protection)

        if not app_protection:
            self.add_finding(
                control_name="No App Protection Policies (MAM)",
                detection_logic="Zero MAM app protection policies found",
                severity="high",
                score_impact=12,
                risk_explanation=(
                    "Without MAM policies, corporate data on BYOD devices is unprotected. "
                    "Data can be copied, shared, or backed up without restrictions."
                ),
                exploit_scenario="User copies corporate data to personal cloud storage from unmanaged device",
                blast_radius="All BYOD/unmanaged device access",
                zero_trust_pillar="Applications",
                nist_family="AC — Access Control",
                maturity_level=0,
            )
        else:
            missing_platforms = set()
            for expected in ["iOS", "Android"]:
                if expected not in mam_platforms:
                    missing_platforms.add(expected)

            if missing_platforms:
                self.add_finding(
                    control_name="Incomplete MAM Platform Coverage",
                    detection_logic="App protection policies missing for some platforms",
                    evidence={
                        "covered_platforms": list(mam_platforms),
                        "missing_platforms": list(missing_platforms),
                    },
                    severity="medium",
                    score_impact=8,
                    risk_explanation=f"No app protection for: {', '.join(missing_platforms)}",
                    zero_trust_pillar="Applications",
                    nist_family="AC — Access Control",
                    maturity_level=2,
                )

    def _analyze_update_rings(self, rings: list):
        """Assess Windows Update ring configuration."""
        if not rings:
            self.add_finding(
                control_name="No Windows Update Rings Configured",
                detection_logic="No Windows Update for Business configuration profiles found",
                severity="medium",
                score_impact=8,
                risk_explanation="Without update rings, Windows update behavior is unmanaged",
                zero_trust_pillar="Devices",
                nist_family="SI — System and Information Integrity",
                maturity_level=1,
            )

    def _analyze_baselines(self, baselines: list):
        """Assess security baseline deployment."""
        if not baselines:
            self.add_finding(
                control_name="No Security Baselines Deployed",
                detection_logic="No Intune security baseline profiles found",
                severity="medium",
                score_impact=8,
                risk_explanation="Security baselines provide recommended security configurations",
                zero_trust_pillar="Devices",
                nist_family="CM — Configuration Management",
                maturity_level=1,
            )
        else:
            unassigned = [b for b in baselines if not b.get("isAssigned")]
            if unassigned:
                self.add_finding(
                    control_name="Unassigned Security Baselines",
                    detection_logic="Security baselines not assigned to any group",
                    evidence={"count": len(unassigned), "names": [b["displayName"] for b in unassigned]},
                    severity="medium",
                    score_impact=5,
                    zero_trust_pillar="Devices",
                    nist_family="CM — Configuration Management",
                    maturity_level=2,
                )

    def _analyze_enrollment(self, restrictions: list):
        """Analyze enrollment restriction configuration."""
        personal_allowed = [
            r for r in restrictions
            if r.get("personalDeviceEnrollmentBlocked") is False
        ]

        if personal_allowed:
            self.add_finding(
                control_name="Personal Device Enrollment Allowed",
                detection_logic="Enrollment restrictions allow personal device enrollment",
                evidence={"count": len(personal_allowed)},
                severity="low",
                score_impact=3,
                risk_explanation="Personal devices can enroll in MDM — may be intentional for BYOD",
                zero_trust_pillar="Devices",
                nist_family="CM — Configuration Management",
                maturity_level=3,
            )
