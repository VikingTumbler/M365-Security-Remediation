"""
Base analyzer class — Abstract interface for all analysis modules.
Defines the Finding data model and analyzer contract.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("m365_security_engine.analyzers")


@dataclass
class Finding:
    """
    A single security finding from analysis.
    Maps to CIS benchmarks, NIST 800-53, and Zero Trust pillars.
    """
    id: str                              # Unique finding ID (e.g., "IDN-001")
    domain: str                          # Domain (identity, ca, intune, etc.)
    control_name: str                    # Human-readable control name
    detection_logic: str                 # How this was detected
    evidence: Any = None                 # Extracted evidence data
    risk_explanation: str = ""           # Why this matters
    exploit_scenario: str = ""           # How an attacker could exploit this
    blast_radius: str = ""              # Impact scope estimate
    severity: str = "medium"            # critical, high, medium, low, informational
    maturity_level: int = 0             # 0-5 maturity score
    score_impact: float = 0.0           # Points deducted from domain score

    # Framework mappings
    zero_trust_pillar: str = ""         # Identities, Devices, Applications, etc.
    cis_benchmark: str = ""             # CIS M365 control reference
    nist_family: str = ""               # NIST 800-53 family (AC, IA, etc.)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "domain": self.domain,
            "control_name": self.control_name,
            "detection_logic": self.detection_logic,
            "evidence": self.evidence,
            "risk_explanation": self.risk_explanation,
            "exploit_scenario": self.exploit_scenario,
            "blast_radius": self.blast_radius,
            "severity": self.severity,
            "maturity_level": self.maturity_level,
            "score_impact": self.score_impact,
            "zero_trust_pillar": self.zero_trust_pillar,
            "cis_benchmark": self.cis_benchmark,
            "nist_family": self.nist_family,
        }


class BaseAnalyzer(ABC):
    """
    Abstract base class for all analyzers.
    Analyzers receive collected data and produce findings.
    """

    name: str = "base"
    domain: str = "general"
    description: str = "Base analyzer"

    def __init__(self):
        self.findings: list[Finding] = []
        self._finding_counter = 0

    def analyze(self, collected_data: dict[str, Any]) -> list[Finding]:
        """
        Execute analysis and return findings.
        Subclasses implement _analyze() with specific logic.
        """
        self.findings = []
        self._finding_counter = 0

        try:
            self._analyze(collected_data)
        except Exception as e:
            logger.exception(f"[{self.name}] Analysis failed: {e}")
            self.findings.append(Finding(
                id=f"{self.domain.upper()[:3]}-ERR",
                domain=self.domain,
                control_name=f"{self.name} Analysis Error",
                detection_logic="Analyzer encountered an exception",
                evidence={"error": str(e)},
                severity="informational",
                risk_explanation=f"Analysis module {self.name} failed to complete",
            ))

        logger.info(f"[{self.name}] Analysis complete — {len(self.findings)} findings")
        return self.findings

    @abstractmethod
    def _analyze(self, data: dict[str, Any]):
        """Implement analysis logic. Add findings via self.add_finding()."""
        raise NotImplementedError

    def add_finding(self, **kwargs) -> Finding:
        """Create and register a new finding."""
        self._finding_counter += 1
        prefix = self.domain.upper()[:3]
        finding_id = kwargs.pop("id", f"{prefix}-{self._finding_counter:03d}")

        finding = Finding(
            id=finding_id,
            domain=self.domain,
            **kwargs,
        )
        self.findings.append(finding)
        return finding

    def get_safe(self, data: dict, *keys, default=None):
        """Safely navigate nested dict keys."""
        current = data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key, default)
            else:
                return default
        return current
