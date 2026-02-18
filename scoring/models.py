"""
Scoring data models — Defines structured types for the scoring engine output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DomainScore:
    """Score for a single security domain."""
    domain: str
    display_name: str
    raw_score: float = 100.0    # Start at 100, deductions applied
    weight: float = 0.0
    weighted_score: float = 0.0
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    maturity_level: float = 0.0
    total_deductions: float = 0.0

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "display_name": self.display_name,
            "score": round(max(0, min(100, self.raw_score)), 1),
            "weight": self.weight,
            "weighted_contribution": round(self.weighted_score, 1),
            "finding_count": self.finding_count,
            "severity_breakdown": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "maturity_level": round(self.maturity_level, 1),
            "total_deductions": round(self.total_deductions, 1),
        }


@dataclass
class FrameworkMapping:
    """Maps findings to compliance frameworks."""
    zero_trust: dict[str, list[dict]] = field(default_factory=dict)
    cis_benchmark: dict[str, list[dict]] = field(default_factory=dict)
    nist_families: dict[str, list[dict]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "zero_trust_pillars": {
                pillar: {
                    "findings": findings,
                    "count": len(findings),
                }
                for pillar, findings in self.zero_trust.items()
            },
            "cis_m365_benchmark": {
                ref: {
                    "findings": findings,
                    "count": len(findings),
                }
                for ref, findings in self.cis_benchmark.items()
            },
            "nist_800_53_families": {
                family: {
                    "findings": findings,
                    "count": len(findings),
                }
                for family, findings in self.nist_families.items()
            },
        }


@dataclass
class ScanScore:
    """Complete scoring result for a scan."""
    overall_score: float = 0.0
    domain_scores: dict[str, DomainScore] = field(default_factory=dict)
    framework_mapping: FrameworkMapping = field(default_factory=FrameworkMapping)
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    risk_rating: str = "Unknown"
    top_weaknesses: list[dict] = field(default_factory=list)
    attack_paths: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "overall_score": round(self.overall_score, 1),
            "risk_rating": self.risk_rating,
            "total_findings": self.total_findings,
            "severity_summary": {
                "critical": self.critical_findings,
                "high": self.high_findings,
            },
            "domain_scores": {
                k: v.to_dict() for k, v in self.domain_scores.items()
            },
            "framework_mapping": self.framework_mapping.to_dict(),
            "top_10_weaknesses": self.top_weaknesses[:10],
            "attack_path_simulation": self.attack_paths,
        }
