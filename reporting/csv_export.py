"""
CSV exporter — Produces structured CSV summaries of findings and scores.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


def export_csv(
    scan_score: Any,
    all_findings: list,
    output_dir: Path,
    scan_id: str,
) -> list[Path]:
    """
    Write CSV files for findings and domain scores.

    Returns:
        List of created CSV file paths.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    created = []

    # --- Findings CSV ---
    findings_path = output_dir / f"findings_{scan_id}.csv"
    FINDING_FIELDS = [
        "id", "domain", "control_name", "severity", "maturity_level",
        "detection_logic", "risk_explanation", "exploit_scenario",
        "blast_radius", "score_impact", "zero_trust_pillar",
        "cis_benchmark", "nist_family",
    ]

    with open(findings_path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=FINDING_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for f in all_findings:
            row = {field: getattr(f, field, "") for field in FINDING_FIELDS}
            # Flatten evidence dict to string
            if hasattr(f, "evidence") and isinstance(f.evidence, dict):
                row["evidence_summary"] = "; ".join(
                    f"{k}={v}" for k, v in f.evidence.items()
                )
            writer.writerow(row)
    created.append(findings_path)

    # --- Domain Scores CSV ---
    scores_path = output_dir / f"domain_scores_{scan_id}.csv"
    SCORE_FIELDS = [
        "domain", "display_name", "score", "weight", "weighted_contribution",
        "finding_count", "critical", "high", "medium", "low",
        "maturity_level", "total_deductions",
    ]

    with open(scores_path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=SCORE_FIELDS)
        writer.writeheader()
        for ds in scan_score.domain_scores.values():
            writer.writerow({
                "domain": ds.domain,
                "display_name": ds.display_name,
                "score": round(ds.raw_score, 1),
                "weight": ds.weight,
                "weighted_contribution": round(ds.weighted_score, 1),
                "finding_count": ds.finding_count,
                "critical": ds.critical_count,
                "high": ds.high_count,
                "medium": ds.medium_count,
                "low": ds.low_count,
                "maturity_level": round(ds.maturity_level, 1),
                "total_deductions": round(ds.total_deductions, 1),
            })
    created.append(scores_path)

    # --- Summary Row CSV ---
    summary_path = output_dir / f"scan_summary_{scan_id}.csv"
    with open(summary_path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow(["metric", "value"])
        writer.writerow(["overall_score", round(scan_score.overall_score, 1)])
        writer.writerow(["risk_rating", scan_score.risk_rating])
        writer.writerow(["total_findings", scan_score.total_findings])
        writer.writerow(["critical_findings", scan_score.critical_findings])
        writer.writerow(["high_findings", scan_score.high_findings])
        writer.writerow(["attack_paths_triggered", len(scan_score.attack_paths)])
    created.append(summary_path)

    return created
