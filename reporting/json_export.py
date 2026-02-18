"""
JSON exporter — Produces the full raw JSON output of the scan.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def export_json(
    scan_score: Any,
    all_findings: list,
    collector_results: dict,
    output_dir: Path,
    scan_id: str,
) -> Path:
    """
    Write full scan results to a JSON file.

    Returns:
        Path to the created JSON file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "metadata": {
            "engine": "M365 Security & IAM Intelligence Engine",
            "version": "1.0.0",
            "scan_id": scan_id,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "mode": "READ-ONLY",
        },
        "scoring": scan_score.to_dict(),
        "findings": [_finding_to_dict(f) for f in all_findings],
        "raw_data_summary": _summarize_raw(collector_results),
    }

    filename = f"m365_security_scan_{scan_id}.json"
    filepath = output_dir / filename

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str, ensure_ascii=False)

    return filepath


def _finding_to_dict(finding) -> dict:
    return {
        "id": finding.id,
        "domain": finding.domain,
        "control_name": finding.control_name,
        "severity": finding.severity,
        "maturity_level": finding.maturity_level,
        "detection_logic": finding.detection_logic,
        "evidence": finding.evidence,
        "risk_explanation": finding.risk_explanation,
        "exploit_scenario": finding.exploit_scenario,
        "blast_radius": finding.blast_radius,
        "score_impact": finding.score_impact,
        "zero_trust_pillar": finding.zero_trust_pillar,
        "cis_benchmark": finding.cis_benchmark,
        "nist_family": finding.nist_family,
    }


def _summarize_raw(collector_results: dict) -> dict:
    """Produce a compact summary of raw collection without dumping everything."""
    summary = {}
    for name, result in collector_results.items():
        data = result.data if hasattr(result, "data") else result
        section = {}
        for key, value in (data.items() if isinstance(data, dict) else []):
            if isinstance(value, list):
                section[key] = {"count": len(value), "type": "list"}
            elif isinstance(value, dict):
                section[key] = {"keys": list(value.keys())[:20], "type": "dict"}
            else:
                section[key] = {"value": str(value)[:200], "type": type(value).__name__}
        summary[name] = section
    return summary
