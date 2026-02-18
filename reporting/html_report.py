"""
HTML Remediation Report — Decision-focused, single-file HTML output.

Generates a self-contained HTML report with inline CSS designed for
security decision-makers. Shows only what's needed to prioritize and
execute remediation work.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..analyzers.base import Finding
from ..scoring.models import ScanScore, DomainScore


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
_SEVERITY_COLOURS = {
    "critical": {"bg": "#dc2626", "fg": "#fff", "ring": "#fca5a5"},
    "high":     {"bg": "#ea580c", "fg": "#fff", "ring": "#fdba74"},
    "medium":   {"bg": "#d97706", "fg": "#fff", "ring": "#fcd34d"},
    "low":      {"bg": "#2563eb", "fg": "#fff", "ring": "#93c5fd"},
    "informational": {"bg": "#6b7280", "fg": "#fff", "ring": "#d1d5db"},
}

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

_SCORE_COLOUR_MAP = [
    (0,  40, "#dc2626"),   # red
    (40, 60, "#ea580c"),   # orange
    (60, 75, "#d97706"),   # amber
    (75, 90, "#16a34a"),   # green
    (90, 101, "#059669"),  # emerald
]

_DOMAIN_DISPLAY = {
    "identity_security": "Identity Security",
    "conditional_access": "Conditional Access",
    "privileged_access": "Privileged Access",
    "device_security": "Device Security",
    "app_protection": "Application Protection",
    "monitoring_detection": "Monitoring & Detection",
}

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _score_colour(score: float) -> str:
    for lo, hi, colour in _SCORE_COLOUR_MAP:
        if lo <= score < hi:
            return colour
    return "#6b7280"


def _severity_badge(sev: str) -> str:
    s = sev.lower()
    c = _SEVERITY_COLOURS.get(s, _SEVERITY_COLOURS["informational"])
    return (
        f'<span class="badge" style="background:{c["bg"]};color:{c["fg"]}">'
        f'{html.escape(sev.upper())}</span>'
    )


def _esc(val: Any) -> str:
    if val is None:
        return ""
    return html.escape(str(val))


def _maturity_label(level: float) -> str:
    labels = {0: "Ad-hoc", 1: "Initial", 2: "Managed", 3: "Defined", 4: "Measured", 5: "Optimising"}
    return labels.get(int(level), f"Level {level:.0f}")


def _domain_icon(domain: str) -> str:
    icons = {
        "identity_security": "&#x1F464;",   # bust in silhouette
        "conditional_access": "&#x1F6E1;",  # shield
        "privileged_access": "&#x1F451;",   # crown
        "device_security": "&#x1F4BB;",     # laptop
        "app_protection": "&#x1F4E6;",      # package
        "monitoring_detection": "&#x1F50D;", # mag glass
    }
    return icons.get(domain, "&#x2699;")


def _format_evidence_summary(evidence: Any) -> str:
    """
    Create a compact one-liner from evidence data.
    Keeps it decision-relevant — not a raw dump.
    """
    if evidence is None:
        return ""
    if isinstance(evidence, dict):
        parts = []
        skip_keys = {"sample_users", "sample", "accounts", "apps", "roles",
                      "devices", "policies", "heuristic", "detail", "details",
                      "top_overlaps", "top_creep", "grants", "conflicts",
                      "sample_unencrypted", "expired", "os_distribution",
                      "top_versions", "covered_platforms", "missing_platforms",
                      "licensing", "summary", "sample_categories"}
        for k, v in evidence.items():
            if k in skip_keys:
                if isinstance(v, list):
                    parts.append(f"{len(v)} {k.replace('_', ' ')}")
                continue
            if isinstance(v, (int, float)):
                label = k.replace("_", " ").title()
                if isinstance(v, float):
                    parts.append(f"{label}: {v:.1f}")
                else:
                    parts.append(f"{label}: {v}")
            elif isinstance(v, str) and len(v) < 120:
                parts.append(f"{k.replace('_', ' ').title()}: {v}")
        return " &middot; ".join(parts) if parts else ""
    return _esc(str(evidence)[:200])


def _render_evidence_detail(evidence: Any, finding_id: str) -> str:
    """
    Build rich, expandable HTML for evidence data.
    Scalar metrics render as a summary bar; lists become tables inside <details>.
    """
    if evidence is None:
        return ""
    if not isinstance(evidence, dict):
        return f'<div class="evidence">{_esc(str(evidence)[:300])}</div>'

    parts: list[str] = []

    # --- 1. Scalar summary bar (always visible) ---
    summary = _format_evidence_summary(evidence)
    if summary:
        parts.append(f'<div class="evidence ev-summary">{summary}</div>')

    # --- 2. Expandable detail tables for list/dict evidence ---
    detail_html = _render_list_evidence(evidence, finding_id)
    if detail_html:
        parts.append(detail_html)

    return "\n".join(parts)


def _render_list_evidence(evidence: dict, finding_id: str) -> str:
    """Scan evidence dict for list/dict fields and render detailed tables."""
    sections: list[str] = []

    # ---- User / account lists ----
    for key in ("sample", "accounts", "sample_users"):
        items = evidence.get(key)
        if not items or not isinstance(items, list):
            continue
        # Could be list of dicts or list of strings
        if items and isinstance(items[0], dict):
            rows = _table_from_dicts(items, _USER_COLUMNS)
        else:
            rows = "".join(f"<tr><td>{_esc(str(i))}</td></tr>" for i in items)
            rows = f"<table class='ev-table'><thead><tr><th>Account</th></tr></thead><tbody>{rows}</tbody></table>"
        label = key.replace("_", " ").title()
        sections.append(_detail_section(f"{label} ({len(items)})", rows, finding_id, key))

    # ---- Policy lists ----
    for key in ("policies",):
        items = evidence.get(key)
        if not items or not isinstance(items, list):
            continue
        if isinstance(items[0], dict):
            rows = _table_from_dicts(items, _POLICY_COLUMNS)
        else:
            rows = "".join(f"<tr><td>{_esc(str(i))}</td></tr>" for i in items)
            rows = f"<table class='ev-table'><thead><tr><th>Policy</th></tr></thead><tbody>{rows}</tbody></table>"
        sections.append(_detail_section(f"Policies ({len(items)})", rows, finding_id, key))

    # ---- CA exclusion detail ----
    detail = evidence.get("detail")
    if detail and isinstance(detail, list) and detail and isinstance(detail[0], dict):
        rows = []
        for d in detail:
            name = _esc(d.get("name", ""))
            excluded_users = d.get("excludedUsers", [])
            excluded_groups = d.get("excludedGroups", [])
            eu = ", ".join(_esc(str(u)) for u in excluded_users) if excluded_users else "—"
            eg = ", ".join(_esc(str(g)) for g in excluded_groups) if excluded_groups else "—"
            rows.append(f"<tr><td>{name}</td><td>{eu}</td><td>{eg}</td></tr>")
        table = (
            "<table class='ev-table'><thead><tr>"
            "<th>Policy Name</th><th>Excluded Users</th><th>Excluded Groups</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
        sections.append(_detail_section(f"Exclusion Details ({len(detail)})", table, finding_id, "detail"))

    # ---- Toxic combinations / details ----
    details = evidence.get("details")
    if details and isinstance(details, list) and details and isinstance(details[0], dict):
        if "toxic_pair" in details[0]:
            rows = []
            for d in details:
                principal = _esc(d.get("principal", ""))
                ptype = _esc(d.get("type", ""))
                pair = ", ".join(_esc(str(r)) for r in d.get("toxic_pair", []))
                all_roles = ", ".join(_esc(str(r)) for r in d.get("all_roles", []))
                rows.append(
                    f"<tr><td>{principal}</td><td>{ptype}</td>"
                    f"<td class='ev-highlight'>{pair}</td><td class='ev-small'>{all_roles}</td></tr>"
                )
            table = (
                "<table class='ev-table'><thead><tr>"
                "<th>Principal</th><th>Type</th><th>Toxic Pair</th><th>All Roles</th>"
                "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
            )
            sections.append(_detail_section(f"Toxic Combinations ({len(details)})", table, finding_id, "details"))

    # ---- Role overlap / top_overlaps ----
    overlaps = evidence.get("top_overlaps")
    if overlaps and isinstance(overlaps, list):
        rows = []
        for o in overlaps:
            principal = _esc(o.get("principal", ""))
            ptype = _esc(o.get("type", ""))
            count = o.get("roleCount", 0)
            roles = ", ".join(_esc(str(r)) for r in o.get("roles", []))
            rows.append(f"<tr><td>{principal}</td><td>{ptype}</td><td>{count}</td><td class='ev-small'>{roles}</td></tr>")
        table = (
            "<table class='ev-table'><thead><tr>"
            "<th>Principal</th><th>Type</th><th>Roles</th><th>Role List</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
        sections.append(_detail_section(f"Role Overlaps ({len(overlaps)})", table, finding_id, "overlaps"))

    # ---- Privilege creep / top_creep ----
    creep = evidence.get("top_creep")
    if creep and isinstance(creep, list):
        rows = []
        for c in creep:
            principal = _esc(c.get("principal", ""))
            ptype = _esc(c.get("type", ""))
            score = c.get("creep_score", 0)
            crit = c.get("critical_roles", 0)
            total = c.get("total_roles", 0)
            rows.append(f"<tr><td>{principal}</td><td>{ptype}</td><td>{score}</td><td>{crit}</td><td>{total}</td></tr>")
        table = (
            "<table class='ev-table'><thead><tr>"
            "<th>Principal</th><th>Type</th><th>Creep Score</th><th>Critical Roles</th><th>Total Roles</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
        sections.append(_detail_section(f"Privilege Creep ({len(creep)})", table, finding_id, "creep"))

    # ---- Apps (expired creds, overprivileged, multi-tenant) ----
    apps = evidence.get("apps")
    if apps and isinstance(apps, list) and apps and isinstance(apps[0], dict):
        first = apps[0]
        if "expired" in first:
            # Expired credentials
            rows = []
            for a in apps:
                name = _esc(a.get("name", ""))
                app_id = _esc(a.get("appId", ""))
                creds = a.get("expired", [])
                cred_lines = "<br>".join(
                    f"{_esc(c.get('displayName',''))} ({_esc(c.get('type',''))}) — expired {_esc(c.get('endDateTime','')[:10])}"
                    for c in creds
                )
                rows.append(f"<tr><td>{name}</td><td class='ev-mono'>{app_id}</td><td>{cred_lines}</td></tr>")
            table = (
                "<table class='ev-table'><thead><tr>"
                "<th>Application</th><th>App ID</th><th>Expired Credentials</th>"
                "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
            )
            sections.append(_detail_section(f"Apps with Expired Credentials ({len(apps)})", table, finding_id, "apps"))
        elif "applicationPermissionCount" in first or "totalPermissions" in first:
            # Overprivileged
            rows = []
            for a in apps:
                name = _esc(a.get("name", ""))
                app_id = _esc(a.get("appId", ""))
                app_perms = a.get("applicationPermissionCount", 0)
                total = a.get("totalPermissions", 0)
                rows.append(f"<tr><td>{name}</td><td class='ev-mono'>{app_id}</td><td>{app_perms}</td><td>{total}</td></tr>")
            table = (
                "<table class='ev-table'><thead><tr>"
                "<th>Application</th><th>App ID</th><th>App Permissions</th><th>Total Permissions</th>"
                "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
            )
            sections.append(_detail_section(f"Overprivileged Apps ({len(apps)})", table, finding_id, "apps"))
        elif "audience" in first:
            # Multi-tenant
            rows = []
            for a in apps:
                rows.append(f"<tr><td>{_esc(a.get('name',''))}</td><td>{_esc(a.get('audience',''))}</td></tr>")
            table = (
                "<table class='ev-table'><thead><tr>"
                "<th>Application</th><th>Audience</th>"
                "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
            )
            sections.append(_detail_section(f"Multi-Tenant Apps ({len(apps)})", table, finding_id, "apps"))
        else:
            # Generic app list
            rows = _table_from_dicts(apps, None)
            sections.append(_detail_section(f"Applications ({len(apps)})", rows, finding_id, "apps"))

    # ---- Consent grants ----
    grants = evidence.get("grants")
    if grants and isinstance(grants, list) and grants and isinstance(grants[0], dict):
        rows = []
        for g in grants:
            cid = _esc(g.get("clientId", ""))
            rid = _esc(g.get("resourceId", ""))
            scopes = ", ".join(_esc(str(s)) for s in g.get("riskyScopes", []))
            rows.append(f"<tr><td class='ev-mono'>{cid}</td><td class='ev-mono'>{rid}</td><td class='ev-highlight'>{scopes}</td></tr>")
        table = (
            "<table class='ev-table'><thead><tr>"
            "<th>Client ID</th><th>Resource ID</th><th>Risky Scopes</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
        sections.append(_detail_section(f"Admin Consent Grants ({len(grants)})", table, finding_id, "grants"))

    # ---- Conflicts ----
    conflicts = evidence.get("conflicts")
    if conflicts and isinstance(conflicts, list) and conflicts and isinstance(conflicts[0], dict):
        rows = []
        for c in conflicts:
            rows.append(
                f"<tr><td>{_esc(c.get('blocking',''))}</td><td>{_esc(c.get('allowing',''))}</td></tr>"
            )
        table = (
            "<table class='ev-table'><thead><tr>"
            "<th>Blocking Policy</th><th>Allowing Policy</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
        sections.append(_detail_section(f"Potential Conflicts ({len(conflicts)})", table, finding_id, "conflicts"))

    # ---- Unencrypted devices ----
    udevices = evidence.get("sample_unencrypted")
    if udevices and isinstance(udevices, list):
        rows = []
        for d in udevices:
            if isinstance(d, dict):
                rows.append(f"<tr><td>{_esc(d.get('name',''))}</td><td>{_esc(d.get('os',''))}</td></tr>")
            else:
                rows.append(f"<tr><td>{_esc(str(d))}</td><td>—</td></tr>")
        table = (
            "<table class='ev-table'><thead><tr>"
            "<th>Device Name</th><th>OS</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
        sections.append(_detail_section(f"Unencrypted Devices ({len(udevices)})", table, finding_id, "unencrypted"))

    # ---- Licensing table ----
    licensing = evidence.get("licensing")
    if licensing and isinstance(licensing, dict):
        rows = []
        for svc, info in licensing.items():
            if isinstance(info, dict):
                status = info.get("status", "Unknown")
                colour = "#16a34a" if info.get("licensed") else "#dc2626"
                rows.append(f"<tr><td>{_esc(svc)}</td><td style='color:{colour};font-weight:600'>{_esc(status)}</td></tr>")
        if rows:
            table = (
                "<table class='ev-table'><thead><tr>"
                "<th>Service</th><th>Status</th>"
                "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
            )
            sections.append(_detail_section("Licensing Status", table, finding_id, "licensing"))

    # ---- Disabled apps (simple string list) ----
    if "apps" in evidence and isinstance(evidence["apps"], list) and evidence["apps"] and isinstance(evidence["apps"][0], str):
        items = evidence["apps"]
        rows = "".join(f"<tr><td>{_esc(a)}</td></tr>" for a in items)
        table = f"<table class='ev-table'><thead><tr><th>Application</th></tr></thead><tbody>{rows}</tbody></table>"
        sections.append(_detail_section(f"Applications ({len(items)})", table, finding_id, "apps_str"))

    return "\n".join(sections)


def _detail_section(title: str, table_html: str, finding_id: str, key: str) -> str:
    """Wrap a table in an expandable <details> block."""
    uid = f"ev-{finding_id}-{key}".replace(" ", "-")
    return (
        f'<details class="ev-details" id="{_esc(uid)}">'
        f'<summary class="ev-toggle">{title}</summary>'
        f'<div class="ev-content">{table_html}</div>'
        f'</details>'
    )


# --- Column maps for common structures ---
_USER_COLUMNS = {
    "upn": "UPN",
    "userPrincipalName": "UPN",
    "displayName": "Display Name",
    "principal": "Principal",
    "name": "Name",
    "lastSignIn": "Last Sign-In",
    "enabled": "Enabled",
    "hasLicense": "Licensed",
    "type": "Type",
}

_POLICY_COLUMNS = {
    "name": "Policy Name",
    "id": "ID",
    "state": "State",
}


def _table_from_dicts(items: list[dict], col_map: dict | None) -> str:
    """Build an HTML table from a list of dicts, using col_map for header labels."""
    if not items:
        return ""
    if col_map:
        # Use only columns that exist in at least one item
        all_keys = set()
        for item in items:
            all_keys.update(item.keys())
        cols = [(k, v) for k, v in col_map.items() if k in all_keys]
        if not cols:
            # Fallback: use all keys
            cols = [(k, k.replace("_", " ").title()) for k in items[0].keys()]
    else:
        cols = [(k, k.replace("_", " ").title()) for k in items[0].keys()]

    header = "".join(f"<th>{_esc(label)}</th>" for _, label in cols)
    rows = []
    for item in items:
        cells = "".join(f"<td>{_esc(str(item.get(k, '')))}</td>" for k, _ in cols)
        rows.append(f"<tr>{cells}</tr>")
    return (
        f"<table class='ev-table'><thead><tr>{header}</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


# ---------------------------------------------------------------------------
# Main renderer
# ---------------------------------------------------------------------------

def _render_html(
    scan_score: ScanScore,
    all_findings: list[Finding],
    scan_id: str,
    tenant_name: str,
    generated_at: str,
) -> str:
    """Build the full HTML string."""

    overall = round(scan_score.overall_score, 1)
    overall_colour = _score_colour(overall)

    # ---- Domain cards HTML ----
    domain_cards = []
    for key in _DOMAIN_DISPLAY:
        ds: DomainScore | None = scan_score.domain_scores.get(key)
        if not ds:
            continue
        score = round(max(0, min(100, ds.raw_score)), 1)
        sc = _score_colour(score)
        icon = _domain_icon(key)
        card = f"""
        <div class="domain-card">
          <div class="domain-icon">{icon}</div>
          <div class="domain-name">{_esc(ds.display_name)}</div>
          <div class="domain-score" style="color:{sc}">{score}</div>
          <div class="domain-meta">
            <span class="dm-item crit">{ds.critical_count}C</span>
            <span class="dm-item high">{ds.high_count}H</span>
            <span class="dm-item med">{ds.medium_count}M</span>
            <span class="dm-item low">{ds.low_count}L</span>
          </div>
          <div class="domain-bar-track"><div class="domain-bar-fill" style="width:{score}%;background:{sc}"></div></div>
        </div>"""
        domain_cards.append(card)

    domain_cards_html = "\n".join(domain_cards)

    # ---- Findings by severity (only actionable: critical, high, medium) ----
    actionable = [f for f in all_findings if f.severity in ("critical", "high", "medium")]
    actionable.sort(key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.domain, f.id))

    findings_rows = []
    for f in actionable:
        ev_detail = _render_evidence_detail(f.evidence, f.id)
        risk = _esc(f.risk_explanation)
        exploit = _esc(f.exploit_scenario) if f.exploit_scenario else ""
        exploit_html = f'<div class="exploit"><strong>Attack vector:</strong> {exploit}</div>' if exploit else ""
        blast = _esc(f.blast_radius) if f.blast_radius else ""
        blast_html = f'<div class="blast"><strong>Blast radius:</strong> {blast}</div>' if blast else ""
        domain_display = _DOMAIN_DISPLAY.get(f.domain, f.domain)

        findings_rows.append(f"""
        <tr class="finding-row sev-{f.severity}">
          <td class="col-id">{_esc(f.id)}</td>
          <td class="col-sev">{_severity_badge(f.severity)}</td>
          <td class="col-detail">
            <div class="finding-title">{_esc(f.control_name)}</div>
            <div class="finding-domain">{_esc(domain_display)}</div>
            <div class="finding-risk">{risk}</div>
            {exploit_html}
            {blast_html}
            {ev_detail}
          </td>
          <td class="col-ref">
            <div class="ref-item" title="CIS Benchmark">{_esc(f.cis_benchmark) if f.cis_benchmark else '—'}</div>
            <div class="ref-item" title="NIST 800-53">{_esc(f.nist_family) if f.nist_family else ''}</div>
          </td>
        </tr>""")

    findings_html = "\n".join(findings_rows)

    # ---- Info/Low findings — collapsed summary ----
    non_actionable = [f for f in all_findings if f.severity in ("low", "informational")]
    non_actionable.sort(key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.id))
    low_rows = []
    for f in non_actionable:
        domain_display = _DOMAIN_DISPLAY.get(f.domain, f.domain)
        low_rows.append(f"""
          <tr>
            <td>{_esc(f.id)}</td>
            <td>{_severity_badge(f.severity)}</td>
            <td>{_esc(f.control_name)}</td>
            <td>{_esc(domain_display)}</td>
            <td>{_esc(f.risk_explanation[:120])}</td>
          </tr>""")
    low_html = "\n".join(low_rows)

    # ---- Top weaknesses ----
    weakness_cards = []
    for i, w in enumerate(scan_score.top_weaknesses[:10], 1):
        sev = w.get("severity", "medium")
        sc = _SEVERITY_COLOURS.get(sev, _SEVERITY_COLOURS["medium"])
        weakness_cards.append(f"""
        <div class="weakness-card" style="border-left:4px solid {sc['bg']}">
          <div class="wk-rank">#{i}</div>
          <div class="wk-body">
            <div class="wk-title">{_esc(w.get('control', ''))}</div>
            <div class="wk-id">{_severity_badge(sev)} {_esc(w.get('finding_id', ''))}</div>
            <div class="wk-risk">{_esc(w.get('risk_explanation', ''))}</div>
            <div class="wk-impact">Impact score: <strong>{w.get('impact_score', 0):.1f}</strong></div>
          </div>
        </div>""")
    weakness_html = "\n".join(weakness_cards)

    # ---- Attack paths ----
    attack_html = ""
    if scan_score.attack_paths:
        attack_items = []
        for ap in scan_score.attack_paths:
            steps = " &#x2192; ".join(_esc(s) for s in ap.get("steps", []))
            attack_items.append(f"""
            <div class="attack-path">
              <div class="ap-name">{_esc(ap.get('name', ''))}</div>
              <div class="ap-steps">{steps}</div>
              <div class="ap-desc">{_esc(ap.get('description', ''))}</div>
            </div>""")
        attack_html = f"""
        <section class="report-section">
          <h2>Attack Path Simulations</h2>
          {"".join(attack_items)}
        </section>"""
    else:
        attack_html = """
        <section class="report-section">
          <h2>Attack Path Simulations</h2>
          <p class="muted">No attack paths were triggered in this scan. This does not guarantee their absence — it means the specific precondition chains were not met with the data collected.</p>
        </section>"""

    # ---- Full HTML document ----
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>M365 Security Remediation Report — {_esc(tenant_name)}</title>
<style>
/* ---------- Reset & base ---------- */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ font-size: 15px; }}
body {{
  font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, "Helvetica Neue", sans-serif;
  background: #f8fafc; color: #1e293b; line-height: 1.55;
  padding: 0; margin: 0;
}}
a {{ color: #2563eb; text-decoration: none; }}

/* ---------- Layout ---------- */
.page {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }}

/* ---------- Header ---------- */
.report-header {{
  background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
  color: #f1f5f9; padding: 2rem 2.5rem; border-radius: 12px;
  margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;
}}
.header-left h1 {{ font-size: 1.6rem; font-weight: 700; margin-bottom: .3rem; }}
.header-left .subtitle {{ font-size: .85rem; opacity: .75; }}
.header-right {{ text-align: right; }}
.header-right .scan-meta {{ font-size: .78rem; opacity: .65; line-height: 1.7; }}

/* ---------- Score hero ---------- */
.score-hero {{
  display: flex; align-items: center; gap: 2rem; background: #fff;
  border-radius: 12px; padding: 1.8rem 2rem; box-shadow: 0 1px 3px rgba(0,0,0,.08);
  margin-bottom: 2rem;
}}
.score-ring {{
  width: 120px; height: 120px; border-radius: 50%; display: flex;
  align-items: center; justify-content: center; flex-shrink: 0;
  font-size: 2.4rem; font-weight: 800; color: #fff;
  box-shadow: 0 0 0 6px color-mix(in srgb, var(--ring-col) 30%, transparent);
}}
.score-summary h2 {{ font-size: 1.3rem; margin-bottom: .5rem; }}
.score-summary .risk-label {{ font-weight: 600; }}
.score-summary .stat-row {{ display: flex; gap: 1.5rem; margin-top: .6rem; font-size: .88rem; }}
.stat-row .stat {{ display: flex; align-items: center; gap: .3rem; }}
.stat .dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}

/* ---------- Domain grid ---------- */
.domain-grid {{
  display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 1rem; margin-bottom: 2rem;
}}
.domain-card {{
  background: #fff; border-radius: 10px; padding: 1.2rem 1.4rem;
  box-shadow: 0 1px 3px rgba(0,0,0,.06);
}}
.domain-icon {{ font-size: 1.4rem; margin-bottom: .3rem; }}
.domain-name {{ font-weight: 600; font-size: .95rem; margin-bottom: .2rem; }}
.domain-score {{ font-size: 1.8rem; font-weight: 800; line-height: 1.1; }}
.domain-meta {{ display: flex; gap: .5rem; margin-top: .4rem; font-size: .72rem; font-weight: 600; }}
.dm-item {{ padding: 2px 6px; border-radius: 4px; }}
.dm-item.crit {{ background: #fef2f2; color: #dc2626; }}
.dm-item.high {{ background: #fff7ed; color: #ea580c; }}
.dm-item.med {{ background: #fffbeb; color: #d97706; }}
.dm-item.low {{ background: #eff6ff; color: #2563eb; }}
.domain-bar-track {{ height: 5px; background: #e2e8f0; border-radius: 3px; margin-top: .6rem; overflow: hidden; }}
.domain-bar-fill {{ height: 100%; border-radius: 3px; transition: width .3s; }}

/* ---------- Sections ---------- */
.report-section {{ margin-bottom: 2rem; }}
.report-section h2 {{
  font-size: 1.15rem; font-weight: 700; margin-bottom: 1rem;
  padding-bottom: .5rem; border-bottom: 2px solid #e2e8f0;
}}

/* ---------- Findings table ---------- */
.findings-table {{ width: 100%; border-collapse: separate; border-spacing: 0; }}
.findings-table th {{
  text-align: left; font-size: .75rem; text-transform: uppercase;
  letter-spacing: .04em; color: #64748b; padding: .6rem .8rem;
  background: #f8fafc; position: sticky; top: 0; z-index: 2;
  border-bottom: 2px solid #e2e8f0;
}}
.findings-table td {{ padding: .8rem .8rem; vertical-align: top; border-bottom: 1px solid #f1f5f9; }}
.finding-row:hover {{ background: #f8fafc; }}
.col-id {{ width: 70px; font-family: "Cascadia Code", "Consolas", monospace; font-size: .82rem; color: #64748b; }}
.col-sev {{ width: 95px; }}
.col-ref {{ width: 200px; font-size: .78rem; color: #64748b; }}
.ref-item {{ margin-bottom: .2rem; }}
.finding-title {{ font-weight: 600; font-size: .95rem; margin-bottom: .15rem; }}
.finding-domain {{ font-size: .78rem; color: #64748b; margin-bottom: .4rem; }}
.finding-risk {{ font-size: .85rem; line-height: 1.5; margin-bottom: .3rem; }}
.exploit, .blast {{ font-size: .82rem; color: #475569; margin-bottom: .2rem; }}
.evidence {{ font-size: .78rem; color: #94a3b8; margin-top: .3rem; }}
.ev-summary {{ font-size: .8rem; color: #64748b; padding: .3rem 0; }}

/* ---------- Evidence detail tables ---------- */
.ev-details {{
  background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px;
  margin-top: .5rem; overflow: hidden;
}}
.ev-details + .ev-details {{ margin-top: .4rem; }}
.ev-toggle {{
  cursor: pointer; font-weight: 600; font-size: .82rem; color: #475569;
  padding: .5rem .8rem; display: flex; align-items: center; gap: .4rem;
  user-select: none;
}}
.ev-toggle:hover {{ color: #1e293b; background: #f1f5f9; }}
.ev-toggle::before {{ content: '\25B6'; font-size: .6rem; transition: transform .15s; }}
.ev-details[open] .ev-toggle::before {{ transform: rotate(90deg); }}
.ev-content {{ padding: 0 .8rem .6rem; overflow-x: auto; }}
.ev-table {{
  width: 100%; border-collapse: collapse; font-size: .78rem;
  margin-top: .3rem;
}}
.ev-table th {{
  text-align: left; font-size: .7rem; text-transform: uppercase;
  letter-spacing: .03em; color: #64748b; padding: .35rem .5rem;
  background: #eef2f7; border-bottom: 1px solid #e2e8f0;
  white-space: nowrap;
}}
.ev-table td {{
  padding: .35rem .5rem; border-bottom: 1px solid #f1f5f9;
  color: #334155; vertical-align: top; word-break: break-word;
}}
.ev-table tr:last-child td {{ border-bottom: none; }}
.ev-table tr:hover td {{ background: #f1f5f9; }}
.ev-mono {{ font-family: "Cascadia Code", "Consolas", monospace; font-size: .72rem; }}
.ev-highlight {{ color: #dc2626; font-weight: 600; }}
.ev-small {{ font-size: .72rem; color: #64748b; max-width: 350px; }}

/* ---------- Badge ---------- */
.badge {{
  display: inline-block; font-size: .7rem; font-weight: 700; letter-spacing: .03em;
  padding: 3px 8px; border-radius: 4px; text-transform: uppercase;
}}

/* ---------- Weakness cards ---------- */
.weakness-card {{
  display: flex; gap: 1rem; background: #fff; border-radius: 8px;
  padding: 1rem 1.2rem; margin-bottom: .7rem;
  box-shadow: 0 1px 2px rgba(0,0,0,.04);
}}
.wk-rank {{ font-size: 1.3rem; font-weight: 800; color: #94a3b8; min-width: 2rem; text-align: center; padding-top: .15rem; }}
.wk-title {{ font-weight: 600; font-size: .93rem; margin-bottom: .2rem; }}
.wk-id {{ margin-bottom: .3rem; }}
.wk-risk {{ font-size: .85rem; color: #475569; line-height: 1.5; }}
.wk-impact {{ font-size: .78rem; color: #94a3b8; margin-top: .3rem; }}

/* ---------- Attack paths ---------- */
.attack-path {{
  background: #fff; padding: 1rem 1.2rem; border-radius: 8px;
  border-left: 4px solid #dc2626; margin-bottom: .7rem;
  box-shadow: 0 1px 2px rgba(0,0,0,.04);
}}
.ap-name {{ font-weight: 700; font-size: .95rem; margin-bottom: .3rem; }}
.ap-steps {{ font-family: "Cascadia Code", "Consolas", monospace; font-size: .82rem; color: #dc2626; margin-bottom: .3rem; }}
.ap-desc {{ font-size: .85rem; color: #475569; }}

/* ---------- Details/summary (low/info) ---------- */
details {{ background: #fff; border-radius: 8px; padding: 1rem 1.2rem; box-shadow: 0 1px 2px rgba(0,0,0,.04); }}
details summary {{ cursor: pointer; font-weight: 600; font-size: .95rem; color: #475569; }}
details summary:hover {{ color: #1e293b; }}
details table {{ width: 100%; margin-top: .8rem; font-size: .82rem; border-collapse: collapse; }}
details th {{ text-align: left; font-size: .72rem; text-transform: uppercase; color: #94a3b8; padding: .4rem .6rem; border-bottom: 1px solid #e2e8f0; }}
details td {{ padding: .4rem .6rem; border-bottom: 1px solid #f1f5f9; }}

/* ---------- Legend ---------- */
.legend {{
  background: #fff; border-radius: 10px; padding: 1.4rem 1.6rem;
  box-shadow: 0 1px 3px rgba(0,0,0,.06); margin-bottom: 2rem;
}}
.legend h2 {{
  font-size: 1.05rem; font-weight: 700; margin-bottom: 1rem;
  padding-bottom: .5rem; border-bottom: 2px solid #e2e8f0;
}}
.legend-grid {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 1.4rem;
}}
.legend-group h3 {{
  font-size: .78rem; text-transform: uppercase; letter-spacing: .05em;
  color: #64748b; margin-bottom: .6rem; font-weight: 700;
}}
.legend-items {{ display: flex; flex-direction: column; gap: .35rem; }}
.legend-item {{
  display: flex; align-items: center; gap: .5rem; font-size: .82rem;
}}
.legend-dot {{
  width: 12px; height: 12px; border-radius: 3px; flex-shrink: 0;
}}
.legend-swatch {{
  display: inline-block; width: 28px; height: 12px; border-radius: 3px; flex-shrink: 0;
}}
.legend-icon {{ font-size: 1rem; width: 1.4rem; text-align: center; flex-shrink: 0; }}
.legend-label {{ color: #334155; }}
.legend-desc {{ color: #94a3b8; font-size: .78rem; }}

/* ---------- Misc ---------- */
.muted {{ color: #94a3b8; font-size: .88rem; font-style: italic; }}
.footer {{ text-align: center; font-size: .75rem; color: #94a3b8; margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid #e2e8f0; }}

/* ---------- Print ---------- */
@media print {{
  body {{ background: #fff; }}
  .page {{ max-width: 100%; padding: 1rem; }}
  .report-header {{ break-inside: avoid; }}
  .finding-row {{ break-inside: avoid; }}
  .weakness-card {{ break-inside: avoid; }}
  details {{ open: true; }}
}}
</style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <div class="report-header">
    <div class="header-left">
      <h1>M365 Security Remediation Report</h1>
      <div class="subtitle">Decision-ready findings for {_esc(tenant_name)}</div>
    </div>
    <div class="header-right">
      <div class="scan-meta">
        Scan ID: {_esc(scan_id)}<br>
        Generated: {_esc(generated_at)}<br>
        Engine: M365 Security Intelligence v1.0
      </div>
    </div>
  </div>

  <!-- Score hero -->
  <div class="score-hero">
    <div class="score-ring" style="background:{overall_colour};--ring-col:{overall_colour}">
      {overall}
    </div>
    <div class="score-summary">
      <h2>Overall Posture: <span class="risk-label" style="color:{overall_colour}">{_esc(scan_score.risk_rating)}</span></h2>
      <div class="stat-row">
        <div class="stat"><span class="dot" style="background:#dc2626"></span> {scan_score.critical_findings} Critical</div>
        <div class="stat"><span class="dot" style="background:#ea580c"></span> {scan_score.high_findings} High</div>
        <div class="stat"><span class="dot" style="background:#d97706"></span> {sum(1 for f in all_findings if f.severity=='medium')} Medium</div>
        <div class="stat"><span class="dot" style="background:#2563eb"></span> {sum(1 for f in all_findings if f.severity=='low')} Low</div>
        <div class="stat"><span class="dot" style="background:#6b7280"></span> {sum(1 for f in all_findings if f.severity=='informational')} Info</div>
      </div>
      <div style="margin-top:.6rem;font-size:.85rem;color:#64748b">
        {scan_score.total_findings} total findings &middot; {len(actionable)} require remediation decisions
      </div>
    </div>
  </div>

  <!-- Legend -->
  <div class="legend">
    <h2>Report Legend</h2>
    <div class="legend-grid">
      <div class="legend-group">
        <h3>Severity Levels</h3>
        <div class="legend-items">
          <div class="legend-item"><span class="legend-dot" style="background:#dc2626"></span> <span class="legend-label"><strong>Critical</strong></span> <span class="legend-desc">&mdash; Immediate exploitation risk; remediate within 24&ndash;48 hrs</span></div>
          <div class="legend-item"><span class="legend-dot" style="background:#ea580c"></span> <span class="legend-label"><strong>High</strong></span> <span class="legend-desc">&mdash; Significant risk; remediate within 1&ndash;2 weeks</span></div>
          <div class="legend-item"><span class="legend-dot" style="background:#d97706"></span> <span class="legend-label"><strong>Medium</strong></span> <span class="legend-desc">&mdash; Moderate risk; plan remediation within 30 days</span></div>
          <div class="legend-item"><span class="legend-dot" style="background:#2563eb"></span> <span class="legend-label"><strong>Low</strong></span> <span class="legend-desc">&mdash; Minor risk; address in next review cycle</span></div>
          <div class="legend-item"><span class="legend-dot" style="background:#6b7280"></span> <span class="legend-label"><strong>Info</strong></span> <span class="legend-desc">&mdash; Awareness only; no action required</span></div>
        </div>
      </div>
      <div class="legend-group">
        <h3>Score Ranges</h3>
        <div class="legend-items">
          <div class="legend-item"><span class="legend-swatch" style="background:#059669"></span> <span class="legend-label"><strong>90&ndash;100</strong> Excellent</span></div>
          <div class="legend-item"><span class="legend-swatch" style="background:#16a34a"></span> <span class="legend-label"><strong>75&ndash;89</strong> Good</span></div>
          <div class="legend-item"><span class="legend-swatch" style="background:#d97706"></span> <span class="legend-label"><strong>60&ndash;74</strong> Needs Improvement</span></div>
          <div class="legend-item"><span class="legend-swatch" style="background:#ea580c"></span> <span class="legend-label"><strong>40&ndash;59</strong> Concerning</span></div>
          <div class="legend-item"><span class="legend-swatch" style="background:#dc2626"></span> <span class="legend-label"><strong>0&ndash;39</strong> Critical</span></div>
        </div>
      </div>
      <div class="legend-group">
        <h3>Security Domains</h3>
        <div class="legend-items">
          <div class="legend-item"><span class="legend-icon">&#x1F464;</span> <span class="legend-label">Identity Security</span></div>
          <div class="legend-item"><span class="legend-icon">&#x1F6E1;</span> <span class="legend-label">Conditional Access</span></div>
          <div class="legend-item"><span class="legend-icon">&#x1F451;</span> <span class="legend-label">Privileged Access</span></div>
          <div class="legend-item"><span class="legend-icon">&#x1F4BB;</span> <span class="legend-label">Device Security</span></div>
          <div class="legend-item"><span class="legend-icon">&#x1F4E6;</span> <span class="legend-label">Application Protection</span></div>
          <div class="legend-item"><span class="legend-icon">&#x1F50D;</span> <span class="legend-label">Monitoring &amp; Detection</span></div>
        </div>
      </div>
      <div class="legend-group">
        <h3>Maturity Levels</h3>
        <div class="legend-items">
          <div class="legend-item"><span class="legend-label"><strong>0 &mdash; Ad-hoc:</strong></span> <span class="legend-desc">No formal controls</span></div>
          <div class="legend-item"><span class="legend-label"><strong>1 &mdash; Initial:</strong></span> <span class="legend-desc">Basic controls, reactive</span></div>
          <div class="legend-item"><span class="legend-label"><strong>2 &mdash; Managed:</strong></span> <span class="legend-desc">Defined processes, partially enforced</span></div>
          <div class="legend-item"><span class="legend-label"><strong>3 &mdash; Defined:</strong></span> <span class="legend-desc">Consistent enforcement, documented</span></div>
          <div class="legend-item"><span class="legend-label"><strong>4 &mdash; Measured:</strong></span> <span class="legend-desc">Metrics-driven, continuously monitored</span></div>
          <div class="legend-item"><span class="legend-label"><strong>5 &mdash; Optimising:</strong></span> <span class="legend-desc">Automated, adaptive, best-in-class</span></div>
        </div>
      </div>
    </div>
  </div>

  <!-- Domain scores grid -->
  <section class="report-section">
    <h2>Security Domain Scores</h2>
    <div class="domain-grid">
      {domain_cards_html}
    </div>
  </section>

  <!-- Top 10 weaknesses -->
  <section class="report-section">
    <h2>Top 10 Weaknesses by Impact</h2>
    {weakness_html}
  </section>

  <!-- Attack paths -->
  {attack_html}

  <!-- Actionable findings (Critical / High / Medium) -->
  <section class="report-section">
    <h2>Findings Requiring Remediation</h2>
    <table class="findings-table">
      <thead>
        <tr>
          <th>ID</th>
          <th>Severity</th>
          <th>Finding &amp; Risk Context</th>
          <th>Framework</th>
        </tr>
      </thead>
      <tbody>
        {findings_html}
      </tbody>
    </table>
  </section>

  <!-- Low / Info findings (collapsed) -->
  <section class="report-section">
    <details>
      <summary>Low &amp; Informational Findings ({len(non_actionable)})</summary>
      <table>
        <thead><tr><th>ID</th><th>Severity</th><th>Control</th><th>Domain</th><th>Description</th></tr></thead>
        <tbody>{low_html}</tbody>
      </table>
    </details>
  </section>

  <div class="footer">
    M365 Security &amp; IAM Intelligence Engine &middot; Read-Only Scan &middot; {_esc(generated_at)}
  </div>

</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def export_html(
    scan_score: ScanScore,
    all_findings: list[Finding],
    output_dir: Path,
    scan_id: str,
    tenant_name: str = "Unknown Tenant",
) -> Path:
    """
    Generate a self-contained HTML remediation report.

    Returns the Path to the written file.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html_content = _render_html(
        scan_score=scan_score,
        all_findings=all_findings,
        scan_id=scan_id,
        tenant_name=tenant_name,
        generated_at=generated_at,
    )

    filename = f"m365_remediation_report_{scan_id}.html"
    filepath = output_dir / filename
    filepath.write_text(html_content, encoding="utf-8")

    return filepath
