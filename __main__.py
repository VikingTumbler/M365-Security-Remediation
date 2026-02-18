"""
M365 Security & IAM Intelligence Engine — Main Orchestrator

Usage:
    python -m m365_security_engine                             # use default profile
    python -m m365_security_engine --profile contoso-prod      # named profile
    python -m m365_security_engine --config config.json        # JSON config file
    python -m m365_security_engine --delegated                 # device-code auth flow
    python -m m365_security_engine --skip-intune --skip-defender

Profile management:
    python -m m365_security_engine profile add <name> --tenant-id ... --client-id ...
    python -m m365_security_engine profile list
    python -m m365_security_engine profile remove <name>
    python -m m365_security_engine profile set-default <name>

This tool is STRICTLY READ-ONLY. It will NEVER modify the tenant.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Engine imports
# ---------------------------------------------------------------------------
from .config import EngineConfig, AuthConfig, CollectionConfig, OutputConfig
from .safety.guardian import SafetyGuardian
from .auth.authenticator import Authenticator
from .graph.client import GraphClient
from .cache.store import ScanCache
from .collectors import ALL_COLLECTORS
from .analyzers import ALL_ANALYZERS
from .scoring import compute_scores
from .reporting import (
    export_json,
    export_csv,
    export_markdown,
    export_executive_summary,
    export_html,
)
from .profiles import ProfileStore, TenantProfile, resolve_profile


# ---------------------------------------------------------------------------
# Profile management sub-commands
# ---------------------------------------------------------------------------

def _cmd_profile(args: argparse.Namespace) -> int:
    """Handle `profile add|list|remove|set-default` sub-commands."""
    action = args.profile_action

    if action == "list":
        return _profile_list()
    elif action == "add":
        return _profile_add(args)
    elif action == "remove":
        return _profile_remove(args)
    elif action == "set-default":
        return _profile_set_default(args)
    return 0


def _profile_list() -> int:
    store = ProfileStore.load()
    profiles = store.list_profiles()
    if not profiles:
        print("No profiles configured. Add one with:\n")
        print("  python -m m365_security_engine profile add <name> \\")
        print("    --tenant-id <GUID> --client-id <GUID> --cert-path ./base64.txt")
        return 0

    print(f"\n  {'Name':<20s} {'Tenant ID':<38s} {'Client ID':<38s} {'Cert Path':<30s} {'Default'}")
    print(f"  {'─'*20} {'─'*38} {'─'*38} {'─'*30} {'─'*7}")
    for p in profiles:
        default_marker = "  ✓" if p.name == store.default_profile else ""
        display = p.tenant_display_name or ""
        name_col = f"{p.name}" + (f" ({display})" if display else "")
        print(f"  {name_col:<20s} {p.tenant_id:<38s} {p.client_id:<38s} {p.cert_path:<30s}{default_marker}")
    print()
    return 0


def _profile_add(args: argparse.Namespace) -> int:
    store = ProfileStore.load()
    name = args.profile_name
    if store.get(name):
        print(f"  Profile '{name}' already exists. It will be overwritten.")

    profile = TenantProfile(
        name=name,
        tenant_id=args.tenant_id,
        client_id=args.client_id,
        cert_path=args.cert_path or "./base64.txt",
        tenant_display_name=args.display_name or "",
        notes=args.notes or "",
    )
    set_as_default = args.set_default or not store.profiles
    store.add(profile, set_default=set_as_default)
    print(f"  ✅ Profile '{name}' saved.")
    if set_as_default:
        print(f"  ✅ Set as default profile.")
    return 0


def _profile_remove(args: argparse.Namespace) -> int:
    store = ProfileStore.load()
    if store.remove(args.profile_name):
        print(f"  ✅ Profile '{args.profile_name}' removed.")
    else:
        print(f"  ❌ Profile '{args.profile_name}' not found.")
    return 0


def _profile_set_default(args: argparse.Namespace) -> int:
    store = ProfileStore.load()
    if store.set_default(args.profile_name):
        print(f"  ✅ Default profile set to '{args.profile_name}'.")
    else:
        print(f"  ❌ Profile '{args.profile_name}' not found.")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="m365_security_engine",
        description="M365 Security & IAM Intelligence Engine (READ-ONLY)",
    )

    # --- Sub-commands: profile management ---
    subparsers = parser.add_subparsers(dest="command", help="Management commands")

    prof_parser = subparsers.add_parser("profile", help="Manage tenant profiles")
    prof_sub = prof_parser.add_subparsers(dest="profile_action", help="Profile actions")

    # profile add
    add_p = prof_sub.add_parser("add", help="Add or update a tenant profile")
    add_p.add_argument("profile_name", help="Short name for the profile (e.g. 'contoso-prod')")
    add_p.add_argument("--tenant-id", required=True, help="Azure AD tenant ID (GUID)")
    add_p.add_argument("--client-id", required=True, help="App registration client ID (GUID)")
    add_p.add_argument("--cert-path", default="./base64.txt", help="Path to base64-encoded PFX (default: ./base64.txt)")
    add_p.add_argument("--display-name", help="Friendly tenant display name for reports")
    add_p.add_argument("--notes", help="Optional admin notes")
    add_p.add_argument("--set-default", action="store_true", help="Set as default profile")

    # profile list
    prof_sub.add_parser("list", help="List all configured profiles")

    # profile remove
    rm_p = prof_sub.add_parser("remove", help="Remove a profile")
    rm_p.add_argument("profile_name", help="Name of the profile to remove")

    # profile set-default
    sd_p = prof_sub.add_parser("set-default", help="Set the default profile")
    sd_p.add_argument("profile_name", help="Name of the profile to set as default")

    # --- Scan options ---
    parser.add_argument(
        "--profile", "-p",
        type=str,
        default=None,
        help="Tenant profile name to use (run 'profile list' to see available)",
    )
    parser.add_argument(
        "--config", "-c",
        type=Path,
        help="Path to JSON configuration file",
    )
    parser.add_argument(
        "--delegated",
        action="store_true",
        help="Use delegated (device-code) authentication instead of certificate",
    )
    parser.add_argument(
        "--cert-path",
        type=Path,
        help="Path to base64-encoded certificate file (overrides profile)",
    )
    parser.add_argument(
        "--tenant-id",
        type=str,
        default=None,
        help="Tenant ID (overrides profile; use with --client-id for ad-hoc scans)",
    )
    parser.add_argument(
        "--client-id",
        type=str,
        default=None,
        help="Client ID (overrides profile; use with --tenant-id for ad-hoc scans)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=Path,
        default=Path("./m365_scan_output"),
        help="Output directory for reports (default: ./m365_scan_output)",
    )
    parser.add_argument(
        "--tenant-name",
        type=str,
        default=None,
        help="Display name for the tenant in reports (overrides profile display name)",
    )
    parser.add_argument(
        "--skip-intune",
        action="store_true",
        help="Skip Intune/device compliance collection",
    )
    parser.add_argument(
        "--skip-defender",
        action="store_true",
        help="Skip Defender collection",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable caching (fresh collection every time)",
    )
    parser.add_argument(
        "--formats",
        nargs="+",
        choices=["json", "csv", "markdown", "executive", "html"],
        default=["json", "csv", "markdown", "executive", "html"],
        help="Output formats to generate",
    )
    return parser.parse_args()


def build_config(args: argparse.Namespace) -> EngineConfig:
    """Build engine configuration from profile, CLI args, or config file."""
    if args.config and args.config.exists():
        config = EngineConfig.from_file(args.config)
    else:
        config = EngineConfig()

    # CLI overrides
    if getattr(args, "delegated", False):
        config.auth.mode = "delegated"

    # --- Resolve tenant identity from profile or CLI flags ---
    profile = None
    if args.profile:
        profile = resolve_profile(args.profile)
        if not profile:
            print(f"\n❌ Profile '{args.profile}' not found. Use 'profile list' to see available profiles.")
            sys.exit(1)
    elif not args.config and not args.tenant_id:
        # Try default profile
        profile = resolve_profile()

    # Apply profile values (CLI flags override profile values)
    if profile:
        tenant_id = args.tenant_id or profile.tenant_id
        client_id = args.client_id or profile.client_id
        cert_path = str(args.cert_path) if args.cert_path else profile.resolve_cert_path()
    elif args.tenant_id and args.client_id:
        # Ad-hoc: both provided on CLI
        tenant_id = args.tenant_id
        client_id = args.client_id
        cert_path = str(args.cert_path) if args.cert_path else "./base64.txt"
    elif config.auth.certificate:
        # From config file
        tenant_id = config.auth.certificate.tenant_id
        client_id = config.auth.certificate.client_id
        cert_path = config.auth.certificate.certificate_path
    else:
        print("\n❌ No tenant credentials found. Use one of:")
        print("   • --profile <name>             (from saved profiles)")
        print("   • --tenant-id X --client-id Y  (ad-hoc)")
        print("   • --config config.json         (JSON config file)")
        print("\n   To create a profile:")
        print("   python -m m365_security_engine profile add <name> --tenant-id <GUID> --client-id <GUID>")
        sys.exit(1)

    # Build certificate auth config
    if config.auth.mode == "certificate":
        from .config import CertificateAuth
        config.auth.certificate = CertificateAuth(
            tenant_id=tenant_id,
            client_id=client_id,
            certificate_path=cert_path,
        )

    if args.cert_path and config.auth.certificate:
        config.auth.certificate.certificate_path = str(args.cert_path)

    config.collection.enable_intune = not getattr(args, "skip_intune", False)
    config.collection.enable_defender = not getattr(args, "skip_defender", False)
    config.output.base_dir = str(args.output_dir)

    return config


async def run_collection(
    client: GraphClient,
    cache: ScanCache | None,
    config: EngineConfig,
    scan_id: str,
) -> dict[str, Any]:
    """
    Run all collectors in parallel where possible.

    Returns:
        Dict mapping collector name to CollectorResult.
    """
    results = {}

    # Instantiate all collectors
    collectors = []
    for cls in ALL_COLLECTORS:
        name = cls.__name__.lower()
        # Skip disabled modules
        if "intune" in name and not config.collection.enable_intune:
            print(f"  ⏭  Skipping {cls.__name__} (Intune disabled)")
            continue
        if "defender" in name and not config.collection.enable_defender:
            print(f"  ⏭  Skipping {cls.__name__} (Defender disabled)")
            continue

        collectors.append(cls(graph=client, config=config.collection, cache=cache, scan_id=scan_id))

    # Run collectors concurrently
    print(f"\n  Running {len(collectors)} collectors concurrently...\n")
    tasks = [c.execute() for c in collectors]
    completed = await asyncio.gather(*tasks, return_exceptions=True)

    for collector, result in zip(collectors, completed):
        display_name = collector.__class__.__name__
        if isinstance(result, Exception):
            print(f"  ❌ {display_name}: FAILED — {result}")
        else:
            count = sum(
                len(v) if isinstance(v, list) else 1
                for k, v in result.data.items()
                if not k.startswith("_")
            )
            print(f"  ✅ {display_name}: {count} data points collected "
                  f"({result.metadata.get('duration_seconds', '?')}s)")

            # Surface warnings (permission gaps, partial failures)
            for w in result.metadata.get("warnings", []):
                print(f"      ⚠  {w}")

            # Key by collector.name so analyzers can look up by domain name
            results[collector.name] = result

    return results


def run_analysis(
    collector_results: dict[str, Any],
    config: EngineConfig,
) -> list:
    """
    Run all analyzers against collected data and return merged findings.
    """
    # Build a merged data dict keyed by collector name → collector data
    # so analyzers can do data.get("identity", {}), data.get("applications", {}) etc.
    # Include _metadata so analyzers can detect permission gaps vs genuine empty data.
    merged_data = {}
    for name, result in collector_results.items():
        merged_data[name] = {**result.data, "_metadata": result.metadata}

    all_findings = []

    for cls in ALL_ANALYZERS:
        name = cls.__name__
        analyzer = cls()

        try:
            findings = analyzer.analyze(merged_data)
            all_findings.extend(findings)
            severity_counts = {}
            for f in findings:
                sev = f.severity or "unknown"
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            print(f"  ✅ {name}: {len(findings)} findings {severity_counts}")
        except Exception as e:
            print(f"  ❌ {name}: FAILED — {e}")

    return all_findings


def generate_reports(
    scan_score,
    all_findings: list,
    collector_results: dict,
    output_dir: Path,
    scan_id: str,
    tenant_name: str,
    formats: list[str],
) -> list[Path]:
    """Generate all requested report formats."""
    created = []

    if "json" in formats:
        path = export_json(scan_score, all_findings, collector_results, output_dir, scan_id)
        created.append(path)
        print(f"  📄 JSON:       {path}")

    if "csv" in formats:
        paths = export_csv(scan_score, all_findings, output_dir, scan_id)
        created.extend(paths)
        for p in paths:
            print(f"  📊 CSV:        {p}")

    if "markdown" in formats:
        path = export_markdown(scan_score, all_findings, output_dir, scan_id, tenant_name)
        created.append(path)
        print(f"  📝 Markdown:   {path}")

    if "executive" in formats:
        path = export_executive_summary(scan_score, all_findings, output_dir, scan_id, tenant_name)
        created.append(path)
        print(f"  📋 Executive:  {path}")

    if "html" in formats:
        path = export_html(scan_score, all_findings, output_dir, scan_id, tenant_name)
        created.append(path)
        print(f"  🌐 HTML:       {path}")

    return created


async def main_async():
    """Async entry point."""
    args = parse_args()

    # --- Handle profile management sub-commands ---
    if getattr(args, "command", None) == "profile":
        if not getattr(args, "profile_action", None):
            print("Usage: python -m m365_security_engine profile {add|list|remove|set-default}")
            sys.exit(0)
        sys.exit(_cmd_profile(args))

    # --- Safety banner ---
    guardian = SafetyGuardian()
    guardian.print_banner()

    print("=" * 70)
    print(" M365 Security & IAM Intelligence Engine v1.0.0")
    print(" Mode: READ-ONLY — No tenant modifications will be made")
    print("=" * 70)

    # --- Configuration ---
    config = build_config(args)
    scan_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]
    output_dir = config.output.scan_dir

    # Resolve tenant display name: CLI flag > profile > fallback
    profile = None
    if args.profile:
        profile = resolve_profile(args.profile)
    elif not args.config and not args.tenant_id:
        profile = resolve_profile()

    if args.tenant_name:
        tenant_name = args.tenant_name
    elif profile and profile.tenant_display_name:
        tenant_name = profile.tenant_display_name
    else:
        tenant_name = "Unknown Tenant"

    profile_label = f" (profile: {profile.name})" if profile else ""
    print(f"\n📋 Scan ID: {scan_id}")
    print(f"📂 Output:  {output_dir.resolve()}")
    print(f"🏢 Tenant:  {tenant_name}{profile_label}")

    # --- Authentication ---
    print("\n🔐 Authenticating...")
    authenticator = Authenticator(config.auth)

    if config.auth.mode == "delegated":
        token = await authenticator.acquire_token()
    else:
        # Certificate-based: config already built with profile/CLI values
        if not config.auth.certificate:
            print("❌ No certificate configuration available. Use --profile or --config.")
            sys.exit(1)
        # Password will be prompted inside authenticator if blank
        token = await authenticator.acquire_token()

    if not token:
        print("❌ Authentication failed. Exiting.")
        sys.exit(1)
    print("✅ Authentication successful.")

    # --- Initialize Graph client (with safety guardian) ---
    client = GraphClient(access_token=token, guardian=guardian)
    await client.__aenter__()

    # --- Cache ---
    cache = None
    if not args.no_cache:
        cache_path = output_dir / ".cache" / "scan_cache.db"
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache = ScanCache(str(cache_path))
        cache.start_scan(scan_id)

    # --- Collection Phase ---
    print("\n" + "=" * 70)
    print(" PHASE 1: DATA COLLECTION")
    print("=" * 70)
    collector_results = await run_collection(client, cache, config, scan_id)

    if not collector_results:
        print("\n❌ No data collected. Cannot proceed with analysis.")
        sys.exit(1)

    # --- Analysis Phase ---
    print("\n" + "=" * 70)
    print(" PHASE 2: SECURITY ANALYSIS")
    print("=" * 70 + "\n")
    all_findings = run_analysis(collector_results, config)
    print(f"\n  Total findings: {len(all_findings)}")

    # --- Scoring Phase ---
    print("\n" + "=" * 70)
    print(" PHASE 3: SCORING & RISK ASSESSMENT")
    print("=" * 70 + "\n")
    scan_score = compute_scores(all_findings)

    print(f"  Overall Score:    {scan_score.overall_score:.1f}/100")
    print(f"  Risk Rating:      {scan_score.risk_rating}")
    print(f"  Critical:         {scan_score.critical_findings}")
    print(f"  High:             {scan_score.high_findings}")
    print(f"  Attack Paths:     {len(scan_score.attack_paths)}")

    for ds in scan_score.domain_scores.values():
        print(f"    {ds.display_name:40s} {ds.raw_score:5.1f}/100 "
              f"(maturity {ds.maturity_level:.1f})")

    # --- Reporting Phase ---
    print("\n" + "=" * 70)
    print(" PHASE 4: REPORT GENERATION")
    print("=" * 70 + "\n")
    created_files = generate_reports(
        scan_score=scan_score,
        all_findings=all_findings,
        collector_results=collector_results,
        output_dir=output_dir,
        scan_id=scan_id,
        tenant_name=tenant_name,
        formats=args.formats,
    )

    # --- Finalize ---
    if cache:
        cache.complete_scan(scan_id)

    await client.__aexit__(None, None, None)

    print("\n" + "=" * 70)
    print(" SCAN COMPLETE")
    print("=" * 70)
    print(f"\n  Score: {scan_score.overall_score:.1f}/100 ({scan_score.risk_rating})")
    print(f"  Files: {len(created_files)} reports generated")
    print(f"  Path:  {output_dir.resolve()}")
    print()


def main():
    """Synchronous entry point for `python -m m365_security_engine`."""
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
