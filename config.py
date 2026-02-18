"""
Configuration module for M365 Security Intelligence Engine.
Defines all tunable parameters, API endpoints, and operational settings.
"""

from __future__ import annotations

import os
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from datetime import datetime


# ─── Tenant Authentication ───────────────────────────────────────────────────

@dataclass
class CertificateAuth:
    """Certificate-based app-only authentication configuration."""
    tenant_id: str
    client_id: str
    certificate_path: str          # Path to base64-encoded PFX
    certificate_password: str = "" # Will be prompted if empty
    thumbprint: str = ""

@dataclass
class DelegatedAuth:
    """Delegated (interactive) authentication configuration."""
    tenant_id: str
    client_id: str
    scopes: list[str] = field(default_factory=lambda: [
        "https://graph.microsoft.com/.default"
    ])

@dataclass
class AuthConfig:
    """Authentication configuration — supports both modes."""
    mode: str = "certificate"  # "certificate" or "delegated"
    certificate: Optional[CertificateAuth] = None
    delegated: Optional[DelegatedAuth] = None


# ─── Graph API Settings ─────────────────────────────────────────────────────

GRAPH_BASE_URL = "https://graph.microsoft.com"
GRAPH_API_VERSION = "v1.0"
GRAPH_BETA_VERSION = "beta"

# Rate limiting / throttling
MAX_CONCURRENT_REQUESTS = 4       # Parallel requests to Graph
MAX_RETRIES = 5                   # Retry count for throttled requests
INITIAL_BACKOFF_SECONDS = 2.0     # First retry delay
MAX_BACKOFF_SECONDS = 120.0       # Cap on exponential backoff
BACKOFF_MULTIPLIER = 2.0          # Exponential factor

# Pagination
DEFAULT_PAGE_SIZE = 999           # Maximum items per page ($top)
MAX_PAGES_PER_ENDPOINT = 10000   # Safety cap on pagination loops

# Batch
BATCH_SIZE = 20                   # Graph $batch max is 20 requests


# ─── Collection Settings ────────────────────────────────────────────────────

@dataclass
class CollectionConfig:
    """Controls for data collection behavior."""
    parallel_collectors: int = 4
    page_size: int = DEFAULT_PAGE_SIZE
    max_pages: int = MAX_PAGES_PER_ENDPOINT
    stream_threshold: int = 5000          # Switch to streaming above this count
    chunk_size: int = 1000                # Chunk size for memory-safe processing
    dormant_days_threshold: int = 90      # Days without sign-in = dormant
    stale_group_days: int = 180           # Days without activity = stale group
    secret_expiry_warning_days: int = 30  # Warn if secret expires within N days
    enable_beta_endpoints: bool = True    # Use /beta where needed
    enable_intune: bool = True            # Attempt Intune collection
    enable_defender: bool = True          # Attempt Defender collection


# ─── Scoring Weights ────────────────────────────────────────────────────────

DOMAIN_WEIGHTS = {
    "identity_security": 0.25,
    "conditional_access": 0.20,
    "privileged_access": 0.20,
    "device_security": 0.15,
    "app_protection": 0.10,
    "monitoring_detection": 0.10,
}

SEVERITY_SCORES = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 2,
    "informational": 0,
}


# ─── Output Configuration ───────────────────────────────────────────────────

@dataclass
class OutputConfig:
    """Output directory and format settings."""
    base_dir: str = ""
    timestamp: str = ""
    formats: list[str] = field(default_factory=lambda: [
        "json", "csv", "markdown", "executive"
    ])

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        if not self.base_dir:
            self.base_dir = os.path.join(
                os.getcwd(),
                f"m365_security_scan_{self.timestamp}"
            )

    @property
    def scan_dir(self) -> Path:
        return Path(self.base_dir)

    @property
    def json_dir(self) -> Path:
        return self.scan_dir / "json"

    @property
    def csv_dir(self) -> Path:
        return self.scan_dir / "csv"

    @property
    def reports_dir(self) -> Path:
        return self.scan_dir / "reports"

    @property
    def audit_dir(self) -> Path:
        return self.scan_dir / "audit"

    def create_directories(self):
        for d in [self.json_dir, self.csv_dir, self.reports_dir, self.audit_dir]:
            d.mkdir(parents=True, exist_ok=True)


# ─── Master Configuration ───────────────────────────────────────────────────

@dataclass
class EngineConfig:
    """Top-level configuration for the entire engine."""
    auth: AuthConfig = field(default_factory=AuthConfig)
    collection: CollectionConfig = field(default_factory=CollectionConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    cache_enabled: bool = True
    cache_ttl_hours: int = 24     # Cache validity period
    delta_scan: bool = False      # Enable delta re-scan mode
    verbose: bool = False

    @classmethod
    def from_file(cls, path: str) -> "EngineConfig":
        """Load configuration from a JSON file."""
        with open(path, "r") as f:
            data = json.load(f)
        config = cls()
        if "auth" in data:
            auth_data = data["auth"]
            config.auth.mode = auth_data.get("mode", "certificate")
            if "certificate" in auth_data:
                c = auth_data["certificate"]
                config.auth.certificate = CertificateAuth(
                    tenant_id=c["tenant_id"],
                    client_id=c["client_id"],
                    certificate_path=c.get("certificate_path", "./base64.txt"),
                    certificate_password=c.get("certificate_password", ""),
                    thumbprint=c.get("thumbprint", ""),
                )
            if "delegated" in auth_data:
                d = auth_data["delegated"]
                config.auth.delegated = DelegatedAuth(
                    tenant_id=d["tenant_id"],
                    client_id=d["client_id"],
                )
        if "collection" in data:
            for k, v in data["collection"].items():
                if hasattr(config.collection, k):
                    setattr(config.collection, k, v)
        if "output" in data:
            for k, v in data["output"].items():
                if hasattr(config.output, k):
                    setattr(config.output, k, v)
        config.cache_enabled = data.get("cache_enabled", True)
        config.delta_scan = data.get("delta_scan", False)
        config.verbose = data.get("verbose", False)
        return config


# ─── Required Graph API Permissions (Least Privilege, Read-Only) ─────────

REQUIRED_PERMISSIONS = {
    # Identity surface
    "Directory.Read.All": "Enumerate users, groups, org details, domains",
    "User.Read.All": "Read user profiles, auth methods, sign-in activity",
    "Group.Read.All": "Read all groups and memberships",
    "GroupMember.Read.All": "Read group member details for nesting analysis",
    "UserAuthenticationMethod.Read.All": "Read MFA and auth method registrations",
    "IdentityRiskyUser.Read.All": "Read risky user signals",
    "IdentityRiskEvent.Read.All": "Read risk event detections",

    # Roles & PIM
    "RoleManagement.Read.All": "Read all role definitions and assignments",
    "PrivilegedAccess.Read.AzureADGroup": "Read PIM eligible assignments",
    "RoleManagement.Read.Directory": "Read directory role assignments",

    # Applications
    "Application.Read.All": "Read app registrations and service principals",

    # Conditional Access
    "Policy.Read.All": "Read CA policies, auth methods policies, etc.",

    # Intune / Endpoint Management
    "DeviceManagementConfiguration.Read.All": "Read compliance policies, config profiles",
    "DeviceManagementManagedDevices.Read.All": "Read managed device inventory",
    "DeviceManagementApps.Read.All": "Read MAM/app protection policies",
    "DeviceManagementServiceConfig.Read.All": "Read enrollment restrictions",
    "DeviceManagementRBAC.Read.All": "Read Intune RBAC roles",

    # Security / Defender
    "SecurityEvents.Read.All": "Read security alerts and events",
    "ThreatHunting.Read.All": "Read advanced hunting data (if licensed)",

    # Audit & Reports
    "AuditLog.Read.All": "Read audit and sign-in logs",
    "Reports.Read.All": "Read usage and activity reports",

    # Organization
    "Organization.Read.All": "Read tenant and domain information",

    # Mail (for monitoring config detection only)
    "MailboxSettings.Read": "Detect mail flow rules presence (optional)",
}

# Permissions that require admin consent
ADMIN_CONSENT_REQUIRED = [
    "Directory.Read.All",
    "User.Read.All",
    "Group.Read.All",
    "RoleManagement.Read.All",
    "Policy.Read.All",
    "AuditLog.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "SecurityEvents.Read.All",
]
