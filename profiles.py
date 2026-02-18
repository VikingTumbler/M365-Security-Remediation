"""
Tenant Profile Manager — Named profiles for multi-tenant support.

Profiles are stored in:
    ~/.m365_security_engine/profiles.json

Each profile contains tenant_id, client_id, cert_path, and an
optional display name. Admins managing multiple tenants can switch
between them via `--profile <name>` on the CLI.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CONFIG_DIR = Path.home() / ".m365_security_engine"
_PROFILES_FILE = _CONFIG_DIR / "profiles.json"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class TenantProfile:
    """A single named tenant profile."""
    name: str                          # Unique short name (e.g. "ncc1701", "contoso-prod")
    tenant_id: str                     # Azure AD / Entra tenant ID
    client_id: str                     # App registration client ID
    cert_path: str = "./base64.txt"    # Path to the base64-encoded PFX certificate
    tenant_display_name: str = ""      # Friendly name shown in reports
    notes: str = ""                    # Optional admin notes

    def resolve_cert_path(self) -> str:
        """Return absolute cert path, resolving ~ and relative paths."""
        p = Path(self.cert_path).expanduser()
        if not p.is_absolute():
            p = Path.cwd() / p
        return str(p)


@dataclass
class ProfileStore:
    """Manages the collection of tenant profiles on disk."""
    profiles: dict[str, TenantProfile] = field(default_factory=dict)
    default_profile: str = ""

    # --- Persistence ---

    @classmethod
    def load(cls) -> "ProfileStore":
        """Load profiles from disk. Returns empty store if file doesn't exist."""
        if not _PROFILES_FILE.exists():
            return cls()
        try:
            data = json.loads(_PROFILES_FILE.read_text(encoding="utf-8"))
            store = cls()
            store.default_profile = data.get("default_profile", "")
            for name, pdata in data.get("profiles", {}).items():
                store.profiles[name] = TenantProfile(
                    name=name,
                    tenant_id=pdata["tenant_id"],
                    client_id=pdata["client_id"],
                    cert_path=pdata.get("cert_path", "./base64.txt"),
                    tenant_display_name=pdata.get("tenant_display_name", ""),
                    notes=pdata.get("notes", ""),
                )
            return store
        except (json.JSONDecodeError, KeyError) as e:
            print(f"  ⚠  Failed to parse profiles.json: {e}")
            return cls()

    def save(self) -> None:
        """Persist profiles to disk."""
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "default_profile": self.default_profile,
            "profiles": {
                name: {
                    "tenant_id": p.tenant_id,
                    "client_id": p.client_id,
                    "cert_path": p.cert_path,
                    "tenant_display_name": p.tenant_display_name,
                    "notes": p.notes,
                }
                for name, p in self.profiles.items()
            },
        }
        _PROFILES_FILE.write_text(
            json.dumps(data, indent=2) + "\n", encoding="utf-8"
        )

    # --- CRUD ---

    def add(self, profile: TenantProfile, set_default: bool = False) -> None:
        """Add or overwrite a profile."""
        self.profiles[profile.name] = profile
        if set_default or not self.default_profile:
            self.default_profile = profile.name
        self.save()

    def remove(self, name: str) -> bool:
        """Remove a profile by name. Returns True if it existed."""
        if name not in self.profiles:
            return False
        del self.profiles[name]
        if self.default_profile == name:
            self.default_profile = next(iter(self.profiles), "")
        self.save()
        return True

    def get(self, name: str) -> Optional[TenantProfile]:
        """Get a profile by name (case-insensitive)."""
        key = name.lower()
        for pname, profile in self.profiles.items():
            if pname.lower() == key:
                return profile
        return None

    def get_default(self) -> Optional[TenantProfile]:
        """Get the default profile, or None if no profiles exist."""
        if self.default_profile:
            return self.profiles.get(self.default_profile)
        if self.profiles:
            return next(iter(self.profiles.values()))
        return None

    def set_default(self, name: str) -> bool:
        """Set the default profile. Returns True if profile exists."""
        if name not in self.profiles:
            return False
        self.default_profile = name
        self.save()
        return True

    def list_profiles(self) -> list[TenantProfile]:
        """Return all profiles sorted by name."""
        return sorted(self.profiles.values(), key=lambda p: p.name)


# ---------------------------------------------------------------------------
# Convenience: resolve profile for a scan
# ---------------------------------------------------------------------------

def resolve_profile(
    profile_name: Optional[str] = None,
) -> Optional[TenantProfile]:
    """
    Look up a tenant profile by name.
    If no name given, returns the default profile.
    Returns None if no profiles are configured.
    """
    store = ProfileStore.load()
    if profile_name:
        return store.get(profile_name)
    return store.get_default()
