"""
Safety Guardian — Enforces strict read-only operation.
Validates all HTTP methods, blocks write attempts, and logs safety events.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Optional

logger = logging.getLogger("m365_security_engine.safety")

# ─── Blocked HTTP Methods ────────────────────────────────────────────────────

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Known read-only POST endpoints (Graph uses POST for some queries)
SAFE_POST_ENDPOINTS = [
    re.compile(r"/\$batch$"),                        # Batch read requests
    re.compile(r"/microsoft\.graph\.getByIds$"),     # Resolve IDs
    re.compile(r"/reports/"),                         # Report exports use POST
    re.compile(r"/security/microsoft\.graph\.security\.runHuntingQuery$"),
]

# Explicitly blocked write-pattern URLs
BLOCKED_URL_PATTERNS = [
    re.compile(r"/invite$", re.IGNORECASE),
    re.compile(r"/assign$", re.IGNORECASE),
    re.compile(r"/remove$", re.IGNORECASE),
    re.compile(r"/update$", re.IGNORECASE),
    re.compile(r"/enable$", re.IGNORECASE),
    re.compile(r"/disable$", re.IGNORECASE),
    re.compile(r"/resetPassword$", re.IGNORECASE),
    re.compile(r"/revokeSignInSessions$", re.IGNORECASE),
    re.compile(r"/addPassword$", re.IGNORECASE),
    re.compile(r"/removePassword$", re.IGNORECASE),
    re.compile(r"/setMobileDeviceManagementAuthority$", re.IGNORECASE),
    re.compile(r"/wipe$", re.IGNORECASE),
    re.compile(r"/retire$", re.IGNORECASE),
    re.compile(r"/sync$", re.IGNORECASE),
]


class SafetyViolation(Exception):
    """Raised when a write operation is attempted."""
    pass


class SafetyGuardian:
    """
    Validates every outbound HTTP request to ensure read-only operation.
    Maintains an audit log of all safety checks and violations.
    """

    def __init__(self):
        self.violations: list[dict] = []
        self.checks_performed: int = 0
        self.started_at: str = datetime.utcnow().isoformat() + "Z"
        self._active = True

    def validate_request(self, method: str, url: str, body: Optional[dict] = None) -> bool:
        """
        Validate that a request is read-only.
        Returns True if safe, raises SafetyViolation if not.
        """
        self.checks_performed += 1
        method_upper = method.upper()

        # GET and HEAD are always safe
        if method_upper in ("GET", "HEAD", "OPTIONS"):
            return True

        # POST is allowed only for known safe endpoints
        if method_upper == "POST":
            for pattern in SAFE_POST_ENDPOINTS:
                if pattern.search(url):
                    return True

        # Check for explicitly blocked URL patterns on any method
        for pattern in BLOCKED_URL_PATTERNS:
            if pattern.search(url):
                self._record_violation(method_upper, url, "Blocked write-pattern URL")
                raise SafetyViolation(
                    f"SAFETY VIOLATION: Write-pattern URL detected: {method_upper} {url}"
                )

        # Block all other write methods
        if method_upper in WRITE_METHODS:
            self._record_violation(method_upper, url, "Write HTTP method blocked")
            raise SafetyViolation(
                f"SAFETY VIOLATION: Write method blocked: {method_upper} {url}"
            )

        return True

    def _record_violation(self, method: str, url: str, reason: str):
        """Record a safety violation for audit."""
        violation = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "method": method,
            "url": url,
            "reason": reason,
        }
        self.violations.append(violation)
        logger.critical(f"SAFETY VIOLATION: {reason} — {method} {url}")

    def get_audit_record(self) -> dict:
        """Return the full safety audit record."""
        return {
            "safety_guardian": {
                "mode": "READ-ONLY",
                "started_at": self.started_at,
                "checks_performed": self.checks_performed,
                "violations_detected": len(self.violations),
                "violations": self.violations,
                "status": "CLEAN" if not self.violations else "VIOLATIONS_DETECTED",
            }
        }

    @staticmethod
    def print_banner():
        """Print the read-only warning banner."""
        import sys
        # Use Unicode box-drawing only when stdout is an interactive terminal
        # that knowably supports UTF-8.  Piped/redirected output (e.g. captured
        # in PowerShell) or CP1252 consoles fall back to ASCII.
        enc = getattr(sys.stdout, "encoding", "") or ""
        unicode_ok = (
            sys.stdout.isatty()
            and enc.lower().replace("-", "") in ("utf8", "utf16", "utf32")
        )

        if unicode_ok:
            banner = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                         ║
║   ██████  ███████  █████  ██████        ██████  ███    ██ ██      ██    ║
║   ██   ██ ██      ██   ██ ██   ██      ██    ██ ████   ██ ██       ██   ║
║   ██████  █████   ███████ ██   ██ ████ ██    ██ ██ ██  ██ ██        ██  ║
║   ██   ██ ██      ██   ██ ██   ██      ██    ██ ██  ██ ██ ██       ██   ║
║   ██   ██ ███████ ██   ██ ██████        ██████  ██   ████ ███████ ██    ║
║                                                                         ║
║   READ-ONLY SECURITY INTELLIGENCE SCAN — NO CHANGES WILL BE MADE       ║
║                                                                         ║
║   * All API calls are GET/read-only                                     ║
║   * No policies, users, or settings will be modified                    ║
║   * Safety Guardian enforces read-only at the HTTP layer                ║
║   * Every request is validated before execution                         ║
║                                                                         ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""
            try:
                print(banner)
                return
            except UnicodeEncodeError:
                pass  # fall through to ASCII banner

        # ASCII fallback for CP1252 / non-Unicode terminals
        print("=" * 75)
        print("  READ-ONLY SECURITY INTELLIGENCE SCAN -- NO CHANGES WILL BE MADE")
        print("  * All API calls are GET/read-only")
        print("  * No policies, users, or settings will be modified")
        print("  * Safety Guardian enforces read-only at the HTTP layer")
        print("=" * 75)
