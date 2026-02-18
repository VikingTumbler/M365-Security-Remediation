"""
Authentication module — Supports certificate-based and delegated interactive auth.
Uses MSAL for token acquisition against Microsoft Identity Platform.
"""

from __future__ import annotations

import base64
import getpass
import logging
import os
from typing import Optional

from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.hashes import SHA1
import msal

from ..config import AuthConfig, CertificateAuth, DelegatedAuth, REQUIRED_PERMISSIONS

logger = logging.getLogger("m365_security_engine.auth")

# Default scopes for app-only auth
APP_SCOPES = ["https://graph.microsoft.com/.default"]


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


class Authenticator:
    """
    Handles MSAL-based authentication for Microsoft Graph.
    Supports:
      - Certificate-based app-only authentication
      - Delegated interactive authentication (device code flow)
    """

    def __init__(self, config: AuthConfig):
        self.config = config
        self._access_token: Optional[str] = None
        self._token_expiry: Optional[float] = None

    async def acquire_token(self) -> str:
        """Acquire an access token based on configured auth mode."""
        if self.config.mode == "certificate":
            return self._acquire_certificate_token()
        elif self.config.mode == "delegated":
            return self._acquire_delegated_token()
        else:
            raise AuthenticationError(f"Unknown auth mode: {self.config.mode}")

    def _acquire_certificate_token(self) -> str:
        """Acquire token using certificate-based client credentials."""
        cert_config = self.config.certificate
        if not cert_config:
            raise AuthenticationError("Certificate auth config not provided.")

        logger.info("Authenticating with certificate-based app credentials...")

        # Load the certificate
        cert_path = cert_config.certificate_path
        password = cert_config.certificate_password
        if not password:
            password = os.environ.get("M365_CERT_PASSWORD", "")
        if not password:
            password = getpass.getpass("Enter the certificate password: ")

        try:
            with open(cert_path, "r") as f:
                cert_base64 = f.read().strip()

            cert_bytes = base64.b64decode(cert_base64)
            password_bytes = password.encode("utf-8") if password else None

            private_key, certificate, _ = pkcs12.load_key_and_certificates(
                cert_bytes, password_bytes
            )

            # Extract PEM strings
            private_key_pem = private_key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            ).decode("utf-8")

            cert_pem = certificate.public_bytes(Encoding.PEM).decode("utf-8")

            # Compute thumbprint
            thumbprint = certificate.fingerprint(SHA1()).hex()

            logger.info(f"Certificate loaded. Thumbprint: {thumbprint}")

        except FileNotFoundError:
            raise AuthenticationError(
                f"Certificate file not found: {cert_path}. "
                "Ensure base64.txt exists in the script directory."
            )
        except Exception as e:
            raise AuthenticationError(f"Failed to load certificate: {e}")

        # Create MSAL confidential client
        app = msal.ConfidentialClientApplication(
            client_id=cert_config.client_id,
            authority=f"https://login.microsoftonline.com/{cert_config.tenant_id}",
            client_credential={
                "thumbprint": thumbprint,
                "private_key": private_key_pem,
            },
        )

        result = app.acquire_token_for_client(scopes=APP_SCOPES)

        if "access_token" in result:
            self._access_token = result["access_token"]
            logger.info("Certificate authentication successful.")
            return self._access_token
        else:
            error = result.get("error_description", result.get("error", "Unknown"))
            raise AuthenticationError(f"Certificate auth failed: {error}")

    def _acquire_delegated_token(self) -> str:
        """Acquire token using delegated (device code) flow."""
        deleg_config = self.config.delegated
        if not deleg_config:
            raise AuthenticationError("Delegated auth config not provided.")

        logger.info("Initiating device code authentication flow...")

        app = msal.PublicClientApplication(
            client_id=deleg_config.client_id,
            authority=f"https://login.microsoftonline.com/{deleg_config.tenant_id}",
        )

        # Use device code flow for interactive auth
        flow = app.initiate_device_flow(scopes=deleg_config.scopes)
        if "user_code" not in flow:
            raise AuthenticationError(
                f"Device code flow failed: {flow.get('error_description', 'Unknown')}"
            )

        print(f"\n{'='*60}")
        print(f"  To sign in, open: {flow['verification_uri']}")
        print(f"  Enter code: {flow['user_code']}")
        print(f"{'='*60}\n")

        result = app.acquire_token_by_device_flow(flow)

        if "access_token" in result:
            self._access_token = result["access_token"]
            logger.info("Delegated authentication successful.")
            return self._access_token
        else:
            error = result.get("error_description", result.get("error", "Unknown"))
            raise AuthenticationError(f"Delegated auth failed: {error}")

    @property
    def access_token(self) -> Optional[str]:
        return self._access_token

    @staticmethod
    def list_required_permissions() -> dict[str, str]:
        """Return the map of required Graph API permissions."""
        return REQUIRED_PERMISSIONS
