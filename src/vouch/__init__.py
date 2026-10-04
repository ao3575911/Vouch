"""Vouch — your name, your key, your proof. Plan B to government digital ID.

Vouch is the public face of the ``did:home`` namespace. Plain words only:

    name   = your handle (@adam)
    key    = the secret only you hold
    vouch  = a permission slip you sign for a helper
    prove  = show something is really from you

Government digital ID: they check you against their database and log it.
Vouch: you prove it yourself; nobody is called, nothing is logged.

The cryptographic engine lives in ``capgate.didhome`` (internal). This
package re-exports it under friendly names and ships the ``vouch`` CLI.
"""

from capgate.didhome import (
    CapabilityToken,
    DelegationError,
    Manifest,
    ManifestError,
    Ping,
    PingError,
    Registry,
    RegistryError,
    create_manifest,
    create_ping,
    did_for_handle,
    export_bundle,
    issue_capability_token,
    update_manifest,
    validate_handle,
    verify_capability_token,
    verify_manifest,
    verify_ping,
)

__all__ = [
    "CapabilityToken",
    "DelegationError",
    "Manifest",
    "ManifestError",
    "Ping",
    "PingError",
    "Registry",
    "RegistryError",
    "create_manifest",
    "create_ping",
    "did_for_handle",
    "export_bundle",
    "issue_capability_token",
    "update_manifest",
    "validate_handle",
    "verify_capability_token",
    "verify_manifest",
    "verify_ping",
]
