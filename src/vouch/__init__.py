"""Vouch — your name, your key, your proof.

Vouch is the public face of the ``did:home`` namespace. Plain words only:

    name   = your handle (@adam)
    key    = the secret only you hold
    vouch  = a permission slip you sign for a helper
    prove  = show something is really from you

A portable handle, login with it, and signed statements anyone can check
offline. Scope: docs/adr-0001-scope.md.

The cryptographic engine lives in ``capgate.didhome`` (internal). This
package re-exports it under friendly names and ships the ``vouch-id`` CLI.
"""

from capgate.didhome import (
    CapabilityToken,
    DelegationError,
    Manifest,
    ManifestError,
    Ping,
    PingError,
    ProofError,
    RecoveryError,
    Registry,
    RegistryError,
    approve_recovery,
    card_html,
    create_manifest,
    create_ping,
    create_proof,
    did_for_handle,
    export_bundle,
    issue_capability_token,
    issue_child_identity,
    update_manifest,
    validate_handle,
    verify_approvals,
    verify_capability_token,
    verify_manifest,
    verify_ping,
    verify_proof,
    verify_proof_for_handle,
)

__all__ = [
    "CapabilityToken",
    "DelegationError",
    "Manifest",
    "ManifestError",
    "Ping",
    "PingError",
    "ProofError",
    "RecoveryError",
    "Registry",
    "RegistryError",
    "approve_recovery",
    "card_html",
    "create_manifest",
    "create_ping",
    "create_proof",
    "did_for_handle",
    "export_bundle",
    "issue_capability_token",
    "issue_child_identity",
    "update_manifest",
    "validate_handle",
    "verify_approvals",
    "verify_capability_token",
    "verify_manifest",
    "verify_ping",
    "verify_proof",
    "verify_proof_for_handle",
]
