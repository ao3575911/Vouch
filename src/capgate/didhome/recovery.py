"""Social recovery and guardianship for did:home handles.

Recovery = people, not helpdesks. A handle's root key declares N guardians
and a threshold M. If the key is lost, M guardians sign approvals for a
new root key; the registry records a ``recovered`` event and the manifest
rotates to the new key. The whole ceremony verifies offline.

Guardianship: a parent's name issues a scoped child identity through the
existing permission-slip (capability token) machinery.
"""

from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capgate.didhome.delegation import (
    DEFAULT_TOKEN_TTL,
    CapabilityToken,
    issue_capability_token,
)
from capgate.didhome.manifest import (
    Manifest,
    _canonical_json,
    public_key_from_hex,
    validate_handle,
)

CHILD_PERMISSIONS = ("ping:send",)


class RecoveryError(ValueError):
    """Raised when a recovery ceremony fails validation."""


def recovery_payload(handle: str, new_root_public_key: str, prior_root_public_key: str) -> bytes:
    """Canonical bytes every guardian signs to approve a key rotation."""
    return _canonical_json(
        {
            "event": "recover",
            "handle": validate_handle(handle),
            "new_root_public_key": new_root_public_key,
            "prior_root_public_key": prior_root_public_key,
        }
    )


def approve_recovery(
    guardian_handle: str,
    guardian_key: Ed25519PrivateKey,
    handle: str,
    new_root_public_key: str,
    prior_root_public_key: str,
) -> dict[str, Any]:
    """A guardian's signed approval of a specific old-key -> new-key rotation."""
    payload = recovery_payload(handle, new_root_public_key, prior_root_public_key)
    return {
        "guardian": validate_handle(guardian_handle),
        "signature": guardian_key.sign(payload).hex(),
    }


def verify_approvals(
    handle: str,
    new_root_public_key: str,
    prior_root_public_key: str,
    approvals: list[dict[str, Any]],
    guardians: list[str],
    threshold: int,
    guardian_keys: dict[str, str],
) -> None:
    """Check that >= threshold distinct declared guardians validly approved.

    ``guardian_keys`` maps guardian handle -> hex root public key (resolved
    from the registry by the caller). Raises RecoveryError on any failure.
    """
    payload = recovery_payload(handle, new_root_public_key, prior_root_public_key)
    seen: set[str] = set()
    for approval in approvals:
        try:
            guardian = approval["guardian"]
            signature = bytes.fromhex(approval["signature"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RecoveryError(f"malformed approval: {exc}") from exc
        if guardian not in guardians:
            raise RecoveryError(f"@{guardian} is not a declared guardian")
        if guardian in seen:
            raise RecoveryError(f"duplicate approval from @{guardian}")
        key_hex = guardian_keys.get(guardian)
        if key_hex is None:
            raise RecoveryError(f"guardian @{guardian} unresolvable")
        try:
            public_key_from_hex(key_hex).verify(signature, payload)
        except (InvalidSignature, ValueError) as exc:
            raise RecoveryError(f"approval signature from @{guardian} invalid") from exc
        seen.add(guardian)
    if len(seen) < threshold:
        raise RecoveryError(
            f"insufficient approvals: {len(seen)} of {threshold} required (deny by default)"
        )


def issue_child_identity(
    parent_manifest: Manifest,
    parent_root_key: Ed25519PrivateKey,
    child_name: str,
    child_key: Ed25519PrivateKey,
    permissions: list[str] | None = None,
    ttl_seconds: float = DEFAULT_TOKEN_TTL,
    now: float | None = None,
) -> CapabilityToken:
    """Guardianship: a parent mints a scoped child identity.

    Rides the existing permission-slip machinery — the child token can be
    revoked or re-scoped by the parent at any time. Deny by default.
    """
    subject = f"{validate_handle(child_name)}@{parent_manifest.handle}"
    return issue_capability_token(
        parent_manifest.did,
        parent_root_key,
        subject,
        child_key,
        list(permissions) if permissions else list(CHILD_PERMISSIONS),
        ttl_seconds=ttl_seconds,
        now=now,
    )
