"""Capability-scoped delegation under a did:home handle.

The root key of ``@adam`` mints a sub-identity (``calendar@adam``) with its
own keypair and an explicit permission list. A third party verifies, using
only the static registry, that a token really grants exactly those
permissions and has not been revoked. Deny by default.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capgate.didhome.manifest import (
    _canonical_json,
    public_key_from_hex,
    public_key_hex,
)
from capgate.didhome.registry import Registry, RegistryError

DEFAULT_TOKEN_TTL = 30 * 24 * 3600  # 30 days


class DelegationError(ValueError):
    """Raised when a capability token fails validation."""


@dataclass(frozen=True)
class CapabilityToken:
    """A root-signed grant of specific permissions to a sub-identity key."""

    token_id: str
    issuer: str  # did:home:<handle>
    subject: str  # e.g. "calendar@adam"
    subject_public_key: str  # hex Ed25519
    permissions: tuple[str, ...]
    issued_at: float
    expires_at: float
    signature: str  # hex, by issuer root key

    def payload(self) -> bytes:
        return _canonical_json({k: v for k, v in self.to_dict().items() if k != "signature"})

    def to_dict(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "subject_public_key": self.subject_public_key,
            "permissions": list(self.permissions),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CapabilityToken:
        try:
            return cls(
                token_id=data["token_id"],
                issuer=data["issuer"],
                subject=data["subject"],
                subject_public_key=data["subject_public_key"],
                permissions=tuple(data["permissions"]),
                issued_at=float(data["issued_at"]),
                expires_at=float(data["expires_at"]),
                signature=data["signature"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DelegationError(f"malformed capability token: {exc}") from exc


def issue_capability_token(
    issuer_did: str,
    root_key: Ed25519PrivateKey,
    subject: str,
    subject_key: Ed25519PrivateKey,
    permissions: list[str],
    ttl_seconds: float = DEFAULT_TOKEN_TTL,
    now: float | None = None,
) -> CapabilityToken:
    """Mint a scoped token for a sub-identity. Empty permission lists refused."""
    if not permissions:
        raise DelegationError("refusing to issue a token with no permissions")
    issued = time.time() if now is None else now
    unsigned = CapabilityToken(
        token_id=secrets.token_hex(16),
        issuer=issuer_did,
        subject=subject,
        subject_public_key=public_key_hex(subject_key.public_key()),
        permissions=tuple(sorted(set(permissions))),
        issued_at=issued,
        expires_at=issued + ttl_seconds,
        signature="",
    )
    data = unsigned.to_dict()
    data["signature"] = root_key.sign(unsigned.payload()).hex()
    return CapabilityToken.from_dict(data)


def verify_capability_token(
    registry: Registry,
    token: CapabilityToken,
    required_permission: str,
    now: float | None = None,
) -> None:
    """Verify a token against the static registry. Raises DelegationError.

    Checks: issuer resolves + manifest verifies, root signature, expiry,
    revocation via the registry event log, and that the required permission
    is explicitly granted.
    """
    handle = token.issuer.removeprefix("did:home:")
    try:
        manifest = registry.resolve(handle)
    except RegistryError as exc:
        raise DelegationError(f"issuer unresolvable: {exc}") from exc
    if manifest.did != token.issuer:
        raise DelegationError("issuer DID mismatch")
    key = public_key_from_hex(manifest.root_public_key)
    try:
        key.verify(bytes.fromhex(token.signature), token.payload())
    except (InvalidSignature, ValueError) as exc:
        raise DelegationError("token signature invalid") from exc
    current = time.time() if now is None else now
    if current > token.expires_at:
        raise DelegationError("token expired")
    if token.token_id in registry.revoked_token_ids(handle):
        raise DelegationError("token revoked")
    if required_permission not in token.permissions:
        raise DelegationError(
            f"permission {required_permission!r} not granted (deny by default)"
        )
