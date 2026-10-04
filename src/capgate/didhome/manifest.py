"""Self-signed identity manifests — the DID documents of did:home.

A manifest binds a handle (``@adam`` → ``did:home:adam``) to an Ed25519
root key, service endpoints, and delegated agents. The signature covers
canonical JSON with the ``signature`` field excluded, so manifests are
reproducible and independently verifiable offline.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DID_PREFIX = "did:home:"
HANDLE_RE = re.compile(r"^[a-z0-9_]{3,24}$")
RESERVED_HANDLES = frozenset(
    {"admin", "root", "system", "home", "registry", "did", "www", "mail", "api", "help"}
)


class ManifestError(ValueError):
    """Raised when a manifest fails structural or cryptographic validation."""


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_handle(handle: str) -> str:
    """Return the handle (without '@') or raise ManifestError."""
    name = handle.lstrip("@")
    if not HANDLE_RE.match(name):
        raise ManifestError(f"invalid handle {handle!r}: must match [a-z0-9_]{{3,24}}")
    if name in RESERVED_HANDLES:
        raise ManifestError(f"handle {handle!r} is reserved")
    return name


def did_for_handle(handle: str) -> str:
    return DID_PREFIX + validate_handle(handle)


def public_key_hex(key: Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def public_key_from_hex(hex_key: str) -> Ed25519PublicKey:
    try:
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_key))
    except ValueError as exc:
        raise ManifestError("malformed public key") from exc


@dataclass(frozen=True)
class Manifest:
    """A did:home DID document: self-signed identity manifest."""

    did: str
    handle: str
    root_public_key: str  # hex-encoded Ed25519 public key
    services: list[dict[str, Any]] = field(default_factory=list)
    agents: list[dict[str, Any]] = field(default_factory=list)
    version: int = 1
    created_at: float = 0.0
    updated_at: float = 0.0
    signature: str = ""  # hex Ed25519 signature over payload()

    def payload(self) -> bytes:
        return _canonical_json({k: v for k, v in self.to_dict().items() if k != "signature"})

    def to_dict(self) -> dict[str, Any]:
        return {
            "did": self.did,
            "handle": self.handle,
            "root_public_key": self.root_public_key,
            "services": self.services,
            "agents": self.agents,
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Manifest:
        try:
            return cls(
                did=data["did"],
                handle=data["handle"],
                root_public_key=data["root_public_key"],
                services=list(data.get("services", [])),
                agents=list(data.get("agents", [])),
                version=int(data["version"]),
                created_at=float(data["created_at"]),
                updated_at=float(data["updated_at"]),
                signature=data["signature"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ManifestError(f"malformed manifest: {exc}") from exc

    def manifest_hash(self) -> str:
        return hashlib.sha256(_canonical_json(self.to_dict())).hexdigest()


def _sign(manifest: Manifest, root_key: Ed25519PrivateKey) -> Manifest:
    data = manifest.to_dict()
    data["signature"] = root_key.sign(manifest.payload()).hex()
    return Manifest.from_dict(data)


def create_manifest(
    handle: str,
    root_key: Ed25519PrivateKey,
    services: list[dict[str, Any]] | None = None,
    agents: list[dict[str, Any]] | None = None,
    now: float | None = None,
) -> Manifest:
    """Create and self-sign a v1 manifest for a handle."""
    name = validate_handle(handle)
    ts = time.time() if now is None else now
    unsigned = Manifest(
        did=DID_PREFIX + name,
        handle=name,
        root_public_key=public_key_hex(root_key.public_key()),
        services=services or [],
        agents=agents or [],
        version=1,
        created_at=ts,
        updated_at=ts,
    )
    return _sign(unsigned, root_key)


def update_manifest(
    manifest: Manifest,
    root_key: Ed25519PrivateKey,
    services: list[dict[str, Any]] | None = None,
    agents: list[dict[str, Any]] | None = None,
    now: float | None = None,
) -> Manifest:
    """Produce the next signed version. Key continuity enforced by registry."""
    verify_manifest(manifest)
    if public_key_hex(root_key.public_key()) != manifest.root_public_key:
        raise ManifestError("update must be signed by the current root key")
    data = manifest.to_dict()
    if services is not None:
        data["services"] = services
    if agents is not None:
        data["agents"] = agents
    data["version"] = manifest.version + 1
    data["updated_at"] = time.time() if now is None else now
    return _sign(Manifest.from_dict(data), root_key)


def verify_manifest(manifest: Manifest) -> None:
    """Verify structure + self-signature. Raises ManifestError on failure."""
    name = validate_handle(manifest.handle)
    if manifest.did != DID_PREFIX + name:
        raise ManifestError("did does not match handle")
    key = public_key_from_hex(manifest.root_public_key)
    try:
        key.verify(bytes.fromhex(manifest.signature), manifest.payload())
    except (InvalidSignature, ValueError) as exc:
        raise ManifestError("manifest signature invalid") from exc
