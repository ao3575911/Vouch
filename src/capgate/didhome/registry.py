"""Static did:home registry: files + hash-chained, signed event log.

Layout (a plain directory — intended to live in a public git repo / Pages):

    registry/
    ├── names/<handle>.json   current signed manifest per handle
    └── events.jsonl          hash-chained log (capgate AuditLog format);
                              every mutating event detail carries an
                              Ed25519 signature by the handle's root key

First valid claim wins. The whole registry verifies offline — this is the
CI gate for a pull-request-based namespace.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capgate.audit import AuditLog
from capgate.didhome.manifest import (
    Manifest,
    ManifestError,
    _canonical_json,
    public_key_from_hex,
    public_key_hex,
    validate_handle,
    verify_manifest,
)


class RegistryError(ValueError):
    """Raised on invalid registry operations or failed verification."""


def _event_payload(event: str, handle: str, body: dict[str, Any]) -> bytes:
    return _canonical_json({"event": event, "handle": handle, "body": body})


class Registry:
    """File-backed did:home registry with a tamper-evident event log."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.names_dir = self.root / "names"
        self.names_dir.mkdir(parents=True, exist_ok=True)
        self.log = AuditLog(self.root / "events.jsonl")

    # -- resolution -------------------------------------------------------

    def _path(self, handle: str) -> Path:
        return self.names_dir / f"{validate_handle(handle)}.json"

    def resolve(self, handle: str) -> Manifest:
        """Resolve a handle to its verified manifest."""
        path = self._path(handle)
        if not path.exists():
            raise RegistryError(f"handle @{validate_handle(handle)} not found")
        manifest = Manifest.from_dict(json.loads(path.read_text(encoding="utf-8")))
        verify_manifest(manifest)
        if self.is_deactivated(manifest.handle):
            raise RegistryError(f"handle @{manifest.handle} is deactivated")
        return manifest

    def handles(self) -> list[str]:
        return sorted(p.stem for p in self.names_dir.glob("*.json"))

    # -- mutations (all root-key signed) ----------------------------------

    def _append(
        self,
        event: str,
        manifest: Manifest,
        root_key: Ed25519PrivateKey,
        body: dict[str, Any],
        now: float | None = None,
    ) -> None:
        if public_key_hex(root_key.public_key()) != manifest.root_public_key:
            raise RegistryError("event must be signed by the handle's root key")
        detail = {
            "body": body,
            "signature": root_key.sign(_event_payload(event, manifest.handle, body)).hex(),
        }
        self.log.append(event, manifest.did, detail, now=now)

    def claim(
        self, manifest: Manifest, root_key: Ed25519PrivateKey, now: float | None = None
    ) -> None:
        """First-valid-signature-wins claim of a handle."""
        verify_manifest(manifest)
        path = self._path(manifest.handle)
        if path.exists():
            raise RegistryError(f"handle @{manifest.handle} already claimed")
        if manifest.version != 1:
            raise RegistryError("claim requires a version-1 manifest")
        self._append("claimed", manifest, root_key, {"manifest_hash": manifest.manifest_hash()}, now)
        path.write_text(json.dumps(manifest.to_dict(), sort_keys=True, indent=2), encoding="utf-8")

    def update(
        self, manifest: Manifest, root_key: Ed25519PrivateKey, now: float | None = None
    ) -> None:
        """Replace a manifest with its next version (same root key, version+1)."""
        verify_manifest(manifest)
        current = self.resolve(manifest.handle)
        if manifest.root_public_key != current.root_public_key:
            raise RegistryError("root key continuity violated")
        if manifest.version != current.version + 1:
            raise RegistryError("manifest version must increment by exactly 1")
        self._append("updated", manifest, root_key, {"manifest_hash": manifest.manifest_hash()}, now)
        self._path(manifest.handle).write_text(
            json.dumps(manifest.to_dict(), sort_keys=True, indent=2), encoding="utf-8"
        )

    def revoke_token(
        self, handle: str, token_id: str, root_key: Ed25519PrivateKey, now: float | None = None
    ) -> None:
        manifest = self.resolve(handle)
        self._append("token_revoked", manifest, root_key, {"token_id": token_id}, now)

    def deactivate(
        self, handle: str, root_key: Ed25519PrivateKey, now: float | None = None
    ) -> None:
        manifest = self.resolve(handle)
        self._append("deactivated", manifest, root_key, {}, now)

    # -- derived state -----------------------------------------------------

    def revoked_token_ids(self, handle: str) -> set[str]:
        did = "did:home:" + validate_handle(handle)
        return {
            r["detail"]["body"]["token_id"]
            for r in self.log.records()
            if r["event"] == "token_revoked" and r["agent_id"] == did
        }

    def is_deactivated(self, handle: str) -> bool:
        did = "did:home:" + validate_handle(handle)
        return any(
            r["event"] == "deactivated" and r["agent_id"] == did for r in self.log.records()
        )

    # -- offline verification (the CI gate) --------------------------------

    def verify(self) -> int:
        """Verify the hash chain, every event signature, and every manifest.

        Returns the event count. Raises on any inconsistency.
        """
        count = self.log.verify()
        manifests: dict[str, Manifest] = {}
        for name in self.handles():
            m = Manifest.from_dict(
                json.loads(self._path(name).read_text(encoding="utf-8"))
            )
            try:
                verify_manifest(m)
            except ManifestError as exc:
                raise RegistryError(f"manifest for @{name} invalid: {exc}") from exc
            manifests[m.did] = m
        claimed: dict[str, str] = {}  # did -> root key at claim time
        for i, r in enumerate(self.log.records()):
            event, did, detail = r["event"], r["agent_id"], r["detail"]
            handle = did.removeprefix("did:home:")
            if event == "claimed":
                if did in claimed:
                    raise RegistryError(f"event {i}: duplicate claim for {did}")
                if did not in manifests:
                    raise RegistryError(f"event {i}: claim for {did} without manifest file")
                claimed[did] = manifests[did].root_public_key
            elif did not in claimed:
                raise RegistryError(f"event {i}: {event} for unclaimed {did}")
            key = public_key_from_hex(
                manifests[did].root_public_key if did in manifests else claimed[did]
            )
            try:
                key.verify(
                    bytes.fromhex(detail["signature"]),
                    _event_payload(event, handle, detail["body"]),
                )
            except (InvalidSignature, ValueError, KeyError) as exc:
                raise RegistryError(f"event {i}: bad signature for {event} on {did}") from exc
        for did, m in manifests.items():
            if did not in claimed:
                raise RegistryError(f"manifest {did} present without a claim event")
            if m.root_public_key != claimed[did]:
                raise RegistryError(f"root key continuity violated for {did}")
        return count


def export_bundle(registry: Registry, handle: str, private_key_hex: str) -> dict[str, Any]:
    """Portable identity bundle: manifest + key + the handle's event history."""
    manifest = registry.resolve(handle)
    did = manifest.did
    return {
        "did": did,
        "manifest": manifest.to_dict(),
        "private_key": private_key_hex,
        "events": [r for r in registry.log.records() if r["agent_id"] == did],
        "exported_at": time.time(),
    }
