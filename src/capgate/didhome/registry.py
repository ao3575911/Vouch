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
        if manifest.handle != validate_handle(handle):
            raise RegistryError(f"names file for @{validate_handle(handle)} holds another handle")
        if manifest.root_public_key != self.current_root_key(manifest.did):
            raise RegistryError(
                f"manifest key for @{manifest.handle} does not match the event log"
            )
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

    def set_guardians(
        self,
        handle: str,
        guardians: list[str],
        threshold: int,
        root_key: Ed25519PrivateKey,
        now: float | None = None,
    ) -> None:
        """Declare the handle's recovery guardians and approval threshold."""
        manifest = self.resolve(handle)
        names = sorted({validate_handle(g) for g in guardians})
        if manifest.handle in names:
            raise RegistryError("a handle cannot be its own guardian")
        if not 1 <= threshold <= len(names):
            raise RegistryError("threshold must be between 1 and the number of guardians")
        for g in names:
            self.resolve(g)  # every guardian must be a claimed, active handle
        self._append(
            "guardians_set", manifest, root_key, {"guardians": names, "threshold": threshold}, now
        )

    def guardian_policy(self, handle: str) -> tuple[list[str], int] | None:
        """Latest declared (guardians, threshold) for a handle, if any."""
        did = "did:home:" + validate_handle(handle)
        policy = None
        for r in self.log.records():
            if r["event"] == "guardians_set" and r["agent_id"] == did:
                body = r["detail"]["body"]
                policy = (list(body["guardians"]), int(body["threshold"]))
        return policy

    def recover(
        self,
        handle: str,
        new_root_key: Ed25519PrivateKey,
        approvals: list[dict[str, Any]],
        now: float | None = None,
    ) -> Manifest:
        """Rotate a lost root key via N-of-M guardian approvals.

        The ``recovered`` event is signed by the NEW root key and carries the
        guardian approvals; offline verification re-checks everything.
        """
        from capgate.didhome.recovery import RecoveryError, verify_approvals

        current = self.resolve(handle)
        policy = self.guardian_policy(handle)
        if policy is None:
            raise RegistryError(f"no guardians declared for @{current.handle}")
        guardians, threshold = policy
        new_pub = public_key_hex(new_root_key.public_key())
        if new_pub == current.root_public_key:
            raise RegistryError("new root key must differ from the current root key")
        guardian_keys = {g: self.resolve(g).root_public_key for g in guardians}
        try:
            verify_approvals(
                current.handle,
                new_pub,
                current.root_public_key,
                approvals,
                guardians,
                threshold,
                guardian_keys,
            )
        except RecoveryError as exc:
            raise RegistryError(f"recovery denied: {exc}") from exc
        body = {
            "new_root_public_key": new_pub,
            "prior_root_public_key": current.root_public_key,
            "approvals": approvals,
        }
        detail = {
            "body": body,
            "signature": new_root_key.sign(
                _event_payload("recovered", current.handle, body)
            ).hex(),
        }
        self.log.append("recovered", current.did, detail, now=now)
        data = current.to_dict()
        data["root_public_key"] = new_pub
        data["version"] = current.version + 1
        data["updated_at"] = time.time() if now is None else now
        unsigned = Manifest.from_dict(data)
        data["signature"] = new_root_key.sign(unsigned.payload()).hex()
        manifest = Manifest.from_dict(data)
        self._path(current.handle).write_text(
            json.dumps(manifest.to_dict(), sort_keys=True, indent=2), encoding="utf-8"
        )
        return manifest

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

    # -- key history from the log -----------------------------------------

    def _file_keys(self) -> dict[str, str]:
        """did -> root key as written in each names file (unverified)."""
        keys: dict[str, str] = {}
        for name in self.handles():
            try:
                data = json.loads(self._path(name).read_text(encoding="utf-8"))
                keys[str(data["did"])] = str(data["root_public_key"])
            except (OSError, ValueError, KeyError, TypeError, ManifestError):
                continue
        return keys

    def _replay(self, file_keys: dict[str, str]) -> dict[str, str]:
        """Replay the event log; return did -> root key after the last event.

        Checks every event signature against the key that was current at that
        event, and every recovery's guardian approvals. ``file_keys`` supplies
        the claim-time key for handles that were never recovered; the claim
        event signature is what pins it.
        """
        from capgate.didhome.recovery import RecoveryError, verify_approvals

        records = list(self.log.records())
        # initial (claim-time) root key: walk back through any recoveries
        initial: dict[str, str] = {}
        for r in records:
            if r["event"] == "recovered":
                initial.setdefault(
                    r["agent_id"], r["detail"]["body"]["prior_root_public_key"]
                )
        for did, key_hex in file_keys.items():
            initial.setdefault(did, key_hex)
        claimed: dict[str, str] = {}  # did -> root key as of the current event
        policies: dict[str, tuple[list[str], int]] = {}  # did -> (guardians, threshold)
        for i, r in enumerate(records):
            event, did, detail = r["event"], r["agent_id"], r["detail"]
            handle = did.removeprefix("did:home:")
            if event == "claimed":
                if did in claimed:
                    raise RegistryError(f"event {i}: duplicate claim for {did}")
                if did not in file_keys:
                    raise RegistryError(f"event {i}: claim for {did} without manifest file")
                claimed[did] = initial[did]
            elif did not in claimed:
                raise RegistryError(f"event {i}: {event} for unclaimed {did}")
            if event == "recovered":
                body = detail["body"]
                if body["prior_root_public_key"] != claimed[did]:
                    raise RegistryError(f"event {i}: recovery prior key mismatch for {did}")
                policy = policies.get(did)
                if policy is None:
                    raise RegistryError(f"event {i}: recovery without declared guardians")
                guardians, threshold = policy
                guardian_keys = {
                    g: claimed.get("did:home:" + g, "") for g in guardians
                }
                try:
                    verify_approvals(
                        handle,
                        body["new_root_public_key"],
                        body["prior_root_public_key"],
                        body["approvals"],
                        guardians,
                        threshold,
                        guardian_keys,
                    )
                except RecoveryError as exc:
                    raise RegistryError(f"event {i}: {exc}") from exc
                claimed[did] = body["new_root_public_key"]
            try:
                key = public_key_from_hex(claimed[did])
                key.verify(
                    bytes.fromhex(detail["signature"]),
                    _event_payload(event, handle, detail["body"]),
                )
            except (InvalidSignature, ValueError, KeyError) as exc:
                raise RegistryError(f"event {i}: bad signature for {event} on {did}") from exc
            if event == "guardians_set":
                body = detail["body"]
                policies[did] = (list(body["guardians"]), int(body["threshold"]))
        return claimed

    def current_root_key(self, did: str) -> str:
        """The root key the event log says ``did`` holds now.

        Replays the whole log (signatures and recoveries), so a names file
        swapped for a self-signed manifest under another key is caught here
        rather than only by ``verify()``. Fails closed if the log does not
        replay cleanly.
        """
        claimed = self._replay(self._file_keys())
        if did not in claimed:
            raise RegistryError(f"no claim event for {did}")
        return claimed[did]

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
        claimed = self._replay({did: m.root_public_key for did, m in manifests.items()})
        for did, m in manifests.items():
            if did not in claimed:
                raise RegistryError(f"manifest {did} present without a claim event")
            if m.root_public_key != claimed[did]:
                raise RegistryError(f"root key continuity violated for {did}")
        return count


def export_bundle(
    registry: Registry, handle: str, private_key: str | None
) -> dict[str, Any]:
    """Portable identity bundle: manifest + the handle's event history + key.

    ``private_key`` is raw hex, an encrypted PEM, or None to leave it out.
    """
    manifest = registry.resolve(handle)
    did = manifest.did
    bundle = {
        "did": did,
        "manifest": manifest.to_dict(),
        "events": [r for r in registry.log.records() if r["agent_id"] == did],
        "exported_at": time.time(),
    }
    if private_key is not None:
        bundle["private_key"] = private_key
    return bundle
