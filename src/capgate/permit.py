"""Signed, short-lived, single-use permits.

A permit binds: agent identity, the exact tool call (canonical hash),
the contract name+version the decision came from, an expiry, and a nonce.
It is signed with an Ed25519 key held by the harness — never by the agent.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DEFAULT_TTL_SECONDS = 30


class PermitError(ValueError):
    """Raised when a permit fails structural or cryptographic validation."""


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_call_hash(tool: str, arguments: dict[str, Any]) -> str:
    """Deterministic hash of a tool call. Any argument change changes the hash."""
    return hashlib.sha256(_canonical_json({"tool": tool, "arguments": arguments})).hexdigest()


@dataclass(frozen=True)
class Permit:
    """A single-use authorization for one exact tool call."""

    permit_id: str
    agent_id: str
    call_hash: str
    contract_name: str
    contract_version: str
    issued_at: float
    expires_at: float
    signature: str  # hex-encoded Ed25519 signature over the payload

    def payload(self) -> bytes:
        return _canonical_json(
            {
                "permit_id": self.permit_id,
                "agent_id": self.agent_id,
                "call_hash": self.call_hash,
                "contract_name": self.contract_name,
                "contract_version": self.contract_version,
                "issued_at": self.issued_at,
                "expires_at": self.expires_at,
            }
        )


def issue_permit(
    signing_key: Ed25519PrivateKey,
    agent_id: str,
    tool: str,
    arguments: dict[str, Any],
    contract_name: str,
    contract_version: str,
    ttl_seconds: float = DEFAULT_TTL_SECONDS,
    now: float | None = None,
) -> Permit:
    """Sign a permit for one exact call. Only the harness holds the key."""
    issued_at = time.time() if now is None else now
    unsigned = Permit(
        permit_id=secrets.token_hex(16),
        agent_id=agent_id,
        call_hash=canonical_call_hash(tool, arguments),
        contract_name=contract_name,
        contract_version=contract_version,
        issued_at=issued_at,
        expires_at=issued_at + ttl_seconds,
        signature="",
    )
    signature = signing_key.sign(unsigned.payload()).hex()
    return Permit(
        permit_id=unsigned.permit_id,
        agent_id=unsigned.agent_id,
        call_hash=unsigned.call_hash,
        contract_name=unsigned.contract_name,
        contract_version=unsigned.contract_version,
        issued_at=unsigned.issued_at,
        expires_at=unsigned.expires_at,
        signature=signature,
    )


def verify_permit(
    verify_key: Ed25519PublicKey,
    permit: Permit,
    now: float | None = None,
) -> None:
    """Verify signature and expiry. Raises PermitError on any failure."""
    try:
        verify_key.verify(bytes.fromhex(permit.signature), permit.payload())
    except (InvalidSignature, ValueError) as exc:
        raise PermitError("permit signature invalid") from exc
    current = time.time() if now is None else now
    if current > permit.expires_at:
        raise PermitError("permit expired")
