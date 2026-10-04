"""Signed agent-to-agent ping: @adam ⇄ @sam with receipts-grade verifiability.

A ping is signed by the *sub-identity* key named in an attached capability
token. The recipient verifies everything against the static registry only:
token chain, body hash, timestamp freshness, and nonce replay. Delivery
transport is out of scope (webhook URL lives in the manifest's services).
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capgate.didhome.delegation import (
    CapabilityToken,
    DelegationError,
    verify_capability_token,
)
from capgate.didhome.manifest import _canonical_json, public_key_from_hex
from capgate.didhome.registry import Registry

PING_PERMISSION = "ping:send"
MAX_SKEW_SECONDS = 300


class PingError(ValueError):
    """Raised when a ping fails verification."""


@dataclass(frozen=True)
class Ping:
    """A signed agent-to-agent message."""

    sender: str  # did:home:<handle>
    recipient: str  # did:home:<handle>
    body: dict[str, Any]
    body_hash: str
    timestamp: float
    nonce: str
    token: dict[str, Any]
    signature: str  # hex, by token subject key

    def payload(self) -> bytes:
        return _canonical_json(
            {
                "sender": self.sender,
                "recipient": self.recipient,
                "body_hash": self.body_hash,
                "timestamp": self.timestamp,
                "nonce": self.nonce,
                "token_id": self.token["token_id"],
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "body": self.body,
            "body_hash": self.body_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "token": self.token,
            "signature": self.signature,
        }


def _body_hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(body)).hexdigest()


def create_ping(
    sender_did: str,
    recipient_did: str,
    body: dict[str, Any],
    token: CapabilityToken,
    subject_key: Ed25519PrivateKey,
    now: float | None = None,
) -> Ping:
    """Build and sign a ping with the delegated sub-identity key."""
    ts = time.time() if now is None else now
    unsigned = Ping(
        sender=sender_did,
        recipient=recipient_did,
        body=body,
        body_hash=_body_hash(body),
        timestamp=ts,
        nonce=secrets.token_hex(16),
        token=token.to_dict(),
        signature="",
    )
    return Ping(
        sender=unsigned.sender,
        recipient=unsigned.recipient,
        body=unsigned.body,
        body_hash=unsigned.body_hash,
        timestamp=unsigned.timestamp,
        nonce=unsigned.nonce,
        token=unsigned.token,
        signature=subject_key.sign(unsigned.payload()).hex(),
    )


def verify_ping(
    registry: Registry,
    ping: Ping,
    seen_nonces: set[str],
    now: float | None = None,
) -> None:
    """Verify a ping; mutates seen_nonces on success. Raises PingError."""
    token = CapabilityToken.from_dict(ping.token)
    if token.issuer != ping.sender:
        raise PingError("token issuer does not match ping sender")
    try:
        verify_capability_token(registry, token, PING_PERMISSION, now=now)
    except DelegationError as exc:
        raise PingError(f"capability check failed: {exc}") from exc
    if ping.body_hash != _body_hash(ping.body):
        raise PingError("body hash mismatch")
    current = time.time() if now is None else now
    if abs(current - ping.timestamp) > MAX_SKEW_SECONDS:
        raise PingError("timestamp outside freshness window")
    if ping.nonce in seen_nonces:
        raise PingError("nonce replayed")
    key = public_key_from_hex(token.subject_public_key)
    try:
        key.verify(bytes.fromhex(ping.signature), ping.payload())
    except (InvalidSignature, ValueError) as exc:
        raise PingError("ping signature invalid") from exc
    seen_nonces.add(ping.nonce)
