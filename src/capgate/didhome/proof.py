"""Offline-verifiable proofs and printable cards.

A proof is a statement ("I am @adam", "over 18 member") signed by a
handle's root key. Anyone can verify it against the public key alone —
offline, no phone-home, no log. ``web/verify.html`` checks the same JSON
in a browser; ``card_html`` renders a printable card (QR if the optional
``segno`` package is installed).
"""

from __future__ import annotations

import html
import json
import secrets
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capgate.didhome.manifest import (
    Manifest,
    _canonical_json,
    public_key_from_hex,
    public_key_hex,
)


class ProofError(ValueError):
    """Raised when a proof fails verification."""


def _proof_payload(proof: dict[str, Any]) -> bytes:
    return _canonical_json({k: v for k, v in proof.items() if k != "signature"})


def create_proof(
    manifest: Manifest,
    root_key: Ed25519PrivateKey,
    statement: str,
    now: float | None = None,
) -> dict[str, Any]:
    """Sign a statement with the handle's root key. Verifies offline."""
    if public_key_hex(root_key.public_key()) != manifest.root_public_key:
        raise ProofError("proof must be signed by the handle's root key")
    proof = {
        "did": manifest.did,
        "handle": manifest.handle,
        "statement": statement,
        "public_key": manifest.root_public_key,
        "issued_at": int(time.time() if now is None else now),
        "nonce": secrets.token_hex(8),
        "signature": "",
    }
    proof["signature"] = root_key.sign(_proof_payload(proof)).hex()
    return proof


def verify_proof(proof: dict[str, Any], expected_public_key: str | None = None) -> None:
    """Verify a proof's signature (and, optionally, who signed it)."""
    try:
        key_hex = proof["public_key"]
        signature = bytes.fromhex(proof["signature"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProofError(f"malformed proof: {exc}") from exc
    if expected_public_key is not None and key_hex != expected_public_key:
        raise ProofError("proof signed by an unexpected key")
    try:
        public_key_from_hex(key_hex).verify(signature, _proof_payload(proof))
    except (InvalidSignature, ValueError) as exc:
        raise ProofError("proof signature invalid") from exc


def _qr_data_uri(text: str) -> str | None:
    """PNG data URI QR for the proof, if the optional ``segno`` package exists."""
    try:
        import base64
        import io

        import segno
    except ImportError:
        return None
    buf = io.BytesIO()
    segno.make(text, error="m").save(buf, kind="png", scale=4)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


def card_html(proof: dict[str, Any]) -> str:
    """A single printable HTML card carrying the proof.

    Scan the QR (or paste the JSON) into ``web/verify.html`` — the check
    runs entirely in the browser, offline.
    """
    proof_json = json.dumps(proof, sort_keys=True, separators=(",", ":"))
    qr = _qr_data_uri(proof_json)
    qr_block = (
        f'<img class="qr" alt="proof QR" src="{qr}">'
        if qr
        else '<p class="noqr">(install <code>vouch[qr]</code> for a QR code)</p>'
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Vouch card — @{html.escape(proof["handle"])}</title>
<style>
body{{font-family:system-ui,sans-serif;display:flex;justify-content:center;padding:2rem}}
.card{{border:2px solid #222;border-radius:12px;padding:1.5rem;max-width:26rem;text-align:center}}
h1{{margin:.2rem 0;font-size:1.6rem}} .stmt{{font-size:1.1rem;margin:.6rem 0}}
.qr{{margin:.8rem 0}} textarea{{width:100%;height:7rem;font-size:.65rem}}
.hint{{color:#555;font-size:.8rem}}
@media print{{textarea{{display:none}}}}
</style></head><body>
<div class="card">
<h1>@{html.escape(proof["handle"])}</h1>
<p class="stmt">{html.escape(proof["statement"])}</p>
{qr_block}
<textarea readonly>{html.escape(proof_json)}</textarea>
<p class="hint">Verify offline with web/verify.html — nobody is called,
nothing is logged.</p>
</div></body></html>
"""
