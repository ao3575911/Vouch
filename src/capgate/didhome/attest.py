"""Attestations ("vouches"): signed claims one handle makes about another.

A voucher who has checked something about you (a pharmacist who saw your
passport, a notary, someone who has known you for years) signs a claim such
as ``over18`` or ``name = Adam Smith`` about your handle. Each attestation
holds one claim, so you can show one without the others.

An attestation is bound to the subject's DID and key. To use it, the holder
builds a presentation: the chosen attestations plus a fresh signature by the
holder's key over the verifier's audience and nonce. Someone who copies the
attestations can't present them, and a presentation can't be replayed to a
verifier who asks for a fresh nonce.

Verifiers check every signature against the registry, expiry, revocation
(vouchers revoke through the event log) and their own policy: which vouchers
they trust and how many they need.

Age is attested as thresholds (over13, over16, over18, over21). A birthdate
can be given to ``derive_age_claims`` to work those out, but it is never put
in an attestation or written anywhere.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capgate.didhome.manifest import (
    Manifest,
    _canonical_json,
    public_key_from_hex,
    public_key_hex,
    validate_handle,
)
from capgate.didhome.registry import Registry, RegistryError

ATTESTATION_TYPE = "vouch-attestation"
PRESENTATION_TYPE = "vouch-presentation"
AGE_THRESHOLDS = (13, 16, 18, 21)
CLAIM_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,31}$")
OVER_RE = re.compile(r"^over([1-9][0-9]?)$")
MAX_VALUE_LEN = 200
MAX_METHOD_LEN = 64
MAX_ATTESTATIONS = 50
MAX_AGE_SECONDS = 300
FUTURE_SKEW_SECONDS = 30


class AttestationError(ValueError):
    """Raised when an attestation or presentation is malformed or invalid."""


def _payload(obj: dict[str, Any]) -> bytes:
    return _canonical_json({k: v for k, v in obj.items() if k != "signature"})


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def over_claim(age: int) -> str:
    if not 1 <= age <= 99:
        raise AttestationError("age threshold must be between 1 and 99")
    return f"over{age}"


def derive_age_claims(birthdate: date, today: date | None = None) -> list[str]:
    """Threshold claims a birthdate supports today. The birthdate is not kept."""
    today = today or datetime.now().astimezone().date()
    age = (
        today.year - birthdate.year - ((today.month, today.day) < (birthdate.month, birthdate.day))
    )
    return [over_claim(n) for n in AGE_THRESHOLDS if age >= n]


def _check_claim(claim: str, value: Any) -> None:
    if not isinstance(claim, str) or not CLAIM_RE.match(claim):
        raise AttestationError(f"bad claim name {claim!r}: want [a-z][a-z0-9_.-], max 32")
    if OVER_RE.match(claim):
        if value is not True:
            raise AttestationError(f"{claim} must have the value true")
    elif not isinstance(value, str) or not value or len(value) > MAX_VALUE_LEN:
        raise AttestationError(f"claim {claim!r} needs a text value of 1-{MAX_VALUE_LEN} chars")


def create_attestation(
    voucher: Manifest,
    voucher_key: Ed25519PrivateKey,
    subject: Manifest,
    claim: str,
    value: Any,
    method: str,
    expires_at: int | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Sign one claim about ``subject``, bound to the subject's current key."""
    if public_key_hex(voucher_key.public_key()) != voucher.root_public_key:
        raise AttestationError("voucher key does not match the voucher's manifest")
    if voucher.did == subject.did:
        raise AttestationError("you can't vouch for yourself")
    _check_claim(claim, value)
    if not isinstance(method, str) or not method.strip() or len(method) > MAX_METHOD_LEN:
        raise AttestationError(f"say how you checked (1-{MAX_METHOD_LEN} chars)")
    issued = int(time.time() if now is None else now)
    if expires_at is not None and (not _is_int(expires_at) or expires_at <= issued):
        raise AttestationError("expiry must be a whole-second time in the future")
    att: dict[str, Any] = {
        "type": ATTESTATION_TYPE,
        "v": 1,
        "id": secrets.token_hex(16),
        "voucher": voucher.did,
        "subject": subject.did,
        "subject_public_key": subject.root_public_key,
        "claim": claim,
        "value": value,
        "method": method.strip(),
        "issued_at": issued,
        "expires_at": expires_at,
    }
    att["signature"] = voucher_key.sign(_payload(att)).hex()
    return att


def satisfies(claim: str, wanted: str) -> bool:
    """over21 satisfies a request for over18; other claims match by name."""
    have, want = OVER_RE.match(claim), OVER_RE.match(wanted)
    if have and want:
        return int(have.group(1)) >= int(want.group(1))
    return claim == wanted


def _handle(did: Any) -> str:
    if not isinstance(did, str) or not did.startswith("did:home:"):
        raise AttestationError(f"not a did:home DID: {did!r}")
    return validate_handle(did.removeprefix("did:home:"))


def verify_attestation(
    registry: Registry,
    att: dict[str, Any],
    subject_keys: set[str] | None = None,
    now: float | None = None,
) -> None:
    """Check one attestation against the registry. Raises AttestationError.

    Checks the voucher's current key signed it, it's for the subject's key
    (current, or one rotated away by a recovery), it hasn't expired and the
    voucher hasn't revoked it.
    """
    if not isinstance(att, dict) or att.get("type") != ATTESTATION_TYPE or att.get("v") != 1:
        raise AttestationError("not a version-1 vouch attestation")
    for key in ("id", "subject_public_key", "method", "signature"):
        if not isinstance(att.get(key), str):
            raise AttestationError(f"attestation field {key!r} missing")
    if not _is_int(att.get("issued_at")):
        raise AttestationError("issued_at must be a whole number")
    expires_at = att.get("expires_at")
    if expires_at is not None and not _is_int(expires_at):
        raise AttestationError("expires_at must be a whole number or null")
    _check_claim(att.get("claim"), att.get("value"))
    voucher, subject = _handle(att.get("voucher")), _handle(att.get("subject"))
    if voucher == subject:
        raise AttestationError("self-vouch")
    try:
        manifest = registry.resolve(voucher)
        if subject_keys is None:
            subject_keys = registry.root_key_history(f"did:home:{subject}")
    except RegistryError as exc:
        raise AttestationError(str(exc)) from exc
    try:
        public_key_from_hex(manifest.root_public_key).verify(
            bytes.fromhex(att["signature"]), _payload(att)
        )
    except (InvalidSignature, ValueError) as exc:
        raise AttestationError("signature is not by the voucher's current key") from exc
    if att["subject_public_key"] not in subject_keys:
        raise AttestationError("made for a different key")
    current = time.time() if now is None else now
    if att["issued_at"] > current + FUTURE_SKEW_SECONDS:
        raise AttestationError("issued in the future")
    if expires_at is not None and current >= expires_at:
        raise AttestationError("expired")
    if att["id"] in registry.revoked_attestation_ids(voucher):
        raise AttestationError("revoked by the voucher")


def create_presentation(
    holder: Manifest,
    holder_key: Ed25519PrivateKey,
    attestations: list[dict[str, Any]],
    show: list[str],
    audience: str = "",
    nonce: str = "",
    now: float | None = None,
) -> dict[str, Any]:
    """Pick the attestations that back ``show`` and sign them for one verifier."""
    if public_key_hex(holder_key.public_key()) != holder.root_public_key:
        raise AttestationError("key does not match the holder's manifest")
    if not show:
        raise AttestationError("say what to show, e.g. over18 or name")
    chosen: dict[str, dict[str, Any]] = {}
    for wanted in show:
        _check_claim(wanted, True if OVER_RE.match(wanted) else "x")
        matches = [
            a
            for a in attestations
            if a.get("subject") == holder.did and satisfies(str(a.get("claim")), wanted)
        ]
        if not matches:
            raise AttestationError(f"no vouch for {wanted!r}")
        if OVER_RE.match(wanted):
            # Per voucher, show the lowest age that answers the question.
            lowest: dict[str, dict[str, Any]] = {}
            for a in sorted(matches, key=lambda a: int(OVER_RE.match(a["claim"]).group(1))):
                lowest.setdefault(a.get("voucher"), a)
            matches = list(lowest.values())
        for a in matches:
            chosen[a["id"]] = a
    if len(chosen) > MAX_ATTESTATIONS:
        raise AttestationError(f"more than {MAX_ATTESTATIONS} attestations")
    pres: dict[str, Any] = {
        "type": PRESENTATION_TYPE,
        "v": 1,
        "holder": holder.did,
        "show": list(dict.fromkeys(show)),
        "attestations": list(chosen.values()),
        "audience": audience,
        "nonce": nonce,
        "issued_at": int(time.time() if now is None else now),
    }
    pres["signature"] = holder_key.sign(_payload(pres)).hex()
    return pres


@dataclass
class ClaimResult:
    wanted: str
    ok: bool = False
    value: Any = None
    vouchers: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class PresentationResult:
    holder: str
    bound: bool  # the verifier's nonce was checked
    issued_at: int
    claims: list[ClaimResult]
    rejected: list[tuple[str, str]]  # (who/what, reason)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.claims)


def verify_presentation(
    registry: Registry,
    pres: dict[str, Any],
    audience: str | None = None,
    nonce: str | None = None,
    trust: set[str] | None = None,
    min_vouchers: int = 1,
    max_age: int = MAX_AGE_SECONDS,
    now: float | None = None,
) -> PresentationResult:
    """Verify a presentation and apply the verifier's policy.

    Raises AttestationError if the presentation itself is bad (holder
    signature, audience, nonce, age). Individual attestations that fail are
    listed in ``rejected``; each shown claim passes when at least
    ``min_vouchers`` distinct vouchers (from ``trust``, if given) agree on it.
    """
    if not isinstance(pres, dict) or pres.get("type") != PRESENTATION_TYPE or pres.get("v") != 1:
        raise AttestationError("not a version-1 vouch presentation")
    if min_vouchers < 1:
        raise AttestationError("min_vouchers must be at least 1")
    holder = _handle(pres.get("holder"))
    show, atts = pres.get("show"), pres.get("attestations")
    if not isinstance(show, list) or not show or not all(isinstance(s, str) for s in show):
        raise AttestationError("presentation has no claims to show")
    if not isinstance(atts, list) or len(atts) > MAX_ATTESTATIONS:
        raise AttestationError("bad attestation list")
    if not isinstance(pres.get("signature"), str) or not _is_int(pres.get("issued_at")):
        raise AttestationError("presentation is not signed")
    try:
        manifest = registry.resolve(holder)
        subject_keys = registry.root_key_history(manifest.did)
    except RegistryError as exc:
        raise AttestationError(str(exc)) from exc
    try:
        public_key_from_hex(manifest.root_public_key).verify(
            bytes.fromhex(pres["signature"]), _payload(pres)
        )
    except (InvalidSignature, ValueError) as exc:
        raise AttestationError("holder signature invalid") from exc
    current = time.time() if now is None else now
    age = current - pres["issued_at"]
    if age > max_age or age < -FUTURE_SKEW_SECONDS:
        raise AttestationError(f"presentation is {int(age)}s old (max {max_age}s)")
    if audience is not None and pres.get("audience") != audience:
        raise AttestationError(f"made for {pres.get('audience')!r}, not {audience!r}")
    if nonce is not None and pres.get("nonce") != nonce:
        raise AttestationError("nonce does not match: possible replay")

    rejected: list[tuple[str, str]] = []
    good: list[dict[str, Any]] = []
    for att in atts:
        label = f"{str(att.get('id', '?'))[:8]} from {str(att.get('voucher', '?')).replace('did:home:', '@')}"
        try:
            if att.get("subject") != manifest.did:
                raise AttestationError("about someone else")
            verify_attestation(registry, att, subject_keys, current)
        except AttestationError as exc:
            rejected.append((label, str(exc)))
            continue
        voucher = _handle(att["voucher"])
        if trust is not None and voucher not in trust:
            rejected.append((label, "voucher not on your trusted list"))
            continue
        good.append(att)

    claims = []
    for wanted in dict.fromkeys(show):
        result = ClaimResult(wanted)
        groups: dict[str, dict[str, dict[str, Any]]] = {}
        for att in good:
            if satisfies(att["claim"], wanted):
                value = True if OVER_RE.match(wanted) else att["value"]
                groups.setdefault(repr(value), {}).setdefault(att["voucher"], att)
        if groups:
            best = max(groups.values(), key=len)
            sample = next(iter(best.values()))
            result.value = True if OVER_RE.match(wanted) else sample["value"]
            result.vouchers = [
                {
                    "voucher": "@" + _handle(a["voucher"]),
                    "method": a["method"],
                    "issued_at": a["issued_at"],
                    "expires_at": a["expires_at"],
                    "id": a["id"],
                }
                for a in best.values()
            ]
            result.ok = len(best) >= min_vouchers
        claims.append(result)
    return PresentationResult(
        holder="@" + holder,
        bound=nonce is not None,
        issued_at=pres["issued_at"],
        claims=claims,
        rejected=rejected,
    )
