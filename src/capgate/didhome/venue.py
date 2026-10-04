"""Venue entry: a door policy with voucher trust tiers, checked offline.

A venue (a bar, a bottle shop, a licensed premises) writes one JSON policy
file saying what it needs at the door ("over18"), which vouchers it trusts
and how much weight each class of voucher carries (a police officer or a
pharmacy more than a neighbour). The patron mints an entry pass: a fresh
presentation bound to the venue's id and the door's nonce, rendered as a QR.
The door checks it against its own copy of the registry — offline, no
phone-home, no log — and adds up the weight behind each required claim.

Weighting is the verifier's call, not a central score: tiers live in the
venue's policy file, nowhere else. Fail-closed throughout: a voucher the
policy does not list counts for nothing, a tier the policy does not define
is an error, and a missing or underweight claim denies entry.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from capgate.didhome.attest import (
    AttestationError,
    verify_presentation,
)
from capgate.didhome.manifest import validate_handle
from capgate.didhome.registry import Registry

POLICY_TYPE = "vouch-venue-policy"
MAX_PASS_AGE_SECONDS = 120  # entry passes are short-lived by default
MAX_TIER_WEIGHT = 100
MAX_VOUCHERS = 1000


class VenuePolicyError(ValueError):
    """Raised when a venue policy file is malformed. Fail closed: no entry."""


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True)
class VenuePolicy:
    """A venue's door policy: required claims, trusted vouchers, tier weights."""

    venue: str  # audience string presentations must be bound to
    require: tuple[str, ...]  # claims needed at the door, e.g. ("over18",)
    tiers: dict[str, int]  # tier name -> weight, e.g. {"police": 3, "peer": 1}
    vouchers: dict[str, str]  # handle -> tier name; unlisted vouchers count 0
    min_weight: int = 1  # total weight each required claim must reach
    max_age: int = MAX_PASS_AGE_SECONDS  # how old a pass may be, in seconds

    def weight(self, voucher_handle: str) -> int:
        """Weight this venue gives one voucher. Unlisted means zero."""
        tier = self.vouchers.get(voucher_handle)
        return self.tiers[tier] if tier is not None else 0

    @classmethod
    def from_dict(cls, doc: Any) -> VenuePolicy:
        if not isinstance(doc, dict) or doc.get("type") != POLICY_TYPE or doc.get("v") != 1:
            raise VenuePolicyError("not a version-1 vouch venue policy")
        venue = doc.get("venue")
        if not isinstance(venue, str) or not venue.strip():
            raise VenuePolicyError("policy needs a venue id, e.g. bottleshop.perth.example")
        require = doc.get("require")
        if (
            not isinstance(require, list)
            or not require
            or not all(isinstance(c, str) and c for c in require)
        ):
            raise VenuePolicyError("policy needs a non-empty 'require' list, e.g. [\"over18\"]")
        tiers = doc.get("tiers")
        if not isinstance(tiers, dict) or not tiers:
            raise VenuePolicyError("policy needs 'tiers', e.g. {\"police\": 3, \"peer\": 1}")
        for name, weight in tiers.items():
            if not isinstance(name, str) or not name:
                raise VenuePolicyError("tier names must be non-empty strings")
            if not _is_int(weight) or not 1 <= weight <= MAX_TIER_WEIGHT:
                raise VenuePolicyError(
                    f"tier {name!r} weight must be a whole number 1-{MAX_TIER_WEIGHT}"
                )
        vouchers_doc = doc.get("vouchers")
        if not isinstance(vouchers_doc, dict) or not vouchers_doc:
            raise VenuePolicyError("policy needs 'vouchers': handle -> tier")
        if len(vouchers_doc) > MAX_VOUCHERS:
            raise VenuePolicyError(f"more than {MAX_VOUCHERS} vouchers")
        vouchers: dict[str, str] = {}
        for handle, tier in vouchers_doc.items():
            if tier not in tiers:  # fail closed on unknown tiers
                raise VenuePolicyError(f"voucher {handle!r} has unknown tier {tier!r}")
            vouchers[validate_handle(handle)] = tier
        min_weight = doc.get("min_weight", 1)
        if not _is_int(min_weight) or min_weight < 1:
            raise VenuePolicyError("min_weight must be a whole number of at least 1")
        max_age = doc.get("max_age", MAX_PASS_AGE_SECONDS)
        if not _is_int(max_age) or not 1 <= max_age <= 3600:
            raise VenuePolicyError("max_age must be 1-3600 seconds")
        return cls(venue.strip(), tuple(require), dict(tiers), vouchers, min_weight, max_age)

    @classmethod
    def load(cls, path: str | Path) -> VenuePolicy:
        try:
            doc = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise VenuePolicyError(f"cannot read policy {path}: {exc}") from exc
        return cls.from_dict(doc)


@dataclass
class EntryClaim:
    wanted: str
    weight: int = 0
    ok: bool = False
    vouchers: list[dict[str, Any]] = field(default_factory=list)  # voucher, tier, weight, method


@dataclass
class EntryResult:
    holder: str
    venue: str
    min_weight: int
    claims: list[EntryClaim]
    rejected: list[tuple[str, str]]

    @property
    def ok(self) -> bool:
        return bool(self.claims) and all(c.ok for c in self.claims)


def check_entry(
    registry: Registry,
    policy: VenuePolicy,
    pres: dict[str, Any],
    nonce: str,
    now: float | None = None,
) -> EntryResult:
    """Check an entry pass against a venue policy. Raises AttestationError.

    The pass must be bound to the venue's id and the door's nonce, be fresh,
    and carry enough trusted weight behind every required claim. Vouchers the
    policy does not list, and claims below ``min_weight``, deny entry.
    """
    if not nonce:
        raise AttestationError("the door must supply a fresh nonce")
    result = verify_presentation(
        registry,
        pres,
        audience=policy.venue,
        nonce=nonce,
        trust=set(policy.vouchers),
        min_vouchers=1,
        max_age=policy.max_age,
        now=now,
    )
    shown = {c.wanted: c for c in result.claims}
    claims: list[EntryClaim] = []
    for wanted in dict.fromkeys(policy.require):
        entry = EntryClaim(wanted)
        got = shown.get(wanted)
        if got is not None and got.ok:
            for v in got.vouchers:
                handle = v["voucher"].removeprefix("@")
                weight = policy.weight(handle)
                if weight < 1:  # fail closed: unlisted voucher counts 0
                    continue
                entry.weight += weight
                entry.vouchers.append(
                    {
                        "voucher": v["voucher"],
                        "tier": policy.vouchers[handle],
                        "weight": weight,
                        "method": v["method"],
                    }
                )
            entry.ok = entry.weight >= policy.min_weight
        claims.append(entry)
    return EntryResult(
        holder=result.holder,
        venue=policy.venue,
        min_weight=policy.min_weight,
        claims=claims,
        rejected=result.rejected,
    )


def entry_pass_html(pres: dict[str, Any], venue: str) -> str:
    """A one-screen entry pass carrying the presentation, QR if possible.

    The QR holds the presentation JSON. The door scans it and checks it
    against its own registry copy and policy — nobody is called.
    """
    from capgate.didhome.proof import _qr_data_uri

    pres_json = json.dumps(pres, sort_keys=True, separators=(",", ":"))
    qr = _qr_data_uri(pres_json)
    qr_block = (
        f'<img class="qr" alt="entry pass QR" src="{qr}">'
        if qr
        else '<p class="noqr">(install <code>vouch-id[qr]</code> for a QR code)</p>'
    )
    holder = html.escape(str(pres.get("holder", "")).removeprefix("did:home:"))
    show = html.escape(", ".join(str(s) for s in pres.get("show", [])))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Vouch entry pass — @{holder}</title>
<style>
body{{font-family:system-ui,sans-serif;display:flex;justify-content:center;padding:2rem}}
.card{{border:2px solid #222;border-radius:12px;padding:1.5rem;max-width:26rem;text-align:center}}
h1{{margin:.2rem 0;font-size:1.6rem}} .stmt{{font-size:1.1rem;margin:.6rem 0}}
.qr{{margin:.8rem 0}} textarea{{width:100%;height:7rem;font-size:.65rem}}
.hint{{color:#555;font-size:.8rem}}
@media print{{textarea{{display:none}}}}
</style></head><body>
<div class="card">
<h1>@{holder}</h1>
<p class="stmt">entry pass for {html.escape(venue)}: {show}</p>
{qr_block}
<textarea readonly>{html.escape(pres_json)}</textarea>
<p class="hint">Short-lived and bound to this venue and the door's nonce —
a copy is useless anywhere else. Checked offline; nobody is called,
nothing is logged.</p>
</div></body></html>
"""
