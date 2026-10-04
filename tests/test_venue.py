"""Venue entry: policy loading (fail-closed) and door checks with tier weights."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capgate.didhome.attest import AttestationError, create_attestation, create_presentation
from capgate.didhome.manifest import create_manifest
from capgate.didhome.registry import Registry
from capgate.didhome.venue import (
    VenuePolicy,
    VenuePolicyError,
    check_entry,
    entry_pass_html,
)

NOW = 1_800_000_000
VENUE = "bottleshop.perth.example"

POLICY_DOC = {
    "type": "vouch-venue-policy",
    "v": 1,
    "venue": VENUE,
    "require": ["over18"],
    "tiers": {"police": 3, "licensed": 2, "peer": 1},
    "vouchers": {"police": "police", "pharmacy": "licensed", "sam": "peer"},
    "min_weight": 2,
    "max_age": 120,
}


@pytest.fixture
def world(tmp_path):
    registry = Registry(tmp_path / "registry")
    keys = {}
    for name in ("adam", "police", "pharmacy", "sam", "eve"):
        keys[name] = Ed25519PrivateKey.generate()
        registry.claim(create_manifest(name, keys[name]), keys[name])
    return registry, keys


def _vouch(world, voucher, claim="over18", value=True):
    registry, keys = world
    return create_attestation(
        registry.resolve(voucher),
        keys[voucher],
        registry.resolve("adam"),
        claim,
        value,
        "saw-passport",
        now=NOW,
    )


def _pass(world, atts, show=("over18",), venue=VENUE, nonce="77", now=NOW):
    registry, keys = world
    return create_presentation(
        registry.resolve("adam"), keys["adam"], atts, list(show), venue, nonce, now=now
    )


def _policy(**over):
    return VenuePolicy.from_dict({**POLICY_DOC, **over})


def test_policy_fail_closed():
    with pytest.raises(VenuePolicyError):
        VenuePolicy.from_dict({"type": "other"})
    with pytest.raises(VenuePolicyError, match="unknown tier"):
        _policy(vouchers={"police": "mystery"})
    with pytest.raises(VenuePolicyError, match="weight"):
        _policy(tiers={"police": 0})
    with pytest.raises(VenuePolicyError, match="weight"):
        _policy(tiers={"police": True})
    with pytest.raises(VenuePolicyError, match="min_weight"):
        _policy(min_weight=0)
    with pytest.raises(VenuePolicyError, match="require"):
        _policy(require=[])
    with pytest.raises(VenuePolicyError, match="max_age"):
        _policy(max_age=0)


def test_policy_load(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(__import__("json").dumps(POLICY_DOC), encoding="utf-8")
    policy = VenuePolicy.load(path)
    assert policy.venue == VENUE
    assert policy.weight("police") == 3
    assert policy.weight("unknown") == 0  # unlisted vouchers count nothing


def test_entry_ok_by_weight(world):
    registry, _ = world
    pres = _pass(world, [_vouch(world, "police")])
    result = check_entry(registry, _policy(), pres, "77", now=NOW + 5)
    assert result.ok
    assert result.claims[0].weight == 3
    assert result.claims[0].vouchers[0]["tier"] == "police"


def test_entry_denied_underweight(world):
    registry, _ = world
    pres = _pass(world, [_vouch(world, "sam")])  # peer weight 1 < min 2
    result = check_entry(registry, _policy(), pres, "77", now=NOW + 5)
    assert not result.ok
    assert result.claims[0].weight == 1


def test_entry_peers_add_up(world):
    registry, _ = world
    pres = _pass(world, [_vouch(world, "sam"), _vouch(world, "pharmacy")])
    result = check_entry(registry, _policy(), pres, "77", now=NOW + 5)
    assert result.ok
    assert result.claims[0].weight == 3


def test_entry_untrusted_voucher_counts_zero(world):
    registry, _ = world
    pres = _pass(world, [_vouch(world, "eve")])  # eve not in policy
    result = check_entry(registry, _policy(), pres, "77", now=NOW + 5)
    assert not result.ok
    assert result.rejected  # filtered by trust


def test_entry_missing_required_claim(world):
    registry, _ = world
    pres = _pass(world, [_vouch(world, "police", "name", "Adam Smith")], show=["name"])
    result = check_entry(registry, _policy(), pres, "77", now=NOW + 5)
    assert not result.ok
    assert result.claims[0].wanted == "over18"
    assert result.claims[0].weight == 0


def test_entry_bound_to_venue_nonce_and_fresh(world):
    registry, _ = world
    pres = _pass(world, [_vouch(world, "police")])
    with pytest.raises(AttestationError):
        check_entry(registry, _policy(), pres, "other-nonce", now=NOW + 5)
    with pytest.raises(AttestationError):
        check_entry(registry, _policy(venue="bar.example"), pres, "77", now=NOW + 5)
    with pytest.raises(AttestationError):  # stale: past policy max_age
        check_entry(registry, _policy(), pres, "77", now=NOW + 121)
    with pytest.raises(AttestationError):  # door must supply a nonce
        check_entry(registry, _policy(), pres, "", now=NOW + 5)


def test_entry_pass_html(world):
    pres = _pass(world, [_vouch(world, "police")])
    page = entry_pass_html(pres, VENUE)
    assert "@adam" in page and VENUE in page and "over18" in page
