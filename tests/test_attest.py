"""Attestations (vouches) and presentations."""

import json
from datetime import date

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capgate.didhome.attest import (
    AttestationError,
    create_attestation,
    create_presentation,
    derive_age_claims,
    satisfies,
    verify_attestation,
    verify_presentation,
)
from capgate.didhome.manifest import create_manifest, public_key_hex
from capgate.didhome.recovery import approve_recovery
from capgate.didhome.registry import Registry

NOW = 1_800_000_000


@pytest.fixture
def world(tmp_path):
    registry = Registry(tmp_path / "registry")
    keys = {}
    for name in ("adam", "pharmacy", "notary", "eve", "kim", "sam"):
        keys[name] = Ed25519PrivateKey.generate()
        registry.claim(create_manifest(name, keys[name]), keys[name])
    return registry, keys


def _vouch(world, voucher, claim="over18", value=True, subject="adam", **kw):
    registry, keys = world
    return create_attestation(
        registry.resolve(voucher),
        keys[voucher],
        registry.resolve(subject),
        claim,
        value,
        kw.pop("method", "saw-passport"),
        now=kw.pop("now", NOW),
        **kw,
    )


def _present(world, atts, show=("over18",), holder="adam", **kw):
    registry, keys = world
    kw.setdefault("now", NOW)
    return create_presentation(registry.resolve(holder), keys[holder], atts, list(show), **kw)


def test_over18_with_two_vouchers_and_policy(world):
    registry, _ = world
    atts = [_vouch(world, "pharmacy"), _vouch(world, "notary", "over21")]
    pres = _present(world, atts, audience="shop.example", nonce="4821")
    r = verify_presentation(registry, pres, "shop.example", "4821", min_vouchers=2, now=NOW + 5)
    assert r.ok and r.bound
    assert {v["voucher"] for v in r.claims[0].vouchers} == {"@pharmacy", "@notary"}
    assert r.claims[0].vouchers[0]["method"] == "saw-passport"
    r = verify_presentation(registry, pres, trust={"pharmacy"}, min_vouchers=2, now=NOW)
    assert not r.ok
    assert any("trusted" in reason for _, reason in r.rejected)
    r = verify_presentation(registry, pres, trust={"pharmacy"}, now=NOW)
    assert r.ok and not r.bound


def test_name_shows_only_name(world):
    registry, _ = world
    atts = [_vouch(world, "notary", "name", "Adam Smith"), _vouch(world, "notary")]
    pres = _present(world, atts, show=["name"])
    assert [a["claim"] for a in pres["attestations"]] == ["name"]
    r = verify_presentation(registry, pres, now=NOW)
    assert r.ok and r.claims[0].value == "Adam Smith"


def test_presentation_binding(world):
    registry, _ = world
    pres = _present(world, [_vouch(world, "pharmacy")], audience="shop.example", nonce="n1")
    with pytest.raises(AttestationError, match="not 'bar.example'"):
        verify_presentation(registry, pres, audience="bar.example", now=NOW)
    with pytest.raises(AttestationError, match="replay"):
        verify_presentation(registry, pres, nonce="n2", now=NOW)
    with pytest.raises(AttestationError, match="old"):
        verify_presentation(registry, pres, now=NOW + 301)
    tampered = dict(pres, show=["over21"])
    with pytest.raises(AttestationError, match="holder signature"):
        verify_presentation(registry, tampered, now=NOW)


def test_stolen_attestations_cant_be_presented(world):
    registry, keys = world
    att = _vouch(world, "pharmacy")
    # Eve copies Adam's vouch into her own presentation.
    with pytest.raises(AttestationError, match="no vouch"):
        _present(world, [att], holder="eve")
    eve = registry.resolve("eve")
    forged = {
        "type": "vouch-presentation",
        "v": 1,
        "holder": eve.did,
        "show": ["over18"],
        "attestations": [att],
        "audience": "",
        "nonce": "",
        "issued_at": NOW,
    }
    from capgate.didhome.attest import _payload

    forged["signature"] = keys["eve"].sign(_payload(forged)).hex()
    r = verify_presentation(registry, forged, now=NOW)
    assert not r.ok and r.rejected[0][1] == "about someone else"


def test_rejections(world):
    registry, keys = world
    expired = _vouch(world, "pharmacy", expires_at=NOW + 10)
    revoked = _vouch(world, "notary")
    registry.revoke_attestation("notary", revoked["id"], keys["notary"])
    tampered = dict(_vouch(world, "kim"), value=True, claim="over21")
    pres = _present(world, [expired, revoked, tampered], show=["over18"], now=NOW + 20)
    r = verify_presentation(registry, pres, now=NOW + 20)
    reasons = sorted(reason for _, reason in r.rejected)
    assert not r.ok
    assert reasons == [
        "expired",
        "revoked by the voucher",
        "signature is not by the voucher's current key",
    ]


def test_no_self_vouch_and_claim_rules(world):
    with pytest.raises(AttestationError, match="yourself"):
        _vouch(world, "adam")
    with pytest.raises(AttestationError, match="true"):
        _vouch(world, "notary", "over18", "yes")
    with pytest.raises(AttestationError, match="how you checked"):
        _vouch(world, "notary", method=" ")
    with pytest.raises(AttestationError, match="bad claim"):
        _vouch(world, "notary", "Bad Claim", "x")


def test_vouch_survives_holder_recovery_but_not_voucher_recovery(world):
    registry, keys = world
    att = _vouch(world, "pharmacy")
    registry.set_guardians("adam", ["kim", "sam"], 2, keys["adam"])
    new = Ed25519PrivateKey.generate()
    prior = registry.resolve("adam").root_public_key
    approvals = [
        approve_recovery(g, keys[g], "adam", public_key_hex(new.public_key()), prior)
        for g in ("kim", "sam")
    ]
    registry.recover("adam", new, approvals)
    keys["adam"] = new
    verify_attestation(registry, att, now=NOW)
    r = verify_presentation(registry, _present(world, [att]), now=NOW)
    assert r.ok


def test_age_thresholds():
    assert derive_age_claims(date(2008, 10, 5), date(2026, 10, 4)) == ["over13", "over16"]
    assert derive_age_claims(date(2008, 10, 4), date(2026, 10, 4)) == [
        "over13",
        "over16",
        "over18",
    ]
    assert satisfies("over21", "over18") and not satisfies("over16", "over18")
    assert not satisfies("name", "over18")


def test_cli_round_trip(tmp_path, capsys):
    from vouch.cli import main

    reg = str(tmp_path / "reg")
    adam = ["--home", str(tmp_path / "adam"), "--registry", reg]
    shop = ["--home", str(tmp_path / "shop"), "--registry", reg]
    assert main([*adam, "get", "@adam"]) == 0
    assert main([*shop, "get", "@pharmacy"]) == 0
    vouch_file = tmp_path / "v.json"
    args = ["vouch", "@adam", "--birthdate", "1990-01-01", "--name", "Adam Smith"]
    args += ["--method", "saw-passport", "--expires", "5y", "--out", str(vouch_file)]
    assert main([*shop, *args]) == 0
    saved = vouch_file.read_text()
    assert "1990" not in saved
    assert {a["claim"] for a in json.loads(saved)} == {
        "over13",
        "over16",
        "over18",
        "over21",
        "name",
    }
    assert main([*adam, "keep", "@adam", str(vouch_file)]) == 0
    pres = tmp_path / "p.json"
    args = ["prove", "@adam", "--show", "over18", "--nonce", "4821", "--out", str(pres)]
    assert main([*adam, *args]) == 0
    assert "Adam Smith" not in pres.read_text()
    assert [a["claim"] for a in json.loads(pres.read_text())["attestations"]] == ["over18"]
    capsys.readouterr()
    assert main([*shop, "check", str(pres), "--nonce", "4821", "--trust", "@pharmacy"]) == 0
    out = capsys.readouterr().out
    assert "over18: yes  [OK" in out and "vouched by @pharmacy (saw-passport" in out
    with pytest.raises(SystemExit):
        main([*shop, "check", str(pres), "--nonce", "9999"])
    att_id = json.loads(pres.read_text())["attestations"][0]["id"]
    assert main([*shop, "unvouch", att_id]) == 0
    with pytest.raises(SystemExit):
        main([*shop, "check", str(pres), "--nonce", "4821"])
