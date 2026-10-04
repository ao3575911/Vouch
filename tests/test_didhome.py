"""did:home suite: manifests, registry, delegation, ping, CLI."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capgate.didhome import (
    DelegationError,
    Manifest,
    ManifestError,
    PingError,
    Registry,
    RegistryError,
    create_manifest,
    create_ping,
    export_bundle,
    issue_capability_token,
    update_manifest,
    validate_handle,
    verify_capability_token,
    verify_manifest,
    verify_ping,
)
from capgate.didhome.cli import main as cli_main


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def registry(tmp_path):
    return Registry(tmp_path / "registry")


# -- handle rules ----------------------------------------------------------


@pytest.mark.parametrize("bad", ["ab", "a" * 25, "Adam", "ad-am", "@admin", "root"])
def test_invalid_or_reserved_handles_rejected(bad):
    with pytest.raises(ManifestError):
        validate_handle(bad)


def test_valid_handle_strips_at():
    assert validate_handle("@adam_1") == "adam_1"


# -- manifest --------------------------------------------------------------


def test_manifest_self_verifies(key):
    verify_manifest(create_manifest("@adam", key))


def test_int_timestamp_survives_json_round_trip(key):
    m = create_manifest("@adam", key, now=1759550400)
    assert isinstance(m.created_at, float)
    round_tripped = Manifest.from_dict(json.loads(json.dumps(m.to_dict())))
    verify_manifest(round_tripped)
    m2 = update_manifest(round_tripped, key, now=1759550500)
    assert isinstance(m2.updated_at, float)
    verify_manifest(Manifest.from_dict(json.loads(json.dumps(m2.to_dict()))))


def test_tampered_manifest_rejected(key):
    m = create_manifest("@adam", key)
    data = m.to_dict()
    data["services"] = [{"id": "evil", "type": "x", "endpoint": "http://evil"}]
    with pytest.raises(ManifestError, match="signature invalid"):
        verify_manifest(Manifest.from_dict(data))


def test_update_requires_current_root_key(key):
    m = create_manifest("@adam", key)
    with pytest.raises(ManifestError, match="current root key"):
        update_manifest(m, Ed25519PrivateKey.generate())


# -- registry --------------------------------------------------------------


def test_claim_resolve_roundtrip(registry, key):
    registry.claim(create_manifest("@adam", key), key)
    assert registry.resolve("@adam").did == "did:home:adam"
    assert registry.verify() == 1


def test_first_valid_claim_wins(registry, key):
    registry.claim(create_manifest("@adam", key), key)
    other = Ed25519PrivateKey.generate()
    with pytest.raises(RegistryError, match="already claimed"):
        registry.claim(create_manifest("@adam", other), other)


def test_update_enforces_key_continuity_and_version(registry, key):
    m = create_manifest("@adam", key)
    registry.claim(m, key)
    m2 = update_manifest(m, key, services=[{"id": "p", "type": "t", "endpoint": "e"}])
    registry.update(m2, key)
    assert registry.resolve("adam").version == 2
    with pytest.raises(RegistryError, match="version"):
        registry.update(m2, key)  # replay of same version


def test_deactivated_handle_unresolvable(registry, key):
    registry.claim(create_manifest("@adam", key), key)
    registry.deactivate("adam", key)
    with pytest.raises(RegistryError, match="deactivated"):
        registry.resolve("adam")


def test_registry_verify_detects_forged_manifest_file(registry, key):
    registry.claim(create_manifest("@adam", key), key)
    squatter = Ed25519PrivateKey.generate()
    forged = create_manifest("@eve", squatter)  # file without claim event
    path = registry.names_dir / "eve.json"
    path.write_text(json.dumps(forged.to_dict(), sort_keys=True), encoding="utf-8")
    with pytest.raises(RegistryError, match="without a claim"):
        registry.verify()


def test_registry_verify_detects_key_swap(registry, key):
    m = create_manifest("@adam", key)
    registry.claim(m, key)
    attacker = Ed25519PrivateKey.generate()
    swapped = create_manifest("@adam", attacker)
    (registry.names_dir / "adam.json").write_text(
        json.dumps(swapped.to_dict(), sort_keys=True), encoding="utf-8"
    )
    with pytest.raises(RegistryError):
        registry.verify()


def test_export_bundle_contains_identity(registry, key):
    registry.claim(create_manifest("@adam", key), key)
    bundle = export_bundle(registry, "adam", "00" * 32)
    assert bundle["did"] == "did:home:adam"
    assert bundle["events"][0]["event"] == "claimed"


# -- delegation ------------------------------------------------------------


def _delegated(registry, key, perms=("ping:send",)):
    m = create_manifest("@adam", key)
    registry.claim(m, key)
    sub_key = Ed25519PrivateKey.generate()
    token = issue_capability_token(m.did, key, "cal@adam", sub_key, list(perms))
    return m, token, sub_key


def test_token_grants_exactly_scoped_permission(registry, key):
    _, token, _ = _delegated(registry, key, ("email:draft",))
    verify_capability_token(registry, token, "email:draft")
    with pytest.raises(DelegationError, match="deny by default"):
        verify_capability_token(registry, token, "payment:send")


def test_token_from_wrong_root_key_rejected(registry, key):
    m = create_manifest("@adam", key)
    registry.claim(m, key)
    attacker = Ed25519PrivateKey.generate()
    forged = issue_capability_token(
        m.did, attacker, "cal@adam", Ed25519PrivateKey.generate(), ["email:draft"]
    )
    with pytest.raises(DelegationError, match="signature invalid"):
        verify_capability_token(registry, forged, "email:draft")


def test_revoked_token_rejected(registry, key):
    _, token, _ = _delegated(registry, key)
    registry.revoke_token("adam", token.token_id, key)
    with pytest.raises(DelegationError, match="revoked"):
        verify_capability_token(registry, token, "ping:send")


def test_expired_token_rejected(registry, key):
    _, token, _ = _delegated(registry, key)
    with pytest.raises(DelegationError, match="expired"):
        verify_capability_token(registry, token, "ping:send", now=token.expires_at + 1)


def test_empty_permissions_refused(key):
    with pytest.raises(DelegationError, match="no permissions"):
        issue_capability_token("did:home:adam", key, "cal@adam", Ed25519PrivateKey.generate(), [])


# -- ping ------------------------------------------------------------------


def _ping_pair(registry, key):
    _, token, sub_key = _delegated(registry, key)
    sam_key = Ed25519PrivateKey.generate()
    registry.claim(create_manifest("@sam", sam_key), sam_key)
    return create_ping("did:home:adam", "did:home:sam", {"msg": "hi"}, token, sub_key)


def test_ping_roundtrip_and_replay_blocked(registry, key):
    ping = _ping_pair(registry, key)
    seen: set[str] = set()
    verify_ping(registry, ping, seen)
    with pytest.raises(PingError, match="replayed"):
        verify_ping(registry, ping, seen)


def test_ping_body_tamper_detected(registry, key):
    ping = _ping_pair(registry, key)
    data = ping.to_dict()
    data["body"] = {"msg": "send $$$"}
    from capgate.didhome.ping import Ping

    with pytest.raises(PingError, match="body hash"):
        verify_ping(registry, Ping(**data), set())


def test_stale_ping_rejected(registry, key):
    ping = _ping_pair(registry, key)
    with pytest.raises(PingError, match="freshness"):
        verify_ping(registry, ping, set(), now=ping.timestamp + 3600)


def test_ping_after_revocation_rejected(registry, key):
    ping = _ping_pair(registry, key)
    registry.revoke_token("adam", ping.token["token_id"], key)
    with pytest.raises(PingError, match="revoked"):
        verify_ping(registry, ping, set())


# -- CLI -------------------------------------------------------------------


def test_cli_end_to_end(tmp_path, capsys):
    home, reg = str(tmp_path / "keys"), str(tmp_path / "registry")
    base = ["--home", home, "--registry", reg]
    assert cli_main([*base, "claim", "@adam"]) == 0
    assert cli_main([*base, "claim", "@sam"]) == 0
    assert cli_main([*base, "claim", "@adam"]) == 1  # already claimed
    token_path = str(tmp_path / "t.json")
    assert cli_main([*base, "delegate", "@adam", "cal", "ping:send", "--out", token_path]) == 0
    ping_path = str(tmp_path / "p.json")
    assert (
        cli_main(
            [
                *base,
                "ping",
                "@adam",
                "@sam",
                "--token",
                token_path,
                "--body",
                '{"msg":"hi"}',
                "--out",
                ping_path,
            ]
        )
        == 0
    )
    assert cli_main([*base, "verify-ping", ping_path]) == 0
    token_id = json.loads((tmp_path / "t.json").read_text())["token_id"]
    assert cli_main([*base, "revoke", "@adam", token_id]) == 0
    assert cli_main([*base, "verify-ping", ping_path]) == 1  # revoked
    bundle = str(tmp_path / "b.json")
    assert cli_main([*base, "move", "@adam", "--out", bundle]) == 0
    assert json.loads((tmp_path / "b.json").read_text())["did"] == "did:home:adam"
    assert cli_main([*base, "whoami", "@adam"]) == 0
    assert cli_main([*base, "verify-registry"]) == 0
    out = capsys.readouterr().out
    assert "registry OK" in out
