"""Social recovery + guardianship: the ceremony works and resists abuse."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capgate.didhome.delegation import verify_capability_token
from capgate.didhome.manifest import create_manifest, public_key_hex
from capgate.didhome.recovery import approve_recovery, issue_child_identity
from capgate.didhome.registry import Registry, RegistryError


@pytest.fixture
def world(tmp_path):
    """Registry with @adam plus guardians @sam and @kim (threshold 2)."""
    registry = Registry(tmp_path / "registry")
    keys = {}
    for name in ("adam", "sam", "kim"):
        key = Ed25519PrivateKey.generate()
        registry.claim(create_manifest(name, key), key)
        keys[name] = key
    registry.set_guardians("adam", ["sam", "kim"], 2, keys["adam"])
    return registry, keys


def _approvals(registry, keys, new_pub, guardians=("sam", "kim")):
    prior = registry.resolve("adam").root_public_key
    return [approve_recovery(g, keys[g], "adam", new_pub, prior) for g in guardians]


def test_recovery_rotates_root_key(world):
    registry, keys = world
    new_key = Ed25519PrivateKey.generate()
    new_pub = public_key_hex(new_key.public_key())
    registry.recover("adam", new_key, _approvals(registry, keys, new_pub))
    assert registry.resolve("adam").root_public_key == new_pub
    registry.verify()  # whole log, including rotation, verifies offline


def test_recovered_key_can_keep_mutating(world):
    registry, keys = world
    new_key = Ed25519PrivateKey.generate()
    new_pub = public_key_hex(new_key.public_key())
    registry.recover("adam", new_key, _approvals(registry, keys, new_pub))
    registry.revoke_token("adam", "sometoken", new_key)
    registry.verify()


def test_below_threshold_denied(world):
    registry, keys = world
    new_key = Ed25519PrivateKey.generate()
    new_pub = public_key_hex(new_key.public_key())
    with pytest.raises(RegistryError, match="insufficient approvals"):
        registry.recover("adam", new_key, _approvals(registry, keys, new_pub, ("sam",)))


def test_duplicate_guardian_does_not_count_twice(world):
    registry, keys = world
    new_key = Ed25519PrivateKey.generate()
    new_pub = public_key_hex(new_key.public_key())
    approvals = _approvals(registry, keys, new_pub, ("sam",)) * 2
    with pytest.raises(RegistryError, match="duplicate approval"):
        registry.recover("adam", new_key, approvals)


def test_non_guardian_approval_rejected(world):
    registry, keys = world
    outsider = Ed25519PrivateKey.generate()
    registry.claim(create_manifest("eve", outsider), outsider)
    new_key = Ed25519PrivateKey.generate()
    new_pub = public_key_hex(new_key.public_key())
    prior = registry.resolve("adam").root_public_key
    approvals = _approvals(registry, keys, new_pub, ("sam",)) + [
        approve_recovery("eve", outsider, "adam", new_pub, prior)
    ]
    with pytest.raises(RegistryError, match="not a declared guardian"):
        registry.recover("adam", new_key, approvals)


def test_forged_approval_rejected(world):
    registry, keys = world
    new_key = Ed25519PrivateKey.generate()
    new_pub = public_key_hex(new_key.public_key())
    prior = registry.resolve("adam").root_public_key
    forged = approve_recovery("kim", Ed25519PrivateKey.generate(), "adam", new_pub, prior)
    approvals = _approvals(registry, keys, new_pub, ("sam",)) + [forged]
    with pytest.raises(RegistryError, match="signature.*invalid"):
        registry.recover("adam", new_key, approvals)


def test_approvals_cannot_be_replayed_for_second_rotation(world):
    """Approvals bind old->new keys, so they are useless for any other rotation."""
    registry, keys = world
    first = Ed25519PrivateKey.generate()
    approvals = _approvals(registry, keys, public_key_hex(first.public_key()))
    registry.recover("adam", first, approvals)
    second = Ed25519PrivateKey.generate()
    with pytest.raises(RegistryError):
        registry.recover("adam", second, approvals)


def test_recovery_without_declared_guardians_denied(tmp_path):
    registry = Registry(tmp_path / "registry")
    key = Ed25519PrivateKey.generate()
    registry.claim(create_manifest("solo", key), key)
    with pytest.raises(RegistryError, match="no guardians"):
        registry.recover("solo", Ed25519PrivateKey.generate(), [])


def test_set_guardians_validations(world):
    registry, keys = world
    with pytest.raises(RegistryError, match="own guardian"):
        registry.set_guardians("adam", ["adam", "sam"], 1, keys["adam"])
    with pytest.raises(RegistryError, match="threshold"):
        registry.set_guardians("adam", ["sam"], 2, keys["adam"])


def test_child_identity_is_scoped_and_revocable(world):
    registry, keys = world
    manifest = registry.resolve("adam")
    child_key = Ed25519PrivateKey.generate()
    token = issue_child_identity(manifest, keys["adam"], "junior", child_key)
    assert token.subject == "junior@adam"
    verify_capability_token(registry, token, "ping:send")
    import pytest as _pytest

    from capgate.didhome.delegation import DelegationError

    with _pytest.raises(DelegationError, match="deny by default"):
        verify_capability_token(registry, token, "email:send")
    registry.revoke_token("adam", token.token_id, keys["adam"])
    with _pytest.raises(DelegationError, match="revoked"):
        verify_capability_token(registry, token, "ping:send")
