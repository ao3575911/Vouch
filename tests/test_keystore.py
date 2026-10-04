"""Keystore: 0600 from creation, optional passphrase, recovery key, takeout."""

from __future__ import annotations

import json
import os
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capgate.didhome.cli import PASSPHRASE_ENV, Keystore, main

PEM = "-----BEGIN ENCRYPTED PRIVATE KEY-----"


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_key_file_is_0600_even_with_open_umask(tmp_path):
    old = os.umask(0)
    try:
        Keystore(tmp_path).save("adam", Ed25519PrivateKey.generate())
    finally:
        os.umask(old)
    assert _mode(tmp_path / "adam.key") == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["adam.key"]  # no temp files left


def test_plain_key_round_trips_as_hex(tmp_path):
    key = Ed25519PrivateKey.generate()
    ks = Keystore(tmp_path)
    ks.save("adam", key)
    assert not (tmp_path / "adam.key").read_text().startswith(PEM)
    assert ks.load("adam").public_key() == key.public_key()


def test_passphrase_encrypts_and_is_required(tmp_path):
    key = Ed25519PrivateKey.generate()
    Keystore(tmp_path, "correct horse").save("adam", key)
    assert (tmp_path / "adam.key").read_text().startswith(PEM)
    loaded = Keystore(tmp_path, "correct horse").load("adam")
    assert loaded.public_key() == key.public_key()
    with pytest.raises(SystemExit, match="encrypted"):
        Keystore(tmp_path).load("adam")
    with pytest.raises(SystemExit, match="wrong passphrase"):
        Keystore(tmp_path, "wrong").load("adam")


def test_cli_with_passphrase_covers_recovery_key_and_takeout(tmp_path, monkeypatch):
    monkeypatch.setenv(PASSPHRASE_ENV, "s3cret")
    home = tmp_path / "keys"
    base = ["--home", str(home), "--registry", str(tmp_path / "reg")]
    assert main([*base, "claim", "@adam"]) == 0
    assert main([*base, "recover-start", "@adam"]) == 0
    for name in ("adam.key", "adam.recovering.key"):
        assert (home / name).read_text().startswith(PEM)
        assert _mode(home / name) == 0o600

    bundle = tmp_path / "b.json"
    assert main([*base, "move", "@adam", "--out", str(bundle)]) == 0
    assert _mode(bundle) == 0o600
    assert json.loads(bundle.read_text())["private_key"].startswith(PEM)

    bare = tmp_path / "bare.json"
    assert main([*base, "move", "@adam", "--out", str(bare), "--without-key"]) == 0
    assert "private_key" not in json.loads(bare.read_text())

    monkeypatch.delenv(PASSPHRASE_ENV)
    with pytest.raises(SystemExit, match="encrypted"):
        main([*base, "card", "@adam", "--json"])
