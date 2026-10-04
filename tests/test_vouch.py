"""Vouch rebrand suite: package re-exports + plain-language CLI aliases."""

from __future__ import annotations

import json


def test_vouch_reexports_engine():
    import vouch
    from capgate import didhome

    for name in didhome.__all__:
        assert getattr(vouch, name) is getattr(didhome, name)


def test_vouch_cli_aliases_end_to_end(tmp_path, capsys):
    from vouch.cli import main

    base = ["--home", str(tmp_path / "keys"), "--registry", str(tmp_path / "reg")]
    assert main([*base, "get", "@adam"]) == 0
    assert main([*base, "get", "@sam"]) == 0
    token = str(tmp_path / "t.json")
    assert main([*base, "helper", "@adam", "cal", "ping:send", "--out", token]) == 0
    msg = str(tmp_path / "p.json")
    assert main([*base, "send", "@adam", "@sam", "--token", token, "--out", msg]) == 0
    assert main([*base, "check", msg]) == 0
    from pathlib import Path

    token_id = json.loads(Path(token).read_text())["token_id"]
    assert main([*base, "cancel", "@adam", token_id]) == 0
    assert main([*base, "check", msg]) == 1  # cancelled slip no longer proves
    bundle = str(tmp_path / "b.json")
    assert main([*base, "takeout", "@adam", "--out", bundle]) == 0
    assert main([*base, "show", "@adam"]) == 0
    assert main([*base, "audit"]) == 0
    assert "registry OK" in capsys.readouterr().out


def test_vouch_cli_engine_names_still_work(tmp_path):
    from vouch.cli import main

    base = ["--home", str(tmp_path / "keys"), "--registry", str(tmp_path / "reg")]
    assert main([*base, "claim", "@adam"]) == 0
    assert main([*base, "verify-registry"]) == 0


def test_vouch_cli_top_level_help_uses_plain_words(capsys):
    from vouch.cli import main

    assert main(["--help"]) == 0
    out = capsys.readouterr().out
    for word in (
        "get @you",
        "helper @you <helper> <scope>",
        "vouch @them",
        "prove @you",
        "takeout @you",
        "audit",
    ):
        assert word in out
    assert "attest" not in out  # engine names stay out of the plain help
    assert main(["--home", "x", "-h"]) == 0
    assert "get @you" in capsys.readouterr().out


def test_vouch_cli_no_args_prints_plain_help(capsys):
    from vouch.cli import main

    assert main([]) == 2
    assert "get @you" in capsys.readouterr().err
