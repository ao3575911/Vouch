"""``vouch-id`` CLI — plain-language front for the did:home engine.

    vouch-id get @adam              claim your name (one step, no signup)
    vouch-id show @adam             see a name's public card
    vouch-id helper @adam cal ...   give a helper a permission slip
    vouch-id cancel @adam <slip>    cancel a permission slip
    vouch-id send @adam @sam ...    send a signed message
    vouch-id check msg.json         check a signed message or presentation is genuine
    vouch-id takeout @adam ...      take your whole identity with you
    vouch-id audit                  check the whole registry is untampered
    vouch-id card @adam             printable proof card, checked in the browser verifier
    vouch-id guardians @adam @sam @kim --threshold 2   people who can rescue your name
    vouch-id recover-start / approve-recovery / recover   the rescue ceremony
    vouch-id vouch @adam --over 18 --method saw-passport   vouch for someone
    vouch-id keep @adam adam.vouch.json                   store vouches you were given
    vouch-id prove @adam --show over18 --nonce 4821       show a vouched claim
    vouch-id check proof.json --nonce 4821 --min 2      check a presentation
    vouch-id entry @adam --venue bar.x --nonce 77       mint a QR entry pass for a venue
    vouch-id door pass.json --policy venue.json --nonce 77   door staff check a pass
    vouch-id unvouch <id>                                 withdraw a vouch you made

Same engine, friendlier words. Technical users can keep using
``python -m capgate.didhome`` — the commands map 1:1.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from capgate.didhome.cli import build_parser

PLAIN_HELP = """\
usage: vouch-id [--home HOME] [--registry REGISTRY] [--passphrase] <command> ...

Your name, your key, no signup. Plain-word commands:

  get @you                 claim your name (one step, no signup)
  show @you                see a name's public card
  card @you                printable proof card for the browser verifier
  helper @you <scope>      give a helper a permission slip
  cancel @you <slip>       cancel a permission slip
  send @you @them ...      send a signed message
  check <file>             check a signed message or presentation is genuine
  vouch @them ...          vouch for someone (age, name, custom claims)
  keep @you <file>         store vouches you were given
  prove @you ...           show vouched claims to one verifier
  unvouch <id>             withdraw a vouch you made
  entry @you ...           mint a short-lived QR entry pass for a venue
  door <pass> ...          door staff: check an entry pass against a policy
  guardians @you ...       name the people who can rescue your name
  recover-start            begin the rescue ceremony (then approve-recovery, recover)
  takeout @you             take your whole identity with you
  audit                    check the whole registry is untampered

options:
  --home HOME              keystore dir (default ~/.didhome)
  --registry REGISTRY      registry dir
  --passphrase             prompt for a passphrase (or set VOUCH_ID_PASSPHRASE)
  -h, --help               show this help

Run `vouch-id <command> --help` for details. The technical names
(claim, whoami, delegate, ...) work too — same engine, friendlier words.
"""

# plain word -> engine command
ALIASES = {
    "get": "claim",
    "show": "whoami",
    "helper": "delegate",
    "cancel": "revoke",
    "send": "ping",
    "check": "verify-ping",
    "takeout": "move",
    "audit": "verify-registry",
    "guardians": "set-guardians",
    "vouch": "attest",
    "prove": "present",
    "entry": "entry-pass",
    "door": "door-check",
    "unvouch": "revoke-attestation",
}


def _is_presentation(path: str) -> bool:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and data.get("type") == "vouch-presentation"


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(PLAIN_HELP, end="", file=sys.stderr)
        return 2
    skip_next = False
    for i, token in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if token in ("--home", "--registry"):
            skip_next = True
            continue
        if token in ("-h", "--help"):
            # top-level help, before any subcommand: show plain words
            print(PLAIN_HELP, end="")
            return 0
        if token.startswith("-"):
            continue
        # first positional = the subcommand
        args[i] = ALIASES.get(token, token)
        if token == "check":
            files = [a for a in args[i + 1 :] if not a.startswith("-")]
            if any(_is_presentation(f) for f in files):
                args[i] = "verify-presentation"
        break
    parser = build_parser()
    parser.prog = "vouch-id"
    parsed = parser.parse_args(args)
    try:
        parsed.func(parsed)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
