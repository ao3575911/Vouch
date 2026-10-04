"""``vouch-id`` CLI — plain-language front for the did:home engine.

    vouch-id get @adam              claim your name (one step, no signup)
    vouch-id show @adam             see a name's public card
    vouch-id helper @adam cal ...   give a helper a permission slip
    vouch-id cancel @adam <slip>    cancel a permission slip
    vouch-id send @adam @sam ...    send a signed message
    vouch-id check msg.json         check a signed message is genuine
    vouch-id takeout @adam ...      take your whole identity with you
    vouch-id audit                  check the whole registry is untampered
    vouch-id card @adam             printable proof card (web/verify.html checks it)
    vouch-id guardians @adam @sam @kim --threshold 2   people who can rescue your name
    vouch-id recover-start / approve-recovery / recover   the rescue ceremony

Same engine, friendlier words. Technical users can keep using
``python -m capgate.didhome`` — the commands map 1:1.
"""

from __future__ import annotations

import sys

from capgate.didhome.cli import build_parser

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
}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    skip_next = False
    for i, token in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if token in ("--home", "--registry"):
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        # first positional = the subcommand
        args[i] = ALIASES.get(token, token)
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
