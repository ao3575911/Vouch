---
title: CLI reference
nav_order: 3
---

# CLI reference

```bash
vouch-id [--home DIR] [--registry DIR] <command> ...
```

- `--home` is your keystore, default `~/.didhome`. Keys never go in the registry.
- `--registry` is the registry folder, default `./registry`.
- Global options go before the command.

Every plain-word command maps to an engine command, and both names work.
`python -m capgate.didhome` takes the engine names.

| Command | Engine name | What it does |
|---|---|---|
| `get @adam` | `claim` | make a key and claim the name (`--service id=type=endpoint`, repeatable) |
| `show @adam` | `whoami` | print a name's manifest |
| `helper @adam cal ping:send` | `delegate` | give a helper a permission slip (`--out FILE`) |
| `cancel @adam <token_id>` | `revoke` | cancel a permission slip |
| `send @adam @sam --token slip.json` | `ping` | send a signed message (`--body JSON`, `--out FILE`) |
| `check ping.json` | `verify-ping` | check a signed message against the registry |
| `takeout @adam --out bundle.json` | `move` | export manifest, private key and history |
| `audit` | `verify-registry` | check the whole registry offline |
| `card @adam` | `card` | make a printable proof card |
| `guardians @adam @sam @kim --threshold 2` | `set-guardians` | name the people who can recover your name |
| `recover-start @adam` | `recover-start` | make a new key and print its public half |
| `approve-recovery @sam @adam --new-public-key HEX` | `approve-recovery` | a guardian signs off on a new key |
| `recover @adam --approval FILE ...` | `recover` | rotate the key with enough approvals |

Recovery is covered step by step in [Recovery](recovery.md).

## Example

```bash
vouch-id get @adam
vouch-id get @sam
vouch-id helper @adam cal ping:send --out slip.json
vouch-id send @adam @sam --token slip.json --body '{"msg":"hi"}' --out ping.json
vouch-id check ping.json        # ping verified: did:home:adam -> did:home:sam
vouch-id audit                  # registry OK: 2 handles, 3 events, chain verified
```

`takeout` writes your private key into the bundle and warns you to keep it
secret.

## Proof cards

```bash
vouch-id card @adam                           # writes adam.card.html
vouch-id card @adam --statement "I wrote this" --out card.html
vouch-id card @adam --json                    # print the proof JSON instead
```

The default statement is "this is my name". For a QR code on the card,
install the extra:
`pip install "vouch-id[qr] @ https://github.com/ao3575911/vouch-id/releases/download/v0.3.1/vouch_id-0.3.1-py3-none-any.whl"`.

To check a card, open the [browser verifier](https://ao3575911.github.io/vouch-id/verify.html). It's a single static
page that doesn't phone home; save it to use offline. The wheel ships a copy
(`verify.html` in the `vouch` package). Paste
the card's JSON and the handle's manifest (`names/adam.json`) from a registry
copy you trust. Without the manifest the page shows an amber "unpinned"
result, because anyone can sign a proof that names any handle. In Python, use
`verify_proof_for_handle(proof, registry)`.
