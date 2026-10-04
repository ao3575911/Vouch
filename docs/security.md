---
title: Security model
nav_order: 6
---

# Security model

## What a proof shows

A proof shows one thing: the exact statement was signed by the key behind a
handle. Nobody attests that the statement is true. Don't treat a proof as
evidence of age, government identity or anything beyond control of the key
and the signed statement ([ADR 0001](adr-0001-scope.md)).

## Pin the key

Anyone can sign a proof that names any handle with their own key. A proof
only means something once its key is checked against the handle's manifest
from a registry copy you trust:

- In Python, `verify_proof_for_handle(proof, registry)` does that, and
  `Registry.resolve()` checks the manifest key against the event log.
- The [browser verifier](verify.html) checks the pasted manifest's signature,
  but not the log. Without a manifest the result is amber "unpinned".

## What to trust

- **Your keystore.** Private keys stay in `--home` (default `~/.didhome`) and
  never enter the registry. Key files are 0600 from the moment they exist.
  Set `VOUCH_ID_PASSPHRASE` (or pass `--passphrase` to be prompted) to encrypt
  new keys, the recovery key and the key in `takeout` bundles.
  `takeout --without-key` leaves the key out.
- **Not the registry host.** A host can withhold data (availability) but
  can't forge manifests, events, tokens or pings (integrity).
  `vouch-id audit` re-checks the hash chain, every signature and key
  continuity offline.
- **Key loss or theft.** Whoever holds the key controls the handle. Guardians
  you declared beforehand can rotate it ([Recovery](recovery.md)). Witness
  receipts are future work.
- **Squatting** is handled at the repo layer (PR review, rate limits), not in
  the protocol.

## Login bridge

The OIDC bridge has its own limits: in-memory keys and state, no TLS, local
rate limits. See [Login with Vouch](login.md).

## More

- capgate threat model: [`THREATMODEL.md`](https://github.com/ao3575911/vouch-id/blob/main/THREATMODEL.md)
- Reporting a vulnerability: [`SECURITY.md`](https://github.com/ao3575911/vouch-id/blob/main/SECURITY.md) (private advisory, not a public issue)
