---
title: Home
nav_order: 1
---

# Vouch

**ID you carry, not ID they control.** Your name, your key, your proof.

Vouch is a plan B to government digital ID ([why](adr-0001-scope.md), [ADR 0002](adr-0002-attestations.md)):

- **A handle you own.** `@adam` is `did:home:adam`, a self-signed manifest in
  a static, forkable registry with a signed, tamper-evident log. No account,
  no email, no phone number. Lost your key? Your guardians can recover it.
- **Login.** A small self-hostable OpenID Connect bridge that turns a signed
  login proof into an ID token. Reference implementation, not yet tested with
  real relying parties.
- **Signed statements.** Proof cards anyone can check offline, on paper or in
  a browser, against the handle's key in the registry. Nobody is called and
  nothing is logged.

- **Age and name.** Pharmacies, notaries and people who know you vouch for
  you ("over 18", "full name is …"). You show only what's asked, signed fresh
  for that verifier, and they decide whose vouches they trust. No central
  database, no tracking. Not legally recognised ID.
  [How it works](attestations.md).

## Install

Vouch isn't on PyPI yet. Install the wheel from the latest
[GitHub release](https://github.com/ao3575911/vouch-id/releases):

```bash
pip install https://github.com/ao3575911/vouch-id/releases/download/v0.3.1/vouch_id-0.3.1-py3-none-any.whl
```

Or build from the tag (needs git):

```bash
pip install "git+https://github.com/ao3575911/vouch-id@v0.3.1"
```

The Python distribution and the CLI are `vouch-id` (`vouch` on PyPI is someone
else's project). The import name is `vouch`. `python -m capgate.didhome` runs
the same engine with its technical command names.

## Plain words

| Word | Means |
|---|---|
| name | your handle, `@adam` (`did:home:adam`) |
| key | the Ed25519 secret only you hold |
| helper | a scoped sub-identity such as `cal@adam` |
| permission slip | a capability token you sign for a helper |
| prove | show a vouched claim, signed fresh for one verifier |
| vouch | a signed claim someone makes about you, like "over 18" |

## Pages

- [Concepts](concepts.md): the `did:home` method, manifests, registry, delegation, pings, moving
- [CLI reference](cli.md): every `vouch-id` command, proof cards and the browser verifier
- [Proving age and name](attestations.md): vouches, presentations and verifier policy
- [Venues](venues.md): door policy files, tier weights and QR entry passes
- [Login with Vouch](login.md): the OIDC bridge, its flow and deployment limits
- [Recovery](recovery.md): guardians and child identities
- [Security model](security.md): what a proof does and doesn't show, and what to trust
- [ADR 0001: scope](adr-0001-scope.md) and [Background: Plan B](plan-b.md)
- [capgate](capgate.md): the separate tool gate for AI agents that shares this repo for now
- [Maintainers](maintainers.md): development, releases and repo governance
