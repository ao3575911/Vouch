---
title: "ADR 0001: scope"
nav_order: 7
---

# ADR 0001: What Vouch is and isn't

Status: accepted, 4 Oct 2026

## Context

The repo grew from two projects. capgate is a fail-closed tool gate for AI
agents. did:home (vendored as `capgate.didhome`) is a self-certifying handle
namespace, and Vouch is the plain-language layer and OIDC bridge on top of it.
The README pitched Vouch as a "Plan B to government digital ID" and promised
instant login on WordPress and Nextcloud. The code does less than that, and
two products in one wheel and one README muddy both.

A Vouch proof is a statement signed by a key the user holds. Nothing attests
that the statement is true. Government ID is useful because a trusted issuer
attests attributes such as age or legal name. Vouch can't replace that
without an issuer and a selective-disclosure proof system, and neither is on
the table.

## Decision

Vouch is three things:

1. **A portable handle.** `@adam` maps to `did:home:adam`, a self-signed
   manifest in a static, forkable registry with a signed, hash-chained event
   log. Social recovery through guardians.
2. **Login.** A self-hostable OIDC bridge that turns a signed login proof
   into an ID token. It is a reference implementation until it passes
   interop with a real relying party.
3. **Signed statements.** Proof cards that anyone can check offline against
   the handle's registry key, on paper, in a browser or from the CLI.

Vouch is not:

- a source of attested attributes (age, legal name, citizenship, address)
- a replacement for government ID or a credential wallet
- a blockchain, a DNS-based identity, or a hosted account service

capgate is a separate product. It moves to its own repository, and the
did:home engine moves into the `vouch` package (tracked in issue #15). Until
then capgate stays in `src/capgate/`, documented in `docs/capgate.md`, and
the README covers it in one short section.

The Python distribution is `vouch-id`, because `vouch` on PyPI belongs to an
unrelated project. The repo and the CLI are `vouch-id` too. The import name
stays `vouch`. Nothing is published yet.

## Consequences

- The README leads with the three things above and states the limits.
  `docs/plan-b.md` stays as background on the digital-ID problem, not as the
  product pitch.
- Attested attributes (for example an over-18 proof) would need an issuer,
  most likely a government wallet credential with a zero-knowledge layer.
  That is a separate project and would get its own ADR.
- Work on the OIDC bridge aims at standard relying parties first (GET
  `/authorize`, PKCE, issuer-bound login statements).
