---
title: "ADR 0002: attestations"
nav_order: 10
---

# ADR 0002: Attestations (vouches)

Status: accepted, 4 Oct 2026. Amends [ADR 0001](adr-0001-scope.md).

## Context

ADR 0001 said Vouch can't prove age or legal name because nothing attests
that a statement is true, and so it isn't an alternative to government ID.
That undersold the goal. Government ID is a trusted party checking you once
and signing for it. That doesn't need a government or a central database:
pharmacies, notaries, banks and people who know you already check ID every
day.

## Decision

Vouch is a plan B to government digital ID. It proves age and name through
attestations ("vouches"):

- A voucher signs one claim about a subject's handle and key: `overN`,
  `name`, or a custom `key=value`, with how they checked and an optional
  expiry. Age is attested as thresholds; a birthdate is used only to work
  them out and is never stored.
- The holder presents chosen vouches with a fresh signature over the
  verifier's audience and nonce, valid for five minutes.
- Verifiers check signatures against the registry, expiry and revocation
  (an `attestation_revoked` event signed by the voucher), then apply their own
  policy: a trusted-voucher list and/or a minimum number of vouchers.
- Formats are plain canonical JSON with whole-second times, so the Python
  verifier and the browser verifier agree byte for byte (shared test vectors).
- Recovery is unchanged. Vouches follow the holder through a guardian
  recovery; vouches signed with a voucher's replaced key stop counting.

## Consequences

- The README and docs describe Vouch as an alternative to government digital
  ID for proving age and name, stating plainly that it isn't legally
  recognised ID and that a vouch is only as good as the voucher.
- ADR 0001's "not a source of attested attributes" and "not a replacement for
  government ID" no longer apply.
- Presentations reveal the holder's handle. Unlinkable proofs, a phone
  wallet, a directory of known vouchers and fast offline revocation are the
  v0.5 milestone (issues #37 to #41).
