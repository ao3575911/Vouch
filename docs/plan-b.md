---
title: "Background: Plan B"
nav_order: 11
---

# Plan B: escaping digital-ID lock-in with Vouch

**Thesis:** government digital ID wins by being *mandatory, central, and
convenient*. Vouch is a plan B: the people and businesses who already check
ID vouch for you, you prove what's needed, and nobody keeps a central record.
See [ADR 0001](adr-0001-scope.md) and [ADR 0002](adr-0002-attestations.md)
for what is built today. Items below marked *roadmap* are not built yet.
Vouch is not legally recognised ID.

## 1. The trap, mapped

```
TRAP                          COUNTER (Vouch)
────────────────────────────  ─────────────────────────────────
Mandatory for services        Vouches: pharmacies, notaries and
(banking, benefits, age        people who know you sign "over 18"
 checks, login)                or your name; services check them
Central register = tracking   Static forkable registry; verify
every verification call        OFFLINE — no phone-home, no log
Phone-app monopoly            Paper QR card, browser, CLI —
                               any device, no account
Network effect / default      Plug-ins for existing systems
                               (§3) — meet people where they are
Revocation = social cutoff    User-held keys; no central
                               off-switch exists to pull
"Convenience" onboarding      60-second claim: no signup, no
                               email, no phone number
```

One sentence to repeat everywhere: **they verify you against their
database and log it; with Vouch you prove it yourself and nobody is
called.**

## 2. Onboarding: all ages, all skill levels

One protocol, three tiers:

| Tier | Who | How |
|---|---|---|
| Paper | grandma, kids, no-phone | printed QR card; anyone scans it against a static verifier page |
| Browser | most people | phone wallet (PWA) holding key and vouches — *roadmap* (#37) |
| CLI | technical | `vouch-id get @adam` (shipping today) |

Rules that keep it human:
- UI words only: *name, key, helper, permission slip, prove, vouch*.
  Never "DID", "Ed25519", "manifest" in user-facing surfaces.
- **Recovery = people, not helpdesks.** N trusted family/friends can
  restore your name (social recovery ceremony, built).
- **Guardianship built in.** A parent's name issues a scoped child
  identity via the existing permission-slip (capability token)
  machinery — *roadmap*.

## 3. Integration surface (priority order)

1. **OpenID Connect bridge** — self-hostable OIDC provider backed by
   did:home proofs: "Login with Vouch" with the standard code flow and PKCE.
   Built as a reference implementation; not yet tested with real relying
   parties.
2. **Age and name proofs** — vouches for over13/16/18/21, name and custom
   claims, presented with a fresh signature and checked against the
   registry. Built ([Proving age and name](attestations.md)); the birthdate
   is never revealed. Proofs that also hide the handle are *roadmap* (#39).
3. **Passkey / WebAuthn custody** — ride existing hardware + browser
   support for key storage; nothing new for users to learn. Planned; browser
   credential APIs do not expose an authenticator's private key, so Vouch
   needs a reviewed custody and recovery design before claiming passkey-backed
   Ed25519 keys. *Roadmap.*
4. **QR verification page** — single static HTML file anyone can host;
   scan a card → green tick; works offline. Built (it also checks
   presentations).
5. **Email / signature shim** — sign any message with your name;
   verifiable by anyone holding a registry mirror. *Roadmap.*
6. **W3C Verifiable Credentials import/export** — Vouch proofs work
   inside existing wallet apps, including govt-wallet ecosystems.
   Interop is the escape hatch, not isolation. *Roadmap.*

## 4. Sequencing

| # | Milestone | Status |
|---|---|---|
| 1 | Rename + rebrand (Vouch CLI, plain-language README) | ✅ this repo |
| 2 | Mission README: why + trap/counter + 3-step quickstart | ✅ this repo |
| 3 | Phone wallet (PWA) with QR presentation | roadmap (#37) |
| 4 | OIDC bridge | ✅ reference implementation; relying-party interoperability unvalidated |
| 5 | Age and name proofs via vouches | ✅ this repo |
| 5b | Unlinkable over-18 proofs, known-voucher directory, fast revocation | roadmap (#38, #39, #41) |
| 6 | QR paper identity + static verifier page | ✅ this repo |
| 6b | Venue entry passes: offline door checks against a signed policy | ✅ this repo ([Venues](venues.md)) |
| 7 | Social recovery ceremony | ✅ this repo |

## 5. Principles (non-negotiable)

- Verification must work **offline** from a registry mirror. Any feature
  that requires calling home is rejected.
- No accounts, no email, no phone number to claim a name.
- The registry is forkable; leaving is always possible (`vouch-id takeout`).
- Free forever: no VM, no storage service, no billing — nothing that
  forces charging money (see did:home spec §8).
