# Plan B: escaping digital-ID lock-in with Vouch

**Thesis:** government digital ID wins by being *mandatory, central, and
convenient*. Vouch counters each lever without asking anyone to boycott
anything — it plugs into the systems people already use.

## 1. The trap, mapped

```
TRAP                          COUNTER (Vouch)
────────────────────────────  ─────────────────────────────────
Mandatory for services        Verifier shim: services accept a
(banking, benefits, age        Vouch proof wherever they accept
 checks, login)                govt ID assertions
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
| Browser | most people | PWA / extension; key lives in a passkey, claim = one click |
| CLI | technical | `vouch get @adam` (shipping today) |

Rules that keep it human:
- UI words only: *name, key, helper, permission slip, prove, vouch*.
  Never "DID", "Ed25519", "manifest" in user-facing surfaces.
- **Recovery = people, not helpdesks.** N trusted family/friends can
  restore your name (social recovery ceremony — roadmap §4).
- **Guardianship built in.** A parent's name issues a scoped child
  identity via the existing permission-slip (capability token) machinery.

## 3. Integration surface (priority order)

1. **OpenID Connect bridge** — tiny self-hostable OIDC provider backed by
   did:home proofs → instant "Login with Vouch" on WordPress, Nextcloud,
   forums, workplaces. Biggest win per effort.
2. **Browser extension** — "prove my age / name / membership" on any
   site; selective disclosure (prove over-18 **without** revealing
   birthdate). Planned; no age credential or selective-disclosure proof is
   implemented. A signed self-assertion or hash of a birthdate is not an
   age proof.
3. **Passkey / WebAuthn custody** — ride existing hardware + browser
   support for key storage; nothing new for users to learn. Planned; browser
   credential APIs do not expose an authenticator's private key, so Vouch
   needs a reviewed custody and recovery design before claiming passkey-backed
   Ed25519 keys.
4. **QR verification page** — single static HTML file anyone can host;
   scan a card → green tick; works offline.
5. **Email / signature shim** — sign any message with your name;
   verifiable by anyone holding a registry mirror.
6. **W3C Verifiable Credentials import/export** — Vouch proofs work
   inside existing wallet apps, including govt-wallet ecosystems.
   Interop is the escape hatch, not isolation.

## 4. Sequencing

| # | Milestone | Status |
|---|---|---|
| 1 | Rename + rebrand (Vouch CLI, plain-language README) | ✅ this repo |
| 2 | Mission README: why + trap/counter + 3-step quickstart | ✅ this repo |
| 3 | Passkey custody + PWA claim flow (kills the CLI barrier) | planned |
| 4 | OIDC bridge | ✅ reference implementation; relying-party interoperability unvalidated |
| 5 | Selective-disclosure age proof (the main govt-ID wedge) | planned; trusted issuer and proof system not selected |
| 6 | QR paper identity + static verifier page | ✅ this repo |
| 7 | Social recovery ceremony | ✅ this repo |

## 5. Principles (non-negotiable)

- Verification must work **offline** from a registry mirror. Any feature
  that requires calling home is rejected.
- No accounts, no email, no phone number to claim a name.
- The registry is forkable; leaving is always possible (`vouch takeout`).
- Free forever: no VM, no storage service, no billing — nothing that
  forces charging money (see did:home spec §8).
