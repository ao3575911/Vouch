# The `did:home` DID Method — a free, local-first namespace for agents

**Status:** draft v0.1 (research preview). Merges the product vision of
[handle](https://github.com/ao3575911/handle) with the signed-manifest
machinery of [atHome](https://github.com/ao3575911/atHome), reimplemented
on capgate's Ed25519 / canonical-JSON / hash-chain primitives.
No microVMs, no mail gateway, no object storage, no billing.

```
                 @adam  ⇄  did:home:adam
                   │
   ┌───────────────┼──────────────────┐
   │               │                  │
 names/adam.json  cal@adam          @adam ⇄ @sam
 DID document     scoped token      signed ping
 (self-signed)    (deny-by-default) (replay-proof)
```

## 1. Method name and syntax

```
did:home:<handle>
handle = [a-z0-9_]{3,24}, not in the reserved list
```

Reserved: `admin root system home registry did www mail api help`.
`@adam` is shorthand for `did:home:adam`. First valid claim wins.

## 2. DID document = self-signed manifest

The DID document is a JSON manifest (`capgate.didhome.manifest.Manifest`):

| Field | Meaning |
|---|---|
| `did`, `handle` | `did:home:adam`, `adam` |
| `root_public_key` | hex Ed25519 verification key |
| `services` | `{id, type, endpoint}` — e.g. a ping webhook |
| `agents` | delegated sub-identities `{id, public_key, token_id}` |
| `version` | monotonically increasing integer, starts at 1 |
| `created_at`, `updated_at` | unix timestamps |
| `signature` | hex Ed25519 over canonical JSON minus `signature` |

Canonical JSON = sorted keys, `(",", ":")` separators, UTF-8. Manifests are
reproducible and verify offline with no resolver trust.

## 3. Resolution: static registry

A registry is a plain directory, intended to be a public git repo (served
via GitHub Pages or any static host):

```
registry/
├── names/<handle>.json   current manifest per handle
└── events.jsonl          hash-chained event log (capgate AuditLog format)
```

Resolution = fetch `names/<handle>.json`, verify the self-signature,
check the event log for deactivation. Anyone can mirror or fork the whole
namespace — portability is structural, not a feature.

### Operations (CRUD)

| DID op | Registry event | Rule |
|---|---|---|
| Create | `claimed` | file must not exist; manifest version 1 |
| Update | `updated` | same root key; version increments by exactly 1 |
| Revoke token | `token_revoked` | root-key-signed |
| Deactivate | `deactivated` | root-key-signed; handle stops resolving |

Every event detail carries an Ed25519 signature by the handle's root key
over `{event, handle, body}`. The log itself is hash-chained (SHA-256,
genesis `0…0`), so tampering, reordering, or deletion breaks verification.

### CI gate

`Registry.verify()` (CLI: `verify-registry`) checks, fully offline:
hash chain intact → every manifest self-verifies → every event signature
valid → every manifest has a claim event → no duplicate claims → root-key
continuity per handle. A namespace repo runs this on every pull request;
claims merge only if the whole registry still verifies.

## 4. Utility: capability-scoped delegation

The namespace's novelty: a handle is a **verifiable authority root**.

```
root key of @adam
   │ signs
   ▼
CapabilityToken { subject: "cal@adam", subject_public_key,
                  permissions: ["ping:send"], expires_at, … }
   │ held by
   ▼
any agent runtime, anywhere ──signed request──► verifier
                                                 │ resolves registry only
                                                 ▼
                       "this really acts for @adam, with exactly these
                        permissions, not expired, not revoked"
```

Deny by default: an unlisted permission is refused. Revocation is a
root-signed registry event; verifiers see it on the next resolution.

## 5. Ping: agent-to-agent messages

A ping is signed by the delegated subject key and carries its token.
Verification (registry-only, no platform): token chain → body hash →
timestamp freshness (±300 s) → nonce replay check → subject signature.
Delivery transport is out of scope; the recipient's webhook lives in the
manifest `services`.

## 6. Move (portable identity)

`move` exports a bundle: manifest + private key + the handle's full event
history. Because the registry is forkable and the manifest self-certifies,
a new host needs nothing from the old one. Endpoint changes are ordinary
signed `updated` events.

## 7. Security considerations

- Private keys never enter the registry; the CLI keystore writes 0600 files.
- Registry hosts are untrusted: they can withhold data (availability) but
  cannot forge manifests, events, tokens, or pings (integrity).
- Key compromise = handle compromise; mitigations (recovery ceremonies,
  key rotation events, witness receipts) are future work inherited from
  atHome's design.
- Squatting is governed at the repo layer (PR review / rate limits), not
  in the protocol.

## 8. What was deliberately dropped from handle

Firecracker microVMs, mail gateway (MX/SPF/DKIM), `adam://` object storage,
quota/billing packages, Stripe — everything that forces charging money.
The name, the receipts, the delegation, and the portability remain, at $0.
