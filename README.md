# Vouch

**Your name. Your key. Your proof.** A free Plan B to government digital ID.

Government digital ID: *they* check you against *their* database — and log
every check. Vouch: *you* prove it yourself. Nobody is called. Nothing is
logged. Nobody can switch you off.

```
 govt digital ID                     Vouch
 ───────────────────────────        ───────────────────────────
 you ──► their server ──► log       you ──► signed proof ──► ✓
        (tracked, revocable)             (offline, yours forever)
```

## Why a Plan B

| How digital ID traps you | How Vouch counters it |
|---|---|
| Mandatory for services (banking, benefits, age checks, login) | Verifier shim: services accept a Vouch proof wherever they accept ID assertions |
| Central register tracks every verification | Static, forkable registry; proofs verify **offline**, no phone-home |
| Phone-app monopoly | Works on paper (QR), browser, CLI — any device, no account |
| Network effect / default | Plugs into systems people already use ([roadmap](./docs/plan-b.md)) |
| Central revocation = social cutoff | You hold the keys; nobody can centrally disable your name |
| "Convenient" onboarding hooks you | 60-second claim: no signup, no email, no phone number |

Full strategy: [`docs/plan-b.md`](./docs/plan-b.md).

## Get your name in 3 steps

```bash
pip install -e .
vouch get @adam                 # 1. claim your name (makes your key)
vouch helper @adam cal ping:send  # 2. give a helper a permission slip
vouch audit                     # 3. prove the whole registry is untampered
```

Plain words everywhere: **name, key, helper, permission slip, prove,
vouch**. No jargon required to use it. (Technical alias:
`python -m capgate.didhome` — same engine, same commands.)

## What's underneath

Two layers, one set of audited primitives (Ed25519, canonical JSON,
hash-chained logs):

1. **did:home** — the identity namespace (manifests, registry, delegation,
   pings). Spec: [`docs/did-home-spec.md`](./docs/did-home-spec.md).
2. **capgate** — the fail-closed capability-token tool gate (internal
   engine, documented below).

---

# capgate (internal engine)

**Research preview — not production-grade.** Fail-closed capability-token MCP tool gate.

## Invariant

No tool invocation reaches an executor without a valid, signed, single-use
permit derived from a deterministic policy decision against a named contract.

The agent proposes; the harness authorizes; the executor acts. Unauthorized
actions are structurally unable to reach a tool — not "asked nicely not to."

## Architecture

```
agent (proposes) ──► harness (deterministic policy + Ed25519 permit signer + audit)
                          │
                     signed single-use permit
                          │
                          ▼
                     executor (verifies signature, nonce, call hash) ──► tool
```

- **Contract** (`src/capgate/contract.py`, `contracts/example.yaml`): names one
  agent identity, its capabilities (tool + argument constraints), approvers,
  a hard step budget, and allow/deny/escalate effects. Anything not named is
  denied. Delegation is non-transitive unless a capability explicitly
  escalates and names targets.
- **Policy** (`src/capgate/policy.py`): deterministic evaluation. No model in
  the decision path. Deny by default.
- **Permit** (`src/capgate/permit.py`): short-lived, single-use, Ed25519-signed;
  binds agent identity + canonical hash of the exact tool call + contract
  version. The signing key lives in the harness, never the agent process.
- **Audit** (`src/capgate/audit.py`): hash-chained, append-only JSONL. Any
  tamper, reorder, or deletion breaks the chain. Verifiable offline.
- **Harness** (`src/capgate/harness.py`): proposal → decision → permit → audit.
- **Executor** (`src/capgate/executor.py`): validates signature, expiry,
  single-use nonce, agent identity, and call hash before any tool runs.
  Holds tool credentials; the agent never sees them.

## did:home — free, local-first DID namespace for agents

Built on the same primitives (Ed25519, canonical JSON, hash-chained logs):
`@adam` → `did:home:adam`, a self-signed manifest in a static, forkable
registry. Utility = capability-scoped delegation (`cal@adam` acts for
`@adam` with exactly the granted permissions) + signed replay-proof pings.
No VM, no mail, no storage, no billing.

```bash
python -m capgate.didhome --registry ./registry claim @adam
python -m capgate.didhome --registry ./registry delegate @adam cal ping:send
python -m capgate.didhome --registry ./registry verify-registry
```

Spec: [`docs/did-home-spec.md`](./docs/did-home-spec.md). Code:
`src/capgate/didhome/` (manifest, registry, delegation, ping, cli).

## Try it

```bash
pip install -e ".[dev]"
ruff check src tests
pytest -v
```

The test suite is adversarial by design: unauthorized tools, permit replay,
expiry, argument tampering after authorization, forged permits, stolen
permits, delegation without escalation, step-budget exhaustion, and audit
chain tampering are all proven denied/detected.

## Status

- [x] Phase 0 — contract schema, permit format, hash-chained audit
- [x] Phase 1 — harness/executor split (in-process reference implementation)
- [ ] Phase 1 — process/network isolation (agent egress limited to the harness proxy)
- [x] Phase 2 — adversarial test suite
- [ ] Phase 2 — docker compose demo with hostile agent + network policy
- [ ] Phase 3 — production claim (blocked until the above pass in CI)

Kill list: no dashboards, no extra agents, no "AI policy" layer. Nothing
ships unless it moves the enforcement boundary.
