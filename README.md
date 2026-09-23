# capgate

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
