---
title: capgate
nav_order: 11
---

# capgate

A separate product that shares this repo for now. It moves to its own repo
in issue #15.

**Research preview — not production-grade.** Fail-closed capability-token MCP tool gate.
The isolated Unix-socket gateway and hostile-agent Docker demo are exercised
in CI; they do not by themselves establish production readiness.

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

Spec: [Concepts](concepts.md). Code:
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

## Isolated demo

The in-process harness/executor remains the reference API. `capgate.isolation`
adds an IPC boundary for untrusted proposals: the agent sends bounded tool and
argument JSON over a Unix-domain socket, while the trusted service assigns the
contract's agent identity and owns the contract, signing key, audit log,
executor, and registered tools. The service evaluates each proposal and
executes only an explicitly permitted tool call. Signed permits and key
material are never returned to the agent.

Run the hostile-agent demo from the repository root:

```bash
docker compose -f examples/hostile-agent-demo/compose.yml build
docker compose -f examples/hostile-agent-demo/compose.yml up \
  --detach --wait harness
docker compose -f examples/hostile-agent-demo/compose.yml run \
  --rm --no-deps hostile-agent
docker compose -f examples/hostile-agent-demo/compose.yml down --volumes
```

The agent container has no network interface, runs read-only with all Linux
capabilities dropped, has no-new-privileges enabled, and receives the private
IPC volume read-only. The demo verifies that an allowed, constrained tool call
executes in the harness; an unknown tool is denied; a caller-supplied identity
field is rejected; and direct public-network access fails.

### Boundary and limitations

- The IPC request is one JSON object, limited to 64 KiB, with duplicate keys
  rejected. The server processes one connection at a time.
- The socket is mode `0666`; its protection depends on placing it in a
  dedicated directory/volume shared only with the untrusted agent. Do not put
  it in a generally accessible host directory.
- Each socket represents one contract identity. The caller cannot choose its
  audit identity. Use a distinct protected socket for each agent; this protocol
  does not authenticate multiple principals sharing one socket.
- This is process/container isolation, not a defense against a compromised
  host, Docker daemon, kernel, harness, or registered tool.
- The demo is not a general-purpose remote tool runner. Keep tool registration
  explicit and treat every registered tool as trusted code.
- CI exercises this Docker configuration. Deployment-specific hardening,
  independent security review, and recovery/operational procedures are still
  required before any production-readiness claim.

## Status

- [x] Phase 0 — contract schema, permit format, hash-chained audit
- [x] Phase 1 — harness/executor split (in-process reference implementation)
- [ ] Phase 1 — process/network isolation (agent egress limited to the harness proxy)
- [x] Phase 2 — adversarial test suite
- [x] Phase 1 — Unix-socket process boundary; agent network egress disabled in the demo
- [x] Phase 2 — docker compose demo with hostile agent + restrictive container policy
- [ ] Phase 3 — production claim (requires independent security review and operational readiness)

Kill list: no dashboards, no extra agents, no "AI policy" layer. Nothing
ships unless it moves the enforcement boundary.
