# Threat Model (High-Level)

## Assets

- Signing keys for permits and identities
- Contract/policy definitions
- Capability-bound tool invocations
- Hash-chained audit logs

## Primary threats

1. Unauthorized tool execution
2. Permit replay or tampering
3. Identity/key substitution
4. Audit-log rewriting or deletion
5. Overly broad delegation and escalation

## Mitigations

- Deny-by-default policy evaluation
- Ed25519-signed, single-use permits with expiry and call-hash binding
- Offline-verifiable hash-chained audit trail
- Explicit capability scoping and non-transitive delegation defaults
- Adversarial tests in CI
- Optional Unix-socket isolation boundary: the trusted harness retains the
  signing key, executor, audit log, and tool implementations; the agent can
  send only bounded proposals.
- Hostile-agent demo disables container networking and drops Linux
  capabilities.

## Residual risks

- Misconfiguration of repository protections
- Compromised maintainer credentials
- Incomplete rollout of branch/ruleset enforcement
- Container isolation relies on the host kernel and Docker daemon; it does not
  protect against their compromise, a compromised harness, or unsafe
  registered tools.
