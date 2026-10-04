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

## Residual risks

- Misconfiguration of repository protections
- Compromised maintainer credentials
- Incomplete rollout of branch/ruleset enforcement
