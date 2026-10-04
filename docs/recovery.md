# Social recovery & guardianship spec

Recovery = people, not helpdesks. N trusted guardians can restore a lost
name; a parent can issue a scoped child identity. Everything verifies
offline against the registry's event log — deny by default.

## Events

| Event | Signed by | Body |
|---|---|---|
| `guardians_set` | current root key | `{guardians: [handles], threshold: M}` |
| `recovered` | **new** root key | `{new_root_public_key, prior_root_public_key, approvals}` |

Guardians must be claimed, active handles in the same registry; a handle
cannot be its own guardian; `1 <= threshold <= len(guardians)`.

## Approval

Each guardian signs the canonical JSON payload

```
{"event":"recover","handle":H,"new_root_public_key":NEW,"prior_root_public_key":PRIOR}
```

with their own root key: `{guardian: handle, signature: hex}`. Binding
both PRIOR and NEW keys makes approvals single-purpose — they cannot be
replayed for any other rotation.

## Ceremony (CLI)

```bash
vouch guardians @adam @sam @kim --threshold 2   # while you still hold the key
vouch recover-start @adam                       # lost it: new keypair, prints pub
vouch approve-recovery @sam @adam --new-public-key <hex>
vouch approve-recovery @kim @adam --new-public-key <hex>
vouch recover @adam --approval sam.approval.json --approval kim.approval.json
vouch audit                                      # whole log re-verifies offline
```

`recover` checks ≥ M distinct declared guardians with valid signatures,
appends the `recovered` event (signed by the new key), and re-signs the
manifest with the new root key (version +1).

## Offline verification

`Registry.verify()` tracks each handle's root key *as of each event*:
claim-time key is reconstructed from the first `recovered` event's prior
key; every event signature is checked against the then-current key; a
`recovered` event is accepted only if the prior key matches, a guardian
policy was previously declared, and the embedded approvals meet the
threshold using the guardians' then-current root keys. Final manifests
must match the final tracked key.

Threat cases covered by `tests/test_recovery.py`: below threshold,
duplicate guardian, non-guardian signer, forged signature, approval
replay for a second rotation, recovery with no declared guardians.

## Guardianship (child identities)

A parent mints a scoped child identity through the existing
permission-slip machinery (`issue_child_identity`): the child gets its
own key and an explicit permission list (default `ping:send`), revocable
by the parent at any time via the normal token-revocation event.
