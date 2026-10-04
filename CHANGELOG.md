# Changelog

Versions follow [SemVer](https://semver.org). Each version is a `vX.Y.Z` tag and a GitHub Release.

## Unreleased

- Proof verification pins the key to the registry (`verify_proof_for_handle`); `web/verify.html` shows "unpinned" without a manifest.
- `Registry.resolve()` checks the manifest key against the event log; the OIDC bridge verifies the registry at startup.
- OIDC bridge: integer `issued_at` with skew limits, expiring nonces and state caps, threaded server with timeouts, URL-encoded redirect, `--trusted-proxy`.
- Browser and Python canonical JSON agree for non-ASCII, with shared test vectors.
- Distribution renamed to `vouch-id`; import name and CLI stay `vouch`. Scope recorded in `docs/adr-0001-scope.md`; capgate docs moved to `docs/capgate.md`.

## v0.2.0 (2026-10-04)

- Rebrand to Vouch: plain-language CLI, mission README, Plan B strategy doc.
- did:home namespace: manifests, static registry, delegation, ping, CLI.
- Plan B steps 2–5: OIDC bridge, offline verifier and proof cards, social recovery.
- Merged handle and atHome projects.
- Governance: CODEOWNERS, issue and PR templates, SECURITY.md, THREATMODEL.md.

## v0.1.0 (2026-09-23)

- Phase 0/1 spine: contract, policy, permit, audit, harness/executor, adversarial tests.
- CI `GITHUB_TOKEN` restricted to `contents: read`.
