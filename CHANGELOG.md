# Changelog

Versions follow [SemVer](https://semver.org). Each version is a `vX.Y.Z` tag and a GitHub Release.

## Unreleased

- Key files are created 0600 atomically. Optional passphrase (`--passphrase` or `VOUCH_ID_PASSPHRASE`) encrypts keys, the recovery key and takeout bundles. `takeout --without-key`.
- The browser verifier is hosted at https://ao3575911.github.io/vouch-id/verify.html and ships in the wheel. It now checks the pasted manifest's signature, not just its key. Cards and the CLI point at it.

## v0.3.1 (2026-10-04)

- Releases attach the wheel and sdist, so you can install from GitHub without PyPI. The PyPI upload in `publish.yml` is off for now.
- README cut to one screen with flow diagrams; the detail moved to a docs site in `docs/` (GitHub Pages).
- Packaging for PyPI: SPDX licence, project URLs and classifiers; README links work on PyPI; trusted-publishing workflow (`publish.yml`).

## v0.3.0 (2026-10-04)

- **Breaking:** the CLI command is now `vouch-id` (was `vouch`), e.g. `vouch-id get @adam`. There is no `vouch` alias. The import package stays `vouch`.
- Repo renamed to `ao3575911/vouch-id`. GitHub redirects the old URLs.
- Proof verification pins the key to the registry (`verify_proof_for_handle`); `web/verify.html` shows "unpinned" without a manifest.
- `Registry.resolve()` checks the manifest key against the event log; the OIDC bridge verifies the registry at startup.
- OIDC bridge: integer `issued_at` with skew limits, expiring nonces and state caps, threaded server with timeouts, URL-encoded redirect, `--trusted-proxy`.
- Browser and Python canonical JSON agree for non-ASCII, with shared test vectors.
- Distribution renamed to `vouch-id`; import name stays `vouch`. Scope recorded in `docs/adr-0001-scope.md`; capgate docs moved to `docs/capgate.md`.

## v0.2.0 (2026-10-04)

- Rebrand to Vouch: plain-language CLI, mission README, Plan B strategy doc.
- did:home namespace: manifests, static registry, delegation, ping, CLI.
- Plan B steps 2–5: OIDC bridge, offline verifier and proof cards, social recovery.
- Merged handle and atHome projects.
- Governance: CODEOWNERS, issue and PR templates, SECURITY.md, THREATMODEL.md.

## v0.1.0 (2026-09-23)

- Phase 0/1 spine: contract, policy, permit, audit, harness/executor, adversarial tests.
- CI `GITHUB_TOKEN` restricted to `contents: read`.
