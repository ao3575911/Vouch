# Vouch

**Your name. Your key. Your proof.** A portable handle you own, login with
it, and statements anyone can check offline.

- **Handle**: `@adam` is `did:home:adam`, a self-signed manifest in a static,
  forkable registry with a signed, tamper-evident log. No account, no email,
  no phone number. Lost your key? Your guardians can recover it.
- **Login**: a small self-hostable OpenID Connect bridge that turns a signed
  login proof into an ID token. Reference implementation, not yet tested
  with real relying parties.
- **Signed statements**: proof cards checked offline on paper, in a browser
  or from the CLI. Nobody is called and nothing is logged.

What it isn't: a proof is a statement signed by your key. Nobody attests
that it's true, so Vouch can't prove your age or legal name and doesn't
replace government ID. Scope and reasons:
[`docs/adr-0001-scope.md`](./docs/adr-0001-scope.md). Background on the
digital-ID problem: [`docs/plan-b.md`](./docs/plan-b.md).

The Python distribution is `vouch-id` (`vouch` on PyPI is someone else's
project). It isn't published yet; install from a clone. The import name and
the CLI are `vouch`.

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

## Prove it anywhere

```bash
vouch card @adam                  # printable proof card (QR with pip install -e ".[qr]")
# open web/verify.html, paste the card's JSON and @adam's manifest -> green tick, offline
```

[`web/verify.html`](./web/verify.html) is a single static file — host it
on GitHub Pages or scan a paper card against it; nothing phones home.
Paste the handle's manifest from a registry copy you trust to pin the key.
Without it the page shows an amber "unpinned" result, because anyone can
sign a proof that names any handle. In Python, use
`verify_proof_for_handle(proof, registry)`.

## Login with Vouch (OIDC bridge)

Self-hostable OpenID Connect provider backed by did:home proofs. Today it
takes a POSTed login proof; the browser redirect flow that WordPress or
Nextcloud expect is not built yet (issue #13). Limits and deployment notes:
[`docs/oidc-deployment.md`](./docs/oidc-deployment.md).

```bash
python -m vouch.oidc --registry ./registry --client myapp=https://app/cb
vouch card @adam --json --statement "login:myapp"   # the login proof
# POST it to /authorize, exchange the code at /token -> EdDSA ID token
```

## Recovery = people, not helpdesks

```bash
vouch guardians @adam @sam @kim --threshold 2   # declare who can rescue you
vouch recover-start @adam                       # lost key? make a new one
vouch approve-recovery @sam @adam --new-public-key <hex>   # each guardian signs
vouch recover @adam --approval sam.approval.json --approval kim.approval.json
```

The rotation is recorded in the tamper-evident log and the whole ceremony
re-verifies offline (`vouch audit`). Guardianship: a parent issues a
scoped child identity with the same permission-slip machinery.

Maintainers: repo transfer checklist in [`docs/transfer.md`](./docs/transfer.md).
Isolated capgate demo: [`docs/isolation.md`](./docs/isolation.md). OIDC
deployment limits: [`docs/oidc-deployment.md`](./docs/oidc-deployment.md).

## Versioning and traceability

- [SemVer](https://semver.org) tags: `vX.Y.Z`. History in [`CHANGELOG.md`](./CHANGELOG.md).
- To release: bump `version` in `pyproject.toml` in a PR. Merging it to `main` creates the tag and a GitHub Release.
- Every tag points at an exact commit, so `vX.Y.Z` is the trace reference for issues and PRs.

## Repository governance and templates

- CODEOWNERS: [`.github/CODEOWNERS`](./.github/CODEOWNERS)
- Contributing guide: [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- Contributor guide: [`CONTRIBUTORS.md`](./CONTRIBUTORS.md)
- Security policy: [`SECURITY.md`](./SECURITY.md)
- Threat model: [`THREATMODEL.md`](./THREATMODEL.md)
- Pull request template: [`.github/pull_request_template.md`](./.github/pull_request_template.md)
- Issue templates: [`.github/ISSUE_TEMPLATE/`](./.github/ISSUE_TEMPLATE)
- Hygiene bootstrap backlog: [`docs/repo-hygiene-bootstrap.md`](./docs/repo-hygiene-bootstrap.md)
- Copilot repository instructions: [`.github/copilot-instructions.md`](./.github/copilot-instructions.md)
- Settings-as-code baseline: [`.github/settings.yml`](./.github/settings.yml)

Social preview asset: [`.github/assets/social-preview.svg`](./.github/assets/social-preview.svg) (set in repository settings).

## What's underneath

1. **did:home**: the identity namespace (manifests, registry, delegation,
   pings, recovery, proofs). Spec: [`docs/did-home-spec.md`](./docs/did-home-spec.md).
   The code lives in `src/capgate/didhome/` for now.
2. **capgate**: a fail-closed capability-token tool gate for AI agents. It
   shares the primitives (Ed25519, canonical JSON, hash-chained logs) but is
   a separate product and will move to its own repo (issue #15). Docs:
   [`docs/capgate.md`](./docs/capgate.md).

## Try it

```bash
pip install -e ".[dev]"
ruff check src tests
pytest -v
node tests/js/verify_vectors.mjs   # browser verifier, Node 22+
```
