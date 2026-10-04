---
title: Maintainers
nav_order: 13
---

# Maintainers

## Development

Setup and the PR workflow are in [`CONTRIBUTING.md`](https://github.com/ao3575911/vouch-id/blob/main/CONTRIBUTING.md).

```bash
git clone https://github.com/ao3575911/vouch-id.git && cd vouch-id
pip install -e ".[dev]"
ruff check src tests
pytest -v
node tests/js/verify_vectors.mjs   # browser verifier against shared vectors, Node 22+
```

## Versioning and releases

- [SemVer](https://semver.org) tags, `vX.Y.Z`. History in [`CHANGELOG.md`](https://github.com/ao3575911/vouch-id/blob/main/CHANGELOG.md).
- To release, bump `version` in `pyproject.toml` in a PR. Merging it to `main`
  runs `release.yml`, which creates the tag and a GitHub Release.
- `release.yml` then builds the sdist and wheel from the tag and attaches them
  to the release. Re-running it (`gh workflow run release.yml`) attaches them
  if they're missing.
- After a release, update the version in the install lines in `README.md`,
  `docs/index.md` and `docs/cli.md`.
- PyPI upload is off for now: the `pypi` job in `publish.yml` has `if: false`.
  To switch it on, add a trusted publisher on PyPI (project `vouch-id`, repo
  `ao3575911/vouch-id`, workflow `publish.yml`, environment `pypi`), remove the
  `if: false`, then run `gh workflow run publish.yml -R ao3575911/vouch-id -f tag=vX.Y.Z`.
- Every tag points at an exact commit, so `vX.Y.Z` is the trace reference for
  issues and PRs.

## Governance files

- CODEOWNERS: [`.github/CODEOWNERS`](https://github.com/ao3575911/vouch-id/blob/main/.github/CODEOWNERS)
- Contributors: [`CONTRIBUTORS.md`](https://github.com/ao3575911/vouch-id/blob/main/CONTRIBUTORS.md)
- Security policy: [`SECURITY.md`](https://github.com/ao3575911/vouch-id/blob/main/SECURITY.md)
- Threat model: [`THREATMODEL.md`](https://github.com/ao3575911/vouch-id/blob/main/THREATMODEL.md)
- PR template: [`.github/pull_request_template.md`](https://github.com/ao3575911/vouch-id/blob/main/.github/pull_request_template.md)
- Issue templates: [`.github/ISSUE_TEMPLATE/`](https://github.com/ao3575911/vouch-id/tree/main/.github/ISSUE_TEMPLATE)
- Copilot instructions: [`.github/copilot-instructions.md`](https://github.com/ao3575911/vouch-id/blob/main/.github/copilot-instructions.md)
- Settings as code: [`.github/settings.yml`](https://github.com/ao3575911/vouch-id/blob/main/.github/settings.yml)
- Social preview: [`.github/assets/social-preview.svg`](https://github.com/ao3575911/vouch-id/blob/main/.github/assets/social-preview.svg), uploaded in repo settings

## Repo history

- Started as `SM260845/capgate`, transferred to `ao3575911`, renamed to
  `vouch`, then to `vouch-id` (Oct 2026). GitHub redirects the old URLs, but
  point local remotes at `https://github.com/ao3575911/vouch-id.git`.
- `SM260845` stays on as a collaborator and code owner, and keeps Copilot
  access through their own account.
- After a transfer or rename, check Actions are enabled, CI is green and the
  `main` ruleset still applies.

## Hygiene backlog

The bootstrap backlog from Oct 2026 is done or tracked: CONTRIBUTING, the
3.10-3.12 CI matrix, pre-commit and OIDC rate limiting (#8) shipped;
settings.yml and the docs match the ruleset (#21), roadmap milestones #22, starter discussions #23.
The rest lives in GitHub issues.

- Labels: `bug`, `enhancement`, `documentation`, `good first issue`,
  `help wanted`, `question`, `invalid`, `duplicate`, `wontfix`,
  `accessibility`, `security`, `ci`, `governance`, `roadmap`, `needs-triage`,
  `blocked`, `priority:p0`, `priority:p1`, `priority:p2`.
- Topics: `identity`, `did`, `self-sovereign-identity`, `oidc`, `ed25519`,
  `offline-verification`, `security`, `python`, `privacy`.
