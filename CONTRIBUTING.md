# Contributing to Vouch

Thanks for contributing.

## Development setup

```bash
git clone https://github.com/ao3575911/vouch-id.git && cd vouch-id
pip install -e ".[dev]"
```

Optional local guardrails:

```bash
pre-commit install
pre-commit run --all-files
```

## Local checks (required before PR)

```bash
ruff check src tests
pytest -v
```

## Branching and pull requests

- Create a focused branch per change.
- Keep commits reviewable and scoped.
- Open a pull request against `main`.
- GitHub requests CODEOWNERS review automatically; it isn't required to merge.
- Reference exact commit SHA/tag when relevant.

## Security and vulnerability reporting

- Do **not** file public issues for vulnerabilities.
- Use private reporting: `Security > Advisories` in GitHub.
- Include impact, reproduction, and affected commit SHA/tag.

## Repository hygiene checklist

- Branch protection/ruleset keeps:
  - pull request required, 0 approvals, no required code-owner review
  - required status check `test`, branch up to date
  - squash merge only, linear history, no bypass
- Release tag hygiene:
  - tags are created by `.github/workflows/release.yml`
  - release tags follow `vX.Y.Z`
