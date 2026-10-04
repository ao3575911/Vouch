# Repository hygiene bootstrap backlog

Prepared to open and track the first community/governance work items.

Status (4 Oct 2026): items 2, 3, 4 and 5 are done (CONTRIBUTING.md, the
3.10-3.12 CI matrix, pre-commit, and OIDC rate limiting in #8). Item 1 is
#21, item 6 is #22, the starter discussions are #23. Labels and topics below
are applied. The rest of the backlog lives in GitHub issues.

## Issues to open (6)

1. **Enforce CODEOWNERS review on `main`**
   - Labels: `governance`, `security`, `priority:p0`
   - Milestone: Hygiene
   - Owner: `@SM260845`
   - Definition of done:
     - `.github/settings.yml` requires CODEOWNERS review and >=1 approval
     - docs and settings are consistent
     - CI green and PR references commit SHA/tag

2. **Add CONTRIBUTING.md with workflow + security reporting**
   - Labels: `documentation`, `governance`, `priority:p1`
   - Milestone: DX/Onboarding
   - Owner: `@SM260845`
   - Definition of done:
     - `CONTRIBUTING.md` added and linked from README
     - includes local checks and PR expectations
     - CI green and PR references commit SHA/tag

3. **Expand CI matrix to Python 3.10–3.12**
   - Labels: `ci`, `priority:p1`
   - Milestone: Hygiene
   - Owner: `@SM260845`
   - Definition of done:
     - `.github/workflows/ci.yml` tests 3.10, 3.11, 3.12
     - all matrix jobs pass
     - PR references commit SHA/tag

4. **Add optional pre-commit hooks (`ruff`, pytest smoke)**
   - Labels: `ci`, `documentation`, `priority:p2`
   - Milestone: DX/Onboarding
   - Owner: `@SM260845`
   - Definition of done:
     - `.pre-commit-config.yaml` added
     - dev docs include setup/use
     - CI green and PR references commit SHA/tag

5. **OIDC abuse controls: basic rate limiting**
   - Labels: `security`, `enhancement`, `priority:p1`
   - Milestone: OIDC hardening
   - Owner: `@SM260845`
   - Definition of done:
     - rate limits for `/authorize`, `/token`, `/userinfo`
     - tests for limit enforcement
     - CI green and PR references commit SHA/tag

6. **Define MVP roadmap milestones aligned to Plan B**
   - Labels: `roadmap`, `governance`, `priority:p2`
   - Milestone: Plan-B milestones
   - Owner: `@SM260845`
   - Definition of done:
     - milestones created and described
     - key issues mapped to milestones
     - PR references commit SHA/tag where relevant

## Discussions to create

1. **Welcome / Start Here** (Announcements, pinned)
   - Purpose: onboarding, where to start, contribution links
2. **Roadmap feedback (OIDC, passkey, recovery priorities)** (Ideas)
3. **Q&A: setup, proofs, and verifier usage** (Q&A)

## Labels to ensure

Keep: `bug`, `enhancement`, `documentation`, `good first issue`, `help wanted`, `question`, `invalid`, `duplicate`, `wontfix`, `accessibility`.

Add/ensure: `security`, `ci`, `governance`, `roadmap`, `needs-triage`, `blocked`, `priority:p0`, `priority:p1`, `priority:p2`.

## Repository topics/tags to ensure

`identity`, `did`, `self-sovereign-identity`, `oidc`, `ed25519`, `offline-verification`, `security`, `python`, `privacy`.

## First week sequence

- **Day 1:** governance alignment, labels/topics, welcome discussion (pinned)
- **Day 2:** CONTRIBUTING + CI matrix
- **Day 3+:** OIDC hardening + roadmap/milestones
