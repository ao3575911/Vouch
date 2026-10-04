# Repo transfer checklist: SM260845 → ao3575911

Copilot follows your **account**, not the repo. After transfer, `SM260845`
(who holds the Copilot sub) keeps full Copilot access as a collaborator.
GitHub auto-redirects the old repo URL.

1. **Transfer** (from SM260845): Settings → Danger Zone → Transfer
   ownership → enter `ao3575911`. Accept from that account.
2. **Collaborator** (from ao3575911): Settings → Collaborators → add
   `SM260845` with **Write** (or Admin) access.
3. **Verify Copilot** (from SM260845): open chat on
   `ao3575911/capgate`, assign a trivial task to the coding agent.
4. **Local remotes**: `git remote set-url origin
   git@github.com:ao3575911/capgate.git` (redirects work, be explicit).
5. **Rename at the same time** (optional, one redirect for both moves):
   branding is **Vouch** — rename `capgate` → `vouch` during transfer.
6. **Post-transfer**: re-check Actions are enabled and CI (ruff + pytest)
   is green; re-enable branch protection if used.
