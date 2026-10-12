# Agents

- **Tickets and design** live in `Impulse-Engineering/aseva-foundation-hosting`: parent issue #697, ADR 0002 and the glossary (`CONTEXT.md`) there. Commit messages use `Refs Impulse-Engineering/aseva-foundation-hosting#<n>`.
- **Upstream source** is in the pinned image, not on PyPI. Read it as plain files under the path `scripts/upstream-src.sh` prints (`.upstream/<version>-<digest prefix>/hindsight_api`, gitignored; the script needs Docker once, and readers without Docker use the copy it left).
- **Conductor operations:** `docs/cutover.md`. The platform's own docs are in aseva-foundation-hosting `conductor/docs/`.
- **Tests and CI:** README "Tests" and "CI and publishing". CI on the PR is the full gate.
- **Merge bar:** the `protect-main` ruleset (a ruleset, so the branch-protection API returns 404) requires a PR, code-owner review and the `test` and `scan` checks.
- **Review rules:** `CODING_STANDARDS.md`.

## Agent skills

### Issue tracker

GitHub issues in `Impulse-Engineering/aseva-foundation-hosting` (always `gh ... -R`); PRs stay here. See `docs/agents/issue-tracker.md`.

### Triage labels

The five defaults (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`), already defined in the tracker repo. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context, held in the foundation repo (`CONTEXT.md` + `docs/adr/`); none in this repo. See `docs/agents/domain.md`.
