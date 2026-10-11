# Agents

- **Tickets and design** live in `Impulse-Engineering/aseva-foundation-hosting`: parent issue #697, ADR 0002 and the glossary (`CONTEXT.md`) there. Commit messages use `Refs Impulse-Engineering/aseva-foundation-hosting#<n>`.
- **Upstream source** is in the pinned image, not on PyPI. The package sits at `/app/api/hindsight_api` (not `site-packages`). Read it with `docker run --rm --entrypoint sh "$(scripts/upstream-ref.sh)" -c '<read-only command>'`.
- **Tests and CI:** README "Tests" and "CI and publishing". CI on the PR is the full gate.
- **Review rules:** `CODING_STANDARDS.md`.
