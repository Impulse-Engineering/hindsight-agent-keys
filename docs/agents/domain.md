# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Where they live

This repo has no glossary or ADRs of its own. They live in **`Impulse-Engineering/aseva-foundation-hosting`**:

- **`CONTEXT.md`** at that repo's root: the glossary.
- **`docs/adr/`**: the ADRs. ADR 0002 (`0002-hindsight-self-issued-agent-keys.md`) is the design for this repo.

Read them without cloning:

```sh
gh api repos/Impulse-Engineering/aseva-foundation-hosting/contents/CONTEXT.md --jq .content | base64 -d
gh api repos/Impulse-Engineering/aseva-foundation-hosting/contents/docs/adr --jq '.[].name'
gh api repos/Impulse-Engineering/aseva-foundation-hosting/contents/docs/adr/<file> --jq .content | base64 -d
```

## Before exploring, read these

- **`CONTEXT.md`** (foundation repo).
- **`docs/adr/`** (foundation repo): read ADRs that touch the area you're about to work in.

Do not create `GLOSSARY.md`, `CONTEXT.md` or `docs/adr/` in this repo. New terms and decisions go to the foundation repo (via `/domain-modeling` there, or a PR against it).

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md`. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal: either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0002 (self-issued agent keys), but worth reopening because…_
