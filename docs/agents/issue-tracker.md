# Issue tracker: GitHub

Issues and specs for this repo live as GitHub issues in **`Impulse-Engineering/aseva-foundation-hosting`**, not in this repo. Use the `gh` CLI for all operations. Every `gh issue` command below carries `-R Impulse-Engineering/aseva-foundation-hosting`; keep it when you adapt one. Do not infer the repo from `git remote -v`: the remote is `hindsight-agent-keys`. Pull requests stay in this repo.

Parent issue for this component: #697. Commit messages reference tickets as `Refs Impulse-Engineering/aseva-foundation-hosting#<n>`.

## Conventions

- **Create an issue**: `gh issue create -R Impulse-Engineering/aseva-foundation-hosting --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> -R Impulse-Engineering/aseva-foundation-hosting --json number,title,body,state,labels,comments --jq '{number, title, body, state, labels: [.labels[].name], comments: [.comments[].body]}'`
- **List issues**: `gh issue list -R Impulse-Engineering/aseva-foundation-hosting --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> -R Impulse-Engineering/aseva-foundation-hosting --body "..."`
- **Apply / remove labels**: `gh issue edit <number> -R Impulse-Engineering/aseva-foundation-hosting --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close <number> -R Impulse-Engineering/aseva-foundation-hosting --comment "..."`

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external PRs as feature requests; `/triage` reads this flag.)_

When set to `yes`, PRs run through the same labels and states as issues, using the `gh pr` equivalents (these run against this repo, so no `-R`):

- **Read a PR**: `gh pr view <number> --comments` and `gh pr diff <number>` for the diff.
- **List external PRs for triage**: `gh pr list --state open --json number,title,body,labels,author,authorAssociation,comments` then keep only `authorAssociation` of `CONTRIBUTOR`, `FIRST_TIME_CONTRIBUTOR`, or `NONE` (drop `OWNER`/`MEMBER`/`COLLABORATOR`).
- **Comment / label / close**: `gh pr comment`, `gh pr edit --add-label`/`--remove-label`, `gh pr close`.

Issues and PRs are in different repos, so a bare `#42` is ambiguous: a ticket reference means the foundation repo's issue (`gh issue view 42 -R Impulse-Engineering/aseva-foundation-hosting`), a PR reference means this repo's PR (`gh pr view 42`).

## When a skill says "publish to the issue tracker"

Create a GitHub issue in `Impulse-Engineering/aseva-foundation-hosting` (the create command above).

## When a skill says "fetch the relevant ticket"

Run the read command above.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a single issue with **child** issues as tickets.

- **Map**: a single issue labelled `wayfinder:map`, holding the Notes / Decisions-so-far / Fog body. `gh issue create -R Impulse-Engineering/aseva-foundation-hosting --label wayfinder:map ...`.
- **Child ticket**: an issue linked to the map as a GitHub sub-issue: `gh issue edit <map> -R Impulse-Engineering/aseva-foundation-hosting --add-sub-issue <child>`. Labels: `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`). Once claimed, the ticket is assigned to the driving dev.
- **Blocking**: GitHub's native issue dependencies: `gh issue edit <child> -R Impulse-Engineering/aseva-foundation-hosting --add-blocked-by <blocker>`. A ticket is unblocked when every blocker is closed.
- **Frontier query**: `gh issue view <map> -R Impulse-Engineering/aseva-foundation-hosting --json subIssues --jq '.subIssues.nodes[] | select(.state == "OPEN") | .number'` lists the open children in map order. For each, `gh issue view <child> -R Impulse-Engineering/aseva-foundation-hosting --json assignees,blockedBy --jq '{assignees: [.assignees[].login], open_blockers: [.blockedBy.nodes[] | select(.state == "OPEN") | .number]}'`; drop any with an assignee or an open blocker. First remaining wins.
- **Claim**: `gh issue edit <n> -R Impulse-Engineering/aseva-foundation-hosting --add-assignee @me`, the session's first write.
- **Resolve**: `gh issue comment <n> -R Impulse-Engineering/aseva-foundation-hosting --body "<answer>"`, then `gh issue close <n> -R Impulse-Engineering/aseva-foundation-hosting`, then append a context pointer (gist + link) to the map's Decisions-so-far.
