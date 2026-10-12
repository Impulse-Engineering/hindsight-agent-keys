# hindsight-agent-keys

A container image of [Hindsight](https://github.com/vectorize-io/hindsight) (by Vectorize) with a tenant extension that gives each caller only the memory its key allows.

It knows three kinds of key:

- The **legacy key**, the deployment's existing shared key. It reaches the **Public Team**, whose banks live in the Postgres `public` schema.
- **Personal Agent Keys**, which people create for themselves on the key page (below). Each reaches only its owner's own schema.
- **Team keys**, which members create on the Teams page (below). Each reaches only its Team's schema, and only while its holder is in the Team. A Public Team key reaches `public`.

Every other key, and a request with no key, gets 401 on the API and on MCP. There is one exception. Upstream answers an MCP `GET` with no session ID before authentication runs: it is the handshake probe some clients send, and it returns `200 {}` with no data.

Upstream serves these routes without a key, and they carry no memory data: `/health`, `/health/ready`, `/health/live`, `/version`, `/metrics`, `/v1/bank-template-schema`, `/docs`, `/redoc` and `/openapi.json`. Upstream also mounts our key pages under `/ext` without authentication; the extension gates them itself.

## What the image adds to upstream

- **The tenant extension** `hindsight_agent_keys.extension:AgentKeysTenantExtension`.
  - It lists `public` first, then every personal and Team schema, so startup migrates them all and the worker processes them (`public` also because of upstream issue #5400). If the database cannot be read when Hindsight starts, startup fails rather than skip a schema; later, the worker keeps the last list it had.
  - Banks cannot switch on upstream audit logging.
  - Refused keys go to its own event log. Each row holds the key ID (never the secret), the client IP and the time. Each client (an IPv4 address, or an IPv6 /64) gets at most one row a minute, whatever the event. All clients together get at most 60 refusal rows a minute, plus one `refusal_log_saturated` row when that budget runs out. The limits apply per API process.
- **The key pages** `hindsight_agent_keys.web:AgentKeysHttpExtension`, under `/ext` (see "Personal Agent Keys", "The Key Allowlist" and "Teams").
- **Team tools for agents** `hindsight_agent_keys.tools:AgentKeysMcpExtension`, on both MCP endpoints (see "Teams over MCP").
- **A startup guard**, described in its own section below.
- **Safe defaults:** the UI is off, MCP is stateless, upstream audit logging is off, and the `X-Real-IP` header is passed through to the extension.

## Startup guard

The guard is the image's entrypoint, so it runs even when the command is overridden. It exits with status 78 before Hindsight starts, naming each problem, if any of these hold:

| Setting | Why it is refused |
| --- | --- |
| A `.env` file exists at `/app/api/.env`, `/app/.env` or `/.env` | Upstream loads the first one it finds over the process environment, after the guard has checked it. |
| `HINDSIGHT_API_TENANT_EXTENSION` is not ours | Without our extension Hindsight admits every request into `public`. |
| `HINDSIGHT_API_HTTP_EXTENSION` is not ours | Hindsight serves whatever another HTTP extension mounts at `/ext` without authentication, and without ours there are no key pages. |
| `HINDSIGHT_API_MCP_EXTENSION` is not ours | Another MCP extension would add its own tools to every MCP endpoint, and without ours agents cannot manage Teams. |
| `HINDSIGHT_API_MCP_AUTH_TOKEN` is set, even empty | It bypasses the tenant extension for MCP. |
| `HINDSIGHT_API_DATABASE_SCHEMA` is anything but `public` | The worker would skip the Public Team's background tasks. |
| `HINDSIGHT_ENABLE_CP` is not `false` | The bundled UI sends one shared key for every visitor. |
| `HINDSIGHT_API_AUDIT_LOG_ENABLED` is `true` | Unauthenticated requests would write into the Public Team's audit log. |
| `HINDSIGHT_API_MCP_STATELESS` is not `true` (read exactly as upstream reads it) | A stateful MCP session can keep a revoked key's identity. |

## Configuration

| Variable | Meaning |
| --- | --- |
| `HINDSIGHT_API_TENANT_LEGACY_KEY` | The legacy key. Without it every key is refused. Supply it as a secret. |
| `HINDSIGHT_API_TENANT_LEGACY_KEY_EXPIRES` | Optional ISO date or datetime (a bare date means midnight UTC). From then on the legacy key is refused. An unreadable value stops startup. |
| `HINDSIGHT_API_TENANT_KEY_PEPPER` | The server-side secret Agent Keys are hashed with, at least 32 bytes; a shorter value stops startup. Without it no key can be created and every Agent Key is refused; the legacy key still works. Changing it invalidates every Agent Key. Supply it as a secret. |
| `HINDSIGHT_API_TENANT_ACCESS_TEAM_DOMAIN` | The Cloudflare Access team URL, such as `https://<team>.cloudflareaccess.com` (Conductor's `CF_ACCESS_TEAM_DOMAIN`). It is the JWT issuer and serves the signing keys. |
| `HINDSIGHT_API_TENANT_ACCESS_AUD` | The Access application's AUD tag (Conductor's `CF_ACCESS_AUD`). It changes if the Access application is recreated. |
| `HINDSIGHT_API_TENANT_ACCESS_HOST` | The app's Access-protected hostname, such as `hindsight.internal.aseva.ai`. The key pages answer only on it. |
| `AGENT_KEYS_ADMIN_EMAILS` | Comma-separated emails of the bootstrap admins; case and spaces are ignored. They are always admins, so always on the Key Allowlist, and the admin page cannot change them. |

Without all three `ACCESS` settings the key pages refuse every request. Everything else is upstream Hindsight configuration, such as the LLM provider and its key.

Behind a proxy, set `X-Real-IP` to the real client address and overwrite any value the client sent. Otherwise the event log records whatever the client claims.

## Personal Agent Keys

A person on the Key Allowlist opens `https://<access host>/ext/`, names a key and creates it. Agents then send it as `Authorization: Bearer hsk_<id>_<secret>` on the bypass hostname, over the API and MCP.

- **Who:** the key pages trust only the Access JWT in `Cf-Access-Jwt-Assertion`. It must be RS256, signed by a key the team publishes, issued by the team URL, carry the AUD tag, and have `exp` and `iat`. The person is its `email`, lower-cased; no other claim is read. A token without `email` (a service token) is refused. Signing keys are fetched from the team and fetched again when a token names an unknown key ID, at most every 30 seconds.
- **Where:** only on `HINDSIGHT_API_TENANT_ACCESS_HOST`. Any other `Host`, including the bypass hostname, gets 404.
- **State changes** (anything but `GET`) also need `Content-Type: application/json`, the header `X-Agent-Keys: 1`, and `Origin: https://<access host>`; otherwise 403.
- **The key** has a 64-bit ID and a 256-bit secret. It is shown once. The database stores only HMAC-SHA256 of the whole key under the pepper, and a presented key is compared in constant time.
- **Limits:** each person can create 5 keys an hour and hold 10 active (neither revoked nor expired) keys. Both are counted in the database.
- **Schema:** a person's first key creates their schema, `p_` plus 16 random hex digits, never derived from their email, and migrates it before the key is shown. Every later key of theirs reaches the same schema.
- **Life:** every Agent Key, personal or Team, works for 90 days from its creation or its last renewal. The page lists the keys the person holds with their state; the owner can renew an unexpired key for 90 days from then, and revoke a key. A revoked or expired key cannot be renewed.
- **Sign-in:** a key also works only while its owner has signed in through Access within the last 30 days, so offboarding someone in the identity provider stops their keys without touching Hindsight. Every key page request is a sign-in, dated by when Access issued the token (its `iat`), not by when the page was loaded. Signing in again revives the keys.
- **Revoke identity:** an admin enters a person's email on `/ext/admin` to revoke every key that person holds. They can still create new keys while they are on the Key Allowlist; remove them from it as well to stop that.
- **When changes take effect:** there is no auth cache. Every request looks its key up, so a revocation, an expiry or a lapsed sign-in refuses the key's next request, including inside an MCP session that is already open (MCP is stateless).

Tables in `agent_keys`: `people` (email, schema, empty until the person's first personal key), `keys` (ID, HMAC, name, owner's email, schema, kind `personal` or `team`, and creation, expiry and revocation times), `sign_ins` (email, last Access sign-in), `allowlist` (email, role), `teams` (schema, name, creator's email), `members` (Team schema, email, role `owner` or `member`) and `member_requests` (Team schema, email, role asked for, who asked).

## The Key Allowlist

Only people on the Key Allowlist can create Agent Keys. The bootstrap admins in `AGENT_KEYS_ADMIN_EMAILS` are always on it; everyone else has a row in `agent_keys.allowlist` with the role `member`, `admin`, or `requested` (asked to join, not yet on the list).

- **Asking to join:** a signed-in person who is not on the list sees a button on `/ext/` that files a request. Asking again changes nothing.
- **Admins** (bootstrap admins and anyone granted admin rights) manage the list at `https://<access host>/ext/admin`: add people by email, approve or decline requests, grant and remove admin rights, and remove people. The same page revokes an identity (see "Personal Agent Keys"). Everyone else gets 403 on every `/ext/admin` route. The bootstrap admins cannot be changed there (409); edit the secret instead.
- **Removing someone** stops them creating keys and disables the keys they hold: every request with a key checks its owner is still on the list. Their keys are not deleted, so adding them back makes the keys work again.
- **Logging:** every change is an event (see "The event log").

## Teams

A Team is a named set of people who share one schema. A person on the Key Allowlist opens `https://<access host>/ext/teams`, the Teams page, which follows the same hostname, sign-in and state-change rules as the key page.

- **Creating:** the creator becomes the Team's first owner. The Team gets its own schema, `t_` plus 16 random hex digits, migrated before the Team is shown; the worker processes it like any other. Names are unique whatever their case, and `public` is reserved for the Public Team. Each person can create 10 Teams, counted in the database (429 after that).
- **Members:** owners add people by email, as a member or an owner, including people who have not signed in yet; they change roles and remove people. A change that would leave a Team without an owner is refused. Admins manage every Team and see every Team on the page, whether or not they are in it.
- **Pending requests:** people an agent asked to add over MCP are listed under their Team, with the role asked for and who asked. An owner or admin presses **Confirm** to give them that role, or **Decline** to drop the request and leave their place in the Team as it was.
- **Team keys:** a member on the Key Allowlist creates a Team key the same way as a personal key, with the same limits, which count personal and Team keys together. Membership is checked on every request, so removing a member stops their Team keys on their next request.
- **Public Team:** everyone on the Key Allowlist can create a Public Team key, which reaches the banks in `public`. The Public Team has no owners or members.

### Teams over MCP

Agents manage Teams with these tools, on the multi-bank endpoint `/mcp/` and on every single-bank endpoint `/mcp/<bank>/`. They act as the person whose personal Agent Key the agent sends, with that person's rights; a Team key, a Public Team key and the legacy key get an error from every one of them.

| Tool | What it does |
| --- | --- |
| `create_team(name)` | Creates a Team as on the Teams page, with the same limit. Returns its ID (`t_…`), which the other tools take as `team`. |
| `list_teams()` | The person's Teams (every Team for an admin), each with the person's role, its members and its pending requests. |
| `add_team_member(team, email, role)` | Files a pending request to make the person a `member` (the default) or an `owner`. Nobody gains access until an owner or admin confirms it on the Teams page. |
| `remove_team_member(team, email)` | Takes the person out of the Team; their Team keys stop on their next request. |

A refusal is answered as `{"error": "<reason>"}`, as upstream's own tools answer. Only owners and admins can file requests and remove people. A bank whose config sets `mcp_enabled_tools` hides every tool not named there, these included.

## The event log

Events go to `agent_keys.events` in Hindsight's own database. That schema sits outside upstream's migration history, so stock Hindsight still starts against the same database.

| Column | Meaning |
| --- | --- |
| `kind` | `key_refused`, `legacy_key_expired`, `refusal_log_saturated` (the 60-a-minute budget ran out; further refusals that minute were not recorded), `key_created`, `key_renewed`, `key_revoked`, `identity_revoked`, a Key Allowlist change: `access_requested`, `access_approved`, `access_declined`, `allowlist_added`, `allowlist_removed`, `admin_granted`, `admin_removed`, or a Team change: `team_created`, `owner_added` or `member_added` (the person was made an owner or a member, whether new to the Team or not), `owner_requested` or `member_requested` (an agent asked over MCP to make the person an owner or a member; nothing changed yet), `owner_confirmed` or `member_confirmed` (an owner or admin confirmed that request, so the person now has that role), `owner_declined` or `member_declined` (an owner or admin dropped that request), `member_removed` |
| `key_id` | `(missing)`, `(unrecognized)`, `(legacy)`, `(none)` (also `identity_revoked` and every Key Allowlist and Team change), or the `<id>` part of a presented, created, renewed or revoked `hsk_<id>_<secret>` key. Parenthesised values are reserved; a key's ID is never parenthesised. |
| `client_ip` | The `X-Real-IP` address in canonical form (an IPv4-mapped IPv6 address is stored as IPv4), or `NULL` if the header is missing or not an IP address |
| `email` | For `key_created`, `key_renewed` and `key_revoked`, the key's owner; for `identity_revoked`, the person whose keys were revoked; for a Key Allowlist or Team change, the person it concerns (for `team_created`, the creator); otherwise `NULL` |
| `actor` | For `identity_revoked`, the admin who revoked it; for a Key Allowlist or Team change, who made it: the admin or owner (for `*_requested`, the person whose personal key the agent used), or for `access_requested` the person asking; otherwise `NULL` |
| `team` | For a Team change and for a Team key's `key_created`, the Team's schema (`public` for the Public Team); otherwise `NULL` |

The extension connects to the database once, at startup. If that fails it logs a warning and records nothing until the next restart; refusals are still enforced.

## Tests

Unit tests run inside the pinned upstream image, which ships `hindsight_api` and pytest:

```sh
scripts/unit-tests.sh -v
```

Integration tests start the real container on Hindsight's mock LLM, so they need no credentials. They need Docker and pytest on the host:

```sh
docker build -t hindsight-agent-keys:test .
uv run --no-project --with pytest==9.0.3 pytest -p no:cacheprovider -c /dev/null --rootdir . tests/integration -v
```

Script tests run the release watcher in a scratch repository with fake `gh` and `docker`. They need git, jq and pytest on the host:

```sh
uv run --no-project --with pytest==9.0.3 pytest -p no:cacheprovider -c /dev/null --rootdir . tests/scripts -v
```

Lint runs the same script as CI. It needs ruff on PATH, shellcheck and Docker:

```sh
uv run --no-project --with ruff==0.17.0 scripts/lint.sh
```

Behind a TLS-inspecting proxy, the vulnerability scan needs that proxy's CA mounted into the Grype container (`SSL_CERT_FILE`).

## CI and publishing

- **Every PR:** lint (ruff, shellcheck, actionlint), script tests, unit tests, integration tests, and a Grype scan. The scan runs as a digest-pinned container against an exported image tar and blocks on critical vulnerabilities that have a fix.
- **On `main`:** an amd64 image is published to `ghcr.io/impulse-engineering/hindsight-agent-keys:<upstream version>-ak.<run>` (a re-run adds `.<attempt>`), with an SBOM, a GitHub build provenance attestation and a keyless cosign signature. A follow-up job then runs the integration tests and the scan against that exact digest. Approve a digest only once that job has passed.
- **Daily (upstream releases):** the `upstream-release` workflow reads upstream's latest GitHub Release, which is never a draft or a pre-release. If it is newer than the pin and has no PR yet, it opens one PR that pins `ghcr.io/vectorize-io/hindsight:<version>@<digest>` and links the release notes. A release overtaken by a newer one before the next run gets no PR. Closing a PR declines that release; reopen it to take the release up again. Only an exact `vX.Y.Z` release is followed, never a floating tag such as `latest` or `0.10`, or a `-slim` tag. A release tag that is not `vX.Y.Z` fails the run. GitHub holds CI on that PR until a maintainer selects **Approve workflows to run**. Nothing merges automatically; merging publishes the new image as above. It can also be started by hand from the Actions tab, on `main`.

All actions are pinned by commit SHA. Only the publish job can write packages. Only the `upstream-release` workflow can push branches and open PRs, and its own token is its only credential.

Verify a published image:

```sh
gh attestation verify oci://ghcr.io/impulse-engineering/hindsight-agent-keys@<digest> -R Impulse-Engineering/hindsight-agent-keys
cosign verify ghcr.io/impulse-engineering/hindsight-agent-keys@<digest> \
  --certificate-identity-regexp '^https://github.com/Impulse-Engineering/hindsight-agent-keys/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Moving a Conductor app onto the image

[docs/cutover.md](docs/cutover.md) is the runbook: back up pg0, upgrade to the stock release this image is built on, then swap the image while the bypass hostname is behind Access.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| The container exits with status 78 | The startup guard refused the configuration. Its stderr names each variable to fix. |
| Every request gets 401 | `HINDSIGHT_API_TENANT_LEGACY_KEY` is unset or different, or the legacy key has passed its expiry. |
| Background tasks in `public` never complete | `public` is missing from the tenant list. Check the startup logs for migration of `public`. |
| The key page answers 404 | The request's hostname is not `HINDSIGHT_API_TENANT_ACCESS_HOST`, or one of the three `ACCESS` settings is unset. |
| The key page answers 403 "Sign in through Cloudflare Access" | The Access JWT failed validation. Look for `agent-keys: refused an Access token` in the logs; a wrong or changed AUD tag is the usual cause. |
| Key creation answers 503 | `HINDSIGHT_API_TENANT_KEY_PEPPER` is unset. |
| A person's Agent Keys all get 401 at once | They were removed from the Key Allowlist (`allowlist_removed` in the event log). Adding them back restores the keys. |
| Every Agent Key gets 401 | The pepper was changed or removed. Agent Keys must be created again. |
| One person's Agent Key gets 401 | The key was revoked, it expired (90 days after its creation or last renewal), or its owner has not opened the key page for 30 days. The owner sees each key's state on the key page; opening the page revives keys held back by the 30-day rule. |
| A Team key gets 401 | Its holder is no longer in the Team. An owner can add them again; the key works again on its next request. |
| An agent added someone to a Team but they still have no access | Adding over MCP only files a request. An owner or admin must press **Confirm** under the Team on `/ext/teams`. |
| The Team tools are missing from an MCP endpoint | The bank's `mcp_enabled_tools` config does not list them. |
| The event log stays empty | The extension's database connection failed at startup. Look for `agent-keys` warnings in the logs, then restart the container. Refusals are still enforced. |

## License

MIT. Hindsight itself is MIT-licensed by Vectorize.
