# hindsight-agent-keys

A container image of [Hindsight](https://github.com/vectorize-io/hindsight) (by Vectorize) with a tenant extension that gives each caller only the memory its key allows.

It knows three kinds of key:

- The **legacy key**, the deployment's existing shared key. It reaches the **Public Team**, whose banks live in the Postgres `public` schema.
- **Personal Agent Keys**, which people create for themselves on the key page (below). Each reaches only its owner's own schema.
- **Team keys**, which members create on the Teams page (below). Each reaches only its Team's schema, and only while its holder is in the Team. A Public Team key reaches `public`.

Every other key, and a request with no key, gets 401 on the API and on MCP. There is one exception. Upstream answers an MCP `GET` with no session ID before authentication runs: it is the handshake probe some clients send, and it returns `200 {}` with no data.

The same Dockerfile builds a second image, `hindsight-ui`, which runs upstream's web UI once per Team (see "The UI image").

Upstream serves these routes without a key, and they carry no memory data: `/health`, `/health/ready`, `/health/live`, `/version`, `/metrics`, `/v1/bank-template-schema`, `/docs`, `/redoc` and `/openapi.json`. Upstream also mounts our key pages under `/ext` without authentication; the extension gates them itself.

## What the image adds to upstream

- **The tenant extension** `hindsight_agent_keys.extension:AgentKeysTenantExtension`.
  - It lists `public` first, then every personal and Team schema, so startup migrates them all and the worker processes them (`public` also because of upstream issue #5400). If the database cannot be read when Hindsight starts, startup fails rather than skip a schema; later, the worker keeps the last list it had.
  - Banks cannot switch on upstream audit logging from now on. A bank that stored the setting under stock Hindsight, or brought it in through a bank import or clone, keeps it, but it has no effect: see "Safe defaults".
  - It writes its own event log (see "The event log"): refused keys and refused Delegated Requests, and every key, Key Allowlist and Team change. A refusal row holds the key ID (never the secret), the client IP and the time. Each client (an IPv4 address, or an IPv6 /64) gets at most one refusal row a minute, whatever the refusal. All clients together get at most 60 refusal rows a minute, plus one `refusal_log_saturated` row when that budget runs out. The limits apply per API process. The other rows also name the people (`email`, `actor`) and the Team (`team`) they concern, and are not throttled. A row also names the channel the request came in on and the Delegate, if any (`channel`, `delegate`).
- **The key pages** `hindsight_agent_keys.web:AgentKeysHttpExtension`, under `/ext` (see "Personal Agent Keys", "The Key Allowlist", "Teams" and "Stale personal schemas"), and Delegated Requests under `/ext/delegated` (see "Delegated Requests").
- **Team tools for agents** `hindsight_agent_keys.tools:AgentKeysMcpExtension`, on both MCP endpoints (see "Teams over MCP").
- **A startup guard**, described in its own section below.
- **Safe defaults:** the UI is off, MCP is stateless, upstream audit logging is off, and the `X-Real-IP` header is passed through to the extension. Audit logging stays off for every bank because the audit action allowlist, `HINDSIGHT_API_AUDIT_LOG_ACTIONS`, is `(none)`, which names no action. Upstream checks that deployment-wide list before a bank's stored `audit_log_enabled`, and no bank can change it.

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
| `HINDSIGHT_API_AUDIT_LOG_ACTIONS` is not `(none)` (parsed as upstream parses it: split on commas, spaces trimmed, empty entries dropped) | Any other list, including the empty one that means every action, lets a bank's stored `audit_log_enabled` write unauthenticated requests into the Public Team's audit log. |
| `HINDSIGHT_API_MCP_STATELESS` is not `true` (read exactly as upstream reads it) | A stateful MCP session can keep a revoked key's identity. |

Of these settings, a bank's stored config or a tenant's config can override only `audit_log_enabled`, which the `(none)` allowlist makes inert: upstream checks the allowlist before it reads a tenant's config or a bank's stored value (see "Safe defaults"). Upstream applies a bank's stored config, whether written at bank creation, by a bank template, the bank config API, a bank import or a clone, and a tenant's config only to the fields it marks configurable, and reads every other setting here from the environment alone. A unit test fails if an upstream release makes another of them configurable.

## Configuration

| Variable | Meaning |
| --- | --- |
| `HINDSIGHT_API_TENANT_LEGACY_KEY` | The legacy key, which reaches the Public Team. Without it only Agent Keys work. Supply it as a secret. |
| `HINDSIGHT_API_TENANT_LEGACY_KEY_EXPIRES` | Optional ISO date or datetime (a bare date means midnight UTC). From then on the legacy key is refused. An unreadable value stops startup. |
| `HINDSIGHT_API_TENANT_KEY_PEPPER` | The server-side secret Agent Keys are hashed with, at least 32 bytes; a shorter value stops startup. Without it no key can be created and every Agent Key is refused; the legacy key still works. Changing it invalidates every Agent Key. Supply it as a secret. |
| `HINDSIGHT_API_TENANT_ACCESS_TEAM_DOMAIN` | The Cloudflare Access team URL, such as `https://<team>.cloudflareaccess.com` (Conductor's `CF_ACCESS_TEAM_DOMAIN`). It is the JWT issuer and serves the signing keys, for the key pages and Delegated Requests alike. |
| `HINDSIGHT_API_TENANT_ACCESS_AUD` | The Access application's AUD tag (Conductor's `CF_ACCESS_AUD`). It changes if the Access application is recreated. |
| `HINDSIGHT_API_TENANT_ACCESS_HOST` | The app's Access-protected hostname, such as `hindsight.example.com`. The key pages answer only on it. |
| `AGENT_KEYS_ADMIN_EMAILS` | Comma-separated emails of the bootstrap admins; case and spaces are ignored. They are always admins, so always on the Key Allowlist, and the admin page cannot change them. |
| `HINDSIGHT_API_TENANT_DELEGATION_HOST` | The delegation application's hostname, such as `hindsight-delegation.example.com`. Delegated Requests answer only on it (see "Delegated Requests"). |
| `HINDSIGHT_API_TENANT_DELEGATION_AUD` | The delegation application's AUD tag. The Delegate's service-token JWT must carry it. |
| `HINDSIGHT_API_TENANT_WORKPLANE_AUD` | The AUD tag of WorkPlane's own Access application. The person's JWT on a Delegated Request must carry it. |
| `HINDSIGHT_API_TENANT_DELEGATE_CLIENT_ID` | The client ID of WorkPlane's Access service token (it ends in `.access`; not a secret). The Delegate's JWT must name it in `common_name`. |
| `HINDSIGHT_API_TENANT_WORKPLANE_ACTIVE_KEYS` | How many active keys created via WorkPlane each person may hold, apart from their own 10; default 25. Checked only when a key is created, so lowering it revokes nothing. A value that is not a whole number stops startup. |
| `HINDSIGHT_API_TENANT_WORKPLANE_KEYS_PER_HOUR` | How many keys WorkPlane may create for each person an hour, apart from their own 5; default 25, so one hour can fill the whole cap when someone joins many Teams at once. A value that is not a whole number stops startup. |

`.env.example` lists every setting in this table. An `ACCESS` or delegation setting that is only spaces counts as unset. Without all three `ACCESS` settings the key pages refuse every request. Without all four delegation settings and `HINDSIGHT_API_TENANT_ACCESS_TEAM_DOMAIN`, Delegated Requests get 404. Keep the Access application's session duration under 30 days, including any policy session duration; Cloudflare's default is 24 hours. A key page request is a sign-in dated by its token's `iat`, and Access keeps the same token for the whole session, so a session of 30 days or more can stop the keys of someone who opens the page every day (see "Sign-in" under "Personal Agent Keys"). The same holds for WorkPlane's Access application, whose JWT dates the sign-in a Delegated Request records. Everything else is upstream Hindsight configuration, such as the LLM provider and its key.

Behind a proxy, set `X-Real-IP` to the real client address and overwrite any value the client sent. Otherwise the event log records whatever the client claims.

## Personal Agent Keys

A person on the Key Allowlist opens `https://<access host>/ext/`, names a key and creates it. Agents then send it as `Authorization: Bearer hsk_<id>_<secret>` on the bypass hostname, over the API and MCP.

- **Who:** the key pages trust only the Access JWT in `Cf-Access-Jwt-Assertion`. It must be RS256, signed by a key the team publishes, issued by the team URL, carry the AUD tag and no other audience, and have `exp` and a numeric `iat`. The person is its `email`, trimmed and lower-cased; no other claim is read. A token without an `email` string that is more than spaces (a service token has none) is refused. Signing keys are fetched from the team and fetched again when a token names an unknown key ID, at most every 30 seconds.
- **Where:** only on `HINDSIGHT_API_TENANT_ACCESS_HOST`. Any other `Host`, including the bypass hostname, gets 404.
- **State changes** (anything but `GET`) also need `Content-Type: application/json`, the header `X-Agent-Keys: 1`, and `Origin: https://<access host>`; otherwise 403.
- **Framing:** `/ext/`, `/ext/admin` and `/ext/teams` send `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`, so no other site can frame them and trick a signed-in person into pressing their buttons.
- **The key** has a 64-bit ID and a 256-bit secret. It is shown once. The database stores only HMAC-SHA256 of the whole key under the pepper, and a presented key is compared in constant time.
- **Limits:** each person can create 5 keys an hour and hold 10 active (neither revoked nor expired) keys. Both are counted in the database. Keys created via WorkPlane are counted apart, against their own limits (see "Delegated Requests").
- **Schema:** a person's first key creates their schema, `p_` plus 16 random hex digits, never derived from their email, and migrates it before the key is shown. Every later key of theirs reaches the same schema.
- **Life:** every Agent Key, personal or Team, works for 90 days from its creation or its last renewal. The page lists the keys the person holds, those created via WorkPlane included, with where each was created and its state; the owner can renew an unexpired key for 90 days from then, and revoke a key. A revoked or expired key cannot be renewed, and no key can be renewed once its owner's 30-day sign-in window has closed (403), on the page or by a Delegated Request: the key already stopped working, so the owner signs in again first.
- **Sign-in:** a key also works only while its owner has signed in through Access within the last 30 days, so offboarding someone in the identity provider stops their keys without touching Hindsight. Every key page request is a sign-in, dated by when Access issued the token (its `iat`), not by when the page was loaded, and so is every Delegated Request, dated by the person's JWT (see "Delegated Requests"). Signing in again revives the keys.
- **Revoke identity:** an admin enters a person's email on `/ext/admin`, or asks WorkPlane (see "Delegated Requests"), to revoke every key that person holds. They can still create new keys while they are on the Key Allowlist; remove them from it as well to stop that.
- **When changes take effect:** there is no auth cache. Every request looks its key up, so a revocation, an expiry or a lapsed sign-in refuses the key's next request, including inside an MCP session that is already open (MCP is stateless).

Tables in `agent_keys`: `people` (email, schema, empty until the person's first personal key and again once that schema is purged), `keys` (ID, HMAC, name, owner's email, schema, kind `personal` or `team`, creation, expiry and revocation times, and `via`, the client ID of the Delegate that created it, empty for a key created on the page), `idempotency` (the Delegate, the person, the Delegate's idempotency key, a digest of the request and the key ID it created; a row is matched for 24 hours and deleted on that person's next creation with an idempotency key after that), `sign_ins` (email, last Access sign-in), `allowlist` (email, role), `teams` (schema, name, creator's email), `members` (Team schema, email, role `owner` or `member`) and `member_requests` (Team schema, email, role asked for, who asked), and the view `stale_schemas` (see "Stale personal schemas").

## The Key Allowlist

Only people on the Key Allowlist can create Agent Keys. The bootstrap admins in `AGENT_KEYS_ADMIN_EMAILS` are always on it; everyone else has a row in `agent_keys.allowlist` with the role `member`, `admin`, or `requested` (asked to join, not yet on the list).

- **Asking to join:** a signed-in person who is not on the list sees a button on `/ext/` that files a request. Asking again changes nothing.
- **Admins** (bootstrap admins and anyone granted admin rights) manage the list at `https://<access host>/ext/admin`: add people by email, approve or decline requests, grant and remove admin rights, and remove people. The same page revokes an identity (see "Personal Agent Keys"), lists stale personal schemas (see "Stale personal schemas"), and holds the kill switch: it revokes every key created via WorkPlane, whoever holds it, and leaves keys created on the page working. It does not stop WorkPlane creating new keys while WorkPlane's service token works, so delete the token in Access first, then press it, and press it again a minute later for a creation that was already under way (`docs/operating.md`, "Kill switch"). A repeat revokes only keys not yet revoked. Everyone else gets 403 on every `/ext/admin` route. The bootstrap admins cannot be changed there (409); edit the secret instead.
- **Removing someone** stops them creating keys and disables the keys they hold: every request with a key checks its owner is still on the list. Their keys are not deleted, so adding them back makes the keys work again. It also stops them acting as a Team owner (adding or removing members, asking for people to join, confirming or declining requests, creating Team keys) until they are added back. Their Teams, ownership and memberships are kept, and they can still list and revoke their own keys and ask to be added back.
- **Logging:** every change is an event (see "The event log").

## Teams

A Team is a named set of people who share one schema. A person on the Key Allowlist opens `https://<access host>/ext/teams`, the Teams page, which follows the same hostname, sign-in and state-change rules as the key page.

- **Creating:** the creator becomes the Team's first owner. The Team gets its own schema, `t_` plus 16 random hex digits, migrated before the Team is shown; the worker processes it like any other. Names are unique whatever their case, and `public` is reserved for the Public Team. Creations of one name run one at a time, across API processes: the first migrates and stores the Team, and a concurrent one waits for it, at most a minute (503 after that, to try again), then is refused (409) without migrating a schema of its own (a Delegated Request by the Team's owner is answered with that Team instead, see "Delegated Requests"). A waiter has a database connection of its own that it gives back when it gives up. Each person can create 10 Teams, counted in the database (429 after that).
- **Members:** owners on the Key Allowlist add people by email, as a member or an owner, including people who have not signed in yet; they change roles and remove people. A change that would leave a Team without an owner is refused. Admins manage every Team and see every Team on the page, whether or not they are in it.
- **Pending requests:** people an agent asked to add over MCP are listed under their Team, with the role asked for and who asked. An owner on the Key Allowlist, or an admin, presses **Confirm** to give them that role, or **Decline** to drop the request and leave their place in the Team as it was. Confirm sends the role the page showed: if an agent has asked for another role since, nothing is granted and the page answers 409, so the owner reloads it and sees the new request.
- **Team keys:** a member on the Key Allowlist creates a Team key the same way as a personal key, with the same limits, which count personal and Team keys together. Membership is checked on every request, so removing a member stops their Team keys on their next request.
- **Public Team:** everyone on the Key Allowlist can create a Public Team key, which reaches the banks in `public`. The Public Team has no owners or members.

### Teams over MCP

Agents manage Teams with these tools, on the multi-bank endpoint `/mcp/` and on every single-bank endpoint `/mcp/<bank>/`. They act as the person whose personal Agent Key the agent sends, with that person's rights; a Team key, a Public Team key and the legacy key get an error from every one of them.

| Tool | What it does |
| --- | --- |
| `create_team(name)` | Creates a Team as on the Teams page, with the same limit. Returns its ID (`t_…`), which the other tools take as `team`. |
| `list_teams()` | The Teams the person is in, admins included (they manage other Teams on the Teams page), each with the person's role, its members and its pending requests. |
| `add_team_member(team, email, role)` | Files a pending request to make the person a `member` (the default) or an `owner`. Nobody gains access until an owner on the Key Allowlist, or an admin, confirms it on the Teams page. |
| `remove_team_member(team, email)` | Takes the person out of the Team; their Team keys stop on their next request. |

A refusal is answered as `{"error": "<reason>"}`, as upstream's own tools answer. Only owners on the Key Allowlist and admins can file requests and remove people. A bank whose config sets `mcp_enabled_tools` hides every tool not named there, these included.

## Delegated Requests

A Delegate (WorkPlane, the organization's agent) acts for a person signed in to it, with that person's rights, through routes under `https://<delegation host>/ext/delegated/`. It calls them server to server.

- **Two credentials,** each verified on its own; failing either gets 403. Both are RS256 JWTs signed by a key the Access team publishes and issued by the team URL, with `exp`, a numeric `iat`, and their application's AUD tag and no other audience.
  - **The Delegate:** the service-token JWT that Access forwards in `Cf-Access-Jwt-Assertion`. It must carry the delegation application's AUD tag, name `HINDSIGHT_API_TENANT_DELEGATE_CLIENT_ID` in `common_name`, and have no `email` claim at all, not even an empty one, so a person's JWT in its place is refused.
  - **The person:** their own Access JWT for WorkPlane's application, which WorkPlane forwards in `X-Delegated-Access-Jwt`. It must carry WorkPlane's AUD tag, so a JWT for the key pages or the delegation application is refused, and an `email` string that is more than spaces. It is read only after the Delegate's credential has passed.
- **Who:** the person is that JWT's `email`, trimmed and lower-cased. `Cf-Access-Authenticated-User-Email` and every other identity header are ignored, and a request about the person takes no email from its body.
- **Where:** only on `HINDSIGHT_API_TENANT_DELEGATION_HOST`; any other `Host` gets 404.
- **State changes** (anything but `GET`) also need `Content-Type: application/json`; otherwise 403.
- **Sign-in:** the person's JWT records a sign-in as a key page request does, dated by its `iat`, and an older `iat` never moves the stored one back. Making the request does not count by itself, so replaying an old JWT cannot extend the 30-day window.
- **Replay:** a captured pair of credentials works until the person's JWT expires, and only alongside WorkPlane's service token.
- **Refusals** are `delegation_refused` events, under the same per-client and total limits as refused keys.

| Route | What it does |
| --- | --- |
| `POST /ext/delegated/access-requests` | Asks the admins to add the person to the Key Allowlist, as the button on `/ext/` does (the new-hire path). Answers `{"email": …, "role": …}` with the person's role now: `requested`, `member` or `admin`. A repeat files nothing new. |
| `POST /ext/delegated/keys` | Creates a personal key for the person, on the same terms as the key page, marked as created via WorkPlane. Takes `{"name": …}` and an `Idempotency-Key` header (1 to 200 characters, else 422). Answers `{"id": …, "name": …, "key": …}`; the key is shown only then. A repeat of the idempotency key by the same Delegate for the same person within 24 hours creates nothing and answers the same ID without `key`; with another name it is refused (409). |
| `GET /ext/delegated/keys` | The person's keys created via WorkPlane, as the key page lists keys, each with its `state` and `days_to_expiry` (whole days, rounded up; 0 once expired). |
| `POST /ext/delegated/keys/<id>/renew` | Renews one of them for 90 days from now, as the key page does, with the same refusals. Answers `{"id": …, "expires_at": …}`. |
| `POST /ext/delegated/keys/<id>/revoke` | Revokes one of them. Answers `{"id": …, "state": "revoked"}`, a repeat too. |
| `POST /ext/delegated/teams` | Creates a Team with the person as its first owner, on the same terms as the Teams page. Takes `{"name": …}` and answers `{"team": …, "name": …}`. The name of a Team the person already owns answers that Team and creates nothing; any other taken name is refused (409). |
| `POST /ext/delegated/teams/<team>/keys` | Creates a Team key for a Team the person is in (`public` for the Public Team), on the same terms as the Teams page, marked as created via WorkPlane. It counts with the person's other keys created via WorkPlane, personal ones included, against the limits below. Takes `{"name": …}` and an `Idempotency-Key` header, and answers and repeats as `POST /ext/delegated/keys` does; the same idempotency key for another Team is a different request (409). |
| `POST /ext/delegated/teams/<team>/members` | Adds the person in `{"email": …, "role": "member" or "owner"}` to the Team directly, or changes their role. Only an owner of the Team on the Key Allowlist, or an admin, may; anyone else gets 403, a Join Request not being built yet. A repeat that leaves their role as it was answers the same and records no event. |
| `DELETE /ext/delegated/teams/<team>/members` | Takes the person in `{"email": …}` out of the Team, for the same people; their Team keys stop on their next request. Someone who is not in the Team answers the same and records no event. |
| `POST /ext/delegated/admin/people` | Changes someone's place on the Key Allowlist, as `/ext/admin` does: takes `{"email": …, "role": …}`, the role `member`, `admin` or `null` (which removes them, or declines their request). Answers `{"email": …, "role": …}` with their role now; a repeat changes and records nothing. The bootstrap admins cannot be changed (409). |
| `POST /ext/delegated/admin/revoke-identity` | Revokes every key the person `{"email": …}` holds, whoever created them, as `/ext/admin` does. Answers `{"email": …, "revoked": …, "active": …}`: how many keys this request revoked, and how many of the person's keys are active now. A repeat revokes and records nothing. |

The key routes reach only the person's own keys created via WorkPlane, Team keys included: never their key page keys (404), nor anyone else's. A key's holder is one member, not the Team, so no member, an owner included, can list, renew or revoke another member's Team key on any channel: owners stop it by removing the member, admins by revoking the identity. Keys created via WorkPlane are listed on the person's key page, where they can renew and revoke them. Each person may hold 25 active keys created via WorkPlane, and WorkPlane may create 25 an hour for them (`HINDSIGHT_API_TENANT_WORKPLANE_ACTIVE_KEYS` and `..._KEYS_PER_HOUR`), counted apart from the person's own 10 and 5, in the database under the same per-person lock, so concurrent creations stop at the cap (429).

The routes under `/ext/delegated/admin/` answer 403 unless the person is an admin. They are the admin exception: an admin's revoke-identity reaches anyone's keys, created on the key page or via WorkPlane, and records `identity_revoked` with the admin as `actor`, the person as `email` and WorkPlane as `delegate`. Revoking every key created via WorkPlane, the kill switch, is on `/ext/admin` only (see "The Key Allowlist"): no Delegated Request reaches it, so a compromised Delegate cannot be the one to switch itself off.

A creation stores the key, with its idempotency key, in one transaction, then records `key_created`. If the process stops between the two, or the event log fails, the key exists, works and is listed, with no `key_created` row; a retry with the same idempotency key returns its ID and records nothing either. Nothing needs repairing: the key is revoked like any other, and its later events name it.

A Team creation migrates the Team's schema, stores the Team with its first owner, then records `team_created`; a member change stores, then records `member_added`, `owner_added` or `member_removed`. A stop before the Team is stored leaves a migrated schema that no Team or person lists; it is unreachable and harmless, and a repeat creates the Team under a new schema. A stop, or an event-log failure, after a change is stored leaves the change with no event row, and a repeat of the request by a Delegate answers the current state and records nothing, so the row is never written. The tables are the source of truth: the Team, its members and their Team keys work as stored, and later events name them.

## Stale personal schemas

`/ext/admin` lists each personal schema that no valid key has reached for 90 days, with its owner's email and last key activity. Nothing is deleted automatically: an operator purges a schema with `scripts/purge-schema.sql`, one schema per run.

- **Last key activity:** the latest moment any key reaching the schema could have worked. A key works at the latest until it expires, it is revoked, or 30 days pass after its owner's last sign-in. Only the latest sign-in is stored, so this errs late, never early. A schema with no key (its first key was refused at a limit) counts from when its owner was first recorded. The rule lives in the view `agent_keys.stale_schemas`, which the page and the script both read.
- **Not counted:** removal from the Key Allowlist, because it is reversible and recorded only as an event. A removed owner's schema is listed 90 days after their keys have also expired, been revoked or gone 30 days without a sign-in.
- **Never listed:** Team schemas and `public`. Only keys that reach the personal schema count, so a person's Team and Public Team keys do not keep their personal schema off the list.

**Purging.** Take a backup first (docs/cutover.md, step 1); the purge cannot be undone otherwise. Copy `scripts/purge-schema.sql` to the CT (`scp` it to the node, then `pct push <vmid> purge-schema.sql /root/purge-schema.sql`). Then, with the `pg` helper from docs/cutover.md, type the schema ID from `/ext/admin` and your email:

```sh
# CT
read -r -p 'Schema ID to purge: ' schema && read -r -p 'Your email: ' operator &&
  pg psql -X -d hindsight -v schema="$schema" -v operator="$operator" < /root/purge-schema.sql &&
  echo "purge OK" || { echo "PURGE FAILED: read the output above"; false; }
```

1. **Unlist** (one transaction). It stops, changing nothing, unless the schema is listed as stale at that moment and the email is set. It locks the owner's row as key creation does, so a key created meanwhile counts. Before and during it, no valid key reaches the schema; after it, every key that names the schema is revoked, the schema is off the tenant list so the worker stops processing it, and the owner's next personal key creates a new schema.
2. **Wait** 60 seconds, so tasks the worker had already claimed there finish.
3. **Drop** (one transaction). It stops, changing nothing, if a row in `agent_keys.people` names the schema again. Otherwise it revokes again any key that names the schema (one created in the instant before step 1), drops the schema, and records a `schema_purged` event naming the owner, the operator and the schema.

psql stops at the first error with a non-zero status. If the output ends at `Unlisted` followed by `no rows returned for \gset`, step 3 found the schema in use again and dropped nothing: it is back on the tenant list with its owner, so the worker processes it and their keys created since step 1 work, while the keys step 1 revoked stay revoked. Purge it only if `/ext/admin` lists it as stale again. If the output ends at `Unlisted` with any other error, the run stopped in the wait or in step 3: no key reaches the schema, and its data is intact unless step 3 committed just before the connection failed. Put it back on the list if it still exists, passing both values as psql variables (psql substitutes them only in input it reads, never in `-c`), and run the script again:

```sh
# CT (not verified on Dev; runs in the integration tests)
read -r -p 'Owner email: ' owner &&
  echo "UPDATE agent_keys.people SET schema = :'schema' WHERE email = :'owner' AND schema IS NULL AND EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = :'schema') RETURNING email" |
  pg psql -X -d hindsight -At -v ON_ERROR_STOP=1 -v schema="$schema" -v owner="$owner"
```

Its keys stay revoked, so this reopens nothing. If that returns no row, either the schema is gone, so step 3 committed and the purge is done (its `schema_purged` event is in `agent_keys.events`), or the owner already has a new schema, and the old one stays unlisted and unreachable until it is dropped by hand.

## The event log

Events go to `agent_keys.events` in Hindsight's own database. That schema sits outside upstream's migration history, so stock Hindsight still starts against the same database.

| Column | Meaning |
| --- | --- |
| `kind` | What happened; the kinds are listed below the table |
| `key_id` | For `key_refused`, `(missing)` (no key), `(unrecognized)` (not shaped like an Agent Key) or the presented key's ID; for `legacy_key_expired`, `(legacy)`; for `key_created`, `key_renewed` and `key_revoked`, the key's ID; for every other kind (`refusal_log_saturated`, `delegation_refused`, `identity_revoked`, `workplane_keys_revoked`, `schema_purged` and every Key Allowlist and Team change), `(none)`. A key's ID is the `<id>` part of `hsk_<id>_<secret>`. Parenthesised values are reserved; a key's ID is never parenthesised. |
| `client_ip` | The `X-Real-IP` address in canonical form (an IPv4-mapped IPv6 address is stored as IPv4), or `NULL` if the header is missing or not an IP address |
| `email` | For `key_created`, `key_renewed` and `key_revoked`, the key's owner; for `identity_revoked`, the person whose keys were revoked; for a Key Allowlist or Team change, the person it concerns (for `team_created`, the creator); for `schema_purged`, the schema's owner; otherwise `NULL` |
| `actor` | The signed-in person who made the change, on every kind a person causes: for `key_created`, `key_renewed` and `key_revoked`, the key's owner (only they do these); for `identity_revoked` and `workplane_keys_revoked`, the admin; for `access_requested`, the person asking; for any other Key Allowlist or Team change, the admin or owner (for `*_requested`, the person whose personal key the agent used); for `schema_purged`, the email the operator typed. On a Delegated Request it is the person the Delegate acted for, never the Delegate. `NULL` only where no person is known: `key_refused`, `legacy_key_expired`, `refusal_log_saturated` and `delegation_refused`. |
| `team` | For a Team change and for a Team key's `key_created`, the Team's schema (`public` for the Public Team); for `schema_purged`, the purged personal schema; otherwise `NULL` |
| `channel` | Where the request came in, on every kind a request causes: `ext` (the key pages), `delegated` (a Delegated Request, `delegation_refused` included) or `mcp` (a Team tool). `NULL` only for `key_refused` and `legacy_key_expired` (upstream checks keys before any channel), `refusal_log_saturated` (every channel's refusals share its budget) and `schema_purged` (the operator's script). |
| `delegate` | On the `delegated` channel, the Delegate's service-token client ID once its credential has passed; otherwise `NULL`. A `delegation_refused` row without one means the Delegate's own credential failed. |

Kinds:

- `key_refused`
- `legacy_key_expired`
- `refusal_log_saturated`: the 60-a-minute budget ran out; further refusals that minute were not recorded
- `delegation_refused`: a Delegated Request failed either credential
- `key_created`
- `key_renewed`
- `key_revoked`
- `identity_revoked`: an admin revoked every key a person held; recorded only when that revoked at least one
- `workplane_keys_revoked`: an admin used the kill switch on `/ext/admin`; every key created via WorkPlane was revoked
- Key Allowlist changes:
  - `access_requested`
  - `access_approved`
  - `access_declined`
  - `allowlist_added`
  - `allowlist_removed`
  - `admin_granted`
  - `admin_removed`
- Team changes:
  - `team_created`
  - `owner_added`, `member_added`: the person was made an owner or a member, whether new to the Team or not
  - `owner_requested`, `member_requested`: an agent asked over MCP to make the person an owner or a member; nothing changed yet
  - `owner_confirmed`, `member_confirmed`: an owner on the Key Allowlist, or an admin, confirmed that request, so the person now has that role
  - `owner_declined`, `member_declined`: an owner on the Key Allowlist, or an admin, dropped that request
  - `member_removed`
- `schema_purged`: written by `scripts/purge-schema.sql`

The extension connects to the database once, at startup. If that fails it logs a warning and records nothing until the next restart; refusals are still enforced.

## The UI image

`ghcr.io/impulse-engineering/hindsight-ui` runs upstream's web UI and nothing else, built from the same pinned upstream release as the API image (`docker build --target ui`). Upstream's UI sends one key, and a key reaches one Team, so the image starts one UI process per listed Team, each on its own port with its own key. Its entrypoint is `docker/ui-start.sh`. It never starts the API, and it takes no command. The image sets `HINDSIGHT_ENABLE_API=false`, so even an entrypoint override that runs upstream's launcher starts only one UI; never override that variable.

| Variable | Meaning |
| --- | --- |
| `HINDSIGHT_UI_TEAMS` | The Teams to serve, as space-separated `<team>:<port>` entries, such as `public:9999 silver-air:10000`. `<team>` is a label the operator picks, which need not be the Team's name on `/ext/teams`: lowercase letters, digits and inner hyphens. A port is 1024 to 65535. |
| `HINDSIGHT_UI_KEY_<TEAM>` | The key of each listed Team, where `<TEAM>` is its label upper-cased with `-` as `_` (`HINDSIGHT_UI_KEY_SILVER_AIR`): a Team key, or for `public` a Public Team key or the legacy key. Supply it as a secret. |
| `HINDSIGHT_CP_DATAPLANE_API_URL` | Upstream's setting: the API every UI process calls. |

Before any UI process starts, the script exits with status 78, naming each problem, if `HINDSIGHT_UI_TEAMS` is empty or holds a tab or line break, an entry is malformed, a Team or a port is listed twice, a listed Team's key is unset or empty, or a command is passed. When one UI process exits, the script stops the others and the container exits non-zero (that process's status, or 1 if it was 0), so a platform that restarts on failure restarts the whole set. A stop signal (`SIGTERM` or `SIGINT`), at any point, stops every UI process and exits 0.

Every UI shows its Team's banks to whoever reaches its port, so put each hostname behind Access. Each UI process takes roughly 150 to 200 MB of memory: size the container for the Team count. Adding a Team to a running app is in [docs/operating.md](docs/operating.md), "The UI app".

## Tests

Unit tests run inside the pinned upstream image, which ships `hindsight_api` and pytest. CI runs them inside the image it built (`UNIT_TEST_IMAGE`), so they also see the image's pinned packages:

```sh
scripts/unit-tests.sh -v
```

Integration tests start the real container on Hindsight's mock LLM, so they need no credentials, and run the UI image against it with two Teams. They also run the README's purge recovery and the operating guide's checks of a revoked identity's keys and of the kill switch as written, with an owner whose email holds an apostrophe. They need Docker, pytest and markdown-it-py on the host. The build needs BuildKit (Docker's default builder since 23.0) for the Dockerfile's `RUN --mount`:

```sh
docker build -t hindsight-agent-keys:test .
docker build --target ui -t hindsight-ui:test .
uv run --no-project --with pytest==9.0.3 --with markdown-it-py==4.2.0 pytest -p no:cacheprovider -c /dev/null --rootdir . tests/integration -v
```

Script tests run the release watcher in a scratch repository with fake `gh` and `docker`, and the scan alert (`scripts/scan-alert.sh`) with a fake `gh`. `tests/scripts/test_public_repo.py` fails when a tracked file names the company's domains or a private IPv4 address, since this repository is public. `tests/scripts/test_pins.py` checks the pins in the Dockerfile, the workflows and `scripts/`: actions by commit SHA and images by digest (a `FROM`, an `image=` or `image:` value, and the image a `docker run`, `pull` or `create` runs), each with its version, and every `pip install` command with `--require-hashes`. It reads the forms this repo writes and fails on the unusual ones its docstring lists; it is a guardrail, not a shell or YAML interpreter, so review still applies rule 5 to any other form. They also check the shell this README and `docs/` give operators (`tests/scripts/test_doc_shell.py`), in every fenced block tagged `sh`, `bash`, `shell` or `zsh`, or not tagged. Blocks are found with a CommonMark parser (markdown-it-py), and their shell is read from shfmt's syntax tree, as bash in a `bash` block and POSIX sh otherwise, with any heredoc body that reads as shell (a script fed to `ssh` or `sh`), read as bash, which takes all sh syntax too. Shell inside a quoted string (`sh -c '…'`) is not read. A placeholder such as `<port>` reads as a value not yet known, like `$port`. A block that is not shell needs a tag such as `text`, or the tests stop at it:

- Each gate, a function that prints STOP when its check fails, runs against fake `curl` and `cloudflared` answering 200, 302, 401, 403, 404, 500 and a refused connection, and must succeed only on the status it waits for. It runs under `bash` in a `bash` block and under `sh` otherwise, with the functions its block's shell has. A gate in a heredoc body runs under `bash` when the command it is fed to names bash (`ssh h bash`), else under `sh`, with only that body's functions. Every function a block defines, in a heredoc body too, is found, whatever its form.
- A `curl` that sends PUT, PATCH or DELETE, or a method held in a variable or a placeholder, uses `-f`, in a shell block or an inline command. Options are read as curl reads them, so `-sSX DELETE` counts; the options that take an argument come from `curl --help all`.
- Each `curl` call the `-f` check accepts, in its own test cases and in the docs (`cloudflared access curl` too), runs through the fakes answering 200, and the test names any call the fake refuses. The fake `curl` reads the options it models as curl 8 does and refuses any other (`--user-agent`, `--proxy`), so a doc or test case that adds one fails until the fake models it.
- SQL takes each value as a psql variable, in a shell block or an inline command: `-v name=…` with `:'name'` in SQL that psql reads from stdin. The SQL psql runs (its `-c`, a heredoc or here-string, or what `echo` or `printf` pipes in, also through a group or a longer pipeline) holds no shell expansion or `<placeholder>`, and its `-c` holds no psql variable (`:name`, `:'name'`, `:"name"`), since psql substitutes them only in what it reads. A `$` in that SQL counts as a value. psql's options come from `psql --help`.
- A failure branch that prints (`|| echo …`, `|| { echo …; }`, `|| ( echo … )`, or the same with `printf`) ends in `false`, `return 1` or `exit 1` (not negated with `!` or sent to the background), and nothing around it discards its status: `!` or `&` on it, a later `|` or `||`, or an `if` or loop condition, also around a group, subshell or `time` that holds it. A compound command after `||` (`if`, `case`, a loop) is refused: write the branch as `{ …; }`.

They need git, jq, curl, psql and the Docker CLI on the host, pytest and markdown-it-py in the Python that runs them, and shfmt on PATH (shfmt-py installs it):

```sh
uv run --no-project --with pytest==9.0.3 --with markdown-it-py==4.2.0 --with shfmt-py==4.2.0 pytest -p no:cacheprovider -c /dev/null --rootdir . tests/scripts -v
```

Lint runs the same script as CI. It needs ruff on PATH, shellcheck and Docker:

```sh
uv run --no-project --with ruff==0.17.0 scripts/lint.sh
```

Behind a TLS-inspecting proxy, the vulnerability scan needs that proxy's CA mounted into the Grype container (`SSL_CERT_FILE`).

## CI and publishing

- **Every PR:** lint (ruff, shellcheck, actionlint), script tests, unit tests, integration tests, and a Grype scan of both images. The scan runs as a digest-pinned container against an exported image tar and blocks on critical vulnerabilities that have a fix.
- **On `main`:** two amd64 images are published, `ghcr.io/impulse-engineering/hindsight-agent-keys:<upstream version>-ak.<run>` and `ghcr.io/impulse-engineering/hindsight-ui` with the same tag (a re-run adds `.<attempt>`), each with an SBOM, a GitHub build provenance attestation and a keyless cosign signature. A follow-up job then runs the integration tests and the scan against those exact digests. Approve a digest only once that job has passed.
- **Daily (scan):** the scan also runs on `main` every morning (UTC), building `main` as a PR does, so an advisory published since the last merge turns `main` red at the next scheduled run, not when it is published, and GitHub can delay or drop a scheduled run under load. A scheduled scan that does not pass (failed, cancelled or timed out) opens an issue in this repository, "Scheduled scan failed on main", linking the run, or comments on the one this workflow opened while it is open (an issue anyone else opens with that title is ignored); close it once a scheduled run passes. Only that job, `scan-alert`, can write issues. GitHub turns the schedule off after 60 days without activity in the repository.
- **Daily (upstream releases):** the `upstream-release` workflow reads upstream's latest GitHub Release, which is never a draft or a pre-release. If it is newer than the pin and has no PR yet, it opens one PR that pins `ghcr.io/vectorize-io/hindsight:<version>@<digest>` and links the release notes. A release overtaken by a newer one before the next run gets no PR. Closing a PR declines that release; reopen it to take the release up again. Only an exact `vX.Y.Z` release is followed, never a floating tag such as `latest` or `0.10`, or a `-slim` tag. A release tag that is not `vX.Y.Z` fails the run. GitHub holds CI on that PR until a maintainer selects **Approve workflows to run**. Nothing merges automatically; merging publishes the new image as above. It can also be started by hand from the Actions tab, on `main`.

All actions are pinned by commit SHA. Only the publish job can write packages, and only the `scan-alert` job can write issues. Only the `upstream-release` workflow can push branches and open PRs, and its own token is its only credential.

Verify a published image:

```sh
gh attestation verify oci://ghcr.io/impulse-engineering/hindsight-agent-keys@<digest> -R Impulse-Engineering/hindsight-agent-keys
cosign verify ghcr.io/impulse-engineering/hindsight-agent-keys@<digest> \
  --certificate-identity-regexp '^https://github.com/Impulse-Engineering/hindsight-agent-keys/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The UI image verifies the same way, with `hindsight-ui` in place of `hindsight-agent-keys` in the image name.

## Moving a Conductor app onto the image

[docs/cutover.md](docs/cutover.md) is the runbook: back up pg0, upgrade to the stock release this image is built on, then swap the image while the bypass hostname is behind Access. It also covers the rollback.

[docs/operating.md](docs/operating.md) covers running it afterwards: the Key Allowlist, Agent Keys, Teams, revoking an identity, upstream upgrades and troubleshooting.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| The container exits with status 78 | The startup guard refused the configuration. Its stderr names each variable to fix. For the UI image, `ui-start: refusing to start:` lines name each problem with its Teams (see "The UI image"). |
| The legacy key gets 401 | `HINDSIGHT_API_TENANT_LEGACY_KEY` is unset or different, or the legacy key has passed its expiry (`legacy_key_expired` in the event log). |
| Background tasks in a new personal or Team schema stay `pending` | The log shows `agent-keys: could not list tenants; using the last list`: the database could not be read when the worker refreshed its tenant list, so it keeps the schemas it last listed. It picks up the new schema once the database answers again. |
| The key page answers 404 | The request's hostname is not `HINDSIGHT_API_TENANT_ACCESS_HOST`, or one of the three `ACCESS` settings is unset. |
| The key page answers 403 "Sign in through Cloudflare Access" | The Access JWT failed validation. Look for `agent-keys: refused an Access token` in the logs; a wrong or changed AUD tag is the usual cause. |
| Key creation answers 503 | `HINDSIGHT_API_TENANT_KEY_PEPPER` is unset. |
| A person's Agent Keys all get 401 at once | They were removed from the Key Allowlist (`allowlist_removed` in the event log). Adding them back restores the keys. |
| Every Agent Key gets 401 | The pepper was changed or removed. Agent Keys must be created again. |
| One person's Agent Key gets 401 | The key was revoked, it expired (90 days after its creation or last renewal), or its owner has not signed in for 30 days, on the key page or through WorkPlane. The owner sees each key's state on the key page; opening the page revives keys held back by the 30-day rule, and until then renewal is refused (403). |
| A Team key gets 401 | Its holder is no longer in the Team. An owner on the Key Allowlist, or an admin, can add them again; the key works again on its next request. |
| A Team owner is refused with "You are not on the Key Allowlist." when changing members | They were removed from the Key Allowlist. They keep the Team and an admin can answer its requests meanwhile; adding them back restores their actions. |
| An agent added someone to a Team but they still have no access | Adding over MCP only files a request. An owner on the key allowlist, or an admin, must press **Confirm** under the Team on `/ext/teams`. |
| Upstream's `public.audit_log` gains rows | The app runs an image older than the `HINDSIGHT_API_AUDIT_LOG_ACTIONS=(none)` default, or not this image: the guard refuses any other value. Check the digest the app runs. |
| The Team tools are missing from an MCP endpoint | The bank's `mcp_enabled_tools` config does not list them. |
| The event log stays empty | The extension's database connection failed at startup. Look for `agent-keys` warnings in the logs, then restart the container. Refusals are still enforced. |

## License

MIT. Hindsight itself is MIT-licensed by Vectorize.
