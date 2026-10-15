# Operating multi-user Hindsight

How to run the `hindsight` app on this image day to day: the Key Allowlist, Agent Keys, Teams, revoking an identity, upstream upgrades and troubleshooting. The [README](../README.md) states the rules each part enforces; this page says who does what and how to check it. The cut-over and its rollback are in [cutover.md](cutover.md).

Commands marked *(not verified)* have not been run on Dev. Commands marked **CT** run on the app's container, after the setup block in [cutover.md](cutover.md) (the one that defines `pg` and `api`).

| | Dev | Prod |
| --- | --- | --- |
| Key pages (behind Access) | `https://<primary>/ext/` | `https://<primary>/ext/` |
| Agents: API and MCP (bypass hostname) | `https://<bypass>` | `https://<bypass>` |

## Who does what

| Who | Where | What |
| --- | --- | --- |
| Anyone who signs in through Access | `/ext/` | Asks to join the Key Allowlist |
| People on the Key Allowlist | `/ext/`, `/ext/teams` | Create, renew and revoke their own keys; create Teams; create Team and Public Team keys |
| Team owners | `/ext/teams` | Add and remove members and owners; confirm or decline the people agents asked to add |
| Admins | `/ext/admin`, `/ext/teams` | Manage the Key Allowlist, revoke identities, see stale personal schemas, manage every Team |
| Platform admins | Conductor and the CT | Set secrets (the first admins among them), approve digests, deploy, run CT commands |
| Agents | The bypass hostname | Use memory with an Agent Key over the API and MCP; with a personal key, manage Teams over MCP |

## The Key Allowlist

Only people on it can create Agent Keys.

- **First admins** come from the `AGENT_KEYS_ADMIN_EMAILS` secret, comma-separated. The image reads it at startup, so changing it with `platform_set_secret` restarts the app *(not verified)*. **Auth state:** down during the restart, then the same image and extension, so nothing opens. The page cannot change first admins (409), so to drop someone from the secret but keep them on the Key Allowlist: remove them from the secret (the app restarts), then add them on `/ext/admin` as a member or an admin. Between the two steps they are off the Key Allowlist and their keys get 401; adding them back makes those keys work again.
- **Everyone else** is managed on `/ext/admin`: add people by email, approve or decline requests, grant or remove admin rights, and remove people. A signed-in person who is not on the list sees a button on `/ext/` that files a request.
- **Removing someone** disables the keys they hold from their next request, without deleting them, so adding the person back makes those keys work again. To end someone's access, revoke their identity as well (below).
- **Listing it** from the CT *(not verified)*: `pg psql -d hindsight -Atc 'select role, email from agent_keys.allowlist order by 1, 2'`. The first admins come from the secret, so this can miss them.

Every change is an event in `agent_keys.events` (README, "The event log").

## Agent Keys

- **Creating.** A person on the Key Allowlist creates a personal key on `/ext/`, and a Team or Public Team key on `/ext/teams`. The key is shown once. An agent sends it as `Authorization: Bearer hsk_<id>_<secret>` on the bypass hostname, to the API and to MCP (`/mcp/` or `/mcp/<bank>/`). An agent that needs personal and Team memory holds two keys.
- **Limits.** Each person can create 5 keys an hour and hold 10 active keys, personal and Team keys together; past either, creation answers 429. Each person can create 10 Teams.
- **90 days.** A key works for 90 days from its creation or its last renewal. Its owner renews an unexpired key, or revokes one, on `/ext/`. An expired or revoked key cannot be renewed; create a new one.
- **30-day sign-in.** A key works only while its owner has signed in through Access to a key page within the last 30 days. Tell people to open `/ext/` at least once a month. Opening it after a lapse means signing in again, which revives the held-back keys at once. This is also what stops a leaver's keys: once the identity provider disables them, their keys stop within 30 days without anyone touching Hindsight. To stop them at once, revoke the identity.
- **Access session length.** A sign-in is dated by the `iat` of the Access token, and Access keeps one token for a whole session. Keep the Access application's session duration under 30 days, including any policy session duration; Cloudflare's default is 24 hours. With 30 days or more, someone who opens `/ext/` every day can still have their keys stop.
- **Leaked key.** Its owner revokes it on `/ext/`; it fails on its next request, including inside an open MCP session. If the owner cannot, an admin revokes their identity.
- **The legacy key** reaches the Public Team until `HINDSIGHT_API_TENANT_LEGACY_KEY_EXPIRES`; on Prod that is 30 days after the cut-over ([cutover.md](cutover.md), step 9). Its users get on the Key Allowlist and create Public Team keys before then.
- **The pepper** (`HINDSIGHT_API_TENANT_KEY_PEPPER`) never changes: a new one invalidates every Agent Key at once. Without it, key creation answers 503 and every Agent Key gets 401, while the legacy key still works.

## Revoke identity

For someone who leaves, or whose keys must stop now:

1. On `/ext/admin`, enter their email to revoke their identity. Every key they hold, personal and Team, is revoked and fails on its next request, including inside an open MCP session. The event log records `identity_revoked` with you as `actor`.
2. Remove them from the Key Allowlist on the same page. Otherwise they can create new keys.
3. Remove them from their Teams on `/ext/teams`; admins see every Team there. Otherwise adding them back to the Key Allowlist later would give their new Team keys access again.

Their personal schema stays. It is listed as stale 90 days after their last key stopped working, and can then be purged (below).

To check from the CT, type their email; every key it lists shows a `revoked_at` *(not verified on Dev; runs in the integration tests)*:

```sh
# CT
read -r -p 'Email: ' email &&
  echo "select id, kind, schema, revoked_at from agent_keys.keys where email = :'email'" |
  pg psql -X -d hindsight -At -v email="$email"
```

## Teams

- **Creating.** A person on the Key Allowlist creates a Team on `/ext/teams`, or an agent does with the MCP tool `create_team`; the creator is its first owner. A Team's ID (`t_…`), which the other MCP tools take, comes from `list_teams`.
- **Members.** Owners add people by email, as a member or an owner, including people who have not signed in yet, and remove them. Admins can manage every Team.
- **Agents cannot add people on their own.** `add_team_member` over MCP only files a pending request, shown under the Team on `/ext/teams`. Nobody gains access until an owner or admin presses **Confirm** there, so a poisoned memory cannot add someone to a Team. Tell owners to expect these requests.
- **Removing a member** stops their Team keys on their next request. A Team's data stays whoever leaves, and Team schemas are never listed for purging.
- **Over MCP**, the Team tools need a personal Agent Key; a Team key, a Public Team key or the legacy key gets an error. A bank whose config sets `mcp_enabled_tools` hides them on that bank's endpoint unless it names them.
- **The Public Team** has no owners or members: everyone on the Key Allowlist can create a Public Team key.

## Stale personal schemas

`/ext/admin` lists each personal schema that no valid key has reached for 90 days. Nothing is deleted on its own. To purge one, follow the README, ["Stale personal schemas"](../README.md#stale-personal-schemas): take a backup first ([cutover.md](cutover.md), step 1), copy `scripts/purge-schema.sql` onto the CT, and run it for one schema at a time. If its drop step stops, read its last error: `no rows returned for \gset` means the schema is in use again and nothing was dropped; any other error means put the schema back on the list as the README shows and run the script again.

## The Public Team stays in `public`

The banks that existed before the cut-over are the Public Team, in the `public` schema. Upstream falls back to `public` on unauthenticated code paths, so it stays there only while all six of these conditions hold (#697). Change none of them without first moving the Public Team out of `public`.

| | Condition | What holds it |
| --- | --- | --- |
| 1 | `HINDSIGHT_API_MCP_AUTH_TOKEN` is never set. | The startup guard refuses it, even empty. |
| 2 | `authenticate()` rejects unknown keys and never returns an empty schema. | The tenant extension. A key it does not accept gets 401; an accepted key reaches `public`, a `p_…` schema or a `t_…` schema, and the keys table refuses an empty schema. |
| 3 | `list_tenants()` returns `public` once, plus every personal and Team schema. | The tenant extension. Startup fails rather than run with a partial list. |
| 4 | `HINDSIGHT_API_DATABASE_SCHEMA` stays `public`. | The startup guard. |
| 5 | Upstream audit logging stays off; the extension logs key and membership events itself. | The startup guard refuses `HINDSIGHT_API_AUDIT_LOG_ENABLED=true` and any `HINDSIGHT_API_AUDIT_LOG_ACTIONS` but the image's `(none)`. That deployment-wide allowlist names no action, and upstream checks it before a bank's stored `audit_log_enabled`, so a bank that stored the setting under stock Hindsight or brought it in through an import or clone audits nothing. No bank can switch the setting on from the deploy on, and events go to `agent_keys.events`. |
| 6 | Extension code reaches data only through engine calls made with the caller's key. | Code review. The extension's own SQL touches only `agent_keys`, and it creates schemas through upstream's migration call. Purging a schema is an operator script, not extension code. |

## Upgrading upstream Hindsight

Each upstream release reaches Prod through a PR, a published digest and a platform admin's approval.

1. **PR.** The daily `upstream-release` workflow opens a PR that pins the new release and links its notes. A maintainer selects **Approve workflows to run**. Read the notes for changes to the tenant, HTTP or MCP extension interfaces, new routes that skip authentication, and new settings that would weaken isolation; each such setting needs a startup guard row.
2. **Merge.** A code owner merges once the `test` and `scan` checks pass. CI on `main` publishes the image, then the `verify-published` job runs the integration tests and the scan on that exact digest. Its summary names the tag and digest. Approve no other digest. To check its signature, see the README, "CI and publishing".
3. **Dev.** `platform_update_app container_image=ghcr.io/impulse-engineering/hindsight-agent-keys@sha256:<digest>`, then `platform_approve_image` (platform admin), then `platform_get_deploy_status` until the job is `completed` with `Applied image ref recorded:` naming the digest. Check on the bypass hostname that a request with no key gets 401 and that a key reaches its banks ([cutover.md](cutover.md), step 8).
4. **Prod.** Back up first ([cutover.md](cutover.md), step 1): the new release migrates `public` and every listed schema when it starts. Then deploy as on Dev.

**Auth state:** the bypass hostname can stay open. Every digest of this image runs the startup guard, so no container of it serves without our extension; the old container answers until the deploy completes, then the new one does. If the keyless check does not return 401, close the bypass hostname at once ([cutover.md](cutover.md), step 3).

**Going back** *(not verified)*. Once a new digest has started, the previous one is not a valid target: its upstream predates the migrations that ran, so do not use `platform_rollback_deploy` for it. Fix forward with a new digest. If the data is damaged, restore the dump taken in step 4 ([cutover.md](cutover.md), "Restore").

## Troubleshooting

The README's "Troubleshooting" table maps each symptom to its cause. These are the checks behind the common ones. The app's log is `journalctl -u app-$app --since -30min` on the CT; a deploy's log is in `platform_get_deploy_status`.

### A request gets 401

- **302 instead of 401:** the request went to the primary hostname, or the bypass hostname is closed. Agents use the bypass hostname.
- **The legacy key:** a `legacy_key_expired` event means it has passed `HINDSIGHT_API_TENANT_LEGACY_KEY_EXPIRES`. Otherwise `HINDSIGHT_API_TENANT_LEGACY_KEY` is unset, or the agent sends a different key.
- **An Agent Key** `hsk_<id>_<secret>`: this shows which rule refuses it *(not verified)*.

  ```sh
  # CT: type the <id> part of the key
  read -r -p 'Key ID: ' id &&
    echo "select k.kind, k.schema, k.expires_at, k.revoked_at, a.role, s.last_seen,
      k.kind = 'team' and k.schema <> 'public' and not exists (select 1 from agent_keys.members m
        where m.team = k.schema and m.email = k.email) as left_team
      from agent_keys.keys k left join agent_keys.allowlist a on a.email = k.email
      left join agent_keys.sign_ins s on s.email = k.email where k.id = :'id'" |
    pg psql -X -d hindsight -At -v id="$id"
  ```

  | Result | Cause |
  | --- | --- |
  | No row | The key was not created here: another environment, or a mistyped ID. |
  | `revoked_at` set | Revoked by its owner, by revoke identity, or by a schema purge. |
  | `expires_at` past | Expired. The owner creates a new key. |
  | `last_seen` empty or older than 30 days | The owner must open `/ext/`. If they did and `last_seen` did not move, the Access application's session duration is 30 days or more ("Access session length", above): shorten it, then have them sign out of Access and open `/ext/` again, so Access issues a new token. |
  | `role` empty or `requested` | The owner is off the Key Allowlist, unless they are a first admin. |
  | `left_team` true | The owner is no longer in the Team. |
  | None of these | The secret part is wrong (a mistyped or cut-off key), or the pepper changed since the key was created. |

- **The event log** *(not verified)*: `pg psql -d hindsight -Atc "select at, kind, key_id, client_ip from agent_keys.events where kind in ('key_refused', 'legacy_key_expired') order by id desc limit 20"`. It does not hold every refusal. Each client address gets at most one refusal row a minute, and through the Tunnel every caller is logged as the connector's address (#697 comment, item 8), so all agents share that one row. A refusal missing from the log does not mean the request was accepted.

### A schema the worker is not processing

Background tasks, such as an async retain, stay `pending` in one person's or one Team's banks.

1. **Is the schema on the tenant list?** The worker processes `public` and only the schemas this lists *(not verified)*:

   ```sh
   # CT
   pg psql -d hindsight -Atc "select schema from agent_keys.people where schema is not null union all select schema from agent_keys.teams"
   ```

   A personal schema missing from it was purged, or a purge stopped after unlisting it (README, "Stale personal schemas").
2. **Can the extension read its tables?** If the log shows `agent-keys: could not list tenants; using the last list`, the worker keeps the list it had, so schemas created since then are not processed. It picks them up once the database answers again.
3. **What is waiting?** Type the schema *(not verified)*:

   ```sh
   # CT
   read -r -p 'Schema: ' schema &&
     echo 'select status, count(*) from :"schema".async_operations group by 1' |
     pg psql -X -d hindsight -At -v schema="$schema"
   ```

   A `failed` operation whose error names the LLM provider is a problem with the LLM credentials, not with this image.
4. **After a rollback to stock Hindsight**, only `public` is processed: stock does not list the other schemas. Their data stays until the image comes back.

If `public` itself is not processed, check the startup log for its migration (README, "Troubleshooting").

### An image that refuses to start

The deploy's health checks fail, or the app restarts over and over. A refused start leaves the app down, never open: fix the cause, then approve or restart again.

| Log line | Cause | Fix |
| --- | --- | --- |
| `agent-keys guard: refusing to start: …`, exit status 78 | A setting the startup guard refuses (README, "Startup guard") | Change or delete the secret the line names |
| `Failed to instantiate extension 'AgentKeysTenantExtension': HINDSIGHT_API_TENANT_KEY_PEPPER must be at least 32 bytes` | The pepper is too short | Set the pepper from the password manager ([cutover.md](cutover.md), step 4.3) |
| `Failed to instantiate extension 'AgentKeysTenantExtension': HINDSIGHT_API_TENANT_LEGACY_KEY_EXPIRES is not an ISO date or datetime` | The legacy key's expiry cannot be read | Set it as `YYYY-MM-DD` |
| `ExtensionLoadError` naming `hindsight_agent_keys` | Stock Hindsight is running with our extension secret | Expected between steps 4.5 and 5 of the cut-over; otherwise the app runs the wrong image |
| A database error while startup migrates the schemas | pg0 or the `agent_keys` tables could not be read. Startup fails rather than skip a schema's migrations | Check that pg0 started, earlier in the same log |
| Health checks fail with HTTP 0 for about 30 seconds | pg0 is starting and migrating | Nothing; this is expected |

## Known limits

- **Client addresses.** The event log records the Tunnel connector's address for every caller through the Tunnel, not the caller's (#697 comment, item 8). Logging the real caller needs Conductor's nginx to pass `CF-Connecting-IP` for Tunnel traffic. Key creation limits count per person, so they are unaffected.
- **Routes without a key.** The bypass hostname answers a few routes without a key, none with memory data; the README lists them at the top.
- **Backups.** The whole-database `pg_dump` in [cutover.md](cutover.md), step 1, covers `public`, every personal and Team schema, and `agent_keys`. Upstream's `hindsight-admin backup` copies one schema's upstream tables and leaves out `agent_keys`.
- **The Access application.** If it is recreated, its AUD tag changes, and the key pages answer 403 "Sign in through Cloudflare Access" until `HINDSIGHT_API_TENANT_ACCESS_AUD` is set to the new `CF_ACCESS_AUD` from the app's `platform://apps/<app>/claude-md`.
