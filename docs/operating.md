# Operating multi-user Hindsight

How to run the `hindsight` app on this image day to day: the Key Allowlist, Agent Keys, Teams, the `hindsight-ui` app, revoking an identity, the kill switch for WorkPlane, upstream upgrades and troubleshooting. The [README](../README.md) states the rules each part enforces; this page says who does what and how to check it. The cut-over and its rollback are in [cutover.md](cutover.md).

Commands marked *(not verified)* have not been run on Dev. Commands marked **CT** run on the app's container, after the setup block in [cutover.md](cutover.md) (the one that defines `pg` and `api`).

| | Dev | Prod |
| --- | --- | --- |
| Key pages (behind Access) | `https://<primary>/ext/` | `https://<primary>/ext/` |
| Agents: API and MCP (bypass hostname) | `https://<bypass>` | `https://<bypass>` |

## Who does what

| Who | Where | What |
| --- | --- | --- |
| Anyone who signs in through Access | `/ext/` | Asks to join the Key Allowlist |
| People on the Key Allowlist | `/ext/`, `/ext/teams` | Create, renew and revoke their own keys; create Teams; ask to join a Team by name; join Open Teams; create Team and Public Team keys |
| Team owners on the Key Allowlist | `/ext/teams`, or WorkPlane | Add and remove members and owners; confirm or decline the people agents asked to add and the people who asked to join |
| Admins | `/ext/admin`, `/ext/teams` | Manage the Key Allowlist, revoke identities, revoke every key created via WorkPlane (the kill switch), see stale personal schemas, manage every Team, open and close Teams |
| Platform admins | Conductor and the CT | Set secrets (the first admins among them), approve digests, deploy, run CT commands |
| Agents | The bypass hostname | Use memory with an Agent Key over the API and MCP; with a personal key, manage Teams over MCP |

## The Key Allowlist

Only people on it can create Agent Keys.

- **First admins** come from the `AGENT_KEYS_ADMIN_EMAILS` secret, comma-separated. The image reads it at startup, so changing it with `platform_set_secret` restarts the app *(not verified)*. **Auth state:** down during the restart, then the same image and extension, so nothing opens. The page cannot change first admins (409), so to drop someone from the secret but keep them on the Key Allowlist: remove them from the secret (the app restarts), then add them on `/ext/admin` as a member or an admin. Between the two steps they are off the Key Allowlist and their keys get 401; adding them back makes those keys work again.
- **Everyone else** is managed on `/ext/admin`: add people by email, approve or decline requests, grant or remove admin rights, and remove people. A signed-in person who is not on the list sees a button on `/ext/` that files a request.
- **Removing someone** disables the keys they hold from their next request, without deleting them, and stops them acting as a Team owner: adding or removing members, asking for people to join, confirming or declining requests, and creating Team keys. Their Teams, ownership and memberships are kept, so adding the person back makes the keys and the owner actions work again. Until then they can still list and revoke their own keys and ask to be added back. To end someone's access, revoke their identity as well (below).
- **Listing it** from the CT *(not verified)*: `pg psql -d hindsight -Atc 'select role, email from agent_keys.allowlist order by 1, 2'`. The first admins come from the secret, so this can miss them.

Every change is recorded as an event in `agent_keys.events` (README, "The event log"). A change stored just before a stop or an event-log failure has no event row; the tables are the source of truth and nothing needs repairing (README, "Delegated Requests").

## Agent Keys

- **Creating.** A person on the Key Allowlist creates a personal key on `/ext/`, and a Team or Public Team key on `/ext/teams`. The key is shown once. An agent sends it as `Authorization: Bearer hsk_<id>_<secret>` on the bypass hostname, to the API and to MCP (`/mcp/` or `/mcp/<bank>/`). An agent that needs personal and Team memory holds two keys.
- **Limits.** Each person can create 5 keys an hour and hold 10 active keys, personal and Team keys together; past either, creation answers 429. Keys WorkPlane creates for them are counted apart: 25 active and 25 an hour by default (`HINDSIGHT_API_TENANT_WORKPLANE_ACTIVE_KEYS` and `..._KEYS_PER_HOUR`; lowering either revokes nothing). Each person can create 10 Teams.
- **90 days.** A key works for 90 days from its creation or its last renewal. Its owner renews an unexpired key, or revokes one, on `/ext/`; WorkPlane does the same for the keys it created. An expired or revoked key cannot be renewed; create a new one. Once the owner's 30-day sign-in has lapsed, renewal answers 403 on either channel until they sign in again.
- **30-day sign-in.** A key works only while its owner has signed in through Access within the last 30 days: a key page request, or a Delegated Request WorkPlane makes for them, dated by the `iat` of their own Access JWT. Tell people to open `/ext/`, or use WorkPlane, at least once a month. Opening it after a lapse means signing in again, which revives the held-back keys at once. This is also what stops a leaver's keys: once the identity provider disables them, their keys stop within 30 days without anyone touching Hindsight. To stop them at once, revoke the identity.
- **Access session length.** A sign-in is dated by the `iat` of the Access token, and Access keeps one token for a whole session. Keep the Access application's session duration under 30 days, including any policy session duration; Cloudflare's default is 24 hours. With 30 days or more, someone who opens `/ext/` every day can still have their keys stop. The same holds for WorkPlane's Access application, whose JWT dates a Delegated Request's sign-in.
- **Leaked key.** Its owner revokes it on `/ext/`; it fails on its next request, including inside an open MCP session. If the owner cannot, an admin revokes their identity.
- **The legacy key** reaches the Public Team until `HINDSIGHT_API_TENANT_LEGACY_KEY_EXPIRES`; on Prod that is 30 days after the cut-over ([cutover.md](cutover.md), step 9). Its users get on the Key Allowlist and create Public Team keys before then.
- **The pepper** (`HINDSIGHT_API_TENANT_KEY_PEPPER`) never changes: a new one invalidates every Agent Key at once. Without it, key creation answers 503 and every Agent Key gets 401, while the legacy key still works.

## Revoke identity

For someone who leaves, or whose keys must stop now:

1. On `/ext/admin`, enter their email to revoke their identity. Every key they hold, personal and Team, is revoked and fails on its next request, including inside an open MCP session. If that revoked any key, the event log records `identity_revoked` with you as `actor`.
2. Remove them from the Key Allowlist on the same page. Otherwise they can create new keys.
3. Remove them from their Teams on `/ext/teams`; admins see every Team there. Otherwise adding them back to the Key Allowlist later would give their new Team keys access again, and an owner would manage the Team again.

Their personal schema stays. It is listed as stale 90 days after their last key stopped working, and can then be purged (below).

To check from the CT, type their email; every key it lists shows a `revoked_at` *(not verified on Dev; runs in the integration tests)*:

```sh
# CT
read -r -p 'Email: ' email &&
  echo "select id, kind, schema, revoked_at from agent_keys.keys where email = :'email'" |
  pg psql -X -d hindsight -At -v email="$email"
```

An admin signed in to WorkPlane can also do steps 1 and 2 through it, for keys of either origin; the events then name WorkPlane as the `delegate`.

## Kill switch

For a compromised or misbehaving WorkPlane: stop everything it does in Hindsight at once. Do the steps in this order. Revoking the keys (step 2) stops their retain and recall, but not WorkPlane creating new keys for the people who use it: only deleting its service token (step 1) stops that.

1. **Stop Delegated Requests in Access** (a Cloudflare Zero Trust admin). Under **Access controls** > **Service credentials** > **Service Tokens**, delete WorkPlane's service token, the one whose client ID is `HINDSIGHT_API_TENANT_DELEGATE_CLIENT_ID`; a deleted token cannot be recovered. Then edit the delegation application and select **Revoke existing tokens**, which ends the sessions Access already issued to it. **Auth state:** from then on Access refuses every Delegated Request, so WorkPlane can neither manage access nor create keys, but the keys it created still retain and recall until step 2.
2. **Revoke every key created via WorkPlane** (an admin). On `/ext/admin`, under **Kill switch**, press **Revoke every key created via WorkPlane**. Every such key, personal or Team, whoever holds it, is revoked in one transaction and fails on its next request, including inside an open MCP session. Keys people created on `/ext/` keep working. The event log records `workplane_keys_revoked` with you as `actor`. No Delegated Request can do this, even an admin's, so it never depends on WorkPlane.
3. **Press it again a minute later.** A key creation that had already passed Hindsight's checks when step 1 took effect can still be stored after the first press. The second press revokes it. Pressing again is safe: it revokes only keys not yet revoked, and answers how many, normally 0.

If step 1 has to wait for an Access admin, do step 2 at once, then steps 1 to 3 as soon as you can: until step 1, WorkPlane can still create keys for the people who use it.

To check from the CT, this prints the number of keys created via WorkPlane that are not revoked, 0 after step 3 *(not verified on Dev; runs in the integration tests)*:

```sh
# CT
pg psql -X -d hindsight -Atc 'select count(*) from agent_keys.keys where via is not null and revoked_at is null'
```

To bring WorkPlane back once the cause is fixed *(not verified)*: create a new service token for it, add it to the delegation application's policy, and set `HINDSIGHT_API_TENANT_DELEGATE_CLIENT_ID` to its client ID with `platform_set_secret`, which restarts the app. **Auth state:** down during the restart; afterwards Hindsight accepts only the new token. Then give WorkPlane the token. The revoked keys stay revoked; WorkPlane creates new ones the next time each person uses it.

## Teams

- **Creating.** A person on the Key Allowlist creates a Team on `/ext/teams`, or an agent does with the MCP tool `create_team`; the creator is its first owner. A Team's ID (`t_…`), which the other MCP tools take, comes from `list_teams`.
- **Members.** Owners add people by email, as a member or an owner, including people who have not signed in yet, and remove them. An owner acts only while on the Key Allowlist; admins can manage every Team, and handle the requests of a Team with no owner on the list.
- **Join Requests.** Anyone on the Key Allowlist asks to join a Team by its name (the form on `/ext/teams`, the MCP tool `request_to_join_team`, or WorkPlane). The request waits under the Team, as an agent's does; any one owner on the Key Allowlist, or an admin, presses **Confirm** or **Decline**, on the page or by WorkPlane for the signed-in owner or admin, and never an agent. A person adding themselves to a Team they do not own, as a member or an owner, asks the same way, for that role. Asking tells the person nothing about whether the Team exists, so tell people the exact name.
- **Agents cannot add people on their own.** `add_team_member` over MCP only files a pending request, shown under the Team on `/ext/teams`. Nobody gains access until an owner on the Key Allowlist, or an admin, presses **Confirm** there (or WorkPlane confirms for them by Delegated Request), so a poisoned memory cannot add someone to a Team. Tell owners to expect these requests.
- **Open Teams.** An admin opens a Team under its entry on `/ext/teams`, or WorkPlane does for a signed-in admin. Anyone on the Key Allowlist then sees it under **Open Teams** and joins with **Join**, without asking; no agent joins for them. Closing it keeps its members, and new members then ask to join. A removed member may join an Open Team again, so close it first to keep someone out. The Public Team cannot be opened or closed (README, "Open Teams").
- **Waiting requests.** An agent holding a personal key learns that requests wait with the MCP tool `pending_reviews`, and `list_teams` returns the same in its `pending_reviews` field. That field is counts and the link to `/ext/teams` only, so it holds no Team name or email; the rest of `list_teams` still lists Teams and the people in and asking to join them, as before. For an owner it counts the requests for their Teams; for an admin it also counts those for other Teams left waiting more than 7 days, and the Key Allowlist's. Tell people to expect their agent to mention them at the start of a session. The tool does not replace the page, which lists who is waiting.
- **Removing a member** stops their Team keys on their next request. A Team's data stays whoever leaves, and Team schemas are never listed for purging.
- **Over MCP**, the Team tools need a personal Agent Key; a Team key, a Public Team key or the legacy key gets an error. A bank whose config sets `mcp_enabled_tools` hides them on that bank's endpoint unless it names them.
- **The Public Team** has no owners or members: everyone on the Key Allowlist can create a Public Team key.

## The UI app

The `hindsight-ui` app runs the UI image (README, "The UI image"): one upstream UI per Team, each on its own port and hostname, all behind the app's Access policy (on Prod, platform admins). A UI shows its Team's banks to everyone that policy admits.

- **Its keys** are Agent Keys like any other, held by whoever created them: a Team key, created on `/ext/teams` by a member of the Team, or a Public Team key for `public`. A UI stops showing banks when its key stops, so the holder opens `/ext/` at least once every 30 days and renews the key on `/ext/` before its 90 days run out. A renewed key keeps its value, so the secret stays as it is. A replaced key needs its secret set again, which restarts the app.
- **The Team's label** is a short name you pick for the Team in this app, such as `silver-air`: lowercase letters, digits and inner hyphens. It need not be the Team's name on `/ext/teams`, which can hold spaces and capitals. It names the Team's entry in `HINDSIGHT_UI_TEAMS`, its key secret `HINDSIGHT_UI_KEY_<LABEL>` (upper-cased, `-` as `_`), its `image_ports` label and its hostname.
- **How many.** An app declares at most 36 ports, one per Team. Each UI takes roughly 150 to 200 MB and an app has at most 8 GB, so 36 Teams is also near the memory ceiling. Raise `alloc_ram_mb` (`platform_update_app`, platform admin) as Teams are added.
- **A refused start** leaves every Team's UI down, never open: the log's `ui-start: refusing to start:` lines name each problem. Fix the secret they name; setting it restarts the app.

### Adding a Team *(not verified)*

Do the steps in this order. Each `platform_set_secret` and the deploy restart the app, so every Team's UI is down for a few seconds, and down until fixed if the start is refused. Nothing opens at any point: the new Team's port is not published until step 3, and its hostname comes last, behind Access. An interruption leaves a state the next step picks up from: after step 1 nothing reads the new key; after step 2 the new UI runs inside the CT where nothing routes to it; after step 3 its port is published on the CT but no hostname reaches it; after step 4 it is done.

1. **Its key.** Create a Team key for the Team on `/ext/teams`. Register the secret `HINDSIGHT_UI_KEY_<LABEL>` with `platform_request_secret` and set it with `platform_set_secret`.
2. **The Team list.** Set `HINDSIGHT_UI_TEAMS` to the current list plus `<label>:<port>`, with a port no listed Team uses (the next after the highest, such as `10000` after `9999`). If the app then refuses to start, fix what its log names (above).
3. **The port.** With `platform_update_app`, append `{"port": <port>, "label": "<label>"}` to `image_ports`, keeping every existing entry as it is and in order (they are append-only), then deploy with `platform_deploy_lxc`. The deploy publishes the port; wait until `platform_get_app` lists it under `applied_image_ports`.
4. **The hostname.** `platform_request_domain` for the Team's hostname with `container_port_label` set to `<label>`. On this internal app the hostname is behind the app's Access application before it routes.
5. **Check.** Open the hostname: it lists the Team's banks and no other Team's.

### Moving `hindsight-ui` onto the image *(not verified)*

The app ran stock upstream with one key in `HINDSIGHT_CP_DATAPLANE_API_KEY`. Keep that secret until the new image is checked: stock upstream reads it, so going back is `platform_update_app` to the stock digest, then `platform_approve_image`. Conductor refuses `platform_rollback_deploy` across repositories, as in [cutover.md](cutover.md), "Rollback".

1. **The package.** The first publish creates the `hindsight-ui` package private, and the org allows only private packages. Make it public as `hindsight-agent-keys` is: on GitHub, allow Public in the org's Packages settings, set the package's visibility to Public, then allow only Private again; there is no API for it. Check that an anonymous pull token for `repository:impulse-engineering/hindsight-ui:pull` is granted before going on, or the deploy fails to pull.
2. **The new secrets.** Check first that the app's `HINDSIGHT_ENABLE_API` secret, if it has one, is `false`; a secret overrides the image's `false`. Then register `HINDSIGHT_UI_KEY_PUBLIC` and `HINDSIGHT_UI_TEAMS` with `platform_request_secret`. Set the first to the key the app holds now and the second to `public:9999`, the port the app already publishes. Stock upstream ignores both; each set restarts it unchanged.
3. **The image.** `platform_update_app container_image=ghcr.io/impulse-engineering/hindsight-ui@sha256:<digest>`, with the digest `verify-published` passed. This revokes the old approval; the running container keeps serving. Then `platform_approve_image` (platform admin), which deploys it: wait as in [cutover.md](cutover.md), step 2.4. The hostnames keep the same Access application throughout, so nothing opens. A refused start leaves the app down, not open; fix what its log names.
4. **Check** that each hostname lists the Public Team's banks, then add the other Teams as above. `HINDSIGHT_CP_DATAPLANE_API_KEY` is no longer read; delete it once the image has run without needing to go back. Leave `HINDSIGHT_ENABLE_API` at `false`, or delete it so the image's own `false` applies, and never set it to anything else: upstream's launcher reads it, and the image relies on it to start no API.

## Webex notices

The extension sends Webex direct messages from a bot: to a Team's owners on the Key Allowlist when someone asks to join, to the other owners on the Key Allowlist when an owner or an admin (an agent) asks for someone else to join, to the admins when someone asks for the Key Allowlist, and to the person who asked when their request is decided, unless they made the decision themselves (README, "Webex notices", has the rules and what an interruption leaves). They are best effort and the pages stay the source of truth, so nothing here is needed for Hindsight to work. Joining an Open Team is direct, so it sends no notice; only a Join Request on a Team that is not open does. Once a day, at the first sweep after 13:00 UTC (or earlier that day, at a start after a missed day; never within 20 hours of the run before), the same background task also reminds owners and admins of requests left waiting more than 3 days (admins hear of a request to join a Team after 7), and warns people 14 days before a key of theirs expires and 7 days before their sign-in window closes; there is no separate job to run (README, "Webex notices", has who hears what, when, and what an interrupted run leaves).

**Setting up** *(not verified)*:

1. **Create the bot** (a Webex developer account in the organization). On developer.webex.com create a bot (**My Webex Apps**, **Create a New App**, **Create a Bot**): its name, username and icon are what people see in their Webex app. The page then shows the bot's access token once. Copy it into the password manager entry for the app; do not paste it into a terminal or a chat. Note the expiry the bot's page shows for the token. If it shows one within a year, add a renewal reminder for the date.
2. **Set the secret.** `HINDSIGHT_API_TENANT_WEBEX_BOT_TOKEN` is a secret like the pepper: Conductor keeps it in the app's `.env` on the CT, and the image itself holds no `.env` (README, "Startup guard"). Register it with `platform_request_secret`, then set it as [cutover.md](cutover.md), step 4.3, sets the pepper, so the value comes from a file and never appears in a terminal or a chat; trash the file afterwards and empty the Trash. Setting it restarts the app. **Auth state:** down during the restart, then the same image and extension, so nothing opens. The three `ACCESS` settings must be set too (README, "Configuration"); without them nothing is sent.
3. **Check once on Dev** with a test person who has never messaged the bot. Each of these must hold, or no notice is queued and the check proves nothing:
   - the test person is on the Key Allowlist and has not turned Webex notices off on `/ext/`;
   - they are an owner of a new Team that is not open (an Open Team is silent: joining it is direct);
   - a second person, also on the Key Allowlist, who is not in that Team and has no request waiting for it, asks to join it by name, which files a new Join Request.

   The owner should see the message in their Webex app. For the admin variant instead, make the test person an admin (notices on), and have someone with no place on the Key Allowlist at all (not a member, not an admin, and no request of theirs waiting: decline an old one first) sign in and ask for it, which files a new request. It passes on HTTP 200 (`sent` in the send log below) and the message shown in their Webex app. Whether a bot may message a person by email before that person has messaged it is exactly what this checks. Fill in the table below.

**Dev check and token record.** Fill in a row when the check runs, and again each time the token is regenerated.

| Date | Who ran it | Result: HTTP status, and whether the message showed in Webex | Token expiry the bot's page showed |
| --- | --- | --- | --- |
| *(not yet run)* | | | |

**Renewing the token.** Before the date in the reminder, regenerate the token on the bot's page and set the secret again as in step 2. If the token is wrong or has expired, messages fail with `HTTP 401` in the send log and nobody is told anything; the pages are unaffected. With no token set at all, nothing is queued and the send log gets no rows.

**Reading the send log** from the CT: one row per claimed message, newest first, with the person, how many notices it held, its status (`sent`, `skipped`, `failed` or `sending`), and why it was not sent *(not verified on Dev; runs in the integration tests)*:

```sh
# CT
pg psql -X -d hindsight -Atc 'select at, recipient, items, status, detail from agent_keys.notice_log order by id desc limit 20'
```

- `skipped` means nothing was sent: the person turned notices off after their message was claimed, or (`no longer eligible`) lost what made it theirs to read, such as owning the Team or being an admin, before it went.
- `failed` with `HTTP 401` is a wrong or expired token; `HTTP 429, retry after N s` is a rate limit; any other `HTTP` status comes with Webex's reason, such as a person it cannot find by that email. The notices in a failed message are not sent again.
- `sending` for more than a minute means the process stopped between claiming the message and recording its outcome, or the outcome could not be written (the logs say `agent-keys: could not write the Webex send log`). The person may or may not have the message, and nothing sends it again; the pages show the request.
- No row at all for a person who should have been told: they turned notices off, they were not eligible when the message was claimed (no longer an owner on the Key Allowlist or an admin, or a key holder taken off the Key Allowlist or whose key no longer works), the change was stored but its notice could not be queued (the logs say `agent-keys: could not queue a Webex notice`), or the token is unset and nothing is queued. For a reminder or a warning: it was not due at the day's run (README, "Webex notices"), or the day has not been run yet (`agent_keys.reminder_runs` lists the days run). A warning queued by a release before the one that names each warning's key, and still waiting at its first start, was dropped then, unsent.

**People turn them off** with the switch on `/ext/`; there is no admin switch. The pages and the MCP tools are the same either way.

## Stale personal schemas

`/ext/admin` lists each personal schema that no valid key has reached for 90 days. Nothing is deleted on its own. To purge one, follow the README, ["Stale personal schemas"](../README.md#stale-personal-schemas): take a backup first ([cutover.md](cutover.md), step 1), copy `scripts/purge-schema.sql` onto the CT, and run it for one schema at a time. If it stops after `Unlisted`, read its last error: `no rows returned for \gset` means the schema is in use again and nothing was dropped; any other error means follow the README's recovery, which puts the schema back on the list only if it still exists, then run the script again. If the recovery returns no row because the schema is gone, the purge is done.

## The Public Team stays in `public`

The banks that existed before the cut-over are the Public Team, in the `public` schema. Upstream falls back to `public` on unauthenticated code paths, so it stays there only while all six of these conditions hold (#697). Change none of them without first moving the Public Team out of `public`.

| | Condition | What holds it |
| --- | --- | --- |
| 1 | `HINDSIGHT_API_MCP_AUTH_TOKEN` is never set. | The startup guard refuses it, even empty. Upstream reads it from the environment only; no bank or tenant config can set it. |
| 2 | `authenticate()` rejects unknown keys and never returns an empty schema. | The tenant extension. A key it does not accept gets 401; an accepted key reaches `public`, a `p_…` schema or a `t_…` schema, and the keys table refuses an empty schema. |
| 3 | `list_tenants()` returns `public` once, plus every personal and Team schema. | The tenant extension. Startup fails rather than run with a partial list. |
| 4 | `HINDSIGHT_API_DATABASE_SCHEMA` stays `public`. | The startup guard. Upstream reads it from the environment only; no bank or tenant config can set it. |
| 5 | Upstream audit logging stays off; the extension logs key and membership events itself. | The startup guard refuses `HINDSIGHT_API_AUDIT_LOG_ENABLED=true` and any `HINDSIGHT_API_AUDIT_LOG_ACTIONS` but the image's `(none)`. `audit_log_enabled` is the only setting the guard checks that a bank's or tenant's config can override. The deployment-wide allowlist names no action, and upstream checks it before a tenant's config or a bank's stored `audit_log_enabled`, so nothing is audited whichever writer stored the setting, under stock Hindsight or since: bank creation, a bank template, the bank config API, an import or a clone. No bank can switch the setting on from the deploy on, and events go to `agent_keys.events`. |
| 6 | Extension code reaches data only through engine calls made with the caller's key. | Code review. The extension's own SQL touches only `agent_keys`, and it creates schemas through upstream's migration call. Purging a schema is an operator script, not extension code. |

## Upgrading upstream Hindsight

Each upstream release reaches Prod through a PR, a published digest and a platform admin's approval.

1. **PR.** The daily `upstream-release` workflow opens a PR that pins the new release and links its notes. A maintainer selects **Approve workflows to run**. Read the notes for changes to the tenant, HTTP or MCP extension interfaces, new routes that skip authentication, and new settings that would weaken isolation; each such setting needs a startup guard row. The unit tests fail if the release lets a bank or tenant override another setting the guard checks. Drop each pin in `docker/pins.txt` (the API's venv) and `docker/system-pins.txt` (upstream's uv in the system Python) that the release already meets, since an exact pin would downgrade it, and regenerate the file with the Dockerfile's recipe for it (each file has its own, beside the `RUN` line that installs it). Once a file has no pin left, delete it and its Dockerfile block: its comments, recipe and `RUN` line (for `system-pins.txt`, the `USER` lines around it too).
2. **Merge.** A code owner merges once the `test` and `scan` checks pass. CI on `main` publishes the image, then the `verify-published` job runs the integration tests and the scan on that exact digest. Its summary and a notice on the run name the tag and digest. Approve no other digest. To check its signature, see the README, "CI and publishing".
3. **Dev.** `platform_update_app container_image=ghcr.io/impulse-engineering/hindsight-agent-keys@sha256:<digest>`, then `platform_approve_image` (platform admin), then `platform_get_deploy_status` until the job is `completed` with `Applied image ref recorded:` naming the digest. A `failed` before the job's final state does not count, and nothing is stopped because of it ([cutover.md](cutover.md), step 2.4). Check on the bypass hostname that a request with no key gets 401 and that a key reaches its banks ([cutover.md](cutover.md), step 8). Deploy the run's `hindsight-ui` digest to a UI app the same way, after the API it calls.
4. **Prod.** Back up first ([cutover.md](cutover.md), step 1): the new release migrates `public` and every listed schema when it starts. Then deploy as on Dev.

**Auth state:** the bypass hostname can stay open. Every digest of this image runs the startup guard, so no container of it serves without our extension; the old container answers until the deploy completes, then the new one does. If the keyless check does not return 401, close the bypass hostname at once ([cutover.md](cutover.md), step 3). A UI app's hostnames stay behind its Access application throughout its deploy: the old UI answers until the deploy completes, then the new one does, and a refused start leaves it down, not open.

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
  | `last_seen` empty or older than 30 days | The owner must open `/ext/` (or use WorkPlane). If they did and `last_seen` did not move, the Access application's session duration is 30 days or more ("Access session length", above): shorten it, then have them sign out of Access and open `/ext/` again, so Access issues a new token. |
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
