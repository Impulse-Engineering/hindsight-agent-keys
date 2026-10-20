# Moving a Conductor app onto this image

This runbook takes a Conductor Image App running stock Hindsight with embedded pg0 onto this image, and back. Dev ran it first (Impulse-Engineering/aseva-foundation-hosting#703) and runs the image now. Prod follows the same steps in the same order (#712). The **Prod** notes under a step record what the Dev run showed about Prod (#697, comment "Dev cut-over (#703)"). Confirm each change with the app owner before running it. Running the app afterwards is in [operating.md](operating.md).

Every command here ran on Dev in #703, step 1's block and `banks` in #710, and step 5's `platform_update_app`, `platform_approve_image` and deploy-status check again in #711, unless it is marked *(not verified)*. Record what an unverified command printed on the cut-over ticket.

Each step that restarts or redeploys the app names its **auth state**: what a caller can reach during and after it. The bypass hostname reopens only after a request with no key has returned 401 from the container that is running at that moment.

| | Dev | Prod |
| --- | --- | --- |
| App | `hindsight` on Conductor Dev | `hindsight` on Conductor Prod |
| Container | `<vmid>` on `<node>`, nginx on `<port>` | `<vmid>` on `<node>`, nginx on `<port>` |
| Conductor API | `https://<conductor>/api` on Dev | `https://<conductor>/api` on Prod |
| Primary hostname (behind Access) | `<primary>` | `<primary>` |
| Bypass hostname (`access_exempt`) | `<bypass>` | `<bypass>` |
| UI hostname (removed in step 7) | `<ui>` | `<ui>` |

This repo is public, so it names no real hostnames or hosts. Read the hostnames, container and port from the app's record in Conductor (`platform_get_app`). `<conductor>` is the host of the environment's Conductor UI, the one you sign in to through Access.

The order:

1. Back up.
2. Upgrade to stock 0.10.3 and check it.
3. Close the bypass hostname.
4. Set the secrets.
5. Approve and deploy the image.
6. Confirm a request with no key returns 401.
7. Remove the UI hostname.
8. Reopen the bypass hostname.
9. Record the legacy key's expiry.

The secrets come before the deploy, although the spec (#697) names them after it. The image refuses to start while the app's `HINDSIGHT_API_TENANT_EXTENSION` secret names stock's extension, and without the legacy key every existing client gets 401 (#697 comment, item 2).

Conductor has no MCP tool for switching a domain's `access_exempt`, removing a domain, or deleting a secret (platform admin only). Use the app's Domains and Secrets panels in the Conductor UI, or its REST API through `cloudflared access curl`, which reuses your Access login. The REST API also sets a secret from a file, so its value never appears in a terminal or a chat.

```sh
# Operator machine
capi=https://<conductor>/api/apps/hindsight
cloudflared access curl "$capi/domains" -sS   # the app's extra hostnames and their ids; the primary is not listed
closed() { [ "$(curl -sS -o /dev/null -w '%{http_code}' "https://$1/health")" = 302 ] && echo "bypass closed OK" ||
  { echo "STOP: the bypass hostname still answers without Access"; return 1; }; }   # closed <bypass> (not verified)
```

Commands marked **CT** run as root on the app's container: `ssh root@<node>`, then `pct enter <vmid>`. `podman exec` fails there (`setrlimit RLIMIT_NOFILE`), so the database tools run in a throwaway container that joins the app's network and borrows pg0's own PostgreSQL binaries from the volume. pg0's user, password and database are all `hindsight` (upstream's defaults in `hindsight_api/pg0.py`), and the database is reachable only inside the app container's network namespace.

```sh
# CT: set up once per shell
app=hindsight port=<port>
pg0=/var/lib/apps/$app/home/hindsight/.pg0
pg() { t=$1; shift; podman run --rm -i --network "container:app-$app" -e PGPASSWORD=hindsight \
  -e LD_LIBRARY_PATH=/pgbin/lib -v "$(ls -d $pg0/installation/*/ | tail -1):/pgbin:ro" --entrypoint "/pgbin/bin/$t" \
  "$(podman ps --filter "name=^app-$app\$" --format '{{.Image}}')" \
  -h 127.0.0.1 -p "$(sed -n 4p $pg0/instances/hindsight/data/postmaster.pid)" -U hindsight "$@"; }
api() { curl -sS -o /dev/null -w '%{http_code}\n' "$@"; }
keyless() { [ "$(api "$@")" = 401 ] && echo "keyless 401 OK" || { echo "STOP: no 401 without a key; do not reopen the bypass hostname"; return 1; }; }   # (not verified)
banks() { pg psql -d hindsight -Atc "select b.bank_id, (select count(*) from memory_units m where m.bank_id = b.bank_id),
  (select count(*) from documents d where d.bank_id = b.bank_id), (select count(*) from mental_models x where x.bank_id = b.bank_id)
  from banks b order by 1"; }   # bank_id|memory units|documents|mental models
key=$(sed -n 's/^HINDSIGHT_API_TENANT_LEGACY_KEY=//p' /etc/apps/$app/.env)   # empty until step 4; Conductor writes each secret there
```

## 1. Back up

```sh
# CT. Stop the cut-over unless this ends with "backup OK"
out=/root/$app-pg0-$(date -u +%Y%m%dT%H%M%SZ).dump
pg pg_dump -Fc hindsight > "$out" &&
  pg pg_restore -f /dev/null < "$out" &&   # reads every block, so a truncated dump fails here
  pg pg_restore --list < "$out" > "$out.toc" && grep ' TABLE ' "$out.toc" > /dev/null &&
  banks > /root/$app-banks-before.txt && cat /root/$app-banks-before.txt &&   # the baseline for steps 2 and 6
  sha256sum "$out" && echo "backup OK" || { echo "BACKUP FAILED: do not continue"; false; }
```

- Copy the dump off the CT: on the node, `pct pull <vmid> /root/<file> /root/<file>`, then `scp` it somewhere safe. Its `sha256sum` there must match the one above.
- Take a fresh vzdump of the CT on the node: `vzdump <vmid> --mode snapshot --storage <PBS storage>`. Dev's rootfs cannot snapshot, so there it falls back to suspend mode. Check the archive with `pvesm list <storage> --vmid <vmid>`. A reused VMID can carry an older tenant's archives, so compare dates with the app's `created_at`.

**Prod:** the Prod CT's rootfs can snapshot, so vzdump can take a snapshot (#697 comment, item 7). The two existing banks in the snapshot are the Public Team; #712 compares their counts after the cut-over.

### Restore

*(Not verified on Dev: drilled locally, restoring a 0.9.2 dump into stock 0.10.3 with the worker running.)* Restore into a side database in the running app, then swap it in by name. The app's live sessions never see a half-restored database: writes before the swap land in the old one and are dropped with it. The app's image may be newer than the dump; it migrates the restored data at the next start. Close the bypass hostname first (step 3).

```sh
# CT
pg dropdb --if-exists hindsight_restore && pg createdb hindsight_restore &&
  pg pg_restore --exit-on-error -d hindsight_restore < /root/<file>.dump &&
  pg dropdb --force hindsight &&
  pg psql -d postgres -v ON_ERROR_STOP=1 -c 'ALTER DATABASE hindsight_restore RENAME TO hindsight' &&
  systemctl restart app-$app
```

**Auth state:** with the bypass hostname closed, only callers signed in through Access reach the app. The restart brings back the same image and secrets.

Then check `/version`, and `banks` against the snapshot taken with the dump. If the app no longer starts, PBS file-restore can pull `/var/lib/apps/<app>/home/hindsight/.pg0` out of the vzdump archive. That copy only runs on the image digest it was taken with, because pg0 keeps its PostgreSQL binaries and pgvector in the same directory.

## 2. Upgrade to stock Hindsight and check it

The target is the upstream digest this image is built on: `scripts/upstream-ref.sh` prints its tag and digest. Skip the upgrade if the app already runs it.

1. `platform_resolve_image_version tag=<tag>` *(not verified)* must return that digest.
2. `platform_update_app container_image=ghcr.io/vectorize-io/hindsight@sha256:<digest>`.
3. `platform_approve_image` (platform admin). On a live app this queues the deploy itself and returns its `job_id`. Its health checks fail with HTTP 0 for about 30 seconds while pg0 starts and migrates. That is expected.
4. `platform_get_deploy_status` shows the job `completed`, with `Applied image ref recorded:` naming the digest from 2 *(not verified for the stock image; the same check ran for step 5's deploy in #711)*.

**Auth state:** unchanged. Stock Hindsight keeps the app's tenant secrets across the deploy; on Prod that is stock's ApiKey extension with the shared key.

On the CT, `curl -sS http://127.0.0.1:$port/version` shows the new version, and `banks | diff /root/$app-banks-before.txt -` *(not verified)* shows every bank still present, with no count lower. Counts can grow if tasks queued before the change finish.

**Prod:** already runs stock 0.10.3 (`b5da1a9a…`, #697 comment, item 1). Skip 1 to 4 and only check: `platform_get_app` *(not verified)* shows a `container_image` with the digest `scripts/upstream-ref.sh` prints, and `/version` on the CT shows 0.10.3.

## 3. Close the bypass hostname

```sh
# Operator machine. Go no further until this prints "bypass closed OK" (not verified)
cloudflared access curl "$capi/domains/<id>" -sS -f -X PATCH -H 'Content-Type: application/json' --data '{"access_exempt": false}' &&
  closed <bypass>   # (not verified)
```

The change takes a few seconds to reach Cloudflare. If `closed` prints STOP right after a PATCH that succeeded, wait and run `closed <bypass>` again; go on only once it prints `bypass closed OK` *(not verified)*.

If the app has no bypass hostname yet, create it closed: `platform_request_domain domain_type=managed domain=<bypass label> managed_domain_id=<zone> access_exempt=false`, where `<bypass label>` is `<bypass>` without the zone suffix and `<zone>` is that zone's id from `platform_list_managed_domains` *(not verified)*. Its certificate takes a few minutes. Until then, TLS handshakes fail.

**Auth state:** from `bypass closed OK` on, both hostnames are behind Access. Agents on the bypass hostname get 302 until step 8.

**Prod:** the bypass hostname is already exempt (#697 comment, item 6), so this closes it, and Prod's agents are down from here to step 8.

## 4. Set the secrets

Copy the current value of every secret this step or step 6 changes into the password manager first; rollback needs them. They are in `/etc/apps/$app/.env` on the CT. Register each new key with `platform_request_secret` before setting it.

Each change restarts the app, so keep this order. Until 4.5, stock Hindsight restarts with its own tenant extension, which ignores the new settings: upstream hands every `HINDSIGHT_API_TENANT_*` variable to the configured extension, and stock's reads only its own.

**Auth state:** through 4.1 to 4.4, the app's current tenant extension, behind Access. 4.5 stops stock Hindsight, and the app stays down until step 5 completes.

1. Register the legacy key: `platform_request_secret key_name=HINDSIGHT_API_TENANT_LEGACY_KEY`. Then set its value from a file. The legacy key is the deployment's existing shared key: on Prod, the value of `HINDSIGHT_API_TENANT_API_KEY`.

   ```sh
   # Operator machine
   python3 -c 'import json,sys; print(json.dumps({"value": open(sys.argv[1]).read().strip()}), end="")' <key file> |
     cloudflared access curl "$capi/secrets/HINDSIGHT_API_TENANT_LEGACY_KEY" -sS -f -X PUT -H 'Content-Type: application/json' --data-binary @-   # prints "is_set":true
   ```

   **Prod:** write the key file on the CT without printing the key *(not verified)*, then copy it to the operator machine as the dump in step 1:

   ```sh
   # CT
   (umask 077; sed -n 's/^HINDSIGHT_API_TENANT_API_KEY=//p' /etc/apps/$app/.env > /root/$app-legacy-key)
   ```

2. Prod only: register `HINDSIGHT_API_TENANT_LEGACY_KEY_EXPIRES` and set it to the cut-over date plus 30 days (#697), for example `2026-11-30`. A bare date means midnight UTC. It is not secret, so `platform_set_secret` is fine *(not verified)*. The extension treats it as optional, so step 6 checks it is there, and step 9 records it.
3. Set the Agent Key settings (README, "Configuration"). Until all of them are set in the image, the key pages refuse every request and no key can be created, while the legacy key keeps working.
   - `HINDSIGHT_API_TENANT_KEY_PEPPER`: generate it straight into a file, so it never appears in a terminal or a chat, and set it from that file as in 4.1 *(not verified)*:

     ```sh
     # Operator machine
     (umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(48))' > pepper)
     python3 -c 'import json,sys; print(json.dumps({"value": open(sys.argv[1]).read().strip()}), end="")' pepper |
       cloudflared access curl "$capi/secrets/HINDSIGHT_API_TENANT_KEY_PEPPER" -sS -f -X PUT -H 'Content-Type: application/json' --data-binary @-   # prints "is_set":true
     ```

     Attach the file to the app's entry in the password manager, then trash it and empty the Trash. Never change the pepper later: a new one invalidates every Agent Key.
   - `HINDSIGHT_API_TENANT_ACCESS_TEAM_DOMAIN` and `HINDSIGHT_API_TENANT_ACCESS_AUD`: the `CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_AUD` values in the app's `platform://apps/<app>/claude-md`. If either reads `N/A`, the app's primary hostname has no Access application to validate against; fix that first. Not secret, so `platform_set_secret` is fine *(not verified)*.
   - `HINDSIGHT_API_TENANT_ACCESS_HOST`: the app's primary hostname, from the table above. `platform_set_secret` *(not verified)*.
   - `AGENT_KEYS_ADMIN_EMAILS`: the first admins, comma-separated. `platform_set_secret` *(not verified)*.
4. Delete any other secret the startup guard refuses (README, "Startup guard"), for example `HINDSIGHT_API_MCP_AUTH_TOKEN`, with `cloudflared access curl "$capi/secrets/<KEY>" -sS -f -X DELETE` (platform admin) *(not verified)*. Otherwise the deploy exits 78 and its log names the variable. `platform_get_secret_keys` *(not verified)* lists the app's secrets; delete only those listed, since `-f` fails on one that is not there. **Prod:** #697 found only the tenant ones.
5. Last, if the app has a `HINDSIGHT_API_TENANT_EXTENSION` secret, set it to `hindsight_agent_keys.extension:AgentKeysTenantExtension` *(not verified on Dev, which had none; the stop was checked locally on stock 0.10.3)*. Do not delete it: deleting it restarts stock Hindsight with no tenant extension, which admits every request into `public`. Stock Hindsight cannot import our class, so it stops (`ExtensionLoadError`) and stays down until step 5. A secret overrides the image's own value, and the guard accepts only ours. Go straight on to step 5.

The six conditions that keep the Public Team safe in `public` are in [operating.md](operating.md#the-public-team-stays-in-public).

## 5. Approve and deploy the image

1. `platform_update_app container_image=ghcr.io/impulse-engineering/hindsight-agent-keys@sha256:<digest>`, a digest whose `verify-published` job passed. Use the newest such digest, and run it on Dev first.
2. `platform_approve_image` (platform admin) queues the deploy. Check it as in step 2.4.

**Auth state:** during the deploy, the app is down on Prod (stock stopped in 4.5); on Dev, which had no tenant extension to replace, stock ran until the new container took over, behind Access. After it, this image with our extension; the guard refuses to start it otherwise. Both hostnames are still behind Access. If the deploy log shows exit status 78, the guard names the variable: fix it as in step 4 and approve again. The app stays down meanwhile.

## 6. Confirm a request with no key returns 401

```sh
# CT (re-run the key= line from the setup block)
api http://127.0.0.1:$port/health                                       # 200
keyless http://127.0.0.1:$port/v1/default/banks                         # keyless 401 OK (not verified)
api -H "Authorization: Bearer $key" http://127.0.0.1:$port/v1/default/banks   # 200
banks | diff /root/$app-banks-before.txt -   # every bank from step 1, no count lower (not verified)
sed -n 's/^HINDSIGHT_API_TENANT_LEGACY_KEY_EXPIRES=//p' /etc/apps/$app/.env   # Prod: the date from step 4.2 (not verified)
journalctl -u app-$app --since -10min | grep -iE 'agent-keys|tenant|migrat'   # extension loaded, public migrated, no event-log warning
pg psql -d hindsight -Atc 'select * from agent_keys.events order by 1 desc limit 5'   # the 401 above, as key_refused
```

The check runs on the CT because both hostnames are behind Access now. **Prod:** the `banks` diff must be empty: #712 requires the two banks unchanged.

Then delete the secrets the image no longer reads: `cloudflared access curl "$capi/secrets/<KEY>" -sS -f -X DELETE` (platform admin) *(not verified)* for each of `HINDSIGHT_API_TENANT_API_KEY`, `HINDSIGHT_CP_DATAPLANE_API_KEY` and `HINDSIGHT_API_TENANT_EXTENSION` that `platform_get_secret_keys` *(not verified)* lists; `-f` fails on a secret that is not there (Dev has no `HINDSIGHT_API_TENANT_EXTENSION`). Each deletion restarts the app.

**Auth state:** down during each restart. After it, this image again; once the `HINDSIGHT_API_TENANT_EXTENSION` secret is gone, the image's own value applies, which is ours. After the last deletion, run the keyless check again:

```sh
# CT
keyless http://127.0.0.1:$port/v1/default/banks   # keyless 401 OK, from the container now running (not verified)
```

## 7. Remove the UI hostname

```sh
# Operator machine
cloudflared access curl "$capi/domains/<id>" -sS -f -X DELETE   # (not verified)
```

Port 9999 stays in `image_ports`: Conductor keeps a deployed port there for good (`imagePortsAppendOnlyError`, aseva-foundation-hosting `conductor/docs/LXC-CONTAINER-PIPELINE.md`, "`image_ports` is append-only after provisioning"). Nothing listens on it.

**Auth state:** during and after the removal, the app runs this image with our extension, and the primary and bypass hostnames stay behind Access. The UI hostname reaches nothing (nothing listens on 9999), then is gone. This is the last change to the app before step 8 reopens the bypass hostname, so check again that a request with no key gets 401 from the container running now:

```sh
# CT
keyless http://127.0.0.1:$port/v1/default/banks   # keyless 401 OK (not verified)
```

## 8. Reopen the bypass hostname and verify

Only once the keyless check at the end of step 7 printed `keyless 401 OK`: switch the bypass domain to `access_exempt=true`, as in step 3 with `--data '{"access_exempt": true}'`. Then:

```sh
# Operator machine
b=https://<bypass>
key=$(cat <key file>)   # the file step 4 set the key from
[ "$(curl -sS -o /dev/null -w '%{http_code}' $b/v1/default/banks)" = 401 ] && echo "keyless 401 OK" ||
  { echo "STOP: no 401 without a key; close the bypass hostname again (step 3)"; false; }            # (not verified)
curl -sS -H "Authorization: Bearer $key" $b/v1/default/banks                                      # the bank_ids in step 1's snapshot
curl -sS -H "Authorization: Bearer $key" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' $b/mcp/ \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_banks","arguments":{}}}'   # the same banks
```

**Auth state:** the bypass hostname answers without Access, and every request on it needs a key.

Dev only: retain a memory into an existing bank with `"async": true`, then poll `GET /v1/default/banks/<bank>/operations/<operation_id>` until `completed`. That shows the worker still processes `public`. A `failed` operation whose error names the LLM provider is a problem with the LLM credentials, not with this image. **Prod:** skip the retain. It calls the LLM and the embedding model, and #712 allows neither during the cut-over.

Then remove the key file *(not verified)*: `shred -u` it on the CT and the node, and on the operator machine trash it, then empty the Trash. The password manager keeps the key.

## 9. Record the legacy key's expiry

Post on the cut-over ticket the expiry that step 6 read back, and when it takes effect (a bare date is midnight UTC). Tell everyone who uses the legacy key to get on the Key Allowlist and create a Public Team key on `/ext/teams` before then ([operating.md](operating.md#agent-keys)). From then on the legacy key gets 401, and each refusal is logged as `legacy_key_expired`.

## Rollback

*(Not verified: rollback has not been run on Dev. Its commands are those of steps 2 to 4.)*

1. Close the bypass hostname as in step 3. Do nothing below until `closed <bypass>` prints `bypass closed OK` *(not verified)*. **Auth state:** from then on, only callers signed in through Access reach the app.
2. Restore the environment from the values saved in step 4, re-creating any secret step 6 deleted. Set `HINDSIGHT_API_TENANT_API_KEY` and `HINDSIGHT_CP_DATAPLANE_API_KEY` from a file, as in 4.1, then `HINDSIGHT_API_TENANT_EXTENSION` to its old value (on Prod, stock's ApiKey extension). Leave the legacy key, its expiry, the pepper, the `ACCESS` settings and `AGENT_KEYS_ADMIN_EMAILS` in place: stock Hindsight ignores them, and keeping the pepper keeps every Agent Key valid if the image comes back. If the app had no `HINDSIGHT_API_TENANT_EXTENSION` before (Dev before #703), there is nothing to restore: stock Hindsight will run with no authentication. **Auth state:** this image ignores the first two. On Prod, the guard refuses the old extension, so the image stops and stays down instead of serving without ours. Where there was no extension to restore (Dev), this image keeps running with ours, behind Access.
3. `platform_update_app` to the stock digest from step 2, then `platform_approve_image`, then wait for the deploy as in step 2.4: the job `completed` and `Applied image ref recorded:` naming the stock digest. Until then a check in step 4 would test the wrong state: on Prod nothing answers (step 2 stopped this image), and on Dev this image still answers. Conductor refuses a rollback across repositories, so this is a new approval, not `platform_rollback_deploy`. Stock Hindsight starts against a database this image used, because the extension's `agent_keys` schema sits outside upstream's migrations; CI checks this with a personal and a Team schema present. **Auth state:** until the deploy completes, on Prod the app is down, and on Dev this image with our extension answers until stock takes over, behind Access. After it, stock's extension: the shared key reaches `public`, and Agent Keys get 401. Stock lists only `public`, so personal and Team schemas are neither reachable nor processed by the worker; their data stays.
4. On the CT, `podman ps --filter "name=^app-$app\$" --format '{{.Image}}'` shows `localhost/app-<app>:<first 40 hex of the stock digest>` and `/version` shows the stock version. Reopen the bypass hostname only if `keyless http://127.0.0.1:$port/v1/default/banks` (setup block) then prints `keyless 401 OK` from the stock extension. Otherwise leave it closed: the app is then reachable only through Access, as it was before the cut-over. Re-create the UI hostname only if the UI comes back: `platform_request_domain container_port_label=ui`.
5. The target is the stock digest of the release the running image is built on: `scripts/upstream-ref.sh` at the commit that built it. For the cut-over that is stock 0.10.3, `b5da1a9a…`, which Prod already runs. The old Prod digest, from before Prod's upgrade to 0.10.3, is not a valid target, nor is any digest older than the step 2 upgrade: they predate 0.10.3's migrations, which have already run on the data. If the data itself is damaged, restore the step 1 dump instead.
