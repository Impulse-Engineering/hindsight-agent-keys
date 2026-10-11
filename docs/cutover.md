# Moving a Conductor app onto this image

This runbook takes a Conductor Image App running stock Hindsight with embedded pg0 onto this image. Dev ran it first (Impulse-Engineering/aseva-foundation-hosting#703); Prod follows the same order (#697). Confirm each change with the app owner before running it.

| | Dev | Prod |
| --- | --- | --- |
| App | `hindsight` on Conductor Dev | `hindsight` on Conductor Prod |
| Container | CT 209 on `pve-r630-a`, nginx on port 8110 | CT 452, nginx on port 8102 |
| Conductor API | `https://platform.apps.dev.aseva.ai/api` | `https://platform.apps.aseva.ai/api` |
| Primary hostname (behind Access) | `hindsight.internal.dev.aseva.ai` | `hindsight.internal.aseva.ai` |
| Bypass hostname (`access_exempt`) | `hindsight-api.internal.dev.aseva.ai` | `hindsight-api.internal.aseva.ai` |
| UI hostname (removed in step 7) | `hindsight-ui.dev.aseva.ai` | `hindsight-ui.aseva.ai` |

Conductor has no MCP tool for switching a domain's `access_exempt`, removing a domain, or deleting a secret (platform admin only). Use the app's Domains and Secrets panels in the Conductor UI, or its REST API through `cloudflared access curl`, which reuses your Access login. The REST API also sets a secret from a file, so its value never appears in a terminal or a chat.

```sh
# Operator machine
capi=https://platform.apps.dev.aseva.ai/api/apps/hindsight   # Prod: https://platform.apps.aseva.ai/api/apps/hindsight
cloudflared access curl "$capi/domains" -sS   # the app's extra hostnames and their ids; the primary is not listed
```

Commands marked **CT** run as root on the app's container: `ssh root@<node>`, then `pct enter <vmid>`. `podman exec` fails there (`setrlimit RLIMIT_NOFILE`), so the database tools run in a throwaway container that joins the app's network and borrows pg0's own PostgreSQL binaries from the volume. pg0's user, password and database are all `hindsight` (upstream's defaults in `hindsight_api/pg0.py`), and the database is reachable only inside the app container's network namespace.

```sh
# CT: set up once per shell
app=hindsight port=8110   # Prod: port=8102
pg0=/var/lib/apps/$app/home/hindsight/.pg0
pg() { t=$1; shift; podman run --rm -i --network "container:app-$app" -e PGPASSWORD=hindsight \
  -e LD_LIBRARY_PATH=/pgbin/lib -v "$(ls -d $pg0/installation/*/ | tail -1):/pgbin:ro" --entrypoint "/pgbin/bin/$t" \
  "$(podman ps --filter "name=^app-$app\$" --format '{{.Image}}')" \
  -h 127.0.0.1 -p "$(sed -n 4p $pg0/instances/hindsight/data/postmaster.pid)" -U hindsight "$@"; }
api() { curl -sS -o /dev/null -w '%{http_code}\n' "$@"; }
key=$(sed -n 's/^HINDSIGHT_API_TENANT_LEGACY_KEY=//p' /etc/apps/$app/.env)   # empty until step 4; Conductor writes each secret there
```

## 1. Back up

```sh
# CT
out=/root/$app-pg0-$(date -u +%Y%m%dT%H%M%SZ).dump
pg pg_dump -Fc hindsight > "$out"
ls -l "$out"; sha256sum "$out"
pg pg_restore --list < "$out" | grep -c ' TABLE '   # non-zero, or the dump is not usable
```

- Copy the dump off the CT: on the node, `pct pull <vmid> /root/<file> /root/<file>`, then `scp` it somewhere safe.
- Take a fresh vzdump of the CT on the node: `vzdump <vmid> --mode snapshot --storage <PBS storage>`. Dev's rootfs cannot snapshot, so there it falls back to suspend mode. Check the archive with `pvesm list <storage> --vmid <vmid>`. A reused VMID can carry an older tenant's archives, so compare dates with the app's `created_at`.
- Record the bank count, for step 2: `curl -sS -H "Authorization: Bearer <current key>" http://127.0.0.1:$port/v1/default/banks` (no header if the app has no key).

### Restore

Restore into a fresh database in the running app, not over pg0's data directory. The app's image may be newer than the dump; it migrates the restored data at the next start. Close the bypass hostname first (step 3).

```sh
# CT
pg dropdb --force hindsight
pg createdb hindsight
pg pg_restore --exit-on-error -d hindsight < /root/<file>.dump
systemctl restart app-$app
```

Then check `/version` and the bank list as in step 2. If the app no longer starts, PBS file-restore can pull `/var/lib/apps/<app>/home/hindsight/.pg0` out of the vzdump archive. That copy only runs on the image digest it was taken with, because pg0 keeps its PostgreSQL binaries and pgvector in the same directory.

## 2. Upgrade to stock Hindsight

The target is the upstream digest this image is built on: `scripts/upstream-ref.sh` prints its tag and digest. Skip the upgrade if the app already runs it.

1. `platform_resolve_image_version tag=<tag>` must return that digest.
2. `platform_update_app container_image=ghcr.io/vectorize-io/hindsight@sha256:<digest>`.
3. `platform_approve_image` (platform admin). On a live app this queues the deploy itself. Its health checks fail with HTTP 0 for about 30 seconds while pg0 starts and migrates. That is expected.

On the CT, `curl -sS http://127.0.0.1:$port/version` shows the new version, and the bank list matches the count from step 1.

## 3. Close the bypass hostname

```sh
# Operator machine
cloudflared access curl "$capi/domains/<id>" -sS -X PATCH -H 'Content-Type: application/json' --data '{"access_exempt": false}'
curl -sS -o /dev/null -w '%{http_code}\n' https://<bypass>/health   # 302 (to Cloudflare Access), within seconds
```

If the app has no bypass hostname yet, create it closed: `platform_request_domain domain_type=managed domain=hindsight-api.internal managed_domain_id=<zone> access_exempt=false`. Its certificate takes a few minutes. Until then, TLS handshakes fail.

## 4. Set the secrets

Copy the current value of every secret this step or step 5 changes into the password manager first; rollback needs them. They are in `/etc/apps/$app/.env` on the CT.

1. Register the legacy key: `platform_request_secret key_name=HINDSIGHT_API_TENANT_LEGACY_KEY`. Then set its value from a file. The legacy key is the deployment's existing shared key: on Prod, the value of `HINDSIGHT_API_TENANT_API_KEY`.

   ```sh
   # Operator machine
   python3 -c 'import json,sys; print(json.dumps({"value": open(sys.argv[1]).read().strip()}), end="")' <key file> |
     cloudflared access curl "$capi/secrets/HINDSIGHT_API_TENANT_LEGACY_KEY" -sS -X PUT -H 'Content-Type: application/json' --data-binary @-
   ```

2. Prod only: register `HINDSIGHT_API_TENANT_LEGACY_KEY_EXPIRES` and set it to the cut-over date plus 30 days (#697).
3. If the app has a `HINDSIGHT_API_TENANT_EXTENSION` secret, set it to `hindsight_agent_keys.extension:AgentKeysTenantExtension`. Do not delete it: deleting it restarts stock Hindsight with no tenant extension, which admits every request into `public`. Stock Hindsight cannot import our class, so it stops (`ExtensionLoadError`) and stays down until step 5. A secret overrides the image's own value, and the guard accepts only ours.
4. Delete any other secret the startup guard refuses (README, "Startup guard"), for example `HINDSIGHT_API_MCP_AUTH_TOKEN`. Otherwise the deploy exits 78 and its log names the variable.

## 5. Deploy the image

1. `platform_update_app container_image=ghcr.io/impulse-engineering/hindsight-agent-keys@sha256:<digest>`, a digest whose `verify-published` job passed.
2. `platform_approve_image` (platform admin) queues the deploy.

## 6. Verify behind Access

```sh
# CT (re-run the key= line from the setup block)
api http://127.0.0.1:$port/health                                       # 200
api http://127.0.0.1:$port/v1/default/banks                             # 401
api -H "Authorization: Bearer $key" http://127.0.0.1:$port/v1/default/banks   # 200
curl -sS -H "Authorization: Bearer $key" http://127.0.0.1:$port/v1/default/banks   # the banks from step 1
journalctl -u app-$app --since -10min | grep -iE 'agent-keys|tenant|migrat'   # extension loaded, public migrated, no event-log warning
pg psql -d hindsight -Atc 'select * from agent_keys.events order by 1 desc limit 5'   # the 401 above, as key_refused
```

Then delete the secrets the image no longer reads: `cloudflared access curl "$capi/secrets/<KEY>" -sS -X DELETE` (platform admin) for `HINDSIGHT_API_TENANT_API_KEY`, `HINDSIGHT_CP_DATAPLANE_API_KEY` and `HINDSIGHT_API_TENANT_EXTENSION`. Each deletion restarts the app; check `/health` afterwards.

## 7. Remove the UI hostname

```sh
# Operator machine
cloudflared access curl "$capi/domains/<id>" -sS -X DELETE
```

Port 9999 stays in `image_ports`, which is append-only; nothing listens on it.

## 8. Open the bypass hostname and verify

Only once step 6 returned 401 for the keyless request: switch the bypass domain to `access_exempt=true`, as in step 3. Then:

```sh
# Operator machine
b=https://<bypass>
key=$(cat <key file>)   # the file step 4 set the key from
curl -sS -o /dev/null -w '%{http_code}\n' $b/v1/default/banks                                     # 401
curl -sS -H "Authorization: Bearer $key" $b/v1/default/banks                                      # the banks from step 1
curl -sS -H "Authorization: Bearer $key" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' $b/mcp/ \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_banks","arguments":{}}}'   # the same banks
```

Retain a memory into an existing bank with `"async": true`, then poll `GET /v1/default/banks/<bank>/operations/<operation_id>` until `completed`. That shows the worker still processes `public`. A `failed` operation whose error names the LLM provider is a problem with the LLM credentials, not with this image.

## Rollback

1. Close the bypass hostname (step 3).
2. Restore the secrets from step 4: set `HINDSIGHT_API_TENANT_EXTENSION` to its old value, and re-create and set the deleted keys. The guard refuses the old extension, so this image stops and stays down instead of serving without our extension.
3. `platform_update_app` to the stock digest from step 2, then `platform_approve_image`. Conductor refuses a rollback across repositories, so this is a new approval, not `platform_rollback_deploy`. Stock Hindsight starts against a database this image used, because the extension's `agent_keys` schema sits outside upstream's migrations.
4. Check that a keyless request on the CT gets 401 from the stock extension, then reopen the bypass hostname. Re-create the UI hostname only if the UI comes back: `platform_request_domain container_port_label=ui`.
5. Digests older than the step 2 upgrade are not valid targets, because they predate its migrations. Restore the step 1 dump instead.
