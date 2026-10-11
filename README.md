# hindsight-agent-keys

A container image of [Hindsight](https://github.com/vectorize-io/hindsight) (by Vectorize) with a tenant extension that gives each caller only the memory its key allows.

This first version knows one key, the **legacy key**: the deployment's existing shared key. It reaches the **Public Team**, whose banks live in the Postgres `public` schema. Every other key, and a request with no key, gets 401 on the API and on MCP. There is one exception. Upstream answers an MCP `GET` with no session ID before authentication runs: it is the handshake probe some clients send, and it returns `200 {}` with no data. Personal Agent Keys and Teams are built on top of this.

## What the image adds to upstream

- **The tenant extension** `hindsight_agent_keys.extension:AgentKeysTenantExtension`.
  - It always lists `public` as a tenant, so startup migrates `public` and the worker processes it (see upstream issue #5400).
  - Banks cannot switch on upstream audit logging.
  - Refused keys go to its own event log. Each row holds the key ID (never the secret), the client IP and the time. Each client (an IPv4 address, or an IPv6 /64) gets at most one row a minute, whatever the event. All clients together get at most 60 refusal rows a minute, plus one `refusal_log_saturated` row when that budget runs out. The limits apply per API process.
- **A startup guard**, described in its own section below.
- **Safe defaults:** the UI is off, MCP is stateless, upstream audit logging is off, and the `X-Real-IP` header is passed through to the extension.

## Startup guard

The guard is the image's entrypoint, so it runs even when the command is overridden. It exits with status 78 before Hindsight starts, naming each problem, if any of these hold:

| Setting | Why it is refused |
| --- | --- |
| A `.env` file exists at `/app/api/.env`, `/app/.env` or `/.env` | Upstream loads the first one it finds over the process environment, after the guard has checked it. |
| `HINDSIGHT_API_TENANT_EXTENSION` is not ours | Without our extension Hindsight admits every request into `public`. |
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

Everything else is upstream Hindsight configuration, such as the LLM provider and its key.

Behind a proxy, set `X-Real-IP` to the real client address and overwrite any value the client sent. Otherwise the event log records whatever the client claims.

## The event log

Events go to `agent_keys.events` in Hindsight's own database. That schema sits outside upstream's migration history, so stock Hindsight still starts against the same database.

| Column | Meaning |
| --- | --- |
| `kind` | `key_refused`, `legacy_key_expired`, or `refusal_log_saturated` (the 60-a-minute budget ran out; further refusals that minute were not recorded) |
| `key_id` | `(missing)`, `(unrecognized)`, `(legacy)`, `(none)`, or the `<id>` part of a presented `hsk_<id>_<secret>` key. Parenthesised values are reserved; a presented key's ID is never parenthesised. |
| `client_ip` | The `X-Real-IP` address in canonical form (an IPv4-mapped IPv6 address is stored as IPv4), or `NULL` if the header is missing or not an IP address |

The extension connects to the database once, at startup. If that fails it logs a warning and records nothing until the next restart; refusals are still enforced.

## Tests

Unit tests run inside the pinned upstream image, which ships `hindsight_api` and pytest:

```sh
scripts/unit-tests.sh -v
```

Integration tests start the real container on Hindsight's mock LLM, so they need no credentials. They need Docker and pytest on the host:

```sh
docker build -t hindsight-agent-keys:test .
uv run --no-project --with pytest==8.4.2 pytest -p no:cacheprovider -c /dev/null --rootdir . tests/integration -v
```

Behind a TLS-inspecting proxy, the vulnerability scan needs that proxy's CA mounted into the Grype container (`SSL_CERT_FILE`).

## CI and publishing

- **Every PR:** unit tests, integration tests, and a Grype scan. The scan runs as a digest-pinned container against an exported image tar and blocks on critical vulnerabilities that have a fix.
- **On `main`:** an amd64 image is published to `ghcr.io/impulse-engineering/hindsight-agent-keys:<upstream version>-ak.<run>` (a re-run adds `.<attempt>`), with an SBOM, a GitHub build provenance attestation and a keyless cosign signature. A follow-up job then runs the integration tests and the scan against that exact digest. Approve a digest only once that job has passed.

All actions are pinned by commit SHA. Only the publish job can write packages.

Verify a published image:

```sh
gh attestation verify oci://ghcr.io/impulse-engineering/hindsight-agent-keys@<digest> -R Impulse-Engineering/hindsight-agent-keys
cosign verify ghcr.io/impulse-engineering/hindsight-agent-keys@<digest> \
  --certificate-identity-regexp '^https://github.com/Impulse-Engineering/hindsight-agent-keys/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| The container exits with status 78 | The startup guard refused the configuration. Its stderr names each variable to fix. |
| Every request gets 401 | `HINDSIGHT_API_TENANT_LEGACY_KEY` is unset or different, or the legacy key has passed its expiry. |
| Background tasks in `public` never complete | `public` is missing from the tenant list. Check the startup logs for migration of `public`. |
| The event log stays empty | The extension's database connection failed at startup. Look for `agent-keys` warnings in the logs, then restart the container. Refusals are still enforced. |

## License

MIT. Hindsight itself is MIT-licensed by Vectorize.
