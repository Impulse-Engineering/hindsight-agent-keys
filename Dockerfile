# Two images from one pin: the API image (the default, last stage) and the UI image (--target ui).
# scripts/upstream-ref.sh reads this pin, and the upstream-release workflow bumps it for both.
FROM ghcr.io/vectorize-io/hindsight:1.1.0@sha256:50311d02b4d5d2b7c5242bd336edf8735df8374eaad496a92f49c83b37d2aa06 AS base

LABEL org.opencontainers.image.source="https://github.com/Impulse-Engineering/hindsight-agent-keys" \
      org.opencontainers.image.licenses="MIT"

# The UI image: upstream's web UI, one process per Team, never the API (README, "The UI image").
FROM base AS ui
LABEL org.opencontainers.image.description="Hindsight's web UI, one process per Team"
# Upstream's launcher stays in the image; if an entrypoint override runs it, it starts no API.
ENV HINDSIGHT_ENABLE_API=false
COPY docker/ui-start.sh /app/ui-start.sh
ENTRYPOINT ["/app/ui-start.sh"]
CMD []

FROM base
LABEL org.opencontainers.image.description="Hindsight with a tenant extension for self-issued Agent Keys"

COPY hindsight_agent_keys /app/extensions/hindsight_agent_keys
# The script's executable bit comes from git; COPY keeps it.
COPY docker/agent-keys-start.sh /app/agent-keys-start.sh

# Safe defaults; the startup guard refuses any override that weakens isolation.
ENV PYTHONPATH=/app/extensions \
    HINDSIGHT_API_TENANT_EXTENSION=hindsight_agent_keys.extension:AgentKeysTenantExtension \
    HINDSIGHT_API_HTTP_EXTENSION=hindsight_agent_keys.web:AgentKeysHttpExtension \
    HINDSIGHT_API_MCP_EXTENSION=hindsight_agent_keys.tools:AgentKeysMcpExtension \
    HINDSIGHT_ENABLE_CP=false \
    HINDSIGHT_API_MCP_STATELESS=true \
    HINDSIGHT_API_AUDIT_LOG_ENABLED=false \
    HINDSIGHT_API_AUDIT_LOG_ACTIONS="(none)" \
    HINDSIGHT_API_EXTENSION_PASSTHROUGH_HEADERS=x-real-ip

# Fail the build, not the deploy, if the extension cannot be imported.
RUN ["/app/api/.venv/bin/python", "-c", "import hindsight_agent_keys.extension, hindsight_agent_keys.web, hindsight_agent_keys.bodies, hindsight_agent_keys.delegation, hindsight_agent_keys.tools, hindsight_agent_keys.guard"]

# The guard is the entrypoint so that overriding the command cannot skip it.
ENTRYPOINT ["/app/agent-keys-start.sh"]
CMD ["/app/start-all.sh"]
