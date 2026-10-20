FROM ghcr.io/vectorize-io/hindsight:0.10.3@sha256:b5da1a9aece1f53a15f12821fb1470f358ed6c74dfaa0c4b1a39c3f3ae93e002

LABEL org.opencontainers.image.source="https://github.com/Impulse-Engineering/hindsight-agent-keys" \
      org.opencontainers.image.description="Hindsight with a tenant extension for self-issued Agent Keys" \
      org.opencontainers.image.licenses="MIT"

# Fixed versions over upstream's lockfile, for advisories the scan blocks or reports as High:
# GHSA-h4mw-j7qp-8mwm (claude-agent-sdk), GHSA-2g87-pp6c-29x5 and GHSA-5wr8-gcqf-gqf3 (aiohttp, which needs this yarl).
# shortcut: exact pins downgrade a newer upstream; drop each one the pinned release already meets.
RUN ["uv", "pip", "install", "--no-cache", "--python", "/app/api/.venv/bin/python", \
     "claude-agent-sdk==0.2.121", "aiohttp==3.14.4", "yarl==1.25.1"]

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
RUN ["/app/api/.venv/bin/python", "-c", "import hindsight_agent_keys.extension, hindsight_agent_keys.web, hindsight_agent_keys.tools, hindsight_agent_keys.guard"]

# The guard is the entrypoint so that overriding the command cannot skip it.
ENTRYPOINT ["/app/agent-keys-start.sh"]
CMD ["/app/start-all.sh"]
