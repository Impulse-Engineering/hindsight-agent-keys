FROM ghcr.io/vectorize-io/hindsight:1.0.0@sha256:a88678c038b0e4340822b02a5efc566c56d8176b5bffa731bc433fd37f978e4c

LABEL org.opencontainers.image.source="https://github.com/Impulse-Engineering/hindsight-agent-keys" \
      org.opencontainers.image.description="Hindsight with a tenant extension for self-issued Agent Keys" \
      org.opencontainers.image.licenses="MIT"

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
