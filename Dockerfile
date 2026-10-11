FROM ghcr.io/vectorize-io/hindsight:0.10.3@sha256:b5da1a9aece1f53a15f12821fb1470f358ed6c74dfaa0c4b1a39c3f3ae93e002

LABEL org.opencontainers.image.source="https://github.com/Impulse-Engineering/hindsight-agent-keys" \
      org.opencontainers.image.description="Hindsight with a tenant extension for self-issued Agent Keys" \
      org.opencontainers.image.licenses="MIT"

COPY hindsight_agent_keys /app/extensions/hindsight_agent_keys
# The script's executable bit comes from git; COPY keeps it.
COPY docker/agent-keys-start.sh /app/agent-keys-start.sh

# Safe defaults; the startup guard refuses any override that weakens isolation.
ENV PYTHONPATH=/app/extensions \
    HINDSIGHT_API_TENANT_EXTENSION=hindsight_agent_keys.extension:AgentKeysTenantExtension \
    HINDSIGHT_ENABLE_CP=false \
    HINDSIGHT_API_MCP_STATELESS=true \
    HINDSIGHT_API_AUDIT_LOG_ENABLED=false \
    HINDSIGHT_API_EXTENSION_PASSTHROUGH_HEADERS=x-real-ip

# Fail the build, not the deploy, if the extension cannot be imported.
RUN ["/app/api/.venv/bin/python", "-c", "import hindsight_agent_keys.extension, hindsight_agent_keys.guard"]

# The guard is the entrypoint so that overriding the command cannot skip it.
ENTRYPOINT ["/app/agent-keys-start.sh"]
CMD ["/app/start-all.sh"]
