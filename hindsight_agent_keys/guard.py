"""Startup guard: refuse to start Hindsight in a configuration that weakens tenant isolation.

Run before upstream's start-all.sh. Without our tenant extension, Hindsight admits
every request into the `public` schema, and an MCP auth token skips the tenant
extension entirely, so either mistake would expose every bank.
"""

import os
import sys
from collections.abc import Mapping

EXTENSION_PATH = "hindsight_agent_keys.extension:AgentKeysTenantExtension"

# Exit status for a configuration error (sysexits EX_CONFIG).
EX_CONFIG = 78

README_POINTER = "See 'Startup guard' in the README for each setting and why it is refused."


def _is_true(value: str | None) -> bool:
    return (value or "").strip().lower() == "true"


def problems(env: Mapping[str, str]) -> list[str]:
    """Return one message per unsafe setting; an empty list means safe to start."""
    found = []
    if env.get("HINDSIGHT_API_TENANT_EXTENSION", "") != EXTENSION_PATH:
        found.append(
            f"HINDSIGHT_API_TENANT_EXTENSION must be {EXTENSION_PATH}; "
            "without it Hindsight admits every request into the public schema."
        )
    if "HINDSIGHT_API_MCP_AUTH_TOKEN" in env:
        found.append(
            "HINDSIGHT_API_MCP_AUTH_TOKEN must be unset; it bypasses the tenant extension for MCP."
        )
    if env.get("HINDSIGHT_API_DATABASE_SCHEMA", "public") != "public":
        found.append(
            "HINDSIGHT_API_DATABASE_SCHEMA must be unset or public; "
            "the worker skips Public Team tasks under any other default schema."
        )
    if env.get("HINDSIGHT_ENABLE_CP", "").strip().lower() != "false":
        found.append(
            "HINDSIGHT_ENABLE_CP must be false; the bundled UI sends one shared key for every visitor."
        )
    if _is_true(env.get("HINDSIGHT_API_AUDIT_LOG_ENABLED")):
        found.append(
            "HINDSIGHT_API_AUDIT_LOG_ENABLED must not be true; "
            "unauthenticated requests would write into the Public Team's audit log."
        )
    # Read exactly as upstream does (value.lower() == "true", no strip): a looser
    # parse here would accept a value upstream treats as stateful.
    if env.get("HINDSIGHT_API_MCP_STATELESS", "").lower() != "true":
        found.append(
            "HINDSIGHT_API_MCP_STATELESS must be true; "
            "stateful MCP sessions can keep a revoked key's identity."
        )
    return found


def main() -> int:
    found = problems(os.environ)
    for message in found:
        print(f"agent-keys guard: refusing to start: {message}", file=sys.stderr)
    if found:
        print(f"agent-keys guard: {README_POINTER}", file=sys.stderr)
    return EX_CONFIG if found else 0


if __name__ == "__main__":
    sys.exit(main())
