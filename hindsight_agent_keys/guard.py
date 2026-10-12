"""Startup guard: refuse to start Hindsight in a configuration that weakens tenant isolation.

Run before upstream's start-all.sh. Without our tenant extension, Hindsight admits
every request into the `public` schema, and an MCP auth token skips the tenant
extension entirely, so either mistake would expose every bank.
"""

import os
import sys
from collections.abc import Iterable, Mapping

EXTENSION_PATH = "hindsight_agent_keys.extension:AgentKeysTenantExtension"
HTTP_EXTENSION_PATH = "hindsight_agent_keys.web:AgentKeysHttpExtension"
MCP_EXTENSION_PATH = "hindsight_agent_keys.tools:AgentKeysMcpExtension"
# Upstream's audit actions are snake_case names, so an allowlist of only this audits nothing.
AUDIT_NO_ACTIONS = "(none)"

# Exit status for a configuration error (sysexits EX_CONFIG).
EX_CONFIG = 78

README_POINTER = "See 'Startup guard' in the README for each setting and why it is refused."

# upstream's start-all.sh runs hindsight-api from here, and the API loads the
# first .env found walking up from its working directory with override=True.
API_WORKDIR = "/app/api"


def _is_true(value: str | None) -> bool:
    return (value or "").strip().lower() == "true"


def dotenv_files(start: str, stop: str = "/") -> list[str]:
    """Every .env that upstream's upward search from `start` could load, nearest first."""
    found = []
    current = os.path.abspath(start)
    stop = os.path.abspath(stop)
    while True:
        candidate = os.path.join(current, ".env")
        if os.path.isfile(candidate):
            found.append(candidate)
        if current == stop or os.path.dirname(current) == current:
            return found
        current = os.path.dirname(current)


def problems(env: Mapping[str, str], dotenv_files: Iterable[str] = ()) -> list[str]:
    """Return one message per unsafe setting; an empty list means safe to start."""
    found = []
    for path in dotenv_files:
        found.append(
            f"{path} must not exist; Hindsight would load it over the checked environment. "
            "Configure the container through its environment only."
        )
    if env.get("HINDSIGHT_API_TENANT_EXTENSION", "") != EXTENSION_PATH:
        found.append(
            f"HINDSIGHT_API_TENANT_EXTENSION must be {EXTENSION_PATH}; "
            "without it Hindsight admits every request into the public schema."
        )
    if env.get("HINDSIGHT_API_HTTP_EXTENSION", "") != HTTP_EXTENSION_PATH:
        found.append(
            f"HINDSIGHT_API_HTTP_EXTENSION must be {HTTP_EXTENSION_PATH}; "
            "Hindsight serves whatever another one mounts at /ext unauthenticated, and without ours there are no key pages."
        )
    if env.get("HINDSIGHT_API_MCP_EXTENSION", "") != MCP_EXTENSION_PATH:
        found.append(
            f"HINDSIGHT_API_MCP_EXTENSION must be {MCP_EXTENSION_PATH}; "
            "another one would add its own tools to every MCP endpoint, and without ours agents cannot manage Teams."
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
    # Parsed as upstream parses it; an empty list audits every action, and a bank's
    # stored audit_log_enabled then decides, before authentication.
    actions = [a.strip() for a in env.get("HINDSIGHT_API_AUDIT_LOG_ACTIONS", "").split(",") if a.strip()]
    if actions != [AUDIT_NO_ACTIONS]:
        found.append(
            f"HINDSIGHT_API_AUDIT_LOG_ACTIONS must be {AUDIT_NO_ACTIONS}; "
            "any other list lets a bank's stored config write unauthenticated requests into the Public Team's audit log."
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
    found = problems(os.environ, dotenv_files(API_WORKDIR))
    for message in found:
        print(f"agent-keys guard: refusing to start: {message}", file=sys.stderr)
    if found:
        print(f"agent-keys guard: {README_POINTER}", file=sys.stderr)
    return EX_CONFIG if found else 0


if __name__ == "__main__":
    sys.exit(main())
