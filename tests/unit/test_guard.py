"""The startup guard refuses any environment that would weaken tenant isolation."""

import pytest

from hindsight_agent_keys.guard import EXTENSION_PATH, problems

SAFE = {
    "HINDSIGHT_API_TENANT_EXTENSION": "hindsight_agent_keys.extension:AgentKeysTenantExtension",
    "HINDSIGHT_API_HTTP_EXTENSION": "hindsight_agent_keys.web:AgentKeysHttpExtension",
    "HINDSIGHT_API_MCP_EXTENSION": "hindsight_agent_keys.tools:AgentKeysMcpExtension",
    "HINDSIGHT_ENABLE_CP": "false",
    "HINDSIGHT_API_MCP_STATELESS": "true",
    "HINDSIGHT_API_AUDIT_LOG_ACTIONS": "(none)",
}


def env(**overrides):
    merged = dict(SAFE)
    for name, value in overrides.items():
        if value is None:
            merged.pop(name, None)
        else:
            merged[name] = value
    return merged


def test_image_defaults_are_accepted():
    assert problems(SAFE) == []


def test_extension_path_names_our_extension():
    assert EXTENSION_PATH == "hindsight_agent_keys.extension:AgentKeysTenantExtension"


# Upstream mounts whatever class HINDSIGHT_API_HTTP_EXTENSION names at /ext with no
# authentication, or nothing when it is unset or empty (extensions/loader.py:106-111,
# api/http.py:5301-5316): either way the key pages would not be ours.
@pytest.mark.parametrize("value", [None, "", "some_package.pages:OpenPages"])
def test_refuses_when_our_http_extension_is_not_configured(value):
    found = problems(env(HINDSIGHT_API_HTTP_EXTENSION=value))
    assert len(found) == 1
    assert "HINDSIGHT_API_HTTP_EXTENSION" in found[0]


# Upstream registers the tools of whatever class HINDSIGHT_API_MCP_EXTENSION names on
# both MCP servers, or none when it is unset or empty (extensions/loader.py:106-111,
# api/mcp.py:201-204): either way the Team tools would not be ours.
@pytest.mark.parametrize("value", [None, "", "some_package.tools:OpenTools"])
def test_refuses_when_our_mcp_extension_is_not_configured(value):
    found = problems(env(HINDSIGHT_API_MCP_EXTENSION=value))
    assert len(found) == 1
    assert "HINDSIGHT_API_MCP_EXTENSION" in found[0]


@pytest.mark.parametrize(
    "value",
    [None, "", "hindsight_api.extensions.builtin.tenant:ApiKeyTenantExtension"],
)
def test_refuses_when_our_tenant_extension_is_not_configured(value):
    found = problems(env(HINDSIGHT_API_TENANT_EXTENSION=value))
    assert len(found) == 1
    assert "HINDSIGHT_API_TENANT_EXTENSION" in found[0]


@pytest.mark.parametrize("value", ["", "some-token"])
def test_refuses_any_mcp_auth_token_even_empty(value):
    found = problems(env(HINDSIGHT_API_MCP_AUTH_TOKEN=value))
    assert len(found) == 1
    assert "HINDSIGHT_API_MCP_AUTH_TOKEN" in found[0]


def test_accepts_public_as_the_default_schema():
    assert problems(env(HINDSIGHT_API_DATABASE_SCHEMA="public")) == []


def test_refuses_a_default_schema_other_than_public():
    found = problems(env(HINDSIGHT_API_DATABASE_SCHEMA="sentinel"))
    assert len(found) == 1
    assert "HINDSIGHT_API_DATABASE_SCHEMA" in found[0]


@pytest.mark.parametrize("value", [None, "true", "TRUE"])
def test_refuses_the_bundled_ui_unless_explicitly_off(value):
    found = problems(env(HINDSIGHT_ENABLE_CP=value))
    assert len(found) == 1
    assert "HINDSIGHT_ENABLE_CP" in found[0]


@pytest.mark.parametrize("value", ["true", "True"])
def test_refuses_upstream_audit_logging(value):
    found = problems(env(HINDSIGHT_API_AUDIT_LOG_ENABLED=value))
    assert len(found) == 1
    assert "HINDSIGHT_API_AUDIT_LOG_ENABLED" in found[0]


# Upstream reads this as value.lower() == "true" with no strip, so "true " means stateful.
@pytest.mark.parametrize("value", [None, "false", "true ", " true"])
def test_refuses_stateful_mcp(value):
    found = problems(env(HINDSIGHT_API_MCP_STATELESS=value))
    assert len(found) == 1
    assert "HINDSIGHT_API_MCP_STATELESS" in found[0]


# Upstream reads the allowlist as [a.strip() for a in value.split(",") if a.strip()] and audits
# every action when it is empty (config.py:5265-5267, engine/audit.py:144 and 159-161), and every
# audit path checks it before a bank's stored audit_log_enabled (engine/audit.py:170 and 193,
# api/http.py:4990, mcp_tools.py:916 and 967). Only "(none)" names no action.
@pytest.mark.parametrize("value", [None, "", " , ", "retain", "(none),recall"])
def test_refuses_an_audit_allowlist_that_could_name_an_action(value):
    found = problems(env(HINDSIGHT_API_AUDIT_LOG_ACTIONS=value))
    assert len(found) == 1
    assert "HINDSIGHT_API_AUDIT_LOG_ACTIONS" in found[0]


def test_accepts_the_audit_allowlist_as_upstream_parses_it():
    assert problems(env(HINDSIGHT_API_AUDIT_LOG_ACTIONS=" (none) ,")) == []


# A bank's stored config (banks.config, written by the bank config API at config_resolver.py:697,
# and verbatim by transfer import and clone at engine/transfer/importer.py:1063-1069) and a tenant's
# get_tenant_config() override only the fields upstream marks configurable (config_resolver.py:204
# and 456, apply_strategy at 1039); the rest come from the environment alone. Of the settings the
# guard checks, only audit_log_enabled is configurable (config.py:3786), and the guard's (none)
# allowlist makes it inert (test_refuses_an_audit_allowlist_that_could_name_an_action).
def test_no_bank_or_tenant_can_override_a_guarded_setting_but_audit_log_enabled():
    from hindsight_api.config import HindsightConfig, normalize_config_key

    unsafe = {
        "HINDSIGHT_API_MCP_AUTH_TOKEN": "",
        "HINDSIGHT_API_DATABASE_SCHEMA": "sentinel",
        "HINDSIGHT_API_AUDIT_LOG_ENABLED": "true",
    }
    # Each refusal starts with the variable it names.
    guarded = {normalize_config_key(message.split()[0]) for message in problems(unsafe)}
    assert len(guarded) == 9
    assert guarded & HindsightConfig.get_configurable_fields() == {"audit_log_enabled"}


def test_reports_every_problem_at_once():
    found = problems({"HINDSIGHT_API_MCP_AUTH_TOKEN": "x"})
    assert len(found) == 7


def test_accepts_stateless_mcp_in_any_case():
    assert problems(env(HINDSIGHT_API_MCP_STATELESS="TRUE")) == []


def test_every_refusal_points_to_the_readme():
    from hindsight_agent_keys.guard import README_POINTER

    assert "README" in README_POINTER


def test_refuses_when_a_dotenv_file_would_override_the_environment():
    found = problems(SAFE, dotenv_files=["/app/.env"])
    assert len(found) == 1
    assert "/app/.env" in found[0]


def test_finds_every_dotenv_file_upstream_could_load(tmp_path):
    from hindsight_agent_keys.guard import dotenv_files

    workdir = tmp_path / "app" / "api"
    workdir.mkdir(parents=True)
    (tmp_path / "app" / ".env").write_text("HINDSIGHT_API_TENANT_EXTENSION=x\n")
    (tmp_path / ".env").write_text("")
    assert dotenv_files(str(workdir), stop=str(tmp_path)) == [
        str(tmp_path / "app" / ".env"),
        str(tmp_path / ".env"),
    ]


def test_finds_no_dotenv_files_in_a_clean_tree(tmp_path):
    from hindsight_agent_keys.guard import dotenv_files

    workdir = tmp_path / "app" / "api"
    workdir.mkdir(parents=True)
    assert dotenv_files(str(workdir), stop=str(tmp_path)) == []
