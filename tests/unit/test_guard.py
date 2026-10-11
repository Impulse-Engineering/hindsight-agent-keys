"""The startup guard refuses any environment that would weaken tenant isolation."""

import pytest

from hindsight_agent_keys.guard import EXTENSION_PATH, problems

SAFE = {
    "HINDSIGHT_API_TENANT_EXTENSION": "hindsight_agent_keys.extension:AgentKeysTenantExtension",
    "HINDSIGHT_ENABLE_CP": "false",
    "HINDSIGHT_API_MCP_STATELESS": "true",
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


def test_reports_every_problem_at_once():
    found = problems({"HINDSIGHT_API_MCP_AUTH_TOKEN": "x"})
    assert len(found) == 4


def test_accepts_stateless_mcp_in_any_case():
    assert problems(env(HINDSIGHT_API_MCP_STATELESS="TRUE")) == []


def test_every_refusal_points_to_the_readme():
    from hindsight_agent_keys.guard import README_POINTER

    assert "README" in README_POINTER
