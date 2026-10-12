"""The key pages know a person only by the email in a valid Cloudflare Access JWT."""

import time
from datetime import UTC, datetime

import jwt
import pytest
from conftest import FIRST, SECOND

from hindsight_agent_keys.access import AccessVerifier


async def test_a_valid_token_identifies_the_person_by_lowercase_email_and_when_they_signed_in(team):
    verifier = AccessVerifier(team.url, team.aud)
    issued = int(time.time()) - 3600
    assert await verifier.email(team.token(iat=issued)) == ("alice@example.com", datetime.fromtimestamp(issued, UTC))


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": ["another-application"]},
        {"iss": "https://other-team.cloudflareaccess.com"},
        {"exp": int(time.time()) - 60},
        {"exp": None},
        {"iat": None},
        {"aud": None},
        # A service token carries common_name, not email.
        {"email": None, "common_name": "ci-service-token.access"},
        {"email": ""},
        # Custom claims are never read: an email there is not an identity.
        {"email": None, "custom": {"email": "alice@example.com"}},
    ],
)
async def test_a_token_that_fails_validation_is_refused(team, claims):
    assert await AccessVerifier(team.url, team.aud).email(team.token(**claims)) is None


async def test_a_token_signed_by_an_unpublished_key_is_refused(team):
    claims = jwt.decode(team.token(), options={"verify_signature": False})
    # The published key's ID, signed with another key.
    impostor = jwt.encode(claims, SECOND.key, algorithm="RS256", headers={"kid": FIRST.kid})
    assert await AccessVerifier(team.url, team.aud).email(impostor) is None


@pytest.mark.parametrize("algorithm", ["none", "HS256"])
async def test_a_token_that_is_not_rs256_is_refused(team, algorithm):
    claims = jwt.decode(team.token(), options={"verify_signature": False})
    key = None if algorithm == "none" else "a-guessable-shared-secret-0123456789"
    token = jwt.encode(claims, key, algorithm=algorithm, headers={"kid": FIRST.kid})
    assert await AccessVerifier(team.url, team.aud).email(token) is None


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b.c"])
async def test_a_malformed_token_is_refused(team, token):
    assert await AccessVerifier(team.url, team.aud).email(token) is None


async def test_without_reachable_signing_keys_every_token_is_refused(team):
    token = team.token()
    team.server.shutdown()
    team.server.server_close()
    assert await AccessVerifier(team.url, team.aud).email(token) is None


async def test_signing_keys_are_refetched_when_a_token_names_an_unknown_key_id(team):
    verifier = AccessVerifier(team.url, team.aud, refetch_cooldown=0)
    assert (await verifier.email(team.token(FIRST)))[0] == "alice@example.com"
    team.published = [FIRST, SECOND]
    assert (await verifier.email(team.token(SECOND)))[0] == "alice@example.com"
    assert team.fetches == 2


async def test_known_signing_keys_are_not_refetched(team):
    verifier = AccessVerifier(team.url, team.aud)
    for _ in range(3):
        assert (await verifier.email(team.token()))[0] == "alice@example.com"
    assert team.fetches == 1
