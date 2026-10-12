"""Identify a person from the Cloudflare Access JWT that Access puts on each request."""

import asyncio
import logging
from datetime import UTC, datetime

import jwt

logger = logging.getLogger(__name__)


class AccessVerifier:
    """Validates Access JWTs for one Access application.

    `team_domain` is the team's URL (https://<team>.cloudflareaccess.com): it is the
    issuer, and it serves the signing keys at /cdn-cgi/access/certs. `audience` is the
    application's AUD tag.
    """

    def __init__(self, team_domain: str, audience: str, *, refetch_cooldown: float = 30):
        self._issuer = team_domain.rstrip("/")
        self._audience = audience
        # The key set is refetched when a token names an unknown key ID, at most once
        # per cooldown, so forged key IDs cannot make us hammer the endpoint.
        self._keys = jwt.PyJWKClient(
            f"{self._issuer}/cdn-cgi/access/certs", timeout=5, cooldown_duration=refetch_cooldown
        )

    async def email(self, token: str) -> tuple[str, datetime] | None:
        """The person's lowercase email and when Access issued the token, or None if it is not valid."""
        try:
            # PyJWKClient fetches with blocking urllib.
            key = await asyncio.to_thread(self._keys.get_signing_key_from_jwt, token)
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "aud", "iss"]},
            )
        except jwt.PyJWTError as exc:
            logger.info("agent-keys: refused an Access token: %s", exc)
            return None
        # Service tokens carry common_name instead of email; they are not people.
        email = claims.get("email")
        if not isinstance(email, str) or not email:
            return None
        # iat is when the person signed in to Access; replaying a token cannot make it newer.
        return email.lower(), datetime.fromtimestamp(claims["iat"], UTC)
