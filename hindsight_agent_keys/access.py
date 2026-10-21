"""Identify a person from the Cloudflare Access JWT that Access puts on each request."""

import asyncio
import logging
from datetime import UTC, datetime

import jwt

logger = logging.getLogger(__name__)

# Where Access puts its JWT on each request it lets through.
ACCESS_JWT_HEADER = "cf-access-jwt-assertion"


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

    async def claims(self, token: str) -> dict | None:
        """The token's claims if it is valid for this application (signature, issuer, this audience
        alone, expiry and a numeric `iat`), else None."""
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
        # PyJWT accepts a token whose audiences merely include ours; Access issues ours alone.
        if claims["aud"] not in (self._audience, [self._audience]):
            logger.info("agent-keys: refused an Access token: it names other audiences")
            return None
        # PyJWT accepts any iat int() can read, such as "1700000000"; it dates a sign-in, so it must be a number.
        iat = claims["iat"]
        if isinstance(iat, bool) or not isinstance(iat, int | float):
            logger.info("agent-keys: refused an Access token: iat is not a number")
            return None
        return claims

    async def email(self, token: str) -> tuple[str, datetime] | None:
        """The person's lowercase email and when Access issued the token, or None if it is not valid."""
        claims = await self.claims(token)
        if claims is None:
            return None
        # Service tokens carry common_name instead of email; they are not people.
        email = claims.get("email")
        if not isinstance(email, str) or not email.strip():
            return None
        # iat is when the person signed in to Access; replaying a token cannot make it newer.
        return email.strip().lower(), datetime.fromtimestamp(claims["iat"], UTC)
