"""What the key pages (web.py), Delegated Requests (delegation.py) and the MCP tools share:
request bodies, and how a refusal is answered over HTTP."""

from collections.abc import Awaitable
from typing import Annotated, Literal

from fastapi import HTTPException
from pydantic import BaseModel, StringConstraints

from hindsight_agent_keys.store import Refused

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]
Email = Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, max_length=254, pattern=r"^[^@\s]+@[^@\s]+$")]


class NewKey(BaseModel):
    name: Name


class NewTeam(BaseModel):
    name: Name


class JoinRequest(BaseModel):
    name: Name  # the Team's name, in any case


class Member(BaseModel):
    email: Email
    role: Literal["owner", "member"]


class FormerMember(BaseModel):
    email: Email


class RoleChange(BaseModel):
    email: Email
    role: Literal["member", "admin"] | None  # None removes the person, or declines their request


class Identity(BaseModel):
    email: Email


class NoticePreference(BaseModel):
    enabled: bool  # whether Webex notices to the person are on


class Openness(BaseModel):
    open: bool  # true opens the Team, false closes it


async def _or_refused(change: Awaitable):
    """The change's result; a refusal becomes its HTTP status with the reason as detail."""
    try:
        return await change
    except Refused as refusal:
        raise HTTPException(refusal.status, str(refusal)) from None
