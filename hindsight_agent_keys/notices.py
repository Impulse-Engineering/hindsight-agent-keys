"""Webex direct messages to people about requests that wait for them or were decided (README, "Webex notices").

A hook queues a one-line notice for each person it concerns, after the change it announces is stored. A sweep in
the background sends each person's queued lines as one message, at most one message per person per WINDOW. All
state is in the database, so every API process and every restart sees the same queue and the same window.

No notice code runs before the change it announces, and none can stall it: queuing happens after the commit and
adds at most QUEUE_DEADLINE to the request, whatever the database or Webex are doing. A message is sent at most
once and never retried. The one wait the other way round is deliberate: a change that ends someone's eligibility for
a notice waits for a message to them in flight (SEND_DEADLINE at most), so that nothing is sent to them after it commits.
"""

import asyncio
import logging
import re
import unicodedata
from collections.abc import Awaitable, Callable, Iterable
from datetime import datetime, timedelta
from typing import NamedTuple, Protocol

import httpx

logger = logging.getLogger(__name__)

WEBEX_URL = "https://webexapis.com"
# Each phase of a call to Webex waits this long at most.
SEND_TIMEOUT = 10.0
# The whole call, a slow trickle of bytes included; an opt-out waits for a send in flight, so this bounds it.
SEND_DEADLINE = 15.0
# At most one message per person in this long; what arrives meanwhile goes out together when it has passed.
WINDOW = timedelta(minutes=15)
# Making and queuing a notice waits this long at most, so a slow database never holds up the request that caused it.
QUEUE_DEADLINE = 2.0
# The sweep runs when a notice is queued and at least this often (seconds).
SWEEP_EVERY = 30.0
# A message lists this many notices and counts the rest, so it stays short whatever the backlog.
MAX_LINES = 10

# An address that is shown as it is. Webex may turn one into a mailto link, which is fine.
_ADDRESS = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


def plain(value: str) -> str:
    """A value a person wrote (an email, a Team name) as it may appear in a message: on one line, with nothing
    Webex would make a link of, even in plain text. Control, format and separator characters, line breaks included,
    become spaces and runs of spaces one. A plain address is left as it is. Anything else has its web scheme
    defanged (`https://` is `hxxps://`, any other `://` is `[://]`) and each dot between two word characters
    written `[.]`, so `www.evil.test` reads `www[.]evil[.]test`."""
    text = unicodedata.normalize("NFKC", value)
    text = " ".join("".join(" " if unicodedata.category(c)[0] in "CZ" else c for c in text).split())
    if _ADDRESS.fullmatch(text):
        return text
    text = re.sub(r"(?i)\bhttp(s?)://", lambda m: f"hxxp{m[1].lower()}://", text)
    text = re.sub(r"(?<!hxxp)(?<!hxxps)://", "[://]", text)
    return re.sub(r"(?<=\w)\.(?=\w)", "[.]", text)


class WebexError(Exception):
    """A message Webex did not take. The text is safe to log and to store: no token, no message text."""


class WebexClient:
    """The one external call: send a direct message. Tests and the sender use anything with `send_message`."""

    def __init__(self, token: str, *, base_url: str = WEBEX_URL, timeout: float = SEND_TIMEOUT):
        self._token = token
        self._base_url = base_url
        self._timeout = timeout

    async def send_message(self, to_email: str, text: str) -> None:
        """Send `text` as the bot to the person with this email; raise WebexError if Webex does not take it.
        Plain `text`, never `markdown`, so nothing a person typed (a Team name) can format the message or hide a link.
        Sent once: a refusal or a timeout is the caller's to log, never retried here."""
        try:
            # A client per message: they are rare, and none outlives its send. No redirects are followed.
            async with httpx.AsyncClient(
                base_url=self._base_url, headers={"Authorization": f"Bearer {self._token}"}, timeout=self._timeout
            ) as http:
                resp = await http.post("/v1/messages", json={"toPersonEmail": to_email, "text": text})
        except httpx.HTTPError as exc:
            # The type only: a transport error's text can carry the request.
            raise WebexError(type(exc).__name__) from None
        if not resp.is_success:
            raise WebexError(_refusal(resp))


def _refusal(resp: httpx.Response) -> str:
    """'HTTP 429, retry after 30 s' or 'HTTP 400: <Webex's reason>', cut short."""
    reason = ""
    try:
        body = resp.json()
        reason = body.get("message") if isinstance(body, dict) else ""
    except ValueError:
        pass
    wait = resp.headers.get("Retry-After")
    detail = f", retry after {wait} s" if resp.status_code == 429 and wait else f": {reason}" if reason else ""
    return f"HTTP {resp.status_code}{detail}"[:150]


class Webex(Protocol):
    async def send_message(self, to_email: str, text: str) -> None: ...


class Notice(NamedTuple):
    """One line for each of the recipients, and the page it links to. `kind` is who they are to it, which the store
    checks again when it takes the notice to send: an "owner" of `team` who is on the Key Allowlist, an "admin", or
    the "asker" of a request that was decided (a decision is about their own request, so nothing needs checking)."""

    kind: str
    recipients: list[str]
    line: str
    path: str
    team: str | None = None


class Notices:
    """Queue notices and send them. `webex` is the one external call; `store` is the PostgresKeyStore; `admins` are
    the bootstrap admins, who are admins whatever the Key Allowlist says."""

    def __init__(self, store, webex: Webex, host: str, clock: Callable[[], datetime], admins: Iterable[str]):
        self._store = store
        self._webex = webex
        self._host = host
        self._clock = clock
        self._admins = sorted(admins)
        self._wake = asyncio.Event()
        self._task: asyncio.Task | None = None

    async def tell(self, build: Callable[[], Awaitable[Notice]]) -> None:
        """Queue the notice `build()` makes. Never raises, and waits QUEUE_DEADLINE at most, the reads that make
        the notice included: one that cannot be made or queued is logged and dropped, and the page still shows
        what it was about. Call it only after the change it announces is stored."""
        try:
            async with asyncio.timeout(QUEUE_DEADLINE):
                notice = await build()
                if not notice.recipients:
                    return
                await self._store.queue_notice(notice.recipients, notice.kind, notice.team, notice.line, notice.path)
        except Exception as exc:  # noqa: BLE001 - a notice never fails the request that caused it
            logger.warning("agent-keys: could not queue a Webex notice: %s", type(exc).__name__)
            return
        self._wake.set()

    async def send_due(self) -> None:
        """One sweep: send each person's queued notices as one message unless they heard within WINDOW.
        A message is claimed in the database before it is sent (the claim is its send log row, `sending`) and
        its outcome is written after, so a stop in between, or an outcome that cannot be written, leaves a `sending`
        row and never a second message."""
        try:
            for recipient in await self._store.queued_recipients():
                await self._deliver(recipient)
        except Exception:  # the next sweep tries again
            logger.warning("agent-keys: the Webex notice sweep failed", exc_info=True)

    async def _deliver(self, to: str) -> None:
        now = self._clock()
        claim = await self._store.claim_notice(to, now, now - WINDOW, self._admins)
        if claim is None:
            return
        log_id, items = claim
        try:
            # The final checks and the send happen under the person's notice lock, and everything that can end their
            # eligibility (an opt-out, a removal from a Team, a role change) takes that lock before it commits. So a
            # change that has committed is seen here, and one that has not waits until the message is sent: once it
            # commits, nothing more is sent to that person for what it ended.
            async with self._store.notice_lock(to):
                still = await self._store.still_eligible(to, items, self._admins)
                items = [item for item, ok in zip(items, still, strict=True) if ok]
                if not items:
                    status, detail = "skipped", "no longer eligible"
                elif not await self._store.notices_enabled(to):
                    status, detail = "skipped", "turned off"
                else:
                    async with asyncio.timeout(SEND_DEADLINE):
                        await self._webex.send_message(to, self._message(items))
                    status, detail = "sent", None
        except Exception as exc:  # noqa: BLE001 - logged in the send log, not retried
            # Only a WebexError's text is safe to store; any other exception is named by its type.
            status, detail = "failed", str(exc) if isinstance(exc, WebexError) else type(exc).__name__
            logger.warning("agent-keys: a Webex notice was not delivered: %s", detail)
        try:
            await self._store.finish_notice(log_id, status, detail)
        except Exception as exc:  # noqa: BLE001 - the row stays `sending`; the message is not sent again
            logger.warning("agent-keys: could not write the Webex send log: %s", type(exc).__name__)

    def _message(self, items: list[tuple[str, str, str, str | None]]) -> str:
        shown = [f"- {item[0]}" for item in items[:MAX_LINES]]
        more = [f"...and {len(items) - MAX_LINES} more."] if len(items) > MAX_LINES else []
        pages = dict.fromkeys(f"https://{self._host}{item[1]}" for item in items)
        return "\n".join(["Hindsight:", *shown, *more, "See " + " and ".join(pages)])

    def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def _run(self) -> None:
        while True:
            # Cleared first, so a notice queued during the sweep wakes the next one.
            self._wake.clear()
            await self.send_due()
            # Not wait_for: on Python 3.11 it can swallow the cancellation of stop() when a notice arrives
            # at the same moment, and the loop would then run on.
            try:
                async with asyncio.timeout(SWEEP_EVERY):
                    await self._wake.wait()
            except TimeoutError:
                pass
