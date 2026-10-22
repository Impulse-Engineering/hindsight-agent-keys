"""The Webex client sends one direct message by email to Webex's Messages API, and says why when it could not."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hindsight_agent_keys.notices import WebexClient, WebexError

TOKEN = "bot-token-0123456789abcdef"


class Webex:
    """Stands in for webexapis.com: records each request and answers as told."""

    def __init__(self, status=200, headers=None, body=b"{}", delay=0.0):
        self.requests = []
        webex = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                webex.requests.append(
                    {"path": self.path, "headers": dict(self.headers), "body": json.loads(self.rfile.read(length))}
                )
                time.sleep(delay)
                self.send_response(status)
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        class Quiet(ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                pass  # a client that gave up on a slow answer is the point of a test, not a traceback

        self.server = Quiet(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True).start()

    def client(self, **kwargs):
        return WebexClient(TOKEN, base_url=self.url, **kwargs)


@pytest.fixture
def make_webex():
    made = []

    def make(**kwargs):
        made.append(Webex(**kwargs))
        return made[-1]

    yield make
    for webex in made:
        webex.server.shutdown()
        webex.server.server_close()


async def test_a_message_is_posted_to_a_person_by_email_as_plain_text_with_the_bot_token(make_webex):
    webex = make_webex()
    await webex.client().send_message("alice@example.com", "bob@example.com asked to join Platform.\nSee https://x/ext/teams")
    [sent] = webex.requests
    assert sent["path"] == "/v1/messages"
    assert sent["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert sent["headers"]["Content-Type"] == "application/json"
    # Plain `text`, never `markdown`: a Team name cannot format the message or hide a link in it.
    assert sent["body"] == {
        "toPersonEmail": "alice@example.com",
        "text": "bob@example.com asked to join Platform.\nSee https://x/ext/teams",
    }


async def test_a_rate_limited_send_fails_with_how_long_webex_asked_to_wait_and_is_not_retried(make_webex):
    webex = make_webex(status=429, headers={"Retry-After": "30"}, body=b'{"message": "Too many requests"}')
    with pytest.raises(WebexError, match=r"HTTP 429.*30 s") as failed:
        await webex.client().send_message("alice@example.com", "hello")
    assert len(webex.requests) == 1
    assert TOKEN not in str(failed.value)


async def test_a_refusal_fails_with_webexs_reason_cut_short_and_never_the_token(make_webex):
    reason = "Unable to post message to user: " + "x" * 500
    webex = make_webex(status=400, body=json.dumps({"message": reason, "trackingId": "T_1"}).encode())
    with pytest.raises(WebexError, match="HTTP 400: Unable to post message") as failed:
        await webex.client().send_message("alice@example.com", "hello")
    assert len(str(failed.value)) < 200
    assert TOKEN not in str(failed.value)


async def test_an_answer_that_is_not_json_still_fails_cleanly(make_webex):
    webex = make_webex(status=502, body=b"<html>bad gateway</html>")
    with pytest.raises(WebexError, match="HTTP 502"):
        await webex.client().send_message("alice@example.com", "hello")


async def test_a_webex_that_does_not_answer_fails_at_the_deadline(make_webex):
    webex = make_webex(delay=2.0)
    started = time.monotonic()
    with pytest.raises(WebexError, match="ReadTimeout"):
        await webex.client(timeout=0.2).send_message("alice@example.com", "hello")
    assert time.monotonic() - started < 1.5


async def test_an_unreachable_webex_fails_without_the_token():
    with pytest.raises(WebexError, match="ConnectError") as failed:
        await WebexClient(TOKEN, base_url="http://127.0.0.1:1").send_message("alice@example.com", "hello")
    assert TOKEN not in str(failed.value)
