"""The scan client.

Thin, and the thinness is the feature. Every convenience a client like this
could grow - a cached verdict, a fallback, a circuit breaker that opens into
"allow", a ``safe=True`` default - is a way for a passage to reach a model
without having been scanned. So this module does exactly four things: build
the request, send it, classify the outcome, and refuse.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Final, Self
from urllib.parse import urljoin, urlsplit

import httpx

from .contract import (
    MAX_CONTENT_ID_CHARS,
    MAX_TEXT_CHARS,
    Action,
    ErrorCode,
    ResponseRejected,
    SourceType,
    TaskID,
    Verdict,
    parse_verdict,
)
from .errors import (
    NotConfigured,
    ResponseUnusable,
    ScanFailed,
    ServiceFailed,
    TransportFailed,
)

logger = logging.getLogger("avoidpp")

SCAN_PATH: Final = "v1/scans"

# Hosts for which an unencrypted base URL is accepted. Anywhere else, http://
# would put a bearer token on the wire in clear text, and the service it
# authenticates spends money.
_LOCAL_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


@dataclass(frozen=True, slots=True)
class Retry:
    """When to send a scan again.

    The default is not to. One attempt, no retries - because a scan is a paid
    provider call and a retry that is not certain the first attempt failed is
    a way to spend twice for one verdict.

    Retries that are enabled still apply only to the failures listed in
    ``errors.RETRYABLE_CODES`` and to HTTP 429: the cases where the server has
    said the work did not happen.
    """

    max_attempts: int = 1
    # Honour the server's Retry-After, but never block a request for longer
    # than this. A gateway under load can legitimately ask for 30 seconds, and
    # a client that obeys silently has turned one slow scan into a hang.
    max_delay_seconds: float = 5.0
    # Used when a retryable failure arrives with no retry guidance at all.
    fallback_delay_seconds: float = 0.5

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise NotConfigured("max_attempts must be at least 1")
        if self.max_delay_seconds < 0 or self.fallback_delay_seconds < 0:
            raise NotConfigured("retry delays must not be negative")


class ScanClient:
    """Calls ``POST /v1/scans``.

    Async only, and one instance is meant to be reused: a per-request client
    discards its connection pool and repeats the TLS handshake every time,
    which for a service on the request path is a latency cost paid for nothing.

    There is no default timeout. The right value depends on the gateway's
    configured scan budget, which this client cannot know, and the failure of
    getting it wrong by omission is a stalled application rather than an
    error - so it has to be stated.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        timeout_seconds: float,
        task_id: TaskID = TaskID.TRANSLATE_FI_EN_V1,
        language_hint: str | None = "fi",
        retry: Retry | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not api_key:
            # Refused here rather than discovered as a 401 on the first real
            # passage. A client with no credential is a misconfiguration, and
            # a misconfigured guard is a guard that is not running.
            raise NotConfigured("api_key must not be empty")
        if timeout_seconds <= 0:
            raise NotConfigured("timeout_seconds must be greater than zero")

        parsed = urlsplit(base_url)
        if parsed.scheme not in ("http", "https"):
            raise NotConfigured("base_url must be an http or https URL")
        if not parsed.hostname:
            raise NotConfigured("base_url must include a host")
        if parsed.scheme == "http" and parsed.hostname not in _LOCAL_HOSTS:
            raise NotConfigured(
                "base_url must use https for a non-local host, because the "
                "API key would otherwise be sent in clear text"
            )
        if parsed.username or parsed.password:
            # Credentials in a URL end up in logs and process listings, and
            # this client authenticates with a bearer token anyway.
            raise NotConfigured("base_url must not embed credentials")

        self._base_url = base_url if base_url.endswith("/") else base_url + "/"
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._task_id = task_id
        self._language_hint = language_hint
        self._retry = retry or Retry()
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    def __repr__(self) -> str:
        """Redacted, always.

        A client object reaches a log, a traceback frame or a debugger dump
        eventually, and the default dataclass-style repr would carry the key
        into all three.
        """
        return f"ScanClient(base_url={self._base_url!r}, api_key=<redacted>)"

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.stop()

    async def start(self) -> None:
        if self._client is not None:
            return
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            transport=self._transport,
            # Not followed. A redirect on an authenticated POST is an
            # invitation to send the bearer token to whatever host the
            # Location header names.
            follow_redirects=False,
        )

    async def stop(self) -> None:
        client = self._client
        self._client = None
        if client is not None:
            await client.aclose()

    async def scan(self, text: str, *, content_id: str) -> Verdict:
        """Scan one passage and return the decision, or raise.

        ``text`` is sent byte for byte. No trimming, no Unicode normalisation,
        no whitespace collapsing: the bytes handed in are the bytes scanned,
        because they are the bytes the caller is about to use. A client that
        tidied the passage first would produce a verdict about text that never
        existed anywhere else.

        Raises a :class:`~avoidpp.errors.ScanFailed` subclass on every outcome
        that is not a complete, internally consistent verdict about exactly
        this passage. There is no return value that means "failed".
        """
        if self._client is None:
            raise NotConfigured("the client was not started")
        if not text:
            # The contract requires a non-empty passage, and sending an empty
            # one would spend a round trip to be told so.
            raise NotConfigured("text must not be empty")
        if len(text) > MAX_TEXT_CHARS:
            raise NotConfigured(
                f"text is {len(text)} characters and the contract allows "
                f"{MAX_TEXT_CHARS}"
            )
        if not content_id or len(content_id) > MAX_CONTENT_ID_CHARS:
            raise NotConfigured(
                f"content_id must be 1 to {MAX_CONTENT_ID_CHARS} characters"
            )

        body: dict[str, Any] = {
            "task_id": self._task_id.value,
            "content": {
                "id": content_id,
                "source_type": SourceType.TRANSLATION_INPUT.value,
                "text": text,
            },
        }
        if self._language_hint:
            # Routing metadata only. It never shortens, bypasses or disables a
            # scan, and the gateway treats it as an assertion by the caller
            # rather than a verified result.
            body["content"]["language_hint"] = self._language_hint

        attempt = 0
        while True:
            attempt += 1
            try:
                return await self._attempt(body, sent_text=text)
            except ScanFailed as failure:
                if attempt >= self._retry.max_attempts or not failure.retryable:
                    raise
                delay = self._delay_for(failure)
                logger.info(
                    "retrying scan",
                    extra={
                        "content_id": content_id,
                        "attempt": attempt,
                        "delay_seconds": delay,
                        # The failure's type and code. Never the passage, and
                        # never the message, which is not ours to trust.
                        "failure": type(failure).__name__,
                    },
                )
                await asyncio.sleep(delay)

    async def _attempt(self, body: dict[str, Any], *, sent_text: str) -> Verdict:
        assert self._client is not None  # guarded by scan()
        try:
            response = await self._client.post(
                urljoin(self._base_url, SCAN_PATH),
                json=body,
                headers={
                    # The Authorization header, and nowhere else. A key in a
                    # query string lands in access logs, proxy logs, browser
                    # history and referrer headers.
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise TransportFailed(type(exc).__name__) from exc

        if response.status_code != 200:
            raise self._service_failure(response)

        try:
            decoded = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise ResponseUnusable(
                "unreadable_body", "the response body is not JSON"
            ) from exc

        try:
            return parse_verdict(decoded, sent_text=sent_text)
        except ResponseRejected as exc:
            raise ResponseUnusable(exc.reason, str(exc)) from exc

    def _service_failure(self, response: httpx.Response) -> ServiceFailed:
        """Classify a non-200 response.

        The status and the contract's code are read; the message is not
        surfaced. A gateway message is ours and safe by construction, but this
        client talks to whatever is at the base URL, and an intermediary's
        error page is neither.
        """
        code = ErrorCode.UNKNOWN
        request_id: str | None = None
        retry_after: int | None = None

        payload: Any = None
        try:
            payload = response.json()
        except (json.JSONDecodeError, ValueError):
            payload = None

        if isinstance(payload, dict):
            candidate = payload.get("request_id")
            if isinstance(candidate, str) and candidate:
                request_id = candidate
            error = payload.get("error")
            if isinstance(error, dict):
                raw_code = error.get("code")
                if isinstance(raw_code, str):
                    try:
                        code = ErrorCode(raw_code)
                    except ValueError:
                        # A code from a later contract version. Still a
                        # failure, so it stays UNKNOWN rather than becoming
                        # an absence of error.
                        code = ErrorCode.UNKNOWN
                seconds = error.get("retry_after_seconds")
                if isinstance(seconds, int) and not isinstance(seconds, bool):
                    retry_after = seconds

        header = response.headers.get("Retry-After")
        if retry_after is None and header is not None:
            try:
                retry_after = int(header.strip())
            except ValueError:
                # An HTTP-date is legal here and deliberately not parsed: a
                # date requires trusting the server's clock against ours, and
                # the fallback delay is a safe answer.
                retry_after = None

        return ServiceFailed(
            status=response.status_code,
            code=code,
            request_id=request_id,
            retry_after_seconds=retry_after,
        )

    def _delay_for(self, failure: ScanFailed) -> float:
        return retry_delay(failure, self._retry)


def retry_delay(failure: ScanFailed, retry: Retry) -> float:
    """How long to wait before sending a scan again.

    A pure function rather than a method, so the cap can be tested without a
    client and without a test that actually waits. The cap is the interesting
    part: a gateway under load can legitimately ask for 30 seconds, and a
    client that obeys that silently has converted one slow scan into a hang.
    """
    advised = getattr(failure, "retry_after_seconds", None)
    if not isinstance(advised, int) or isinstance(advised, bool) or advised < 0:
        return retry.fallback_delay_seconds
    return min(float(advised), retry.max_delay_seconds)


def permits_translation(verdict: Verdict, *, translate_on_flag: bool = False) -> bool:
    """Whether an application may act on this verdict.

    Provided as a free function taking an explicit policy argument rather than
    as ``Verdict.is_safe``, because whether a flag proceeds is a property of
    the deployment and not of the verdict. A method would have had to pick a
    default, and that default would then be the policy of every caller who did
    not know there was a question.

    Written as an allowlist: an action this build does not recognise does not
    translate.
    """
    if verdict.action is Action.ALLOW:
        return True
    if verdict.action is Action.FLAG:
        return translate_on_flag
    return False
