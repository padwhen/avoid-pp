"""A minimal client for the gateway's scan API.

Deliberately thin. It does not retry, does not interpret the decision, and
does not fall back to anything - all three would be helpful behaviours that
turn a failure into an allow somewhere up the stack.

The one judgement it makes is which failures are failures, and the answer is
all of them: a timeout, a 503, a 429, a malformed body and a 500 are reported
as exceptions, and the backend turns every exception into a block.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin

import httpx


class ScanFailed(Exception):
    """The scan did not produce a usable verdict."""


class GatewayClient:
    """Calls POST /v1/scans."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        task_id: str = "translate_fi_en_v1",
        language_hint: str = "fi",
        timeout_seconds: float = 30.0,
    ) -> None:
        self._base_url = base_url if base_url.endswith("/") else base_url + "/"
        self._api_key = api_key
        self._task_id = task_id
        self._language_hint = language_hint
        self._timeout = timeout_seconds
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        # One client, reused. A per-request client discards its connection
        # pool and handshakes afresh every time, which C09 established for
        # the gateway's own detector client.
        self._client = httpx.AsyncClient(timeout=self._timeout)

    async def stop(self) -> None:
        client = self._client
        self._client = None
        if client is not None:
            await client.aclose()

    async def scan(self, source_text: str, *, request_id: str) -> dict[str, Any]:
        if self._client is None:
            raise ScanFailed("client was not started")

        body = {
            "task_id": self._task_id,
            "content": {
                "id": request_id,
                "source_type": "translation_input",
                "language_hint": self._language_hint,
                # The passage, unmodified. No trimming, no normalising - the
                # bytes the caller gave us are the bytes that get scanned,
                # because they are the bytes that will be translated.
                "text": source_text,
            },
        }

        try:
            response = await self._client.post(
                urljoin(self._base_url, "v1/scans"),
                json=body,
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
        except httpx.HTTPError as exc:
            # The type name only. An httpx error can embed the URL, which
            # carries no passage - but the rule is cheaper to keep than to
            # make exceptions to.
            raise ScanFailed(f"gateway unreachable ({type(exc).__name__})") from exc

        if response.status_code != 200:
            # The status and the contract's error code, never the body. A
            # gateway error body is ours and safe, but this client is the
            # template a caller copies, and theirs may not be.
            code = "unknown"
            try:
                code = str(response.json().get("error", {}).get("code", "unknown"))
            except (json.JSONDecodeError, AttributeError, ValueError):
                pass
            raise ScanFailed(f"gateway returned {response.status_code} ({code})")

        try:
            return dict(response.json())
        except (json.JSONDecodeError, ValueError) as exc:
            raise ScanFailed("gateway returned an unreadable body") from exc
