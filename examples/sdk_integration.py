"""The same integration as C28, built on the SDK instead of by hand.

C28 wrote its own scan client and its own digest-bound ticket, because there
was no client to use. C41 provides one, and this file is what the integration
looks like once it exists:

  * the HTTP call, the status mapping and the error-code handling are gone -
    they were never application code;
  * so is the ticket. ``Verdict`` already carries ``scanned_digest`` and
    ``covers()``, because binding a verdict to the bytes it was made about is
    a property of a scan result rather than of one application;
  * what is left is the only part that was ever this file's business: what to
    do about a flag, and what to say when a translation did not happen.

C28's version is kept rather than rewritten. It is the code the C26 and C29
measurements actually ran through, and replacing it would leave those
documents describing something that no longer exists. For new work, this is
the shape to copy.

Three outcomes, not two - unchanged from C28 and the reason that file exists:

    BLOCKED      the guard decided this must not be translated
    TRANSLATED   the guard allowed it and the translator produced text
    UNAVAILABLE  the guard allowed it and no translation was produced

A scan that did not happen is a BLOCKED, never a TRANSLATED. That is the whole
design, and it is why every failure from the SDK raises rather than returning
something a caller might read as permission.
"""

from __future__ import annotations

import logging

from avoidpp import ScanClient, ScanFailed, permits_translation

from examples.protected_backend.backend import Outcome, Result, TicketMismatch
from examples.protected_translator.translator import (
    TranslationRefused,
    TranslationRejected,
    TranslationUnavailable,
    Translator,
)

logger = logging.getLogger("sdk_integration")


class GuardedTranslator:
    """Scan, then translate the scanned bytes, or do not translate at all."""

    def __init__(
        self,
        client: ScanClient,
        translator: Translator,
        *,
        # Monitoring semantics: a flag is recorded and the translation
        # proceeds. Enforcement: a flag is treated as a block.
        #
        # The default is the strict one, because the failure of getting this
        # backwards is silent - everything keeps working and nothing is
        # enforced.
        translate_on_flag: bool = False,
    ) -> None:
        self._client = client
        self._translator = translator
        self._translate_on_flag = translate_on_flag

    async def translate(self, source_text: str, *, request_id: str) -> Result:
        try:
            verdict = await self._client.scan(source_text, content_id=request_id)
        except ScanFailed as failure:
            # One except clause for every way a scan can fail to produce a
            # verdict: transport, authentication, rate limiting, a 503, a
            # contradictory 200, a verdict about different bytes, and a
            # misconfigured client. That is what the sentinel base class is
            # for - the safe behaviour is identical for all of them, and a
            # list of specific exception types would be a list to forget to
            # extend.
            logger.warning(
                "scan did not produce a verdict",
                extra={
                    "request_id": request_id,
                    "error_type": type(failure).__name__,
                    "retryable": failure.retryable,
                },
            )
            return Result(
                outcome=Outcome.BLOCKED,
                request_id=request_id,
                action="block",
                reason_code="scan_unavailable",
                label="unknown",
                detail="The passage could not be scanned, so it was not translated.",
            )

        if not permits_translation(verdict, translate_on_flag=self._translate_on_flag):
            return Result(
                outcome=Outcome.BLOCKED,
                request_id=request_id,
                action=str(verdict.action),
                reason_code=verdict.reason_code,
                label=str(verdict.label),
                detail="The passage was not translated.",
            )

        # Checked here, against the string about to be handed over, and not
        # only inside the client. The client proved the verdict describes the
        # bytes it sent; this proves the bytes about to be translated are
        # those same bytes. Between the two is where a caller substitutes
        # text - a trim before display, a retry carrying an edit, an excerpt
        # scanned and a document used.
        if not verdict.covers(source_text):
            raise TicketMismatch(
                "the text about to be translated is not the text that was scanned"
            )

        try:
            translation = await self._translator.translate(
                source_text, request_id=request_id
            )
        except TranslationRefused as exc:
            # The provider declined. Allowed by the guard and not translated
            # by the translator - the third outcome, and visibly not a block.
            return Result(
                outcome=Outcome.UNAVAILABLE,
                request_id=request_id,
                action=str(verdict.action),
                reason_code="translator_refused",
                label=str(verdict.label),
                detail=str(exc),
            )
        except (TranslationUnavailable, TranslationRejected) as exc:
            return Result(
                outcome=Outcome.UNAVAILABLE,
                request_id=request_id,
                action=str(verdict.action),
                reason_code="translator_unavailable",
                label=str(verdict.label),
                detail=f"{type(exc).__name__}: {exc}",
            )

        return Result(
            outcome=Outcome.TRANSLATED,
            request_id=request_id,
            action=str(verdict.action),
            reason_code=verdict.reason_code,
            label=str(verdict.label),
            translation=translation,
        )
