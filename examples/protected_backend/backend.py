"""Enforce the scan decision before translating.

## The property that is hard to get right

"Scan the text, then translate the text" is easy to write and easy to get
subtly wrong, because nothing in that sentence says the two texts are the same
one. Every realistic bug here is a divergence between them:

  * the frontend trims whitespace before display but sends the original to be
    scanned, then the trimmed version to be translated;
  * a retry re-sends a slightly edited passage and reuses the earlier verdict;
  * a caller scans a short excerpt and translates the whole document;
  * a normalisation step runs between the two calls.

In each case the scan was real and the verdict was honest, and the text that
reached the translator was never examined. The guard did its job and protected
nothing.

So the decision is not a boolean that travels alongside the text. It is a
**ticket bound to a digest of the exact bytes that were scanned**, and
translation requires a ticket whose digest matches the text being translated.
A modified source cannot be translated under an old verdict, because the
digest no longer matches - which makes C28-AC3 a structural property rather
than a rule someone has to remember.

## Three outcomes, not two

C27's live run found that the provider's own safety system refuses some
passages the detector correctly clears as material to translate. So an allow
decision does not guarantee a translation, and the integration has to
distinguish:

    BLOCKED      the guard decided this must not be translated
    TRANSLATED   the guard allowed it and the translator produced text
    UNAVAILABLE  the guard allowed it and no translation was produced

The third must be visibly distinct from the first. "We refused to translate
this" and "we were unable to translate this" are different statements to make
to a user, and collapsing them would hide a provider outage behind a security
message - or worse, make a security block look like a transient failure worth
retrying.

## Why the frontend's opinion is ignored

A request may arrive carrying a verdict, a `safe: true` flag, a prior scan id,
or a `skip_scan` parameter. All of it is ignored, and not because it is
untrusted in the usual sense: the frontend may be perfectly honest. It is
ignored because a decision made anywhere other than this server, from a scan
performed by this server, is not a decision this server can stand behind.

An attacker who can set `safe: true` does not need an injection.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from examples.protected_translator.translator import (
    Translation,
    TranslationRefused,
    TranslationRejected,
    TranslationUnavailable,
    Translator,
)

logger = logging.getLogger("protected_backend")


class Outcome(StrEnum):
    """What happened, from the caller's point of view."""

    TRANSLATED = "translated"
    BLOCKED = "blocked"
    # Allowed, but no translation was produced. Distinct from blocked on
    # purpose: see the module docstring.
    UNAVAILABLE = "unavailable"


class TicketMismatch(Exception):
    """The text to translate is not the text that was scanned."""


def digest_of(text: str) -> str:
    """A digest over the exact UTF-8 bytes.

    Not a normalised form. The corpus exists to test characters that careless
    pipelines damage, so a digest that folded whitespace or case would be
    exactly the careless pipeline - it would let a modified passage pass as
    the scanned one, which is the whole thing this prevents.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ScanTicket:
    """A scan decision bound to the bytes it was made about.

    Frozen, and the digest is not optional. A ticket without a digest would be
    a boolean with extra steps.
    """

    action: str
    reason_code: str
    scanned_digest: str
    request_id: str
    label: str
    scanned_bytes: int

    @classmethod
    def of(cls, source_text: str, scan_response: dict[str, Any]) -> ScanTicket:
        """Build a ticket from the gateway's response.

        The digest is computed from the **local** source text, and it is worth
        being precise about what that does and does not establish.

        **It does** bind the verdict to those exact bytes, so the ticket
        cannot later be used to translate anything else. That is what C28-AC3
        asks for, and it closes every divergence that originates on this side:
        a frontend that trims before display, a retry carrying edited text, a
        normalisation pass between the two calls, an excerpt scanned and a
        document translated.

        **It does not** detect a gateway that returns a verdict about
        different text. The digest is of what this process holds, so comparing
        it with itself proves nothing - a first draft of this class checked
        exactly that, immediately before calling the translator, and the check
        was tautological. The test that was meant to prove it worked is what
        found it.

        The only available cross-check against the gateway is the byte count
        it reports, which catches a transformation in transit but not a
        substitution of the same length. Closing that properly needs the
        gateway to return a digest of what it scanned, which is a contract
        change rather than something this example can do - and the gateway is
        a component of this system rather than an adversary, so the weaker
        check is proportionate. It is recorded here so the limit is known
        rather than assumed away.
        """
        decision = scan_response["decision"]
        assessment = scan_response["assessment"]
        coverage = scan_response["coverage"]

        encoded = len(source_text.encode("utf-8"))
        if coverage["original_utf8_bytes"] != encoded:
            # The gateway scanned a different number of bytes than this
            # process is holding. Something transformed the text in transit,
            # and whichever side is wrong, the verdict does not describe this
            # text.
            raise TicketMismatch(
                f"the gateway scanned {coverage['original_utf8_bytes']} bytes "
                f"but the local source is {encoded}; the verdict does not "
                "describe this text"
            )
        if coverage["scanned_utf8_bytes"] != coverage["original_utf8_bytes"]:
            raise TicketMismatch(
                "the gateway reported incomplete coverage; a partial scan is "
                "not a verdict about the whole passage"
            )
        if coverage.get("truncated"):
            raise TicketMismatch("the gateway reported the passage truncated")

        return cls(
            action=str(decision["action"]),
            reason_code=str(decision["reason_code"]),
            scanned_digest=digest_of(source_text),
            request_id=str(scan_response["request_id"]),
            label=str(assessment["label"]),
            scanned_bytes=encoded,
        )

    def covers(self, text: str) -> bool:
        """Whether this ticket is a verdict about exactly this text."""
        return digest_of(text) == self.scanned_digest


@dataclass(frozen=True)
class Result:
    """What the backend returns. Always one of three outcomes."""

    outcome: Outcome
    request_id: str
    action: str
    reason_code: str
    label: str
    translation: Translation | None = None
    detail: str | None = None

    @property
    def translated(self) -> bool:
        return self.outcome is Outcome.TRANSLATED


class Scanner(Protocol):
    """The gateway, narrowed to what the backend needs."""

    async def scan(self, source_text: str, *, request_id: str) -> dict[str, Any]: ...


class ProtectedTranslator:
    """Scan, then translate the scanned bytes, or do not translate at all.

    The enforcement policy lives here rather than in the gateway because it is
    the *application's* decision what to do with a verdict. The gateway says
    allow, flag or block; whether a flag proceeds is a property of this
    deployment, and a different application could reasonably choose otherwise.
    """

    def __init__(
        self,
        scanner: Scanner,
        translator: Translator,
        *,
        # Monitoring semantics: a flag is recorded and the translation
        # proceeds. Enforcement: a flag is treated as a block.
        #
        # The default is the strict one. A deployment that wants monitoring
        # has to ask for it, because the failure of getting this backwards is
        # silent - everything keeps working and nothing is enforced.
        translate_on_flag: bool = False,
    ) -> None:
        self._scanner = scanner
        self._translator = translator
        self._translate_on_flag = translate_on_flag

    async def translate(self, source_text: str, *, request_id: str) -> Result:
        """Scan the passage, then translate it only if the verdict allows.

        The same string is passed to both. Not a copy, not a normalised form -
        the identical object, and the ticket's digest is checked against it
        again immediately before the translator is called.
        """
        try:
            response = await self._scanner.scan(source_text, request_id=request_id)
        except Exception as exc:
            # A scan that did not happen is not an allow. This is the case the
            # whole design turns on: the tempting failure is to translate
            # anyway because the guard was unavailable.
            logger.warning(
                "scan unavailable",
                extra={"request_id": request_id, "error_type": type(exc).__name__},
            )
            return Result(
                outcome=Outcome.BLOCKED,
                request_id=request_id,
                action="block",
                reason_code="scan_unavailable",
                label="unknown",
                detail=("The passage could not be scanned, so it was not translated."),
            )

        try:
            ticket = ScanTicket.of(source_text, response)
        except (TicketMismatch, KeyError) as exc:
            logger.warning(
                "scan response unusable",
                extra={"request_id": request_id, "error_type": type(exc).__name__},
            )
            return Result(
                outcome=Outcome.BLOCKED,
                request_id=request_id,
                action="block",
                reason_code="scan_unusable",
                label="unknown",
                detail="The scan result did not describe this passage.",
            )

        if not self._permits(ticket):
            return Result(
                outcome=Outcome.BLOCKED,
                request_id=request_id,
                action=ticket.action,
                reason_code=ticket.reason_code,
                label=ticket.label,
                detail="The passage was not translated.",
            )

        # Checked again here, against the string about to be handed over. The
        # first check was against the scan response; this one is the one that
        # matters, because between them is where a caller could have
        # substituted the text.
        if not ticket.covers(source_text):
            raise TicketMismatch(
                "the text about to be translated is not the text that was scanned"
            )

        try:
            translation = await self._translator.translate(
                source_text, request_id=request_id
            )
        except TranslationRefused as exc:
            # The provider declined. Allowed by the guard, not translated by
            # the translator - the third outcome, and visibly not a block.
            return Result(
                outcome=Outcome.UNAVAILABLE,
                request_id=request_id,
                action=ticket.action,
                reason_code="translator_refused",
                label=ticket.label,
                detail=str(exc),
            )
        except (TranslationUnavailable, TranslationRejected) as exc:
            return Result(
                outcome=Outcome.UNAVAILABLE,
                request_id=request_id,
                action=ticket.action,
                reason_code="translator_unavailable",
                label=ticket.label,
                detail=f"{type(exc).__name__}: {exc}",
            )

        return Result(
            outcome=Outcome.TRANSLATED,
            request_id=request_id,
            action=ticket.action,
            reason_code=ticket.reason_code,
            label=ticket.label,
            translation=translation,
        )

    def _permits(self, ticket: ScanTicket) -> bool:
        """Whether this action may proceed to translation.

        Written as an allowlist of actions rather than a denylist. An action
        this build does not recognise does not translate - a new action added
        to the contract must be considered here deliberately, and until it is,
        it is refused rather than silently permitted.
        """
        if ticket.action == "allow":
            return True
        if ticket.action == "flag":
            return self._translate_on_flag
        # block, and anything unrecognised.
        return False
