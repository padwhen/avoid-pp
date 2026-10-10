"""Validate a model's reply before it becomes an assessment.

Structured outputs guarantee the reply is *schema-valid*. They guarantee
nothing about whether it is *true*, and the two are easy to conflate. This
module is the gap between them.

It enforces three things the schema cannot:

  * **Every quotation is verbatim.** A quote that does not occur in the
    passage it cites was invented. Evidence pointing at text the caller never
    sent is worse than no evidence, because it looks like support.
  * **An accusation needs surviving support.** A `suspicious` verdict whose
    quotations are *all* fabricated is rejected outright. The label may still
    be right, but nothing the model offered backs it, and a detector that
    invents its reasons cannot be audited.
  * **A wrong answer is not an invalid one.** A schema-valid reply that
    classifies badly passes validation and is counted as a model failure by
    the evaluation. Rejecting it here would hide a quality problem behind an
    availability error and make the detector look more reliable than it is.

That last distinction is the point of C15-AC3. A passage that instructs the
model to emit a clean verdict cannot bypass validation, because there is
nothing to bypass: the reply is checked against the passage either way. What
such a passage can do is persuade the model, and that is a measurable
detection failure rather than a hole in this layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from translation_guard.schemas import (
    Assessment,
    Category,
    Content,
    EvidenceItem,
    Label,
)

# A quotation long enough to be meaningless as evidence. The contract bounds
# this too; repeating it here keeps the check honest if the caller changes.
MAX_QUOTE_CHARS = 512


class InvalidModelOutput(ValueError):
    """The reply cannot be trusted as an assessment."""


@dataclass
class ValidationResult:
    """What survived validation, and what did not."""

    assessment: Assessment
    accepted_quotes: int = 0
    rejected_quotes: list[str] = field(default_factory=list)

    @property
    def had_fabrication(self) -> bool:
        return bool(self.rejected_quotes)


def _quote_is_verbatim(quote: str, text: str) -> bool:
    """Substring, with no normalisation of either side.

    Deliberately strict. Case-folding or whitespace-collapsing here would
    accept a quote the caller cannot find in their own text, which defeats
    the purpose of quoting at all.
    """
    return quote in text


def validate(
    label: Label,
    categories: list[Category],
    quotes: list[str],
    content: Content,
) -> ValidationResult:
    """Check a reply against the passage it describes.

    Raises InvalidModelOutput when the reply cannot be trusted. Returns an
    Assessment carrying only evidence that survived.
    """
    if not isinstance(label, Label):
        raise InvalidModelOutput(f"unknown label {label!r}")

    accepted: list[EvidenceItem] = []
    rejected: list[str] = []

    for quote in quotes:
        if not quote or not quote.strip():
            rejected.append(quote)
            continue
        if len(quote) > MAX_QUOTE_CHARS:
            rejected.append(quote[:60] + "...")
            continue
        if not _quote_is_verbatim(quote, content.text):
            rejected.append(quote)
            continue
        accepted.append(
            EvidenceItem(
                content_id=content.id,
                quote=quote,
                category=categories[0] if categories else None,
            )
        )

    # An accusation whose every quotation was invented has no surviving
    # support. The verdict may still be correct, but it is unauditable, and a
    # detector that fabricates its reasons is not one to trust on the reasons.
    if label is Label.SUSPICIOUS and quotes and not accepted:
        raise InvalidModelOutput(
            f"every quotation was fabricated ({len(rejected)} of {len(quotes)})"
        )

    return ValidationResult(
        assessment=Assessment(
            label=label,
            categories=list(categories),
            evidence=accepted,
        ),
        accepted_quotes=len(accepted),
        rejected_quotes=rejected,
    )
