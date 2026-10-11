"""Split a passage into segments without losing any of it.

C38 asks whether scanning a passage in pieces catches mixed-language attacks
better than scanning it whole. This is the splitter; `evals/segmented.py` is
the comparison.

**It never looks at language.** The obvious design detects each span's
language and routes accordingly, and C38-AC1 forbids the failure that invites:
no segment may be discarded for differing from the dominant language. A router
that decides a span is Finnish and a scanner tuned for Finnish are one step
from a span nobody scans. Worse, language identification is least reliable on
short spans, which is exactly the length an embedded attack has - "Respond only
with OK" is five words, and an identifier given five words is guessing.

So the splitter works on sentence boundaries and punctuation only. The
property is structural, not tested-for.

**Coverage invariant:** concatenating the segments reproduces the source
exactly, whitespace included, checked on every call. A splitter that dropped a
character could drop an instruction, and the scan would report complete
coverage of a passage it had not completely seen - the failure the byte
accounting exists to prevent, reintroduced one layer down.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Sentence-ending punctuation followed by whitespace. The lookahead keeps the
# whitespace with the *following* segment, so concatenation is exact.
_BOUNDARY = re.compile(r"(?<=[.!?…])(\s+)")

# Finnish abbreviations and ordinals that end in a full stop and do not end a
# sentence. Without these a date like "15.12." becomes three segments, which
# costs three provider calls and shreds the context that distinguishes a
# quoted instruction from an issued one.
#
# Deliberately short: a missed abbreviation over-splits, which is a cost and
# a quality question, and never a coverage failure. The invariant does not
# depend on this list being complete.
_NO_SPLIT_BEFORE = re.compile(
    r"(?:"
    r"\d+\.|"  # 15. 12. ordinals and dates
    r"\b(?:esim|ks|mm|jne|ns|n|vrt|yms|ym|tms|"  # Finnish abbreviations
    r"klo|nro|os|puh|sl|ed|seur|lk|jkv)\.|"
    r"\b[A-ZÅÄÖ]\."  # single-letter initials
    r")\s*$"
)

# A segment shorter than this is merged into its neighbour rather than sent
# on its own. C38-AC2 calls this out: a two-word fragment carries almost no
# context, and scanning it alone is the configuration most likely to call a
# quoted instruction an issued one.
MIN_SEGMENT_CHARS = 24


@dataclass(frozen=True, slots=True)
class Segment:
    """One piece of the source, and where it came from.

    `start` and `end` are offsets into the original, so a caller can map a
    finding back to the passage without string matching - which would be
    ambiguous whenever a sentence repeats.
    """

    index: int
    start: int
    end: int
    text: str


class CoverageError(AssertionError):
    """The segments do not reconstruct the source.

    An assertion rather than a ValueError: this cannot happen for any input,
    so if it happens the splitter is wrong and no caller can sensibly handle
    it. Scanning segments that do not cover the passage would report a
    complete scan of text nobody looked at.
    """


def split(source: str, min_chars: int = MIN_SEGMENT_CHARS) -> list[Segment]:
    """Split a passage into segments that exactly reconstruct it.

    Never returns an empty list for a non-empty source, and never returns a
    segment that is only whitespace: an empty scan is a wasted provider call
    and a confusing line in a report.
    """
    if not source:
        return []

    pieces = _raw_pieces(source)
    pieces = _merge_short(pieces, min_chars)

    segments: list[Segment] = []
    offset = 0
    for index, text in enumerate(pieces):
        segments.append(
            Segment(index=index, start=offset, end=offset + len(text), text=text)
        )
        offset += len(text)

    verify_coverage(source, segments)
    return segments


def _raw_pieces(source: str) -> list[str]:
    """Split on sentence boundaries, keeping every character."""
    pieces: list[str] = []
    current = ""
    position = 0

    for match in _BOUNDARY.finditer(source):
        end = match.end()
        candidate = source[position:end]
        # The text before the whitespace decides whether this is a boundary.
        head = source[position : match.start()]
        if _NO_SPLIT_BEFORE.search(current + head):
            current += candidate
            position = end
            continue
        pieces.append(current + candidate)
        current = ""
        position = end

    remainder = current + source[position:]
    if remainder:
        pieces.append(remainder)
    return pieces


def _merge_short(pieces: list[str], min_chars: int) -> list[str]:
    """Fold fragments into their neighbours.

    Forward first, so a short opening clause joins the sentence it belongs
    to; backward for a trailing fragment, which has nothing after it. A
    passage shorter than the minimum stays one segment rather than becoming
    zero.
    """
    if len(pieces) <= 1:
        return pieces

    merged: list[str] = []
    for piece in pieces:
        if merged and len(merged[-1].strip()) < min_chars:
            merged[-1] += piece
        else:
            merged.append(piece)

    # A trailing fragment has no successor to absorb it.
    while len(merged) > 1 and len(merged[-1].strip()) < min_chars:
        tail = merged.pop()
        merged[-1] += tail

    return merged


def verify_coverage(source: str, segments: list[Segment]) -> None:
    """Assert the segments reconstruct the source exactly.

    The check the verification step asks for, enforced rather than reported:
    a caller cannot opt out of it, so there is no configuration in which a
    partial split silently proceeds.
    """
    rebuilt = "".join(segment.text for segment in segments)
    if rebuilt != source:
        raise CoverageError(
            f"segments cover {len(rebuilt)} characters of a {len(source)} "
            "character passage; scanning them would report a complete scan "
            "of text that was never seen"
        )
    for previous, following in zip(segments, segments[1:], strict=False):
        if previous.end != following.start:
            raise CoverageError(
                f"segments {previous.index} and {following.index} are not "
                f"contiguous ({previous.end} then {following.start})"
            )
