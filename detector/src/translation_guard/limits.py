"""Input bounds applied before any provider request.

Three different budgets govern one passage, and conflating them is how a
system ends up silently truncating:

  * **Bytes** bound what the transport and the contract accept.
  * **Tokens** bound what the model can actually read, alongside the
    instructions and the room reserved for its answer.
  * **Characters** bound neither, and are not used for either decision.

Oversized input is **rejected**, never trimmed. A truncated scan that reports
success is the exact failure the contract's `scan_status` field exists to make
impossible: the caller would believe a passage was examined when only its
first few thousand tokens were.

## Why the token estimate is what it is

Token counts were measured against the real Finnish corpus using the
provider's own `count_tokens`, over 25 passages:

    min 1.52   median 1.69   max 1.97   characters per token

That is roughly half the ~4 characters per token an English-shaped intuition
suggests, because Finnish is agglutinative and its long inflected forms
fragment. Sizing a limit on English assumptions would under-count Finnish by
more than a factor of two.

`CONSERVATIVE_CHARS_PER_TOKEN` is set *below* the measured minimum so the
estimate over-counts tokens and errs toward rejection. It is still an
estimate: text outside the measured distribution - dense emoji, astral-plane
symbols, CJK - can cost more than one token per character, which is why the
byte ceiling exists underneath it rather than being derived from it.
"""

from __future__ import annotations

from dataclasses import dataclass

# Measured floor is 1.52 for Finnish. Rounding down leaves margin for text
# outside that distribution without making the limit uselessly tight.
CONSERVATIVE_CHARS_PER_TOKEN = 1.3

# From contracts/schemas: the transport-level ceiling on one passage.
MAX_PASSAGE_BYTES = 32 * 1024

# Development default from the commit plan. Deliberately not derived from the
# byte ceiling: at the measured Finnish ratio, 32 KiB of Finnish is roughly
# 21,500 tokens, so these two bounds are not interchangeable and the smaller
# one binds first.
DEFAULT_MAX_SOURCE_TOKENS = 4096


class InputTooLarge(ValueError):
    """The passage exceeds a bound and must not be scanned in part."""


@dataclass(frozen=True)
class Budget:
    """What one request is allowed to consume."""

    max_passage_bytes: int = MAX_PASSAGE_BYTES
    max_source_tokens: int = DEFAULT_MAX_SOURCE_TOKENS
    # Room the instructions and the model's answer need inside the context
    # window. Checked so a generous source limit cannot crowd them out.
    reserved_tokens: int = 2048
    model_context_tokens: int = 200_000

    def __post_init__(self) -> None:
        if self.max_source_tokens + self.reserved_tokens > self.model_context_tokens:
            raise ValueError(
                "max_source_tokens plus reserved_tokens exceeds the model context; "
                "the source budget would leave no room for instructions or output"
            )


def estimate_tokens(text: str) -> int:
    """A deliberately pessimistic token estimate.

    Over-counting is the safe direction: it rejects a passage that might have
    fit, rather than accepting one that does not.
    """
    if not text:
        return 0
    return max(1, int(len(text) / CONSERVATIVE_CHARS_PER_TOKEN) + 1)


def check(text: str, budget: Budget | None = None) -> int:
    """Validate a passage against the budget. Returns the estimated tokens.

    Raises InputTooLarge rather than returning a trimmed passage. There is no
    code path here that shortens input.
    """
    limits = budget or Budget()

    encoded = len(text.encode("utf-8"))
    if encoded > limits.max_passage_bytes:
        raise InputTooLarge(
            f"passage is {encoded} UTF-8 bytes, over the {limits.max_passage_bytes} limit"
        )

    estimated = estimate_tokens(text)
    if estimated > limits.max_source_tokens:
        raise InputTooLarge(
            f"passage is approximately {estimated} tokens, over the "
            f"{limits.max_source_tokens} limit "
            f"(estimated at {CONSERVATIVE_CHARS_PER_TOKEN} characters per token)"
        )

    return estimated
