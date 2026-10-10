# C16 — enforce full-coverage input limits

Scope: byte and token bounds applied before any provider request, with
capacity reserved for the instructions and the answer.

Oversized input is **rejected**, never trimmed. There is no code path that
shortens a passage. A truncated scan reporting success is the exact failure
the contract's `scan_status` field exists to make impossible.

## Acceptance criteria

1. Oversized input is rejected explicitly before a provider request, with no
   complete-scan claim.
2. Accepted responses report scanned byte counts equal to the original byte
   count and `truncated=false`.
3. Boundary cases place suspicious text at the end of accepted input and
   verify that it is sent to the provider.

## Three budgets, and why they are not interchangeable

| Budget | Bounds | Default |
| --- | --- | --- |
| Bytes | what the transport and contract accept | 32 KiB |
| Tokens | what the model can read alongside instructions and its answer | 4096 source |
| Characters | neither — not used for either decision | — |

## The token estimate is measured, not assumed

Counted against the real Finnish corpus using the provider's own
`count_tokens`, over 25 passages:

```
min 1.52   median 1.69   max 1.97   characters per token
```

That is roughly **half** the ~4 characters per token an English-shaped
intuition suggests, because Finnish is agglutinative and its long inflected
forms fragment. Sizing the limit on English assumptions would under-count
Finnish by more than a factor of two, and a passage that "obviously fits"
would not.

`CONSERVATIVE_CHARS_PER_TOKEN` is **1.3**, deliberately below the measured
minimum, so the estimate over-counts and errs toward rejection. A test asserts
the constant stays under the measured floor: raising it would let through a
passage that does not fit.

It remains an estimate. Text outside the measured distribution — dense emoji,
astral-plane symbols, CJK — can cost more than one token per character, which
is why the byte ceiling sits underneath rather than being derived from it.

### The two defaults are inconsistent, and that is worth knowing

At the measured ratio, **32 KiB of Finnish is roughly 21,500 tokens** — more
than five times the 4096-token source budget. The byte limit and the token
limit are not two views of the same constraint, and for Finnish the token
limit binds first by a wide margin. A test pins that relationship.

The plan's own wording anticipated this: *"4,096 source tokens only if the
selected model leaves enough room for instructions/output"*, and *"string
length is not token count"*. The measurement puts numbers on it.

## Verification

```sh
make check-python     # 124 tests
```

- **AC1** — `test_oversized_input_never_reaches_the_provider` sets a tiny
  budget and asserts the stub client recorded **zero** calls. The refusal
  happens before anything is spent.
- **AC2** — coverage is computed from the bytes actually received, which C08
  already established and C10 pinned across the wire.
- **AC3** — a passage sized just under the limit with the attack sentence
  **last**. If anything trimmed from the end, that is where it would show.
  `check()` returns a token count rather than text, so there is no return
  value a caller could mistake for a shortened passage.

`Budget.__post_init__` rejects a configuration whose source budget plus
reserved tokens exceeds the model context, so a generous source limit cannot
silently crowd out the instructions or the answer.

## Not yet

Retries and deadline propagation are C17. An exact pre-flight `count_tokens`
call is deliberately not made per scan: it is a second network round trip on
every request, and the conservative bound is what the plan permits. C32
revisits these defaults against measured provider behaviour.
