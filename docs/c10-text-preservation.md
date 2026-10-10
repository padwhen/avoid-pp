# C10 — preserve full text across language routing

Scope: prove that the passage reaches the detector unchanged, and that the
language hint is routing metadata with no power over what gets scanned.

This commit adds tests, not behaviour. The guarantee it pins down is the one
the whole design rests on: if the text that was scanned is not the text that
gets translated, the scan certifies a different string from the one the user
sees.

```sh
cd gateway && go test -race ./internal/integration/
cd detector && uv run python -m pytest tests/test_text_preservation.py
```

## Acceptance criteria

1. Given Finnish–Dutch–Finnish text and `language_hint=fi`, Python receives the
   entire exact string.
2. Changing only the hint never removes the scan call or drops
   foreign-language spans.
3. Original ä/ö, newlines, quotes and Unicode are preserved; normalized or
   translated views cannot replace the source.

## Why an integration test rather than more unit tests

The existing unit tests substitute a fake assessor, so nothing is ever
serialised. Corruption happens in precisely the parts they skip: JSON
encoding, the HTTP hop, and decoding on the far side.

`gateway/internal/integration` therefore wires the **real** router to the
**real** detector client, pointed at a server that captures the request body
byte for byte. Everything is the production path except the final service.

## Verification

### AC1 and AC3 — a corpus chosen to break careless pipelines

Fifteen passages, each included because some common "helpful" transformation
mangles it:

| Case | What it catches |
| --- | --- |
| Finnish with embedded Dutch | A span dropped for not matching the hint |
| Finnish diacritics | Charset mangling of ä, ö, å |
| Combining versus precomposed | An NFC normalisation pass |
| Typographic quotes | Smart-quote rewriting |
| Newlines, tabs, CRLF | Line-ending normalisation |
| Leading and trailing whitespace | A trim |
| Repeated internal spaces | Whitespace collapsing |
| Zero-width space, soft hyphen, nbsp | An invisible-character stripper |
| Emoji with ZWJ sequences | Grapheme splitting |
| Astral plane | Broken surrogate handling |
| RTL with bidi marks | Direction-mark stripping |
| JSON metacharacters | Double-escaping |
| HTML and script lookalikes | An HTML sanitiser |
| Control characters and ANSI escapes | A log-safety filter |
| Very long single line | Truncation |

The combining-versus-precomposed case is the sharp one. `a` plus a combining
diaeresis and a precomposed `ä` render identically but differ as bytes, so an
accidental normalisation is invisible to the eye and obvious to the test.

Invisible code points are written as Go escapes and as `chr()` calls in Python
rather than pasted literally, so a reviewer can see what is covered and an
editor cannot silently eat them.

### AC2 — the hint cannot suppress a scan

Six hint values are tried against the same passage: `fi`, `nl`, `en`, `sv`,
`xx`, and absent. Each must produce exactly one detector call with an
unchanged passage. Six foreign-language spans are then embedded in Finnish
text — Dutch, English, Swedish, German, Arabic, Korean — and each must survive
intact under `language_hint=fi`.

A detector that only ever sees the Finnish parts cannot find the Dutch attack.

### The tests are themselves tested

Two regressions were injected and both failed the build:

| Injected regression | Caught by |
| --- | --- |
| Gateway trims whitespace before forwarding | `leading_and_trailing_whitespace`, `very_long_single_line` |
| Detector NFC-normalises before counting bytes | `combining_vs_precomposed` |

The second landed on exactly the case written for it, and on nothing else.

### Python side

The Go tests prove what is *sent*. `detector/tests/test_text_preservation.py`
proves what Python does on arrival: strict Pydantic parsing does not normalise,
trim, collapse or repair anything, coverage describes the bytes that actually
arrived, and the fake detector's evidence quote is a literal substring of the
original rather than of its lowercased matching copy.

## Not yet

Preservation is proven across the gateway and into the detector's own models.
End-to-end against the real Python process arrives with Compose at C12. Byte
and token limits are C16 and C20; this commit asserts that nothing is altered,
not that oversized input is refused.
