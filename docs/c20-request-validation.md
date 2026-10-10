# C20 · Rejecting malformed and oversized requests early

Everything here runs before the detector is called, so a bad request costs no
provider work. The tests assert that directly: a call counter on a detector
fake that would otherwise answer successfully must read zero on every rejected
path.

## The duplicate key

This is the case the commit exists for.

```json
{"task_id":"translate_fi_en_v1",
 "content":{"id":"p","source_type":"translation_input","text":"harmless"},
 "task_id":"translate_fi_en_v1",
 "content":{"id":"p","source_type":"translation_input","text":"ATTACK"}}
```

Before this commit the gateway accepted that body and scanned `ATTACK`,
because Go's `encoding/json` keeps the last occurrence of a repeated key and
reports no error. `DisallowUnknownFields` does not help: every key is a known
one. Anything in the path that kept the *first* occurrence instead — many
parsers, and most log and audit pipelines — recorded `harmless`.

That disagreement is the whole attack. The text that gets scanned and the text
that gets recorded are different strings, and no layer reports a problem.

There is no correct interpretation to choose. RFC 8259 says names "SHOULD be
unique" and leaves the behaviour undefined when they are not, so any choice
would differ from some other parser in the chain. The only safe answer is to
refuse the request.

Duplicates are rejected at every depth, not only for keys that look
security-relevant. Deciding which keys matter is a judgment that has to be
revisited every time the schema grows, and the cost of getting it wrong is
silent — which is the failure mode being closed.

### Why this is not in the schema

It cannot be. The JSON Schema in `contracts/schemas/` is the normative
contract, but a validator never sees the duplication: `json.loads` has already
collapsed it to a single key before validation runs. There is no keyword that
could catch it, because the evidence is destroyed by the parser.

`contracts/validate.py` asserts that limitation rather than leaving it
implicit. The fixture lives in `contracts/fixtures/ambiguous/`, and the check
requires two things: a duplicate-detecting parser must reject it, and the
schema must accept it. If JSON Schema ever gains key uniqueness, that second
assertion fails and the parser-level guard can be revisited.

Marking it `invalid/` would have been the easy move and the wrong one — it
asserts something the schema layer cannot deliver.

## Two ways to silently repair text

C20-AC3 asks for invalid UTF-8 to be rejected rather than repaired. There are
two distinct routes to repaired text, and the obvious check catches neither.

**Raw malformed UTF-8 in a JSON string.** `encoding/json` substitutes U+FFFD
and returns no error. A check on the decoded string afterwards is useless,
because U+FFFD is itself valid UTF-8:

```go
raw := []byte("{\"text\":\"hei \xff\xfe vaan\"}")
json.Unmarshal(raw, &v)                 // err == nil
utf8.ValidString(v.Text)                // true — on repaired text
```

The gateway had exactly that check in `validateScanRequest`. It was dead code:
it could never fire, because by the time it ran the bytes had already been
replaced. It has been removed and replaced with a check on the raw body before
decoding.

**A lone surrogate escape.** `{"text":"hei \ud800 vaan"}` is all ASCII, so the
body is perfectly valid UTF-8 and a raw byte check sees nothing wrong. The
decoder still produces U+FFFD, because an unpaired surrogate has no UTF-8
encoding.

So the invariant checked is not "is the text valid" but **did the parser
introduce a character the caller did not send**. A caller may legitimately send
U+FFFD, literally or escaped, so those are counted rather than assumed away —
otherwise the gateway would reject text that was correct all along. A test
covers the awkward middle case: one sent replacement character does not buy
cover for a substituted one.

## Order of checks

Cheapest and most conclusive first:

1. **Content-Type** — costs nothing. An absent header is refused rather than
   assumed, because assuming it is how a form-encoded or `text/plain` body
   ends up parsed as JSON by accident. 415.
2. **Declared Content-Length** — an oversized declaration is refused without
   transferring the body. Reading it to "confirm" would mean paying the cost
   the limit exists to avoid. A test uses a reader that fails if it is read
   from at all. 413.
3. **The actual body**, through `http.MaxBytesReader`. Content-Length is a
   claim, and a chunked request makes no claim at all, so this is the real
   enforcement. A test sends a large body behind a `Content-Length: 10` header.
4. **Structure** — duplicate keys, nesting depth, trailing content, raw UTF-8.
5. **Contract shape** — unknown fields, wrong types.
6. **Substitution** — whether decoding altered the text.

Authentication precedes all of it, so unauthenticated traffic never reaches
the parser.

## Status codes

Each code maps to exactly one status, asserted by a test. A code that means
two different things to a client is worse than a coarser code.

| Code | Status | Covers |
| --- | --- | --- |
| `malformed_json` | 400 | Syntax, duplicate keys, depth, trailing content, invalid UTF-8, substitution, unknown fields |
| `payload_too_large` | 413 | Declared or actual body over the limit |
| `unsupported_media_type` | 415 | Content-Type absent or not JSON |
| `schema_invalid` | 422 | Wrong types, field-level contract violations |
| `unknown_task_id` | 422 | A task this contract version does not define |

## Limits, and which one binds

Three different limits apply to one request, and the smallest binds first:

| Limit | Value | Enforced by |
| --- | --- | --- |
| Headers | 16 KiB | `http.Server.MaxHeaderBytes` |
| Body | 64 KiB | `MaxRequestBytes` |
| Passage | 32,768 characters | `contract.MaxTextChars` |
| Nesting | 32 levels | `jsonstrict.MaxDepth` |

Go's default header limit is 1 MiB, which is generous for a request whose
largest legitimate header is a bearer token.

The boundary tests assert both sides, and say which limit fires: a body of
exactly 64 KiB is *not* a 413 — it is refused at 422 for its text length,
which is what proves the byte limit did not fire early. One byte more is a
413.

The nesting limit exists because a few hundred bytes of `[[[[` is otherwise
enough to recurse as far as the parser will go. The contract's deepest legal
request is three levels; 32 leaves room to grow.

## Rejections never echo the body

A parser error embeds the offending input. Passing it through turns an error
response into a reflection channel, so every message is written by hand and
the parser's own text goes only to the log. Wrong-type errors name the field
and the JSON kind that arrived — both the caller's own — but never the value,
and never the Go type, which would disclose internal package names for no
benefit to the caller.

A test posts a unique marker inside a duplicate key's value, an unknown field
name, a wrong-typed value, malformed JSON, an oversized body and a bad
Content-Type, and fails if the marker appears in any response.

## Verification

- `gateway/internal/jsonstrict` unit tests: duplicates at every depth, the
  same name at different depths accepted, nesting boundary from both sides,
  trailing content, malformed syntax, invalid UTF-8, lone surrogates,
  deliberate U+FFFD.
- `FuzzCheck` with the seed corpus the acceptance criteria name — duplicate
  fields, invalid UTF-8, boundary-sized bodies. It asserts four properties:
  accepted input is valid UTF-8, is valid JSON by the standard library's
  reckoning, contains no duplicate key by an *independently written* detector,
  and Check is deterministic. 1.13M executions, no failures. The seeds run on
  every `go test`, so CI exercises them without a fuzzing budget.
- A timing test at the body-size limit, to catch a quadratic blow-up rather
  than to measure performance. Worst case is 2.1 ms for 8,000 distinct keys.
- `make smoke` covers duplicate keys, wrong types, lone surrogates, excess
  nesting, `text/plain` and an oversized body against containers.
