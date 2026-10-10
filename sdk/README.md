# SDK clients

Thin typed clients for `POST /v1/scans`, in Python and Go.

```sh
make check-sdk     # both clients against the shared expectations table
```

There is no package to install. Vendor the directory you need, or import it
from a checkout:

```python
import sys; sys.path.insert(0, "path/to/avoid-pp/sdk/python")
from avoidpp import ScanClient, permits_translation
```

```go
import "github.com/padwhen/avoid-pp/sdk/go/avoidpp"
```

Standard library only on the Go side; `httpx` on the Python side, which the
repository already depends on.

## Using them

```python
async with ScanClient(
    base_url="https://gateway.internal",
    api_key=key,
    timeout_seconds=20.0,
) as client:
    verdict = await client.scan(passage, content_id="doc-17")

if permits_translation(verdict) and verdict.covers(passage):
    await translate(passage)
```

```go
client, err := avoidpp.New(avoidpp.Options{
    BaseURL: "https://gateway.internal",
    APIKey:  key,
    Timeout: 20 * time.Second,
})

verdict, err := client.Scan(ctx, avoidpp.Input{Text: passage, ContentID: "doc-17"})
if err != nil {
    return err // a scan that did not happen is not an allow
}
if verdict.PermitsTranslation(false) && verdict.Covers(passage) {
    translate(passage)
}
```

## What they refuse to do

- **No boolean.** `allow`, `flag` and `block` are three answers. Monitoring
  mode produces flags, and whether a flag proceeds is a property of the
  deployment - so the policy is an argument you pass, not a default you
  inherit.
- **No failure that reads as success.** Every outcome that is not a complete,
  consistent verdict about exactly your bytes raises, or returns an error
  wrapping `ErrScanFailed`. The zero Go `Verdict` permits nothing, so ignoring
  the error still does not get you an allow.
- **No retry you did not ask for.** One attempt by default, and even when
  retries are enabled only for failures where the server said the work did not
  happen. A scan is a paid provider call.
- **No tidying of the passage.** The bytes you pass are the bytes scanned. A
  client that trimmed or normalised first would produce a verdict about text
  that exists nowhere else.
- **No http to a remote host, and no redirects.** Both would put a bearer
  token somewhere it does not belong.

## The shared expectations table

[`contract-expectations.json`](contract-expectations.json) states what a
correct client does with every wire shape - 48 cases, most of them pointing at
`contracts/fixtures/`. Both test suites read it, so the two clients cannot
quietly disagree; they already did once, about wrong-typed JSON fields, and
that is how it was found.

Reasoning in [docs/c41-sdk.md](../docs/c41-sdk.md).
