# Examples

## protected_translator

The thing the guard protects: a Finnish-to-English translator, isolated by
construction. Not part of the guard - nothing here inspects a passage or makes
a policy decision.

```sh
make check-examples                        # 35 tests, no provider needed
make live-translate CONFIRM=yes            # one real translation, ~$0.011
make live-translate CONFIRM=yes SHOW_REQUEST=yes
make live-translate CONFIRM=yes PASSAGE=quoted-attack
```

What makes it isolated is what it cannot do:

- **no tools** in the provider request - asserted as absence of the keys, not
  as an empty list, because an empty tool list is still a tool parameter
- **one secret**, the provider key, and a test fails if the translator holds
  anything resembling a database handle, session or subprocess
- **no caller-chosen target language** - `translate()` takes the source text
  and a request id, and that is the whole signature
- **bounded output**, rejected rather than truncated

The source text is passed as delimited content with the instructions in the
system prompt, and a test asserts the passage never appears in the
instructions.

`render.py` escapes for HTML, because a faithful translation of hostile input
is still hostile input - that is a different safety question from the one the
detector answers, and the detector should not flag `<script>` in ordinary
prose.

See [C27 acceptance criteria](../docs/c27-translator.md). The integration that
puts the guard in front of this is C28.
