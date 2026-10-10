# Ambiguous fixtures

These documents are syntactically valid JSON that **no JSON Schema can
reject**, because the ambiguity is destroyed by the parser before a validator
ever sees the document.

`scan-request.duplicate-task-id.json` repeats `task_id` and `content`. Both
Python's `json.loads` and Go's `encoding/json` keep the last occurrence and
report no error, so by the time the schema runs there is only one of each key
and the document looks ordinary. A parser that kept the *first* occurrence —
which RFC 8259 permits, since it only says names "SHOULD be unique" — would
see a different request from the same bytes.

That is why these live in their own directory rather than in `invalid/`:
marking them invalid would assert something the schema layer cannot deliver,
and the test would fail for the right reason in a misleading way.

The constraint is enforced at the parser instead, in
`gateway/internal/jsonstrict`, and `validate.py` asserts the limitation
directly: it checks that the schema accepts these documents and that a
duplicate-detecting parser rejects them. If JSON Schema ever gains a way to
express key uniqueness, that check will start failing and should be revisited.
