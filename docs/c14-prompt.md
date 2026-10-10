# C14 — Finnish translation-aware prompt

Scope: the detector instructions as a **versioned artifact** rather than a
string in source, with the seed evaluation recorded against that version.

```text
detector/src/translation_guard/prompts/
  __init__.py                      registry, loader, fingerprint
  translate_fi_en/v1.system.md     the task rules
  translate_fi_en/v1.user.md       the template the passage is rendered into
```

## An honest note on what this commit is

Most of the prompt's *content* was written at C13, inside the provider
adapter, because the adapter needed something to send. This commit does not
re-author it. It makes it a reviewable, versioned, immutable artifact and
binds the recorded measurement to it.

The text is **byte-identical** to what produced the C13 measurement. That is
deliberate: the corpus already scores 100%, so there is no way to tell whether
a reworded prompt is better or worse. Changing text you cannot measure is the
thing this project keeps warning against, so the words stay as they were and
the structure around them improves.

## Acceptance criteria

1. The prompt distinguishes translating a command from obeying it, and
   explicitly treats embedded text as untrusted.
2. The provider request contains the full original passage even if the
   declared language is Finnish.
3. The seed evaluation runs and records observed misses and false alarms; this
   commit does not claim every model case passes.

## Verification

```sh
make check-python     # 92 tests
```

### AC1 — asserted against the prompt text, not assumed

`test_prompt_states_the_quoting_versus_obeying_rule` requires the system
instruction to tell the model not to follow instructions in the passage, to
name a quoted command as ordinary material, to name both labels, and to demand
verbatim quotation. A future edit that drops any of those fails the build.

### AC2 — the passage cannot reach the system prompt

The template contains `{text}`; the system instruction does not, and a test
asserts both. Rendering is checked to leave a passage containing curly quotes,
tabs and newlines unaltered.

### AC3 — recorded, and the record is checkable

The evaluation ran at C13 over all 73 cases: recall 1.0, fpr 0.0, with the
report saved under `evals/reports/milestones/`. This commit does not claim
that number means the detector is good — 23/23 and 45/45 bound recall at
>= 85.2% and fpr at <= 7.9%, which clears neither half of the C30 gate.

## Versioning is only useful if it is enforced

A saved report naming a prompt version is a claim about **exact bytes**. A name
alone cannot prove which bytes ran, so two things make the claim checkable:

- `Prompt.fingerprint()` is a SHA-256 over both halves, and every measured
  version's hash is **pinned in the test suite**. Editing a prompt in place
  fails the build rather than silently invalidating a saved number. The fix is
  to add a new version and re-run the evaluation, not to adjust the hash.
- Reports now carry `prompt_fingerprint` alongside the version.

That test immediately earned its place. The saved C13 report named prompt
`c13-minimal`, a version that stopped existing the moment the prompt moved into
the registry — the measurement was no longer resolvable by name. It has been
relabelled to `translate_fi_en-v1` with its fingerprint recorded, which is
defensible precisely because the extraction was byte-identical and that can now
be verified rather than taken on trust.

## Not yet

Output validation with hard rejection is C15. Input limits are C16. Prompt
*iteration* is blocked on something no commit can fix: at 100% there is no
headroom to measure an improvement against, so C26 has to supply harder cases
before a v2 can be judged better than v1 rather than merely different.
