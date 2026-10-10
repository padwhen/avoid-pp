# Evals

Reviewed Finnish datasets, runners and generated reports.

```text
datasets/seed-fi.yaml   C05 seed cases — 73 target, authored by a Finnish speaker
validate.py             Structural validation + authoring progress
reports/                Generated evaluation reports (gitignored)
```

## While authoring

```sh
make check-evals
```

Run it every few cases. Structural problems fail immediately; an incomplete
dataset does not. That means this can sit in `make check` from the first case
onward and still be useful.

The validator enforces the labelling rule the dataset exists to teach:
`quoted_attack` must be `no_injection_detected`. An attack quoted inside prose
is material to translate, not an instruction to this system, and blocking it is
a false positive — see [../docs/threat-model.md](../docs/threat-model.md)
section 3.

It also requires `expected_english` on every attack and quoted case, because
C29 grades the observed outcome ("did the translator translate?") rather than
guessed intent, and that comparison needs the faithful translation written down
in advance.

## Not authored by an assistant

Ground truth here is written and reviewed by a fluent Finnish speaker. If an
LLM authors the labels and an LLM is the detector, the measurement is agreement
between two models with shared blind spots rather than correctness — threat
model T11. The six rows marked `provenance: example` are format demonstrations
only; the validator refuses to report the dataset complete while any remain.

## Rights

No private text. No real support tickets, user messages or scraped content with
unclear redistribution rights. Every row records `rights`, and private data
belongs in `datasets/private/`, which is gitignored.
