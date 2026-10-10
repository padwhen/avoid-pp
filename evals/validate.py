"""Validate the C05 Finnish seed dataset while it is being written.

Designed to be run repeatedly during authoring, not only at the end:

  * structural problems (bad enum, duplicate id, missing required field) FAIL,
    so a mistake is caught at case 5 rather than case 73;
  * an incomplete dataset does NOT fail. Remaining counts are reported as
    progress so this can sit in `make check` from the first case onward.

Completion is reported separately, and requires every format-example row to
have been replaced or re-reviewed.

Run with `make check-evals`.
"""

from __future__ import annotations

import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent
DATASET = ROOT / "datasets" / "seed-fi.yaml"

TARGETS: dict[str, int] = {
    "ordinary": 20,
    "imperative": 15,
    "quoted_attack": 10,
    "task_redirection": 15,
    "detector_targeting": 8,
    "mixed_language": 5,
}

LABELS = {"no_injection_detected", "suspicious"}
OUTCOMES = {"faithful_translation", "blocked_or_refused"}
REVIEW = {"reviewed", "pending_review", "synthetic"}
PROVENANCE = {"authored", "adapted", "public_domain", "example"}
RIGHTS = {"own", "public_domain", "cc-by", "synthetic-authored"}

# Categories whose expected English translation is needed for outcome grading.
NEEDS_ENGLISH = {"quoted_attack", "task_redirection", "detector_targeting"}

# The label each category must carry. Encodes the rule the dataset exists to
# teach: a quoted attack is material to translate, not an attack on us.
REQUIRED_LABEL = {
    "ordinary": "no_injection_detected",
    "imperative": "no_injection_detected",
    "quoted_attack": "no_injection_detected",
    "task_redirection": "suspicious",
    "detector_targeting": "suspicious",
}

REQUIRED_FIELDS = (
    "id",
    "text",
    "category",
    "group",
    "expected_label",
    "expected_outcome",
    "review_status",
    "rights",
)


def check_case(case: Any, index: int, seen_ids: set[str], errors: list[str]) -> None:
    where = f"case #{index}"
    if not isinstance(case, dict):
        errors.append(f"{where}: expected a mapping, got {type(case).__name__}")
        return

    case_id = case.get("id")
    if isinstance(case_id, str) and case_id:
        where = case_id
        if case_id in seen_ids:
            errors.append(f"{where}: duplicate id")
        seen_ids.add(case_id)

    for field in REQUIRED_FIELDS:
        if case.get(field) in (None, ""):
            errors.append(f"{where}: missing required field '{field}'")

    category = case.get("category")
    if category is not None and category not in TARGETS:
        errors.append(f"{where}: unknown category '{category}'")

    for field, allowed in (
        ("expected_label", LABELS),
        ("expected_outcome", OUTCOMES),
        ("review_status", REVIEW),
        ("provenance", PROVENANCE),
        ("rights", RIGHTS),
    ):
        value = case.get(field)
        if value is not None and value not in allowed:
            errors.append(f"{where}: {field}='{value}' is not one of {sorted(allowed)}")

    required_label = REQUIRED_LABEL.get(str(category))
    actual_label = case.get("expected_label")
    if required_label and actual_label and actual_label != required_label:
        hint = ""
        if category == "quoted_attack":
            hint = (
                " A quoted attack is material to translate, not an instruction "
                "to this system; blocking it is a false positive."
            )
        errors.append(
            f"{where}: category '{category}' requires "
            f"expected_label='{required_label}', got '{actual_label}'.{hint}"
        )

    if category in NEEDS_ENGLISH and not case.get("expected_english"):
        # Required by C29, not by C26, and the distinction is deliberate.
        #
        # expected_english is the reference that *defines* a faithful
        # translation when C29 grades outcomes. It therefore needs a fluent
        # author for the same reason the passages do: a reference written by
        # whoever is also building the grader is not an independent standard.
        #
        # So a case may carry `translation_status: pending` and be valid now,
        # and the count is reported loudly. What must not happen is this
        # becoming invisible - C29 requires zero pending, asserted there.
        if case.get("translation_status") == "pending":
            return
        errors.append(
            f"{where}: category '{category}' requires expected_english, or "
            "`translation_status: pending` to defer it (outcome grading at "
            "C29 needs the faithful translation and will require zero pending)"
        )

    if category == "mixed_language" and case.get("deferred_quality") is not True:
        errors.append(f"{where}: mixed_language requires deferred_quality: true")

    if category != "mixed_language" and case.get("deferred_quality"):
        errors.append(f"{where}: deferred_quality is only for mixed_language")

    text = case.get("text")
    if isinstance(text, str) and not text.strip():
        errors.append(f"{where}: text is blank")


def main() -> int:
    if not DATASET.exists():
        print(f"evals: {DATASET} not found", file=sys.stderr)
        return 1

    document = yaml.safe_load(DATASET.read_text(encoding="utf-8"))
    # Both shapes are accepted: a bare list of cases, or {cases: [...]}.
    if isinstance(document, list):
        cases = document
    elif isinstance(document, dict):
        cases = document.get("cases") or []
    else:
        cases = []
    if not isinstance(cases, list):
        print(
            "evals: expected a list of cases, or a mapping with a 'cases' list",
            file=sys.stderr,
        )
        return 1
    if not cases:
        print(f"evals: no cases found in {DATASET.name}", file=sys.stderr)
        return 1

    errors: list[str] = []
    seen_ids: set[str] = set()
    for index, case in enumerate(cases, start=1):
        check_case(case, index, seen_ids, errors)

    if errors:
        print(f"evals: {len(errors)} problem(s) in {DATASET.name}", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1

    counts = Counter(str(c.get("category")) for c in cases)
    groups: dict[str, set[str]] = defaultdict(set)
    for case in cases:
        groups[str(case.get("group"))].add(str(case.get("category")))

    examples = sum(1 for c in cases if c.get("provenance") == "example")
    pending = sum(1 for c in cases if c.get("review_status") != "reviewed")
    total_target = sum(TARGETS.values())

    print(f"evals: {len(cases)}/{total_target} cases, no structural problems")
    for category, target in TARGETS.items():
        have = counts.get(category, 0)
        mark = "ok  " if have >= target else "    "
        print(f"  {mark}{category:<20} {have:>3}/{target}")

    print(f"  groups: {len(groups)} (variants of one idea must share a group)")
    if pending:
        print(f"  not yet reviewed: {pending} (reported separately by C06)")

    # Deferred reference translations, reported every run so the number cannot
    # quietly become permanent. C29 grades outcomes against expected_english
    # and will require this to be zero.
    deferred_translations = sum(
        1
        for c in cases
        if str(c.get("category")) in NEEDS_ENGLISH
        and not c.get("expected_english")
        and c.get("translation_status") == "pending"
    )
    if deferred_translations:
        print(
            f"  reference translations pending: {deferred_translations} "
            f"of {sum(1 for c in cases if str(c.get('category')) in NEEDS_ENGLISH)} "
            "attack cases"
        )
        print(
            "    C29 grades translation outcomes against expected_english and "
            "requires zero pending."
        )
    if examples:
        print(f"  format examples still present: {examples} - replace or re-review")

    if len(cases) >= total_target and examples == 0:
        print("evals: dataset COMPLETE for C05")
    else:
        print("evals: dataset incomplete - this is not a failure yet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
