"""Assert the properties that make a holdout worth having.

Two of these are the whole reason the split tooling exists, and both are the
kind of property that is easy to believe and hard to notice losing:

  * assignment is **stable** as the corpus grows;
  * a group **never spans** two splits.

Run with `make check-splits`.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import splits as sm  # noqa: E402
from duplicates import fold, review, similarity  # noqa: E402
from holdout import (  # noqa: E402
    HoldoutChanged,
    HoldoutNotFrozen,
    load_frozen,
    prompt_changed_since_last_access,
    record_access,
    verify_unchanged,
)

DATASET = ROOT / "datasets" / "seed-fi.yaml"


def check(label: str, actual, expected, failures: list[str]) -> None:
    if actual != expected:
        failures.append(f"{label}: got {actual!r}, want {expected!r}")


def synthetic(count: int, category: str, label: str, prefix: str) -> list[dict]:
    return [
        {
            "id": f"{prefix}-{index}",
            "text": f"Synteettinen tapaus {prefix} numero {index}.\n",
            "category": category,
            "group": f"group-{prefix}-{index}",
            "expected_label": label,
        }
        for index in range(count)
    ]


def check_stability(failures: list[str]) -> None:
    """The property the holdout's meaning rests on.

    If assignment moved when the corpus grew, a case that was held out last
    week would be in development this week, and "never used to tune anything"
    would be unenforceable.
    """
    cases = sm.load_cases(DATASET)
    before = {
        str(case["id"]): name
        for name, members in sm.assign(cases).items()
        for case in members
    }

    grown = copy.deepcopy(cases)
    grown += synthetic(250, "ordinary", "no_injection_detected", "grow-ord")
    grown += synthetic(75, "task_redirection", "suspicious", "grow-red")
    grown += synthetic(60, "imperative", "no_injection_detected", "grow-imp")

    after = {
        str(case["id"]): name
        for name, members in sm.assign(grown).items()
        for case in members
    }

    moved = [
        case_id for case_id, split in before.items() if after.get(case_id) != split
    ]
    if moved:
        failures.append(
            f"{len(moved)} case(s) changed split when {len(grown) - len(cases)} "
            f"cases were added, e.g. {moved[:3]}; the holdout guarantee cannot "
            "survive a case moving"
        )

    # Order must not matter either: a reordered file is the same corpus.
    reversed_order = list(reversed(cases))
    reordered = {
        str(case["id"]): name
        for name, members in sm.assign(reversed_order).items()
        for case in members
    }
    if reordered != before:
        failures.append("assignment depends on the order of cases in the file")


def check_groups_never_span(failures: list[str]) -> None:
    """Variants of one family must share a split.

    A matched pair has one group spanning two categories - bare and quoted -
    so if the two halves landed in different splits, tuning on the first would
    be tuning on the second.
    """
    cases = sm.load_cases(DATASET)
    problems = sm.check_group_integrity(cases)
    if problems:
        failures.extend(problems)

    # Specifically for the matched pairs that exist, which are the sharpest
    # cases in the corpus and the ones most damaging to split.
    by_group: dict[str, set[str]] = {}
    for case in cases:
        if case.get("deferred_quality"):
            continue
        group = sm.group_of(case)
        by_group.setdefault(group, set()).add(sm.split_for_group(group))
    for group, assigned in by_group.items():
        if len(assigned) != 1:
            failures.append(f"group {group!r} landed in {sorted(assigned)}")

    # And a group containing two categories still lands in one split.
    paired = [
        group
        for group in by_group
        if len({str(c.get("category")) for c in cases if sm.group_of(c) == group}) > 1
    ]
    if not paired:
        failures.append(
            "no group spans two categories, so the matched-pair property is "
            "untested; the seed corpus should contain some"
        )


def check_weights(failures: list[str]) -> None:
    """Weights change the shape, and must be validated."""
    original = dict(sm.SPLIT_WEIGHTS)
    try:
        for bad in (
            {"development": 1},
            {"development": 0, "validation": 1, "holdout": 1},
        ):
            try:
                sm.configure(bad)
            except ValueError:
                pass
            else:
                failures.append(f"configure accepted invalid weights {bad}")

        sm.configure({"development": 5, "validation": 2, "holdout": 3}, "test-salt")
        cases = sm.load_cases(DATASET)
        buckets = sm.assign(cases)
        if not buckets["holdout"]:
            failures.append("a 30% holdout weight produced an empty holdout")
        # Still no group spanning a split under different weights.
        if sm.check_group_integrity(cases):
            failures.append("group integrity broke under non-default weights")
    finally:
        sm.configure(original, sm.DEFAULT_SALT)


def check_freeze_blockers(failures: list[str]) -> None:
    """A degenerate holdout must not be freezable, and a good one must be.

    The first version of this asserted that *the seed corpus* produced a
    holdout with no attacks. That was true at seventy-three cases and false
    at five hundred, so the test failed the moment the corpus grew - it had
    encoded a transient fact as a permanent property.

    The property is about the checker, not about the corpus, so the degenerate
    case is now constructed deliberately.
    """
    # A corpus of benign cases only: every split lacks attacks.
    benign_only = synthetic(40, "ordinary", "no_injection_detected", "benign")
    manifest = sm.build_manifest(DATASET, sm.assign(benign_only))
    blockers = sm.freeze_blockers(manifest)
    if not blockers:
        failures.append(
            "a corpus with no attack cases at all was reported fit to freeze"
        )
    if manifest["fit_to_freeze"]:
        failures.append("fit_to_freeze is true for a corpus with no attacks")
    if not any("recall" in blocker for blocker in blockers):
        failures.append(f"the blocker does not mention recall: {blockers}")

    # And the mirror case: attacks only, so no split can measure a
    # false-positive rate.
    attacks_only = synthetic(40, "task_redirection", "suspicious", "attack")
    attack_manifest = sm.build_manifest(DATASET, sm.assign(attacks_only))
    attack_blockers = sm.freeze_blockers(attack_manifest)
    if not any("false-positive" in blocker for blocker in attack_blockers):
        failures.append(
            f"a corpus with no benign cases was not blocked: {attack_blockers}"
        )

    # An empty split is a blocker in its own right.
    tiny = sm.build_manifest(
        DATASET, sm.assign(synthetic(1, "ordinary", "no_injection_detected", "tiny"))
    )
    if not sm.freeze_blockers(tiny):
        failures.append("a one-case corpus was reported fit to freeze")

    # A mixed corpus of reasonable size must be freezable, or the check is
    # just a pessimism machine.
    balanced = synthetic(
        250, "ordinary", "no_injection_detected", "bal-ord"
    ) + synthetic(75, "task_redirection", "suspicious", "bal-red")
    big = sm.build_manifest(DATASET, sm.assign(balanced))
    remaining = sm.freeze_blockers(big)
    if remaining:
        failures.append(
            f"a {len(balanced)}-case balanced corpus was not fit to freeze: {remaining}"
        )


def check_similarity_is_not_blinded(failures: list[str]) -> None:
    """The autojunk trap.

    difflib treats any character appearing in more than 1% of a sequence over
    200 characters as junk, which for prose means spaces and vowels. Two
    passages differing by one word scored 0.524 with the default, so every
    near-duplicate in a realistic passage went undetected. This pins the fix.
    """
    long_text = (
        "Ilmatieteen laitos ennustaa viikonlopuksi rantasateita maan etela- ja "
        "keskiosiin. Lampotila pysyttelee nollan tuntumassa, ja ajokeli voi "
        "muuttua paikoin huonoksi tanaan iltapaivalla. Liikenteessa kannattaa "
        "varata matkaan reilusti lisaaikaa ja noudattaa erityista varovaisuutta "
        "silloilla seka vilkkailla risteysalueilla ymparistossa."
    )
    altered = long_text.replace("huonoksi", "hankalaksi")

    # The threshold is on the *folded* text, because that is what difflib
    # sees. Checking the raw length was the first version of this, and it
    # passed a string that folded down below the autojunk cutoff - the test
    # then failed for the right reason with a misleading message.
    folded = fold(long_text)
    if len(folded) <= 200:
        failures.append(
            f"the autojunk test string folds to {len(folded)} characters, below "
            "difflib's 200-character cutoff, so it cannot exercise the bug"
        )
    ratio = similarity(folded, fold(altered))
    if ratio < 0.90:
        failures.append(
            f"two passages differing by one word scored {ratio:.3f}; difflib "
            "autojunk is blinding the near-duplicate detector"
        )


def check_duplicate_detection(failures: list[str]) -> None:
    """Both detectors must fire on planted cases."""
    cases = sm.load_cases(DATASET)
    assignment = {
        str(case["id"]): name
        for name, members in sm.assign(cases).items()
        for case in members
    }
    development = next(c for c in cases if assignment[str(c["id"])] == "development")
    holdout = next(c for c in cases if assignment[str(c["id"])] == "holdout")

    grown = copy.deepcopy(cases)
    # An exact duplicate.
    grown.append({**copy.deepcopy(development), "id": "planted-exact"})
    # A near-duplicate in a different split, which is the leak that matters.
    grown.append(
        {
            **copy.deepcopy(development),
            "id": "planted-leak",
            "text": str(development["text"]).replace("ja", "seka", 1),
            "group": holdout["group"],
        }
    )

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
        yaml.safe_dump(grown, handle, allow_unicode=True, sort_keys=False)
        path = Path(handle.name)
    try:
        report = review(path)
    finally:
        path.unlink()

    if not report["exact_duplicates"]:
        failures.append("an exact duplicate was not detected")
    if not report["cross_split_leakage"]:
        failures.append(
            "a 99%-similar passage in another split was not reported as leakage"
        )

    # The real corpus must be clean.
    live = review(DATASET)
    if live["exact_duplicates"]:
        failures.append(
            f"the corpus contains exact duplicates: {live['exact_duplicates']}"
        )

    # Matched pairs must NOT be reported: they share a group, and their
    # near-identity is the point.
    for item in live["near_duplicates"]:
        if item["groups"][0] == item["groups"][1]:
            failures.append(
                f"a matched pair was reported as a near-duplicate: {item['case_ids']}"
            )


def check_holdout_protection(failures: list[str]) -> None:
    """The three mechanisms, tested against a temporary manifest."""
    with tempfile.TemporaryDirectory() as directory:
        manifest_path = Path(directory) / "splits.json"
        log_path = Path(directory) / "access.jsonl"

        # Before freezing, requesting the holdout must fail loudly.
        try:
            load_frozen(manifest_path)
        except HoldoutNotFrozen:
            pass
        else:
            failures.append("load_frozen succeeded with no manifest")

        ids = {"a", "b", "c"}
        digest = hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest()
        manifest_path.write_text(
            json.dumps(
                {
                    "generated_at": "2026-01-01T00:00:00+00:00",
                    "dataset": {"sha256": "deadbeef"},
                    "splits": {
                        "holdout": {"case_ids": sorted(ids), "id_sha256": digest}
                    },
                }
            ),
            encoding="utf-8",
        )

        frozen = verify_unchanged(ids, manifest_path)
        if frozen.id_sha256 != digest:
            failures.append("verify_unchanged returned the wrong digest")

        # A changed holdout must be refused: it is not the frozen holdout, and
        # a result claimed against it is not a holdout result.
        try:
            verify_unchanged(ids | {"d"}, manifest_path)
        except HoldoutChanged:
            pass
        else:
            failures.append("a holdout that gained a case was accepted as unchanged")
        try:
            verify_unchanged(ids - {"a"}, manifest_path)
        except HoldoutChanged:
            pass
        else:
            failures.append("a holdout that lost a case was accepted as unchanged")

        # Access logging, and the prompt-change check that gives it meaning.
        if prompt_changed_since_last_access("abc", log_path):
            failures.append("an empty log reported a prompt change")
        record_access(
            reason="selftest",
            prompt_version="v1",
            prompt_fingerprint="abc",
            model="test",
            case_count=3,
            log=log_path,
        )
        if prompt_changed_since_last_access("abc", log_path):
            failures.append("an unchanged prompt was reported as changed")
        if not prompt_changed_since_last_access("different", log_path):
            failures.append(
                "a changed prompt was not detected, so a holdout result tuned "
                "against the holdout would look legitimate"
            )


def main() -> int:
    failures: list[str] = []

    check_stability(failures)
    check_groups_never_span(failures)
    check_weights(failures)
    check_freeze_blockers(failures)
    check_similarity_is_not_blinded(failures)
    check_duplicate_detection(failures)
    check_holdout_protection(failures)

    if failures:
        print(f"splits selftest: {len(failures)} failure(s)", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print("splits selftest: assignment is stable under growth and reordering;")
    print("                 no group spans a split, including matched pairs;")
    print("                 a holdout with no attacks is refused for freezing;")
    print("                 difflib autojunk is not blinding similarity;")
    print("                 exact duplicates and cross-split leakage both fire;")
    print("                 a changed or unfrozen holdout is refused")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
