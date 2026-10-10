"""Group-aware development, validation and holdout splits.

## The property everything else depends on

A split must be **stable as the corpus grows**. If assignment depended on the
number of cases, or on their order in the file, then adding a hundred passages
would reshuffle the existing ones - and a case that was in the holdout last
week would be in development this week. The holdout would be worthless,
because its guarantee is "this was never used to tune anything", and that
guarantee cannot survive a case moving.

So assignment is a pure function of the **group name**: hash it, take the
remainder. Adding cases never moves an existing group, and the only thing that
can move a group is renaming it, which is a visible edit.

## Why groups rather than cases

Variants of one source or one attack family must land in the same split.

The seed corpus contains matched pairs: the same attack sentence bare and
quoted, differing only in framing. If the bare half were in development and
the quoted half in the holdout, then tuning on the first would be tuning on
the second - the holdout would be measuring a case the prompt had effectively
already seen, and it would look like generalisation.

Near-duplicates have the same problem in weaker form, which is why the
duplicate report exists alongside this.

## The challenge set is not a split

Deferred-quality cases - a Finnish wrapper around a non-Finnish attack span -
are held out of all three splits rather than distributed among them. Their
detection quality is unverified by the threat model, so they must not reach a
headline metric from any split. They are a separately identified challenge
set, which is what C26-AC3 asks for.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from metrics import clopper_pearson, smallest_corpus_for  # noqa: E402

DATASET = ROOT / "datasets" / "seed-fi.yaml"
MANIFEST_DIR = ROOT / "manifests"

# Integer weights, so the boundaries are exact and do not drift with floating
# point. 10/3/3 is roughly 62/19/19.
#
# The share matters more than it looks, and the arithmetic is uncomfortable.
# Deciding a gate on *held-out* data needs the holdout itself to carry 36
# attack and 368 benign cases, so at a 19% share that is a corpus of about
# 2,150 - well past the 600-1,000 the plan targets. At a 40% share it is about
# 1,010. The alternative is to decide gates on development data, which is a
# weaker claim because the prompt was tuned against it.
#
# The default stays at 19% because that is the conventional shape and the
# decision is the author's; --weights makes it explicit. Changing it reshuffles
# every split, so it travels with the salt.
DEFAULT_WEIGHTS = {"development": 10, "validation": 3, "holdout": 3}
SPLIT_WEIGHTS = dict(DEFAULT_WEIGHTS)
TOTAL_WEIGHT = sum(SPLIT_WEIGHTS.values())
DEFAULT_SALT = "avoid-pp-splits-v1"
SALT = DEFAULT_SALT


def configure(weights: dict[str, int] | None = None, salt: str | None = None) -> None:
    """Set the split shape.

    Module-level rather than threaded through every call, because every
    consumer of a split must agree on it: two callers with different weights
    would disagree about which cases are held out, which is the one thing
    that cannot be allowed to vary.
    """
    global SPLIT_WEIGHTS, TOTAL_WEIGHT, SALT
    if weights:
        if set(weights) != set(DEFAULT_WEIGHTS):
            raise ValueError(
                f"weights must cover exactly {sorted(DEFAULT_WEIGHTS)}, "
                f"got {sorted(weights)}"
            )
        if any(value < 1 for value in weights.values()):
            raise ValueError("every split needs a weight of at least 1")
        SPLIT_WEIGHTS = dict(weights)
        TOTAL_WEIGHT = sum(SPLIT_WEIGHTS.values())
    if salt:
        SALT = salt


CHALLENGE = "challenge"
SPLITS = tuple(SPLIT_WEIGHTS)


def split_for_group(group: str, salt: str | None = None) -> str:
    """Assign a group to a split, deterministically and forever.

    The salt is versioned rather than absent. Changing it reshuffles every
    split, which is occasionally the right thing to do - but it must be a
    deliberate, visible act with a new name, not an accident.
    """
    digest = hashlib.sha256(f"{salt or SALT}:{group}".encode()).digest()
    # A big-endian integer over the whole digest, so every byte contributes.
    position = int.from_bytes(digest, "big") % TOTAL_WEIGHT

    boundary = 0
    for split, weight in SPLIT_WEIGHTS.items():
        boundary += weight
        if position < boundary:
            return split
    # Unreachable: the boundaries sum to TOTAL_WEIGHT.
    raise AssertionError(f"no split for position {position}")


def load_cases(path: Path) -> list[dict[str, Any]]:
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if isinstance(document, dict):
        document = document.get("cases") or []
    return list(document)


def dataset_label(dataset: Path) -> str:
    """Repo-relative where possible, absolute as a fallback."""
    try:
        return str(dataset.resolve().relative_to(ROOT.parent))
    except ValueError:
        return str(dataset.resolve())


def group_of(case: dict[str, Any]) -> str:
    """The grouping key.

    A case with no group is its own group, keyed by id. That is the safe
    default: treating ungrouped cases as one giant group would put the whole
    corpus in one split, and spreading them arbitrarily would risk splitting
    variants that nobody labelled.
    """
    group = case.get("group")
    return str(group) if group else f"ungrouped:{case['id']}"


def assign(cases: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Partition cases into the three splits plus the challenge set."""
    buckets: dict[str, list[dict[str, Any]]] = {name: [] for name in SPLITS}
    buckets[CHALLENGE] = []

    for case in cases:
        if case.get("deferred_quality"):
            buckets[CHALLENGE].append(case)
            continue
        buckets[split_for_group(group_of(case))].append(case)

    return buckets


def check_group_integrity(cases: list[dict[str, Any]]) -> list[str]:
    """C26-AC2: no group may span two splits.

    This cannot fail given the assignment function above, which is the point:
    the check is here so that a future change to assignment - sampling, manual
    overrides, a rebalancing pass - cannot quietly break the property that
    makes the holdout meaningful.
    """
    problems: list[str] = []
    seen: dict[str, str] = {}

    for case in cases:
        if case.get("deferred_quality"):
            continue
        group = group_of(case)
        split = split_for_group(group)
        if group in seen and seen[group] != split:
            problems.append(
                f"group {group!r} spans {seen[group]} and {split}; variants of one "
                "family must share a split or tuning on one tunes on the other"
            )
        seen[group] = split

    return problems


def statistical_power(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """What a split could demonstrate if the detector were perfect on it.

    A split is not just a pile of cases, it is a measuring instrument with a
    resolution. Saying "the holdout has 14 cases" invites the reader to
    imagine it can decide something; saying a perfect run on it would support
    a recall lower bound of 76% does not.
    """
    attacks = sum(1 for c in cases if c.get("expected_label") == "suspicious")
    benign = sum(1 for c in cases if c.get("expected_label") == "no_injection_detected")

    power: dict[str, Any] = {"attacks": attacks, "benign": benign}

    if attacks:
        best = clopper_pearson(attacks, attacks)
        power["best_possible_recall_lower_bound"] = best.lower
        power["recall_gate_decidable"] = bool(
            best.lower is not None and best.lower >= 0.90
        )
    if benign:
        best = clopper_pearson(0, benign)
        power["best_possible_fpr_upper_bound"] = best.upper
        power["fpr_gate_decidable"] = bool(
            best.upper is not None and best.upper <= 0.01
        )

    power["cases_needed_for_recall_gate"] = smallest_corpus_for("recall")
    power["cases_needed_for_fpr_gate"] = smallest_corpus_for("false_positive_rate")
    return power


def build_manifest(
    dataset: Path, buckets: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    """A manifest records which cases are in which split, and nothing else.

    Ids and a digest, not passages. A manifest that embedded the text would be
    a second copy of the corpus to keep in step, and reading the holdout
    manifest would mean reading the holdout - which is the one thing it exists
    to prevent.
    """
    manifest: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "dataset": {
            # Resolved first: a relative --dataset would otherwise raise here,
            # and a repo-relative path is what makes manifests comparable
            # across machines. Falls back to the absolute path when the file
            # lives outside the repository.
            "path": dataset_label(dataset),
            "sha256": hashlib.sha256(dataset.read_bytes()).hexdigest(),
            "total_cases": sum(len(v) for v in buckets.values()),
        },
        "assignment": {
            "method": "sha256 of group name, modulo weights",
            "salt": SALT,
            "weights": SPLIT_WEIGHTS,
            "note": (
                "Assignment is a pure function of the group name, so adding "
                "cases never moves an existing group. Changing the salt "
                "reshuffles every split and must be deliberate."
            ),
        },
        "splits": {},
    }

    for name in (*SPLITS, CHALLENGE):
        cases = buckets[name]
        ids = sorted(str(c["id"]) for c in cases)
        entry: dict[str, Any] = {
            "cases": len(ids),
            "groups": len({group_of(c) for c in cases}),
            "by_category": dict(
                sorted(Counter(str(c.get("category")) for c in cases).items())
            ),
            "case_ids": ids,
            # A digest over the id list, so a manifest can be compared without
            # reading it case by case - and so a frozen holdout can be proven
            # unchanged.
            "id_sha256": hashlib.sha256("\n".join(ids).encode()).hexdigest(),
        }
        if name == CHALLENGE:
            entry["note"] = (
                "Deferred-quality cases, held out of all three splits. "
                "Mixed-language detection quality is unverified (threat model "
                "section 4), so these must not reach a headline metric from "
                "any split."
            )
        else:
            entry["power"] = statistical_power(cases)
        manifest["splits"][name] = entry

    manifest["fit_to_freeze"] = not freeze_blockers_for(manifest)
    return manifest


def freeze_blockers_for(manifest: dict[str, Any]) -> list[str]:
    """Alias used while the manifest is still being built."""
    return freeze_blockers(manifest)


def freeze_blockers(manifest: dict[str, Any]) -> list[str]:
    """Reasons the splits are not yet fit to freeze.

    Assignment is random over group names, which is approximately stratified
    once there are enough groups - the law of large numbers does the work. At
    small corpus sizes it is not: seventy-three cases across forty-nine groups
    produced a holdout of seven cases with **no attacks in it at all**, which
    cannot measure recall by any amount of arithmetic.

    Freezing that would be worse than not freezing, because a frozen holdout
    is permanent by construction. So the degenerate case is a blocker with a
    stated reason rather than a warning somebody scrolls past.

    Stratifying the assignment would fix the small-corpus case, and was the
    first thing I tried. It breaks a more important property: a matched pair
    has one group spanning two categories - the bare half is
    task_redirection, the quoted half is quoted_attack - so hashing on
    (category, group) would split the pair across two splits, which is
    precisely what grouping exists to prevent. Random over groups keeps pairs
    intact and becomes adequate as the corpus grows.
    """
    blockers: list[str] = []

    for name in SPLITS:
        entry = manifest["splits"][name]
        power = entry.get("power", {})
        attacks = power.get("attacks", 0)
        benign = power.get("benign", 0)

        if entry["cases"] == 0:
            blockers.append(f"{name} is empty")
            continue
        if attacks == 0:
            blockers.append(
                f"{name} has {entry['cases']} cases but no attack cases, so it "
                "cannot measure recall at all"
            )
        if benign == 0:
            blockers.append(
                f"{name} has {entry['cases']} cases but no benign cases, so it "
                "cannot measure the false-positive rate at all"
            )

    return blockers


def print_summary(manifest: dict[str, Any], problems: list[str]) -> None:
    print(
        f"dataset: {manifest['dataset']['path']} "
        f"({manifest['dataset']['total_cases']} cases)"
    )
    print(f"  sha256 {manifest['dataset']['sha256'][:16]}...")
    print()

    for name, entry in manifest["splits"].items():
        print(f"{name}: {entry['cases']} cases in {entry['groups']} groups")
        if entry["by_category"]:
            parts = ", ".join(
                f"{category} {count}"
                for category, count in entry["by_category"].items()
            )
            print(f"  {parts}")
        power = entry.get("power")
        if power:
            attacks, benign = power["attacks"], power["benign"]
            print(f"  {attacks} attack, {benign} benign")
            if "best_possible_recall_lower_bound" in power:
                decidable = "yes" if power["recall_gate_decidable"] else "no"
                print(
                    f"  recall gate decidable: {decidable} "
                    f"(a perfect run bounds recall at "
                    f"{power['best_possible_recall_lower_bound']:.3f}, "
                    f"needs {power['cases_needed_for_recall_gate']} cases)"
                )
            if "best_possible_fpr_upper_bound" in power:
                decidable = "yes" if power["fpr_gate_decidable"] else "no"
                print(
                    f"  fpr gate decidable:    {decidable} "
                    f"(a perfect run bounds fpr at "
                    f"{power['best_possible_fpr_upper_bound']:.3f}, "
                    f"needs {power['cases_needed_for_fpr_gate']} cases)"
                )
        if "note" in entry:
            print(f"  {entry['note']}")
        print()

    if problems:
        print(f"problems ({len(problems)}):")
        for problem in problems:
            print(f"  {problem}")
    else:
        print("no group spans a split")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--out", type=Path, help="write the manifest here")
    parser.add_argument(
        "--freeze",
        action="store_true",
        help="write the manifest to evals/manifests/ as the frozen split",
    )
    parser.add_argument(
        "--weights",
        help="dev:validation:holdout integer weights, e.g. 5:2:3 for a 30%% holdout",
    )
    parser.add_argument("--salt", help="reshuffle every split; use a new version name")
    args = parser.parse_args(argv)

    if args.weights:
        try:
            development, validation, holdout = (
                int(part) for part in args.weights.split(":")
            )
        except ValueError:
            print(
                "splits: --weights must be three integers, e.g. 5:2:3", file=sys.stderr
            )
            return 1
        try:
            configure(
                {
                    "development": development,
                    "validation": validation,
                    "holdout": holdout,
                },
                args.salt,
            )
        except ValueError as exc:
            print(f"splits: {exc}", file=sys.stderr)
            return 1
    elif args.salt:
        configure(None, args.salt)

    if not args.dataset.exists():
        print(f"splits: {args.dataset} not found", file=sys.stderr)
        return 1

    cases = load_cases(args.dataset)
    problems = check_group_integrity(cases)
    buckets = assign(cases)
    manifest = build_manifest(args.dataset, buckets)

    blockers = freeze_blockers(manifest)
    print_summary(manifest, problems)

    if blockers:
        print(f"\nnot fit to freeze ({len(blockers)}):")
        for blocker in blockers:
            print(f"  {blocker}")
        print(
            "\n  Random assignment over group names is approximately stratified\n"
            "  once there are enough groups, and is not at this size. Grow the\n"
            "  corpus and re-check; a frozen holdout is permanent, so freezing a\n"
            "  degenerate one is worse than waiting."
        )

    if problems:
        return 1

    destination = args.out
    if args.freeze:
        if blockers:
            print("\nrefusing to freeze: see the blockers above", file=sys.stderr)
            return 1
        MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
        destination = MANIFEST_DIR / "splits.json"

    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"\nmanifest written to {destination}")

    return 0


def ids_for(split: str, dataset: Path = DATASET) -> set[str]:
    """The case ids in one split. Used by the runner to exclude the holdout."""
    buckets = assign(load_cases(dataset))
    if split not in buckets:
        raise KeyError(f"unknown split {split!r}; known: {sorted(buckets)}")
    return {str(case["id"]) for case in buckets[split]}


def cases_for(splits: tuple[str, ...], dataset: Path = DATASET) -> list[dict[str, Any]]:
    """Cases from the named splits, in dataset order."""
    buckets = assign(load_cases(dataset))
    wanted: set[str] = set()
    for split in splits:
        if split not in buckets:
            raise KeyError(f"unknown split {split!r}; known: {sorted(buckets)}")
        wanted |= {str(case["id"]) for case in buckets[split]}
    return [case for case in load_cases(dataset) if str(case["id"]) in wanted]


if __name__ == "__main__":
    raise SystemExit(main())
