"""C26-AC2: a duplicate and near-duplicate review report over the corpus.

Reported, never removed. The judgement is the author's, because the tool
cannot tell the difference between a mistake and the point:

  * Two passages differing only in framing are a **matched pair**, and that
    near-identity is exactly what makes them the sharpest cases in the corpus.
  * Two passages differing only in a diacritic are a **deliberate pair**
    testing whether a missing umlaut changes the verdict.
  * Two passages differing only in a typo are probably one passage entered
    twice.

A tool that deduplicated automatically would delete the first two kinds, and
would do it silently, and nobody would find out until the corpus had quietly
lost the cases it was built for.

## Why near-duplicates matter beyond tidiness

A near-duplicate spanning two splits leaks. If a passage in development is
95% identical to one in the holdout, then tuning on the first is tuning on the
second, and the holdout result measures memorisation rather than
generalisation. So the report flags cross-split similarity separately and more
loudly than similarity within one split, which is merely redundant.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
import unicodedata
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import splits as splits_module  # noqa: E402

DATASET = ROOT / "datasets" / "seed-fi.yaml"

# Two thresholds, because the two findings are not equally serious.
EXACT = 1.0
NEAR = 0.90
# Cross-split leakage is worth reporting at a lower bar than redundancy.
CROSS_SPLIT_NEAR = 0.80


def fold(text: str) -> str:
    """Fold a passage for comparison only.

    Never used for storage. Case, diacritics and punctuation are all
    meaningful in this corpus - a missing diacritic is a deliberate test case
    - so this exists purely to notice that two passages are the same thing
    typed twice.
    """
    folded = unicodedata.normalize("NFKD", text.casefold())
    folded = "".join(ch for ch in folded if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", " ", folded).strip()


def similarity(left: str, right: str) -> float:
    """Character-level similarity of two folded passages.

    autojunk=False is load-bearing. difflib treats any character appearing in
    more than 1% of a sequence longer than 200 characters as "junk" and
    excludes it from matching - which for prose means spaces and common
    vowels. Two Finnish passages differing by one word scored 0.524 with the
    default, so every near-duplicate above the 200-character mark went
    undetected, and realistic passages are all above it.
    """
    return difflib.SequenceMatcher(None, left, right, autojunk=False).ratio()


def review(dataset: Path) -> dict[str, Any]:
    cases = splits_module.load_cases(dataset)
    assignment = {
        str(case["id"]): name
        for name, members in splits_module.assign(cases).items()
        for case in members
    }

    folded = {str(case["id"]): fold(str(case["text"])) for case in cases}
    group = {str(case["id"]): splits_module.group_of(case) for case in cases}
    label = {str(case["id"]): str(case.get("expected_label")) for case in cases}

    exact: list[dict[str, Any]] = []
    near: list[dict[str, Any]] = []
    leakage: list[dict[str, Any]] = []

    by_fold: dict[str, list[str]] = defaultdict(list)
    for case_id, text in folded.items():
        by_fold[text].append(case_id)

    for text, ids in by_fold.items():
        if len(ids) > 1 and text:
            exact.append(
                {
                    "case_ids": sorted(ids),
                    "splits": sorted({assignment[i] for i in ids}),
                    "groups": sorted({group[i] for i in ids}),
                    "labels": sorted({label[i] for i in ids}),
                }
            )

    ids = sorted(folded)
    for index, left in enumerate(ids):
        for right in ids[index + 1 :]:
            if folded[left] == folded[right]:
                continue
            ratio = similarity(folded[left], folded[right])
            same_group = group[left] == group[right]
            same_split = assignment[left] == assignment[right]

            if ratio >= NEAR and not same_group:
                near.append(
                    {
                        "case_ids": [left, right],
                        "similarity": round(ratio, 3),
                        "splits": [assignment[left], assignment[right]],
                        "groups": [group[left], group[right]],
                        "labels": [label[left], label[right]],
                        "same_split": same_split,
                    }
                )
            # Leakage: similar, in different splits, and not deliberately
            # grouped together. A lower bar, because the consequence is a
            # holdout that measures memorisation.
            if ratio >= CROSS_SPLIT_NEAR and not same_split and not same_group:
                leakage.append(
                    {
                        "case_ids": [left, right],
                        "similarity": round(ratio, 3),
                        "splits": [assignment[left], assignment[right]],
                        "groups": [group[left], group[right]],
                    }
                )

    near.sort(key=lambda item: -item["similarity"])
    leakage.sort(key=lambda item: -item["similarity"])

    return {
        "dataset": splits_module.dataset_label(dataset),
        "cases_compared": len(cases),
        "comparisons": len(ids) * (len(ids) - 1) // 2,
        "thresholds": {
            "exact": EXACT,
            "near": NEAR,
            "cross_split_near": CROSS_SPLIT_NEAR,
        },
        "exact_duplicates": exact,
        "near_duplicates": near,
        "cross_split_leakage": leakage,
        "note": (
            "Nothing is removed. Two passages differing only in framing are a "
            "matched pair, and that near-identity is the point - a tool that "
            "deduplicated automatically would delete the sharpest cases in "
            "the corpus. Cases sharing a group are exempt."
        ),
    }


def print_report(report: dict[str, Any]) -> None:
    print(f"dataset: {report['dataset']}")
    print(f"  {report['cases_compared']} cases, {report['comparisons']} comparisons")
    print()

    exact = report["exact_duplicates"]
    if exact:
        print(f"exact duplicates ({len(exact)}) - almost certainly a mistake:")
        for item in exact:
            print(f"  {', '.join(item['case_ids'])}")
            print(f"      splits {item['splits']}  labels {item['labels']}")
    else:
        print("exact duplicates: none")
    print()

    near = report["near_duplicates"]
    if near:
        print(f"near duplicates ({len(near)}) - your call:")
        for item in near[:25]:
            marker = "" if item["same_split"] else "  [different splits]"
            print(
                f"  {item['similarity']:.0%}  {item['case_ids'][0]} / "
                f"{item['case_ids'][1]}{marker}"
            )
            if item["labels"][0] != item["labels"][1]:
                print(
                    f"      different labels: {item['labels']} - this may be a "
                    "matched pair that is not grouped"
                )
        if len(near) > 25:
            print(f"  ... and {len(near) - 25} more")
    else:
        print(f"near duplicates: none above {report['thresholds']['near']:.0%}")
    print()

    leakage = report["cross_split_leakage"]
    if leakage:
        print(f"cross-split leakage ({len(leakage)}) - these matter most:")
        print("  A passage similar to one in another split means tuning on the")
        print("  first tunes on the second, so the holdout measures memorisation.")
        for item in leakage[:25]:
            print(
                f"  {item['similarity']:.0%}  {item['case_ids'][0]} ({item['splits'][0]})"
                f" / {item['case_ids'][1]} ({item['splits'][1]})"
            )
        if len(leakage) > 25:
            print(f"  ... and {len(leakage) - 25} more")
        print()
        print("  Fix by giving both cases the same group, which puts them in the")
        print("  same split, or by rewriting one of them.")
    else:
        print(
            "cross-split leakage: none above "
            f"{report['thresholds']['cross_split_near']:.0%}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--out", type=Path, help="write the report as JSON")
    parser.add_argument(
        "--fail-on-leakage",
        action="store_true",
        help="exit non-zero if any cross-split leakage is found",
    )
    args = parser.parse_args(argv)

    if not args.dataset.exists():
        print(f"duplicates: {args.dataset} not found", file=sys.stderr)
        return 1

    report = review(args.dataset)
    print_report(report)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"\nreport written to {args.out}")

    if args.fail_on_leakage and report["cross_split_leakage"]:
        return 1
    # Exact duplicates always fail: there is no reading under which the same
    # passage twice is intentional.
    return 1 if report["exact_duplicates"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
