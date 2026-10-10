"""C26-AC1: what the corpus covers, and what it is missing.

The acceptance criteria name specific properties the corpus must include:
colloquial Finnish, inflections, missing diacritics, benign commands, attack
contexts, and a fluent review status. This counts them, so the author can see
progress against each one instead of against a single total.

## These are heuristics, and say so

Detecting "colloquial register" by looking for `mä` and `sä` is crude. A
fluent speaker reading the corpus is the real check, which is what the review
status records. What this is for is the one thing a human cannot do quickly
over four hundred passages: notice that a property is at **zero** or stuck.

So every number here is reported as a count with its detector written down,
never as a score. A low count is a prompt to look, not a verdict.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import splits as splits_module  # noqa: E402

DATASET = ROOT / "datasets" / "seed-fi.yaml"

# Spoken-Finnish markers. Deliberately narrow: a false positive here would
# overstate coverage, and overstating is the failure that matters.
COLLOQUIAL = (
    r"\bmä\b",
    r"\bmun\b",
    r"\bmua\b",
    r"\bsä\b",
    r"\bsun\b",
    r"\bsua\b",
    r"\bse on\b",
    r"\bne on\b",
    r"\boo\b",
    r"\btoi\b",
    r"\btää\b",
    r"\btän\b",
    r"\bmeiän\b",
    r"\bteiän\b",
    r"\bku\b",
    r"\bet\b\s",
    r"\bni\b",
    r"\bjoo\b",
    r"\bei oo\b",
    r"\bmitä\b.*\?",
    r"\bnii\b",
)

# Finnish words that very commonly carry diacritics. A passage containing the
# undiacriticised spelling of one of these was probably typed without them.
MISSING_DIACRITICS = (
    ("paiva", "päivä"),
    ("aanest", "äänest"),
    ("kaanno", "käännö"),
    ("kaanna", "käännä"),
    ("tanaan", "tänään"),
    ("saa ", "sää "),
    ("laikkeel", "läikkeel"),
    ("hyva", "hyvä"),
    ("viikko", None),
    ("tyo", "työ"),
    ("yli", None),
    ("maara", "määrä"),
    ("aiti", "äiti"),
    ("elama", "elämä"),
    ("jarjest", "järjest"),
    ("kaytt", "käytt"),
    ("mahdollisu", None),
    ("paatos", "päätös"),
    ("tarkea", "tärkeä"),
)

# Imperative-mood endings and common command verbs, as a rough signal.
IMPERATIVE = (
    r"\b\w+kaa\b",
    r"\b\w+kää\b",
    r"\bsekoita\b",
    r"\blisää\b",
    r"\bpaista\b",
    r"\baseta\b",
    r"\bkäännä\b",
    r"\botta\b",
    r"\bpoista\b",
    r"\bkiinnitä\b",
    r"\btarkista\b",
    r"\bodota\b",
    r"\bvalitse\b",
    r"\bpaina\b",
    r"\bavaa\b",
    r"\bsulje\b",
    r"\bnosta\b",
    r"\blaske\b",
    r"\bkirjoita\b",
    r"\bälä\b",
)

# A long single token is the agglutinative case the tokeniser fragments.
LONG_TOKEN = 20


def has_any(text: str, patterns: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(re.search(pattern, lowered) for pattern in patterns)


def looks_undiacriticised(text: str) -> bool:
    """Whether a passage looks typed without diacritics.

    Two signals, both needed: a word that normally carries a diacritic spelled
    without one, and no Finnish diacritics anywhere in the passage. Requiring
    both avoids counting a passage that simply happens to contain "hyva" as a
    name.
    """
    lowered = text.lower()
    if re.search(r"[äöåÄÖÅ]", text):
        return False
    return any(bare in lowered for bare, accented in MISSING_DIACRITICS if accented)


def longest_token(text: str) -> int:
    tokens = re.findall(r"\w+", text, flags=re.UNICODE)
    return max((len(token) for token in tokens), default=0)


def audit(dataset: Path) -> dict[str, Any]:
    cases = splits_module.load_cases(dataset)
    assignment = {
        str(case["id"]): name
        for name, members in splits_module.assign(cases).items()
        for case in members
    }

    properties: dict[str, list[str]] = {
        "colloquial_register": [],
        "missing_diacritics": [],
        "long_inflected_tokens": [],
        "imperative_mood": [],
        "contains_digits": [],
        "contains_url_or_email": [],
        "multi_paragraph": [],
        "quoted_speech": [],
    }

    lengths: list[int] = []
    for case in cases:
        case_id = str(case["id"])
        text = str(case["text"])
        lengths.append(len(text))

        if has_any(text, COLLOQUIAL):
            properties["colloquial_register"].append(case_id)
        if looks_undiacriticised(text):
            properties["missing_diacritics"].append(case_id)
        if longest_token(text) >= LONG_TOKEN:
            properties["long_inflected_tokens"].append(case_id)
        if has_any(text, IMPERATIVE):
            properties["imperative_mood"].append(case_id)
        if re.search(r"\d", text):
            properties["contains_digits"].append(case_id)
        if re.search(r"https?://|\S+@\S+\.\w+", text):
            properties["contains_url_or_email"].append(case_id)
        if "\n\n" in text.strip():
            properties["multi_paragraph"].append(case_id)
        if re.search(r"[\"“”«»]", text):
            properties["quoted_speech"].append(case_id)

    review = Counter(str(case.get("review_status", "missing")) for case in cases)
    categories = Counter(str(case.get("category")) for case in cases)
    labels = Counter(str(case.get("expected_label")) for case in cases)
    by_split = Counter(assignment.values())

    lengths.sort()
    return {
        "dataset": splits_module.dataset_label(dataset),
        "total_cases": len(cases),
        "by_category": dict(sorted(categories.items())),
        "by_label": dict(sorted(labels.items())),
        "by_split": dict(sorted(by_split.items())),
        "review_status": dict(sorted(review.items())),
        "length_chars": {
            "min": lengths[0] if lengths else 0,
            "median": lengths[len(lengths) // 2] if lengths else 0,
            "max": lengths[-1] if lengths else 0,
        },
        "properties": {
            name: {"cases": len(ids), "case_ids": ids}
            for name, ids in sorted(properties.items())
        },
        "detectors": {
            "colloquial_register": "spoken-Finnish pronoun and particle markers",
            "missing_diacritics": (
                "a normally-diacriticised word spelled without one, and no "
                "diacritics anywhere in the passage"
            ),
            "long_inflected_tokens": f"a single token of {LONG_TOKEN}+ characters",
            "imperative_mood": "imperative endings and common command verbs",
        },
        "note": (
            "These are heuristics, not measurements. A fluent speaker reading "
            "the corpus is the real check, which review_status records. What "
            "this catches is a property sitting at zero across four hundred "
            "passages, which a human reading them would not notice."
        ),
    }


# What C26-AC1 asks the corpus to include, with a floor worth aiming at.
AC1_TARGETS = {
    "colloquial_register": 60,
    "missing_diacritics": 40,
    "long_inflected_tokens": 60,
    "imperative_mood": 60,
}


def print_audit(report: dict[str, Any]) -> None:
    print(f"dataset: {report['dataset']} ({report['total_cases']} cases)")
    print()
    print("composition:")
    for name, counts in (
        ("category", report["by_category"]),
        ("label", report["by_label"]),
        ("split", report["by_split"]),
        ("review", report["review_status"]),
    ):
        parts = ", ".join(f"{key} {value}" for key, value in counts.items())
        print(f"  {name:<10} {parts}")
    length = report["length_chars"]
    print(
        f"  {'length':<10} min {length['min']}, median {length['median']}, "
        f"max {length['max']} characters"
    )
    print()

    print("C26-AC1 coverage (heuristic counts, not scores):")
    for name, target in AC1_TARGETS.items():
        found = report["properties"][name]["cases"]
        marker = "ok " if found >= target else "   "
        print(f"  {marker} {name:<24} {found:>4} / {target}")
    print()
    print("other properties present:")
    for name, entry in report["properties"].items():
        if name in AC1_TARGETS:
            continue
        print(f"      {name:<24} {entry['cases']:>4}")

    pending = report["review_status"].get("pending_review", 0)
    if pending:
        print()
        print(f"{pending} case(s) are pending review. C26-AC1 requires fluent")
        print("review status before any quality claim, so these cannot support one:")
        print("  (ids in the JSON report)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    if not args.dataset.exists():
        print(f"audit: {args.dataset} not found", file=sys.stderr)
        return 1

    report = audit(args.dataset)
    print_audit(report)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"\nreport written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
