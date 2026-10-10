"""Write authored reference translations into the dataset.

Separate from ingest.py because the input is different: this fills a field on
existing cases rather than adding new ones, so the failure modes are different
too - a translation attached to the wrong id is worse than a missing one, and
it would be invisible.

So the Finnish in the file is checked against the Finnish in the dataset
before anything is written. If they disagree, the pairing is wrong and nothing
is written for that case.

    python evals/authoring/ingest_translations.py            # report only
    python evals/authoring/ingest_translations.py --write
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
EVALS = HERE.parent
DATASET = EVALS / "datasets" / "seed-fi.yaml"
SOURCE = HERE / "07-reference-translations.txt"

NEEDS_ENGLISH = {"quoted_attack", "task_redirection", "detector_targeting"}


@dataclass
class Authored:
    case_id: str
    finnish: str
    english: str
    line: int


@dataclass
class Report:
    authored: list[Authored] = field(default_factory=list)
    blank: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    # Already written to the dataset by an earlier run. Counted, not listed:
    # the authoring file is kept as the record rather than emptied, so every
    # later run sees its own earlier work - and reporting that as a problem
    # made the tool fail after succeeding.
    already_written: int = 0
    # A translation in the file that differs from the one in the dataset.
    # That one *is* a problem: two different answers and no way to tell which
    # is intended.
    conflicts: list[str] = field(default_factory=list)


def parse(path: Path) -> Report:
    """Read the authoring file.

    A block is `=== id`, then `FI:` and `EN:` lines. The FI line is carried
    through only so it can be compared with the dataset; it is never written.
    """
    report = Report()
    if not path.exists():
        report.problems.append(f"{path} not found")
        return report

    case_id: str | None = None
    start = 0
    finnish: list[str] = []
    english: list[str] = []
    field_name: str | None = None

    def flush() -> None:
        nonlocal case_id, finnish, english, field_name
        if case_id is not None:
            text = " ".join(part.strip() for part in english).strip()
            if text:
                report.authored.append(
                    Authored(
                        case_id=case_id,
                        finnish=" ".join(p.strip() for p in finnish).strip(),
                        english=text,
                        line=start,
                    )
                )
            else:
                report.blank.append(case_id)
        case_id, finnish, english, field_name = None, [], [], None

    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw.strip()
        if stripped.startswith("==="):
            flush()
            case_id = stripped.lstrip("= ").strip()
            start = number
            if not case_id:
                report.problems.append(f"{path.name}:{number}: '===' with no case id")
            continue
        if stripped.startswith("#"):
            continue
        if stripped.upper().startswith("FI:"):
            field_name = "FI"
            finnish.append(stripped[3:])
            continue
        if stripped.upper().startswith("EN:"):
            field_name = "EN"
            english.append(stripped[3:])
            continue
        if not stripped:
            field_name = None
            continue
        if field_name == "EN":
            english.append(stripped)
        elif field_name == "FI":
            finnish.append(stripped)
        elif case_id is not None:
            report.problems.append(
                f"{path.name}:{number}: text outside FI:/EN: in {case_id}"
            )

    flush()
    return report


def normalise_whitespace(text: str) -> str:
    """Collapse whitespace for the pairing check only.

    The authoring file joins a multi-line passage onto one line, so the stored
    text and the file's text differ in whitespace by construction. Everything
    else must match exactly - this is not a licence to accept a different
    passage, only a different line wrapping of the same one.
    """
    return re.sub(r"\s+", " ", text).strip()


def validate(report: Report, cases: list[dict[str, Any]]) -> dict[str, str]:
    """Pair authored translations with cases, refusing anything suspicious."""
    by_id = {str(c["id"]): c for c in cases}
    accepted: dict[str, str] = {}

    for authored in report.authored:
        case = by_id.get(authored.case_id)
        if case is None:
            report.problems.append(
                f"line {authored.line}: no case with id {authored.case_id!r}"
            )
            continue

        # The check that matters. A translation attached to the wrong id would
        # be invisible afterwards, and would quietly make every outcome grade
        # for that case wrong.
        if normalise_whitespace(str(case["text"])) != normalise_whitespace(
            authored.finnish
        ):
            report.problems.append(
                f"line {authored.line}: the FI line for {authored.case_id} does not "
                "match the dataset; the file and the corpus have drifted, so the "
                "pairing cannot be trusted"
            )
            continue

        if str(case.get("category")) not in NEEDS_ENGLISH:
            report.problems.append(
                f"line {authored.line}: {authored.case_id} is "
                f"{case.get('category')}, which does not take a reference "
                "translation"
            )
            continue

        existing = case.get("expected_english")
        if existing:
            if normalise_whitespace(str(existing)) == normalise_whitespace(
                authored.english
            ):
                # Written by an earlier run. Nothing to do and nothing wrong.
                report.already_written += 1
            else:
                report.conflicts.append(
                    f"line {authored.line}: {authored.case_id} has a different "
                    "reference translation in the dataset; remove one of them "
                    "rather than guessing which is intended"
                )
            continue

        # A translation identical to the source is almost always a mistake -
        # either the EN line was left as a copy, or the case is not Finnish.
        if normalise_whitespace(authored.english) == normalise_whitespace(
            str(case["text"])
        ):
            report.problems.append(
                f"line {authored.line}: {authored.case_id} the English is identical "
                "to the Finnish"
            )
            continue

        accepted[authored.case_id] = authored.english

    return accepted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    args = parser.parse_args(argv)

    cases = yaml.safe_load(args.dataset.read_text(encoding="utf-8")) or []
    report = parse(args.source)
    accepted = validate(report, cases)

    outstanding = [
        str(c["id"])
        for c in cases
        if str(c.get("category")) in NEEDS_ENGLISH and not c.get("expected_english")
    ]

    total_needing = sum(1 for c in cases if str(c.get("category")) in NEEDS_ENGLISH)
    print(f"authored: {len(report.authored)} translations in the file")
    print(f"  new, ready to write : {len(accepted)}")
    if report.already_written:
        print(f"  already in dataset  : {report.already_written}")
    print(f"  left blank          : {len(report.blank)}")
    print(
        f"  still outstanding   : {len(outstanding) - len(accepted)} of "
        f"{total_needing} attack cases"
    )

    # A translation in the file differing from the one in the dataset is a
    # real problem: two different answers and no way to tell which is meant.
    # Distinct from work an earlier run already wrote, which is counted above
    # and is not a problem at all - reporting that as one made the tool fail
    # immediately after succeeding.
    if report.conflicts:
        print(f"\nconflicts ({len(report.conflicts)}):")
        for conflict in report.conflicts:
            print(f"  {conflict}")
        report.problems.extend(report.conflicts)

    if report.problems:
        print(f"\nproblems ({len(report.problems)}):")
        for problem in report.problems:
            print(f"  {problem}")
        print("\nnot writing: fix the problems above first")
        return 1

    if not args.write:
        if accepted:
            print(f"\ndry run. {len(accepted)} ready; re-run with --write")
        return 0

    if not accepted:
        print("\nnothing to write")
        return 0

    written = 0
    for case in cases:
        english = accepted.get(str(case["id"]))
        if english is None:
            continue
        # Trailing newline to match the corpus convention for text fields.
        case["expected_english"] = english + "\n"
        # The field is no longer pending, so the marker goes.
        case.pop("translation_status", None)
        written += 1

    args.dataset.write_text(
        yaml.safe_dump(cases, allow_unicode=True, sort_keys=False, width=100),
        encoding="utf-8",
    )
    print(f"\nwrote {written} reference translations to {args.dataset}")
    print("now run: make check-evals")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
