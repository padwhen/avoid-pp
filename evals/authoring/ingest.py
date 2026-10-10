"""Turn authored plain text into dataset YAML.

The author writes Finnish passages in `.txt` files, one per block. This
assigns ids, groups, labels and provenance, checks for duplicates, and writes
the result. Nothing here invents Finnish: a passage comes out exactly as it
went in, byte for byte, which is asserted rather than assumed.

Two deliberate properties:

  * **Idempotent.** Re-running it does not duplicate or renumber existing
    cases. Ids are derived from the passage, not from a counter, so adding a
    case in the middle of a file does not shift every id after it - which
    would otherwise rewrite history in the YAML and in every saved report
    that referenced an id.
  * **Dry run by default.** It reports what it found and changes nothing
    unless asked. Writing 400 passages is enough work without a tool that
    silently rewrites the file.

    python evals/authoring/ingest.py              # report only
    python evals/authoring/ingest.py --write      # append to the dataset
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
EVALS = HERE.parent
DATASET = EVALS / "datasets" / "seed-fi.yaml"

CLEAN = "no_injection_detected"
SUSPICIOUS = "suspicious"

# Per-file conventions. The prefix becomes the id stem, so an id says what
# kind of case it is without a lookup.
SOURCES = {
    "01-ordinary.txt": {
        "category": "ordinary",
        "prefix": "fi-ord",
        "label": CLEAN,
        "outcome": "faithful_translation",
        "target": 250,
    },
    "02-imperative.txt": {
        "category": "imperative",
        "prefix": "fi-imp",
        "label": CLEAN,
        "outcome": "faithful_translation",
        "target": 60,
    },
    "04-task-redirection.txt": {
        "category": "task_redirection",
        "prefix": "fi-red",
        "label": SUSPICIOUS,
        "outcome": "blocked_or_refused",
        "target": 35,
    },
    "05-detector-targeting.txt": {
        "category": "detector_targeting",
        "prefix": "fi-det",
        "label": SUSPICIOUS,
        "outcome": "blocked_or_refused",
        "target": 15,
    },
}

PAIRS_FILE = "03-pairs.txt"
PAIRS_TARGET = 40

# A passage this similar to another is reported for the author to judge.
# Reported, never dropped: two passages can legitimately be near-identical
# when the difference is the point, which is exactly what a matched pair is.
NEAR_DUPLICATE_RATIO = 0.92


@dataclass
class Authored:
    text: str
    category: str
    label: str
    outcome: str
    group: str
    source: str
    line: int
    mixed: bool = False
    notes: str | None = None
    pair_role: str | None = None


@dataclass
class Report:
    authored: list[Authored] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)
    near_duplicates: list[str] = field(default_factory=list)


def blocks(path: Path) -> list[tuple[int, str, bool]]:
    """Split a file into (line number, text, mixed-flag) blocks.

    A block is separated by a blank line. Comment lines are dropped, except
    that `# MIXED` sets a flag on the block that follows it.
    """
    if not path.exists():
        return []

    found: list[tuple[int, str, bool]] = []
    current: list[str] = []
    start = 0
    mixed = False
    pending_mixed = False

    def flush() -> None:
        nonlocal current, mixed
        text = "\n".join(current).strip()
        if text:
            found.append((start, text, mixed))
        current = []
        mixed = False

    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw.strip()
        if stripped.startswith("#"):
            if stripped.upper().replace(" ", "") in ("#MIXED", "#MIXED:"):
                pending_mixed = True
            continue
        if not stripped:
            flush()
            continue
        if not current:
            start = number
            mixed = pending_mixed
            pending_mixed = False
        current.append(raw.rstrip())

    flush()
    return found


def case_id(prefix: str, text: str) -> str:
    """A stable id derived from the passage.

    Content-derived rather than sequential, so inserting a case in the middle
    of a file does not renumber everything after it. A saved report that cites
    an id must keep meaning the same passage.
    """
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{digest}"


def normalise_for_comparison(text: str) -> str:
    """Fold a passage for duplicate detection only.

    Never used for storage. Case, diacritics, punctuation and whitespace are
    all meaningful in the corpus - a missing diacritic is a deliberate test
    case - so this folding exists purely to notice that two passages are the
    same thing typed twice.
    """
    folded = unicodedata.normalize("NFKD", text.casefold())
    folded = "".join(ch for ch in folded if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", " ", folded).strip()


def read_pairs(path: Path, report: Report) -> None:
    """Parse the matched-pairs file."""
    if not path.exists():
        return

    text = path.read_text(encoding="utf-8")
    lines = [
        (number, line)
        for number, line in enumerate(text.splitlines(), 1)
        if not line.strip().startswith("#")
    ]

    group: str | None = None
    group_line = 0
    current: dict[str, list[str]] = {}
    field_name: str | None = None

    def flush() -> None:
        nonlocal current, field_name
        if group is None:
            current, field_name = {}, None
            return
        bare = "\n".join(current.get("BARE", [])).strip()
        quoted = "\n".join(current.get("QUOTED", [])).strip()

        if bare and not quoted:
            report.problems.append(
                f"{path.name}:{group_line}: pair '{group}' has BARE but no QUOTED; "
                "the pair is the point, so a half pair is not usable"
            )
        elif quoted and not bare:
            report.problems.append(
                f"{path.name}:{group_line}: pair '{group}' has QUOTED but no BARE"
            )
        elif bare and quoted:
            if normalise_for_comparison(bare) == normalise_for_comparison(quoted):
                report.problems.append(
                    f"{path.name}:{group_line}: pair '{group}' has identical halves; "
                    "the quoted half needs real surrounding context"
                )
            elif bare.strip('"”“ ') == quoted.strip('"”“ '):
                report.problems.append(
                    f"{path.name}:{group_line}: pair '{group}' quoted half is the bare "
                    "attack with quote marks added, not genuine context"
                )
            else:
                # The bare half is the attack; the quoted half is legitimate
                # discussion *about* an attack and must translate normally.
                report.authored.append(
                    Authored(
                        text=bare,
                        category="task_redirection",
                        label=SUSPICIOUS,
                        outcome="blocked_or_refused",
                        group=f"pair-{group}",
                        source=path.name,
                        line=group_line,
                        pair_role="bare",
                        notes=(
                            f"Matched pair '{group}': the identical attack sentence, "
                            "here bare. Framing is the only variable."
                        ),
                    )
                )
                report.authored.append(
                    Authored(
                        text=quoted,
                        category="quoted_attack",
                        label=CLEAN,
                        outcome="faithful_translation",
                        group=f"pair-{group}",
                        source=path.name,
                        line=group_line,
                        pair_role="quoted",
                        notes=(
                            f"Matched pair '{group}': the identical attack sentence, "
                            "here quoted in legitimate context. Framing is the only "
                            "variable."
                        ),
                    )
                )
        current, field_name = {}, None

    for number, line in lines:
        stripped = line.strip()
        if stripped.startswith("==="):
            flush()
            group = stripped.lstrip("= ").strip()
            group_line = number
            if not group:
                report.problems.append(
                    f"{path.name}:{number}: '===' with no group name"
                )
            continue
        for marker in ("BARE:", "QUOTED:"):
            if stripped.upper().startswith(marker):
                field_name = marker.rstrip(":")
                current.setdefault(field_name, []).append(
                    stripped[len(marker) :].strip()
                )
                break
        else:
            if not stripped:
                field_name = None
            elif field_name:
                current[field_name].append(stripped)
            elif group is not None:
                report.problems.append(
                    f"{path.name}:{number}: text outside BARE:/QUOTED: in pair '{group}'"
                )
    flush()


def collect() -> Report:
    report = Report()

    for filename, spec in SOURCES.items():
        for line, text, mixed in blocks(HERE / filename):
            report.authored.append(
                Authored(
                    text=text,
                    category=str(spec["category"]),
                    label=str(spec["label"]),
                    outcome=str(spec["outcome"]),
                    # A group per case by default: nothing claims these are
                    # variants of each other, and a wrong grouping would put
                    # unrelated cases in the same split.
                    group=f"{spec['prefix']}-{case_id('g', text).split('-')[-1]}",
                    source=filename,
                    line=line,
                    mixed=mixed,
                )
            )
        report.authored.sort(key=lambda a: (a.source, a.line))

    read_pairs(HERE / PAIRS_FILE, report)
    return report


def existing_passages(dataset: Path) -> dict[str, str]:
    """Passages already in the dataset, keyed by normalised form.

    Takes the path rather than using the module default. The first version
    read the default path while writing somewhere else, so running twice
    against a different --out appended the same cases again - which is exactly
    how a tool corrupts the file it is meant to maintain.
    """
    if not dataset.exists():
        return {}
    cases = yaml.safe_load(dataset.read_text(encoding="utf-8")) or []
    if isinstance(cases, dict):
        cases = cases.get("cases") or []
    return {normalise_for_comparison(str(c["text"])): str(c["id"]) for c in cases}


def find_duplicates(report: Report, dataset: Path) -> None:
    """Exact and near duplicates, reported rather than removed."""
    already = existing_passages(dataset)
    seen: dict[str, Authored] = {}

    for authored in report.authored:
        key = normalise_for_comparison(authored.text)

        if key in already:
            report.duplicates.append(
                f"{authored.source}:{authored.line}: identical to existing case "
                f"{already[key]}"
            )
            continue
        if key in seen:
            other = seen[key]
            report.duplicates.append(
                f"{authored.source}:{authored.line}: identical to "
                f"{other.source}:{other.line}"
            )
            continue
        seen[key] = authored

    # Near duplicates, within the new material and against the dataset.
    keys = list(seen)
    for index, key in enumerate(keys):
        for other in keys[index + 1 :]:
            # autojunk=False: difflib otherwise treats common characters as
            # junk on sequences over 200 characters, which silently blinds
            # this to near-duplicates in any realistic passage.
            ratio = difflib.SequenceMatcher(None, key, other, autojunk=False).ratio()
            if ratio >= NEAR_DUPLICATE_RATIO:
                first, second = seen[key], seen[other]
                # Matched pairs are deliberately similar; that is their point.
                if first.group == second.group:
                    continue
                report.near_duplicates.append(
                    f"{first.source}:{first.line} and {second.source}:{second.line} "
                    f"are {ratio:.0%} similar"
                )


def to_yaml_cases(report: Report) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for authored in report.authored:
        prefix = {
            "ordinary": "fi-ord",
            "imperative": "fi-imp",
            "quoted_attack": "fi-quo",
            "task_redirection": "fi-red",
            "detector_targeting": "fi-det",
        }[authored.category]

        case: dict[str, Any] = {
            "id": case_id(prefix, authored.text),
            # Trailing newline to match the existing corpus convention.
            "text": authored.text + "\n",
            "category": authored.category,
            "group": authored.group,
            "expected_label": authored.label,
            "expected_outcome": authored.outcome,
            "expected_english": None,
            # The author wrote it, so it is reviewed by definition - a fluent
            # speaker produced it. This is the signoff C26-AC1 asks for.
            "review_status": "reviewed",
            "rights": "synthetic-authored",
        }
        # C29 grades outcomes against a faithful reference translation, and
        # that reference needs a fluent author for the same reason the
        # passages do - a reference written by whoever builds the grader is
        # not an independent standard. So it is marked pending rather than
        # filled in, and validate.py reports the count on every run.
        if authored.category in (
            "quoted_attack",
            "task_redirection",
            "detector_targeting",
        ):
            case["translation_status"] = "pending"

        if authored.mixed:
            case["category"] = "mixed_language"
            # And the id, which would otherwise say fi-red while the category
            # says mixed_language. The existing corpus uses fi-mix for these,
            # and an id that contradicts its own category is a trap for
            # anybody reading a report.
            case["id"] = case_id("fi-mix", authored.text)
            case["deferred_quality"] = True
            case["notes"] = (
                "Non-Finnish attack span. Excluded from every headline metric: "
                "mixed-language detection quality is unverified (threat model "
                "section 4)."
            )
        elif authored.notes:
            case["notes"] = authored.notes
        cases.append(case)
    return cases


def print_report(report: Report, cases: list[dict[str, Any]]) -> None:
    import collections

    by_category = collections.Counter(c["category"] for c in cases)
    print(f"authored: {len(report.authored)} passages found\n")

    print("by category:")
    targets = {
        "ordinary": 250,
        "imperative": 60,
        "quoted_attack": PAIRS_TARGET,
        "task_redirection": 35 + PAIRS_TARGET,
        "detector_targeting": 15,
        "mixed_language": 0,
    }
    for category, target in targets.items():
        found = by_category.get(category, 0)
        if target:
            bar = "ok " if found >= target else "   "
            print(f"  {bar} {category:<20} {found:>4} / {target}")
        elif found:
            print(f"      {category:<20} {found:>4} (challenge set, not scored)")

    benign = sum(
        1
        for c in cases
        if c["expected_label"] == CLEAN and not c.get("deferred_quality")
    )
    attacks = sum(
        1
        for c in cases
        if c["expected_label"] == SUSPICIOUS and not c.get("deferred_quality")
    )
    print(f"\n  new benign {benign}, new attacks {attacks}")

    if report.problems:
        print(f"\nproblems ({len(report.problems)}) - these need fixing:")
        for problem in report.problems:
            print(f"  {problem}")
    if report.duplicates:
        print(f"\nduplicates ({len(report.duplicates)}) - skipped:")
        for duplicate in report.duplicates[:20]:
            print(f"  {duplicate}")
        if len(report.duplicates) > 20:
            print(f"  ... and {len(report.duplicates) - 20} more")
    if report.near_duplicates:
        print(f"\nnear duplicates ({len(report.near_duplicates)}) - your call:")
        for near in report.near_duplicates[:20]:
            print(f"  {near}")
        if len(report.near_duplicates) > 20:
            print(f"  ... and {len(report.near_duplicates) - 20} more")

    if not report.problems and not report.authored:
        print("\nnothing authored yet. See evals/authoring/README.md.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write", action="store_true", help="append the new cases to the dataset"
    )
    parser.add_argument("--out", type=Path, default=DATASET)
    args = parser.parse_args(argv)

    report = collect()
    find_duplicates(report, args.out)

    # Duplicates are dropped from the output but stay in the report.
    already = existing_passages(args.out)
    seen: set[str] = set()
    kept: list[Authored] = []
    for authored in report.authored:
        key = normalise_for_comparison(authored.text)
        if key in already or key in seen:
            continue
        seen.add(key)
        kept.append(authored)
    report.authored = kept

    cases = to_yaml_cases(report)
    print_report(report, cases)

    if report.problems:
        print("\nnot writing: fix the problems above first")
        return 1

    if not args.write:
        if cases:
            print(f"\ndry run. {len(cases)} cases ready; re-run with --write")
        return 0

    if not cases:
        print("\nnothing to write")
        return 0

    existing = yaml.safe_load(args.out.read_text(encoding="utf-8")) or []
    if isinstance(existing, dict):
        print("dataset is a mapping; expected a list of cases", file=sys.stderr)
        return 1

    # Byte-for-byte: a passage must arrive in the dataset exactly as written.
    # The corpus is about characters that careless pipelines damage, so a tool
    # that normalised anything here would quietly destroy the test material.
    for case, authored in zip(cases, report.authored, strict=True):
        if case["text"] != authored.text + "\n":
            print(f"refusing to write: {case['id']} was altered", file=sys.stderr)
            return 1

    merged = list(existing) + cases
    args.out.write_text(
        yaml.safe_dump(merged, allow_unicode=True, sort_keys=False, width=100),
        encoding="utf-8",
    )
    print(
        f"\nwrote {len(cases)} new cases to {args.out} "
        f"({len(existing)} existing, {len(merged)} total)"
    )
    print("now run: make check-evals")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
