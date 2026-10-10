"""Pin the inputs a published report is a claim about.

## The problem this exists for

The C26 measurement records the dataset it ran on as
``50cfb7ce...``. The frozen split manifest records ``3484a8af...``. The file
on disk today is ``ed1439b6...``. Three digests, one dataset, and at first
glance a report whose provenance has evaporated.

Nothing is wrong. Between the measurement and today, seven cases moved from
``pending_review`` to ``reviewed`` and 161 reference translations were filled
in. Not one character of any passage, label, or category changed - the diff
confirms it. But a whole-file digest cannot say that, so it says the only
thing it can: the bytes differ.

That is the wrong granularity for the question a report needs answered. "Is
this measurement still a claim about the current dataset?" does not depend on
annotation fields. It depends on the inputs the detector saw and the labels it
was scored against, and on nothing else.

## What a content digest covers

``id``, ``text``, ``expected_label``, ``category``, ``deferred_quality``. That
is the whole of what a detection metric reads.

Deliberately excluded:

  * ``expected_english``, ``expected_outcome`` - these feed outcome grading
    (C29), not detection scoring, and filling one in must not invalidate a
    detection result;
  * ``review_status``, ``rights``, ``notes`` - annotation;
  * ``group`` - it decides split membership, and membership is pinned harder
    elsewhere: the frozen manifest lists every case id per split, so a moved
    case changes that manifest's digest rather than hiding here.

So a content digest that still matches means the measurement describes the
same passages, scored against the same labels, as the dataset holds now. A
content digest that has changed means a published number is about text that no
longer exists, and the report has to be re-derived.

## The digest that cannot be resolved at all

The C26 report's recorded dataset digest, ``50cfb7ce...``, matches no
committed state of the file. The reason is mundane and worth writing down: the
run found two passages the provider refuses to process, and those findings
were written back into the corpus as ``notes`` before the commit. So the
digest describes a working tree that existed for about twenty minutes and was
never saved.

A whole-file digest is therefore not only the wrong granularity, it is a
provenance claim that can stop being checkable through ordinary, correct work.

What *is* checkable is stronger and more to the point. Every report in this
project records ``id``, ``category``, ``expected_label`` and
``deferred_quality`` per scored case, so each one can be replayed against the
corpus as it stands: every case it scored still exists, and still carries the
label it was scored against. :func:`verify_scored_cases` does that for all 662
case records across the cited reports, and it is the check that actually
supports the published numbers.

The remedy for new runs is in this module rather than in prose: record the
scored-content digest, which does not move when an annotation does.

## Why this is a check and not a note

A report that says "the corpus has not changed in any way that matters" is
making a claim that decays silently. ``make check-gate-report`` recomputes it
on every commit, so the claim either holds or the build fails.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET = REPO_ROOT / "evals" / "datasets" / "seed-fi.yaml"
MANIFEST = REPO_ROOT / "evals" / "manifests" / "gate-report.json"

# The fields a detection measurement reads. Adding one here changes every
# recorded digest, which is the correct consequence and should be deliberate.
SCORED_FIELDS = ("id", "text", "expected_label", "category", "deferred_quality")


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def content_digest(cases: list[dict[str, Any]]) -> str:
    """Digest the scored content of a corpus, and nothing else.

    Sorted by id and serialised canonically, so neither reordering the file nor
    reformatting it changes the result. Only the content does.
    """
    reduced = [
        {field: case.get(field) for field in SCORED_FIELDS}
        for case in sorted(cases, key=lambda case: str(case["id"]))
    ]
    canonical = json.dumps(
        reduced, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_cases(path: Path) -> list[dict[str, Any]]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, list):
        raise SystemExit(f"{path}: expected a list of cases")
    return loaded


def verify_scored_cases(
    report: dict[str, Any], cases: dict[str, dict[str, Any]], label: str
) -> list[str]:
    """Replay a report's per-case records against the corpus as it stands.

    Three questions, none of which a file digest can answer:

      * does every case this report scored still exist?
      * does it still carry the label it was scored against?
      * is it still in the category the report's slice table attributed it to?

    A no to any of them means a published number is about something the corpus
    no longer contains, which is the thing worth failing a build over. A
    report whose cases all still check out is one whose numbers still mean
    what they said, whatever happened to the file's bytes.
    """
    problems: list[str] = []
    for record in report.get("per_case", []):
        case_id = str(record.get("id"))
        case = cases.get(case_id)
        if case is None:
            problems.append(
                f"{label}: scored {case_id}, which is no longer in the corpus"
            )
            continue
        for field in ("expected_label", "category"):
            if field in record and record[field] != case.get(field):
                problems.append(
                    f"{label}: scored {case_id} as {field}={record[field]!r}; "
                    f"the corpus now says {case.get(field)!r}"
                )
        if "deferred_quality" in record:
            recorded = bool(record["deferred_quality"])
            if recorded != bool(case.get("deferred_quality", False)):
                problems.append(
                    f"{label}: scored {case_id} with deferred_quality="
                    f"{recorded}; the corpus now disagrees"
                )
    return problems


def check(manifest_path: Path) -> int:
    """Verify every input the report is a claim about. Returns an exit code."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    problems: list[str] = []

    dataset_path = REPO_ROOT / manifest["dataset"]["path"]
    cases = load_cases(dataset_path)

    actual_content = content_digest(cases)
    expected_content = manifest["dataset"]["scored_content_sha256"]
    if actual_content != expected_content:
        problems.append(
            f"{manifest['dataset']['path']}: scored content is {actual_content}, "
            f"and {manifest['report']} is a claim about {expected_content}. "
            "A passage, label or category has changed, so the published "
            "numbers describe text the corpus no longer holds."
        )

    if len(cases) != manifest["dataset"]["cases"]:
        problems.append(
            f"{manifest['dataset']['path']}: {len(cases)} cases, "
            f"manifest records {manifest['dataset']['cases']}"
        )

    # Every input report, and the frozen split manifest. These are immutable
    # snapshots: a report that changes after being published is not a
    # correction, it is a different report.
    for entry in manifest["inputs"]:
        path = REPO_ROOT / entry["path"]
        if not path.exists():
            problems.append(f"{entry['path']}: missing, and the report cites it")
            continue
        actual = file_digest(path)
        if actual != entry["sha256"]:
            problems.append(
                f"{entry['path']}: {actual}, manifest records {entry['sha256']}"
            )

    by_id = {str(case["id"]): case for case in cases}
    replayed = 0
    for entry in manifest["inputs"]:
        path = REPO_ROOT / entry["path"]
        if not path.exists() or not entry.get("scored_cases"):
            continue
        report = json.loads(path.read_text(encoding="utf-8"))
        records = report.get("per_case", [])
        if len(records) != entry["scored_cases"]:
            problems.append(
                f"{entry['path']}: {len(records)} per-case records, "
                f"manifest records {entry['scored_cases']}"
            )
        replayed += len(records)
        problems.extend(verify_scored_cases(report, by_id, entry["path"]))

    if problems:
        print(f"gate report provenance: {len(problems)} problem(s)", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    holdout = manifest["holdout"]["state"]
    print(
        "gate report provenance: "
        f"{len(cases)} cases, scored content {actual_content[:12]};\n"
        f"                       {len(manifest['inputs'])} cited inputs unchanged;\n"
        f"                       {replayed} scored case records still match the corpus;\n"
        f"                       holdout {holdout}; "
        f"enforcement {manifest['decision']['enforcement']}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the gate report's recorded inputs against the tree",
    )
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    args = parser.parse_args()

    if args.check:
        return check(args.manifest)

    cases = load_cases(args.dataset)
    try:
        shown = args.dataset.resolve().relative_to(REPO_ROOT)
    except ValueError:
        # --dataset can point at a copy outside the tree, which is how an
        # older revision's content digest gets computed (git show into a temp
        # file). Reporting the absolute path is the honest answer there.
        shown = args.dataset
    print(f"dataset:               {shown}")
    print(f"cases:                 {len(cases)}")
    print(f"file sha256:           {file_digest(args.dataset)}")
    print(f"scored content sha256: {content_digest(cases)}")
    print(f"scored fields:         {', '.join(SCORED_FIELDS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
