"""Pin the inputs a published report is a claim about.

A whole-file digest answers "did any byte change", which is not the question.
"Is this measurement still about the current dataset?" depends only on what
the detector saw and the labels it was scored against.

So the scored-content digest covers `id`, `text`, `expected_label`,
`category` and `deferred_quality`, and nothing else. Annotation fields,
reference translations and outcome labels are excluded on purpose: filling one
in must not invalidate a detection result. `group` is excluded because split
membership is pinned harder elsewhere - the manifest lists every case id per
split, so a moved case changes that digest instead.

Split digests matter as much as the corpus digest. The gate report's numbers
are about the development split; adding sixty cases to the challenge set at
C37 changed the corpus digest and changed neither split. The corpus digest
still moves on any content change, which is how a report notices it describes
an older corpus.

`verify_scored_cases` replays every per-case record in the cited reports
against the corpus: each case still exists and still carries the label it was
scored against. That is the check that supports the published numbers.

Run by `make check-gate-report`, so the claim either holds or the build fails.
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


def assigned_split(case: dict[str, Any]) -> str:
    """Which split a case belongs to, by the same rule splits.py uses."""
    import splits

    if case.get("deferred_quality") or case.get("category") == "mixed_language":
        return splits.CHALLENGE
    return splits.split_for_group(splits.group_of(case))


def split_digest(name: str, cases: list[dict[str, Any]]) -> str:
    """SHA-256 over one split's sorted case ids."""
    members = sorted(str(c["id"]) for c in cases if assigned_split(c) == name)
    return hashlib.sha256("\n".join(members).encode("utf-8")).hexdigest()


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

    # The split memberships the published numbers are actually about.
    #
    # A case id list, hashed. If a case moved between splits - or a new case
    # landed in one - a figure computed from that split is no longer a claim
    # about the cases it names, and no amount of corpus-level digesting
    # would say so.
    for name, expected_split in manifest.get("splits", {}).items():
        actual = split_digest(name, cases)
        if actual != expected_split["id_sha256"]:
            problems.append(
                f"split {name}: membership is {actual[:16]}, "
                f"{manifest['report']} is a claim about "
                f"{expected_split['id_sha256'][:16]}. Cases have moved into "
                "or out of it, so the published figures describe a different "
                "set than the one that exists."
            )
        if (
            len([c for c in cases if assigned_split(c) == name])
            != expected_split["cases"]
        ):
            problems.append(f"split {name}: case count has changed")

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
    pinned = ", ".join(sorted(manifest.get("splits", {})))
    print(
        "gate report provenance: "
        f"{len(cases)} cases, scored content {actual_content[:12]};\n"
        f"                       split membership unchanged ({pinned});\n"
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
