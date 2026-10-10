"""Re-derive outcome classifications from a saved report. No provider calls.

The per-case records hold the outputs, so a change to the classifier does not
require paying for the evaluation again - the same reasoning as
evals/reanalyse.py, and the same reason prices carry a date.

    python evals/outcome_reanalyse.py evals/reports/outcomes-development-sample90.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import splits as split_module  # noqa: E402
from outcome_eval import summarise  # noqa: E402
from outcomes import classify, propose_grade  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    report = json.loads(args.report.read_text(encoding="utf-8"))
    cases = {
        str(c["id"]): c
        for c in split_module.load_cases(ROOT / "datasets" / "seed-fi.yaml")
    }

    for record in report["per_case"]:
        case = cases.get(str(record["id"]))
        if case is None:
            continue
        reference = case.get("expected_english")
        for side in ("baseline", "protected"):
            proposal = propose_grade(record[f"{side}_output"], reference)
            record[f"{side}_proposed_grade"] = proposal.grade.value
            record[f"{side}_confidence"] = proposal.confidence
            record[f"{side}_reasons"] = proposal.reasons
        record["baseline_outcome_proposed"] = classify(
            case=case,
            action="allow",
            label=None,
            produced=record["baseline_output"],
            reference=reference,
            failed=record["baseline_failed"],
        ).value
        record["protected_outcome_proposed"] = classify(
            case=case,
            action=record["action"],
            label=record["label"],
            produced=record["protected_output"],
            reference=reference,
            failed=record["protected_failed"],
        ).value

    report["summary"] = summarise(report["per_case"])
    report["reanalysis"] = {
        "source_report": str(args.report),
        "note": (
            "Outcomes re-derived from the saved outputs. No provider call was made."
        ),
    }

    destination = args.out or args.report
    destination.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    summary = report["summary"]
    print(f"re-derived from {len(report['per_case'])} saved cases\n")
    print("baseline (translator alone):")
    for outcome, count in summary["baseline"].items():
        print(f"  {outcome:<24} {count:>4}")
    print("\nprotected (guard in front):")
    for outcome, count in summary["protected"].items():
        print(f"  {outcome:<24} {count:>4}")
    if "false_block_rate" in summary:
        rate = summary["false_block_rate"]
        print(
            f"\nfalse block rate: {rate['point']:.4f} "
            f"[{rate['lower']:.4f}, {rate['upper']:.4f}] over {rate['trials']} benign"
        )
    print(f"\nwritten to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
