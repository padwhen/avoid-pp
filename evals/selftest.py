"""Assert the C06 runner's arithmetic against a hand-calculated fixture.

`evals/fixtures/toy-10.yaml` fixes every detector output, so the confusion
counts are a property of the file and are verifiable by reading it. If the
scoring logic drifts, these assertions fail with the specific number that
moved.

Also pins the two behaviours that exist to stop a detector flattering itself:

  * abstaining on everything must NOT look like success;
  * deferred-quality cases must never reach any headline metric, whether they
    would have helped or hurt.

Run with `make check-evals-runner`.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from runner import ADAPTERS, build_report, load_cases, score  # noqa: E402

TOY = ROOT / "fixtures" / "toy-10.yaml"

# Hand-calculated from toy-10.yaml:
#   attacks scored (4): 2 caught, 1 missed, 1 abstention
#   benign  scored (4): 2 passed, 1 false alarm, 1 operational error
EXPECTED_COUNTS = {
    "true_positive": 2,
    "false_negative": 1,
    "false_positive": 1,
    "true_negative": 2,
    "uncertain_on_attack": 1,
    "uncertain_on_benign": 0,
    "error_on_attack": 0,
    "error_on_benign": 1,
}
EXPECTED_CONDITIONAL = {
    "answered_cases": 6,
    "recall": 0.6667,
    "false_positive_rate": 0.3333,
    "precision": 0.6667,
}
EXPECTED_OPERATIONAL = {
    "attack_caught_rate": 0.5,
    "benign_passed_rate": 0.5,
    "uncertainty_rate": 0.125,
    "error_rate": 0.125,
}


def run(adapter_name: str):
    cases = load_cases(TOY)
    result, per_case = score(cases, ADAPTERS[adapter_name])
    return build_report(TOY, adapter_name, result["counts"], per_case, result["deferred"])


def check(label: str, actual, expected, failures: list[str]) -> None:
    if actual != expected:
        failures.append(f"{label}: expected {expected}, got {actual}")


def main() -> int:
    failures: list[str] = []

    # 1. Scripted outputs produce exactly the hand-calculated confusion counts.
    report = run("scripted")
    for key, expected in EXPECTED_COUNTS.items():
        check(f"scripted counts.{key}", report["counts"][key], expected, failures)
    for key, expected in EXPECTED_CONDITIONAL.items():
        check(
            f"scripted conditional.{key}",
            report["metrics"]["conditional"][key],
            expected,
            failures,
        )
    for key, expected in EXPECTED_OPERATIONAL.items():
        check(
            f"scripted operational.{key}",
            report["metrics"]["operational"][key],
            expected,
            failures,
        )

    # 2. C06-AC3: deferred cases are reported apart and never scored.
    check("scripted deferred count", report["deferred_quality"]["count"], 2, failures)
    check("scripted scored_cases", report["metrics"]["scored_cases"], 8, failures)
    scored_ids = {row["id"] for row in report["per_case"]}
    leaked = {"toy-mix-001", "toy-mix-002"} & scored_ids
    if leaked:
        failures.append(f"deferred cases leaked into per_case: {sorted(leaked)}")

    # The fixture contains one deferred case the detector got RIGHT and one it
    # got WRONG, so a leak in either direction would move a headline number.
    oracle_scored = run("oracle")["metrics"]["scored_cases"]
    check("oracle scored_cases (deferred still excluded)", oracle_scored, 8, failures)

    # 3. Abstaining on everything must not look like success.
    abstain = run("always_uncertain")
    cond = abstain["metrics"]["conditional"]
    oper = abstain["metrics"]["operational"]
    check("always_uncertain answered_cases", cond["answered_cases"], 0, failures)
    check("always_uncertain recall (undefined)", cond["recall"], None, failures)
    check("always_uncertain attack_caught_rate", oper["attack_caught_rate"], 0.0, failures)
    check("always_uncertain uncertainty_rate", oper["uncertainty_rate"], 1.0, failures)

    # 4. Catching nothing must read as zero recall, not as missing data.
    silent = run("always_clean")["metrics"]
    check("always_clean recall", silent["conditional"]["recall"], 0.0, failures)
    check(
        "always_clean attack_caught_rate",
        silent["operational"]["attack_caught_rate"],
        0.0,
        failures,
    )

    # 5. Blocking everything must show a perfect recall and a ruinous FPR.
    paranoid = run("always_suspicious")["metrics"]["conditional"]
    check("always_suspicious recall", paranoid["recall"], 1.0, failures)
    check("always_suspicious fpr", paranoid["false_positive_rate"], 1.0, failures)

    # 6. The report carries what C06-AC2 requires for reproducibility.
    for field in ("sha256", "path", "scored_cases", "deferred_quality_cases"):
        if field not in report["dataset"]:
            failures.append(f"report dataset block missing '{field}'")
    for field in ("identity", "prompt_version", "config_version"):
        if field not in report["detector"]:
            failures.append(f"report detector block missing '{field}'")
    if len(report["dataset"]["sha256"]) != 64:
        failures.append("dataset sha256 is not a full digest")

    if failures:
        print(f"runner selftest: {len(failures)} failure(s)", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print("runner selftest: hand-calculated counts match; deferred excluded;")
    print("                 abstaining and silence both score as failures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
