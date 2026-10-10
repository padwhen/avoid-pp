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
    return build_report(
        TOY, f"fake:{adapter_name}", result["counts"], per_case, result["deferred"]
    )


def check(label: str, actual, expected, failures: list[str]) -> None:
    if actual != expected:
        failures.append(f"{label}: expected {expected}, got {actual}")


# ---------------------------------------------------------------------------
# C25: intervals, slices, gates, latency and cost, all hand-checked.
# ---------------------------------------------------------------------------

from metrics import (  # noqa: E402
    clopper_pearson,
    cost_record,
    gate_verdict,
    percentiles,
    smallest_corpus_for,
)

# Published Clopper-Pearson 95% intervals. These are not derived from this
# implementation - they are the textbook values, so the arithmetic is checked
# against something external rather than against itself.
PUBLISHED_INTERVALS = [
    # successes, trials, lower, upper
    (0, 10, 0.0000, 0.3085),
    (0, 20, 0.0000, 0.1684),
    (0, 45, 0.0000, 0.0787),
    (1, 100, 0.0003, 0.0545),
    (5, 10, 0.1871, 0.8129),
    (10, 10, 0.6915, 1.0000),
    (23, 23, 0.8518, 1.0000),
    (2, 3, 0.0943, 0.9916),
]


def check_intervals(failures: list[str]) -> None:
    for successes, trials, want_lower, want_upper in PUBLISHED_INTERVALS:
        interval = clopper_pearson(successes, trials)
        if abs(interval.lower - want_lower) > 0.0005:
            failures.append(
                f"clopper_pearson({successes},{trials}).lower = {interval.lower:.4f}, "
                f"want {want_lower:.4f}"
            )
        if abs(interval.upper - want_upper) > 0.0005:
            failures.append(
                f"clopper_pearson({successes},{trials}).upper = {interval.upper:.4f}, "
                f"want {want_upper:.4f}"
            )

    # No data is not a rate of zero, and must not render as one.
    empty = clopper_pearson(0, 0)
    if empty.point is not None or empty.lower is not None:
        failures.append("clopper_pearson(0,0) reported a rate where there is no data")

    # The boundaries are exact, not approximated.
    if clopper_pearson(0, 7).lower != 0.0:
        failures.append("the lower bound at zero successes is not exactly 0")
    if clopper_pearson(7, 7).upper != 1.0:
        failures.append("the upper bound at all successes is not exactly 1")

    # Monotonicity: more evidence must never widen the interval.
    previous = None
    for trials in (10, 50, 100, 500):
        width = clopper_pearson(trials, trials).lower
        if previous is not None and width < previous:
            failures.append(
                f"a perfect run of {trials} gives a weaker bound than a smaller one"
            )
        previous = width


def check_gates(failures: list[str]) -> None:
    """The gates must be undetermined at the seed corpus size.

    This is the assertion that matters most in this file. A perfect run on 23
    attack cases and 45 benign ones cannot demonstrate recall >= 90% or a
    false-positive rate <= 1%, and a report that said otherwise would make an
    unmeasurable gate look met.
    """
    recall = gate_verdict("recall", clopper_pearson(23, 23))
    if recall["verdict"] != "undetermined":
        failures.append(
            f"a perfect 23/23 recall reported {recall['verdict']}, want undetermined"
        )

    fpr = gate_verdict("false_positive_rate", clopper_pearson(0, 45))
    if fpr["verdict"] != "undetermined":
        failures.append(
            f"a perfect 0/45 false-positive rate reported {fpr['verdict']}, "
            "want undetermined"
        )

    # Hand-checked corpus sizes. 300 benign cases is NOT enough for a 1% claim
    # even with zero false positives, which corrects an earlier estimate.
    needed_recall = smallest_corpus_for("recall")
    if needed_recall != 36:
        failures.append(f"recall gate needs {needed_recall} cases, hand-checked 36")
    needed_fpr = smallest_corpus_for("false_positive_rate")
    if needed_fpr != 368:
        failures.append(f"fpr gate needs {needed_fpr} cases, hand-checked 368")
    if clopper_pearson(0, 300).upper <= 0.01:
        failures.append("300 perfect benign cases should NOT satisfy a 1% gate")

    # A gate that genuinely is met must say so, or the verdict is just a
    # pessimism machine.
    met = gate_verdict("recall", clopper_pearson(100, 100))
    if met["verdict"] != "met":
        failures.append(f"a perfect 100/100 recall reported {met['verdict']}, want met")

    # And one that is genuinely failed.
    not_met = gate_verdict("recall", clopper_pearson(10, 100))
    if not_met["verdict"] != "not_met":
        failures.append(
            f"a 10% recall over 100 cases reported {not_met['verdict']}, want not_met"
        )

    no_data = gate_verdict("recall", clopper_pearson(0, 0))
    if no_data["verdict"] != "no_data":
        failures.append(f"an empty corpus reported {no_data['verdict']}, want no_data")


def check_percentiles(failures: list[str]) -> None:
    # Nearest-rank over a known sample: 1..10, so every percentile is one of
    # the observations and can be read off by hand.
    result = percentiles([float(n) for n in range(1, 11)])
    expected = {
        "samples": 10,
        "min_ms": 1.0,
        "p50_ms": 5.0,
        "p90_ms": 9.0,
        "p95_ms": 10.0,
        "p99_ms": 10.0,
        "max_ms": 10.0,
        "mean_ms": 5.5,
    }
    for key, want in expected.items():
        if result[key] != want:
            failures.append(f"percentiles[{key}] = {result[key]}, want {want}")

    # A small sample must carry the caveat rather than imply precision.
    if "note" not in result:
        failures.append("a 10-sample percentile set carries no small-sample note")
    if "note" in percentiles([1.0] * 200):
        failures.append("a 200-sample set should not carry the small-sample note")

    # Order must not matter.
    if percentiles([3.0, 1.0, 2.0])["p50_ms"] != percentiles([1.0, 2.0, 3.0])["p50_ms"]:
        failures.append("percentiles depend on input order")

    if percentiles([])["samples"] != 0:
        failures.append("an empty sample did not report zero samples")


PRICES = {"test-model": {"input": 5.00, "output": 25.00, "as_of": "2026-06-24"}}


def check_cost(failures: list[str]) -> None:
    # Hand-calculated: 1,000,000 input at $5/Mtok plus 100,000 output at
    # $25/Mtok is $5.00 + $2.50 = $7.50.
    full = cost_record("test-model", [(1_000_000, 100_000)], PRICES)
    if full["usd"] != 7.50:
        failures.append(f"cost usd = {full['usd']}, hand-calculated 7.50")
    if not isinstance(full.get("price_assumption"), dict):
        failures.append("a priced report carries no dated price assumption")
    elif full["price_assumption"]["as_of"] != "2026-06-24":
        failures.append("the price assumption carries no date")
    if full.get("usd_is_a_floor"):
        failures.append("a fully measured run was marked as a floor")

    # C25-AC3: missing usage is not free.
    partial = cost_record(
        "test-model", [(1_000_000, 100_000), (None, None), (None, None)], PRICES
    )
    if partial["requests"] != 3:
        failures.append(f"requests = {partial['requests']}, want 3")
    if partial["requests_without_usage"] != 2:
        failures.append(
            f"requests_without_usage = {partial['requests_without_usage']}, want 2"
        )
    if partial["usd"] != 7.50:
        failures.append("the measured cost changed when unmeasured calls were added")
    if not partial.get("usd_is_a_floor"):
        failures.append(
            "a run with unreported usage was not marked as a floor, so the "
            "figure reads as a measurement"
        )
    if "unmeasured_note" not in partial:
        failures.append("unreported usage was not explained")

    # An unknown model must not be costed at zero.
    unknown = cost_record("mystery-model", [(1000, 100)], PRICES)
    if unknown["usd"] is not None:
        failures.append(
            f"an unpriced model was costed at {unknown['usd']}; an unknown "
            "price is not a price of zero"
        )
    if unknown["input_tokens"] != 1000:
        failures.append("token counts were dropped along with the price")

    # No calls at all is zero requests, not zero cost with a claim attached.
    empty = cost_record("test-model", [], PRICES)
    if empty["requests"] != 0 or empty["input_tokens"] != 0:
        failures.append("an empty usage list was mis-reported")


def check_slices(failures: list[str]) -> None:
    report = run("scripted")
    slices = report["slices"]

    # Hand-checked from toy-10.yaml: every scored case has a category, and the
    # slice totals must add up to the scored total.
    sliced_total = sum(bucket["cases"] for bucket in slices.values())
    if sliced_total != report["metrics"]["scored_cases"]:
        failures.append(
            f"slices cover {sliced_total} cases but {report['metrics']['scored_cases']} "
            "were scored"
        )

    # Every slice's outcomes must account for its cases.
    for category, bucket in slices.items():
        total = (
            bucket["correct"] + bucket["wrong"] + bucket["uncertain"] + bucket["error"]
        )
        if total != bucket["cases"]:
            failures.append(
                f"slice {category}: {total} outcomes for {bucket['cases']} cases"
            )

    # A deferred case must not appear in any slice.
    deferred_ids = {case["id"] for case in report["deferred_quality"]["cases"]}
    if deferred_ids:
        sliced_ids = {record["id"] for record in report["per_case"]}
        if deferred_ids & sliced_ids:
            failures.append("a deferred case reached the slices")


def check_report_fingerprint(failures: list[str]) -> None:
    """The same inputs must produce the same digest, and different ones must not."""
    first = run("scripted")["config_sha256"]
    second = run("scripted")["config_sha256"]
    if first != second:
        failures.append("the config digest is not stable across identical runs")

    cases = load_cases(TOY)
    result, per_case = score(cases, ADAPTERS["scripted"])
    changed = build_report(
        TOY,
        "fake:scripted",
        result["counts"],
        per_case,
        result["deferred"],
        model="a-different-model",
    )["config_sha256"]
    if changed == first:
        failures.append("changing the model did not change the config digest")


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
    check(
        "always_uncertain attack_caught_rate", oper["attack_caught_rate"], 0.0, failures
    )
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

    # 4. C25: intervals, gates, slices, latency and cost.
    check_intervals(failures)
    check_gates(failures)
    check_percentiles(failures)
    check_cost(failures)
    check_slices(failures)
    check_report_fingerprint(failures)

    if failures:
        print(f"runner selftest: {len(failures)} failure(s)", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print("runner selftest: hand-calculated counts match; deferred excluded;")
    print("                 abstaining and silence both score as failures;")
    print("                 Clopper-Pearson matches published intervals;")
    print("                 both release gates read UNDETERMINED at seed size;")
    print("                 unreported token usage is not costed as free")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
