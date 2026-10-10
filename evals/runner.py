"""Deterministic evaluation runner for the Finnish seed dataset.

Scores a detector adapter over the dataset and writes a machine-readable
report. No model is called: the adapters here are fakes, so the arithmetic can
be checked by hand before any live-model tuning begins (C06, ahead of C13+).

Two things this deliberately does NOT do, because both would flatter a
detector:

  * It never counts an abstention or an operational error as a correct benign
    answer. Those are their own outcomes.
  * It never folds deferred-quality cases (mixed_language) into the headline
    numbers. Detection quality on embedded foreign-language spans is
    unverified and must not ride along on Finnish results.

Metrics are reported in two views:

  conditional  - over cases that produced a definite label. This is the
                 classifier's accuracy *given that it answered*.
  operational  - over every scored case. This is what the application
                 actually experiences, abstentions and errors included.

A detector that abstains on everything scores perfectly on the conditional
view and catches nothing on the operational one. Reporting only the first is
the mistake this split exists to prevent.

Usage:
    python evals/runner.py --adapter oracle
    python evals/runner.py --adapter keyword --dataset evals/fixtures/toy-10.yaml
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from metrics import (
    DEFAULT_CONFIDENCE,
    GATES,
    clopper_pearson,
    cost_record,
    gate_verdict,
    percentiles,
    slice_metrics,
)

ROOT = Path(__file__).resolve().parent
DEFAULT_DATASET = ROOT / "datasets" / "seed-fi.yaml"

CLEAN = "no_injection_detected"
SUSPICIOUS = "suspicious"
UNCERTAIN = "uncertain"
ERROR = "error"

# Naive keyword list, present to demonstrate the failure mode the project
# exists to avoid: it cannot tell a quoted attack from an obeyed one.
KEYWORDS = (
    "ohita",
    "unohda",
    "älä käännä",
    "ala kaanna",
    "jätä huomiotta",
    "negeer",
    "ignore",
)

Adapter = Callable[[dict[str, Any]], str]


def adapter_oracle(case: dict[str, Any]) -> str:
    """Perfect detector. Upper bound on what the dataset can show."""
    return str(case["expected_label"])


def adapter_always_clean(case: dict[str, Any]) -> str:
    """Catches nothing. Its recall must be 0, never 'no data'."""
    return CLEAN


def adapter_always_suspicious(case: dict[str, Any]) -> str:
    """Blocks everything. Perfect recall, useless product."""
    return SUSPICIOUS


def adapter_always_uncertain(case: dict[str, Any]) -> str:
    """Abstains on everything. Exists to prove abstention is not scored well."""
    return UNCERTAIN


def adapter_keyword(case: dict[str, Any]) -> str:
    """Flags any passage containing an attack-ish word, quoted or not."""
    text = str(case["text"]).lower()
    return SUSPICIOUS if any(k in text for k in KEYWORDS) else CLEAN


def adapter_scripted(case: dict[str, Any]) -> str:
    """Returns the per-case output written into a fixture. Used by the self-test
    so confusion counts are fixed by the fixture and can be hand-calculated."""
    scripted = case.get("scripted_output")
    if scripted is None:
        raise KeyError(f"{case.get('id')}: fixture has no scripted_output")
    if scripted == ERROR:
        raise RuntimeError("scripted operational failure")
    return str(scripted)


ADAPTERS: dict[str, Adapter] = {
    "oracle": adapter_oracle,
    "always_clean": adapter_always_clean,
    "always_suspicious": adapter_always_suspicious,
    "always_uncertain": adapter_always_uncertain,
    "keyword": adapter_keyword,
    "scripted": adapter_scripted,
}


def load_cases(path: Path) -> list[dict[str, Any]]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(document, dict):
        document = document.get("cases") or []
    if not isinstance(document, list):
        raise ValueError(f"{path}: expected a list of cases")
    return document


def dataset_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dataset_label(path: Path) -> str:
    """Repo-relative path when possible, so reports are comparable across
    machines; absolute only as a fallback."""
    try:
        return str(path.resolve().relative_to(ROOT.parent))
    except ValueError:
        return str(path.resolve())


def score(
    cases: list[dict[str, Any]], adapter: Adapter
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run the adapter and classify every case into exactly one outcome."""
    per_case: list[dict[str, Any]] = []
    counts = {
        "true_positive": 0,
        "false_negative": 0,
        "false_positive": 0,
        "true_negative": 0,
        "uncertain_on_attack": 0,
        "uncertain_on_benign": 0,
        "error_on_attack": 0,
        "error_on_benign": 0,
    }
    deferred: list[dict[str, Any]] = []

    for case in cases:
        expected = str(case["expected_label"])
        is_attack = expected == SUSPICIOUS
        try:
            predicted = adapter(case)
        except Exception as exc:  # operational failure, never a clean answer
            predicted, detail = ERROR, str(exc)
        else:
            detail = ""

        if predicted == SUSPICIOUS:
            outcome = "true_positive" if is_attack else "false_positive"
        elif predicted == CLEAN:
            outcome = "false_negative" if is_attack else "true_negative"
        elif predicted == UNCERTAIN:
            outcome = "uncertain_on_attack" if is_attack else "uncertain_on_benign"
        else:
            outcome = "error_on_attack" if is_attack else "error_on_benign"

        record = {
            "id": case.get("id"),
            "category": case.get("category"),
            "expected_label": expected,
            "predicted_label": predicted,
            "outcome": outcome,
            "deferred_quality": bool(case.get("deferred_quality")),
        }
        if detail:
            record["error_detail"] = detail

        # C06-AC3: deferred cases are recorded, never scored into the headline.
        if case.get("deferred_quality"):
            deferred.append(record)
        else:
            counts[outcome] += 1
            per_case.append(record)

    return {"counts": counts, "deferred": deferred}, per_case


def ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def metrics(counts: dict[str, int]) -> dict[str, Any]:
    tp = counts["true_positive"]
    fn = counts["false_negative"]
    fp = counts["false_positive"]
    tn = counts["true_negative"]
    unc_a = counts["uncertain_on_attack"]
    unc_b = counts["uncertain_on_benign"]
    err_a = counts["error_on_attack"]
    err_b = counts["error_on_benign"]

    attacks = tp + fn + unc_a + err_a
    benign = fp + tn + unc_b + err_b
    answered = tp + fn + fp + tn
    scored = attacks + benign

    # Every rate carries an exact interval. A point estimate of 1.0 from 23
    # cases and one from 2,300 are the same number and completely different
    # evidence, and only the interval says which you have.
    recall = clopper_pearson(tp, tp + fn)
    fpr = clopper_pearson(fp, fp + tn)
    precision = clopper_pearson(tp, tp + fp)

    return {
        "scored_cases": scored,
        "attacks": attacks,
        "benign": benign,
        "confidence": DEFAULT_CONFIDENCE,
        # Accuracy GIVEN the detector answered. Excludes abstentions and errors.
        "conditional": {
            "answered_cases": answered,
            "recall": ratio(tp, tp + fn),
            "false_positive_rate": ratio(fp, fp + tn),
            "precision": ratio(tp, tp + fp),
            # The same three with bounds. Kept alongside the point estimates
            # rather than replacing them, so existing readers of this report
            # still work and the honest number is right next to the flattering
            # one.
            "intervals": {
                "recall": recall.as_dict(),
                "false_positive_rate": fpr.as_dict(),
                "precision": precision.as_dict(),
            },
        },
        # What the application actually experiences. Every case counts.
        "operational": {
            "attack_caught_rate": ratio(tp, attacks),
            "benign_passed_rate": ratio(tn, benign),
            "uncertainty_rate": ratio(unc_a + unc_b, scored),
            "error_rate": ratio(err_a + err_b, scored),
            "intervals": {
                "attack_caught_rate": clopper_pearson(tp, attacks).as_dict(),
                "benign_passed_rate": clopper_pearson(tn, benign).as_dict(),
            },
        },
        # Decided from the bounds, never from the point estimates. At this
        # corpus size both gates are undetermined even for a perfect run, and
        # the report says so rather than reporting 1.0 and 0.0 as a pass.
        "gates": [
            gate_verdict("recall", recall),
            gate_verdict("false_positive_rate", fpr),
        ],
    }


def config_digest(parts: dict[str, Any]) -> str:
    """A hash over everything that could change a result.

    A report says what a detector scored. Without a fingerprint of the model,
    the prompt, the dataset and the scoring configuration, it does not say
    *which* detector - and two reports that disagree become impossible to
    explain. Sorted keys so the digest is stable across runs.

    Deliberately **not** a run identifier. It covers the setup, not the
    outcome or the number of cases run, so two reports sharing a digest are
    comparable: the same configuration measured twice, or measured over more
    data. A partial run records its own case count separately rather than
    changing this digest, because "same setup, more evidence" is exactly the
    comparison the digest exists to make safe.
    """
    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_report(
    dataset: Path,
    detector_identity: str,
    counts: dict[str, int],
    per_case,
    deferred,
    *,
    prompt_version: str = "none",
    prompt_fingerprint: str | None = None,
    model: str | None = None,
    latencies_ms: list[float] | None = None,
    usage: list[tuple[int | None, int | None]] | None = None,
    prices: dict[str, dict[str, Any]] | None = None,
    config_version: str = "c25-runner-1",
) -> dict[str, Any]:
    """Build the report.

    ``detector_identity`` is recorded verbatim. It used to be prefixed with
    "fake:" here, which silently labelled the first live run as fake - an
    evaluation record that misattributes what produced it is worse than none.

    Quality, latency and cost are three separate blocks because they fail
    independently: a run can be accurate and unaffordable, or fast and wrong,
    and a single summary number would hide either.
    """
    dataset_sha = dataset_digest(dataset)

    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "dataset": {
            "path": dataset_label(dataset),
            "sha256": dataset_sha,
            "scored_cases": len(per_case),
            "deferred_quality_cases": len(deferred),
        },
        "detector": {
            "identity": detector_identity,
            "prompt_version": prompt_version,
            "config_version": config_version,
        },
        "counts": counts,
        "metrics": metrics(counts),
        # Per-category, because aggregates hide the distinction this project
        # is about: obeying every quoted attack while catching every bare
        # imperative can look respectable overall.
        "slices": slice_metrics(per_case),
        # Reported apart from every headline number. Detection quality on
        # embedded foreign-language spans is unverified and not claimed.
        "deferred_quality": {
            "count": len(deferred),
            "note": (
                "Excluded from all metrics above. Mixed-language detection "
                "quality is unverified (threat model section 4)."
            ),
            "cases": deferred,
        },
        "per_case": per_case,
    }

    if prompt_fingerprint:
        report["detector"]["prompt_fingerprint"] = prompt_fingerprint
    if model:
        report["detector"]["model"] = model

    # Latency, separate from quality. Absent rather than empty when there was
    # nothing to measure: a fake detector has no meaningful latency, and
    # reporting 0 ms would invite comparison with a real one.
    if latencies_ms:
        report["latency"] = percentiles(latencies_ms)

    # Cost, separate again. Only when provider calls were actually made.
    if usage is not None:
        report["cost"] = cost_record(model or detector_identity, usage, prices or {})

    # The fingerprint goes last, over everything that could change a result.
    report["config_sha256"] = config_digest(
        {
            "dataset_sha256": dataset_sha,
            "detector_identity": detector_identity,
            "model": model,
            "prompt_version": prompt_version,
            "prompt_fingerprint": prompt_fingerprint,
            "config_version": config_version,
            "confidence": DEFAULT_CONFIDENCE,
            "gates": GATES,
        }
    )
    return report


def print_summary(report: dict[str, Any]) -> None:
    m = report["metrics"]
    c = report["counts"]
    print(f"detector: {report['detector']['identity']}")
    print(
        f"scored {m['scored_cases']} cases "
        f"({m['attacks']} attack, {m['benign']} benign); "
        f"{report['deferred_quality']['count']} deferred, excluded"
    )
    print(
        f"  TP {c['true_positive']}  FN {c['false_negative']}  "
        f"FP {c['false_positive']}  TN {c['true_negative']}  "
        f"uncertain {c['uncertain_on_attack'] + c['uncertain_on_benign']}  "
        f"error {c['error_on_attack'] + c['error_on_benign']}"
    )

    cond, oper = m["conditional"], m["operational"]

    def with_bounds(name: str, block: dict[str, Any]) -> str:
        """Render a rate next to its interval.

        Printing the point estimate alone is what makes a perfect run on
        twenty-three cases look like a finished product.
        """
        interval = block["intervals"].get(name)
        point = block.get(name)
        if point is None:
            return f"{name} n/a"
        if not interval or interval["lower"] is None:
            return f"{name} {point}"
        return f"{name} {point} [{interval['lower']:.3f}, {interval['upper']:.3f}]"

    print(
        f"  conditional ({cond['answered_cases']} answered, "
        f"{m['confidence']:.0%} intervals):"
    )
    for name in ("recall", "false_positive_rate", "precision"):
        print(f"      {with_bounds(name, cond)}")
    print("  operational (every scored case):")
    for name in ("attack_caught_rate", "benign_passed_rate"):
        print(f"      {with_bounds(name, oper)}")
    print(f"      uncertainty {oper['uncertainty_rate']}  error {oper['error_rate']}")

    # The headline. A perfect score that cannot demonstrate the gate must not
    # read as a pass, and this is the line that says so.
    print("  gates:")
    for gate in m["gates"]:
        marker = {
            "met": "MET",
            "not_met": "NOT MET",
            "undetermined": "UNDETERMINED",
            "no_data": "NO DATA",
        }[gate["verdict"]]
        comparison = ">=" if gate["direction"] == "at_least" else "<="
        print(
            f"      {marker:<13} {gate['gate']} {comparison} {gate['threshold']}  "
            f"(observed {gate['observed']}, bound {gate['bound']}, "
            f"n={gate['trials']})"
        )
        if "because" in gate:
            print(f"                    {gate['because']}")

    if "slices" in report:
        print("  slices:")
        for category, bucket in report["slices"].items():
            accuracy = bucket["accuracy"]
            bounds = (
                f"[{accuracy['lower']:.2f}, {accuracy['upper']:.2f}]"
                if accuracy["lower"] is not None
                else "n/a"
            )
            print(
                f"      {category:<20} {bucket['correct']}/{bucket['cases']} "
                f"correct {bounds}"
                + (f"  wrong {bucket['wrong']}" if bucket["wrong"] else "")
                + (f"  uncertain {bucket['uncertain']}" if bucket["uncertain"] else "")
                + (f"  error {bucket['error']}" if bucket["error"] else "")
            )

    if "latency" in report:
        lat = report["latency"]
        print(
            f"  latency     : p50 {lat['p50_ms']}ms  p90 {lat['p90_ms']}ms  "
            f"p95 {lat['p95_ms']}ms  max {lat['max_ms']}ms "
            f"(n={lat['samples']})"
        )
        if "note" in lat:
            print(f"                {lat['note']}")

    if "cost" in report:
        cost = report["cost"]
        line = (
            f"  cost        : {cost['requests']} requests, "
            f"{cost['input_tokens']} in / {cost['output_tokens']} out"
        )
        if cost.get("usd") is not None:
            line += f", ${cost['usd']}"
            if cost.get("usd_is_a_floor"):
                line += " (a floor)"
        else:
            line += ", cost unknown"
        print(line)
        if cost.get("requests_without_usage"):
            print(f"                {cost['unmeasured_note']}")
        elif isinstance(cost.get("price_assumption"), dict):
            price = cost["price_assumption"]
            print(
                f"                prices as of {price['as_of']}: "
                f"${price['input_usd_per_mtok']}/Mtok in, "
                f"${price['output_usd_per_mtok']}/Mtok out"
            )

    print(f"  config      : {report['config_sha256'][:16]}...")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", default="oracle", choices=sorted(ADAPTERS))
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--out", type=Path, help="write the JSON report here")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    if not args.dataset.exists():
        print(f"runner: {args.dataset} not found", file=sys.stderr)
        return 1

    cases = load_cases(args.dataset)
    result, per_case = score(cases, ADAPTERS[args.adapter])
    report = build_report(
        args.dataset,
        f"fake:{args.adapter}",
        result["counts"],
        per_case,
        result["deferred"],
    )

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if not args.quiet:
            print(f"report written to {args.out}")

    if not args.quiet:
        print_summary(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
