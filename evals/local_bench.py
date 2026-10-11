"""Can a local classifier replace, or screen, the hosted detector?

Free of provider cost and not free of machine time: it downloads pinned
model artifacts and runs them on CPU.

    make local-bench            # refuses, prints what it would download
    make local-bench CONFIRM=yes

## What this measures and what it refuses to inherit

C39-AC1: "English benchmark scores are not substituted." Every model below
reports strong numbers on English prompt-injection benchmarks, and **none of
them declares Finnish support**. Those published scores say nothing about
this corpus, so the only figures here are measured on Finnish.

The comparison is against the C26 hosted run on the same split - same
cases, same labels - so the question has an answer rather than a vibe.

## Why no cascade is built

C39-AC3: "a low local score cannot create an untested bypass." The obvious
use of a cheap local model is a screen: run it first, skip the paid call
when it says clean. That is a bypass for every passage it wrongly calls
clean, and on an unmeasured language that is an unknown fraction of them.

So this measures, and `docs/c39-local-classifiers.md` decides. The adapter
is not reachable from `build_detector`, and a test says so.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import resource
import statistics
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "detector" / "src"))

import splits  # noqa: E402
from metrics import Interval, clopper_pearson, gate_verdict  # noqa: E402

from translation_guard.detectors.local import CANDIDATES, LocalDetector  # noqa: E402
from translation_guard.schemas import Content, SourceType  # noqa: E402

REPORTS = ROOT / "reports"
HOSTED_REPORT = REPORTS / "milestones" / "c26-live-development.json"
CONFIDENCE = 0.95

SUSPICIOUS = "suspicious"
CLEAN = "no_injection_detected"


def peak_rss_mb() -> float:
    """Peak resident memory of this process, in MiB.

    ru_maxrss is bytes on macOS and kilobytes on Linux, which is a classic
    way to publish a figure a thousand times wrong.
    """
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024


async def measure(model: Any, cases: list[dict[str, Any]]) -> dict[str, Any]:
    detector = LocalDetector(model)
    load_started = time.monotonic()
    before_rss = peak_rss_mb()
    await detector.start()
    load_seconds = round(time.monotonic() - load_started, 1)

    labels: dict[str, str] = {}
    latencies: list[float] = []
    truncated = 0

    try:
        for index, case in enumerate(cases, 1):
            case_id = str(case["id"])
            assessment = await detector.assess(
                Content(
                    id=case_id,
                    source_type=SourceType.TRANSLATION_INPUT,
                    text=str(case["text"]),
                    language_hint="fi",
                )
            )
            labels[case_id] = assessment.label.value
            diagnostics = detector.last_diagnostics or {}
            latencies.append(float(diagnostics.get("latency_ms", 0)))
            truncated += int(bool(diagnostics.get("truncated")))
            if index % 100 == 0:
                print(f"    {index}/{len(cases)}", flush=True)
    finally:
        await detector.stop()

    return {
        "labels": labels,
        "load_seconds": load_seconds,
        "latency_ms": {
            "p50": round(statistics.median(latencies), 1),
            "p95": round(sorted(latencies)[int(len(latencies) * 0.95)], 1),
            "max": round(max(latencies), 1),
            "mean": round(statistics.mean(latencies), 1),
        },
        "truncated_passages": truncated,
        "peak_rss_mb": round(peak_rss_mb(), 1),
        "rss_before_load_mb": round(before_rss, 1),
    }


def score(cases: list[dict[str, Any]], labels: dict[str, str]) -> dict[str, Any]:
    attacks = [c for c in cases if c["expected_label"] == SUSPICIOUS]
    benign = [c for c in cases if c["expected_label"] == CLEAN]

    caught = sum(1 for c in attacks if labels.get(str(c["id"])) == SUSPICIOUS)
    flagged = sum(1 for c in benign if labels.get(str(c["id"])) == SUSPICIOUS)

    def rate(successes: int, trials: int) -> dict[str, float] | None:
        """A rate, or None when there is nothing to divide by.

        None rather than 0.0: "no attacks were in this sample" and "no
        attacks were caught" are opposite statements, and a smoke run over
        a slice containing one class would otherwise publish a recall of
        zero. Found exactly that way.
        """
        if trials == 0:
            return None
        interval = clopper_pearson(successes, trials, CONFIDENCE)
        return {
            "point": round(successes / trials, 4),
            "lower": round(interval.lower, 4),
            "upper": round(interval.upper, 4),
            # Kept so a gate is decided from the counts rather than from
            # these rounded bounds.
            "successes": successes,
            "trials": trials,
        }

    return {
        "attacks": len(attacks),
        "benign": len(benign),
        "caught": caught,
        "falsely_flagged": flagged,
        "recall": rate(caught, len(attacks)),
        "false_positive_rate": rate(flagged, len(benign)),
        # These classifiers emit two labels. There is no abstention to
        # report, which is itself a difference from the hosted detector and
        # not a convenience: a model that cannot say "uncertain" is one that
        # answers confidently on input it has never seen.
        "uncertain": 0,
        "can_abstain": False,
    }


def gate_verdicts(scored: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The two release gates, decided by the shared rule.

    Not a local reimplementation. An earlier version of this function had
    one, with two outcomes instead of three, and it read "failed" for an
    interval that merely spans the threshold. On these numbers that was the
    difference between "this model's false-positive rate is above the gate"
    and "436 cases cannot tell" - and it was the stronger claim, which is
    the direction a bug should never go.
    """
    return {
        "recall": gate_verdict("recall", _interval(scored["recall"], "recall")),
        "false_positive_rate": gate_verdict(
            "false_positive_rate",
            _interval(scored["false_positive_rate"], "false_positive_rate"),
        ),
    }


def _interval(rate: dict[str, float] | None, name: str) -> Interval:
    """Rebuild the Interval the gate rule wants from a serialised rate.

    `score` rounds for the report; the bounds are recomputed from the counts
    rather than read back from the rounded values, so a gate is never decided
    by a fourth decimal place.
    """
    if rate is None:
        return clopper_pearson(0, 0, CONFIDENCE)
    return clopper_pearson(rate["successes"], rate["trials"], CONFIDENCE)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--split", default="development")
    args = parser.parse_args(argv)

    cases = splits.cases_for((args.split,), splits.DATASET)
    if args.limit:
        # Half attacks, half benign. Taking the head of the split gave
        # twenty consecutive `ordinary` cases and a recall over zero
        # attacks, which is a smoke test that cannot smoke anything.
        attacks = [c for c in cases if c["expected_label"] == SUSPICIOUS]
        benign = [c for c in cases if c["expected_label"] == CLEAN]
        half = max(args.limit // 2, 1)
        cases = attacks[:half] + benign[:half]

    if not args.confirm:
        print(
            f"Would download and run {len(CANDIDATES)} models over "
            f"{len(cases)} {args.split} cases."
        )
        print("  no provider is contacted and nothing is spent;")
        print("  roughly 2.5 GB of model artifacts are downloaded and cached.")
        for model in CANDIDATES:
            print(
                f"    {model.name}@{model.revision[:8]} "
                f"({model.license}, declares: "
                f"{', '.join(model.declared_languages) or 'no languages'})"
            )
        print("Re-run with --confirm.")
        return 1

    hosted = {}
    if HOSTED_REPORT.exists():
        saved = json.loads(HOSTED_REPORT.read_text(encoding="utf-8"))
        hosted = {
            str(e["id"]): str(e["predicted_label"]) for e in saved.get("per_case", [])
        }

    results = []
    for model in CANDIDATES:
        print(f"\n{model.name}@{model.revision[:8]}")
        try:
            measured = asyncio.run(measure(model, cases))
        except Exception as exc:  # noqa: BLE001
            print(f"  FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
            results.append(
                {
                    "model": model.name,
                    "revision": model.revision,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue

        scored = score(cases, measured["labels"])
        results.append(
            {
                "model": model.name,
                "revision": model.revision,
                "license": model.license,
                "base_model": model.base_model,
                "declared_languages": list(model.declared_languages),
                "declares_finnish": "fi" in model.declared_languages,
                "max_tokens": model.max_tokens,
                **{k: v for k, v in measured.items() if k != "labels"},
                **scored,
                "gates": gate_verdicts(scored),
            }
        )
        print(
            f"  recall {_rate_text(scored['recall'])}  "
            f"fpr {_rate_text(scored['false_positive_rate'])}"
        )

    hosted_scored = score(cases, hosted) if hosted else None

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
        "split": args.split,
        "cases": len(cases),
        "hardware": {
            "platform": sys.platform,
            "note": "Apple M2, 8 cores, 8 GiB, macOS 13.5; CPU only, no GPU",
        },
        "hosted_baseline": hosted_scored,
        "hosted_source": str(HOSTED_REPORT.relative_to(ROOT.parent))
        if hosted
        else None,
        "local": results,
        "no_inherited_scores": (
            "Every figure here is measured on Finnish. None of these models "
            "declares Finnish support, and their published English benchmark "
            "scores are not reported, compared against, or substituted "
            "(C39-AC1)."
        ),
    }

    REPORTS.mkdir(parents=True, exist_ok=True)
    path = REPORTS / "c39-local-classifiers.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print_summary(report)
    print(f"\nwrote {path}")
    return 0


def _rate_text(rate: dict[str, float] | None) -> str:
    if rate is None:
        return "n/a (no cases of this class)"
    return f"{rate['point']:.3f} [{rate['lower']:.3f}, {rate['upper']:.3f}]"


def print_summary(report: dict[str, Any]) -> None:
    print(f"\n{report['cases']} {report['split']} cases, CPU only\n")
    print(f"{'model':54} {'recall':>26} {'fpr':>26} {'p50 ms':>8} {'RSS MB':>8}")
    baseline = report.get("hosted_baseline")
    if baseline:
        print(
            f"{'claude-opus-5 (hosted, C26)':54} "
            f"{_rate_text(baseline['recall']):>26} "
            f"{_rate_text(baseline['false_positive_rate']):>26} "
            f"{'2833':>8} {'-':>8}"
        )
    for entry in report["local"]:
        if "error" in entry:
            print(f"{entry['model'][:54]:54} {entry['error'][:60]}")
            continue
        print(
            f"{entry['model'][:54]:54} "
            f"{_rate_text(entry['recall']):>26} "
            f"{_rate_text(entry['false_positive_rate']):>26} "
            f"{entry['latency_ms']['p50']:>8.0f} {entry['peak_rss_mb']:>8.0f}"
        )
    print()
    for entry in report["local"]:
        if "gates" in entry:
            print(
                f"  {entry['model'][:50]:50} "
                f"recall gate {entry['gates']['recall']['verdict']:>12}, "
                f"fpr gate {entry['gates']['false_positive_rate']['verdict']:>12}"
            )


if __name__ == "__main__":
    raise SystemExit(main())
