"""Run the seed corpus against the live detector and score it.

THIS SPENDS MONEY — one provider request per case. It is never run by CI or by
`make check`, and it requires an explicit confirmation flag.

It deliberately reuses `runner.py` for the scoring rather than recomputing
metrics here: the arithmetic in that module is pinned by `selftest.py` against
a hand-calculated fixture, and a second implementation would be unverified.
This file only turns live calls into a label per case; everything downstream is
the tested path.

    make live-eval                   # refuses, prints an estimate
    make live-eval CONFIRM=yes       # runs
    make live-eval CONFIRM=yes LIMIT=10
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "detector" / "src"))

import holdout  # noqa: E402
import splits  # noqa: E402
from runner import (  # noqa: E402
    build_report,
    print_summary,
    score,
)

from translation_guard import prompts  # noqa: E402
from translation_guard.config import Settings  # noqa: E402
from translation_guard.detectors.base import DetectorUnavailable  # noqa: E402
from translation_guard.detectors.claude import ClaudeDetector  # noqa: E402
from translation_guard.schemas import Content, SourceType  # noqa: E402

DATASET = ROOT / "datasets" / "seed-fi.yaml"
REPORTS = ROOT / "reports"

# Dated list price per million tokens, recorded so a saved report can be
# re-costed later rather than silently assuming today's rates.
# Measured from the C13 full-corpus run: 73 requests, 85,223 input and 14,090
# output tokens, $0.7784 at the prices below. Finnish passages vary, so this
# is an average rather than a bound - but it is an average of real calls.
MEASURED_USD_PER_CASE = 0.7784 / 73
MEASURED_SOURCE = "C13 run: 73 cases, $0.7784"

PRICING = {
    "claude-opus-5": {"input": 5.00, "output": 25.00, "as_of": "2026-06-24"},
    "claude-sonnet-5": {"input": 2.00, "output": 10.00, "as_of": "2026-06-24"},
    "claude-haiku-4-5": {"input": 1.00, "output": 5.00, "as_of": "2026-06-24"},
}


async def assess_all(
    cases: list[dict], model: str, concurrency: int
) -> tuple[dict[str, str], list[tuple[int | None, int | None]], list[float], float]:
    """Return labels, token usage, per-case latencies, and wall-clock seconds.

    Usage is collected per assessment rather than summed, so a call that
    reported nothing stays visible as a gap. Summing would turn an unmeasured
    call into a free one.
    """
    settings = Settings()
    usage: list[tuple[int | None, int | None]] = []
    latencies: list[float] = []

    detector = ClaudeDetector(
        api_key=settings.api_key,
        model=model,
        identity=f"claude:{model}",
        timeout_seconds=60.0,
        # Recorded even when a field is missing, so the report can say how
        # many calls went unmeasured instead of treating them as free.
        on_usage=lambda i, o: usage.append((i, o)),
    )
    await detector.start()

    results: dict[str, str] = {}
    semaphore = asyncio.Semaphore(concurrency)
    done = 0
    total = len(cases)
    started = time.monotonic()

    async def one(case: dict) -> None:
        nonlocal done
        case_id = str(case["id"])
        async with semaphore:
            try:
                assessment = await detector.assess(
                    Content(
                        id=case_id,
                        source_type=SourceType.TRANSLATION_INPUT,
                        text=str(case["text"]),
                        language_hint="fi",
                    ),
                    deadline_ms=60_000,
                )
                results[case_id] = assessment.label.value
                # The detector's own measurement, not the wall clock here,
                # which would include queueing behind the semaphore.
                diagnostics = getattr(detector, "last_diagnostics", None)
                if diagnostics is not None and diagnostics.latency_ms is not None:
                    latencies.append(float(diagnostics.latency_ms))
            except DetectorUnavailable as exc:
                # An operational failure is its own outcome, never a clean one.
                results[case_id] = "error"
                print(f"  {case_id}: ERROR {exc}", file=sys.stderr)
            except Exception as exc:  # noqa: BLE001
                # One bad case must not abandon the other 72, which have
                # already been paid for.
                results[case_id] = "error"
                print(f"  {case_id}: UNEXPECTED {type(exc).__name__}", file=sys.stderr)
        done += 1
        if done % 10 == 0 or done == total:
            print(f"  {done}/{total} assessed", flush=True)

    try:
        await asyncio.gather(*(one(case) for case in cases))
    finally:
        await detector.stop()

    return results, usage, latencies, time.monotonic() - started


# cost_of lived here until C25. It summed usage into a single figure, which
# meant a call that reported no tokens was indistinguishable from a free one.
# metrics.cost_record counts unmeasured calls separately and marks the dollar
# figure as a floor when there were any.


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--model", default=None)
    parser.add_argument("--limit", type=int, default=0, help="first N cases only")
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument(
        "--splits",
        default=",".join(holdout.DEFAULT_SPLITS),
        help="comma-separated splits to evaluate (default: development,validation)",
    )
    parser.add_argument(
        "--confirm-holdout",
        action="store_true",
        help="required to evaluate the holdout; the access is logged",
    )
    args = parser.parse_args()

    settings = Settings()
    model = args.model or settings.model
    # Splits, not the whole dataset. Until C26 this ran every case including
    # the holdout, which would have spent the holdout's one-time value on a
    # routine iteration - and silently, since nothing in the output said which
    # cases had been used.
    requested = tuple(part.strip() for part in args.splits.split(",") if part.strip())
    try:
        cases = splits.cases_for(requested, DATASET)
    except KeyError as exc:
        print(f"live-eval: {exc}", file=sys.stderr)
        return 1

    if "holdout" in requested:
        # Not blocked, because a holdout that can never be used is not a
        # holdout, it is dead weight. Recorded instead, with the prompt
        # fingerprint, so a holdout result can be shown to predate the
        # prompt change rather than to have informed it.
        prompt_now = prompts.get(prompts.DEFAULT_VERSION)
        if holdout.prompt_changed_since_last_access(prompt_now.fingerprint()):
            print(
                "live-eval: WARNING - the prompt has changed since the holdout "
                "was last read.\n"
                "           Repeated holdout runs across prompt changes are how "
                "a holdout stops\n"
                "           being one. This access is being logged."
            )
        if not args.confirm_holdout:
            print(
                "live-eval: refusing to read the holdout without "
                "--confirm-holdout.\n"
                "           The holdout exists to be read once, against a "
                "frozen prompt.",
                file=sys.stderr,
            )
            return 1

    if args.limit:
        cases = cases[: args.limit]

    if not args.confirm:
        price = PRICING.get(model, {})
        # Measured, not guessed. The previous estimate used a flat $0.04 per
        # case for Opus and was four times the real figure - an estimate that
        # wrong either scares someone off a cheap run or surprises them on an
        # expensive one.
        print(__doc__)
        print(f"Would call {model} once per case: {len(cases)} requests")
        print(f"  splits: {', '.join(requested)}")
        if price:
            estimate = len(cases) * MEASURED_USD_PER_CASE
            print(
                f"  estimate: ${estimate:.2f} at the measured "
                f"${MEASURED_USD_PER_CASE:.4f} per case "
                f"({MEASURED_SOURCE})"
            )
            print(
                f"  list price {price['input']}/{price['output']} per Mtok, "
                f"as of {price['as_of']}"
            )
        else:
            print(f"  no recorded price for {model}; cost unknown")
        print("Re-run with --confirm.")
        return 1

    if not settings.api_key:
        print("live-eval: no API key. Set LLM_API_KEY in .env", file=sys.stderr)
        return 1

    print(f"live-eval: {model}, {len(cases)} cases, concurrency {args.concurrency}\n")
    labels, usage, latencies, elapsed = asyncio.run(
        assess_all(cases, model, args.concurrency)
    )

    # Hand the precomputed labels to the tested scorer. An adapter that raises
    # for "error" lets runner.py classify it as an operational failure exactly
    # as it would for a live exception.
    def adapter(case: dict) -> str:
        label = labels.get(str(case["id"]), "error")
        if label == "error":
            raise RuntimeError("detector unavailable for this case")
        return label

    result, per_case = score(cases, adapter)
    prompt = prompts.get(prompts.DEFAULT_VERSION)

    # Quality, latency and cost are passed in separately and reported
    # separately: a run can be accurate and unaffordable, or fast and wrong,
    # and one summary number would hide either.
    report = build_report(
        DATASET,
        f"claude:{model}",
        result["counts"],
        per_case,
        result["deferred"],
        # The fingerprint makes the report self-verifying: a version name
        # cannot prove which prompt bytes ran, and a hash can.
        prompt_version=prompt.version,
        prompt_fingerprint=prompt.fingerprint(),
        model=model,
        latencies_ms=latencies,
        usage=usage,
        prices=PRICING,
    )
    report["wall_clock_seconds"] = round(elapsed, 1)
    # Which splits produced this number. A report that does not say is a
    # report whose claim cannot be checked.
    report["dataset"]["splits"] = list(requested)

    if "holdout" in requested:
        prompt_now = prompts.get(prompts.DEFAULT_VERSION)
        entry = holdout.record_access(
            reason="live-eval",
            prompt_version=prompt_now.version,
            prompt_fingerprint=prompt_now.fingerprint(),
            model=model,
            case_count=len(cases),
        )
        report["holdout_access"] = entry
        print(f"  holdout access logged: {holdout.ACCESS_LOG}")
    if args.limit:
        # Stated in the report as well as the filename, because a file gets
        # renamed and copied and its name stops being evidence.
        report["dataset"]["partial_run"] = {
            "cases_run": len(cases),
            "note": (
                f"Only the first {len(cases)} cases of the dataset were run. "
                "Metrics describe this subset, not the corpus, and the "
                "dataset digest is of the whole file."
            ),
        }

    REPORTS.mkdir(parents=True, exist_ok=True)
    # A limited run must not overwrite a full one. The first version of this
    # wrote both to the same path, so a ten-case subset silently replaced a
    # seventy-three-case corpus report - the file still claimed to be "the"
    # live report for the model, with a tenth of the evidence behind it.
    # The filename says which splits ran, so a development report cannot be
    # mistaken for a holdout one later.
    suffix = "-" + "-".join(requested)
    if args.limit:
        suffix += f"-first{len(cases)}"
    out = REPORTS / f"live-{model}{suffix}.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print()
    print_summary(report)
    print(f"  wall clock  : {report['wall_clock_seconds']}s")
    print(f"\nreport written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
