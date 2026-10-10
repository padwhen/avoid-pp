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

from runner import (  # noqa: E402
    build_report,
    load_cases,
    print_summary,
    score,
)
from translation_guard.config import Settings  # noqa: E402
from translation_guard.detectors.base import DetectorUnavailable  # noqa: E402
from translation_guard.detectors.claude import (  # noqa: E402
    PROMPT_VERSION,
    ClaudeDetector,
)
from translation_guard.schemas import Content, SourceType  # noqa: E402

DATASET = ROOT / "datasets" / "seed-fi.yaml"
REPORTS = ROOT / "reports"

# Dated list price per million tokens, recorded so a saved report can be
# re-costed later rather than silently assuming today's rates.
PRICING = {
    "claude-opus-5": {"input": 5.00, "output": 25.00, "as_of": "2026-06-24"},
    "claude-sonnet-5": {"input": 2.00, "output": 10.00, "as_of": "2026-06-24"},
    "claude-haiku-4-5": {"input": 1.00, "output": 5.00, "as_of": "2026-06-24"},
}


async def assess_all(
    cases: list[dict], model: str, concurrency: int
) -> tuple[dict[str, str], list[tuple[int, int]], float]:
    """Return {case_id: label-or-"error"}, token usage, and wall-clock seconds."""
    settings = Settings()
    usage: list[tuple[int, int]] = []

    detector = ClaudeDetector(
        api_key=settings.api_key,
        model=model,
        identity=f"claude:{model}",
        timeout_seconds=60.0,
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

    return results, usage, time.monotonic() - started


def cost_of(model: str, usage: list[tuple[int, int]]) -> dict:
    inp = sum(i for i, _ in usage)
    out = sum(o for _, o in usage)
    price = PRICING.get(model)
    block = {"input_tokens": inp, "output_tokens": out, "requests": len(usage)}
    if price:
        block["usd"] = round(
            inp / 1e6 * price["input"] + out / 1e6 * price["output"], 4
        )
        block["price_as_of"] = price["as_of"]
    return block


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--model", default=None)
    parser.add_argument("--limit", type=int, default=0, help="first N cases only")
    parser.add_argument("--concurrency", type=int, default=5)
    args = parser.parse_args()

    settings = Settings()
    model = args.model or settings.model
    cases = load_cases(DATASET)
    if args.limit:
        cases = cases[: args.limit]

    if not args.confirm:
        price = PRICING.get(model, {})
        rough = len(cases) * 0.04 if model == "claude-opus-5" else len(cases) * 0.01
        print(__doc__)
        print(f"Would call {model} once per case: {len(cases)} requests.")
        print(f"Rough estimate: ${rough:.2f} (list price {price or 'unknown'}).")
        print("Re-run with --confirm.")
        return 1

    if not settings.api_key:
        print("live-eval: no API key. Set LLM_API_KEY in .env", file=sys.stderr)
        return 1

    print(f"live-eval: {model}, {len(cases)} cases, concurrency {args.concurrency}\n")
    labels, usage, elapsed = asyncio.run(assess_all(cases, model, args.concurrency))

    # Hand the precomputed labels to the tested scorer. An adapter that raises
    # for "error" lets runner.py classify it as an operational failure exactly
    # as it would for a live exception.
    def adapter(case: dict) -> str:
        label = labels.get(str(case["id"]), "error")
        if label == "error":
            raise RuntimeError("detector unavailable for this case")
        return label

    result, per_case = score(cases, adapter)
    report = build_report(
        DATASET, f"claude:{model}", result["counts"], per_case, result["deferred"]
    )
    report["detector"]["prompt_version"] = PROMPT_VERSION
    report["cost"] = cost_of(model, usage)
    report["wall_clock_seconds"] = round(elapsed, 1)

    REPORTS.mkdir(parents=True, exist_ok=True)
    out = REPORTS / f"live-{model}.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print()
    print_summary(report)
    cost = report["cost"]
    print(
        f"  cost        : {cost['requests']} requests, "
        f"{cost['input_tokens']} in / {cost['output_tokens']} out"
        + (f", ${cost['usd']}" if "usd" in cost else "")
    )
    print(f"  wall clock  : {report['wall_clock_seconds']}s")
    print(f"\nreport written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
