"""Re-analyse a saved report through the current metrics.

This exists because prices are dated and metrics change. A report records
what was measured; it should not have to record every conclusion that could
ever be drawn from those measurements, or an improvement to the analysis would
mean re-running the evaluation and paying for it again.

So the saved counts and token usage are the evidence, and this re-derives the
metrics from them. Two uses:

  * **Re-costing.** `--prices-as-of` applies a different dated price to the
    same usage, which is the reason prices carry a date at all.
  * **Re-scoring.** A report written before confidence intervals and gate
    verdicts existed can be brought forward without spending anything.

What it cannot invent is anything that was not recorded. A report with no
per-case latencies produces no percentiles, and says so rather than
estimating them.

    python evals/reanalyse.py evals/reports/milestones/c13-live-claude-opus-5.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from runner import build_report, print_summary  # noqa: E402

# Dated price history. A new row is added when prices change; old rows are
# never edited, because an old report's cost figure has to stay reproducible.
PRICE_HISTORY: dict[str, dict[str, dict[str, Any]]] = {
    "2026-06-24": {
        "claude-opus-5": {"input": 5.00, "output": 25.00, "as_of": "2026-06-24"},
        "claude-sonnet-5": {"input": 2.00, "output": 10.00, "as_of": "2026-06-24"},
        "claude-haiku-4-5": {"input": 1.00, "output": 5.00, "as_of": "2026-06-24"},
    },
}

DEFAULT_PRICES_AS_OF = "2026-06-24"


def usage_from(report: dict[str, Any]) -> list[tuple[int | None, int | None]]:
    """Reconstruct per-request usage from a saved report.

    Older reports recorded only aggregates, so the per-request detail is gone.
    The totals are split across the recorded request count as a single
    synthetic entry plus placeholders, which keeps the token totals exact and
    the request count honest without inventing a distribution.
    """
    cost = report.get("cost") or {}
    requests = int(cost.get("requests") or 0)
    if requests == 0:
        return []

    total_in = int(cost.get("input_tokens") or 0)
    total_out = int(cost.get("output_tokens") or 0)

    # One entry carries the measured totals; the rest are recorded as having
    # reported usage, because the original report's request count says they
    # did. Splitting evenly would imply a per-request measurement that was
    # never made.
    entries: list[tuple[int | None, int | None]] = [(total_in, total_out)]
    entries.extend([(0, 0)] * (requests - 1))
    return entries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument(
        "--dataset", type=Path, default=ROOT / "datasets" / "seed-fi.yaml"
    )
    parser.add_argument(
        "--prices-as-of", default=DEFAULT_PRICES_AS_OF, choices=sorted(PRICE_HISTORY)
    )
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    if not args.report.exists():
        print(f"reanalyse: {args.report} not found", file=sys.stderr)
        return 1

    original = json.loads(args.report.read_text(encoding="utf-8"))
    detector = original.get("detector", {})
    model = detector.get("model") or detector.get("identity", "").split(":")[-1]

    rebuilt = build_report(
        args.dataset,
        detector.get("identity", "unknown"),
        original["counts"],
        original.get("per_case", []),
        (original.get("deferred_quality") or {}).get("cases", []),
        prompt_version=detector.get("prompt_version", "none"),
        prompt_fingerprint=detector.get("prompt_fingerprint"),
        model=model,
        # Absent, not estimated. The original run did not record per-case
        # latencies, and inventing percentiles from a wall-clock total would
        # produce numbers indistinguishable from measurements.
        latencies_ms=None,
        usage=usage_from(original),
        prices=PRICE_HISTORY[args.prices_as_of],
    )

    rebuilt["reanalysis"] = {
        "source_report": str(args.report),
        "source_generated_at": original.get("generated_at"),
        "prices_as_of": args.prices_as_of,
        "note": (
            "Metrics re-derived from the saved counts and token usage. No "
            "provider call was made. Latency percentiles are absent because "
            "the original run did not record per-case latencies."
        ),
    }
    if "wall_clock_seconds" in original:
        rebuilt["wall_clock_seconds"] = original["wall_clock_seconds"]

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(rebuilt, indent=2) + "\n", encoding="utf-8")
        print(f"report written to {args.out}\n")

    print_summary(rebuilt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
