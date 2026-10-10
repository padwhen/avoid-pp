"""Measure what a scan costs the provider, by input size.

THIS SPENDS MONEY. It is never run by CI or by `make check`, and it requires
an explicit confirmation flag.

    make provider-profile                 # refuses, prints an estimate
    make provider-profile CONFIRM=yes     # runs
    make provider-profile CONFIRM=yes REPS=5

## Why this exists separately from the Go harness

C32-AC3 asks for provider work and gateway overhead to be reported
separately. `gateway/internal/capacity` measures the gateway by injecting a
known provider latency, so everything above that latency is the gateway's. It
cannot measure the provider at all - that is what this does.

## Why by input size

The C26 run measured 436 real scans and every one of them was a short
passage: the corpus maximum is 510 characters against a contract ceiling of
32768. So the existing latency and cost figures describe 1.6% of the
supported input range, and both latency and cost scale with input tokens.
Capacity planning from those numbers alone would be planning for the easy
case.

Three sizes, few repetitions. The point is the *shape* of the scaling, which
a handful of calls at each end establishes well enough to size a timeout
with; a tight confidence interval on a latency at one size would cost more
than it tells us.

## The passages are built, not sampled

The same fixed Finnish sentence the Go harness repeats. Sampling the corpus
would make a benchmark depend on dataset contents, and reading the holdout to
time a request would spend a one-time resource on a stopwatch.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "detector" / "src"))

from translation_guard import limits as detector_limits  # noqa: E402
from translation_guard import prompts  # noqa: E402
from translation_guard.config import Settings  # noqa: E402
from translation_guard.detectors.base import DetectorUnavailable  # noqa: E402
from translation_guard.detectors.claude import ClaudeDetector  # noqa: E402
from translation_guard.schemas import MAX_TEXT_CHARS, Content, SourceType  # noqa: E402

REPORTS = ROOT / "reports"

# The same sentence gateway/internal/capacity/profile_test.go repeats, so the
# two halves of C32 describe passages of identical shape.
SOURCE_SENTENCE = (
    "Ilmatieteen laitos ennustaa viikonlopuksi räntäsateita maan "
    "etelä- ja keskiosiin, ja lämpötila pysyttelee nollan tuntumassa. "
)


def passage_of(chars: int) -> str:
    """A passage of exactly `chars` characters."""
    repeated = SOURCE_SENTENCE * (chars // len(SOURCE_SENTENCE) + 1)
    return repeated[:chars]


def effective_max_chars() -> int:
    """The largest passage the detector will actually accept.

    Computed from the detector's own budget rather than written down, because
    the number that matters is not the one in the contract. Four bounds apply
    to a single passage and they are in three different units:

        contract.MaxTextChars        32768 characters   (the public schema)
        api.MaxRequestBytes          65536 bytes        (gateway body cap)
        limits.MAX_PASSAGE_BYTES     32768 bytes        (detector passage cap)
        limits.DEFAULT_MAX_SOURCE_TOKENS  4096 tokens   (detector token budget)

    The token budget binds first by a wide margin, and limits.py says so. But
    the contract still advertises 32768 characters, so the documented maximum
    is roughly six times what the service accepts. C32 measures the real one.
    """
    low, high = 1, MAX_TEXT_CHARS
    while low < high:
        middle = (low + high + 1) // 2
        try:
            detector_limits.check(passage_of(middle))
        except detector_limits.InputTooLarge:
            high = middle - 1
        else:
            low = middle
    return low


SIZES = [
    ("short", 50),
    ("typical", 150),
    # Not MAX_TEXT_CHARS. A passage that size is rejected before any provider
    # call, so timing it would measure a validation error.
    ("effective_maximum", effective_max_chars()),
]

PRICING = {
    "claude-opus-5": {"input": 5.00, "output": 25.00, "as_of": "2026-06-24"},
    "claude-sonnet-5": {"input": 2.00, "output": 10.00, "as_of": "2026-06-24"},
    "claude-haiku-4-5": {"input": 1.00, "output": 5.00, "as_of": "2026-06-24"},
}

# Deliberately pessimistic: Finnish is agglutinative and tokenises worse than
# English, and an estimate that undershoots is the one that surprises
# somebody. Two characters per token plus a fixed prompt overhead.
EST_CHARS_PER_TOKEN = 2.0
EST_PROMPT_TOKENS = 1100
EST_OUTPUT_TOKENS = 400


def estimate_usd(model: str, reps: int) -> float | None:
    price = PRICING.get(model)
    if price is None:
        return None
    total = 0.0
    for _, chars in SIZES:
        tokens_in = EST_PROMPT_TOKENS + chars / EST_CHARS_PER_TOKEN
        total += reps * (
            tokens_in * price["input"] / 1e6 + EST_OUTPUT_TOKENS * price["output"] / 1e6
        )
    return total


async def profile(model: str, reps: int, on_size=None) -> list[dict]:
    """Measure each size class, handing each result to `on_size` as it lands.

    The callback exists because the first run of this script made six paid
    calls and then crashed in its own report-assembly code, discarding all
    six. Results are now durable before anything that could fail touches
    them: paid data is written as it arrives, not when the run finishes.
    """
    settings = Settings()
    results: list[dict] = []

    for name, chars in SIZES:
        text = passage_of(chars)
        samples: list[dict] = []

        detector = ClaudeDetector(
            api_key=settings.api_key,
            model=model,
            identity=f"claude:{model}",
            # Generous, because the question is how long a maximum passage
            # takes - not whether it fits in the service's own budget. A
            # timeout here would turn the measurement into its own answer.
            timeout_seconds=180.0,
        )
        await detector.start()
        try:
            for rep in range(reps):
                started = time.monotonic()
                try:
                    assessment = await detector.assess(
                        Content(
                            id=f"profile-{name}-{rep}",
                            source_type=SourceType.TRANSLATION_INPUT,
                            text=text,
                            language_hint="fi",
                        ),
                        deadline_ms=180_000,
                    )
                    label = assessment.label.value
                    failed = None
                except DetectorUnavailable as exc:
                    label = "error"
                    failed = type(exc).__name__
                    print(f"  {name} rep {rep}: ERROR {exc}", file=sys.stderr)
                except Exception as exc:  # noqa: BLE001
                    label = "error"
                    failed = type(exc).__name__
                    print(f"  {name} rep {rep}: UNEXPECTED {failed}", file=sys.stderr)

                wall_ms = (time.monotonic() - started) * 1000
                diagnostics = getattr(detector, "last_diagnostics", None)
                samples.append(
                    {
                        "rep": rep,
                        "label": label,
                        "error": failed,
                        "wall_ms": round(wall_ms, 1),
                        # The detector's own figure where it has one. Absent
                        # stays absent: an unmeasured call is not a free one.
                        "latency_ms": getattr(diagnostics, "latency_ms", None),
                        "input_tokens": getattr(diagnostics, "input_tokens", None),
                        "output_tokens": getattr(diagnostics, "output_tokens", None),
                        "attempts": getattr(diagnostics, "attempts", None),
                    }
                )
                print(
                    f"  {name} rep {rep}: {label} in {wall_ms:.0f}ms "
                    f"({samples[-1]['input_tokens']} in, "
                    f"{samples[-1]['output_tokens']} out)",
                    flush=True,
                )
        finally:
            await detector.stop()

        entry = {
            "size": name,
            "chars": chars,
            "utf8_bytes": len(text.encode("utf-8")),
            "samples": samples,
            **summarise(samples, model),
        }
        results.append(entry)
        if on_size is not None:
            on_size(list(results))
    return results


def summarise(samples: list[dict], model: str) -> dict:
    """Aggregate a handful of samples without pretending they are many.

    No percentiles. Three repetitions cannot support a p95, and printing one
    would invite it to be quoted as though they could. Minimum, median and
    maximum say exactly as much as the data contains.
    """
    latencies = [s["wall_ms"] for s in samples if s["error"] is None]
    measured = [
        s
        for s in samples
        if s["input_tokens"] is not None and s["output_tokens"] is not None
    ]
    price = PRICING.get(model)

    summary: dict = {
        "successful": len(latencies),
        "failed": len(samples) - len(latencies),
        "unmeasured_usage": len(samples) - len(measured),
    }
    if latencies:
        summary["wall_ms"] = {
            "min": round(min(latencies), 1),
            "median": round(statistics.median(latencies), 1),
            "max": round(max(latencies), 1),
        }
    if measured:
        mean_in = statistics.mean(s["input_tokens"] for s in measured)
        mean_out = statistics.mean(s["output_tokens"] for s in measured)
        summary["mean_input_tokens"] = round(mean_in, 1)
        summary["mean_output_tokens"] = round(mean_out, 1)
        if price:
            per_scan = mean_in * price["input"] / 1e6 + mean_out * price["output"] / 1e6
            summary["usd_per_scan"] = round(per_scan, 6)
            summary["usd_per_1000_scans"] = round(per_scan * 1000, 2)
    if summary["unmeasured_usage"]:
        # Said out loud, because a cost figure derived from some of the calls
        # is a floor and not a measurement.
        summary["cost_is_a_floor"] = True
    return summary


def main(argv: list[str] | None = None) -> int:
    # argv is a parameter rather than read from sys.argv so the spend-guard
    # self-test can invoke this in-process and assert it refuses.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--model", default=None)
    parser.add_argument("--reps", type=int, default=3)
    args = parser.parse_args(argv)

    settings = Settings()
    model = args.model or settings.model
    reps = max(1, args.reps)

    if not args.confirm:
        estimate = estimate_usd(model, reps)
        print(f"Would call {model} {reps * len(SIZES)} times:")
        for name, chars in SIZES:
            print(f"  {name}: {reps} x {chars} characters")
        if estimate is None:
            print(f"  no recorded price for {model}; cost unknown")
        else:
            print(f"  estimate: ${estimate:.2f} (deliberately pessimistic)")
        print("Re-run with --confirm.")
        return 1

    print(f"provider profile: {model}, {reps} repetitions per size")

    REPORTS.mkdir(parents=True, exist_ok=True)
    path = REPORTS / "c32-provider-profile.json"

    def envelope(sizes: list[dict]) -> dict:
        return {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
            "model": model,
            "prompt_version": prompts.DEFAULT_VERSION,
            "prompt_fingerprint": prompts.get(prompts.DEFAULT_VERSION).fingerprint(),
            "repetitions": reps,
            "pricing": PRICING.get(model),
            "complete": len(sizes) == len(SIZES),
            "method": {
                "passages": "a fixed Finnish sentence repeated to length; "
                "no corpus case is read",
                "latency": "wall clock around the detector call, so it includes retries",
                "note": "few repetitions by design; min/median/max only, never percentiles",
            },
            "sizes": sizes,
        }

    def persist(sizes: list[dict]) -> None:
        path.write_text(
            json.dumps(envelope(sizes), indent=2, ensure_ascii=False) + "\n"
        )

    results = asyncio.run(profile(model, reps, on_size=persist))

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
        "model": model,
        "prompt_version": prompts.DEFAULT_VERSION,
        "prompt_fingerprint": prompts.get(prompts.DEFAULT_VERSION).fingerprint(),
        "repetitions": reps,
        "pricing": PRICING.get(model),
        "complete": True,
        "method": {
            "passages": "a fixed Finnish sentence repeated to length; no corpus case is read",
            "latency": "wall clock around the detector call, so it includes retries",
            "note": "few repetitions by design; min/median/max only, never percentiles",
        },
        "sizes": results,
    }

    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(f"\nwrote {path}")

    print("\nsize      chars   in_tok  out_tok   median_ms   $/scan   $/1000")
    for entry in results:
        wall = entry.get("wall_ms", {})
        print(
            f"{entry['size']:9s} {entry['chars']:6d} "
            f"{entry.get('mean_input_tokens', 0):8.0f} "
            f"{entry.get('mean_output_tokens', 0):8.0f} "
            f"{wall.get('median', 0):11.0f} "
            f"{entry.get('usd_per_scan', 0):8.4f} "
            f"{entry.get('usd_per_1000_scans', 0):8.2f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
