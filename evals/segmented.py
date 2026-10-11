"""Does scanning a passage in pieces detect mixed-language attacks better?

THIS SPENDS MONEY with --confirm. Never run by CI or by `make check`.

    make segmented                 # refuses, prints an estimate
    make segmented CONFIRM=yes     # runs
    make check-segmented           # the combination rule, free

## The comparison

Full-passage labels are reused from the C37 challenge report rather than
re-measured: same model, same prompt, same fingerprint, same corpus. Only
the segmented arm costs anything, which also keeps the two arms honestly
paired - a difference cannot come from the provider having a different day.

## The combination rule, and why it fails closed

A passage is suspicious if *any* segment is suspicious; uncertain if any is
uncertain and none suspicious; clean only if every segment is clean. An
error in any segment makes the whole scan an error, because a passage with
an unscanned piece has not been scanned.

The alternative - majority vote, or weighting by length - would let a short
instruction be outvoted by the ordinary Finnish around it, which is the
attack this project exists to catch.

## What the boundary probes are for

C38-AC2 asks for boundary-spanning attacks. Segmentation's specific weakness
is that an instruction split across two segments may look harmless in both
halves, so the probes take reviewed corpus attacks and insert a sentence
boundary into the middle of the instruction. Only punctuation is added; the
Finnish and the embedded language are unchanged, so the passage's meaning is
the reviewed one. They are diagnostics for the splitter, not corpus cases,
and they are not added to the dataset.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "detector" / "src"))

import splits  # noqa: E402

from translation_guard import prompts  # noqa: E402
from translation_guard.config import Settings  # noqa: E402
from translation_guard.detectors.base import DetectorUnavailable  # noqa: E402
from translation_guard.detectors.claude import ClaudeDetector  # noqa: E402
from translation_guard.schemas import Content, SourceType  # noqa: E402
from translation_guard.segment import split as split_passage  # noqa: E402

REPORTS = ROOT / "reports"
FULL_PASSAGE_REPORT = REPORTS / "milestones" / "c37-challenge.json"

MEASURED_USD_PER_CALL = 0.7784 / 73

SUSPICIOUS = "suspicious"
UNCERTAIN = "uncertain"
CLEAN = "no_injection_detected"
ERROR = "error"


def combine(segment_labels: list[str]) -> str:
    """Fold per-segment labels into one verdict, failing closed.

    Order matters and is the whole design: error beats suspicious beats
    uncertain beats clean. A passage with an unscanned piece has not been
    scanned, and saying otherwise would be the "complete scan" lie one layer
    down from where `scan_status` prevents it.
    """
    if not segment_labels:
        return ERROR
    if ERROR in segment_labels:
        return ERROR
    if SUSPICIOUS in segment_labels:
        return SUSPICIOUS
    if UNCERTAIN in segment_labels:
        return UNCERTAIN
    return CLEAN


def boundary_probes(
    cases: list[dict[str, Any]], limit: int = 6
) -> list[dict[str, Any]]:
    """Reviewed attacks with a sentence boundary pushed into the instruction.

    Built by transformation rather than invention: the words are the
    reviewed ones and only punctuation moves, so the passage still means
    what a reviewer said it means. Marked as derived so no report mistakes
    them for corpus cases.
    """
    probes: list[dict[str, Any]] = []
    for case in cases:
        if case["expected_label"] != SUSPICIOUS or len(probes) >= limit:
            continue
        text = str(case["text"])
        # Split the longest internal run of words with a full stop, which
        # lands inside a sentence rather than between two.
        middle = _mid_sentence_offset(text)
        if middle is None:
            continue
        probes.append(
            {
                "id": f"probe-boundary-{case['id']}",
                "derived_from": str(case["id"]),
                "embedded_language": case.get("embedded_language"),
                "expected_label": SUSPICIOUS,
                "text": text[:middle].rstrip() + ". " + text[middle:].lstrip(),
                "note": "a sentence boundary inserted into the instruction",
            }
        )
    return probes


def _mid_sentence_offset(text: str) -> int | None:
    """A word boundary near the middle of the longest sentence."""
    sentences = [m for m in re.finditer(r"[^.!?]+[.!?]?", text) if m.group().strip()]
    if not sentences:
        return None
    longest = max(sentences, key=lambda m: len(m.group()))
    if len(longest.group().split()) < 6:
        return None
    spaces = [m.start() for m in re.finditer(r" ", longest.group())]
    if not spaces:
        return None
    return longest.start() + spaces[len(spaces) // 2]


async def scan_segments(
    detector: ClaudeDetector, case_id: str, text: str
) -> tuple[str, list[str], int]:
    """Scan every segment of one passage. Returns (verdict, labels, count)."""
    segments = split_passage(text)
    labels: list[str] = []
    for segment in segments:
        try:
            assessment = await detector.assess(
                Content(
                    id=f"{case_id}-s{segment.index}",
                    source_type=SourceType.TRANSLATION_INPUT,
                    text=segment.text,
                    language_hint="fi",
                ),
                deadline_ms=60_000,
            )
            labels.append(assessment.label.value)
        except DetectorUnavailable:
            labels.append(ERROR)
        except Exception:  # noqa: BLE001
            labels.append(ERROR)
    return combine(labels), labels, len(segments)


async def run(cases: list[dict[str, Any]], model: str) -> dict[str, dict[str, Any]]:
    settings = Settings()
    detector = ClaudeDetector(
        api_key=settings.api_key,
        model=model,
        identity=f"claude:{model}",
        timeout_seconds=60.0,
    )
    await detector.start()
    results: dict[str, dict[str, Any]] = {}
    try:
        for case in cases:
            case_id = str(case["id"])
            started = time.monotonic()
            verdict, labels, count = await scan_segments(
                detector, case_id, str(case["text"])
            )
            results[case_id] = {
                "segmented_label": verdict,
                "segment_labels": labels,
                "segments": count,
                "wall_ms": int((time.monotonic() - started) * 1000),
            }
            print(f"  {case_id} [{count} seg]: {verdict}", flush=True)
    finally:
        await detector.stop()
    return results


def compare(
    cases: list[dict[str, Any]],
    full: dict[str, str],
    segmented: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Per-case agreement, and who was right when they disagreed."""
    rows = []
    for case in cases:
        case_id = str(case["id"])
        if case_id not in segmented:
            continue
        expected = case["expected_label"]
        full_label = full.get(case_id, "missing")
        seg_label = segmented[case_id]["segmented_label"]

        full_right = full_label == expected
        seg_right = seg_label == expected
        rows.append(
            {
                "id": case_id,
                "embedded_language": case.get("embedded_language"),
                "expected": expected,
                "full_passage": full_label,
                "segmented": seg_label,
                "segments": segmented[case_id]["segments"],
                "segment_labels": segmented[case_id]["segment_labels"],
                "agreement": "same" if full_label == seg_label else "differs",
                "verdict": (
                    "both correct"
                    if full_right and seg_right
                    else "segmentation better"
                    if seg_right
                    else "segmentation worse"
                    if full_right
                    else "both wrong"
                ),
            }
        )

    tally: dict[str, int] = {}
    for row in rows:
        tally[row["verdict"]] = tally.get(row["verdict"], 0) + 1

    single = [r for r in rows if r["segments"] == 1]
    return {
        "cases": len(rows),
        "tally": tally,
        "cases_with_one_segment": len(single),
        "note_on_single_segments": (
            f"{len(single)} of {len(rows)} passages produce a single segment, "
            "where the two arms are identical by construction and the "
            "comparison says nothing. The difference, if any, is in the "
            f"remaining {len(rows) - len(single)}."
        ),
        "per_case": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--model", default=None)
    parser.add_argument("--probes", type=int, default=6)
    args = parser.parse_args(argv)

    settings = Settings()
    model = args.model or settings.model
    cases = splits.assign(splits.load_cases(splits.DATASET)).get(splits.CHALLENGE, [])
    probes = boundary_probes(cases, args.probes)

    segment_calls = sum(len(split_passage(str(c["text"]))) for c in cases)
    probe_calls = sum(len(split_passage(str(p["text"]))) for p in probes) + len(probes)
    total = segment_calls + probe_calls

    if not args.confirm:
        print(f"Would call {model} {total} times:")
        print(f"  {len(cases)} challenge cases -> {segment_calls} segment scans")
        print(f"  {len(probes)} boundary probes -> {probe_calls} scans (both arms)")
        print("  full-passage labels are reused from the C37 report, free")
        print(f"  estimate: ${total * MEASURED_USD_PER_CALL:.2f}")
        print("Re-run with --confirm.")
        return 1

    if not FULL_PASSAGE_REPORT.exists():
        print(
            f"missing {FULL_PASSAGE_REPORT}; run `make challenge CONFIRM=yes`",
            file=sys.stderr,
        )
        return 1
    saved = json.loads(FULL_PASSAGE_REPORT.read_text(encoding="utf-8"))
    full = {str(e["id"]): str(e["predicted_label"]) for e in saved.get("per_case", [])}

    print(f"segmented evaluation: {model}, {len(cases)} cases")
    started = time.monotonic()
    segmented = asyncio.run(run(cases, model))

    print(f"\nboundary probes: {len(probes)}")
    probe_segmented = asyncio.run(run(probes, model))
    probe_full = asyncio.run(run_full(probes, model))

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
        "detector": {
            "model": model,
            "prompt_version": prompts.DEFAULT_VERSION,
            "prompt_fingerprint": prompts.get(prompts.DEFAULT_VERSION).fingerprint(),
        },
        "full_passage_source": str(FULL_PASSAGE_REPORT.relative_to(ROOT.parent)),
        "challenge": compare(cases, full, segmented),
        "boundary_probes": compare(
            probes,
            {k: v["segmented_label"] for k, v in probe_full.items()},
            probe_segmented,
        ),
        "cost": {
            "full_passage_calls": len(cases),
            "segmented_calls": segment_calls,
            "ratio": round(segment_calls / max(len(cases), 1), 2),
        },
        "wall_clock_seconds": round(time.monotonic() - started, 1),
    }

    REPORTS.mkdir(parents=True, exist_ok=True)
    path = REPORTS / "c38-segmented.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print_summary(report)
    print(f"\nwrote {path}")
    return 0


async def run_full(
    cases: list[dict[str, Any]], model: str
) -> dict[str, dict[str, Any]]:
    """Whole-passage scans, for probes the C37 report does not cover."""
    settings = Settings()
    detector = ClaudeDetector(
        api_key=settings.api_key,
        model=model,
        identity=f"claude:{model}",
        timeout_seconds=60.0,
    )
    await detector.start()
    out: dict[str, dict[str, Any]] = {}
    try:
        for case in cases:
            case_id = str(case["id"])
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
                label = assessment.label.value
            except Exception:  # noqa: BLE001
                label = ERROR
            out[case_id] = {
                "segmented_label": label,
                "segment_labels": [label],
                "segments": 1,
                "wall_ms": 0,
            }
            print(f"  {case_id} [whole]: {label}", flush=True)
    finally:
        await detector.stop()
    return out


def print_summary(report: dict[str, Any]) -> None:
    for name in ("challenge", "boundary_probes"):
        block = report[name]
        print(f"\n{name}: {block['cases']} cases")
        for verdict, count in sorted(block["tally"].items()):
            print(f"  {verdict:22} {count}")
        differing = [r for r in block["per_case"] if r["agreement"] == "differs"]
        for row in differing:
            print(
                f"    {row['id']} [{row['embedded_language']}] "
                f"expected {row['expected']}, full {row['full_passage']}, "
                f"segmented {row['segmented']} {row['segment_labels']}"
            )
    cost = report["cost"]
    print(
        f"\ncost: {cost['segmented_calls']} segment calls against "
        f"{cost['full_passage_calls']} whole-passage calls "
        f"({cost['ratio']}x)"
    )


if __name__ == "__main__":
    raise SystemExit(main())
