"""The mixed-language challenge report.

THIS SPENDS MONEY with --confirm. It is never run by CI or by `make check`.

    make challenge                 # refuses, prints an estimate
    make challenge CONFIRM=yes     # runs
    make challenge-selftest        # the arithmetic, free

## Why this is a separate report and not a split

Mixed-language detection quality has been unverified since C02. The nine
cases that existed before C37 sit in a `challenge` set that is held out of
development, validation and holdout, so no recall or false-positive figure
in the gate report is computed from them. That is deliberate: a bad result
here must not drag the Finnish claim down, and a good one must not flatter
it.

The cost of that choice is that nobody was looking at them at all. This is
the report that looks.

## Why there is no overall number

C37-AC3 says outcomes must be broken down by embedded language and "not
hidden behind dominant-language averages". The obvious implementation
reports per-language figures *and* a total, and the total is then the number
everyone quotes.

So this report does not compute one. There is no combined recall and no
combined false-positive rate, anywhere in the output or the JSON. A detector
that handles Swedish and fails on Russian has not got a rate; it has two
rates, and averaging them describes neither.

The one aggregate present is a count of cases, which cannot be mistaken for
a quality claim.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "detector" / "src"))

import splits  # noqa: E402
from metrics import clopper_pearson  # noqa: E402

from translation_guard import prompts  # noqa: E402
from translation_guard.config import Settings  # noqa: E402
from translation_guard.detectors.base import DetectorUnavailable  # noqa: E402
from translation_guard.detectors.claude import ClaudeDetector  # noqa: E402
from translation_guard.schemas import Content, SourceType  # noqa: E402

DATASET = ROOT / "datasets" / "seed-fi.yaml"
REPORTS = ROOT / "reports"

# From the C13 run, the same figure live_eval uses.
MEASURED_USD_PER_CASE = 0.7784 / 73

PRICING = {
    "claude-opus-5": {"input": 5.00, "output": 25.00, "as_of": "2026-06-24"},
    "claude-sonnet-5": {"input": 2.00, "output": 10.00, "as_of": "2026-06-24"},
    "claude-haiku-4-5": {"input": 1.00, "output": 5.00, "as_of": "2026-06-24"},
}

CONFIDENCE = 0.95


def challenge_cases(dataset: Path = DATASET) -> list[dict[str, Any]]:
    """Every case in the challenge set, which is every mixed-language case."""
    return splits.assign(splits.load_cases(dataset)).get(splits.CHALLENGE, [])


def by_language(
    cases: list[dict[str, Any]], labels: dict[str, str]
) -> dict[str, dict[str, Any]]:
    """Group outcomes by the language embedded in the passage.

    `labels` maps case id to the label the detector returned, or "error".
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        grouped[str(case.get("embedded_language") or "unknown")].append(case)

    out: dict[str, dict[str, Any]] = {}
    for language in sorted(grouped):
        attacks = [c for c in grouped[language] if c["expected_label"] == "suspicious"]
        benign = [
            c
            for c in grouped[language]
            if c["expected_label"] == "no_injection_detected"
        ]

        caught = sum(1 for c in attacks if labels.get(str(c["id"])) == "suspicious")
        flagged = sum(
            1 for c in benign if labels.get(str(c["id"])) in ("suspicious", "uncertain")
        )
        errors = sum(
            1 for c in grouped[language] if labels.get(str(c["id"])) == "error"
        )

        entry: dict[str, Any] = {
            "cases": len(grouped[language]),
            "attacks": len(attacks),
            "benign": len(benign),
            "attacks_caught": caught,
            "benign_flagged": flagged,
            "errors": errors,
            "missed": [
                str(c["id"])
                for c in attacks
                if labels.get(str(c["id"])) not in ("suspicious",)
            ],
            "false_positives": [
                str(c["id"])
                for c in benign
                if labels.get(str(c["id"])) in ("suspicious", "uncertain")
            ],
        }
        # Intervals, not point estimates, because at these counts a point
        # estimate is theatre: 4 of 4 is "somewhere above 40%".
        if attacks:
            interval = clopper_pearson(caught, len(attacks), CONFIDENCE)
            entry["recall"] = {
                "point": round(caught / len(attacks), 4),
                "lower": round(interval.lower, 4),
                "upper": round(interval.upper, 4),
            }
        if benign:
            interval = clopper_pearson(flagged, len(benign), CONFIDENCE)
            entry["false_positive_rate"] = {
                "point": round(flagged / len(benign), 4),
                "lower": round(interval.lower, 4),
                "upper": round(interval.upper, 4),
            }
        out[language] = entry
    return out


def by_dimension(
    cases: list[dict[str, Any]], labels: dict[str, str], field: str
) -> dict[str, dict[str, int]]:
    """Attack outcomes grouped by some other recorded dimension.

    A cut across languages, not an average of them. C37-AC3 forbids hiding
    per-language outcomes behind a dominant-language average; it does not
    forbid asking a different question, and "are middle-of-passage attacks
    harder than trailing ones" is a different question.

    The distinction that keeps this honest: there is still no single number
    anywhere. Every figure here is a count against a named bucket, and the
    language breakdown remains the primary one.
    """
    grouped: dict[str, dict[str, int]] = {}
    for case in cases:
        value = case.get(field)
        if value is None:
            continue
        bucket = grouped.setdefault(str(value), {"cases": 0, "caught": 0})
        bucket["cases"] += 1
        if labels.get(str(case["id"])) == "suspicious":
            bucket["caught"] += 1
    return dict(sorted(grouped.items()))


def benign_subtypes(
    cases: list[dict[str, Any]], labels: dict[str, str]
) -> dict[str, dict[str, int]]:
    """Benign outcomes, split by whether the foreign text reads as a command.

    The sharpest benign subtype in the corpus: a phishing email quoted in a
    warning, a tutorial explaining prompt injection, a partner's note about
    a contract title. These are the cases a careless detector flags, and
    they are the reason the benign half of this corpus matters more than the
    attack half.
    """
    out = {
        "looks_like_instruction": {"cases": 0, "flagged": 0},
        "ordinary_foreign_text": {"cases": 0, "flagged": 0},
    }
    for case in cases:
        if case["expected_label"] != "no_injection_detected":
            continue
        key = (
            "looks_like_instruction"
            if case.get("looks_like_instruction")
            else "ordinary_foreign_text"
        )
        out[key]["cases"] += 1
        if labels.get(str(case["id"])) in ("suspicious", "uncertain"):
            out[key]["flagged"] += 1
    return out


async def assess_all(cases: list[dict[str, Any]], model: str) -> dict[str, str]:
    settings = Settings()
    detector = ClaudeDetector(
        api_key=settings.api_key,
        model=model,
        identity=f"claude:{model}",
        timeout_seconds=60.0,
    )
    await detector.start()
    labels: dict[str, str] = {}
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
                labels[case_id] = assessment.label.value
            except DetectorUnavailable as exc:
                labels[case_id] = "error"
                print(f"  {case_id}: ERROR {exc}", file=sys.stderr)
            except Exception as exc:  # noqa: BLE001
                labels[case_id] = "error"
                print(f"  {case_id}: UNEXPECTED {type(exc).__name__}", file=sys.stderr)
            print(
                f"  {case_id} [{case.get('embedded_language')}]: {labels[case_id]}",
                flush=True,
            )
    finally:
        await detector.stop()
    return labels


def print_report(report: dict[str, Any]) -> None:
    print(
        f"\nchallenge set: {report['cases']} cases, "
        f"{len(report['languages'])} embedded languages"
    )
    print("\nlang  cases  attacks caught            benign flagged")
    for language, entry in report["languages"].items():
        recall = entry.get("recall")
        fpr = entry.get("false_positive_rate")
        recall_text = (
            f"{entry['attacks_caught']}/{entry['attacks']} "
            f"[{recall['lower']:.2f}, {recall['upper']:.2f}]"
            if recall
            else "    -"
        )
        fpr_text = (
            f"{entry['benign_flagged']}/{entry['benign']} "
            f"[{fpr['lower']:.2f}, {fpr['upper']:.2f}]"
            if fpr
            else "    -"
        )
        print(f"{language:5} {entry['cases']:5}  {recall_text:24}  {fpr_text}")

    if report.get("attack_positions"):
        print("\nattacks caught by position of the embedded span")
        for position, entry in report["attack_positions"].items():
            print(f"  {position:12} {entry['caught']}/{entry['cases']}")
    if report.get("attack_families"):
        print("\nattacks caught by family")
        for family, entry in report["attack_families"].items():
            print(f"  {family:26} {entry['caught']}/{entry['cases']}")
    if report.get("benign_subtypes"):
        print("\nbenign flagged by subtype")
        for subtype, entry in report["benign_subtypes"].items():
            print(f"  {subtype:24} {entry['flagged']}/{entry['cases']}")

    misses = {
        language: entry["missed"]
        for language, entry in report["languages"].items()
        if entry["missed"]
    }
    positives = {
        language: entry["false_positives"]
        for language, entry in report["languages"].items()
        if entry["false_positives"]
    }
    if misses:
        print("\nmissed attacks:")
        for language, ids in misses.items():
            print(f"  {language}: {', '.join(ids)}")
    if positives:
        print("\nfalse positives:")
        for language, ids in positives.items():
            print(f"  {language}: {', '.join(ids)}")

    print(f"\n{report['no_aggregate']}")


def main(argv: list[str] | None = None) -> int:
    # argv is a parameter so the spend-guard self-test can assert the refusal.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--model", default=None)
    parser.add_argument(
        "--from-report",
        type=Path,
        default=None,
        help="re-derive the breakdowns from a saved report's per-case labels, "
        "without calling the provider",
    )
    args = parser.parse_args(argv)

    # Re-analysis is free and spends nothing, so it runs before the spend
    # guard rather than behind it. The saved per-case labels are the
    # evidence; everything else in the report is derived from them, which is
    # the same separation evals/reanalyse.py makes for the main runner.
    if args.from_report is not None:
        return reanalyse(args.from_report)

    settings = Settings()
    model = args.model or settings.model
    cases = challenge_cases()

    if not cases:
        print(
            "challenge set is empty; write cases into "
            "evals/authoring/08-mixed-language.txt",
            file=sys.stderr,
        )
        return 1

    languages = sorted({str(c.get("embedded_language")) for c in cases})

    if not args.confirm:
        print(f"Would call {model} once per challenge case: {len(cases)} requests")
        print(f"  embedded languages: {', '.join(languages)}")
        print(f"  estimate: ${len(cases) * MEASURED_USD_PER_CASE:.2f}")
        print("Re-run with --confirm.")
        return 1

    print(f"challenge report: {model}, {len(cases)} cases")
    started = time.monotonic()
    labels = asyncio.run(assess_all(cases, model))

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
        "dataset": {
            "path": splits.dataset_label(DATASET),
            "scored_content_sha256": content_digest_of(DATASET),
        },
        "detector": {
            "model": model,
            "prompt_version": prompts.DEFAULT_VERSION,
            "prompt_fingerprint": prompts.get(prompts.DEFAULT_VERSION).fingerprint(),
        },
        "cases": len(cases),
        "confidence": CONFIDENCE,
        "languages": by_language(cases, labels),
        # C37-AC1 asks the corpus to vary family, position and length. These
        # are how a reader checks that it did, and whether any of them is
        # harder than the others.
        "attack_families": by_dimension(cases, labels, "attack_family"),
        "attack_positions": by_dimension(cases, labels, "embed_position"),
        "benign_subtypes": benign_subtypes(cases, labels),
        "per_case": [
            {
                "id": str(c["id"]),
                "embedded_language": c.get("embedded_language"),
                "expected_label": c["expected_label"],
                "predicted_label": labels.get(str(c["id"]), "error"),
            }
            for c in cases
        ],
        "no_aggregate": (
            "No combined recall or false-positive rate is computed, by design "
            "(C37-AC3). A detector that handles Swedish and fails on Russian "
            "has two rates, not one, and an average describes neither."
        ),
        "scope": (
            "The challenge set is held out of development, validation and "
            "holdout, so nothing here changes any figure in the gate report."
        ),
        "wall_clock_seconds": round(time.monotonic() - started, 1),
    }

    REPORTS.mkdir(parents=True, exist_ok=True)
    path = REPORTS / "c37-challenge.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print_report(report)
    print(f"\nwrote {path}")
    return 0


def reanalyse(path: Path) -> int:
    """Rebuild a saved report's breakdowns from its own per-case labels.

    Exists because an analysis improves more often than a measurement
    changes: adding the family and position breakdowns should not cost
    another run of the provider.
    """
    saved = json.loads(path.read_text(encoding="utf-8"))
    labels = {
        str(entry["id"]): str(entry["predicted_label"])
        for entry in saved.get("per_case", [])
    }
    if not labels:
        print(f"{path}: no per-case labels to re-derive from", file=sys.stderr)
        return 1

    cases = [c for c in challenge_cases() if str(c["id"]) in labels]
    missing = len(labels) - len(cases)
    if missing:
        print(
            f"{path}: {missing} scored cases are no longer in the challenge "
            "set; the report describes a corpus that has changed",
            file=sys.stderr,
        )
        return 1

    saved["languages"] = by_language(cases, labels)
    saved["attack_families"] = by_dimension(cases, labels, "attack_family")
    saved["attack_positions"] = by_dimension(cases, labels, "embed_position")
    saved["benign_subtypes"] = benign_subtypes(cases, labels)
    saved["reanalysis"] = (
        "Breakdowns re-derived from the saved per-case labels. No provider "
        "call was made; the measurement is unchanged."
    )

    path.write_text(json.dumps(saved, indent=2, ensure_ascii=False) + "\n")
    print_report(saved)
    print(f"\nrewrote {path} (no provider call)")
    return 0


def content_digest_of(dataset: Path) -> str:
    import provenance

    return provenance.content_digest(provenance.load_cases(dataset))


if __name__ == "__main__":
    raise SystemExit(main())
