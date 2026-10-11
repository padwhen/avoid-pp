"""Assert that no money-spending tool runs without explicit confirmation.

This exists because one of them did. An indentation mistake in a string
replacement moved `return 1` inside an unrelated `if`, so
`evals/outcome_eval.py` fell through its confirmation check and made 396
provider calls - about $1.60 - when it had been asked only for an estimate.

The guard had no test, so nothing noticed. A confirmation check is a safety
property, and a safety property without a test is a comment.

Each tool is invoked in-process with no confirmation flag and must:

  * return a non-zero exit code;
  * print an estimate;
  * make no provider call.

The third is the one that matters, so it is enforced rather than inspected:
the provider client is replaced with one that fails the test if it is
constructed at all.

Run with `make check-spend-guards`.
"""

from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent))


class ProviderContacted(AssertionError):
    """A tool reached for the provider without confirmation."""


def _poison_provider() -> None:
    """Make any provider client construction fail loudly.

    Patching the SDK rather than checking afterwards: a tool that constructs
    a client has already decided to spend, and the point is to catch the
    decision rather than the invoice.
    """
    import anthropic

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise ProviderContacted("a provider client was constructed without --confirm")

    anthropic.AsyncAnthropic = refuse  # type: ignore[assignment]
    anthropic.Anthropic = refuse  # type: ignore[assignment]


# Each entry: a label, the module path, and the argv that must be refused.
TOOLS = [
    ("outcome_eval", "outcome_eval", []),
    ("outcome_eval --attacks-only", "outcome_eval", ["--attacks-only"]),
    ("outcome_eval --limit 5", "outcome_eval", ["--limit", "5"]),
    ("live_eval", "live_eval", []),
    ("live_eval --limit 3", "live_eval", ["--limit", "3"]),
    ("provider_profile", "provider_profile", []),
    ("provider_profile --reps 1", "provider_profile", ["--reps", "1"]),
]


def check(label: str, module_name: str, argv: list[str], failures: list[str]) -> None:
    import importlib

    module = importlib.import_module(module_name)
    captured = io.StringIO()

    try:
        with redirect_stdout(captured):
            code = module.main(argv)
    except ProviderContacted as exc:
        failures.append(f"{label}: {exc}")
        return
    except SystemExit as exc:  # a tool that exits rather than returns
        code = int(exc.code or 0)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{label}: raised {type(exc).__name__}: {exc}")
        return

    output = captured.getvalue()

    if code == 0:
        failures.append(
            f"{label}: returned 0 without confirmation, so a caller scripting "
            "it would not know it had been refused"
        )
    # An estimate is the whole point of the dry run: a refusal that does not
    # say what the run would cost is a refusal the user cannot act on.
    if "$" not in output:
        failures.append(f"{label}: refused without printing a cost estimate")
    if "confirm" not in output.lower():
        failures.append(f"{label}: refused without saying how to proceed")


def main() -> int:
    _poison_provider()
    failures: list[str] = []

    for label, module_name, argv in TOOLS:
        check(label, module_name, argv, failures)

    # And the holdout refusal, which is a different guard with the same shape:
    # a tool that reads the holdout must refuse even *with* confirmation.
    import importlib

    outcome_eval = importlib.import_module("outcome_eval")
    captured = io.StringIO()
    try:
        with redirect_stdout(captured):
            code = outcome_eval.main(["--confirm", "--splits", "holdout"])
    except ProviderContacted as exc:
        failures.append(f"outcome_eval --splits holdout: {exc}")
        code = 1
    if code == 0:
        failures.append(
            "outcome_eval ran on the holdout with --confirm; outcome grading "
            "is iterative and the holdout is read once"
        )

    if failures:
        print(f"spend guards: {len(failures)} failure(s)", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(f"spend guards: {len(TOOLS)} tools refuse without confirmation,")
    print("              each prints an estimate, none contacts the provider;")
    print("              outcome grading refuses the holdout even with --confirm")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
