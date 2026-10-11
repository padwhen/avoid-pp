"""Every AVOIDPP_* variable named in the documentation must be one the code reads.

C35 wrote a runbook telling an operator to set
`AVOIDPP_DETECTOR_MAX_SOURCE_TOKENS`. No such variable exists: the token
budget is a constant in limits.py with no Settings field behind it. The
runbook drills could not catch it, because they exercise the commands in the
drill script and that one was only in the prose.

A runbook naming a variable nothing reads is worse than no runbook. It sends
someone to edit a Deployment, watch the pod roll, and conclude the change did
not take effect for some other reason.

So the documentation is checked against the code. Two sources of truth:

  * the gateway's Env* constants in gateway/internal/config
  * the detector's Settings fields, which pydantic prefixes AVOIDPP_DETECTOR_

A third category arrived with the Fly deployment: AVOIDPP_URL and AVOIDPP_KEY
are read by the application calling the gateway, not by anything here. Those
are listed separately from the absent ones, because "nothing reads this" and
"the caller reads this" are different claims and merging them would turn the
absent list into a place to put anything that fails the check.

A name may be absent from all of them only if it is listed below as
deliberately documented-as-missing.

The first run of this check found a second name, and it was the checker that
was wrong: AVOIDPP_HOST_PORT is real and is read by Compose and the Makefile
rather than by either service. "Read by the code" has to mean the whole
repository, not just the two config modules - so orchestration files count
as readers too.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Searched for AVOIDPP_* mentions.
DOC_GLOBS = ("docs/*.md", "deploy/**/*.md", "README.md", "deploy/**/*.yaml")

# Names the documentation mentions precisely because they do *not* exist.
# Each needs a reason, so removing one is a decision rather than a tidy-up.
DOCUMENTED_AS_ABSENT = {
    # C35 runbook 5 and its closing section: the token budget is hardcoded,
    # and saying so is the point of the passage that names it.
    "AVOIDPP_DETECTOR_MAX_SOURCE_TOKENS": "C35 names it to say it does not exist",
}

# Names that belong to a *caller* of this service rather than to the service.
#
# A third category, separate from DOCUMENTED_AS_ABSENT because it is a
# different claim. "Nothing reads this" and "the application on the other end
# of the client reads this" are not the same statement, and collapsing them
# would make the absent list a place to put anything the checker complains
# about. The deployment documentation has to name these, because telling an
# operator to deploy the gateway without telling them what the caller needs
# is half an instruction.
READ_BY_A_CALLER = {
    "AVOIDPP_URL": "the gateway address, read by the integrating application",
    "AVOIDPP_KEY": "the caller's own credential, read by the integrating application",
}


def gateway_variables() -> set[str]:
    """Every string constant in the gateway's config package."""
    found: set[str] = set()
    for path in (ROOT / "gateway" / "internal" / "config").glob("*.go"):
        found |= set(re.findall(r'"(AVOIDPP_[A-Z0-9_]+)"', path.read_text()))
    return found


def detector_variables() -> set[str]:
    """Settings fields, with the pydantic env prefix applied."""
    source = (ROOT / "detector" / "src" / "translation_guard" / "config.py").read_text()
    prefix_match = re.search(r'env_prefix="([A-Z_]+)"', source)
    prefix = prefix_match.group(1) if prefix_match else "AVOIDPP_DETECTOR_"

    found = {
        prefix + name.upper()
        for name in re.findall(r"^    ([a-z_]+):\s", source, re.MULTILINE)
    }
    # An aliased field is read under the alias, not the prefixed name.
    found |= set(re.findall(r'alias="([A-Z_]+)"', source))
    return found


def orchestration_variables() -> set[str]:
    """Names substituted by Compose, the Makefile or the deployment scripts.

    A variable the gateway never sees can still be real: AVOIDPP_HOST_PORT
    decides which host port Compose publishes, and nothing in Go or Python
    reads it.
    """
    found: set[str] = set()
    for pattern in ("compose.yaml", "Makefile", "scripts/*.sh", "deploy/**/*.sh"):
        for path in ROOT.glob(pattern):
            text = path.read_text()
            # ${VAR...} in Compose and shell, $${VAR...} in a Makefile recipe.
            found |= set(re.findall(r"\$\$?\{(AVOIDPP_[A-Z0-9_]+)", text))
            found |= set(re.findall(r"\$\((AVOIDPP_[A-Z0-9_]+)\)", text))
    return found


def documented() -> dict[str, set[Path]]:
    """Every AVOIDPP_* mention, and where it was found."""
    mentions: dict[str, set[Path]] = {}
    for pattern in DOC_GLOBS:
        for path in ROOT.glob(pattern):
            for name in re.findall(r"\bAVOIDPP_[A-Z0-9_]+", path.read_text()):
                mentions.setdefault(name, set()).add(path.relative_to(ROOT))
    return mentions


def main() -> int:
    known = gateway_variables() | detector_variables() | orchestration_variables()
    problems: list[str] = []

    for name, paths in sorted(documented().items()):
        if name in known or name in DOCUMENTED_AS_ABSENT or name in READ_BY_A_CALLER:
            continue
        where = ", ".join(sorted(str(p) for p in paths))
        problems.append(f"{name}: named in {where}, read by nothing")

    # And the other direction, loosely: an allowlisted name that has since
    # become real is an allowlist entry nobody removed.
    for name, reason in sorted(DOCUMENTED_AS_ABSENT.items()):
        if name in known:
            problems.append(
                f"{name}: listed as absent ({reason}) but the code now reads it"
            )
    for name, reason in sorted(READ_BY_A_CALLER.items()):
        if name in known:
            problems.append(
                f"{name}: listed as a caller's variable ({reason}) but this "
                "repository now reads it too"
            )

    if problems:
        print(
            f"documented environment variables: {len(problems)} problem(s)",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(
        f"documented environment variables: {len(documented())} named, all read "
        f"by the gateway config,\n"
        f"                                  the detector settings, Compose or "
        f"the Makefile\n"
        f"                                  "
        f"({len(DOCUMENTED_AS_ABSENT)} deliberately documented as absent, "
        f"{len(READ_BY_A_CALLER)} a caller's)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
