"""Keep the frozen holdout out of everything that tunes a prompt.

## What can and cannot be enforced

"The holdout is not used to tune prompts" is a process guarantee, and no
amount of code can make it true: anybody can open the YAML and read it. What
code *can* do is make the safe thing the default and make every exception
leave a record.

So three mechanisms, in descending order of how much they actually prevent:

  1. **The default excludes it.** Every evaluation runs on development plus
     validation unless the holdout is named explicitly. Nobody touches the
     holdout by forgetting something.
  2. **Every access is logged**, with the prompt fingerprint that was current
     at the time. That turns the guarantee into something checkable: a
     holdout result is only meaningful if the prompt had not changed since,
     and the log shows whether it had.
  3. **The frozen manifest is digested.** If the holdout's membership changes
     after freezing, the digest changes, and a result claimed against the
     frozen holdout can be shown not to be one.

Mechanism 2 is the one that does the real work. It cannot stop the holdout
being used badly, but it makes using it badly leave evidence - and a
guarantee nobody can check is not a guarantee.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "manifests" / "splits.json"
ACCESS_LOG = ROOT / "manifests" / "holdout-access.jsonl"

# The splits an evaluation uses unless told otherwise.
DEFAULT_SPLITS = ("development", "validation")


class HoldoutNotFrozen(Exception):
    """The holdout was requested before a manifest was frozen."""


class HoldoutChanged(Exception):
    """The holdout's membership differs from the frozen manifest."""


@dataclass(frozen=True)
class FrozenHoldout:
    case_ids: frozenset[str]
    id_sha256: str
    frozen_at: str
    dataset_sha256: str


def load_frozen(manifest: Path = MANIFEST) -> FrozenHoldout:
    """Read the frozen holdout membership.

    Ids only. Reading the manifest must not mean reading the passages, or the
    file designed to protect the holdout would be a way around it.
    """
    if not manifest.exists():
        raise HoldoutNotFrozen(
            f"no frozen manifest at {manifest}. Run `make splits-freeze` once "
            "the corpus is large enough; until then there is no holdout to "
            "protect and no holdout result to claim."
        )
    document = json.loads(manifest.read_text(encoding="utf-8"))
    entry = document["splits"]["holdout"]
    return FrozenHoldout(
        case_ids=frozenset(entry["case_ids"]),
        id_sha256=entry["id_sha256"],
        frozen_at=document["generated_at"],
        dataset_sha256=document["dataset"]["sha256"],
    )


def verify_unchanged(current_ids: set[str], manifest: Path = MANIFEST) -> FrozenHoldout:
    """Check that the holdout still contains exactly what was frozen.

    A holdout that gained cases is not the frozen holdout, and a result
    claimed against it is not a holdout result. This is what makes the freeze
    mean something: the assignment function is stable, so a change here means
    a case was edited, renamed or regrouped, and that is worth refusing over.
    """
    frozen = load_frozen(manifest)
    digest = hashlib.sha256("\n".join(sorted(current_ids)).encode()).hexdigest()
    if digest != frozen.id_sha256:
        added = sorted(current_ids - frozen.case_ids)
        removed = sorted(frozen.case_ids - current_ids)
        detail = []
        if added:
            detail.append(f"{len(added)} added ({', '.join(added[:5])}...)")
        if removed:
            detail.append(f"{len(removed)} removed ({', '.join(removed[:5])}...)")
        raise HoldoutChanged(
            f"the holdout differs from the manifest frozen at {frozen.frozen_at}: "
            + "; ".join(detail or ["membership digest differs"])
        )
    return frozen


def record_access(
    *,
    reason: str,
    prompt_version: str,
    prompt_fingerprint: str | None,
    model: str | None,
    case_count: int,
    log: Path = ACCESS_LOG,
) -> dict[str, Any]:
    """Append a line recording that the holdout was read.

    Append-only JSONL, committed to the repository. The point is not that the
    log cannot be edited - it can - but that editing it is a deliberate act
    that shows up in a diff, whereas quietly evaluating against the holdout
    while iterating on a prompt does not.

    The prompt fingerprint is the field that matters. A holdout result is only
    a holdout result if the prompt was frozen beforehand, and the fingerprints
    in this log are what demonstrate it.
    """
    entry = {
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        "reason": reason,
        "prompt_version": prompt_version,
        "prompt_fingerprint": prompt_fingerprint,
        "model": model,
        "holdout_cases": case_count,
    }
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def access_history(log: Path = ACCESS_LOG) -> list[dict[str, Any]]:
    if not log.exists():
        return []
    return [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def prompt_changed_since_last_access(
    prompt_fingerprint: str | None, log: Path = ACCESS_LOG
) -> bool:
    """Whether the prompt has changed since the holdout was last read.

    If it has not, repeated holdout runs are measuring the same frozen prompt
    and are fine. If it has, the holdout has now informed a prompt change -
    which is the thing it exists not to do, and the caller should say so
    rather than quietly reporting a number.
    """
    history = access_history(log)
    if not history:
        return False
    return history[-1].get("prompt_fingerprint") != prompt_fingerprint
