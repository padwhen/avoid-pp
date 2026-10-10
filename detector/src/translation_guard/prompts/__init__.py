"""Versioned detector prompts, loaded from files rather than source strings.

A prompt is content, not code. Keeping it in a file makes a change reviewable
as a diff, and makes "which prompt produced this result" answerable by
checking out the commit a report names.

Each version is immutable once a measurement has been recorded against it.
Changing the wording means a new version, because an evaluation report that
names `translate_fi_en-v1` is a claim about those exact bytes. `fingerprint()`
exists so that claim can be checked rather than trusted: the test suite pins
the hash of every measured version, and editing the file in place fails the
build instead of silently invalidating a saved number.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from pathlib import Path

PROMPT_DIR = Path(__file__).resolve().parent


class UnknownPromptVersion(KeyError):
    """No prompt is registered under that version."""


@dataclass(frozen=True)
class Prompt:
    """One versioned prompt: a system instruction and a user template."""

    version: str
    system: str
    user_template: str

    @property
    def uses_nonce(self) -> bool:
        """Whether this version's markers carry a per-request token."""
        return "{nonce}" in self.user_template

    def render_user(
        self,
        *,
        content_id: str,
        language_hint: str,
        text: str,
        nonce: str | None = None,
    ) -> str:
        """Fill the template.

        The passage is substituted into a template rather than concatenated
        into the system instruction, so the boundary between task rules and
        untrusted data stays where it was designed to be.

        A version whose markers carry a nonce gets a fresh random one unless
        the caller supplies it, which only tests do. The nonce is why the
        boundary holds: v1's `</passage>` can be written by the passage
        itself, and a passage that closes the marker places its own text
        outside the data region, at the same level as the instructions. With
        a random token the passage cannot close anything, because it cannot
        know the token.

        v1 is unchanged and takes no nonce. Its bytes are what the C26
        measurement was produced with, and this module's rule is that a
        measured version is immutable.
        """
        if not self.uses_nonce:
            return self.user_template.format(
                content_id=content_id,
                language_hint=language_hint,
                text=text,
            )

        # 128 bits. The passage is bounded at 32 KiB, so guessing is not a
        # consideration; what matters is that it is unpredictable per request
        # rather than a constant an attacker can read in this file.
        token = nonce or secrets.token_hex(16)
        return self.user_template.format(
            content_id=content_id,
            language_hint=language_hint,
            text=text,
            nonce=token,
        )

    def fingerprint(self) -> str:
        """SHA-256 over both halves. Changes if a single byte does."""
        digest = hashlib.sha256()
        digest.update(self.system.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(self.user_template.encode("utf-8"))
        return digest.hexdigest()


def _load(task: str, version: str) -> Prompt:
    base = PROMPT_DIR / task
    system = base / f"{version}.system.md"
    user = base / f"{version}.user.md"
    if not system.is_file() or not user.is_file():
        raise UnknownPromptVersion(f"{task}-{version}")
    return Prompt(
        version=f"{task}-{version}",
        # Files end with a trailing newline that the original strings did not
        # have. Stripping it keeps the bytes sent to the provider identical to
        # the ones the recorded measurement was produced with.
        system=system.read_text(encoding="utf-8").rstrip("\n"),
        user_template=user.read_text(encoding="utf-8").rstrip("\n"),
    )


def get(version: str) -> Prompt:
    """Resolve a prompt by its full version string, e.g. translate_fi_en-v1."""
    task, _, suffix = version.rpartition("-")
    if not task or not suffix:
        raise UnknownPromptVersion(version)
    return _load(task, suffix)


def available() -> list[str]:
    """Every registered version, for diagnostics and tests."""
    versions: list[str] = []
    for task_dir in sorted(p for p in PROMPT_DIR.iterdir() if p.is_dir()):
        if task_dir.name == "__pycache__":
            continue
        for system_file in sorted(task_dir.glob("*.system.md")):
            versions.append(f"{task_dir.name}-{system_file.name.split('.')[0]}")
    return versions


# The default for the first supported task.
#
# Still v1, deliberately. v2 fixes a structural weakness - a passage can close
# v1's `</passage>` marker and place its own text outside the data region -
# but the weakness is not currently exploitable against claude-opus-5, which
# labels the attempt suspicious and quotes the escaped text as evidence.
#
# Switching the default would invalidate the C26 measurement, because that
# measurement is a claim about v1's exact bytes. Adopting v2 means re-running
# the development evaluation, which is a decision with a cost rather than a
# silent prompt change. Until then v2 is available, tested, and unmeasured -
# and the report would say so.
DEFAULT_VERSION = "translate_fi_en-v1"
