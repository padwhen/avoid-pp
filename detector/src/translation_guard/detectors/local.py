"""An experimental local classifier adapter. Not in the request path.

C39 asks whether a small model running on this machine could replace, or
screen, the hosted provider call that costs USD 0.009 and 2.8 seconds. This
is the adapter that makes the question measurable; `evals/local_bench.py` is
the measurement and `docs/c39-local-classifiers.md` is the answer.

## Why it is not wired into build_detector

C39-AC3: "a low local score cannot create an untested bypass." The tempting
shape is a cascade - run the free local model first, skip the paid call when
it says clean - and that is exactly a bypass if the local model is weak on
Finnish. Every passage it wrongly calls clean would never reach the detector
that can tell.

So `DetectorMode` has no `local` member and `build_detector` cannot
construct this. Adopting it needs a code change in front of a reviewer, and
a test asserts the gap is still there.

## Why the import is deferred

torch and transformers are an optional dependency group, roughly two
gigabytes installed. Importing them at module scope would make this file
unimportable in the default environment, and therefore make the detector
package unimportable. They are imported inside `start()` instead, where the
failure is a clear message rather than a collection error.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from translation_guard.detectors.base import DetectorUnavailable
from translation_guard.schemas import Assessment, Content, Label


@dataclass(frozen=True, slots=True)
class LocalModel:
    """A pinned classifier, and what is known about it.

    `revision` is a commit sha rather than a branch name. A report that said
    "we measured protectai/deberta-v3-base-prompt-injection-v2" would name a
    moving target; C39-AC1 asks for the revision, and this is where it is
    recorded so the adapter cannot be run against an unpinned one.

    `declared_languages` is what the model card claims, not what it does.
    The whole point of C39 is that no card claims Finnish, so every Finnish
    number here is measured rather than inherited.
    """

    name: str
    revision: str
    license: str
    base_model: str
    declared_languages: tuple[str, ...]
    max_tokens: int
    # The label the model emits for "this is an injection". Varies: some
    # models say INJECTION, others LABEL_1, others JAILBREAK.
    injection_label: str


class LocalDetector:
    """Runs a text-classification model locally.

    Conforms to the same shape as ClaudeDetector - `start`, `assess`, `stop`,
    `identity` - so the evaluation harness can drive either without knowing
    which it has.
    """

    def __init__(self, model: LocalModel, *, threshold: float = 0.5) -> None:
        self._model = model
        self._threshold = threshold
        # Declared here rather than in start(), and as Any, for two
        # reasons: stop() sets them back to None, and the types come from
        # an optional dependency group that the checked environment does
        # not install.
        self._torch: Any | None = None
        self._tokenizer: Any | None = None
        self._net: Any | None = None
        self.identity = f"local:{model.name}@{model.revision[:8]}"
        self.last_diagnostics: Any | None = None

    async def start(self) -> None:
        try:
            import torch  # noqa: PLC0415
            from transformers import (  # noqa: PLC0415
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise DetectorUnavailable(
                "the local classifier needs the optional dependency group: "
                "uv sync --group local"
            ) from exc

        tokenizer = AutoTokenizer.from_pretrained(
            self._model.name, revision=self._model.revision
        )
        model = AutoModelForSequenceClassification.from_pretrained(
            self._model.name, revision=self._model.revision
        )
        model.eval()
        self._torch = torch
        self._tokenizer = tokenizer
        self._net = model

    async def stop(self) -> None:
        self._net = None
        self._tokenizer = None
        self._torch = None

    async def assess(
        self, content: Content, deadline_ms: int | None = None
    ) -> Assessment:
        """Classify one passage.

        Truncation is explicit and recorded rather than silent. The models
        here take 512 tokens; a passage over that would otherwise be cut by
        the tokenizer and scored as though it were whole - the same
        "complete scan of text nobody saw" failure the gateway's coverage
        accounting exists to prevent.
        """
        # Bound to locals so the "started" check narrows all three at once:
        # a half-started detector that had a tokenizer and no network would
        # otherwise fail deeper in, with a worse message.
        net, tokenizer, torch = self._net, self._tokenizer, self._torch
        if net is None or tokenizer is None or torch is None:
            raise DetectorUnavailable("local detector was not started")

        started = time.monotonic()
        encoded = tokenizer(
            content.text,
            return_tensors="pt",
            truncation=True,
            max_length=self._model.max_tokens,
        )
        truncated = int(encoded["input_ids"].shape[1]) >= self._model.max_tokens

        with torch.no_grad():
            logits = net(**encoded).logits
        probabilities = torch.softmax(logits, dim=-1)[0]

        labels = net.config.id2label
        scores = {
            str(labels[index]).upper(): float(probabilities[index])
            for index in range(len(probabilities))
        }
        injection = scores.get(self._model.injection_label.upper(), 0.0)

        self.last_diagnostics = {
            "scores": scores,
            "injection_score": round(injection, 6),
            "latency_ms": int((time.monotonic() - started) * 1000),
            "truncated": truncated,
        }

        # Two labels only. These classifiers have no "uncertain" output, and
        # inventing one from a probability band would be a calibration claim
        # nothing here supports - the same reason the contract has no
        # confidence field.
        return Assessment(
            label=Label.SUSPICIOUS
            if injection >= self._threshold
            else Label.NO_INJECTION_DETECTED,
            categories=[],
            evidence=[],
        )


# The candidates C39 reviewed. Every field is from the Hugging Face model
# API or the model card, checked rather than remembered - an earlier draft
# of the review cited a model that does not exist.
CANDIDATES = (
    LocalModel(
        name="protectai/deberta-v3-base-prompt-injection-v2",
        revision="90c9989b1a342275dd0d1a95aad283c04e075671",
        license="apache-2.0",
        base_model="microsoft/deberta-v3-base",
        declared_languages=("en",),
        max_tokens=512,
        injection_label="INJECTION",
    ),
    LocalModel(
        name="proventra/mdeberta-v3-base-prompt-injection",
        revision="b8a89d3096cf11a71d57b283c854f5ae2ed3df83",
        license="mit",
        base_model="microsoft/mdeberta-v3-base",
        declared_languages=(),
        max_tokens=512,
        injection_label="INJECTION",
    ),
    LocalModel(
        name="Horizon-Labs/prompt-injection-guard-base",
        revision="e4fbfc6f603e24c675cdf310c3b8d7abaa825666",
        license="apache-2.0",
        base_model="jhu-clsp/mmBERT-base",
        declared_languages=(
            "en",
            "de",
            "fr",
            "es",
            "pt",
            "it",
            "nl",
            "pl",
            "ru",
            "uk",
            "tr",
            "ar",
            "hi",
            "zh",
            "ja",
            "ko",
            "vi",
            "id",
            "th",
        ),
        max_tokens=512,
        injection_label="INJECTION",
    ),
)
