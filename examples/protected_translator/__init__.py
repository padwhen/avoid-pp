"""The thing being protected.

This is a deliberately boring Finnish-to-English translator. It exists so the
guard has something real to sit in front of, and so the integration at C28 is
a wiring exercise against working code rather than a thought experiment.

It is *not* part of the guard. Nothing here inspects a passage for attacks,
and nothing here makes a policy decision - that is the gateway's job, and
mixing the two would make the example useless as a demonstration of how a
caller integrates.
"""

from examples.protected_translator.translator import (
    ClaudeTranslator,
    FakeTranslator,
    Translation,
    TranslationRefused,
    TranslationRejected,
    TranslationUnavailable,
    Translator,
    TranslatorConfig,
)

__all__ = [
    "ClaudeTranslator",
    "FakeTranslator",
    "Translation",
    "TranslationRefused",
    "TranslationRejected",
    "TranslationUnavailable",
    "Translator",
    "TranslatorConfig",
]
