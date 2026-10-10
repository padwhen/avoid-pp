"""Render a translation as text, never as markup.

## Why this is a security boundary and not a formatting concern

The translator's output is a faithful translation of attacker-controlled
input. If the source contains `<script>alert(1)</script>`, a faithful
translation contains it too - that is the translator working correctly, not
failing. The guard's job was to decide whether the passage was an *injection
against the translator*; it was never to decide whether the text is safe to
paste into a document.

So there are two different safety questions and only one of them is the
guard's:

  * Does this passage try to redirect the translator?  -> the detector
  * Is this text safe to render as HTML?               -> here, and it is not

A caller that renders a translation as markup has a cross-site scripting hole
whatever the detector said, including on a passage the detector correctly
labelled clean - because `<script>` in ordinary Finnish prose is not a prompt
injection and the detector should not flag it.

## Escape rather than strip

Stripping tags would silently alter the translation, and a translation that
quietly lost content is the failure this project spends most of its effort
avoiding. Escaping preserves every character and renders it inert: the reader
sees `<script>` as text, which is what the source said.

The five XML entities, not html.escape's default. html.escape leaves the
single quote alone unless asked, and an unescaped apostrophe inside a
single-quoted attribute is an attribute-injection hole.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from examples.protected_translator.translator import Translation

# All five, always. The ampersand must be first or it would double-escape the
# entities introduced after it.
_ESCAPES = (
    ("&", "&amp;"),
    ("<", "&lt;"),
    (">", "&gt;"),
    ('"', "&quot;"),
    ("'", "&#x27;"),
)


def escape_html(text: str) -> str:
    """Make text inert as HTML while preserving every character."""
    for character, entity in _ESCAPES:
        text = text.replace(character, entity)
    return text


def as_plain_text(translation: Translation) -> str:
    """The translation as text, unchanged.

    This is the right answer for most callers: a JSON field, a plain-text
    response body, a terminal. Nothing is escaped because nothing is being
    interpreted.
    """
    return translation.text


def as_html_fragment(translation: Translation) -> str:
    """The translation inside a paragraph, escaped.

    For a caller that has decided to put it in a page. The content is escaped;
    the surrounding element is ours.
    """
    return f"<p>{escape_html(translation.text)}</p>"


def as_json_response(translation: Translation) -> str:
    """A JSON body.

    json.dumps with ensure_ascii=False, so Finnish survives as Finnish rather
    than as escape sequences - the corpus exists to test characters that
    careless pipelines damage, and a renderer that mangles them would be one.

    The translation goes in a field of its own. It is never interpolated into
    a string that something else parses.
    """
    return json.dumps(
        {
            "task_id": translation.task_id,
            "target_language": translation.target_language,
            "translation": translation.text,
            "model": translation.model,
            "latency_ms": translation.latency_ms,
        },
        ensure_ascii=False,
    )


@dataclass(frozen=True)
class RenderedTranslation:
    """A translation with its rendering already decided.

    Returning this rather than a bare string makes the choice explicit at the
    call site. A caller that wants markup has to say so, and a caller that
    says nothing gets text - which is the safe default rather than the
    convenient one.
    """

    text: str
    html: str
    json: str

    @classmethod
    def of(cls, translation: Translation) -> RenderedTranslation:
        return cls(
            text=as_plain_text(translation),
            html=as_html_fragment(translation),
            json=as_json_response(translation),
        )
