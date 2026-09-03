"""The bound a producer string is under before either verdict renders it.

``receipt.cli`` truncates every result-derived string it prints, so a
release manifest with a million-character ``schemaVersion`` cannot scroll a
verdict away. ``receipt.corpus`` charges every producer string against a
budget, so a journal cannot fill a verdict with legal ones. Those are two
statements about the same rendering, and they were made by two pieces of
code that did not know about each other: the corpus charged the string the
producer wrote, and the CLI printed the string this module returns. The
accounting and the rendering therefore disagreed in both directions — a
gate whose evidence renders to well under the cap once bounded was refused
for a charge nothing would ever print, and the charge for a gate that
passed was not the length of what appeared (peer review, Sol round 3).

So the transformation lives here, in one module both import, and the charge
is made on its output. What ``receipt.corpus`` charges is now the string
``receipt.cli`` renders, character for character, and a test asserts the
equality on a near-cap journal rather than leaving it to be believed.

This module holds the transformation and nothing else: no schema, no
filesystem, no trust anchors. It imports the standard library alone, which
is what lets both of those modules import it.
"""

from __future__ import annotations

import hashlib
import json.encoder

#: The most characters of any one result-derived string either renderer
#: prints. The corpus schema bounds what a *producer* can put in a verdict —
#: ``MAX_EVIDENCE_TEXT`` per string, ``MAX_GATE_TEXT`` and
#: ``MAX_REMOVED_TEXT`` per section — and those bounds cover corpus-derived
#: output only. Nothing bounded the custody half: a release manifest whose
#: ``schemaVersion`` is a million characters puts that value into a
#: ``ReleaseChainError`` before the signature is ever checked, and the text
#: renderer printed it twice — once on the pass line and once after
#: ``VERDICT: FAIL`` — while the JSON printed it once (peer review, round
#: eight). Bounding at the schema boundary of every library the command
#: calls is not the answer: ``receipt.release_chain``'s wording is pinned
#: byte for byte by a differential harness. So the bound is here, at the one
#: place a verdict is rendered, and it is global — every result-derived
#: string in either renderer, not a list of the fields someone thought of.
#:
#: What is bounded is what the command *prints*, not what the library
#: raises. ``receipt.release_chain`` and ``receipt.corpus`` still raise their
#: full text, and a machine consumer that needs all of it can call the
#: library directly rather than parse the command's output.
#:
#: Four thousand and ninety-six is generous for anything a verdict
#: legitimately carries — sixteen times the 256 ``receipt.corpus._quoted``
#: allows a refusal to quote — and small enough that the whole verdict stays
#: readable in a terminal.
MAX_RENDERED_FIELD = 4096


def encoded_length(character: str) -> int:
    """What ``json.dumps`` emits for one character, its quotes excluded.

    Taken from the escaper ``json.dumps`` applies rather than guessed at,
    the way ``receipt.corpus._rendered_length`` takes it: with
    ``ensure_ascii`` at its default one BMP character outside ASCII leaves
    as six characters and one outside the BMP as twelve, a surrogate pair
    spelled ``\\uXXXX\\uXXXX``.
    """

    return len(json.encoder.encode_basestring_ascii(character)) - 2


def encoded_split(text: str) -> tuple[str, int] | None:
    """The longest prefix whose encoding fits the bound, and what it dropped.

    ``None`` when the whole string fits. Accumulated one character at a time
    and stopped at the first character that carries the total over, so the
    work is bounded by the limit rather than by the length of the string.
    """

    total = 0
    for index, character in enumerate(text):
        total += encoded_length(character)
        if total > MAX_RENDERED_FIELD:
            return text[:index], len(text) - index
    return None


def bounded_encoded(text: str) -> str:
    """Truncate one JSON string value to :data:`MAX_RENDERED_FIELD` *encoded*.

    The bound counted Python characters on both sides of the renderer, and
    on the JSON side that is not what the verdict carries. ``json.dumps``
    escapes with ``ensure_ascii`` on, so a value bounded to 4,096 code
    points outside the BMP renders as 49,152 characters — a flood twelve
    times the bound, assembled out of a string the bound had already
    accepted (peer review, Sol round 2). This measures each character as
    the encoder will emit it and truncates by that length, so no string
    value's rendering exceeds the bound plus the marker.

    The text renderer keeps counting the characters it prints, because
    that is what a terminal receives: see ``receipt.cli._bounded``.
    """

    split = encoded_split(text)
    if split is None:
        return text
    prefix, omitted = split
    return f"{prefix}…[{omitted} more characters]"


def key_digest(key: str) -> str:
    """The SHA-256 of a key's UTF-8, as hex.

    ``surrogatepass``, because a key that reached here from a filesystem
    name may carry a lone surrogate and a digest that raises would defeat
    the renderer it protects.
    """

    return hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()


def bounded_key(key: str) -> str:
    """The same bound for a JSON object key, made collision-proof by digest.

    Keys were left unbounded, and the reason given was a real one: two long
    keys truncated to the same text collide, and one silently replaces the
    other, which turns a length policy into a data-loss policy. What was
    wrong was the conclusion. A gate evidence key may be 1,024 characters
    under ``receipt.corpus.MAX_EVIDENCE_TEXT``, and 1,024 characters outside
    the BMP render as 12,288 — a key alone can scroll the verdict away, and
    ``receipt.cli._bounded_payload`` never looked at one (peer review, Sol
    round 2).

    So a key is bounded like a value and then made unambiguous: the marker
    carries the SHA-256 of the whole key, so two keys sharing a bounded
    prefix differ in the marker.
    """

    split = encoded_split(key)
    if split is None:
        return key
    prefix, omitted = split
    digest = key_digest(key)
    return f"{prefix}…[{omitted} more characters; sha256 {digest[:16]}]"
