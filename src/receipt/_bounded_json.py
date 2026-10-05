"""JSON decoding with two fixed ceilings that the input alone can exceed.

``json.loads`` already refuses some inputs with something other than
``JSONDecodeError``, and neither limit is stated by the bytes:

* nesting is bounded by the interpreter's recursion limit and, from Python
  3.14, by the C stack the calling thread has left, so one file parses in one
  call context and raises ``RecursionError`` in another. ``RecursionError`` is
  not a ``ValueError``, so it escaped every verifier's refusal handler;
* an integer literal is bounded by ``sys.get_int_max_str_digits()``, 4,300
  digits unless the process changed it, and raises a plain ``ValueError``
  that the handlers, which caught ``JSONDecodeError``, also let through.

A producer-written file could therefore end a verification with an
interpreter exception instead of the module's refusal. Several modules
decode producer bytes, so the two bounds are stated once, here:

* ``MAX_DEPTH`` open containers (arrays and objects together). 128 is also
  ``serde_json``'s default recursion limit (which admits 127 levels), and it
  is well below the recursion ``receipt.canonical`` needs for the same value
  (two frames per list level), so a decoded value can be canonicalised when
  the caller has an ordinary stack left;
* ``MAX_INTEGER_DIGITS`` digits in one integer literal, the interpreter's own
  default, enforced by a ``parse_int`` hook so that it holds whatever the
  process configured.

The ceilings are fixed; acceptance below them is not wholly independent of
context. ``json.loads`` can still exhaust the caller's remaining stack, or a
process can lower its integer-digit limit below ``MAX_INTEGER_DIGITS``, on
text under both ceilings. Those failures are raised as ``JsonBoundError``
too, so a caller gets this module's refusal and never an interpreter
exception, but whether such text is accepted depends on where it is read.

Everything else is ``json.loads``: the same grammar, the same values and, for
malformed text, the same ``JSONDecodeError`` with the same message. A
document is refused for depth only if ``json.loads`` did not refuse it first,
so the decode error a malformed file always reported is still the one it
reports. What the bound does change is deliberate: text nested more than
``MAX_DEPTH`` deep is refused even where ``json.loads`` would have parsed it,
so a caller that accepted such a value, or refused it later for its shape,
now refuses it here, by this reason, on every interpreter alike.

This module imports the standard library alone, so any module may use it.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

#: Most containers one JSON value may nest, arrays and objects counted
#: together. ``[[]]`` has depth 2.
MAX_DEPTH = 128

#: Most digits in one integer literal, a leading minus sign not counted.
MAX_INTEGER_DIGITS = 4300

# One string token, closed or running to the end of the text, or one bracket.
# Within a string, ``\\.`` consumes an escape, so ``\"`` does not close it and
# a bracket inside a string is never counted. For text ``json.loads`` accepts
# this reads exactly its containers; for other text it reads the same
# containers up to the point where ``json.loads`` stops.
_STRUCTURE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"?|[\[\]{}]')


class JsonBoundError(ValueError):
    """A JSON text is refused by one of this module's bounds."""


def _first_excess(text: str) -> int | None:
    """Offset of the bracket that opens container ``MAX_DEPTH + 1``, if any."""

    depth = 0
    for match in _STRUCTURE.finditer(text):
        token = match.group()
        if token in ("[", "{"):
            depth += 1
            if depth > MAX_DEPTH:
                return match.start()
        elif token in ("]", "}"):
            depth = max(depth - 1, 0)
    return None


def _parse_int(literal: str) -> int:
    digits = len(literal) - literal.startswith("-")
    if digits > MAX_INTEGER_DIGITS:
        raise JsonBoundError(
            f"JSON integer literal has {digits} digits, more than "
            f"{MAX_INTEGER_DIGITS}"
        )
    try:
        return int(literal)
    except ValueError as exc:
        # A process that lowered its own int-string limit below ours.
        raise JsonBoundError(
            f"JSON integer literal has {digits} digits, more than this "
            "interpreter converts"
        ) from exc


def loads(
    text: str,
    *,
    object_pairs_hook: Callable[[list[tuple[str, Any]]], Any] | None = None,
    parse_constant: Callable[[str], Any] | None = None,
) -> Any:
    """``json.loads(text)`` under ``MAX_DEPTH`` and ``MAX_INTEGER_DIGITS``.

    Raises ``json.JSONDecodeError`` exactly where ``json.loads`` does, and
    ``JsonBoundError`` for text nested deeper than ``MAX_DEPTH`` or holding an
    integer literal longer than ``MAX_INTEGER_DIGITS`` digits. Whatever the two
    hooks raise passes through unchanged.
    """

    excess = _first_excess(text)
    try:
        value = json.loads(
            text,
            parse_int=_parse_int,
            object_pairs_hook=object_pairs_hook,
            parse_constant=parse_constant,
        )
    except RecursionError:
        # Text deeper than MAX_DEPTH that json.loads did not refuse first. A
        # caller already near the interpreter's limit can land here on
        # shallower text; that is refused too, under its own reason, rather
        # than the interpreter's exception passed on.
        if excess is None:
            raise JsonBoundError(
                "JSON nesting exhausted the interpreter's recursion limit"
            ) from None
        raise JsonBoundError(_too_deep(excess)) from None
    if excess is not None:
        raise JsonBoundError(_too_deep(excess))
    return value


def _too_deep(offset: int) -> str:
    return f"JSON nesting exceeds {MAX_DEPTH} levels at char {offset}"
