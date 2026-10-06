"""The pinned Unicode format-control table, so what a verdict may print
does not move.

One table lives here, :data:`FORMAT_CONTROL_RANGES`: Unicode 16.0's general
category ``Cf``. It is consulted by two modules, which is why it is not in
either of them. ``receipt.corpus`` refuses producer text — a gate id, an
evidence key or value, a not-run reason — carrying one of these code points
at the schema boundary; ``receipt.cli`` escapes the same set on its way to a
terminal, because ``receipt.release_chain``'s wording is pinned byte for byte
by a differential harness and cannot be screened at its own boundary.

What makes the class worth refusing is that a format control prints as
nothing while changing what a reader sees. U+202E RIGHT-TO-LEFT OVERRIDE
reverses the remainder of a line, so a gate declared not-run can be spelled
to read as passed; U+200B lets two evidence keys print identically.

The table is pinned in the *widening* direction, which is the safe one for
this job: a code point refuses if it is in this table **or** the running
interpreter calls it ``Cf``, so a newer interpreter can only add to the set.
Asking the running table alone made the refusal version-dependent — U+1343A
is unassigned under the Unicode 14 that Python 3.11 ships and ``Cf`` under
3.12's — and in the direction that lets the same journal pass on one
supported interpreter and fail on the next (peer review).

Two further tables lived here and do not any more: Unicode 14.0's ``Cn`` set
and its ``Default_Ignorable_Code_Point`` set, both consulted by
``receipt.corpus``'s screen on *filesystem names*. That screen is now the
portable-name policy — ASCII letters, digits, ``.``, ``_`` and ``-`` — under
which an unassigned code point and a default-ignorable one are both refused
by the repertoire itself, with no table to consult and no interpreter to
disagree with. ``receipt.corpus``'s module docstring says why the policy
replaced the modelling; the tables went with the questions they answered.
"""

from __future__ import annotations

#: Unicode category ``Cf`` as of Unicode 16.0.0, the table Python 3.14 ships.
#: Pinned so the refusal does not depend on which interpreter renders the
#: verdict: Python 3.11 carries Unicode 14, under which U+1343A is unassigned
#: and passed while 3.12 and 3.13 refused it (peer review). A code point
#: refuses if it is in this table OR the running interpreter's table calls it
#: ``Cf``, so a later table can only widen the set, never narrow it.
#:
#: Lives here rather than in ``receipt.corpus`` because two modules screen
#: against it: the schema boundary, which refuses producer text carrying one,
#: and ``receipt.cli``'s text renderer, which escapes one on its way to a
#: terminal. The contents are what ``receipt.corpus._FORMAT_CONTROL_RANGES``
#: held before the move, unchanged.
FORMAT_CONTROL_RANGES: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD), (0x0600, 0x0605), (0x061C, 0x061C), (0x06DD, 0x06DD),
    (0x070F, 0x070F), (0x0890, 0x0891), (0x08E2, 0x08E2), (0x180E, 0x180E),
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x206F),
    (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0x110BD, 0x110BD), (0x110CD, 0x110CD),
    (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001), (0xE0020, 0xE007F),
)
