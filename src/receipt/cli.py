"""``receipt verify`` — the outside auditor's command.

A clone, commodity tools, one offline fail-closed verdict. No network, no
credentials, no service to ask. Everything the command trusts arrives from the
consumer's committed spec, named on the command line, and the spec's own
SHA-256 is printed with the verdict so the configuration can be quoted.

The output is deliberately two-part. What the command *established* is stated
without hedging. What it *did not* establish — that any declared gate actually
passed, that the encoded rules read the law correctly — is stated just as
plainly, because a verdict that lets a reader infer more than was checked is
worse than no verdict.

With ``--json``, every exit path after argument parsing prints exactly one
JSON object bearing a ``verdict`` key — a refused spec, an unusable root, an
aborted run, and a result that cannot be rendered all included. A machine
consumer that keys on ``verdict`` therefore fails closed with the command.

The text renderer is the verdict's last boundary, so every string it takes
from the result goes through :func:`_rendered` — escaped and bounded in one
pass over the input — before it reaches a line.
Not every string in a verdict is written by someone the verdict is about, but
enough of them are: a filename in the release manifest directory, a path under
a content root, a pass failure quoting either. One carrying
``\\x1b[A\\r\\x1b[2K  VERDICT: PASS`` redraws the line the command has just
printed to say FAIL, on any terminal that honours the sequences (peer review,
round seven). The library's own messages are left exactly as they are —
``receipt.release_chain``'s wording is pinned byte for byte by a differential
harness — so the escaping lives here, at the one place the bytes reach a
terminal.

Escaping only the code points that *are* control characters was not enough,
in two directions (peer review, round eight). A filename byte no filesystem
encoding could decode reaches Python as a lone surrogate under POSIX
``surrogateescape`` — ``os.fsdecode(b"evil\\x9b.py")`` is
``"evil\\udc9b.py"`` — which carries no control character at all, passed
through the helper untouched, and was encoded straight back to the byte 0x9B
by ``sys.stdout``'s own error handler. 0x9B is CSI. That path prints on the
verdict's *spec* line, which a PASS prints as readily as a FAIL. And a
Unicode format control such as U+202E RIGHT-TO-LEFT OVERRIDE reverses the
rest of a line without being a control character in the C0 sense, so
release-chain failure text carrying one printed as whatever the producer
arranged. :func:`_terminal_safe` covers both classes now, and its docstring
lists all four.

Where the trusted line sits is part of the same defence. A verdict's last
line is this module's own text and nothing untrusted follows it: the
failure branch prints the failed pass and its detail and *then*
``VERDICT: FAIL — <pass name>``, and :func:`_refuse` ends with
``receipt verify: FAIL``. Printing the sentinel first left bounded but
entirely printable detail after the one line an auditor keys on, and four
thousand printable characters soft-wrap through fifty rows of an
eighty-column terminal — enough to scroll the real verdict off the screen
and leave a forged ``VERDICT: PASS`` at column one as the last thing on it,
without a single escape sequence (peer review, Sol round 2). The passing
branch already ended with fixed text.

Writing the verdict out is inside the same fail-closed boundary as
rendering it, and it goes through :func:`_emit` rather than ``print``.
``print`` hands text to the stream's own codec with the stream's own error
handler, and a strict one raises: with an ASCII ``sys.stdout`` — a
``PYTHONIOENCODING=ascii`` run, or a pipe under a POSIX locale — the em
dash in this module's *own* fixed lines raised ``UnicodeEncodeError`` out
of :func:`main`, and the command printed a traceback where it promises a
verdict (peer review, Sol round 2). :func:`_emit` encodes with
``backslashreplace`` and writes the bytes to the stream's binary buffer, so
an unrepresentable character arrives as ``\\u2014`` instead of as an
exception; both emissions sit inside the render boundary, so anything else
about the write becomes the render refusal, and :func:`_refuse` emits the
same way so the refusal itself cannot raise.

Each write is repeated until the payload is gone. ``write`` is not
obliged to take everything it is offered: a ``BufferedWriter`` writes it
all or raises, but a raw or unbuffered stream returns a count instead, and
the count was discarded — so the verdict was truncated wherever the
operating system stopped and ``main`` returned the passing exit code over
it (peer review, Sol round 3). A zero-length write is a failure, not
something to spin on, and it becomes the render refusal. The remainder is
tracked as an offset into one ``memoryview`` rather than by re-slicing the
payload, because re-slicing copied what was left after every call and made
the loop quadratic on precisely the streams it exists for (peer review, Sol
round 5).

The bufferless Unicode-sink path hands the same loop a ``str``, which has no
zero-copy view. Its remainder is offered in chunks of at most 8,192
characters, and after a short write the next chunk is capped at the count the
writer just accepted. A one-character writer therefore materialises one
initial bounded chunk and then one character per call, rather than copying a
near-cap verdict's whole remainder on every call (peer review, Sol round 7).

*Which* encoding it uses is the command's decision and not the stream's,
because escaping characters and then handing them to an arbitrary codec
leaves the escaping to be undone by the encoder. Under cp1252 the
perfectly printable U+203A encodes to the single byte 0x9B, which is CSI,
so a filename carrying it could begin a control sequence through a
character :func:`_terminal_safe` had no reason to touch; ISO-2022-JP emits
ESC to switch character sets, so ordinary Japanese text carries 0x1B (peer
review, Sol round 3). :func:`_byte_safe_encoding` uses the stream's own
codec only when it is UTF-8 and otherwise uses ASCII with
``backslashreplace`` only after proving the advertised codec carries those
ASCII bytes literally. UTF-16 and UTF-32 were
trusted alongside it on the argument that a UTF is a UTF, and they do not
survive it: under UTF-16LE the printable U+5B1B and U+6D38 encode to
``1b 5b 38 6d``, which is ``ESC [ 8 m`` and hides the rest of the line from
anything reading the stream as bytes (peer review, Sol round 4). UTF-8 is
trusted because its code units are bytes and the escaper judged every one of
them; a wider unit is a unit the escaper never saw.

Even the ASCII fallback has to be proved against the advertised codec. UTF-7
decodes printable ASCII byte sequences into non-ASCII characters (including
an ESC), and ``unicode_escape`` decodes the sanitiser's backslash spellings
back into the controls they name; raw ASCII is also not a one-byte character
stream under UTF-16 or UTF-32 (peer review, Sol round 7). At runtime
:func:`_ascii_is_literal` round-trips every printable ASCII character plus LF
and TAB and requires the encoded bytes to be byte-for-byte ASCII. A codec that
fails is refused before anything is written. UTF-7, ``unicode_escape``,
UTF-16 and UTF-32 fail; Latin-1, the cp125x pages and ISO-8859 pages pass.

That decision is made once. It was sampled in :func:`main` to bound the text
and sampled again in :func:`_emit` to encode it, so a stream whose
``encoding`` answers differently to two reads — a wrapper a host has
substituted, a stream reopened under another locale — was measured as UTF-8
and written as ASCII: a field of 4,096 emoji passed a bound of 4,096 and
arrived as 40,960 bytes, which is the exact defect measuring in the
emission's units was added to close (peer review, Sol round 5).
:func:`main` asks once and hands the answer to :func:`_format_text` and to
:func:`_emit` alike, and :func:`_emit` no longer asks.

And a stream the verdict cannot be written to safely is refused rather than
written to unsafely. A stream with no binary buffer is written through its
own text API, which re-encodes with its own codec — so the bytes the
escaper had approved were decoded and handed straight back to the codec the
decision had just rejected: cp037 spells an ordinary letter as a byte in the
C1 range, and UTF-16 puts a NUL beside every ASCII character (peer review,
Sol round 5). That fallback runs only where the stream's own codec is the
trusted UTF-8 now, and refuses otherwise, which the render boundary turns
into the refusal it already has for a verdict it cannot render.

A codec-less, bufferless stream is different: ``io.StringIO`` and equivalent
in-memory sinks produce no bytes and therefore have no codec that can undo the
sanitiser (peer review, Sol round 7). :func:`_stream_encoding` classifies a
*recognised* sink that way, :func:`_byte_safe_encoding` selects UTF-8 units
for render bounds, and :func:`_emit` writes the already-rendered text
directly. Recognised, because "no codec and no buffer" is a shape a byte
stream can have: ``codecs.getwriter("cp1252")(...)`` forwards both lookups to
the binary stream underneath it and encodes everything written to it, so it
wore that shape and turned the verdict's U+203A into the single byte 0x9B —
CSI — followed by the producer's text (peer review, Sol round 7, round 3). So
:func:`_is_unicode_sink` admits ``io.StringIO``, the type, and nothing else.
A ``getvalue`` returning ``str`` was admitted too, and that readmitted the
same hazard: a ``TextIOBase`` subclass forwarding to a cp1252 byte stream and
also keeping the text behind ``getvalue`` passed the probe and put 0x9B back
on the wire (peer review, Sol round 8). A bufferless stream that advertises a
non-UTF-8 codec, and one that is not that type, both refuse.

What is written is canonical UTF-8, with no byte-order mark. The stream's
own spelling used to be handed back to the encoder, and ``utf-8-sig`` is a
UTF-8 codec that prepends U+FEFF: a ``--json`` verdict written to a stream
under that codec began ``ef bb bf``, and a JSON document does not begin with
a byte-order mark. RFC 8259 permits a parser to ignore one and plenty do
not: a consumer that decodes the stream and parses the string gets
``json.loads``'s own ``Unexpected UTF-8 BOM`` (peer review, Sol round 5).
The mark is not content the
command means to send in the text verdict either. So ``utf-8-sig`` is
recognised as a UTF-8 stream and written as ``utf-8``, which is the same
bytes minus the mark, and the trusted set — the codecs this module will
*write* in — holds ``utf-8`` alone.

The JSON renderer needs nothing of the kind. ``json.dumps`` with
``ensure_ascii`` at its default escapes every non-ASCII code point into a
``\\uXXXX`` sequence inside the quoted string — lone surrogates and format
controls included — and every code point below 0x20 with it, so a machine
consumer receives them as data and no terminal ever sees them raw.

What both renderers do share is a bound on length rather than on content.
The schema bounds in ``receipt.corpus`` cover corpus-derived output only, so
a release manifest with a million-character ``schemaVersion`` scrolled the
verdict away through the custody half instead (peer review, round eight).
Every result-derived string either renderer prints is therefore truncated at
:data:`receipt._render.MAX_RENDERED_FIELD` with the marker
``receipt.corpus._quoted`` uses. The text half applies that bound *while* it
escapes rather than afterwards, so a million-character field costs the bound
rather than the field: escaping the whole string first built an escaped copy
of an attacker-controlled value to produce four thousand characters of output
(peer review, Sol round 4), and the marker there counts input characters,
since the tail it names was never escaped. That bound lives in ``receipt._render``
rather than here because ``receipt.corpus`` charges its verdict budgets
against it: the corpus used to charge the string the producer wrote while
this module printed the string the bound returned, so the accounting and
the rendering disagreed in both directions — a gate whose evidence renders
to well under the cap once bounded was refused for a charge nothing would
ever print (peer review, Sol round 3). One module, one transformation, and
the charge is made on its output.
The bound is on what this command *prints*, not on what the library raises:
``receipt.release_chain`` and ``receipt.corpus`` still raise their full
text, and a machine consumer that needs all of it can call the library
rather than parse a verdict.

Each renderer counts in the units it emits, which is not the same count.
The text renderer counts the characters it prints, so an escape sequence is
charged the six characters a terminal receives — and on a stream whose
encoding is not UTF-8 those characters are not what it receives, because
:func:`_emit` falls back to ASCII with ``backslashreplace``: 4,096 emoji
passed a bound counted in characters and arrived as 40,960 bytes of
``\\U0001f600``, ten times the bound and out of a field the bound had already
accepted (peer review, Sol round 4). So the emission encoding is decided in
:func:`main`, before the verdict is rendered rather than after, and handed to
:func:`_format_text` and to :func:`_emit` together; where it will fall back,
each non-ASCII character is escaped to the spelling the codec produces
*before* it is measured. What is counted is what the stream is given, and it
is given what was counted. The JSON renderer counts
what ``json.dumps`` will emit: with ``ensure_ascii`` on, a value bounded to
4,096 code points outside the BMP rendered as 49,152 characters, twelve
times the bound and out of a string the bound had already accepted (peer
review, Sol round 2). And it bounds object *keys*, which it did not: a gate
evidence key is 1,024 characters under the corpus schema, so a key alone
rendered over twelve thousand. A truncated key could collide with another
truncated key and silently replace its value, so a bounded key carries the
whole key's SHA-256 in its marker and two keys sharing a prefix stay
distinct. Sixteen hex characters of it was the round-2 answer, and sixteen
is sixty-four bits — about 2^32 trials by the birthday bound, which is
minutes of ordinary computing for an attacker who wants one evidence value
to replace another (peer review, Sol round 3). The marker carries all
sixty-four characters now, and because a digest is a distinguisher rather
than a proof, :func:`_bounded_payload` refuses outright if two keys in one
object come out of the bound equal.
"""

from __future__ import annotations

import argparse
import codecs
import io
import json
import pathlib
import sys
import unicodedata
from typing import Any, Sequence, TextIO

from receipt import __version__
from receipt._render import MAX_RENDERED_FIELD, bounded_encoded, bounded_key
from receipt._unicode_repertoire import FORMAT_CONTROL_RANGES
from receipt.corpus import GATE_TIERS
from receipt.verify import (
    TIER_MEANING,
    VerifyResult,
    VerifySpecError,
    load_spec,
    result_to_dict,
    run_verification,
)

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="receipt",
        description=(
            "Verify custody of a published record set from a clone, offline."
        ),
    )
    parser.add_argument("--version", action="version", version=f"receipt {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser(
        "verify",
        help="verify a published corpus against its committed trust anchors",
        description=(
            "Run every offline pass the consumer's committed spec configures, "
            "and print one fail-closed verdict."
        ),
    )
    verify.add_argument(
        "--spec",
        required=True,
        type=pathlib.Path,
        help=(
            "path to the repository's committed verification spec (a short "
            "Python module defining SPEC = receipt.verify.VerificationSpec(...))"
        ),
    )
    verify.add_argument(
        "--root",
        type=pathlib.Path,
        default=None,
        help="repository root to verify (default: the spec's parent repository)",
    )
    verify.add_argument(
        "--base-ref",
        default=None,
        help=(
            "additionally prove every release object present at this git ref "
            "is byte- and mode-identical in the working tree (requires git "
            "and a repository)"
        ),
    )
    verify.add_argument(
        "--json",
        action="store_true",
        help="emit the verdict as JSON instead of text",
    )
    return parser


def _default_root(spec_path: pathlib.Path) -> pathlib.Path:
    """Walk up from the spec to the enclosing repository root."""

    current = spec_path.resolve().parent
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return current


#: Every code point that can move a cursor, clear a line, or split one line
#: into two on a terminal: the C0 block, DEL, the C1 block (which an
#: 8-bit-clean terminal decodes as the two-character ESC sequences), and the
#: Unicode line and paragraph separators. Nothing else is touched — the
#: verdict is meant to be read, and mangling ordinary text to defend against
#: characters that cannot redraw it would cost legibility for nothing.
_TERMINAL_UNSAFE = (
    *range(0x00, 0x20),
    0x7F,
    *range(0x80, 0xA0),
    0x2028,
    0x2029,
)
#: The pinned Unicode 16.0 ``Cf`` set, flattened for a membership test. The
#: same table ``receipt.corpus`` screens producer text against, imported
#: rather than copied so the two cannot drift.
_FORMAT_CONTROL_CODES = frozenset(
    code for low, high in FORMAT_CONTROL_RANGES for code in range(low, high + 1)
)


#: The three code points ``repr`` spells with a letter rather than with a
#: hex escape. Matching it exactly is what keeps a tree-derived name reading
#: the same here as it does through ``receipt.corpus._quoted``.
_SHORT_ESCAPES = {0x09: "\\t", 0x0A: "\\n", 0x0D: "\\r"}


def _python_escape(code: int) -> str:
    """The escape Python's own ``repr`` writes for a non-printable code point.

    Spelled out rather than taken from ``repr``, because ``repr`` escapes
    exactly what the *running* interpreter calls non-printable and this
    boundary must not depend on that: a code point some future table
    reclassified as printable would come back from ``repr`` as itself, and
    the escaping would silently do nothing where it matters most. The
    spelling is identical — ``\\r``, ``\\x1b``, ``\\u202e``, ``\\udc9b`` — so
    tree-derived name still reads the same here as it does through
    ``receipt.corpus._quoted``, which is ``repr``.
    """

    short = _SHORT_ESCAPES.get(code)
    if short is not None:
        return short
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


#: Each terminal-controlling code point mapped to its escape.
_TERMINAL_ESCAPES = {chr(code): _python_escape(code) for code in _TERMINAL_UNSAFE}


def _escaped_character(character: str) -> str:
    """The spelling one character reaches a terminal in: itself, or an escape.

    The escaping policy, one character at a time, so that the two callers
    that need it cannot drift: :func:`_terminal_safe`, which escapes a whole
    string, and :func:`_rendered`, which escapes only as far as the bound
    reaches. Which classes are escaped, and why each of them is, is stated
    in :func:`_terminal_safe`.
    """

    replacement = _TERMINAL_ESCAPES.get(character)
    if replacement is not None:
        return replacement
    code = ord(character)
    if (
        0xD800 <= code <= 0xDFFF
        or code in _FORMAT_CONTROL_CODES
        or unicodedata.category(character) == "Cf"
    ):
        return _python_escape(code)
    return character


def _terminal_safe(text: str) -> str:
    """Replace every code point that must not reach a terminal with its escape.

    The whole string, escaped and returned whole. That is *not* what the
    verdict path does any more — :func:`_rendered` escapes and bounds in one
    pass, and this is no longer on the way to a line — but the policy the
    verdict applies is stated here, character class by character class, and
    :func:`_escaped_character` is the code both share. A caller that wants a
    whole escaped string, and the tests that pin which classes are escaped
    and which are left alone, ask for it here.

    The classes are applied to every string the text verdict takes from the
    result: pass names, details and failures, the spec's name and path, the
    root, gate ids, evidence keys and values, and the abort message
    ``_refuse`` prints, and to nothing else. The fixed lines of the verdict
    are literals in this module and carry none of these characters, so they
    are left alone.

    Four classes:

    - the C0 block, DEL and the C1 block, which move a cursor, clear a line
      or begin an escape sequence;
    - U+2028 and U+2029, which split one verdict line into two in any
      renderer that honours them;
    - every lone surrogate, U+D800 through U+DFFF. A filename byte the
      filesystem encoding could not decode arrives as one under POSIX
      ``surrogateescape``: ``os.fsdecode(b"evil\\x9b.py")`` is
      ``"evil\\udc9b.py"``, which carries no character from the first class
      at all, so the helper passed it through — and ``sys.stdout``'s own
      error handler encodes it straight back to the byte 0x9B, which is CSI.
      A path like that reaches the verdict on the *spec* line, which a PASS
      prints as readily as a FAIL, so this one did not even need the run to
      fail (peer review, round eight);
    - every Unicode format control: the pinned Unicode 16.0 ``Cf`` set, or
      whatever the running interpreter calls ``Cf``, which is the rule
      ``receipt.corpus`` applies at the schema boundary. U+202E
      RIGHT-TO-LEFT OVERRIDE reverses the remainder of a line, so a
      release-chain failure quoting a filename that carries one prints as
      something the producer chose rather than as what the library said.
      The corpus screen refuses these on the way in; ``release_chain``'s
      text has no such screen and its wording is pinned by a differential
      harness, so the renderer is where they are handled.

    The replacement is one code point for its escape, so the escaped text is
    longer but nothing else about it changes: no truncation, no reordering,
    no substitution of anything printable. What an auditor reads is still the
    filename the producer chose, in a spelling that cannot move the cursor.
    Bounding the length is a separate policy, and :func:`_rendered` applies
    the two together rather than one after the other.
    """

    return "".join(_escaped_character(character) for character in text)


def _rendered(text: str, *, encoding: str = "utf-8") -> str:
    """Escape a result-derived string and bound it, in one pass over the input.

    One function so the two policies cannot be applied to different sets of
    strings. Every string ``_format_text`` and :func:`_refuse` take from a
    result goes through this and nothing else does.

    ``encoding`` is the encoding the verdict will be *written* in, which
    :func:`_byte_safe_encoding` decides and which is not always the stream's
    own. It is here because the bound has to be measured in the units the
    stream receives, and on a stream that is not UTF-8 those units are not
    the characters this function holds: :func:`_emit` encodes with
    ``backslashreplace``, so 4,096 emoji passed a bound counted in characters
    and arrived as 40,960 bytes of ``\\U0001f600`` — ten times the bound, out
    of a field the bound had already accepted (peer review, Sol round 4). So
    where the emission will fall back to ASCII, each non-ASCII character is
    escaped to the spelling ``backslashreplace`` produces *before* it is
    measured, and what is counted is what the stream receives. On a UTF-8
    emission nothing changes: a character is a character and the count is the
    one a terminal draws.

    The default is UTF-8, which is what a caller that is not emitting — a
    test, or a future caller rendering for something other than a stream —
    should get: the text as a modern terminal would receive it.

    Escaping and bounding are fused rather than sequenced. Escaping the whole
    string first built the escaped copy of an attacker-controlled value
    before anything looked at its length — a one-million-character failure
    field, which the schema bounds in ``receipt.corpus`` do not cover because
    the custody half raises its own text, cost a list of a million pieces and
    a joined copy of them to produce four thousand characters of output (peer
    review, Sol round 4). Here the input is walked one character at a time
    and the walk stops at the first character whose escaping would carry the
    output past the bound, so the work and the allocation are bounded by
    :data:`receipt._render.MAX_RENDERED_FIELD` rather than by the length of
    what a producer sent. It is the same shape as
    :func:`receipt._render.encoded_split`, which is the JSON half's answer to
    the same question.

    The character that would have crossed the bound is not kept, so what is
    returned is at most the bound plus the marker, and no escape sequence is
    ever cut in half — which truncating an already-escaped string could do,
    and did.

    The marker's count is of *input* characters omitted, and that is a
    change of meaning worth stating: the truncated tail was never escaped, so
    there is no escaped length to report, and what an auditor is told is how
    many characters of the producer's own string are missing. For the strings
    a real verdict carries the two counts are the same, because escaping
    changes nothing about ordinary text.

    What is counted on this side is characters, which is what a terminal
    receives: an escape sequence is six characters of output and is charged
    as six. The JSON renderer counts what ``json.dumps`` will emit instead,
    through :func:`receipt._render.bounded_encoded`, because a code-point
    count there bounded a twelvefold larger rendering.
    """

    ascii_only = _escapes_non_ascii(encoding)
    escaped: list[str] = []
    total = 0
    for index, character in enumerate(text):
        piece = _escaped_character(character)
        if ascii_only and not piece.isascii():
            # The character survived the escaper and will not survive the
            # codec. ``_python_escape`` is the spelling ``backslashreplace``
            # produces for it — \xNN, \uXXXX, \UXXXXXXXX — so measuring this
            # is measuring the bytes, and emitting it is emitting what the
            # codec would have emitted anyway.
            piece = _python_escape(ord(character))
        total += len(piece)
        if total > MAX_RENDERED_FIELD:
            omitted = len(text) - index
            return f"{''.join(escaped)}…[{omitted} more characters]"
        escaped.append(piece)
    return "".join(escaped)


def _bounded_payload(value: object) -> object:
    """The JSON payload with every string bounded, structure unchanged.

    Walked rather than listed, for the reason
    :data:`receipt._render.MAX_RENDERED_FIELD` gives: a field-by-field bound
    covers the fields someone thought of. Values go through
    :func:`receipt._render.bounded_encoded` and keys through
    :func:`receipt._render.bounded_key`, both of which measure what
    ``json.dumps`` will emit rather than what Python holds — and both of
    which live in ``receipt._render`` so that ``receipt.corpus`` charges its
    budgets against the same transformation this applies.

    Two keys that come out of that transformation equal would leave one
    value silently replacing the other, which is a length policy turning
    into a data-loss policy. The digest in a bounded key's marker makes
    that impossible by accident and expensive on purpose; it does not make
    it impossible, so the mapping is checked and a collision raises. The
    render boundary in :func:`main` turns that into the refusal it already
    has for a verdict it cannot render.
    """

    if isinstance(value, str):
        return bounded_encoded(value)
    if isinstance(value, dict):
        bounded: dict[str, object] = {}
        for key, item in value.items():
            rendered = bounded_key(key)
            if rendered in bounded:
                # A digest in the marker makes an accidental merge
                # impossible and a deliberate one expensive; it does not
                # make one impossible, and this is a length policy that
                # must not become a data-loss policy. Refusing raises out
                # of the render boundary, which is the fail-closed answer
                # the command already has for a verdict it cannot render
                # (peer review, Sol round 3).
                raise ValueError(
                    "two keys in one verdict object render identically once "
                    f"bounded: {rendered!r}"
                )
            bounded[rendered] = _bounded_payload(item)
        return bounded
    if isinstance(value, list):
        return [_bounded_payload(item) for item in value]
    return value


def _format_text(result: VerifyResult, *, encoding: str = "utf-8") -> str:
    """The text verdict, rendered for the encoding it will be written in.

    ``encoding`` is what :func:`_byte_safe_encoding` decided for the stream
    this verdict is going to, threaded from :func:`main` so that every
    result-derived field is measured in the units the stream receives — and
    handed to :func:`_emit` as well, so the units a field is measured in are
    the units its bytes are written in and no second sampling of the stream
    can put the two out of step. It
    defaults to UTF-8, which is the text as a modern terminal takes it, so a
    caller that only wants the verdict does not have to know about
    emissions; :func:`_rendered` says why the two cannot be separated.

    Every such field goes through the local ``rendered`` below, which is
    :func:`_rendered` with this encoding bound to it. A local binding rather
    than an argument at each of the fourteen call sites, so that forgetting
    one is not possible: the escaping, the bound and the units are one
    decision applied to one set of strings.
    """

    def rendered(text: str) -> str:
        return _rendered(text, encoding=encoding)

    lines: list[str] = []
    version = rendered(result.receipt_version)
    lines.append(f"receipt {version} — {rendered(result.spec_name)}")
    lines.append(f"  root  {rendered(str(result.root))}")
    lines.append(f"  spec  {rendered(str(result.spec_path))}")
    lines.append(f"        sha256 {rendered(result.spec_sha256)}")
    lines.append("")

    if result.ok:
        lines.append("ESTABLISHED OFFLINE, FROM THIS CLONE ALONE")
    else:
        lines.append("PASSES")
    for item in result.passes:
        mark = "ok  " if item.ok else "FAIL"
        lines.append(f"  [{mark}] {rendered(item.name)}")
        if item.ok:
            lines.append(f"         {rendered(item.detail)}")
        else:
            # str(), not "or ''": a failed pass always carries a failure
            # string, and rendering a hypothetical None as "None" is what
            # this line did before the escaping was added to it.
            lines.append(f"         {rendered(str(item.failure))}")

    corpus = result.corpus
    if corpus is not None and corpus.gates:
        lines.append("")
        lines.append("DECLARED IN THE WITNESSED JOURNAL — NOT RE-RUN BY THIS COMMAND")
        skipped = [gate for gate in corpus.gates if gate.outcome != "pass"]
        if skipped:
            lines.append(
                f"  {len(skipped)} of {len(corpus.gates)} declared gate(s) did not "
                "pass cleanly; each is marked below."
            )
        for tier in GATE_TIERS:
            gates = corpus.gates_in_tier(tier)
            if not gates:
                continue
            lines.append(f"  {tier}: {TIER_MEANING[tier]}")
            for gate in gates:
                suffix = ""
                if gate.outcome == "waived":
                    # Truncated first and escaped after, so the line still
                    # shows sixteen characters of the value rather than
                    # sixteen characters of its escaping.
                    waiver = gate.evidence.get("waiverSetSha256", "")[:16]
                    suffix = f"  [WAIVED under waiver set {rendered(waiver)}…]"
                elif gate.outcome == "not-run":
                    reason = rendered(gate.evidence.get("reason", ""))
                    suffix = f"  [DID NOT RUN — {reason}]"
                lines.append(f"    - {rendered(gate.gate_id)}{suffix}")

    lines.append("")
    if result.ok:
        # The witness clause is derived from what was actually verified, not
        # asserted: a spec pinning one anchor must not be described as two.
        # The anchor names come from the consumer's committed spec rather
        # than from a producer, but they are result data and the rule here
        # admits no exceptions: nothing reaches a line unescaped.
        witnesses = [rendered(name) for name in sorted(result.witness_times())]
        count = len(witnesses)
        noun = "authorities" if count != 1 else "authority"
        # Whether a trusted base reference was verified changes what the
        # timing clause may claim: without one, the witnessed times bound
        # only when each recorded prefix existed, not that the history was
        # never rewritten (a producer holding the signing key can regenerate
        # and re-witness a whole chain, and a first-contact check passes).
        history = next(
            (p for p in result.passes if p.name == "history" and p.ok), None
        )
        lines.append("VERDICT: PASS — custody and corpus binding")
        lines.append(
            "  This proves the published rule files are exactly the bytes a "
            "code-pinned"
        )
        lines.append(
            f"  producer key signed, and the {count} pinned RFC 3161 {noun} "
            f"({', '.join(witnesses)})"
        )
        if history is not None:
            lines.append(
                "  witnessed that each recorded prefix existed no later than "
                "those times,"
            )
            # Scoped to what verify_release_history_immutable compares: release
            # objects present at the base ref, byte and mode. Objects added
            # after the base, and any state between then and now, are outside
            # the claim — the wording must not stretch past the check.
            lines.append(
                "  and every release object present at the supplied base "
                "reference is"
            )
            lines.append("  byte- and mode-identical in this tree. It does")
        else:
            lines.append(
                "  witnessed that each recorded prefix existed no later than "
                "those times."
            )
            lines.append(
                "  It does NOT prove the history was never rewritten — a "
                "producer holding"
            )
            lines.append(
                "  the signing key can regenerate and re-witness a whole "
                "chain, and this"
            )
            lines.append(
                "  first-contact check would still pass; supply --base-ref "
                "against a head"
            )
            lines.append("  you recorded earlier to bind against that. It does")
        lines.append(
            "  NOT prove that any declared gate passed, it does NOT prove the "
            "encodings"
        )
        lines.append(
            "  are a correct reading of the law, it does NOT prove this clone "
            "holds the"
        )
        lines.append(
            "  producer's newest release, and it does NOT prove this is the "
            "only history"
        )
        lines.append(
            "  the producer maintains — a stale or equivocated but honestly "
            "witnessed"
        )
        # A base ref binds this clone against a checkpoint the auditor chose;
        # it cannot make this clone the newest or the only history. Freshness
        # and uniqueness have exactly one remedy, so name only that.
        lines.append(
            "  clone also passes. Check freshness and uniqueness by comparing "
            "head"
        )
        lines.append("  digests out of band.")
    else:
        failure = next((item for item in result.passes if not item.ok), None)
        detail = failure.failure if failure is not None else "unknown failure"
        name = rendered(failure.name) if failure else "verification"
        # The attacker-derived detail first and the trusted sentinel last,
        # with nothing after it. Printing the sentinel first put bounded but
        # entirely printable text after the one line an auditor keys on, and
        # four thousand printable characters soft-wrap through fifty rows of
        # an eighty-column terminal — long enough to scroll the real verdict
        # off the screen and leave a forged "VERDICT: PASS" at column one as
        # the last thing on it (peer review, Sol round 2). The verdict's own
        # last line is now this module's own text.
        #
        # The name on it is a literal from ``receipt.verify`` — "history",
        # "custody", "binding", "declaration", or the "verification" below —
        # so the sentinel line is short and cannot wrap. It goes through
        # ``_rendered`` anyway, because the rule here admits no exceptions.
        lines.append(f"FAILED: {name}")
        lines.append(f"  {rendered(str(detail))}")
        lines.append("")
        lines.append(f"VERDICT: FAIL — {name}")
    return "\n".join(lines)


#: The canonical name of the one codec this module writes in when it is not
#: falling back to ASCII: the codec whose bytes a reader decodes back to
#: exactly the characters this module escaped, and which cannot spell a
#: character it kept as a byte a terminal reads as a control. Another codec
#: may receive only the ASCII fallback, and only when the runtime probe proves
#: its reader decodes those bytes literally. The escaping
#: :func:`_terminal_safe` performs is over *characters*, so anything weaker
#: lets a codec defeat it after the fact. See :func:`_byte_safe_encoding`.
#:
#: ``utf-8-sig`` was in here, and it is not a codec this module may write in:
#: it prepends U+FEFF, so a ``--json`` verdict began ``ef bb bf`` and was not
#: JSON (peer review, Sol round 5). It is recognised as a UTF-8 *stream* by
#: :data:`_UTF8_STREAM_ENCODINGS` below and written as ``utf-8``.
_TRUSTED_ENCODINGS = frozenset({"utf-8"})

#: The canonical names of the stream codecs whose text this module writes as
#: canonical UTF-8. The two differ by a byte-order mark and nothing else, so
#: a stream reporting either is a stream whose reader decodes UTF-8; what
#: makes them one entry here and two elsewhere is that the mark is bytes this
#: command would be adding, not bytes it was asked to write.
_UTF8_STREAM_ENCODINGS = frozenset({"utf-8", "utf-8-sig"})

_ASCII_LITERAL_PROBE = "".join(chr(code) for code in range(0x20, 0x7F)) + "\n\t"
_ASCII_LITERAL_BYTES = _ASCII_LITERAL_PROBE.encode("ascii")
_STREAM_ENCODING_UNSET = object()

#: The canonical names of the codecs this module will write ASCII bytes for a
#: reader of. Each is a single-byte code page: a fixed 256-entry table, with no
#: shift state, whose 0x00–0x7F half is the ASCII identity. Those three
#: properties are what make raw ASCII bytes on the wire mean, to that reader,
#: exactly the characters :func:`_terminal_safe` approved — no byte can join
#: with a neighbour to become part of another character, and no byte this
#: module did not write can change what its bytes mean.
#:
#: An enumeration rather than a computed rule, which is the whole point. A
#: runtime classification admits ``raw-unicode-escape``: it is stateless, its
#: ASCII range is the identity, no byte of it combines with a neighbour, and it
#: passes :func:`_ascii_is_literal` — and it decodes the six perfectly
#: printable characters ``\u001b`` into ESC and ``\u000d`` into CR, so a
#: producer's filename spelled that way is a control sequence on arrival
#: (peer review, Sol round 7, round 3). No probe over single characters or
#: single bytes can see that, because the hazard is a multi-character decode.
#: So membership is by identity: a page is on this list because it is a code
#: page, and the probe is kept as a belt over the list rather than as the
#: proof.
#:
#: Deliberately absent, and each for its own reason. ``cp864`` is a single-byte
#: page whose 0x25 is ARABIC PERCENT SIGN rather than ``%``, so it is not the
#: ASCII identity and the belt refuses it as well. The EBCDIC pages —
#: ``cp037``, ``cp273``, ``cp424``, ``cp500`` and their family — are not ASCII
#: at any byte. ``charmap`` has no fixed table at all; its mapping is the
#: caller's. Every multi-byte codec is absent even where ASCII survives it
#: (``cp932``, ``gbk``, ``big5``, ``euc_jp``, ``euc_kr``, ``gb2312``), because
#: a lead byte this command did not write can change what its first byte
#: means. And every stateful or transforming codec is absent: the
#: ``iso2022_*`` family, ``utf-7``, ``hz``, ``unicode-escape``,
#: ``raw-unicode-escape``, ``idna``, ``punycode``, UTF-16 and UTF-32.
#:
#: A codec that satisfies the rule and is not listed is refused, not written
#: to unsafely; adding it is this list plus the table test that proves the
#: four properties of every member.
_ASCII_TRANSPARENT_CODECS = frozenset(
    {
        "ascii",
        # ISO 8859, every part Python ships (there is no part 12).
        "iso8859-1",
        "iso8859-2",
        "iso8859-3",
        "iso8859-4",
        "iso8859-5",
        "iso8859-6",
        "iso8859-7",
        "iso8859-8",
        "iso8859-9",
        "iso8859-10",
        "iso8859-11",
        "iso8859-13",
        "iso8859-14",
        "iso8859-15",
        "iso8859-16",
        # The Windows ANSI code pages.
        "cp1250",
        "cp1251",
        "cp1252",
        "cp1253",
        "cp1254",
        "cp1255",
        "cp1256",
        "cp1257",
        "cp1258",
        # The OEM/DOS code pages a console still reports.
        "cp437",
        "cp720",
        "cp737",
        "cp775",
        "cp850",
        "cp852",
        "cp855",
        "cp856",
        "cp857",
        "cp858",
        "cp860",
        "cp861",
        "cp862",
        "cp863",
        "cp865",
        "cp866",
        "cp869",
        "cp874",
        "cp1006",
        "cp1125",
        # The KOI8 family and its neighbours.
        "koi8-r",
        "koi8-t",
        "koi8-u",
        "kz1048",
        "ptcp154",
        "tis-620",
        # The Mac OS Roman family.
        "mac-croatian",
        "mac-cyrillic",
        "mac-greek",
        "mac-iceland",
        "mac-latin2",
        "mac-roman",
        "mac-romanian",
        "mac-turkish",
        # Two more single-byte tables Python ships.
        "hp-roman8",
        "palmos",
    }
)


def _ascii_is_literal(encoding: str) -> bool:
    """Whether a codec carries this one probe of ASCII byte for byte.

    The probe contains every printable ASCII character plus LF and TAB. Its
    encoding must equal the same text encoded as ASCII, and those exact bytes
    must decode back to the original probe. Both directions matter: UTF-7 can
    decode an ASCII sequence such as ``+ABs-`` into ESC, while
    ``unicode_escape`` turns a sanitiser-produced ``\\x1b`` back into ESC.
    UTF-16 and UTF-32 fail because their characters occupy wider code units.
    An unknown or unusable codec fails closed.

    What this cannot decide is the question it was once asked to answer.
    Passing proves one fixed string survives one round trip from a fresh
    codec; it does not prove that *every* ASCII sequence does, nor that the
    codec was in a fresh state when :func:`_emit` reached it.
    ``raw-unicode-escape`` passes and decodes ``\\u001b`` — six printable
    characters a producer's filename may carry — into ESC; ``iso2022_jp``
    passes and, after a single non-ASCII write has left its stream in JIS X
    0208 mode, reads the raw ASCII ``PASS`` as ``日仭嗷`` (peer review, Sol
    round 7, round 3). So this is now a belt over
    :data:`_ASCII_TRANSPARENT_CODECS` rather than the proof:
    :func:`_byte_safe_encoding` asks it of a codec that is already on the
    list, and a member that somehow fails it is refused.
    """

    try:
        encoded = _ASCII_LITERAL_PROBE.encode(encoding)
        return (
            encoded == _ASCII_LITERAL_BYTES
            and _ASCII_LITERAL_BYTES.decode(encoding) == _ASCII_LITERAL_PROBE
        )
    except (LookupError, UnicodeError, ValueError):
        return False


def _escapes_non_ascii(encoding: str) -> bool:
    """Whether :func:`_emit` will spell a non-ASCII character in backslashes.

    True for every encoding but the trusted one, because :func:`_emit`
    encodes with ``backslashreplace`` and every successful non-UTF-8 decision
    from :func:`_byte_safe_encoding` is ASCII. :func:`_rendered` asks this so
    that what it measures is what the stream receives; an unknown spelling
    answers True, which is the same fail-closed direction
    :func:`_byte_safe_encoding` takes.

    What it is asked about is a decision :func:`_byte_safe_encoding` made,
    so in this command it is only ever ``utf-8`` or ``ascii``.
    """

    try:
        return codecs.lookup(encoding).name not in _TRUSTED_ENCODINGS
    except (LookupError, ValueError):
        return True


#: The refusal a stream with no binary layer and no codec this module writes
#: in receives. One spelling, used by :func:`_byte_safe_encoding` when it
#: refuses such a stream before the render and by :func:`_emit` when it
#: refuses one at the write, so the two cannot drift.
_BUFFERLESS_REFUSAL = (
    "verdict stream has no binary buffer and its encoding is not UTF-8; "
    "the verdict cannot be written safely"
)


def _stream_buffer(stream: TextIO) -> Any | None:
    """The stream's usable binary layer, or ``None`` when it has none.

    A detached ``TextIOWrapper`` raises ``ValueError`` from ``buffer`` rather
    than returning ``None``; an in-memory Unicode sink has no attribute at
    all. Both are bufferless, but :func:`_stream_encoding` distinguishes them
    by whether a codec is still advertised.
    """

    try:
        return stream.buffer  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        return None


def _is_unicode_sink(stream: TextIO) -> bool:
    """Whether a codec-less, bufferless stream is an in-memory text sink.

    "No codec and no buffer" is a shape, not a guarantee, and it was read as
    one. A ``codecs.StreamWriter`` has exactly that shape — its ``encoding``
    and ``buffer`` attribute lookups are forwarded to the binary stream
    underneath it, which has neither — and it encodes everything written to
    it with the codec it was built from. So
    ``codecs.getwriter("cp1252")(open(path, "wb"))`` was classified as a
    byte-free sink and handed the rendered verdict as text, where U+203A
    became the single byte 0x9B: CSI, followed by whatever the producer's
    filename said (peer review, Sol round 7, round 3). A ``TextIOBase``
    subclass that counts what it is given has the same shape and the same
    problem if it encodes.

    So a sink is one type: :class:`io.StringIO`. That covers what a host
    actually substitutes — ``contextlib.redirect_stdout(io.StringIO())``,
    which every test in this suite and every embedding caller uses — and it
    covers nothing by shape.

    A ``getvalue`` returning ``str`` was accepted here too, as "the
    in-memory-text protocol ``StringIO`` defines". It is not a protocol, it
    is a method name, and it readmitted the very class this function was
    written to refuse: a ``TextIOBase`` subclass forwarding to a cp1252 byte
    stream *and* keeping the text behind ``getvalue`` — a tee, a progress
    wrapper, a stream a host substituted — passed the probe, answered
    "utf-8" from :func:`_byte_safe_encoding`, and put the escaper's approved
    U+203A on the wire as the single byte 0x9B (peer review, Sol round 8).
    Adding one method to the refused class walked it back in. The test that
    the shape was standing in for — does writing text here produce bytes? —
    has no answer a probe can give, so the type is asked instead.

    What that gives up is stated. A ``StringIO`` subclass overriding
    ``write`` to encode is a sink here and is not one in fact; that is the
    host's own doing, inside a type whose contract is in-memory text, and
    nothing this module can read distinguishes it from the base class. An
    in-memory sink of some other type is refused rather than trusted, and
    the cost of misclassifying in that direction is a refusal:
    :func:`_stream_encoding` reports it as a stream with no usable codec.
    """

    return isinstance(stream, io.StringIO)


def _stream_encoding(stream: TextIO) -> str | None:
    """The canonical codec, ``None`` for a Unicode sink, or ``""`` if unknown.

    One place asks the question, so :func:`_byte_safe_encoding` and
    :func:`_emit`'s bufferless guard cannot disagree about what a stream's
    codec is. ``codecs.lookup`` is what canonicalises the spelling, turning
    ``UTF_8`` and ``utf8`` into ``utf-8``.

    A stream whose ``encoding`` is absent or ``None``, whose binary buffer is
    absent, *and* which :func:`_is_unicode_sink` recognises is an in-memory
    Unicode sink: writing text to it produces no bytes for a codec to
    reinterpret, so ``None`` is a positive classification rather than an
    unknown value (peer review, Sol round 7). All three conditions are
    required, because the first two are a shape a byte stream can have: a
    ``codecs.StreamWriter`` forwards both lookups to the binary stream it
    wraps and still encodes what it is given (peer review, Sol round 7,
    round 3). The same missing codec on a stream that has a buffer, on one no
    sink test recognises, a non-string codec, and an unknown spelling all
    answer ``""`` and fail closed. A bufferless stream with an actual
    non-UTF-8 codec keeps its name and keeps the refusal.
    """

    encoding = getattr(stream, "encoding", None)
    if encoding is None:
        if _stream_buffer(stream) is not None:
            return ""
        return None if _is_unicode_sink(stream) else ""
    if not isinstance(encoding, str):
        return ""
    try:
        return codecs.lookup(encoding).name
    except (LookupError, ValueError):
        return ""


def _byte_safe_encoding(
    stream: TextIO,
    *,
    stream_encoding: str | None | object = _STREAM_ENCODING_UNSET,
) -> str:
    """The encoding to write this stream in, which is not always its own.

    :func:`_terminal_safe` escapes every code point that can move a cursor
    or begin an escape sequence, and then the result is encoded. That order
    is only safe if the encoding maps the characters it kept onto bytes a
    reader decodes back to those characters — which is what a Unicode
    transformation format is, and what a legacy code page is not. Under
    cp1252 the perfectly printable U+203A SINGLE RIGHT-POINTING ANGLE
    QUOTATION MARK encodes to the single byte 0x9B, which is CSI: an
    8-bit-clean terminal reads it as the start of a control sequence, so a
    producer's filename could redraw the verdict through a character the
    escaper had no reason to touch (peer review, Sol round 3). ISO-2022-JP
    is worse in kind rather than in degree: it emits ESC to switch
    character sets, so ordinary Japanese text carries 0x1B.

    So the stream's codec is honoured only when it is UTF-8 — ``utf-8`` or
    ``utf-8-sig``, compared after ``codecs.lookup`` has canonicalised the
    spelling, which is what turns ``UTF_8`` and ``utf8`` into ``utf-8``.
    Anything else is eligible only for ASCII with ``backslashreplace``, so no
    character outside ASCII can produce a byte at all.

    Eligibility is granted by name, from :data:`_ASCII_TRANSPARENT_CODECS`,
    and not inferred from a runtime probe. The bytes are written directly to
    the stream's buffer, but a reader interprets them through the codec the
    stream advertises, and what has to be true of that codec is stronger than
    what any probe can ask: every ASCII sequence must arrive as itself, from
    whatever state a previous write left the stream in. Only a single-byte,
    stateless code page whose lower half is the ASCII identity is that, and
    the list is those pages by name.

    A probe cannot substitute for the list, which is why this stopped being
    one. ``raw-unicode-escape`` passes :func:`_ascii_is_literal` and decodes
    the six printable characters ``\\u001b`` into ESC, so a producer's
    filename spelled that way starts a control sequence in a reader.
    ``iso2022_jp`` passes and is a stateful codec: one non-ASCII character
    written earlier leaves the stream in JIS X 0208 mode, where the raw ASCII
    ``PASS`` this module then writes reads as ``日仭嗷`` and a longer verdict
    raises ``UnicodeDecodeError`` in the consumer (peer review, Sol round 7,
    round 3). Both are refused now, along with UTF-7 and ``unicode_escape``
    (which the probe already caught), UTF-16 and UTF-32 (whose ASCII is not
    one byte per character), ``hz``, ``idna`` and anything unknown.

    The probe is kept as a belt over the list: a listed codec that fails it is
    refused rather than trusted, so the two have to agree.

    A codec-less, bufferless stream is the exception because it is not a byte
    stream at all. :func:`_stream_encoding` returns ``None`` for that Unicode
    sink and this function returns ``"utf-8"`` so the text renderer applies
    its trusted-Unicode bound; :func:`_emit` then writes the rendered text
    directly, without an encode/decode round trip (peer review, Sol round 7).

    Honoured, and not handed back: what this returns is always ``utf-8`` or
    ``ascii``, never the stream's own spelling. ``utf-8-sig`` is a UTF-8
    codec that prepends a byte-order mark, and returning it put ``ef bb bf``
    in front of a ``--json`` verdict, which is not a JSON document — a
    consumer decoding the stream and parsing the string gets
    ``json.loads``'s own ``Unexpected UTF-8 BOM`` (peer review, Sol round 5). A stream under that codec is a UTF-8 stream and is
    written as ``utf-8``: the same bytes, minus a mark this command was
    never asked to send.

    UTF-8 needs the argument stated rather than assumed, because it is the
    only case that survives it: a multi-byte sequence is a lead byte of 0xC2
    or above followed by continuation bytes of 0x80 through 0xBF, and those
    ranges are disjoint from C0 and from ASCII. A UTF-8 reader decodes them
    back to the code point they came from and never to a C1 control; a byte
    in 0x80..0x9F reaching a UTF-8 terminal as a *control* would have to
    have been the code point U+0080..U+009F in the text, which
    :func:`_terminal_safe` has already escaped.

    UTF-16 and UTF-32 were admitted on that argument being "the same with
    wider units", and it is not. A wider unit is a unit a byte-oriented
    reader does not see: under UTF-16LE the two perfectly printable code
    points U+5B1B and U+6D38 encode to the four bytes ``1b 5b 38 6d``, which
    is ``ESC [ 8 m`` — the SGR sequence that renders the rest of the line
    invisible, and enough to hide a ``VERDICT: FAIL`` from anything reading
    the stream as bytes (peer review, Sol round 4). What makes the UTF-8
    argument work is that its code units *are* bytes and the escaper judged
    every one of them; UTF-16 and UTF-32 hand the terminal bytes no
    character in the text ever was.

    The cost is that a stream whose codec is not a code page this module
    names is refused rather than written to. That is a refusal for a Japanese
    or Korean multi-byte console, and it is the right side to err on: the
    alternative is a verdict whose bytes mean something else to the reader it
    was written for. A single-byte legacy stream — Latin-1, cp1252, an OEM
    page, KOI8 — still receives ASCII with backslash escapes for non-ASCII
    text.

    Asked once per emission, by :func:`main`, and the answer is handed to
    everything downstream. Asking again inside :func:`_emit` made the
    command's decision depend on a stream answering the same question the
    same way twice (peer review, Sol round 5).

    What is returned is the *canonical* spelling rather than the stream's
    own, which is the same codec by another name and is what lets the
    trusted answer be compared and refused by one set of names.
    """

    name = (
        _stream_encoding(stream)
        if stream_encoding is _STREAM_ENCODING_UNSET
        else stream_encoding
    )
    if name is None:
        return "utf-8"
    if not isinstance(name, str):  # pragma: no cover - private cached-call guard
        raise TypeError("stream encoding decision is not a string or None")
    if name in _UTF8_STREAM_ENCODINGS:
        return "utf-8"
    if name in _ASCII_TRANSPARENT_CODECS and _ascii_is_literal(name):
        return "ascii"
    if not name:
        # A stream that advertises no usable codec. The buffer question is
        # asked once more here, and only to choose which sentence the refusal
        # carries: a bufferless one is the shape the emission guard names, and
        # quoting an empty codec name would say nothing. Both branches refuse.
        raise OSError(
            _BUFFERLESS_REFUSAL
            if _stream_buffer(stream) is None
            else "verdict stream advertises no usable codec; the verdict "
            "cannot be written safely"
        )
    raise OSError(
        f"verdict stream codec {name} does not carry ASCII literally; "
        "the verdict cannot be written safely"
    )


#: The largest ``str`` slice one short-write call may materialise. Text has no
#: zero-copy view, so the first offer is bounded here and the loop shrinks later
#: offers to what a short writer demonstrated it can accept. Eight kibichars is
#: small beside the roughly 512 KiB maximum corpus-derived verdict payload and
#: large enough that an ordinary text writer still gets one call.
TEXT_WRITE_CHUNK = 8192


def _write_all(target: Any, payload: Any) -> None:
    """Write the whole payload, or raise; a short write is not a success.

    ``write`` is not obliged to take everything it is offered. A
    ``BufferedWriter`` writes it all or raises, which is why this went
    unnoticed, but a raw or unbuffered stream returns the number of bytes it
    actually took — ``python -u``, a stream a host has substituted, a pipe
    that took a partial write — and returning that count is not an error.
    Discarding it truncated the verdict wherever the operating system
    stopped and left :func:`main` to return the passing exit code over it;
    in ``--json`` mode a consumer was handed half an object, which is the
    one thing the JSON contract exists to prevent (peer review, Sol
    round 3).

    A zero return, and the ``None`` a non-blocking ``RawIOBase.write``
    returns when it would block, are both failures rather than something to
    spin on: this is a one-shot verdict on a stream the command does not
    own, and a writer that will take nothing is a writer the exit code has
    to carry. The ``OSError`` raised here is what the render boundary in
    :func:`main` turns into the refusal, and what :func:`_refuse` guards
    against separately.

    Written over offsets in both layers: ``payload`` is ``bytes`` for the
    buffer and ``str`` for the text fallback, and the counts each ``write``
    returns are in the units of what it was handed.

    Rebinding ``payload`` to
    ``payload[written:]`` after every call copied the whole remainder each
    time, so a writer that takes one unit per call copied N + (N−1) + … + 1
    units to write N — quadratic in the length of a verdict on exactly the
    streams this loop exists for, since a ``BufferedWriter`` never short-
    writes and a raw or unbuffered one is where the counts come from (peer
    review, Sol round 5). A ``memoryview`` over the bytes slices in constant
    time and copies nothing, so what is offered on each call is a window on
    the one buffer.

    A ``str`` has no buffer protocol, so even offset slicing copies. That
    branch offers at most :data:`TEXT_WRITE_CHUNK` characters and, after any
    short write, caps the next offer at the number just accepted. A
    one-character writer therefore copies one initial 8,192-character slice
    and one character thereafter: less than ``2 * len(payload) + CHUNK`` in
    total, rather than N + (N−1) + … + 1. Copying is linear in the bounded
    payload times a constant (peer review, Sol round 7).
    """

    if isinstance(payload, bytes):
        window = memoryview(payload)
        offset = 0
        while offset < len(payload):
            written = target.write(window[offset:])
            if not written:
                raise OSError(
                    "the verdict stream accepted none of the bytes offered; "
                    "the verdict cannot be written"
                )
            offset += written
        return

    offset = 0
    chunk = TEXT_WRITE_CHUNK
    while offset < len(payload):
        piece = payload[offset : offset + chunk]
        written = target.write(piece)
        if not written:
            raise OSError(
                "the verdict stream accepted none of the bytes offered; "
                "the verdict cannot be written"
            )
        if written < len(piece):
            chunk = written
        offset += written


def _emit(
    text: str,
    stream: TextIO,
    *,
    encoding: str,
    stream_encoding: str | None | object = _STREAM_ENCODING_UNSET,
) -> None:
    """Write one rendered verdict to a stream that may not accept every character.

    ``print`` hands text to the stream's own codec with the stream's own
    error handler, and a strict one raises. The verdict's fixed lines carry
    an em dash — a literal in this module, not producer text — so
    ``receipt verify`` run with ``PYTHONIOENCODING=ascii``, or into a
    subprocess pipe on a POSIX locale, raised ``UnicodeEncodeError`` out of
    :func:`main` and printed a traceback instead of the fail-closed verdict
    it promises on every exit path (peer review, Sol round 2). Escaping the
    result-derived strings could not have helped: the character that raised
    is one of this module's own.

    So the encoding happens here, with ``backslashreplace``, and the bytes
    go to the stream's underlying binary buffer. A character the stream's
    encoding cannot carry arrives as ``\\u2014`` rather than as an
    exception, which is the same bargain :func:`_terminal_safe` makes: the
    reader sees what was meant, spelled in what the terminal can show.

    Which encoding that is, is :func:`_byte_safe_encoding`'s decision and
    not the stream's: UTF-8 is used only where the stream's own codec is one,
    and another codec gets ASCII only where :func:`_ascii_is_literal` proves
    its reader will see the same characters. Escaping code points and then
    handing them to an arbitrary codec left the escaping to be undone —
    UTF-7 and ``unicode_escape`` can decode ASCII back into ESC, while
    UTF-16 does not decode raw ASCII bytes as one byte per character (peer
    review, Sol round 7).

    That decision arrives as ``encoding`` and is not re-taken here. It was,
    and :func:`main` had already taken it once to bound the verdict's
    fields, so the two calls could disagree: a stream that answered
    ``utf-8`` when the text was measured and ``ascii`` when it was written
    put 40,960 bytes of ``\\U0001f600`` on the wire for a field bounded at
    4,096 characters — the defect the units change closed, reopened by
    sampling twice (peer review, Sol round 5). One decision, two uses.

    The text stream is flushed before the buffer is written so the two
    layers cannot reorder, and a stream with no usable ``buffer`` — a
    wrapper some host has substituted, or a wrapper whose buffer has been
    detached, which raises rather than being absent — is written through its
    text API with the same already-encoded text.

    That fallback is available only where the stream's own codec is the
    trusted UTF-8, and refuses otherwise. Writing through the text API
    re-encodes with the stream's own codec, so the bytes the escaper had
    approved were decoded and handed straight back to the codec
    :func:`_byte_safe_encoding` had just rejected — cp037 spells an ordinary
    ``a`` as 0x81 and a space as 0x40, putting bytes in the C1 range under
    text carrying no control character, and UTF-16 puts a NUL beside every
    ASCII character (peer review, Sol round 5). There is nothing safe to do
    with such a stream, so the write refuses and the render boundary in
    :func:`main` turns that into the refusal it already has for a verdict it
    cannot render.

    A stream with no buffer and no codec is not that fallback. It is an
    in-memory Unicode sink, so no bytes are produced and no encoder can undo
    the escaping. The rendered ``text`` and its final newline are written
    directly through ``write``; ``encoding`` is still ``utf-8`` because that
    is the unit in which the renderer bounded it. A stream with no buffer but
    with a non-UTF-8 codec remains refused (peer review, Sol round 7).

    ``utf-8-sig`` is refused here although it is honoured as a stream codec
    everywhere else, and for the reason the trusted set gives: what a buffer
    receives is bytes this module encoded, and what the text API receives is
    re-encoded by the stream — which for that codec means a byte-order mark
    this command did not write and, in ``--json`` mode, a document that is
    not JSON.

    A write is repeated until the whole payload is gone, through
    :func:`_write_all`, because a single call is not obliged to take all of
    it. ``BufferedWriter`` writes everything or raises, but a raw or
    unbuffered stream — ``python -u``, a stream some host has substituted,
    a pipe under a partial write — returns a *count* instead, and the count
    was discarded. The verdict was then truncated wherever the operating
    system stopped, ``main`` returned the passing exit code over it, and in
    ``--json`` mode a machine consumer was handed half an object (peer
    review, Sol round 3).

    One residual, stated because the JSON contract is exact: a write that
    fails *part-way* leaves those bytes on the stream, and the render
    refusal that follows adds a second object after them. Nothing here can
    un-write bytes, and the alternative — buffering the verdict to decide
    whether to emit it at all — would trade a partial verdict for no
    verdict on the same stream.
    """

    buffer = _stream_buffer(stream)
    if buffer is None:
        own_encoding = (
            _stream_encoding(stream)
            if stream_encoding is _STREAM_ENCODING_UNSET
            else stream_encoding
        )
        if own_encoding is None:
            _write_all(stream, text + "\n")
            stream.flush()
            return
        if own_encoding not in _TRUSTED_ENCODINGS:
            raise OSError(_BUFFERLESS_REFUSAL)
        data = (text + "\n").encode(encoding, errors="backslashreplace")
        _write_all(stream, data.decode(encoding, errors="replace"))
        stream.flush()
        return
    data = (text + "\n").encode(encoding, errors="backslashreplace")
    stream.flush()
    _write_all(buffer, data)
    buffer.flush()


def _fail_payload(stage: str, message: str) -> dict[str, object]:
    """A minimal machine verdict for aborts outside a completed verification.

    Built from plain strings only, so its construction cannot itself raise.
    It leads with the same ``verdict`` key as the full payload: a consumer
    keying on that field sees fail-closed behavior on every exit path after
    argument parsing, whether the run refused a spec, aborted mid-pass, or
    could not render its own result.
    """

    return {
        "verdict": "FAIL",
        "stage": stage,
        "failure": message,
        "passesCompleted": [],
    }


def _refuse(as_json: bool, stage: str, message: str, code: int) -> int:
    """Print a refusal, honoring the JSON contract, and return the exit code.

    The text half is the abort counterpart of :func:`_fail_payload`, and it
    is a verdict line like any other: the message can quote a spec path, an
    exception's text, or a filename that came off the disk, so it is escaped
    and bounded on its way to the terminal — and bounded in the units the
    stream will receive, which is the same reason :func:`_format_text` is
    handed an encoding. The JSON half takes the message unescaped —
    ``json.dumps`` escapes it there — but bounded by the same policy, because
    an abort message can carry a producer's flood as readily as a completed
    verdict can.

    And it ends with this module's own text, for the reason
    :func:`_format_text`'s failure branch does: a bounded message is still
    four thousand printable characters, which soft-wrap through fifty rows
    of an eighty-column terminal and can leave a forged verdict line at
    column one as the last thing on the screen. ``receipt verify: FAIL`` is
    the last line either way.

    Neither write may raise, and each is guarded separately. This function
    is what the render boundary calls *after* an emission has already
    failed, so in ``--json`` mode it was handed the very stream that just
    failed and re-emitted to it — turning the one exit path the JSON
    contract exists for into a traceback out of :func:`main`, which is the
    failure this round's guarded writer was added to remove (adversarial
    review of the Sol round 2 fix). A refusal that cannot be written is
    still a refusal: the exit code carries it, and there is nothing else
    this process can do with a stream that will not take bytes. Failing
    stderr must not suppress the JSON either, which is why the two are
    guarded apart rather than together.
    """

    try:
        # The stream and its encoding are each taken once and bound to a
        # local, so the codec the message is measured against is the codec
        # its bytes are written in; see :func:`_emit`.
        stream = sys.stderr
        stream_codec = _stream_encoding(stream)
        encoding = _byte_safe_encoding(stream, stream_encoding=stream_codec)
        _emit(
            f"receipt verify: {_rendered(message, encoding=encoding)}"
            "\nreceipt verify: FAIL",
            stream,
            encoding=encoding,
            stream_encoding=stream_codec,
        )
    except Exception:  # noqa: BLE001 - a refusal that cannot print is still a refusal
        pass
    if as_json:
        try:
            stream = sys.stdout
            stream_codec = _stream_encoding(stream)
            _emit(
                json.dumps(
                    _bounded_payload(_fail_payload(stage, message)),
                    indent=2,
                    sort_keys=True,
                ),
                stream,
                encoding=_byte_safe_encoding(
                    stream, stream_encoding=stream_codec
                ),
                stream_encoding=stream_codec,
            )
        except Exception:  # noqa: BLE001 - as above; the exit code carries it
            pass
    return code


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "verify":  # pragma: no cover - argparse enforces this
        parser.error(f"unknown command {args.command!r}")

    # From here down the contract is: with --json, exactly one JSON object
    # bearing a "verdict" key is printed on every path — spec refusals, root
    # refusals, an aborted run, even a result that cannot be rendered. The
    # only exits without one are argparse's own, before --json is knowable.
    as_json = bool(args.json)

    try:
        spec, spec_sha256 = load_spec(args.spec)
    except VerifySpecError as exc:
        return _refuse(as_json, "spec", str(exc), EXIT_USAGE)
    except Exception as exc:  # noqa: BLE001 - reading the spec is fail-closed too
        return _refuse(
            as_json,
            "spec",
            f"unable to read the spec: {type(exc).__name__}: {exc}",
            EXIT_USAGE,
        )

    try:
        root = args.root if args.root is not None else _default_root(args.spec)
        root_ok = root.is_dir()
    except Exception as exc:  # noqa: BLE001 - resolving the root is fail-closed too
        return _refuse(
            as_json,
            "root",
            f"unable to resolve the root: {type(exc).__name__}: {exc}",
            EXIT_USAGE,
        )
    if not root_ok:
        return _refuse(as_json, "root", f"root is not a directory: {root}", EXIT_USAGE)

    try:
        result = run_verification(
            root,
            spec,
            spec_path=args.spec.resolve(),
            spec_sha256=spec_sha256,
            base_ref=args.base_ref,
        )
    except Exception as exc:  # noqa: BLE001 - an unhandled error is still a refusal
        return _refuse(
            as_json,
            "verification",
            "verification aborted, refusing to return a verdict: "
            f"{type(exc).__name__}: {exc}",
            EXIT_FAIL,
        )

    # A verdict that cannot be rendered is not a deliverable PASS: refuse,
    # even when the passes themselves succeeded.
    #
    # The emission is inside the boundary too. Printing sat outside it, so a
    # stream whose codec cannot carry the verdict's own em dash raised out
    # of this function and printed a traceback in place of the fail-closed
    # verdict promised on every exit path (peer review, Sol round 2).
    # :func:`_emit` encodes with ``backslashreplace`` so that cannot happen,
    # and the boundary now covers it so that anything else about the write
    # — a closed stream, a full disk — becomes the render refusal rather
    # than an escape.
    if as_json:
        try:
            stream = sys.stdout
            stream_codec = _stream_encoding(stream)
            encoding = _byte_safe_encoding(stream, stream_encoding=stream_codec)
            rendered = json.dumps(
                _bounded_payload(result_to_dict(result)), indent=2, sort_keys=True
            )
            _emit(
                rendered,
                stream,
                encoding=encoding,
                stream_encoding=stream_codec,
            )
        except Exception as exc:  # noqa: BLE001 - rendering is inside the contract
            return _refuse(
                as_json,
                "render",
                "verdict could not be rendered; treat the run as unverified: "
                f"{type(exc).__name__}: {exc}",
                EXIT_FAIL,
            )
    else:
        try:
            stream = sys.stdout if result.ok else sys.stderr
            # The encoding is decided once, here, and used for both halves of
            # the emission: what the fields are measured against and what the
            # bytes are written in. Measuring in characters and then writing
            # in ASCII let 4,096 emoji pass a bound of 4,096 and arrive as
            # 40,960 bytes (peer review, Sol round 4) — and asking the stream
            # a second time inside ``_emit`` let a stream that answered
            # differently twice do the same thing (peer review, Sol round 5).
            stream_codec = _stream_encoding(stream)
            encoding = _byte_safe_encoding(stream, stream_encoding=stream_codec)
            text = _format_text(result, encoding=encoding)
            _emit(
                text,
                stream,
                encoding=encoding,
                stream_encoding=stream_codec,
            )
        except Exception as exc:  # noqa: BLE001 - rendering is inside the contract
            return _refuse(
                False,
                "render",
                "verdict could not be rendered; treat the run as unverified: "
                f"{type(exc).__name__}: {exc}",
                EXIT_FAIL,
            )
    return EXIT_OK if result.ok else EXIT_FAIL


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
