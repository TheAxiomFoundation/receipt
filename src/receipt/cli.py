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
from the result goes through :func:`_rendered` — escaped by
:func:`_terminal_safe`, then bounded by :func:`_bounded` — before it reaches
a line.
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
:data:`MAX_RENDERED_FIELD` with the marker ``receipt.corpus._quoted`` uses.
The bound is on what this command *prints*, not on what the library raises:
``receipt.release_chain`` and ``receipt.corpus`` still raise their full
text, and a machine consumer that needs all of it can call the library
rather than parse a verdict.

Each renderer counts in the units it emits, which is not the same count.
The text renderer counts the characters it prints, so an escape sequence is
charged the six characters a terminal receives. The JSON renderer counts
what ``json.dumps`` will emit: with ``ensure_ascii`` on, a value bounded to
4,096 code points outside the BMP rendered as 49,152 characters, twelve
times the bound and out of a string the bound had already accepted (peer
review, Sol round 2). And it bounds object *keys*, which it did not: a gate
evidence key is 1,024 characters under the corpus schema, so a key alone
rendered over twelve thousand. A truncated key could collide with another
truncated key and silently replace its value, so a bounded key carries the
first sixteen hex characters of the whole key's SHA-256 in its marker and
two keys sharing a prefix stay distinct.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import json.encoder
import pathlib
import sys
import unicodedata
from typing import Sequence, TextIO

from receipt import __version__
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


def _terminal_safe(text: str) -> str:
    """Replace every code point that must not reach a terminal with its escape.

    Applied — through :func:`_rendered`, which bounds the result afterwards
    — to every string the text verdict takes from the result: pass names,
    details and failures, the spec's name and path, the root, gate ids,
    evidence keys and values, and the abort message ``_refuse`` prints, and
    to nothing else. The fixed lines of the verdict are literals in this
    module and carry none of these characters, so they are left alone.

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
    Bounding the length is a separate policy — see :func:`_bounded` — applied
    after this one, so an escape sequence counts as the characters it prints.
    """

    escaped: list[str] = []
    for character in text:
        replacement = _TERMINAL_ESCAPES.get(character)
        if replacement is not None:
            escaped.append(replacement)
            continue
        code = ord(character)
        if (
            0xD800 <= code <= 0xDFFF
            or code in _FORMAT_CONTROL_CODES
            or unicodedata.category(character) == "Cf"
        ):
            escaped.append(_python_escape(code))
            continue
        escaped.append(character)
    return "".join(escaped)


#: The most characters of any one result-derived string either renderer
#: prints. The corpus schema bounds what a *producer* can put in a verdict —
#: ``MAX_EVIDENCE_TEXT`` per string, ``MAX_GATE_TEXT`` and
#: ``MAX_REMOVED_TEXT`` per section — and those bounds cover corpus-derived
#: output only. Nothing bounded the custody half: a release manifest whose
#: ``schemaVersion`` is a million characters puts that value into a
#: ``ReleaseChainError`` before the signature is ever checked, and the text
#: renderer printed it twice — once on the pass line and once after
#: ``VERDICT: FAIL`` — while the JSON printed it once (peer review, round
#: eight). Bounding at the schema boundary of every library this command
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


def _bounded(text: str) -> str:
    """Truncate one rendered string to :data:`MAX_RENDERED_FIELD` characters.

    The marker is ``receipt.corpus._quoted``'s, so a truncation reads the
    same wherever an auditor meets one, and it names the number of
    characters omitted rather than merely saying that something was.

    Applied *after* :func:`_terminal_safe` in the text renderer, so what is
    counted is what the terminal receives: an escape sequence is six
    characters of output and is charged as six. In the JSON renderer it is
    applied to the payload's string values before ``json.dumps``, which is
    the same rule one step earlier — the escaping there is the encoder's own
    and cannot be applied first.
    """

    if len(text) <= MAX_RENDERED_FIELD:
        return text
    omitted = len(text) - MAX_RENDERED_FIELD
    return f"{text[:MAX_RENDERED_FIELD]}…[{omitted} more characters]"


def _rendered(text: str) -> str:
    """Escape a result-derived string and then bound it: the text renderer's rule.

    One function so the two policies cannot be applied to different sets of
    strings. Every string ``_format_text`` and :func:`_refuse` take from a
    result go through this and nothing else does.
    """

    return _bounded(_terminal_safe(text))


def _encoded_length(character: str) -> int:
    """What ``json.dumps`` emits for one character, its quotes excluded.

    Taken from the escaper ``json.dumps`` applies rather than guessed at,
    the way ``receipt.corpus._rendered_length`` takes it: with
    ``ensure_ascii`` at its default one BMP character outside ASCII leaves
    as six characters and one outside the BMP as twelve, a surrogate pair
    spelled ``\\uXXXX\\uXXXX``.
    """

    return len(json.encoder.encode_basestring_ascii(character)) - 2


def _encoded_split(text: str) -> tuple[str, int] | None:
    """The longest prefix whose encoding fits the bound, and what it dropped.

    ``None`` when the whole string fits. Accumulated one character at a time
    and stopped at the first character that carries the total over, so the
    work is bounded by the limit rather than by the length of the string.
    """

    total = 0
    for index, character in enumerate(text):
        total += _encoded_length(character)
        if total > MAX_RENDERED_FIELD:
            return text[:index], len(text) - index
    return None


def _bounded_encoded(text: str) -> str:
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
    that is what a terminal receives: see :func:`_bounded`.
    """

    split = _encoded_split(text)
    if split is None:
        return text
    prefix, omitted = split
    return f"{prefix}…[{omitted} more characters]"


def _bounded_key(key: str) -> str:
    """The same bound for a JSON object key, made collision-proof by digest.

    Keys were left unbounded, and the reason given was a real one: two long
    keys truncated to the same text collide, and one silently replaces the
    other, which turns a length policy into a data-loss policy. What was
    wrong was the conclusion. A gate evidence key may be 1,024 characters
    under ``receipt.corpus.MAX_EVIDENCE_TEXT``, and 1,024 characters outside
    the BMP render as 12,288 — a key alone can scroll the verdict away, and
    ``_bounded_payload`` never looked at one (peer review, Sol round 2).

    So a key is bounded like a value and then made unambiguous: the marker
    carries the first sixteen hex characters of the key's SHA-256, so two
    keys sharing a bounded prefix differ in the marker and cannot merge.
    The digest is over the key's UTF-8 with ``surrogatepass``, because a key
    that reached here from a filesystem name may carry a lone surrogate and
    a digest that raises would defeat the renderer it protects.
    """

    split = _encoded_split(key)
    if split is None:
        return key
    prefix, omitted = split
    digest = hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()
    return f"{prefix}…[{omitted} more characters; sha256 {digest[:16]}]"


def _bounded_payload(value: object) -> object:
    """The JSON payload with every string bounded, structure unchanged.

    Walked rather than listed, for the reason :data:`MAX_RENDERED_FIELD`
    gives: a field-by-field bound covers the fields someone thought of.
    Values go through :func:`_bounded_encoded` and keys through
    :func:`_bounded_key`, both of which measure what ``json.dumps`` will
    emit rather than what Python holds.
    """

    if isinstance(value, str):
        return _bounded_encoded(value)
    if isinstance(value, dict):
        return {
            _bounded_key(key): _bounded_payload(item) for key, item in value.items()
        }
    if isinstance(value, list):
        return [_bounded_payload(item) for item in value]
    return value


def _format_text(result: VerifyResult) -> str:
    lines: list[str] = []
    version = _rendered(result.receipt_version)
    lines.append(f"receipt {version} — {_rendered(result.spec_name)}")
    lines.append(f"  root  {_rendered(str(result.root))}")
    lines.append(f"  spec  {_rendered(str(result.spec_path))}")
    lines.append(f"        sha256 {_rendered(result.spec_sha256)}")
    lines.append("")

    if result.ok:
        lines.append("ESTABLISHED OFFLINE, FROM THIS CLONE ALONE")
    else:
        lines.append("PASSES")
    for item in result.passes:
        mark = "ok  " if item.ok else "FAIL"
        lines.append(f"  [{mark}] {_rendered(item.name)}")
        if item.ok:
            lines.append(f"         {_rendered(item.detail)}")
        else:
            # str(), not "or ''": a failed pass always carries a failure
            # string, and rendering a hypothetical None as "None" is what
            # this line did before the escaping was added to it.
            lines.append(f"         {_rendered(str(item.failure))}")

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
                    suffix = f"  [WAIVED under waiver set {_rendered(waiver)}…]"
                elif gate.outcome == "not-run":
                    reason = _rendered(gate.evidence.get("reason", ""))
                    suffix = f"  [DID NOT RUN — {reason}]"
                lines.append(f"    - {_rendered(gate.gate_id)}{suffix}")

    lines.append("")
    if result.ok:
        # The witness clause is derived from what was actually verified, not
        # asserted: a spec pinning one anchor must not be described as two.
        # The anchor names come from the consumer's committed spec rather
        # than from a producer, but they are result data and the rule here
        # admits no exceptions: nothing reaches a line unescaped.
        witnesses = [_rendered(name) for name in sorted(result.witness_times())]
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
        name = _rendered(failure.name) if failure else "verification"
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
        lines.append(f"  {_rendered(str(detail))}")
        lines.append("")
        lines.append(f"VERDICT: FAIL — {name}")
    return "\n".join(lines)


def _emit(text: str, stream: TextIO) -> None:
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

    The text stream is flushed before the buffer is written so the two
    layers cannot reorder, and a stream with no usable ``buffer`` — a
    wrapper some host has substituted, or a wrapper whose buffer has been
    detached, which raises rather than being absent — is written through its
    text API with the same already-encoded text, which by construction it
    can encode.
    """

    encoding = getattr(stream, "encoding", None) or "utf-8"
    data = (text + "\n").encode(encoding, errors="backslashreplace")
    try:
        # Not ``getattr(..., None)``: a detached ``TextIOWrapper`` raises
        # ValueError from the property rather than being missing it, and a
        # default only absorbs AttributeError.
        buffer = stream.buffer
    except (AttributeError, ValueError):
        buffer = None
    if buffer is None:
        stream.write(data.decode(encoding, errors="replace"))
        stream.flush()
        return
    stream.flush()
    buffer.write(data)
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
    and bounded on its way to the terminal. The JSON half takes the message
    unescaped — ``json.dumps`` escapes it there — but bounded by the same
    policy, because an abort message can carry a producer's flood as readily
    as a completed verdict can.

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
        _emit(f"receipt verify: {_rendered(message)}\nreceipt verify: FAIL", sys.stderr)
    except Exception:  # noqa: BLE001 - a refusal that cannot print is still a refusal
        pass
    if as_json:
        try:
            _emit(
                json.dumps(
                    _bounded_payload(_fail_payload(stage, message)),
                    indent=2,
                    sort_keys=True,
                ),
                sys.stdout,
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
            rendered = json.dumps(
                _bounded_payload(result_to_dict(result)), indent=2, sort_keys=True
            )
            _emit(rendered, sys.stdout)
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
            text = _format_text(result)
            _emit(text, sys.stdout if result.ok else sys.stderr)
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
