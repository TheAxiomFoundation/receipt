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
from the result goes through :func:`_terminal_safe` before it reaches a line.
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

The JSON renderer needs nothing of the kind. ``json.dumps`` with
``ensure_ascii`` at its default escapes every non-ASCII code point into a
``\\uXXXX`` sequence inside the quoted string — lone surrogates and format
controls included — and every code point below 0x20 with it, so a machine
consumer receives them as data and no terminal ever sees them raw.

What both renderers do share is a bound on length rather than on content:
see :data:`MAX_RENDERED_FIELD`.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import unicodedata
from typing import Sequence

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

    Applied to every string the text verdict takes from the result — pass
    names, details and failures, the spec's name and path, the root, gate
    ids, evidence keys and values, and the abort message ``_refuse`` prints —
    and to nothing else. The fixed lines of the verdict are literals in this
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


def _format_text(result: VerifyResult) -> str:
    lines: list[str] = []
    version = _terminal_safe(result.receipt_version)
    lines.append(f"receipt {version} — {_terminal_safe(result.spec_name)}")
    lines.append(f"  root  {_terminal_safe(str(result.root))}")
    lines.append(f"  spec  {_terminal_safe(str(result.spec_path))}")
    lines.append(f"        sha256 {_terminal_safe(result.spec_sha256)}")
    lines.append("")

    if result.ok:
        lines.append("ESTABLISHED OFFLINE, FROM THIS CLONE ALONE")
    else:
        lines.append("PASSES")
    for item in result.passes:
        mark = "ok  " if item.ok else "FAIL"
        lines.append(f"  [{mark}] {_terminal_safe(item.name)}")
        if item.ok:
            lines.append(f"         {_terminal_safe(item.detail)}")
        else:
            # str(), not "or ''": a failed pass always carries a failure
            # string, and rendering a hypothetical None as "None" is what
            # this line did before the escaping was added to it.
            lines.append(f"         {_terminal_safe(str(item.failure))}")

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
                    suffix = f"  [WAIVED under waiver set {_terminal_safe(waiver)}…]"
                elif gate.outcome == "not-run":
                    reason = _terminal_safe(gate.evidence.get("reason", ""))
                    suffix = f"  [DID NOT RUN — {reason}]"
                lines.append(f"    - {_terminal_safe(gate.gate_id)}{suffix}")

    lines.append("")
    if result.ok:
        # The witness clause is derived from what was actually verified, not
        # asserted: a spec pinning one anchor must not be described as two.
        # The anchor names come from the consumer's committed spec rather
        # than from a producer, but they are result data and the rule here
        # admits no exceptions: nothing reaches a line unescaped.
        witnesses = [_terminal_safe(name) for name in sorted(result.witness_times())]
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
        name = _terminal_safe(failure.name) if failure else "verification"
        lines.append(f"VERDICT: FAIL — {name}")
        lines.append(f"  {_terminal_safe(str(detail))}")
    return "\n".join(lines)


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
    on its way to the terminal. The JSON half takes the message unescaped —
    ``json.dumps`` escapes it there — so a machine consumer still receives
    exactly what the exception said.
    """

    print(f"receipt verify: {_terminal_safe(message)}", file=sys.stderr)
    if as_json:
        print(json.dumps(_fail_payload(stage, message), indent=2, sort_keys=True))
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
    if as_json:
        try:
            rendered = json.dumps(result_to_dict(result), indent=2, sort_keys=True)
        except Exception as exc:  # noqa: BLE001 - rendering is inside the contract
            return _refuse(
                as_json,
                "render",
                "verdict could not be rendered; treat the run as unverified: "
                f"{type(exc).__name__}: {exc}",
                EXIT_FAIL,
            )
        print(rendered)
    else:
        try:
            text = _format_text(result)
        except Exception as exc:  # noqa: BLE001 - rendering is inside the contract
            return _refuse(
                False,
                "render",
                "verdict could not be rendered; treat the run as unverified: "
                f"{type(exc).__name__}: {exc}",
                EXIT_FAIL,
            )
        stream = sys.stdout if result.ok else sys.stderr
        print(text, file=stream)
    return EXIT_OK if result.ok else EXIT_FAIL


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
