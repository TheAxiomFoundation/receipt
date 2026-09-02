"""Consumer-side corpus binding: does a witnessed journal describe THIS tree?

``receipt.release_chain`` proves custody of a journal — that the manifests are
hash-chained, canonically serialized, signed by a code-pinned producer key, and
witnessed by the consumer's configured RFC 3161 anchor set. It says nothing about
what the journal's rows *mean*.

This module supplies the missing half for a published rule corpus: the journal
rows enumerate content files by digest, and verification is a closed-world
comparison against the working tree. An unlisted file, a missing file, a
rewritten byte, a symlink where a regular file was recorded — each refuses.

A binding covers the bytes and the regular-file type, not the permission bits
— no row kind carries a mode, so a content file that gained the execute bit
after witnessing still matches its digest and still verifies here, while
release-object modes are covered separately by ``receipt verify --base-ref``,
which holds every release file present at that ref byte- and mode-identical.

Three row kinds, one journal:

``content``
    A file inside a consumer-declared content root, with a consumer-declared
    suffix. These are swept closed-world: the effective present set must equal
    the tree's set exactly, in both membership and digest. Membership is
    decided after folding — root and suffix alike are compared under Unicode
    NFC plus case folding — so neither a case- or normalization-varied
    spelling of a pinned suffix nor one of a pinned root can sit outside the
    closed world on a filesystem that treats it as the same file. A tree
    entry that aliases a root's own spelling is refused by name rather than
    merged.

``attested``
    An exact path bound by digest without a sweep — the toolchain pin, the
    pinned validation workflow, an apply manifest. The consumer's spec names
    which paths it *requires*, so a producer cannot quietly drop one.
    Retiring one is recorded by a ``removed`` row, and the file has to leave
    the tree with it: a removed path still on disk refuses, whichever kind
    it was. Two questions are asked about a tombstone, in this order — does
    the host resolve the exact spelling, and does any fold-equal spelling
    survive in a listing — because a filesystem resolves names its own
    enumeration does not emit.

``gate``
    A declaration that some verification gate ran, carrying a reproducibility
    tier (axiom-encode#1192 requirement 6). This module validates the shape of
    the declaration and refuses an unpinned tier. It never re-executes a gate
    and never treats a declaration as evidence the gate passed. A caller that
    reports a ``restricted`` or ``ci-attested`` gate as "verified" is
    misreporting; :func:`verify_corpus_binding` returns the tiers separated so
    the distinction survives into the verdict.

Every trust anchor arrives from the consumer's committed :class:`CorpusSpec`.
The module ships no defaults: not a content root, not a required gate, not an
accepted tier.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import stat
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, NamedTuple

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
GATE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}\Z")
#: The 8.3 shape an NTFS short name has: a stem of at most eight characters
#: and an optional extension of at most three. A component of this shape that
#: also carries a tilde-digit is the spelling Win32 hands out as an alias for
#: a long name, and it opens the long name's file.
SHORT_NAME_SHAPE_RE = re.compile(r"[^.]{1,8}(\.[^.]{1,3})?\Z")
SHORT_NAME_TILDE_RE = re.compile(r"~[0-9]")

CONTENT_KIND = "content"
ATTESTED_KIND = "attested"
GATE_KIND = "gate"
ROW_KINDS = frozenset({CONTENT_KIND, ATTESTED_KIND, GATE_KIND})

PRESENT = "present"
REMOVED = "removed"
FILE_STATES = frozenset({PRESENT, REMOVED})

PASS = "pass"
WAIVED = "waived"
#: A gate the pipeline was configured not to run. Recording it is mandatory:
#: a journal that simply omits a disabled gate reads identically to one where
#: the gate passed, which is the exact over-claim this schema exists to stop.
NOT_RUN = "not-run"
GATE_OUTCOMES = frozenset({PASS, WAIVED, NOT_RUN})

#: Reproducibility tiers, in descending order of what an outsider can check
#: alone. The consumer pins which of these its spec accepts; the package
#: asserts only that a tier outside this closed set is a hard refusal.
PUBLIC_TIER = "public"
RESTRICTED_TIER = "restricted"
CI_ATTESTED_TIER = "ci-attested"
GATE_TIERS = (PUBLIC_TIER, RESTRICTED_TIER, CI_ATTESTED_TIER)

#: Tiers an offline third party can re-establish without privileged inputs.
#: Exactly one, and naming it here keeps the honesty rule in one place.
INDEPENDENTLY_REPRODUCIBLE_TIERS = frozenset({PUBLIC_TIER})

#: The longest gate-evidence key or value the schema accepts. Sanitising
#: bounds what one character can do to a rendered verdict; nothing bounded how
#: many of them a producer may supply. A gate whose evidence carries two
#: hundred thousand blameless characters scrolls every line an auditor needed
#: to read out of the terminal, which defeats the verdict as surely as an
#: escape sequence would.
MAX_EVIDENCE_TEXT = 1024
#: The most characters of gate id and evidence the effective view may carry
#: in total. The per-string bound above caps one flood; a journal of a
#: thousand not-run gates each carrying a bound-length reason still put a
#: million characters into the verdict (peer review). Generous for any real
#: corpus, which declares tens of gates with digest-sized evidence.
MAX_GATE_TEXT = 262144
#: The most characters one journal path may carry. Paths are quoted in
#: refusals and, for removed paths, rendered in the verdict; the bound is
#: checked before any other path rule so no refusal quotes a flood.
MAX_PATH_TEXT = 1024
#: The most characters the verdict's removedPaths may carry in total; the
#: gate budget's counterpart for the other producer-controlled list the
#: verdict renders verbatim (peer review, round two).
MAX_REMOVED_TEXT = 262144
#: The most directory entries the whole tombstone pass may touch before it is
#: refused as unverifiable rather than allowed to run on. Counted in entries
#: rather than listings, and once for the pass rather than once per removed
#: path: a per-path listing budget bounded each search while leaving the pass
#: itself quadratic, so R tombstones against a root of E entries cost R×E with
#: nothing to stop it (peer review, round three). The index below reads each
#: directory once and shares it across every removed path, so the real cost is
#: the tree, and this bounds that.
#:
#: An entry is charged when it is consumed from a listing and again each time
#: a search visits it as a candidate, because both are work and neither was
#: bounded by counting listings alone: the whole of an arbitrarily wide
#: directory was read and sorted before anything checked the budget, and a
#: cached fold-collision bucket was re-traversed by every tombstone for free
#: (peer review, round four).
MAX_TOMBSTONE_WORK = 262144
#: The most characters a refusal quotes of a producer-controlled value.
MAX_QUOTED_TEXT = 256

_ROW_KEYS: dict[str, frozenset[str]] = {
    CONTENT_KIND: frozenset(
        {"schemaVersion", "entryIndex", "kind", "path", "sha256", "state"}
    ),
    ATTESTED_KIND: frozenset(
        {"schemaVersion", "entryIndex", "kind", "path", "sha256", "state"}
    ),
    GATE_KIND: frozenset(
        {"schemaVersion", "entryIndex", "kind", "gateId", "tier", "outcome", "evidence"}
    ),
}


class CorpusError(ValueError):
    """The journal is malformed, or it does not describe this working tree."""


@dataclass(frozen=True)
class CorpusSpec:
    """Corpus-specific binding constants, pinned in the consumer's code.

    The producer chooses what to write into the journal. The consumer chooses
    what the journal must cover before a verdict is allowed to pass. Every
    field here is the second kind of choice, which is why none of them have
    package defaults.
    """

    schema_version: str
    content_roots: tuple[pathlib.PurePosixPath, ...]
    content_suffixes: tuple[str, ...]
    required_attested_paths: frozenset[str]
    accepted_gate_tiers: frozenset[str]
    required_gates: frozenset[str]

    def __post_init__(self) -> None:
        if type(self.schema_version) is not str or not self.schema_version:
            raise CorpusError("CorpusSpec schema_version must be a non-empty string")
        if type(self.content_roots) is not tuple or not self.content_roots:
            raise CorpusError("CorpusSpec must declare at least one content root")
        for root in self.content_roots:
            if not isinstance(root, pathlib.PurePosixPath):
                raise CorpusError("CorpusSpec content_roots must be PurePosixPath")
            # The spec's own two fold inputs are screened here, before the
            # path rules, so a refusal names the committed spec that carries
            # the fault rather than a path. A root also reaches
            # _validate_relative_path below, which screens it again; a suffix
            # reached nothing, which is the hole (see the suffix loop).
            for component in root.as_posix().split("/"):
                _assert_assigned(component, "CorpusSpec content root")
            _validate_relative_path(root.as_posix(), "content root")
        if type(self.content_suffixes) is not tuple or not self.content_suffixes:
            raise CorpusError("CorpusSpec must declare at least one content suffix")
        for suffix in self.content_suffixes:
            if type(suffix) is not str or not suffix.startswith("."):
                raise CorpusError(
                    f"CorpusSpec content suffix must start with '.': {_quoted(suffix)}"
                )
            # A suffix was checked for its leading dot and nothing else, while
            # _has_pinned_suffix folds it against every path in the tree and
            # against every entry name the sweep sees. An unassigned code
            # point in one folds differently under each supported table, so
            # which files the closed world contained depended on the
            # verifier's interpreter — the same defect _assert_assigned closes
            # everywhere else this module folds (peer review, round four).
            _assert_assigned(suffix, "CorpusSpec content suffix")
        if type(self.required_attested_paths) is not frozenset:
            raise CorpusError("CorpusSpec required_attested_paths must be a frozenset")
        for path in sorted(self.required_attested_paths):
            _validate_relative_path(path, "required attested path")
        if type(self.accepted_gate_tiers) is not frozenset:
            raise CorpusError("CorpusSpec accepted_gate_tiers must be a frozenset")
        unknown = sorted(self.accepted_gate_tiers - set(GATE_TIERS))
        if unknown:
            raise CorpusError(
                "CorpusSpec accepts unknown reproducibility tier "
                f"{_quoted(unknown[0])}; "
                f"known tiers are {', '.join(GATE_TIERS)}"
            )
        if type(self.required_gates) is not frozenset:
            raise CorpusError("CorpusSpec required_gates must be a frozenset")
        for gate_id in sorted(self.required_gates):
            if GATE_ID_RE.fullmatch(gate_id) is None:
                raise CorpusError(
                    f"CorpusSpec required gate id is malformed: {_quoted(gate_id)}"
                )

    def content_root_of(self, path: str) -> pathlib.PurePosixPath | None:
        """The pinned root this path sits under, compared by fold key.

        Byte-exact membership contradicted the rest of the module. The suffix
        predicate folds, the alias guard folds, and the tombstone search
        folds — but a path's *root* was matched byte for byte, so on a
        case-sensitive host "RULES/evil.yaml" sat outside the pinned "rules/"
        root, was not content, and was never swept; on a case-insensitive
        host the same bytes are inside it. Which host the auditor cloned onto
        decided whether the closed world contained the file (peer review,
        round three). Folded, both hosts agree it is content, and the tree
        walk below refuses the aliasing spelling outright.
        """

        folded = _path_fold(path)
        for root in self.content_roots:
            if folded.startswith(_path_fold(root.as_posix()) + "/"):
                return root
        return None

    def is_content_path(self, path: str) -> bool:
        if self.content_root_of(path) is None:
            return False
        return _has_pinned_suffix(path, self.content_suffixes)


@dataclass(frozen=True)
class FileBinding:
    path: str
    sha256: str
    entry_index: int


@dataclass(frozen=True)
class GateDeclaration:
    """One gate the producer declares ran, with its reproducibility tier.

    This is a *declaration*, not a verification. ``tier`` states what an
    outsider could do about it: re-run it (``public``), re-run it only with
    inputs they may not have (``restricted``), or nothing but trust CI's
    identity (``ci-attested``).
    """

    gate_id: str
    tier: str
    outcome: str
    evidence: Mapping[str, str]
    entry_index: int

    @property
    def independently_reproducible(self) -> bool:
        return self.tier in INDEPENDENTLY_REPRODUCIBLE_TIERS


@dataclass(frozen=True)
class CorpusVerification:
    """What the journal binds, after it has been proved to match the tree."""

    content: tuple[FileBinding, ...]
    attested: tuple[FileBinding, ...]
    gates: tuple[GateDeclaration, ...]
    removed_paths: tuple[str, ...]

    def gates_in_tier(self, tier: str) -> tuple[GateDeclaration, ...]:
        return tuple(gate for gate in self.gates if gate.tier == tier)

    @property
    def reproducible_gates(self) -> tuple[GateDeclaration, ...]:
        return tuple(gate for gate in self.gates if gate.independently_reproducible)

    @property
    def unreproducible_gates(self) -> tuple[GateDeclaration, ...]:
        return tuple(gate for gate in self.gates if not gate.independently_reproducible)


def _quoted(value: Any) -> str:
    """repr of a producer-controlled value, truncated so a refusal is bounded.

    Every value a refusal quotes goes through here, not only the two that
    started it. A refusal is rendered into the verdict an auditor reads, and
    the schema bounds only some of the strings a producer can put in one: a
    row's ``kind``, ``schemaVersion``, ``entryIndex``, ``tier``, ``outcome``,
    ``sha256`` and ``state``, and the unknown-key list, were all reproduced
    verbatim, so a million-character tier scrolled the verdict away exactly
    as an oversized evidence string would have (peer review, round three).
    A path is bounded at ``MAX_PATH_TEXT``, which is still four times what
    belongs on a line.

    Under the bound this is plain ``repr``, so it changes no refusal a real
    corpus can produce — and ``repr`` is also what escapes a control character
    a filesystem name may carry, which is why tree-derived paths come through
    here too.
    """

    text = repr(value)
    if len(text) <= MAX_QUOTED_TEXT:
        return text
    return f"{text[:MAX_QUOTED_TEXT]}…[{len(text) - MAX_QUOTED_TEXT} more characters]"


#: Unicode category Cf as of Unicode 16.0.0, the table Python 3.14 ships,
#: pinned here so the refusal does not depend on which interpreter renders
#: the verdict: Python 3.11 carries Unicode 14, under which U+1343A is
#: unassigned and passed while 3.12 and 3.13 refused it (peer review). A code
#: point refuses if it is in this table OR the running interpreter's table
#: calls it Cf, so a later table can only widen the set, never narrow it.
_FORMAT_CONTROL_RANGES = (
    (0x00AD, 0x00AD), (0x0600, 0x0605), (0x061C, 0x061C), (0x06DD, 0x06DD),
    (0x070F, 0x070F), (0x0890, 0x0891), (0x08E2, 0x08E2), (0x180E, 0x180E),
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x206F),
    (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0x110BD, 0x110BD), (0x110CD, 0x110CD),
    (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001), (0xE0020, 0xE007F),
)


def _is_format_control(code: int, category: str) -> bool:
    if category == "Cf":
        return True
    return any(low <= code <= high for low, high in _FORMAT_CONTROL_RANGES)


def _reject_control_characters(value: str, label: str) -> str:
    """Refuse control, format, and line-separator code points in producer text.

    Every string in this schema is written by a producer and later rendered to
    a terminal. A carriage return, an ESC, or a line feed inside one lets the
    producer redraw the verdict: a witnessed "reason" carrying
    ``\\x1b[2K\\r  VERDICT: PASS`` overwrites the line that was about to say the
    gate did not run. The verdict is the product here, so the sanitising
    belongs at the schema boundary where the text enters, not only at the
    point where it is printed. (Found by cross-family review.)

    The C0 block is not the only way to do it, so two more classes refuse
    here:

    - Every code point in Unicode category Cf, as of Unicode 16.0 and pinned
      in this module (``_FORMAT_CONTROL_RANGES``), or in the running
      interpreter's own table. These render as nothing while
      changing what the reader sees: U+202E RIGHT-TO-LEFT OVERRIDE reverses
      the remainder of the line, so a gate declared not-run can be spelled to
      read as passed, and U+200B lets two evidence keys print identically.
    - U+2028 and U+2029, line separators outside the C0 block, which split one
      evidence string into as many verdict lines as the producer wants in any
      renderer that honours them.
    - Every code point in category Cs, a lone surrogate. JSON spells one as
      ``\\ud800`` inside otherwise valid UTF-8, so it survives the decode; no
      filesystem call accepts it (``os.lstat`` raises ``UnicodeEncodeError``,
      a ``ValueError`` no ``OSError`` handler sees); and no legitimate path or
      reason carries one.

    Taking the Cf class whole has a cost, accepted deliberately: U+200C and
    U+200D are required spelling in Persian, Hindi and Sinhala, and U+061C
    appears in ordinary Arabic text, so a rule file named in those scripts,
    or a not-run reason written in them, refuses here. The verdict quotes
    these strings to a reader, and a reader cannot tell apart two spellings
    that differ only in an invisible code point; a narrower list would have
    to be maintained against exactly that threat. Refusing is the fail-closed
    side, and the refusal names the code point so the cause is legible.
    """

    for character in value:
        code = ord(character)
        category = unicodedata.category(character)
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            raise CorpusError(
                f"{label} contains a control character ({code:#04x}): {_quoted(value)}"
            )
        if _is_format_control(code, category):
            raise CorpusError(
                f"{label} contains a Unicode format control "
                f"({code:#04x}): {_quoted(value)}"
            )
        if category == "Cs":
            raise CorpusError(
                f"{label} contains a lone surrogate ({code:#04x}): {_quoted(value)}"
            )
        if code in (0x2028, 0x2029):
            raise CorpusError(
                f"{label} contains a Unicode line separator "
                f"({code:#04x}): {_quoted(value)}"
            )
    return value


def _reject_oversized_text(value: str, label: str) -> str:
    """Refuse producer text too long to belong in a verdict a human reads.

    Checked before the character screen, deliberately: that screen quotes the
    offending value back, so refusing a two-hundred-thousand-character string
    there would emit the flood it exists to prevent. This message carries the
    length instead of the text.
    """

    if len(value) > MAX_EVIDENCE_TEXT:
        raise CorpusError(
            f"{label} is longer than {MAX_EVIDENCE_TEXT} characters: "
            f"{len(value)} characters"
        )
    return value


def _assert_assigned(value: str, label: str) -> str:
    """Refuse text carrying a code point no Unicode table has assigned yet.

    The fold key (see :func:`_path_fold`) is only stable across Unicode tables
    for assigned characters: the standard's stability policies fix case
    folding and normalization once a character is encoded, and say nothing
    before. An unassigned code point folded one way on Unicode 15 and another
    on 16 (U+10D50, peer review), so text carrying one could alias under one
    interpreter and not another.

    Declared paths were screened here from the start. Filesystem entry names
    were not, and they are folded by the sweep, by the suffix predicate, and
    by the tombstone search — U+A7CB folds to U+0264 on Unicode 16 and to
    itself before it, so which files a closed-world sweep considers the same
    file depended on the verifier's interpreter (peer review, round three).
    Every name this module folds passes through here first, so the fold key
    means one thing on every supported table.

    The refusal names the running table, since that is what decided it.
    """

    for character in value:
        if unicodedata.category(character) == "Cn":
            raise CorpusError(
                f"{label} contains a code point unassigned in Unicode "
                f"{unicodedata.unidata_version} ({ord(character):#06x}): "
                f"{_quoted(value)}"
            )
    return value


def _aliases_natively(segment: str) -> bool:
    """Whether Win32 resolves this component under a spelling nothing emits.

    Two shapes, both of which open a file the fold model would call a
    different name. Win32 strips trailing dots and spaces from a component
    before the lookup, so ``"x.yaml."`` and ``"x.yaml "`` open ``"x.yaml"``;
    and an NTFS volume with 8.3 generation on hands out a short name such as
    ``"RULESF~1.YAM"`` that opens the long name's file. Neither spelling is
    ever emitted by a directory listing, so no fold key can catch it.
    """

    if segment != segment.rstrip(". "):
        return True
    return (
        SHORT_NAME_TILDE_RE.search(segment) is not None
        and SHORT_NAME_SHAPE_RE.fullmatch(segment) is not None
    )


def _validate_relative_path(value: Any, label: str) -> str:
    """Reject anything that could escape the root or alias another entry."""

    if type(value) is not str or not value:
        raise CorpusError(f"{label} must be a non-empty string")
    if len(value) > MAX_PATH_TEXT:
        # First, so that no refusal below quotes a flood.
        raise CorpusError(
            f"{label} is longer than {MAX_PATH_TEXT} characters ({len(value)})"
        )
    if "\\" in value:
        raise CorpusError(f"{label} must use POSIX separators: {_quoted(value)}")
    if value.startswith("/") or value.endswith("/"):
        raise CorpusError(
            f"{label} must be relative with no trailing slash: {_quoted(value)}"
        )
    segments = value.split("/")
    for segment in segments:
        if not segment:
            raise CorpusError(f"{label} has an empty path segment: {_quoted(value)}")
        if segment in (".", ".."):
            raise CorpusError(f"{label} contains a relative segment: {_quoted(value)}")
        if _aliases_natively(segment):
            # Two spellings Win32 resolves that no enumeration emits, so the
            # fold model cannot see them and a tombstone or a closed-world
            # sweep would call the file absent while it still opens (peer
            # review, round three). "rules.yaml." and "rules.yaml " are the
            # same file as "rules.yaml" — the lookup strips trailing dots and
            # spaces — and "RULESF~1.YAM" is the 8.3 short name NTFS hands
            # out for a long one. A declared path spelled either way aliases
            # a path this module cannot enumerate, so it is refused rather
            # than modelled.
            raise CorpusError(
                f"{label} has a component Windows would alias: {_quoted(value)}"
            )
    _reject_control_characters(value, label)
    _assert_assigned(value, label)
    if ":" in value:
        # On Windows, "C:/x" survives every relative-path check above yet
        # joins drive-absolute under pathlib, letting a row reference a file
        # outside the root. No path in this schema legitimately contains a
        # colon; refuse rather than special-case the platform.
        raise CorpusError(f"{label} contains ':': {_quoted(value)}")
    return value


def _exact_keys(row: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if type(row) is not dict:
        raise CorpusError(f"{label} must be a JSON object")
    actual = set(row)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise CorpusError(
            f"{label} keys are not closed-world: missing={_quoted(missing)}, "
            f"unknown={_quoted(unknown)}"
        )
    return row


def _string(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise CorpusError(f"{label} must be a non-empty string")
    return value


def _sha256(value: Any, label: str) -> str:
    text = _string(value, label)
    if SHA256_RE.fullmatch(text) is None:
        raise CorpusError(
            f"{label} is not a lowercase SHA-256 hex digest: {_quoted(text)}"
        )
    return text


def _parse_row(line: str, number: int, spec: CorpusSpec) -> dict[str, Any]:
    try:
        parsed = json.loads(line, object_pairs_hook=_object_without_duplicates)
    except json.JSONDecodeError as exc:
        raise CorpusError(f"journal row {number} is not valid JSON: {exc}") from exc
    if type(parsed) is not dict:
        raise CorpusError(f"journal row {number} is not a JSON object")
    kind = parsed.get("kind")
    # Check the type before set membership: an unhashable JSON value such as
    # [] or {} would make `kind not in ROW_KINDS` raise TypeError instead of
    # refusing with the documented CorpusError.
    if type(kind) is not str or kind not in ROW_KINDS:
        raise CorpusError(
            f"journal row {number} has unknown kind {_quoted(kind)}; "
            f"expected one of {', '.join(sorted(ROW_KINDS))}"
        )
    row = _exact_keys(parsed, _ROW_KEYS[kind], f"journal row {number}")
    if row["schemaVersion"] != spec.schema_version:
        raise CorpusError(
            f"journal row {number} declares schema {_quoted(row['schemaVersion'])}, "
            f"but the pinned spec is {_quoted(spec.schema_version)}"
        )
    index = row["entryIndex"]
    if type(index) is not int or index != number - 1:
        raise CorpusError(
            f"journal row {number} entryIndex must be {number - 1}, "
            f"found {_quoted(index)}"
        )
    return row


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CorpusError(f"journal row has duplicate key {_quoted(key)}")
        result[key] = value
    return result


def _validate_gate(row: dict[str, Any], number: int, spec: CorpusSpec) -> GateDeclaration:
    gate_id = _string(row["gateId"], f"journal row {number} gateId")
    if GATE_ID_RE.fullmatch(gate_id) is None:
        raise CorpusError(
            f"journal row {number} gateId is malformed: {_quoted(gate_id)}"
        )
    tier = _string(row["tier"], f"journal row {number} tier")
    if tier not in GATE_TIERS:
        raise CorpusError(
            f"journal row {number} gate {_quoted(gate_id)} declares unknown "
            f"reproducibility tier {_quoted(tier)}"
        )
    if tier not in spec.accepted_gate_tiers:
        raise CorpusError(
            f"journal row {number} gate {_quoted(gate_id)} declares tier "
            f"{_quoted(tier)}, which the pinned spec does not accept"
        )
    outcome = _string(row["outcome"], f"journal row {number} outcome")
    if outcome not in GATE_OUTCOMES:
        raise CorpusError(
            f"journal row {number} gate {_quoted(gate_id)} has unknown "
            f"outcome {_quoted(outcome)}"
        )
    evidence = row["evidence"]
    if type(evidence) is not dict or not evidence:
        raise CorpusError(
            f"journal row {number} gate {_quoted(gate_id)} evidence must be "
            "a non-empty object"
        )
    for key, value in evidence.items():
        if type(key) is not str or type(value) is not str:
            raise CorpusError(
                f"journal row {number} gate {_quoted(gate_id)} evidence must map "
                "strings to strings"
            )
        key_label = f"journal row {number} gate {_quoted(gate_id)} evidence key"
        value_label = (
            f"journal row {number} gate {_quoted(gate_id)} evidence value "
            f"{_quoted(key)}"
        )
        _reject_oversized_text(key, key_label)
        _reject_oversized_text(value, value_label)
        _reject_control_characters(key, key_label)
        _reject_control_characters(value, value_label)
    # A waiver is the one outcome that admits a known failure. It has to name
    # the waiver set it was excused under by digest, or "waived" is
    # unfalsifiable — and a placeholder like "x" is no more falsifiable than a
    # missing field, so the value must be a real SHA-256.
    if outcome == WAIVED:
        if "waiverSetSha256" not in evidence:
            raise CorpusError(
                f"journal row {number} gate {_quoted(gate_id)} is waived "
                "without naming evidence.waiverSetSha256"
            )
        _sha256(
            evidence["waiverSetSha256"],
            f"journal row {number} gate {_quoted(gate_id)} evidence.waiverSetSha256",
        )
    # Same principle for a gate that did not run: state why, or the
    # declaration is decoration. A whitespace-only reason is no reason.
    if outcome == NOT_RUN and not evidence.get("reason", "").strip():
        raise CorpusError(
            f"journal row {number} gate {_quoted(gate_id)} is declared not-run "
            "without a non-empty evidence.reason"
        )
    return GateDeclaration(
        gate_id=gate_id,
        tier=tier,
        outcome=outcome,
        evidence=dict(evidence),
        entry_index=int(row["entryIndex"]),
    )


def parse_journal(
    journal_bytes: bytes, *, spec: CorpusSpec
) -> tuple[dict[str, FileBinding], dict[str, FileBinding], tuple[GateDeclaration, ...], tuple[str, ...]]:
    """Parse and validate the journal, returning the effective current view.

    Later rows supersede earlier rows for the same path — that is how an
    append-only journal records a corrected encoding without rewriting
    history. A ``removed`` row drops the path from the present view, and it
    is a claim about the tree as well as the journal: verification refuses a
    tombstoned path that is still on disk. A file that stays in the
    repository stays bound; the only way to stop binding it is to remove it.
    """

    try:
        text = journal_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CorpusError("corpus journal is not UTF-8") from exc
    if not text.endswith("\n"):
        raise CorpusError("corpus journal must end with exactly one LF")
    lines = text.split("\n")[:-1]
    if not lines:
        raise CorpusError("corpus journal is empty; genesis must bind content")

    content: dict[str, FileBinding] = {}
    attested: dict[str, FileBinding] = {}
    gates: list[GateDeclaration] = []
    gate_ids: dict[str, int] = {}
    removed: set[str] = set()

    for number, line in enumerate(lines, start=1):
        if not line.strip():
            raise CorpusError(f"journal row {number} is blank")
        if line.endswith("\r"):
            raise CorpusError(f"journal row {number} uses CRLF, not exact LF")
        row = _parse_row(line, number, spec)
        kind = row["kind"]

        if kind == GATE_KIND:
            gate = _validate_gate(row, number, spec)
            # A re-declared gate would let a later row silently downgrade an
            # earlier tier; every gate is stated once per journal.
            if gate.gate_id in gate_ids:
                raise CorpusError(
                    f"journal row {number} restates gate {_quoted(gate.gate_id)} "
                    f"from row {gate_ids[gate.gate_id]}"
                )
            gate_ids[gate.gate_id] = number
            gates.append(gate)
            continue

        path = _validate_relative_path(row["path"], f"journal row {number} path")
        digest = _sha256(row["sha256"], f"journal row {number} sha256")
        state = _string(row["state"], f"journal row {number} state")
        if state not in FILE_STATES:
            raise CorpusError(
                f"journal row {number} has unknown state {_quoted(state)}"
            )

        target = content if kind == CONTENT_KIND else attested
        # Kind is a function of the path, not the producer's choice: the two
        # checks below decide it from the pinned roots and suffixes, so the same
        # path can never legitimately appear under both kinds and no
        # order-dependent cross-kind bookkeeping is needed.
        if kind == CONTENT_KIND and not spec.is_content_path(path):
            raise CorpusError(
                f"journal row {number} binds {_quoted(path)} as content, but it is not "
                "under a pinned content root with a pinned suffix"
            )
        if kind == ATTESTED_KIND and spec.is_content_path(path):
            raise CorpusError(
                f"journal row {number} binds {_quoted(path)} as attested, but it is a "
                "content path and must be swept closed-world"
            )

        if state == PRESENT:
            target[path] = FileBinding(
                path=path, sha256=digest, entry_index=int(row["entryIndex"])
            )
            removed.discard(path)
        else:
            if path not in target:
                raise CorpusError(
                    f"journal row {number} removes {_quoted(path)}, which was "
                    "never present"
                )
            # The tombstone must name the revision it retires. Otherwise
            # present(H1) → present(H2) → removed(H1) verifies, deleting the
            # effective H2 while the journal records the removal of a digest
            # that had already been superseded. (Found by cross-family review.)
            if target[path].sha256 != digest:
                raise CorpusError(
                    f"journal row {number} removes {_quoted(path)} naming digest "
                    f"{digest}, but the effective revision is "
                    f"{target[path].sha256}"
                )
            del target[path]
            removed.add(path)

    rendered = sum(
        len(gate.gate_id)
        + sum(len(key) + len(value) for key, value in gate.evidence.items())
        for gate in gates
    )
    if rendered > MAX_GATE_TEXT:
        raise CorpusError(
            f"journal gate declarations total {rendered} characters of id and "
            f"evidence, over the verdict budget of {MAX_GATE_TEXT}"
        )
    removed_text = sum(len(path) for path in removed)
    if removed_text > MAX_REMOVED_TEXT:
        raise CorpusError(
            f"journal removed paths total {removed_text} characters, over the "
            f"verdict budget of {MAX_REMOVED_TEXT}"
        )

    return content, attested, tuple(gates), tuple(sorted(removed))


def _list_directory(directory: pathlib.Path, relative: str) -> list[pathlib.Path]:
    """List one directory, refusing to continue if it cannot be read.

    ``Path.rglob`` swallows ``PermissionError`` while descending, so a
    directory that is searchable but not listable (mode 0111) silently
    contributes nothing to a walk while its files stay readable by exact path.
    A closed-world sweep built on that behaviour reports "no extra files"
    when it simply could not look. Enumeration failure must be a refusal, not
    an empty result. (Found by cross-family review.)
    """

    try:
        return sorted(directory.iterdir(), key=lambda entry: entry.name)
    except OSError as exc:
        raise CorpusError(
            f"cannot enumerate a directory under a content root, so the file "
            f"set cannot be closed: {_quoted(relative or '.')} ({exc.strerror})"
        ) from exc


class _TombstoneIndex:
    """Every directory the tombstone pass reads, folded and indexed once.

    One :func:`verify_corpus_binding` call may carry many removed paths, and
    they overlap: each search starts at the tree root and most of them share
    their leading components. Reading a directory per removed path made the
    pass cost R×E for R tombstones over a root of E entries, and the budget
    that was supposed to bound it counted listings *per removed path*, so it
    bounded each search and nothing at all about the pass (peer review, round
    three).

    So a directory is listed once per verification and kept as
    ``{fold key: [entries]}``, shared by every subsequent search, and the work
    budget is a single running count of entries indexed for the whole pass.

    Failure to list is a refusal, not an absence, for the reason
    :func:`_list_directory` gives; a directory that is simply not there is an
    absence, cached as one.

    A listing is consumed one entry at a time and charged as it is consumed,
    so a directory wider than the budget stops the pass part-way through
    rather than being read and sorted in full first; each bucket is sorted
    once, here, so a search that revisits it never sorts it again.

    The cache is keyed by the directory's exact spelling as the search walked
    it — the ``/``-joined component names, ``""`` for the root — and never by
    a :class:`pathlib.Path`. Path equality and hashing are case-insensitive on
    Windows, so ``WindowsPath("A")`` and ``WindowsPath("a")`` are one key
    there; with NTFS per-directory case sensitivity they are two directories,
    and an empty ``A/`` cached under that shared key answered for a surviving
    ``a/TARGET``, turning a tombstone this pass exists to refuse into a PASS
    (peer review, round four). A string key means the cache distinguishes
    exactly what the walk distinguishes, on every platform.
    """

    def __init__(self, root: pathlib.Path) -> None:
        self.root = root
        self._directories: dict[str, dict[str, list[pathlib.Path]] | None] = {}
        self._work = 0

    def charge(self, relative: str) -> None:
        """Charge one directory entry against the pass budget.

        Called for every entry consumed from a listing and for every candidate
        a search visits. ``relative`` is the removed path whose search is being
        charged, so the refusal names the tombstone that could not be checked.
        """

        self._work += 1
        if self._work > MAX_TOMBSTONE_WORK:
            raise CorpusError(
                "cannot check whether a removed path is still in the tree, so "
                f"the tombstone is unverifiable: {relative} (tombstone work "
                f"budget of {MAX_TOMBSTONE_WORK} entries exceeded)"
            )

    def folded(
        self, directory: pathlib.Path, key: str, relative: str
    ) -> dict[str, list[pathlib.Path]] | None:
        """This directory's entries by fold key, or None if it is not there.

        ``key`` is the directory's exact spelling relative to the tree root,
        which is what the cache is keyed by; ``relative`` is the removed path
        whose search wanted the directory, and it names the tombstone in any
        refusal this raises.
        """

        if key in self._directories:
            return self._directories[key]
        entries: list[pathlib.Path] = []
        try:
            for entry in directory.iterdir():
                # Charged as it is consumed, and refused from inside the loop:
                # sorting the listing first read an arbitrarily wide directory
                # in full — and sorted it — before anything looked at the
                # budget, so the constant named no bound on the work actually
                # done (peer review, round four).
                self.charge(relative)
                entries.append(entry)
        except (FileNotFoundError, NotADirectoryError):
            self._directories[key] = None
            return None
        except OSError as exc:
            raise CorpusError(
                "cannot check whether a removed path is still in the tree, so "
                f"the tombstone is unverifiable: {relative} ({exc.strerror})"
            ) from exc
        folded: dict[str, list[pathlib.Path]] = {}
        # Sorted once, here, rather than in every search that reaches this
        # directory: the order a bucket is tried in does not depend on which
        # tombstone is asking, only which spelling comes first does.
        for entry in sorted(entries, key=lambda entry: entry.name):
            # Screened before it is folded, for the reason _assert_assigned
            # gives: an unassigned code point in an entry name would put the
            # entry in one fold bucket on one interpreter and another on the
            # next, which decides whether a tombstone is honoured.
            _assert_assigned(entry.name, "tree entry examined for a tombstone")
            folded.setdefault(_path_fold(entry.name), []).append(entry)
        self._directories[key] = folded
        return folded


def _fold_survivor(index: _TombstoneIndex, relative: str) -> str | None:
    """The spelling under which a tombstoned path still answers, if any.

    The module's portability model is that two paths whose fold keys agree
    are one file on some real filesystem; the sweep and the alias guard are
    built on it, and a tombstone checked by exact-spelling lstat was not. On
    a case-sensitive host a tombstone for ".axiom/apply-manifest.json" passed
    while ".AXIOM/APPLY-MANIFEST.JSON" remained, and that survivor answers to
    the tombstoned name on a case-insensitive consumer (peer review). So each
    component is matched by fold key against a listing of its directory,
    exact spelling first, every fold-equal branch explored. An intermediate
    symlink refuses, as it does for every bound path, which also bounds the
    walk by the tree; :class:`_TombstoneIndex` reads each directory once and
    refuses a tree wider than its work budget.

    What this search cannot see is a name the filesystem resolves but never
    emits — Win32 strips trailing dots and spaces before a lookup, and NTFS
    answers to 8.3 short names. Those are handled outside this function, from
    both ends. A *declared* path spelled that way is refused at the schema
    boundary by :func:`_aliases_natively`, so no tombstone names one. A *tree
    entry* that answers to the tombstoned spelling is caught by the native
    ``os.lstat`` of the exact path in :func:`verify_corpus_binding`, which
    runs before this search and lets the host that is actually running decide
    what its own lookup resolves.

    That leaves one case modelled by neither, and it is deliberate: an entry
    whose name aliases another *on Windows only*, examined on a POSIX host.
    POSIX lstat will not resolve the alias and POSIX enumeration will not emit
    it, so a tombstone can pass on Linux for a tree that would still hold the
    file on Windows. Verifying on the filesystem you intend to use is the
    remedy; this module refuses what it can see and does not pretend to model
    a lookup it is not running.
    """

    def search(
        directory: pathlib.Path, components: list[str], spelled: list[str]
    ) -> str | None:
        folded = index.folded(directory, "/".join(spelled), relative)
        if folded is None:
            return None
        head, rest = components[0], components[1:]
        # The bucket is re-ordered rather than re-sorted: the index sorted it
        # by name when it read the directory, and only which spelling to try
        # first depends on the component being matched. Sorting here instead
        # meant every tombstone that reached this bucket paid to sort it
        # again (peer review, round four).
        bucket = folded.get(_path_fold(head), ())
        matches = [entry for entry in bucket if entry.name == head]
        matches += [entry for entry in bucket if entry.name != head]
        for entry in matches:
            # A visited candidate is a directory entry examined, so it is
            # charged like an indexed one and against the same running total.
            # Re-traversing a cached bucket was free before, so R tombstones
            # over one collision bucket of K entries examined R×K candidates
            # without the budget moving (peer review, round four).
            index.charge(relative)
            if not rest:
                return "/".join([*spelled, entry.name])
            # One lstat, inside the handler, answering both questions below.
            # It sat outside: a listed entry deleted between the listing and
            # the probe raised FileNotFoundError, and an entry in a directory
            # that is readable but not searchable raised PermissionError, and
            # neither is a CorpusError — the verifier crashed where it should
            # have refused (peer review, round three). A vanished entry is not
            # a survivor; any other error means the tombstone could not be
            # checked, which is the same "failure to look is not an absence"
            # rule _list_directory states.
            try:
                info = entry.lstat()
            except (FileNotFoundError, NotADirectoryError):
                continue
            except OSError as exc:
                raise CorpusError(
                    "cannot check whether a removed path is still in the tree, so "
                    f"the tombstone is unverifiable: {relative} ({exc.strerror})"
                ) from exc
            # An intermediate symlink is refused, as it is for every bound
            # path: a journal path never traverses a link. Following it
            # also made the walk unbounded, since case-varied links back
            # into the same directory branch without end (peer review,
            # round two). A link in the final position still counts as
            # present: it answers to the name.
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_reparse_tag", 0):
                raise CorpusError(
                    "removed path traverses a symlink or reparse point at "
                    f"{_quoted('/'.join([*spelled, entry.name]))}: {relative}"
                )
            found = search(entry, rest, [*spelled, entry.name])
            if found is not None:
                return found
        return None

    return search(index.root, relative.split("/"), [])


def _path_fold(relative: str) -> str:
    """A filesystem-insensitivity-proof key for a relative path.

    NFC folds NFD/NFC spellings of the same characters together; casefold folds
    case together. Two distinct declared paths sharing a fold key would alias on
    some real filesystem, so the fold key is what closed-world uniqueness is
    checked over.
    """

    # Stable across interpreters only for assigned characters: the Unicode
    # stability policies fix case folding and normalization once a character
    # is encoded, so _validate_relative_path refuses unassigned code points
    # and this key means the same thing under every supported table.
    # Normalized again after folding, deliberately: casefold itself can
    # produce decomposed text (U+00DF followed by U+0301 folds to s, s,
    # U+0301, whose composed form is s, U+015B), so a variant that differs
    # in case AND normalization at once produced an unequal key and the
    # suffix predicate let it out of the sweep (peer review).
    return unicodedata.normalize(
        "NFC", unicodedata.normalize("NFC", relative).casefold()
    )


def _has_pinned_suffix(relative: str, suffixes: tuple[str, ...]) -> bool:
    """Whether a path ends in one of the pinned content suffixes, folded.

    Both sides fold, for the reason _path_fold exists: on a case-insensitive
    filesystem "rules/x.YAML" and "rules/x.yaml" are one file, so a byte-exact
    suffix match would let a case-varied spelling be classified as not-content
    and escape the sweep. The journal classifier and the tree sweep share this
    one predicate; the bug it closes was the two of them disagreeing.
    """

    folded = _path_fold(relative)
    return any(folded.endswith(_path_fold(suffix)) for suffix in suffixes)


def _reject_aliasing_paths(relatives: list[str]) -> None:
    seen: dict[str, str] = {}
    for relative in relatives:
        key = _path_fold(relative)
        if key in seen and seen[key] != relative:
            raise CorpusError(
                "two declared paths would alias on a case- or "
                "normalization-insensitive filesystem, so the closed-world set "
                f"is ambiguous: {_quoted(seen[key])} and {_quoted(relative)}"
            )
        seen[key] = relative


def _tree_content_paths(root: pathlib.Path, spec: CorpusSpec) -> dict[str, pathlib.Path]:
    """Enumerate every regular file the spec calls content.

    Walks explicitly rather than globbing: every directory is listed with
    errors surfaced, every symlink refuses, and every non-regular entry
    refuses. What this returns is the complete set of content files, or the
    call raises — there is no third outcome where it returns a partial set.

    Every path these refusals name is quoted through :func:`_quoted`, which
    is not cosmetic. A journal path is control-screened at the schema
    boundary; a *filesystem* name is not screened by anything, and the CLI
    prints refusal text into its verdict. A file named
    ``"\\x1b[2K\\rVERDICT: PASS"`` planted under a content root would have
    redrawn the line the command was about to fail on — the same attack
    :func:`_reject_control_characters` closes from the producer's side, open
    from the tree's (peer review, round three).
    """

    found: dict[str, pathlib.Path] = {}
    for content_root in spec.content_roots:
        base_relative = content_root.as_posix()
        # Guard every component of the root, not just its last segment: an
        # empty or suffix-empty root behind a symlinked parent would enumerate
        # nothing and silently pass. (Cross-family review finding.)
        base = _assert_no_symlinked_component(
            root, base_relative, what="pinned content root"
        )
        _assert_no_aliasing_root_component(root, base_relative)
        if not base.exists():
            raise CorpusError(
                f"pinned content root is absent from the tree: {base_relative}"
            )
        if not base.is_dir():
            raise CorpusError(f"pinned content root is not a directory: {base_relative}")

        pending: list[tuple[pathlib.Path, str]] = [(base, base_relative)]
        while pending:
            directory, directory_relative = pending.pop()
            for candidate in _list_directory(directory, directory_relative):
                relative = candidate.relative_to(root).as_posix()
                # Before the suffix predicate folds this name. A tree entry
                # carrying an unassigned code point folds differently on
                # different Unicode tables, so whether it is content — and so
                # whether the closed world contains it — would depend on the
                # verifier's interpreter rather than on the tree.
                _assert_assigned(candidate.name, f"tree entry {_quoted(relative)}")
                if candidate.is_symlink():
                    # ANY symlink under a content root defeats the closed-world
                    # claim, whatever it is named: a walk does not descend
                    # symlinked directories, so a linked tree of suffix-named
                    # files would be invisible here while remaining reachable
                    # to any consumer that resolves links.
                    raise CorpusError(
                        f"content root contains a symlink: {_quoted(relative)}"
                    )
                if candidate.is_dir():
                    pending.append((candidate, relative))
                    continue
                if not candidate.is_file():
                    # FIFOs, sockets, devices: not bindable, yet a reader could
                    # still open them where a rule file is expected. Refuse.
                    raise CorpusError(
                        f"content root contains a non-regular file: {_quoted(relative)}"
                    )
                # The same predicate the journal classifier uses, so the sweep
                # and the classifier cannot disagree about what is content.
                if not _has_pinned_suffix(relative, spec.content_suffixes):
                    continue
                found[relative] = candidate
    return found


def _assert_no_aliasing_root_component(root: pathlib.Path, relative: str) -> None:
    """Refuse a tree entry that aliases a component of a pinned content root.

    :meth:`CorpusSpec.content_root_of` folds, so a path under "RULES/" is
    classified as content wherever it is spelled. Classification is only half
    of it: the *walk* still descends the pinned spelling, so on a
    case-sensitive host "RULES/evil.yaml" is content the walk never visits,
    and it would be reported missing from the tree rather than named for what
    it is. Worse, an auditor on a case-insensitive host holds one merged
    directory and an auditor on a case-sensitive host holds two, from the
    same bytes.

    So each component of each pinned root is checked against a listing of its
    parent: an entry whose fold key matches the component but whose spelling
    does not is refused by name. A parent that is not there is left to the
    absent and not-a-directory refusals in :func:`_tree_content_paths`, which
    say something more useful, and a symlinked parent has already been
    refused by :func:`_assert_no_symlinked_component`.
    """

    current = root
    walked: list[str] = []
    for component in relative.split("/"):
        if current.is_symlink() or not current.is_dir():
            return
        for entry in _list_directory(current, "/".join(walked)):
            _assert_assigned(entry.name, f"tree entry beside {_quoted(relative)}")
            if entry.name != component and _path_fold(entry.name) == _path_fold(
                component
            ):
                raise CorpusError(
                    f"tree entry {_quoted(entry.name)} aliases the pinned content "
                    f"root component {_quoted(component)} on a case- or "
                    "normalization-insensitive filesystem"
                )
        current = current / component
        walked.append(component)


def _assert_no_symlinked_component(
    root: pathlib.Path, relative: str, *, what: str = "bound path"
) -> pathlib.Path:
    """Walk every component, refusing if any of them is a symlink or reparse.

    Checking only the final component lets an intermediate directory symlink
    put a bound file outside the clone entirely: replace ``.axiom/`` with a
    link to an ambient directory and ``.axiom/toolchain.toml`` still looks like
    a regular file and still matches its digest, while not being part of what
    the auditor cloned. (Found by cross-family review.)

    The same hole exists one level up for a content root: an empty or
    suffix-empty root behind a symlinked *parent* would enumerate no files and
    silently pass, so this guards content roots too.
    """

    current = root
    for segment in relative.split("/"):
        current = current / segment
        # is_symlink() catches POSIX symlinks; on Windows a junction/reparse
        # point is not a symlink but is reported by st_reparse_tag, so refuse
        # any reparse point as well.
        reparse = getattr(current.lstat(), "st_reparse_tag", 0) if current.exists() else 0
        if current.is_symlink() or reparse:
            raise CorpusError(
                f"{what} traverses a symlink or reparse point at "
                f"{_quoted(current.relative_to(root).as_posix())}: {relative}"
            )
    return current


class _FileIdentity(NamedTuple):
    """What the descriptor said about a file at the moment it was hashed."""

    device: int
    inode: int
    size: int
    mtime_ns: int


def _regular_file_digest(root: pathlib.Path, relative: str) -> tuple[str, _FileIdentity]:
    """Hash a bound file, closing the check/open race at the final component.

    Validating the path then opening it by name leaves a window in which a
    symlink is swapped in between the check and the read. Three layers close
    it portably (cross-family review findings, two rounds):

    - ``os.lstat`` of the final component must show a regular file before the
      open — a symlink, FIFO, or device reachable by the name refuses without
      ever being opened, on every platform.
    - The open adds ``O_NOFOLLOW`` where the platform provides it and
      ``O_NONBLOCK`` unconditionally, so a FIFO raced into place between the
      ``lstat`` and the open cannot block the verifier (a read-only
      non-blocking FIFO open returns immediately; regular-file reads ignore
      the flag).
    - ``os.fstat`` of the open descriptor must agree with the ``lstat`` on
      device and inode and show a regular file — so even without
      ``O_NOFOLLOW``, a name swapped between the two calls resolves to a
      different inode and refuses.

    Residual, bounded: an intermediate directory swapped to a symlink
    *between* the component guard and this open is not caught here. Closing
    that fully needs descent by ``dir_fd``; it is left because the
    precondition is an adversary with write access to the auditor's clone
    *during* verification, who can already defeat a local check by other
    means. The post-hash sweeps in :func:`verify_corpus_binding` (membership
    re-enumeration plus per-file identity re-check) catch a resulting set
    change or file swap after the fact; a same-inode rewrite that also
    restores size and ``mtime_ns`` is beneath their resolution, which is one
    reason the verdict speaks of the bytes as they existed when hashed.
    """

    path = _assert_no_symlinked_component(root, relative)
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise CorpusError(
            f"bound file is missing or not a regular file: {relative}"
        ) from exc
    if not stat.S_ISREG(before.st_mode):
        raise CorpusError(f"bound file is not a regular file: {relative}")
    flags = (
        os.O_RDONLY
        | os.O_NONBLOCK
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise CorpusError(
            f"bound file is missing or not a regular file: {relative}"
        ) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise CorpusError(f"bound file is not a regular file: {relative}")
        if (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
            raise CorpusError(
                f"bound file changed identity while being opened: {relative}"
            )
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
        identity = _FileIdentity(
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
        )
    finally:
        os.close(fd)
    return digest.hexdigest(), identity


def verify_declarations(
    verification: CorpusVerification, *, spec: CorpusSpec
) -> tuple[GateDeclaration, ...]:
    """Check the journal declares every gate the consumer's spec requires.

    Separate from :func:`verify_corpus_binding` so a missing declaration is
    reported as a declaration failure rather than a binding failure — the pass
    boundary the verdict describes. Row-level tier and outcome validity is
    already enforced during parsing; this is the completeness half.
    """

    declared = {gate.gate_id for gate in verification.gates}
    missing = sorted(spec.required_gates - declared)
    if missing:
        raise CorpusError(
            "the witnessed journal does not declare a gate the pinned spec "
            f"requires: {_quoted(missing[0])}"
        )
    return verification.gates


def verify_corpus_binding(
    root: pathlib.Path,
    journal_bytes: bytes,
    *,
    spec: CorpusSpec,
) -> CorpusVerification:
    """Prove the witnessed journal describes exactly this working tree.

    ``journal_bytes`` must be the same bytes the release chain verified — pass
    them through rather than re-reading the file, so nothing can change between
    the custody proof and the binding proof.
    """

    root = root.resolve()
    content, attested, gates, removed = parse_journal(journal_bytes, spec=spec)

    # Two declared paths that a case- or normalization-insensitive filesystem
    # would treat as one make the closed-world claim ambiguous: which file did
    # the auditor actually get? Detect the collision host-independently — under
    # Unicode NFC plus case folding — and refuse. Deliberately conservative: a
    # case-sensitive filesystem can hold two genuinely distinct files whose
    # names collide only after folding, and such a corpus is refused by design,
    # because its closed-world claim would depend on which filesystem the
    # auditor cloned onto.
    _reject_aliasing_paths(list(content) + list(attested))

    tree = _tree_content_paths(root, spec)
    journal_paths = set(content)
    tree_paths = set(tree)

    unlisted = sorted(tree_paths - journal_paths)
    if unlisted:
        raise CorpusError(
            f"{len(unlisted)} content file(s) in the tree are not bound by the "
            f"witnessed journal, starting with {_quoted(unlisted[0])}"
        )
    absent = sorted(journal_paths - tree_paths)
    if absent:
        raise CorpusError(
            f"{len(absent)} content file(s) bound by the journal are missing "
            f"from the tree, starting with {_quoted(absent[0])}"
        )

    hashed: dict[str, _FileIdentity] = {}

    for path in sorted(journal_paths):
        digest, identity = _regular_file_digest(root, path)
        if digest != content[path].sha256:
            raise CorpusError(
                f"content file {_quoted(path)} does not match its witnessed digest: "
                f"tree has {digest}, journal binds {content[path].sha256}"
            )
        hashed[path] = identity

    missing_required = sorted(spec.required_attested_paths - set(attested))
    if missing_required:
        raise CorpusError(
            "the witnessed journal does not attest a path the pinned spec "
            f"requires: {_quoted(missing_required[0])}"
        )
    for path in sorted(attested):
        digest, identity = _regular_file_digest(root, path)
        if digest != attested[path].sha256:
            raise CorpusError(
                f"attested file {_quoted(path)} does not match its witnessed digest: "
                f"tree has {digest}, journal binds {attested[path].sha256}"
            )
        hashed[path] = identity

    # Closed-world means the set proven equal to the journal must not have
    # changed while it was being proven. Two sweeps after hashing, because
    # they catch different things (cross-family review findings, two rounds):
    # membership re-enumeration catches a file unlisted-and-inserted or a
    # bound file deleted after the first walk; the per-file identity re-check
    # catches a hashed file replaced or rewritten in place afterwards — for
    # every bound file, content and attested alike, the path must still be a
    # regular file with the device, inode, size, and mtime the hashing
    # descriptor saw. A same-inode rewrite that also restores size and
    # mtime_ns is beneath this sweep's resolution; re-reading every byte
    # would double the verifier's IO to move that boundary, not remove it.
    if set(_tree_content_paths(root, spec)) != tree_paths:
        raise CorpusError(
            "the content tree changed during verification; the closed-world "
            "set is not stable and the verdict is refused"
        )
    for path in sorted(hashed):
        try:
            after = os.lstat(_assert_no_symlinked_component(root, path))
        except OSError as exc:
            raise CorpusError(
                f"bound file {_quoted(path)} disappeared during verification; the "
                "verdict is refused"
            ) from exc
        seen = hashed[path]
        if not stat.S_ISREG(after.st_mode) or (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) != (seen.device, seen.inode, seen.size, seen.mtime_ns):
            raise CorpusError(
                f"bound file {_quoted(path)} changed during verification; the "
                "verdict is refused"
            )

    # A tombstone is a claim about the tree, not only about the journal, and
    # the verdict repeats it as removedPaths. For a content path the sweep
    # above already catches a file that outlived its removal row — it is
    # unlisted. For an attested path nothing else looks: attested paths sit
    # outside the content roots, so a retired toolchain pin or apply manifest
    # could sit on disk bound by no row, reported as removed, and be read as
    # current by every consumer. Look for both kinds, by fold key so an
    # aliasing spelling counts, and refuse what is still there. One index
    # serves the whole pass: the searches overlap, and re-reading a directory
    # per removed path was what made the pass quadratic.
    tombstones = _TombstoneIndex(root)
    for path in removed:
        # Ask the filesystem about the tombstoned spelling itself before
        # asking the fold model about it. _fold_survivor decides absence from
        # the names iterdir emits, and Win32 lookup resolves names enumeration
        # never emits: a trailing dot or space is stripped before the lookup,
        # and an NTFS 8.3 short name answers for a long one. Both would be
        # reported absent by a search over the listing while the file opens
        # under the tombstoned name (peer review, round three). The host that
        # runs knows its own aliases; ask it first.
        try:
            os.lstat(root / path)
        except (FileNotFoundError, NotADirectoryError):
            pass
        except OSError as exc:
            raise CorpusError(
                "cannot check whether a removed path is still in the tree, so "
                f"the tombstone is unverifiable: {path} ({exc.strerror})"
            ) from exc
        else:
            raise CorpusError(f"removed path is still present in the tree: {path}")
        survivor = _fold_survivor(tombstones, path)
        if survivor is None:
            continue
        if survivor == path:
            raise CorpusError(f"removed path is still present in the tree: {path}")
        raise CorpusError(
            "removed path is still present in the tree under a spelling that "
            "aliases it on a case- or normalization-insensitive filesystem: "
            f"{path} ({_quoted(survivor)})"
        )

    return CorpusVerification(
        content=tuple(content[path] for path in sorted(content)),
        attested=tuple(attested[path] for path in sorted(attested)),
        gates=gates,
        removed_paths=removed,
    )
