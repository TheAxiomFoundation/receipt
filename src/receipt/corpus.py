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
    the tree's set exactly, in both membership and digest. The sweep is
    suffix-scoped after folding — path and suffix are compared under Unicode
    NFC plus case folding — so a case- or normalization-varied spelling of a
    pinned suffix cannot sit outside the closed world on a filesystem that
    treats it as the same file.

``attested``
    An exact path bound by digest without a sweep — the toolchain pin, the
    pinned validation workflow, an apply manifest. The consumer's spec names
    which paths it *requires*, so a producer cannot quietly drop one.
    Retiring one is recorded by a ``removed`` row, and the file has to leave
    the tree with it: a removed path still on disk refuses, whichever kind
    it was.

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
#: The most directory listings one tombstone check may perform before it is
#: refused as unverifiable rather than allowed to run on.
MAX_TOMBSTONE_LISTINGS = 4096
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
            _validate_relative_path(root.as_posix(), "content root")
        if type(self.content_suffixes) is not tuple or not self.content_suffixes:
            raise CorpusError("CorpusSpec must declare at least one content suffix")
        for suffix in self.content_suffixes:
            if type(suffix) is not str or not suffix.startswith("."):
                raise CorpusError(
                    f"CorpusSpec content suffix must start with '.': {suffix!r}"
                )
        if type(self.required_attested_paths) is not frozenset:
            raise CorpusError("CorpusSpec required_attested_paths must be a frozenset")
        for path in sorted(self.required_attested_paths):
            _validate_relative_path(path, "required attested path")
        if type(self.accepted_gate_tiers) is not frozenset:
            raise CorpusError("CorpusSpec accepted_gate_tiers must be a frozenset")
        unknown = sorted(self.accepted_gate_tiers - set(GATE_TIERS))
        if unknown:
            raise CorpusError(
                f"CorpusSpec accepts unknown reproducibility tier {unknown[0]!r}; "
                f"known tiers are {', '.join(GATE_TIERS)}"
            )
        if type(self.required_gates) is not frozenset:
            raise CorpusError("CorpusSpec required_gates must be a frozenset")
        for gate_id in sorted(self.required_gates):
            if GATE_ID_RE.fullmatch(gate_id) is None:
                raise CorpusError(f"CorpusSpec required gate id is malformed: {gate_id!r}")

    def content_root_of(self, path: str) -> pathlib.PurePosixPath | None:
        for root in self.content_roots:
            prefix = root.as_posix() + "/"
            if path.startswith(prefix):
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
    """repr of a producer-controlled value, truncated so a refusal is bounded."""

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
                f"{label} contains a control character ({code:#04x}): {value!r}"
            )
        if _is_format_control(code, category):
            raise CorpusError(
                f"{label} contains a Unicode format control ({code:#04x}): {value!r}"
            )
        if category == "Cs":
            raise CorpusError(
                f"{label} contains a lone surrogate ({code:#04x}): {value!r}"
            )
        if code in (0x2028, 0x2029):
            raise CorpusError(
                f"{label} contains a Unicode line separator ({code:#04x}): {value!r}"
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
        raise CorpusError(f"{label} must use POSIX separators: {value!r}")
    if value.startswith("/") or value.endswith("/"):
        raise CorpusError(f"{label} must be relative with no trailing slash: {value!r}")
    segments = value.split("/")
    for segment in segments:
        if not segment:
            raise CorpusError(f"{label} has an empty path segment: {value!r}")
        if segment in (".", ".."):
            raise CorpusError(f"{label} contains a relative segment: {value!r}")
    _reject_control_characters(value, label)
    for character in value:
        if unicodedata.category(character) == "Cn":
            # The fold key (see _path_fold) is only stable across Unicode
            # tables for assigned characters: the standard's stability
            # policies fix case folding and normalization once a character
            # is encoded, and say nothing before. An unassigned code point
            # folded one way on Unicode 15 and another on 16 (U+10D50, peer
            # review), so a path carrying one could alias under one
            # interpreter and not another. Refused, naming the table.
            raise CorpusError(
                f"{label} contains a code point unassigned in Unicode "
                f"{unicodedata.unidata_version} ({ord(character):#06x}): {value!r}"
            )
    if ":" in value:
        # On Windows, "C:/x" survives every relative-path check above yet
        # joins drive-absolute under pathlib, letting a row reference a file
        # outside the root. No path in this schema legitimately contains a
        # colon; refuse rather than special-case the platform.
        raise CorpusError(f"{label} contains ':': {value!r}")
    return value


def _exact_keys(row: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if type(row) is not dict:
        raise CorpusError(f"{label} must be a JSON object")
    actual = set(row)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise CorpusError(
            f"{label} keys are not closed-world: missing={missing}, unknown={unknown}"
        )
    return row


def _string(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise CorpusError(f"{label} must be a non-empty string")
    return value


def _sha256(value: Any, label: str) -> str:
    text = _string(value, label)
    if SHA256_RE.fullmatch(text) is None:
        raise CorpusError(f"{label} is not a lowercase SHA-256 hex digest: {text!r}")
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
            f"journal row {number} has unknown kind {kind!r}; "
            f"expected one of {', '.join(sorted(ROW_KINDS))}"
        )
    row = _exact_keys(parsed, _ROW_KEYS[kind], f"journal row {number}")
    if row["schemaVersion"] != spec.schema_version:
        raise CorpusError(
            f"journal row {number} declares schema {row['schemaVersion']!r}, "
            f"but the pinned spec is {spec.schema_version!r}"
        )
    index = row["entryIndex"]
    if type(index) is not int or index != number - 1:
        raise CorpusError(
            f"journal row {number} entryIndex must be {number - 1}, found {index!r}"
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
            f"journal row {number} gate {gate_id!r} declares unknown "
            f"reproducibility tier {tier!r}"
        )
    if tier not in spec.accepted_gate_tiers:
        raise CorpusError(
            f"journal row {number} gate {gate_id!r} declares tier {tier!r}, "
            "which the pinned spec does not accept"
        )
    outcome = _string(row["outcome"], f"journal row {number} outcome")
    if outcome not in GATE_OUTCOMES:
        raise CorpusError(
            f"journal row {number} gate {gate_id!r} has unknown outcome {outcome!r}"
        )
    evidence = row["evidence"]
    if type(evidence) is not dict or not evidence:
        raise CorpusError(
            f"journal row {number} gate {gate_id!r} evidence must be a non-empty object"
        )
    for key, value in evidence.items():
        if type(key) is not str or type(value) is not str:
            raise CorpusError(
                f"journal row {number} gate {gate_id!r} evidence must map "
                "strings to strings"
            )
        key_label = f"journal row {number} gate {gate_id!r} evidence key"
        value_label = f"journal row {number} gate {gate_id!r} evidence value {key!r}"
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
                f"journal row {number} gate {gate_id!r} is waived without naming "
                "evidence.waiverSetSha256"
            )
        _sha256(
            evidence["waiverSetSha256"],
            f"journal row {number} gate {gate_id!r} evidence.waiverSetSha256",
        )
    # Same principle for a gate that did not run: state why, or the
    # declaration is decoration. A whitespace-only reason is no reason.
    if outcome == NOT_RUN and not evidence.get("reason", "").strip():
        raise CorpusError(
            f"journal row {number} gate {gate_id!r} is declared not-run "
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
                    f"journal row {number} restates gate {gate.gate_id!r} "
                    f"from row {gate_ids[gate.gate_id]}"
                )
            gate_ids[gate.gate_id] = number
            gates.append(gate)
            continue

        path = _validate_relative_path(row["path"], f"journal row {number} path")
        digest = _sha256(row["sha256"], f"journal row {number} sha256")
        state = _string(row["state"], f"journal row {number} state")
        if state not in FILE_STATES:
            raise CorpusError(f"journal row {number} has unknown state {state!r}")

        target = content if kind == CONTENT_KIND else attested
        # Kind is a function of the path, not the producer's choice: the two
        # checks below decide it from the pinned roots and suffixes, so the same
        # path can never legitimately appear under both kinds and no
        # order-dependent cross-kind bookkeeping is needed.
        if kind == CONTENT_KIND and not spec.is_content_path(path):
            raise CorpusError(
                f"journal row {number} binds {path!r} as content, but it is not "
                "under a pinned content root with a pinned suffix"
            )
        if kind == ATTESTED_KIND and spec.is_content_path(path):
            raise CorpusError(
                f"journal row {number} binds {path!r} as attested, but it is a "
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
                    f"journal row {number} removes {path!r}, which was never present"
                )
            # The tombstone must name the revision it retires. Otherwise
            # present(H1) → present(H2) → removed(H1) verifies, deleting the
            # effective H2 while the journal records the removal of a digest
            # that had already been superseded. (Found by cross-family review.)
            if target[path].sha256 != digest:
                raise CorpusError(
                    f"journal row {number} removes {path!r} naming digest "
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
            f"set cannot be closed: {relative or '.'} ({exc.strerror})"
        ) from exc


def _fold_survivor(root: pathlib.Path, relative: str) -> str | None:
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
    walk by the tree; a listing budget refuses a tree wider than that.
    Failure to list is a refusal, not an absence, for the reason
    _list_directory gives.
    """

    listings = 0

    def search(
        directory: pathlib.Path, components: list[str], spelled: list[str]
    ) -> str | None:
        nonlocal listings
        listings += 1
        if listings > MAX_TOMBSTONE_LISTINGS:
            # Every fold-equal branch is explored, and with symlinks refused
            # below the branching is bounded by the tree itself; a tree wide
            # enough to exceed this is refused as unverifiable rather than
            # walked on (peer review, round two).
            raise CorpusError(
                "cannot check whether a removed path is still in the tree, so "
                f"the tombstone is unverifiable: {relative} (more than "
                f"{MAX_TOMBSTONE_LISTINGS} aliasing directories)"
            )
        try:
            entries = list(directory.iterdir())
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError as exc:
            raise CorpusError(
                "cannot check whether a removed path is still in the tree, so "
                f"the tombstone is unverifiable: {relative} ({exc.strerror})"
            ) from exc
        head, rest = components[0], components[1:]
        key = _path_fold(head)
        matches = sorted(
            (entry for entry in entries if _path_fold(entry.name) == key),
            key=lambda entry: (entry.name != head, entry.name),
        )
        for entry in matches:
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
                    f"{'/'.join([*spelled, entry.name])!r}: {relative}"
                )
            found = search(entry, rest, [*spelled, entry.name])
            if found is not None:
                return found
        return None

    return search(root, relative.split("/"), [])


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
                f"is ambiguous: {seen[key]!r} and {relative!r}"
            )
        seen[key] = relative


def _tree_content_paths(root: pathlib.Path, spec: CorpusSpec) -> dict[str, pathlib.Path]:
    """Enumerate every regular file the spec calls content.

    Walks explicitly rather than globbing: every directory is listed with
    errors surfaced, every symlink refuses, and every non-regular entry
    refuses. What this returns is the complete set of content files, or the
    call raises — there is no third outcome where it returns a partial set.
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
                if candidate.is_symlink():
                    # ANY symlink under a content root defeats the closed-world
                    # claim, whatever it is named: a walk does not descend
                    # symlinked directories, so a linked tree of suffix-named
                    # files would be invisible here while remaining reachable
                    # to any consumer that resolves links.
                    raise CorpusError(f"content root contains a symlink: {relative}")
                if candidate.is_dir():
                    pending.append((candidate, relative))
                    continue
                if not candidate.is_file():
                    # FIFOs, sockets, devices: not bindable, yet a reader could
                    # still open them where a rule file is expected. Refuse.
                    raise CorpusError(
                        f"content root contains a non-regular file: {relative}"
                    )
                # The same predicate the journal classifier uses, so the sweep
                # and the classifier cannot disagree about what is content.
                if not _has_pinned_suffix(relative, spec.content_suffixes):
                    continue
                found[relative] = candidate
    return found


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
                f"{current.relative_to(root).as_posix()!r}: {relative}"
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
            f"requires: {missing[0]!r}"
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
            f"witnessed journal, starting with {unlisted[0]!r}"
        )
    absent = sorted(journal_paths - tree_paths)
    if absent:
        raise CorpusError(
            f"{len(absent)} content file(s) bound by the journal are missing "
            f"from the tree, starting with {absent[0]!r}"
        )

    hashed: dict[str, _FileIdentity] = {}

    for path in sorted(journal_paths):
        digest, identity = _regular_file_digest(root, path)
        if digest != content[path].sha256:
            raise CorpusError(
                f"content file {path!r} does not match its witnessed digest: "
                f"tree has {digest}, journal binds {content[path].sha256}"
            )
        hashed[path] = identity

    missing_required = sorted(spec.required_attested_paths - set(attested))
    if missing_required:
        raise CorpusError(
            "the witnessed journal does not attest a path the pinned spec "
            f"requires: {missing_required[0]!r}"
        )
    for path in sorted(attested):
        digest, identity = _regular_file_digest(root, path)
        if digest != attested[path].sha256:
            raise CorpusError(
                f"attested file {path!r} does not match its witnessed digest: "
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
                f"bound file {path!r} disappeared during verification; the "
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
                f"bound file {path!r} changed during verification; the "
                "verdict is refused"
            )

    # A tombstone is a claim about the tree, not only about the journal, and
    # the verdict repeats it as removedPaths. For a content path the sweep
    # above already catches a file that outlived its removal row — it is
    # unlisted. For an attested path nothing else looks: attested paths sit
    # outside the content roots, so a retired toolchain pin or apply manifest
    # could sit on disk bound by no row, reported as removed, and be read as
    # current by every consumer. Look for both kinds, by fold key so an
    # aliasing spelling counts, and refuse what is still there.
    for path in removed:
        survivor = _fold_survivor(root, path)
        if survivor is None:
            continue
        if survivor == path:
            raise CorpusError(f"removed path is still present in the tree: {path}")
        raise CorpusError(
            "removed path is still present in the tree under a spelling that "
            "aliases it on a case- or normalization-insensitive filesystem: "
            f"{path} ({survivor})"
        )

    return CorpusVerification(
        content=tuple(content[path] for path in sorted(content)),
        attested=tuple(attested[path] for path in sorted(attested)),
        gates=gates,
        removed_paths=removed,
    )
