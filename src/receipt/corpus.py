"""Bind a witnessed corpus journal to one authenticated immutable Git tree.

``receipt.release_chain`` proves custody of the journal bytes. This module
proves what those rows mean: the effective content rows are exactly the files
selected by the consumer's content roots and suffixes, every present content
and attested row binds a regular blob's SHA-256 digest, every effective
tombstone is absent, and every gate declaration has the pinned schema shape.

The listing is of an immutable tree object selected by
:class:`receipt.snapshot.TreeSnapshot`. Every bound blob is streamed through
the snapshot reader, which authenticates it against its object name before
yielding a digest. The working tree and index are not read. Checkout fidelity
is outside this claim; ``CorpusVerification.name_repertoire`` records the name
policy under which the tree was judged.

Both name repertoires require valid UTF-8 wherever a name is quoted or ASCII
folded and refuse sibling names that merge under ASCII case folding. The
default ``portable`` repertoire additionally permits only ASCII letters,
digits, ``.``, ``_`` and ``-``, refuses a trailing period and Win32 device
basename, and screens the extension an 8.3 alias would carry. ``posix-bytes``
otherwise compares exact tree-name bytes and deliberately adds no Unicode
normalization or case-fold model.

``content`` rows participate in a closed-world set comparison. ``attested``
rows are exact paths required by the consumer spec without a content sweep.
``removed`` rows retire an effective content or attested binding and assert
that neither the exact path nor an ASCII-fold-equal spelling survives.
``gate`` rows are declarations, not proof a gate ran; callers use
:func:`verify_declarations` as the separate completeness pass.

Journal parsing retains hard bounds on the raw payload, each raw row, row
count, path depth and text, evidence cardinality and text, and rendered gate
and tombstone sections. Tree width, depth, path bytes, blob bytes, and total
content bytes are bounded by :mod:`receipt.snapshot`. Where the contract does
not prescribe a recovery, malformed input and exhausted budgets fail closed.
"""

from __future__ import annotations

import json
import json.encoder
import pathlib
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from receipt._names import (
    ALIAS_CAPABLE_SUFFIX_RE,
    PORTABLE_NAME_RE,
    SHORT_NAME_PUNCTUATION,
    WIN32_RESERVED_DEVICE_NAMES,
    NamePolicyError,
    ascii_fold_text,
    assert_no_merging_entries as assert_no_merging_tree_names,
    assert_portable_name,
    short_name_carries_pinned_suffix,
    short_name_extension,
    validate_component_text,
    validate_repertoire,
)
from receipt._render import bounded_encoded, bounded_key
from receipt._unicode_repertoire import FORMAT_CONTROL_RANGES
from receipt.snapshot import (
    MAX_CONTENT_BLOB_BYTES,
    MAX_CONTENT_BYTES_TOTAL,
    GitEntry,
    SnapshotError,
    TreeSnapshot,
)

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
GATE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}\Z")
#: The punctuation an 8.3 short name may carry unchanged. An ASCII character
#: outside this set, the ASCII letters and the ASCII digits is replaced by an
#: underscore when Win32 derives a short name — except a space, which is
#: removed rather than replaced, and which is why
#: :func:`_short_name_extension` strips spaces before it maps anything.
#: Every name this module screens, as one path component. The whole of the
#: portability model is here: ASCII letters, digits, ``.``, ``_`` and ``-``.
#: :func:`_assert_portable_name` asks two more questions of a component that
#: matches — that it does not end in a period, and that it does not present a
#: Win32 device basename — and the module docstring says why the three
#: together replaced five filesystem models.
#:
#: The pattern admits a leading period, because ``.axiom`` is the directory
#: every consumer corpus keeps its attested toolchain pin in and a rule that
#: refused it would refuse every corpus this package exists to verify. It
#: does not admit an empty component, nor ``.`` or ``..``, both of which end
#: in a period.
#: A pinned content suffix: a period, then one or more characters of the
#: portable repertoire, refused by :class:`CorpusSpec` at construction if it
#: is anything else. What it adds to :data:`PORTABLE_NAME_RE` is the leading
#: period and nothing else — a suffix is compared against names that have
#: passed that screen, so a character outside the repertoire could never
#: match one, and a character inside it always can.
#:
#: The released ``CorpusSpec`` accepted any dot-prefixed portable suffix, and
#: a grammar of one to sixteen ASCII letters or digits was a compatibility
#: break for no gain: it refused ``.tar.gz``, ``.ssxx``, ``.a-b`` and ``._``
#: and capped a length nothing about this module depends on (peer review, Sol
#: round 4). All four are content-suffix syntax. Alias capability is the
#: separate regex below: ``.a-b`` and ``._`` are structurally 8.3 extensions
#: and are screened, while ``.ssxx`` and ``.tar.gz`` are not (peer review,
#: Sol round 7).
#:
#: The two questions asked of a pin stay separate, and the separation is
#: where the old grammar was trying to help. ``_has_pinned_suffix`` asks
#: whether a path *ends in* the pin, which is well defined for any suffix;
#: :func:`_short_name_carries_pinned_suffix` asks whether an alias's
#: three-character extension *is* the pin, which is well defined only for a
#: pin that is structurally an 8.3 extension. So the second question is
#: asked of those pins alone — see :data:`ALIAS_CAPABLE_SUFFIX_RE` — rather
#: than being made safe by refusing every other pin at construction.
CONTENT_SUFFIX_RE = re.compile(r"\.[A-Za-z0-9._-]+\Z")
#: A pin that is structurally an 8.3 extension: a single period followed by
#: one to three repertoire characters, which is what an alias's extension can
#: be. A pin carrying a second period, or more than three characters after
#: the period, is the extension of no short name and
#: :func:`_short_name_carries_pinned_suffix` ignores it.

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
#: escape sequence would. A count of characters for the same reason
#: ``MAX_PATH_TEXT`` is one: this bounds what a refusal quotes.
MAX_EVIDENCE_TEXT = 1024
#: The most evidence entries one gate declaration may carry. The per-string
#: bound above caps each key and value; nothing capped how many pairs one
#: gate could hold, so a single legal gate row could carry an unbounded
#: number of short entries and every one of them was validated — screened
#: for size, for control characters, twice each — before the text budget
#: below was consulted at all (peer review, Sol round 2). Checked against
#: ``len(mapping)`` before the first entry is looked at.
#:
#: What that bounds is the *validation* a gate can ask for, not its
#: decoding: ``json.loads`` has already built the mapping by the time this
#: runs, and what bounds that is the row's own bytes, which are the input.
#: The two live at different levels and both are stated rather than
#: conflated.
#:
#: Sixty-four is generous for a real declaration, which names a command, a
#: workflow, a digest or two, and a reason.
MAX_EVIDENCE_ENTRIES = 64
#: The most characters of verdict text the effective view's gates may cost
#: in total. The per-string bound above caps one flood; a journal of a
#: thousand not-run gates each carrying a bound-length reason still put a
#: million characters into the verdict (peer review). Generous for any real
#: corpus, which declares tens of gates with digest-sized evidence.
#:
#: What is charged is what a gate costs the verdict, not what its producer
#: typed. Counting only gate-id and evidence payload characters let thirty
#: thousand gates carrying two characters of evidence each charge about a
#: quarter of a million and pass, while rendering four hundred thousand
#: characters of text and four million of JSON — the flood the constant
#: exists to stop, assembled out of strings none of which is long (peer
#: review, round five). So the fixed cost of the lines a gate produces is
#: charged alongside the characters it declares.
#:
#: And the characters it declares are counted as the verdict renders them,
#: not as Python holds them. ``json.dumps`` escapes with ``ensure_ascii``
#: on, so one character outside the BMP leaves as twelve; 249 four-character
#: evidence keys with 1024 of them per value charged 262,013 and rendered
#: 3,065,876 (peer review, round six). That row is not a legal gate under the
#: caps this module now ships, and calling it one overstated what the charge
#: is holding back: ``MAX_EVIDENCE_ENTRIES`` refuses it at its 65th key and
#: ``MAX_JOURNAL_ROW_BYTES`` refuses its 3,062,821 bytes (peer review, Sol
#: round 8). It is what the ratio between characters and rendered text looks
#: like, which is why the charge is on the rendered text. See
#: :func:`_rendered_length`.
#:
#: What is charged is now exactly what the JSON renderer emits for the
#: gates — every brace, key, separator, indent and newline of the section,
#: derived from the shape and pinned by a test — so this number is the size
#: of that section and not a proxy for it (peer review, round seven).
MAX_GATE_TEXT = 262144
#: The exact JSON structure one gate declaration costs the verdict, beyond
#: the escaped characters of its id and outcome and of its evidence.
#:
#: Derived from the shape ``receipt.verify.result_to_dict`` builds and the
#: ``json.dumps(..., indent=2, sort_keys=True)`` that ``receipt.cli`` renders
#: it with, not estimated: a gate is an object inside
#: ``gateDeclarations.byTier.<tier>``, so its members are indented ten spaces
#: and its evidence entries twelve. Counting from the newline that precedes
#: the object to the separator that follows it —
#:
#: * ``\n`` + eight spaces + ``{``                              = 10
#: * ``\n`` + ten spaces + ``"evidence": {``                    = 24
#: * ten spaces + ``}`` + ``,``                                 = 12
#: * ``\n`` + ten spaces + ``"gateId": `` + ``,``               = 22
#: * ``\n`` + ten spaces + ``"outcome": ``                      = 22
#: * ``\n`` + eight spaces + ``}`` + separator                  = 11
#:
#: — comes to 101. The last item of a list carries the newline before the
#: closing bracket where the others carry a comma, so the per-item cost is
#: the same wherever the gate sits.
#:
#: Charging a *floor* instead was the round-five decision, and it was wrong
#: in the direction that matters: 64 per gate and 24 per evidence entry
#: under-counted the structure by about half, so a journal filled to just
#: under the cap rendered well past it, and the test that was supposed to
#: hold the budget to the renderer permitted a ratio of four (peer review,
#: round seven). These constants are the renderer's own numbers now, and a
#: test asserts equality between what is charged and what is rendered, so a
#: change to either renderer fails a test rather than loosening a budget.
GATE_RENDER_STRUCTURE = 101
#: The same for one evidence entry, beyond its escaped key and value:
#: ``\n`` + twelve spaces + ``: `` + separator = 16. The schema requires a
#: non-empty evidence object, which is what makes this exact — an empty one
#: would render as ``{}`` and cost nothing per entry.
EVIDENCE_RENDER_STRUCTURE = 16
#: And one removed path, beyond its escaped string: ``\n`` + six spaces +
#: separator = 8. ``binding.removedPaths`` is a list of strings two levels
#: down, so its items are indented six. Charged before this round as the
#: escaped string alone, with the indentation, comma and newline free.
REMOVED_PATH_RENDER_STRUCTURE = 8
#: The most gate declarations one journal may carry. The text budget bounds
#: what a verdict renders; nothing bounded how many gates a producer could
#: put in front of an auditor, and cardinality is worth bounding for its own
#: sake — a verdict enumerating thousands of gates is unreadable however
#: short each line is, and no honest corpus declares them (peer review,
#: round five). Generous for any real one, which declares tens.
#:
#: Counted as the gate rows are met and refused at the declaration that
#: would be the cap plus one, *before* that row is validated. Comparing
#: ``len(gates)`` after the parse loop had finished meant a 2,050-gate
#: journal was decoded and validated in full — every gate id matched
#: against its pattern, every tier and outcome checked, every evidence
#: string screened twice — and only then refused for the count that was
#: knowable at row 2,049 (peer review, Sol round 2).
#:
#: Enforcing both budgets in row order makes something plain that checking
#: this one after the loop hid: it is a backstop and not a live limit. The
#: cheapest gate the schema admits — a one-character id, the shortest
#: outcome, one evidence entry with an empty key and an empty value —
#: costs 130 characters of rendered verdict once ``GATE_RENDER_STRUCTURE``
#: is charged exactly, which round seven made it, so 2,048 of them cost
#: 266,240 and ``MAX_GATE_TEXT`` refuses at about the 2,016th. No journal
#: can reach this cap. It is kept because it states a bound a reader can
#: check and because it would become live again if either of the other two
#: constants moved; a test pins the arithmetic so a change to either fails
#: a test rather than quietly reviving or burying it.
MAX_GATE_DECLARATIONS = 2048
#: The default number of rows a consumer lets one journal carry, checked by
#: counting line feeds before any row is parsed. Every other budget here bounds
#: what a *valid* journal costs; this one defaults the bound on what an invalid
#: one can make the parser allocate before a single row has been decoded.
#:
#: Derived rather than picked: the gate cap above is 2,048 declarations, and
#: the other three row kinds — content, attested and removed — get an equal
#: margin of 2,048 between them, which is 4,096.
#:
#: That margin bounds the whole *journal*, not the tree it describes, and the
#: journal is append-only: a corpus of five hundred rule files that has cut
#: four releases has written more than two thousand content rows, whatever its
#: tree holds today. So what a consumer has to watch is bound paths times
#: revisions plus tombstones. A corpus that outgrows the default pins a larger
#: ``CorpusSpec.journal_row_capacity`` in committed consumer code rather than
#: editing this process-global default (peer review, Sol round 7).
MAX_JOURNAL_ROWS = 4096
#: The most bytes one journal row may occupy, checked on the row's own bytes
#: before the row is decoded and before ``json.loads`` is asked to build
#: anything out of it.
#:
#: The pinned row capacity bounds how many rows a journal may carry and says
#: nothing about how large one of them is, so a single row of arbitrary size
#: was decoded, split out, and handed to ``json.loads`` — which materialises
#: the whole object graph — before any budget had been consulted (peer
#: review, Sol round 3). Checking this cap on the *decoded* text then left the
#: allocation it exists to stop already made: the journal was decoded whole
#: and split whole before the first row was measured, so the row bound bounded
#: ``json.loads`` and nothing else (peer review, Sol round 4). The rows are
#: found by splitting the raw bytes on ``b"\n"`` — which is exact, because a
#: line feed cannot occur inside a UTF-8 multi-byte sequence — and each row is
#: measured as bytes before it is turned into text.
#:
#: Derived from the largest row this schema admits, which is a gate
#: declaration. Its evidence may carry ``MAX_EVIDENCE_ENTRIES`` = 64 entries
#: whose key and value are each up to ``MAX_EVIDENCE_TEXT`` = 1024
#: characters, and JSON may spell one character in as many as twelve bytes —
#: a character outside the BMP escaped as a surrogate pair, ``\uXXXX\uXXXX``
#: — so one string costs at most 12 × 1024 + 2 quotes = 12,290 bytes and one
#: entry at most 2 × 12,290 + 4 for its colon, space and comma = 24,584.
#: Sixty-four of those come to 1,573,376.
#:
#: Two megabytes is that rounded up to the next power of two, which leaves
#: 523,776 bytes for everything else in the row: the braces and separators,
#: ``entryIndex``, ``kind``, ``tier``, ``outcome``, a gate id of at most 128
#: characters, and the consumer's own pinned ``schemaVersion``, which is the
#: one term here that is not bounded by this module. A consumer whose schema
#: version is half a megabyte long has to raise this, and would know it.
MAX_JOURNAL_ROW_BYTES = 2097152
#: The most bytes one journal may occupy in total, checked on the raw bytes
#: before anything else looks at them. Every other budget here bounds what a
#: journal *shaped like a journal* costs; this one bounds an input that is
#: not one at all, whose size is the only thing about it knowable before it
#: is decoded.
#:
#: Stated rather than derived. It was the product of the two constants above
#: — 4,096 rows times two megabytes, or eight gibibytes — which is the product
#: of two worst cases no journal reaches at once, and a ceiling of eight
#: gibibytes on the one input this module cannot recognise is not a ceiling
#: (peer review, Sol round 4). Sixty-four mebibytes is a statement about what
#: a corpus journal may be at all: a real one is kilobytes, because it carries
#: one row per bound path per revision plus its gates and tombstones. The hard
#: row-capacity ceiling below is derived *from* this stated input bound; this
#: bound itself is not derived from the row limits. Raising it is a visible
#: change to a consumer-facing bound.
#:
#: The bytes are already in the caller's hand by then —
#: :func:`verify_corpus_binding` is passed the same bytes the release chain
#: verified — so what this bounds is the decode and everything downstream of
#: it, not the read.
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
#: The largest row capacity any consumer may pin. The shortest valid row is a
#: compact gate declaration with one-character ``schemaVersion`` and ``gateId``,
#: ``entryIndex`` zero, tier ``public``, outcome ``pass`` and evidence
#: ``{"": ""}``: 115 bytes plus its required LF, or 116. No valid journal of
#: at most 64 MiB can carry more than 67,108,864 // 116 = 578,524 such rows
#: (remainder 80), so a larger pin could weaken no byte-bound journal and would
#: only invite an invalid input to allocate more row slots (peer review, Sol
#: round 7).
MAX_JOURNAL_ROWS_CEILING = MAX_JOURNAL_BYTES // 116
#: The most characters one journal path may carry. Paths are quoted in
#: refusals and, for removed paths, rendered in the verdict; the bound is
#: checked before any other path rule so no refusal quotes a flood. A count
#: of characters, deliberately: what it bounds is the Python text a refusal
#: quotes back, not the JSON a verdict renders, and the total the verdict
#: renders is bounded by ``MAX_REMOVED_TEXT`` instead.
MAX_PATH_TEXT = 1024
#: The most components any single path can have. A path with ``n`` non-empty
#: components carries at least ``2n - 1`` characters — ``n`` one-character
#: names and ``n - 1`` separators — so ``MAX_PATH_TEXT`` admits no path deeper
#: than this. Written as the arithmetic rather than as 512 because it is a
#: consequence of the path-text bound and moves with it.
MAX_PATH_COMPONENTS = (MAX_PATH_TEXT + 1) // 2
#: Total component-folding work for declared paths. The alias pass charges
#: once while building each folded component sequence and once when counting
#: the distinct prefixes represented by adjacent sorted paths.
MAX_PATH_COMPONENTS_TOTAL = MAX_JOURNAL_ROWS * MAX_PATH_TEXT
#: The most distinct folded prefixes the declared-path alias pass may count.
MAX_ALIAS_INDEX_NODES = MAX_JOURNAL_ROWS * MAX_PATH_COMPONENTS
#: The most characters the verdict's removedPaths may carry in total; the
#: gate budget's counterpart for the other producer-controlled list the
#: verdict renders verbatim (peer review, round two). Counted the same way
#: as the gate budget and for the same reason: a path of non-BMP characters
#: renders twelve times its length, so a set of them charged an eighth of
#: what the verdict would carry (peer review, round six). And with the same
#: correction: the eight characters of indentation, comma and newline the
#: renderer puts around each path are charged too, so this bounds the
#: section rather than the strings inside it (peer review, round seven).
MAX_REMOVED_TEXT = 262144
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
    """The journal is malformed, or it does not describe the selected tree."""


@dataclass(frozen=True)
class CorpusSpec:
    """Corpus-specific binding constants, pinned in the consumer's code.

    The producer chooses what to write into the journal. The consumer chooses
    what the journal must cover before a verdict is allowed to pass. Every
    field here is the second kind of choice. Trust anchors have no package
    defaults. ``journal_row_capacity`` is the resource pin and alone defaults
    to :data:`MAX_JOURNAL_ROWS`, preserving every existing consumer spec while
    letting one with a longer append-only history raise its own capacity.
    """

    schema_version: str
    content_roots: tuple[pathlib.PurePosixPath, ...]
    content_suffixes: tuple[str, ...]
    required_attested_paths: frozenset[str]
    accepted_gate_tiers: frozenset[str]
    required_gates: frozenset[str]
    journal_row_capacity: int = MAX_JOURNAL_ROWS
    name_repertoire: str = "portable"

    def __post_init__(self) -> None:
        try:
            selected_repertoire = validate_repertoire(self.name_repertoire)
        except NamePolicyError as exc:
            raise CorpusError(str(exc)) from exc
        if type(self.schema_version) is not str or not self.schema_version:
            raise CorpusError("CorpusSpec schema_version must be a non-empty string")
        if (
            type(self.journal_row_capacity) is not int
            or not 1 <= self.journal_row_capacity <= MAX_JOURNAL_ROWS_CEILING
        ):
            raise CorpusError(
                "CorpusSpec journal_row_capacity must be an integer from 1 to "
                f"{MAX_JOURNAL_ROWS_CEILING}"
            )
        if type(self.content_roots) is not tuple or not self.content_roots:
            raise CorpusError("CorpusSpec must declare at least one content root")
        for root in self.content_roots:
            if not isinstance(root, pathlib.PurePosixPath):
                raise CorpusError("CorpusSpec content_roots must be PurePosixPath")
            if selected_repertoire == "portable":
                # Preserve the spec-specific portable-name diagnostic before
                # the general relative-path screen.
                for component in root.as_posix().split("/"):
                    _assert_portable_name(component, "CorpusSpec content root")
            _validate_relative_path(
                root.as_posix(),
                "content root",
                repertoire=selected_repertoire,
            )
        if type(self.content_suffixes) is not tuple or not self.content_suffixes:
            raise CorpusError("CorpusSpec must declare at least one content suffix")
        for suffix in self.content_suffixes:
            # One rule, CONTENT_SUFFIX_RE, in place of four screens that grew
            # one review round at a time: a leading dot, a foldability screen,
            # an ASCII rule asked only of alias-capable pins, and a fold-key
            # length test to decide which those were. What a pin has to be is
            # a period followed by portable characters — the released
            # semantics, narrowed by the repertoire and by nothing else. A
            # length cap and a ban on interior periods were a compatibility
            # break that bought nothing, because the question they were
            # protecting is asked only of the pins it is well defined for
            # (peer review, Sol round 4).
            if type(suffix) is not str or CONTENT_SUFFIX_RE.fullmatch(suffix) is None:
                raise CorpusError(
                    "CorpusSpec content suffix must be '.' followed by one or "
                    "more portable characters (ASCII letters, digits, '.', "
                    f"'_' and '-'): {_quoted(suffix)}"
                )
        if type(self.required_attested_paths) is not frozenset:
            raise CorpusError("CorpusSpec required_attested_paths must be a frozenset")
        for path in sorted(self.required_attested_paths):
            _validate_relative_path(
                path,
                "required attested path",
                repertoire=selected_repertoire,
            )
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
    name_repertoire: str

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


def _is_format_control(code: int, category: str) -> bool:
    """Whether this code point is a Unicode format control on any pinned table.

    The pinned Unicode 16.0 ``Cf`` set lives in
    :data:`receipt._unicode_repertoire.FORMAT_CONTROL_RANGES` — it moved
    there so ``receipt.cli`` can escape the same set on its way to a
    terminal — and the running interpreter's own answer widens it, never
    narrows it.
    """

    if category == "Cf":
        return True
    return any(low <= code <= high for low, high in FORMAT_CONTROL_RANGES)


def _reject_control_characters(value: str, label: str) -> str:
    """Refuse control, format, and line-separator code points in producer text.

    Asked of gate evidence — the keys and the values — and of nothing else.
    It used to screen declared paths as well, and does not now: a path is a
    name, so :func:`_assert_portable_name` decides what it may carry, and
    every class refused here is outside the portable repertoire. Evidence is
    not a name and cannot be constrained that way; it is prose a producer
    writes for a reader.

    Every string this sees is written by a producer and later rendered to
    a terminal. A carriage return, an ESC, or a line feed inside one lets the
    producer redraw the verdict: a witnessed "reason" carrying
    ``\\x1b[2K\\r  VERDICT: PASS`` overwrites the line that was about to say the
    gate did not run. The verdict is the product here, so the sanitising
    belongs at the schema boundary where the text enters, not only at the
    point where it is printed. (Found by cross-family review.)

    The C0 block is not the only way to do it, so two more classes refuse
    here:

    - Every code point in Unicode category Cf, as of Unicode 16.0 and pinned
      in :data:`receipt._unicode_repertoire.FORMAT_CONTROL_RANGES`, or in
      the running interpreter's own table. These render as nothing while
      changing what the reader sees: U+202E RIGHT-TO-LEFT OVERRIDE reverses
      the remainder of the line, so a gate declared not-run can be spelled to
      read as passed, and U+200B lets two evidence keys print identically.
    - U+2028 and U+2029, line separators outside the C0 block, which split one
      evidence string into as many verdict lines as the producer wants in any
      renderer that honours them.
    - Every code point in category Cs, a lone surrogate. JSON spells one as
      ``\\ud800`` inside otherwise valid UTF-8, so it survives the decode, and
      no legitimate reason carries one. The other half of why it was refused
      belonged to paths — ``os.lstat`` raises ``UnicodeEncodeError`` on one,
      a ``ValueError`` no ``OSError`` handler sees — and that half is the
      portable-name screen's now.

    Taking the Cf class whole has a cost, accepted deliberately: U+200C and
    U+200D are required spelling in Persian, Hindi and Sinhala, and U+061C
    appears in ordinary Arabic text, so a not-run reason written in them
    refuses here. The verdict quotes
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


def _rendered_length(text: str) -> int:
    """What one producer string costs the verdict once JSON has escaped it.

    The budgets below bound what a verdict renders, and the verdict is
    rendered by ``json.dumps(..., indent=2, sort_keys=True)`` in
    ``receipt.cli`` — with ``ensure_ascii`` left at its default of True. So
    every non-ASCII character a producer writes leaves this module as an
    escape: three ASCII characters become six for a BMP character, and a
    character outside the BMP becomes a surrogate pair spelled as twelve
    (peer review, round six). Charging Python characters let a gate with 249
    four-character keys and 1024 U+1F600 characters per value charge 262,013
    against a budget of 262,144 and render 3,065,876 characters of JSON — the
    flood the budget exists to stop, a factor of twelve under the cap. That
    row is refused twice over by the caps this module now ships —
    ``MAX_EVIDENCE_ENTRIES`` at its 65th key, ``MAX_JOURNAL_ROW_BYTES`` at
    its 3,062,821 bytes — so it is the ratio it demonstrates and not a row a
    producer could still send (peer review, Sol round 8).

    So the charge is what ``json.dumps`` makes of the string, quotes
    included — taken from the escaper ``json.dumps`` applies to a string
    rather than by calling it. ``JSONEncoder.encode`` short-circuits a
    top-level string to exactly this function when ``ensure_ascii`` is on, so
    the two are equal by construction and a test pins the equality; naming
    the escaper keeps a caller who has substituted something for
    ``json.dumps`` from silently changing what a budget charges.

    The per-string bounds (``MAX_EVIDENCE_TEXT``, ``MAX_PATH_TEXT``) stay
    counts of characters, because what they bound is what a *refusal* quotes
    back, which is Python text and not JSON.
    """

    return len(json.encoder.encode_basestring_ascii(text))


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


#: The basenames Win32 resolves to a character device instead of to a file,
#: in every directory and whatever extension follows them: ``rules/NUL.yaml``
#: opens the null device, not the bytes a journal bound. Pinned here rather
#: than derived, because it is a Win32 fact and not a Unicode one, and every
#: entry is attributed to the source it rests on rather than to a union of
#: sources that disagree.
#:
#: Microsoft, "Naming Files, Paths, and Namespaces",
#: learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file, fetched
#: 2026-09-03 with the page and its docs source both dated 2024-08-28:
#:
#:     Do not use the following reserved names for the name of a file:
#:     CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8,
#:     COM9, COM¹, COM², COM³, LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7,
#:     LPT8, LPT9, LPT¹, LPT², and LPT³. Also avoid these names followed
#:     immediately by an extension; for example, NUL.txt and NUL.tar.gz are
#:     both equivalent to NUL. [The page continues with a cross-reference
#:     to its Namespaces section, trimmed here.]
#:
#: That sentence is the source of every entry below except the two named
#: next, and of the superscripts in particular, which the same page's note
#: says Windows "treats [...] as valid parts of COM# and LPT# device names,
#: making them reserved in every directory".
#:
#: CONIN$ and CONOUT$ rest on ``ntdll``'s own matcher instead:
#: ``RtlIsDosDeviceName_U`` resolves both, and Microsoft's page does not
#: list them. Two Wine files were read for that, both fetched 2026-09-03:
#: the implementation, ``dlls/ntdll/path.c``, and the conformance table in
#: ``dlls/ntdll/tests/path.c``, which is run against real Windows and
#: records ``{ "CONIN$", 0, 12, TRUE }`` — a device name, and the ``TRUE``
#: is the comment's note that it fails on Windows 7.
#:
#: COM0 and LPT0 were in this table and are not any more, because neither
#: source supports them. The sentence above lists COM1 through COM9; the
#: matcher's digit test is ``if (*end <= '0' || *end > '9') break;``, so a
#: zero is not a device there either; and the conformance table asserts it
#: directly, with ``{ "c:\\lpt0.txt", 0, 0 }`` among its cases. The entry
#: was kept as the fail-closed side of a disagreement that does not exist,
#: and its cost is real: a corpus holding an ordinary ``COM0.yaml`` was
#: refused outright (peer review, Sol round 2).
def _assert_portable_name(value: str, label: str) -> str:
    """Refuse a name outside the repertoire every filesystem agrees about.

    One screen, run everywhere this module takes a name: declared paths, the
    spec's own content roots, the tree entry names the closed-world sweep
    judges, the entry names beside a pinned root's components, and the entry
    names a tombstone search reads out of a listing. What it asks is not "is
    this name legal" but "does this module know what this name means on the
    filesystem a consumer will resolve the tree on".

    Three questions, one refusal, one message. The component must be spelled
    with ASCII letters, digits, ``.``, ``_`` and ``-``
    (:data:`PORTABLE_NAME_RE`); it must not end in a period, which Win32
    strips before a lookup, so that the entry carrying one is the entry
    beside it; and its Win32 device basename must not be in
    :data:`WIN32_RESERVED_DEVICE_NAMES`, because ``rules/NUL.yaml`` opens the
    null device there rather than the bytes a journal bound. The three are
    asked over the whole value before it is quoted back, so which of them a
    name fails is a property of the name and not of where in it the offending
    character sits.

    The module docstring says why this replaced the modelling that used to
    live here — a pinned Unicode repertoire, a default-ignorable table, the
    Turkic dotless i, a colon, a backslash, a trailing space, and an 8.3
    tilde grammar, each of them a guess at a filesystem this module cannot
    identify. The short version is that every corpus this package verifies
    was already inside the portable repertoire, so refusing the rest costs
    nothing that a real corpus carries and removes five models that were
    wrong more often than they were right.

    What that buys is stated as an equality rather than as a hope: inside the
    repertoire :func:`_path_fold` is ASCII case-insensitivity, and ASCII case
    is the one insensitivity every filesystem in question actually has. There
    is no second equivalence class left to model.

    ``value`` may be a whole relative path or a single component; the split
    is over ``/``, so a value that is already one component is screened as
    one, and every message quotes the value whole through :func:`_quoted`.
    """

    try:
        return assert_portable_name(value, label)
    except NamePolicyError as exc:
        raise CorpusError(
            f"{label} is not a portable name (ASCII letters, digits, "
            "'.', '_' and '-', not ending in '.', not a Win32 device "
            f"name): {_quoted(value)}"
        ) from exc


def _alias_capable_suffix(suffix: str) -> bool:
    """Whether an 8.3 alias extension could ever be this pinned suffix.

    An alias extension is one to three characters of the 8.3 namespace, so a
    carryable pin is a period followed by one to three repertoire characters
    and nothing else — which is exactly :data:`ALIAS_CAPABLE_SUFFIX_RE`. A
    pin longer than that is the extension of no alias, and comparing the
    first three characters of one refused an ordinary ``notes.yam`` under a
    ``.yaml`` configuration although no alias can end ``.yaml`` (peer review,
    round eight).

    Measured by shape rather than by length, because the schema admits a pin
    with interior periods again: ``.tar.gz`` is six characters and would have
    passed a two-to-four *length* test on nothing but arithmetic if the
    schema had ever admitted a six-character one, and it is emphatically not
    an extension — the text after the last period of an 8.3 name is ``GZ``,
    which is a different pin (peer review, Sol round 4). A single period,
    then one to three characters an 8.3 extension can hold, is the whole
    rule.

    The written spelling is the measurement, and under the portable-name
    policy that is not a shortcut: :data:`CONTENT_SUFFIX_RE` admits only
    repertoire characters after the period, and NFC plus case folding changes
    neither the length nor the character count of ASCII. Measuring the fold
    key instead was necessary while a pin could be an NFD spelling of
    something non-ASCII, which is a state the schema no longer admits.

    The low end is a statement rather than a guard: the shortest pin the
    schema admits is two characters, so nothing reaching here is shorter.
    """

    return ALIAS_CAPABLE_SUFFIX_RE.fullmatch(suffix) is not None


def _short_name_extension(name: str) -> str | None:
    """The extension 8.3 generation gives this name, or None if it gives none.

    Derived the way Win32 derives it, in the order Win32 applies the rules,
    because the order is what decides the answer:

    - every space is removed first. Win32 strips spaces out of a name before
      it truncates, so ``"smuggled.y mlx"`` yields ``YML`` and not ``Y M``
      (peer review, round seven: truncating the raw extension read the space
      as a character and the helper answered false for a name whose alias
      really would carry the pinned suffix). No name the sweep hands this
      function can carry a space any more — the portable repertoire holds
      none — so this rule is unreachable from there and is kept because it
      is Win32's rule and because the function is asked directly;
    - leading periods are then removed, so ``".yml"`` has no extension here
      at all, exactly as it has none in the short name Win32 hands out;
    - what follows the last remaining period is the extension. If no period
      remains there is none;
    - it is truncated to three characters, which is all an 8.3 extension
      holds;
    - each of those three is mapped: an ASCII letter is uppercased, an
      ASCII digit and the punctuation in :data:`SHORT_NAME_PUNCTUATION` are
      kept, and any other ASCII character — a surviving period included —
      becomes an underscore, which is what Win32 substitutes for a character
      the 8.3 namespace cannot hold.

    A *non-ASCII* character cannot reach any of that, because every name
    this is asked about has already passed :func:`_assert_portable_name`.
    That is the whole of what the portable-name policy does for this
    function, and it is a great deal: the 8.3 namespace is an OEM code page
    rather than ASCII, so which non-ASCII characters survive into an alias is
    the volume's decision and not this verifier's, and two review rounds went
    on bounding a derivation over characters no clone reports. With the names
    ASCII the derivation is exact rather than bounded, and the refusal it
    used to raise — "cannot be derived" — is gone with the question.

    What is modelled is the extension and nothing else. The *stem* is not:
    it depends on collisions with names this verifier cannot see, so the
    tilde-digit part of a short name is unmodellable from here. Whether 8.3
    generation is even on for the volume is not modelled either — it is a
    per-volume setting an auditor's clone cannot report. Both of those are
    why the caller refuses on the extension alone rather than reconstructing
    a short name and looking for it.
    """

    return short_name_extension(name)


def _short_name_carries_pinned_suffix(name: str, suffixes: tuple[str, ...]) -> bool:
    """Whether 8.3 generation would give this name a pinned content suffix.

    An NTFS volume with 8.3 generation on hands a long name a second,
    addressable spelling: the stem shortened with a tilde-digit and the
    extension truncated to its first three characters, uppercased. So with
    ``.yml`` pinned, a file emitted as ``smuggled.ymlx`` is not content under
    :func:`_has_pinned_suffix` — its suffix is ``.ymlx`` — while the
    ``SMUGGL~1.YML`` that opens the same bytes is content, and sits outside
    the closed world the sweep just called closed (peer review, round six).

    The alias's extension comes from :func:`_short_name_extension`, which
    applies the 8.3 rules in Win32's own order rather than truncating the
    written name. What that models, and what it does not, is stated there.

    Only a pin an alias can carry is compared, and it is compared exactly.
    An 8.3 extension is at most three characters and carries no period of its
    own, so a pin longer than that, or one carrying a second period like
    ``.tar.gz``, is the extension of no alias and is ignored here entirely;
    :func:`_alias_capable_suffix` decides that. Truncating the pin instead and
    comparing the first three characters was unsound the other way: with
    ``.yaml`` pinned, an ordinary ``notes.yam`` was refused as though its
    alias carried the pin, although no alias of anything can end ``.yaml``
    and the file is simply not content (peer review, round eight). What is
    left is an exact comparison between the derived alias extension and a
    pin short enough to be one.

    The pins are filtered before the name is touched, which costs nothing
    and keeps the two halves in the order they belong: where no pin can be
    carried by an alias there is no question, and no name is asked one.

    Compared through :func:`_path_fold`, the key by which membership is
    decided everywhere else in this module, so ``.YML`` and ``.yml`` are one
    suffix here exactly as they are there.
    """

    return short_name_carries_pinned_suffix(name, suffixes)


def _validate_relative_path(
    value: Any, label: str, *, repertoire: str = "portable"
) -> str:
    """Reject anything that could escape the root or mean two things at once.

    Four shape rules and then the name screen. The shape rules are about the
    path — it must be a bounded non-empty string, relative, with no empty
    and no ``.``/``..`` segment — and they run first so that a path with one
    of those faults is told what is wrong with it as a path.

    :func:`_assert_portable_name` is the rest, and it is now the whole of the
    rest. It subsumes four screens this function used to carry separately: a
    backslash (not in the repertoire), a colon (not in the repertoire, which
    is what kept ``C:/x`` from joining drive-absolute under ``pathlib``), the
    control, format-control, surrogate and line-separator classes
    :func:`_reject_control_characters` refuses in producer text (none of them
    in the repertoire), and the two Win32 alias shapes — a trailing dot or
    space, and the 8.3 tilde grammar — which the repertoire and the
    trailing-period rule between them make unspellable. One screen and one
    message in place of five, and the module docstring says why.
    """

    if type(value) is not str or not value:
        raise CorpusError(f"{label} must be a non-empty string")
    if len(value) > MAX_PATH_TEXT:
        # First, so that no refusal below quotes a flood.
        raise CorpusError(
            f"{label} is longer than {MAX_PATH_TEXT} characters ({len(value)})"
        )
    if value.startswith("/") or value.endswith("/"):
        raise CorpusError(
            f"{label} must be relative with no trailing slash: {_quoted(value)}"
        )
    for segment in value.split("/"):
        if not segment:
            raise CorpusError(f"{label} has an empty path segment: {_quoted(value)}")
        if segment in (".", ".."):
            raise CorpusError(f"{label} contains a relative segment: {_quoted(value)}")
    try:
        selected_repertoire = validate_repertoire(repertoire)
    except NamePolicyError as exc:
        raise CorpusError(str(exc)) from exc
    if selected_repertoire == "portable":
        _assert_portable_name(value, label)
    else:
        for segment in value.split("/"):
            try:
                validate_component_text(
                    segment,
                    repertoire=selected_repertoire,
                    label=label,
                )
                # Every path enters an ASCII-fold index later. This strict
                # boundary refuses surrogateescaped, non-UTF-8 tree bytes
                # before the value can be quoted in a verdict.
                ascii_fold_text(segment)
            except NamePolicyError as exc:
                raise CorpusError(str(exc)) from exc
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
    # Cardinality before content, and before the first entry is looked at:
    # the per-string bounds cap what one entry costs and capped nothing
    # about how many of them one gate may carry, so a single legal row could
    # make this loop screen an unbounded number of short pairs before any
    # budget was consulted (peer review, Sol round 2).
    if len(evidence) > MAX_EVIDENCE_ENTRIES:
        raise CorpusError(
            f"journal row {number} gate {_quoted(gate_id)} declares "
            f"{len(evidence)} evidence entries, over the limit of "
            f"{MAX_EVIDENCE_ENTRIES}"
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

    Row capacity is the consumer's committed resource pin, not a process-wide
    corpus limit. It defaults to :data:`MAX_JOURNAL_ROWS` and is validated
    against :data:`MAX_JOURNAL_ROWS_CEILING` when the spec is constructed.
    """

    # Before the decode, because the decode is the allocation every later
    # bound is measured against: a journal of arbitrary size became a ``str``
    # of arbitrary size before anything looked at it (peer review, Sol
    # round 3).
    if len(journal_bytes) > MAX_JOURNAL_BYTES:
        raise CorpusError(
            f"corpus journal is {len(journal_bytes)} bytes, over the parser "
            f"budget of {MAX_JOURNAL_BYTES}"
        )
    if not journal_bytes.endswith(b"\n"):
        raise CorpusError("corpus journal must end with exactly one LF")
    # Counted, not split, and checked before the split: ``bytes.count`` walks
    # the payload without building the list, so the list a journal can make
    # this function allocate — and everything downstream of it — is bounded
    # by a stated input size before a single row has been read.
    row_count = journal_bytes.count(b"\n")
    if row_count > spec.journal_row_capacity:
        raise CorpusError(
            f"corpus journal carries {row_count} rows, over the parser "
            f"budget of {spec.journal_row_capacity}"
        )
    # Split on the raw bytes, and every question below asked of a row before
    # it becomes text. A line feed cannot occur inside a UTF-8 multi-byte
    # sequence, so splitting the encoded form finds exactly the rows
    # splitting the decoded form would, and it finds them without decoding
    # anything: the row bound below is measured on what arrived rather than
    # on what an allocation the bound exists to stop has already produced
    # (peer review, Sol round 4).
    raw_rows = journal_bytes.split(b"\n")[:-1]
    if not raw_rows:
        raise CorpusError("corpus journal is empty; genesis must bind content")

    content: dict[str, FileBinding] = {}
    attested: dict[str, FileBinding] = {}
    gates: list[GateDeclaration] = []
    gate_ids: dict[str, int] = {}
    removed: set[str] = set()
    gate_text_charged = 0

    for number, raw_row in enumerate(raw_rows, start=1):
        # First, so that nothing else in this loop — not the decode, not
        # ``strip``, and certainly not ``json.loads``, which materialises the
        # whole object graph — is asked to work on a row of unbounded size.
        # Measured on the bytes the row arrived as, which is what makes the
        # bound exact and what makes it bind before the allocation rather
        # than after it.
        if len(raw_row) > MAX_JOURNAL_ROW_BYTES:
            raise CorpusError(
                f"journal row {number} is {len(raw_row)} bytes, over the "
                f"parser budget of {MAX_JOURNAL_ROW_BYTES}"
            )
        try:
            line = raw_row.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CorpusError("corpus journal is not UTF-8") from exc
        if not line.strip():
            raise CorpusError(f"journal row {number} is blank")
        if line.endswith("\r"):
            raise CorpusError(f"journal row {number} uses CRLF, not exact LF")
        row = _parse_row(line, number, spec)
        kind = row["kind"]

        if kind == GATE_KIND:
            # Cardinality before validation, so the declaration that would be
            # the cap plus one is refused rather than checked. Comparing the
            # total after the loop meant every gate of a 2,050-gate journal
            # was validated first (peer review, Sol round 2).
            if len(gates) >= MAX_GATE_DECLARATIONS:
                raise CorpusError(
                    f"journal row {number} declares more gates than the "
                    f"verdict budget of {MAX_GATE_DECLARATIONS} declarations"
                )
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
            # And the render cost as the row is validated, refused at the
            # first gate that carries the running total over. Summing after
            # the loop bounded the verdict and nothing else: the journal that
            # cost twice the budget was decoded and validated in full before
            # the sum was compared. The gate's own evidence is summed whole,
            # because ``json.loads`` materialised the row before this point
            # and MAX_EVIDENCE_ENTRIES bounds how many entries that is.
            # Charged on what the renderer will print, not on what the
            # producer wrote: ``receipt.cli`` puts every string in the
            # verdict through ``receipt._render`` first, and charging the
            # unbounded string made the accounting and the rendering
            # disagree in both directions (peer review, Sol round 3). The
            # bound is a no-op for every string a real corpus carries, and
            # for the ones it is not, this is the difference between
            # refusing a gate for text nothing would print and charging what
            # appears.
            gate_text_charged += (
                GATE_RENDER_STRUCTURE
                + _rendered_length(bounded_encoded(gate.gate_id))
                + _rendered_length(bounded_encoded(gate.outcome))
                + sum(
                    EVIDENCE_RENDER_STRUCTURE
                    + _rendered_length(bounded_key(key))
                    + _rendered_length(bounded_encoded(value))
                    for key, value in gate.evidence.items()
                )
            )
            if gate_text_charged > MAX_GATE_TEXT:
                raise CorpusError(
                    "journal gate declarations cost more than the verdict "
                    f"budget of {MAX_GATE_TEXT} characters: "
                    f"{gate_text_charged} charged at declaration "
                    f"{len(gates)} (journal row {number})"
                )
            continue

        path = _validate_relative_path(
            row["path"],
            f"journal row {number} path",
            repertoire=spec.name_repertoire,
        )
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

    # Sorted first, so which path the refusal names is a property of the
    # journal and not of set iteration order, and so that it is the same
    # order the verdict renders them in.
    removed_paths = tuple(sorted(removed))
    charged = 0
    for number, path in enumerate(removed_paths, start=1):
        # The same bound the renderer applies, for the same reason.
        charged += REMOVED_PATH_RENDER_STRUCTURE + _rendered_length(
            bounded_encoded(path)
        )
        if charged > MAX_REMOVED_TEXT:
            raise CorpusError(
                "journal removed paths total more than the verdict budget of "
                f"{MAX_REMOVED_TEXT} characters: {charged} charged at path "
                f"{number} of {len(removed_paths)}"
            )

    return content, attested, tuple(gates), removed_paths


class _PathPrefixWork:
    """The bounded component work performed by the declared-path alias pass.

    Units are charged in batches of at most one path's depth, so that a
    2.1-million-visit walk does not pay 2.1 million calls to arrive at the
    same total. The overshoot that buys is bounded by
    :data:`MAX_PATH_COMPONENTS` — one path's worth — and every batch is
    charged before the work it pays for, which is what the bound needs.
    """

    def __init__(self) -> None:
        self._work = 0

    @property
    def work(self) -> int:
        """Path-prefix units charged so far."""

        return self._work

    def charge(self, units: int = 1) -> None:
        """Charge path-prefix work before it folds or allocates a key."""

        self._work += units
        if self._work > MAX_PATH_COMPONENTS_TOTAL:
            raise CorpusError(
                "declared paths visit more than "
                f"{MAX_PATH_COMPONENTS_TOTAL} prefixes; the corpus cannot be "
                "bound safely"
            )


def _under(directory: str, name: str) -> str:
    """Return an entry path from its tree-relative directory and local name."""

    return f"{directory}/{name}" if directory else name


def _path_fold(relative: str) -> str:
    """Fold ASCII letters component-wise and preserve every other code point."""

    try:
        return "/".join(ascii_fold_text(component) for component in relative.split("/"))
    except NamePolicyError as exc:
        raise CorpusError(str(exc)) from exc


def _has_pinned_suffix(relative: str, suffixes: tuple[str, ...]) -> bool:
    """Whether a path ends in a pinned suffix after the policy's ASCII fold."""

    folded = _path_fold(relative)
    return any(folded.endswith(_path_fold(suffix)) for suffix in suffixes)


def _reject_aliasing_paths(
    relatives: list[str], *, work: _PathPrefixWork
) -> int:
    """Refuse two declared paths a real filesystem would treat as one.

    Two passes, because a path can alias another in two places and the
    second one was missed.

    The first compares whole paths, which is what "the closed-world set is
    ambiguous" is about: a journal binding both ``rules/x.yaml`` and
    ``rules/X.yaml`` says two different digests about one file on APFS, and
    an auditor cannot say which one they have.

    The second compares every *prefix* of every path — each ancestor
    directory and the path itself — at the depth it sits. Comparing whole
    paths alone missed the case where the collision is a directory:
    ``rules/A/x.yaml`` and ``rules/a/y.yaml`` are two distinct paths whose
    fold keys differ, so the first pass passes them, while an insensitive
    clone merges ``A`` and ``a`` into one directory holding both files —
    and the closed-world sweep, which descends the spellings the journal
    named, walks two directories on the auditor's host and one on the
    consumer's (peer review, Sol round 3). The path itself is included at
    its own depth as well, so a directory in one path colliding with a file
    in another is caught too.

    Under the portable-name policy the fold key over a declared path is
    ASCII case-insensitivity, so what both passes are asking is whether two
    spellings differ only in case.

    **The prefix pass holds no index.** It used to build one — first a
    cumulative string per visit, then a component trie of one node per
    distinct prefix — and a trie is an index whose size is the thing an
    adversary chooses. 4,096 portable 1,023-character paths with distinct
    three-character first components and 510 one-character descendants are
    inside ``MAX_JOURNAL_ROWS``, inside ``MAX_PATH_TEXT`` and inside half of
    :data:`MAX_PATH_COMPONENTS_TOTAL`, and they name 2,093,056 distinct
    prefixes: 594 MB of trie nodes and 4.8 seconds, measured, for a journal
    the budget waved through (peer review, Sol round 7, round 3). Compacting
    the node — ``__slots__``, one shared child dictionary, interned spellings
    — cannot fix that. A Python object plus its dictionary entry is on the
    order of 150 bytes whatever is done to it, so the *representation* was
    never the choice worth making; holding one at all was.

    So the pass sorts instead. Each path is folded a component at a time and
    the folded components are joined by a NUL — a character no portable name
    can hold and one that sorts below every character one can — so
    ordering the keys as strings orders the paths by their folded component
    *sequences*. Two facts make neighbour comparison sufficient:

    - every path sharing a folded prefix occupies a contiguous run of that
      order, which is what sorting by a sequence means;
    - so if two paths in such a run disagree about the spelling of a
      component inside their shared prefix, then some *adjacent* pair in the
      run disagrees about it too — agreement between neighbours is
      transitive along the chain that joins them, and every neighbour in the
      run shares at least that prefix.

    Each adjacent pair is therefore compared for as many components as their
    folded keys agree on, and the first disagreement in spelling is the
    refusal. What is live at any moment is two paths' components and one
    string key per declared path, so the pass allocates a small multiple of
    the declared path text — the text the journal already carries — instead
    of a structure whose size is the adversary's to choose. The same 4,096
    maximum-depth paths now peak at 9.0 MB and 0.6 seconds.

    The number of distinct folded prefixes is the number of components the
    first path contributes plus, for every later path, the components below
    what it shares with its predecessor. Every component visit and every
    counted prefix charges ``work`` before folding or comparison.

    The whole-path pass runs first and completely, so a journal with both
    kinds of collision keeps the message that names the more specific one.
    """

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

    keys: list[str] = []
    for relative in relatives:
        components = relative.split("/")
        # Charged before the components are folded, so the fold work and the
        # key it builds are both inside the budget rather than beside it.
        work.charge(len(components))
        keys.append("\x00".join(_path_fold(component) for component in components))

    nodes = 0
    previous_folded: list[str] = []
    previous_spelled: list[str] = []
    for index in sorted(range(len(relatives)), key=keys.__getitem__):
        folded = keys[index].split("\x00")
        spelled = relatives[index].split("/")
        shared = 0
        limit = min(len(folded), len(previous_folded))
        while shared < limit and folded[shared] == previous_folded[shared]:
            shared += 1
        for depth in range(shared):
            if spelled[depth] != previous_spelled[depth]:
                raise CorpusError(
                    "two declared paths would alias at a directory: "
                    f"{_quoted('/'.join(previous_spelled[: depth + 1]))} and "
                    f"{_quoted('/'.join(spelled[: depth + 1]))}"
                )
        work.charge(len(folded) - shared)
        nodes += len(folded) - shared
        if nodes > MAX_ALIAS_INDEX_NODES:
            raise CorpusError(
                f"declared paths name more than {MAX_ALIAS_INDEX_NODES} "
                "distinct directories; declared paths exceed the alias index "
                "budget"
            )
        previous_folded, previous_spelled = folded, spelled
    return nodes


_REGULAR_BLOB_MODES = frozenset({"100644", "100755"})
_TREE_MODE = "040000"


def _screen_tree_listing(
    entries: Mapping[str, GitEntry],
    by_directory: Mapping[str, Mapping[str, GitEntry]],
    *,
    repertoire: str,
) -> None:
    """Validate every component and every tree directory's sibling set.

    ``TreeListing.as_dict`` has already materialized each authenticated full
    path exactly once.  Deriving local names from that flat view avoids a
    second charged path traversal through ``TreeListing.children``.
    """

    for relative in sorted(entries):
        name = relative.rpartition("/")[2]
        if repertoire == "portable":
            # The portable operation supplies the retained corpus diagnostic.
            # Ask the strict fold first so undecodable surrogateescaped tree
            # bytes are still refused as undecodable under both repertoires.
            try:
                ascii_fold_text(name)
            except NamePolicyError as exc:
                raise CorpusError(str(exc)) from exc
            _assert_portable_name(name, f"tree entry {_quoted(relative)}")
        else:
            try:
                validate_component_text(
                    name,
                    repertoire=repertoire,
                    label=f"tree entry {_quoted(relative)}",
                )
                # Folding is required under both repertoires. In particular,
                # this refuses surrogateescaped non-UTF-8 bytes before a
                # verdict could quote or fold them.
                ascii_fold_text(name)
            except NamePolicyError as exc:
                raise CorpusError(str(exc)) from exc

    directories = {""}
    directories.update(
        path for path, entry in entries.items() if entry.mode == _TREE_MODE
    )
    for directory in sorted(directories):
        names = tuple(sorted(by_directory.get(directory, {})))

        # Keep the established corpus refusal text. The shared helper still
        # runs for every directory; this pre-check only supplies the retained
        # path-rich diagnostic when the sibling pair itself is the fault.
        seen: dict[str, str] = {}
        for name in names:
            folded = _path_fold(name)
            previous = seen.get(folded)
            if previous is not None:
                raise CorpusError(
                    "directory holds two entries a case-insensitive filesystem "
                    f"would merge: {_quoted(_under(directory, previous))} and "
                    f"{_quoted(_under(directory, name))}"
                )
            seen[folded] = name
        try:
            assert_no_merging_tree_names(
                names,
                repertoire=repertoire,
                label=f"tree directory {_quoted(directory or '.')}",
            )
        except NamePolicyError as exc:
            raise CorpusError(str(exc)) from exc


def _entries_by_directory(
    entries: Mapping[str, GitEntry],
) -> dict[str, dict[str, GitEntry]]:
    """Index an authenticated flat listing by each entry's immediate parent."""

    result: dict[str, dict[str, GitEntry]] = {}
    for path, entry in entries.items():
        parent, separator, name = path.rpartition("/")
        if not separator:
            parent, name = "", path
        result.setdefault(parent, {})[name] = entry
    return result


def _assert_content_root_spellings(
    entries: Mapping[str, GitEntry],
    by_directory: Mapping[str, Mapping[str, GitEntry]],
    spec: CorpusSpec,
) -> None:
    """Retain the pinned-root alias refusal over immutable listing names."""

    for root in spec.content_roots:
        relative = root.as_posix()
        parent = ""
        for component in relative.split("/"):
            for name in sorted(by_directory.get(parent, {})):
                if name != component and _path_fold(name) == _path_fold(component):
                    raise CorpusError(
                        f"tree entry {_quoted(name)} aliases the pinned content "
                        f"root component {_quoted(component)} on a case- or "
                        "normalization-insensitive filesystem"
                    )
            exact = _under(parent, component)
            entry = entries.get(exact)
            if entry is None or entry.mode != _TREE_MODE:
                break
            parent = exact


def _content_entries_from_listing(
    entries: Mapping[str, GitEntry], spec: CorpusSpec
) -> dict[str, GitEntry]:
    """Return the exact closed-world content set from one tree listing."""

    found: dict[str, GitEntry] = {}
    for content_root in spec.content_roots:
        base_relative = content_root.as_posix()
        root_entry = entries.get(base_relative)
        if root_entry is None:
            raise CorpusError(
                f"pinned content root is absent from the tree: {base_relative}"
            )
        if root_entry.mode != _TREE_MODE:
            raise CorpusError(
                f"pinned content root is not a directory: {base_relative}"
            )

        prefix = base_relative + "/"
        for relative in sorted(entries):
            if not relative.startswith(prefix):
                continue
            entry = entries[relative]
            if entry.mode == "160000":
                raise CorpusError(
                    f"content root contains a gitlink: {_quoted(relative)}"
                )

            carries_suffix = _has_pinned_suffix(relative, spec.content_suffixes)
            if not carries_suffix:
                if (
                    spec.name_repertoire == "portable"
                    and entry.mode in _REGULAR_BLOB_MODES
                    and _short_name_carries_pinned_suffix(
                        relative.rpartition("/")[2], spec.content_suffixes
                    )
                ):
                    raise CorpusError(
                        "content root contains a file whose short-name alias "
                        "would carry a pinned suffix: "
                        f"{_quoted(relative)}"
                    )
                continue

            if entry.mode == "120000":
                raise CorpusError(
                    "content root contains a symlink where a regular file was "
                    f"recorded: {_quoted(relative)}"
                )
            if entry.mode not in _REGULAR_BLOB_MODES or entry.object_type != "blob":
                raise CorpusError(
                    f"content root contains a non-regular file: {_quoted(relative)}"
                )
            found[relative] = entry
    return found


def _assert_tombstones_absent_from_listing(
    entries: Mapping[str, GitEntry], removed: tuple[str, ...]
) -> None:
    """Ask exact and ASCII-fold indexes once whether a removed path survives."""

    folded: dict[str, str] = {}
    for path in sorted(entries):
        folded.setdefault(_path_fold(path), path)
    for path in removed:
        if path in entries:
            raise CorpusError(f"removed path is still present in the tree: {path}")
        survivor = folded.get(_path_fold(path))
        if survivor is not None:
            raise CorpusError(
                "removed path is still present in the tree under a spelling "
                "that aliases it on a case- or normalization-insensitive "
                f"filesystem: {path} ({_quoted(survivor)})"
            )


def _attested_entries_from_snapshot(
    snapshot: TreeSnapshot, attested: Mapping[str, FileBinding]
) -> dict[str, GitEntry]:
    """Resolve every attested path exactly and require a regular blob."""

    result: dict[str, GitEntry] = {}
    for path in sorted(attested):
        try:
            entry = snapshot.entry(path)
        except SnapshotError as exc:
            raise CorpusError(
                f"bound file is missing or not a regular file: {path}"
            ) from exc
        if entry.mode not in _REGULAR_BLOB_MODES or entry.object_type != "blob":
            raise CorpusError(f"bound file is not a regular file: {path}")
        result[path] = entry
    return result


def _verify_binding_digests(
    snapshot: TreeSnapshot,
    content: Mapping[str, FileBinding],
    content_entries: Mapping[str, GitEntry],
    attested: Mapping[str, FileBinding],
    attested_entries: Mapping[str, GitEntry],
) -> None:
    """Stream every authenticated bound blob once, in retained pass order."""

    ordered = [content_entries[path] for path in sorted(content)]
    ordered.extend(attested_entries[path] for path in sorted(attested))
    try:
        digests = snapshot.digests(
            ordered,
            per_blob=MAX_CONTENT_BLOB_BYTES,
            total=MAX_CONTENT_BYTES_TOTAL,
        )
        for entry, digest in digests:
            if entry.path in content:
                expected = content[entry.path].sha256
                if digest != expected:
                    raise CorpusError(
                        f"content file {_quoted(entry.path)} does not match its "
                        f"witnessed digest: tree has {digest}, journal binds "
                        f"{expected}"
                    )
            else:
                expected = attested[entry.path].sha256
                if digest != expected:
                    raise CorpusError(
                        f"attested file {_quoted(entry.path)} does not match its "
                        f"witnessed digest: tree has {digest}, journal binds "
                        f"{expected}"
                    )
    except SnapshotError as exc:
        raise CorpusError(str(exc)) from exc


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
    snapshot: TreeSnapshot,
    journal_bytes: bytes,
    *,
    spec: CorpusSpec,
) -> CorpusVerification:
    """Prove the journal describes the immutable tree selected by ``snapshot``.

    ``journal_bytes`` are the bytes already authenticated by the custody pass.
    The tree is listed once as an immutable object; membership, tombstones,
    exact attested lookups, and streamed digests are all derived from that
    object. Checkout fidelity is outside this binding claim.
    """

    if not isinstance(snapshot, TreeSnapshot):
        raise CorpusError(
            "verify_corpus_binding requires a TreeSnapshot; select one with "
            "TreeSnapshot.select"
        )

    content, attested, gates, removed = parse_journal(journal_bytes, spec=spec)

    prefix_work = _PathPrefixWork()
    _reject_aliasing_paths(list(content) + list(attested), work=prefix_work)

    try:
        listing = snapshot.entries("")
    except SnapshotError as exc:
        raise CorpusError(str(exc)) from exc
    try:
        entries = listing.as_dict(include_trees=True)
    except SnapshotError as exc:
        raise CorpusError(str(exc)) from exc

    by_directory = _entries_by_directory(entries)
    _screen_tree_listing(
        entries,
        by_directory,
        repertoire=spec.name_repertoire,
    )
    _assert_content_root_spellings(entries, by_directory, spec)
    tree = _content_entries_from_listing(entries, spec)

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

    _assert_tombstones_absent_from_listing(entries, removed)

    missing_required = sorted(spec.required_attested_paths - set(attested))
    if missing_required:
        raise CorpusError(
            "the witnessed journal does not attest a path the pinned spec "
            f"requires: {_quoted(missing_required[0])}"
        )
    attested_entries = _attested_entries_from_snapshot(snapshot, attested)

    _verify_binding_digests(
        snapshot,
        content,
        tree,
        attested,
        attested_entries,
    )

    return CorpusVerification(
        content=tuple(content[path] for path in sorted(content)),
        attested=tuple(attested[path] for path in sorted(attested)),
        gates=gates,
        removed_paths=removed,
        name_repertoire=spec.name_repertoire,
    )
