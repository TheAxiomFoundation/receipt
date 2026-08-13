"""Consumer-side corpus binding: does a witnessed journal describe THIS tree?

``receipt.release_chain`` proves custody of a journal — that the manifests are
hash-chained, canonically serialized, signed by a code-pinned producer key, and
witnessed by the consumer's configured RFC 3161 anchor set. It says nothing about
what the journal's rows *mean*.

This module supplies the missing half for a published rule corpus: the journal
rows enumerate content files by digest, and verification is a closed-world
comparison against the working tree. An unlisted file, a missing file, a
rewritten byte, a symlink where a regular file was recorded — each refuses.

Three row kinds, one journal:

``content``
    A file inside a consumer-declared content root, with a consumer-declared
    suffix. These are swept closed-world: the effective present set must equal
    the tree's set exactly, in both membership and digest.

``attested``
    An exact path bound by digest without a sweep — the toolchain pin, the
    pinned validation workflow, an apply manifest. The consumer's spec names
    which paths it *requires*, so a producer cannot quietly drop one.

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
from typing import Any

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
        return any(path.endswith(suffix) for suffix in self.content_suffixes)


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


def _reject_control_characters(value: str, label: str) -> str:
    """Refuse any C0/C1 control character or DEL in producer-supplied text.

    Every string in this schema is written by a producer and later rendered to
    a terminal. A carriage return, an ESC, or a line feed inside one lets the
    producer redraw the verdict: a witnessed "reason" carrying
    ``\\x1b[2K\\r  VERDICT: PASS`` overwrites the line that was about to say the
    gate did not run. The verdict is the product here, so the sanitising
    belongs at the schema boundary where the text enters, not only at the
    point where it is printed. (Found by cross-family review.)
    """

    for character in value:
        code = ord(character)
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            raise CorpusError(
                f"{label} contains a control character ({code:#04x}): {value!r}"
            )
    return value


def _validate_relative_path(value: Any, label: str) -> str:
    """Reject anything that could escape the root or alias another entry."""

    if type(value) is not str or not value:
        raise CorpusError(f"{label} must be a non-empty string")
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
            raise CorpusError(f"journal row has duplicate key {key!r}")
        result[key] = value
    return result


def _validate_gate(row: dict[str, Any], number: int, spec: CorpusSpec) -> GateDeclaration:
    gate_id = _string(row["gateId"], f"journal row {number} gateId")
    if GATE_ID_RE.fullmatch(gate_id) is None:
        raise CorpusError(f"journal row {number} gateId is malformed: {gate_id!r}")
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
        _reject_control_characters(
            key, f"journal row {number} gate {gate_id!r} evidence key"
        )
        _reject_control_characters(
            value, f"journal row {number} gate {gate_id!r} evidence value {key!r}"
        )
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
    history. A ``removed`` row drops the path from the present view.
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


def _path_fold(relative: str) -> str:
    """A filesystem-insensitivity-proof key for a relative path.

    NFC folds NFD/NFC spellings of the same characters together; casefold folds
    case together. Two distinct declared paths sharing a fold key would alias on
    some real filesystem, so the fold key is what closed-world uniqueness is
    checked over.
    """

    return unicodedata.normalize("NFC", relative).casefold()


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
                if not any(
                    relative.endswith(suffix) for suffix in spec.content_suffixes
                ):
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


def _regular_file_digest(root: pathlib.Path, relative: str) -> str:
    """Hash a bound file, closing the check/open race by opening no-follow.

    Validating the path then opening it by name leaves a window in which a
    symlink is swapped in between the check and the read. Opening with
    ``O_NOFOLLOW`` on the final component (after the parent-component guard)
    removes the swap-to-symlink race, and fstat-ing the open descriptor
    confirms what was actually opened is a regular file — never a directory,
    device, or FIFO reachable by the same name. (Cross-family review finding.)
    """

    parent = _assert_no_symlinked_component(root, relative)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(parent, flags)
    except OSError as exc:
        raise CorpusError(
            f"bound file is missing or not a regular file: {relative}"
        ) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise CorpusError(f"bound file is not a regular file: {relative}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest()


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
    # Unicode NFC plus case folding — and refuse. A single legitimate path
    # never collides with itself, so this cannot false-refuse a real corpus.
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

    for path in sorted(journal_paths):
        digest = _regular_file_digest(root, path)
        if digest != content[path].sha256:
            raise CorpusError(
                f"content file {path!r} does not match its witnessed digest: "
                f"tree has {digest}, journal binds {content[path].sha256}"
            )

    missing_required = sorted(spec.required_attested_paths - set(attested))
    if missing_required:
        raise CorpusError(
            "the witnessed journal does not attest a path the pinned spec "
            f"requires: {missing_required[0]!r}"
        )
    for path in sorted(attested):
        digest = _regular_file_digest(root, path)
        if digest != attested[path].sha256:
            raise CorpusError(
                f"attested file {path!r} does not match its witnessed digest: "
                f"tree has {digest}, journal binds {attested[path].sha256}"
            )

    # Closed-world means the set proven equal to the journal must not have
    # changed while it was being proven. Re-enumerate after hashing and require
    # the identical content set: a file unlisted-and-inserted, or a bound file
    # deleted, after the first enumeration would otherwise slip past the
    # set-equality check above. (Cross-family review finding.)
    if set(_tree_content_paths(root, spec)) != tree_paths:
        raise CorpusError(
            "the content tree changed during verification; the closed-world "
            "set is not stable and the verdict is refused"
        )

    return CorpusVerification(
        content=tuple(content[path] for path in sorted(content)),
        attested=tuple(attested[path] for path in sorted(attested)),
        gates=gates,
        removed_paths=removed,
    )
