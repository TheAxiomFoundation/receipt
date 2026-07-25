"""Consumer-side corpus binding: does a witnessed journal describe THIS tree?

``receipt.release_chain`` proves custody of a journal — that the manifests are
hash-chained, canonically serialized, signed by a code-pinned producer key, and
witnessed by two independently pinned RFC 3161 anchors. It says nothing about
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
import pathlib
import re
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
    if any(character in value for character in ("\x00", "\n", "\r")):
        raise CorpusError(f"{label} contains a control character: {value!r}")
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
    if kind not in ROW_KINDS:
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
    # A waiver is the one outcome that admits a known failure. It has to name
    # the waiver set it was excused under, or "waived" is unfalsifiable.
    if outcome == WAIVED and not evidence.get("waiverSetSha256"):
        raise CorpusError(
            f"journal row {number} gate {gate_id!r} is waived without naming "
            "evidence.waiverSetSha256"
        )
    # Same principle for a gate that did not run: state why, or the
    # declaration is decoration.
    if outcome == NOT_RUN and not evidence.get("reason"):
        raise CorpusError(
            f"journal row {number} gate {gate_id!r} is declared not-run "
            "without naming evidence.reason"
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
            del target[path]
            removed.add(path)

    return content, attested, tuple(gates), tuple(sorted(removed))


def _tree_content_paths(root: pathlib.Path, spec: CorpusSpec) -> dict[str, pathlib.Path]:
    """Enumerate every regular file the spec calls content, refusing symlinks."""

    found: dict[str, pathlib.Path] = {}
    for content_root in spec.content_roots:
        base = root / content_root
        if not base.exists():
            raise CorpusError(f"pinned content root is absent from the tree: {content_root}")
        if base.is_symlink() or not base.is_dir():
            raise CorpusError(f"pinned content root is not a directory: {content_root}")
        for candidate in sorted(base.rglob("*")):
            relative = candidate.relative_to(root).as_posix()
            if candidate.is_symlink():
                # A symlink under a content root can point outside the tree;
                # refuse rather than resolve it.
                if any(relative.endswith(suffix) for suffix in spec.content_suffixes):
                    raise CorpusError(
                        f"content path is a symlink, not a regular file: {relative}"
                    )
                continue
            if not candidate.is_file():
                continue
            if not any(relative.endswith(suffix) for suffix in spec.content_suffixes):
                continue
            found[relative] = candidate
    return found


def _regular_file_digest(root: pathlib.Path, relative: str) -> str:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise CorpusError(f"bound file is missing or not a regular file: {relative}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


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

    declared_gates = {gate.gate_id for gate in gates}
    missing_gates = sorted(spec.required_gates - declared_gates)
    if missing_gates:
        raise CorpusError(
            "the witnessed journal does not declare a gate the pinned spec "
            f"requires: {missing_gates[0]!r}"
        )

    return CorpusVerification(
        content=tuple(content[path] for path in sorted(content)),
        attested=tuple(attested[path] for path in sorted(attested)),
        gates=gates,
        removed_paths=removed,
    )
