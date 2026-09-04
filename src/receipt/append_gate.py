"""Gate changes to an append-only observation ledger over immutable Git objects.

What this verdict speaks for

The subject is tree T of commit C.
Every byte comes from an object rehashed against its name.
The base, when supplied, is a second tree.
Anchors belong to the verifier, never the candidate.
The working tree is not read.
"""

from __future__ import annotations

import hashlib
import json
import locale
import pathlib
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from receipt.canonical import canonical_sha256
from receipt.corpus import MAX_JOURNAL_BYTES
from receipt.release_chain import (
    ChainSpec,
    ChainVerification,
    MANIFEST_RE,
    ReleaseChainError,
    assert_no_redirecting_git_environment,
    verify_base_release_chain,
    verify_release_chain,
    verify_release_history_immutable,
)
from receipt.snapshot import GitEntry, SnapshotError, TreeSnapshot


CODE_ROOT = pathlib.Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class AppendGateSpec:
    """Repo-specific gate constants pinned by the consuming repository."""

    chain: ChainSpec
    prefix_schema_version: str
    release_manifest_prefix: str
    genesis_support_files: frozenset[str]
    gate_surface: frozenset[str]
    data_surface: frozenset[str]
    assertion_content_keys: tuple[str, ...]


@dataclass(frozen=True)
class _CandidateTree:
    """The selected candidate snapshot and its two state paths."""

    snapshot: TreeSnapshot
    spec: AppendGateSpec
    ledger_relative: str
    prefix_relative: str


@dataclass(frozen=True)
class _BaseCommit:
    """The entered base snapshot, resolved once for the whole verdict."""

    ref: str
    commit: str
    tree: TreeSnapshot


@dataclass(frozen=True)
class AppendGateVerdict:
    """The append result together with the immutable objects it names."""

    summary: str
    candidate_commit: str
    candidate_tree: str
    base_commit: str | None
    base_tree: str | None
    object_format: str
    name_repertoire: str


class AppendError(ValueError):
    """The proposed ledger change violates an append invariant."""


def _assert_release_paths_are_subdirectories(spec: AppendGateSpec) -> None:
    """Refuse a spec whose release paths name the candidate root itself.

    ``PurePosixPath('.')`` and the empty path both report no components at
    all, and a release root spelled either way is the candidate root. Nothing
    here can speak for such a spec, because this gate's own reads disagree
    about what is inside it. ``git ls-tree`` names the entries under ``.``
    without any prefix — ``a/f.txt``, not ``./a/f.txt``, checked on the git
    this repository is verified with — so ``git_tree_entries`` refuses the
    first of them as a path outside the root it asked about, and the base
    enumeration the release-history pass is built on never returns. From the
    other side, ``check_gate_only_confinement`` asks whether a changed path is
    ``.`` or begins with ``./`` and finds nothing inside the release root at
    all, so the confinement a gate-only verdict rests on is silently a no-op;
    and ``hold_release_root`` has no component to walk or hold.

    So it is refused here, at the gate's entry, rather than left to whichever
    of those the run reaches first. ``ChainSpec`` refuses both spellings at
    construction as well (spec validation, #41), so a spec built through its
    constructor never reaches this check; it is kept because it is the gate's
    own statement about the configuration it was handed, whatever built it —
    like the platform refusals below it, the gate declining to answer.
    """

    for label, relative in (
        ("release root", spec.chain.release_root_relative),
        ("release manifest path", spec.chain.manifest_relative),
        ("release anchor path", spec.chain.anchor_relative),
    ):
        if not relative.parts:
            raise AppendError(f"{label} must be a subdirectory of the candidate root")


def _matches_surface(path: str, surface: frozenset[str]) -> bool:
    for pattern in surface:
        if pattern.endswith("/**"):
            if path.startswith(pattern[:-2]):
                return True
        elif path == pattern:
            return True
    return False


def _classify_surfaces(
    changed: set[str], candidate: _CandidateTree
) -> tuple[set[str], set[str], set[str]]:
    """Split one changed set into DATA, GATE, and everything else.

    Classification is per path, so classifying a union is the same as taking
    the union of the classifications — which is how the gate-only decision
    below folds the index's changed set into the working tree's.
    """

    data_changes = {
        path for path in changed if _matches_surface(path, candidate.spec.data_surface)
    }
    gate_changes = {
        path for path in changed if _matches_surface(path, candidate.spec.gate_surface)
    }
    return data_changes, gate_changes, changed - data_changes - gate_changes


def _release_root_ancestors(candidate: _CandidateTree) -> tuple[str, ...]:
    """Every proper ancestor of the configured release root, shallowest first.

    ``data`` for a root of ``data/releases``; nothing at all for a root of one
    component, which is every consumer's. The candidate root itself is not
    among them: it is the tree, not a path inside it, and a change is always
    at some path under it.
    """

    parts = candidate.spec.chain.release_root_relative.parts
    return tuple("/".join(parts[:depth]) for depth in range(1, len(parts)))


def _is_protected(path: str, candidate: _CandidateTree) -> bool:
    """Whether one path lies on a surface this verdict speaks for.

    The two surfaces the spec names, plus the release root and everything
    under it, which is neither but is read by the release verification all the
    same and is the one place ``check_gate_only_confinement`` refuses an
    unclassified change.

    And the release root's own ancestors, which are on that surface for the
    reason the root is: the root's existence as a real directory is the
    premise of every check made about the release tree, and a path above it
    decides that premise. With a root of ``data/releases``, replacing ``data``
    with a regular file or with a link to a tree outside the checkout changes
    what ``data/releases`` is or where it lives, while ``data`` itself matched
    no surface pattern, was not the root and was not under it — so it
    classified as an ordinary unclassified change, and a proposal carrying it
    beside a gate file was told ``DATA_SURFACE unchanged`` with the release
    root's own walk, the enumeration and the index scan all skipped. A change
    there is a change on the release surface, and a proposal making one is not
    gate-only.
    """

    release_root = candidate.spec.chain.release_root_relative.as_posix()
    return (
        _matches_surface(path, candidate.spec.data_surface)
        or _matches_surface(path, candidate.spec.gate_surface)
        or path == release_root
        or path.startswith(f"{release_root}/")
        or path in _release_root_ancestors(candidate)
    )


def check_surface_separation(
    base: _BaseCommit, candidate: _CandidateTree
) -> tuple[set[str], set[str], set[str]]:
    """Classify authenticated candidate-tree changes against the base tree."""

    changed = candidate.snapshot.changed_paths(base.tree)
    data_changes, gate_changes, unclassified = _classify_surfaces(changed, candidate)
    if data_changes and gate_changes:
        raise AppendError(
            "mixed data/gate proposal is forbidden: DATA_SURFACE changes="
            f"{sorted(data_changes)}; GATE_SURFACE changes="
            f"{sorted(gate_changes)}; split them into separate pull requests"
        )
    return data_changes, gate_changes, unclassified


def check_gate_only_confinement(
    unclassified: set[str], candidate: _CandidateTree
) -> set[str]:
    """Confine a gate-only proposal to the surfaces its verdict speaks for.

    A gate-only verdict returns before the ledger is read, so the frozen
    prefix, the append-only diff, the row bindings, and the release history
    are all skipped. Surface classification never checked that DATA and GATE
    covered the changed set, so a proposal that added a gate file AND
    rewrote an unclassified file under the release root — say
    ``releases/README.md`` — was accepted with none of those checks run.
    An unclassified change on the release surface
    is refused here; the rest are returned for the
    caller to name in its success text, so an unclassified change riding a
    gate-only proposal is never silent.

    The surface is ``_is_protected``'s, which is the release root, everything
    under it, and every proper ancestor of it. The last is what a nested root
    needs: with ``data/releases`` configured, a proposal replacing ``data``
    changes what the release root is — or moves it outside the checkout
    entirely — while ``data`` is at the root and under it, and so was named in
    the success text as an ordinary unclassified change beside ``DATA_SURFACE
    unchanged``. An unclassified change everywhere else is still reported
    rather than refused, because everywhere else is ground this verdict makes
    no claim about; on the release surface the verdict claims exactly this
    confinement. The two surfaces the spec names cannot appear here at all —
    a path matching either is classified, not unclassified — so the set this
    refuses is the release root, its subtree, and its ancestors, which is what
    the sentence names.
    """

    on_the_release_surface = sorted(
        path for path in unclassified if _is_protected(path, candidate)
    )
    if on_the_release_surface:
        raise AppendError(
            "gate-only proposal changes unclassified release path(s): "
            f"{on_the_release_surface}"
        )
    return set(unclassified)


def _as_text(payload: bytes, encoding: str | None = None) -> str:
    """Decode snapshot bytes exactly as ``Path.read_text`` decoded them.

    The snapshot reader replaced two ``read_text`` calls, and this port's
    refusals are compared with the upstream oracle's byte for byte, so the
    decoding those calls performed is reproduced rather than approximated:
    the caller's encoding or, where the call passed none, the same locale
    default ``open`` would have used, and the universal-newline translation
    text mode applies to a whole file (``\r\n`` and a lone ``\r`` both
    become ``\n``).
    """

    decoded = payload.decode(encoding or locale.getpreferredencoding(False))
    return decoded.replace("\r\n", "\n").replace("\r", "\n")


def _lines(text: str) -> list[str]:
    return [line for line in text.split("\n") if line.strip()]


def reject_non_append_bytes(text: str) -> None:
    """Reject blank/whitespace-only lines and any non-single trailing newline.

    ``_lines`` drops blank lines so row parsing is convenient, but that means a
    blank line inserted into the frozen JSONL would normalize away and pass both
    the prefix hash and the append-only diff. A JSONL row is exactly one
    non-empty line: a blank/whitespace-only line inside the covered region is a
    byte tamper, and the file must end with exactly one trailing newline.
    """
    parts = text.split("\n")
    if parts[-1] != "":
        raise AppendError("ledger must end with exactly one trailing newline")
    for index, part in enumerate(parts[:-1], start=1):
        if not part.strip():
            raise AppendError(
                f"line {index} is blank or whitespace-only; a JSONL row is one "
                "non-empty line and a stray blank line is a tamper"
            )


def expected_assertion_version_id(row: dict[str, Any], spec: AppendGateSpec) -> str:
    """Recompute the content address the resolver must have written.

    Mirrors ``assertion_version`` in the Thesis resolver (av1 v2 spec): the ID
    commits to everything that changes what the assertion MEANS — identity,
    value, timing, population, the complete measure concept mapping, exact
    source lineage/digest, row/cell lineage, and the archived response digest —
    so an in-place edit is detectable and a correction must supersede
    explicitly. This projection must stay byte-identical to the Brier writer's
    ``assertion_version`` (both fed to the shared ``canonical_sha256``), so any
    change here is a coordinated schema migration on both sides.
    """
    measure = row.get("measure") or {}
    source = row.get("source") or {}
    projection = {key: row.get(key) for key in spec.assertion_content_keys}
    projection["measure"] = {
        "concept": measure.get("concept"),
        "unit": measure.get("unit"),
        "source_concept": measure.get("source_concept"),
        "concept_relation": measure.get("concept_relation"),
        "concept_authority": measure.get("concept_authority"),
        "legal_vintage": measure.get("legal_vintage"),
    }
    projection["source"] = {
        "source_name": source.get("source_name"),
        "source_table": source.get("source_table"),
        "source_file": source.get("source_file"),
        "url": source.get("url"),
        "vintage": source.get("vintage"),
        "source_sha256": source.get("source_sha256"),
    }
    projection["lineage"] = {
        "source_row_keys": row.get("source_row_keys"),
        "source_cell_keys": row.get("source_cell_keys"),
    }
    projection["responseArchiveSha256"] = (row.get("responseArchive") or {}).get(
        "sha256"
    )
    return f"av2:{canonical_sha256(projection)}"


def _effective_assertion_id(row: dict[str, Any], spec: AppendGateSpec) -> str:
    """Return the row's effective assertion version ID.

    Post-cutover rows carry an explicit ``assertionVersion.id`` (validated
    against the recomputed content address in :func:`check_rows`); legacy
    pre-versioning rows are addressable by their recomputed content address.
    Either way every row has exactly one effective ID that a correction must
    name and that no later row may reissue.
    """
    version = row.get("assertionVersion")
    if isinstance(version, dict) and version.get("id"):
        return str(version["id"])
    return expected_assertion_version_id(row, spec)


def effective_current_rows(
    rows: list[dict[str, Any]], spec: AppendGateSpec
) -> list[dict[str, Any]]:
    """Return the latest non-superseded row per assertion identity.

    A correction names the version it replaces via
    ``assertionVersion.supersedes``; the replaced row drops out of the current
    view. Aggregate-fact validation runs on this supersede-aware view so a
    legitimate correction (same semantic key, new value) is not mistaken for a
    duplicate key.
    """
    superseded: set[str] = set()
    for row in rows:
        version = row.get("assertionVersion")
        if isinstance(version, dict) and version.get("supersedes"):
            superseded.add(str(version["supersedes"]))
    return [row for row in rows if _effective_assertion_id(row, spec) not in superseded]


def check_prefix(
    lines: list[str], prefix_text: str, candidate: _CandidateTree
) -> dict[str, Any]:
    # The manifest text comes from the caller's one snapshot read of the
    # prefix path, taken where this function used to walk and read it, so the
    # refusals below fire in exactly the order they always did.
    prefix = json.loads(prefix_text)
    if prefix.get("schemaVersion") != candidate.spec.prefix_schema_version:
        raise AppendError(
            f"unsupported prefix manifest schema {prefix.get('schemaVersion')!r}"
        )
    count = int(prefix["prefixLineCount"])
    hashes = prefix["lineSha256s"]
    if len(hashes) != count:
        raise AppendError("prefix manifest line hashes disagree with its count")
    if len(lines) < count:
        raise AppendError(
            f"ledger has {len(lines)} rows but the immutable prefix "
            f"requires at least {count}"
        )
    for index in range(count):
        digest = hashlib.sha256(lines[index].encode("utf-8")).hexdigest()
        if digest != hashes[index]:
            row_id = json.loads(lines[index]).get("source_record_id", "?")
            raise AppendError(
                f"immutable prefix line {index + 1} ({row_id}) was rewritten"
            )
    joined = hashlib.sha256(
        ("\n".join(lines[:count]) + "\n").encode("utf-8")
    ).hexdigest()
    if joined != prefix["prefixSha256"]:
        raise AppendError("immutable prefix cumulative hash mismatch")
    return prefix


def _is_canonical_rfc3339(value: Any) -> bool:
    """Accept exactly the canonical RFC 3339 profile the ledger writer emits.

    Narrower than RFC 3339 on purpose, and stated so: uppercase ``T`` and
    ``Z``, an offset only as ``±HH:MM`` with bounded fields, an optional
    fraction, and no leap second (``:60``). The lowercase ``t``/``z`` forms
    and leap seconds the RFC permits are refused as outside the profile
    (peer review, round three). ``datetime.fromisoformat`` alone accepts a
    wider grammar — a bare date, a space separator, a missing offset — and a
    naive timestamp cannot be ordered against a witnessed genTime at all. So
    the shape is pinned by pattern first and the calendar values are then
    checked by the parser, which is what rejects a February 30th that
    matches the pattern. The offset's hour and minute are bounded in the
    pattern as well, because the parser does not refuse an overflowing
    offset: ``+01:60`` is normalised to ``+02:00`` and accepted (round one).
    """

    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
        r"(?:\.[0-9]+)?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
        value,
    ):
        return False
    try:
        return datetime.fromisoformat(value).tzinfo is not None
    except ValueError:
        return False


def check_rows(lines: list[str], prefix_count: int, spec: AppendGateSpec) -> None:
    """Validate every row, and the post-cutover bindings on appended rows.

    The binding values were checked for presence alone, so a response digest
    of ``"x"``, a ``ledgerRepoSha`` of ``"HEAD"``, and a ``retrievedAt`` of
    ``"yesterday"`` each satisfied a contract the row's custody claim rests
    on. Their shapes are validated by check_binding_shapes, which the gate
    runs after every check that existed before it; this function is the
    ported row validation, unchanged. What any of the values MEANS is
    untouched either way. In particular the ``assertionVersion`` projection
    stays exactly as it is — it must remain byte-identical to the Brier
    writer's, so changing it is a coordinated schema migration on both
    sides, not a gate fix.
    """

    versions: dict[str, int] = {}
    active_by_record_id: dict[str, tuple[int, str | None]] = {}
    for number, line in enumerate(lines, start=1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AppendError(f"line {number} is not valid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise AppendError(f"line {number} is not a JSON object")
        record_id = row.get("source_record_id")
        if not record_id:
            raise AppendError(f"line {number} lacks source_record_id")
        if not isinstance(row.get("value"), (int, float)):
            raise AppendError(f"line {number} ({record_id}) has no numeric value")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(row.get("observed_at", ""))):
            raise AppendError(f"line {number} ({record_id}) has no observed_at date")
        unit = (row.get("measure") or {}).get("unit")
        if not unit:
            raise AppendError(f"line {number} ({record_id}) has no measure unit")

        recomputed = expected_assertion_version_id(row, spec)
        version = row.get("assertionVersion")
        supersedes = None
        if version is not None:
            if not isinstance(version, dict):
                raise AppendError(f"line {number} assertionVersion is not an object")
            version_id = str(version.get("id", ""))
            supersedes = version.get("supersedes")
            if version_id != recomputed:
                raise AppendError(
                    f"line {number} ({record_id}) assertionVersion.id does not "
                    f"match its content ({version_id} != {recomputed})"
                )
            effective_id = version_id
        else:
            # Pre-versioning rows are addressable by their recomputed content
            # address; that ID is reserved just like an explicit one so a legacy
            # synthetic ID cannot be silently reissued.
            effective_id = recomputed

        # Reserve the effective ID of EVERY row. A collision means two rows
        # claim the same assertion version — a duplicate legacy ID or an
        # A->B->A chain trying to restore a superseded value.
        if effective_id in versions:
            raise AppendError(
                f"line {number} restates assertion version {effective_id} "
                f"from line {versions[effective_id]}"
            )
        versions[effective_id] = number

        if number > prefix_count:
            for field in (
                "retrievedAt",
                "sourceVintage",
                "ledgerRepoSha",
                "responseArchive",
                "assertionVersion",
            ):
                if not row.get(field):
                    raise AppendError(
                        f"appended line {number} ({record_id}) lacks {field}"
                    )
            archive = row["responseArchive"]
            if not isinstance(archive, dict) or not archive.get("sha256"):
                raise AppendError(
                    f"appended line {number} responseArchive lacks a digest"
                )
            # Key PRESENCE pairs the binding, and present values must be
            # shape-valid: truthiness accepted targetContentHash "" with a
            # missing (or {}) projection, silently waiving the contract
            # binding (found during the extraction review).
            has_hash = "targetContentHash" in row
            has_projection = "sourceBindingProjection" in row
            if has_hash != has_projection:
                raise AppendError(
                    f"appended line {number} ({record_id}) must carry "
                    "targetContentHash and sourceBindingProjection together"
                )
            if has_hash:
                content_hash = row["targetContentHash"]
                if not isinstance(content_hash, str) or not re.fullmatch(
                    r"[0-9a-f]{64}", content_hash
                ):
                    raise AppendError(
                        f"appended line {number} ({record_id}) "
                        "targetContentHash is not a SHA-256 hex digest"
                    )
                projection = row["sourceBindingProjection"]
                if not isinstance(projection, dict) or not projection:
                    raise AppendError(
                        f"appended line {number} ({record_id}) "
                        "sourceBindingProjection must be a non-empty object"
                    )
                if projection.get("responseSha256") != archive.get("sha256"):
                    raise AppendError(
                        f"appended line {number} projection digest does not "
                        "match its archived response"
                    )
                if projection.get("unit") != unit:
                    raise AppendError(
                        f"appended line {number} projection unit "
                        f"{projection.get('unit')!r} contradicts the row unit "
                        f"{unit!r}"
                    )

        previous = active_by_record_id.get(str(record_id))
        if previous is not None:
            previous_line, previous_version = previous
            if supersedes is None:
                raise AppendError(
                    f"line {number} duplicates {record_id} (line "
                    f"{previous_line}) without superseding an assertion "
                    "version — corrections must be explicit"
                )
            if supersedes != previous_version:
                raise AppendError(
                    f"line {number} supersedes {supersedes} but the active "
                    f"version of {record_id} is {previous_version}"
                )
        elif supersedes is not None:
            raise AppendError(
                f"line {number} supersedes {supersedes} but {record_id} has "
                "no earlier row"
            )
        active_by_record_id[str(record_id)] = (number, effective_id)


def check_append_only(
    base: _BaseCommit, lines: list[str], candidate: _CandidateTree
) -> int:
    entry = base.tree.entry(candidate.ledger_relative)
    base_text = _as_text(base.tree.blob(entry, limit=MAX_JOURNAL_BYTES))
    base_lines = _lines(base_text)
    if len(lines) < len(base_lines):
        raise AppendError(
            f"change truncates the ledger: {len(base_lines)} -> {len(lines)} rows"
        )
    for index, line in enumerate(base_lines):
        if lines[index] != line:
            row_id = json.loads(line).get("source_record_id", "?")
            raise AppendError(
                f"change rewrites existing line {index + 1} ({row_id}); "
                "the ledger is append-only — supersede instead"
            )
    return len(lines) - len(base_lines)


def check_prefix_anchored_to_base(
    base: _BaseCommit,
    candidate_prefix: dict[str, Any],
    candidate: _CandidateTree,
) -> int:
    """Require the frozen prefix manifest to be unchanged from the base.

    The immutable-prefix manifest lives beside the ledger and is candidate-
    controlled, so a PR could grow ``prefixLineCount`` over its own append and
    have every post-cutover binding skipped (the appended row would count as
    "prefix"). Growing the frozen prefix is an explicit, separately reviewed
    migration — never part of the automated append path — so under a base ref
    the count, cumulative hash, and per-line hashes must match the base exactly.
    Returns the BASE prefix line count, which callers use as the post-cutover
    binding boundary so a candidate-controlled count can never move it.
    """
    entry = base.tree.entry(candidate.prefix_relative)
    base_prefix = json.loads(_as_text(base.tree.blob(entry, limit=MAX_JOURNAL_BYTES)))
    for field in ("prefixLineCount", "prefixSha256", "lineSha256s"):
        if candidate_prefix.get(field) != base_prefix.get(field):
            raise AppendError(
                f"immutable prefix manifest {field} changed vs base {base.ref}; "
                "the frozen prefix cannot grow through the automated append path "
                "— growing it is an explicit reviewed migration"
            )
    return int(base_prefix["prefixLineCount"])


def check_binding_shapes(lines: list[str], prefix_count: int) -> None:
    """Require the post-cutover binding values to have the shape they claim.

    Presence alone was the whole check on these three. The digest is what
    binds the row to an archived response, the repo sha is what binds it to
    the code that produced it, and retrievedAt is what any chronology claim
    about the row is measured from — a placeholder in any of them satisfied
    the contract while binding nothing.

    Runs after every check that existed before it — row validation, the
    release proposal, the release history — so no pre-existing file-level
    refusal is pre-empted for an input that violates both. Two review rounds
    moved it here: first from ahead of the projection and supersession
    checks, then from ahead of the release checks. The one refusal that does
    run ahead of the pre-existing release checks is the checkout-level one
    in release_chain.assert_file_modes_authoritative, deliberately: a
    checkout that cannot be verified says so before any verdict about its
    files. The rows were parsed and validated by check_rows already, so the
    loads below cannot fail.
    """

    for number, line in enumerate(lines, start=1):
        if number <= prefix_count:
            continue
        row = json.loads(line)
        record_id = row.get("source_record_id")
        digest = row["responseArchive"]["sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise AppendError(
                f"appended line {number} ({record_id}) "
                "responseArchive.sha256 is not a SHA-256 hex digest"
            )
        repo_sha = row["ledgerRepoSha"]
        if not isinstance(repo_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", repo_sha):
            raise AppendError(
                f"appended line {number} ({record_id}) ledgerRepoSha is "
                "not a full 40-character commit id"
            )
        if not _is_canonical_rfc3339(row["retrievedAt"]):
            raise AppendError(
                f"appended line {number} ({record_id}) retrievedAt is not "
                "a canonical RFC 3339 timestamp (uppercase T and Z or "
                "±HH:MM, no leap second)"
            )


def check_state_modes(
    base: _BaseCommit,
    candidate: _CandidateTree,
    *,
    entries: Mapping[str, GitEntry] | None = None,
) -> None:
    """Require both selected state entries to retain their base modes."""

    selected = entries or {}
    for relative in (
        candidate.spec.chain.state_relative,
        candidate.spec.chain.prefix_relative,
    ):
        path = relative.as_posix()
        candidate_entry = selected.get(path) or candidate.snapshot.entry(path)
        base_entry = base.tree.entry(path)
        if candidate_entry.mode != base_entry.mode:
            raise AppendError(f"state file mode changed relative to base: {path}")


def _release_triple(
    new_files: set[str],
    expected_index: int,
    *,
    candidate: _CandidateTree,
    allowed_support_files: set[str] | None = None,
) -> pathlib.PurePosixPath:
    """Require exactly one manifest, producer signature, and two receipts."""

    manifest_files = [
        relative
        for relative in new_files
        if relative.startswith(candidate.spec.release_manifest_prefix)
        and MANIFEST_RE.fullmatch(pathlib.PurePosixPath(relative).name)
    ]
    if len(manifest_files) != 1:
        raise AppendError(
            f"release proposal must add exactly one manifest for index "
            f"{expected_index}; found {sorted(manifest_files)}"
        )
    manifest_relative = manifest_files[0]
    manifest_name = pathlib.PurePosixPath(manifest_relative).name
    match = MANIFEST_RE.fullmatch(manifest_name)
    assert match is not None
    if int(match.group("index")) != expected_index:
        raise AppendError(
            f"release proposal index must be {expected_index}, not "
            f"{int(match.group('index'))}"
        )
    stem = pathlib.PurePosixPath(manifest_name).stem
    expected = {
        manifest_relative,
        *(
            f"{candidate.spec.release_manifest_prefix}{stem}.{tsa}.tsr"
            for tsa in candidate.spec.chain.anchors
        ),
        f"{candidate.spec.release_manifest_prefix}{stem}.producer.sig",
    }
    allowed = expected | (allowed_support_files or set())
    if new_files != expected and not (expected <= new_files and new_files <= allowed):
        raise AppendError(
            "release proposal must add its manifest, producer signature, and "
            f"exactly the {' and '.join(candidate.spec.chain.anchors)} receipts "
            "with no other releases/ changes; "
            f"missing={sorted(expected - new_files)}, "
            f"extra={sorted(new_files - allowed)}"
        )
    return pathlib.PurePosixPath(manifest_relative)


def _base_ledger_bytes(base: _BaseCommit, candidate: _CandidateTree) -> bytes:
    entry = base.tree.entry(candidate.ledger_relative)
    return base.tree.blob(
        entry,
        limit=MAX_JOURNAL_BYTES,
    )


def _check_exact_byte_append(base_bytes: bytes, candidate_bytes: bytes) -> bytes:
    if not candidate_bytes.startswith(base_bytes):
        raise AppendError(
            "change is not an exact byte append to the base JSONL; existing "
            "bytes, including line endings, are immutable"
        )
    return candidate_bytes[len(base_bytes) :]


def _state_snapshot_bytes(
    candidate: _CandidateTree, ledger_bytes: bytes, prefix_bytes: bytes
) -> dict[str, bytes]:
    """The two state snapshots, keyed the way ``release_chain`` reads them.

    The release verification used to open the ledger and the frozen prefix
    by name, which is a second read of each file inside one verdict: an
    A-to-B-to-A replacement showed the row checks one ledger, the release
    chain another, and put the first back before the closing re-read. Handing
    it these bytes means there is only ever one read of each file per run.
    """

    return {
        candidate.spec.chain.state_relative.as_posix(): ledger_bytes,
        candidate.spec.chain.prefix_relative.as_posix(): prefix_bytes,
    }


def _read_state_blob(
    candidate: _CandidateTree,
    relative: pathlib.PurePosixPath,
) -> tuple[GitEntry, bytes]:
    """Read one regular state blob from the selected candidate tree."""

    display = relative.as_posix()
    try:
        entry = candidate.snapshot.entry(display)
    except SnapshotError as exc:
        if str(exc) == f"tree entry does not exist: {display}":
            raise AppendError(
                f"state file is missing or not a regular file: {display}"
            ) from exc
        raise
    if entry.mode == "120000":
        raise AppendError(f"state file is a symlink: {display}")
    if entry.mode not in {"100644", "100755"}:
        raise AppendError(f"state file is not a regular file: {display}")
    return entry, candidate.snapshot.blob(entry, limit=MAX_JOURNAL_BYTES)


def _materialization_prefixes(
    candidate: _CandidateTree,
) -> tuple[pathlib.PurePosixPath, ...]:
    chain = candidate.spec.chain
    return (
        chain.release_root_relative,
        chain.manifest_relative,
        chain.state_relative,
        chain.prefix_relative,
    )


def _candidate_release_entries_regular(candidate: _CandidateTree) -> None:
    """Preserve the release-leaf shape refusals on the push path."""

    release_root = candidate.spec.chain.release_root_relative.as_posix()
    for relative, entry in sorted(
        candidate.snapshot.entries(release_root).as_dict().items()
    ):
        if entry.mode == "120000":
            raise AppendError(f"release path is a symlink: {relative}")
        if entry.mode not in {"100644", "100755"}:
            raise AppendError(f"release path is not regular: {relative}")


def _screen_candidate_materialization(candidate: _CandidateTree) -> None:
    """Rehash and attribute-screen protected candidate blobs without a chain."""

    _candidate_release_entries_regular(candidate)
    with tempfile.TemporaryDirectory(prefix="receipt-append-candidate-") as directory:
        with candidate.snapshot.materialize(
            _materialization_prefixes(candidate),
            pathlib.Path(directory),
            repertoire=candidate.spec.chain.name_repertoire,
        ) as materialized:
            candidate.snapshot.refuse_transforming_attributes(
                materialized.entries.values()
            )


def _verify_candidate_release_chain(
    *,
    candidate: _CandidateTree,
    ledger_bytes: bytes,
    prefix_bytes: bytes,
    anchor_dir: pathlib.Path,
    enforce_production_pins: bool,
) -> ChainVerification:
    """Verify the selected candidate chain through a private materialization."""

    _candidate_release_entries_regular(candidate)
    with tempfile.TemporaryDirectory(prefix="receipt-append-candidate-") as directory:
        with candidate.snapshot.materialize(
            _materialization_prefixes(candidate),
            pathlib.Path(directory),
            repertoire=candidate.spec.chain.name_repertoire,
        ) as materialized:
            candidate.snapshot.refuse_transforming_attributes(
                materialized.entries.values()
            )
            return verify_release_chain(
                materialized.path,
                spec=candidate.spec.chain,
                anchor_dir=anchor_dir,
                require_chain=True,
                verify_state=True,
                enforce_production_pins=enforce_production_pins,
                state_bytes=_state_snapshot_bytes(
                    candidate,
                    ledger_bytes,
                    prefix_bytes,
                ),
            )


def _base_anchors_match_trusted(
    base: _BaseCommit,
    *,
    spec: ChainSpec,
    anchor_dir: pathlib.Path,
) -> bool:
    """Whether Lane C's base helper would consume the caller's trusted bytes.

    Lane C's helper has no anchor-directory parameter and therefore verifies
    the base with its committed anchor copies. Use it only when those bytes
    equal the caller-owned anchors; otherwise the local fallback below keeps
    the append gate's pre-existing trust boundary.
    """

    filenames = (
        spec.producer_public_key_filename,
        *(anchor.filename for anchor in spec.anchors.values()),
    )
    for filename in filenames:
        relative = (spec.anchor_relative / pathlib.PurePosixPath(filename)).as_posix()
        try:
            entry = base.tree.entry(relative)
            committed = base.tree.blob(entry, limit=MAX_JOURNAL_BYTES)
            trusted = (anchor_dir / filename).read_bytes()
        except (OSError, SnapshotError, TypeError, ValueError):
            return False
        if committed != trusted:
            return False
    return True


def _verify_base_chain(
    base: _BaseCommit,
    *,
    candidate: _CandidateTree,
    anchor_dir: pathlib.Path,
    enforce_production_pins: bool,
) -> ChainVerification:
    """Verify the selected base, preserving the gate's trusted-anchor split."""

    if _base_anchors_match_trusted(
        base,
        spec=candidate.spec.chain,
        anchor_dir=anchor_dir,
    ):
        return verify_base_release_chain(candidate.spec.chain, base=base.tree)

    # Integration workaround: verify_base_release_chain currently has no
    # trusted-anchor override. Materialize the same selected base objects but
    # retain the append gate's caller-owned anchor directory.
    with tempfile.TemporaryDirectory(prefix="receipt-append-base-") as directory:
        with base.tree.materialize(
            _materialization_prefixes(candidate),
            pathlib.Path(directory),
            repertoire=candidate.spec.chain.name_repertoire,
        ) as materialized:
            return verify_release_chain(
                materialized.path,
                spec=candidate.spec.chain,
                anchor_dir=anchor_dir,
                require_chain=True,
                verify_state=True,
                enforce_production_pins=enforce_production_pins,
            )


def check_release_proposal(
    base: _BaseCommit,
    *,
    candidate: _CandidateTree,
    ledger_bytes: bytes,
    prefix_bytes: bytes,
    anchor_dir: pathlib.Path,
    enforce_production_pins: bool,
) -> int | None:
    """Verify base custody and the one transition the candidate may add."""

    try:
        _commit, new_files, base_release_entries = verify_release_history_immutable(
            candidate.spec.chain,
            candidate=candidate.snapshot,
            base=base.tree,
        )
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc

    base_has_chain = any(
        relative.startswith(candidate.spec.release_manifest_prefix)
        for relative in base_release_entries
    )
    candidate_has_chain = bool(
        candidate.snapshot.entries(candidate.spec.chain.manifest_relative.as_posix())
    )
    base_bytes = _base_ledger_bytes(base, candidate)
    appended_bytes = _check_exact_byte_append(base_bytes, ledger_bytes)
    ledger_changed = bool(appended_bytes)

    if not base_has_chain:
        if not candidate_has_chain:
            if new_files:
                raise AppendError(
                    "legacy pre-genesis proposal must not change releases/; "
                    "add a complete genesis manifest, producer signature, and "
                    "both receipts or no release files at all "
                    f"(changed={sorted(new_files)})"
                )
            _screen_candidate_materialization(candidate)
            return None
        _release_triple(
            new_files,
            0,
            candidate=candidate,
            allowed_support_files=set(candidate.spec.genesis_support_files),
        )
        try:
            verification = _verify_candidate_release_chain(
                candidate=candidate,
                ledger_bytes=ledger_bytes,
                prefix_bytes=prefix_bytes,
                anchor_dir=anchor_dir,
                enforce_production_pins=enforce_production_pins,
            )
        except ReleaseChainError as exc:
            raise AppendError(str(exc)) from exc
        if len(verification.releases) != 1:
            raise AppendError(
                "genesis proposal must create exactly one release at index 0"
            )
        return 0

    try:
        base_verification = _verify_base_chain(
            base,
            candidate=candidate,
            anchor_dir=anchor_dir,
            enforce_production_pins=enforce_production_pins,
        )
    except ReleaseChainError as exc:
        raise AppendError(f"base release chain is invalid: {exc}") from exc
    assert base_verification.head is not None
    expected_index = base_verification.head.release_index + 1

    if ledger_changed:
        _release_triple(new_files, expected_index, candidate=candidate)
    elif new_files:
        raise AppendError(
            "release-only proposal is forbidden after genesis; a next release "
            "must witness an actual ledger byte append"
        )

    try:
        candidate_verification = _verify_candidate_release_chain(
            candidate=candidate,
            ledger_bytes=ledger_bytes,
            prefix_bytes=prefix_bytes,
            anchor_dir=anchor_dir,
            enforce_production_pins=enforce_production_pins,
        )
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc
    expected_length = len(base_verification.releases) + (1 if ledger_changed else 0)
    if len(candidate_verification.releases) != expected_length:
        raise AppendError(
            f"release chain length must be {expected_length} for this proposal; "
            f"found {len(candidate_verification.releases)}"
        )
    assert candidate_verification.head is not None
    return candidate_verification.head.release_index


def check_release_chain_without_base(
    *,
    candidate: _CandidateTree,
    ledger_bytes: bytes,
    prefix_bytes: bytes,
    anchor_dir: pathlib.Path,
    enforce_production_pins: bool,
) -> int | None:
    """Verify an initialized chain from the selected pushed commit."""

    initialized = bool(
        candidate.snapshot.entries(candidate.spec.chain.manifest_relative.as_posix())
    )
    if not initialized:
        _screen_candidate_materialization(candidate)
        return None
    try:
        verification = _verify_candidate_release_chain(
            candidate=candidate,
            ledger_bytes=ledger_bytes,
            prefix_bytes=prefix_bytes,
            anchor_dir=anchor_dir,
            enforce_production_pins=enforce_production_pins,
        )
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc
    assert verification.head is not None
    return verification.head.release_index


def _verify_selected_tree(
    candidate: _CandidateTree,
    *,
    base: _BaseCommit | None,
    trusted_code_root: pathlib.Path,
    release_anchor_dir: pathlib.Path | None,
) -> str:
    """Run the retained append checks over already-entered snapshots."""

    spec = candidate.spec
    if base is not None:
        _data_changes, gate_changes, unclassified = check_surface_separation(
            base,
            candidate,
        )
        if gate_changes:
            reported = check_gate_only_confinement(unclassified, candidate)
            unclassified_suffix = (
                f"; unclassified changes={sorted(reported)}" if reported else ""
            )
            base_suffix = (
                f"; base {base.ref} ({base.commit})" if base.ref != base.commit else ""
            )
            return (
                "thesis-facts append check OK: gate-only proposal; "
                "DATA_SURFACE unchanged; GATE_SURFACE changes="
                f"{sorted(gate_changes)}{unclassified_suffix}{base_suffix}"
            )

    ledger_entry, ledger_bytes = _read_state_blob(
        candidate,
        spec.chain.state_relative,
    )
    text = _as_text(ledger_bytes, "utf-8")
    reject_non_append_bytes(text)
    lines = _lines(text)

    prefix_entry, prefix_bytes = _read_state_blob(
        candidate,
        spec.chain.prefix_relative,
    )
    prefix = check_prefix(lines, _as_text(prefix_bytes), candidate)
    binding_boundary = int(prefix["prefixLineCount"])
    appended = None
    if base is not None:
        binding_boundary = check_prefix_anchored_to_base(
            base,
            prefix,
            candidate,
        )
        appended = check_append_only(base, lines, candidate)
    check_rows(lines, binding_boundary, spec)

    production_pins = release_anchor_dir is None
    anchor_dir = release_anchor_dir or (trusted_code_root / spec.chain.anchor_relative)
    release_index = (
        check_release_proposal(
            base,
            candidate=candidate,
            ledger_bytes=ledger_bytes,
            prefix_bytes=prefix_bytes,
            anchor_dir=anchor_dir,
            enforce_production_pins=production_pins,
        )
        if base is not None
        else check_release_chain_without_base(
            candidate=candidate,
            ledger_bytes=ledger_bytes,
            prefix_bytes=prefix_bytes,
            anchor_dir=anchor_dir,
            enforce_production_pins=production_pins,
        )
    )

    check_binding_shapes(lines, binding_boundary)
    if base is not None:
        check_state_modes(
            base,
            candidate,
            entries={
                ledger_entry.path: ledger_entry,
                prefix_entry.path: prefix_entry,
            },
        )

    resolved = (
        f" {base.ref} ({base.commit})"
        if base is not None and base.ref != base.commit
        else ""
    )
    suffix = f", +{appended} appended vs base{resolved}" if appended is not None else ""
    release_suffix = f", release {release_index}" if release_index is not None else ""
    return (
        f"thesis-facts append check OK: {len(lines)} rows, immutable prefix "
        f"{prefix['prefixLineCount']}{suffix}{release_suffix}"
    )


def verify_append_gate_verdict(
    root: pathlib.Path,
    *,
    spec: AppendGateSpec,
    base_ref: str | None = None,
    commit: str = "HEAD",
    trusted_code_root: pathlib.Path = CODE_ROOT,
    release_anchor_dir: pathlib.Path | None = None,
) -> AppendGateVerdict:
    """Verify a selected commit and return its immutable object identities."""

    try:
        assert_no_redirecting_git_environment()
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc
    _assert_release_paths_are_subdirectories(spec)
    if base_ref is not None and (
        type(commit) is not str or re.fullmatch(r"[0-9a-f]{40}", commit) is None
    ):
        raise AppendError("base_ref requires a full commit OID")

    try:
        selected = TreeSnapshot.select(root, commit)
        with selected as snapshot:
            candidate = _CandidateTree(
                snapshot=snapshot,
                spec=spec,
                ledger_relative=spec.chain.state_relative.as_posix(),
                prefix_relative=spec.chain.prefix_relative.as_posix(),
            )
            if base_ref is None:
                summary = _verify_selected_tree(
                    candidate,
                    base=None,
                    trusted_code_root=trusted_code_root,
                    release_anchor_dir=release_anchor_dir,
                )
                return AppendGateVerdict(
                    summary=summary,
                    candidate_commit=snapshot.commit,
                    candidate_tree=snapshot.tree,
                    base_commit=None,
                    base_tree=None,
                    object_format=snapshot.object_format,
                    name_repertoire=spec.chain.name_repertoire,
                )

            selected_base = TreeSnapshot.select(root, base_ref)
            with selected_base as base_snapshot:
                snapshot.assert_ancestor(base_snapshot)
                base = _BaseCommit(
                    ref=base_ref,
                    commit=base_snapshot.commit,
                    tree=base_snapshot,
                )
                summary = _verify_selected_tree(
                    candidate,
                    base=base,
                    trusted_code_root=trusted_code_root,
                    release_anchor_dir=release_anchor_dir,
                )
                return AppendGateVerdict(
                    summary=summary,
                    candidate_commit=snapshot.commit,
                    candidate_tree=snapshot.tree,
                    base_commit=base_snapshot.commit,
                    base_tree=base_snapshot.tree,
                    object_format=snapshot.object_format,
                    name_repertoire=spec.chain.name_repertoire,
                )
    except AppendError:
        raise
    except (ReleaseChainError, SnapshotError) as exc:
        raise AppendError(str(exc)) from exc


def verify_append_gate(
    root: pathlib.Path,
    *,
    spec: AppendGateSpec,
    base_ref: str | None = None,
    commit: str = "HEAD",
    trusted_code_root: pathlib.Path = CODE_ROOT,
    release_anchor_dir: pathlib.Path | None = None,
) -> str:
    """Verify one selected commit and return the baseline success text."""

    return verify_append_gate_verdict(
        root,
        spec=spec,
        base_ref=base_ref,
        commit=commit,
        trusted_code_root=trusted_code_root,
        release_anchor_dir=release_anchor_dir,
    ).summary
