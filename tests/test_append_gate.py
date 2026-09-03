"""Confinement the upstream append gate never had, on a local fixture.

tests/test_append_gate_equivalence.py proves the port reproduces its oracle's
verdicts on the pinned production tree. This module covers what that battery
never presents: proposals that stay inside the classified surfaces the gate
speaks for, state paths that stay inside the candidate tree, one base commit
for the whole verdict, one snapshot of each state file, and a checkout whose
modes and types are what git recorded. Every case here is a NEW refusal (or a
previously silent acceptance made explicit), so the differential gate is
untouched. The state-path cases reach the shared reader in
receipt.release_chain, so they are exercised here directly as well.

Docstrings below labelled F1-F5 name the findings of the fourth review round,
in that review's numbering: F1 the checkout guard the push path never reached,
F2 the checkout settings that are a claim rather than evidence, F3 the
check-then-open state reads, F4 the git reads a replacement object could
redirect, F5 the guard that ran before the base ref was resolved.

Docstrings labelled R5-F1 to R5-F4 name the fifth round, whose numbering
starts over: R5-F1 the snapshots the release verification was not given,
R5-F2 the parent confinement that was still check-then-open, R5-F3 the state
paths taken on the working tree's word rather than the index's, R5-F4 the
release-root index entries the filesystem traversal cannot see.

Docstrings labelled R6-F1 onward name the third gate's first round, whose
numbering starts over again: R6-F1 the release-root index entries never
reconciled with the filesystem, R6-F2 the closing state checks a writer could
step between, R6-F3 the state file's mode and parents resolved again after
the read that established them, R6-F4 the descent that fell back to a
pathname open and the root nothing vouched for.

Docstrings labelled R7-F1 onward name that gate's second round, numbering
from one again: R7-F1 the base release file removed from the candidate index
alone, R7-F3 the gate-only classification that could not see what the index
records, R7-F4 the indexed release path answered for through a symlinked
component, R7-F5 the state mode read that followed a link where there was no
snapshot to take, R7-F6 the index reads that passed a path to git as a
pattern. That round's R7-F2 — the writer that can rewrite a state file after
its last re-read — is the stated residual: it wants an immutable snapshot of
the tree under audit, which this gate does not have, and it is tracked as
follow-up rather than bound by a test here.

Docstrings labelled S4-F1 onward name a fourth gate's first round, numbering
from one again: S4-F1 the recorded root identity a gate-only verdict never
consulted, S4-F2 the release-root reconciliation a case- or
normalisation-insensitive filesystem answered for the wrong entry, S4-F3 the
intent-to-add index entry that records no content, S4-F4 the ambient pathspec
mode that rewrote what every index read asked for, S4-F5 the descent that
demanded read permission on directories it only ever traversed, S4-F6 the
platform restriction documented as the gate's when it is the package's. S4-F6
is bound in tests/test_release_chain.py, where the public custody path and
``receipt verify`` itself are driven.

Docstrings labelled S4R2-F1 onward name that fourth gate's second round,
numbering from one again: S4R2-F1 the release root reached through a
symlinked component, S4R2-F2 the protected path an index entry could spell
another way (F2a) or the working tree could spell another way (F2b), S4R2-F3
the root identity that was two numbers a filesystem may hand to another
directory, S4R2-F4 the configured path handed to ``git ls-tree`` as a
pathspec rather than as a name.

The fixture is a local git repository built from scratch — no network, no
witnesses, no signatures. Its release tree holds a README and no manifests, so
the gate's chain verification finds nothing to verify and the checks under
test are the ones that run before it.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
import tempfile
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass, replace
from typing import Any

import pytest

from receipt import append_gate, release_chain
from receipt.append_gate import (
    AppendError,
    AppendGateSpec,
    expected_assertion_version_id,
    verify_append_gate,
)
from receipt.release_chain import (
    AnchorSpec,
    ChainSpec,
    ReleaseChainError,
    _regular_file_bytes,
)

# The fixture repository carries no release manifests, so no anchor identity
# below is ever consumed: these tests exercise the gate's path up to and
# including the ledger and release-history checks, never a signature or an
# RFC 3161 receipt. The layout mirrors the pinned consumer's so the surface
# patterns under test are the real ones.
CHAIN_SPEC = ChainSpec(
    manifest_relative=pathlib.PurePosixPath("releases/manifests"),
    state_relative=pathlib.PurePosixPath("ledger/official_observations.jsonl"),
    prefix_relative=pathlib.PurePosixPath("ledger/immutable_prefix.json"),
    anchor_relative=pathlib.PurePosixPath("releases/anchors"),
    release_root_relative=pathlib.PurePosixPath("releases"),
    schema_version="receipt_fixture_release_v1",
    producer_public_key_filename="producer-ed25519.pub",
    producer_spki_sha256="0" * 64,
    anchors={
        "alpha": AnchorSpec(
            filename="alpha-root.pem",
            pem_sha256="1" * 64,
            policy_oid="1.2.3.4.1",
            signer_certificate_sha256="2" * 64,
            signer_spki_sha256="3" * 64,
        ),
        "beta": AnchorSpec(
            filename="beta-root.pem",
            pem_sha256="4" * 64,
            policy_oid="1.2.3.4.2",
            signer_certificate_sha256="5" * 64,
            signer_spki_sha256="6" * 64,
        ),
    },
)

GATE_SPEC = AppendGateSpec(
    chain=CHAIN_SPEC,
    prefix_schema_version="receipt_fixture_immutable_prefix_v1",
    release_manifest_prefix="releases/manifests/",
    genesis_support_files=frozenset({"releases/README.md"}),
    gate_surface=frozenset(
        {
            "scripts/check_append.py",
            "releases/anchors/**",
        }
    ),
    data_surface=frozenset(
        {
            "ledger/**",
            "releases/manifests/**",
        }
    ),
    assertion_content_keys=(
        "source_record_id",
        "value",
        "observed_at",
        "period",
        "geography",
        "entity",
        "aggregation",
        "filters",
        "domain",
    ),
)

PREFIX_LINE_COUNT = 1
BASE_ROW_COUNT = 2
GATE_FILE = "scripts/check_append.py"


def _filesystem_conflates(spelled: str, with_other: str) -> bool:
    """Whether the filesystem holding temporary files folds two spellings.

    Asked of the filesystem the fixtures are built on, because that is what
    decides whether a spelling case can be constructed at all: where names are
    compared exactly, a name that resolves is a name its directory lists, so a
    working tree cannot hold one spelling and answer to another. APFS and HFS+
    fold both case and Unicode normalisation; ext4 — and so CI — folds
    neither.
    """

    with tempfile.TemporaryDirectory() as name:
        directory = pathlib.Path(name)
        (directory / spelled).mkdir()
        return (directory / with_other).exists()


CASE_IS_FOLDED = _filesystem_conflates("receipt-probe", "RECEIPT-PROBE")
NORMALISATION_IS_FOLDED = _filesystem_conflates(
    unicodedata.normalize("NFD", "receipt-probé"), "receipt-probé"
)


@dataclass(frozen=True)
class Candidate:
    """One fixture repository and the commit its proposal is measured against."""

    root: pathlib.Path
    base: str


def observation_row(number: int, **overrides: Any) -> dict[str, Any]:
    """One post-cutover ledger row, self-consistent by construction.

    ``assertionVersion.id`` is recomputed from the finished row, so a test
    that malforms a binding value still gets past the content-address check
    and binds the branch it is aimed at.
    """

    row: dict[str, Any] = {
        "source_record_id": f"fixture.series.observation_{number}",
        "value": float(number),
        "observed_at": "2026-07-01",
        "period": "2026-06",
        "geography": "US",
        "entity": "national",
        "aggregation": "level",
        "filters": {},
        "domain": "fixture",
        "measure": {
            "concept": "fixture.concept",
            "unit": "percent",
            "source_concept": "FIXTURE",
            "concept_relation": "exact",
            "concept_authority": "fixture",
            "legal_vintage": "2026",
        },
        "source": {
            "source_name": "fixture",
            "source_table": "t1",
            "source_file": "t1.csv",
            "url": "https://example.invalid/t1.csv",
            "vintage": "2026-07",
            "source_sha256": hashlib.sha256(f"source-{number}".encode()).hexdigest(),
        },
        "source_row_keys": ["row", str(number)],
        "source_cell_keys": ["cell", str(number)],
        "retrievedAt": "2026-07-10T20:38:58Z",
        "sourceVintage": "2026-07",
        "ledgerRepoSha": hashlib.sha256(f"repo-{number}".encode()).hexdigest()[:40],
        "responseArchive": {
            "sha256": hashlib.sha256(f"response-{number}".encode()).hexdigest()
        },
    }
    row.update(overrides)
    row["assertionVersion"] = {"id": expected_assertion_version_id(row, GATE_SPEC)}
    return row


def jsonl_line(row: dict[str, Any]) -> str:
    return json.dumps(row, ensure_ascii=False, separators=(",", ":"))


def write_ledger(root: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path = root / CHAIN_SPEC.state_relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(f"{jsonl_line(row)}\n" for row in rows),
        encoding="utf-8",
    )


def write_prefix_manifest(root: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    lines = [jsonl_line(row) for row in rows[:PREFIX_LINE_COUNT]]
    manifest = {
        "schemaVersion": GATE_SPEC.prefix_schema_version,
        "prefixLineCount": PREFIX_LINE_COUNT,
        "lineSha256s": [
            hashlib.sha256(line.encode("utf-8")).hexdigest() for line in lines
        ],
        "prefixSha256": hashlib.sha256(
            ("\n".join(lines) + "\n").encode("utf-8")
        ).hexdigest(),
    }
    path = root / CHAIN_SPEC.prefix_relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def git(root: pathlib.Path, *arguments: str, stdin: str | None = None) -> str:
    """Run fixture git commands with ambient user configuration isolated."""

    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        input=stdin,
    )
    return completed.stdout.strip()


def spec_with_release_root(release_root: str) -> AppendGateSpec:
    """The fixture spec with its release directory named some other way.

    Every configured path under the root moves with it, so the layout is the
    fixture's own and the only thing under test is the name — which is what a
    consumer pins in its committed code and what this package hands to git.
    """

    chain = replace(
        CHAIN_SPEC,
        release_root_relative=pathlib.PurePosixPath(release_root),
        manifest_relative=pathlib.PurePosixPath(f"{release_root}/manifests"),
        anchor_relative=pathlib.PurePosixPath(f"{release_root}/anchors"),
    )
    return replace(
        GATE_SPEC,
        chain=chain,
        release_manifest_prefix=f"{release_root}/manifests/",
        genesis_support_files=frozenset({f"{release_root}/README.md"}),
        gate_surface=frozenset({GATE_FILE, f"{release_root}/anchors/**"}),
        data_surface=frozenset({"ledger/**", f"{release_root}/manifests/**"}),
    )


def base_repository(
    tmp_path: pathlib.Path, release_root: str = "releases"
) -> Candidate:
    """A committed base: two ledger rows, a frozen prefix, a release README.

    ``release_root`` names the release directory this tree is built with, for
    the cases that pair it with ``spec_with_release_root``; the default is the
    one ``CHAIN_SPEC`` carries and every other test below takes it.
    """

    root = tmp_path / "candidate"
    root.mkdir()
    rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 1)]
    write_ledger(root, rows)
    write_prefix_manifest(root, rows)
    releases = root / release_root
    releases.mkdir(parents=True)
    (releases / "README.md").write_text(
        "Release journal for the fixture ledger.\n", encoding="utf-8"
    )
    git(root, "init", "--quiet")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "config", "user.name", "Append Gate Fixture")
    git(root, "add", "-A")
    git(root, "commit", "--quiet", "-m", "base ledger")
    return Candidate(root=root, base=git(root, "rev-parse", "HEAD"))


def append_one_row(candidate: Candidate, **overrides: Any) -> None:
    """The ordinary data proposal: one more row in the working tree."""

    rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 1)]
    rows.append(observation_row(BASE_ROW_COUNT + 1, **overrides))
    write_ledger(candidate.root, rows)


def stage(candidate: Candidate) -> None:
    """Record the working tree in the candidate's index, as a proposal does.

    A pull request is reviewed from a checkout whose index git wrote from the
    commit under review, so a mode the proposal changed is in the index too. A
    test that only chmods the working tree leaves the index disagreeing with
    it, which is now refused in its own words before any base comparison, so
    every mode-change case below stages first and the base comparison is what
    fires.
    """

    git(candidate.root, "add", "-A")


def add_gate_file(candidate: Candidate) -> None:
    script = candidate.root / GATE_FILE
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("# gate fixture\n", encoding="utf-8")


@contextlib.contextmanager
def selected_tree(candidate: Candidate) -> Iterator[Any]:
    """``_set_root``'s candidate tree, with its root descriptor closed after.

    ``verify_append_gate`` holds the candidate root open for the whole verdict
    and closes it once, in one place. A test that drives a single check on its
    own has to do the same or leak the descriptor.
    """

    tree = append_gate._set_root(candidate.root, GATE_SPEC)
    try:
        yield tree
    finally:
        os.close(tree.root_descriptor)


def run_gate(
    candidate: Candidate,
    base_ref: str | None = None,
    spec: AppendGateSpec = GATE_SPEC,
) -> str:
    return verify_append_gate(
        candidate.root,
        spec=spec,
        base_ref=candidate.base if base_ref is None else base_ref,
    )


def run_push_gate(candidate: Candidate, spec: AppendGateSpec = GATE_SPEC) -> str:
    """The push path: no base ref, so only the full-file invariants run.

    ``run_gate`` always names a base, so nothing above exercised the branch
    that skips surface classification, the append-only diff, the base prefix
    anchor, and the release history.
    """

    return verify_append_gate(candidate.root, spec=spec)


def test_an_ordinary_append_is_accepted(tmp_path: pathlib.Path) -> None:
    """The fixture's baseline verdict, so every refusal below is the change."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_a_gate_only_proposal_cannot_rewrite_the_release_tree(
    tmp_path: pathlib.Path,
) -> None:
    """The gap: a gate match returned OK for everything else in the proposal.

    ``releases/README.md`` is in neither surface, so adding the gate script
    and rewriting the README classified as gate-only and returned before the
    ledger, prefix, and release-history checks ever ran.
    """

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.write_text("Rewritten by a gate-only proposal.\n", encoding="utf-8")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "gate-only proposal changes unclassified release path(s): "
        "['releases/README.md']"
    )


def test_an_unclassified_change_outside_the_release_tree_is_named(
    tmp_path: pathlib.Path,
) -> None:
    """Outside the release root a gate-only proposal is still accepted — but
    the verdict names what it did not check, so nothing rides along silently.
    """

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    (candidate.root / "NOTES.md").write_text("unrelated\n", encoding="utf-8")

    assert run_gate(candidate) == (
        "thesis-facts append check OK: gate-only proposal; DATA_SURFACE "
        f"unchanged; GATE_SURFACE changes=['{GATE_FILE}']; "
        "unclassified changes=['NOTES.md']"
    )


def test_a_clean_gate_only_proposal_keeps_its_baseline_verdict(
    tmp_path: pathlib.Path,
) -> None:
    """With nothing unclassified the text is exactly what it always was."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)

    assert run_gate(candidate) == (
        "thesis-facts append check OK: gate-only proposal; DATA_SURFACE "
        f"unchanged; GATE_SURFACE changes=['{GATE_FILE}']"
    )


def relink_ledger_directory(candidate: Candidate, target: pathlib.Path) -> None:
    """Move ``ledger/`` to ``target`` and leave a symlink where it stood.

    The candidate keeps a name that still resolves to a regular JSONL file,
    still hashes to the frozen prefix, and still diffs clean against the base
    blob — while the bytes under audit live wherever the link points.
    """

    ledger = candidate.root / "ledger"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(ledger), str(target))
    ledger.symlink_to(target, target_is_directory=True)


def test_a_symlinked_ledger_parent_cannot_serve_state_from_outside_the_tree(
    tmp_path: pathlib.Path,
) -> None:
    """The gap: only the final component was ever checked for a link.

    With ``ledger/`` pointed at an ambient directory the whole append check
    returned OK on bytes that are no part of the candidate checkout.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    relink_ledger_directory(candidate, tmp_path / "outside" / "ledger")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'ledger': "
        "ledger/official_observations.jsonl"
    )


def test_an_in_tree_symlinked_ledger_parent_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """An in-tree target is the same hole: the accepted bytes then live in a
    directory no surface pattern names and no release check covers."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    relink_ledger_directory(candidate, candidate.root / "shadow")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'ledger': "
        "ledger/official_observations.jsonl"
    )


def test_a_symlinked_state_file_itself_is_refused(tmp_path: pathlib.Path) -> None:
    """The final component too: the gate followed a linked JSONL without
    comment, because nothing between _set_root and read_text looked."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    outside = tmp_path / "outside.jsonl"
    shutil.move(str(ledger), str(outside))
    ledger.symlink_to(outside)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'ledger/official_observations.jsonl': "
        "ledger/official_observations.jsonl"
    )


def test_a_symlinked_prefix_parent_is_refused(tmp_path: pathlib.Path) -> None:
    """The immutable prefix is a state path too, and check_prefix reads it by
    the same lexical join. Here the ledger stays put so the prefix walk is the
    one that fires."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    prefix = candidate.root / CHAIN_SPEC.prefix_relative
    outside = tmp_path / "outside" / "immutable_prefix.json"
    outside.parent.mkdir(parents=True)
    shutil.move(str(prefix), str(outside))
    prefix.symlink_to(outside)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'ledger/immutable_prefix.json': "
        "ledger/immutable_prefix.json"
    )


def test_the_state_reader_refuses_a_symlinked_parent(tmp_path: pathlib.Path) -> None:
    """The same walk in the release-chain reader, which _verify_state_history
    uses for both the ledger and the immutable prefix."""

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "official_observations.jsonl").write_text("{}\n", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "ledger").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ReleaseChainError) as refusal:
        _regular_file_bytes(root, CHAIN_SPEC.state_relative)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'ledger': "
        "ledger/official_observations.jsonl"
    )


def test_the_state_reader_keeps_its_message_for_a_symlinked_state_file(
    tmp_path: pathlib.Path,
) -> None:
    """The final-component refusal predates the walk and is differential-gated:
    a linked state file must still refuse with exactly its own message."""

    root = tmp_path / "repo"
    (root / "ledger").mkdir(parents=True)
    outside = tmp_path / "outside.jsonl"
    outside.write_text("{}\n", encoding="utf-8")
    linked = root / CHAIN_SPEC.state_relative
    linked.symlink_to(outside)

    with pytest.raises(ReleaseChainError) as refusal:
        _regular_file_bytes(root, CHAIN_SPEC.state_relative)
    assert str(refusal.value) == (
        f"required state file is missing or non-regular: {linked}"
    )


def test_the_state_reader_accepts_an_ordinary_regular_file(
    tmp_path: pathlib.Path,
) -> None:
    """The walk costs the ordinary tree nothing."""

    root = tmp_path / "repo"
    (root / "ledger").mkdir(parents=True)
    (root / CHAIN_SPEC.state_relative).write_text("{}\n", encoding="utf-8")

    assert _regular_file_bytes(root, CHAIN_SPEC.state_relative) == b"{}\n"


def moving_base_repository(
    tmp_path: pathlib.Path,
) -> tuple[Candidate, str, str]:
    """A branch on an early commit, a later commit, and a four-row worktree.

    The two commits give different verdicts for the same working tree — two
    appended rows against the first, one against the second — so the verdict
    text alone says which commit the whole run measured against. The later
    commit also differs in the frozen prefix manifest and in the release
    tree, so a consumer that read either at the moved ref would refuse
    outright: the prefix anchor compares manifest fields and the release
    history compares README bytes. That binds every base consumer, not only
    the append count (peer review, round three).
    """

    first = base_repository(tmp_path)
    readme = first.root / CHAIN_SPEC.release_root_relative / "README.md"
    manifest = first.root / CHAIN_SPEC.prefix_relative
    kept_readme, kept_manifest = readme.read_bytes(), manifest.read_bytes()
    rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 2)]
    write_ledger(first.root, rows)
    readme.write_text("Release journal, revised after the base.\n", encoding="utf-8")
    write_prefix_manifest(first.root, [dict(rows[0], value=999.0), *rows[1:]])
    git(first.root, "add", "-A")
    git(first.root, "commit", "--quiet", "-m", "third row, revised prefix and release tree")
    later = git(first.root, "rev-parse", "HEAD")
    git(first.root, "branch", "moving", first.base)
    readme.write_bytes(kept_readme)
    manifest.write_bytes(kept_manifest)
    rows.append(observation_row(BASE_ROW_COUNT + 2))
    write_ledger(first.root, rows)
    return Candidate(root=first.root, base="moving"), first.base, later


def test_the_success_text_names_the_commit_a_symbolic_base_resolved_to(
    tmp_path: pathlib.Path,
) -> None:
    """A verdict against a movable name must say which commit that name was."""

    moving, first, _later = moving_base_repository(tmp_path)

    assert run_gate(moving) == (
        "thesis-facts append check OK: 4 rows, immutable prefix 1, "
        f"+2 appended vs base moving ({first})"
    )


def test_a_base_named_by_its_own_commit_keeps_the_baseline_text(
    tmp_path: pathlib.Path,
) -> None:
    """A caller who named the OID already named the commit, so that verdict
    text is exactly what it always was."""

    moving, first, _later = moving_base_repository(tmp_path)

    assert run_gate(moving, base_ref=first) == (
        "thesis-facts append check OK: 4 rows, immutable prefix 1, "
        "+2 appended vs base"
    )


def test_the_moved_branch_alone_would_change_the_verdict(
    tmp_path: pathlib.Path,
) -> None:
    """The control: the two commits really do disagree about this worktree,
    and not only in the append count. Against the later commit the same tree
    is refused by the prefix anchor or the release history, so the mid-run
    test below proves every base consumer read the first commit (peer
    review, round three)."""

    moving, _first, later = moving_base_repository(tmp_path)
    git(moving.root, "branch", "-f", "moving", later)

    with pytest.raises(AppendError) as refusal:
        run_gate(moving)
    assert "appended" not in str(refusal.value)


def test_a_branch_that_moves_mid_verdict_is_still_read_at_one_commit(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gap: the base was resolved by name at the surface check, again at
    the append-only diff and the frozen prefix, and again at the release
    history. Move the branch after the surface check and the run must still
    answer about the commit it started with."""

    moving, first, later = moving_base_repository(tmp_path)
    separate = append_gate.check_surface_separation

    def move_the_branch(
        base: Any, candidate: Any
    ) -> tuple[set[str], set[str], set[str]]:
        classified = separate(base, candidate)
        git(candidate.root, "branch", "-f", "moving", later)
        return classified

    monkeypatch.setattr(append_gate, "check_surface_separation", move_the_branch)

    assert run_gate(moving) == (
        "thesis-facts append check OK: 4 rows, immutable prefix 1, "
        f"+2 appended vs base moving ({first})"
    )
    assert git(moving.root, "rev-parse", "moving") == later


def test_the_ledger_cannot_be_made_executable_by_a_proposal(
    tmp_path: pathlib.Path,
) -> None:
    """The gap: the append path compared bytes, never the mode git tracks."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.chmod(ledger.stat().st_mode | 0o111)
    stage(candidate)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file mode changed relative to base: "
        "ledger/official_observations.jsonl"
    )


def test_the_frozen_prefix_cannot_be_made_executable_by_a_proposal(
    tmp_path: pathlib.Path,
) -> None:
    """The manifest is candidate-controlled too, and its fields were the only
    thing anchored to the base."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    prefix = candidate.root / CHAIN_SPEC.prefix_relative
    prefix.chmod(prefix.stat().st_mode | 0o111)
    stage(candidate)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file mode changed relative to base: ledger/immutable_prefix.json"
    )


def test_a_ledger_executable_at_the_base_may_stay_executable(
    tmp_path: pathlib.Path,
) -> None:
    """The invariant is "keeps the base's category", not "must be 644": a base
    that already recorded 100755 accepts an ordinary append."""

    candidate = base_repository(tmp_path)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.chmod(ledger.stat().st_mode | 0o111)
    git(candidate.root, "add", "-A")
    git(candidate.root, "commit", "--quiet", "-m", "executable ledger")
    executable_base = Candidate(
        root=candidate.root, base=git(candidate.root, "rev-parse", "HEAD")
    )
    append_one_row(executable_base)
    ledger.chmod(ledger.stat().st_mode | 0o111)

    assert run_gate(executable_base) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_a_response_archive_digest_that_is_not_a_digest_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """The gap: presence was the whole check, so any truthy value bound the
    row to an archived response that may not exist."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, responseArchive={"sha256": "not-a-sha256"})

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) "
        "responseArchive.sha256 is not a SHA-256 hex digest"
    )


def test_an_uppercase_response_archive_digest_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """One spelling per digest: an upper-case twin of the same bytes would
    compare unequal to every digest this package recomputes."""

    candidate = base_repository(tmp_path)
    append_one_row(
        candidate,
        responseArchive={
            "sha256": hashlib.sha256(b"response-3").hexdigest().upper()
        },
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) "
        "responseArchive.sha256 is not a SHA-256 hex digest"
    )


def test_an_abbreviated_ledger_repo_sha_is_refused(tmp_path: pathlib.Path) -> None:
    """An abbreviation names a commit only until the repository grows one
    that shares its prefix."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, ledgerRepoSha="47ca684")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) ledgerRepoSha is "
        "not a full 40-character commit id"
    )


def test_a_symbolic_ledger_repo_sha_is_refused(tmp_path: pathlib.Path) -> None:
    """A symbolic name is truthy and binds nothing: it names whatever the
    repository points it at today."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, ledgerRepoSha="HEAD")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) ledgerRepoSha is "
        "not a full 40-character commit id"
    )


def test_a_retrieved_at_without_a_time_zone_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """A naive timestamp cannot be ordered against a witnessed genTime."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, retrievedAt="2026-07-10T20:38:58")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) retrievedAt is not "
        "a canonical RFC 3339 timestamp (uppercase T and Z or ±HH:MM, no "
        "leap second)"
    )


def test_a_retrieved_at_that_is_not_a_timestamp_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Prose satisfied presence exactly as well as a timestamp did."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, retrievedAt="yesterday")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) retrievedAt is not "
        "a canonical RFC 3339 timestamp (uppercase T and Z or ±HH:MM, no "
        "leap second)"
    )


def test_a_retrieved_at_naming_an_impossible_day_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """The pattern accepts the shape; the parser is what rejects the day."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, retrievedAt="2026-02-30T00:00:00Z")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) retrievedAt is not "
        "a canonical RFC 3339 timestamp (uppercase T and Z or ±HH:MM, no "
        "leap second)"
    )


def test_a_retrieved_at_with_a_non_utc_offset_is_accepted(
    tmp_path: pathlib.Path,
) -> None:
    """RFC 3339 with a time zone, not UTC-only: the check adds a shape, not a
    policy about which zone a resolver may report from."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, retrievedAt="2026-07-10T20:38:58.5+05:30")

    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


@pytest.mark.parametrize("offset", ["+01:60", "+24:00", "-00:60"])
def test_a_retrieved_at_with_an_overflowing_offset_is_refused(
    tmp_path: pathlib.Path, offset: str
) -> None:
    """The parser normalises ``+01:60`` to ``+02:00`` rather than refusing it,
    so the offset's hour and minute are bounded in the pattern (peer review)."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, retrievedAt=f"2026-07-10T20:38:58{offset}")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) retrievedAt is not "
        "a canonical RFC 3339 timestamp (uppercase T and Z or ±HH:MM, no "
        "leap second)"
    )


def test_a_group_execute_bit_alone_is_not_a_mode_change(
    tmp_path: pathlib.Path,
) -> None:
    """Git keys the executable category on the owner bit, so 0655 is 100644
    to git and an ordinary append with it is not a mode change."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.chmod(0o655)

    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_dropping_the_owner_execute_bit_is_a_mode_change_whatever_others_keep(
    tmp_path: pathlib.Path,
) -> None:
    """The case the any-bit test missed: 100755 at the base, 0655 in the
    candidate, which git records as 100644 (peer review)."""

    candidate = base_repository(tmp_path)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.chmod(ledger.stat().st_mode | 0o111)
    git(candidate.root, "add", "-A")
    git(candidate.root, "commit", "--quiet", "-m", "executable ledger")
    executable_base = Candidate(
        root=candidate.root, base=git(candidate.root, "rev-parse", "HEAD")
    )
    append_one_row(executable_base)
    ledger.chmod(0o655)
    stage(executable_base)

    with pytest.raises(AppendError) as refusal:
        run_gate(executable_base)
    assert str(refusal.value) == (
        "state file mode changed relative to base: "
        "ledger/official_observations.jsonl"
    )


def test_a_gate_only_verdict_names_the_commit_a_symbolic_base_resolved_to(
    tmp_path: pathlib.Path,
) -> None:
    """The gate-only acceptance returned before the resolved-base suffix was
    built, so against a movable name it named no snapshot (peer review)."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)

    assert run_gate(candidate, base_ref="HEAD") == (
        "thesis-facts append check OK: gate-only proposal; DATA_SURFACE "
        f"unchanged; GATE_SURFACE changes=['{GATE_FILE}']; base HEAD "
        f"({candidate.base})"
    )


def test_an_existing_row_refusal_wins_over_a_binding_shape_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """A row that both duplicates a record without superseding it and carries
    a symbolic ledgerRepoSha gets the refusal that existed before this branch:
    the shape checks run last in the row (peer review)."""

    candidate = base_repository(tmp_path)
    append_one_row(
        candidate,
        source_record_id="fixture.series.observation_2",
        value=999.0,
        ledgerRepoSha="HEAD",
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "line 3 duplicates fixture.series.observation_2 (line 2) without "
        "superseding an assertion version — corrections must be explicit"
    )


def test_an_existing_row_refusal_wins_over_the_mode_check(
    tmp_path: pathlib.Path,
) -> None:
    """Pins the order the mode check runs in: a proposal that both flips the
    ledger's mode and appends a row lacking retrievedAt gets the row refusal,
    which existed before the mode check did (peer review asked for this)."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, retrievedAt=None)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.chmod(ledger.stat().st_mode | 0o100)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) lacks retrievedAt"
    )


def test_a_release_file_with_a_group_execute_bit_alone_keeps_its_category(
    tmp_path: pathlib.Path,
) -> None:
    """The release-file comparison keys on the owner bit like the state check:
    0655 is 100644 to git, so a 100644 base accepts it."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.chmod(0o655)

    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_dropping_a_release_files_owner_execute_bit_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """100755 at the base, 0655 in the candidate: a mode change the any-bit
    test in the release-file comparison missed (peer review, round two)."""

    candidate = base_repository(tmp_path)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.chmod(readme.stat().st_mode | 0o111)
    git(candidate.root, "add", "-A")
    git(candidate.root, "commit", "--quiet", "-m", "executable readme")
    executable_base = Candidate(
        root=candidate.root, base=git(candidate.root, "rev-parse", "HEAD")
    )
    append_one_row(executable_base)
    readme.chmod(0o655)
    stage(executable_base)

    with pytest.raises(AppendError) as refusal:
        run_gate(executable_base)
    assert str(refusal.value) == (
        f"existing release file mode changed relative to {executable_base.base}: "
        "releases/README.md (100755 -> 100644)"
    )


def test_a_checkout_whose_modes_are_not_authoritative_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """With core.fileMode false the working tree says nothing about the mode
    git records, so comparing it would be fail-open; the gate refuses instead
    (peer review, round two)."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(candidate.root, "config", "core.fileMode", "false")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "file modes cannot be verified: core.fileMode is false in this "
        "checkout, so the working tree does not carry the executable bit git "
        "records"
    )


def test_a_pre_existing_release_refusal_wins_over_a_binding_shape_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """A proposal that both rewrites a base release file and carries a
    symbolic ledgerRepoSha gets the release-history refusal, which existed
    before the shape checks did: they run after the release checks (peer
    review, round two)."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, ledgerRepoSha="HEAD")
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.write_text("rewritten\n", encoding="utf-8")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert "ledgerRepoSha" not in str(refusal.value)
    assert "releases/README.md" in str(refusal.value)


@pytest.mark.parametrize(
    "value",
    ["2026-07-10t20:38:58Z", "2026-07-10T20:38:58z", "2016-12-31T23:59:60Z"],
    ids=["lowercase-t", "lowercase-z", "leap-second"],
)
def test_forms_the_rfc_permits_but_the_profile_does_not_are_refused(
    tmp_path: pathlib.Path, value: str
) -> None:
    """The validator is a stated profile, narrower than RFC 3339: uppercase T
    and Z, ±HH:MM, no leap second (peer review, round three)."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, retrievedAt=value)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) retrievedAt is not "
        "a canonical RFC 3339 timestamp (uppercase T and Z or ±HH:MM, no "
        "leap second)"
    )


def test_a_checkout_that_does_not_materialise_symlinks_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """With core.symlinks false a symlink blob is checked out as a plain file
    holding its target, so byte, mode, and component-walk checks all pass
    over a type change (peer review, round three)."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(candidate.root, "config", "core.symlinks", "false")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "file types cannot be verified: core.symlinks is false in this "
        "checkout, so a symlink entry is materialised as a plain file"
    )


@pytest.mark.parametrize(
    ("key", "message"),
    [
        (
            "core.fileMode",
            "file modes cannot be verified: core.fileMode is false in this "
            "checkout, so the working tree does not carry the executable bit git "
            "records",
        ),
        (
            "core.symlinks",
            "file types cannot be verified: core.symlinks is false in this "
            "checkout, so a symlink entry is materialised as a plain file",
        ),
    ],
    ids=["fileMode", "symlinks"],
)
def test_the_release_history_pass_refuses_a_non_authoritative_checkout_itself(
    tmp_path: pathlib.Path, key: str, message: str
) -> None:
    """Binds the guard inside verify_release_history_immutable directly, since
    through the gate check_state_modes would refuse the same way later
    (peer review, round three)."""

    from receipt.release_chain import ReleaseChainError, verify_release_history_immutable

    candidate = base_repository(tmp_path)
    git(candidate.root, "config", key, "false")

    with pytest.raises(ReleaseChainError) as refusal:
        verify_release_history_immutable(candidate.root, candidate.base, spec=CHAIN_SPEC)
    assert str(refusal.value) == message


def test_the_checkout_refusal_precedes_file_level_release_refusals(
    tmp_path: pathlib.Path,
) -> None:
    """Pins the one intended precedence over pre-existing release checks: a
    checkout that cannot be verified says so before any verdict about its
    files, even a rewritten base release file."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.write_text("rewritten\n", encoding="utf-8")
    git(candidate.root, "config", "core.fileMode", "false")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value).startswith("file modes cannot be verified")


def test_a_replacement_object_cannot_change_what_the_base_commit_reads_as(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F4: every git read in the gate disables ``refs/replace``.

    A replacement rewrites what git returns for an object while every command
    still prints the original OID, so a base commit replaced by a later one is
    shown, diffed, and enumerated as that later commit behind the name the
    verdict prints. Without ``GIT_NO_REPLACE_OBJECTS`` this run reads the
    later commit — which differs in the ledger, the frozen prefix manifest,
    and the release tree — and refuses; the control below shows exactly that.
    """

    moving, first, later = moving_base_repository(tmp_path)
    git(moving.root, "replace", first, later)
    # The replacement is live for an ordinary read: the base OID now shows the
    # later commit's three-row ledger.
    replaced = git(
        moving.root,
        "show",
        f"{first}:{CHAIN_SPEC.state_relative.as_posix()}",
    )
    assert len(replaced.splitlines()) == BASE_ROW_COUNT + 1

    assert run_gate(moving) == (
        "thesis-facts append check OK: 4 rows, immutable prefix 1, "
        f"+2 appended vs base moving ({first})"
    )


def test_the_replacement_control_shows_the_environment_is_what_stops_it(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for F4: strip ``GIT_NO_REPLACE_OBJECTS`` from the shared
    environment helper — in both modules, since append_gate binds the name at
    import — and the same tree is read at the replacement and refused. That is
    the verdict this branch would still be giving without the fix."""

    moving, first, later = moving_base_repository(tmp_path)
    git(moving.root, "replace", first, later)
    monkeypatch.setattr(append_gate, "_git_environment", lambda: dict(os.environ))
    monkeypatch.setattr(release_chain, "_git_environment", lambda: dict(os.environ))

    with pytest.raises(AppendError) as refusal:
        run_gate(moving)
    assert "changed vs base moving" in str(refusal.value)


def test_the_push_path_accepts_an_ordinary_tree(tmp_path: pathlib.Path) -> None:
    """The baseline for F1, so the refusals below are the change: with no base
    ref the verdict carries neither an append count nor a release, and this
    branch of verify_append_gate had no test at all before."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)

    assert run_push_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1"
    )


@pytest.mark.parametrize(
    ("key", "message"),
    [
        (
            "core.fileMode",
            "file modes cannot be verified: core.fileMode is false in this "
            "checkout, so the working tree does not carry the executable bit "
            "git records",
        ),
        (
            "core.symlinks",
            "file types cannot be verified: core.symlinks is false in this "
            "checkout, so a symlink entry is materialised as a plain file",
        ),
    ],
    ids=["fileMode", "symlinks"],
)
def test_the_push_path_refuses_a_non_authoritative_checkout(
    tmp_path: pathlib.Path, key: str, message: str
) -> None:
    """Binds F1: the checkout guard was reachable only through the base-ref
    path — the release-history pass and check_state_modes. On a push both are
    skipped, so with core.symlinks false a git 120000 state entry materialised
    as a plain file holding its target text passed the component walk (there
    is no link to see) and both state reads, and the run returned OK. The
    guard now runs at entry for both paths."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(candidate.root, "config", key, "false")

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == message


def test_an_invalid_base_ref_is_refused_before_the_checkout_guard(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F5: the guard used to run before the base ref was resolved, so a
    false core.fileMode masked an unresolvable base — the run blamed the
    checkout for a proposal that never named a real commit. The base is
    resolved first now, and this refusal is the one that predates the guard."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(candidate.root, "config", "core.fileMode", "false")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate, base_ref="refs/heads/does-not-exist")
    assert str(refusal.value).startswith(
        "git rev-parse --verify --end-of-options "
        "refs/heads/does-not-exist^{commit} failed:"
    )


def test_the_release_history_pass_resolves_the_base_before_its_checkout_guard(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F5 at the release-chain level: the guard ran before
    resolve_base_commit, so a false core.fileMode answered a base ref that
    names nothing with a complaint about the checkout. Called directly — the
    gate resolves the base itself and passes an OID — the refusal must be the
    unresolvable ref."""

    candidate = base_repository(tmp_path)
    git(candidate.root, "config", "core.fileMode", "false")

    with pytest.raises(ReleaseChainError) as refusal:
        release_chain.verify_release_history_immutable(
            candidate.root, "refs/heads/does-not-exist", spec=CHAIN_SPEC
        )
    assert str(refusal.value).startswith(
        "cannot resolve base ref 'refs/heads/does-not-exist' to a commit:"
    )


def test_a_symlink_staged_over_a_regular_state_file_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F2: the checkout settings do not prove how the tree was
    materialised. With core.symlinks true and the index holding a 120000
    entry for the ledger, a working tree that carries a plain file there is
    not what git recorded — the exact shape core.symlinks false produces, and
    the shape a filesystem without symlinks leaves behind whatever the config
    says. Nothing compared the two, so the byte and mode checks ran on a
    regular file while git held a link.

    R5-F3 moved which refusal the gate gives for this tree: a 120000 entry
    for a state path is not a tracked regular file, and the entry check says
    so before anything reads the file at all. The comparison this case was
    written for is asserted directly below, so both remain bound."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    target = candidate.root / "link-target"
    target.write_text("outside.jsonl", encoding="utf-8")
    blob = git(candidate.root, "hash-object", "-w", "link-target")
    target.unlink()
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"120000,{blob},{CHAIN_SPEC.state_relative.as_posix()}",
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path ledger/official_observations.jsonl has a non-regular "
        "index entry: 120000"
    )
    with pytest.raises(ReleaseChainError) as compared:
        release_chain.assert_index_agrees_with_tree(
            candidate.root, CHAIN_SPEC.state_relative
        )
    assert str(compared.value) == (
        "candidate index records a symlink at ledger/official_observations.jsonl "
        "but the working tree holds a regular file"
    )


def test_a_state_file_whose_mode_the_working_tree_lost_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F2: core.fileMode true is a claim, not evidence. Here the index
    records the ledger executable and the working tree does not carry the bit
    — a checkout on a filesystem that dropped it, or one that was chmodded
    behind git's back. The base comparison would have read the tree's 100644
    as the proposal's own mode; it refuses to compare instead."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(
        candidate.root,
        "update-index",
        "--chmod=+x",
        "--",
        CHAIN_SPEC.state_relative.as_posix(),
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "candidate working tree mode for ledger/official_observations.jsonl "
        "disagrees with its index entry (100755 vs 100644)"
    )


def test_a_release_file_whose_mode_the_working_tree_lost_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F2 at the other call site: the release-history pass compares the
    same kind of stat for every base release file, and it is evidence under
    the same condition. This refusal comes from that pass, before the state
    files are reached."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(candidate.root, "update-index", "--chmod=+x", "--", "releases/README.md")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "candidate working tree mode for releases/README.md disagrees with "
        "its index entry (100755 vs 100644)"
    )


def test_the_index_check_passes_over_a_path_the_index_does_not_hold(
    tmp_path: pathlib.Path,
) -> None:
    """The other half of F2: a new untracked file has no index entry to
    disagree with, so there is nothing to compare and nothing to refuse —
    without which every release proposal, which adds files, would refuse."""

    candidate = base_repository(tmp_path)
    (candidate.root / "NOTES.md").write_text("new\n", encoding="utf-8")

    release_chain.assert_index_agrees_with_tree(candidate.root, "NOTES.md")


@contextlib.contextmanager
def time_limit(seconds: float) -> Iterator[None]:
    """Fail rather than hang: a blocked open cannot be interrupted otherwise.

    The gap the snapshot reader closes includes a reader that waits forever on
    a FIFO, so the test for it must be able to say "did not return" instead of
    stalling the suite.
    """

    def expire(_signum: int, _frame: Any) -> None:
        raise TimeoutError(f"the gate did not return within {seconds}s")

    previous = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="the platform has no FIFOs to refuse"
)
def test_a_fifo_at_the_ledger_path_is_refused_rather_than_waited_on(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F3: the state read was check-then-open. The component walk sees
    no symlink at a FIFO, so the reader that followed opened it — and an open
    of a FIFO with no writer blocks until one arrives, which for a proposal
    that plants one is never. The gate stalls, holding CI, with no verdict.
    The reader now lstats first and opens with O_NONBLOCK, so this returns
    immediately; the time limit is what would fail if it did not."""

    candidate = base_repository(tmp_path)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.unlink()
    os.mkfifo(ledger)

    with time_limit(20), pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file is not a regular file: ledger/official_observations.jsonl"
    )


@pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="the platform has no FIFOs to refuse"
)
def test_a_fifo_at_the_prefix_path_is_refused_rather_than_waited_on(
    tmp_path: pathlib.Path,
) -> None:
    """F3 for the other state file: the frozen prefix is read by the same
    reader, at the point check_prefix used to walk and open it, so a FIFO
    there is refused the same way and just as promptly instead of stalling
    the run."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    prefix = candidate.root / CHAIN_SPEC.prefix_relative
    prefix.unlink()
    os.mkfifo(prefix)

    with time_limit(20), pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file is not a regular file: ledger/immutable_prefix.json"
    )


def test_a_state_file_swapped_between_the_check_and_the_open_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F3's other half of the check-then-open gap: the file the walk
    inspected and the file the reader opened were resolved separately, so the
    final component could be swapped in between and the bytes verified were
    never the ones checked. Standing in a different file for every lstat of
    the ledger path reproduces exactly that; the open's fstat no longer
    matches what the check saw, and the run refuses instead of reading on."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    decoy = tmp_path / "decoy.jsonl"
    decoy.write_text("{}\n", encoding="utf-8")
    real_lstat = os.lstat

    def swapped(path: Any, *arguments: Any, **keywords: Any) -> os.stat_result:
        try:
            named = os.fspath(path)
        except TypeError:
            return real_lstat(path, *arguments, **keywords)
        if named == os.fspath(ledger):
            return real_lstat(decoy)
        return real_lstat(path, *arguments, **keywords)

    monkeypatch.setattr(os, "lstat", swapped)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file was replaced while it was being read: "
        "ledger/official_observations.jsonl"
    )


def rewrite_ledger_inside(
    candidate: Candidate, monkeypatch: pytest.MonkeyPatch, rows: int
) -> None:
    """Let check_rows return, then rewrite the ledger before the next consumer.

    check_rows is the last consumer of the parsed rows before the release
    verification opens the ledger again, so this is the window in which one
    tree could satisfy the row checks with one ledger and the release chain
    with another.
    """

    checked = append_gate.check_rows

    def rewrite(lines: list[str], prefix_count: int, spec: AppendGateSpec) -> None:
        checked(lines, prefix_count, spec)
        write_ledger(
            candidate.root,
            [observation_row(number) for number in range(1, rows + 1)],
        )

    monkeypatch.setattr(append_gate, "check_rows", rewrite)


def test_a_ledger_rewritten_between_consumers_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F3: the ledger was opened once for the row checks and again by
    the release verification, so a proposal that rewrote it in between got a
    verdict assembled from two different files — the row count, the prefix
    hashes, and the append count from the first, the byte-append and release
    state from the second. Every consumer in append_gate is now fed the one
    snapshot, and the re-check at the end refuses a tree that moved."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    rewrite_ledger_inside(candidate, monkeypatch, rows=BASE_ROW_COUNT + 2)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file changed during verification: "
        "ledger/official_observations.jsonl"
    )
    # The rewrite really did land: the refusal is about the tree, not a
    # rewrite that never happened.
    ledger = candidate.root / CHAIN_SPEC.state_relative
    assert len(ledger.read_text(encoding="utf-8").splitlines()) == BASE_ROW_COUNT + 2


def test_a_prefix_manifest_rewritten_between_consumers_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F3 for the other state file: the frozen prefix is what the release
    verification re-reads and what every base comparison was made from, so it
    is re-checked the same way. Without the re-check the run answered about a
    manifest that no longer existed."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    checked = append_gate.check_rows

    def rewrite(lines: list[str], prefix_count: int, spec: AppendGateSpec) -> None:
        checked(lines, prefix_count, spec)
        prefix = candidate.root / CHAIN_SPEC.prefix_relative
        prefix.write_text(prefix.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    monkeypatch.setattr(append_gate, "check_rows", rewrite)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file changed during verification: ledger/immutable_prefix.json"
    )


def test_a_ledger_replaced_by_an_identical_copy_mid_verdict_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The identity half of F3's re-check, which bytes alone cannot see: the
    ledger is replaced mid-run by a different file holding the same bytes.
    Nothing downstream would notice — every byte comparison still holds — but
    the file this verdict read is gone, and whatever replaced it was never
    the one the walk, the lstat, and the open agreed on."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    checked = append_gate.check_rows

    def replace(lines: list[str], prefix_count: int, spec: AppendGateSpec) -> None:
        checked(lines, prefix_count, spec)
        payload = ledger.read_bytes()
        ledger.unlink()
        ledger.write_bytes(payload)

    monkeypatch.setattr(append_gate, "check_rows", replace)
    before = ledger.stat()

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file changed during verification: "
        "ledger/official_observations.jsonl"
    )
    # Same bytes, different file: only the recorded identity says so. A
    # filesystem may hand the replacement the inode it just freed (ext4 does,
    # APFS does not), in which case the inode change time is what still
    # distinguishes the two; either way the identity the run recorded no
    # longer holds.
    after = ledger.stat()
    assert (after.st_ino, after.st_ctime_ns) != (before.st_ino, before.st_ctime_ns)


def test_a_state_file_that_cannot_be_re_read_is_refused_as_changed(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A re-read that cannot be completed at all is the same answer: the file
    changed. Here the ledger becomes a link to bytes outside the tree after
    the last consumer, which the re-read's component walk refuses — and the
    caller reports the change, because the run had already answered about the
    file that was there."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    compared = append_gate.check_state_modes

    def relink(base: Any, tree: Any, **keywords: Any) -> None:
        compared(base, tree, **keywords)
        ledger = candidate.root / CHAIN_SPEC.state_relative
        outside = tmp_path / "outside.jsonl"
        shutil.move(str(ledger), str(outside))
        ledger.symlink_to(outside)

    monkeypatch.setattr(append_gate, "check_state_modes", relink)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file changed during verification: "
        "ledger/official_observations.jsonl"
    )


def test_an_unchanged_tree_passes_the_re_read(tmp_path: pathlib.Path) -> None:
    """The acceptance F3 must not disturb: an ordinary proposal is the same
    file with the same bytes at the end, and gets the verdict text it got
    before the snapshot reader existed."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)

    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_a_conflicted_index_entry_is_refused(tmp_path: pathlib.Path) -> None:
    """The remaining index state F2 has to answer for: a conflicted merge
    records stages 1-3 and no single mode for the path, so there is nothing
    for the working tree to agree with and no basis for comparing modes.
    Refuse rather than pick one of the stages."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    relative = CHAIN_SPEC.state_relative.as_posix()
    blob = git(candidate.root, "rev-parse", f"HEAD:{relative}")
    git(candidate.root, "rm", "--cached", "--quiet", "--", relative)
    git(
        candidate.root,
        "update-index",
        "--index-info",
        stdin=f"100644 {blob} 1\t{relative}\n100644 {blob} 2\t{relative}\n",
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "candidate index holds an unmerged entry at "
        "ledger/official_observations.jsonl"
    )


def test_file_level_release_refusals_precede_the_index_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """The per-file index check runs after the comparisons it qualifies.

    An unstaged chmod on a base release file is both a mode change against
    the base and an index/worktree disagreement. The upstream verifier
    refuses it as a mode change, and the ledger differential harness pins
    that text (`base_mode_change`), so the index refusal must not pre-empt
    it: a comparison that passed fail-open is caught afterwards instead.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.chmod(readme.stat().st_mode | 0o111)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        f"existing release file mode changed relative to {candidate.base}: "
        "releases/README.md (100644 -> 100755)"
    )


def test_a_ledger_swapped_and_restored_inside_the_release_pass_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R5-F1: the closing re-read could be satisfied by a restoration.

    A candidate that swaps the ledger while the release verification runs and
    puts the original back before the run ends is invisible to a comparison
    over device, inode, size, and modification time: writing the bytes back
    in place keeps the first three, and ``os.utime`` restores the fourth.
    That is the second half of the A-to-B-to-A hole — the first half, the
    release verification reading the path again rather than being handed
    what this run read, is bound in tests/test_release_chain.py, where a
    chain exists to verify. The identity now carries ``st_ctime_ns``, which
    the kernel stamps on every metadata write and no caller can set back.
    Without it this run is accepted, with a verdict about a file that was
    not there for the whole of it.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    original = ledger.read_bytes()
    before = ledger.stat()
    verified = append_gate.verify_release_history_immutable

    def swap(root: Any, commit: str, *, spec: Any) -> Any:
        # B, in place: two more rows than the run read, and a valid byte
        # append in its own right, so nothing downstream would object to it.
        write_ledger(
            candidate.root,
            [observation_row(number) for number in range(1, BASE_ROW_COUNT + 3)],
        )
        try:
            return verified(root, commit, spec=spec)
        finally:
            ledger.write_bytes(original)
            os.utime(ledger, ns=(before.st_atime_ns, before.st_mtime_ns))

    monkeypatch.setattr(append_gate, "verify_release_history_immutable", swap)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file changed during verification: "
        "ledger/official_observations.jsonl"
    )
    # The restoration really was complete in every field the identity carried
    # before this round, so the change time is what refused.
    after = ledger.stat()
    assert ledger.read_bytes() == original
    assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    assert after.st_ctime_ns != before.st_ctime_ns


def test_the_push_path_hands_the_release_verification_its_snapshots(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R5-F1 at the gate: the release verification is given the bytes.

    ``check_release_chain_without_base`` used to let ``verify_release_chain``
    open the ledger and the frozen prefix by name, a second read of each file
    inside one verdict. It now passes the snapshots this run took, keyed by
    their relative POSIX paths. The fixture carries no chain, so the call is
    made directly with the manifest directory stubbed non-empty; what is
    asserted is the mapping the gate hands down.
    """

    candidate = base_repository(tmp_path)
    manifests = candidate.root / CHAIN_SPEC.manifest_relative
    manifests.mkdir(parents=True)
    (manifests / "0000-0000000000000000.json").write_text("{}\n", encoding="utf-8")
    captured: dict[str, Any] = {}

    def capture(root: pathlib.Path, **keywords: Any) -> None:
        captured.update(keywords)
        raise ReleaseChainError("stop before verifying anything")

    monkeypatch.setattr(append_gate, "verify_release_chain", capture)

    with selected_tree(candidate) as tree, pytest.raises(AppendError):
        append_gate.check_release_chain_without_base(
            candidate=tree,
            ledger_bytes=b"ledger snapshot",
            prefix_bytes=b"prefix snapshot",
        )
    assert captured["state_bytes"] == {
        "ledger/official_observations.jsonl": b"ledger snapshot",
        "ledger/immutable_prefix.json": b"prefix snapshot",
    }


def test_a_state_parent_swapped_after_the_walk_cannot_be_followed(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R5-F2: the parent confinement was still check-then-open.

    The component walk inspects ``ledger/`` and then the reader opens
    ``ledger/official_observations.jsonl`` by pathname, which resolves
    ``ledger/`` all over again — so a checked parent could be replaced with a
    symlink in between and the open would follow it. ``O_NOFOLLOW`` on the
    leaf says nothing about its parents. Here the swap is performed on the
    first ``lstat`` of the ledger path, which is after the walk has cleared
    ``ledger/``, and the target holds a decoy ledger of four self-consistent
    rows over the same frozen prefix.

    Without the descriptor walk the reader follows the swapped parent and
    the snapshot this verdict is built from is four rows from outside the
    checkout. The run does still refuse — the frozen prefix is walked next
    and sees the link that is there by then — but it refuses about
    ``ledger/immutable_prefix.json``, having already read the ledger the
    walk was taken to confine. What is bound here is that the ledger read
    itself refuses, and names the component that moved.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    decoy_root = tmp_path / "outside"
    decoy_rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 3)]
    write_ledger(decoy_root, decoy_rows)
    write_prefix_manifest(decoy_root, decoy_rows)

    ledger = candidate.root / CHAIN_SPEC.state_relative
    directory = candidate.root / "ledger"
    real_lstat = os.lstat
    swapped = {"done": False}

    def swap_then_lstat(path: Any, *arguments: Any, **keywords: Any) -> os.stat_result:
        try:
            named = os.fspath(path)
        except TypeError:
            named = None
        if named == os.fspath(ledger) and not swapped["done"]:
            swapped["done"] = True
            shutil.move(str(directory), str(tmp_path / "real-ledger"))
            directory.symlink_to(decoy_root / "ledger", target_is_directory=True)
        return real_lstat(path, *arguments, **keywords)

    monkeypatch.setattr(os, "lstat", swap_then_lstat)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'ledger': "
        "ledger/official_observations.jsonl"
    )
    # The swap really did happen, and the decoy really was reachable by name.
    assert swapped["done"]
    monkeypatch.undo()
    assert len(ledger.read_text(encoding="utf-8").splitlines()) == BASE_ROW_COUNT + 2


def test_the_state_reader_cannot_follow_a_parent_swapped_after_its_walk(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R5-F2 in the release-chain reader, which has the same two steps.

    ``_regular_file_bytes`` checks the final component, walks the parents,
    and then reads the pathname. Replacing ``ledger/`` immediately after the
    walk returns is the gap; the read now goes through the descriptor walk,
    which cannot resolve that name a second time, and refuses in the walk's
    own words. Both refusals the reader already gave still come first and
    still say what they said.
    """

    root = tmp_path / "repo"
    (root / "ledger").mkdir(parents=True)
    (root / CHAIN_SPEC.state_relative).write_text('{"real":true}\n', encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "official_observations.jsonl").write_text(
        '{"decoy":true}\n', encoding="utf-8"
    )
    walked = release_chain.assert_no_symlinked_state_component

    def walk_then_swap(
        walk_root: pathlib.Path, relative: pathlib.PurePosixPath
    ) -> None:
        walked(walk_root, relative)
        directory = walk_root / "ledger"
        shutil.rmtree(directory)
        directory.symlink_to(outside, target_is_directory=True)

    monkeypatch.setattr(
        release_chain, "assert_no_symlinked_state_component", walk_then_swap
    )

    with pytest.raises(ReleaseChainError) as refusal:
        _regular_file_bytes(root, CHAIN_SPEC.state_relative)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'ledger': "
        "ledger/official_observations.jsonl"
    )


def test_a_gitlink_over_the_ledger_directory_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R5-F3: nothing looked at a state path's ancestors.

    A directory reaches the index only as a gitlink, and a 160000 entry at
    ``ledger`` is a submodule boundary: what lies beneath it belongs to
    another repository and is no part of this commit's content, while
    arriving in the working tree as ordinary regular files that hash, parse,
    and satisfy every byte comparison the gate makes. The index check that
    existed returned on a path the index does not hold — which is exactly
    what a gitlink over it produces — so the whole append ran on files git
    never recorded here.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    for relative in (CHAIN_SPEC.state_relative, CHAIN_SPEC.prefix_relative):
        git(candidate.root, "rm", "--cached", "--quiet", "--", relative.as_posix())
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{candidate.base},ledger",
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path ledger/official_observations.jsonl has an indexed "
        "ancestor ledger (160000)"
    )


def test_an_untracked_ledger_is_refused_as_absent_from_the_index(
    tmp_path: pathlib.Path,
) -> None:
    """The other half of R5-F3's leaf rule: an untracked state file is not
    part of the commit under review. Its bytes are not what a merge would
    take and no diff against the base can reach them, so there is nothing for
    this verdict to be about. The index check that existed treated a path it
    did not hold as nothing to compare, and returned."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(
        candidate.root,
        "rm",
        "--cached",
        "--quiet",
        "--",
        CHAIN_SPEC.state_relative.as_posix(),
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path ledger/official_observations.jsonl is absent from the "
        "candidate index"
    )


def test_the_push_path_refuses_a_symlink_index_entry_for_the_ledger(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R5-F3 on the push path, which had no state check of any kind.

    With no base ref there is no release-history pass and no
    ``check_state_modes``, so a 120000 index entry standing over a regular
    file — what ``core.symlinks`` false materialises, and what a filesystem
    without symlinks leaves whatever the config claims — reached every byte
    check on this path unexamined. The entry check refuses it on both paths
    now, before anything is read.
    """

    candidate = base_repository(tmp_path)
    target = candidate.root / "link-target"
    target.write_text("outside.jsonl", encoding="utf-8")
    blob = git(candidate.root, "hash-object", "-w", "link-target")
    target.unlink()
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"120000,{blob},{CHAIN_SPEC.state_relative.as_posix()}",
    )

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "state path ledger/official_observations.jsonl has a non-regular "
        "index entry: 120000"
    )


def test_the_push_path_compares_the_state_files_against_the_index(
    tmp_path: pathlib.Path,
) -> None:
    """R5-F3's second push-path gap: the working tree was never compared with
    the index there at all. ``check_state_modes`` carries that comparison on
    the base-ref path and does not run without a base, so a state file whose
    recorded executable bit the checkout did not materialise was accepted.
    The comparison runs on the push path in the position check_state_modes
    occupies on the other one — after every check that existed before it."""

    candidate = base_repository(tmp_path)
    git(
        candidate.root,
        "update-index",
        "--chmod=+x",
        "--",
        CHAIN_SPEC.prefix_relative.as_posix(),
    )

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "candidate working tree mode for ledger/immutable_prefix.json "
        "disagrees with its index entry (100755 vs 100644)"
    )


def test_the_tracked_state_refusal_precedes_pre_existing_row_refusals(
    tmp_path: pathlib.Path,
) -> None:
    """The precedence R5-F3 introduces, stated in the module docstring and
    pinned here: like the checkout guard, the entry check says a comparison
    cannot be made and so runs ahead of the checks that would make it — the
    only other place a refusal added after the extraction pre-empts one the
    upstream gate gives. The same tree carries a row the upstream verifier
    refuses in its own words, and that refusal is what fires once the ledger
    is tracked again."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, responseArchive={"sha256": "not-a-digest"})
    relative = CHAIN_SPEC.state_relative.as_posix()
    git(candidate.root, "rm", "--cached", "--quiet", "--", relative)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        f"state path {relative} is absent from the candidate index"
    )

    git(candidate.root, "add", "--", relative)
    with pytest.raises(AppendError) as pre_existing:
        run_gate(candidate)
    assert "responseArchive.sha256 is not a SHA-256 hex digest" in str(
        pre_existing.value
    )


def stage_release_gitlink(candidate: Candidate) -> None:
    """Record a gitlink under ``releases/`` that nothing has checked out.

    An empty or uninitialised submodule directory is the ordinary state of a
    fresh checkout, and it is the case the filesystem walk cannot see at all:
    there is no directory on disk to skip, and no file to enumerate.
    """

    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{candidate.base},releases/vendor",
    )


def test_a_gitlink_under_the_release_root_is_refused_against_a_base(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R5-F4: the release root's content was taken from a walk.

    ``_working_release_files`` enumerates the release tree from the
    filesystem and skips directories, so an uninitialised gitlink under
    ``releases/`` is in neither the current files nor the new files. The
    release-proposal rules assert the release root holds exactly what that
    walk found, while the index records a boundary into another repository
    inside it — and on the data path no refusal spoke for the difference.
    The base-tree scan refuses a non-regular mode only once such an entry is
    in the base; this is the same entry, in the candidate.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    stage_release_gitlink(candidate)
    # The walk really is blind to it: nothing exists at that path on disk.
    assert not (candidate.root / "releases" / "vendor").exists()

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "release root carries an unsupported index entry: "
        "releases/vendor (160000)"
    )


def test_a_gitlink_under_the_release_root_is_refused_on_the_push_path(
    tmp_path: pathlib.Path,
) -> None:
    """R5-F4 on the push path, which runs none of the base-tree comparisons
    and, with no chain to verify, returned before looking at the release root
    at all. The scan runs there ahead of that early return."""

    candidate = base_repository(tmp_path)
    stage_release_gitlink(candidate)

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "release root carries an unsupported index entry: "
        "releases/vendor (160000)"
    )


def test_a_release_directory_the_index_holds_an_entry_for_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """R5-F4's other half: a directory the walk does find, standing where the
    index records a file. The mode scan calls that entry supported, because
    100644 is supported; what is wrong is that the working tree does not hold
    a file there, and the walk skipped it in silence. A populated gitlink is
    the same shape with an unsupported mode, and the scan above catches
    that."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    blob = git(candidate.root, "hash-object", "-w", "releases/README.md")
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},releases/vendor",
    )
    (candidate.root / "releases" / "vendor").mkdir()

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "release path is a directory with an index entry: "
        "releases/vendor (100644)"
    )


def test_file_level_release_refusals_precede_the_release_root_index_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """R5-F4's placement, pinned the way the per-file index check's is.

    The release root's index scan is new, so it runs after every comparison
    the release-history pass already made: a tree that both rewrites a base
    release file and stages a gitlink beside it gets the byte refusal the
    upstream verifier gives, which the ledger differential harness pins, not
    the scan's.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.write_text("Rewritten beside a gitlink.\n", encoding="utf-8")
    stage_release_gitlink(candidate)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        f"existing release file bytes changed relative to {candidate.base}: "
        "releases/README.md"
    )


def replace_release_root_with_a_tracked_file(candidate: Candidate) -> None:
    """Stage a regular file where ``releases/`` stood, as a commit may do.

    Git records this perfectly happily: one blob at ``releases``, and every
    path that was under it gone from the index. The working tree then has no
    release directory at all.
    """

    releases = candidate.root / CHAIN_SPEC.release_root_relative
    shutil.rmtree(releases)
    releases.write_text("releases is a file now.\n", encoding="utf-8")
    git(candidate.root, "add", "-A")


def test_the_push_path_refuses_a_tracked_file_standing_for_the_release_root(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R6-F1: the release-root scan returned when the root was not a
    directory, and every other release check on the push path is reached
    through the manifest directory. A commit that replaces ``releases/`` with
    a tracked regular file therefore makes chain initialisation false — there
    is no ``releases/manifests`` to find — and the gate accepted the tree with
    the whole chain gone, naming no release. The index says otherwise, and is
    now read against the filesystem: an entry under the root with no
    directory to hold it refuses."""

    candidate = base_repository(tmp_path)
    replace_release_root_with_a_tracked_file(candidate)
    # The manifest directory really is unreachable, which is what made this
    # an acceptance rather than a refusal.
    assert not (candidate.root / CHAIN_SPEC.manifest_relative).is_dir()

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "release root is not a directory while the index records 1 entry "
        "under it"
    )


def test_a_tracked_file_standing_for_the_release_root_is_refused_with_a_base(
    tmp_path: pathlib.Path,
) -> None:
    """R6-F1 on the base-ref path, where a pre-existing refusal gets there
    first and must keep doing so: ``_working_release_files`` enumerates the
    release tree before any of this PR's checks and refuses a root that is
    not a real directory in the words the extraction gave it. The reconciled
    scan is asserted directly on the same tree, so both are bound and the
    order between them is pinned."""

    candidate = base_repository(tmp_path)
    replace_release_root_with_a_tracked_file(candidate)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "releases must be a real directory, not a symlink"
    with pytest.raises(ReleaseChainError) as scanned:
        release_chain.assert_release_root_index_regular(candidate.root, CHAIN_SPEC)
    assert str(scanned.value) == (
        "release root is not a directory while the index records 1 entry "
        "under it"
    )


def test_the_push_path_refuses_a_release_entry_the_working_tree_lost(
    tmp_path: pathlib.Path,
) -> None:
    """R6-F1's other direction: a stage-0 regular entry the filesystem walk
    cannot find. ``_working_release_files`` derives the release files from the
    working tree, so a release file deleted from disk — or never materialised,
    as a sparse checkout leaves it — was simply not among them, and the push
    path, which makes no base comparison, had nothing that would notice. The
    index records the commit under review; every entry it holds must be on
    disk as a regular file."""

    candidate = base_repository(tmp_path)
    (candidate.root / CHAIN_SPEC.release_root_relative / "README.md").unlink()

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "release file recorded in the index is absent or not a regular file: "
        "releases/README.md"
    )


def test_a_release_entry_the_working_tree_lost_is_refused_against_a_base(
    tmp_path: pathlib.Path,
) -> None:
    """R6-F1 on the base-ref path, for an entry the base does not carry: a
    release file staged by the proposal and then removed from the working
    tree. A base release file removed the same way already had a refusal —
    the per-file loop says it was deleted relative to the base — but this one
    is in neither the base tree nor the walk, so it was in ``new_files``
    nowhere and no release-proposal rule was ever applied to it."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    extra = candidate.root / CHAIN_SPEC.release_root_relative / "extra.md"
    extra.write_text("staged, then removed from the working tree.\n", encoding="utf-8")
    git(candidate.root, "add", "--", "releases/extra.md")
    extra.unlink()

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "release file recorded in the index is absent or not a regular file: "
        "releases/extra.md"
    )


def test_a_ledger_rewritten_during_the_prefix_re_check_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R6-F2: the closing re-checks were sequential, one per file.

    The ledger was re-checked, then the frozen prefix, and nothing looked at
    the ledger again — so a writer that waits for the ledger's re-check to
    return and rewrites the ledger while the prefix is being re-checked gets
    an acceptance. The verdict then reports a row count, a prefix hash, an
    append count, and a release index measured on a ledger the tree no longer
    holds, with the last look at that file taken before the rewrite.

    The re-check now runs the files forwards and then backwards — ledger,
    prefix, prefix, ledger — so the rewrite is seen by the ledger's second
    re-read. The recorded call order is asserted because it is the whole
    point: the mutation lands strictly after a ledger re-check that passed,
    which is exactly the run the old order accepted.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = CHAIN_SPEC.state_relative.as_posix()
    prefix = CHAIN_SPEC.prefix_relative.as_posix()
    read = append_gate._read_state_snapshot
    asked: list[str] = []

    def read_then_rewrite(
        relative: pathlib.PurePosixPath, tree: Any
    ) -> append_gate._StateSnapshot:
        asked.append(relative.as_posix())
        snapshot = read(relative, tree)
        # The second time the prefix is asked for is the first prefix
        # re-check, which is after the ledger's own re-check has returned.
        if relative.as_posix() == prefix and asked.count(prefix) == 2:
            write_ledger(
                candidate.root,
                [observation_row(number) for number in range(1, BASE_ROW_COUNT + 3)],
            )
        return snapshot

    monkeypatch.setattr(append_gate, "_read_state_snapshot", read_then_rewrite)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file changed during verification: "
        "ledger/official_observations.jsonl"
    )
    assert asked == [ledger, prefix, ledger, prefix, prefix, ledger]
    # The rewrite really landed, and really was a different ledger.
    written = candidate.root / CHAIN_SPEC.state_relative
    assert len(written.read_text(encoding="utf-8").splitlines()) == BASE_ROW_COUNT + 2


def test_a_state_parent_exchanged_after_the_snapshot_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R6-F3: the closing re-check compared the leaf and nothing else.

    Device, inode, size, modification time and change time are all
    properties of the file, not of where it is, so a candidate can exchange
    ``ledger/`` for a different directory holding a hard link to the same
    inode and every one of them still agrees. The bytes agree too. What has
    changed is the directory the state path resolves through — the thing the
    component walk and the descriptor walk exist to pin — and afterwards the
    candidate owns it: the next run, and every reader that is not this one,
    follows the new parent.

    The snapshot now records the identity of every directory descriptor the
    walk opened, and the re-check compares those as well. The assertions
    below show that nothing else could have refused: the leaf's whole stat
    and its bytes are what they were, and only the parent's inode moved.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    directory = candidate.root / "ledger"
    ledger = candidate.root / CHAIN_SPEC.state_relative
    twin = tmp_path / "twin"
    twin.mkdir()
    for name in ("official_observations.jsonl", "immutable_prefix.json"):
        # Linked before the run, so the change time the link bumps is already
        # the one the snapshot records.
        os.link(directory / name, twin / name)
    payload = ledger.read_bytes()
    before = ledger.stat()
    directory_before = directory.stat().st_ino
    checked = append_gate.check_rows

    def exchange(lines: list[str], prefix_count: int, spec: AppendGateSpec) -> None:
        checked(lines, prefix_count, spec)
        shutil.move(str(directory), str(tmp_path / "real-ledger"))
        shutil.move(str(twin), str(directory))

    monkeypatch.setattr(append_gate, "check_rows", exchange)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file changed during verification: "
        "ledger/official_observations.jsonl"
    )
    after = ledger.stat()
    assert ledger.read_bytes() == payload
    assert (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) == (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    assert directory.stat().st_ino != directory_before


def test_check_state_modes_takes_the_mode_from_the_snapshot(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R6-F3's other half: the base mode comparison resolved the state
    path all over again to read its mode, so what it compared was about
    whatever the name reached by then rather than about the file this run
    read — and the index comparison after it resolved the name a third time.
    Here every ``Path.stat`` and ``Path.lstat`` of the ledger reports an
    executable bit the file does not carry. Through the gate the snapshot's
    own ``fstat`` is what answers and the ordinary verdict stands; called on
    its own, with no snapshot to take, the same function believes the lie and
    refuses. The tree is identical in both, so the difference is only where
    the mode came from. (Both reads are made to lie because R7-F5 moved that
    fallback from ``stat`` to ``lstat``, which is the read that can also tell
    a link from a file.)"""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root.resolve() / CHAIN_SPEC.state_relative

    def executable(observed: os.stat_result) -> os.stat_result:
        return os.stat_result((observed.st_mode | 0o111, *tuple(observed)[1:]))

    real_stat = pathlib.Path.stat
    real_lstat = pathlib.Path.lstat

    def lying_stat(self: pathlib.Path, **keywords: Any) -> os.stat_result:
        observed = real_stat(self, **keywords)
        if os.fspath(self) != os.fspath(ledger):
            return observed
        return executable(observed)

    def lying_lstat(self: pathlib.Path, *arguments: Any) -> os.stat_result:
        observed = real_lstat(self, *arguments)
        if os.fspath(self) != os.fspath(ledger):
            return observed
        return executable(observed)

    monkeypatch.setattr(pathlib.Path, "stat", lying_stat)
    monkeypatch.setattr(pathlib.Path, "lstat", lying_lstat)

    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )
    with selected_tree(candidate) as tree, pytest.raises(AppendError) as refusal:
        append_gate.check_state_modes(
            append_gate._BaseCommit(ref=candidate.base, commit=candidate.base),
            tree,
        )
    assert str(refusal.value) == (
        "state file mode changed relative to base: "
        "ledger/official_observations.jsonl"
    )


def test_state_reads_refuse_a_platform_without_secure_descent(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R6-F4: the descriptor walk fell back to the pathname open where
    ``os.open`` takes no ``dir_fd``, which is the behaviour every check in
    that walk exists to replace — the whole path resolved a second time, with
    the walk's findings about the parents already stale, and no refusal
    anywhere saying the confinement had lapsed. A verifier that quietly
    weakens itself on some platforms states an invariant it does not hold
    there. It now says it cannot read the state files instead. Both readers
    go through the same helper, so both say it.

    The message also names the requirement as the package's, which is S4-F6:
    ``release_chain``'s reader is the one ``verify_release_chain`` uses, so
    the same refusal stops ``receipt verify``'s custody pass and not only
    this gate."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    without_open = frozenset(os.supports_dir_fd) - {os.open}
    monkeypatch.setattr(os, "supports_dir_fd", without_open)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state files cannot be read with secure descent on this platform "
        "(os.open lacks dir_fd support); receipt requires a POSIX platform"
    )
    with pytest.raises(ReleaseChainError) as read:
        _regular_file_bytes(candidate.root, CHAIN_SPEC.state_relative)
    assert str(read.value) == (
        "state files cannot be read with secure descent on this platform "
        "(os.open lacks dir_fd support); receipt requires a POSIX platform"
    )


def test_a_root_that_is_not_the_recorded_one_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R6-F4's other half: the candidate root was the one component of every
    state path that nothing vouched for. The walk below it starts at the root
    and checks what it finds *inside* it, and the descriptor open took the
    root by name with neither ``O_NOFOLLOW`` nor an identity check — so a
    root exchanged for another directory, or for a link to one, was simply
    the tree every subsequent read descended from. ``_set_root`` records the
    resolved root's identity once, and every descent compares against it.
    Here the recorded identity is made to differ from the root on disk; the
    same tree with the identity it really has gets the ordinary verdict, so
    the comparison is what refused."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    real_set_root = append_gate._set_root

    def misrecord(root: pathlib.Path, spec: AppendGateSpec) -> Any:
        tree = real_set_root(root, spec)
        device, inode = tree.root_identity
        return replace(tree, root_identity=(device, inode + 1))

    monkeypatch.setattr(append_gate, "_set_root", misrecord)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "candidate root changed during verification"

    monkeypatch.undo()
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_a_root_relinked_between_the_two_state_reads_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R6-F4 driven by an actual swap rather than a recorded one: the root is
    moved aside and a symlink left in its place after the ledger has been
    read and before the frozen prefix is. Every git command still resolves,
    the component walk still finds real directories inside the root — it
    never looks at the root itself — and before this round the prefix was
    read through the link without complaint. The root open now refuses to
    follow it, and for a caller that recorded the root that is the same
    answer as an identity that does not match."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    checked = append_gate.reject_non_append_bytes

    def relink_root(text: str) -> None:
        checked(text)
        moved = tmp_path / "real-candidate"
        shutil.move(str(candidate.root), str(moved))
        candidate.root.symlink_to(moved, target_is_directory=True)

    monkeypatch.setattr(append_gate, "reject_non_append_bytes", relink_root)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "candidate root changed during verification"
    # The link really is there, and really does still resolve to the tree.
    assert candidate.root.is_symlink()
    assert (candidate.root / CHAIN_SPEC.prefix_relative).is_file()


def test_the_index_comparison_uses_a_category_the_caller_supplies(
    tmp_path: pathlib.Path,
) -> None:
    """R6-F3 at the comparison itself. ``assert_index_agrees_with_tree`` read
    the working tree by resolving the path, which for a state file is a
    resolution after the read that established the file and after the mode
    comparison that precedes this call. It takes an already-observed category
    instead when the caller has one. Here the tree carries an executable bit
    the index does not record, so resolving the path refuses; supplied the
    category a descriptor observed, the same call compares that and returns.
    A caller that supplies nothing — every caller that predates the parameter
    — gets the first behaviour, which is the one asserted first."""

    candidate = base_repository(tmp_path)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.chmod(ledger.stat().st_mode | 0o111)

    with pytest.raises(ReleaseChainError) as refusal:
        release_chain.assert_index_agrees_with_tree(
            candidate.root, CHAIN_SPEC.state_relative
        )
    assert str(refusal.value) == (
        "candidate working tree mode for ledger/official_observations.jsonl "
        "disagrees with its index entry (100644 vs 100755)"
    )
    release_chain.assert_index_agrees_with_tree(
        candidate.root, CHAIN_SPEC.state_relative, observed="100644"
    )


def test_the_push_paths_index_comparison_takes_the_snapshots_category(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R6-F3 at the push path's own call site, which is the only index
    comparison that path makes: it resolved the state path once more, after
    the read that had the file open. Every ``Path.lstat`` of the ledger here
    reports an executable bit the file does not carry — what that second
    resolution could be shown — and the gate answers ordinarily, because the
    category comes from the snapshot. Asked to resolve the path itself, the
    same comparison on the same tree refuses."""

    candidate = base_repository(tmp_path)
    ledger = candidate.root.resolve() / CHAIN_SPEC.state_relative
    real_lstat = pathlib.Path.lstat

    def lying_lstat(self: pathlib.Path, *arguments: Any) -> os.stat_result:
        observed = real_lstat(self, *arguments)
        if os.fspath(self) != os.fspath(ledger):
            return observed
        return os.stat_result((observed.st_mode | 0o111, *tuple(observed)[1:]))

    monkeypatch.setattr(pathlib.Path, "lstat", lying_lstat)

    assert run_push_gate(candidate) == (
        "thesis-facts append check OK: 2 rows, immutable prefix 1"
    )
    with pytest.raises(ReleaseChainError) as refusal:
        release_chain.assert_index_agrees_with_tree(
            candidate.root, CHAIN_SPEC.state_relative
        )
    assert str(refusal.value) == (
        "candidate working tree mode for ledger/official_observations.jsonl "
        "disagrees with its index entry (100644 vs 100755)"
    )


def commit_all(candidate: Candidate, message: str) -> Candidate:
    """Commit the working tree and return the candidate rebased on it."""

    git(candidate.root, "add", "-A")
    git(candidate.root, "commit", "--quiet", "-m", message)
    return replace(candidate, base=git(candidate.root, "rev-parse", "HEAD"))


def test_the_index_is_asked_about_a_path_not_a_pattern(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R7-F6: every index read passed the path to git as a bare
    pathspec, which is a *pattern*. ``releases/x[y]z.md`` is a legitimate
    filename and a glob at the same time, so the read about it also returned
    the sibling ``releases/xyz.md`` that the bracket expression matches —
    entries for a path the caller never asked about, kept out of the two
    exact-path checks only by their own ``listed == path`` filter and not
    kept out of the release root's scan at all, which has no single path to
    filter on. Without the literal pathspec the first assertion here gets
    two records instead of one.

    The missing-entry direction is bound by the two tests below; git compares
    an exact pathspec literally before it tries the pattern, so a bracketed
    name is still found today and this file's own checks pass either way.
    They are asserted so the literal pathspec is pinned as not having lost
    the ordinary match — including through the gate, where the release
    history now requires every base release file to still be in the index."""

    candidate = base_repository(tmp_path)
    releases = candidate.root / CHAIN_SPEC.release_root_relative
    (releases / "x[y]z.md").write_text("bracketed\n", encoding="utf-8")
    (releases / "xyz.md").write_text("what the bracket matches\n", encoding="utf-8")
    candidate = commit_all(candidate, "release files with glob magic in a name")
    append_one_row(candidate)

    assert release_chain._index_entries(candidate.root, "releases/x[y]z.md") == [
        ("100644", "0", "releases/x[y]z.md", False)
    ]
    release_chain.assert_index_agrees_with_tree(candidate.root, "releases/x[y]z.md")
    release_chain.assert_state_path_tracked(candidate.root, "releases/x[y]z.md")
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


MAGIC_STATE_PATH = ":odd/official_observations.jsonl"


def track_a_path_git_reads_as_magic(candidate: Candidate) -> pathlib.Path:
    """Commit a file whose first character git parses as pathspec magic.

    ``:odd/x`` asked of ``git ls-files`` is not that path: the leading colon
    introduces pathspec magic, the unrecognised ``o`` ends it, and git looks
    for ``odd/x`` instead — matching nothing, exiting zero, and reporting a
    tracked file as absent from the index.
    """

    path = candidate.root / MAGIC_STATE_PATH
    path.parent.mkdir()
    path.write_text("tracked, whatever the pathspec parser makes of it\n")
    git(candidate.root, "add", "-A")
    return path


def test_a_state_path_git_would_read_as_pathspec_magic_is_tracked(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R7-F6 in the direction that refuses: a path the index does hold,
    reported as absent because git read its name as a pathspec instruction
    rather than as a name. Without the literal pathspec this refuses
    ``state path :odd/official_observations.jsonl is absent from the
    candidate index`` — a tracked file the gate declines to verify."""

    candidate = base_repository(tmp_path)
    track_a_path_git_reads_as_magic(candidate)

    release_chain.assert_state_path_tracked(candidate.root, MAGIC_STATE_PATH)


def test_the_index_comparison_finds_a_path_git_would_read_as_magic(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R7-F6 in the direction that accepts, which is the dangerous one:
    the same misread name leaves ``assert_index_agrees_with_tree`` with no
    entry to compare, and no entry is how a new untracked file looks — so it
    returns, and a working tree that does not carry what git recorded passes
    the check written to catch exactly that. Without the literal pathspec
    this raises nothing at all."""

    candidate = base_repository(tmp_path)
    path = track_a_path_git_reads_as_magic(candidate)
    path.chmod(0o755)

    with pytest.raises(ReleaseChainError) as refusal:
        release_chain.assert_index_agrees_with_tree(candidate.root, MAGIC_STATE_PATH)
    assert str(refusal.value) == (
        f"candidate working tree mode for {MAGIC_STATE_PATH} disagrees with "
        "its index entry (100644 vs 100755)"
    )


def test_a_base_release_file_dropped_from_the_index_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R7-F1: the release-history pass compared the base against the
    working tree and asked the index only whether it disagreed with what was
    on disk. ``git rm --cached`` produces no disagreement — it leaves the
    file exactly where it was, byte-identical and at the base's mode, and
    removes only the entry that makes it part of the commit under review, at
    which point the agreement check has no entry to compare and returns. So
    the mode matched, the bytes matched, the proposal was accepted, and
    merging it deletes a release manifest, receipt, or signature this package
    calls immutable. Without the new check this tree gets the ordinary
    acceptance below."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(candidate.root, "rm", "--cached", "--quiet", "--", "releases/README.md")
    # Nothing on disk moved: that is the whole point of the case.
    assert (candidate.root / "releases" / "README.md").read_text(
        encoding="utf-8"
    ) == "Release journal for the fixture ledger.\n"

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "existing release file was removed from the candidate index: "
        "releases/README.md"
    )


def test_a_base_release_file_still_indexed_is_left_alone(
    tmp_path: pathlib.Path,
) -> None:
    """R7-F1's other half, and the reason the check is not a presence test on
    the working tree: an ordinary proposal keeps every base release file in
    the index, so the pass says nothing about them."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)

    release_chain.assert_release_file_still_indexed(
        candidate.root, "releases/README.md"
    )
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_a_gate_only_proposal_whose_index_changes_the_ledger_is_not_gate_only(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R7-F3: surface classification was derived from the working
    tree's diff against the base, and a gate-only match returned on it before
    the ledger, the prefix, the release history, or any mode or index check
    ran. The index is the commit under review, and it can differ: here it
    records the ledger executable while the working tree carries 100644 and
    only the gate script has changed on disk. Without the index's own changed
    set the proposal classifies as gate-only and is accepted with
    ``GATE_SURFACE changes=['scripts/check_append.py']``, carrying a ledger
    mode change no check ever saw. With it the ledger is a DATA change beside
    a GATE change, which is a mixed proposal, refused in the words the
    working-tree classification has always used for one."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    git(
        candidate.root,
        "update-index",
        "--chmod=+x",
        "--",
        CHAIN_SPEC.state_relative.as_posix(),
    )
    # The working tree really does look gate-only: git diff against the base
    # names the ledger nowhere.
    assert "official_observations" not in git(
        candidate.root, "diff", "--name-only", candidate.base, "--"
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "mixed data/gate proposal is forbidden: DATA_SURFACE changes="
        "['ledger/official_observations.jsonl']; GATE_SURFACE changes="
        "['scripts/check_append.py']; split them into separate pull requests"
    )


def test_a_data_proposal_whose_index_carries_a_gate_change_is_mixed(
    tmp_path: pathlib.Path,
) -> None:
    """R7-F3 from the other side. The working tree carries an ordinary
    append and no gate change; the index records the gate script, written
    straight into it with no file on disk. The commit under review touches
    both surfaces, which is the mixed proposal the working-tree classification
    refuses whenever it can see both halves — and here it sees only one. The
    union sees both, and refuses in the same words, naming the path each side
    carries. Without the index's changed set this ran the data path and
    accepted a data verdict over a commit that also changes the gate."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    blob = git(candidate.root, "hash-object", "-w", "--stdin", stdin="# staged gate\n")
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},{GATE_FILE}",
    )
    assert not (candidate.root / GATE_FILE).exists()
    assert "official_observations" in git(
        candidate.root, "diff", "--name-only", candidate.base, "--"
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "mixed data/gate proposal is forbidden: DATA_SURFACE changes="
        "['ledger/official_observations.jsonl']; GATE_SURFACE changes="
        "['scripts/check_append.py']; split them into separate pull requests"
    )


def test_a_gate_only_proposal_whose_index_rewrites_a_release_file_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """R7-F3 for an unclassified release path, which is the gap the gate-only
    confinement was added to close, one level down: the rewrite is staged and
    then undone on disk, so the working tree matches the base exactly and the
    proposal looks clean. The commit under review still rewrites
    ``releases/README.md``. Without the index's changed set this is accepted
    as a clean gate-only proposal."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    original = readme.read_text(encoding="utf-8")
    readme.write_text("Rewritten in the index alone.\n", encoding="utf-8")
    git(candidate.root, "add", "--", "releases/README.md")
    readme.write_text(original, encoding="utf-8")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "gate-only proposal changes unclassified release path(s): "
        "['releases/README.md']"
    )


def serve_a_release_path_through_a_symlink(
    candidate: Candidate, outside: pathlib.Path
) -> None:
    """Index ``releases/vendor/file.md`` and point ``vendor`` outside the tree.

    The entry is written straight into the index because git will not add a
    path that lies beyond a symlink — which is the whole shape of the case:
    the commit records a release file, and the working tree answers for it
    with a file the checkout does not contain.
    """

    outside.mkdir(parents=True)
    (outside / "file.md").write_text("served from outside the tree\n", encoding="utf-8")
    (candidate.root / CHAIN_SPEC.release_root_relative / "vendor").symlink_to(
        outside, target_is_directory=True
    )
    blob = git(
        candidate.root, "hash-object", "-w", "--stdin", stdin="served from outside\n"
    )
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},releases/vendor/file.md",
    )


def test_an_indexed_release_path_served_through_a_symlink_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R7-F4: the release root's index and its working tree were
    reconciled by asking ``is_file()`` about each indexed path, which resolves
    every component of the name — while the traversal that would have seen
    those components resolves none of them, because ``rglob`` yields a
    symlinked directory without descending it and the scan skips it. So
    ``releases/vendor -> /outside`` served an indexed release file: present,
    regular, and no part of the candidate tree. Without the parent walk the
    push path accepts this tree outright."""

    candidate = base_repository(tmp_path)
    serve_a_release_path_through_a_symlink(candidate, tmp_path / "outside")
    # The name resolves to a regular file, which is exactly what the
    # reconciliation used to ask about.
    assert (candidate.root / "releases" / "vendor" / "file.md").is_file()

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "release path traverses a symlink at 'releases/vendor': "
        "releases/vendor/file.md"
    )


def test_the_enumerations_symlink_refusal_still_comes_first_with_a_base(
    tmp_path: pathlib.Path,
) -> None:
    """R7-F4's placement: on the base-ref path the same tree meets
    ``_working_release_files`` first, which is on ``main`` and refuses the
    link it walks into by name. That refusal is not pre-empted; the new walk
    speaks only for the path no traversal reaches, which is why the push path
    above is where it fires."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    serve_a_release_path_through_a_symlink(candidate, tmp_path / "outside")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "release path is a symlink: releases/vendor"


def test_check_state_modes_refuses_a_symlinked_state_file_on_its_own(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R7-F5: with no snapshot to take, the mode comparison read the
    path with ``stat``, which follows a link. So a ledger replaced by a
    symlink to a non-executable regular file reported that target's 100644,
    compared equal to the base's 100644, and passed — a category change git
    records, synthesised away by the read meant to observe it. The index
    comparison after it does not save the case either: with the link staged,
    the index says 120000 and the working tree holds 120000, which agree.
    Without the ``lstat`` this function returns cleanly on this tree.

    Through the gate the tree never gets this far — a 120000 state entry is
    not a tracked regular file, and the entry check at the top says so, which
    is asserted here as the scope of the finding."""

    candidate = base_repository(tmp_path)
    outside = tmp_path / "outside" / "official_observations.jsonl"
    outside.parent.mkdir()
    ledger = candidate.root / CHAIN_SPEC.state_relative
    outside.write_text(ledger.read_text(encoding="utf-8"), encoding="utf-8")
    ledger.unlink()
    ledger.symlink_to(outside)
    git(candidate.root, "add", "--", CHAIN_SPEC.state_relative.as_posix())

    with selected_tree(candidate) as tree, pytest.raises(AppendError) as refusal:
        append_gate.check_state_modes(
            append_gate._BaseCommit(ref=candidate.base, commit=candidate.base),
            tree,
        )
    assert str(refusal.value) == (
        "state file is a symlink: ledger/official_observations.jsonl"
    )
    with pytest.raises(AppendError) as through_the_gate:
        run_gate(candidate)
    assert str(through_the_gate.value) == (
        "state path ledger/official_observations.jsonl has a non-regular "
        "index entry: 120000"
    )


def test_an_ambient_literal_pathspec_mode_cannot_hide_the_index(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S4-F4: every index read here writes ``:(literal)<path>`` so git
    is asked about the exact path, and ``GIT_LITERAL_PATHSPECS`` in the
    ambient environment makes git take that pathspec *as typed* — the magic
    prefix included. The read then looks for a file literally named
    ``:(literal)ledger/official_observations.jsonl``, matches nothing, and
    exits zero, so the state file the whole verdict is about is reported
    absent from the index and the tracked-state check at entry refuses a
    perfectly ordinary proposal. The gate ran every git read under the
    caller's ambient environment, so any CI job or shell that exports the
    variable turned the checks it was meant to help into a refusal battery.
    Without dropping the variable this raises ``state path
    ledger/official_observations.jsonl is absent from the candidate index``."""

    monkeypatch.setenv("GIT_LITERAL_PATHSPECS", "1")
    candidate = base_repository(tmp_path)
    append_one_row(candidate)

    state_path = CHAIN_SPEC.state_relative.as_posix()
    assert [
        listed
        for _mode, _stage, listed, _intent in release_chain._index_entries(
            candidate.root, state_path
        )
    ] == [state_path]
    release_chain.assert_state_path_tracked(candidate.root, CHAIN_SPEC.state_relative)
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_an_ambient_icase_pathspec_mode_cannot_widen_an_index_read(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S4-F4 from the other direction. ``GIT_ICASE_PATHSPECS`` makes every
    pathspec case-insensitive, so a read about one path answers with records
    for differently spelled siblings: here the index carries both
    ``releases/README.md`` and a ``releases/README.MD`` entry, and the read
    about the first returns both. The checks that ask about exactly one path
    filter the records afterwards and survive that; the release root's scan,
    which reads every record under a directory, does not filter and would
    take in whatever a differently cased sibling directory holds. Without
    dropping the variable ``_index_entries`` returns two records here."""

    monkeypatch.setenv("GIT_ICASE_PATHSPECS", "1")
    candidate = base_repository(tmp_path)
    blob = git(candidate.root, "rev-parse", ":releases/README.md")
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},releases/README.MD",
    )

    assert [
        listed
        for _mode, _stage, listed, _intent in release_chain._index_entries(
            candidate.root, "releases/README.md"
        )
    ] == ["releases/README.md"]


def test_an_ambient_icase_pathspec_mode_leaves_an_ordinary_proposal_alone(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S4-F4 for a proposal with nothing odd in it at all, which is the case
    that shows how wide the variable's reach is: the base tree enumeration
    hands git a plain ``releases`` pathspec, and ``git ls-tree`` does not
    accept icase magic, so with the variable set an ordinary append is
    refused with ``cannot enumerate releases at base <oid>: fatal: releases:
    pathspec magic not supported by this command: 'icase'`` before any
    comparison is made. With the variable dropped the verdict is exactly the
    one the gate always gave."""

    monkeypatch.setenv("GIT_ICASE_PATHSPECS", "1")
    candidate = base_repository(tmp_path)
    append_one_row(candidate)

    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_the_git_environment_drops_every_pathspec_mode(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """S4-F4 at the source. All four variables decide what a pathspec means
    before any command line is read, so all four are dropped and nothing else
    is: the replacement-object setting is still applied and the rest of the
    ambient environment still reaches git."""

    for name in release_chain.PATHSPEC_ENVIRONMENT:
        monkeypatch.setenv(name, "1")
    monkeypatch.setenv("GIT_DIR_FIXTURE_MARKER", "carried through")

    environment = release_chain._git_environment()

    assert set(release_chain.PATHSPEC_ENVIRONMENT) == {
        "GIT_LITERAL_PATHSPECS",
        "GIT_GLOB_PATHSPECS",
        "GIT_NOGLOB_PATHSPECS",
        "GIT_ICASE_PATHSPECS",
    }
    assert not set(environment) & set(release_chain.PATHSPEC_ENVIRONMENT)
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["GIT_DIR_FIXTURE_MARKER"] == "carried through"


def re_add_as_intent_to_add(candidate: Candidate, relative: str) -> None:
    """Drop one tracked path from the index and re-add it with ``git add -N``.

    What is left is an *intent-to-add* entry: stage 0, mode 100644, the empty
    blob's object id and no content. The working tree is untouched throughout,
    so every comparison that reads it agrees with the entry — and a commit
    made from this index deletes the path.
    """

    git(candidate.root, "rm", "--cached", "--quiet", "--", relative)
    git(candidate.root, "add", "-N", "--", relative)


def test_an_intent_to_add_index_entry_is_readable_as_such(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F3 at the parse. ``git ls-files -s`` gives an intent-to-add
    entry as ``100644 <empty blob> 0``, which is exactly what an ordinary
    tracked file with the same content looks like — and an empty file really
    does carry that object id, so the object id is no test either. The flag
    word ``git ls-files --debug`` prints is: ``CE_INTENT_TO_ADD`` is set for
    one and clear for the other. Without reading it the two records here are
    indistinguishable."""

    candidate = base_repository(tmp_path)
    state_path = CHAIN_SPEC.state_relative.as_posix()
    empty = candidate.root / "releases" / "empty.md"
    empty.write_text("", encoding="utf-8")
    git(candidate.root, "add", "--", "releases/empty.md")
    re_add_as_intent_to_add(candidate, state_path)

    (intent_mode, intent_stage, _path, intent) = release_chain._index_entries(
        candidate.root, state_path
    )[0]
    (empty_mode, empty_stage, _empty_path, empty_intent) = release_chain._index_entries(
        candidate.root, "releases/empty.md"
    )[0]
    # Same mode, same stage, same object id — and only one of them records
    # anything.
    assert (intent_mode, intent_stage) == (empty_mode, empty_stage) == ("100644", "0")
    assert git(candidate.root, "rev-parse", f":{state_path}") == git(
        candidate.root, "rev-parse", ":releases/empty.md"
    )
    assert intent is True
    assert empty_intent is False


@pytest.mark.parametrize("with_base", [True, False], ids=["base-ref", "push"])
def test_an_intent_to_add_state_entry_is_refused(
    tmp_path: pathlib.Path, with_base: bool
) -> None:
    """Binds S4-F3 for the two files the whole verdict is about. ``git rm
    --cached`` of the ledger followed by ``git add -N`` of it leaves a stage-0
    100644 entry at the path, so the tracked-state check found an entry, the
    mode was supported, and the working tree carried exactly what the entry
    claimed — while the entry records no content and the commit under review
    deletes the ledger. Without the flag read this proposal is accepted on
    both paths."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    state_path = CHAIN_SPEC.state_relative.as_posix()
    re_add_as_intent_to_add(candidate, state_path)
    # git itself calls the entry a modification of a tracked path, which is
    # the disguise: nothing an index read returns says the content is gone.
    assert f"M\t{state_path}" in git(
        candidate.root, "diff-index", "--cached", "--name-status", "HEAD"
    ).splitlines()

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate) if with_base else run_push_gate(candidate)
    assert str(refusal.value) == (
        f"index entry for {state_path} is intent-to-add and records no content"
    )


def test_an_intent_to_add_state_entry_keeps_the_earlier_refusals(
    tmp_path: pathlib.Path,
) -> None:
    """S4-F3's placement inside the tracked-state check: last, after absent,
    unmerged and non-regular, because a 100644 stage-0 entry has already
    answered all three and there is nothing else left to say about it. An
    intent-to-add entry is not always 100644 — ``git add -N`` records the
    working tree's type, so a state path replaced by a symlink and re-added
    that way is an intent-to-add 120000 entry — and that is the refusal that
    fires, in the words it already had."""

    candidate = base_repository(tmp_path)
    state_path = CHAIN_SPEC.state_relative.as_posix()
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.unlink()
    ledger.symlink_to(tmp_path / "elsewhere.jsonl")
    re_add_as_intent_to_add(candidate, state_path)
    assert release_chain._index_entries(candidate.root, state_path) == [
        ("120000", "0", state_path, True)
    ]

    with pytest.raises(ReleaseChainError) as refusal:
        release_chain.assert_state_path_tracked(
            candidate.root, CHAIN_SPEC.state_relative
        )
    assert str(refusal.value) == (
        f"state path {state_path} has a non-regular index entry: 120000"
    )


def test_an_intent_to_add_base_release_entry_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F3 for a base release file. The still-indexed check refuses a
    path ``git rm --cached`` removed outright; ``git add -N`` puts an entry
    back where that check looks, at the mode and stage it requires, so the
    removal was hidden behind an entry recording nothing. The release file is
    still on disk and byte-identical, so neither byte nor mode comparison
    above says anything. Without the flag read this proposal is accepted."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    re_add_as_intent_to_add(candidate, "releases/README.md")
    assert (candidate.root / "releases" / "README.md").read_text(
        encoding="utf-8"
    ) == "Release journal for the fixture ledger.\n"

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "index entry for releases/README.md is intent-to-add and records no "
        "content"
    )


def test_an_intent_to_add_base_release_entry_keeps_the_byte_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """S4-F3's placement in the release-history pass: the new refusal sits
    after every comparison for that path, so a proposal that also rewrites
    the file's bytes gets the byte refusal the upstream verifier gives, not
    this one."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.write_text("Rewritten as well.\n", encoding="utf-8")
    re_add_as_intent_to_add(candidate, "releases/README.md")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        f"existing release file bytes changed relative to {candidate.base}: "
        "releases/README.md"
    )


def test_an_intent_to_add_release_path_is_refused_by_the_root_scan(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F3 for a release path the base does not carry, which no
    per-file comparison reaches: ``git add -N`` under ``releases/`` records a
    stage-0 100644 entry for a file the reconciliation then finds on disk, so
    the index and the working tree were called agreed over an entry holding
    nothing. The root scan reads the flag beside the mode. Without it the
    push path accepts this tree outright."""

    candidate = base_repository(tmp_path)
    (candidate.root / "releases" / "NOTES.md").write_text(
        "release notes\n", encoding="utf-8"
    )
    git(candidate.root, "add", "-N", "--", "releases/NOTES.md")

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "index entry for releases/NOTES.md is intent-to-add and records no "
        "content"
    )


def index_a_second_spelling(candidate: Candidate, spelling: str) -> None:
    """Record a second index entry for one release file, spelled differently.

    Written straight into the index because there is only one file: git
    cannot be asked to add a name the directory does not hold, and on a
    case-insensitive filesystem it could not hold both anyway. That is the
    shape of the case — two committed release objects, one file to answer for
    them.
    """

    blob = git(candidate.root, "rev-parse", ":releases/README.md")
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},{spelling}",
    )
    assert sorted(
        path.name for path in (candidate.root / "releases").iterdir()
    ) == ["README.md"]


def test_a_second_cased_spelling_of_a_release_entry_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F2: the release root's index was reconciled with the working
    tree by asking ``is_file()`` about each indexed path, which is a question
    the *filesystem* answers. Where names are compared case-insensitively —
    APFS and HFS+ by default, and any case-insensitive mount — it answers
    about whatever entry it considers the same name, so ``releases/README.MD``
    and
    ``releases/README.md`` — two entries the commit carries, two release
    objects — were both answered by the one file on disk. One of them was in
    no enumeration, was never byte- or mode-verified, and the reconciliation
    reported the index and the working tree in agreement. The walk's own
    spelling decides instead: it yields ``releases/README.md`` and nothing
    else, so the other entry is absent under its own spelling.

    On a case-insensitive filesystem this fails without the fix, because
    ``is_file()`` says yes; on a case-sensitive one the entry was already
    absent and the same refusal was already given. The refusal is the same
    sentence on both, which is the point — the verdict does not depend on
    which filesystem the auditor cloned onto."""

    candidate = base_repository(tmp_path)
    index_a_second_spelling(candidate, "releases/README.MD")

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "release file recorded in the index is absent or not a regular file: "
        "releases/README.MD"
    )


def test_a_second_normalisation_of_a_release_entry_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """S4-F2 for Unicode normalisation, which is the same hole without any
    change of case: APFS and HFS+ compare names normalisation-insensitively,
    so an index entry spelled NFD (``e`` + U+0301) resolves to the NFC file
    on disk and ``is_file()`` says yes. Two entries, two release objects, one
    file answering for both. The walk spells the file one way, and the entry
    that is not that spelling is absent.

    As above: without the fix this fails where names are compared
    insensitively and passes where they are not, and with it the refusal is
    the same sentence everywhere."""

    candidate = base_repository(tmp_path)
    composed = "réadme.md"
    decomposed = unicodedata.normalize("NFD", composed)
    assert composed != decomposed
    (candidate.root / "releases" / composed).write_text("r\n", encoding="utf-8")
    candidate = commit_all(candidate, "a release file with a composed name")
    # git records the name the directory holds; the decomposed spelling is a
    # different string, and only the index carries it.
    tracked = git(candidate.root, "ls-files", "-z").split("\0")
    assert f"releases/{composed}" in tracked
    blob = git(candidate.root, "rev-parse", f":releases/{composed}")
    # ``core.precomposeunicode`` — on by default where the filesystem
    # decomposes — would rewrite the decomposed pathname on this command line
    # back to the composed one, so the entry is written with it off. That is
    # what a history authored where the two names are distinct files looks
    # like once it is cloned onto a filesystem where they are not: two
    # entries checked out over one file.
    git(
        candidate.root,
        "-c",
        "core.precomposeunicode=false",
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},releases/{decomposed}",
    )
    assert sorted(
        entry for entry in git(candidate.root, "ls-files", "-z").split("\0") if entry
    ) == [
        "ledger/immutable_prefix.json",
        "ledger/official_observations.jsonl",
        "releases/README.md",
        f"releases/{decomposed}",
        f"releases/{composed}",
    ]

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "release file recorded in the index is absent or not a regular file: "
        f"releases/{decomposed}"
    )


def test_a_second_spelling_is_refused_against_a_base_as_well(
    tmp_path: pathlib.Path,
) -> None:
    """S4-F2 on the other path. The release-history pass compares every base
    release file and finds nothing wrong — the one file on disk is
    byte-identical and at the base's mode — and the root's scan, which runs
    after all of it, is where the second entry is named."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    index_a_second_spelling(candidate, "releases/README.MD")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "release file recorded in the index is absent or not a regular file: "
        "releases/README.MD"
    )


def a_replacement_repository(
    candidate: Candidate, tmp_path: pathlib.Path
) -> pathlib.Path:
    """A second checkout of the candidate, ready to be moved into its place.

    Copied from it, so every OID this run has already resolved still exists
    in the replacement and git answers about it exactly as it would about the
    original — which an unrelated repository would not, and which is what
    makes a swapped root produce a *verdict* rather than an error.
    """

    replacement = tmp_path / "replacement"
    shutil.copytree(candidate.root, replacement, symlinks=True)
    return replacement


def move_a_repository_into_the_root(
    candidate: Candidate, replacement: pathlib.Path
) -> None:
    """Rename the candidate root aside and put ``replacement`` at its path."""

    candidate.root.rename(candidate.root.parent / "moved-aside")
    replacement.rename(candidate.root)


def test_a_gate_only_verdict_is_bound_to_the_recorded_root(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S4-F1: ``_set_root`` records the resolved root's identity, and
    the only thing that ever compared it against what the name resolves to
    now is the descriptor walk a state read performs. A gate-only proposal
    performs none — it classifies the changed sets and returns — so the whole
    branch ran without the recorded root being consulted once. Here the root
    is renamed aside and another repository is moved into its place after the
    classification, exactly where nothing looked; without the check the run
    returns the ordinary gate-only acceptance for a tree it never selected,
    and the tree it is standing in is one the same gate would refuse."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    replacement = a_replacement_repository(candidate, tmp_path)
    # Its first row is not the frozen one, so a run that really did read this
    # tree would refuse it — the acceptance is not merely about the wrong
    # tree, it is about a tree this gate rejects.
    rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 1)]
    rows[0] = observation_row(99)
    write_ledger(replacement, rows)
    staged = append_gate._staged_surface_changes

    def swap_after_classifying(
        base: append_gate._BaseCommit, tree: append_gate._CandidateTree
    ) -> tuple[set[str], set[str], set[str]]:
        classified = staged(base, tree)
        move_a_repository_into_the_root(candidate, replacement)
        return classified

    monkeypatch.setattr(append_gate, "_staged_surface_changes", swap_after_classifying)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "candidate root changed during verification"


def test_the_classification_is_bound_to_the_recorded_root_too(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S4-F1's other call. The checkout guard and the tracked-state check run
    before any classification and reach the tree by name, so a root exchanged
    between ``_set_root`` and the surface probes has those two answered by
    the tree that was selected and everything after them answered by a
    replacement — one verdict assembled from two repositories. The
    classification decides which path the whole run takes, so it is bound to
    the recorded root as well. Here the replacement carries the candidate's
    data change *and* a gate script, so without the check the surface probes
    classify it and the run refuses it as a mixed proposal — a refusal about
    a tree that was never under review, naming files the selected one does
    not contain."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    replacement = a_replacement_repository(candidate, tmp_path)
    script = replacement / GATE_FILE
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("# gate fixture\n", encoding="utf-8")
    assert not (candidate.root / GATE_FILE).exists()
    tracked = append_gate.assert_state_path_tracked
    swapped = False

    def swap_after_the_last_state_path(
        root: pathlib.Path, relative: pathlib.PurePosixPath
    ) -> None:
        nonlocal swapped
        tracked(root, relative)
        if relative == CHAIN_SPEC.prefix_relative and not swapped:
            swapped = True
            move_a_repository_into_the_root(candidate, replacement)

    monkeypatch.setattr(
        append_gate, "assert_state_path_tracked", swap_after_the_last_state_path
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert swapped
    assert str(refusal.value) == "candidate root changed during verification"


@pytest.mark.skipif(
    os.getuid() == 0, reason="root traverses a directory it has no rights on"
)
def test_a_search_only_state_directory_is_descended_where_the_platform_allows(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F5: the descriptor walk opened every directory above a state
    file with ``O_RDONLY | O_DIRECTORY``, which asks for read permission the
    pathname open it replaced never needed. A POSIX search-only directory —
    mode 0o111, traversable but not listable, which is how a directory above
    a published state file is often locked down — was read from happily
    before and failed with a bare ``PermissionError`` afterwards. All the
    walk does with a directory descriptor is ``openat`` and ``fstat`` through
    it, and ``O_PATH`` and ``O_SEARCH`` both give exactly that without asking
    for read.

    So where the platform offers search rights the file is read and the
    ordinary verdict stands; where it offers neither the requirement is
    stated instead of raised. Linux has ``O_PATH`` and Darwin has
    ``O_SEARCH``, so every platform this is tested on takes the first branch
    — the assertion follows the module's own answer rather than the
    platform's name, and the test below forces the second branch so its
    refusal is bound too. Without the flag change this is a
    ``PermissionError`` escaping the gate."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger_directory = candidate.root / "ledger"
    ledger_directory.chmod(0o111)
    try:
        # Search-only, and the state file inside it is readable: the walk is
        # the only thing standing between the gate and those bytes.
        assert (candidate.root / CHAIN_SPEC.state_relative).read_bytes()
        if release_chain.DESCENT_REQUIRES_DIRECTORY_READ:
            with pytest.raises(AppendError) as refusal:
                run_gate(candidate)
            assert str(refusal.value) == (
                "state path component ledger is not readable by this "
                "verifier; secure descent requires read permission on every "
                "directory above a state file on this platform: "
                "ledger/official_observations.jsonl"
            )
        else:
            assert run_gate(candidate) == (
                "thesis-facts append check OK: 3 rows, immutable prefix 1, "
                "+1 appended vs base"
            )
    finally:
        ledger_directory.chmod(0o755)


@pytest.mark.skipif(
    os.getuid() == 0, reason="root traverses a directory it has no rights on"
)
def test_the_shared_state_reader_answers_the_same_way(
    tmp_path: pathlib.Path,
) -> None:
    """S4-F5 through ``release_chain``'s own reader, which is the one
    ``verify_release_chain`` — and so ``receipt verify``'s custody pass —
    uses. Both readers go through the same descent, so both gained the same
    requirement and both state it the same way."""

    candidate = base_repository(tmp_path)
    ledger_directory = candidate.root / "ledger"
    expected = (candidate.root / CHAIN_SPEC.state_relative).read_bytes()
    ledger_directory.chmod(0o111)
    try:
        if release_chain.DESCENT_REQUIRES_DIRECTORY_READ:
            with pytest.raises(ReleaseChainError) as refusal:
                _regular_file_bytes(candidate.root, CHAIN_SPEC.state_relative)
            assert str(refusal.value) == (
                "state path component ledger is not readable by this "
                "verifier; secure descent requires read permission on every "
                "directory above a state file on this platform: "
                "ledger/official_observations.jsonl"
            )
        else:
            assert (
                _regular_file_bytes(candidate.root, CHAIN_SPEC.state_relative)
                == expected
            )
    finally:
        ledger_directory.chmod(0o755)


def test_the_descent_asks_for_no_more_than_it_uses(tmp_path: pathlib.Path) -> None:
    """S4-F5's flag choice, stated rather than implied. Where the platform
    has a search-only flag the walk uses it and asks for no read permission;
    where it does not the walk falls back to ``O_RDONLY`` and says so through
    ``DESCENT_REQUIRES_DIRECTORY_READ``, which is what the two tests above
    branch on. ``O_DIRECTORY`` and ``O_NOFOLLOW`` are in the set either way,
    because a component that became a file or a link must fail rather than be
    followed."""

    flags = release_chain.DIRECTORY_OPEN_FLAGS
    assert flags & os.O_DIRECTORY
    assert flags & os.O_NOFOLLOW
    # Whatever this platform offers, the walk takes it: leaving an available
    # search-only flag unused is the finding, and on a platform offering
    # neither both sides of this are zero.
    offered = getattr(os, "O_PATH", 0) or getattr(os, "O_SEARCH", 0)
    assert release_chain.SEARCH_ONLY_DIRECTORY_FLAG == offered
    if offered:
        assert flags & offered
        assert release_chain.DESCENT_REQUIRES_DIRECTORY_READ is False
    else:
        assert release_chain.DESCENT_REQUIRES_DIRECTORY_READ is True
    # Whichever it is, the walk still reaches an ordinary state file.
    candidate = base_repository(tmp_path)
    assert _regular_file_bytes(candidate.root, CHAIN_SPEC.state_relative)


def without_a_search_only_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """Present a platform whose ``os`` exposes neither ``O_PATH`` nor
    ``O_SEARCH``, which no interpreter this is run on actually is.

    Both constants are read at call time, so patching them is the same
    technique the ``os.supports_dir_fd`` cases use, and it reaches the branch
    that only such a platform would otherwise take.
    """

    monkeypatch.setattr(release_chain, "SEARCH_ONLY_DIRECTORY_FLAG", 0)
    monkeypatch.setattr(release_chain, "DESCENT_REQUIRES_DIRECTORY_READ", True)
    monkeypatch.setattr(
        release_chain,
        "DIRECTORY_OPEN_FLAGS",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )


@pytest.mark.skipif(
    os.getuid() == 0, reason="root traverses a directory it has no rights on"
)
@pytest.mark.parametrize(
    "unreadable", ["ledger", ""], ids=["intermediate-component", "candidate-root"]
)
def test_the_descent_states_the_read_it_needs_where_it_has_no_search_flag(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, unreadable: str
) -> None:
    """S4-F5's other branch, which no interpreter this runs on takes: Linux
    exposes ``O_PATH`` and Darwin exposes ``O_SEARCH`` (checked from CPython
    3.9 to 3.14), so ``DESCENT_REQUIRES_DIRECTORY_READ`` is false everywhere
    the suite runs and the refusal that branch gives would otherwise be
    asserted by nothing. Forcing the fallback flags binds it. Both the
    candidate root and an intermediate component are covered, because the
    root is opened before the component walk and would otherwise answer
    ``candidate root changed during verification`` — which would be false:
    the root did not change, it cannot be read."""

    candidate = base_repository(tmp_path)
    without_a_search_only_flag(monkeypatch)
    directory = candidate.root / unreadable if unreadable else candidate.root
    expected = (
        f"state path component {directory if not unreadable else unreadable} "
        "is not readable by this verifier; secure descent requires read "
        "permission on every directory above a state file on this platform: "
        "ledger/official_observations.jsonl"
    )
    directory.chmod(0o111)
    try:
        with pytest.raises(ReleaseChainError) as read:
            _regular_file_bytes(candidate.root, CHAIN_SPEC.state_relative)
        assert str(read.value) == expected
        with pytest.raises(AppendError) as refusal:
            run_push_gate(candidate)
        assert str(refusal.value) == expected
    finally:
        directory.chmod(0o755)


@pytest.mark.skipif(
    os.getuid() == 0, reason="root lists a directory it has no rights on"
)
def test_an_indexed_release_file_the_walk_cannot_enumerate_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """S4-F2 on any POSIX filesystem, which the two spelling cases above are
    not: they need names compared insensitively, so on a case- and
    normalisation-sensitive filesystem — ext4, and so CI — the entry was
    already absent and the old question already gave the same answer. This
    one binds everywhere, because it is the same substitution with the
    filesystem's *lookup* rather than its comparison doing the work:
    ``is_file()`` resolves the whole name and needs only search permission on
    the parents, so it answered "regular file" for an entry inside a
    directory the traversal cannot list — and the traversal is what the index
    is reconciled against. One committed release object, in no enumeration,
    never byte- or mode-verified, and the two sides called agreed.

    The refusal is deliberate and fail-closed, and it is the standard the
    package already applies with a base: ``_working_release_files`` keys the
    base comparison by the same traversal, so this tree is already refused
    there, in ``main``'s words. Without the fix the push path accepts it
    outright."""

    candidate = base_repository(tmp_path)
    vendor = candidate.root / CHAIN_SPEC.release_root_relative / "vendor"
    vendor.mkdir()
    (vendor / "notes.md").write_text("release notes\n", encoding="utf-8")
    git(candidate.root, "add", "--", "releases/vendor/notes.md")
    vendor.chmod(0o111)
    try:
        # Search permission is all the old question ever needed, and the file
        # really is there: this is a refusal about what can be enumerated,
        # not about what exists.
        assert (vendor / "notes.md").read_text(encoding="utf-8") == "release notes\n"
        assert (candidate.root / "releases" / "vendor" / "notes.md").is_file()

        with pytest.raises(AppendError) as refusal:
            run_push_gate(candidate)
        assert str(refusal.value) == (
            "release file recorded in the index is absent or not a regular "
            "file: releases/vendor/notes.md"
        )
    finally:
        vendor.chmod(0o755)


@pytest.mark.skipif(
    os.getuid() == 0, reason="root lists a directory it has no rights on"
)
def test_the_base_pass_already_refused_the_tree_the_walk_cannot_enumerate(
    tmp_path: pathlib.Path,
) -> None:
    """The other half of the test above, and the reason its refusal is not a
    new standard: with a base ref the same tree is refused by
    ``_working_release_files`` and the per-file loop, which are on ``main``
    and have always keyed the base comparison by the traversal's own
    enumeration. This test passes with S4-F2 reverted — that is its point.
    What S4-F2 changed is that the candidate index and the push path are now
    held to what the base-ref path already required."""

    candidate = base_repository(tmp_path)
    vendor = candidate.root / CHAIN_SPEC.release_root_relative / "vendor"
    vendor.mkdir()
    (vendor / "notes.md").write_text("release notes\n", encoding="utf-8")
    candidate = commit_all(candidate, "a release file under its own directory")
    append_one_row(candidate)
    vendor.chmod(0o111)
    try:
        with pytest.raises(AppendError) as refusal:
            run_gate(candidate)
        assert str(refusal.value) == (
            f"existing release file was deleted relative to {candidate.base}: "
            "releases/vendor/notes.md"
        )
    finally:
        vendor.chmod(0o755)


def test_a_release_root_beginning_with_a_colon_is_enumerated_at_the_base(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4R2-F4: the base tree was enumerated by handing the configured
    release root to ``git ls-tree`` as a bare pathspec, and a pathspec
    beginning with ``:`` is magic. The magic is stripped and what is left is
    the path git looks for, so a spec whose root is ``:releases`` asks about
    ``releases``, which this tree does not have: the enumeration comes back
    empty and exits zero. Every release file the base carries is then outside
    the comparison — the history pass has nothing to hold immutable, the whole
    root classifies as newly added files, and a rewritten release file rides
    through as a legacy pre-genesis proposal instead of being refused for the
    bytes it changed.

    With the root named literally the base entries are found and the rewrite
    gets the refusal it has always had. Without the fix this fails with
    ``legacy pre-genesis proposal must not change releases/`` — a message
    about a root the spec never named, for a file whose immutability was
    never checked."""

    spec = spec_with_release_root(":releases")
    candidate = base_repository(tmp_path, ":releases")
    append_one_row(candidate)
    readme = candidate.root / ":releases" / "README.md"
    readme.write_text("Rewritten by a data proposal.\n", encoding="utf-8")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate, spec=spec)
    assert str(refusal.value) == (
        f"existing release file bytes changed relative to {candidate.base}: "
        ":releases/README.md"
    )


def test_a_release_root_carrying_glob_magic_enumerates_only_itself(
    tmp_path: pathlib.Path,
) -> None:
    """S4R2-F4's other half of what a pathspec means, and the honest state of
    it: ``git ls-tree`` does not glob a bare pathspec on the git this package
    is verified with, so a root spelled ``rel[e]ases`` was already enumerated
    as the directory of that name and this case passes with the literalization
    reverted. ``git ls-files`` with the same pathspec is the other way — it
    returns a sibling ``releases/`` too — which is why the index reads were
    literalized first, and which is the whole point here: whether a configured
    path is read as a name or as a pattern was a property of one command's
    default in one version of git, and git's pathspec-mode variables rewrite
    it for every command. ``_git_environment`` drops those and ``:(literal)``
    says what is meant, so this run does not depend on either.

    The sibling is committed and left alone, so anything that enumerated it as
    part of the release root would report it deleted from a root the walk
    cannot find it under."""

    spec = spec_with_release_root("rel[e]ases")
    candidate = base_repository(tmp_path, "rel[e]ases")
    sibling = candidate.root / "releases"
    sibling.mkdir()
    (sibling / "unrelated.md").write_text("not a release\n", encoding="utf-8")
    candidate = commit_all(candidate, "a sibling the glob would reach")
    append_one_row(candidate)

    assert set(
        release_chain.git_tree_entries(candidate.root, candidate.base, "rel[e]ases")
    ) == {"rel[e]ases/README.md"}
    assert run_gate(candidate, spec=spec) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_the_base_enumeration_refuses_a_path_outside_the_root_it_asked_for(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S4R2-F4's check on the answer rather than on the question. A literal
    pathspec cannot return a path outside the root asked about, so this is
    what the enumeration is held to rather than what git is expected to do:
    every base entry the release history compares must be the requested root
    or lie under it. Here ``git ls-tree``'s own output is given one more
    record, for a path in neither place, and the enumeration refuses it
    instead of carrying it into the per-file loop — where it would be looked
    for in the release walk, not found, and reported as a release file
    deleted from a root it was never in.

    Without the filter the run refuses with ``existing release file was
    deleted relative to <commit>: outside/x``."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    real_git_run = release_chain._git_run

    def with_a_foreign_record(
        root: pathlib.Path, arguments: list[str], *, text: bool = False
    ) -> Any:
        completed = real_git_run(root, arguments, text=text)
        if arguments[0] == "ls-tree" and arguments[-1].endswith("releases"):
            completed.stdout += b"100644 blob " + b"0" * 40 + b"\toutside/x\0"
        return completed

    monkeypatch.setattr(release_chain, "_git_run", with_a_foreign_record)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "git tree enumeration returned a path outside releases: outside/x"
    )


def test_a_root_deleted_and_recreated_in_place_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S4R2-F3: the recorded root identity was ``(st_dev, st_ino)`` from
    an ``lstat``, and that pair is not a name for a directory over time. A
    POSIX filesystem is free to give a deleted directory's inode number to the
    next directory — or symlink — created in its place, so a root removed
    outright and replaced could be handed the number this run wrote down, and
    both comparisons against it then pass for a tree the run never selected.
    The tests above cannot show that: they rename the original aside, which
    keeps its inode live and therefore guarantees the replacement a different
    one. Here the original is deleted, which is the only way the number
    becomes available.

    What binds it is not a comparison but a descriptor: ``_set_root`` opens
    the resolved root and the gate holds it for the whole verdict, so the
    inode stays allocated to the directory this verdict is about and no other
    directory can be given its number while the run lasts. The assertions
    inside the swap say exactly that — the recreated root is not the recorded
    identity, and the held descriptor still is — and the gate then refuses.
    Without the descriptor the refusal depends on the filesystem's allocator:
    on APFS, whose inode numbers are not reused, this passes with the change
    reverted; where they are, it does not."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    replacement = a_replacement_repository(candidate, tmp_path)
    # Its first row is not the frozen one, so a run that really did read this
    # tree would refuse it: the acceptance would not merely be about the
    # wrong tree, it would be about a tree this gate rejects.
    rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 1)]
    rows[0] = observation_row(99)
    write_ledger(replacement, rows)
    staged = append_gate._staged_surface_changes

    def recreate_the_root_after_classifying(
        base: append_gate._BaseCommit, tree: append_gate._CandidateTree
    ) -> tuple[set[str], set[str], set[str]]:
        classified = staged(base, tree)
        shutil.rmtree(candidate.root)
        # Created at the path, not moved there: this is the moment the freed
        # inode number could be handed out again.
        shutil.copytree(replacement, candidate.root, symlinks=True)
        recreated = os.lstat(candidate.root)
        assert (recreated.st_dev, recreated.st_ino) != tree.root_identity
        held = os.fstat(tree.root_descriptor)
        assert (held.st_dev, held.st_ino) == tree.root_identity
        return classified

    monkeypatch.setattr(
        append_gate, "_staged_surface_changes", recreate_the_root_after_classifying
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "candidate root changed during verification"


@pytest.mark.parametrize("verdict", ["accepted", "refused"])
def test_the_root_descriptor_does_not_outlive_the_verdict(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, verdict: str
) -> None:
    """S4R2-F3's other half. The root descriptor is held for exactly the run
    it speaks for: opened as the candidate tree is selected and closed once,
    on the way out, whichever way the verdict goes. A descriptor kept past the
    verdict is a directory this process is still holding open — and one leaked
    per call in a caller that verifies many trees.

    Both exits are covered because they are different code paths out of the
    same run, and the ``finally`` is what makes them the same for the
    descriptor. Without the change there is no descriptor to close."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    if verdict == "refused":
        # An ordinary refusal from the middle of the run, after the root is
        # opened and well before the end.
        (candidate.root / CHAIN_SPEC.prefix_relative).write_text(
            "{}\n", encoding="utf-8"
        )
    trees: list[append_gate._CandidateTree] = []
    real_set_root = append_gate._set_root
    closed: list[int] = []
    real_close = os.close

    def capture(root: pathlib.Path, spec: AppendGateSpec) -> Any:
        tree = real_set_root(root, spec)
        trees.append(tree)
        return tree

    def record(descriptor: int) -> None:
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(append_gate, "_set_root", capture)
    monkeypatch.setattr(os, "close", record)

    if verdict == "refused":
        with pytest.raises(AppendError):
            run_gate(candidate)
    else:
        assert run_gate(candidate) == (
            "thesis-facts append check OK: 3 rows, immutable prefix 1, "
            "+1 appended vs base"
        )

    (tree,) = trees
    # Exactly once: no descriptor this run opened afterwards can have been
    # given the root's number while the root was still holding it.
    assert closed.count(tree.root_descriptor) == 1
    with pytest.raises(OSError) as after:
        os.fstat(tree.root_descriptor)
    assert after.value.errno == errno.EBADF


def index_an_alias(candidate: Candidate, tracked: str, alias: str) -> None:
    """Add ``alias`` to the index with the blob ``tracked`` already carries.

    What a commit authored where the two names are distinct files looks like:
    two entries, and — on a filesystem that folds names — one file on disk
    once it is checked out. ``update-index --cacheinfo`` is the only way to
    write the second entry from here, because ``git add`` would go through the
    working tree and find the one file.
    """

    blob = git(candidate.root, "rev-parse", f":{tracked}")
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},{alias}",
    )


def test_an_index_alias_of_the_release_root_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4R2-F2a: the exact-spelling reconciliation the release root's
    scan makes covers the entries *under* that root, and the root's own
    component was never anybody's question. ``:(literal)releases`` does not
    match ``Releases/README.md``, so that entry is in no ``modes`` mapping, no
    walk compares it, and nothing in the gate reads it at all — while the
    commit under review carries it as a second release object and, on a
    case-insensitive filesystem, a checkout materializes it over the same
    file the protected entry names.

    The whole index is read once at entry to say so. Nothing about this
    depends on how the filesystem compares names: the entry is an alias by its
    spelling, and it is refused on every filesystem. Without the check the
    push path accepts this tree outright."""

    candidate = base_repository(tmp_path)
    index_an_alias(candidate, "releases/README.md", "Releases/README.md")

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "index carries an alias of a protected path: Releases/README.md "
        "(for releases)"
    )


def test_an_index_alias_of_a_state_path_is_refused(tmp_path: pathlib.Path) -> None:
    """S4R2-F2a for the two paths the whole verdict is about, where the leaf's
    own spelling can differ too. ``assert_state_path_tracked`` and
    ``assert_index_agrees_with_tree`` both look the state path up in the index
    by the name the spec pins and are answered correctly, because that entry
    is there and is exactly what they asked for. Neither can see a second
    entry beside it that a name-folding filesystem resolves to the same file —
    a ledger this commit also carries, under a name no check here reads, whose
    bytes are whatever that entry's blob holds rather than the bytes this
    verdict read.

    Without the check this tree is accepted with the alias in the commit."""

    candidate = base_repository(tmp_path)
    index_an_alias(
        candidate,
        "ledger/official_observations.jsonl",
        "Ledger/official_observations.jsonl",
    )

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "index carries an alias of a protected path: "
        "Ledger/official_observations.jsonl (for ledger/official_observations.jsonl)"
    )


def test_an_index_alias_is_refused_against_a_base_as_well(
    tmp_path: pathlib.Path,
) -> None:
    """S4R2-F2a on the other path. The check runs once, at entry, before the
    surface classification decides which path the run takes, so a proposal
    that carries an alias is refused whether or not it names a base — and
    before the classification could report the alias as an unclassified change
    and accept it as gate-only."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    index_an_alias(candidate, "releases/README.md", "Releases/README.md")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "index carries an alias of a protected path: Releases/README.md "
        "(for releases)"
    )


def an_outside_release_tree(tmp_path: pathlib.Path, holding: str) -> pathlib.Path:
    """A release tree outside the candidate, with a manifest directory in it.

    A manifest is what makes the difference visible: the push path decides
    whether a chain exists by asking ``is_dir()`` about the manifest
    directory, which follows every component of the path it is given, so a
    root pointing here made this chain the one the verdict spoke for.
    """

    outside = tmp_path / "outside"
    manifests = outside / holding
    manifests.mkdir(parents=True)
    (manifests / "0000-0000000000000000.json").write_text("{}\n", encoding="utf-8")
    return outside


def test_a_symlinked_release_root_is_refused_on_the_push_path(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4R2-F1: on the push path everything the gate knows about a
    release tree it learns by joining the configured root onto the candidate
    root and reading what the join lands on — ``initialized`` is
    ``manifest_directory.is_dir()``, which follows links — and nothing asked
    what the join went through. So an untracked ``releases`` pointing at a
    directory outside the checkout made the chain inside *that* directory the
    one ``verify_release_chain`` was run against, and the verdict spoke for a
    release history that is no part of the tree under review, no part of the
    commit under review, and diffable against no base.

    The root's index scan cannot say so: it refuses a symlinked root only
    when the index records entries under that root, and an untracked one
    records none, so it returns. Walking the root's own components before
    anything reads through them is what answers it, in the words this package
    has always refused a symlinked ``releases`` with.

    Without the walk this run reaches ``verify_release_chain`` and refuses —
    or accepts — on the strength of the outside manifest."""

    candidate = base_repository(tmp_path)
    shutil.rmtree(candidate.root / "releases")
    candidate = commit_all(candidate, "a base with no release tree")
    outside = an_outside_release_tree(tmp_path, "manifests")
    (candidate.root / "releases").symlink_to(outside)

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == "releases must be a real directory, not a symlink"


def test_a_symlinked_parent_of_a_nested_release_root_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """S4R2-F1 for a component above the root, which is the same substitution
    without the root itself being a link: a spec whose release root is
    ``data/releases`` reaches it through ``data``, and a link there redirects
    the whole subtree exactly as a link at the leaf does. The leaf's own
    refusal cannot see it — ``releases`` under the link is a real directory —
    and the index scan again records nothing for an untracked root.

    The component that redirects is named, in the shape the state-path walk
    uses for the same fact."""

    spec = spec_with_release_root("data/releases")
    candidate = base_repository(tmp_path, "data/releases")
    shutil.rmtree(candidate.root / "data")
    candidate = commit_all(candidate, "a base with no release tree")
    outside = an_outside_release_tree(tmp_path, "releases/manifests")
    (candidate.root / "data").symlink_to(outside)

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate, spec=spec)
    assert str(refusal.value) == (
        "release root path traverses a symlink at 'data': data/releases"
    )


def test_the_base_ref_path_keeps_its_symlinked_release_root_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """S4R2-F1's placement against a base, which is the order this pins. With
    a base ref a symlinked ``releases`` was already refused, by
    ``_working_release_files`` at the top of the release-history pass, and the
    walk now runs ahead of that pass. It says the same sentence, so the
    refusal for this tree is unchanged — that is the point of borrowing the
    enumeration's words rather than minting new ones. This passes either way,
    deliberately."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    outside = tmp_path / "outside"
    shutil.move(str(candidate.root / "releases"), str(outside))
    (candidate.root / "releases").symlink_to(outside)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "releases must be a real directory, not a symlink"


@pytest.mark.parametrize("path", ["push", "base-ref"])
def test_a_release_root_spelled_differently_on_disk_is_refused(
    tmp_path: pathlib.Path, path: str
) -> None:
    """Binds S4R2-F2b: every component of a configured path was checked by
    resolving its name, and resolution is exactly where a case- or
    normalisation-insensitive filesystem answers with a directory this package
    never named. A checkout whose release directory is spelled ``Releases``
    answers to ``releases``: the enumeration walks it, the index scan
    reconciles against it, the manifests are read out of it, and the whole
    verdict is about a release tree whose name is neither the one the spec
    pins nor the one the index records. The directory's own listing is the
    question that does not go through resolution, and it says ``Releases``.

    On a filesystem that compares names exactly the rename is a deletion, so
    the spelling case cannot exist there at all — a name that resolves is a
    name its directory lists — and this tree is refused for being gone
    instead. Both answers are fail-closed and both are asserted, because the
    finding is about the filesystems where the first one is reachable. Without
    the check, a case-folding filesystem accepts this tree on both paths."""

    candidate = base_repository(tmp_path)
    (candidate.root / "releases").rename(candidate.root / "Releases")

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate) if path == "push" else run_gate(candidate)
    if CASE_IS_FOLDED:
        expected = (
            "path component releases is not spelled by its directory: releases"
        )
    elif path == "push":
        expected = (
            "release root is not a directory while the index records 1 entry "
            "under it"
        )
    else:
        expected = (
            f"existing release file was deleted relative to {candidate.base}: "
            "releases/README.md"
        )
    assert str(refusal.value) == expected


def test_a_nested_release_root_component_in_another_normalisation_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """S4R2-F2b for Unicode normalisation and for a component above the leaf,
    which is the same hole without any change of case: APFS and HFS+ compare
    names normalisation-insensitively, so a spec naming ``donnée/releases`` in
    NFC is answered by a directory stored in NFD, and every read below is of a
    subtree the spec does not name. The listing spells it one way, and the
    component that is not that spelling is refused.

    Where names are compared exactly the NFD rename is again a deletion, and
    the tree is refused for that instead."""

    composed = "donnée"
    decomposed = unicodedata.normalize("NFD", composed)
    assert composed != decomposed
    spec = spec_with_release_root(f"{composed}/releases")
    candidate = base_repository(tmp_path, f"{composed}/releases")
    (candidate.root / composed).rename(candidate.root / decomposed)

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate, spec=spec)
    if NORMALISATION_IS_FOLDED:
        expected = (
            f"path component {composed} is not spelled by its directory: "
            f"{composed}/releases"
        )
    else:
        expected = (
            "release root is not a directory while the index records 1 entry "
            "under it"
        )
    assert str(refusal.value) == expected


@pytest.mark.skipif(
    not CASE_IS_FOLDED,
    reason="a name that resolves is a name its directory lists here",
)
def test_a_state_path_component_spelled_differently_on_disk_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """S4R2-F2b for the two state paths, which reach their file through the
    same kind of walk and had the same gap. ``ledger/`` resolves to a
    ``Ledger/`` on disk, the descent opens it component by component and never
    asks whether the component it opened is the one the directory holds, and
    the bytes this verdict speaks for come out of a directory the index does
    not record and no surface pattern names.

    ``assert_state_path_tracked`` cannot answer it: the index entry it asks
    about is there and is exactly right, which is the point — the index is
    correct and the working tree is answering for it with something else.
    Where names are compared exactly this refusal is unreachable, so the test
    is skipped rather than asserting a different tree's answer; what covers
    the index side there, on every filesystem, is
    ``assert_index_carries_no_protected_alias``. Without the check this tree
    is accepted, with the ledger read out of ``Ledger/``."""

    candidate = base_repository(tmp_path)
    (candidate.root / "ledger").rename(candidate.root / "Ledger")

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "path component ledger is not spelled by its directory: "
        "ledger/official_observations.jsonl"
    )
