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

The fixture is a local git repository built from scratch — no network, no
witnesses, no signatures. Its release tree holds a README and no manifests, so
the gate's chain verification finds nothing to verify and the checks under
test are the ones that run before it.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
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


def base_repository(tmp_path: pathlib.Path) -> Candidate:
    """A committed base: two ledger rows, a frozen prefix, a release README."""

    root = tmp_path / "candidate"
    root.mkdir()
    rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 1)]
    write_ledger(root, rows)
    write_prefix_manifest(root, rows)
    releases = root / CHAIN_SPEC.release_root_relative
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


def run_gate(candidate: Candidate, base_ref: str | None = None) -> str:
    return verify_append_gate(
        candidate.root,
        spec=GATE_SPEC,
        base_ref=candidate.base if base_ref is None else base_ref,
    )


def run_push_gate(candidate: Candidate) -> str:
    """The push path: no base ref, so only the full-file invariants run.

    ``run_gate`` always names a base, so nothing above exercised the branch
    that skips surface classification, the append-only diff, the base prefix
    anchor, and the release history.
    """

    return verify_append_gate(candidate.root, spec=GATE_SPEC)


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
    inode = ledger.stat().st_ino

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file changed during verification: "
        "ledger/official_observations.jsonl"
    )
    # Same bytes, different file: only the recorded identity says so.
    assert ledger.stat().st_ino != inode


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
    tree = append_gate._set_root(candidate.root, GATE_SPEC)

    with pytest.raises(AppendError):
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
        "release root is not a directory while the index records 1 entries "
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
        "release root is not a directory while the index records 1 entries "
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
    path all over again to ``stat`` it, so the mode it compared was about
    whatever the name reached by then rather than about the file this run
    read — and the index comparison after it resolved the name a third time.
    Here every ``Path.stat`` of the ledger reports an executable bit the file
    does not carry. Through the gate the snapshot's own ``fstat`` is what
    answers and the ordinary verdict stands; called on its own, with no
    snapshot to take, the same function believes the lie and refuses. The
    tree is identical in both, so the difference is only where the mode came
    from."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root.resolve() / CHAIN_SPEC.state_relative
    real_stat = pathlib.Path.stat

    def lying_stat(self: pathlib.Path, **keywords: Any) -> os.stat_result:
        observed = real_stat(self, **keywords)
        if os.fspath(self) != os.fspath(ledger):
            return observed
        return os.stat_result((observed.st_mode | 0o111, *tuple(observed)[1:]))

    monkeypatch.setattr(pathlib.Path, "stat", lying_stat)

    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )
    with pytest.raises(AppendError) as refusal:
        append_gate.check_state_modes(
            append_gate._BaseCommit(ref=candidate.base, commit=candidate.base),
            append_gate._set_root(candidate.root, GATE_SPEC),
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
    go through the same helper, so both say it."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    without_open = frozenset(os.supports_dir_fd) - {os.open}
    monkeypatch.setattr(os, "supports_dir_fd", without_open)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state files cannot be read with secure descent on this platform "
        "(os.open lacks dir_fd support)"
    )
    with pytest.raises(ReleaseChainError) as read:
        _regular_file_bytes(candidate.root, CHAIN_SPEC.state_relative)
    assert str(read.value) == (
        "state files cannot be read with secure descent on this platform "
        "(os.open lacks dir_fd support)"
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
