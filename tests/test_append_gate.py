"""Confinement the upstream append gate never had, on a local fixture.

tests/test_append_gate_equivalence.py proves the port reproduces its oracle's
verdicts on the pinned production tree. This module covers what that battery
never presents: proposals that stay inside the classified surfaces the gate
speaks for, state paths that stay inside the candidate tree, and one base
commit for the whole verdict. Every case here is a NEW refusal (or a
previously silent acceptance made explicit), so the differential gate is
untouched. The state-path cases reach the shared reader in
receipt.release_chain, so they are exercised here directly as well.

The fixture is a local git repository built from scratch — no network, no
witnesses, no signatures. Its release tree holds a README and no manifests, so
the gate's chain verification finds nothing to verify and the checks under
test are the ones that run before it.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

import pytest

from receipt import append_gate
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


def git(root: pathlib.Path, *arguments: str) -> str:
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
    text alone says which commit the whole run measured against.
    """

    first = base_repository(tmp_path)
    rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 2)]
    write_ledger(first.root, rows)
    git(first.root, "add", "-A")
    git(first.root, "commit", "--quiet", "-m", "third row")
    later = git(first.root, "rev-parse", "HEAD")
    git(first.root, "branch", "moving", first.base)
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
    """The control: the two commits really do disagree about this worktree."""

    moving, _first, later = moving_base_repository(tmp_path)
    git(moving.root, "branch", "-f", "moving", later)

    assert run_gate(moving) == (
        "thesis-facts append check OK: 4 rows, immutable prefix 1, "
        f"+1 appended vs base moving ({later})"
    )


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
        "an RFC 3339 timestamp with a time zone"
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
        "an RFC 3339 timestamp with a time zone"
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
        "an RFC 3339 timestamp with a time zone"
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
        "an RFC 3339 timestamp with a time zone"
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
