"""Unit coverage for the append policy over authenticated commit snapshots.

The production-tree differential in ``test_append_gate_equivalence.py`` binds
the extracted policy and its baseline messages. These local repositories cover
snapshot integration: candidate/base selection, tree-only surface
classification, regular state entries, release-history immutability, private
release materialization, trusted anchors, and the object identities exposed by
``AppendGateVerdict``.

Every ordinary helper commits the proposed tree and passes its full object ID.
Tests which mutate the checkout after that point call the public API directly,
so they can prove that neither the working tree nor index is a verdict subject.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
from types import SimpleNamespace
from dataclasses import dataclass, replace
from typing import Any

import pytest

from receipt import append_gate, release_chain
from receipt.append_gate import (
    AppendError,
    AppendGateSpec,
    _assert_release_paths_are_subdirectories,
    expected_assertion_version_id,
    verify_append_gate,
)
from receipt.canonical import canonical_bytes
from receipt.release_chain import (
    AnchorSpec,
    ChainSpec,
    ReleaseChainError,
)
from receipt.snapshot import TreeSnapshot
from receipt.sign import generate_signing_keypair, sign_payload

from corpus_fixture import LocalTsa, build_local_tsa, created_at

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


def commit_candidate(candidate: Candidate, message: str = "candidate tree") -> str:
    """Commit the proposed tree and return the full candidate object ID."""

    git(candidate.root, "add", "-A")
    if git(candidate.root, "status", "--porcelain"):
        git(candidate.root, "commit", "--quiet", "-m", message)
    return git(candidate.root, "rev-parse", "HEAD")


def run_gate(
    candidate: Candidate,
    base_ref: str | None = None,
    spec: AppendGateSpec = GATE_SPEC,
    *,
    commit: str | None = None,
) -> str:
    oid = commit or commit_candidate(candidate)
    return verify_append_gate(
        candidate.root,
        spec=spec,
        base_ref=candidate.base if base_ref is None else base_ref,
        commit=oid,
    )


def run_push_gate(
    candidate: Candidate,
    spec: AppendGateSpec = GATE_SPEC,
    *,
    commit: str | None = None,
) -> str:
    """The push path: no base ref, so only the full-file invariants run.

    ``run_gate`` always names a base, so nothing above exercised the branch
    that skips surface classification, the append-only diff, the base prefix
    anchor, and the release history.
    """

    return verify_append_gate(
        candidate.root,
        spec=spec,
        commit=commit or commit_candidate(candidate),
    )


def test_an_ordinary_append_is_accepted(tmp_path: pathlib.Path) -> None:
    """The fixture's baseline verdict, so every refusal below is the change."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, +1 appended vs base"
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
    git(
        first.root,
        "commit",
        "--quiet",
        "-m",
        "third row, revised prefix and release tree",
    )
    later = git(first.root, "rev-parse", "HEAD")
    git(first.root, "branch", "moving", first.base)
    readme.write_bytes(kept_readme)
    manifest.write_bytes(kept_manifest)
    rows.append(observation_row(BASE_ROW_COUNT + 2))
    write_ledger(first.root, rows)
    # The proposal is staged, as a reviewed checkout's is. Without this the
    # index still holds the later commit's README while the working tree
    # holds the base's, which is a staged rewrite of a base release file with
    # the disk restored — exactly what S4R3-F1 refuses, and nothing this
    # fixture is about.
    git(first.root, "add", "-A")
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
        "thesis-facts append check OK: 4 rows, immutable prefix 1, +2 appended vs base"
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
        git(candidate.snapshot.root, "branch", "-f", "moving", later)
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
        "state file mode changed relative to base: ledger/official_observations.jsonl"
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
        "thesis-facts append check OK: 3 rows, immutable prefix 1, +1 appended vs base"
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
        responseArchive={"sha256": hashlib.sha256(b"response-3").hexdigest().upper()},
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
        "thesis-facts append check OK: 3 rows, immutable prefix 1, +1 appended vs base"
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
        "thesis-facts append check OK: 3 rows, immutable prefix 1, +1 appended vs base"
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
        "state file mode changed relative to base: ledger/official_observations.jsonl"
    )


def test_a_gate_only_verdict_names_the_commit_a_symbolic_base_resolved_to(
    tmp_path: pathlib.Path,
) -> None:
    """The gate-only acceptance returned before the resolved-base suffix was
    built, so against a movable name it named no snapshot (peer review)."""

    candidate = base_repository(tmp_path)
    git(candidate.root, "branch", "base-symbol", candidate.base)
    add_gate_file(candidate)

    assert run_gate(candidate, base_ref="base-symbol") == (
        "thesis-facts append check OK: gate-only proposal; DATA_SURFACE "
        f"unchanged; GATE_SURFACE changes=['{GATE_FILE}']; base base-symbol "
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
        "thesis-facts append check OK: 3 rows, immutable prefix 1, +1 appended vs base"
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


def test_the_push_path_accepts_an_ordinary_tree(tmp_path: pathlib.Path) -> None:
    """The baseline for F1, so the refusals below are the change: with no base
    ref the verdict carries neither an append count nor a release, and this
    branch of verify_append_gate had no test at all before."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)

    assert run_push_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1"
    )


CLASSIFICATION_READS = ("diff", "ls-files", "diff-index")


def test_an_invalid_base_ref_is_refused_before_the_checkout_guard(
    tmp_path: pathlib.Path,
) -> None:
    """An unresolvable base is reported by immutable snapshot selection."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(candidate.root, "config", "core.fileMode", "false")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate, base_ref="refs/heads/does-not-exist")
    assert str(refusal.value) == ("cannot resolve commit 'refs/heads/does-not-exist'")


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

    oid = commit_candidate(candidate, "initialized push tree")
    with TreeSnapshot.select(candidate.root, oid) as snapshot:
        tree = append_gate._CandidateTree(
            snapshot=snapshot,
            spec=GATE_SPEC,
            ledger_relative=CHAIN_SPEC.state_relative.as_posix(),
            prefix_relative=CHAIN_SPEC.prefix_relative.as_posix(),
        )
        with pytest.raises(AppendError):
            append_gate.check_release_chain_without_base(
                candidate=tree,
                ledger_bytes=b"ledger snapshot",
                prefix_bytes=b"prefix snapshot",
                anchor_dir=tmp_path,
                enforce_production_pins=False,
            )
    assert captured["state_bytes"] == {
        "ledger/official_observations.jsonl": b"ledger snapshot",
        "ledger/immutable_prefix.json": b"prefix snapshot",
    }


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
    assert str(refusal.value) == "tree path ancestor is not a directory: ledger"


def commit_release_gitlink(candidate: Candidate) -> str:
    """Commit a gitlink under ``releases/`` that nothing has checked out.

    An empty or uninitialised submodule directory is the ordinary state of a
    fresh checkout, and it is the case the filesystem walk cannot see at all:
    there is no directory on disk to skip, and no file to enumerate.
    """

    git(candidate.root, "add", "-A")
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{candidate.base},releases/vendor",
    )
    git(candidate.root, "commit", "--quiet", "-m", "release gitlink")
    return git(candidate.root, "rev-parse", "HEAD")


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
    oid = commit_release_gitlink(candidate)
    # The walk really is blind to it: nothing exists at that path on disk.
    assert not (candidate.root / "releases" / "vendor").exists()

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate, commit=oid)
    assert str(refusal.value) == "release path is not regular: releases/vendor"


def test_a_gitlink_under_the_release_root_is_refused_on_the_push_path(
    tmp_path: pathlib.Path,
) -> None:
    """R5-F4 on the push path, which runs none of the base-tree comparisons
    and, with no chain to verify, returned before looking at the release root
    at all. The scan runs there ahead of that early return."""

    candidate = base_repository(tmp_path)
    oid = commit_release_gitlink(candidate)

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate, commit=oid)
    assert str(refusal.value) == "release path is not regular: releases/vendor"


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
    directory to hold it refuses.

    S5-R2-F2 answers the same tree one step earlier, and both are asserted
    here the way the base-ref sibling below asserts both of its. The manifest
    path's own type is decided before ``initialized`` asks the filesystem
    whether there is a chain, and with the components walked rather than
    ``lstat``-ed whole, a regular file standing at ``releases`` is a
    non-directory ancestor rather than an ``ENOTDIR`` read as absence.
    Measured at this round's head with ``assert_manifest_directory_regular``
    put back to its single ``lstat`` and bare ``except OSError``: ``release
    root is not a directory while the index records 1 entry under it`` — the
    scan's own sentence, which the scan still gives for this tree and which is
    asserted directly below, so the order between the two is pinned rather
    than assumed. R6-F1's finding is untouched: this pre-emption needs a
    *tracked* entry under the root, and the tree S5-R2-F2 is actually about
    leaves the scan nothing to say at all."""

    candidate = base_repository(tmp_path)
    replace_release_root_with_a_tracked_file(candidate)
    # The manifest directory really is unreachable, which is what made this
    # an acceptance rather than a refusal.
    assert not (candidate.root / CHAIN_SPEC.manifest_relative).is_dir()

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == "tree path ancestor is not a directory: releases"


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
    assert str(refusal.value) == (
        f"existing release file was deleted relative to {candidate.base}: "
        "releases/README.md"
    )


def commit_all(candidate: Candidate, message: str) -> Candidate:
    """Commit the working tree and return the candidate rebased on it."""

    git(candidate.root, "add", "-A")
    git(candidate.root, "commit", "--quiet", "-m", message)
    return replace(candidate, base=git(candidate.root, "rev-parse", "HEAD"))


MAGIC_STATE_PATH = ":odd/official_observations.jsonl"


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


def a_nested_base_with_no_release_tree(tmp_path: pathlib.Path) -> Candidate:
    """A base configured for ``data/releases`` with nothing at ``data`` yet.

    The release tree arrives later, which is the tree the ancestor cases below
    are about: with nothing tracked under ``data``, a proposal that puts a
    file or a link there is a change at a single path, and no deleted release
    file gives the confinement something to refuse for another reason.
    """

    candidate = base_repository(tmp_path, "data/releases")
    shutil.rmtree(candidate.root / "data")
    return commit_all(candidate, "a base with no release tree")


def test_a_file_standing_where_a_nested_release_root_lives_is_not_gate_only(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-G1-F1. The gate-only exit claims a confinement over the
    release root, and every check that could make that claim good — the root's
    component walk, the working-tree enumeration, the index scan — is
    downstream of it. What the confinement itself asked was whether an
    unclassified change was *at* the root or under it, so with a root of
    ``data/releases`` a proposal replacing ``data`` was neither: ``data``
    matches no surface pattern, is not the release root and is not inside it.
    It classified as an ordinary unclassified change and the verdict named it
    beside ``DATA_SURFACE unchanged``, over a tree whose release root had
    stopped being a directory at all.

    The release root's ancestors are on the release surface for the reason the
    root is: the root's existence as a real directory is the premise of every
    release-root check, and a proposal that changes that premise is not
    gate-only.

    Measured at 427e08d: ``thesis-facts append check OK: gate-only proposal;
    DATA_SURFACE unchanged; GATE_SURFACE changes=['scripts/check_append.py'];
    unclassified changes=['data']``. The walk has nothing to say about this
    tree — ``data`` is a regular file, not a link, and a listing of it fails
    with ``ENOTDIR``, which is the absence answer both walks pass on — so what
    refuses is the confinement, in its own words."""

    spec = spec_with_release_root("data/releases")
    candidate = a_nested_base_with_no_release_tree(tmp_path)
    add_gate_file(candidate)
    (candidate.root / "data").write_text("not a directory\n", encoding="utf-8")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate, spec=spec)
    assert str(refusal.value) == (
        "gate-only proposal changes unclassified release path(s): ['data']"
    )


def test_an_untouched_nested_release_root_still_returns_gate_only(
    tmp_path: pathlib.Path,
) -> None:
    """S5-G1-F1's other side. Neither half of the fix costs a legitimate
    proposal anything: a nested release root that is a real directory the
    proposal does not touch is walked, found to be what the spec names, and
    the gate-only verdict is exactly the one it always was. The ancestor
    ``data`` is on the release surface, and no change is proposed at it.

    The same verdict with and without the fix, which is the binding."""

    spec = spec_with_release_root("data/releases")
    candidate = base_repository(tmp_path, "data/releases")
    add_gate_file(candidate)

    assert run_gate(candidate, spec=spec) == (
        "thesis-facts append check OK: gate-only proposal; DATA_SURFACE "
        f"unchanged; GATE_SURFACE changes=['{GATE_FILE}']"
    )


@pytest.mark.parametrize("spelling", [".", ""], ids=["dot", "empty"])
@pytest.mark.parametrize(
    "field",
    ["release_root_relative", "manifest_relative", "anchor_relative"],
    ids=["release-root", "manifest", "anchor"],
)
def test_a_release_path_spelled_as_the_candidate_root_is_refused(
    tmp_path: pathlib.Path, field: str, spelling: str
) -> None:
    """Binds S4R4-F8. A configured release path with no components at all —
    ``.`` and the empty path both give that — names the candidate root itself,
    and the gate's own reads disagree about what is inside such a root.
    ``git ls-tree`` lists the entries under ``.`` with no prefix (``a/f.txt``,
    not ``./a/f.txt``, checked on the git this repository is verified with),
    so ``git_tree_entries`` refuses the first of them as a path outside the
    root it asked about and the base enumeration never returns; the gate-only
    confinement asks whether a changed path is ``.`` or begins with ``./`` and
    finds nothing inside the release root, so that confinement is silently a
    no-op; and the release root's hold has no component to walk.

    Only the descriptor holder ever supported such a spec, by seeding its walk
    with the candidate root — which answered the ``AssertionError`` an earlier
    draft raised, and left every read above still disagreeing. The seeding is
    gone and the spec is refused at the gate's entry instead, before the tree
    is touched — and, since spec validation landed (#41), by ``ChainSpec``
    itself at construction, so the gate's check is reached only by a chain
    that was never built through the constructor.

    Measured at de1dbe4 with the refusal removed, for both spellings. A
    release root of ``.``: the push path accepts it outright, as
    ``thesis-facts append check OK: 2 rows, immutable prefix 1``, having
    walked, held and scanned nothing; against a base it is refused as ``git
    tree enumeration returned a path outside .:
    ledger/immutable_prefix.json`` — the enumeration meeting the tree's own
    first file. A manifest path of ``.``: the push path refuses as ``release
    manifest directory contains a non-regular entry: <root>/releases``, the
    enumeration having taken the whole checkout for a manifest directory,
    while against a base the tree is accepted, since no ``*.json`` sits at the
    root and the run decides there is no chain. An anchor path of ``.`` is
    accepted on both paths, because the gate reads the anchors it is handed
    rather than the candidate's. Three configurations, five different
    answers, none of them about this proposal.

    No consumer pins such a spec and no fixture here builds one; the point is
    that a verifier answers rather than asserting or half-reading."""

    # ``ChainSpec`` refuses both spellings at construction (spec validation,
    # #41), so no gate ever meets such a spec through the public constructor.
    with pytest.raises(ReleaseChainError) as constructed:
        replace(CHAIN_SPEC, **{field: pathlib.PurePosixPath(spelling)})
    assert str(constructed.value) == (
        f"ChainSpec {field} must be a relative path naming at least one "
        f"component, with no '..': {pathlib.PurePosixPath(spelling).as_posix()!r}"
    )

    # The gate's own entry check stays, in its own words, for a spec that did
    # not come through ``ChainSpec.__post_init__``: it is asked of the chain
    # the gate is handed, whatever built it.
    label = {
        "release_root_relative": "release root",
        "manifest_relative": "release manifest path",
        "anchor_relative": "release anchor path",
    }[field]
    fields = {
        name: getattr(CHAIN_SPEC, name)
        for name in ("release_root_relative", "manifest_relative", "anchor_relative")
    }
    fields[field] = pathlib.PurePosixPath(spelling)
    bypassed = SimpleNamespace(chain=SimpleNamespace(**fields))
    with pytest.raises(AppendError) as refusal:
        _assert_release_paths_are_subdirectories(bypassed)  # type: ignore[arg-type]
    assert str(refusal.value) == (
        f"{label} must be a subdirectory of the candidate root"
    )


def test_an_ordinary_spec_names_a_subdirectory_for_every_release_path(
    tmp_path: pathlib.Path,
) -> None:
    """S4R4-F8's other side: the check is about a path with no components, and
    every spec in this repository — and every consumer's — names a
    subdirectory for all three. The fixture's own is accepted exactly as
    before."""

    for relative in (
        CHAIN_SPEC.release_root_relative,
        CHAIN_SPEC.manifest_relative,
        CHAIN_SPEC.anchor_relative,
    ):
        assert relative.parts

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, +1 appended vs base"
    )


# The environment that can redirect a git read this gate makes (#45, the
# cheap half). GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE, GIT_OBJECT_DIRECTORY
# and GIT_ALTERNATE_OBJECT_DIRECTORIES can each decide which repository,
# working tree, index or object store some read resolves in, rather than the
# checkout `root` names (not every read moves under every variable; see
# release_chain.assert_no_redirecting_git_environment), while the verdict
# still speaks of the checkout named — and this gate reads the candidate tree directly as well, so under any of
# them the two halves of one verdict are about two trees. They are refused
# rather than dropped for the child processes: dropping them would leave the
# verifier's own environment redirected while its children's was not.
def redirecting_refusal(name: str) -> str:
    return f"{name} is set in the environment and would redirect git reads; unset it"


@pytest.mark.parametrize("name", release_chain.REDIRECTING_GIT_ENVIRONMENT)
@pytest.mark.parametrize("with_base", [False, True], ids=["push", "base-ref"])
def test_a_redirecting_git_variable_refuses_the_whole_verdict(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    with_base: bool,
) -> None:
    """#45's cheap half, once per variable and on both paths.

    The proposal is the ordinary accepted append, so nothing but the
    environment distinguishes these runs from the baseline verdict — the
    refusal is the environment's and not the tree's.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    oid = commit_candidate(candidate, "redirecting environment fixture")
    monkeypatch.setenv(name, str(tmp_path / "elsewhere"))

    with pytest.raises(AppendError) as refusal:
        (
            run_gate(candidate, commit=oid)
            if with_base
            else run_push_gate(candidate, commit=oid)
        )
    assert str(refusal.value) == redirecting_refusal(name)


def test_the_five_redirecting_variables_are_the_ones_named(
    tmp_path: pathlib.Path,
) -> None:
    """The list itself, so a name cannot be dropped from it unnoticed."""

    assert release_chain.REDIRECTING_GIT_ENVIRONMENT == (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    )


def test_a_redirecting_variable_is_refused_before_any_git_command_runs(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """And it is the first thing asked: before the root is opened at all.

    The root here does not exist, which is its own refusal one line further
    down (#46), and git is replaced with a raise. The environment's sentence
    is what arrives, so the order is the stated one: the process first, then
    the tree.
    """

    def refuse_to_run(*arguments: Any, **keywords: Any) -> Any:
        raise RuntimeError("a git command ran before the environment was refused")

    monkeypatch.setattr(subprocess, "run", refuse_to_run)
    monkeypatch.setattr(subprocess, "check_output", refuse_to_run)
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "elsewhere.git"))

    with pytest.raises(AppendError) as refusal:
        verify_append_gate(tmp_path / "no-such-tree", spec=GATE_SPEC)
    assert str(refusal.value) == redirecting_refusal("GIT_DIR")


def test_the_redirecting_refusal_names_the_first_variable_set(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With several set, one sentence: the first in the module's own order.

    The instruction is the same for each, so a caller with two set fixes one,
    asks again, and is told about the other.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    oid = commit_candidate(candidate, "redirecting environment fixture")
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "foreign.index"))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(tmp_path / "foreign-objects"))

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate, commit=oid)
    assert str(refusal.value) == redirecting_refusal("GIT_INDEX_FILE")

    monkeypatch.delenv("GIT_INDEX_FILE")
    with pytest.raises(AppendError) as second:
        run_push_gate(candidate, commit=oid)
    assert str(second.value) == redirecting_refusal("GIT_OBJECT_DIRECTORY")


# The candidate root that is not there to be opened (#46). ``_set_root``
# recorded the root's identity with an unguarded open, so a ``--root`` naming
# nothing, or naming a regular file, escaped as the OS's own ``OSError``
# rather than as the ``AppendError`` every other refusal in this module
# raises. The consumer command that reaches this code catches ``AppendError``
# alone, so the bare exception ended that run non-zero with a traceback and
# nothing was ever accepted that should not have been; a library caller got an
# exception from outside this module's vocabulary, with the OS's message and
# no mention of the root it was asked about.
MISSING_ROOT_REFUSAL = "candidate repository is missing or not a git repository: "


@pytest.mark.parametrize("with_base", [False, True], ids=["push", "base-ref"])
def test_a_root_that_is_not_there_refuses_as_the_gate_rather_than_the_os(
    tmp_path: pathlib.Path, with_base: bool
) -> None:
    """#46, the absent root: an ``AppendError`` naming what the caller named.

    Measured with the refusal removed, on both paths: ``FileNotFoundError:
    [Errno 2] No such file or directory: '<root>'`` — the OS's exception, the
    OS's message, and the resolved path rather than the one asked about.
    """

    candidate = base_repository(tmp_path)
    missing = replace(candidate, root=tmp_path / "no-such-tree")

    with pytest.raises(AppendError) as refusal:
        (
            run_gate(missing, commit=candidate.base)
            if with_base
            else run_push_gate(missing, commit=candidate.base)
        )

    assert str(refusal.value) == MISSING_ROOT_REFUSAL + str(missing.root)


@pytest.mark.parametrize("with_base", [False, True], ids=["push", "base-ref"])
def test_a_regular_file_named_as_the_root_refuses_in_the_same_words(
    tmp_path: pathlib.Path, with_base: bool
) -> None:
    """#46's other half: a root that exists and is not a directory.

    ``O_DIRECTORY`` is what makes this an error rather than an open of the
    file, and it arrives as ``ENOTDIR`` rather than ``ENOENT``. One sentence
    covers both, because the fact it states is the same one: there is no
    candidate tree at this name for the gate to answer about.
    """

    candidate = base_repository(tmp_path)
    file_root = tmp_path / "not-a-tree"
    file_root.write_text("this is a file, not a checkout\n", encoding="utf-8")
    named = replace(candidate, root=file_root)

    with pytest.raises(AppendError) as refusal:
        (
            run_gate(named, commit=candidate.base)
            if with_base
            else run_push_gate(named, commit=candidate.base)
        )

    assert str(refusal.value) == MISSING_ROOT_REFUSAL + str(file_root)


def test_a_root_reached_through_a_regular_file_refuses_in_the_same_words(
    tmp_path: pathlib.Path,
) -> None:
    """And a root whose *component* is a file, which is the same ``ENOTDIR``.

    ``pathlib.Path.resolve`` does not raise for a path that does not resolve,
    so this arrives at the open exactly as the two above do rather than being
    caught earlier by something else.
    """

    candidate = base_repository(tmp_path)
    blocker = tmp_path / "blocker"
    blocker.write_text(
        "a file standing where a directory was asked for\n", encoding="utf-8"
    )
    through = replace(candidate, root=blocker / "inside")

    with pytest.raises(AppendError) as refusal:
        run_push_gate(through, commit=candidate.base)

    assert str(refusal.value) == MISSING_ROOT_REFUSAL + str(through.root)


def test_an_ordinary_root_is_unaffected_by_the_missing_root_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """The refusal's negative side: a root that is there still verifies.

    The check is the one ``os.open`` already made; only the two errnos that
    mean "no tree here" are answered differently, so every accepting input
    reaches exactly what it reached before.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, +1 appended vs base"
    )
    assert run_push_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1"
    )


def test_the_chain_inside_a_walked_root_is_what_the_verdict_reads(
    tmp_path: pathlib.Path, witnesses: Witnesses
) -> None:
    """S4R3-F3's control, and the half of the case the swap test asserts by
    contradiction: the in-tree chain those parameters plant really is one this
    verifier refuses, so an acceptance there could only have been the outside
    one. Left unswapped, this tree is refused for the state its own manifest
    claims."""

    candidate = base_repository(tmp_path)
    shutil.rmtree(candidate.root / "releases")
    candidate = commit_all(candidate, "a base with no release tree")
    anchors = tmp_path / "anchors"
    ledger_bytes, prefix_bytes = state_bytes_of(candidate)
    write_release_chain(
        candidate.root / CHAIN_SPEC.manifest_relative,
        anchors,
        witnesses=witnesses,
        ledger_bytes=ledger_bytes + b"a row this ledger does not carry\n",
        prefix_bytes=prefix_bytes,
    )

    with pytest.raises(AppendError) as refusal:
        run_push_gate_with_anchors(candidate, anchors)
    assert str(refusal.value) == (
        "release 0 lineCount 3 exceeds working-tree line count 2"
    )


def spec_with_nested_manifests(release_root: str = "releases") -> AppendGateSpec:
    """The fixture spec with its manifest directory one component deeper.

    ``releases/journal/manifests`` is a layout a ``ChainSpec`` permits and the
    pinned consumer does not use: the manifest directory is no longer the
    release root's own child, so ``journal`` is a component of a configured
    path that walking the release root alone never looks at.
    """

    chain = replace(
        CHAIN_SPEC,
        release_root_relative=pathlib.PurePosixPath(release_root),
        manifest_relative=pathlib.PurePosixPath(f"{release_root}/journal/manifests"),
        anchor_relative=pathlib.PurePosixPath(f"{release_root}/anchors"),
    )
    return replace(
        GATE_SPEC,
        chain=chain,
        release_manifest_prefix=f"{release_root}/journal/manifests/",
        genesis_support_files=frozenset({f"{release_root}/README.md"}),
        gate_surface=frozenset({GATE_FILE, f"{release_root}/anchors/**"}),
        data_surface=frozenset({"ledger/**", f"{release_root}/journal/**"}),
    )


def test_a_nested_manifest_directory_in_the_tree_is_accepted(
    tmp_path: pathlib.Path, witnesses: Witnesses
) -> None:
    """S4R3-F4's other side: the extension refuses links, not depth. The same
    spec with its chain really inside ``releases/journal/manifests`` is
    verified and accepted, so the walk added here costs a legitimate nested
    layout nothing."""

    spec = spec_with_nested_manifests()
    candidate = base_repository(tmp_path)
    anchors = tmp_path / "anchors"
    ledger_bytes, prefix_bytes = state_bytes_of(candidate)
    write_release_chain(
        candidate.root / spec.chain.manifest_relative,
        anchors,
        witnesses=witnesses,
        chain=spec.chain,
        ledger_bytes=ledger_bytes,
        prefix_bytes=prefix_bytes,
    )

    assert run_push_gate_with_anchors(candidate, anchors, spec=spec) == (
        "thesis-facts append check OK: 2 rows, immutable prefix 1, release 0"
    )


def a_manifest_path_that_is_not_a_directory(
    candidate: Candidate, tmp_path: pathlib.Path, shape: str
) -> None:
    """Put one of the three non-directories at the manifest path.

    Each is a thing ``manifest_directory.is_dir() and any(iterdir())`` reads as
    "this tree has no chain": a tracked regular file, a link to an empty
    directory, and a link to nothing at all.
    """

    manifests = candidate.root / CHAIN_SPEC.manifest_relative
    if shape == "tracked-blob":
        manifests.write_text("not a manifest directory\n", encoding="utf-8")
        git(candidate.root, "add", "-A")
        git(candidate.root, "commit", "--quiet", "-m", "a blob at the manifest path")
        return
    if shape == "empty-directory-link":
        empty = tmp_path / "an-empty-directory"
        empty.mkdir()
        manifests.symlink_to(empty)
        return
    manifests.symlink_to(tmp_path / "nothing-is-here")


@pytest.mark.parametrize(
    "shape",
    ["tracked-blob", "empty-directory-link", "dangling-link"],
)
def test_the_push_path_decides_the_manifest_paths_type_before_its_chain(
    tmp_path: pathlib.Path, shape: str
) -> None:
    """Binds S4R4-F3. On the push path there is no base to compare against, so
    whether this tree has a chain at all is decided by asking the filesystem:
    ``initialized`` is ``manifest_directory.is_dir() and any(iterdir())``. All
    three shapes here answer that question ``False`` — a tracked 100644 blob
    standing where the manifest directory was is not a directory, a link to an
    empty directory has nothing in it, a dangling link resolves to nothing —
    and ``False`` means "no chain", which is an acceptance with no manifest,
    no signature and no receipt verified.

    Nothing else on this path says otherwise. The release root's walk stops one
    component short of this leaf, deliberately, because the leaf has the
    enumeration's own refusal — but the enumeration only runs once something
    has decided to enumerate, and this is the decision. The root's index scan
    that follows reconciles the tracked blob with the regular file the
    traversal finds, which is exactly what it is, and holds no entry at all for
    either untracked link.

    Measured at 22da6c4 with the type decision removed: all three return
    ``thesis-facts append check OK: 2 rows, immutable prefix 1``. Refused now
    in ``_enumerate_manifest_files``'s own words, which is what a link to a
    *populated* directory here has always been refused with."""

    candidate = base_repository(tmp_path)
    a_manifest_path_that_is_not_a_directory(candidate, tmp_path, shape)

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "release manifest path is not a regular directory: "
        f"{candidate.root}/{CHAIN_SPEC.manifest_relative.as_posix()}"
    )


def test_a_manifest_path_that_is_absent_is_still_no_chain(
    tmp_path: pathlib.Path,
) -> None:
    """S4R4-F3's other side: an absent chain is legal and stays legal. The
    fixture carries no manifest directory at all, which is the ordinary
    pre-genesis tree, and the type decision returns for it exactly as
    ``_enumerate_manifest_files``'s own ``exists()`` does — the push path's
    acceptance for such a tree is unchanged."""

    candidate = base_repository(tmp_path)
    assert not (candidate.root / CHAIN_SPEC.manifest_relative).exists()

    assert run_push_gate(candidate) == (
        "thesis-facts append check OK: 2 rows, immutable prefix 1"
    )


def test_a_file_above_a_nested_manifest_path_is_not_no_chain(
    tmp_path: pathlib.Path,
) -> None:
    """S5-R2-F2 one component further down, which is the shape S4R3-F4 named
    for the walk and this decision had the same gap in. A spec whose manifest
    directory sits below an interior component — ``releases/journal/manifests``
    — reads ``ENOTDIR`` for a regular file at *any* ancestor, and the single
    ``lstat`` could not tell which component it was about or that it was a
    type answer at all.

    Measured at this round's head with the single ``lstat`` and bare
    ``except OSError`` put back: ``thesis-facts append check OK: 2 rows,
    immutable prefix 1``. The component walk names the ancestor it refused
    for."""

    spec = spec_with_release_root("releases/journal")
    candidate = base_repository(tmp_path, "releases/journal")
    shutil.rmtree(candidate.root / "releases")
    candidate = commit_all(candidate, "no release tree yet")
    (candidate.root / "releases").write_text("not a directory\n", encoding="utf-8")

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate, spec=spec)
    assert str(refusal.value) == "tree path ancestor is not a directory: releases"


def test_an_absent_ancestor_of_a_nested_manifest_path_is_still_no_chain(
    tmp_path: pathlib.Path,
) -> None:
    """S5-R2-F2's other side, beside the single-component case
    ``test_a_manifest_path_that_is_absent_is_still_no_chain`` already binds.
    ``FileNotFoundError`` at any component is absence: nothing stands there,
    so nothing stands at the leaf either, and an absent chain is legal. Only
    the two facts that are not absence changed answers."""

    spec = spec_with_release_root("releases/journal")
    candidate = base_repository(tmp_path, "releases/journal")
    shutil.rmtree(candidate.root / "releases")
    candidate = commit_all(candidate, "no release tree yet")
    assert not (candidate.root / "releases").exists()

    assert run_push_gate(candidate, spec=spec) == (
        "thesis-facts append check OK: 2 rows, immutable prefix 1"
    )


def test_an_anchor_path_that_is_not_a_directory_keeps_its_own_refusal(
    tmp_path: pathlib.Path, witnesses: Witnesses
) -> None:
    """S4R4-F3's boundary, which is why only the manifest leaf gets a type
    decision. The release root's walk stops one component short of the anchor
    path too, on the same reasoning — the leaf has a refusal of its own — and
    unlike the manifest path nothing here decides whether the anchors are
    read. The first read through that path meets them, and a path that is not
    a directory is refused in words the extraction gave: the producer key's,
    and past it the TSA anchor's. Adding a check ahead of them would replace
    those sentences for every tree they answer.

    The anchor directory the gate reads is the one it is handed — the trusted
    code root's, or this override — so this drives it through the same
    ``release_anchor_dir`` the fixtures use. Passes either way by design."""

    candidate, _anchors, _stem = genesis_proposal(tmp_path, witnesses)
    not_a_directory = tmp_path / "anchors-as-a-file"
    not_a_directory.write_text("not a directory\n", encoding="utf-8")

    with pytest.raises(AppendError) as refusal:
        run_push_gate_with_anchors(candidate, not_a_directory)
    assert str(refusal.value) == (
        "missing or non-regular producer public key: "
        f"{not_a_directory}/{CHAIN_SPEC.producer_public_key_filename}"
    )


def test_the_manifest_leaf_keeps_its_own_type_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """S5-F3's other side: what the walk binds at a leaf is its spelling, not
    its type. A manifest directory spelled exactly as the spec names it and
    standing over a symlink is still refused by
    ``assert_manifest_directory_regular`` in the enumeration's own words, and a
    regular file there likewise, because the walk asks the directory's listing
    about the name and leaves what the name resolves to alone. The two
    questions are separable because they are asked of different things.

    ``test_a_manifest_directory_that_is_itself_a_link_keeps_its_own_refusal``
    and ``test_the_push_path_decides_the_manifest_paths_type_before_its_chain``
    bind the same boundary from the other direction; this one states it for
    the leaf the walk now visits."""

    candidate = base_repository(tmp_path)
    release_root = candidate.root / CHAIN_SPEC.release_root_relative
    manifest_path = candidate.root / CHAIN_SPEC.manifest_relative
    manifest_path.write_text("not a directory\n", encoding="utf-8")
    assert CHAIN_SPEC.manifest_relative.name in os.listdir(release_root)

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        f"release manifest path is not a regular directory: {manifest_path}"
    )


def test_the_anchor_leaf_is_spelled_but_not_typed_by_the_walk(
    tmp_path: pathlib.Path,
) -> None:
    """S5-F3 for the other leaf the walk now visits, which is where the
    separation of the two questions earns its keep. A regular file standing at
    the candidate's own ``releases/anchors`` is spelled exactly as the spec
    names it, so the walk passes it — and nothing here reads that path at all:
    the anchors this gate reads come from the trusted code root or from a
    caller's override, never from the candidate. Judging the leaf's type in the
    walk would refuse this tree over a directory the verdict never opens.

    ``test_an_anchor_path_that_is_not_a_directory_keeps_its_own_refusal`` binds
    the sentence for the anchor path that *is* read; this binds that the walk
    does not take it over, and that visiting the leaf for its spelling costs
    the tree nothing."""

    candidate = base_repository(tmp_path)
    release_root = candidate.root / CHAIN_SPEC.release_root_relative
    (candidate.root / CHAIN_SPEC.anchor_relative).write_text(
        "not a directory\n", encoding="utf-8"
    )
    assert CHAIN_SPEC.anchor_relative.name in os.listdir(release_root)

    assert run_push_gate(candidate) == (
        "thesis-facts append check OK: 2 rows, immutable prefix 1"
    )


def test_a_dangling_release_root_link_is_named_as_a_link(
    tmp_path: pathlib.Path,
) -> None:
    """S4R2-F1's one pre-emption, pinned rather than left incidental. A link
    at the release root that points nowhere is the one link
    ``_working_release_files`` never met: ``exists()`` follows it, finds
    nothing, and the enumeration returns an empty mapping, so against a base
    this tree was refused a file later — ``existing release file was deleted
    relative to <commit>: releases/README.md`` — for the consequence rather
    than for the link. Verified by running this tree with the walk removed.

    The walk refuses it as the link it is, which changes that refusal. Of the
    links the walk meets it is the only one whose refusal moves — a link the
    enumeration does reach still gets the enumeration's own sentence, which
    the test above pins — and this test is what holds it to that one case. It
    is not the only pre-existing refusal this round pre-empts: the spelling
    check inside both walks pre-empts whatever the content behind a folded
    name would have been refused for, which ``append_gate``'s module docstring
    states with both cases measured."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    shutil.move(str(candidate.root / "releases"), str(tmp_path / "moved-away"))
    (candidate.root / "releases").symlink_to(tmp_path / "nothing-is-here")
    assert not (candidate.root / "releases").exists()
    assert (candidate.root / "releases").is_symlink()

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "release path is a symlink: releases"


@dataclass(frozen=True)
class Witnesses:
    """One generated producer key and two locally generated timestamp authorities.

    Everything a real release carries, built offline: the anchors, policy OIDs,
    signer certificates and SPKIs are real values, so a chain written with them
    is one ``verify_release_chain`` verifies for real rather than one it skips.
    Expensive (two RSA keygens and two certificate signings), so it is built
    once per module and the trees below are written from it.
    """

    alpha: LocalTsa
    beta: LocalTsa
    private_pem: bytes
    public_pem: bytes


@pytest.fixture(scope="module")
def witnesses(tmp_path_factory: pytest.TempPathFactory) -> Witnesses:
    workspace = tmp_path_factory.mktemp("witnesses")
    alpha = build_local_tsa(workspace / "alpha", "alpha", "1.3.6.1.4.1.99999.1.1")
    beta = build_local_tsa(workspace / "beta", "beta", "1.3.6.1.4.1.99999.2.1")
    private_pem, public_pem = generate_signing_keypair()
    return Witnesses(
        alpha=alpha, beta=beta, private_pem=private_pem, public_pem=public_pem
    )


def write_release_chain(
    manifests: pathlib.Path,
    anchors: pathlib.Path,
    *,
    witnesses: Witnesses,
    chain: ChainSpec = CHAIN_SPEC,
    ledger_bytes: bytes,
    prefix_bytes: bytes,
) -> str:
    """A valid genesis release over exactly these state bytes; return its stem.

    ``manifests`` and ``anchors`` are written wherever the caller points them,
    which is the whole point for the cases below: a chain that verifies is what
    makes an escape an *acceptance* rather than a refusal about a malformed
    manifest, and where such a chain sits decides which tree a verdict spoke
    for.
    """

    manifests.mkdir(parents=True, exist_ok=True)
    anchors.mkdir(parents=True, exist_ok=True)
    (anchors / chain.producer_public_key_filename).write_bytes(witnesses.public_pem)
    for tsa in (witnesses.alpha, witnesses.beta):
        (anchors / tsa.root_pem.name).write_bytes(tsa.root_pem.read_bytes())
    lines = ledger_bytes.decode("utf-8").split("\n")[:-1]
    manifest = {
        "schemaVersion": chain.schema_version,
        "releaseIndex": 0,
        "previousManifestSha256": None,
        "state": {
            "path": chain.state_path,
            "jsonlSha256": hashlib.sha256(ledger_bytes).hexdigest(),
            "lineCount": len(lines),
            "immutablePrefixSha256": hashlib.sha256(prefix_bytes).hexdigest(),
        },
        "append": None,
        "createdAtUtc": created_at(120),
        "producer": {"repo": "TheAxiomFoundation/receipt", "branch": "fixture"},
    }
    raw = canonical_bytes(manifest) + b"\n"
    digest = hashlib.sha256(raw).hexdigest()
    stem = f"0000-{digest[:16]}"
    (manifests / f"{stem}.json").write_bytes(raw)
    (manifests / f"{stem}.producer.sig").write_bytes(
        sign_payload(witnesses.private_pem, raw, domain=b"")
    )
    for tsa in (witnesses.alpha, witnesses.beta):
        tsa.stamp(digest, manifests / f"{stem}.{tsa.name}.tsr")
    return stem


def state_bytes_of(
    candidate: Candidate, chain: ChainSpec = CHAIN_SPEC
) -> tuple[bytes, bytes]:
    return (
        (candidate.root / chain.state_relative).read_bytes(),
        (candidate.root / chain.prefix_relative).read_bytes(),
    )


def genesis_proposal(
    tmp_path: pathlib.Path, witnesses: Witnesses
) -> tuple[Candidate, pathlib.Path, str]:
    """A base with no chain, and a working tree carrying a valid genesis one.

    The anchors live outside the candidate deliberately: ``releases/anchors``
    is GATE_SURFACE here, so a proposal that wrote them into the tree would be
    a mixed data/gate proposal and never reach the release verification at all.
    The gate takes them through ``release_anchor_dir``, which is also what
    turns production pin enforcement off for these fixture identities.
    """

    candidate = base_repository(tmp_path)
    anchors = tmp_path / "anchors"
    ledger_bytes, prefix_bytes = state_bytes_of(candidate)
    stem = write_release_chain(
        candidate.root / CHAIN_SPEC.manifest_relative,
        anchors,
        witnesses=witnesses,
        ledger_bytes=ledger_bytes,
        prefix_bytes=prefix_bytes,
    )
    return candidate, anchors, stem


def run_gate_with_anchors(
    candidate: Candidate,
    anchors: pathlib.Path,
    *,
    base_ref: str | None = None,
    spec: AppendGateSpec = GATE_SPEC,
    commit: str | None = None,
) -> str:
    return verify_append_gate(
        candidate.root,
        spec=spec,
        base_ref=candidate.base if base_ref is None else base_ref,
        commit=commit or commit_candidate(candidate),
        release_anchor_dir=anchors,
    )


def run_push_gate_with_anchors(
    candidate: Candidate,
    anchors: pathlib.Path,
    *,
    spec: AppendGateSpec = GATE_SPEC,
    commit: str | None = None,
) -> str:
    """The push path over a chain built by this module's own witnesses.

    ``release_anchor_dir`` is what turns production pin enforcement off for
    those generated identities, exactly as it does on the base-ref path; the
    cases that need a chain the gate actually verifies take this rather than
    ``run_push_gate``, which points the verifier at the production anchors the
    fixture has none of.
    """

    return verify_append_gate(
        candidate.root,
        spec=spec,
        commit=commit or commit_candidate(candidate),
        release_anchor_dir=anchors,
    )


def test_a_valid_genesis_proposal_is_accepted(
    tmp_path: pathlib.Path, witnesses: Witnesses
) -> None:
    """The control the three cases below need: a genesis release this fixture
    builds offline really does verify, so an acceptance means the chain was
    verified rather than that nothing was found to verify."""

    candidate, anchors, _stem = genesis_proposal(tmp_path, witnesses)
    stage(candidate)

    assert run_gate_with_anchors(candidate, anchors) == (
        "thesis-facts append check OK: 2 rows, immutable prefix 1, "
        "+0 appended vs base, release 0"
    )
