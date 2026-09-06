"""Large generated acceptance and remaining reader-budget refusal tests."""

from __future__ import annotations

import io
import os
import pathlib
import subprocess

import pytest

import receipt.snapshot as snapshot_module
from receipt.snapshot import SnapshotError, TreeSnapshot


ENTRY_COUNT = 20_000
LOGICAL_CONTENT_BYTES = 128 * 1024 * 1024
COMMON_BLOB_BYTES = 6_711
FINAL_BLOB_BYTES = LOGICAL_CONTENT_BYTES - COMMON_BLOB_BYTES * (ENTRY_COUNT - 1)


def _git(
    root: pathlib.Path,
    *arguments: str,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        ["git", "-C", os.fspath(root), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        raise AssertionError(
            f"git {' '.join(arguments)} failed: "
            f"{completed.stderr.decode(errors='replace')}"
        )
    return completed


def _hash_object(root: pathlib.Path, object_type: str, payload: bytes) -> str:
    return (
        _git(
            root,
            "hash-object",
            "--literally",
            "-t",
            object_type,
            "-w",
            "--stdin",
            input_bytes=payload,
        )
        .stdout.decode("ascii")
        .strip()
    )


def _tree_entry(name: bytes, oid: str, *, mode: bytes = b"100644") -> bytes:
    return mode + b" " + name + b"\0" + bytes.fromhex(oid)


def _commit_object(root: pathlib.Path, tree: str) -> tuple[str, int]:
    payload = (
        f"tree {tree}\n".encode("ascii")
        + b"author Snapshot Test <snapshot@example.test> 0 +0000\n"
        + b"committer Snapshot Test <snapshot@example.test> 0 +0000\n\n"
        + b"generated acceptance fixture\n"
    )
    return _hash_object(root, "commit", payload), len(payload)


@pytest.fixture(scope="module")
def generated_snapshot_repository(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[pathlib.Path, str, int, int, tuple[str, ...]]:
    """Generate 20,000 entries carrying exactly 128 MiB of logical bytes."""

    assert FINAL_BLOB_BYTES == 4_439
    root = tmp_path_factory.mktemp("snapshot-acceptance") / "repository"
    root.mkdir()
    _git(root, "init", "-q")
    common_oid = _hash_object(root, "blob", b"x" * COMMON_BLOB_BYTES)
    final_oid = _hash_object(root, "blob", b"y" * FINAL_BLOB_BYTES)
    names = tuple(f"entry-{index:05d}.bin" for index in range(ENTRY_COUNT))
    tree_payload = b"".join(
        _tree_entry(
            name.encode("ascii"),
            final_oid if index == ENTRY_COUNT - 1 else common_oid,
        )
        for index, name in enumerate(names)
    )
    tree = _hash_object(root, "tree", tree_payload)
    commit, commit_bytes = _commit_object(root, tree)
    return root, commit, len(tree_payload), commit_bytes, names


def test_generated_twenty_thousand_entry_128_mib_fixture_verifies_under_defaults(
    generated_snapshot_repository: tuple[
        pathlib.Path, str, int, int, tuple[str, ...]
    ],
    tmp_path: pathlib.Path,
) -> None:
    root, commit, tree_bytes, commit_bytes, names = generated_snapshot_repository
    destination = tmp_path / "materializations"
    destination.mkdir()
    path_bytes_once = sum(len(name.encode("ascii")) for name in names)

    with TreeSnapshot.select(root, commit) as selected:
        listing = selected.entries("")
        entries = tuple(listing)
        assert len(entries) == ENTRY_COUNT
        assert sum(
            COMMON_BLOB_BYTES if entry.path != names[-1] else FINAL_BLOB_BYTES
            for entry in entries
        ) == LOGICAL_CONTENT_BYTES

        digests = tuple(selected.digests(entries))
        assert len(digests) == ENTRY_COUNT
        selected.refuse_transforming_attributes(entries)

        with selected.materialize(
            ("",), destination, repertoire="portable"
        ) as materialized:
            assert len(materialized.entries) == ENTRY_COUNT
            assert sum(
                path.stat().st_size
                for path in materialized.path.iterdir()
                if path.is_file()
            ) == LOGICAL_CONTENT_BYTES

        work = selected.work
        assert work.tree_entries == 3 * ENTRY_COUNT < snapshot_module.MAX_TREE_ENTRIES
        assert (
            work.max_tree_entries_in_walk
            == ENTRY_COUNT
            < snapshot_module.MAX_TREE_ENTRIES
        )
        assert (
            work.tree_bytes
            == tree_bytes + commit_bytes
            < snapshot_module.MAX_TREE_BYTES_TOTAL
        )
        assert (
            work.max_tree_object_bytes
            == tree_bytes
            < snapshot_module.MAX_TREE_OBJECT_BYTES
        )
        assert (
            work.path_bytes
            == 3 * path_bytes_once
            < snapshot_module.MAX_PATH_BYTES_TOTAL
        )
        assert (
            work.max_path_bytes
            == len(names[-1])
            < snapshot_module.MAX_PATH_BYTES
        )
        assert work.attribute_bytes == 0 < snapshot_module.MAX_ATTRIBUTE_BYTES_TOTAL
        assert work.attribute_rules == 0 < snapshot_module.MAX_ATTRIBUTE_RULES_TOTAL
        assert (
            work.attribute_match_work
            == 0
            < snapshot_module.MAX_ATTRIBUTE_MATCH_WORK
        )
        assert (
            work.content_bytes
            == LOGICAL_CONTENT_BYTES
            < snapshot_module.MAX_CONTENT_BYTES_TOTAL
        )
        assert (
            work.max_content_blob_bytes
            == COMMON_BLOB_BYTES
            < snapshot_module.MAX_CONTENT_BLOB_BYTES
        )
        assert (
            work.materialized_bytes
            == LOGICAL_CONTENT_BYTES
            < snapshot_module.MAX_MATERIALIZED_BYTES
        )
        assert (
            work.max_materialized_blob_bytes
            == COMMON_BLOB_BYTES
            < snapshot_module.MAX_MATERIALIZED_BLOB_BYTES
        )
        assert work.ancestry_commits == 0 < snapshot_module.MAX_ANCESTRY_COMMITS
        assert work.ancestry_edges == 0 < snapshot_module.MAX_ANCESTRY_COMMITS


def test_large_fixture_refuses_tree_entry_budget(
    generated_snapshot_repository: tuple[
        pathlib.Path, str, int, int, tuple[str, ...]
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, commit, _tree_bytes, _commit_bytes, _names = generated_snapshot_repository
    monkeypatch.setattr(snapshot_module, "MAX_TREE_ENTRIES", ENTRY_COUNT - 1)

    with pytest.raises(
        SnapshotError,
        match=f"tree walk exceeds the budget of {ENTRY_COUNT - 1} entries",
    ):
        TreeSnapshot.select(root, commit)


@pytest.mark.parametrize(
    "constant",
    ["MAX_TREE_OBJECT_BYTES", "MAX_TREE_BYTES_TOTAL"],
)
def test_large_fixture_refuses_tree_object_byte_budgets(
    generated_snapshot_repository: tuple[
        pathlib.Path, str, int, int, tuple[str, ...]
    ],
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
) -> None:
    root, commit, tree_bytes, commit_bytes, _names = generated_snapshot_repository
    limit = tree_bytes - 1 if constant == "MAX_TREE_OBJECT_BYTES" else tree_bytes + commit_bytes - 1
    monkeypatch.setattr(snapshot_module, constant, limit)

    with pytest.raises(SnapshotError, match="budget"):
        TreeSnapshot.select(root, commit)


@pytest.mark.parametrize(
    ("constant", "limit", "message"),
    [
        ("MAX_PATH_BYTES", 14, "tree path exceeds the budget of 14 bytes"),
        ("MAX_PATH_BYTES_TOTAL", 0, "tree paths exceed the snapshot budget of 0 bytes"),
    ],
)
def test_large_fixture_refuses_path_budgets(
    generated_snapshot_repository: tuple[
        pathlib.Path, str, int, int, tuple[str, ...]
    ],
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    limit: int,
    message: str,
) -> None:
    root, commit, _tree_bytes, _commit_bytes, _names = generated_snapshot_repository

    with TreeSnapshot.select(root, commit) as selected:
        monkeypatch.setattr(snapshot_module, constant, limit)
        with pytest.raises(SnapshotError, match=message):
            next(iter(selected.entries("")))


def test_tree_depth_budget_refuses_before_a_deeper_walk(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deep-repository"
    root.mkdir()
    _git(root, "init", "-q")
    blob = _hash_object(root, "blob", b"leaf\n")
    child = _hash_object(root, "tree", _tree_entry(b"leaf.txt", blob))
    tree = _hash_object(
        root,
        "tree",
        _tree_entry(b"directory", child, mode=b"40000"),
    )
    commit, _commit_bytes = _commit_object(root, tree)
    monkeypatch.setattr(snapshot_module, "MAX_TREE_DEPTH", 0)

    with TreeSnapshot.select(root, commit) as selected:
        with pytest.raises(
            SnapshotError, match="tree depth exceeds the budget of 0"
        ):
            selected.entries("")


@pytest.mark.parametrize(
    ("constant", "message"),
    [
        ("MAX_CONTENT_BLOB_BYTES", "content blob 'entry-00000.bin' exceeds"),
        ("MAX_CONTENT_BYTES_TOTAL", "content bytes exceed the snapshot budget"),
    ],
)
def test_large_fixture_refuses_default_content_budgets(
    generated_snapshot_repository: tuple[
        pathlib.Path, str, int, int, tuple[str, ...]
    ],
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    message: str,
) -> None:
    root, commit, _tree_bytes, _commit_bytes, _names = generated_snapshot_repository

    with TreeSnapshot.select(root, commit) as selected:
        entry = selected.entry("entry-00000.bin")
        monkeypatch.setattr(snapshot_module, constant, COMMON_BLOB_BYTES - 1)
        with pytest.raises(SnapshotError, match=message):
            next(selected.digests((entry,)))


def test_git_output_budget_refuses_bounded_child_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(snapshot_module, "MAX_GIT_OUTPUT_BYTES", 0)
    with pytest.raises(
        SnapshotError, match="git output exceeds the budget of 0 bytes"
    ):
        snapshot_module._git_run(
            ["version"],
            cwd=None,
            environment=os.environ,
            output_limit=snapshot_module.MAX_GIT_OUTPUT_BYTES,
        )


class _TimedOutProcess:
    """Minimal Popen stand-in that deterministically exhausts a time budget."""

    def __init__(self) -> None:
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()
        self.stdin = None
        self._waits = 0

    def wait(self, timeout: float | None = None) -> int:
        self._waits += 1
        if self._waits == 1:
            raise subprocess.TimeoutExpired(["git", "version"], timeout)
        return -9

    def kill(self) -> None:
        return None


def test_git_seconds_budget_refuses_a_timed_out_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _TimedOutProcess()
    monkeypatch.setattr(snapshot_module, "MAX_GIT_SECONDS", 0)
    monkeypatch.setattr(snapshot_module.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(
        SnapshotError,
        match="git command exceeded its 0 second budget",
    ):
        snapshot_module._git_run(
            ["version"],
            cwd=None,
            environment=os.environ,
            seconds=snapshot_module.MAX_GIT_SECONDS,
        )


def _require_store_verification_support() -> None:
    completed = subprocess.run(
        ["git", "version", "--build-options"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        pytest.skip("git build options are unavailable")
    version = snapshot_module._parse_version(completed.stdout)
    if version < snapshot_module.GIT_FSCK_NO_REFERENCES_MIN_VERSION:
        pytest.skip("Git is below the fsck --no-references floor")
    if b"SHA-1: SHA1_DC" not in completed.stdout.splitlines():
        pytest.skip("Git was not built with SHA1_DC")


def _small_snapshot_repository(tmp_path: pathlib.Path) -> tuple[pathlib.Path, str]:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-q")
    blob = _hash_object(root, "blob", b"small fixture\n")
    tree = _hash_object(root, "tree", _tree_entry(b"file.txt", blob))
    commit, _commit_bytes = _commit_object(root, tree)
    return root, commit


def test_fsck_output_budget_refuses_diagnostic_output(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_store_verification_support()
    root, commit = _small_snapshot_repository(tmp_path)

    with TreeSnapshot.select(root, commit, verify_objects=True) as selected:
        corrupt = root / ".git" / "objects" / "aa" / ("a" * 38)
        corrupt.parent.mkdir()
        corrupt.write_bytes(b"not a zlib stream")
        monkeypatch.setattr(snapshot_module, "MAX_FSCK_OUTPUT_BYTES", 0)
        with pytest.raises(
            SnapshotError, match="git output exceeds the budget of 0 bytes"
        ):
            selected.verify_object_store((selected.commit,))


def test_fsck_seconds_budget_refuses_a_zero_deadline(
    generated_snapshot_repository: tuple[
        pathlib.Path, str, int, int, tuple[str, ...]
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_store_verification_support()
    root, commit, _tree_bytes, _commit_bytes, _names = generated_snapshot_repository

    with TreeSnapshot.select(root, commit, verify_objects=True) as selected:
        monkeypatch.setattr(snapshot_module, "MAX_FSCK_SECONDS", 0)
        with pytest.raises(
            SnapshotError, match="git command exceeded its 0 second budget"
        ):
            selected.verify_object_store((selected.commit,))
