"""Tests for the immutable Git object reader.

These fixtures create ordinary and deliberately malformed objects in private
scratch repositories.  The production reader never consults their checkout
or index after discovery; a few test-only Git commands are used as independent
oracles for object identity and changed paths.
"""

from __future__ import annotations

import hashlib
import io
import os
import pathlib
import subprocess
import threading
from collections.abc import Iterable

import pytest

import receipt.snapshot as snapshot_module
from receipt.snapshot import (
    GIT_COMMANDS,
    GIT_ENVIRONMENT_DROPPED,
    GIT_MIN_VERSION,
    SnapshotError,
    TreeListing,
    TreeSnapshot,
    _BatchReader,
    _canonical_commit,
    _git_environment,
    _parse_raw_tree,
)


ZERO_OID = "0" * 40
ONE_OID = "1" * 40
TWO_OID = "2" * 40


def _git(
    root: pathlib.Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        ["git", "-C", os.fspath(root), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and completed.returncode:
        raise AssertionError(
            f"git {' '.join(arguments)} failed: "
            f"{completed.stderr.decode(errors='replace')}"
        )
    return completed


def _oid(root: pathlib.Path, revision: str = "HEAD") -> str:
    return _git(root, "rev-parse", revision).stdout.decode("ascii").strip()


def _commit_worktree(root: pathlib.Path, message: str) -> str:
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message)
    return _oid(root)


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


def _tree_entry(mode: bytes, name: bytes, oid: str) -> bytes:
    return mode + b" " + name + b"\0" + bytes.fromhex(oid)


def _tree_object(
    root: pathlib.Path, entries: Iterable[tuple[bytes, bytes, str]]
) -> str:
    ordered = sorted(entries, key=lambda item: item[1] + (b"/" if item[0] == b"40000" else b""))
    return _hash_object(
        root,
        "tree",
        b"".join(_tree_entry(mode, name, oid) for mode, name, oid in ordered),
    )


def _commit_object(
    root: pathlib.Path,
    tree: str,
    *,
    parents: Iterable[str] = (),
    message: bytes = b"fixture\n",
) -> str:
    payload = bytearray(f"tree {tree}\n".encode("ascii"))
    for parent in parents:
        payload.extend(f"parent {parent}\n".encode("ascii"))
    payload.extend(
        b"author Snapshot Test <snapshot@example.test> 0 +0000\n"
        b"committer Snapshot Test <snapshot@example.test> 0 +0000\n\n"
    )
    payload.extend(message)
    return _hash_object(root, "commit", bytes(payload))


def _object_oid(object_type: str, payload: bytes) -> str:
    framed = f"{object_type} {len(payload)}\0".encode("ascii") + payload
    return hashlib.sha1(framed).hexdigest()


def _fake_batch(
    stream: bytes,
    *,
    cached: dict[str, tuple[str, int]] | None = None,
) -> _BatchReader:
    reader = object.__new__(_BatchReader)
    reader._object_format = "sha1"
    reader._abandoned = False
    reader._closed = False
    reader._headers = {} if cached is None else dict(cached)
    reader._stdin = io.BytesIO()
    reader._stdout = io.BytesIO(stream)
    return reader


@pytest.fixture
def git_repo(tmp_path: pathlib.Path) -> pathlib.Path:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Snapshot Test")
    _git(root, "config", "user.email", "snapshot@example.test")
    (root / "tracked.txt").write_bytes(b"committed bytes\n")
    _commit_worktree(root, "initial")
    return root


def test_select_records_authenticated_identity_before_entry(
    git_repo: pathlib.Path,
) -> None:
    commit = _oid(git_repo)
    tree = _oid(git_repo, "HEAD^{tree}")

    selected = TreeSnapshot.select(git_repo)

    assert selected.commit == commit
    assert selected.tree == tree
    assert selected.object_format == "sha1"
    assert selected.git_dir == (git_repo / ".git").resolve()
    assert selected.root == git_repo.resolve()
    assert selected.batch_pid is None
    assert selected.temporary_directory is None
    with pytest.raises(
        SnapshotError, match="snapshot must be entered before object reads"
    ):
        selected.header(tree)


def test_select_expectations_are_checked_commit_then_tree(
    git_repo: pathlib.Path,
) -> None:
    commit = _oid(git_repo)
    tree = _oid(git_repo, "HEAD^{tree}")
    TreeSnapshot.select(
        git_repo, expect_commit=commit, expect_tree=tree
    )

    with pytest.raises(
        SnapshotError,
        match=rf"^commit {commit} is not the expected commit {ZERO_OID}$",
    ):
        TreeSnapshot.select(
            git_repo, expect_commit=ZERO_OID, expect_tree=ONE_OID
        )
    with pytest.raises(
        SnapshotError,
        match=rf"^tree {tree} is not the expected tree {ZERO_OID}$",
    ):
        TreeSnapshot.select(git_repo, expect_tree=ZERO_OID)


def test_commit_identity_distinguishes_commits_with_the_same_tree(
    git_repo: pathlib.Path,
) -> None:
    first = _oid(git_repo)
    tree = _oid(git_repo, "HEAD^{tree}")
    descendant = _commit_object(git_repo, tree, parents=(first,))
    unrelated = _commit_object(git_repo, tree, message=b"unrelated root\n")

    first_snapshot = TreeSnapshot.select(git_repo, first)
    descendant_snapshot = TreeSnapshot.select(git_repo, descendant)
    unrelated_snapshot = TreeSnapshot.select(git_repo, unrelated)

    assert {first_snapshot.tree, descendant_snapshot.tree, unrelated_snapshot.tree} == {
        tree
    }
    assert len(
        {first_snapshot.commit, descendant_snapshot.commit, unrelated_snapshot.commit}
    ) == 3
    with descendant_snapshot:
        assert descendant_snapshot.assert_ancestor(first) == first
        with pytest.raises(SnapshotError, match="is not an ancestor"):
            descendant_snapshot.assert_ancestor(unrelated)


def test_context_acquires_batch_lazily_and_reaps_it(
    git_repo: pathlib.Path,
) -> None:
    selected = TreeSnapshot.select(git_repo)
    assert selected.batch_pid is None

    with selected:
        process = selected._state.batch.process
        temporary = selected.temporary_directory
        assert process.poll() is None
        assert temporary is not None and temporary.is_dir()
        assert selected.blob(selected.entry("tracked.txt"), limit=100) == (
            b"committed bytes\n"
        )

    assert process.poll() is not None
    assert process.stdin is not None and process.stdin.closed
    assert process.stdout is not None and process.stdout.closed
    assert temporary is not None and not temporary.exists()
    assert selected.batch_pid is None
    assert selected.temporary_directory is None
    with pytest.raises(SnapshotError, match="snapshot is closed"):
        selected.__enter__()


def test_context_reaps_batch_and_removes_temporary_directory_on_exception(
    git_repo: pathlib.Path,
) -> None:
    selected = TreeSnapshot.select(git_repo)

    with pytest.raises(RuntimeError, match="downstream failed"):
        with selected:
            process = selected._state.batch.process
            temporary = selected.temporary_directory
            raise RuntimeError("downstream failed")

    assert process.poll() is not None
    assert temporary is not None and not temporary.exists()


def test_selection_failure_reaps_its_short_lived_batch(
    git_repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    processes: list[subprocess.Popen[bytes]] = []
    original_consume = _BatchReader.consume
    original_close = _BatchReader.close

    def refusing_consume(self: _BatchReader, *args: object, **kwargs: object) -> None:
        del args, kwargs
        processes.append(self.process)
        raise SnapshotError("injected selection refusal")

    closed: list[subprocess.Popen[bytes]] = []

    def recording_close(self: _BatchReader) -> None:
        original_close(self)
        closed.append(self.process)

    monkeypatch.setattr(_BatchReader, "consume", refusing_consume)
    monkeypatch.setattr(_BatchReader, "close", recording_close)
    with pytest.raises(SnapshotError, match="injected selection refusal"):
        TreeSnapshot.select(git_repo)

    assert processes == closed
    assert all(process.poll() is not None for process in processes)
    monkeypatch.setattr(_BatchReader, "consume", original_consume)


@pytest.mark.parametrize("batch", [False, True], ids=["bounded-call", "batch"])
def test_thread_start_failure_reaps_a_spawned_git_child(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    batch: bool,
) -> None:
    spawned: list[subprocess.Popen[bytes]] = []
    original_popen = subprocess.Popen

    def recording_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = original_popen(*args, **kwargs)
        spawned.append(process)
        return process

    def fail_start(_thread: threading.Thread) -> None:
        raise RuntimeError("injected thread-start failure")

    monkeypatch.setattr(snapshot_module.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(snapshot_module.threading.Thread, "start", fail_start)
    private = tmp_path / "private.gitconfig"
    with pytest.raises(RuntimeError, match="injected thread-start failure"):
        if batch:
            snapshot_module._BatchReader(
                git_repo / ".git",
                environment=_git_environment(private),
                object_format="sha1",
            )
        else:
            snapshot_module._bounded_process(
                ("git", "version"),
                cwd=None,
                environment=_git_environment(private),
                input_bytes=None,
                output_limit=1024,
                seconds=5,
            )

    assert spawned and all(process.poll() is not None for process in spawned)


def test_snapshot_reads_commit_after_checkout_and_index_mutate(
    git_repo: pathlib.Path,
) -> None:
    selected = TreeSnapshot.select(git_repo)
    (git_repo / "tracked.txt").write_bytes(b"working tree replacement\n")
    _git(git_repo, "add", "tracked.txt")

    with selected:
        entry = selected.entry("tracked.txt")
        assert selected.blob(entry, limit=100) == b"committed bytes\n"


def test_closing_configuration_reaudit_cleans_up_before_refusing(
    git_repo: pathlib.Path,
) -> None:
    selected = TreeSnapshot.select(git_repo)
    with pytest.raises(
        SnapshotError, match="repository configuration changed during verification"
    ):
        with selected:
            process = selected._state.batch.process
            temporary = selected.temporary_directory
            _git(git_repo, "config", "snapshot.changed", "yes")

    assert process.poll() is not None
    assert temporary is not None and not temporary.exists()


def test_nested_tree_walk_covers_all_five_raw_modes(
    git_repo: pathlib.Path,
) -> None:
    plain = _hash_object(git_repo, "blob", b"plain\n")
    executable = _hash_object(git_repo, "blob", b"#!/bin/sh\n")
    link = _hash_object(git_repo, "blob", b"plain.txt")
    manifest = _hash_object(git_repo, "blob", b"{}\n")
    anchor = _hash_object(git_repo, "blob", b"certificate\n")
    manifests = _tree_object(
        git_repo, [(b"100644", b"release.json", manifest)]
    )
    anchors = _tree_object(git_repo, [(b"100644", b"root.pem", anchor)])
    releases = _tree_object(
        git_repo,
        [
            (b"40000", b"anchors", anchors),
            (b"40000", b"manifests", manifests),
        ],
    )
    root_tree = _tree_object(
        git_repo,
        [
            (b"100755", b"executable.sh", executable),
            (b"160000", b"foreign", ONE_OID),
            (b"120000", b"link", link),
            (b"100644", b"plain.txt", plain),
            (b"40000", b"releases", releases),
        ],
    )
    commit = _commit_object(git_repo, root_tree)

    with TreeSnapshot.select(git_repo, commit) as selected:
        listing = selected.entries("")
        flat = listing.as_dict(include_trees=True)
        assert isinstance(listing, TreeListing)
        assert isinstance(listing.children["releases"], TreeListing)
        assert {entry.mode for entry in flat.values()} == {
            "100644",
            "100755",
            "120000",
            "160000",
            "040000",
        }
        assert flat["foreign"].object_type == "commit"
        assert flat["foreign"].object_id == ONE_OID
        assert flat["releases"].object_type == "tree"
        manifest_entry = selected.entry("releases/manifests/release.json")
        assert manifest_entry == flat["releases/manifests/release.json"]
        assert selected.blob(manifest_entry, limit=3) == b"{}\n"
        with pytest.raises(
            SnapshotError, match="tree entry has non-regular mode 120000: link"
        ):
            selected.blob(selected.entry("link"), limit=32)

        digest_entries = [selected.entry("plain.txt"), manifest_entry]
        digests = dict(
            (entry.path, digest)
            for entry, digest in selected.digests(
                digest_entries, per_blob=32, total=64
            )
        )
        assert digests == {
            "plain.txt": hashlib.sha256(b"plain\n").hexdigest(),
            "releases/manifests/release.json": hashlib.sha256(b"{}\n").hexdigest(),
        }


def test_changed_paths_matches_git_diff_tree_oracle(
    git_repo: pathlib.Path,
) -> None:
    (git_repo / "unchanged.txt").write_bytes(b"same\n")
    (git_repo / "modified.txt").write_bytes(b"before\n")
    (git_repo / "deleted.txt").write_bytes(b"delete me\n")
    (git_repo / "mode.txt").write_bytes(b"mode\n")
    base = _commit_worktree(git_repo, "base")

    (git_repo / "modified.txt").write_bytes(b"after\n")
    (git_repo / "deleted.txt").unlink()
    (git_repo / "added.txt").write_bytes(b"new\n")
    (git_repo / "mode.txt").chmod(0o755)
    candidate = _commit_worktree(git_repo, "candidate")

    with TreeSnapshot.select(git_repo, candidate) as selected, TreeSnapshot.select(
        git_repo, base
    ) as prior:
        actual = selected.changed_paths(prior)

    oracle = _git(
        git_repo,
        "diff-tree",
        "-r",
        "--name-only",
        "-z",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        base,
        candidate,
    ).stdout
    expected = {
        os.fsdecode(path) for path in oracle.rstrip(b"\0").split(b"\0") if path
    }
    assert actual == expected == {
        "added.txt",
        "deleted.txt",
        "mode.txt",
        "modified.txt",
    }


def test_environment_drops_every_git_name_but_preserves_home(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = os.fspath(tmp_path / "ambient-home")
    monkeypatch.setenv("HOME", home)
    for name in GIT_ENVIRONMENT_DROPPED:
        monkeypatch.setenv(name, "hostile")
    monkeypatch.setenv("GIT_FUTURE_REDIRECT", "hostile")
    private = tmp_path / "private.gitconfig"

    environment = _git_environment(private)

    assert environment["HOME"] == home
    assert {name for name in environment if name.startswith("GIT_")} == {
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
    }
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"] == os.fspath(private)


def test_every_git_child_receives_frozen_environment_and_allowed_command(
    git_repo: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = os.fspath(tmp_path / "preserved-home")
    monkeypatch.setenv("HOME", home)
    monkeypatch.setenv("GIT_DIR", os.fspath(tmp_path / "wrong.git"))
    monkeypatch.setenv("GIT_WORK_TREE", os.fspath(tmp_path / "wrong-tree"))
    monkeypatch.setenv("GIT_INDEX_FILE", os.fspath(tmp_path / "wrong-index"))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", os.fspath(tmp_path / "wrong-objects"))
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.fsmonitor'='hostile'")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", os.fspath(tmp_path / "hooks"))
    monkeypatch.setenv("GIT_FUTURE_REDIRECT", "hostile")
    original_popen = subprocess.Popen
    calls: list[tuple[tuple[str, ...], dict[str, str], object]] = []

    def recording_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        argv = tuple(os.fspath(part) for part in args[0])
        environment = dict(kwargs["env"])
        calls.append((argv, environment, kwargs.get("cwd")))
        return original_popen(*args, **kwargs)

    monkeypatch.setattr(snapshot_module.subprocess, "Popen", recording_popen)
    with TreeSnapshot.select(git_repo) as selected:
        entry = selected.entry("tracked.txt")
        assert selected.blob(entry, limit=100) == b"committed bytes\n"
        assert selected.assert_ancestor(selected.commit) == selected.commit

    assert calls
    for argv, environment, cwd in calls:
        assert argv[0] == "git"
        assert cwd is None
        assert environment["HOME"] == home
        assert {name for name in environment if name.startswith("GIT_")} == {
            "GIT_NO_REPLACE_OBJECTS",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_GLOBAL",
        }
        assert not any(
            name in environment
            for name in {
                "GIT_CONFIG_PARAMETERS",
                "GIT_CONFIG_COUNT",
                "GIT_CONFIG_KEY_0",
                "GIT_CONFIG_VALUE_0",
                "GIT_FUTURE_REDIRECT",
            }
        )
    commands: list[tuple[str, ...]] = []
    for argv, _environment, _cwd in calls:
        command = list(argv[1:])
        if command[:2] == ["-C", os.fspath(git_repo)]:
            phase = "discovery"
            command = command[2:]
        elif command and command[0].startswith("--git-dir="):
            phase = "object"
            assert command[0] == f"--git-dir={git_repo / '.git'}"
            assert command[1] == "--no-replace-objects"
            command = command[2:]
        else:
            phase = "setup"
        if phase == "setup":
            assert command[0:2] == ["config", "-f"]
            command[2] = "<global>"
            command[-1] = "<root>"
        elif phase == "object" and command[0] == "rev-parse":
            command[-1] = "<rev>^{commit}"
        normalized = (phase, *command)
        assert normalized in GIT_COMMANDS
        commands.append(normalized)
    assert commands == [
        ("setup", "config", "-f", "<global>", "safe.directory", "<root>"),
        ("discovery", "version"),
        (
            "discovery",
            "rev-parse",
            "--show-toplevel",
            "--absolute-git-dir",
            "--git-common-dir",
            "--show-object-format",
        ),
        ("discovery", "config", "--list", "--show-scope", "--no-includes", "-z"),
        ("object", "rev-parse", "--verify", "--end-of-options", "<rev>^{commit}"),
        ("object", "cat-file", "--batch-command"),
        ("object", "cat-file", "--batch-command"),
        ("discovery", "config", "--list", "--show-scope", "--no-includes", "-z"),
    ]


def test_git_floor_pins_batch_command_introduction() -> None:
    assert GIT_MIN_VERSION == (2, 36, 0)
    assert ("object", "cat-file", "--batch-command") in GIT_COMMANDS
    completed = subprocess.run(
        ["git", "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if completed.returncode:
        pytest.skip("git is unavailable, so its reader floor cannot be exercised")
    installed = snapshot_module._parse_version(completed.stdout)
    if installed < GIT_MIN_VERSION:
        pytest.skip(
            "installed Git is below the explicit 2.36.0 batch-command floor"
        )
    assert installed >= GIT_MIN_VERSION


def _valid_commit_payload(
    *,
    tree: str = ONE_OID,
    parents: Iterable[str] = (),
    extra_headers: bytes = b"",
    message: bytes = b"message\n",
) -> bytes:
    parent_lines = b"".join(
        f"parent {parent}\n".encode("ascii") for parent in parents
    )
    return (
        f"tree {tree}\n".encode("ascii")
        + parent_lines
        + b"author A <a@example.test> 0 +0000\n"
        + b"committer C <c@example.test> 0 +0000\n"
        + extra_headers
        + b"\n"
        + message
    )


def test_canonical_commit_parses_merge_signed_header_and_ignores_message() -> None:
    payload = _valid_commit_payload(
        parents=(ZERO_OID, TWO_OID),
        extra_headers=(
            b"gpgsig -----BEGIN PGP SIGNATURE-----\n"
            b" signed-body\n"
            b" -----END PGP SIGNATURE-----\n"
            b"future-header opaque\n"
        ),
        message=f"subject\n\nparent {'f' * 40}\ntree {'e' * 40}\n".encode(),
    )

    parsed = _canonical_commit("f" * 40, payload, object_format="sha1")

    assert parsed.oid == "f" * 40
    assert parsed.tree == ONE_OID
    assert parsed.parents == (ZERO_OID, TWO_OID)


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(
            b"tree " + ONE_OID.encode() + b"\nauthor A\ncommitter C\n",
            id="missing-empty-line",
        ),
        pytest.param(
            b"parent "
            + ZERO_OID.encode()
            + b"\nauthor A\ncommitter C\n\n",
            id="tree-is-not-first",
        ),
        pytest.param(
            _valid_commit_payload(tree="1" * 39), id="short-tree-object-name"
        ),
        pytest.param(
            _valid_commit_payload(tree="A" * 40), id="uppercase-tree-object-name"
        ),
        pytest.param(
            _valid_commit_payload(tree="g" * 40), id="nonhex-tree-object-name"
        ),
        pytest.param(
            b"tree " + ONE_OID.encode() + b"\ncommitter C\n\n", id="missing-author"
        ),
        pytest.param(
            b"tree " + ONE_OID.encode() + b"\nauthor A\n\n", id="missing-committer"
        ),
        pytest.param(
            _valid_commit_payload(extra_headers=b"tree " + TWO_OID.encode() + b"\n"),
            id="second-tree",
        ),
        pytest.param(
            b"tree "
            + ONE_OID.encode()
            + b"\nauthor A\nparent "
            + ZERO_OID.encode()
            + b"\ncommitter C\n\n",
            id="parent-after-author",
        ),
        pytest.param(
            b" orphan continuation\ntree "
            + ONE_OID.encode()
            + b"\nauthor A\ncommitter C\n\n",
            id="orphan-continuation",
        ),
        pytest.param(
            b"tree "
            + ONE_OID.encode()
            + b"\nmalformed\nauthor A\ncommitter C\n\n",
            id="header-without-space",
        ),
    ],
)
def test_canonical_commit_refuses_every_malformed_shape(payload: bytes) -> None:
    oid = "f" * 40
    with pytest.raises(
        SnapshotError, match=rf"^commit {oid} is not a canonical commit object$"
    ):
        _canonical_commit(oid, payload, object_format="sha1")


def test_raw_tree_parser_accepts_five_modes_and_git_directory_sort_rule() -> None:
    payload = b"".join(
        [
            _tree_entry(b"100644", b"foo.bar", ZERO_OID),
            _tree_entry(b"40000", b"foo", ONE_OID),
            _tree_entry(b"100755", b"foo0", TWO_OID),
            _tree_entry(b"120000", b"link", "3" * 40),
            _tree_entry(b"160000", b"submodule", "4" * 40),
        ]
    )

    parsed = _parse_raw_tree("f" * 40, payload, object_format="sha1")

    assert [entry.mode for entry in parsed] == [
        b"100644",
        b"40000",
        b"100755",
        b"120000",
        b"160000",
    ]
    assert parsed[1].display_mode == "040000"
    assert parsed[1].object_type == "tree"
    assert parsed[3].object_type == "blob"
    assert parsed[4].object_type == "commit"


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        pytest.param(
            b"040000 legacy\0" + bytes(20),
            "unsupported raw mode",
            id="zero-padded-mode",
        ),
        pytest.param(b"100600 odd\0" + bytes(20), "unsupported raw mode", id="unknown-mode"),
        pytest.param(b"100644", "malformed entry", id="missing-space"),
        pytest.param(b"100644 name", "malformed entry", id="missing-nul"),
        pytest.param(b"100644 name\0" + bytes(19), "truncated object name", id="short-oid"),
        pytest.param(b"100644 \0" + bytes(20), "invalid entry name", id="empty-name"),
        pytest.param(b"100644 .\0" + bytes(20), "invalid entry name", id="dot-name"),
        pytest.param(b"100644 ..\0" + bytes(20), "invalid entry name", id="dotdot-name"),
        pytest.param(b"100644 a/b\0" + bytes(20), "invalid entry name", id="slash-name"),
        pytest.param(
            _tree_entry(b"100644", b"same", ZERO_OID)
            + _tree_entry(b"100755", b"same", ONE_OID),
            "duplicate entry name",
            id="duplicate-name",
        ),
        pytest.param(
            _tree_entry(b"100644", b"z", ZERO_OID)
            + _tree_entry(b"100644", b"a", ONE_OID),
            "not in canonical Git order",
            id="out-of-order",
        ),
        pytest.param(
            _tree_entry(b"40000", b"foo", ZERO_OID)
            + _tree_entry(b"100644", b"foo.bar", ONE_OID),
            "not in canonical Git order",
            id="directory-sort-rule",
        ),
    ],
)
def test_raw_tree_parser_refuses_noncanonical_entries(
    payload: bytes, message: str
) -> None:
    with pytest.raises(SnapshotError, match=message):
        _parse_raw_tree("f" * 40, payload, object_format="sha1")


def test_raw_tree_parser_refuses_entry_name_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(snapshot_module, "MAX_ENTRY_NAME_BYTES", 3)
    payload = _tree_entry(b"100644", b"four", ZERO_OID)
    with pytest.raises(
        SnapshotError, match="tree entry name exceeds the budget of 3 bytes"
    ):
        _parse_raw_tree("f" * 40, payload, object_format="sha1")


@pytest.mark.parametrize("payload", [b"not-newline-terminated", b"ends-in-lf\n"])
def test_batch_contents_treats_payload_bytes_separately_from_frame_lf(
    payload: bytes,
) -> None:
    oid = _object_oid("blob", payload)
    stream = f"{oid} blob {len(payload)}\n".encode("ascii") + payload + b"\n"
    reader = _fake_batch(stream, cached={oid: ("blob", len(payload))})

    assert reader.consume(oid, role="blob", limit=100, hold=True) == payload
    assert reader._stdin.getvalue() == f"contents {oid}\n".encode("ascii")
    assert not reader.abandoned


def test_batch_consume_uses_info_then_contents_protocol() -> None:
    payload = b"payload"
    oid = _object_oid("blob", payload)
    header = f"{oid} blob {len(payload)}\n".encode("ascii")
    reader = _fake_batch(header + header + payload + b"\n")

    assert reader.consume(oid, role="blob", limit=100, hold=True) == payload
    assert reader._stdin.getvalue() == (
        f"info {oid}\ncontents {oid}\n".encode("ascii")
    )


def test_abandoned_digest_iterator_blocks_later_requests_but_is_reaped(
    git_repo: pathlib.Path,
) -> None:
    (git_repo / "second.txt").write_bytes(b"second\n")
    _commit_worktree(git_repo, "second blob")
    selected = TreeSnapshot.select(git_repo)

    with selected:
        process = selected._state.batch.process
        temporary = selected.temporary_directory
        entries = [selected.entry("tracked.txt"), selected.entry("second.txt")]
        digests = selected.digests(entries, per_blob=100, total=200)
        first_entry, first_digest = next(digests)
        assert first_entry == entries[0]
        assert first_digest == hashlib.sha256(b"committed bytes\n").hexdigest()
        digests.close()
        with pytest.raises(SnapshotError, match="^snapshot stream was abandoned$"):
            selected.header(entries[1].object_id)

    assert process.poll() is not None
    assert temporary is not None and not temporary.exists()


@pytest.mark.parametrize("terminator", [b"", b"x"])
def test_batch_contents_refuses_missing_or_misplaced_frame_lf(
    terminator: bytes,
) -> None:
    payload = b"payload-without-lf"
    oid = _object_oid("blob", payload)
    stream = f"{oid} blob {len(payload)}\n".encode("ascii") + payload + terminator
    reader = _fake_batch(stream, cached={oid: ("blob", len(payload))})

    with pytest.raises(SnapshotError, match="^batch stream out of frame$"):
        reader.consume(oid, role="blob", limit=100, hold=True)
    assert reader.abandoned
    with pytest.raises(SnapshotError, match="^snapshot stream was abandoned$"):
        reader.info(oid)


def test_batch_contents_rehashes_the_exact_framed_object() -> None:
    expected = b"expected"
    altered = b"altered!"
    oid = _object_oid("blob", expected)
    stream = f"{oid} blob {len(altered)}\n".encode("ascii") + altered + b"\n"
    reader = _fake_batch(stream, cached={oid: ("blob", len(altered))})

    with pytest.raises(
        SnapshotError, match=rf"^object {oid} does not hash to its name$"
    ):
        reader.consume(oid, role="blob", limit=100, hold=True)


def test_batch_binds_type_to_role_before_requesting_contents() -> None:
    reader = _fake_batch(b"", cached={ONE_OID: ("tree", 0)})

    with pytest.raises(
        SnapshotError,
        match=rf"^object {ONE_OID} is a tree, not the blob its reference requires$",
    ):
        reader.consume(ONE_OID, role="blob", limit=100, hold=True)
    assert reader._stdin.getvalue() == b""


@pytest.mark.parametrize(
    ("shape", "reported_type", "required_role"),
    [
        ("blob-entry-names-tree", "tree", "blob"),
        ("commit-tree-names-blob", "blob", "tree"),
        ("tree-entry-names-blob", "blob", "tree"),
    ],
)
def test_selection_refuses_crafted_type_to_role_mismatch(
    git_repo: pathlib.Path,
    shape: str,
    reported_type: str,
    required_role: str,
) -> None:
    empty_tree = _tree_object(git_repo, [])
    blob = _hash_object(git_repo, "blob", b"payload")
    if shape == "blob-entry-names-tree":
        root_tree = _tree_object(
            git_repo, [(b"100644", b"file", empty_tree)]
        )
        commit = _commit_object(git_repo, root_tree)
        mismatched_oid = empty_tree
    elif shape == "commit-tree-names-blob":
        commit = _commit_object(git_repo, blob)
        mismatched_oid = blob
    else:
        root_tree = _tree_object(git_repo, [(b"40000", b"dir", blob)])
        commit = _commit_object(git_repo, root_tree)
        mismatched_oid = blob

    with pytest.raises(
        SnapshotError,
        match=(
            rf"^object {mismatched_oid} is a {reported_type}, not the "
            rf"{required_role} its reference requires$"
        ),
    ):
        TreeSnapshot.select(git_repo, commit)


def test_crafted_parent_type_mismatch_is_bound_before_parent_bytes() -> None:
    payload = _valid_commit_payload(parents=(ONE_OID,))
    parsed = _canonical_commit(TWO_OID, payload, object_format="sha1")
    reader = _fake_batch(b"", cached={ONE_OID: ("tree", 0)})

    assert parsed.parents == (ONE_OID,)
    with pytest.raises(
        SnapshotError,
        match=rf"^object {ONE_OID} is a tree, not the commit its reference requires$",
    ):
        reader.info(parsed.parents[0], role="commit")
    assert reader._stdin.getvalue() == b""


def test_selection_type_binds_a_crafted_parent_before_using_it(
    git_repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent_tree = _tree_object(git_repo, [])
    root_tree = _oid(git_repo, "HEAD^{tree}")
    commit = _commit_object(git_repo, root_tree, parents=(parent_tree,))
    original_git_run = snapshot_module._git_run

    def preserve_crafted_candidate(
        arguments: Iterable[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        argv = list(arguments)
        if argv[-1:] == [f"{commit}^{{commit}}"]:
            return subprocess.CompletedProcess(
                ["git", *argv], 0, f"{commit}\n".encode("ascii"), b""
            )
        return original_git_run(argv, **kwargs)

    # Git itself rejects the malformed parent during ``rev-parse OID^{commit}``.
    # Stub only that resolution response so the reader's own real batch child
    # must demonstrate the independently required role binding.
    monkeypatch.setattr(snapshot_module, "_git_run", preserve_crafted_candidate)
    with pytest.raises(
        SnapshotError,
        match=rf"^object {parent_tree} is a tree, not the commit its reference requires$",
    ):
        TreeSnapshot.select(git_repo, commit)


def test_parents_and_ancestry_walk_cover_both_merge_parents(
    git_repo: pathlib.Path,
) -> None:
    tree = _oid(git_repo, "HEAD^{tree}")
    base = _oid(git_repo)
    left = _commit_object(git_repo, tree, parents=(base,), message=b"left\n")
    right = _commit_object(git_repo, tree, parents=(base,), message=b"right\n")
    merge = _commit_object(
        git_repo, tree, parents=(left, right), message=b"merge\n"
    )

    with TreeSnapshot.select(git_repo, merge) as selected, TreeSnapshot.select(
        git_repo, left
    ) as left_snapshot:
        assert selected.parents(merge) == (left, right)
        assert selected.assert_ancestor(left_snapshot) == left
        assert selected.assert_ancestor(right) == right
        assert selected.assert_ancestor(base) == base
        assert selected.work.ancestry_commits >= 6


def test_ancestry_refuses_nonancestor_with_head_wording(
    git_repo: pathlib.Path,
) -> None:
    tree = _oid(git_repo, "HEAD^{tree}")
    unrelated = _commit_object(git_repo, tree, message=b"unrelated\n")

    with TreeSnapshot.select(git_repo) as selected:
        with pytest.raises(
            SnapshotError,
            match=rf"^base commit {unrelated} is not an ancestor of HEAD$",
        ):
            selected.assert_ancestor(unrelated)


def test_ancestry_refuses_nonancestor_with_named_candidate_wording(
    git_repo: pathlib.Path,
) -> None:
    tree = _oid(git_repo, "HEAD^{tree}")
    base = _oid(git_repo)
    candidate = _commit_object(git_repo, tree, parents=(base,))
    unrelated = _commit_object(git_repo, tree, message=b"unrelated\n")

    with TreeSnapshot.select(git_repo, candidate) as selected:
        with pytest.raises(
            SnapshotError,
            match=(
                rf"^base commit {unrelated} is not an ancestor of candidate "
                rf"commit {candidate}$"
            ),
        ):
            selected.assert_ancestor(unrelated)


def test_ancestry_walk_obeys_commit_budget(
    git_repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = _oid(git_repo, "HEAD^{tree}")
    base = _oid(git_repo)
    candidate = _commit_object(git_repo, tree, parents=(base,))
    monkeypatch.setattr(snapshot_module, "MAX_ANCESTRY_COMMITS", 1)

    with TreeSnapshot.select(git_repo, candidate) as selected:
        with pytest.raises(
            SnapshotError, match="ancestry walk exceeds the budget of 1 commits"
        ):
            selected.assert_ancestor(base)


def test_assert_ancestor_refuses_a_symbolic_name_without_resolving_it(
    git_repo: pathlib.Path,
) -> None:
    with TreeSnapshot.select(git_repo) as selected:
        with pytest.raises(
            SnapshotError,
            match=(
                "^object name is not full lowercase hexadecimal: "
                "'does-not-exist'$"
            ),
        ):
            selected.assert_ancestor("does-not-exist")
