"""Hostile-repository and object-store tests for the immutable tree reader.

Test-only Git commands construct adversarial repositories and serve as
oracles.  Production code remains constrained to ``GIT_COMMANDS``.
"""

from __future__ import annotations

import os
import pathlib
import stat
import subprocess
import zlib

import pytest

import receipt.snapshot as snapshot_module
from receipt.snapshot import (
    GIT_COMMANDS,
    GIT_ENVIRONMENT_DROPPED,
    GIT_ENVIRONMENT_DROPPED_DOCUMENTED,
    GIT_ENVIRONMENT_DROPPED_UNDOCUMENTED,
    GIT_FSCK_NO_REFERENCES_MIN_VERSION,
    SnapshotError,
    TreeSnapshot,
)


EXPECTED_GIT_ENVIRONMENT_DROPPED = (
    "GIT_ADVICE",
    "GIT_ALLOW_PROTOCOL",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_ASKPASS",
    "GIT_ATTR_SOURCE",
    "GIT_AUTHOR_DATE",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_NAME",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMITTER_DATE",
    "GIT_COMMITTER_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMIT_GRAPH_PARANOIA",
    "GIT_COMMON_DIR",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_SYSTEM",
    "GIT_DEFAULT_HASH",
    "GIT_DEFAULT_REF_FORMAT",
    "GIT_DIFF_OPTS",
    "GIT_DIFF_PATH_COUNTER",
    "GIT_DIFF_PATH_TOTAL",
    "GIT_DIR",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_EDITOR",
    "GIT_EXEC_PATH",
    "GIT_EXTERNAL_DIFF",
    "GIT_EXTERNAL_DIFF_TRUST_EXIT_CODE",
    "GIT_FLUSH",
    "GIT_GLOB_PATHSPECS",
    "GIT_ICASE_PATHSPECS",
    "GIT_INDEX_FILE",
    "GIT_INDEX_VERSION",
    "GIT_LITERAL_PATHSPECS",
    "GIT_MERGE_VERBOSITY",
    "GIT_NAMESPACE",
    "GIT_NOGLOB_PATHSPECS",
    "GIT_NO_LAZY_FETCH",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_OBJECT_DIRECTORY",
    "GIT_OPTIONAL_LOCKS",
    "GIT_PAGER",
    "GIT_PRINT_SHA1_ELLIPSIS",
    "GIT_PROGRESS_DELAY",
    "GIT_PROTOCOL",
    "GIT_PROTOCOL_FROM_USER",
    "GIT_REDIRECT_STDERR",
    "GIT_REDIRECT_STDIN",
    "GIT_REDIRECT_STDOUT",
    "GIT_REFLOG_ACTION",
    "GIT_REF_PARANOIA",
    "GIT_SEQUENCE_EDITOR",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_SSH_VARIANT",
    "GIT_SSL_NO_VERIFY",
    "GIT_TERMINAL_PROMPT",
    "GIT_TRACE",
    "GIT_TRACE2",
    "GIT_TRACE2_EVENT",
    "GIT_TRACE2_PERF",
    "GIT_TRACE_CURL",
    "GIT_TRACE_CURL_NO_DATA",
    "GIT_TRACE_FSMONITOR",
    "GIT_TRACE_PACKET",
    "GIT_TRACE_PACKFILE",
    "GIT_TRACE_PACK_ACCESS",
    "GIT_TRACE_PERFORMANCE",
    "GIT_TRACE_REDACT",
    "GIT_TRACE_REFS",
    "GIT_TRACE_SETUP",
    "GIT_TRACE_SHALLOW",
    "GIT_WORK_TREE",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_<n>",
    "GIT_CONFIG_VALUE_<n>",
)

EXPECTED_GIT_COMMANDS = (
    ("setup", "config", "-f", "<global>", "safe.directory", "<root>"),
    ("discovery", "version"),
    ("discovery", "version", "--build-options"),
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
    ("object", "count-objects", "-v"),
    (
        "object",
        "-c",
        "core.commitGraph=false",
        "fsck",
        "--full",
        "--no-dangling",
        "--no-reflogs",
        "--no-references",
        "--no-progress",
        "<candidate>",
        "[<base>]",
    ),
)


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


def _commit(root: pathlib.Path, message: str) -> str:
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message)
    return _oid(root)


def _new_repository(tmp_path: pathlib.Path, name: str = "repository") -> pathlib.Path:
    root = tmp_path / name
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Snapshot Security Test")
    _git(root, "config", "user.email", "snapshot-security@example.test")
    (root / "tracked.txt").write_bytes(b"original committed bytes\n")
    _commit(root, "initial")
    return root


@pytest.fixture
def git_repo(tmp_path: pathlib.Path) -> pathlib.Path:
    return _new_repository(tmp_path)


def _git_dir(root: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(
        _git(root, "rev-parse", "--absolute-git-dir")
        .stdout.decode("utf-8")
        .strip()
    )


def _common_dir(root: pathlib.Path) -> pathlib.Path:
    value = (
        _git(root, "rev-parse", "--path-format=absolute", "--git-common-dir")
        .stdout.decode("utf-8")
        .strip()
    )
    return pathlib.Path(value)


def _write_control_file(directory: pathlib.Path, kind: str) -> pathlib.Path:
    relative = {
        "grafts": pathlib.Path("info/grafts"),
        "shallow": pathlib.Path("shallow"),
        "alternates": pathlib.Path("objects/info/alternates"),
    }[kind]
    target = directory / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"\n")
    return target


def _rewrite_loose_object(
    root: pathlib.Path, oid: str, object_type: str, payload: bytes
) -> pathlib.Path:
    framed = f"{object_type} {len(payload)}\0".encode("ascii") + payload
    target = _git_dir(root) / "objects" / oid[:2] / oid[2:]
    assert target.is_file(), f"fixture object {oid} is not loose"
    target.chmod(stat.S_IRUSR | stat.S_IWUSR)
    target.write_bytes(zlib.compress(framed))
    return target


def _verify_objects_support() -> tuple[int, int, int]:
    completed = subprocess.run(
        ["git", "version", "--build-options"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        pytest.skip("git build options are unavailable")
    version = snapshot_module._parse_version(completed.stdout)
    if version < GIT_FSCK_NO_REFERENCES_MIN_VERSION:
        pytest.skip("Git is below the 2.50.0 fsck --no-references floor")
    if b"SHA-1: SHA1_DC" not in completed.stdout.splitlines():
        pytest.skip("Git was not built with SHA1_DC")
    return version


def test_git_environment_and_command_allow_lists_are_frozen_independently() -> None:
    assert GIT_ENVIRONMENT_DROPPED == EXPECTED_GIT_ENVIRONMENT_DROPPED
    assert len(GIT_ENVIRONMENT_DROPPED_DOCUMENTED) == 73
    assert GIT_COMMANDS == EXPECTED_GIT_COMMANDS


@pytest.mark.parametrize(
    ("version_output", "message"),
    (
        (
            b"git version 2.53.0\nSHA-1: SHA1_OPENSSL\n",
            "--verify-objects requires a Git build using SHA-1: SHA1_DC",
        ),
        (
            b"git version 2.49.0\nSHA-1: SHA1_DC\n",
            "--verify-objects requires Git 2.50.0 or later for fsck --no-references",
        ),
    ),
)
def test_verify_objects_preflights_hash_implementation_and_fsck_floor(
    git_repo: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    version_output: bytes,
    message: str,
) -> None:
    original_git_run = snapshot_module._git_run
    commands: list[tuple[str, ...]] = []

    def controlled_git_run(
        arguments: object, **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        argv = tuple(arguments)  # type: ignore[arg-type]
        commands.append(argv)
        if argv[-2:] == ("version", "--build-options"):
            return subprocess.CompletedProcess(
                ["git", *argv], 0, version_output, b""
            )
        return original_git_run(argv, **kwargs)

    monkeypatch.setattr(snapshot_module, "_git_run", controlled_git_run)
    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(git_repo, verify_objects=True)
    assert str(caught.value) == message
    assert commands[-1][-2:] == ("version", "--build-options")


CONFIG_DENY_CASES = (
    ("include.path", "/does/not/exist"),
    ("includeif.gitdir:/hostile/.path", "/does/not/exist"),
    ("core.fsmonitor", "false"),
    ("core.hookspath", "/hostile/hooks"),
    ("core.alternaterefscommand", "hostile-command"),
    ("core.gitproxy", "hostile-command"),
    ("core.sshcommand", "hostile-command"),
    ("core.askpass", "hostile-command"),
    ("extensions.partialclone", "origin"),
    ("remote.origin.promisor", "false"),
    ("remote.origin.partialclonefilter", "blob:none"),
    ("fsck.missingemail", "ignore"),
    ("receive.fsck.missingemail", "ignore"),
    ("transfer.fsckobjects", "false"),
    ("transfer.fsck.missingemail", "ignore"),
)


@pytest.mark.parametrize(("key", "value"), CONFIG_DENY_CASES)
def test_every_repository_configuration_deny_family_refuses(
    git_repo: pathlib.Path, key: str, value: str
) -> None:
    _git(git_repo, "config", key, value)

    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(git_repo)

    assert str(caught.value) == (
        f"repository configuration key {key!r} is not allowed for immutable "
        "tree reads"
    )


def test_valueless_local_configuration_is_implicit_true(
    git_repo: pathlib.Path,
) -> None:
    config = git_repo / ".git" / "config"
    config.write_bytes(config.read_bytes() + b"\n[probe]\n\tflag\n")

    selected = TreeSnapshot.select(git_repo)

    assert ("local", "probe.flag", "true") in selected._state.config_records


def test_valueless_denied_configuration_refuses_through_deny_list(
    git_repo: pathlib.Path,
) -> None:
    config = git_repo / ".git" / "config"
    config.write_bytes(config.read_bytes() + b"\n[core]\n\tfsmonitor\n")

    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(git_repo)

    assert str(caught.value) == (
        "repository configuration key 'core.fsmonitor' is not allowed for "
        "immutable tree reads"
    )


def test_worktree_scope_configuration_is_included_in_the_deny_audit(
    git_repo: pathlib.Path,
) -> None:
    _git(git_repo, "config", "extensions.worktreeConfig", "true")
    configured = _git(
        git_repo,
        "config",
        "--worktree",
        "core.hooksPath",
        "/hostile/worktree-hooks",
        check=False,
    )
    if configured.returncode:
        pytest.fail(
            "this Git advertises worktree config but could not create the test "
            f"fixture: {configured.stderr.decode(errors='replace')}"
        )

    listing = _git(
        git_repo,
        "config",
        "--list",
        "--show-scope",
        "--no-includes",
    ).stdout
    assert b"worktree\tcore.hookspath=/hostile/worktree-hooks" in listing
    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(git_repo)
    assert str(caught.value) == (
        "repository configuration key 'core.hookspath' is not allowed for "
        "immutable tree reads"
    )


HOSTILE_GIT_NAMES = (
    *GIT_ENVIRONMENT_DROPPED_DOCUMENTED,
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_0",
    "GIT_CONFIG_VALUE_0",
    "GIT_FUTURE_REPOSITORY_REDIRECT",
)


@pytest.mark.parametrize("name", HOSTILE_GIT_NAMES)
def test_each_hostile_git_environment_name_is_inert_during_selection(
    git_repo: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    expected = _oid(git_repo)
    hostile_value = {
        "GIT_CONFIG_PARAMETERS": "'core.hooksPath'='/hostile/hooks'",
        "GIT_CONFIG_COUNT": "not-a-number",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "GIT_CONFIG_VALUE_0": "/hostile/hooks",
    }.get(name, "hostile")
    monkeypatch.setenv(name, hostile_value)

    selected = TreeSnapshot.select(git_repo)

    assert selected.commit == expected


def test_numbered_git_config_environment_channel_is_dropped_as_a_unit(
    git_repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "extensions.partialClone")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "origin")

    selected = TreeSnapshot.select(git_repo)

    assert selected.commit == _oid(git_repo)
    assert GIT_ENVIRONMENT_DROPPED_UNDOCUMENTED == (
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_<n>",
        "GIT_CONFIG_VALUE_<n>",
    )


@pytest.mark.parametrize(
    ("present", "message"),
    (
        (("grafts", "shallow", "alternates"), "repository grafts are unsupported"),
        (("shallow", "alternates"), "shallow repositories are unsupported"),
        (("alternates",), "alternate object databases are unsupported"),
    ),
)
def test_repository_control_refusals_follow_the_frozen_order(
    git_repo: pathlib.Path,
    present: tuple[str, ...],
    message: str,
) -> None:
    for kind in present:
        _write_control_file(_git_dir(git_repo), kind)
    _git(git_repo, "config", "extensions.partialClone", "origin")

    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(git_repo)

    assert str(caught.value) == message


def test_configuration_audit_precedes_candidate_resolution(
    git_repo: pathlib.Path,
) -> None:
    _git(git_repo, "config", "core.hooksPath", "/hostile/hooks")

    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(git_repo, "missing-revision")

    assert str(caught.value) == (
        "repository configuration key 'core.hookspath' is not allowed for "
        "immutable tree reads"
    )


def test_not_top_level_refuses_before_repository_control_files(
    git_repo: pathlib.Path,
) -> None:
    nested = git_repo / "nested"
    nested.mkdir()
    _write_control_file(_git_dir(git_repo), "grafts")

    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(nested)

    assert str(caught.value) == "root is not the top level of its repository"


@pytest.mark.parametrize(
    ("kind", "message"),
    (
        ("grafts", "repository grafts are unsupported"),
        ("shallow", "shallow repositories are unsupported"),
        ("alternates", "alternate object databases are unsupported"),
    ),
)
def test_linked_worktree_checks_its_common_directory(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    kind: str,
    message: str,
) -> None:
    linked = tmp_path / "linked"
    _git(git_repo, "worktree", "add", "-q", "--detach", os.fspath(linked), "HEAD")
    assert _git_dir(linked) != _common_dir(linked)
    assert _common_dir(linked) == _git_dir(git_repo)
    _write_control_file(_common_dir(linked), kind)

    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(linked)

    assert str(caught.value) == message


@pytest.mark.parametrize(
    ("kind", "message"),
    (
        ("grafts", "repository grafts are unsupported"),
        ("shallow", "shallow repositories are unsupported"),
        ("alternates", "alternate object databases are unsupported"),
    ),
)
def test_linked_worktree_checks_its_private_git_directory(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    kind: str,
    message: str,
) -> None:
    linked = tmp_path / "linked-private"
    _git(git_repo, "worktree", "add", "-q", "--detach", os.fspath(linked), "HEAD")
    _write_control_file(_git_dir(linked), kind)

    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(linked)

    assert str(caught.value) == message


def test_sha256_refuses_before_alternates_and_partial_clone_configuration(
    tmp_path: pathlib.Path,
) -> None:
    root = tmp_path / "sha256"
    root.mkdir()
    initialized = _git(root, "init", "-q", "--object-format=sha256", check=False)
    if initialized.returncode:
        pytest.skip("installed Git does not support SHA-256 repositories")
    _git(root, "config", "user.name", "Snapshot Security Test")
    _git(root, "config", "user.email", "snapshot-security@example.test")
    (root / "tracked.txt").write_bytes(b"sha256 fixture\n")
    _commit(root, "sha256")
    _write_control_file(_git_dir(root), "alternates")
    _git(root, "config", "extensions.partialClone", "origin")

    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(root)

    assert str(caught.value) == (
        "SHA-256 repositories are unsupported until a complete reader fixture exists"
    )


@pytest.mark.parametrize(
    ("kind", "message"),
    (
        ("grafts", "repository grafts are unsupported"),
        ("shallow", "shallow repositories are unsupported"),
    ),
)
def test_repository_history_sentinels_precede_sha256_refusal(
    tmp_path: pathlib.Path, kind: str, message: str
) -> None:
    root = tmp_path / f"sha256-{kind}"
    root.mkdir()
    initialized = _git(root, "init", "-q", "--object-format=sha256", check=False)
    if initialized.returncode:
        pytest.skip("installed Git does not support SHA-256 repositories")
    _write_control_file(_git_dir(root), kind)

    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(root)

    assert str(caught.value) == message


def test_select_refuses_an_existing_nonrepository(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "not-a-repository"
    root.mkdir()

    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(root)

    assert str(caught.value) == (
        f"candidate repository is missing or not a git repository: {root}"
    )


@pytest.mark.parametrize("kind", ("missing", "file"))
def test_select_refuses_a_root_that_is_not_a_directory(
    tmp_path: pathlib.Path, kind: str
) -> None:
    root = tmp_path / kind
    if kind == "file":
        root.write_bytes(b"not a directory\n")

    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(root)

    assert str(caught.value) == (
        f"candidate repository is missing or not a git repository: {root}"
    )


def test_select_refuses_a_bare_repository(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "bare.git"
    initialized = subprocess.run(
        ["git", "init", "--bare", "-q", os.fspath(root)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert initialized.returncode == 0

    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(root)

    assert str(caught.value) == (
        f"candidate repository is missing or not a git repository: {root}"
    )


def test_private_global_config_serializes_a_hostile_root_spelling(
    tmp_path: pathlib.Path,
) -> None:
    root = _new_repository(tmp_path, "space ' quote \\ repository")

    selected = TreeSnapshot.select(root)

    assert [
        (key, value)
        for scope, key, value in selected._state.config_records
        if scope == "global"
    ] == [("safe.directory", os.fspath(root))]
    assert not any(
        scope == "system" for scope, _key, _value in selected._state.config_records
    )


def test_select_ignores_broken_repository_config_in_callers_cwd(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caller = _new_repository(tmp_path, "caller")
    (caller / ".git" / "config").write_bytes(b"broken config line\n")
    monkeypatch.chdir(caller)

    with TreeSnapshot.select(git_repo) as selected:
        assert selected.root == git_repo.resolve()
        assert selected.blob(selected.entry("tracked.txt"), limit=100) == (
            b"original committed bytes\n"
        )


@pytest.mark.parametrize(
    ("kind", "message"),
    (
        ("grafts", "repository grafts are unsupported"),
        ("shallow", "shallow repositories are unsupported"),
        ("alternates", "alternate object databases are unsupported"),
    ),
)
def test_repository_control_file_added_before_entry_refuses_without_leaking(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    message: str,
) -> None:
    selected = TreeSnapshot.select(git_repo)
    temporary_root = tmp_path / "temporary"
    temporary_root.mkdir()
    monkeypatch.setattr(snapshot_module.tempfile, "tempdir", os.fspath(temporary_root))
    _write_control_file(_git_dir(git_repo), kind)

    with pytest.raises(SnapshotError, match=f"^{message}$"):
        selected.__enter__()

    assert selected.batch_pid is None
    assert tuple(temporary_root.iterdir()) == ()


def test_replace_refs_cannot_change_the_selected_commit_or_bytes(
    git_repo: pathlib.Path,
) -> None:
    original = _oid(git_repo)
    original_tree = _oid(git_repo, f"{original}^{{tree}}")
    (git_repo / "tracked.txt").write_bytes(b"replacement committed bytes\n")
    replacement = _commit(git_repo, "replacement")
    replacement_tree = _oid(git_repo, f"{replacement}^{{tree}}")
    assert replacement_tree != original_tree
    _git(git_repo, "replace", original, replacement)

    replaced = _git(git_repo, "show", f"{original}:tracked.txt").stdout
    unreplaced = _git(
        git_repo,
        "--no-replace-objects",
        "show",
        f"{original}:tracked.txt",
    ).stdout
    assert replaced == b"replacement committed bytes\n"
    assert unreplaced == b"original committed bytes\n"

    with TreeSnapshot.select(git_repo, original) as selected:
        entry = selected.entry("tracked.txt")
        assert selected.commit == original
        assert selected.tree == original_tree
        assert selected.blob(entry, limit=100) == b"original committed bytes\n"


def test_candidate_tree_is_rehashed_even_when_cat_file_serves_tampered_bytes(
    git_repo: pathlib.Path,
) -> None:
    candidate = _oid(git_repo)
    tree = _oid(git_repo, f"{candidate}^{{tree}}")
    original = _git(git_repo, "cat-file", "tree", tree).stdout
    forged = original.replace(b"tracked.txt", b"forged_.txt")
    assert forged != original and len(forged) == len(original)
    _rewrite_loose_object(git_repo, tree, "tree", forged)

    served = _git(git_repo, "cat-file", "tree", tree, check=False)
    assert served.returncode == 0
    assert served.stdout == forged
    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(git_repo, candidate)
    assert str(caught.value) == f"object {tree} does not hash to its name"


def test_candidate_tree_rehash_precedes_parent_role_binding(
    git_repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = _oid(git_repo, "HEAD^{tree}")
    commit_payload = (
        f"tree {tree}\nparent {tree}\n".encode("ascii")
        + b"author Snapshot Test <snapshot@example.test> 0 +0000\n"
        + b"committer Snapshot Test <snapshot@example.test> 0 +0000\n\n"
        + b"crafted parent role mismatch\n"
    )
    commit = (
        _git(
            git_repo,
            "hash-object",
            "--literally",
            "-t",
            "commit",
            "-w",
            "--stdin",
            input_bytes=commit_payload,
        )
        .stdout.decode("ascii")
        .strip()
    )
    original = _git(git_repo, "cat-file", "tree", tree).stdout
    forged = original.replace(b"tracked.txt", b"forged_.txt")
    assert forged != original and len(forged) == len(original)
    _rewrite_loose_object(git_repo, tree, "tree", forged)
    original_git_run = snapshot_module._git_run

    def preserve_crafted_candidate(
        arguments: object, **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        argv = tuple(arguments)  # type: ignore[arg-type]
        if argv[-1:] == (f"{commit}^{{commit}}",):
            return subprocess.CompletedProcess(
                ["git", *argv], 0, f"{commit}\n".encode("ascii"), b""
            )
        return original_git_run(argv, **kwargs)

    monkeypatch.setattr(snapshot_module, "_git_run", preserve_crafted_candidate)
    with pytest.raises(SnapshotError) as caught:
        TreeSnapshot.select(git_repo, commit)

    assert str(caught.value) == f"object {tree} does not hash to its name"


def test_content_blob_is_rehashed_after_selection_when_its_loose_file_changes(
    git_repo: pathlib.Path,
) -> None:
    blob_oid = _oid(git_repo, "HEAD:tracked.txt")
    selected = TreeSnapshot.select(git_repo)
    forged = b"forged!! committed bytes\n"
    _rewrite_loose_object(git_repo, blob_oid, "blob", forged)

    served = _git(git_repo, "cat-file", "blob", blob_oid, check=False)
    assert served.returncode == 0
    assert served.stdout == forged
    with selected as entered:
        entry = entered.entry("tracked.txt")
        with pytest.raises(SnapshotError) as caught:
            entered.blob(entry, limit=100)
    assert str(caught.value) == f"object {blob_oid} does not hash to its name"


def test_verify_objects_catches_a_tampered_unreachable_loose_object(
    git_repo: pathlib.Path,
) -> None:
    _verify_objects_support()
    pristine = b"unreachable pristine payload\n"
    unreachable = (
        _git(
            git_repo,
            "hash-object",
            "-w",
            "--stdin",
            input_bytes=pristine,
        )
        .stdout.decode("ascii")
        .strip()
    )
    forged = b"unreachable forged!! payload\n"
    _rewrite_loose_object(git_repo, unreachable, "blob", forged)

    served = _git(git_repo, "cat-file", "blob", unreachable, check=False)
    assert served.returncode == 0
    assert served.stdout == forged
    assert TreeSnapshot.select(git_repo).commit == _oid(git_repo)

    selected = TreeSnapshot.select(git_repo, verify_objects=True)
    with selected as entered:
        with pytest.raises(SnapshotError) as caught:
            entered.verify_object_store([entered.commit])
    assert str(caught.value).startswith(
        "object database failed git's own verification: "
    )


def test_verify_objects_catches_a_byte_flip_in_a_pack(
    git_repo: pathlib.Path,
) -> None:
    _verify_objects_support()
    unreachable: list[str] = []
    for index in range(24):
        unreachable.append(
            _git(
                git_repo,
                "hash-object",
                "-w",
                "--stdin",
                input_bytes=(f"unreachable packed object {index}\n" * 200).encode(
                    "ascii"
                ),
            )
            .stdout.decode("ascii")
            .strip()
        )
    pack_prefix = _git_dir(git_repo) / "objects" / "pack" / "pack"
    _git(
        git_repo,
        "pack-objects",
        os.fspath(pack_prefix),
        input_bytes=("\n".join(unreachable) + "\n").encode("ascii"),
    )
    _git(git_repo, "prune-packed")
    packs = sorted((_git_dir(git_repo) / "objects" / "pack").glob("*.pack"))
    assert len(packs) == 1
    pack = packs[0]
    index = pack.with_suffix(".idx")
    records: list[tuple[int, int]] = []
    for line in _git(git_repo, "verify-pack", "-v", os.fspath(index)).stdout.splitlines():
        fields = line.split()
        if len(fields) >= 5 and len(fields[0]) == 40:
            records.append((int(fields[4]), int(fields[3])))
    records.sort()
    assert len(records) == len(unreachable)
    offset, packed_size = records[len(records) // 2]
    assert offset > records[0][0]
    packed = bytearray(pack.read_bytes())
    flip_at = offset + max(1, packed_size // 2)
    assert flip_at < len(packed) - 20
    packed[flip_at] ^= 0x01
    pack.chmod(stat.S_IRUSR | stat.S_IWUSR)
    pack.write_bytes(packed)

    candidate = _oid(git_repo)
    assert _git(git_repo, "cat-file", "commit", candidate).returncode == 0
    selected = TreeSnapshot.select(git_repo, candidate, verify_objects=True)
    with selected as entered:
        with pytest.raises(SnapshotError) as caught:
            entered.verify_object_store([candidate])
    assert str(caught.value).startswith(
        "object database failed git's own verification: "
    )


def _normalize_recorded_command(
    argv: tuple[str, ...], root: pathlib.Path, git_dir: pathlib.Path
) -> tuple[str, ...]:
    command = list(argv[1:])
    if command and command[0] == "version":
        phase = "discovery"
    elif command[:2] == ["-C", os.fspath(root)]:
        phase = "discovery"
        command = command[2:]
    elif command and command[0].startswith("--git-dir="):
        phase = "object"
        assert command[0] == f"--git-dir={git_dir}"
        assert command[1] == "--no-replace-objects"
        command = command[2:]
    else:
        phase = "setup"
    if phase == "setup":
        assert command[:2] == ["config", "-f"]
        command[2] = "<global>"
        command[-1] = "<root>"
    elif phase == "object" and command[0] == "rev-parse":
        command[-1] = "<rev>^{commit}"
    elif phase == "object" and command[:3] == [
        "-c",
        "core.commitGraph=false",
        "fsck",
    ]:
        command[-2:] = ["<candidate>", "[<base>]"]
    return (phase, *command)


def test_full_verify_objects_uses_exact_commands_heads_and_environment(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _verify_objects_support()
    base = _oid(git_repo)
    (git_repo / "second.txt").write_bytes(b"second\n")
    candidate = _commit(git_repo, "candidate")
    git_dir = _git_dir(git_repo)
    home = os.fspath(tmp_path / "preserved-home")
    monkeypatch.setenv("HOME", home)
    monkeypatch.setenv("GIT_DIR", os.fspath(tmp_path / "hostile.git"))
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'fsck.missingEmail'='ignore'")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "fsck.missingEmail")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "ignore")
    original_popen = subprocess.Popen
    calls: list[tuple[tuple[str, ...], dict[str, str], object]] = []

    def recording_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        argv = tuple(os.fspath(part) for part in args[0])
        environment = dict(kwargs["env"])
        calls.append((argv, environment, kwargs.get("cwd")))
        return original_popen(*args, **kwargs)

    monkeypatch.setattr(snapshot_module.subprocess, "Popen", recording_popen)
    with TreeSnapshot.select(
        git_repo, candidate, verify_objects=True
    ) as selected, TreeSnapshot.select(git_repo, base) as base_snapshot:
        assert selected.assert_ancestor(base_snapshot) == base
        report = selected.verify_object_store([candidate, base])
        assert report.objects > 0

    git_keys = {
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
    }
    for argv, environment, cwd in calls:
        assert argv[0] == "git"
        if argv[1:3] == ("config", "-f"):
            assert isinstance(cwd, pathlib.Path)
            assert cwd.name.startswith("receipt-snapshot-select-")
        elif argv[1:2] == ("version",):
            assert isinstance(cwd, pathlib.Path)
            assert cwd.name.startswith("receipt-snapshot-discovery-")
        else:
            assert cwd is None
        assert environment["HOME"] == home
        assert {name for name in environment if name.startswith("GIT_")} == git_keys
        assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
        assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
        assert environment["GIT_CONFIG_GLOBAL"]

    fsck_argv = (
        "git",
        f"--git-dir={git_dir}",
        "--no-replace-objects",
        "-c",
        "core.commitGraph=false",
        "fsck",
        "--full",
        "--no-dangling",
        "--no-reflogs",
        "--no-references",
        "--no-progress",
        candidate,
        base,
    )
    assert [argv for argv, _environment, _cwd in calls if "fsck" in argv] == [
        fsck_argv
    ]
    assert [
        argv for argv, _environment, _cwd in calls if "count-objects" in argv
    ] == [
        (
            "git",
            f"--git-dir={git_dir}",
            "--no-replace-objects",
            "count-objects",
            "-v",
        )
    ]

    normalized = [
        _normalize_recorded_command(argv, git_repo, git_dir)
        for argv, _environment, _cwd in calls
    ]
    assert all(command in GIT_COMMANDS for command in normalized)
    assert normalized == [
        ("setup", "config", "-f", "<global>", "safe.directory", "<root>"),
        ("discovery", "version", "--build-options"),
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
        ("object", "count-objects", "-v"),
        (
            "object",
            "-c",
            "core.commitGraph=false",
            "fsck",
            "--full",
            "--no-dangling",
            "--no-reflogs",
            "--no-references",
            "--no-progress",
            "<candidate>",
            "[<base>]",
        ),
        ("discovery", "config", "--list", "--show-scope", "--no-includes", "-z"),
        ("discovery", "config", "--list", "--show-scope", "--no-includes", "-z"),
    ]
