"""Feature tests for attributes, private materialization, and store checks."""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import stat
import subprocess
from collections.abc import Iterable
from dataclasses import replace
from types import SimpleNamespace

import pytest

import receipt.snapshot as snapshot_module
from receipt.canonical import canonical_sha256
from receipt.snapshot import Materialization, SnapshotError, TreeSnapshot


CHRONICLE_ATTRIBUTES = b"""\
# Files whose exact Git and working-tree bytes are hashed by the release chain.
ledger/official_observations.jsonl text eol=lf
ledger/immutable_prefix.json text eol=lf
releases/manifests/*.json text eol=lf
releases/anchors/*.pem text eol=lf

# RFC 3161 timestamp responses are DER binary.
releases/manifests/*.tsr binary
"""


def _git(
    root: pathlib.Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    environment: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        ["git", "-C", os.fspath(root), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
    )
    if check and completed.returncode:
        raise AssertionError(
            f"git {' '.join(arguments)} failed: "
            f"{completed.stderr.decode(errors='replace')}"
        )
    return completed


def _commit(root: pathlib.Path, message: str = "fixture") -> str:
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message)
    return _git(root, "rev-parse", "HEAD").stdout.decode("ascii").strip()


def _write(root: pathlib.Path, relative: str, payload: bytes) -> pathlib.Path:
    path = root.joinpath(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


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
    ordered = sorted(
        entries,
        key=lambda item: item[1] + (b"/" if item[0] == b"40000" else b""),
    )
    return _hash_object(
        root,
        "tree",
        b"".join(_tree_entry(mode, name, oid) for mode, name, oid in ordered),
    )


def _commit_object(root: pathlib.Path, tree: str) -> str:
    payload = (
        f"tree {tree}\n".encode("ascii")
        + b"author Snapshot Test <snapshot@example.test> 0 +0000\n"
        + b"committer Snapshot Test <snapshot@example.test> 0 +0000\n\nfixture\n"
    )
    return _hash_object(root, "commit", payload)


def _snapshot_with_attributes(
    root: pathlib.Path, attributes: bytes, paths: Iterable[str]
) -> TreeSnapshot:
    _write(root, ".gitattributes", attributes)
    for path in paths:
        _write(root, path, f"bytes for {path}\n".encode())
    commit = _commit(root)
    return TreeSnapshot.select(root, commit)


def _raw_attribute_snapshot(root: pathlib.Path, attributes: bytes) -> TreeSnapshot:
    attribute_blob = _hash_object(root, "blob", attributes)
    protected_blob = _hash_object(root, "blob", b"protected bytes\n")
    tree = _tree_object(
        root,
        (
            (b"100644", b".gitattributes", attribute_blob),
            (b"100644", b"protected.txt", protected_blob),
        ),
    )
    return TreeSnapshot.select(root, _commit_object(root, tree))


def _cached_attribute_value(
    root: pathlib.Path,
    tmp_path: pathlib.Path,
    attribute: str,
    protected_path: str,
) -> bytes:
    """Return one hermetic ``check-attr --cached`` oracle value."""

    assert not (root / ".git" / "info" / "attributes").exists()
    empty_global = tmp_path / "empty-global.gitconfig"
    empty_global.write_bytes(b"")
    empty_attributes = tmp_path / "empty-global-attributes"
    empty_attributes.write_bytes(b"")
    environment = snapshot_module._git_environment(empty_global)
    system = subprocess.run(
        ["git", "var", "GIT_ATTR_SYSTEM"],
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert system.returncode == 0, system.stderr.decode(errors="replace")
    system_path = system.stdout.decode(errors="surrogateescape").strip()
    if system_path and pathlib.Path(system_path).exists():
        pytest.skip(f"Git system attributes file exists: {system_path}")
    assert not system_path or not pathlib.Path(system_path).exists()

    oracle = _git(
        root,
        "-c",
        f"core.attributesFile={empty_attributes}",
        "check-attr",
        "--cached",
        "-z",
        attribute,
        "--",
        protected_path,
        environment=environment,
    )
    fields = oracle.stdout.split(b"\0")
    assert fields[-1] == b""
    assert fields[1] == attribute.encode("ascii")
    return fields[2]


def _chain_spec(
    *, producer: object = "producer.pem", anchors: Iterable[object] = ("root.pem",)
) -> SimpleNamespace:
    return SimpleNamespace(
        anchor_relative=pathlib.PurePosixPath("anchors"),
        producer_public_key_filename=producer,
        anchors={
            f"anchor-{index}": SimpleNamespace(filename=filename)
            for index, filename in enumerate(anchors)
        },
    )


@pytest.fixture
def git_repo(tmp_path: pathlib.Path) -> pathlib.Path:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Snapshot Test")
    _git(root, "config", "user.email", "snapshot@example.test")
    return root


def test_exact_chronicle_eight_line_attributes_fixture_is_accepted(
    git_repo: pathlib.Path,
) -> None:
    """Carry the actual eight lines: five rules, two comments, and one blank.

    The fifth rule is ``releases/manifests/*.tsr binary``.
    """

    paths = (
        "ledger/official_observations.jsonl",
        "ledger/immutable_prefix.json",
        "releases/manifests/release.json",
        "releases/anchors/root.pem",
        "releases/manifests/release.tsr",
    )
    assert len(CHRONICLE_ATTRIBUTES.splitlines()) == 8
    selected = _snapshot_with_attributes(git_repo, CHRONICLE_ATTRIBUTES, paths)

    with selected:
        selected.refuse_transforming_attributes(paths)
        assert selected.work.attribute_rules == 5
        assert selected.work.attribute_bytes == len(CHRONICLE_ATTRIBUTES)
        assert (
            selected.work.attribute_match_work
            == 320
            < snapshot_module.MAX_ATTRIBUTE_MATCH_WORK
        )


def test_attribute_parser_accepts_leading_comments_and_a_blank_line(
    git_repo: pathlib.Path,
) -> None:
    attributes = (
        b"# Committed attribute policy.\n"
        b"   # An indented comment is ignored too, including opaque words.\n"
        b"\n"
        b"protected.txt text eol=lf\n"
    )
    selected = _raw_attribute_snapshot(git_repo, attributes)

    with selected:
        selected.refuse_transforming_attributes(("protected.txt",))
        assert selected.work.attribute_rules == 1


@pytest.mark.parametrize(
    ("attribute", "state", "refuses"),
    [
        ("filter", "filter", True),
        ("filter", "filter=cleaner", True),
        ("filter", "filter=", True),
        ("filter", "-filter", False),
        ("filter", "!filter", False),
        ("ident", "ident", True),
        ("ident", "ident=yes", True),
        ("ident", "-ident", False),
        ("ident", "!ident", False),
        ("working-tree-encoding", "working-tree-encoding", True),
        ("working-tree-encoding", "working-tree-encoding=UTF-16", True),
        ("working-tree-encoding", "-working-tree-encoding", False),
        ("working-tree-encoding", "!working-tree-encoding", False),
        ("text", "text", False),
        ("text", "text=auto", False),
        ("text", "-text", False),
        ("text", "!text", False),
        ("eol", "eol", False),
        ("eol", "eol=crlf", False),
        ("eol", "-eol", False),
        ("eol", "!eol", False),
        ("binary", "binary", False),
    ],
)
def test_attribute_states_refuse_only_enabled_transformations(
    git_repo: pathlib.Path,
    attribute: str,
    state: str,
    refuses: bool,
) -> None:
    selected = _raw_attribute_snapshot(
        git_repo, f"protected.txt {state}\n".encode()
    )

    with selected:
        if refuses:
            with pytest.raises(
                SnapshotError,
                match=rf"transforming attribute {attribute} applies to protected path",
            ):
                selected.refuse_transforming_attributes(("protected.txt",))
        else:
            selected.refuse_transforming_attributes(("protected.txt",))


@pytest.mark.parametrize(
    ("root_rules", "nested_rules", "refuses"),
    [
        (b"releases/** filter=evil\n", b"*.json -filter\n", False),
        (b"releases/** -filter\n", b"*.json filter=evil\n", True),
        (
            b"releases/** filter=evil\nreleases/** -filter\n",
            b"",
            False,
        ),
        (
            b"releases/** -filter\nreleases/** filter=evil\n",
            b"",
            True,
        ),
    ],
)
def test_attribute_precedence_uses_later_and_nearer_rules(
    git_repo: pathlib.Path,
    root_rules: bytes,
    nested_rules: bytes,
    refuses: bool,
) -> None:
    _write(git_repo, ".gitattributes", root_rules)
    if nested_rules:
        _write(git_repo, "releases/.gitattributes", nested_rules)
    _write(git_repo, "releases/release.json", b"{}\n")
    selected = TreeSnapshot.select(git_repo, _commit(git_repo))

    with selected:
        if refuses:
            with pytest.raises(SnapshotError, match="transforming attribute filter"):
                selected.refuse_transforming_attributes(("releases/release.json",))
        else:
            selected.refuse_transforming_attributes(("releases/release.json",))


@pytest.mark.parametrize(
    ("line", "construct"),
    [
        (b"file? filter\n", r"\?"),
        (b"file[0] filter\n", "bracket expression"),
        (b"file\\name filter\n", "backslash escape"),
        (b'"file" filter\n', "C-quoted pattern"),
        (b"!file filter\n", "negative pattern"),
        (b"[attr]xf filter=evil\n", "attribute macro definition"),
        (b"directory/ filter\n", "trailing slash"),
        (b"directory//file filter\n", "empty pattern segment"),
        (b"ab**cd filter\n", r"misplaced \*\*"),
        (b"** filter\n", r"misplaced \*\*"),
        (b"file\n", "line has no attribute state"),
        (b"\xff filter\n", "non-ASCII pattern"),
        (b"file filter\x01\n", "control byte"),
    ],
)
def test_attribute_parser_refuses_every_unsupported_construct(
    git_repo: pathlib.Path, line: bytes, construct: str
) -> None:
    selected = _snapshot_with_attributes(git_repo, line, ("file",))

    with selected, pytest.raises(
        SnapshotError,
        match=rf"^unsupported \.gitattributes construct at \.gitattributes:1: {construct}",
    ):
        selected.refuse_transforming_attributes(("file",))


def test_git_info_attributes_cannot_change_the_snapshot_answer(
    git_repo: pathlib.Path,
) -> None:
    _write(git_repo, "protected.txt", b"protected\n")
    commit = _commit(git_repo)
    info_attributes = git_repo / ".git" / "info" / "attributes"
    info_attributes.write_bytes(b"protected.txt filter=hostile\n")

    with TreeSnapshot.select(git_repo, commit) as selected:
        selected.refuse_transforming_attributes(("protected.txt",))


@pytest.mark.parametrize(
    ("mode", "display_mode"),
    ((b"120000", "120000"), (b"160000", "160000"), (b"40000", "040000")),
)
def test_nonblob_gitattributes_entry_refuses_as_unsupported(
    git_repo: pathlib.Path, mode: bytes, display_mode: str
) -> None:
    if mode == b"40000":
        attribute_target = _tree_object(git_repo, ())
    elif mode == b"160000":
        attribute_target = _commit_object(git_repo, _tree_object(git_repo, ()))
    else:
        attribute_target = _hash_object(git_repo, "blob", b"elsewhere")
    protected_blob = _hash_object(git_repo, "blob", b"protected bytes\n")
    tree = _tree_object(
        git_repo,
        (
            (mode, b".gitattributes", attribute_target),
            (b"100644", b"protected.txt", protected_blob),
        ),
    )
    commit = _commit_object(git_repo, tree)

    with TreeSnapshot.select(git_repo, commit) as selected:
        with pytest.raises(
            SnapshotError,
            match=(
                r"^unsupported \.gitattributes entry at \.gitattributes: "
                rf"mode {display_mode}$"
            ),
        ):
            selected.refuse_transforming_attributes(("protected.txt",))


def test_executable_gitattributes_entry_is_accepted(
    git_repo: pathlib.Path,
) -> None:
    attribute_blob = _hash_object(
        git_repo, "blob", b"protected.txt text eol=lf\n"
    )
    protected_blob = _hash_object(git_repo, "blob", b"protected bytes\n")
    tree = _tree_object(
        git_repo,
        (
            (b"100755", b".gitattributes", attribute_blob),
            (b"100644", b"protected.txt", protected_blob),
        ),
    )

    with TreeSnapshot.select(git_repo, _commit_object(git_repo, tree)) as selected:
        selected.refuse_transforming_attributes(("protected.txt",))


@pytest.mark.parametrize(
    ("pattern", "protected_path"),
    [
        ("*.json", "deep/value.json"),
        ("*.json", "deep/value.txt"),
        ("/root.txt", "root.txt"),
        ("/root.txt", "deep/root.txt"),
        ("/**", "root.txt"),
        ("/**", "deep/root.txt"),
        ("**/manifests/*.json", "a/b/manifests/release.json"),
        ("releases/**", "releases/a/b/receipt.json"),
        ("releases/**", "releases"),
        ("releases/**/receipt.json", "releases/receipt.json"),
        ("releases/**/receipt.json", "releases/a/b/receipt.json"),
        ("**/**", "a/b/file.txt"),
        ("/**/**", "a/b/file.txt"),
        ("**/**/**", "a/b/file.txt"),
    ],
)
def test_accepted_attribute_patterns_match_hermetic_git_oracle(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    pattern: str,
    protected_path: str,
) -> None:
    _write(git_repo, ".gitattributes", f"{pattern} filter=reader-test\n".encode())
    _write(git_repo, protected_path, b"protected\n")
    commit = _commit(git_repo)
    git_applies_filter = _cached_attribute_value(
        git_repo, tmp_path, "filter", protected_path
    ) != b"unspecified"

    reader_refused = False
    with TreeSnapshot.select(git_repo, commit) as selected:
        try:
            selected.refuse_transforming_attributes((protected_path,))
        except SnapshotError as exc:
            assert "transforming attribute filter applies" in str(exc)
            reader_refused = True
    assert reader_refused is git_applies_filter


@pytest.mark.parametrize(
    "neutralizing_line",
    [
        b"releases/*.json !filter -bogus",
        b"releases/*.json !filter".ljust(2047, b" "),
    ],
    ids=["valid-name", "largest-git-parsed-line"],
)
def test_attribute_line_boundaries_match_hermetic_git_oracle(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    neutralizing_line: bytes,
) -> None:
    protected_path = "releases/release.json"
    attributes = (
        b"releases/*.json filter=evil\n" + neutralizing_line + b"\n"
    )
    _write(git_repo, ".gitattributes", attributes)
    _write(git_repo, protected_path, b"{}\n")
    commit = _commit(git_repo)
    assert _cached_attribute_value(
        git_repo, tmp_path, "filter", protected_path
    ) == b"unspecified"

    with TreeSnapshot.select(git_repo, commit) as selected:
        selected.refuse_transforming_attributes((protected_path,))


@pytest.mark.parametrize(
    ("neutralizing_line", "construct"),
    [
        (
            b"releases/*.json !filter --bogus",
            "attribute name '-bogus'",
        ),
        (
            b"releases/*.json !filter builtin_probe",
            "attribute name 'builtin_probe'",
        ),
        (
            b"releases/*.json !filter".ljust(2048, b" "),
            "line longer than 2048 bytes",
        ),
    ],
    ids=["invalid-name", "reserved-name", "git-discarded-line"],
)
def test_attribute_lines_git_discards_refuse_fail_closed(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    neutralizing_line: bytes,
    construct: str,
) -> None:
    protected_path = "releases/release.json"
    attributes = (
        b"releases/*.json filter=evil\n" + neutralizing_line + b"\n"
    )
    _write(git_repo, ".gitattributes", attributes)
    _write(git_repo, protected_path, b"{}\n")
    commit = _commit(git_repo)
    assert _cached_attribute_value(
        git_repo, tmp_path, "filter", protected_path
    ) == b"evil"

    with TreeSnapshot.select(git_repo, commit) as selected, pytest.raises(
        SnapshotError,
        match=(
            r"^unsupported \.gitattributes construct at \.gitattributes:2: "
            + re.escape(construct)
            + r"$"
        ),
    ):
        selected.refuse_transforming_attributes((protected_path,))


def test_attribute_blob_nul_that_stops_git_refuses_fail_closed(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
) -> None:
    protected_path = "releases/release.json"
    attributes = (
        b"releases/*.json filter=evil\n"
        b"   # Git stops here\0\n"
        b"releases/*.json !filter\n"
    )
    _write(git_repo, ".gitattributes", attributes)
    _write(git_repo, protected_path, b"{}\n")
    commit = _commit(git_repo)
    assert _cached_attribute_value(
        git_repo, tmp_path, "filter", protected_path
    ) == b"evil"

    with TreeSnapshot.select(git_repo, commit) as selected, pytest.raises(
        SnapshotError,
        match=(
            r"^unsupported \.gitattributes construct at \.gitattributes:2: "
            r"control byte$"
        ),
    ):
        selected.refuse_transforming_attributes((protected_path,))


def test_materialization_selects_and_deduplicates_nested_prefixes(
    git_repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    _write(git_repo, "bundle/a.txt", b"A\n")
    executable = _write(git_repo, "bundle/nested/run.sh", b"#!/bin/sh\n")
    executable.chmod(0o755)
    _write(git_repo, "bundle/nested/data.bin", b"data")
    _write(git_repo, "single.txt", b"single\n")
    _write(git_repo, "outside.txt", b"outside\n")
    commit = _commit(git_repo)
    destination = tmp_path / "materializations"
    destination.mkdir()

    with TreeSnapshot.select(git_repo, commit) as selected:
        pending = selected.materialize(
            ("bundle", "bundle/nested", "single.txt", "missing"),
            destination,
            repertoire="portable",
        )
        with pytest.raises(SnapshotError, match="must be entered before its path"):
            _ = pending.path
        with pytest.raises(SnapshotError, match="must be entered before entries"):
            _ = pending.entries
        assert list(destination.iterdir()) == []

        with pending as materialized:
            materialized_path = materialized.path
            assert materialized_path.name.startswith(selected.tree[:12] + "-")
            assert stat.S_IMODE(materialized_path.stat().st_mode) == 0o700
            assert set(materialized.entries) == {
                "bundle/a.txt",
                "bundle/nested/data.bin",
                "bundle/nested/run.sh",
                "single.txt",
            }
            assert (materialized_path / "bundle" / "a.txt").read_bytes() == b"A\n"
            assert (materialized_path / "single.txt").read_bytes() == b"single\n"
            assert not (materialized_path / "outside.txt").exists()
            assert stat.S_IMODE(
                (materialized_path / "bundle" / "nested" / "run.sh").stat().st_mode
            ) == 0o755
            assert stat.S_IMODE(
                (materialized_path / "bundle" / "a.txt").stat().st_mode
            ) == 0o644
            assert selected.work.materialized_bytes == len(b"A\n#!/bin/sh\ndata") + len(
                b"single\n"
            )

        assert not materialized_path.exists()
        assert list(destination.iterdir()) == []
        with pytest.raises(SnapshotError, match="materialization is closed"):
            pending.__enter__()


def test_materialization_accepts_chain_spec_pure_posix_prefixes(
    git_repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    _write(git_repo, "releases/manifest.json", b"{}\n")
    _commit(git_repo)
    destination = tmp_path / "materializations"
    destination.mkdir()

    with TreeSnapshot.select(git_repo) as selected:
        with selected.materialize(
            (pathlib.PurePosixPath("releases"),),
            destination,
            repertoire="portable",
        ) as materialized:
            assert set(materialized.entries) == {"releases/manifest.json"}


def test_materialization_prefix_deduplication_does_not_scan_all_parents(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_path_parts = TreeSnapshot._path_parts
    slice_reads = 0

    class CountingTuple(tuple[bytes, ...]):
        def __getitem__(self, key: object) -> object:
            nonlocal slice_reads
            if isinstance(key, slice):
                slice_reads += 1
            return super().__getitem__(key)  # type: ignore[call-overload]

    def counting_path_parts(
        path: str | bytes, *, allow_empty: bool
    ) -> tuple[bytes, ...]:
        return CountingTuple(original_path_parts(path, allow_empty=allow_empty))

    monkeypatch.setattr(
        TreeSnapshot, "_path_parts", staticmethod(counting_path_parts)
    )
    _write(git_repo, "seed.txt", b"seed\n")
    _commit(git_repo)
    prefixes = tuple(f"missing-{index:04d}" for index in range(128))
    destination = tmp_path / "materializations"
    destination.mkdir()

    with TreeSnapshot.select(git_repo) as selected:
        pending = selected.materialize(
            prefixes, destination, repertoire="portable"
        )
        assert pending._deduplicated_prefixes() == tuple(
            (prefix.encode("ascii"),) for prefix in prefixes
        )

    assert slice_reads < 2 * len(prefixes)


@pytest.mark.parametrize(
    ("names", "message"),
    [
        ((b"bad name",), "is not a portable name"),
        ((b"Case", b"case"), "merge under ASCII case folding"),
    ],
)
def test_materialization_runs_name_screens_before_creating_a_directory(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    names: tuple[bytes, ...],
    message: str,
) -> None:
    blob = _hash_object(git_repo, "blob", b"bytes\n")
    tree = _tree_object(
        git_repo, ((b"100644", name, blob) for name in names)
    )
    commit = _commit_object(git_repo, tree)
    destination = tmp_path / "materializations"
    destination.mkdir()

    with TreeSnapshot.select(git_repo, commit) as selected:
        pending = selected.materialize(("",), destination, repertoire="posix-bytes")

        def forbidden_mkdtemp(*args: object, **kwargs: object) -> str:
            del args, kwargs
            raise AssertionError("mkdtemp ran before the name screen")

        monkeypatch.setattr(snapshot_module.tempfile, "mkdtemp", forbidden_mkdtemp)
        with pytest.raises(SnapshotError, match=message) as caught:
            pending.__enter__()
        if names == (b"Case", b"case"):
            assert str(caught.value) == (
                "tree root contains names that merge under ASCII case folding: "
                "'Case' and 'case'"
            )

    assert list(destination.iterdir()) == []


def test_materialization_refuses_nonregular_entry_before_creating_directory(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    link_blob = _hash_object(git_repo, "blob", b"target")
    tree = _tree_object(git_repo, ((b"120000", b"link", link_blob),))
    commit = _commit_object(git_repo, tree)
    destination = tmp_path / "materializations"
    destination.mkdir()

    with TreeSnapshot.select(git_repo, commit) as selected:
        pending = selected.materialize(("link",), destination, repertoire="portable")

        def forbidden_mkdtemp(*args: object, **kwargs: object) -> str:
            del args, kwargs
            raise AssertionError("mkdtemp ran before the entry-mode screen")

        monkeypatch.setattr(snapshot_module.tempfile, "mkdtemp", forbidden_mkdtemp)
        with pytest.raises(
            SnapshotError, match="base tree entry has non-regular mode 120000: link"
        ):
            pending.__enter__()

    assert list(destination.iterdir()) == []


def test_materialization_removes_partial_directory_when_a_write_fails(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write(git_repo, "first.txt", b"first\n")
    _write(git_repo, "second.txt", b"second\n")
    commit = _commit(git_repo)
    destination = tmp_path / "materializations"
    destination.mkdir()
    original_write = Materialization._write_chunk
    writes = 0

    def fail_write(
        self: Materialization, handle: object, chunk: bytes
    ) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("injected write failure")
        original_write(self, handle, chunk)  # type: ignore[arg-type]

    monkeypatch.setattr(Materialization, "_write_chunk", fail_write)
    with TreeSnapshot.select(git_repo, commit) as selected:
        process = selected._state.batch.process
        temporary = selected.temporary_directory
        pending = selected.materialize(
            (("first.txt", "second.txt")), destination, repertoire="portable"
        )
        with pytest.raises(OSError, match="injected write failure"):
            pending.__enter__()

    assert writes == 2
    assert selected.work.materialized_bytes == len(b"first\n")
    assert process.poll() is not None
    assert process.stdin is not None and process.stdin.closed
    assert process.stdout is not None and process.stdout.closed
    assert process.stderr is not None and process.stderr.closed
    assert temporary is not None and not temporary.exists()
    assert list(destination.iterdir()) == []


class _ShortWritingHandle:
    def __init__(self, *, fail_after: int | None = None) -> None:
        self.payload = bytearray()
        self.fail_after = fail_after

    def write(self, payload: memoryview) -> int:
        if self.fail_after is not None and len(self.payload) >= self.fail_after:
            raise OSError("injected short-write failure")
        count = min(2, len(payload))
        self.payload.extend(payload[:count])
        return count


def test_materialization_charges_each_successful_short_write(
    git_repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    _write(git_repo, "tracked.txt", b"tracked\n")
    _commit(git_repo)
    destination = tmp_path / "materializations"
    destination.mkdir()

    with TreeSnapshot.select(git_repo) as selected:
        pending = selected.materialize((), destination, repertoire="portable")
        complete = _ShortWritingHandle()
        pending._write_chunk(complete, b"abcdef")
        assert bytes(complete.payload) == b"abcdef"
        assert selected.work.materialized_bytes == 6

        interrupted = _ShortWritingHandle(fail_after=2)
        with pytest.raises(OSError, match="injected short-write failure"):
            pending._write_chunk(interrupted, b"wxyz")
        assert bytes(interrupted.payload) == b"wx"
        assert selected.work.materialized_bytes == 8


def test_materialization_removes_directory_after_downstream_exception(
    git_repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    _write(git_repo, "selected.txt", b"selected\n")
    commit = _commit(git_repo)
    destination = tmp_path / "materializations"
    destination.mkdir()

    with pytest.raises(RuntimeError, match="downstream failed"):
        with TreeSnapshot.select(git_repo, commit) as selected:
            pending = selected.materialize(
                ("selected.txt",), destination, repertoire="portable"
            )
            with pending as materialized:
                materialized_path = materialized.path
                raise RuntimeError("downstream failed")

    assert not materialized_path.exists()
    assert list(destination.iterdir()) == []


def test_materialization_cleanup_failure_is_not_hidden_by_body_exception(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write(git_repo, "selected.txt", b"selected\n")
    commit = _commit(git_repo)
    destination = tmp_path / "materializations"
    destination.mkdir()
    original_rmtree = snapshot_module.shutil.rmtree

    with pytest.raises(RuntimeError, match="body failed") as caught:
        with TreeSnapshot.select(git_repo, commit) as selected:
            pending = selected.materialize(
                ("selected.txt",), destination, repertoire="portable"
            )
            with pending as materialized:
                materialized_path = materialized.path

                def fail_cleanup(
                    path: os.PathLike[str] | str,
                    *args: object,
                    **kwargs: object,
                ) -> None:
                    if pathlib.Path(path) == materialized_path:
                        raise OSError("injected cleanup failure")
                    original_rmtree(path, *args, **kwargs)

                monkeypatch.setattr(snapshot_module.shutil, "rmtree", fail_cleanup)
                raise RuntimeError("body failed")

    assert any(
        "Materialization cleanup also failed: injected cleanup failure" in note
        for note in caught.value.__notes__
    )
    original_rmtree(materialized_path)
    assert list(destination.iterdir()) == []


def test_materialization_rejects_scalar_prefixes_and_forged_entries(
    git_repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    _write(git_repo, "selected.txt", b"selected\n")
    commit = _commit(git_repo)
    destination = tmp_path / "materializations"
    destination.mkdir()

    with TreeSnapshot.select(git_repo, commit) as first, TreeSnapshot.select(
        git_repo, commit
    ) as second:
        with pytest.raises(
            SnapshotError, match="prefixes must be an iterable of paths"
        ):
            first.materialize("selected.txt", destination, repertoire="portable")
        foreign_entry = first.entry("selected.txt")
        with pytest.raises(
            SnapshotError, match="GitEntry does not belong to this snapshot"
        ):
            second.blob(foreign_entry, limit=100)
        with pytest.raises(SnapshotError, match="limit must be a non-negative integer"):
            first.blob(foreign_entry, limit=True)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("mode", "100755"),
        ("object_type", "tree"),
        ("object_id", "0" * 40),
        ("path", "forged.txt"),
    ),
)
def test_entry_binding_refuses_dataclass_replacements(
    git_repo: pathlib.Path, field: str, value: str
) -> None:
    _write(git_repo, "selected.txt", b"selected\n")
    commit = _commit(git_repo)

    with TreeSnapshot.select(git_repo, commit) as selected:
        entry = selected.entry("selected.txt")
        altered = replace(entry, **{field: value})
        with pytest.raises(
            SnapshotError, match="GitEntry does not belong to this snapshot"
        ):
            selected.blob(altered, limit=100)


def test_anchor_set_digest_is_canonical_over_configured_materialized_bytes(
    git_repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    payloads = {
        "producer.pem": b"producer public key\n",
        "root.pem": b"root certificate\n",
        "timestamp.pem": b"timestamp certificate\n",
    }
    for filename, payload in payloads.items():
        _write(git_repo, f"anchors/{filename}", payload)
    _write(git_repo, "anchors/unconfigured.pem", b"not part of digest\n")
    commit = _commit(git_repo)
    destination = tmp_path / "materializations"
    destination.mkdir()
    chain_spec = _chain_spec(anchors=("root.pem", "timestamp.pem"))
    expected = canonical_sha256(
        {
            filename: hashlib.sha256(payload).hexdigest()
            for filename, payload in payloads.items()
        }
    )

    with TreeSnapshot.select(git_repo, commit) as selected:
        pending = selected.materialize(
            ("anchors",), destination, repertoire="portable"
        )
        with pytest.raises(SnapshotError, match="must be entered before anchor"):
            pending.anchor_set_sha256(chain_spec)
        with pending as materialized:
            assert materialized.anchor_set_sha256(chain_spec) == expected
            assert "anchors/unconfigured.pem" in materialized.entries


def test_anchor_filename_refuses_explicit_surrogate_pairs_but_accepts_astral_text() -> None:
    astral = "\U00010000.pem"
    explicit_pair = "\ud800\udc00.pem"

    assert Materialization._exact_filename(astral) == astral
    with pytest.raises(
        SnapshotError,
        match="spells an astral character as an explicit surrogate pair",
    ):
        Materialization._exact_filename(explicit_pair)


@pytest.mark.parametrize(
    ("chain_spec", "message"),
    [
        (
            _chain_spec(anchors=("missing.pem",)),
            "configured anchor was not materialized: anchors/missing.pem",
        ),
        (
            _chain_spec(producer=123),
            "anchor filenames must be str or os.PathLike",
        ),
        (
            _chain_spec(producer="../escape.pem"),
            "configured anchor filename leaves the anchor directory",
        ),
        (
            SimpleNamespace(
                anchor_relative="anchors",
                producer_public_key_filename="producer.pem",
                anchors={},
            ),
            "chain_spec anchor_relative must be a PurePosixPath",
        ),
    ],
)
def test_anchor_set_digest_refuses_incomplete_or_ambiguous_configuration(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    chain_spec: SimpleNamespace,
    message: str,
) -> None:
    _write(git_repo, "anchors/producer.pem", b"producer\n")
    _write(git_repo, "anchors/root.pem", b"root\n")
    commit = _commit(git_repo)
    destination = tmp_path / "materializations"
    destination.mkdir()

    with TreeSnapshot.select(git_repo, commit) as selected:
        with selected.materialize(
            ("anchors",), destination, repertoire="portable"
        ) as materialized:
            with pytest.raises(SnapshotError, match=message):
                materialized.anchor_set_sha256(chain_spec)


def test_reader_budget_constants_are_pinned_to_the_frozen_values() -> None:
    expected = {
        "MAX_TREE_ENTRIES": 1_048_576,
        "MAX_TREE_OBJECT_BYTES": 64 * 1024 * 1024,
        "MAX_TREE_BYTES_TOTAL": 512 * 1024 * 1024,
        "MAX_ENTRY_NAME_BYTES": 4_096,
        "MAX_PATH_BYTES": 4_096,
        "MAX_PATH_BYTES_TOTAL": 256 * 1024 * 1024,
        "MAX_GIT_OUTPUT_BYTES": 1 * 1024 * 1024,
        "MAX_GIT_SECONDS": 60,
        "BATCH_KILL_REAP_SECONDS": 5,
        "MAX_TREE_DEPTH": 256,
        "MAX_ANCESTRY_COMMITS": 1_048_576,
        "MAX_ATTRIBUTE_BYTES": 1 * 1024 * 1024,
        "MAX_ATTRIBUTE_BYTES_TOTAL": 16 * 1024 * 1024,
        "MAX_ATTRIBUTE_RULES_TOTAL": 65_536,
        "MAX_ATTRIBUTE_STATES_PER_LINE": 256,
        "MAX_ATTRIBUTE_MATCH_WORK": 67_108_864,
        "MAX_CONTENT_BLOB_BYTES": 256 * 1024 * 1024,
        "MAX_CONTENT_BYTES_TOTAL": 16 * 1024 * 1024 * 1024,
        "MAX_MATERIALIZED_BYTES": 4 * 1024 * 1024 * 1024,
        "MAX_MATERIALIZED_BLOB_BYTES": 64 * 1024 * 1024,
        "MAX_FSCK_OBJECTS": 4_194_304,
        "MAX_STORE_KIB": 16 * 1024 * 1024,
        "MAX_FSCK_OUTPUT_BYTES": 1 * 1024 * 1024,
        "MAX_FSCK_SECONDS": 600,
    }
    assert {
        name: getattr(snapshot_module, name) for name in expected
    } == expected


@pytest.mark.parametrize(
    ("field", "constant", "message"),
    [
        ("path_bytes", "MAX_PATH_BYTES_TOTAL", "tree paths exceed"),
        ("attribute_bytes", "MAX_ATTRIBUTE_BYTES_TOTAL", "attribute bytes exceed"),
        ("attribute_rules", "MAX_ATTRIBUTE_RULES_TOTAL", "attribute rules exceed"),
        (
            "attribute_match_work",
            "MAX_ATTRIBUTE_MATCH_WORK",
            "attribute matching exceeds",
        ),
        ("content_bytes", "MAX_CONTENT_BYTES_TOTAL", "content bytes exceed"),
        ("materialized_bytes", "MAX_MATERIALIZED_BYTES", "materialized bytes exceed"),
    ],
)
def test_verification_wide_budgets_are_shared_by_candidate_and_base(
    git_repo: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    constant: str,
    message: str,
) -> None:
    _write(git_repo, "file.txt", b"bytes\n")
    commit = _commit(git_repo)
    candidate = TreeSnapshot.select(git_repo, commit)
    base = TreeSnapshot.select(git_repo, commit)
    setattr(candidate.work, field, 6)
    setattr(base.work, field, 5)
    monkeypatch.setattr(snapshot_module, constant, 10)

    with candidate, base, pytest.raises(SnapshotError, match=message):
        candidate.changed_paths(base)


def test_attribute_file_byte_budget_refuses_before_payload_moves(
    git_repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = _raw_attribute_snapshot(
        git_repo, b"protected.txt filter=evil\n"
    )
    monkeypatch.setattr(snapshot_module, "MAX_ATTRIBUTE_BYTES", 3)

    with selected, pytest.raises(
        SnapshotError, match="exceeds the payload budget of 3 bytes"
    ):
        selected.refuse_transforming_attributes(("protected.txt",))
    assert selected.work.attribute_bytes == 0


def test_attribute_cumulative_byte_budget_counts_nested_files(
    git_repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root_rules = b"nested/** -filter\n"
    nested_rules = b"protected.txt -filter\n"
    _write(git_repo, ".gitattributes", root_rules)
    _write(git_repo, "nested/.gitattributes", nested_rules)
    _write(git_repo, "nested/protected.txt", b"protected\n")
    commit = _commit(git_repo)
    monkeypatch.setattr(
        snapshot_module, "MAX_ATTRIBUTE_BYTES_TOTAL", len(root_rules)
    )

    with TreeSnapshot.select(git_repo, commit) as selected, pytest.raises(
        SnapshotError, match="attribute bytes exceed the snapshot budget"
    ):
        selected.refuse_transforming_attributes(("nested/protected.txt",))


def test_attribute_rule_and_match_work_budgets(
    git_repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = _raw_attribute_snapshot(
        git_repo,
        b"protected.txt -filter\nprotected.txt -ident\n",
    )
    monkeypatch.setattr(snapshot_module, "MAX_ATTRIBUTE_RULES_TOTAL", 1)
    with selected, pytest.raises(
        SnapshotError, match="attribute rules exceed the snapshot budget of 1 rules"
    ):
        selected.refuse_transforming_attributes(("protected.txt",))

    second = _raw_attribute_snapshot(
        git_repo, b"protected.txt -filter\n"
    )
    monkeypatch.setattr(snapshot_module, "MAX_ATTRIBUTE_RULES_TOTAL", 65_536)
    monkeypatch.setattr(snapshot_module, "MAX_ATTRIBUTE_MATCH_WORK", 0)
    with second, pytest.raises(
        SnapshotError, match="attribute matching exceeds the work budget of 0 steps"
    ):
        second.refuse_transforming_attributes(("protected.txt",))


def test_attribute_parser_enforces_rule_budget_while_expanding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(snapshot_module, "MAX_ATTRIBUTE_RULES_TOTAL", 1)

    with pytest.raises(
        SnapshotError,
        match=(
            "^attribute rules exceed the snapshot budget of 1 rules$"
        ),
    ):
        snapshot_module._parse_attribute_file(
            ".gitattributes",
            b"one -filter\ntwo -ident\n",
            rule_limit=1,
        )


def test_attribute_state_application_is_charged_per_matching_path(
    git_repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reviewer's 1,000-state/500-path shape charges every application."""

    attributes = b"*.json " + b" ".join([b"a"] * 1_000) + b"\n"
    paths = tuple(f"releases/m{index:04d}.json" for index in range(500))
    selected = _raw_attribute_snapshot(git_repo, attributes)
    monkeypatch.setattr(
        snapshot_module,
        "MAX_ATTRIBUTE_STATES_PER_LINE",
        1_000,
        raising=False,
    )

    with selected:
        selected.refuse_transforming_attributes(paths)
        assert selected.work.attribute_match_work == 505_500


def test_attribute_state_count_has_a_per_line_ceiling(
    git_repo: pathlib.Path,
) -> None:
    attributes = b"* " + b" ".join([b"a"] * 257) + b"\n"
    selected = _raw_attribute_snapshot(git_repo, attributes)

    with selected, pytest.raises(
        SnapshotError,
        match=(
            r"^attribute states at \.gitattributes:1 exceed the per-line "
            r"budget of 256 states$"
        ),
    ):
        selected.refuse_transforming_attributes(("protected.txt",))


def test_digest_per_blob_and_cumulative_budgets(
    git_repo: pathlib.Path,
) -> None:
    _write(git_repo, "one.txt", b"one")
    _write(git_repo, "two.txt", b"two")
    commit = _commit(git_repo)

    with TreeSnapshot.select(git_repo, commit) as selected:
        entries = (selected.entry("one.txt"), selected.entry("two.txt"))
        with pytest.raises(
            SnapshotError, match="content blob 'one.txt' exceeds the budget of 2 bytes"
        ):
            next(selected.digests(entries, per_blob=2, total=100))

    with TreeSnapshot.select(git_repo, commit) as selected:
        entries = (selected.entry("one.txt"), selected.entry("two.txt"))
        with pytest.raises(
            SnapshotError, match="content bytes exceed the budget of 5 bytes"
        ):
            list(selected.digests(entries, per_blob=3, total=5))


def test_digests_refuses_a_symlink_entry_before_reading_its_target(
    git_repo: pathlib.Path,
) -> None:
    target = b"../../outside/secret"
    target_blob = _hash_object(git_repo, "blob", target)
    tree = _tree_object(git_repo, ((b"120000", b"link", target_blob),))

    with TreeSnapshot.select(git_repo, _commit_object(git_repo, tree)) as selected:
        entry = selected.entry("link")
        with pytest.raises(
            SnapshotError,
            match=r"^tree entry has non-regular mode 120000: link$",
        ):
            next(selected.digests((entry,)))
        assert selected.work.content_bytes == 0


@pytest.mark.parametrize(
    ("constant", "value", "message"),
    [
        ("MAX_MATERIALIZED_BLOB_BYTES", 2, "materialized blob 'one.txt'"),
        ("MAX_MATERIALIZED_BYTES", 5, "materialized bytes exceed"),
    ],
)
def test_materialization_byte_budgets_remove_partial_output(
    git_repo: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    value: int,
    message: str,
) -> None:
    _write(git_repo, "one.txt", b"one")
    _write(git_repo, "two.txt", b"two")
    commit = _commit(git_repo)
    destination = tmp_path / "materializations"
    destination.mkdir()
    monkeypatch.setattr(snapshot_module, constant, value)

    with TreeSnapshot.select(git_repo, commit) as selected:
        pending = selected.materialize(("",), destination, repertoire="portable")
        with pytest.raises(SnapshotError, match=message):
            pending.__enter__()
        expected_written = 0 if constant == "MAX_MATERIALIZED_BLOB_BYTES" else 3
        assert selected.work.materialized_bytes == expected_written
    assert list(destination.iterdir()) == []


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


def test_verify_object_store_happy_path_and_scalar_guards(
    git_repo: pathlib.Path,
) -> None:
    _require_store_verification_support()
    _write(git_repo, "file.txt", b"bytes\n")
    commit = _commit(git_repo)

    with TreeSnapshot.select(git_repo, commit, verify_objects=True) as selected:
        with pytest.raises(
            SnapshotError, match="heads must be an iterable of OIDs"
        ):
            selected.verify_object_store(selected.commit)
        report = selected.verify_object_store((selected.commit,))
        assert report.objects >= 3
        assert report.store_kib >= 0
        assert report.seconds >= 0
        with pytest.raises(SnapshotError, match="may be run only once"):
            selected.verify_object_store((selected.commit,))


@pytest.mark.parametrize(
    "head_shape",
    ("unproven-base", "missing-proven-base", "different-second-head"),
)
def test_verify_object_store_requires_the_exact_authenticated_heads(
    git_repo: pathlib.Path,
    head_shape: str,
) -> None:
    _require_store_verification_support()
    _write(git_repo, "base.txt", b"base\n")
    base = _commit(git_repo, "base")
    _write(git_repo, "candidate.txt", b"candidate\n")
    candidate = _commit(git_repo, "candidate")
    candidate_tree = (
        _git(git_repo, "rev-parse", f"{candidate}^{{tree}}")
        .stdout.decode("ascii")
        .strip()
    )
    different = _commit_object(git_repo, candidate_tree)

    with TreeSnapshot.select(
        git_repo, candidate, verify_objects=True
    ) as selected:
        if head_shape == "unproven-base":
            with pytest.raises(
                SnapshotError,
                match=(
                    r"^verify_object_store heads must be exactly the resolved "
                    r"candidate and base$"
                ),
            ):
                selected.verify_object_store((candidate, base))
        else:
            with TreeSnapshot.select(git_repo, base) as prior:
                assert selected.assert_ancestor(prior) == base
                supplied = (
                    (candidate,)
                    if head_shape == "missing-proven-base"
                    else (candidate, different)
                )
                with pytest.raises(
                    SnapshotError,
                    match=(
                        r"^verify_object_store heads must be exactly the resolved "
                        r"candidate and base$"
                    ),
                ):
                    selected.verify_object_store(supplied)


@pytest.mark.parametrize(
    ("constant", "message"),
    [
        ("MAX_FSCK_OBJECTS", "object database exceeds the budget of 0 objects"),
        ("MAX_STORE_KIB", "object database exceeds the budget of 0 KiB"),
    ],
)
def test_verify_object_store_count_and_size_budgets(
    git_repo: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    message: str,
) -> None:
    _require_store_verification_support()
    _write(git_repo, "file.txt", b"bytes\n")
    commit = _commit(git_repo)
    monkeypatch.setattr(snapshot_module, constant, 0)

    with TreeSnapshot.select(git_repo, commit, verify_objects=True) as selected:
        with pytest.raises(SnapshotError, match=message):
            selected.verify_object_store((selected.commit,))
