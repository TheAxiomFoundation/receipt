"""The anchor-set digest: a verdict names the anchor bytes the run consumed.

receipt#24's second half, in its post-review shape: digests are captured at
the verification read sites themselves (OpenSSL is fed a snapshot of the
digested bytes), the computation is opt-in so pre-existing callers keep
byte-identical behavior, and the combined digest is receipt-canonical JSON —
an injective encoding for any accepted filename strings.

Two tests at the end are labelled S4-F6 and belong to a fourth review gate's
first round on the append-gate branch: the ``O_NOFOLLOW`` requirement was
documented as the append gate's, and this is where it is shown to be the
package's — ``verify_release_chain`` and ``receipt verify``'s custody pass
refuse on the same platforms, in the same words, with no append gate in the
picture.

Two more are labelled S5-R2-F3 and belong to that branch's fifth gate, second
round, for the same reason: the release tree's confinement walk was added for
the append gate and reached only from there, so the public verifier had none
of it.

One at the end is labelled S5-G1-F2 and belongs to a fresh gate's first round:
the whole-index alias scan compared each entry against the three paths a
``ChainSpec`` carries and against nothing else, and a caller with configured
surfaces of its own protects more than that. It is the package-level half —
that the widening is the caller's to ask for and changes nothing for a caller
that does not.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
from dataclasses import replace

import pytest

from receipt import release_chain
from receipt.canonical import canonical_sha256
from receipt.release_chain import (
    ReleaseChainError,
    TIME_STAMP_RE,
    _combined_anchor_digest,
    _observe_anchor_bytes,
    _parse_receipt_text,
    _receipt_bytes,
    _regular_file_bytes,
    verify_base_release_chain,
    verify_receipt,
    verify_release_chain,
    verify_release_history_immutable,
)
from receipt.snapshot import GitEntry as SnapshotGitEntry
from receipt.snapshot import Materialization, SnapshotError, TreeSnapshot
from receipt.cli import EXIT_FAIL, main
from receipt.verify import load_spec, run_verification

from corpus_fixture import CONTENT, append_release, build_corpus

ANCHOR_DIR = "releases/anchors"


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """One expensive build (RSA keygen ×2, two TSAs); copied per test."""

    base = tmp_path_factory.mktemp("chain-origin")
    root = base / "repo"
    root.mkdir()
    build_corpus(root, base / "tsa-workspace")
    return root


@pytest.fixture()
def repo(built: pathlib.Path, tmp_path: pathlib.Path) -> pathlib.Path:
    destination = tmp_path / "repo"
    shutil.copytree(built, destination, symlinks=True)
    return destination


def commit_snapshot(root: pathlib.Path, message: str) -> str:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    if not (root / ".git").exists():
        subprocess.run(
            ["git", "-C", str(root), "init", "--quiet"],
            check=True,
            env=environment,
        )
        subprocess.run(
            ["git", "-C", str(root), "config", "user.name", "Receipt Test"],
            check=True,
            env=environment,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "config",
                "user.email",
                "receipt@example.invalid",
            ],
            check=True,
            env=environment,
        )
    subprocess.run(
        ["git", "-C", str(root), "add", "-A"], check=True, env=environment
    )
    changed = subprocess.run(
        ["git", "-C", str(root), "diff", "--cached", "--quiet", "HEAD", "--"],
        check=False,
        env=environment,
    ).returncode
    if changed:
        subprocess.run(
            ["git", "-C", str(root), "commit", "--quiet", "-m", message],
            check=True,
            env=environment,
        )
    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return completed.stdout.strip()


def commit_gitlink(
    root: pathlib.Path,
    relative: str,
    target: str,
    message: str,
) -> str:
    """Commit one index-only gitlink, which a working tree cannot represent."""

    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{target},{relative}",
        ],
        check=True,
        env=environment,
    )
    subprocess.run(
        ["git", "-C", str(root), "commit", "--quiet", "-m", message],
        check=True,
        env=environment,
    )
    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return completed.stdout.strip()


def configured_filenames(repo: pathlib.Path) -> set[str]:
    spec = load_spec(repo / "verification/spec.py").verification
    return {
        spec.chain.producer_public_key_filename,
        *(anchor.filename for anchor in spec.chain.anchors.values()),
    }


def independent_digests(repo: pathlib.Path) -> tuple[str, dict[str, str]]:
    """Recompute from the tree alone, sharing no package code: hash exactly
    the spec-configured files, then SHA-256 the compact sorted-key JSON of
    the mapping (equal to receipt-canonical JSON for these ASCII names)."""

    per_file = {
        name: hashlib.sha256((repo / ANCHOR_DIR / name).read_bytes()).hexdigest()
        for name in configured_filenames(repo)
    }
    combined = hashlib.sha256(
        json.dumps(per_file, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return combined, per_file


def test_a_verified_chain_names_the_consumed_anchor_set(
    repo: pathlib.Path,
) -> None:
    # An unconfigured file in the anchor directory must not enter the set:
    # the digest commits to what the spec configures and the run consumes,
    # not to a directory listing.
    (repo / ANCHOR_DIR / "unrelated.pem").write_bytes(b"not part of the set\n")

    spec = load_spec(repo / "verification/spec.py").verification
    verification = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )
    combined, per_file = independent_digests(repo)
    assert verification.anchor_set_sha256 == combined
    # The exact public shape: a sorted tuple of pairs, not any mapping-like.
    assert verification.anchor_file_sha256s == tuple(sorted(per_file.items()))
    assert "unrelated.pem" not in dict(verification.anchor_file_sha256s)


def test_by_default_no_digest_is_computed(repo: pathlib.Path) -> None:
    """The invariant pre-existing callers rely on: without the flag, the
    fields stay unset and no anchor file is read beyond the old checks."""

    spec = load_spec(repo / "verification/spec.py").verification
    verification = verify_release_chain(repo, spec=spec.chain)
    assert verification.anchor_set_sha256 is None
    assert verification.anchor_file_sha256s == ()


def test_chain_spec_defaults_to_the_portable_name_repertoire(
    repo: pathlib.Path,
) -> None:
    spec = load_spec(repo / "verification/spec.py").verification

    assert spec.chain.name_repertoire == "portable"
    assert replace(spec.chain, name_repertoire="posix-bytes").name_repertoire == (
        "posix-bytes"
    )
    with pytest.raises(
        ReleaseChainError,
        match="name repertoire must be 'portable' or 'posix-bytes'",
    ):
        replace(spec.chain, name_repertoire="unknown")


def test_verification_spec_anchor_set_pin_is_defaulted_and_validated(
    repo: pathlib.Path,
) -> None:
    spec = load_spec(repo / "verification/spec.py").verification

    assert spec.anchor_set_sha256 is None
    assert replace(spec, anchor_set_sha256="0" * 64).anchor_set_sha256 == "0" * 64
    with pytest.raises(
        ValueError,
        match="VerificationSpec anchor_set_sha256 must be a lowercase SHA-256 digest",
    ):
        replace(spec, anchor_set_sha256="A" * 64)


def test_release_chain_reexports_the_snapshot_git_entry() -> None:
    assert release_chain.GitEntry is SnapshotGitEntry


def test_release_history_compares_two_entered_trees_and_returns_new_files(
    repo: pathlib.Path,
) -> None:
    spec = load_spec(repo / "verification/spec.py").verification
    base_oid = commit_snapshot(repo, "base")
    added = repo / "releases" / "new-note.txt"
    added.write_text("new release note\n", encoding="utf-8")
    candidate_oid = commit_snapshot(repo, "candidate")

    with TreeSnapshot.select(repo, candidate_oid) as candidate:
        with TreeSnapshot.select(repo, base_oid) as base:
            candidate.assert_ancestor(base)
            resolved, new_files, base_entries = verify_release_history_immutable(
                spec.chain,
                candidate=candidate,
                base=base,
            )

    assert resolved == base_oid
    assert new_files == {"releases/new-note.txt"}
    assert "releases/new-note.txt" not in base_entries


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("delete", "existing release file was deleted relative to"),
        ("mode", "existing release file mode changed relative to"),
        ("bytes", "existing release file bytes changed relative to"),
        ("symlink", "release path is a symlink:"),
    ],
)
def test_release_history_retains_the_directory_verifier_refusals(
    repo: pathlib.Path,
    mutation: str,
    message: str,
) -> None:
    spec = load_spec(repo / "verification/spec.py").verification
    base_oid = commit_snapshot(repo, "base")
    manifest = next((repo / "releases/manifests").glob("*.json"))
    if mutation == "delete":
        manifest.unlink()
    elif mutation == "mode":
        manifest.chmod(0o755)
    elif mutation == "bytes":
        manifest.write_bytes(manifest.read_bytes() + b" ")
    else:
        manifest.unlink()
        manifest.symlink_to(repo / "receipt/corpus-journal.jsonl")
    candidate_oid = commit_snapshot(repo, mutation)

    with TreeSnapshot.select(repo, candidate_oid) as candidate:
        with TreeSnapshot.select(repo, base_oid) as base:
            candidate.assert_ancestor(base)
            with pytest.raises(ReleaseChainError, match=message):
                verify_release_history_immutable(
                    spec.chain,
                    candidate=candidate,
                    base=base,
                )


@pytest.mark.parametrize(
    ("shape", "message"),
    [
        (
            "blob-to-tree",
            "existing release file was deleted relative to {base}: releases/node",
        ),
        (
            "tree-to-blob",
            "existing release file was deleted relative to {base}: "
            "releases/node/leaf",
        ),
        ("candidate-gitlink", "release path is not regular: releases/node"),
        (
            "base-gitlink",
            "base release entry has non-regular git mode 160000: releases/node",
        ),
    ],
)
def test_release_history_classifies_tree_replacements_and_gitlinks(
    repo: pathlib.Path,
    shape: str,
    message: str,
) -> None:
    spec = load_spec(repo / "verification/spec.py").verification
    node = repo / "releases/node"

    if shape == "blob-to-tree":
        node.write_text("base blob\n", encoding="utf-8")
        base_oid = commit_snapshot(repo, "base blob")
        node.unlink()
        node.mkdir()
        (node / "leaf").write_text("candidate leaf\n", encoding="utf-8")
        candidate_oid = commit_snapshot(repo, "candidate tree")
    elif shape == "tree-to-blob":
        node.mkdir()
        (node / "leaf").write_text("base leaf\n", encoding="utf-8")
        base_oid = commit_snapshot(repo, "base tree")
        shutil.rmtree(node)
        node.write_text("candidate blob\n", encoding="utf-8")
        candidate_oid = commit_snapshot(repo, "candidate blob")
    elif shape == "candidate-gitlink":
        base_oid = commit_snapshot(repo, "base without gitlink")
        candidate_oid = commit_gitlink(
            repo,
            "releases/node",
            base_oid,
            "candidate gitlink",
        )
    else:
        parent_oid = commit_snapshot(repo, "parent without gitlink")
        base_oid = commit_gitlink(
            repo,
            "releases/node",
            parent_oid,
            "base gitlink",
        )
        node.write_text("candidate blob\n", encoding="utf-8")
        candidate_oid = commit_snapshot(repo, "candidate regular file")

    with TreeSnapshot.select(repo, candidate_oid) as candidate:
        with TreeSnapshot.select(repo, base_oid) as base:
            candidate.assert_ancestor(base)
            with pytest.raises(ReleaseChainError) as caught:
                verify_release_history_immutable(
                    spec.chain,
                    candidate=candidate,
                    base=base,
                )

    assert str(caught.value) == message.format(base=base_oid)


def _commit_protected_tree_alias(
    root: pathlib.Path, directory: str, *, empty: bool
) -> str:
    """Build file/tree siblings directly, including trees Git cannot stage."""

    def git(*arguments: str, payload: bytes | None = None) -> bytes:
        return subprocess.run(
            ["git", "-C", str(root), *arguments], input=payload,
            capture_output=True, check=True, timeout=30,
        ).stdout

    def entries(revision: str) -> list[tuple[bytes, bytes, bytes]]:
        result = []
        for record in git("ls-tree", "-z", revision).split(b"\0")[:-1]:
            header, name = record.split(b"\t", 1)
            mode, _kind, oid = header.split()
            result.append((b"40000" if mode == b"040000" else mode, name, oid))
        return result

    def tree(items: list[tuple[bytes, bytes, bytes]]) -> bytes:
        items = sorted(items, key=lambda item: item[1] + (
            b"/" if item[0] == b"40000" else b""
        ))
        raw = b"".join(mode + b" " + name + b"\0" + bytes.fromhex(oid.decode())
                       for mode, name, oid in items)
        return git("hash-object", "-w", "-t", "tree", "--stdin", payload=raw).strip()

    blob = git("hash-object", "-w", "--stdin", payload=b"extra\n").strip()
    alias = tree([] if empty else [(b"100644", b"child", blob)])
    additions = [(b"100644", b"extra", blob), (b"40000", b"EXTRA", alias)]
    root_entries = entries("HEAD")
    if directory:
        subtree = tree(entries(f"HEAD:{directory}") + additions)
        root_entries = [(mode, name, subtree if name == directory.encode() else oid)
                        for mode, name, oid in root_entries]
    else:
        root_entries += additions
    return git("-c", "commit.gpgSign=false", "commit-tree", tree(root_entries).decode(),
               "-p", "HEAD", payload=b"protected alias\n").strip().decode()


@pytest.mark.parametrize("repertoire", ["portable", "posix-bytes"])
@pytest.mark.parametrize("empty", [True, False], ids=["empty", "nonempty"])
@pytest.mark.parametrize("directory", ["releases", ""], ids=["protected", "ancestor"])
def test_base_release_chain_screens_protected_siblings_before_materialization(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
    repertoire: str, empty: bool, directory: str,
) -> None:
    chain = replace(load_spec(repo / "verification/spec.py").verification.chain,
                    name_repertoire=repertoire)
    commit = _commit_protected_tree_alias(repo, directory, empty=empty)

    def no_materialization(*args: object, **kwargs: object) -> None:
        pytest.fail("protected listing screen must precede materialization")

    monkeypatch.setattr(TreeSnapshot, "materialize", no_materialization)
    with TreeSnapshot.select(repo, commit) as base:
        with pytest.raises(ReleaseChainError) as caught:
            verify_base_release_chain(chain, base=base)
    assert str(caught.value) == (
        f"tree directory {directory or '.'!r} contains names that merge under "
        "ASCII case folding: 'EXTRA' and 'extra'"
    )


@pytest.mark.parametrize("repertoire", ["portable", "posix-bytes"])
@pytest.mark.parametrize("empty", [True, False], ids=["empty", "nonempty"])
@pytest.mark.parametrize("directory", ["releases", ""], ids=["protected", "ancestor"])
def test_composed_custody_screens_protected_siblings_before_materialization(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
    repertoire: str, empty: bool, directory: str,
) -> None:
    spec_path = repo / "verification/spec.py"
    spec_path.write_text(spec_path.read_text(encoding="utf-8") + (
        "\nfrom dataclasses import replace\n"
        f"SPEC = replace(SPEC, chain=replace(SPEC.chain, name_repertoire={repertoire!r}), "
        f"corpus=replace(SPEC.corpus, name_repertoire={repertoire!r}))\n"
    ), encoding="utf-8")
    loaded = load_spec(spec_path, expect_sha256=hashlib.sha256(spec_path.read_bytes()).hexdigest())
    commit = _commit_protected_tree_alias(repo, directory, empty=empty)

    def no_materialization(*args: object, **kwargs: object) -> None:
        pytest.fail("protected listing screen must precede materialization")

    monkeypatch.setattr(TreeSnapshot, "materialize", no_materialization)
    result = run_verification(repo, loaded, commit=commit, expect_commit=commit)
    assert not result.ok
    assert result.passes[0].name == "custody"
    assert not result.passes[0].ok
    assert result.passes[0].failure == (
        f"tree directory {directory or '.'!r} contains names that merge under "
        "ASCII case folding: 'EXTRA' and 'extra'"
    )
    assert result.passes[1].name == "binding"
    assert result.passes[1].failure == "not reached"


def _commit_lone_protected_alias(
    root: pathlib.Path, location: str, shape: str,
) -> tuple[str, str, str, str]:
    """Add one alias with no exact counterpart to a signed tree, off checkout."""

    def git(*arguments: str, payload: bytes | None = None) -> bytes:
        return subprocess.run(
            ["git", "-C", str(root), *arguments], input=payload,
            capture_output=True, check=True, timeout=30,
        ).stdout.strip()

    blob = git("hash-object", "-w", "--stdin", payload=b"unrelated\n")
    if shape == "blob":
        mode, kind, alias = b"100644", b"blob", blob
    else:
        contents = b"" if shape == "empty" else b"100644 blob " + blob + b"\tchild\0"
        mode, kind = b"040000", b"tree"
        alias = git("mktree", "-z", payload=contents)
    if location == "leaf":
        spelling, prefix = "evidence/archive/CUSTODY", "evidence/archive/custody"
    else:
        spelling, prefix = "evidence/ARCHIVE", "evidence/archive"
    components = spelling.split("/")
    for component in reversed(components):
        alias = git("mktree", "-z", payload=(
            mode + b" " + kind + b" " + alias + b"\t" + component.encode() + b"\0"
        ))
        mode, kind = b"040000", b"tree"
    records = git("ls-tree", "-z", "HEAD") + git("ls-tree", "-z", alias.decode())
    tree = git("mktree", "-z", payload=records).decode()
    commit = git("-c", "commit.gpgSign=false", "commit-tree", tree,
                 "-p", "HEAD", payload=b"lone configured prefix alias\n").decode()
    return commit, tree, spelling, prefix


@pytest.mark.parametrize("repertoire", ["portable", "posix-bytes"])
@pytest.mark.parametrize("shape", ["empty", "nonempty", "blob"])
@pytest.mark.parametrize("location", ["leaf", "ancestor"])
@pytest.mark.parametrize("entry_point", ["base", "composed"])
def test_lone_configured_prefix_alias_refuses_before_materialization(
    repo: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
    repertoire: str, shape: str, location: str, entry_point: str,
) -> None:
    protected = "evidence/archive/custody"
    spec_path = repo / "verification/spec.py"
    spec_path.write_text(spec_path.read_text(encoding="utf-8") + (
        "\nfrom dataclasses import replace\nfrom pathlib import PurePosixPath\n"
        "SPEC = replace(SPEC, chain=replace(SPEC.chain, "
        f"release_root_relative=PurePosixPath({protected!r}), "
        f"name_repertoire={repertoire!r}), corpus=replace(SPEC.corpus, "
        f"name_repertoire={repertoire!r}))\n"
    ), encoding="utf-8")
    loaded = load_spec(spec_path, expect_sha256=hashlib.sha256(spec_path.read_bytes()).hexdigest())
    chain = loaded.verification.chain
    commit, tree, spelling, prefix = _commit_lone_protected_alias(repo, location, shape)
    with TreeSnapshot.select(repo, commit) as snapshot:
        entries = snapshot.entries("").as_dict(include_trees=True)
        assert prefix not in entries
        assert spelling in entries
        with snapshot.materialize(
            (chain.anchor_relative,), tmp_path, repertoire=repertoire,
        ) as materialized:
            anchors = materialized.anchor_set_sha256(chain)
    shutil.rmtree(repo / "releases")

    def not_reached(*args: object, **kwargs: object) -> None:
        pytest.fail("configured-prefix alias screen must precede materialization and OpenSSL")

    monkeypatch.setattr(TreeSnapshot, "materialize", not_reached)
    monkeypatch.setattr(release_chain._tsa, "_require_supported_openssl", not_reached)
    listed = f"{spelling}/child" if shape == "nonempty" else spelling
    expected = (
        f"index carries an alias of a protected path: {listed} "
        f"(for {protected} at {prefix})"
    )
    if entry_point == "base":
        with TreeSnapshot.select(repo, commit) as base:
            with pytest.raises(ReleaseChainError) as caught:
                verify_base_release_chain(chain, base=base)
        assert str(caught.value) == expected
    else:
        result = run_verification(
            repo, loaded, commit=commit, expect_commit=commit, expect_tree=tree,
            expect_anchor_set=anchors,
        )
        assert not result.ok
        assert result.passes[0].name == "custody"
        assert not result.passes[0].ok
        assert result.passes[0].failure == expected
        assert result.passes[1].name == "binding"
        assert result.passes[1].failure == "not reached"


@pytest.mark.parametrize("repertoire", ["portable", "posix-bytes"])
def test_configured_prefix_comparison_preserves_caller_anchor_exclusion(
    repo: pathlib.Path, tmp_path: pathlib.Path, repertoire: str,
) -> None:
    chain = load_spec(repo / "verification/spec.py").verification.chain
    external = tmp_path / "trusted-anchors"
    shutil.copytree(repo / chain.anchor_relative, external)
    shutil.rmtree(repo / chain.anchor_relative)
    chain = replace(chain, anchor_relative=pathlib.PurePosixPath("separate/anchors"),
                    name_repertoire=repertoire)
    commit_snapshot(repo, "separate caller-owned anchors")

    def git(*arguments: str, payload: bytes | None = None) -> bytes:
        return subprocess.run(
            ["git", "-C", str(repo), *arguments], input=payload,
            capture_output=True, check=True, timeout=30,
        ).stdout.strip()

    empty = git("mktree", payload=b"")
    blob = git("hash-object", "-w", "--stdin", payload=b"unused\n")
    unused = git("mktree", "-z", payload=(
        b"040000 tree " + empty + b"\tEXTRA\0"
        b"100644 blob " + blob + b"\textra\0"
        b"100644 blob " + blob + b"\tbad-\xff\0"
    ))
    separate = git("mktree", "-z", payload=b"040000 tree " + unused + b"\tANCHORS\0")
    tree = git("mktree", "-z", payload=(
        git("ls-tree", "-z", "HEAD") + b"040000 tree " + separate + b"\tseparate\0"
    ))
    commit = git("-c", "commit.gpgSign=false", "commit-tree", tree.decode(),
                 "-p", "HEAD", payload=b"unused anchor aliases and invalid name\n").decode()
    with TreeSnapshot.select(repo, commit) as snapshot:
        verification = verify_base_release_chain(chain, base=snapshot, anchor_dir=external)
        assert len(verification.releases) == 1
    # Selecting that anchor subtree still subjects its immediate ancestor
    # listing to the configured-prefix comparison (without caller trust).
    with TreeSnapshot.select(repo, commit) as snapshot:
        with pytest.raises(ReleaseChainError):
            verify_base_release_chain(chain, base=snapshot)


def test_base_release_chain_materializes_the_entered_snapshot(
    repo: pathlib.Path,
) -> None:
    spec = load_spec(repo / "verification/spec.py").verification
    base_oid = commit_snapshot(repo, "base")
    shutil.rmtree(repo / "releases")
    (repo / "receipt/corpus-journal.jsonl").write_text(
        '{"workingTree":"does not matter"}\n', encoding="utf-8"
    )

    with TreeSnapshot.select(repo, base_oid) as base:
        verification = verify_base_release_chain(spec.chain, base=base)

    assert verification.head is not None


def test_base_release_chain_materializes_anchors_outside_the_release_root(
    repo: pathlib.Path,
) -> None:
    spec = load_spec(repo / "verification/spec.py").verification
    external_anchors = repo / "trust" / "anchors"
    external_anchors.parent.mkdir()
    shutil.move(repo / spec.chain.anchor_relative, external_anchors)
    chain = replace(
        spec.chain,
        anchor_relative=pathlib.PurePosixPath("trust/anchors"),
    )
    base_oid = commit_snapshot(repo, "base with standalone anchors")

    shutil.rmtree(repo / "releases")
    shutil.rmtree(repo / "trust")
    with TreeSnapshot.select(repo, base_oid) as base:
        verification = verify_base_release_chain(chain, base=base)

    assert verification.head is not None


@pytest.mark.parametrize("absolute_filenames", [True, False])
def test_base_release_chain_binds_anchors_before_openssl(
    repo: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    absolute_filenames: bool,
) -> None:
    chain = load_spec(repo / "verification/spec.py").verification.chain
    external = tmp_path / "external-anchors"
    shutil.move(repo / chain.anchor_relative, external)
    base_oid = commit_snapshot(repo, "base without anchors")
    if absolute_filenames:
        chain = replace(
            chain,
            producer_public_key_filename=str(
                external / chain.producer_public_key_filename
            ),
            anchors={
                name: replace(anchor, filename=str(external / anchor.filename))
                for name, anchor in chain.anchors.items()
            },
        )

    def no_openssl() -> None:
        pytest.fail("base anchor binding must precede the OpenSSL preflight")

    monkeypatch.setattr(release_chain._tsa, "_require_supported_openssl", no_openssl)
    message = (
        "configured anchor filename leaves the anchor directory"
        if absolute_filenames
        else "configured anchor was not materialized"
    )
    with TreeSnapshot.select(repo, base_oid) as base:
        assert not base.entries(chain.anchor_relative.as_posix()).as_dict()
        with pytest.raises(SnapshotError, match=message):
            verify_base_release_chain(chain, base=base)


def test_base_release_chain_shares_normalized_spec_with_anchor_binding(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    chain = load_spec(repo / "verification/spec.py").verification.chain

    class OncePath:
        calls = 0

        def __fspath__(self) -> str:
            self.calls += 1
            assert self.calls == 1
            return chain.producer_public_key_filename

    filename = OncePath()
    configured = replace(chain, producer_public_key_filename=filename)
    base_oid = commit_snapshot(repo, "base with matching anchors")
    bound = []
    original_digest = Materialization.anchor_set_sha256
    original_verify = release_chain.verify_release_chain

    def bind(materialized: Materialization, normalized: object) -> str:
        bound.append(normalized)
        return original_digest(materialized, normalized)

    def verify(root: pathlib.Path, *, spec: object, **kwargs: object):
        assert len(bound) == 1 and spec is bound[0]
        assert spec.producer_public_key_filename == chain.producer_public_key_filename
        return original_verify(root, spec=spec, **kwargs)

    monkeypatch.setattr(Materialization, "anchor_set_sha256", bind)
    monkeypatch.setattr(release_chain, "verify_release_chain", verify)
    with TreeSnapshot.select(repo, base_oid) as base:
        verification = verify_base_release_chain(configured, base=base)
    assert verification.head is not None
    assert filename.calls == 1


@pytest.mark.parametrize("tree_anchors", ["absent", "invalid"])
def test_base_release_chain_uses_callers_trusted_anchor_directory(
    repo: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    tree_anchors: str,
) -> None:
    chain = load_spec(repo / "verification/spec.py").verification.chain
    external = tmp_path / "trusted-anchors"
    shutil.copytree(repo / chain.anchor_relative, external)
    if tree_anchors == "absent":
        shutil.rmtree(repo / chain.anchor_relative)
    else:
        for path in (repo / chain.anchor_relative).iterdir():
            path.write_bytes(b"the base tree is not the caller's trust material")
    base_oid = commit_snapshot(repo, "base with untrusted anchors")
    reads = []
    original_read = release_chain._regular_file_bytes

    def read(root: pathlib.Path, relative: pathlib.PurePosixPath, **kwargs: object):
        if root.name in {"anchors", external.name}:
            assert root == external
            reads.append(relative.as_posix())
        return original_read(root, relative, **kwargs)

    def no_tree_binding(*args: object) -> str:
        pytest.fail("caller trust must not bind the base tree's anchor set")

    monkeypatch.setattr(release_chain, "_regular_file_bytes", read)
    monkeypatch.setattr(Materialization, "anchor_set_sha256", no_tree_binding)
    with TreeSnapshot.select(repo, base_oid) as base:
        verification = verify_base_release_chain(chain, base=base, anchor_dir=external)
    assert verification.head is not None
    assert set(reads) == {chain.producer_public_key_filename} | {
        anchor.filename for anchor in chain.anchors.values()
    }


@pytest.mark.parametrize("caller_trust", [True, False], ids=["caller-trust", "tree-trust"])
def test_base_release_chain_ignores_disjoint_tree_anchors_only_with_caller_trust(
    repo: pathlib.Path,
    tmp_path: pathlib.Path,
    caller_trust: bool,
) -> None:
    chain = load_spec(repo / "verification/spec.py").verification.chain
    separate = repo / "separate-anchors"
    shutil.move(repo / chain.anchor_relative, separate)
    external = tmp_path / "trusted-anchors"
    shutil.copytree(separate, external)
    (separate / "unused-symlink").symlink_to("unused-target")
    chain = replace(
        chain,
        anchor_relative=pathlib.PurePosixPath("separate-anchors"),
    )
    base_oid = commit_snapshot(repo, "base with disjoint unused anchor symlink")

    with TreeSnapshot.select(repo, base_oid) as base:
        assert base.entry("separate-anchors/unused-symlink").mode == "120000"
        if caller_trust:
            verification = verify_base_release_chain(
                chain, base=base, anchor_dir=external
            )
            assert verification.head is not None
        else:
            with pytest.raises(SnapshotError) as caught:
                verify_base_release_chain(chain, base=base)
            assert str(caught.value) == (
                "base tree entry has non-regular mode 120000: "
                "separate-anchors/unused-symlink"
            )


def test_base_release_chain_forwards_pin_and_clock_options(repo: pathlib.Path) -> None:
    chain = load_spec(repo / "verification/spec.py").verification.chain
    base_oid = commit_snapshot(repo, "base with matching anchors")
    wrong_pin = replace(chain, producer_spki_sha256="0" * 64)
    with TreeSnapshot.select(repo, base_oid) as base:
        with pytest.raises(ReleaseChainError, match="not code-pinned"):
            verify_base_release_chain(wrong_pin, base=base)
        verification = verify_base_release_chain(
            wrong_pin, base=base, enforce_production_pins=False, clock_skew_seconds=0
        )
    assert verification.head is not None


def test_base_release_chain_refuses_transforming_attributes_before_openssl(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    chain = load_spec(repo / "verification/spec.py").verification.chain
    (repo / ".gitattributes").write_text("releases/** filter=evil\n", encoding="utf-8")
    base_oid = commit_snapshot(repo, "base with transforming release attributes")

    def no_openssl() -> None:
        pytest.fail("base attributes must be checked before the OpenSSL preflight")

    monkeypatch.setattr(release_chain._tsa, "_require_supported_openssl", no_openssl)
    with TreeSnapshot.select(repo, base_oid) as base:
        with pytest.raises(SnapshotError) as expected:
            base.refuse_transforming_attributes(base.entries("releases").as_dict().values())
        with pytest.raises(SnapshotError) as caught:
            verify_base_release_chain(chain, base=base)
    assert str(caught.value) == str(expected.value)
    assert "transforming attribute filter applies to protected path releases/" in str(
        caught.value
    )


def test_observing_adds_no_anchor_reads(built: pathlib.Path, tmp_path: pathlib.Path) -> None:
    """Digest observation rides the same regular-file reads as default mode."""

    import pytest as _pytest

    counts = {}
    for mode, flag in (("default", False), ("observing", True)):
        repo = tmp_path / mode
        shutil.copytree(built, repo, symlinks=True)
        spec = load_spec(repo / "verification/spec.py").verification
        reads = {"count": 0}
        original = release_chain._regular_file_bytes

        def counting_read(
            root: pathlib.Path,
            relative: pathlib.PurePosixPath,
            **kwargs: object,
        ) -> bytes:
            if root.name == "anchors":
                reads["count"] += 1
            return original(root, relative, **kwargs)

        monkeypatch = _pytest.MonkeyPatch()
        try:
            monkeypatch.setattr(release_chain, "_regular_file_bytes", counting_read)
            verify_release_chain(
                repo, spec=spec.chain, compute_anchor_set_digest=flag
            )
        finally:
            monkeypatch.undo()
        counts[mode] = reads["count"]
    # One release, one producer key, two TSA roles: three reads.
    assert counts == {"default": 3, "observing": 3}


def test_openssl_is_fed_the_digested_bytes(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The digest describes bytes OpenSSL actually consumed: every -CAfile
    the run passes must be a private snapshot — never the repository path a
    concurrent writer could swap between the hash and the subprocess — and
    the snapshot's bytes at call time must hash to the digest the verdict
    reports for that anchor."""

    import receipt.release_chain as module

    repo_anchor_dir = (repo / ANCHOR_DIR).resolve()
    consumed: list[tuple[pathlib.Path, str]] = []
    real_run = subprocess.run

    def spying_run(arguments, *args, **kwargs):  # type: ignore[no-untyped-def]
        if isinstance(arguments, list) and "-CAfile" in arguments:
            path = pathlib.Path(arguments[arguments.index("-CAfile") + 1])
            consumed.append(
                (path, hashlib.sha256(path.read_bytes()).hexdigest())
            )
        return real_run(arguments, *args, **kwargs)

    monkeypatch.setattr(module.subprocess, "run", spying_run)
    spec = load_spec(repo / "verification/spec.py").verification
    verification = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )

    assert consumed, "the run must have verified RFC 3161 receipts"
    reported = set(dict(verification.anchor_file_sha256s).values())
    for path, digest in consumed:
        assert path.resolve().parent != repo_anchor_dir
        assert digest in reported

    # Same property with pins off (a caller-supplied anchor directory):
    # snapshots, never the caller's directory.
    aside = repo.parent / "anchors-aside"
    shutil.copytree(repo / ANCHOR_DIR, aside)
    consumed.clear()
    verification = verify_release_chain(
        repo, spec=spec.chain, anchor_dir=aside, compute_anchor_set_digest=True
    )
    reported = set(dict(verification.anchor_file_sha256s).values())
    assert consumed
    for path, digest in consumed:
        assert path.resolve().parent not in (repo_anchor_dir, aside.resolve())
        assert digest in reported

    # A caller that requests neither byte pins nor an observed digest still
    # gets the same private -CAfile discipline.
    consumed.clear()
    verify_release_chain(
        repo,
        spec=spec.chain,
        anchor_dir=aside,
        enforce_production_pins=False,
    )
    expected = {
        hashlib.sha256((aside / anchor.filename).read_bytes()).hexdigest()
        for anchor in spec.chain.anchors.values()
    }
    assert consumed
    for path, digest in consumed:
        assert path.resolve().parent not in (repo_anchor_dir, aside.resolve())
        assert digest in expected


def test_release_chain_runs_the_openssl_floor_preflight_before_paths(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from receipt import tsa

    calls: list[str] = []

    def refuse() -> None:
        calls.append("preflight")
        raise tsa.TsaError(
            "receipt requires OpenSSL 3.0 or newer as `openssl` on the path; "
            "found: LibreSSL 3.3.6"
        )

    monkeypatch.setattr(tsa, "_require_supported_openssl", refuse)
    spec = load_spec(repo / "verification/spec.py").verification
    shutil.rmtree(repo / "releases")

    with pytest.raises(ReleaseChainError) as refusal:
        verify_release_chain(repo, spec=spec.chain)

    assert calls == ["preflight"]
    assert str(refusal.value) == (
        "receipt requires OpenSSL 3.0 or newer as `openssl` on the path; "
        "found: LibreSSL 3.3.6"
    )


def test_release_chain_validates_arguments_then_runs_its_path_guards(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from receipt import tsa

    spec = load_spec(repo / "verification/spec.py").verification
    events: list[str] = []
    anchor_path = repo.resolve() / spec.chain.anchor_relative
    path_is_symlink = pathlib.Path.is_symlink

    def observe_anchor_probe(path: pathlib.Path) -> bool:
        if path == anchor_path:
            events.append("anchors")
        return path_is_symlink(path)

    monkeypatch.setattr(
        tsa, "_require_supported_openssl", lambda: events.append("openssl")
    )
    monkeypatch.setattr(pathlib.Path, "is_symlink", observe_anchor_probe)
    monkeypatch.setattr(
        release_chain,
        "assert_no_symlinked_release_root",
        lambda *_args: events.append("paths"),
    )
    monkeypatch.setattr(
        release_chain,
        "assert_manifest_directory_regular",
        lambda *_args: events.append("manifest-shape"),
    )
    monkeypatch.setattr(
        release_chain,
        "_enumerate_manifest_files",
        lambda *_args: events.append("enumerate") or [],
    )

    verification = verify_release_chain(
        repo,
        spec=spec.chain,
        require_chain=False,
        verify_state=False,
    )
    assert verification.releases == ()
    assert events == [
        "openssl",
        "anchors",
        "paths",
        "manifest-shape",
        "enumerate",
    ]

    events.clear()
    with pytest.raises(
        ReleaseChainError,
        match="clock_skew_seconds must be a non-negative integer",
    ):
        verify_release_chain(repo, spec=spec.chain, clock_skew_seconds=-1)
    assert events == []


def test_anchor_symlink_probe_precedes_the_release_root_refusal(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    spec = load_spec(repo / "verification/spec.py").verification
    releases = repo / "releases"
    actual_releases = tmp_path / "actual-releases"
    shutil.move(releases, actual_releases)
    releases.symlink_to(actual_releases, target_is_directory=True)

    with pytest.raises(ReleaseChainError) as caught:
        verify_release_chain(repo, spec=spec.chain)

    assert str(caught.value) == (
        "anchor path component is a symlink or reparse point: "
        f"{releases}"
    )


def test_release_chain_routes_every_input_file_through_the_regular_reader(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = load_spec(repo / "verification/spec.py").verification
    original = release_chain._regular_file_bytes
    reads: list[str] = []

    def observe(
        root: pathlib.Path,
        relative: pathlib.PurePosixPath,
        **kwargs: object,
    ) -> bytes:
        reads.append((root / relative).name)
        return original(root, relative, **kwargs)

    monkeypatch.setattr(release_chain, "_regular_file_bytes", observe)
    verify_release_chain(repo, spec=spec.chain)

    manifest = next((repo / "releases/manifests").glob("*.json"))
    stem = manifest.stem
    assert sorted(reads) == sorted(
        [
            manifest.name,
            f"{stem}.producer.sig",
            *(f"{stem}.{name}.tsr" for name in spec.chain.anchors),
            spec.chain.producer_public_key_filename,
            *(anchor.filename for anchor in spec.chain.anchors.values()),
            spec.chain.state_relative.name,
            spec.chain.prefix_relative.name,
        ]
    )


def test_component_spelling_uses_constant_time_listing_membership(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The per-component spelling check must not linearly scan its listing."""

    class Listing(list[str]):
        def __contains__(self, item: object) -> bool:
            del item
            raise AssertionError("list membership scanned the directory")

    monkeypatch.setattr(os, "listdir", lambda _parent: Listing(["leaf"]))

    release_chain._assert_component_spelled(
        tmp_path,
        "leaf",
        ("leaf",),
        pathlib.PurePosixPath("leaf"),
    )


def test_the_producer_openssl_fallback_uses_a_private_leaf(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A configured producer filename that is absolute would survive the
    temporary-directory join in the OpenSSL fallback and hand the original
    path to the subprocess. When observing, the temporary name must be a
    fixed private leaf regardless of configuration."""

    import dataclasses

    import receipt.release_chain as module
    from receipt import sign as sign_module

    spec = load_spec(repo / "verification/spec.py").verification
    absolute_name = str((repo / ANCHOR_DIR / "producer-ed25519.pub").resolve())
    chain = dataclasses.replace(
        spec.chain, producer_public_key_filename=absolute_name
    )
    manifests = sorted((repo / "releases/manifests").glob("*.json"))
    manifest_bytes = manifests[0].read_bytes()
    signature = manifests[0].with_name(
        manifests[0].name.replace(".json", ".producer.sig")
    ).read_bytes()

    captured: list[str | None] = []
    fed_pems: list[bytes] = []

    def spying_fallback(*args, **kwargs):  # type: ignore[no-untyped-def]
        captured.append(kwargs.get("temporary_public_key_filename"))
        fed_pems.append(args[2])

    monkeypatch.setattr(module, "CRYPTOGRAPHY_AVAILABLE", False)
    monkeypatch.setattr(
        sign_module, "_verify_producer_signature_with_openssl", spying_fallback
    )
    observer: dict[str, str] = {}
    module.verify_producer_signature_bytes(
        manifest_bytes,
        signature,
        spec=chain,
        anchor_dir=repo / ANCHOR_DIR,
        enforce_production_pin=False,
        label="0000.producer.sig",
        anchor_observer=observer,
    )
    assert captured == ["producer-key-snapshot.pem"]
    assert absolute_name in observer
    # The bytes handed to the fallback are the observed bytes exactly.
    assert hashlib.sha256(fed_pems[0]).hexdigest() == observer[absolute_name]

    # Non-observing mode must keep origin's behavior exactly: the configured
    # name is forwarded as the temporary filename, absolute or not.
    captured.clear()
    module.verify_producer_signature_bytes(
        manifest_bytes,
        signature,
        spec=chain,
        anchor_dir=repo / ANCHOR_DIR,
        enforce_production_pin=False,
        label="0000.producer.sig",
    )
    assert captured == [absolute_name]


def test_a_reserialized_producer_key_is_accepted_and_recorded(
    repo: pathlib.Path,
) -> None:
    """The stated split semantics, pinned: producer identity is SPKI-pinned,
    so a byte-different serialization of the same key verifies — and the
    verdict records the serialization that was actually consumed."""

    spec = load_spec(repo / "verification/spec.py").verification
    key_name = spec.chain.producer_public_key_filename
    key_path = repo / ANCHOR_DIR / key_name
    original = key_path.read_bytes()
    reserialized = original.rstrip(b"\n") + b"\n\n"
    assert reserialized != original
    key_path.write_bytes(reserialized)

    verification = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )
    recorded = dict(verification.anchor_file_sha256s)[key_name]
    assert recorded == hashlib.sha256(reserialized).hexdigest()
    assert recorded != hashlib.sha256(original).hexdigest()


def test_the_producer_openssl_fallback_verifies_while_observing(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fallback path runs for real — the private snapshot leaf must be
    what OpenSSL consumes, in both observing and non-observing modes."""

    import receipt.release_chain as module

    monkeypatch.setattr(module, "CRYPTOGRAPHY_AVAILABLE", False)
    spec = load_spec(repo / "verification/spec.py").verification
    manifests = sorted((repo / "releases/manifests").glob("*.json"))
    manifest_bytes = manifests[0].read_bytes()
    signature = manifests[0].with_name(
        manifests[0].name.replace(".json", ".producer.sig")
    ).read_bytes()

    key_name = spec.chain.producer_public_key_filename
    expected = hashlib.sha256(
        (repo / ANCHOR_DIR / key_name).read_bytes()
    ).hexdigest()
    observer: dict[str, str] = {}
    module.verify_producer_signature_bytes(
        manifest_bytes,
        signature,
        spec=spec.chain,
        anchor_dir=repo / ANCHOR_DIR,
        enforce_production_pin=True,
        label="genesis.producer.sig",
        anchor_observer=observer,
    )
    assert observer == {key_name: expected}

    # Non-observing mode keeps the original configured-name behavior.
    module.verify_producer_signature_bytes(
        manifest_bytes,
        signature,
        spec=spec.chain,
        anchor_dir=repo / ANCHOR_DIR,
        enforce_production_pin=True,
        label="genesis.producer.sig",
    )


def test_the_in_process_verifier_receives_the_observed_producer_bytes(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The producer digest must describe the bytes the signature check
    consumed, not merely bytes read near it."""

    import receipt.release_chain as module

    seen: list[bytes] = []
    real_verify = module._sign.verify_signature_bytes

    def spying_verify(payload, signature, public_key_pem, **kwargs):  # type: ignore[no-untyped-def]
        seen.append(public_key_pem)
        return real_verify(payload, signature, public_key_pem, **kwargs)

    monkeypatch.setattr(module._sign, "verify_signature_bytes", spying_verify)
    spec = load_spec(repo / "verification/spec.py").verification
    verification = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )
    key_name = spec.chain.producer_public_key_filename
    reported = dict(verification.anchor_file_sha256s)[key_name]
    assert seen, "the run must have verified a producer signature"
    for pem in seen:
        assert hashlib.sha256(pem).hexdigest() == reported


def test_pins_off_observing_accepts_a_substitute_producer_identity(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """Pins off establishes no pin claim — a re-signed chain under a fresh
    key verifies against a caller-supplied anchor set, and the verdict
    records the substitute serialization. A regression that re-enabled the
    SPKI pin whenever digests are computed would fail here."""

    from receipt.sign import generate_signing_keypair, sign_payload

    private_pem, public_pem = generate_signing_keypair()
    for manifest in sorted((repo / "releases/manifests").glob("*.json")):
        signature = manifest.with_name(
            manifest.name.replace(".json", ".producer.sig")
        )
        signature.write_bytes(
            sign_payload(private_pem, manifest.read_bytes(), domain=b"")
        )
    aside = tmp_path / "anchors-substitute"
    shutil.copytree(repo / ANCHOR_DIR, aside)
    spec = load_spec(repo / "verification/spec.py").verification
    key_name = spec.chain.producer_public_key_filename
    (aside / key_name).write_bytes(public_pem)

    verification = verify_release_chain(
        repo, spec=spec.chain, anchor_dir=aside, compute_anchor_set_digest=True
    )
    recorded = dict(verification.anchor_file_sha256s)[key_name]
    assert recorded == hashlib.sha256(public_pem).hexdigest()


def test_pathlike_configurations_traverse_end_to_end(
    repo: pathlib.Path,
) -> None:
    """PurePosixPath filenames — runtime-accepted by every older check —
    must produce the same digest as the equivalent plain-string spec, with
    exact built-in str keys in the output."""

    import dataclasses

    spec = load_spec(repo / "verification/spec.py").verification
    plain = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )
    pathlike_chain = dataclasses.replace(
        spec.chain,
        producer_public_key_filename=pathlib.PurePosixPath(  # type: ignore[arg-type]
            spec.chain.producer_public_key_filename
        ),
        anchors={
            tsa: dataclasses.replace(
                anchor,
                filename=pathlib.PurePosixPath(anchor.filename),  # type: ignore[arg-type]
            )
            for tsa, anchor in spec.chain.anchors.items()
        },
    )
    pathlike = verify_release_chain(
        repo, spec=pathlike_chain, compute_anchor_set_digest=True
    )
    assert pathlike.anchor_set_sha256 == plain.anchor_set_sha256
    assert pathlike.anchor_file_sha256s == plain.anchor_file_sha256s
    for name, _digest in pathlike.anchor_file_sha256s:
        assert type(name) is str


def test_a_stateful_pathlike_gets_exactly_one_pathname_call(
    tmp_path: pathlib.Path,
) -> None:
    """The attack round 5 named: a PathLike that answers __fspath__
    differently per call could show one pathname to the join and another to
    the observer. Normalizing once per run — not once per release — means
    the object is asked exactly once over a multi-release chain, and every
    consumer shares that single answer."""

    import dataclasses

    root = tmp_path / "repo"
    root.mkdir()
    workspace = tmp_path / "tsa-workspace"
    build_corpus(root, workspace)
    corrected = dict(CONTENT)
    corrected["rules/tax/rate.yaml"] = "name: rate\nvalue: 0.175\n"
    append_release(root, workspace, content=corrected)

    spec = load_spec(root / "verification/spec.py").verification
    real_name = spec.chain.producer_public_key_filename
    calls = {"count": 0}

    class TwoFaced:
        def __fspath__(self) -> str:
            calls["count"] += 1
            return real_name if calls["count"] == 1 else "reported.pem"

    chain = dataclasses.replace(
        spec.chain, producer_public_key_filename=TwoFaced()  # type: ignore[arg-type]
    )
    verification = verify_release_chain(
        root, spec=chain, compute_anchor_set_digest=True
    )
    assert len(verification.releases) == 2
    assert calls["count"] == 1
    assert real_name in dict(verification.anchor_file_sha256s)
    assert "reported.pem" not in dict(verification.anchor_file_sha256s)


def test_default_mode_resolves_each_anchor_filename_once_per_consumption(
    repo: pathlib.Path,
) -> None:
    """The read-once path asks each configured filename once per release."""

    import dataclasses

    spec = load_spec(repo / "verification/spec.py").verification
    counts: dict[str, int] = {}

    class Counting:
        def __init__(self, label: str, name: str) -> None:
            self._label, self._name = label, name

        def __fspath__(self) -> str:
            counts[self._label] = counts.get(self._label, 0) + 1
            return self._name

    chain = dataclasses.replace(
        spec.chain,
        producer_public_key_filename=Counting(  # type: ignore[arg-type]
            "producer", spec.chain.producer_public_key_filename
        ),
        anchors={
            tsa: dataclasses.replace(
                anchor,
                filename=Counting(tsa, anchor.filename),  # type: ignore[arg-type]
            )
            for tsa, anchor in spec.chain.anchors.items()
        },
    )
    verify_release_chain(repo, spec=chain)
    tsa_labels = sorted(spec.chain.anchors)
    assert counts == {"producer": 1, tsa_labels[0]: 1, tsa_labels[1]: 1}


def test_standalone_receipts_shared_filename_divergence_refuses(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two TSA roles sharing one stateful filename object, whose bytes
    change between their consumptions: the standalone entry point's
    memoized rewrite asks the object once, and the observer — not the
    later OpenSSL failure — refuses the divergence."""

    import dataclasses
    import json as _json

    import receipt.release_chain as module

    spec = load_spec(repo / "verification/spec.py").verification
    first_role = sorted(spec.chain.anchors)[0]
    shared_name = spec.chain.anchors[first_role].filename
    calls = {"count": 0}

    class Shared:
        def __fspath__(self) -> str:
            calls["count"] += 1
            return shared_name

    shared = Shared()
    chain = dataclasses.replace(
        spec.chain,
        anchors={
            tsa: dataclasses.replace(anchor, filename=shared)  # type: ignore[arg-type]
            for tsa, anchor in spec.chain.anchors.items()
        },
    )
    manifest_path = sorted((repo / "releases/manifests").glob("*.json"))[0]
    manifest_bytes = manifest_path.read_bytes()
    manifest = _json.loads(manifest_bytes)
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    receipt_paths = {
        tsa: manifest_path.with_name(
            manifest_path.name.replace(".json", f".{tsa}.tsr")
        )
        for tsa in chain.anchors
    }

    reads = {"count": 0}
    original = module._regular_file_bytes

    def flipping_read(
        root: pathlib.Path,
        relative: pathlib.PurePosixPath,
        **kwargs: object,
    ) -> bytes:
        data = original(root, relative, **kwargs)
        if relative.name == shared_name and root.name == "anchors":
            reads["count"] += 1
            if reads["count"] >= 2:
                return data + b"# diverged between roles\n"
        return data

    monkeypatch.setattr(module, "_regular_file_bytes", flipping_read)
    observer: dict[str, str] = {}
    with pytest.raises(ReleaseChainError, match="changed during verification"):
        module.verify_release_receipts(
            manifest,
            digest,
            receipt_paths,
            spec=chain,
            anchor_dir=repo / ANCHOR_DIR,
            enforce_production_pins=False,
            clock_skew_seconds=300,
            anchor_observer=observer,
        )
    assert calls["count"] == 1
    assert reads["count"] == 2


def test_a_receipt_swapped_mid_verification_cannot_mix_two_tokens(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One receipt, three OpenSSL invocations, and one file between them.

    ``-text`` reads the genTime and the policy OID, ``-verify`` binds the
    token to the manifest digest, and the signer pins run over a token
    extracted a third time. Each reopened the path by name, so the tree under
    audit could hand a different file to each call and the verdict would
    report a time no verified token carried. Here the alpha receipt becomes
    the beta receipt the instant the inspection returns — a token from an
    authority whose root is not the CAfile in force, which the later calls
    cannot verify.

    With the bytes snapshotted once, the swap is inert: the reported genTime
    is the inspected token's, and it is the token that verified. Before the
    snapshot, the same swap refused instead — a refusal is a sound outcome
    too, but the mixed genTime between them is not, and only reading once
    rules it out.
    """

    spec = load_spec(repo / "verification/spec.py").verification
    manifests = repo / "releases/manifests"
    manifest_path = sorted(manifests.glob("*.json"))[0]
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    alpha = manifest_path.with_name(f"{manifest_path.stem}.alpha.tsr")
    beta = manifest_path.with_name(f"{manifest_path.stem}.beta.tsr")

    def check() -> object:
        return verify_receipt(
            digest,
            alpha,
            "alpha",
            spec=spec.chain,
            anchor_dir=repo / ANCHOR_DIR,
            enforce_production_pins=True,
        )

    expected = check()

    real_run = subprocess.run
    swaps = {"count": 0}

    def swapping(arguments: object, **kwargs: object) -> object:
        completed = real_run(arguments, **kwargs)  # type: ignore[arg-type]
        if isinstance(arguments, list) and "-text" in arguments:
            swaps["count"] += 1
            alpha.write_bytes(beta.read_bytes())
        return completed

    monkeypatch.setattr("receipt.release_chain.subprocess.run", swapping)
    observed = check()
    assert swaps["count"] == 1, "the inspection ran, so the swap landed"
    assert alpha.read_bytes() == beta.read_bytes(), "the file really was swapped"
    assert observed == expected


def test_a_receipt_that_is_not_a_regular_file_refuses_before_opening(
    tmp_path: pathlib.Path,
) -> None:
    """The lstat runs before the open, deliberately: opening a fifo for
    reading blocks until a writer arrives, so what kind of file this is has to
    be decided from the directory entry rather than from the descriptor."""

    import os

    fifo = tmp_path / "receipt.tsr"
    os.mkfifo(fifo)
    with pytest.raises(ReleaseChainError, match="non-regular RFC 3161 receipt"):
        _receipt_bytes(fifo)


def test_a_receipt_replaced_between_the_lstat_and_the_open_refuses(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The descriptor is what gets read, so the descriptor is what gets
    checked. A path that named one file at the lstat and another by the time
    it was opened addresses a different file, and its (device, inode) pair
    says so where the pathname cannot."""

    import os

    receipt = tmp_path / "receipt.tsr"
    receipt.write_bytes(b"the inspected token")
    other = tmp_path / "other.tsr"
    other.write_bytes(b"a different token")

    real_lstat = os.lstat

    def lying(path: object, **kwargs: object) -> object:
        if str(path) == str(receipt):
            return real_lstat(other)
        return real_lstat(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("receipt.release_chain.os.lstat", lying)
    with pytest.raises(ReleaseChainError, match="replaced while it was being read"):
        _receipt_bytes(receipt)


def receipt_text(repo: pathlib.Path) -> tuple[str, pathlib.Path]:
    """The real `openssl ts -reply -text` output the verifier parses."""

    manifest_path = sorted((repo / "releases/manifests").glob("*.json"))[0]
    alpha = manifest_path.with_name(f"{manifest_path.stem}.alpha.tsr")
    completed = subprocess.run(
        ["openssl", "ts", "-reply", "-config", "/dev/null", "-in", str(alpha), "-text"],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout, alpha


def with_fraction(text: str, fraction: str) -> str:
    """Rewrite only the genTime's fractional part, leaving the rest as OpenSSL
    printed it — a locally generated authority stamps whole seconds, but a
    production one need not."""

    lines = []
    for line in text.splitlines():
        if line.startswith("Time stamp:"):
            match = TIME_STAMP_RE.fullmatch(line.split(":", 1)[1].strip())
            assert match is not None
            line = (
                f"Time stamp: {match.group('month')} {match.group('day')} "
                f"{match.group('hour')}:{match.group('minute')}:"
                f"{match.group('second')}{fraction} {match.group('year')} GMT"
            )
        lines.append(line)
    return "\n".join(lines)


@pytest.mark.parametrize(
    ("fraction", "microsecond"),
    [("", 0), (".1", 100_000), (".123456", 123_456)],
)
def test_a_fractional_genTime_keeps_every_digit_it_can_represent(
    repo: pathlib.Path, fraction: str, microsecond: int
) -> None:
    """``.1`` is a tenth of a second, not a microsecond: the digits are the
    fraction's leading digits, right-padded, never read as a count."""

    text, alpha = receipt_text(repo)
    parsed, _ = _parse_receipt_text(with_fraction(text, fraction), alpha)
    assert parsed.microsecond == microsecond


def test_a_genTime_finer_than_a_microsecond_refuses(repo: pathlib.Path) -> None:
    """Truncating to six digits moves the parsed time earlier than the instant
    the authority signed — and that time is not merely reported. It is
    compared against createdAtUtc and against the previous release's
    witnesses, and it selects the -attime the signer certificate is validated
    at. A precision this verifier cannot hold refuses rather than rounding
    down into a time no receipt carries."""

    text, alpha = receipt_text(repo)
    with pytest.raises(ReleaseChainError, match="finer than a microsecond"):
        _parse_receipt_text(with_fraction(text, ".1234567"), alpha)


def test_a_genTime_with_zeros_beyond_the_sixth_digit_is_exact(
    repo: pathlib.Path,
) -> None:
    """Seven digits ending in zero name the same instant six digits do.

    The refusal exists for precision the parser cannot hold; a trailing zero
    holds none, so refusing it would be over-refusal in the fail-closed
    direction for no gain. A seventh digit that is not zero still refuses."""

    text, alpha = receipt_text(repo)
    parsed, _ = _parse_receipt_text(with_fraction(text, ".1234560"), alpha)
    assert parsed.microsecond == 123456
    with pytest.raises(ReleaseChainError, match="finer than a microsecond"):
        _parse_receipt_text(with_fraction(text, ".1234561"), alpha)


def test_default_mode_keeps_parts_based_purepath_joins(
    repo: pathlib.Path,
) -> None:
    """Origin joins a PurePath filename by its parts (a PureWindowsPath's
    backslash component splits), and default mode must keep doing exactly
    that — observing-mode pathname semantics never leak into it."""

    import dataclasses

    spec = load_spec(repo / "verification/spec.py").verification
    key_name = spec.chain.producer_public_key_filename
    nested = repo / ANCHOR_DIR / "sub"
    nested.mkdir()
    (nested / key_name).write_bytes(
        (repo / ANCHOR_DIR / key_name).read_bytes()
    )
    chain = dataclasses.replace(
        spec.chain,
        producer_public_key_filename=pathlib.PureWindowsPath(  # type: ignore[arg-type]
            f"sub\\{key_name}"
        ),
    )
    # Parts semantics address anchors/sub/<key>; pathname semantics would
    # address a single "sub\<key>" component that does not exist. Default
    # mode must verify — proving the raw value still reaches the join.
    verification = verify_release_chain(repo, spec=chain)
    assert verification.anchor_set_sha256 is None


def test_a_filename_object_shared_across_roles_is_asked_once(
    repo: pathlib.Path,
) -> None:
    """The memoized rewrite: producer and TSA roles sharing one stateful
    object must collapse to a single pathname answer."""

    from receipt.release_chain import _normalized_spec

    calls = {"count": 0}

    class Shared:
        def __fspath__(self) -> str:
            calls["count"] += 1
            return "shared.pem" if calls["count"] == 1 else "other.pem"

    import dataclasses

    shared = Shared()
    base = load_spec(repo / "verification/spec.py").verification
    base = base.chain
    chain = dataclasses.replace(
        base,
        producer_public_key_filename=shared,  # type: ignore[arg-type]
        anchors={
            tsa: dataclasses.replace(anchor, filename=shared)  # type: ignore[arg-type]
            for tsa, anchor in base.anchors.items()
        },
    )
    normalized = _normalized_spec(chain)
    assert calls["count"] == 1
    names = {normalized.producer_public_key_filename} | {
        anchor.filename for anchor in normalized.anchors.values()
    }
    assert names == {"shared.pem"}


def test_an_already_normalized_chain_spec_keeps_its_identity(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A composing caller can share one normalized spec with its digest."""

    spec = load_spec(repo / "verification/spec.py").verification.chain
    normalized = release_chain._normalized_spec(spec)

    def normalized_twice(*args: object, **kwargs: object) -> None:
        del args, kwargs
        pytest.fail("verify_release_chain normalized an exact-string spec again")

    monkeypatch.setattr(release_chain, "_normalized_spec", normalized_twice)
    verification = verify_release_chain(
        repo,
        spec=normalized,
        compute_anchor_set_digest=True,
    )

    assert verification.anchor_set_sha256 is not None


def test_a_caller_supplied_anchor_directory_still_gets_a_digest(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """Pins off (the caller's own trust choice), digest still computed —
    and byte-identical anchor material yields the production digest, since
    the mapping commits to configured names and consumed bytes, not paths."""

    spec = load_spec(repo / "verification/spec.py").verification
    production = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )
    aside = tmp_path / "anchors-copy"
    shutil.copytree(repo / ANCHOR_DIR, aside)
    substituted = verify_release_chain(
        repo,
        spec=spec.chain,
        anchor_dir=aside,
        compute_anchor_set_digest=True,
    )
    assert substituted.anchor_set_sha256 == production.anchor_set_sha256


def test_the_reported_pairs_cannot_be_mutated(repo: pathlib.Path) -> None:
    """ChainVerification is frozen; mutable state inside it could drift
    from the combined digest it backs."""

    spec = load_spec(repo / "verification/spec.py").verification
    verification = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )
    with pytest.raises(TypeError):
        verification.anchor_file_sha256s[0] = ("x", "y")  # type: ignore[index]


def test_chain_verification_stays_reflection_safe(repo: pathlib.Path) -> None:
    """Adding the anchor-set fields must not tighten 0.5.0's reflection
    contract: asdict, deepcopy, and pickle work in every mode, and the
    empty result stays hashable. (A populated result was already unhashable
    on 0.5.0 through ReleaseRecord's dictionaries — the new fields must not
    be what makes anything unhashable.)"""

    import copy
    import dataclasses
    import pickle

    from receipt.release_chain import ChainVerification

    spec = load_spec(repo / "verification/spec.py").verification
    computed = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )
    default_mode = verify_release_chain(repo, spec=spec.chain)
    for verification in (ChainVerification(()), computed, default_mode):
        assert dataclasses.asdict(verification) is not None
        assert copy.deepcopy(verification) == verification
        assert pickle.loads(pickle.dumps(verification)) == verification
    hash(ChainVerification(()))
    hash(
        ChainVerification(
            (),
            anchor_set_sha256="ab" * 32,
            anchor_file_sha256s=(("a.pem", "cd" * 32),),
        )
    )


def test_bytes_that_change_between_consumptions_refuse() -> None:
    observer: dict[str, str] = {}
    _observe_anchor_bytes(observer, "root.pem", b"first bytes")
    _observe_anchor_bytes(observer, "root.pem", b"first bytes")
    with pytest.raises(ReleaseChainError, match="changed during verification"):
        _observe_anchor_bytes(observer, "root.pem", b"second bytes")


def test_pathlike_filenames_key_by_consumed_pathname() -> None:
    """A custom PathLike names the file through __fspath__; str() could be a
    repr. Two roles naming one file through distinct PathLike objects must
    collapse to one observer key — the consumed pathname."""

    from receipt.release_chain import _observe_anchor_bytes as observe

    class Configured:
        def __init__(self, pathname: str) -> None:
            self._pathname = pathname

        def __fspath__(self) -> str:
            return self._pathname

        def __repr__(self) -> str:  # deliberately address-like
            return f"<Configured at {id(self):#x}>"

    observer: dict[str, str] = {}
    observe(observer, Configured("shared.pem"), b"bytes")  # type: ignore[arg-type]
    observe(observer, Configured("shared.pem"), b"bytes")  # type: ignore[arg-type]
    assert set(observer) == {"shared.pem"}
    with pytest.raises(ReleaseChainError, match="changed during verification"):
        observe(observer, Configured("shared.pem"), b"other")  # type: ignore[arg-type]


@pytest.mark.parametrize("role", ["tsa-anchor", "producer-key"])
def test_a_mid_run_anchor_change_refuses_end_to_end(
    role: str, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One observer spans releases and roles: over a two-release chain each
    anchor file is consumed once per release, and bytes that differ between
    those consumptions refuse — proving the wiring for both consumption
    sites, not just the helper."""

    root = tmp_path / "repo"
    root.mkdir()
    workspace = tmp_path / "tsa-workspace"
    build_corpus(root, workspace)
    corrected = dict(CONTENT)
    corrected["rules/tax/rate.yaml"] = "name: rate\nvalue: 0.175\n"
    append_release(root, workspace, content=corrected)

    spec = load_spec(root / "verification/spec.py").verification
    if role == "tsa-anchor":
        target = sorted(a.filename for a in spec.chain.anchors.values())[0]
    else:
        target = spec.chain.producer_public_key_filename
    aside = tmp_path / "anchors-copy"
    shutil.copytree(root / ANCHOR_DIR, aside)

    reads = {"count": 0}
    original = release_chain._regular_file_bytes

    def flipping_read(
        read_root: pathlib.Path,
        relative: pathlib.PurePosixPath,
        **kwargs: object,
    ) -> bytes:
        data = original(read_root, relative, **kwargs)
        if relative.name == target and read_root.name == aside.name:
            reads["count"] += 1
            if reads["count"] >= 2:
                return data + b"# drifted between consumptions\n"
        return data

    monkeypatch.setattr(release_chain, "_regular_file_bytes", flipping_read)
    with pytest.raises(ReleaseChainError, match="changed during verification"):
        # The caller-supplied anchor directory turns pins off, so the
        # observer — not the byte pin — must be what catches the drift.
        verify_release_chain(
            root,
            spec=spec.chain,
            anchor_dir=aside,
            compute_anchor_set_digest=True,
        )
    assert reads["count"] >= 2, "the run must have consumed the anchor twice"


def test_the_combined_digest_is_injective_and_filename_agnostic() -> None:
    digest_a = "ab" * 32
    digest_b = "cd" * 32
    assert _combined_anchor_digest({"x.pem": digest_a}) != _combined_anchor_digest(
        {"x.pem": digest_b}
    )
    assert _combined_anchor_digest(
        {"x.pem": digest_a, "y.pem": digest_b}
    ) != _combined_anchor_digest({"x.pem": digest_b, "y.pem": digest_a})
    # Any filename string encodes: non-ASCII, spaces, newlines. The encoding
    # is the package's own canonical JSON, so it never raises on the
    # filename domain the older checks accepted.
    exotic = {"ключ\nанкер .pem": digest_a}
    assert _combined_anchor_digest(exotic) == canonical_sha256(exotic)
    # And the canonical rule is pinned against an independently hand-built
    # encoding for the case where key orders diverge: canonical JSON sorts
    # keys by UTF-16 code units, so an astral-plane key (surrogates D800…)
    # precedes U+FF61 even though its code point is higher. A drift to
    # code-point ordering (plain sort_keys) would flip these keys.
    astral, halfwidth = "\U00010000k", "｡k"
    expected = (
        b'{"' + astral.encode() + b'":"' + digest_a.encode()
        + b'","' + halfwidth.encode() + b'":"' + digest_b.encode() + b'"}'
    )
    assert _combined_anchor_digest(
        {halfwidth: digest_b, astral: digest_a}
    ) == hashlib.sha256(expected).hexdigest()
    # A lone surrogate — what os.fsdecode yields for undecodable bytes in a
    # filename — encodes as a JSON escape rather than raising.
    surrogate = {"a\udc80b.pem": digest_a}
    expected_surrogate = (
        b'{"a\\udc80b.pem":"' + digest_a.encode() + b'"}'
    )
    assert _combined_anchor_digest(surrogate) == hashlib.sha256(
        expected_surrogate
    ).hexdigest()


def test_explicit_surrogate_pair_filenames_refuse() -> None:
    """A filename spelling an astral character as an explicit surrogate pair
    is a different Python string from the astral spelling but one and the
    same string after any JSON round trip — with or without the astral twin
    present, a verdict carrying it could never be reproduced from --json,
    so the digest refuses."""

    astral, pair = "\U00010000", "\ud800\udc00"
    assert astral != pair
    with pytest.raises(ReleaseChainError, match="explicit\\s+surrogate pair"):
        _combined_anchor_digest({pair: "cd" * 32})
    with pytest.raises(ReleaseChainError, match="explicit\\s+surrogate pair"):
        _combined_anchor_digest({astral: "ab" * 32, pair: "cd" * 32})
    # The astral spelling alone is fine — it round-trips as itself.
    _combined_anchor_digest({astral: "ab" * 32})


def test_the_reported_mapping_survives_a_json_round_trip() -> None:
    """The auditor-facing property behind the refusals: for every mapping
    the digest accepts — including lone surrogateescape names from
    undecodable filesystem bytes — parsing the JSON rendering back
    reproduces the exact mapping, and its recomputed digest matches."""

    import json as _json

    mapping = {
        "plain.pem": "ab" * 32,
        "ключ.pem": "cd" * 32,
        "escape-a\udc80b.pem": "ef" * 32,
        "\U00010000.pem": "12" * 32,
    }
    digest = _combined_anchor_digest(mapping)
    round_tripped = _json.loads(_json.dumps(mapping))
    assert round_tripped == mapping
    assert _combined_anchor_digest(round_tripped) == digest


def test_out_of_domain_filenames_refuse_cleanly() -> None:
    """The observing-mode domain is exactly str | os.PathLike: bare bytes
    (which os.fsdecode would happily decode) and malformed PathLike objects
    refuse with the package's own error, never an escaping TypeError."""

    from receipt.release_chain import _exact_filename

    with pytest.raises(ReleaseChainError, match="must be str or os.PathLike"):
        _exact_filename(b"anchor.pem")

    class Malformed:
        def __fspath__(self) -> str:
            return 42  # type: ignore[return-value]

    with pytest.raises(ReleaseChainError, match="could not be decoded"):
        _exact_filename(Malformed())

    class Exploding:
        def __fspath__(self) -> str:
            raise RuntimeError("deliberately hostile")

    with pytest.raises(ReleaseChainError, match="could not be decoded"):
        _exact_filename(Exploding())

    class DecodesToNonsense(bytes):
        def decode(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            return 42

    class PathLikeToHostileBytes:
        def __fspath__(self) -> str:
            return DecodesToNonsense(b"x.pem")  # type: ignore[return-value]

    with pytest.raises(ReleaseChainError, match="could not be decoded"):
        _exact_filename(PathLikeToHostileBytes())

    class Unprintable(Exception):
        def __str__(self) -> str:
            raise RuntimeError("even the message is hostile")

    class RaisesUnprintable:
        def __fspath__(self) -> str:
            raise Unprintable()

    with pytest.raises(ReleaseChainError, match="could not be decoded"):
        _exact_filename(RaisesUnprintable())


def test_a_lazy_spec_mapping_cannot_alias_through_id_reuse(
    repo: pathlib.Path,
) -> None:
    """The memo retains each filename object: a mapping that materializes
    fresh filename objects on every access cannot have an early object
    collected mid-rewrite and its id reused for a different filename."""

    import dataclasses
    from collections.abc import Mapping as MappingABC

    from receipt.release_chain import _normalized_spec

    spec = load_spec(repo / "verification/spec.py").verification
    base_anchors = dict(spec.chain.anchors)
    roles = {f"role{i:03d}": f"anchor-{i:03d}.pem" for i in range(200)}

    class FreshName:
        def __init__(self, name: str) -> None:
            self._name = name

        def __fspath__(self) -> str:
            return self._name

    template = next(iter(base_anchors.values()))

    class LazyAnchors(MappingABC):
        def __getitem__(self, tsa: str):  # fresh objects per access
            return dataclasses.replace(
                template, filename=FreshName(roles[tsa])  # type: ignore[arg-type]
            )

        def __iter__(self):
            return iter(roles)

        def __len__(self) -> int:
            return len(roles)

    chain = dataclasses.replace(
        spec.chain, anchors=LazyAnchors()  # type: ignore[arg-type]
    )
    normalized = _normalized_spec(chain, include_producer=False)
    observed = {
        tsa: anchor.filename for tsa, anchor in normalized.anchors.items()
    }
    assert observed == roles


def test_a_pathlike_yielding_a_str_subclass_is_normalized_exact() -> None:
    from receipt.release_chain import _exact_filename

    class Sneaky(str):
        def encode(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            raise AssertionError("subclass method must never be reachable")

        __hash__ = None  # type: ignore[assignment]

    class Wrapper:
        def __fspath__(self) -> str:
            return Sneaky("anchor.pem")

    normalized = _exact_filename(Wrapper())
    assert type(normalized) is str
    assert normalized == "anchor.pem"
    normalized.encode("ascii")


def test_an_empty_optional_chain_asks_no_pathnames(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """require_chain=False on an empty tree returned before touching any
    configured filename on origin, and still must — even when observing."""

    import dataclasses

    spec = load_spec(repo / "verification/spec.py").verification
    calls = {"count": 0}

    class Counting:
        def __init__(self, name: str) -> None:
            self._name = name

        def __fspath__(self) -> str:
            calls["count"] += 1
            return self._name

    chain = dataclasses.replace(
        spec.chain,
        producer_public_key_filename=Counting(  # type: ignore[arg-type]
            spec.chain.producer_public_key_filename
        ),
    )
    empty = tmp_path / "empty"
    empty.mkdir()
    verification = verify_release_chain(
        empty,
        spec=chain,
        require_chain=False,
        compute_anchor_set_digest=True,
    )
    assert verification.releases == ()
    assert calls["count"] == 0


def test_verify_result_exposes_the_anchor_set(repo: pathlib.Path) -> None:
    spec_path = repo / "verification/spec.py"
    loaded = load_spec(spec_path)
    result = run_verification(repo, loaded)
    assert result.ok
    combined, per_file = independent_digests(repo)
    assert result.anchor_set_sha256 == combined
    assert result.anchor_file_sha256s == per_file


def test_an_absent_chain_names_no_anchor_set(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """No chain verified means no anchors consumed — the field must say so
    rather than digest anchor files nothing was checked against."""

    spec = load_spec(repo / "verification/spec.py").verification
    empty = tmp_path / "empty"
    empty.mkdir()
    anchor_reads = {"count": 0}
    original_read_bytes = pathlib.Path.read_bytes

    def counting_read_bytes(self: pathlib.Path) -> bytes:
        if self.parent.name == "anchors":
            anchor_reads["count"] += 1
        return original_read_bytes(self)

    import pytest as _pytest

    monkeypatch = _pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(pathlib.Path, "read_bytes", counting_read_bytes)
        verification = verify_release_chain(
            empty,
            spec=spec.chain,
            require_chain=False,
            compute_anchor_set_digest=True,
        )
    finally:
        monkeypatch.undo()
    assert verification.releases == ()
    assert verification.anchor_set_sha256 is None
    assert verification.anchor_file_sha256s == ()
    assert anchor_reads["count"] == 0


def test_standalone_receipts_never_touch_the_producer_filename(
    repo: pathlib.Path,
) -> None:
    """verify_release_receipts consumes only TSA anchors; a producer
    filename that would refuse normalization must be neither asked nor able
    to fail the call."""

    import dataclasses
    import json as _json

    import receipt.release_chain as module

    spec = load_spec(repo / "verification/spec.py").verification
    chain = dataclasses.replace(
        spec.chain,
        producer_public_key_filename=b"not-in-domain",  # type: ignore[arg-type]
    )
    manifest_path = sorted((repo / "releases/manifests").glob("*.json"))[0]
    manifest_bytes = manifest_path.read_bytes()
    manifest = _json.loads(manifest_bytes)
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    receipt_paths = {
        tsa: manifest_path.with_name(
            manifest_path.name.replace(".json", f".{tsa}.tsr")
        )
        for tsa in chain.anchors
    }
    observer: dict[str, str] = {}
    times = module.verify_release_receipts(
        manifest,
        digest,
        receipt_paths,
        spec=chain,
        anchor_dir=repo / ANCHOR_DIR,
        enforce_production_pins=True,
        clock_skew_seconds=300,
        anchor_observer=observer,
    )
    assert set(times) == set(chain.anchors)
    assert set(observer) == {
        anchor.filename for anchor in spec.chain.anchors.values()
    }


def test_verify_result_accessors_before_custody() -> None:
    from receipt.verify import VerifyResult

    result = VerifyResult(
        spec_name="x",
        spec_path=pathlib.Path("spec.py"),
        spec_sha256="ab" * 32,
        root=pathlib.Path("."),
        receipt_version="0.0.0",
        producer_spki_sha256="cd" * 32,
        passes=(),
        chain=None,
        corpus=None,
    )
    assert result.anchor_set_sha256 is None
    assert result.anchor_file_sha256s == {}
    # And it is not a PASS. "No pass failed" is not "the verdict's passes
    # ran": all() over an empty tuple is true, and this result rendered as
    # "ESTABLISHED OFFLINE, FROM THIS CLONE ALONE" with exit status 0.
    assert result.ok is False


def test_a_verdict_needs_all_three_of_its_passes() -> None:
    """Custody, binding, and declaration each carry part of the claim, so a
    result holding only some of them — every one of them ok — is still not a
    verdict. The one holding all three is."""

    import dataclasses

    from receipt.verify import REQUIRED_PASSES, PassResult, VerifyResult

    def built(*names: str) -> VerifyResult:
        return VerifyResult(
            spec_name="x",
            spec_path=pathlib.Path("spec.py"),
            spec_sha256="ab" * 32,
            root=pathlib.Path("."),
            receipt_version="0.0.0",
            producer_spki_sha256="cd" * 32,
            passes=tuple(PassResult(name, True, "detail") for name in names),
            chain=None,
            corpus=None,
        )

    assert REQUIRED_PASSES == ("custody", "binding", "declaration")
    for missing in REQUIRED_PASSES:
        partial = [name for name in REQUIRED_PASSES if name != missing]
        assert built(*partial).ok is False, missing
    assert built(*REQUIRED_PASSES).ok is True
    # A recorded failure still overrides a complete set.
    complete = built(*REQUIRED_PASSES)
    failed = dataclasses.replace(
        complete,
        passes=complete.passes + (PassResult("history", False, "", "no"),),
    )
    assert failed.ok is False


def test_module_version_matches_project_metadata() -> None:
    import re

    import receipt

    pyproject = (
        pathlib.Path(receipt.__file__).resolve().parents[2] / "pyproject.toml"
    ).read_text()
    declared = re.search(
        r'^version = "([^"]+)"', pyproject, flags=re.MULTILINE
    )
    assert declared is not None
    assert receipt.__version__ == declared.group(1)


def test_pin_inference_follows_resolution_not_spelling(
    repo: pathlib.Path,
) -> None:
    """A caller-supplied anchor directory that merely spells the default
    directory differently still resolves equal, so pin inference keeps
    enforcement on — proven by the pin refusal firing through the alternate
    spelling once an anchor byte is flipped."""

    spec = load_spec(repo / "verification/spec.py").verification
    spelled = repo / ANCHOR_DIR / ".." / "anchors"
    verification = verify_release_chain(
        repo, spec=spec.chain, anchor_dir=spelled, compute_anchor_set_digest=True
    )
    assert verification.anchor_set_sha256 is not None

    target = sorted(a.filename for a in spec.chain.anchors.values())[0]
    data = bytearray((repo / ANCHOR_DIR / target).read_bytes())
    data[len(data) // 2] ^= 0x01
    (repo / ANCHOR_DIR / target).write_bytes(bytes(data))
    with pytest.raises(ReleaseChainError, match="not code-pinned"):
        verify_release_chain(
            repo,
            spec=spec.chain,
            anchor_dir=spelled,
            compute_anchor_set_digest=True,
        )


def state_paths(
    repo: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path, dict[str, bytes]]:
    """The two state files of a built chain, and their bytes keyed as supplied."""

    spec = load_spec(repo / "verification/spec.py").verification
    ledger = repo / spec.chain.state_relative
    prefix = repo / spec.chain.prefix_relative
    return ledger, prefix, {
        spec.chain.state_relative.as_posix(): ledger.read_bytes(),
        spec.chain.prefix_relative.as_posix(): prefix.read_bytes(),
    }


def test_supplied_state_bytes_are_used_instead_of_reading_the_state_paths(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds round five's first finding: the verdict's one read of each file.

    ``append_gate`` reads the ledger and the frozen prefix once, records what
    it read, and feeds every consumer it owns from that snapshot. This
    verifier was not one of them — it opened both paths again by name — so a
    candidate could show the row checks one ledger and the release history
    another inside a single verdict, then restore the first before the
    closing re-read. Given the bytes, the paths are not opened here at all:
    the reader is replaced with one that fails if it is called, and a decoy
    is left on disk for anything that resolves the name anyway.
    """

    spec = load_spec(repo / "verification/spec.py").verification
    ledger, prefix, supplied = state_paths(repo)
    ledger.write_bytes(b'{"decoy":true}\n')
    prefix.write_bytes(b"{}\n")

    original = release_chain._regular_file_bytes

    def refuse(
        root: pathlib.Path,
        relative: pathlib.PurePosixPath,
        **kwargs: object,
    ) -> bytes:
        if relative in {spec.chain.state_relative, spec.chain.prefix_relative}:
            raise AssertionError(f"state path was read by name: {relative}")
        return original(root, relative, **kwargs)

    monkeypatch.setattr(release_chain, "_regular_file_bytes", refuse)

    verification = verify_release_chain(repo, spec=spec.chain, state_bytes=supplied)
    assert len(verification.releases) == 1


def test_without_supplied_bytes_the_state_paths_are_read_exactly_as_before(
    repo: pathlib.Path
) -> None:
    """The control the same finding requires: omitting the parameter changes
    nothing. The identical decoy is refused, because the reader that predates
    the parameter is the one that ran, on the same paths, in the same place."""

    spec = load_spec(repo / "verification/spec.py").verification
    ledger, _prefix, _supplied = state_paths(repo)
    ledger.write_bytes(b'{"decoy":true}\n')

    with pytest.raises(ReleaseChainError) as refusal:
        verify_release_chain(repo, spec=spec.chain)
    assert "lineCount" in str(refusal.value)


def test_state_bytes_must_map_exact_strings_to_exact_bytes(
    repo: pathlib.Path
) -> None:
    """The parameter is trusted in place of a read, so it is checked the way
    this module checks everything else it is handed: a str subclass could
    compare equal to a state path while rendering as something else, and a
    bytes-like view could change under the digests taken from it."""

    spec = load_spec(repo / "verification/spec.py").verification
    _ledger, _prefix, supplied = state_paths(repo)

    with pytest.raises(ReleaseChainError) as not_a_mapping:
        verify_release_chain(repo, spec=spec.chain, state_bytes=[("a", b"b")])
    assert str(not_a_mapping.value) == (
        "state_bytes must be a mapping of state path to bytes"
    )

    key = next(iter(supplied))
    with pytest.raises(ReleaseChainError) as not_exact:
        verify_release_chain(
            repo,
            spec=spec.chain,
            state_bytes={**supplied, key: bytearray(supplied[key])},
        )
    assert str(not_exact.value) == (
        "state_bytes must map exact str state paths to exact bytes"
    )


PLATFORM_REFUSAL = (
    "state files cannot be read with secure descent on this platform "
    "(os.O_NOFOLLOW is unavailable); receipt requires a POSIX platform"
)


def without_no_follow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Present a platform without the non-following open the reader requires."""

    monkeypatch.setattr(os, "O_NOFOLLOW", 0)


def test_the_custody_read_refuses_a_platform_without_no_follow(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S4-F6: the ``O_NOFOLLOW`` requirement was documented as the append
    gate's, but ``_regular_file_bytes`` is where it lives and this verifier is
    that function's other caller — so ``verify_release_chain`` stops on the
    same refusal, on the public path, with no append gate anywhere in the
    picture. The restriction is the package's, and the refusal now says so.
    Without that sentence the message names only ``os.open`` and a reader is
    left to infer how far it reaches."""

    spec = load_spec(repo / "verification/spec.py").verification
    without_no_follow(monkeypatch)

    with pytest.raises(ReleaseChainError) as refusal:
        verify_release_chain(repo, spec=spec.chain)
    assert str(refusal.value) == PLATFORM_REFUSAL


def test_receipt_verify_reports_the_platform_refusal_as_the_custody_failure(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """S4-F6 end to end. ``receipt verify`` is the outside auditor's command
    and its first pass is custody, which reads both state files through the
    same descent — so on Windows the default verification stops there too,
    not only the append gate. The verdict names the pass and carries the
    refusal verbatim, so an auditor is told what the platform costs rather
    than left with a failure they cannot place."""

    without_no_follow(monkeypatch)

    assert main(
        ["verify", "--spec", str(repo / "verification/spec.py"), "--root", str(repo)]
    ) == EXIT_FAIL
    # A failing verdict is rendered on stderr; the text is the same either way.
    rendered = capsys.readouterr().err
    assert "VERDICT: FAIL — custody" in rendered
    assert PLATFORM_REFUSAL in rendered


def test_a_symlinked_interior_manifest_component_is_refused(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """Binds S5-R2-F3. The release tree's confinement walk —
    ``assert_no_symlinked_release_root``, which walks all three configured
    paths whole — now belongs directly to the public directory verifier. A
    spec whose manifest directory sits below an interior
    component (``releases/journal/manifests``) had that component resolved
    like any other name: an untracked symlink at ``releases/journal`` pointing
    outside the tree made the chain in *that* directory the one this function
    verified, and the verdict spoke for a release history no part of which is
    in the tree the auditor was handed.

    Measured at this round's head with ``assert_no_symlinked_release_root``
    removed from ``verify_release_chain``, on this exact arrangement: the call
    returns a verification whose head manifest is the one stored outside the
    root, ``0000-<digest>.json``, and returns it as a pass. Nothing else here
    would have said otherwise — the index reconciliation that catches a linked
    component in the append gate is not on this path at all, and there is no
    base to compare against.

    The walk runs at the top now, after the arguments are validated and the
    anchor probe has had its say and before the enumeration, so both the gate
    and ``receipt verify`` reach it."""

    outside = tmp_path / "elsewhere"
    outside.mkdir()
    shutil.move(str(repo / "releases" / "manifests"), str(outside / "manifests"))
    (repo / "releases" / "journal").symlink_to(outside)
    spec = load_spec(repo / "verification/spec.py").verification
    nested = replace(
        spec.chain,
        manifest_relative=pathlib.PurePosixPath("releases/journal/manifests"),
    )
    # The link really does deliver the chain: this is a confinement question,
    # not a question about whether the manifests are valid.
    assert (repo / "releases/journal/manifests").is_dir()

    with pytest.raises(ReleaseChainError) as refusal:
        verify_release_chain(repo, spec=nested)
    assert str(refusal.value) == (
        "release root path traverses a symlink at 'releases/journal': "
        "releases/journal/manifests"
    )


def test_a_folded_manifest_leaf_is_refused_by_the_public_verifier(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S5-R2-F3's other half, and the reason the walk binds spellings as well
    as types. Round 12 bound the configured leaf's spelling, so a spec naming
    ``releases/manifests`` over a ``releases/Manifests`` on disk is refused
    rather than verified out of a directory the spec never named — but only
    where the walk ran, which was the append gate alone. ``receipt verify``,
    whose custody pass is this function, verified it.

    Simulated the way round 12's own spelling cases are, because a
    name-folding filesystem produces one pair of facts and only one of them
    can be arranged everywhere: the ``lstat`` of the requested spelling
    succeeds (real here — the directory is spelled exactly as the spec pins
    it), and the holding directory's listing does not contain that spelling
    (simulated, by answering the one ``os.listdir`` of the release root with a
    folded name and delegating every other listing, which is the whole of what
    ``_assert_component_spelled`` reads).

    Measured at this round's head with ``assert_no_symlinked_release_root``
    removed from ``verify_release_chain``, under the same simulated listing:
    the chain verifies and the head manifest is returned as a pass."""

    spec = load_spec(repo / "verification/spec.py").verification
    release_root = (repo / "releases").resolve()
    real_listdir = os.listdir

    def a_listing_that_folds(where: object) -> list[str]:
        listed = real_listdir(where)  # type: ignore[arg-type]
        if pathlib.Path(os.fspath(where)).resolve() == release_root:
            return [
                "Manifests" if name == "manifests" else name for name in listed
            ]
        return listed

    monkeypatch.setattr(os, "listdir", a_listing_that_folds)
    # The other half of the pair is real: the pinned spelling still resolves.
    assert (release_root / "manifests").is_dir()

    with pytest.raises(ReleaseChainError) as refusal:
        verify_release_chain(repo, spec=spec.chain)
    assert str(refusal.value) == (
        "path component releases/manifests is not spelled by its directory: "
        "releases/manifests"
    )


@pytest.fixture()
def state_relative() -> pathlib.PurePosixPath:
    """The original append fixture path used by the direct-reader cases."""

    return pathlib.PurePosixPath("ledger/official_observations.jsonl")


def test_the_state_reader_refuses_a_symlinked_parent(
    tmp_path: pathlib.Path, state_relative: pathlib.PurePosixPath
) -> None:
    """The same walk in the release-chain reader, which _verify_state_history
    uses for both the ledger and the immutable prefix."""

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "official_observations.jsonl").write_text("{}\n", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "ledger").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ReleaseChainError) as refusal:
        _regular_file_bytes(root, state_relative)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'ledger': "
        "ledger/official_observations.jsonl"
    )


def test_the_state_reader_keeps_its_message_for_a_symlinked_state_file(
    tmp_path: pathlib.Path, state_relative: pathlib.PurePosixPath
) -> None:
    """The final-component refusal predates the walk and is differential-gated:
    a linked state file must still refuse with exactly its own message."""

    root = tmp_path / "repo"
    (root / "ledger").mkdir(parents=True)
    outside = tmp_path / "outside.jsonl"
    outside.write_text("{}\n", encoding="utf-8")
    linked = root / state_relative
    linked.symlink_to(outside)

    with pytest.raises(ReleaseChainError) as refusal:
        _regular_file_bytes(root, state_relative)
    assert str(refusal.value) == (
        f"required state file is missing or non-regular: {linked}"
    )


def test_the_state_reader_accepts_an_ordinary_regular_file(
    tmp_path: pathlib.Path, state_relative: pathlib.PurePosixPath
) -> None:
    """The walk costs the ordinary tree nothing."""

    root = tmp_path / "repo"
    (root / "ledger").mkdir(parents=True)
    (root / state_relative).write_text("{}\n", encoding="utf-8")

    assert _regular_file_bytes(root, state_relative) == b"{}\n"


@pytest.mark.skipif(
    os.getuid() == 0, reason="root traverses a directory it has no rights on"
)
def test_the_shared_state_reader_answers_the_same_way(
    tmp_path: pathlib.Path, state_relative: pathlib.PurePosixPath
) -> None:
    """S4R4-F7 through ``release_chain``'s own reader, which is the one
    ``verify_release_chain`` — and so ``receipt verify``'s custody pass —
    uses. ``_regular_file_bytes`` runs the same component walk before its
    descent, so the requirement is the package's rather than the gate's and
    both readers state it the same way. That is why ``README.md`` says it
    where a consumer looks. Measured at 4d8039f with the fold probe answering
    False: this reader returns the ledger's bytes for a directory that cannot
    be listed."""

    root = tmp_path / "repo"
    (root / "ledger").mkdir(parents=True)
    (root / state_relative).write_text("{}\n", encoding="utf-8")
    ledger_directory = root / "ledger"
    expected = (root / state_relative).read_bytes()
    assert expected
    ledger_directory.chmod(0o111)
    try:
        with pytest.raises(ReleaseChainError) as refusal:
            _regular_file_bytes(root, state_relative)
        assert str(refusal.value) == (
            "cannot bind the spelling of "
            f"{state_relative.as_posix()}: its directory cannot be "
            f"listed: {state_relative.as_posix()}"
        )
    finally:
        ledger_directory.chmod(0o755)
    assert _regular_file_bytes(root, state_relative) == expected


@pytest.mark.skipif(
    os.getuid() == 0, reason="root searches a directory it has no rights on"
)
def test_a_manifest_path_this_verifier_cannot_stat_is_not_no_chain(
    repo: pathlib.Path,
) -> None:
    """S5-R2-F2's third fact, which the bare ``except OSError`` folded into
    absence along with the type answer: a manifest path under an unsearchable
    ancestor cannot be ``lstat``-ed at all, and "I could not ask" is not "there
    is nothing there". Measured at this round's head with the single ``lstat``
    and bare ``except OSError`` put back, on this exact directory: the call
    returns ``None`` — the acceptance the push path reads as no chain.

    Driven directly rather than through the gate, because the gate cannot
    reach it: a release root at mode 0o444 is readable, so
    ``_assert_component_spelled`` binds every spelling and the walk passes,
    and then ``hold_release_root``'s ``os.open`` of that root with search
    rights fails first — measured on this tree as a bare ``PermissionError:
    [Errno 13] Permission denied: 'releases'``, which is that open's own
    answer and not this decision's to give. What is bound here is that the
    type decision no longer reports an unaskable question as an answer."""

    chain = load_spec(repo / "verification/spec.py").verification.chain
    releases = repo / chain.release_root_relative
    releases.chmod(0o444)
    try:
        with pytest.raises(ReleaseChainError) as refusal:
            release_chain.assert_manifest_directory_regular(repo, chain)
        assert str(refusal.value) == (
            "cannot stat release manifest path: releases/manifests "
            "(Permission denied)"
        )
    finally:
        releases.chmod(0o755)
