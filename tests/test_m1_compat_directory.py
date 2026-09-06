"""Permanent goldens for retained physical readers; these never stage files."""
from __future__ import annotations

import dataclasses
import errno
import os
import pathlib
import shutil

import pytest

from receipt import release_chain as chain
from receipt.snapshot import Materialization, SnapshotError, TreeSnapshot
from receipt import append_gate
from m1_fixture import signed_repo, outcome, assert_golden


@pytest.mark.parametrize("case", ("missing", "ancestor", "leaf", "permission", "race_enotdir"))
def test_manifest_directory_guard(signed_repo, tmp_path, monkeypatch, case):
    root = tmp_path / "directory"
    root.mkdir()
    if case == "ancestor":
        (root / "releases").write_bytes(b"blob")
    elif case in {"leaf", "permission", "race_enotdir"}:
        (root / "releases").mkdir()
        (root / "releases/manifests").write_bytes(b"blob")
    if case in {"permission", "race_enotdir"}:
        original = os.lstat
        def fail(path, *args, **kwargs):
            if pathlib.Path(path) == root / "releases/manifests":
                error = errno.EACCES if case == "permission" else errno.ENOTDIR
                raise OSError(error, os.strerror(error))
            return original(path, *args, **kwargs)
        monkeypatch.setattr(os, "lstat", fail)
    # record: census release_chain.py 487-568 lstat/ancestor/leaf/permission guard
    assert_golden("directory/manifest/" + case,
                  outcome(lambda: chain.assert_manifest_directory_regular(root, signed_repo.chain)),
                  ((root, "<ROOT>"),))


@pytest.mark.parametrize("case", ("missing", "leaf", "nonregular", "unknown"))
def test_closed_manifest_directory(signed_repo, tmp_path, case):
    root = tmp_path / "directory"
    directory = root / "releases/manifests"
    directory.parent.mkdir(parents=True)
    if case == "leaf":
        directory.write_bytes(b"blob")
    elif case != "missing":
        directory.mkdir()
        if case == "nonregular":
            (directory / "extra").symlink_to("missing")
        else:
            (directory / "junk.txt").write_bytes(b"extra")
    # record: census release_chain.py 571-607 closed filename grammar/physical shape
    assert_golden("directory/enumerate/" + case,
                  outcome(lambda: chain._enumerate_manifest_files(root, signed_repo.chain)),
                  ((root, "<ROOT>"),))


@pytest.mark.parametrize("case", ("leaf_link", "ancestor_link", "missing", "regular", "platform", "replaced", "short", "long"))
def test_regular_reader_goldens(tmp_path, monkeypatch, case):
    root = tmp_path / "directory"
    target = root / "state/journal"
    target.parent.mkdir(parents=True)
    if case == "ancestor_link":
        target.parent.rmdir()
        target.parent.symlink_to(tmp_path / "outside")
    elif case == "leaf_link":
        target.symlink_to("missing")
    elif case != "missing":
        target.write_bytes(b"hello")
    if case == "platform":
        monkeypatch.setattr(os, "O_NOFOLLOW", 0)
    elif case == "replaced":
        original_open = os.open
        def replace_on_open(path, *args, **kwargs):
            if pathlib.Path(path) == target:
                replacement = root / "replacement"
                replacement.write_bytes(b"other")
                replacement.replace(target)
            return original_open(path, *args, **kwargs)
        monkeypatch.setattr(os, "open", replace_on_open)
    elif case in {"short", "long"}:
        original_read = os.read
        def changed_read(fd, count):
            if case == "short":
                return b""
            value = original_read(fd, count)
            return value or b"x"
        monkeypatch.setattr(os, "read", changed_read)
    # record: census release_chain.py 1553-1635 secure descent, single-read identity and length
    assert_golden("directory/reader/" + case,
                  outcome(lambda: chain._regular_file_bytes(root, pathlib.PurePosixPath("state/journal"))),
                  ((root, "<ROOT>"),))


@pytest.mark.parametrize("case", ("legacy_state", "release_root", "release_ancestor", "anchor_probe", "spelling", "unlistable"))
def test_directory_path_guard_goldens(signed_repo, tmp_path, monkeypatch, case):
    root = tmp_path / "directory"
    shutil.copytree(signed_repo.root, root, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    if case == "legacy_state":
        shutil.rmtree(root / "receipt")
        (root / "receipt").symlink_to("missing")
        call = lambda: chain.assert_no_symlinked_state_component(root, signed_repo.chain.state_relative)
    elif case in {"release_root", "anchor_probe"}:
        shutil.rmtree(root / "releases")
        (root / "releases").symlink_to("missing")
        call = (lambda: chain.assert_no_symlinked_release_root(root, signed_repo.chain)) if case == "release_root" else (
            lambda: chain.verify_release_chain(root, spec=signed_repo.chain))
    elif case == "release_ancestor":
        (root / "releases/nested").symlink_to("missing")
        nested = dataclasses.replace(signed_repo.chain, manifest_relative=pathlib.PurePosixPath("releases/nested/manifests"))
        call = lambda: chain.verify_release_chain(root, spec=nested)
    else:
        original_listdir = os.listdir
        def listing(path):
            if pathlib.Path(path) == root / "releases":
                if case == "unlistable":
                    raise PermissionError(errno.EACCES, "Permission denied")
                return ["Manifests" if name == "manifests" else name for name in original_listdir(path)]
            return original_listdir(path)
        monkeypatch.setattr(os, "listdir", listing)
        call = lambda: chain.verify_release_chain(root, spec=signed_repo.chain)
    assert not (root / ".git").exists()
    # record: census release_chain.py 1311-1325, 1343-1542, 1984-2015 physical spelling/symlinks
    assert_golden("directory/path/" + case, outcome(call), ((root, "<ROOT>"),))


@pytest.mark.parametrize("case", ("manifest", "producer_key", "producer_signature", "receipt", "tsa_anchor", "receipt_unreadable", "receipt_replaced"))
def test_regular_reader_caller_words(signed_repo, tmp_path, monkeypatch, case):
    root = tmp_path / "directory"
    root.mkdir()
    missing = root / "missing"
    receipt = root / "token.tsr"
    receipt.write_bytes(b"dummy token")
    kwargs = dict(spec=signed_repo.chain, anchor_dir=root)
    if case == "manifest":
        call = lambda: chain.load_manifest(missing, spec=signed_repo.chain)
    elif case == "producer_key":
        call = lambda: chain.verify_producer_signature_bytes(b"manifest", bytes(64), label="fixture", enforce_production_pin=True, **kwargs)
    elif case == "producer_signature":
        call = lambda: chain.verify_producer_signature(b"manifest", missing, enforce_production_pin=True, **kwargs)
    elif case in {"receipt_unreadable", "receipt_replaced"}:
        if case == "receipt_unreadable":
            original_open = os.open
            def fail(path, *args, **options):
                if pathlib.Path(path) == receipt:
                    raise PermissionError(errno.EACCES, "Permission denied")
                return original_open(path, *args, **options)
            monkeypatch.setattr(os, "open", fail)
        else:
            monkeypatch.setattr(os, "read", lambda fd, count: b"")
        call = lambda: chain._receipt_bytes(receipt)
    else:
        call = lambda: chain.verify_receipt("0" * 64, missing if case == "receipt" else receipt,
            "alpha", enforce_production_pins=True, **kwargs)
    # record: census release_chain.py 441-445, 870-875, 926-971, 1082-1112 caller overrides
    assert_golden("directory/caller/" + case, outcome(call), ((root, "<ROOT>"),))


@pytest.mark.parametrize("category", ("release", "snapshot"))
def test_base_wrapper_exception_category(signed_repo, monkeypatch, category):
    """Reach the real base-chain call with authenticated matching release trees."""
    with signed_repo.snapshot() as candidate, signed_repo.snapshot() as base:
        def injected(*args, **kwargs):
            error = chain.ReleaseChainError if category == "release" else SnapshotError
            raise error("captured base failure")
        monkeypatch.setattr(append_gate, "verify_base_release_chain", injected)
        current = signed_repo.candidate(candidate)
        prior = append_gate._BaseCommit(base.commit, base.commit, base)
        def call():
            return append_gate.check_release_proposal(prior, candidate=current,
                ledger_bytes=signed_repo.journal,
                prefix_bytes=(signed_repo.root / signed_repo.chain.prefix_relative).read_bytes(),
                anchor_dir=signed_repo.root / signed_repo.chain.anchor_relative,
                enforce_production_pins=True)
        # record: census append_gate.py 1007-1014, ReleaseChainError-only base prefix
        assert_golden("wrapper/base/" + category, outcome(call))
