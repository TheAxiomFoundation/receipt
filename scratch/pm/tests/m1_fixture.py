"""Raw-object fixtures for the M1 compatibility freeze (record risk 9).

Only the clean cryptographic inputs are generated as files. Even their first
commit is assembled from hash-object/cacheinfo, never git add or checkout.
All adversarial names, modes and empty trees exist exclusively in Git objects.
RECEIPT_M1_IGNORECASE controls every fixture repository, without overriding it
in update-index commands. Tests can therefore be rerun under either setting.
"""
from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import subprocess
import sys
from collections.abc import Callable
from typing import Any
from functools import lru_cache

import pytest

from corpus_fixture import build_corpus, JOURNAL_RELATIVE
from receipt.append_gate import (
    AppendGateSpec, _CandidateTree, _attribute_entries,
    _screen_candidate_tree_aliases,
)
from receipt.corpus import verify_corpus_binding
from receipt.release_chain import (
    _screen_protected_tree_names, verify_base_release_chain,
)
from receipt.snapshot import TreeSnapshot
from receipt.verify import load_spec

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"


def outcome(call: Callable[[], Any]) -> dict[str, Any]:
    """Capture exact exception type/text, or the complete supplied value."""
    try:
        return {"value": call()}
    except Exception as exc:
        return {"exception": f"{type(exc).__module__}.{type(exc).__qualname__}",
                "message": str(exc)}


class RawRepo:
    def __init__(self, root: pathlib.Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.git("init", "-q")
        for key, value in {
            "user.name": "Receipt M1 fixture",
            "user.email": "receipt-m1@example.invalid",
            "commit.gpgSign": "false",
            "core.autocrlf": "false",
            "core.precomposeUnicode": "false",
            "core.ignoreCase": os.environ.get("RECEIPT_M1_IGNORECASE", "false"),
            "core.protectNTFS": "false",
            "core.protectHFS": "false",
        }.items():
            self.git("config", key, value)
        self.base = self.commit()
        self.git("update-ref", "HEAD", self.base)

    def git(self, *args: str | bytes, data: bytes | None = None) -> bytes:
        result = subprocess.run(
            ["git", "-C", os.fspath(self.root), *args], input=data,
            capture_output=True, check=True, timeout=30,
        )
        return result.stdout.rstrip(b"\n")

    def hash(self, payload: bytes, kind: str = "blob") -> str:
        return self.git("hash-object", "--literally", "-w", "-t", kind,
                        "--stdin", data=payload).decode("ascii")

    def add(self, path: str | bytes, mode: str = "100644",
            data: bytes = b"probe\n", *, oid: str | None = None) -> None:
        oid = oid or (self.base if mode == "160000" else self.hash(data))
        self.git("update-index", "--add", "--cacheinfo", mode, oid, path)

    def tree_replace(self, tree: str, path: bytes, mode: str, oid: str) -> str:
        """mktree preserves empty trees and raw names without host path writes."""
        head, _, tail = path.partition(b"/")
        records = {}
        for record in self.git("ls-tree", "-z", tree).split(b"\0"):
            if record:
                metadata, name = record.split(b"\t", 1)
                records[name] = metadata
        if tail:
            old = records.get(head)
            subtree = (old.split()[2].decode() if old else
                       self.git("mktree", data=b"").decode())
            oid = self.tree_replace(subtree, tail, mode, oid)
            mode = "040000"
        kind = "tree" if mode == "040000" else "commit" if mode == "160000" else "blob"
        records[head] = f"{mode} {kind} {oid}".encode()
        return self.git("mktree", "-z", data=b"".join(
            metadata + b"\t" + name + b"\0" for name, metadata in records.items()
        )).decode()

    def commit(self, entries=(), *, remove=(), empty=(), base=None) -> str:
        parent = base if base is not None else getattr(self, "base", None)
        self.git("read-tree", parent or "--empty")
        for path in remove:
            self.git("update-index", "--force-remove", path)
        for entry in entries:
            self.add(*entry)
        tree = self.git("write-tree").decode()
        for path in empty:
            tree = self.tree_replace(tree, os.fsencode(path), "040000",
                                     self.git("mktree", data=b"").decode())
        return self.git("commit-tree", tree, *(("-p", parent) if parent else ()),
                        data=b"M1 raw fixture\n").decode()

    def snapshot(self, commit=None):
        return TreeSnapshot.select(self.root, commit or self.base)


class SignedRepo(RawRepo):
    def __init__(self, root: pathlib.Path, workspace: pathlib.Path):
        build_corpus(root, workspace, commit=False)
        # Capture generated inputs before git init; all are ordinary, portable
        # clean files. Adversarial variants never visit this directory walk.
        inputs = [(p.relative_to(root).as_posix(), "100644", p.read_bytes())
                  for p in sorted(root.rglob("*")) if p.is_file()]
        super().__init__(root)
        self.base = self.commit(inputs)
        self.git("update-ref", "HEAD", self.base)
        self.source = (root / "verification/spec.py").read_text()
        self.loaded = load_spec(root / "verification/spec.py")
        self.chain = self.loaded.verification.chain
        self.corpus = self.loaded.verification.corpus
        self.journal = (root / JOURNAL_RELATIVE).read_bytes()

    @property
    def prefixes(self):
        return tuple(getattr(self.chain, name) for name in (
            "release_root_relative", "manifest_relative", "state_relative",
            "prefix_relative", "anchor_relative",
        ))

    def gate(self, repertoire="portable", *, policy_surface=False):
        return AppendGateSpec(
            chain=dataclasses.replace(self.chain, name_repertoire=repertoire),
            prefix_schema_version="receipt/test-corpus-prefix/v1",
            release_manifest_prefix="releases/manifests/",
            genesis_support_files=frozenset(),
            gate_surface=frozenset({"verification/**"} |
                                   ({"releases/policy/**"} if policy_surface else set())),
            data_surface=frozenset({"rules/**", ".axiom/toolchain.toml"}),
            assertion_content_keys=(),
        )

    def candidate(self, snap, repertoire="portable"):
        return _CandidateTree(snap, self.gate(repertoire),
                              str(self.chain.state_relative), str(self.chain.prefix_relative))

    def cli(self, commit, destination, *, repertoire="portable", yml=False,
            base=None):
        specfile = destination / "probe-spec.py"
        specfile.write_text(self.source + (
            "\nimport dataclasses\n"
            f"SPEC=dataclasses.replace(SPEC, chain=dataclasses.replace(CHAIN, name_repertoire={repertoire!r}), "
            f"corpus=dataclasses.replace(CORPUS, name_repertoire={repertoire!r}"
            + (", content_suffixes=('.yaml', '.yml')" if yml else "") + "))\n"
        ))
        command = [sys.executable, "-m", "receipt.cli", "verify", "--spec",
                   str(specfile), "--root", str(self.root), "--commit", commit, "--json"]
        if base:
            command += ["--base-ref", base, "--expect-commit", commit]
        completed = subprocess.run(command, capture_output=True, timeout=60,
                                   env=dict(os.environ, PYTHONPATH=str(SOURCE)))
        payload = json.loads(completed.stdout)
        # Freeze every phase and its complete failure (success detail contains
        # fresh signing keys/times and is checked by the successful API below).
        return {"exit": completed.returncode, "verdict": payload["verdict"],
                "phases": [[p["name"], p["ok"], p["failure"]] for p in payload["passes"]],
                "stderr": completed.stderr.decode()}

    def matrix(self, commit, destination, *, repertoire="portable", yml=False):
        chain = dataclasses.replace(self.chain, name_repertoire=repertoire)
        corpus = dataclasses.replace(self.corpus, name_repertoire=repertoire,
                                     content_suffixes=(".yaml", ".yml") if yml else self.corpus.content_suffixes)
        def check(operation):
            with self.snapshot(commit) as snap:
                mapping = snap.entries("").as_dict(include_trees=True)
                if operation == "chain_names":
                    return _screen_protected_tree_names(
                        mapping, self.prefixes, repertoire=repertoire,
                        release_directories=(chain.release_root_relative, chain.manifest_relative))
                if operation == "materialize":
                    with snap.materialize(self.prefixes, destination, repertoire=repertoire) as materialized:
                        # Every selected regular byte is checked against its
                        # authenticated blob; the API's accepting outcome is
                        # the exact selected path/mode set, including no trees.
                        for path, entry in materialized.entries.items():
                            assert (materialized.path / path).read_bytes() == snap.blob(entry, limit=1 << 20)
                        return sorted(materialized.entries)
                if operation == "binding":
                    return dataclasses.asdict(verify_corpus_binding(snap, self.journal, spec=corpus))
                if operation == "base_chain":
                    verification = verify_base_release_chain(chain, base=snap)
                    assert len(verification.releases) == 1
                    record = verification.head
                    assert record.raw == (self.root / chain.manifest_relative / record.path.name).read_bytes()
                    # Crypto/signing metadata is generated, but the full
                    # return contract's stable values are frozen explicitly.
                    return {"releases": len(verification.releases),
                            "manifest": record.path.name,
                            "anchor_set_sha256": verification.anchor_set_sha256,
                            "anchor_file_sha256s": verification.anchor_file_sha256s}
                candidate = self.candidate(snap, repertoire)
                listing = _screen_candidate_tree_aliases(candidate)
                return snap.refuse_transforming_attributes(_attribute_entries(candidate, listing))
        return {"cli": self.cli(commit, destination, repertoire=repertoire, yml=yml),
                **{operation: outcome(lambda: check(operation)) for operation in (
                    "chain_names", "materialize", "binding", "base_chain", "append_preflight")}}


@pytest.fixture
def raw_repo(tmp_path):
    return RawRepo(tmp_path / "repo")


@pytest.fixture(scope="module")
def signed_repo(tmp_path_factory):
    work = tmp_path_factory.mktemp("m1-signed")
    return SignedRepo(work / "repo", work / "tsa")


def stable(value, substitutions=()):
    """Replace only fixture identities supplied by each test, never wording.

    JSON also turns tuples into arrays so captured values have one representation.
    Dynamic absolute roots, generated OIDs and signed manifest stems are expanded
    before equality: callers must supply every replacement explicitly.
    """
    if isinstance(value, str):
        for source, token in substitutions:
            value = value.replace(str(source), token)
        return value
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if isinstance(value, dict):
        return {key: stable(item, substitutions) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [stable(item, substitutions) for item in value]
    return value


@lru_cache(maxsize=1)
def _goldens():
    expected = {}
    for source in sorted((pathlib.Path(__file__).parent / "m1_expected").glob("*.json")):
        values = json.loads(source.read_text())
        assert not expected.keys() & values.keys(), f"duplicate golden key in {source}"
        expected.update(values)
    return expected


def assert_golden(key, actual, substitutions=()):
    """Compare the full captured value against committed, locally observed bytes."""
    assert stable(actual, substitutions) == _goldens()[key], key
