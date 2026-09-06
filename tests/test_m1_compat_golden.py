"""Exact census boundary goldens, captured from actual 0.6.1 executions.

The adjacent JSON holds full observed messages/classes/values. Every assertion
names the record row whose compatibility it protects. No golden is regenerated
by these tests. Dynamic identities are the only explicitly substituted values.
"""
from __future__ import annotations

import dataclasses
import hashlib
import pathlib
from types import SimpleNamespace

import pytest

from receipt import _names as names, corpus, snapshot, release_chain, append_gate
from receipt.snapshot import TreeSnapshot
from corpus_fixture import CONTENT, ATTESTED, journal_rows, render_journal, corpus_spec
from m1_fixture import raw_repo, signed_repo, outcome, assert_golden


NAME_CASES = {
    "repertoire": lambda: names.validate_repertoire("Portable"),
    "portable": lambda: names.assert_portable_name("bad?", "fixture"),
    "portable_path": lambda: names.assert_portable_name("good/bad?", "fixture"),
    "portable_accept": lambda: names.assert_portable_name(".axiom/A_2-z.txt", "fixture"),
    "text_bytes": lambda: names.validate_component_text("\ud800", repertoire="posix-bytes"),
    "bytes_type": lambda: names.validate_component_bytes("a"),
    "bytes_empty": lambda: names.validate_component_bytes(b""),
    "bytes_dot": lambda: names.validate_component_bytes(b"."),
    "bytes_dotdot": lambda: names.validate_component_bytes(b".."),
    "bytes_nul": lambda: names.validate_component_bytes(b"a\0b"),
    "bytes_slash": lambda: names.validate_component_bytes(b"a/b"),
    "decode_portable": lambda: names.decode_component(b"bad\xff", repertoire="portable"),
    "decode_export": lambda: names.decode_component(b"bad\xff", repertoire="posix-bytes", materializing=True),
    "decode_lossless": lambda: names.decode_component(b"bad\xff", repertoire="posix-bytes"),
    "text_type": lambda: names.validate_component_text(b"a", repertoire="portable"),
    "text_roundtrip": lambda: names.validate_component_text("\udcc3\udca9", repertoire="posix-bytes"),
    "fold_bytes": lambda: names.ascii_fold_bytes(b"bad\xff"),
    "fold_text": lambda: names.ascii_fold_text("bad\udcff"),
    "fold_type": lambda: names.ascii_fold_text(3),
    "fold_ascii_only": lambda: names.ascii_fold_text("AZ-Äß"),
    "siblings_type": lambda: names.assert_no_merging_entries((3,), repertoire="portable"),
    "siblings_duplicate": lambda: names.assert_no_merging_entries((b"a", b"a"), repertoire="portable"),
    "siblings_fold": lambda: names.assert_no_merging_entries(("A", "a"), repertoire="posix-bytes"),
    "siblings_unicode": lambda: names.assert_no_merging_entries(("é", "é", "Ä", "ä"), repertoire="posix-bytes"),
    "short_extensions": lambda: [names.short_name_extension(v) for v in (
        "hidden.sigx", "hidden.jsonx", "hidden.y mlx", "...archive.tar.gz", "x.a.b+c", ".yml", "dotless")],
    "short_suffixes": lambda: [names.short_name_carries_pinned_suffix(v, (s,)) for v, s in (
        ("hidden.sigx", ".sig"), ("hidden.jsonx", ".json"), ("hidden.yamlx", ".yaml"),
        ("hidden.ymlx", ".yml"), ("archive.tar.gzx", ".tar.gz"))],
}


@pytest.mark.parametrize("case", NAME_CASES)
def test_name_primitive_goldens(case):
    # record: census _names.py 75-83, 113-386 (grammar, context, fold and 8.3)
    assert_golden("names/" + case, outcome(NAME_CASES[case]))


PATH_CASES = {"type": 7, "surrogate": "\ud800", "empty": "", "absolute": "/a",
              "trailing": "a/", "empty_part": "a//b", "dot": "a/./b",
              "dotdot": b"a/../b", "nul": b"a\0b"}


@pytest.mark.parametrize("operation", ("entry", "entries", "attributes", "materialize"))
@pytest.mark.parametrize("case", PATH_CASES)
def test_snapshot_path_argument_goldens(raw_repo, tmp_path, case, operation):
    value = PATH_CASES[case]
    with raw_repo.snapshot() as snap:
        def call():
            if operation == "entry":
                return snap.entry(value)
            if operation == "entries":
                return snap.entries(value).as_dict(include_trees=True)
            if operation == "attributes":
                return snap.refuse_transforming_attributes((value,))
            with snap.materialize((value,), tmp_path, repertoire="portable") as materialized:
                return sorted(materialized.entries)
        # record: census snapshot.py 2514-2542 API paths; 3104-3142 prefix admission
        assert_golden(f"paths/{operation}/{case}", outcome(call))


@pytest.mark.parametrize("case", ("attributes_str", "attributes_bytes", "attributes_entry",
    "attributes_int", "prefix_str", "prefix_bytes", "prefix_path", "prefix_int",
    "prefix_item", "destination", "repertoire", "attributes_count", "prefix_count", "digests_count"))
def test_snapshot_collection_argument_goldens(raw_repo, tmp_path, monkeypatch, case):
    commit = raw_repo.commit((("file", "100644", b"hello"),))
    with raw_repo.snapshot(commit) as snap:
        entry = snap.entry("file")
        def call():
            if case.startswith("attributes_"):
                values = {"str": "file", "bytes": b"file", "entry": entry, "int": 1,
                          "count": ("file", "file")}
                if case.endswith("count"):
                    monkeypatch.setattr(snapshot, "MAX_TREE_ENTRIES", 1)
                return snap.refuse_transforming_attributes(values[case.removeprefix("attributes_")])
            if case == "digests_count":
                monkeypatch.setattr(snapshot, "MAX_TREE_ENTRIES", 1)
                return list(snap.digests((entry, entry)))
            prefixes, destination, repertoire = ("file",), tmp_path, "portable"
            if case.startswith("prefix_"):
                prefixes = {"str": "file", "bytes": b"file", "path": pathlib.PurePosixPath("file"),
                            "int": 1, "item": (1,), "count": ("file", "file")}[case.removeprefix("prefix_")]
                if case.endswith("count"):
                    monkeypatch.setattr(snapshot, "MAX_TREE_ENTRIES", 1)
            if case == "destination":
                destination = 1
            if case == "repertoire":
                repertoire = "Portable"
            return snap.materialize(prefixes, destination, repertoire=repertoire)
        # record: census snapshot.py 3033-3045, 3104-3142, 1735-1740
        assert_golden("arguments/" + case, outcome(call))


@pytest.mark.parametrize("mode", ("100644", "100755", "120000", "160000", "040000", "absent"))
@pytest.mark.parametrize("operation", ("entry", "entries", "attributes", "materialize"))
def test_snapshot_ancestor_renderer_goldens(raw_repo, tmp_path, mode, operation):
    if mode == "040000":
        commit = raw_repo.commit(empty=("parent",))
    elif mode == "absent":
        commit = raw_repo.base
    else:
        commit = raw_repo.commit((("parent", mode),))
    with raw_repo.snapshot(commit) as snap:
        def call():
            if operation == "entry":
                return snap.entry("parent/child")
            if operation == "entries":
                return snap.entries("parent/child").as_dict(include_trees=True)
            if operation == "attributes":
                return snap.refuse_transforming_attributes(("parent/child",))
            with snap.materialize(("parent/child",), tmp_path, repertoire="portable") as selected:
                return sorted(selected.entries)
        # record: census snapshot.py 2619-2687, 2931-2950; D6 three ancestor renderers
        assert_golden(f"ancestor/{mode}/{operation}", outcome(call))


RAW_TREES = {
    "malformed": b"100644", "no_nul": b"100644 name", "mode": b"100600 a\0" + bytes(20),
    "padded_tree_mode": b"040000 a\0" + bytes(20),
    "truncated": b"100644 a\0" + bytes(19), "empty": b"100644 \0" + bytes(20),
    "dot": b"100644 .\0" + bytes(20), "dotdot": b"100644 ..\0" + bytes(20),
    "slash": b"100644 a/b\0" + bytes(20),
    "duplicate": (b"100644 a\0" + bytes(20)) * 2,
    "order": b"100644 z\0" + bytes(20) + b"100644 a\0" + bytes(20),
    "directory_order": b"40000 foo\0" + bytes(20) + b"100644 foo.bar\0" + bytes(20),
}


@pytest.mark.parametrize("case", RAW_TREES)
def test_raw_tree_structural_goldens(raw_repo, case):
    oid = raw_repo.hash(RAW_TREES[case], "tree")
    commit = raw_repo.hash((f"tree {oid}\nauthor M1 <m1@example.invalid> 0 +0000\n"
                           "committer M1 <m1@example.invalid> 0 +0000\n\nfixture\n").encode(), "commit")
    def call():
        with raw_repo.snapshot(commit) as snap:
            return snap.entries("").as_dict(include_trees=True)
    # record: census snapshot.py 797-844, authenticated malformed trees
    assert_golden("raw/" + case, outcome(call), ((oid, "<TREE>"),))


@pytest.mark.parametrize("mode", ("100644", "100755", "120000", "160000", "040000"))
@pytest.mark.parametrize("operation", ("blob", "digests", "materialize"))
def test_payload_mode_goldens(raw_repo, tmp_path, mode, operation):
    commit = (raw_repo.commit(empty=("file",)) if mode == "040000" else
              raw_repo.commit((("file", mode, b"hello"),)))
    with raw_repo.snapshot(commit) as snap:
        entry = snap.entry("file")
        assert entry.mode == mode  # metadata lookup accepts every legal raw mode
        def call():
            if operation == "blob":
                return snap.blob(entry, limit=100)
            if operation == "digests":
                return [(item.path, digest) for item, digest in snap.digests((entry,))]
            with snap.materialize(("file",), tmp_path, repertoire="portable") as selected:
                return sorted(selected.entries)
        # record: census snapshot.py 2690-2703, 1735-1759, 3227-3232; D5 payload readers
        assert_golden(f"payload/{mode}/{operation}", outcome(call), ((entry.object_id, "<OID>"),))


ATTRIBUTE_LINES = {
    "non_ascii": b"\xff filter\n", "quote": b'"file" filter\n', "negative": b"!file filter\n",
    "question": b"file? filter\n", "bracket": b"file[0] filter\n", "backslash": b"file\\name filter\n",
    "trailing": b"directory/ filter\n", "pattern": b"file: filter\n", "empty_segment": b"a//b filter\n",
    "globstar": b"ab**cd filter\n", "control": b"file filter\x01\n",
    "long": b"file " + b"a" * 2043 + b"\n", "no_state": b"file\n",
    "macro": b"[attr]custom filter\n", "non_ascii_state": b"file \xff\n", "state_name": b"file builtin_x\n",
}


@pytest.mark.parametrize("case", ATTRIBUTE_LINES)
def test_attribute_parser_goldens(raw_repo, case):
    commit = raw_repo.commit(((".gitattributes", "100644", b"# heading\n" + ATTRIBUTE_LINES[case]),))
    with raw_repo.snapshot(commit) as snap:
        # record: census snapshot.py 950-1120 unsupported constructs and line numbers
        assert_golden("attribute_parser/" + case, outcome(lambda: snap.refuse_transforming_attributes(("file",))))


def test_attribute_empty_pattern_goldens():
    # record: census snapshot.py 956-988; empty pattern is only reachable by the helper
    assert_golden("attribute_parser/empty_pattern", outcome(lambda: snapshot._attribute_pattern(b"", path=".gitattributes", line=2)))


@pytest.mark.parametrize("attribute", ("filter", "ident", "working-tree-encoding", "text", "eol"))
@pytest.mark.parametrize("state", ("set", "value", "unset", "unspecified"))
def test_attribute_final_state_goldens(raw_repo, attribute, state):
    disposition = {"set": attribute, "value": attribute + "=probe", "unset": "-" + attribute,
                   "unspecified": "!" + attribute}[state]
    commit = raw_repo.commit(((".gitattributes", "100644", ("file " + disposition + "\n").encode()),))
    with raw_repo.snapshot(commit) as snap:
        # record: census snapshot.py 3014-3101 transforming-name scope and harmless states
        assert_golden(f"attribute_state/{attribute}/{state}", outcome(lambda: snap.refuse_transforming_attributes(("file",))))


@pytest.mark.parametrize("mode", ("120000", "160000", "040000"))
def test_attribute_source_mode_goldens(raw_repo, mode):
    commit = (raw_repo.commit(empty=(".gitattributes",)) if mode == "040000" else
              raw_repo.commit(((".gitattributes", mode),)))
    with raw_repo.snapshot(commit) as snap:
        # record: census snapshot.py 2964-2967 exact source mode failures
        assert_golden("attribute_mode/" + mode, outcome(lambda: snap.refuse_transforming_attributes(("absent",))))


def test_attribute_quoting_golden(raw_repo):
    commit = raw_repo.commit(((".gitattributes", "100644", b"* filter=probe\n"), (b"bad\xff", "100644")))
    with raw_repo.snapshot(commit) as snap:
        # record: census snapshot.py 3090-3101 quoting is later than matching
        assert_golden("attribute_quoting", outcome(lambda: snap.refuse_transforming_attributes((b"bad\xff",))))


@pytest.mark.parametrize("case", ("missing", "blob", "executable", "symlink", "gitlink", "empty_tree"))
def test_content_root_goldens(signed_repo, case):
    entries = () if case in {"missing", "empty_tree"} else (("rules", {
        "blob": "100644", "executable": "100755", "symlink": "120000", "gitlink": "160000"}[case]),)
    commit = signed_repo.commit(entries, remove=tuple(CONTENT), empty=("rules",) if case == "empty_tree" else ())
    with signed_repo.snapshot(commit) as snap:
        # record: census corpus.py 1595-1606 content-root existence/modes
        assert_golden("content_root/" + case, outcome(lambda: corpus.verify_corpus_binding(snap, signed_repo.journal, spec=signed_repo.corpus)))


@pytest.mark.parametrize("case", ("full", "prefix", "full_before_prefix"))
@pytest.mark.parametrize("repertoire", ("portable", "posix-bytes"))
def test_declared_alias_goldens(signed_repo, case, repertoire):
    rows = journal_rows()
    paths = {"full": ("rules/A/x.yaml", "rules/a/x.yaml"),
             "prefix": ("rules/A/x.yaml", "rules/a/y.yaml"),
             "full_before_prefix": ("rules/A/x.yaml", "rules/a/y.yaml", "rules/Z/z.yaml", "rules/z/z.yaml")}[case]
    for path in paths:
        rows.append(dict(rows[0], path=path, entryIndex=len(rows)))
    with signed_repo.snapshot() as snap:
        # record: census corpus.py 1430-1475, declared whole-path pass before prefix pass
        assert_golden(f"declared/{repertoire}/{case}", outcome(lambda: corpus.verify_corpus_binding(
            snap, render_journal(rows), spec=dataclasses.replace(signed_repo.corpus, name_repertoire=repertoire))))


@pytest.mark.parametrize("case", ("empty", "long", "absolute", "trailing", "empty_segment", "dot", "portable", "posix_unfoldable"))
def test_declared_path_grammar_goldens(case):
    value = {"empty": "", "long": "a" * 1025, "absolute": "/a", "trailing": "a/",
             "empty_segment": "a//b", "dot": "a/../b", "portable": "a/bad?",
             "posix_unfoldable": "a/bad\udcff"}[case]
    # record: census corpus.py 738-760, 883-934; bounded _quoted renderer 539-561
    assert_golden("declaration_path/" + case, outcome(lambda: corpus._validate_relative_path(
        value, "fixture", repertoire="posix-bytes" if case == "posix_unfoldable" else "portable")))


@pytest.mark.parametrize("case", ("exact", "alias", "absent"))
def test_tombstone_goldens(signed_repo, case):
    rows = journal_rows()
    path = "retired/item.json"
    for state in ("present", "removed"):
        rows.append(dict(rows[3], path=path, state=state, entryIndex=len(rows)))
    commit = signed_repo.commit(() if case == "absent" else ((path if case == "exact" else "retired/ITEM.JSON", "100644"),))
    with signed_repo.snapshot(commit) as snap:
        # record: census corpus.py 1646-1663, exact tombstone before alias spelling
        actual = outcome(lambda: dataclasses.asdict(corpus.verify_corpus_binding(snap, render_journal(rows), spec=signed_repo.corpus)))
        assert_golden("tombstone/" + case, actual)


@pytest.mark.parametrize("case", ("missing", "ancestor_link", "ancestor_blob", "leaf_link", "leaf_gitlink", "leaf_tree"))
def test_attested_shape_goldens(signed_repo, case):
    target = ".axiom/toolchain.toml"
    entries, empty = (), ()
    if case in {"ancestor_link", "ancestor_blob"}:
        entries = ((".axiom", "120000" if case == "ancestor_link" else "100644"),)
    elif case in {"leaf_link", "leaf_gitlink"}:
        entries = ((target, "120000" if case == "leaf_link" else "160000"),)
    elif case == "leaf_tree":
        empty = (target,)
    commit = signed_repo.commit(entries, remove=(target,), empty=empty)
    with signed_repo.snapshot(commit) as snap:
        # record: census corpus.py 1666-1682, lookup SnapshotError masking versus final shape
        assert_golden("attested/" + case, outcome(lambda: corpus.verify_corpus_binding(snap, signed_repo.journal, spec=signed_repo.corpus)))


@pytest.mark.parametrize("relative", ("receipt/corpus-journal.jsonl", "receipt/immutable-prefix.json"))
@pytest.mark.parametrize("mode", ("missing", "100644", "100755", "120000", "160000", "040000"))
def test_state_shape_and_composed_goldens(signed_repo, tmp_path, relative, mode):
    original = (signed_repo.root / relative).read_bytes()
    entries = () if mode in {"missing", "040000"} else ((relative, mode, original),)
    commit = signed_repo.commit(entries, remove=(relative,), empty=(relative,) if mode == "040000" else ())
    with signed_repo.snapshot(commit) as snap:
        def state():
            entry = append_gate._state_entry(signed_repo.candidate(snap), pathlib.PurePosixPath(relative))
            return {"path": entry.path, "mode": entry.mode, "bytes": snap.blob(entry, limit=1 << 20)}
        actual = {"append_state": outcome(state)}
    actual["cli"] = signed_repo.cli(commit, tmp_path)
    # record: census verify.py 675-691; append_gate.py 746-765; both selected state leaves
    assert_golden(f"state/{relative}/{mode}", actual)


@pytest.mark.parametrize("case", ("delete", "mode", "bytes", "symlink", "gitlink", "base_mode", "accept"))
def test_history_goldens(signed_repo, tmp_path, case):
    base = signed_repo.commit((("releases/note", "120000" if case == "base_mode" else "100644", b"base\n"),))
    mode = {"mode": "100755", "symlink": "120000", "gitlink": "160000"}.get(case, "100644")
    data = b"changed\n" if case == "bytes" else b"base\n"
    commit = signed_repo.commit(() if case == "delete" else (("releases/note", mode, data),),
                                remove=("releases/note",), base=base)
    with signed_repo.snapshot(commit) as candidate, signed_repo.snapshot(base) as prior:
        def call():
            resolved, added, entries = release_chain.verify_release_history_immutable(signed_repo.chain, candidate=candidate, base=prior)
            return {"resolved": resolved, "added": sorted(added), "entries": sorted(entries)}
        actual = {"history": outcome(call)}
    actual["cli"] = signed_repo.cli(commit, tmp_path, base=base)
    manifest = next((signed_repo.root / signed_repo.chain.manifest_relative).glob("*.json")).stem
    # record: census release_chain.py 2185-2231; verify.py 638-645, 776-777 history wrapper
    assert_golden("history/" + case, actual, ((base, "<BASE>"), (manifest, "<MANIFEST>")))


@pytest.mark.parametrize("case", ("type", "decode", "surrogate", "astral", "short_source", "suffix_iterable", "suffix_ignored"))
def test_filename_admission_goldens(case):
    class BrokenPath:
        def __fspath__(self):
            raise ValueError("broken path")
    calls = {
        "type": lambda: snapshot.Materialization._exact_filename(123),
        "decode": lambda: snapshot.Materialization._exact_filename(BrokenPath()),
        "surrogate": lambda: snapshot.Materialization._exact_filename("\ud800\udc00.pem"),
        "astral": lambda: snapshot.Materialization._exact_filename("\U00010000.pem"),
        "short_source": lambda: names.short_name_extension(123),
        "suffix_iterable": lambda: names.short_name_carries_pinned_suffix("a.ymlx", 123),
        "suffix_ignored": lambda: names.short_name_carries_pinned_suffix("a.ymlx", (123, ".yml")),
    }
    # record: census snapshot.py 3367-3387; _names.py 122-123, 152-162
    assert_golden("filename/" + case, outcome(calls[case]))


@pytest.mark.parametrize("case", ("escape", "missing", "unavailable", "nonregular", "changed", "json_alias", "accept",
                                  "spec_absent", "spec_relative", "spec_anchors", "spec_filename"))
def test_materialized_anchor_goldens(raw_repo, tmp_path, monkeypatch, case):
    commit = raw_repo.commit((("anchors/producer.pem", "100644", b"producer\n"),
                              ("anchors/root.pem", "100644", b"root\n")))
    spec = SimpleNamespace(anchor_relative=pathlib.PurePosixPath("anchors"),
                           producer_public_key_filename="producer.pem", anchors={"tsa": SimpleNamespace(filename="root.pem")})
    with raw_repo.snapshot(commit) as snap:
        with snap.materialize(("anchors",), tmp_path, repertoire="portable") as materialized:
            target = materialized.path / "anchors/producer.pem"
            if case == "escape":
                spec.producer_public_key_filename = "../escape.pem"
            elif case == "missing":
                spec.producer_public_key_filename = "missing.pem"
            elif case == "unavailable":
                target.unlink()
            elif case == "nonregular":
                target.unlink()
                target.symlink_to("root.pem")
            elif case == "changed":
                spec.anchors["tsa"].filename = "producer.pem"
                original_open = pathlib.Path.open
                opened = 0
                def changed_open(path, *args, **kwargs):
                    nonlocal opened
                    if path == target:
                        opened += 1
                        if opened == 2:
                            with original_open(target, "wb") as handle:
                                handle.write(b"changed\n")
                    return original_open(path, *args, **kwargs)
                monkeypatch.setattr(pathlib.Path, "open", changed_open)
            elif case == "json_alias":
                # Explicit-surrogate admission makes this defense unreachable
                # for ordinary str inputs. Inject colliding serialization keys
                # at its retained seam, without weakening filename admission.
                import receipt.canonical as canonical
                monkeypatch.setattr(canonical, "utf16_sort_key", lambda name: b"same")
            elif case == "spec_absent":
                spec = SimpleNamespace()
            elif case == "spec_relative":
                spec.anchor_relative = "anchors"
            elif case == "spec_anchors":
                spec.anchors = []
            elif case == "spec_filename":
                spec.anchors = {"tsa": SimpleNamespace()}
            # record: census snapshot.py 3394-3456 anchor shape, physical reads and JSON identity
            assert_golden("anchor/" + case, outcome(lambda: materialized.anchor_set_sha256(spec)))


@pytest.mark.parametrize("case", ("path", "entries", "anchor", "closed", "entered", "absent", "file", "link"))
def test_materialization_lifecycle_goldens(raw_repo, tmp_path, case):
    with raw_repo.snapshot() as snap:
        destination = tmp_path
        if case in {"absent", "file", "link"}:
            destination = tmp_path / "destination"
            if case == "file":
                destination.write_bytes(b"file")
            elif case == "link":
                destination.symlink_to(tmp_path, target_is_directory=True)
        pending = snap.materialize((), destination, repertoire="portable")
        def call():
            if case == "path":
                return pending.path
            if case == "entries":
                return pending.entries
            if case == "anchor":
                return pending.anchor_set_sha256(SimpleNamespace())
            if case in {"closed", "entered"}:
                with pending:
                    if case == "entered":
                        return pending.__enter__()
            return pending.__enter__()
        # record: census snapshot.py 3164-3174, 3266-3280 writer lifecycle/destination
        assert_golden("lifecycle/" + case, outcome(call))


@pytest.mark.parametrize("case", ("chain_type", "chain_relative", "chain_repertoire", "corpus_repertoire", "corpus_portable"))
def test_spec_admission_goldens(signed_repo, case):
    def call():
        if case == "chain_type":
            return dataclasses.replace(signed_repo.chain, manifest_relative="releases/manifests")
        if case == "chain_relative":
            return dataclasses.replace(signed_repo.chain, manifest_relative=pathlib.PurePosixPath("../escape"))
        if case == "chain_repertoire":
            return dataclasses.replace(signed_repo.chain, name_repertoire="Portable")
        if case == "corpus_repertoire":
            return dataclasses.replace(signed_repo.corpus, name_repertoire="Portable")
        return dataclasses.replace(signed_repo.corpus, content_roots=(pathlib.PurePosixPath("bad?"),))
    # record: conversion census ChainSpec 177-204, CorpusSpec 385-414, retained constructor admission
    assert_golden("spec/" + case, outcome(call))
