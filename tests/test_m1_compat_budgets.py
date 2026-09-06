"""Exact boundary refusals for every budget owner in the M1 census."""
from __future__ import annotations

import pytest

from receipt import corpus, snapshot
from m1_fixture import raw_repo, signed_repo, outcome, assert_golden


@pytest.mark.parametrize("case", ("entries", "name", "path", "paths_total", "path_depth", "tree_depth", "tree_bytes", "selection_bytes"))
def test_reader_budget_goldens(raw_repo, monkeypatch, case):
    commit = raw_repo.commit((("dir/one", "100644", b"hello"), ("dir/two", "100644", b"hello")))
    if case == "selection_bytes":
        monkeypatch.setattr(snapshot, "MAX_TREE_BYTES_TOTAL", 1)
        # record: budget census snapshot.py 2035-2038 selection's reversed word order
        assert_golden("budget/" + case, outcome(lambda: raw_repo.snapshot(commit)))
        return
    with raw_repo.snapshot(commit) as snap:
        constants = {"entries": ("MAX_TREE_ENTRIES", 1), "name": ("MAX_ENTRY_NAME_BYTES", 2),
            "path": ("MAX_PATH_BYTES", 2), "paths_total": ("MAX_PATH_BYTES_TOTAL", 2),
            "path_depth": ("MAX_TREE_DEPTH", 0), "tree_depth": ("MAX_TREE_DEPTH", 0),
            "tree_bytes": ("MAX_TREE_BYTES_TOTAL", snap.work.tree_bytes)}
        constant, value = constants[case]
        monkeypatch.setattr(snapshot, constant, value)
        def call():
            if case in {"path", "path_depth"}:
                return snap.entry("dir/one")
            return snap.entries("").as_dict(include_trees=True)
        # record: budget census snapshot.py 805-824, 2413-2459, 2528-2605
        assert_golden("budget/" + case, outcome(call), ((value, "<LIMIT>"),) if case == "tree_bytes" else ())


@pytest.mark.parametrize("case", ("blob", "attribute_blob", "attribute_bytes", "attribute_rules", "attribute_states", "attribute_work",
                                  "materialized_blob", "materialized_total", "content_blob", "content_total", "content_snapshot"))
def test_payload_and_attribute_budget_goldens(raw_repo, tmp_path, monkeypatch, case):
    commit = raw_repo.commit((("one", "100644", b"hello"), ("two", "100644", b"world"),
        (".gitattributes", "100644", b"one -filter\ntwo -ident\n")))
    with raw_repo.snapshot(commit) as snap:
        entries = (snap.entry("one"), snap.entry("two"))
        attributes_oid = snap.entry(".gitattributes").object_id
        if case.startswith("attribute_"):
            key, limit = {"blob": ("MAX_ATTRIBUTE_BYTES", 1), "bytes": ("MAX_ATTRIBUTE_BYTES_TOTAL", 1),
                "rules": ("MAX_ATTRIBUTE_RULES_TOTAL", 1), "states": ("MAX_ATTRIBUTE_STATES_PER_LINE", 0),
                "work": ("MAX_ATTRIBUTE_MATCH_WORK", 0)}[case.removeprefix("attribute_")]
            monkeypatch.setattr(snapshot, key, limit)
            call = lambda: snap.refuse_transforming_attributes(("one",))
        elif case.startswith("materialized_"):
            monkeypatch.setattr(snapshot, "MAX_MATERIALIZED_BLOB_BYTES" if case.endswith("blob") else "MAX_MATERIALIZED_BYTES", 1 if case.endswith("blob") else 5)
            def call():
                with snap.materialize(("one", "two"), tmp_path, repertoire="portable") as materialized:
                    return sorted(materialized.entries)
        elif case == "blob":
            call = lambda: snap.blob(entries[0], limit=1)
        else:
            if case == "content_snapshot":
                monkeypatch.setattr(snapshot, "MAX_CONTENT_BYTES_TOTAL", 5)
            call = lambda: list(snap.digests(entries, per_blob=1 if case == "content_blob" else 10,
                                            total=5 if case == "content_total" else 20))
        # record: budget census snapshot.py 1422, 1766-1797, 2969-3012, 3259-3309
        assert_golden("budget/" + case, outcome(call),
                      ((attributes_oid, "<ATTRIBUTE_OID>"), (entries[0].object_id, "<BLOB_OID>")))


@pytest.mark.parametrize("case", ("prefixes", "index"))
def test_declaration_budget_goldens(signed_repo, monkeypatch, case):
    monkeypatch.setattr(corpus, "MAX_PATH_COMPONENTS_TOTAL" if case == "prefixes" else "MAX_ALIAS_INDEX_NODES", 1)
    with signed_repo.snapshot() as snap:
        # record: budget census corpus.py 1317-1326, 1468-1473 bounded declared indexes
        assert_golden("budget/declarations/" + case, outcome(lambda: corpus.verify_corpus_binding(
            snap, signed_repo.journal, spec=signed_repo.corpus)))
