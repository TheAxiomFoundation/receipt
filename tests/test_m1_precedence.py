"""Legacy stage, traversal and within-entry refusal precedence (record risk 1)."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib

import pytest

from receipt import append_gate, corpus, release_chain, snapshot
from receipt.canonical import canonical_bytes
from receipt.sign import sign_payload
from receipt.verify import load_spec, run_verification
from corpus_fixture import JOURNAL_RELATIVE, PREFIX_RELATIVE, LocalTsa
from m1_fixture import signed_repo, raw_repo, outcome, assert_golden
from m1_append_fixture import append_repo, GATE_SPEC


# These literals were copied only AFTER /tmp/m1-pr1-swap-probe.py reproduced
# all four outcomes on this host (the permanent fixture also runs the public API).
@pytest.mark.parametrize("paths,expected", (
    (("Releases/other.txt", "unused/bad\udcff"),
     "index carries an alias of a protected path: Releases/other.txt (for releases at releases)"),
    (("Releases/other.txt", "AAA-bad\udcff"),
     "tree entry name is not valid UTF-8 for folding"),
    (("Releases/other.txt",),
     "index carries an alias of a protected path: Releases/other.txt (for releases at releases)"),
    (("AAA-bad\udcff",), "tree entry name is not valid UTF-8 for folding"),
), ids=("alias-before-unfoldable", "unfoldable-before-alias", "alias-only", "unfoldable-only"))
def test_append_same_stage_two_way_swap(signed_repo, tmp_path, paths, expected):
    commit = signed_repo.commit(tuple((path, "100644") for path in paths))
    with signed_repo.snapshot(commit) as snap:
        listing = snap.entries("").as_dict(include_trees=True)
        ordered = sorted(listing, key=lambda path: (listing[path].mode == "040000", path))
        assert all(path in ordered for path in paths)
        if len(paths) == 2:
            assert (ordered.index(paths[0]) < ordered.index(paths[1])) == paths[1].startswith("unused/")
        with pytest.raises(append_gate.AppendError) as caught:
            append_gate._screen_candidate_tree_aliases(signed_repo.candidate(snap, "posix-bytes"))
        # record: F1, risk 1; census release_chain.py 2272-2295 (fold is an alias sub-step)
        assert type(caught.value) is append_gate.AppendError
        assert str(caught.value) == expected
    with pytest.raises(append_gate.AppendError) as caught:
        append_gate.verify_append_gate(signed_repo.root, spec=signed_repo.gate("posix-bytes"), commit=commit, base_ref=signed_repo.base)
    # record: F1; census append_gate.py 1094-1099, 1273-1274 public wrapper preserves class/text
    assert type(caught.value) is append_gate.AppendError
    assert str(caught.value) == expected
    # Composed custody lacks alias_paths and has its own nested fold schedule.
    assert_golden("precedence/swap_cli/" + paths[-1], signed_repo.cli(commit, tmp_path, repertoire="posix-bytes"))


@pytest.mark.parametrize("case", ("history_names", "state_names", "state_modes", "mode_attributes", "mode_bad_attributes"))
def test_cross_stage_precedence_matrix(signed_repo, tmp_path, monkeypatch, case):
    entries = {
        "history_names": (("Releases/other.txt", "100644"), ("releases/link.txt", "120000")),
        "state_names": ((JOURNAL_RELATIVE, "120000"), ("Releases/other.txt", "100644")),
        "state_modes": ((JOURNAL_RELATIVE, "120000"), ("releases/link.txt", "160000")),
        "mode_attributes": (("releases/link.txt", "120000"), (".gitattributes", "100644", b"releases/** filter=probe\n")),
        "mode_bad_attributes": (("releases/link.txt", "120000"), (".gitattributes", "100644", b"[attr]custom filter=probe\n")),
    }[case]
    commit = signed_repo.commit(entries)
    actual = {"cli": signed_repo.cli(commit, tmp_path, base=signed_repo.base if case == "history_names" else None),
              "append": outcome(lambda: append_gate.verify_append_gate(signed_repo.root, spec=signed_repo.gate(),
                                    commit=commit, base_ref=signed_repo.base))}
    original = snapshot.TreeSnapshot._attribute_rules
    reads = []
    def counted(self, parts):
        reads.append(parts)
        return original(self, parts)
    monkeypatch.setattr(snapshot.TreeSnapshot, "_attribute_rules", counted)
    # Real in-process composition proves no attribute-source I/O happens before
    # its mode/state/name/history barrier. CLI above independently pins phases.
    result = run_verification(signed_repo.root, signed_repo.loaded, commit=commit,
                base_ref=signed_repo.base if case == "history_names" else None,
                expect_commit=commit if case == "history_names" else None)
    assert not result.ok
    assert reads == []
    with signed_repo.snapshot(commit) as snap:
        actual["base_chain"] = outcome(lambda: release_chain.verify_base_release_chain(signed_repo.chain, base=snap))
    # record: D10; census verify.py 638-709, append_gate.py 1094-1117, release_chain.py 2352-2376
    assert_golden("precedence/" + case, actual)


def witnessed_journal(repo, work, journal):
    """Sign and timestamp malformed schema bytes so custody really accepts them."""
    old_path = next((repo.root / repo.chain.manifest_relative).glob("*.json"))
    manifest = json.loads(old_path.read_bytes())
    lines = journal.splitlines(keepends=True)
    prefix = canonical_bytes({"schemaVersion": "receipt/test-corpus-prefix/v1", "prefixLineCount": len(lines),
        "lineSha256s": [hashlib.sha256(line.rstrip(b"\n")).hexdigest() for line in lines],
        "prefixSha256": hashlib.sha256(journal).hexdigest()}) + b"\n"
    manifest["state"].update(jsonlSha256=hashlib.sha256(journal).hexdigest(), lineCount=len(lines),
                              immutablePrefixSha256=hashlib.sha256(prefix).hexdigest())
    payload = canonical_bytes(manifest) + b"\n"
    digest = hashlib.sha256(payload).hexdigest()
    stem = f"0000-{digest[:16]}"
    directory = repo.chain.manifest_relative.as_posix()
    entries = [(JOURNAL_RELATIVE, "100644", journal), (PREFIX_RELATIVE, "100644", prefix),
        (f"{directory}/{stem}.json", "100644", payload),
        (f"{directory}/{stem}.producer.sig", "100644", sign_payload(
            (repo.root.parent / "tsa/producer.key").read_bytes(), payload, domain=b""))]
    for name in repo.chain.anchors:
        tsa_dir = repo.root.parent / "tsa" / name
        tsa = LocalTsa(name, tsa_dir, tsa_dir / f"{name}-root.pem", "", "", "")
        receipt = work / f"{stem}.{name}.tsr"
        tsa.stamp(digest, receipt)
        entries.append((f"{directory}/{receipt.name}", "100644", receipt.read_bytes()))
    remove = tuple(f"{directory}/{p.name}" for p in old_path.parent.iterdir())
    return entries, remove


@pytest.mark.parametrize("fault", ("collision", "unfoldable", "portable"))
def test_malformed_journal_precedes_binding_only_names(signed_repo, tmp_path, fault):
    malformed = b"not-json\n"
    entries, remove = witnessed_journal(signed_repo, tmp_path, malformed)
    bad_names = {"collision": ("unused/Pair.txt", "unused/pair.txt"), "unfoldable": ("unused/bad\udcff",),
                 "portable": ("unused/bad?.txt",)}[fault]
    commit = signed_repo.commit(tuple(entries) + tuple((path, "100644") for path in bad_names), remove=remove)
    actual = {"cli": signed_repo.cli(commit, tmp_path)}
    with signed_repo.snapshot(commit) as snap:
        actual["binding"] = outcome(lambda: corpus.verify_corpus_binding(snap, malformed, spec=signed_repo.corpus))
    assert actual["cli"]["phases"][0] == ["custody", True, None]
    # record: migration step 1, risk 1; census corpus.py 1764-1817 journal prerequisites before names
    assert_golden("precedence/journal/" + fault, actual)


@pytest.mark.parametrize("shape", ("absent", "empty", "blob", "executable", "symlink", "gitlink"))
@pytest.mark.parametrize("with_base", (False, True))
def test_append_manifest_initialization_and_pre_genesis(append_repo, shape, with_base):
    relative = GATE_SPEC.chain.manifest_relative.as_posix()
    entries = () if shape in {"absent", "empty"} else ((relative, {
        "blob": "100644", "executable": "100755", "symlink": "120000", "gitlink": "160000"}[shape]),)
    commit = append_repo.commit(entries, empty=(relative + "/empty",) if shape == "empty" else ())
    # record: census append_gate.py 1056-1068, 948-982; non-tree listing emptiness/manifest leaf exception
    assert_golden(f"precedence/manifest/{with_base}/{shape}", outcome(lambda: append_gate.verify_append_gate(
        append_repo.root, spec=GATE_SPEC, commit=commit, base_ref=append_repo.base if with_base else None)),
        ((append_repo.root, "<ROOT>"), (append_repo.base, "<BASE>")))


@pytest.mark.parametrize("relative", (GATE_SPEC.chain.state_relative, GATE_SPEC.chain.prefix_relative))
@pytest.mark.parametrize("base_mode,candidate_mode", (("100644", "100755"), ("100755", "100755")))
def test_append_state_mode_equality_after_shape(append_repo, relative, base_mode, candidate_mode):
    with append_repo.snapshot() as snap:
        data = snap.blob(snap.entry(relative.as_posix()), limit=1 << 20)
    base = append_repo.commit(((relative.as_posix(), base_mode, data),))
    commit = append_repo.commit(((relative.as_posix(), candidate_mode, data),), base=base)
    # record: census append_gate.py 644-661, 1170-1178; executable is legal, changed mode refuses late
    assert_golden(f"precedence/state_mode/{relative}/{base_mode}", outcome(lambda: append_gate.verify_append_gate(
        append_repo.root, spec=GATE_SPEC, commit=commit, base_ref=base)), ((base, "<BASE>"),))


@pytest.mark.parametrize("mode", ("120000", "160000"))
def test_append_release_leaf_screen_on_push(append_repo, mode):
    commit = append_repo.commit((("releases/link.txt", mode),))
    # record: census append_gate.py 877-891, 1056-1068 release leaf mode before pre-genesis return
    assert_golden("precedence/release_mode/" + mode, outcome(lambda: append_gate.verify_append_gate(
        append_repo.root, spec=GATE_SPEC, commit=commit)))


@pytest.mark.parametrize("fault", ("alias", "attributes"))
def test_base_chain_wrapper_real_faults(signed_repo, fault):
    entries = (("Releases/other.txt", "100644"),) if fault == "alias" else ((".gitattributes", "100644", b"releases/** filter=probe\n"),)
    base_oid = signed_repo.commit(entries)
    candidate_oid = signed_repo.commit(remove=tuple(entry[0] for entry in entries), base=base_oid)
    with signed_repo.snapshot(base_oid) as base, signed_repo.snapshot(candidate_oid) as candidate:
        current = signed_repo.candidate(candidate)
        prior = append_gate._BaseCommit(base_oid, base_oid, base)
        actual = outcome(lambda: append_gate.check_release_proposal(prior, candidate=current,
            ledger_bytes=signed_repo.journal,
            prefix_bytes=(signed_repo.root / signed_repo.chain.prefix_relative).read_bytes(),
            anchor_dir=signed_repo.root / signed_repo.chain.anchor_relative, enforce_production_pins=True))
    # record: census append_gate.py 1007-1014 real ReleaseChainError prefix versus raw SnapshotError
    assert_golden("precedence/base_wrapper/" + fault, actual)


@pytest.mark.parametrize("mode", ("100644", "100755", "040000", "nonempty_tree"))
def test_pre_genesis_manifest_json_child_classification(append_repo, mode):
    path = "releases/manifests/0000-0123456789abcdef.json"
    entries = ((path + "/child", "100644"),) if mode == "nonempty_tree" else (() if mode == "040000" else ((path, mode),))
    commit = append_repo.commit(entries, empty=(path,) if mode == "040000" else ())
    # The record's "tree" wording needs the nonempty qualification: empty
    # trees carry no release leaves and currently return the pre-genesis PASS.
    # record: conversion census append_gate.py 962-967, R2-L1 .json classification before genesis branch
    assert_golden("precedence/json_child/" + mode, outcome(lambda: append_gate.verify_append_gate(
        append_repo.root, spec=GATE_SPEC, commit=commit, base_ref=append_repo.base)))
