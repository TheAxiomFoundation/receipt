"""Differential PR2 admission/cost probes; legacy bodies stay frozen."""
from __future__ import annotations

from dataclasses import asdict
from itertools import product
from pathlib import PurePosixPath

import pytest

from receipt import _names, protected_tree as policy, snapshot, append_gate
from receipt.release_chain import _protected_name_error
from m1_fixture import raw_repo, outcome
from m1_append_fixture import append_repo, GATE_SPEC
import protected_tree_legacy as legacy

PREFIXES = (PurePosixPath("protected"), PurePosixPath("protected/nested"), PurePosixPath("protected"))


def plan():
    return policy.ProtectionPlan.chain_names(PREFIXES, repertoire="portable",
        release_directories=(PurePosixPath("protected"),))


def old_names(entries, value):
    return legacy._screen_protected_tree_names(entries, PREFIXES, repertoire=value.repertoire,
        release_directories=(PurePosixPath("protected"),))


@pytest.mark.parametrize("fault", ("clean", "alias", "siblings", "portable", "suffix"))
@pytest.mark.parametrize("ceiling", (20, 41, 42, 43, 100, 100000))
def test_repeated_and_failed_listing_admission_identical(raw_repo, monkeypatch, fault, ceiling):
    extras = {"clean": (), "alias": (("Protected/leaf", "100644"),),
        "siblings": (("protected/A", "100644"), ("protected/a", "100644")),
        "portable": (("protected/bad?", "100644"),),
        "suffix": (("protected/hidden.sigx", "100644"),)}[fault]
    commit = raw_repo.commit((("protected/nested/leaf", "100644"),) + extras)
    monkeypatch.setattr(snapshot, "MAX_PATH_BYTES_TOTAL", ceiling)
    results = []
    original_charge = snapshot.TreeSnapshot._charge_path_bytes
    for new in (False, True):
        calls, charged_paths = [], []
        def charge(subject, raw):
            charged_paths.append(raw)
            return original_charge(subject, raw)
        monkeypatch.setattr(snapshot.TreeSnapshot, "_charge_path_bytes", charge)
        with raw_repo.snapshot(commit) as snap:
            value = plan()
            subject = policy.TreePolicy(snap, policy_version=policy.POLICY_VERSION, work=snap.work) if new else None
            for _ in range(3):
                def call():
                    if new:
                        subject.read_listing("")  # explicit legacy admission, even on reuse
                        view = subject.evaluate(value, stage="suffixes")
                        view.require(value.use, render=_protected_name_error)
                    else:
                        old_names(snap.entries("").as_dict(include_trees=True), value)
                calls.append((outcome(call), asdict(snap.work), tuple(charged_paths)))
        results.append(calls)
    assert results[0] == results[1]


@pytest.mark.parametrize("fault", ("clean", "mode", "name", "siblings"))
@pytest.mark.parametrize("ceiling", (20, 100, 100000))
def test_overlapping_export_inputs_keep_counter_and_refusal_locations(raw_repo, tmp_path, monkeypatch, fault, ceiling):
    extras = {"clean": (), "mode": (("protected/link", "120000"),),
        "name": (("protected/bad?", "100644"),),
        "siblings": (("protected/A", "100644"), ("protected/a", "100644"))}[fault]
    commit = raw_repo.commit((("protected/nested/leaf", "100644"),) + extras)
    monkeypatch.setattr(snapshot, "MAX_PATH_BYTES_TOTAL", ceiling)
    current = snapshot.assert_no_merging_entries
    results = []
    for screen in (_names.assert_no_merging_entries, current):
        monkeypatch.setattr(snapshot, "assert_no_merging_entries", screen)
        with raw_repo.snapshot(commit) as snap:
            def call():
                with snap.materialize(PREFIXES, tmp_path, repertoire="portable") as exported:
                    return sorted(exported.entries)
            results.append((outcome(call), asdict(snap.work)))
    assert results[0] == results[1]


@pytest.mark.parametrize("ceiling", (39, 40, 41, 100000))
def test_d12_matching_checkpoints_unchanged(raw_repo, monkeypatch, ceiling):
    commit = raw_repo.commit((("protected.txt", "100644"),
        (".gitattributes", "100644", b"protected.txt -filter\n")))
    monkeypatch.setattr(snapshot, "MAX_ATTRIBUTE_MATCH_WORK", ceiling)
    results = []
    original_match = snapshot._attribute_matches
    for new in (False, True):
        matches = []
        def match(*args, **kwargs):
            matches.append(1)
            return original_match(*args, **kwargs)
        monkeypatch.setattr(snapshot, "_attribute_matches", match)
        with raw_repo.snapshot(commit) as snap:
            value = plan()
            if new:
                subject = policy.TreePolicy(snap, policy_version=policy.POLICY_VERSION, work=snap.work)
                view = subject.evaluate(value, stage="suffixes")
                view.require(value.use, render=_protected_name_error)
            else:
                old_names(snap.entries("").as_dict(include_trees=True), value)
            initial_paths = snap.work.path_bytes
            calls = []
            for _ in range(2):
                if new:
                    subject.evaluate(value, stage="suffixes", previous=view)
                result = outcome(lambda: snap.refuse_transforming_attributes(("protected.txt",)))
                counters = asdict(snap.work)
                counters["path_bytes"] -= initial_paths
                calls.append((result, counters))
            results.append((calls, len(matches)))
    assert results[0] == results[1]
    calls, matches = results[1]
    assert calls[0][1]["attribute_match_work"] == 28
    assert calls[1][1]["attribute_match_work"] == min(56, ceiling)
    assert calls[0][1]["path_bytes"] == 27
    assert calls[1][1]["path_bytes"] == 40
    assert matches == (4 if ceiling >= 56 else 3)


@pytest.mark.parametrize("fault", ("clean", "alias", "ancestor", "unfoldable"))
def test_append_old_new_public_work(append_repo, fault):
    extras = {"clean": (), "alias": (("Releases/leaf", "100644"),),
        "ancestor": (("verification", "120000"),),
        "unfoldable": ((b"unused/bad\xff", "100644"),)}[fault]
    commit = append_repo.commit(extras)
    results = []
    for screen in (legacy._screen_candidate_tree_aliases, append_gate._screen_candidate_tree_aliases):
        with append_repo.snapshot(commit) as snap:
            candidate = append_gate._CandidateTree(snap, GATE_SPEC,
                GATE_SPEC.chain.state_relative.as_posix(), GATE_SPEC.chain.prefix_relative.as_posix())
            results.append((outcome(lambda: sorted(screen(candidate))), asdict(snap.work)))
    assert results[0] == results[1]


@pytest.mark.parametrize("ceiling", (60, 120, 100000))
def test_candidate_base_shared_path_ledger(raw_repo, monkeypatch, ceiling):
    commit = raw_repo.commit((("protected/nested/leaf", "100644"),))
    monkeypatch.setattr(snapshot, "MAX_PATH_BYTES_TOTAL", ceiling)
    results = []
    for new in (False, True):
        with raw_repo.snapshot(commit) as candidate, raw_repo.snapshot(commit) as base:
            candidate._link_verification_work(base)
            calls = []
            for snap in (candidate, base):
                def call():
                    if new:
                        subject = policy.TreePolicy(snap, policy_version=policy.POLICY_VERSION, work=snap.work)
                        view = subject.evaluate(plan(), stage="suffixes")
                        view.require(plan().use, render=_protected_name_error)
                    else:
                        old_names(snap.entries("").as_dict(include_trees=True), plan())
                calls.append(outcome(call))
            results.append((calls, asdict(candidate.work), asdict(base.work)))
    assert results[0] == results[1]


def test_actual_folds_and_alias_matches_are_bounded(raw_repo, monkeypatch):
    size, repeats = 64, 32
    paths = tuple(f"root/p{i}/leaf" for i in range(size))
    commit = raw_repo.commit(tuple((p, "100644") for p in paths))
    value = policy.ProtectionPlan.chain_names(
        tuple(PurePosixPath(p) for p in paths) * repeats,
        repertoire="portable", release_directories=(),
    )
    actual_folds, actual_matches = [], []
    original_match = policy._AliasNode.match
    def match(self, key):
        actual_matches.append(key)
        return original_match(self, key)
    monkeypatch.setattr(policy._AliasNode, "match", match)
    original_fold = _names.ascii_fold_text
    def fold(value):
        actual_folds.append(value)
        return original_fold(value)
    monkeypatch.setattr(_names, "ascii_fold_text", fold)
    with raw_repo.snapshot(commit) as snap:
        subject = policy.TreePolicy(snap, policy_version=policy.POLICY_VERSION, work=snap.work)
        early = subject.evaluate(value, stage="aliases")
        first_folds = len(actual_folds)
        final = subject.evaluate(value, stage="suffixes", previous=early)
        work = subject.name_work
        repeated = subject.evaluate(value, stage="suffixes", previous=final)
        assert not repeated.findings
        components = {part for path in paths for part in path.split("/")}
        assert len(actual_folds) == work.folds == len(components) == 66
        assert len(set(actual_folds)) == len(actual_folds)
        assert first_folds == len(actual_folds)
        assert len(actual_matches) == work.alias_steps
        assert work.alias_steps <= sum(len(path.split("/")) for path in final.entries)
        assert work.alias_index_nodes == 129
        assert work.fold_index_entries == 66
        assert subject.name_work == work
        assert len(value.selected_prefixes) == size * repeats == 2048
        print("bounded work:", asdict(work), "public:", asdict(snap.work))


@pytest.mark.parametrize("append", (False, True))
def test_indexed_aliases_match_legacy_order_over_many_target_combinations(append):
    # Separate legacy loops are an oracle for target/depth and listed-entry order.
    targets = ("a/b/c", "a/B/c", "A/b/d", "a/B/C", "elsewhere")
    paths = ("a/B/C/leaf", "a/b/c/leaf", "A/b/D/leaf", "a/B/bad\udcff", "unused/bad\udcff")
    for chosen in product(targets, repeat=2):
        prefixes = tuple(PurePosixPath(p) for p in chosen)
        for listed in product(paths, repeat=2):
            entries = {p: snapshot.GitEntry("100644", "blob", "0" * 40, p) for p in listed}
            value = policy.ProtectionPlan.chain_names(prefixes, repertoire="posix-bytes",
                release_directories=(), alias_paths=chosen if append else None)
            def old():
                legacy._screen_protected_tree_names(entries, prefixes, repertoire="posix-bytes",
                    release_directories=(), alias_paths=chosen if append else None)
            def new():
                finding = policy.evaluate_name_mapping(entries, value)
                if finding is not None:
                    raise _protected_name_error(finding)
            assert outcome(old) == outcome(new), (chosen, listed, append)
