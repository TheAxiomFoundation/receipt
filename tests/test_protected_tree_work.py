"""Differential PR2 admission/cost probes; legacy bodies stay frozen."""
from __future__ import annotations

from dataclasses import asdict, replace
from contextlib import contextmanager
from itertools import product
from pathlib import PurePosixPath

import pytest

from receipt import _names, protected_tree as policy, snapshot, append_gate, release_chain, verify
from receipt.release_chain import _protected_name_error
from m1_fixture import raw_repo, signed_repo, outcome
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
    # PR3b round 1 (low): this comparison used to switch snapshot.assert_no_merging_entries,
    # a hook the exporter stopped reaching once selection moved into the policy, so both
    # legs ran the new path. The legs now switch the selector itself, and each leg proves
    # that its intended body ran.
    # The new leg is proven at prefix admission, which every export reaches, including
    # the ones the path-byte ceiling refuses before a selection is certified.
    admitted = []
    original_prefixes = policy.export_prefixes
    def export_prefixes(*args, **kwargs):
        admitted.append(1)
        return original_prefixes(*args, **kwargs)
    monkeypatch.setattr(policy, "export_prefixes", export_prefixes)
    results = []
    for old in (True, False):
        admitted.clear()
        with trace_exports(monkeypatch, old=old):
            legacy_leg = (snapshot.Materialization._selected_entries.__code__
                          is legacy._selected_entries.__code__)
            assert legacy_leg == old
            with raw_repo.snapshot(commit) as snap:
                def call():
                    with snap.materialize(PREFIXES, tmp_path, repertoire="portable") as exported:
                        return sorted(exported.entries)
                results.append((outcome(call), asdict(snap.work)))
        assert bool(admitted) == (not old)
    assert results[0] == results[1]


@pytest.mark.parametrize("ceiling", (39, 40, 41, 100000))
def test_d12_matching_checkpoints_unchanged(raw_repo, monkeypatch, ceiling):
    # PR4 now switches the real attribute method, including independently frozen
    # parsing and matching, and proves that each leg reached its intended body.
    commit = raw_repo.commit((("protected.txt", "100644"),
        (".gitattributes", "100644", b"protected.txt -filter\n")))
    monkeypatch.setattr(snapshot, "MAX_ATTRIBUTE_MATCH_WORK", ceiling)
    calls, costs = attribute_comparison(raw_repo, commit, monkeypatch, (("protected.txt",),) * 2)
    assert [c[1]["attribute_match_work"] for c in calls] == [28, min(56, ceiling)]
    assert [c[1]["path_bytes"] for c in calls] == [27, 40]
    assert all(c[1]["attribute_bytes"] == 22 and c[1]["attribute_rules"] == 1 for c in calls)
    assert costs[0][0]["matches"] == (4 if ceiling >= 56 else 3)
    assert costs[1][0]["matches"] == (2 if ceiling >= 56 else 3)
    assert costs[1][1].rule_evaluations == 2
    assert costs[1][1].exhaustion_replays == int(ceiling < 56)


@pytest.mark.parametrize("fault", ("clean", "alias", "ancestor", "unfoldable"))
def test_append_old_new_public_work(append_repo, fault):
    extras = {"clean": (), "alias": (("Releases/leaf", "100644"),),
        "ancestor": (("scripts", "120000"),),
        "unfoldable": ((b"unused/bad\xff", "100644"),)}[fault]
    commit = append_repo.commit(extras)
    results = []
    for screen in (legacy._screen_candidate_tree_aliases, append_gate._screen_candidate_tree_aliases):
        with append_repo.snapshot(commit) as snap:
            candidate = append_gate._CandidateTree(snap, GATE_SPEC,
                GATE_SPEC.chain.state_relative.as_posix(), GATE_SPEC.chain.prefix_relative.as_posix())
            results.append((outcome(lambda: sorted(screen(candidate))), asdict(snap.work)))
    assert results[0] == results[1]
    if fault == "ancestor":
        # scripts/ is a proper ancestor of the state path scripts/check_append.py, so the
        # symlink reaches the ancestor-shape barrier on both paths (round 1, low: the
        # earlier fixture path was not an ancestor of any protected path)
        assert results[1][0] == {"exception": "receipt.snapshot.SnapshotError",
                                 "message": "state path has a symlinked component: scripts"}


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


@contextmanager
def trace_reads(monkeypatch, *, old=False):
    """Record admission attempts before the increment, including failed ones."""
    with monkeypatch.context() as patch:
        if old:
            for name in ("entry", "entries", "_raw_entry_at"):
                patch.setattr(snapshot.TreeSnapshot, name, getattr(legacy, name))
        events, subjects = [], []
        def wrap(name, witness):
            original = getattr(snapshot.TreeSnapshot, name)
            def call(subject, *args, **kwargs):
                if all(subject is not previous for previous in subjects):
                    subjects.append(subject)
                events.append((name, witness(*args, **kwargs), asdict(subject.work)))
                return original(subject, *args, **kwargs)
            patch.setattr(snapshot.TreeSnapshot, name, call)
        wrap("_charge_path_bytes", lambda raw: raw)
        wrap("_charge_walk_records", lambda records, count: (len(records), count[0]))
        wrap("entries", lambda prefix="": prefix)
        wrap("entry", lambda path: path)
        wrap("blob", lambda entry, **kw: entry.path)
        wrap("_attribute_rules", lambda parts: parts)
        original_consume = snapshot._BatchReader.consume
        def consume(batch, oid, **kwargs):
            if kwargs.get("role") == "blob":
                owner = next((s for s in subjects if s._state.batch is batch), None)
                events.append(("payload", oid, asdict(owner.work) if owner else None))
            return original_consume(batch, oid, **kwargs)
        patch.setattr(snapshot._BatchReader, "consume", consume)
        yield events, subjects


def public_result(result):
    # Temporary materialization directories are absent from successful phase
    # details. Compare all phases, including full failure and success wording.
    return [(p.name, p.ok, p.detail, p.failure) for p in result.passes]


@pytest.mark.parametrize("fault", ("clean", "alias", "state-link", "ancestor-link", "ancestor-blob",
                                    "missing", "mode", "attributes", "history"))
@pytest.mark.parametrize("ceiling", (80, 10000000))
def test_composed_old_new_work_and_read_barriers(signed_repo, monkeypatch, fault, ceiling):
    journal = str(signed_repo.chain.state_relative)
    prefix = str(signed_repo.chain.prefix_relative)
    parent = journal.rpartition("/")[0]
    extras = {"clean": (), "alias": (("Releases/other", "100644"),),
              "state-link": ((journal, "120000"),), "ancestor-link": ((parent, "120000"),),
              "ancestor-blob": ((parent, "100644"),), "missing": (),
              "mode": (("releases/link", "120000"),),
              "attributes": ((".gitattributes", "100644", b"* filter=probe\n"),),
              "history": (("releases/link", "120000"), ("Releases/other", "100644"))}[fault]
    remove = (journal, prefix) if fault.startswith("ancestor-") else (journal,) if fault == "missing" else ()
    commit = signed_repo.commit(extras, remove=remove)
    monkeypatch.setattr(snapshot, "MAX_PATH_BYTES_TOTAL", ceiling)
    results = []
    for old in (True, False):
        with trace_reads(monkeypatch, old=old) as (events, subjects):
            function = legacy.run_verification if old else verify.run_verification
            result = function(signed_repo.root, signed_repo.loaded, commit=commit,
                              base_ref=signed_repo.base if fault == "history" else None,
                              expect_commit=commit if fault == "history" else None)
            results.append((public_result(result), events, [asdict(s.work) for s in subjects]))
    assert results[0] == results[1]
    events = results[1][1]
    if fault in {"alias", "state-link", "ancestor-link", "ancestor-blob", "missing", "history"}:
        assert not [event for event in events if event[0] in {"blob", "payload", "_attribute_rules"}]
    if fault == "history":
        assert not [event for event in events if event[:2] == ("entries", "")]
    if fault == "mode":
        assert not [event for event in events if event[0] == "_attribute_rules"]
    if ceiling == 10000000:
        print("composed", fault, "events", len(events), "work", results[1][2])


@pytest.mark.parametrize("fault", ("clean", "mode", "ancestor", "missing", "empty", "release-root-blob"))
@pytest.mark.parametrize("caller_anchors", (False, True))
@pytest.mark.parametrize("ceiling", (80, 10000000))
def test_base_chain_old_new_work(signed_repo, monkeypatch, fault, caller_anchors, ceiling):
    state = str(signed_repo.chain.state_relative)
    prefix = str(signed_repo.chain.prefix_relative)
    parent = state.rpartition("/")[0]
    extras = {"clean": (), "mode": ((state, "120000"),), "ancestor": ((parent, "120000"),),
              "missing": (), "empty": (), "release-root-blob": (("releases", "100644"),)}[fault]
    remove = (state, prefix) if fault == "ancestor" else (state,) if fault in {"missing", "empty"} else ()
    if fault == "release-root-blob":
        # The outer regular prefix subsumes manifest/anchor requests. Preserve
        # the facade's acceptance until the directory reader owns its refusal.
        with signed_repo.snapshot() as original:
            remove = tuple(original.entries("releases").as_dict())
    commit = signed_repo.commit(extras, remove=remove, empty=(state,) if fault == "empty" else ())
    monkeypatch.setattr(snapshot, "MAX_PATH_BYTES_TOTAL", ceiling)
    results = []
    for old in (True, False):
        with trace_reads(monkeypatch, old=old) as (events, subjects), signed_repo.snapshot(commit) as snap:
            # Stop at the directory/crypto boundary: its unchanged guards are
            # covered by PR1, and its absolute temporary paths are not stable.
            with monkeypatch.context() as patch:
                owner = legacy if old else release_chain
                patch.setattr(owner, "verify_release_chain", lambda *a, **kw: "directory boundary")
                anchor = signed_repo.root / signed_repo.chain.anchor_relative if caller_anchors else None
                result = outcome(lambda: owner.verify_base_release_chain(signed_repo.chain, base=snap, anchor_dir=anchor))
            results.append((result, events, asdict(snap.work)))
    assert results[0] == results[1]
    if fault in {"mode", "ancestor"}:
        assert not [e for e in results[1][1] if e[0] in {"blob", "payload", "_attribute_rules"}]


@pytest.mark.parametrize("fault", ("clean", "candidate-link", "base-link", "delete", "change-mode", "change-bytes"))
@pytest.mark.parametrize("ceiling", (20, 100000))
def test_history_old_new_work_without_full_listing(raw_repo, monkeypatch, fault, ceiling):
    base = raw_repo.commit((("releases/a", "120000" if fault == "base-link" else "100644"),))
    mode = "120000" if fault == "candidate-link" else "100755" if fault == "change-mode" else "100644"
    candidate = raw_repo.commit(() if fault == "delete" else (("releases/a", mode,
                               b"different" if fault == "change-bytes" else b"probe\n"),))
    monkeypatch.setattr(snapshot, "MAX_PATH_BYTES_TOTAL", ceiling)
    results = []
    for old in (True, False):
        with trace_reads(monkeypatch, old=old) as (events, subjects):
            with raw_repo.snapshot(base) as prior, raw_repo.snapshot(candidate) as current:
                current._link_verification_work(prior)
                function = legacy.verify_release_history_immutable if old else release_chain.verify_release_history_immutable
                result = outcome(lambda: function(GATE_SPEC.chain, candidate=current, base=prior))
                results.append((result, events, asdict(current.work), asdict(prior.work)))
    assert results[0] == results[1]
    assert not [e for e in results[1][1] if e[0] in {"blob", "payload", "_attribute_rules"} or e[:2] == ("entries", "")]


@pytest.mark.parametrize("fault", ("clean", "ancestor-link", "ancestor-blob", "mode", "missing"))
@pytest.mark.parametrize("ceiling", (20, 70, 100000))
def test_overlapping_resumed_shapes_preserve_admission(raw_repo, tmp_path, monkeypatch, fault, ceiling):
    extras = {"clean": (("protected/nested/leaf", "100644"),),
              "ancestor-link": (("protected", "120000"),),
              "ancestor-blob": (("protected", "100644"),),
              "mode": (("protected/nested/leaf", "120000"),), "missing": ()}[fault]
    commit = raw_repo.commit(extras)
    monkeypatch.setattr(snapshot, "MAX_PATH_BYTES_TOTAL", ceiling)
    results = []
    for old in (True, False):
        with trace_reads(monkeypatch, old=old) as (events, subjects), raw_repo.snapshot(commit) as snap:
            evaluator = policy.TreePolicy(snap, policy_version=policy.POLICY_VERSION, work=snap.work)
            calls = []
            def call():
                entries = snap.entries("").as_dict(include_trees=True)
                old_names(entries, plan())
                if not old:
                    evaluator.observe_entries(entries.values())
                    # The explicit full listing above owns this legacy charge.
                    evaluator._scopes[""] = snap.tree
                    value = replace(plan(), obligations=("ancestors", "modes"),
                                    ancestor_paths=("protected/nested/leaf",) * 3,
                                    mode_roles=(("protected/nested/leaf", "state-leaf"),))
                    first = evaluator.evaluate(value, stage="ancestors")
                    final = evaluator.evaluate(value, stage="modes", previous=first)
                    cost = evaluator.shape_work
                    evaluator.evaluate(value, stage="modes", previous=final)
                    assert evaluator.shape_work == cost
                with snap.materialize(PREFIXES, tmp_path, repertoire="portable") as materialized:
                    return sorted(materialized.entries)
            for _ in range(3):
                calls.append((outcome(call), asdict(snap.work), tuple(events)))
            results.append(calls)
    assert results[0] == results[1]
    if ceiling == 100000:
        if fault in {"clean", "missing", "ancestor-blob"}:
            expected = {"clean": ["protected/nested/leaf"], "missing": [], "ancestor-blob": ["protected"]}[fault]
            assert all(call[0] == {"value": expected}
                       for call in results[1])
        else:
            assert all(call[0]["exception"] == "receipt.snapshot.SnapshotError" for call in results[1])
        print("resumed", fault, "paths", [c[1]["path_bytes"] for c in results[1]],
              "walks", [sum(e[0] == "_charge_walk_records" for e in c[2]) for c in results[1]])


def test_pr3a_legacy_bodies_match_recorded_sha256():
    import ast
    import hashlib
    import inspect
    import textwrap
    source = inspect.getsource(legacy)
    nodes = {node.name: node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.FunctionDef)}
    lines = source.splitlines(keepends=True)
    for name, expected in legacy.PR3A_BODY_SHA256.items():
        node = nodes[name]
        body = textwrap.dedent("".join(lines[node.lineno - 1:node.end_lineno]))
        assert hashlib.sha256(body.encode()).hexdigest() == expected, name


@pytest.mark.parametrize("mode", ("100644", "100755", "120000", "160000"))
@pytest.mark.parametrize("supplied", (False, True))
def test_append_equality_old_new_work(append_repo, monkeypatch, mode, supplied):
    from types import SimpleNamespace
    path = GATE_SPEC.chain.state_relative.as_posix()
    commit = append_repo.commit(((path, mode),))
    results = []
    for old in (True, False):
        with trace_reads(monkeypatch, old=old) as (events, subjects):
            with append_repo.snapshot() as base, append_repo.snapshot(commit) as snap:
                candidate = append_gate._CandidateTree(
                    snap, GATE_SPEC, path, GATE_SPEC.chain.prefix_relative.as_posix())
                entries = snap.entries("").as_dict() if supplied else None
                function = legacy.check_state_modes if old else append_gate.check_state_modes
                result = outcome(lambda: function(SimpleNamespace(tree=base), candidate, entries=entries))
                results.append((result, events, asdict(base.work), asdict(snap.work)))
    assert results[0] == results[1]


def test_actual_mode_and_ancestor_work_is_bounded_and_reused(raw_repo, monkeypatch):
    paths = tuple(f"root/p{i}/leaf" for i in range(64))
    commit = raw_repo.commit(tuple((p, "100644") for p in paths))
    with raw_repo.snapshot(commit) as snap:
        evaluator = policy.TreePolicy(snap, policy_version=policy.POLICY_VERSION, work=snap.work)
        evaluator.read_listing("")
        before = asdict(snap.work)
        original = policy.classify_mode
        calls = []
        def classify(*args, **kwargs):
            calls.append((args, kwargs))
            return original(*args, **kwargs)
        monkeypatch.setattr(policy, "classify_mode", classify)
        def forbidden(*args, **kwargs):
            pytest.fail("shape reuse performed listing or payload I/O")
        monkeypatch.setattr(snapshot.TreeSnapshot, "entries", forbidden)
        monkeypatch.setattr(snapshot.TreeSnapshot, "blob", forbidden)
        monkeypatch.setattr(snapshot.TreeSnapshot, "_attribute_rules", forbidden)
        value = policy.ProtectionPlan(obligations=("ancestors", "modes"),
            ancestor_paths=paths * 32, mode_roles=tuple((p, "release-leaf") for p in paths) * 32)
        early = evaluator.evaluate(value, stage="ancestors")
        final = evaluator.evaluate(value, stage="modes", previous=early)
        work = evaluator.shape_work
        selected = final.require(value.use, render=_protected_name_error)
        assert set(selected.entries_for(snap, use=value.use, plan=value)) == set(final.entries)
        evaluator.evaluate(value, stage="modes", previous=final)
        assert evaluator.shape_work == work
        assert len(calls) == work.mode_classifications == work.mode_cache_entries == 129
        assert work.ancestor_steps == 128
        assert work.ancestor_cache_entries == 64
        assert asdict(snap.work) == before
        print("bounded shape work", asdict(work), "public", before)


@contextmanager
def trace_exports(monkeypatch, *, old):
    from types import FunctionType
    with monkeypatch.context() as patch:
        if old:
            namespace = dict(legacy.__dict__, MAX_TREE_ENTRIES=snapshot.MAX_TREE_ENTRIES,
                             _CONTENT_MODES=snapshot._CONTENT_MODES)
            patch.setattr(snapshot.Materialization, "_selected_entries",
                          FunctionType(legacy._selected_entries.__code__, namespace))
            patch.setattr(snapshot.Materialization, "_deduplicated_prefixes",
                          legacy._deduplicated_prefixes)
        with trace_reads(patch) as (events, subjects):
            original = snapshot.TreeListing._walk_from
            def walk(listing, node, prefix, **kwargs):
                events.append(("listing-walk", prefix, len(node.records)))
                yield from original(listing, node, prefix, **kwargs)
            patch.setattr(snapshot.TreeListing, "_walk_from", walk)
            original_charge = snapshot.TreeSnapshot._charge_verification
            def charge(subject, counter, amount, **kwargs):
                if counter == "materialized_bytes":
                    events.append(("write-charge", amount, asdict(subject.work)))
                return original_charge(subject, counter, amount, **kwargs)
            patch.setattr(snapshot.TreeSnapshot, "_charge_verification", charge)
            yield events


def export_comparison(repo, commit, scratch, monkeypatch, prefixes, *, repeats=1, shared=False):
    results = []
    for old in (True, False):
        with trace_exports(monkeypatch, old=old) as events:
            with repo.snapshot(commit) as first, repo.snapshot(commit) as second:
                if shared:
                    first._link_verification_work(second)
                calls = []
                for snap in ((first, second) if shared else (first,) * repeats):
                    def call():
                        with snap.materialize(prefixes, scratch, repertoire="portable") as materialized:
                            return [(p, e.mode, (materialized.path / p).read_bytes())
                                    for p, e in sorted(materialized.entries.items())]
                    calls.append((outcome(call), asdict(snap.work), tuple(events)))
                    assert list(scratch.iterdir()) == []
                results.append(calls)
    assert results[0] == results[1]
    return results[1]


@pytest.mark.parametrize("budget", ("MAX_PATH_BYTES_TOTAL", "MAX_MATERIALIZED_BYTES"))
@pytest.mark.parametrize("delta", (-1, 0, 1))
@pytest.mark.parametrize("shared", (False, True))
def test_export_exact_budget_boundaries(raw_repo, tmp_path, monkeypatch, budget, delta, shared):
    commit = raw_repo.commit((("p/n/a", "100644", b"abc"), ("p/n/b", "100755", b"defgh")))
    scratch = tmp_path / "exports"
    scratch.mkdir()
    prefixes = ("p", "p/n", "p/n/a", "p")
    # 10 supplied prefix bytes + 10 emitted leaf path bytes; 8 written bytes.
    threshold = (20 if budget == "MAX_PATH_BYTES_TOTAL" else 8) * (2 if shared else 1)
    monkeypatch.setattr(snapshot, budget, threshold + delta)
    calls = export_comparison(raw_repo, commit, scratch, monkeypatch, prefixes, shared=shared)
    assert ("value" in calls[-1][0]) == (delta >= 0)
    print("export boundary", budget, threshold + delta, "shared", shared,
          "result", calls[-1][0], "work", calls[-1][1])


@pytest.mark.parametrize("fault", ("clean", "empty", "alias", "mode", "name-mode", "name", "ancestor"))
@pytest.mark.parametrize("prefixes", (("p", "p/n", "p", "p/n/a"), ("", "p/n", ""),
                                      (b"p/n/a", b"p/n/a", b"missing")))
def test_export_overlapping_and_repeated_admission(raw_repo, tmp_path, monkeypatch, fault, prefixes):
    entries = [("p/n/a", "100755", b"abc")]
    empty = ()
    if fault == "empty":
        empty = ("p/n/A", "p/empty")
    if fault == "alias":
        entries.append(("P/unselected", "120000", b"target"))
    if fault in {"mode", "name-mode"}:
        entries.append(("p/z-link", "120000", b"target"))
    if fault in {"name", "name-mode"}:
        entries.append(("p/bad?", "100644", b"name"))
    if fault == "ancestor":
        entries = [("p/n", "120000", b"target")]
    commit = raw_repo.commit(entries, empty=empty)
    scratch = tmp_path / "exports"
    scratch.mkdir()
    export_comparison(raw_repo, commit, scratch, monkeypatch, prefixes, repeats=3)


@pytest.mark.parametrize("ceiling", (2, 3, 4))
def test_export_tree_walk_boundary(raw_repo, tmp_path, monkeypatch, ceiling):
    commit = raw_repo.commit((("p/a", "100644"), ("p/b", "100644")))
    scratch = tmp_path / "exports"
    scratch.mkdir()
    monkeypatch.setattr(snapshot, "MAX_TREE_ENTRIES", ceiling)
    export_comparison(raw_repo, commit, scratch, monkeypatch, ("p",))


def test_export_actual_work_is_bounded_and_reused(raw_repo, monkeypatch):
    paths = tuple(f"root/p{i}/leaf" for i in range(64))
    commit = raw_repo.commit(tuple((p, "100755") for p in paths), empty=("root/empty",))
    prefixes = tuple(p.rpartition("/")[0] for p in paths) * 32 + ("root",)
    value = policy.ProtectionPlan.materialization(prefixes, repertoire="portable")
    with raw_repo.snapshot(commit) as snap:
        evaluator = policy.TreePolicy(snap, policy_version=policy.POLICY_VERSION, work=snap.work)
        early = evaluator.evaluate(value, stage="modes")
        with pytest.raises(policy.PolicyUseError, match="unevaluated"):
            evaluator.select_export(early, render=snapshot.Materialization._export_error)
        final = evaluator.evaluate(value, stage="export-names", previous=early)
        costs = evaluator.export_work, evaluator.name_work, evaluator.shape_work, asdict(snap.work)
        for _ in range(3):
            again = evaluator.evaluate(value, stage="export-names", previous=final)
            selected = evaluator.select_export(again, render=snapshot.Materialization._export_error)
            assert set(selected.entries_for(snap, use=value.use, plan=value)) == set(paths)
        assert (evaluator.export_work, evaluator.name_work, evaluator.shape_work, asdict(snap.work)) == costs
        assert asdict(evaluator.export_work) == dict(prefixes=1, leaves=64, components=192, directory_records=130)
        assert evaluator.name_work.sibling_steps == 129
        assert evaluator.name_work.folds == 66
        assert evaluator.shape_work.mode_classifications == 130
        assert len(final.raw_listings) == 67
        assert len(prefixes) == 2049
        print("bounded exports", asdict(evaluator.export_work), asdict(evaluator.name_work),
              asdict(evaluator.shape_work), "public", asdict(snap.work))


def test_pr3b_legacy_bodies_match_recorded_sha256():
    import hashlib
    import inspect
    import textwrap
    for name, expected in legacy.PR3B_BODY_SHA256.items():
        body = textwrap.dedent(inspect.getsource(getattr(legacy, name)))
        assert hashlib.sha256(body.encode()).hexdigest() == expected


@contextmanager
def trace_attributes(monkeypatch, *, old):
    """Reach independent old bodies or the real forwarding/evaluation seams."""
    from types import FunctionType
    with monkeypatch.context() as patch:
        counts = dict(legacy=0, facade=0, policy=0, matches=0, parses=0)
        if old:
            for name in legacy.PR4_BODY_SHA256:
                target = snapshot.TreeSnapshot if name in {
                    "_attribute_rules", "_attribute_step", "refuse_transforming_attributes"
                } else snapshot
                patch.setattr(target, name, FunctionType(getattr(legacy, name).__code__, snapshot.__dict__))
        original_call = snapshot.TreeSnapshot.refuse_transforming_attributes
        def call(subject, paths):
            counts["legacy" if old else "facade"] += 1
            return original_call(subject, paths)
        patch.setattr(snapshot.TreeSnapshot, "refuse_transforming_attributes", call)
        original_policy = policy.refuse_attributes
        def forward(*args, **kwargs):
            counts["policy"] += 1
            return original_policy(*args, **kwargs)
        patch.setattr(policy, "refuse_attributes", forward)
        original_match = snapshot._attribute_matches
        current_rule = []
        def match(rule, relative, step):
            counts["matches"] += 1
            current_rule[:] = [rule.pattern, relative]
            return original_match(rule, relative, step)
        patch.setattr(snapshot, "_attribute_matches", match)
        original_parse = snapshot._parse_attribute_file
        def parse(*args, **kwargs):
            counts["parses"] += 1
            return original_parse(*args, **kwargs)
        patch.setattr(snapshot, "_parse_attribute_file", parse)
        failed_steps = []
        original_charge = snapshot.TreeSnapshot._charge_verification
        def charge(subject, field, amount, **kwargs):
            try:
                return original_charge(subject, field, amount, **kwargs)
            except snapshot.SnapshotError:
                if field == "attribute_match_work":
                    failed_steps.append((tuple(current_rule), amount, asdict(subject.work)))
                raise
        patch.setattr(snapshot.TreeSnapshot, "_charge_verification", charge)
        with trace_reads(patch) as (events, _):
            yield counts, events, failed_steps
        assert counts["legacy"] > 0 if old else counts["facade"] > 0
        assert counts["policy"] == (0 if old else counts["facade"])


def attribute_comparison(repo, commit, monkeypatch, requests, *, shared=False, ceilings=None):
    results, costs = [], []
    for old in (True, False):
        with trace_attributes(monkeypatch, old=old) as (counts, events, failures):
            with repo.snapshot(commit) as first, repo.snapshot(commit) as second:
                if shared:
                    first._link_verification_work(second)
                calls = []
                for index, paths in enumerate(requests):
                    if ceilings is not None:
                        monkeypatch.setattr(snapshot, "MAX_ATTRIBUTE_MATCH_WORK", ceilings[index])
                    subject = second if shared and index % 2 else first
                    result = outcome(lambda: subject.refuse_transforming_attributes(paths))
                    calls.append((result, asdict(first.work), asdict(second.work), tuple(events), tuple(failures)))
                results.append(calls)
                costs.append((dict(counts), None if old else policy._attribute_store(first).work))
    assert results[0] == results[1]
    return results[1], costs


@pytest.mark.parametrize("budget,threshold,attributes,paths", (
    ("MAX_ATTRIBUTE_BYTES", 22, b"protected.txt -filter\n", ("protected.txt",)),
    ("MAX_ATTRIBUTE_BYTES_TOTAL", 22, b"protected.txt -filter\n", ("protected.txt",)),
    ("MAX_ATTRIBUTE_RULES_TOTAL", 2, b"* -filter\n* -ident\n", ("protected.txt",)),
    ("MAX_ATTRIBUTE_STATES_PER_LINE", 3, b"* binary\n", ("protected.txt",)),
    ("MAX_ATTRIBUTE_MATCH_WORK", 28, b"protected.txt -filter\n", ("protected.txt",)),
    ("MAX_TREE_ENTRIES", 3, b"", ("protected.txt",) * 3),
    ("MAX_PATH_BYTES", 14, b"", ("protected.txt",)),
    ("MAX_PATH_BYTES_TOTAL", 27, b"", ("protected.txt",)),
    ("MAX_TREE_DEPTH", 2, b"", ("p/n/leaf",)),
))
@pytest.mark.parametrize("delta", (-1, 0, 1))
def test_attribute_exact_budget_boundaries(raw_repo, monkeypatch, budget, threshold, attributes, paths, delta):
    # The per-path ceiling also admits the 14-byte committed .gitattributes path.
    commit = raw_repo.commit(((".gitattributes", "100644", attributes),))
    monkeypatch.setattr(snapshot, budget, threshold + delta)
    calls, _ = attribute_comparison(raw_repo, commit, monkeypatch, (paths,))
    assert ("value" in calls[-1][0]) == (delta >= 0)


@pytest.mark.parametrize("shared", (False, True))
@pytest.mark.parametrize("delta", (-1, 0, 1))
@pytest.mark.parametrize("budget,threshold", (("MAX_ATTRIBUTE_BYTES_TOTAL", 44),
                                             ("MAX_ATTRIBUTE_RULES_TOTAL", 2),
                                             ("MAX_ATTRIBUTE_MATCH_WORK", 56),
                                             ("MAX_PATH_BYTES_TOTAL", 54)))
def test_attribute_shared_ledger_boundaries(raw_repo, monkeypatch, shared, delta, budget, threshold):
    commit = raw_repo.commit(((".gitattributes", "100644", b"protected.txt -filter\n"),))
    # One snapshot loads once; linked candidate/base must each admit the source.
    if not shared:
        threshold = {"MAX_ATTRIBUTE_BYTES_TOTAL": 22, "MAX_ATTRIBUTE_RULES_TOTAL": 1,
                     "MAX_ATTRIBUTE_MATCH_WORK": 56, "MAX_PATH_BYTES_TOTAL": 40}[budget]
    monkeypatch.setattr(snapshot, budget, threshold + delta)
    calls, costs = attribute_comparison(raw_repo, commit, monkeypatch,
                                        (("protected.txt",),) * 2, shared=shared)
    assert ("value" in calls[-1][0]) == (delta >= 0)
    if delta >= 0:
        assert costs[0][0]["matches"] == 4
        assert costs[1][0]["matches"] == costs[1][1].rule_evaluations == 2
        assert costs[1][1].exhaustion_replays == 0
        assert costs[1][0]["parses"] == (2 if shared else 1)


@pytest.mark.parametrize("ceilings", ((40, 40, 200, 400), (0, 12, 100, 400), (27, 55, 100, 400)))
@pytest.mark.parametrize("shared", (False, True))
def test_attribute_resumed_overlapping_requests(raw_repo, monkeypatch, ceilings, shared):
    commit = raw_repo.commit(((".gitattributes", "100644", b"* -filter\n"),
                              ("p/.gitattributes", "100755", b"**/leaf -ident\n")))
    requests = (("p/leaf", "p/leaf"), ("p/leaf", "p/other"), ("p/other", "p/leaf"), ("p/leaf",))
    calls, costs = attribute_comparison(raw_repo, commit, monkeypatch, requests,
                                       shared=shared, ceilings=ceilings)
    assert calls[-1][0] == {"value": None}
    assert costs[1][1].checkpoint_entries <= costs[1][1].matching_steps
    assert costs[1][0]["matches"] <= costs[0][0]["matches"]


@pytest.mark.parametrize("ceiling", range(57))
def test_every_d12_stopping_step_matches_legacy(raw_repo, monkeypatch, ceiling):
    commit = raw_repo.commit(((".gitattributes", "100644", b"protected.txt -filter\n"),))
    monkeypatch.setattr(snapshot, "MAX_ATTRIBUTE_MATCH_WORK", ceiling)
    calls, costs = attribute_comparison(raw_repo, commit, monkeypatch, (("protected.txt",),) * 2)
    assert calls[-1][1]["attribute_match_work"] == ceiling
    if ceiling >= 28:
        assert costs[1][1].rule_evaluations == 2
        assert costs[1][1].exhaustion_replays == int(ceiling < 56)


def test_attribute_legacy_bodies_match_recorded_sha256():
    import ast
    import hashlib
    import inspect
    import textwrap
    source = inspect.getsource(legacy)
    lines = source.splitlines(keepends=True)
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.FunctionDef) and node.name in legacy.PR4_BODY_SHA256:
            body = textwrap.dedent("".join(lines[node.lineno - 1:node.end_lineno]))
            assert hashlib.sha256(body.encode()).hexdigest() == legacy.PR4_BODY_SHA256[node.name]


@pytest.mark.parametrize("length", (2047, 2048, 2049))
def test_attribute_physical_line_boundary(raw_repo, monkeypatch, length):
    payload = b"* custom=" + b"x" * (length - len(b"* custom=")) + b"\n"
    commit = raw_repo.commit(((".gitattributes", "100644", payload),))
    calls, _ = attribute_comparison(raw_repo, commit, monkeypatch, (("path",),))
    assert ("value" in calls[0][0]) == (length < 2048)


@pytest.mark.parametrize("states", (255, 256, 257))
def test_attribute_production_state_boundary(raw_repo, monkeypatch, states):
    commit = raw_repo.commit(((".gitattributes", "100644", b"* " + b" ".join([b"a"] * states) + b"\n"),))
    calls, _ = attribute_comparison(raw_repo, commit, monkeypatch, (("path",),))
    assert ("value" in calls[0][0]) == (states <= 256)


@pytest.mark.parametrize("delta", (-1, 0, 1))
def test_attribute_production_blob_boundary(raw_repo, monkeypatch, delta):
    payload = b"#" + b"x" * (snapshot.MAX_ATTRIBUTE_BYTES + delta - 1)
    commit = raw_repo.commit(((".gitattributes", "100644", payload),))
    calls, _ = attribute_comparison(raw_repo, commit, monkeypatch, (("path",),))
    assert ("value" in calls[0][0]) == (delta <= 0)


def test_attribute_checkpoints_are_compact_and_shared_across_linked_subjects(raw_repo, monkeypatch):
    payload = b"*.json " + b" ".join([b"a"] * 200) + b"\n"
    commit = raw_repo.commit(((".gitattributes", "100644", payload),))
    paths = tuple(f"p/{index}.json" for index in range(32))
    requests = (paths + paths, paths, paths[::-1], paths)
    calls, costs = attribute_comparison(raw_repo, commit, monkeypatch, requests, shared=True)
    assert all(c[0] == {"value": None} for c in calls)
    actual = costs[1][1]
    assert actual.rule_evaluations == actual.checkpoint_entries == 64
    assert actual.exhaustion_replays == 0
    assert actual.applied_states == 64 * 200
    assert actual.path_outcomes == 64  # 32 paths in each of two authenticated subjects
    assert costs[0][0]["matches"] == 256 and costs[1][0]["matches"] == 64
    # Applied states use two integers/boolean checkpoint fields, not 12,800
    # objects representing individual matching and state-application charges.
    assert tuple(policy._RuleCheckpoint.__dataclass_fields__) == ("cost", "matched")


@pytest.mark.parametrize("link_after", (0, 1, 2))
def test_linking_attribute_ledgers_retains_completed_facts(raw_repo, monkeypatch, link_after):
    commit = raw_repo.commit(((".gitattributes", "100644", b"path -filter\n"),))
    results, costs = [], []
    for old in (True, False):
        with trace_attributes(monkeypatch, old=old) as (counts, events, failures):
            with raw_repo.snapshot(commit) as first, raw_repo.snapshot(commit) as second:
                calls = []
                for index, snap in enumerate((first, second, first, second)):
                    if index == link_after:
                        first._link_verification_work(second)
                    calls.append((outcome(lambda: snap.refuse_transforming_attributes(("path",))),
                                  asdict(first.work), asdict(second.work), tuple(events), tuple(failures)))
                results.append(calls)
                costs.append(dict(counts))
    assert results[0] == results[1]
    assert costs[0]["matches"] == 8
    assert costs[1]["matches"] == (4 if link_after == 2 else 2)
