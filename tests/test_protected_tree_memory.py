"""Bounded v0.6.1/current cache and work measurements (M1 step 6, risk 3).

Run with pytest -s to retain the JSON measurements. Cache bytes are unique
reachable Python objects, excluding the reader, code, types and weak references;
the maximum is sampled after names, attributes and export/digest barriers.
Tracemalloc runs separately, so cache sizing and call tracing do not inflate its
execution peak. It includes reader/writer allocations, not just policy caches.
Both runs assert identical public counters and counted entry into each leg.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import asdict
import gc
import inspect
import json
from pathlib import PurePosixPath
import sys
from types import FunctionType, ModuleType
import tracemalloc

import pytest

from receipt import _names, protected_tree as policy, release_chain, snapshot
from m1_fixture import raw_repo
import protected_tree_legacy as legacy


REPEATS = 3
_LEGACY_NAMES = legacy._screen_protected_tree_names


def _body(function, namespace):
    result = FunctionType(function.__code__, namespace, argdefs=function.__defaults__)
    result.__kwdefaults__ = function.__kwdefaults__
    return result


@contextmanager
def _leg(monkeypatch, old):
    with monkeypatch.context() as patch:
        if old:
            for name in ("entry", "entries", "_raw_entry_at", *legacy.PR4_BODY_SHA256):
                target = snapshot.TreeSnapshot if hasattr(snapshot.TreeSnapshot, name) else snapshot
                patch.setattr(target, name, _body(getattr(legacy, name), snapshot.__dict__))
            patch.setattr(snapshot.TreeSnapshot, "blob", _body(legacy.PR6Snapshot.blob, snapshot.__dict__))
            patch.setattr(snapshot._DigestIterator, "__next__", _body(legacy.PR6Digest.__next__, snapshot.__dict__))
            namespace = dict(snapshot.__dict__, assert_no_merging_entries=legacy.assert_no_merging_entries)
            for name in ("_selected_entries", "_deduplicated_prefixes"):
                patch.setattr(snapshot.Materialization, name, _body(getattr(legacy, name), namespace))
        reached = Counter()

        def count(target, name, label):
            original = getattr(target, name)

            def call(*args, **kwargs):
                reached[label] += 1
                return original(*args, **kwargs)

            patch.setattr(target, name, call)

        # These count calls into the actual installed bodies, in both measurements.
        count(legacy, "_screen_protected_tree_names", "legacy_names")
        count(snapshot.TreeSnapshot, "refuse_transforming_attributes", "attribute_facade")
        count(policy.TreePolicy, "evaluate", "policy_evaluate")
        count(snapshot.Materialization, "_selected_entries", "legacy_export" if old else "standalone_export")
        count(policy._PolicyMaterialization, "_selected_entries", "policy_export")
        yield reached


def _cache_bytes(subject, evaluator):
    seen = {id(subject)}

    def size(value):
        if id(value) in seen or isinstance(value, (type, FunctionType, ModuleType)):
            return 0
        seen.add(id(value))
        total = sys.getsizeof(value)
        if isinstance(value, Mapping):
            total += sum(size(key) + size(item) for key, item in value.items())
        elif isinstance(value, (tuple, list, set, frozenset)):
            total += sum(size(item) for item in value)
        elif hasattr(value, "__dict__"):
            total += size(vars(value))
        return total

    roots = [subject._state.attribute_cache]
    if evaluator is not None:
        roots.extend(getattr(evaluator, name) for name in (
            "_facts", "_shapes", "_entries", "_scopes", "_empty_roots", "_runs", "_export_counts"))
        roots.append(subject._state.work_pool.root().attributes)
    return sum(size(root) for root in roots)


@contextmanager
def _actual_work():
    counts = Counter(name_folds=0, attribute_lower_calls=0, alias_matches=0, attribute_matches=0)
    source, start = inspect.getsourcelines(_LEGACY_NAMES)
    alias_line = start + next(i for i, line in enumerate(source) if "if listed_folded[:depth] !=" in line)
    alias_code = _LEGACY_NAMES.__code__
    name_files = {_names.__file__, legacy.__file__}
    attribute_files = {policy.__file__, legacy.__file__}

    def profile(frame, event, value):
        if event == "call":
            if frame.f_code in {legacy._attribute_matches.__code__, policy._attribute_matches.__code__}:
                counts["attribute_matches"] += 1
            if frame.f_code is policy._AliasNode.match.__code__:
                counts["alias_matches"] += 1
        elif event == "c_call" and isinstance(getattr(value, "__self__", None), bytes):
            if value.__name__ == "translate" and frame.f_code.co_filename in name_files:
                counts["name_folds"] += 1
            if value.__name__ == "lower" and frame.f_code.co_filename in attribute_files:
                counts["attribute_lower_calls"] += 1

    def trace(frame, event, _value):
        if frame.f_code is alias_code:
            if event == "line" and frame.f_lineno == alias_line:
                counts["alias_matches"] += 1
            return trace
        return None

    previous_profile, previous_trace = sys.getprofile(), sys.gettrace()
    sys.setprofile(profile)
    sys.settrace(trace)
    try:
        yield counts
    finally:
        sys.setprofile(previous_profile)
        sys.settrace(previous_trace)


def _measure(repo, commit, paths, scratch, monkeypatch, *, old, memory):
    prefixes = tuple(PurePosixPath(path) for path in paths)
    name_plan = policy.ProtectionPlan.chain_names(
        prefixes, repertoire="portable", release_directories=(), use="benchmark-names")
    attribute_plan = policy.ProtectionPlan(
        obligations=("attributes",), listing_scope=(), phase="attributes",
        attribute_target_selectors=paths, use="benchmark-attributes")
    # Use the unwrapped legacy function's location when tracing its inner loop.
    tracing = _actual_work()
    with _leg(monkeypatch, old) as reached, repo.snapshot(commit) as subject:
        gc.collect()
        if memory:
            tracemalloc.start()
            actual = {}
        else:
            actual = tracing.__enter__()
        checkpoints, cache_peak = [], 0
        try:
            evaluator = None if old else policy.TreePolicy(
                subject, policy_version=policy.POLICY_VERSION, work=subject.work)

            def checkpoint():
                nonlocal cache_peak
                checkpoints.append(asdict(subject.work))
                if not memory:
                    cache_peak = max(cache_peak, _cache_bytes(subject, evaluator))

            for _ in range(REPEATS):
                if old:
                    legacy._screen_protected_tree_names(
                        subject.entries("").as_dict(include_trees=True), prefixes,
                        repertoire="portable", release_directories=())
                else:
                    evaluator.read_listing("")
                    view = evaluator.evaluate(name_plan, stage="suffixes")
                    view.require(name_plan.use, render=release_chain._protected_name_error)
                checkpoint()
                if old:
                    subject.refuse_transforming_attributes(paths)
                else:
                    view = evaluator.evaluate_attributes(attribute_plan)
                    view.require(attribute_plan.use, render=policy.attribute_error)
                checkpoint()
                materialization = (subject.materialize(prefixes, scratch, repertoire="portable")
                                   if old else evaluator.materialize(name_plan, scratch))
                with materialization as materialized:
                    entries = materialized.entries
                    assert tuple(sorted(entries)) == paths
                    digests = tuple((entry.path, digest) for entry, digest in subject.digests(
                        (entries[path] for path in paths), per_blob=1024, total=1 << 20))
                    assert len(digests) == len(paths)
                checkpoint()
            traced_peak = tracemalloc.get_traced_memory()[1] if memory else 0
        finally:
            if memory:
                tracemalloc.stop()
            else:
                tracing.__exit__(None, None, None)
        assert reached["legacy_names"] == (REPEATS if old else 0)
        assert reached["attribute_facade"] == (REPEATS if old else 0)
        assert reached["legacy_export"] == (REPEATS if old else 0)
        assert reached["policy_export"] == (0 if old else REPEATS)
        assert reached["policy_evaluate"] == (0 if old else 3 * REPEATS)
        counters = {} if old else {name: asdict(getattr(evaluator, name)) for name in (
            "name_work", "shape_work", "attribute_work", "export_work")}
        return dict(public=checkpoints, digests=digests, reached=dict(reached),
                    actual=dict(actual), policy=counters, cache_peak_bytes=cache_peak,
                    traced_peak_bytes=traced_peak)


@pytest.mark.parametrize("shape", ("broad", "deep"))
def test_bounded_v061_memory_and_work(raw_repo, tmp_path, monkeypatch, shape):
    prefix = "protected" if shape == "broad" else "/".join(("protected", *(f"d{i:02}" for i in range(63))))
    paths = tuple(f"{prefix}/leaf{i:03}.txt" for i in range(128 if shape == "broad" else 8))
    commit = raw_repo.commit(tuple((path, "100644") for path in paths) + (
        (".gitattributes", "100644", b"* -filter\nprotected/** -ident\n"),
        ("protected/.gitattributes", "100644", b"* -working-tree-encoding\n"),
    ))
    rows = []
    for old in (True, False):
        counted = _measure(raw_repo, commit, paths, tmp_path, monkeypatch, old=old, memory=False)
        memory = _measure(raw_repo, commit, paths, tmp_path, monkeypatch, old=old, memory=True)
        assert counted["public"] == memory["public"]
        assert counted["digests"] == memory["digests"]
        assert counted["reached"] == memory["reached"]
        counted["traced_peak_bytes"] = memory["traced_peak_bytes"]
        rows.append(counted)
    assert rows[0]["public"] == rows[1]["public"]
    assert rows[0]["digests"] == rows[1]["digests"]
    for key in ("name_folds", "alias_matches", "attribute_matches", "attribute_lower_calls"):
        assert 0 < rows[1]["actual"][key] < rows[0]["actual"][key]
    assert rows[1]["actual"]["name_folds"] == rows[1]["policy"]["name_work"]["folds"]
    assert rows[1]["actual"]["alias_matches"] == rows[1]["policy"]["name_work"]["alias_steps"]
    assert rows[1]["actual"]["attribute_matches"] == rows[1]["policy"]["attribute_work"]["rule_evaluations"]
    # Bounded fixtures must remain bounded even when retained facts cost more memory.
    assert max(row["cache_peak_bytes"] for row in rows) < 8 << 20
    print(json.dumps(dict(shape=shape, leaves=len(paths), depth=len(paths[0].split("/")),
        repeats=REPEATS, rows=[{**row, "public": row["public"][-1], "digests": len(row["digests"])}
                              for row in rows]), sort_keys=True))
