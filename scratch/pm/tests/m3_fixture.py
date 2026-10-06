"""Synchronous raw-index probes and exact reached-body observations for M3."""
import json
from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
import hashlib
import inspect
from pathlib import Path
import sys

import pytest

from m1_fixture import RawRepo
from m3_legacy import authenticate, modules, source_tree


@pytest.fixture(scope="session", autouse=True)
def authenticated_m3_oracle():
    return authenticate()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    # Commit bytes/OIDs, including initial selection charges, are deterministic.
    monkeypatch.setenv("GIT_AUTHOR_DATE", "2001-01-01T00:00:00+0000")
    monkeypatch.setenv("GIT_COMMITTER_DATE", "2001-01-01T00:00:00+0000")
    value = RawRepo(tmp_path / "repo")
    assert value.git("config", "core.precomposeUnicode") == b"false"
    return value


def plain(value):
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if is_dataclass(value):
        return plain(asdict(value))
    if isinstance(value, dict):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [plain(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(plain(v) for v in value)
    if isinstance(value, Path):
        return str(value)
    assert value is None or isinstance(value, (str, int, float, bool)), type(value)
    return value


def outcome(call):
    try:
        return {"value": plain(call())}
    except BaseException as exc:
        return {"exception": f"{type(exc).__module__}.{type(exc).__qualname__}",
                "message": str(exc), "notes": list(getattr(exc, "__notes__", ()))}


def work(*subjects):
    return [asdict(s.work) for s in subjects]


class Trace:
    def __init__(self, *subjects):
        self.subjects, self.events = subjects, []

    def call(self, label, call):
        result = outcome(call)
        self.events.append([label, result, work(*self.subjects)])
        return result


def policy(m, subject):
    p = m.protected_tree
    return p.TreePolicy(subject, policy_version=p.POLICY_VERSION, work=subject.work)


@contextmanager
def reached(m):
    """Count actual code objects, not wrappers or similarly named live globals."""
    selected = {}
    for name in ("TreeSnapshot", "_BatchReader", "_WorkPool", "TreeListing",
                 "_DigestIterator", "Materialization"):
        cls = getattr(m.snapshot, name, None)
        if cls is None:
            continue
        for method, descriptor in vars(cls).items():
            if method == "__replace__":
                # Synthesized by dataclasses on Python 3.13 and later only; it is
                # not a receipt body, and counting it made the freeze depend on
                # the interpreter version (absent on 3.11 and 3.12).
                continue
            body = (descriptor.__func__ if isinstance(descriptor, (classmethod, staticmethod))
                    else descriptor.fget if isinstance(descriptor, property) else descriptor)
            if inspect.isgeneratorfunction(body) or inspect.isasyncgenfunction(body):
                # Generator frames report call events per resumption in a way
                # that differs between interpreter versions (3.12 counted one
                # fewer than 3.11, 3.13 and 3.14 on the D6 cases); their entry
                # counts are interpreter facts, not receipt bodies. The listing
                # walks are still observed through the reader's public counters.
                continue
            if hasattr(body, "__code__"):
                selected[body.__code__] = f"{name}.{method}"
    for module, names in (
        (m.snapshot, ("_parse_raw_tree", "_canonical_commit", "_git_environment", "_git_run")),
        (m.protected_tree, ("_charge_attribute_work", "export_prefixes", "_parse_attribute_file", "_attribute_matches", "_segment_matches", "load_attribute_rules")),
        (m.verify, ("run_verification",)),
        (m.corpus, ("verify_corpus_binding", "_verify_corpus_binding")),
        (m.release_chain, ("verify_release_history_immutable", "verify_base_release_chain")),
        (m.append_gate, ("verify_append_gate", "verify_append_gate_verdict")),
    ):
        for name in names:
            body = getattr(module, name, None)
            if hasattr(body, "__code__"):
                selected[body.__code__] = module.__name__.split(".")[-1] + "." + name
    counts = Counter()
    hash_new = m.snapshot.hashlib.new
    hash_code = getattr(hash_new, "__code__", None)
    old = sys.getprofile()
    def profile(frame, event, arg):
        if event == "call" and frame.f_code in selected:
            counts[selected[frame.f_code]] += 1
        if ((event == "call" and frame.f_code is hash_code
             and frame.f_back.f_code in selected
             and selected[frame.f_back.f_code] == "_BatchReader.consume")
            or (event == "c_call" and arg is hash_new
                and selected.get(frame.f_code) == "_BatchReader.consume")):
            counts["objects.hash"] += 1
    sys.setprofile(profile)
    try:
        yield counts
    finally:
        sys.setprofile(old)


def compare(probe, repo, monkeypatch, *args, expected=None):
    """Compare both independently reached implementations and a captured value."""
    results, codes = [], []
    for old in (True, False):
        with source_tree(old=old), monkeypatch.context() as patch:
            m = modules()
            codes.append(m.snapshot.TreeSnapshot.select.__func__.__code__)
            with reached(m) as counts:
                result = probe(m, repo, patch, *args)
            results.append(plain({"trace": result, "bodies": dict(sorted(counts.items()))}))
    assert codes[0] is not codes[1], "legacy/live selector bodies must be distinct"
    assert results[0] == results[1], (results[0], results[1])
    if expected is not None and results[1] != expected:
        # Print the differing leaves, not the whole structures: CI logs truncate
        # a raw dict diff, which hid the host-dependent D7 traces once already.
        raise AssertionError("observed trace differs from the recorded one: "
                             + json.dumps(_leaf_differences(results[1], expected), sort_keys=True))
    return results[1]


def _leaf_differences(observed, expected, path="$"):
    """Leaves where two plain structures differ, keyed by a JSON-ish path."""
    if isinstance(observed, dict) and isinstance(expected, dict):
        out = {}
        for key in sorted(set(observed) | set(expected), key=str):
            if key not in observed or key not in expected:
                out[f"{path}.{key}"] = {"observed": observed.get(key, "<absent>"),
                                        "expected": expected.get(key, "<absent>")}
            else:
                out.update(_leaf_differences(observed[key], expected[key], f"{path}.{key}"))
        return out
    if isinstance(observed, list) and isinstance(expected, list):
        out = {}
        for index in range(max(len(observed), len(expected))):
            if index >= len(observed) or index >= len(expected):
                out[f"{path}[{index}]"] = {"observed": observed[index] if index < len(observed) else "<absent>",
                                           "expected": expected[index] if index < len(expected) else "<absent>"}
            else:
                out.update(_leaf_differences(observed[index], expected[index], f"{path}[{index}]"))
        return out
    return {} if observed == expected else {path: {"observed": observed, "expected": expected}}
