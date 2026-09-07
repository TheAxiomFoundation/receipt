"""PR6 comparisons retain independent v0.6.1 bodies and reached-call evidence."""
from __future__ import annotations

import hashlib
import inspect
import textwrap
from dataclasses import asdict
from types import FunctionType

import pytest

from receipt import _names, protected_tree, snapshot
from m1_fixture import outcome, raw_repo
import protected_tree_legacy as legacy


def test_pr6_verbatim_v061_body_sha256():
    for group, functions in legacy.PR6_BODY_SHA256.items():
        for name, expected in functions.items():
            source = textwrap.dedent(inspect.getsource(getattr(getattr(legacy, group), name)))
            assert hashlib.sha256(source.encode()).hexdigest() == expected, (group, name)


@pytest.mark.parametrize("names", (
    ("a", "b"), (b"a", "A"), ("a", "a"), ("bad?", "b"),
    (b"bad\xff", "a"), ("a", 1), ("é", "e\u0301"), ("a", "a", b"bad\xff"),
))
@pytest.mark.parametrize("repertoire,materializing", (
    ("portable", False), ("posix-bytes", False), ("posix-bytes", True),
))
def test_sibling_facades_share_one_loop_with_v061_outcomes(
    monkeypatch, names, repertoire, materializing,
):
    kernel = _names._screen_sibling_names
    calls = []

    def counted(*args, **kwargs):
        calls.append(1)
        return kernel(*args, **kwargs)

    monkeypatch.setattr(_names, "_screen_sibling_names", counted)
    results = []
    for body in (legacy.assert_no_merging_entries, _names.assert_no_merging_entries,
                 snapshot.assert_no_merging_entries):
        calls.clear()
        reached = []

        def call():
            reached.append(body.__code__)
            return body(iter(names), repertoire=repertoire, materializing=materializing,
                        label="audited directory")

        results.append(outcome(call))
        assert reached == [body.__code__]
        assert len(calls) == (0 if body is legacy.assert_no_merging_entries else 1)
    assert results[0] == results[1] == results[2]


@pytest.mark.parametrize("mode", ("100644", "100755", "120000", "160000", "040000"))
@pytest.mark.parametrize("operation", ("blob", "digests"))
def test_payload_facades_delegate_modes_with_v061_outcomes(raw_repo, monkeypatch, mode, operation):
    commit = raw_repo.commit((), empty=("target",)) if mode == "040000" else raw_repo.commit((("target", mode),))
    owner, name, frozen = (
        (snapshot.TreeSnapshot, "blob", legacy.PR6Snapshot.blob) if operation == "blob"
        else (snapshot._DigestIterator, "__next__", legacy.PR6Digest.__next__)
    )
    current = getattr(owner, name)
    classify = protected_tree.classify_mode
    results = []
    for old in (True, False):
        with monkeypatch.context() as patch, raw_repo.snapshot(commit) as subject:
            entry = subject.entry("target")
            calls, classifications = [], []
            body = FunctionType(frozen.__code__, snapshot.__dict__) if old else current

            def counted(*args, **kwargs):
                calls.append(body.__code__)
                return body(*args, **kwargs)

            def classified(*args, **kwargs):
                classifications.append(args)
                return classify(*args, **kwargs)

            patch.setattr(owner, name, counted)
            patch.setattr(protected_tree, "classify_mode", classified)

            def call():
                if operation == "blob":
                    return subject.blob(entry, limit=1024)
                return tuple((item.path, digest) for item, digest in
                             subject.digests((entry,), per_blob=1024, total=1024))

            results.append((outcome(call), asdict(subject.work)))
            assert calls and all(code is body.__code__ for code in calls)
            assert (body.__code__ is frozen.__code__) == old
            assert len(classifications) == int(not old and entry.object_type == "blob")
    assert results[0] == results[1]
