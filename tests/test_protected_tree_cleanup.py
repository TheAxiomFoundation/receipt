"""PR6 comparisons retain independent v0.6.1 bodies and reached-call evidence."""
from __future__ import annotations

import hashlib
import inspect
import textwrap

import pytest

from receipt import _names, protected_tree, snapshot
from m1_fixture import outcome
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
