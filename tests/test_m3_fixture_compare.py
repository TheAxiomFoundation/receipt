"""The M3 differential comparator keeps frozen-first aggregate equality.

Without a reviewed delta, ``compare`` must accept a live trace only when the
frozen trace equals it, compared frozen-first. A leaf comparison run in the
reverse direction would let a primitive subclass whose ``__eq__`` is
asymmetric pass a live trace the frozen one rejects (review of #85).
"""

import pytest

from m3_fixture import compare


class _FrozenText(str):
    __hash__ = str.__hash__

    def __eq__(self, other):
        return False


class _LiveText(str):
    __hash__ = str.__hash__

    def __eq__(self, other):
        return True


def test_compare_refuses_an_unreviewed_trace_equal_only_in_reverse(monkeypatch):
    calls = []

    def asymmetric_probe(m, repo, patch):
        calls.append(None)
        # compare runs the frozen implementation first, then the live one.
        text = _FrozenText if len(calls) == 1 else _LiveText
        return {"value": text("same")}

    with pytest.raises(AssertionError, match="live trace differs outside the reviewed changes"):
        compare(asymmetric_probe, None, monkeypatch)
    assert len(calls) == 2


def test_compare_accepts_an_unreviewed_trace_that_is_plainly_equal(monkeypatch):
    def equal_probe(m, repo, patch):
        return {"value": "same"}

    result = compare(equal_probe, None, monkeypatch)
    assert result["trace"] == {"value": "same"}
