"""The M3 differential comparator keeps frozen-first aggregate equality.

Without a reviewed delta, ``compare`` must accept a live trace only when the
frozen trace equals it, compared frozen-first. A leaf comparison run in the
reverse direction would let a primitive subclass whose ``__eq__`` is
asymmetric pass a live trace the frozen one rejects (review of #85).
"""

import hashlib
import json
from pathlib import Path

import pytest
from hypothesis import example, given, settings, strategies as st

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


@settings(max_examples=20, deadline=None, derandomize=True)
@given(frozen=st.integers(), live=st.integers(), exact=st.booleans())
@example(frozen=0, live=1, exact=True)
def test_compare_accepts_only_the_exact_reviewed_delta(frozen, live, exact):
    """A reviewed change pins both ends; a stale review still refuses."""
    calls = []

    def reviewed_probe(m, repo, patch):
        calls.append(None)
        return {"value": frozen if len(calls) == 1 else live}

    identity = {
        "probe": f"{reviewed_probe.__module__}.{reviewed_probe.__qualname__}",
        "args": [],
    }
    key = hashlib.sha256(json.dumps(
        identity, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    reviewed_live = live if exact else live + 1
    differences = {} if reviewed_live == frozen else {
        "$.trace.value": {"expected": frozen, "observed": reviewed_live},
    }
    review = json.dumps({key: {**identity, "differences": differences}})
    read_text = Path.read_text

    def read_review(path, *args, **kwargs):
        if path.name == "m3_review_deltas.json":
            return review
        return read_text(path, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Path, "read_text", read_review)
        if exact:
            result = compare(reviewed_probe, None, patch)
            assert result["trace"] == {"value": live}
        else:
            with pytest.raises(AssertionError):
                compare(reviewed_probe, None, patch)
    assert len(calls) == 2
