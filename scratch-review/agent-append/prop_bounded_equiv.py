"""Head only: bounded_json.loads agrees with json.loads on every text json.loads
accepts that nests <= 128 and has no integer literal > 4300 digits, and refuses
exactly when depth > 128. Strings are drawn from an alphabet heavy in the
characters the depth regex treats specially (brackets, quotes, backslashes).
Also: arbitrary text (valid or not) -> bounded raises JSONDecodeError exactly
when json.loads does (message equal), for shallow text.
"""

import json
import os
import pathlib
import sys

TREE = pathlib.Path(os.environ["TREE"])
import receipt  # noqa: E402
from receipt import _bounded_json as bj  # noqa: E402
from hypothesis import given, settings, strategies as st, HealthCheck  # noqa: E402

print("receipt from", receipt.__file__)
sys.setrecursionlimit(20000)

ALPHA = st.sampled_from(list('[]{}"\\/ \n\t\r,:0aé \ud800\U0001f600') + ["\\u005b", "\\\"", "\\\\"])
strings = st.lists(ALPHA, max_size=8).map("".join)
scalars = st.one_of(st.none(), st.booleans(), st.integers(-(10**30), 10**30), st.floats(allow_nan=False), strings)
values = st.recursive(scalars, lambda c: st.one_of(st.lists(c, max_size=3), st.dictionaries(strings, c, max_size=3)), max_leaves=12)


def depth(v):
    if isinstance(v, list):
        return 1 + max((depth(x) for x in v), default=0)
    if isinstance(v, dict):
        return 1 + max((depth(x) for x in v.values()), default=0)
    return 0


def wrap(v, n, kind):
    for i in range(n):
        v = [v] if kind[i % len(kind)] == "l" else {"k\"[": v}
    return v


S = settings(max_examples=3000, deadline=None, derandomize=True, suppress_health_check=list(HealthCheck))
counts = {"eq": 0, "deep": 0}


@S
@given(values, st.integers(0, 140), st.sampled_from(["l", "d", "ld"]), st.booleans(), st.sampled_from([None, 2]))
def test_equiv(v, extra, kind, ascii_, indent):
    v = wrap(v, extra, kind)
    text = json.dumps(v, ensure_ascii=ascii_, indent=indent)
    d = depth(v)
    ref = json.loads(text)
    try:
        got = bj.loads(text)
    except bj.JsonBoundError as exc:
        assert d > 128, (d, str(exc), text[:200])
        counts["deep"] += 1
        return
    assert d <= 128, (d, text[:200])
    assert json.dumps(got, sort_keys=True) == json.dumps(ref, sort_keys=True)
    counts["eq"] += 1


@S
@given(st.lists(ALPHA, max_size=40).map("".join))
def test_same_decode_error(text):
    try:
        ref = ("ok", json.loads(text))
    except json.JSONDecodeError as exc:
        ref = ("err", str(exc))
    except (ValueError, RecursionError) as exc:
        ref = ("other", type(exc).__name__)
    try:
        got = ("ok", bj.loads(text))
    except bj.JsonBoundError as exc:
        got = ("bound", str(exc))
    except json.JSONDecodeError as exc:
        got = ("err", str(exc))
    if ref[0] == "ok":
        assert got[0] in ("ok", "bound")
        if got[0] == "ok":
            assert json.dumps(got[1], sort_keys=True) == json.dumps(ref[1], sort_keys=True)
    else:
        assert got == ref, (ascii(text), ref, got)


if __name__ == "__main__":
    test_equiv()
    print("equiv ok", counts)
    test_same_decode_error()
    print("decode-error equivalence ok")
