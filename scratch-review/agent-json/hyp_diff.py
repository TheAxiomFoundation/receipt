"""Hypothesis differential: _bounded_json.loads vs json.loads (head tree).

Usage: python hyp_diff.py <tree-dir> <property> <max_examples>
property in: values, mutated, mutated_hooks, jsonish_deep
Prints outcome-class counts; on a disagreement Hypothesis shrinks and the
AssertionError carries the minimal example.
"""
import collections
import json
import pathlib
import sys

tree = pathlib.Path(sys.argv[1]).resolve()
sys.path[:0] = [str(tree / "src"), str(pathlib.Path(__file__).parent)]
import receipt  # noqa: E402

print("receipt:", receipt.__file__, flush=True)
from hypothesis import HealthCheck, given, settings, strategies as st, event  # noqa: E402

import difflib_bj as D  # noqa: E402
from receipt import release_chain as rc  # noqa: E402

PROP, N = sys.argv[2], int(sys.argv[3])
SET = settings(
    max_examples=N,
    deadline=None,
    suppress_health_check=list(HealthCheck),
    database=None,
    derandomize=False,
)
COUNTS: collections.Counter = collections.Counter()

SPECIAL = list('"\\[]{}\n\r,:') + list("abcxyzuUtrfnels0123456789-+.eE") + [
    "\t", " ", "\x00", "\x1f", "\u2028", "\u2029", "\ufeff", "\ud800", "\udc00",
    "\u00e9", "\\u0022", "\\u005c", '\\"', "\\\\", "\\/", "NaN", "Infinity", "-Infinity",
]

str_leaf = st.text(
    alphabet=st.sampled_from(list('[]{}"\\/,:ab \t\n\x00\u2028\ud800\ufeff')), max_size=12
)
leaf = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(10**40), max_value=10**40)
    | st.floats(allow_nan=True, allow_infinity=True)
    | str_leaf
)
values = st.recursive(
    leaf,
    lambda ch: st.lists(ch, max_size=3) | st.dictionaries(str_leaf, ch, max_size=3),
    max_leaves=10,
)


@st.composite
def deep_value(draw):
    v = draw(values)
    depth = draw(st.one_of(st.integers(0, 3), st.integers(122, 132), st.integers(100, 200)))
    for _ in range(depth):
        if draw(st.booleans()):
            v = [v] if draw(st.booleans()) else [draw(leaf), v]
        else:
            v = {draw(str_leaf): v}
    return v


@st.composite
def serialized(draw):
    v = draw(deep_value())
    kw = {}
    kw["ensure_ascii"] = draw(st.booleans())
    kw["indent"] = draw(st.sampled_from([None, None, 0, 1, "\t", "\r\n"]))
    if kw["indent"] is None:
        kw["separators"] = draw(st.sampled_from([(",", ":"), (", ", ": "), (" ,\n", " :\r")]))
    try:
        text = json.dumps(v, **kw)
    except ValueError:
        text = json.dumps(v, ensure_ascii=True)
    if draw(st.booleans()):
        text = draw(st.sampled_from(["", " ", "\n", "\r\n", "\t"])) + text + draw(
            st.sampled_from(["", " ", "\n", "\r\n", "\t"])
        )
    return text


@st.composite
def mutated(draw):
    text = draw(serialized())
    for _ in range(draw(st.integers(0, 4))):
        op = draw(st.sampled_from(["ins", "del", "rep"]))
        pos = draw(st.integers(0, len(text)))
        ch = draw(st.sampled_from(SPECIAL))
        if op == "ins":
            text = text[:pos] + ch + text[pos:]
        elif op == "del" and text:
            pos = min(pos, len(text) - 1)
            text = text[:pos] + text[pos + 1 :]
        elif text:
            pos = min(pos, len(text) - 1)
            text = text[:pos] + ch + text[pos + 1 :]
    return text


@st.composite
def jsonish_deep(draw):
    alpha = list('[]{}"\\,:0123456789-+.eEtrufalsnNIy ') + ["\n", "\r", " ", "é", "\t", "\x00"]
    body = draw(st.text(alphabet=st.sampled_from(alpha), max_size=60))
    pre = draw(st.integers(0, 140))
    opener = draw(st.sampled_from(["[", '{"a":', '["[",', '{"\\"":']))
    closer = {"[": "]", '{"a":': "}", '["[",': "]", '{"\\"":': "}"}[opener]
    k = draw(st.integers(0, pre))
    return opener * pre + body + closer * k


def check(text, **kw):
    r = D.compare(text, **kw)
    ref = D.outcome(__import__("json").loads, text, **kw)[0]
    got = D.outcome(D.bj.loads, text, **kw)[0]
    COUNTS[(ref, got)] += 1
    assert r is None, (r, text[:400])


if PROP == "values":
    @SET
    @given(serialized())
    def prop(text):
        check(text)
elif PROP == "mutated":
    @SET
    @given(mutated())
    def prop(text):
        check(text)
elif PROP == "mutated_hooks":
    @SET
    @given(mutated())
    def prop(text):
        check(text, object_pairs_hook=rc._object_without_duplicates, parse_constant=rc._fail_json_constant)
elif PROP == "jsonish_deep":
    @SET
    @given(jsonish_deep())
    def prop(text):
        check(text)
else:
    raise SystemExit("unknown property")

try:
    prop()
    print("PASS", PROP, N)
finally:
    print(dict(COUNTS))
