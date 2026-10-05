"""``receipt._bounded_json``: ``json.loads`` with bounds stated by the input.

The claims are that it decodes what ``json.loads`` decodes, refuses
malformed text with exactly ``json.loads``'s error, and otherwise refuses
with ``JsonBoundError``, never an interpreter exception: always for text
nested deeper than ``MAX_DEPTH`` or holding an integer literal longer than
``MAX_INTEGER_DIGITS``, and also for shallower text when the call stack or
the process's own int-string limit runs out first.
"""

from __future__ import annotations

import json
import math
import sys

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from receipt._bounded_json import MAX_DEPTH, MAX_INTEGER_DIGITS, JsonBoundError, loads

PROPERTY = settings(
    max_examples=500,
    deadline=None,
    derandomize=True,
    suppress_health_check=list(HealthCheck),
)


def same(left: object, right: object) -> bool:
    """Equality that also holds for NaN in the same place."""

    if isinstance(left, float) and isinstance(right, float):
        return left == right or (math.isnan(left) and math.isnan(right))
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(map(same, left, right))
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(same(left[k], right[k]) for k in left)
    return type(left) is type(right) and left == right


json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=True, allow_infinity=True)
    | st.text(),
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(st.text(max_size=4), children, max_size=4),
    max_leaves=20,
)


@PROPERTY
@given(json_values)
def test_decodes_what_json_loads_decodes(value: object) -> None:
    text = json.dumps(value)
    assert same(loads(text), json.loads(text))


JSONISH = list('[]{}"\\,:0123456789-+.eEtrufalsnNIy ') + ["\n", " ", "é"]


@PROPERTY
@given(st.text(alphabet=JSONISH, max_size=40))
def test_agrees_with_json_loads_on_arbitrary_text(text: str) -> None:
    """Differential on text that is mostly malformed: the same value, or the
    same ``JSONDecodeError`` message, or (only where ``json.loads`` crashed or
    the bounds apply) ``JsonBoundError``."""

    try:
        expected = ("value", json.loads(text))
    except json.JSONDecodeError as exc:
        expected = ("error", str(exc))
    except (ValueError, RecursionError):
        expected = ("crash", None)
    try:
        actual = ("value", loads(text))
    except json.JSONDecodeError as exc:
        actual = ("error", str(exc))
    except JsonBoundError:
        actual = ("bound", None)
    if expected[0] == "value":
        assert actual[0] == "value" and same(actual[1], expected[1])
    elif expected[0] == "error":
        assert actual == expected
    else:
        assert actual[0] == "bound"


@pytest.mark.parametrize("opening", ["[", '{"k":'])
def test_depth_is_bounded_at_exactly_max_depth(opening: str) -> None:
    closing = "]" if opening == "[" else "}"
    at_bound = opening * MAX_DEPTH + "0" + closing * MAX_DEPTH
    assert loads(at_bound) is not None
    past = opening * (MAX_DEPTH + 1) + "0" + closing * (MAX_DEPTH + 1)
    with pytest.raises(JsonBoundError) as caught:
        loads(past)
    assert str(caught.value) == (
        f"JSON nesting exceeds {MAX_DEPTH} levels at char {len(opening) * MAX_DEPTH}"
    )


def test_depth_counts_arrays_and_objects_together() -> None:
    text = '[{"a":' * 64 + "[0]" + "}]" * 64
    with pytest.raises(JsonBoundError, match="^JSON nesting exceeds 128 levels at char 384$"):
        loads(text)
    assert loads('[{"a":' * 63 + "[0]" + "}]" * 63) is not None


@pytest.mark.parametrize(
    "text",
    [
        '"' + "[" * 1000 + '"',
        '"\\"' + "[" * 1000 + '"',
        '["\\\\", "' + "{" * 1000 + '"]',
        '{"' + "[" * 500 + '": "' + "{" * 500 + '"}',
    ],
)
def test_brackets_inside_strings_are_not_nesting(text: str) -> None:
    assert same(loads(text), json.loads(text))


def test_deep_text_json_loads_refuses_first_keeps_its_error() -> None:
    """A malformed document is refused with ``json.loads``'s own message
    wherever ``json.loads`` reports one, however deep it is elsewhere."""

    text = "[" * (MAX_DEPTH + 10) + "x"
    with pytest.raises(json.JSONDecodeError) as caught:
        loads(text)
    with pytest.raises(json.JSONDecodeError) as reference:
        json.loads(text)
    assert str(caught.value) == str(reference.value)


@pytest.mark.parametrize("depth", [MAX_DEPTH + 1, 900, 5_000, 200_000])
def test_any_excess_depth_is_the_bound_whatever_json_loads_would_do(depth: int) -> None:
    """Below the interpreter's limit ``json.loads`` accepts the text; above it
    it raises ``RecursionError``. Both are the same refusal here."""

    with pytest.raises(JsonBoundError, match=rf"^JSON nesting exceeds {MAX_DEPTH} levels"):
        loads("[" * depth + "]" * depth)


def test_depth_refusal_does_not_depend_on_the_callers_stack() -> None:
    """Called near the recursion limit, the same bytes get the same verdict."""

    shallow = "[" * MAX_DEPTH + "]" * MAX_DEPTH
    deep = "[" * 10_000 + "]" * 10_000

    def nested(levels: int) -> tuple[object, str]:
        if levels:
            return nested(levels - 1)
        with pytest.raises(JsonBoundError) as caught:
            loads(deep)
        return loads(shallow), str(caught.value)

    limit = sys.getrecursionlimit()
    accepted, refusal = nested(limit - 200)
    assert accepted is not None
    assert refusal.startswith(f"JSON nesting exceeds {MAX_DEPTH} levels")


def test_integer_width_is_bounded_at_exactly_max_integer_digits() -> None:
    assert loads("9" * MAX_INTEGER_DIGITS) == int("9" * MAX_INTEGER_DIGITS)
    assert loads("-" + "9" * MAX_INTEGER_DIGITS) == -int("9" * MAX_INTEGER_DIGITS)
    for literal in ("9" * (MAX_INTEGER_DIGITS + 1), "-" + "9" * (MAX_INTEGER_DIGITS + 1)):
        with pytest.raises(JsonBoundError) as caught:
            loads(f"[{literal}]")
        assert str(caught.value) == (
            f"JSON integer literal has {MAX_INTEGER_DIGITS + 1} digits, more than "
            f"{MAX_INTEGER_DIGITS}"
        )


def test_long_floats_are_json_loads_floats() -> None:
    """Only integer literals are bounded; a float with 5,000 digits decodes as
    ``json.loads`` decodes it."""

    for text in ("1." + "1" * 5000, "1" * 5000 + ".5", "1e" + "9" * 5000):
        assert same(loads(text), json.loads(text))


def test_integer_width_holds_under_a_lowered_process_limit() -> None:
    literal = "9" * 700
    previous = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)
    try:
        with pytest.raises(JsonBoundError, match="more than this interpreter converts$"):
            loads(literal)
    finally:
        sys.set_int_max_str_digits(previous)


def test_hooks_pass_through() -> None:
    class Refused(Exception):
        pass

    def no_constants(name: str) -> None:
        raise Refused(name)

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        if len({key for key, _ in items}) != len(items):
            raise Refused("duplicate")
        return dict(items)

    with pytest.raises(Refused, match="^NaN$"):
        loads("[NaN]", parse_constant=no_constants)
    with pytest.raises(Refused, match="^duplicate$"):
        loads('{"a": 1, "a": 2}', object_pairs_hook=pairs)
    assert loads('{"a": [1, 2]}', object_pairs_hook=pairs) == {"a": [1, 2]}
