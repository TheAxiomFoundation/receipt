"""Totality of ``receipt.append_gate``'s row and prefix checks.

Each property says that for every input in its domain the check either
returns or raises ``AppendError`` -- never an interpreter exception. They
come from the full Opus 5.5 review of 0.6.2 (leg L6, AG-3 and AG-4), which
found the counterexamples ``tests/test_append_gate.py`` now pins, widened
here to the values that broke the content address (NaN, the infinities,
integers past the Number range and past the decoder's digit bound) and to
arbitrary text. Runs are derandomized, so CI explores the same examples.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from hypothesis import HealthCheck, example, given, settings, strategies as st

import test_append_gate as fixture
from receipt import _bounded_json as bounded_json
from receipt.append_gate import (
    AppendError,
    check_gate_only_confinement,
    check_prefix,
    check_rows,
    effective_current_rows,
    expected_assertion_version_id,
)

SPEC = fixture.GATE_SPEC
STATE_PATHS = (
    "ledger",
    SPEC.chain.state_relative.as_posix(),
    SPEC.chain.prefix_relative.as_posix(),
)
PROPERTY = settings(
    max_examples=400,
    deadline=None,
    derandomize=True,
    suppress_health_check=list(HealthCheck),
)

json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-10, 10),
    st.integers(min_value=2**53, max_value=2**2000),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=4),
)
json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(max_size=3), children, max_size=3),
    ),
    max_leaves=6,
)
ROW_FIELDS = [
    "source_record_id", "value", "observed_at", "measure", "source",
    "responseArchive", "assertionVersion", "retrievedAt", "ledgerRepoSha",
    "sourceBindingProjection", "targetContentHash", "filters",
]


def dumps(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=True)


def base_lines() -> list[str]:
    return [fixture.jsonl_line(fixture.observation_row(n)) for n in (1, 2)]


@PROPERTY
@given(st.lists(st.text(alphabet=st.characters(codec="utf-8"), max_size=80), max_size=12))
@example(lines=[])
@example(lines=["", "caf\u00e9", "\U0001f600", "embedded\nnewline"])
def test_every_prefix_hash_matches_the_release_implementation(lines: list[str]) -> None:
    """Every count, including zero, hashes the release's exact UTF-8 bytes."""

    for count in range(len(lines) + 1):
        manifest = {
            "schemaVersion": SPEC.prefix_schema_version,
            "prefixLineCount": count,
            "lineSha256s": [
                hashlib.sha256(line.encode("utf-8")).hexdigest()
                for line in lines[:count]
            ],
            # The checksum input in release/0.6.x, v0.6.1 and v0.6.2.
            "prefixSha256": hashlib.sha256(
                ("\n".join(lines[:count]) + "\n").encode("utf-8")
            ).hexdigest(),
        }
        assert check_prefix(lines, dumps(manifest), SimpleNamespace(spec=SPEC)) == manifest
        manifest["prefixSha256"] = "0" * 64
        with pytest.raises(AppendError, match="^immutable prefix cumulative hash mismatch$"):
            check_prefix(lines, dumps(manifest), SimpleNamespace(spec=SPEC))


@PROPERTY
@given(st.sampled_from(ROW_FIELDS), json_values)
def test_check_rows_refuses_any_field_value_with_append_error(field: str, value) -> None:
    """One field of an appended row replaced by any JSON value (L6 AG-3:
    measure=1, source=1 and responseArchive=1 raised AttributeError)."""

    row = fixture.observation_row(3)
    row[field] = value
    try:
        if field != "assertionVersion":
            row["assertionVersion"] = {"id": expected_assertion_version_id(row, SPEC)}
    except AppendError:
        pass
    try:
        check_rows([*base_lines(), dumps(row)], 1, SPEC)
    except AppendError:
        pass


@PROPERTY
@given(st.text(max_size=60) | json_values.map(dumps))
def test_check_rows_refuses_any_line_with_append_error(line: str) -> None:
    try:
        check_rows([*base_lines(), line], 1, SPEC)
    except AppendError:
        pass


@PROPERTY
@given(
    st.dictionaries(
        st.sampled_from(["schemaVersion", "prefixLineCount", "lineSha256s", "prefixSha256"]),
        json_values,
        max_size=4,
    )
    | json_values
)
def test_check_prefix_refuses_any_manifest_with_append_error(manifest) -> None:
    """Any JSON prefix manifest (L6 AG-4: prefixLineCount null raised
    TypeError, lineSha256s null TypeError, a missing key KeyError)."""

    if isinstance(manifest, dict):
        manifest.setdefault("schemaVersion", SPEC.prefix_schema_version)
    try:
        check_prefix(base_lines(), dumps(manifest), SimpleNamespace(spec=SPEC))
    except AppendError:
        pass


@PROPERTY
@given(st.text(max_size=60))
def test_check_prefix_refuses_any_manifest_text_with_append_error(text: str) -> None:
    try:
        check_prefix(base_lines(), text, SimpleNamespace(spec=SPEC))
    except AppendError:
        pass


@PROPERTY
@given(st.lists(st.sampled_from(["garbage", "[1]", "null", '{"x":1}', ""]), max_size=2))
def test_a_rewritten_prefix_line_is_named_whatever_it_holds(replacements: list[str]) -> None:
    """The rewritten-line refusal reads the row's id for its message; a row
    that is not a JSON object must not break the message."""

    lines = base_lines()
    for index, text in enumerate(replacements):
        lines[index] = text
    first = base_lines()[0]
    manifest = {
        "schemaVersion": SPEC.prefix_schema_version,
        "prefixLineCount": 1,
        "lineSha256s": [hashlib.sha256(first.encode()).hexdigest()],
        "prefixSha256": hashlib.sha256((first + "\n").encode()).hexdigest(),
    }
    try:
        check_prefix(lines, dumps(manifest), SimpleNamespace(spec=SPEC))
    except AppendError:
        pass


@PROPERTY
@given(st.dictionaries(st.sampled_from(ROW_FIELDS), json_values, max_size=5))
def test_the_content_address_is_total(row: dict) -> None:
    """``expected_assertion_version_id`` and ``effective_current_rows`` are
    public: any JSON object gets an address or an AppendError."""

    try:
        address = expected_assertion_version_id(row, SPEC)
    except AppendError:
        return
    assert address.startswith("av2:") and len(address) == 68
    try:
        effective_current_rows([row], SPEC)
    except AppendError:
        pass


@PROPERTY
@given(
    st.lists(
        st.text(alphabet=st.characters(codec=None), max_size=6)
        | st.sampled_from(["\ud800", "a\udfffb"]),
        min_size=1,
        max_size=3,
    ),
    st.integers(min_value=0, max_value=3),
)
def test_check_prefix_refuses_any_lines_with_append_error(lines: list[str], count: int) -> None:
    """Any rows, lone surrogates included, against a well-shaped manifest:
    a row with no UTF-8 form cannot be hashed and is refused by name."""

    manifest = {
        "schemaVersion": SPEC.prefix_schema_version,
        "prefixLineCount": count,
        "lineSha256s": ["0" * 64] * count,
        "prefixSha256": "0" * 64,
    }
    try:
        check_prefix(lines, dumps(manifest), SimpleNamespace(spec=SPEC))
    except AppendError:
        pass


@PROPERTY
@given(
    st.booleans()
    | st.integers(0, 2).map(str)
    | st.floats(min_value=0, max_value=2.999999, allow_nan=False, allow_infinity=False)
)
def test_prefix_line_count_refuses_every_convertible_non_integer(value) -> None:
    """A count is a JSON integer; coercible strings, floats and booleans
    cannot borrow the hashes of the integer they would convert to."""

    lines = base_lines()[:int(value)]
    manifest = {
        "schemaVersion": SPEC.prefix_schema_version,
        "prefixLineCount": value,
        "lineSha256s": [hashlib.sha256(line.encode()).hexdigest() for line in lines],
        "prefixSha256": hashlib.sha256(
            b"".join(line.encode() + b"\n" for line in lines)
        ).hexdigest(),
    }
    with pytest.raises(AppendError) as caught:
        check_prefix(lines, dumps(manifest), SimpleNamespace(spec=SPEC))
    assert str(caught.value) == "immutable prefix manifest prefixLineCount is not a JSON integer"


@PROPERTY
@given(
    st.none()
    | st.sampled_from([float("nan"), float("inf"), -float("inf")])
    | st.text(alphabet=st.characters(categories=("L",)), min_size=1, max_size=8)
    | st.lists(st.integers(-2, 2), max_size=3)
    | st.dictionaries(st.text(max_size=3), st.integers(-2, 2), max_size=3)
)
def test_prefix_line_count_keeps_its_named_conversion_refusals(value) -> None:
    """Adding the strict integer guard preserves the PR's precise refusal
    for malformed values that ``int`` itself could never convert."""

    manifest = {
        "schemaVersion": SPEC.prefix_schema_version,
        "prefixLineCount": value,
        "lineSha256s": [],
        "prefixSha256": hashlib.sha256(b"").hexdigest(),
    }
    with pytest.raises(AppendError) as caught:
        check_prefix([], dumps(manifest), SimpleNamespace(spec=SPEC))
    assert str(caught.value) == f"prefix manifest prefixLineCount is not a line count: {value!r}"


@PROPERTY
@given(
    st.sampled_from(["measure", "source", "responseArchive"]),
    st.text(max_size=10),
    st.characters().filter(lambda character: not character.isprintable()),
    st.integers(min_value=1, max_value=10),
)
def test_malformed_row_field_refusals_escape_unprintable_record_ids(
    field: str, prefix: str, unprintable: str, value: int
) -> None:
    """The PR's new named object refusals preserve the base's escaping of
    row ids, so malformed objects cannot inject log lines or controls."""

    record_id = prefix + unprintable
    row = fixture.observation_row(3)
    row["source_record_id"] = record_id
    row[field] = value
    shown_id = "".join(
        character if character.isprintable() else repr(character)[1:-1]
        for character in record_id
    )
    with pytest.raises(AppendError) as caught:
        check_rows([dumps(row)], 0, SPEC)
    assert str(caught.value) == f"line 1 ({shown_id}) {field} is not an object"


@settings(PROPERTY, max_examples=50)
@given(st.integers(min_value=bounded_json.MAX_DEPTH, max_value=5000))
def test_deep_raw_row_filters_reach_the_named_depth_refusal(levels: int) -> None:
    """A deep JSON field reaches the gate on every Python version, without
    relying on that interpreter's encoder accepting equally deep lists."""

    row = fixture.observation_row(3)
    del row["filters"]
    line = dumps(row)[:-1] + ',"filters":' + "[" * levels + "0" + "]" * levels + "}"
    with pytest.raises(AppendError) as caught:
        check_rows([*base_lines(), line], 1, SPEC)
    assert str(caught.value).startswith(
        f"line 3 is not valid JSON: JSON nesting exceeds {bounded_json.MAX_DEPTH} levels at char "
    )


@PROPERTY
@given(
    st.sets(st.sampled_from(STATE_PATHS), min_size=1),
    st.sets(st.sampled_from(["docs/note.md", "unrelated.txt"])),
    st.sampled_from(["data", "gate", "unclassified"]),
)
def test_gate_only_refuses_every_state_change_under_every_classification(
    state_changes: set[str], other_changes: set[str], classification: str
) -> None:
    """A gate-only verdict cannot skip changed ledger state merely because
    the spec puts that path or ancestor on its DATA or GATE surface."""

    changed = state_changes | other_changes
    spec = replace(
        SPEC,
        data_surface=frozenset(changed if classification == "data" else ()),
        gate_surface=frozenset(changed if classification == "gate" else ()),
    )
    with pytest.raises(AppendError) as caught:
        check_gate_only_confinement(changed, SimpleNamespace(spec=spec))
    assert "ledger state path(s)" in str(caught.value)
