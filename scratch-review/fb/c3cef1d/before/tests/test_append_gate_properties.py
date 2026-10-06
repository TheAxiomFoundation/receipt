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
from types import SimpleNamespace

from hypothesis import HealthCheck, given, settings, strategies as st

import test_append_gate as fixture
from receipt.append_gate import (
    AppendError,
    check_prefix,
    check_rows,
    effective_current_rows,
    expected_assertion_version_id,
)

SPEC = fixture.GATE_SPEC
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
