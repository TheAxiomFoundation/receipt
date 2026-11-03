"""Properties of ``receipt.tsa``'s parsers and time checks, for every input.

Each test states one property over a whole input domain and lets Hypothesis
search it. They come from the full Opus 5.5 review of 0.6.2 (leg L2), which
ran them against 0.6.1's code and found the counterexamples that the example
tests in ``tests/test_tsa.py`` now pin one by one. Runs are derandomized, so
CI explores the same examples every time and a failure is reproducible.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import HealthCheck, example, given, settings, strategies as st

from receipt import tsa

UTC = timezone.utc
PROPERTY = settings(
    max_examples=500,
    deadline=None,
    derandomize=True,
    suppress_health_check=list(HealthCheck),
)

aware_datetimes = st.datetimes(
    min_value=datetime(1, 1, 1),
    max_value=datetime(9999, 12, 31, 23, 59, 59, 999999),
).map(lambda value: value.replace(tzinfo=UTC))


def generalized_time(value: datetime) -> str:
    """DER GeneralizedTime for ``value``: no trailing zeros in the fraction."""

    text = value.strftime("%m%d%H%M%S")
    text = f"{value.year:04d}{text}"
    if value.microsecond:
        text += "." + f"{value.microsecond:06d}".rstrip("0")
    return text + "Z"


@PROPERTY
@given(aware_datetimes)
def test_gentime_parse_format_and_rfc3339_parse_round_trip(value: datetime) -> None:
    """GeneralizedTime -> datetime -> ``_format_utc`` -> ``_parse_rfc3339`` is
    the identity, fraction included (L2 I6: failed at the first nonzero
    microsecond, whose formatted form ended ``+00:``)."""

    parsed = tsa._parse_generalized_time(generalized_time(value))
    assert parsed == value
    formatted = tsa._format_utc(parsed)
    assert formatted.endswith("Z") and "+" not in formatted
    assert tsa._parse_rfc3339(formatted, "genTime") == value


# ---------------------------------------------------------------------------
# The TSTInfo parser is total: it returns or raises TsaError (L2 F2).


def der_length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def der(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_length(len(body)) + body


def oid_body(arcs: list[int]) -> bytes:
    encoded = b""
    for value in [arcs[0] * 40 + arcs[1], *arcs[2:]]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        encoded += bytes(reversed(chunk))
    return encoded


def tst_info(gen_time: bytes, policy: bytes = oid_body([1, 3, 6, 1, 4, 1, 99999, 1, 1])) -> bytes:
    algorithm = der(0x30, der(0x06, oid_body([2, 16, 840, 1, 101, 3, 4, 2, 1])) + b"\x05\x00")
    imprint = der(0x30, algorithm + der(0x04, b"\x00" * 32))
    return der(
        0x30,
        der(0x02, b"\x01") + der(0x06, policy) + imprint + der(0x02, b"\x07") + der(0x18, gen_time),
    )


@PROPERTY
@given(st.binary(max_size=64), st.integers(min_value=0, max_value=70))
def test_read_der_tlv_is_total_and_stays_inside_its_input(data: bytes, offset: int) -> None:
    try:
        _tag, content, end = tsa._read_der_tlv(data, offset)
    except tsa.TsaError:
        return
    assert end <= len(data)
    assert data[end - len(content) : end] == content


@PROPERTY
@given(st.binary(max_size=200))
def test_parse_tst_info_is_total_on_arbitrary_bytes(data: bytes) -> None:
    try:
        tsa._parse_tst_info(data)
    except tsa.TsaError:
        pass


@PROPERTY
@given(st.from_regex(r"\A[0-9]{14}(\.[0-9]{1,9})?Z\Z", fullmatch=True))
def test_parse_tst_info_is_total_on_every_grammatical_gentime(text: str) -> None:
    """Every genTime the grammar admits either parses to its own calendar
    fields or is refused (L2 I3: '00000110000000Z' and 93,080 of 96,000
    enumerated field combinations raised ValueError)."""

    try:
        parsed = tsa._parse_tst_info(tst_info(text.encode()))[3]
    except tsa.TsaError:
        return
    assert parsed.strftime("%m%d%H%M%S") == text[4:14]
    assert f"{parsed.year:04d}" == text[:4]


oid_arcs = st.one_of(
    st.tuples(st.integers(0, 1), st.integers(0, 39)),
    st.tuples(st.just(2), st.integers(0, 2**70)),
).flatmap(
    lambda head: st.lists(st.integers(0, 2**80), max_size=8).map(
        lambda tail: [*head, *tail]
    )
)


@PROPERTY
@given(oid_arcs)
def test_decode_oid_round_trips_der(arcs: list[int]) -> None:
    assert tsa._decode_oid(oid_body(arcs)) == ".".join(map(str, arcs))


@PROPERTY
@given(oid_arcs, oid_arcs)
def test_decode_oid_is_injective_on_der(first: list[int], second: list[int]) -> None:
    if oid_body(first) != oid_body(second):
        assert tsa._decode_oid(oid_body(first)) != tsa._decode_oid(oid_body(second))


@PROPERTY
@given(st.binary(max_size=64) | st.integers(1, 2400).map(lambda n: b"\x2b" + b"\xff" * n + b"\x7f"))
def test_decode_oid_is_total(data: bytes) -> None:
    """Any content octets decode or are refused by name, including one
    subidentifier long enough that its decimal form passes 4,300 digits."""

    try:
        text = tsa._decode_oid(data)
    except tsa.TsaError:
        return
    assert all(part.isdigit() for part in text.split("."))


# ---------------------------------------------------------------------------
# The time checks decide every in-range input (L2 F3).

allowances = st.integers(min_value=0, max_value=10**6) | st.integers(min_value=0, max_value=10**40)
rfc3339_claims = st.tuples(
    aware_datetimes, st.integers(min_value=-23 * 60, max_value=23 * 60)
).map(
    lambda pair: pair[0].replace(tzinfo=None).isoformat()
    + ("Z" if pair[1] == 0 else f"{'+' if pair[1] > 0 else '-'}{abs(pair[1]) // 60:02d}:{abs(pair[1]) % 60:02d}")
)


@PROPERTY
@given(rfc3339_claims, aware_datetimes, aware_datetimes, allowances, allowances)
def test_validate_token_time_is_total(
    claim: str, gen_time: datetime, now: datetime, future: int, lead: int
) -> None:
    """Any claim spelled with any offset, any genTime and any verification
    time in years 1-9999, and any allowance: accepted or TsaError (L2 I7, E3,
    E4: 300 of 601 claims in year 1's first ten minutes and 46 of 94
    range-end offsets raised OverflowError)."""

    try:
        tsa.validate_token_time(
            {"recordedAt": claim},
            gen_time,
            now=now,
            max_future_seconds=future,
            max_token_lead_seconds=lead,
        )
    except tsa.TsaError:
        pass


mid_range = st.datetimes(min_value=datetime(2000, 1, 1), max_value=datetime(2100, 1, 1)).map(
    lambda value: value.replace(tzinfo=UTC)
)


whole_seconds = st.booleans()


@PROPERTY
@given(
    mid_range,
    mid_range,
    mid_range,
    st.integers(0, 10**8),
    st.integers(0, 10**8),
    whole_seconds,
)
def test_validate_token_time_decides_as_the_shifted_form_did_wherever_it_could(
    claim: datetime,
    gen_time: datetime,
    now: datetime,
    future: int,
    lead: int,
    whole: bool,
) -> None:
    """Differential against 0.6.1's comparisons, over inputs where they could
    not overflow: the same verdict, the same refusal, and -- for whole-second
    instants, which 0.6.1 already rendered correctly -- the same text. (A
    fractional instant now renders as ``...Z`` where 0.6.1 wrote ``...+00:``;
    that change is the L2 F1 fix, pinned in tests/test_tsa.py.)"""

    if whole:
        claim, gen_time, now = (value.replace(microsecond=0) for value in (claim, gen_time, now))

    def rendered(value: datetime) -> str:
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")

    if gen_time > now + timedelta(seconds=future):
        expected = f"RFC 3161 genTime {rendered(gen_time)} postdates verification time {rendered(now)}"
    elif gen_time < claim - timedelta(seconds=lead):
        expected = (
            f"RFC 3161 genTime {rendered(gen_time)} impossibly precedes "
            f"recordedAt={rendered(claim)}"
        )
    else:
        expected = None
    try:
        tsa.validate_token_time(
            {"recordedAt": claim.isoformat()},
            gen_time,
            now=now,
            max_future_seconds=future,
            max_token_lead_seconds=lead,
        )
        actual = None
    except tsa.TsaError as exc:
        actual = str(exc)
    if expected is None or actual is None:
        assert actual == expected
    elif whole:
        assert actual == expected
    else:
        assert actual.split(" ")[4] == expected.split(" ")[4]


@PROPERTY
@given(
    mid_range,
    mid_range,
    mid_range,
    st.integers(0, 10**6),
    st.integers(0, 10**6),
    st.integers(0, 10**8),
    st.integers(0, 10**8),
    st.integers(0, 10**8),
)
def test_validate_token_time_acceptance_is_monotone(
    claim: datetime,
    gen_time: datetime,
    now: datetime,
    future: int,
    lead: int,
    d_now: int,
    d_future: int,
    d_lead: int,
) -> None:
    """Acceptance survives a later ``now``, a larger future allowance and a
    larger lead (L2 I8)."""

    def accepted(at: datetime, future_seconds: int, lead_seconds: int) -> bool:
        try:
            tsa.validate_token_time(
                {"recordedAt": claim.isoformat()},
                gen_time,
                now=at,
                max_future_seconds=future_seconds,
                max_token_lead_seconds=lead_seconds,
            )
        except tsa.TsaError:
            return False
        return True

    if accepted(now, future, lead):
        assert accepted(now + timedelta(seconds=d_now), future + d_future, lead + d_lead)


@PROPERTY
@given(st.sampled_from(["now", "gen_time"]), st.datetimes())
def test_validate_token_time_refuses_every_naive_instant(field: str, value: datetime) -> None:
    """Neither the verification time nor the authority's time may depend
    on the process's local timezone or escape as a datetime TypeError."""

    valid = datetime(2026, 9, 27, 12, tzinfo=UTC)
    arguments = {"now": valid, "gen_time": valid}
    arguments[field] = value
    label = "verification time" if field == "now" else "RFC 3161 genTime"
    with pytest.raises(tsa.TsaError) as caught:
        tsa.validate_token_time(
            {"recordedAt": valid.isoformat()},
            **arguments,
            max_future_seconds=10**40,
            max_token_lead_seconds=10**40,
        )
    assert str(caught.value) == f"{label} must be a timezone-aware datetime: {value!r}"


@PROPERTY
@given(
    st.sampled_from(["now", "gen_time"]),
    st.booleans(),
    st.integers(min_value=1, max_value=23 * 60 + 59),
    st.integers(min_value=0, max_value=999999),
)
def test_validate_token_time_refuses_every_instant_outside_utc_range(
    field: str, lower: bool, offset_minutes: int, microsecond: int
) -> None:
    """Aware wall-clock datetimes whose UTC instants fall beyond years
    1-9999 get the base's named refusal before any difference is measured."""

    if lower:
        value = datetime(1, 1, 1, microsecond=microsecond).replace(
            tzinfo=timezone(timedelta(minutes=offset_minutes))
        )
    else:
        value = datetime(9999, 12, 31, 23, 59, 59, microsecond).replace(
            tzinfo=timezone(-timedelta(minutes=offset_minutes))
        )
    valid = datetime(2026, 9, 27, 12, tzinfo=UTC)
    arguments = {"now": valid, "gen_time": valid}
    arguments[field] = value
    label = "verification time" if field == "now" else "RFC 3161 genTime"
    with pytest.raises(tsa.TsaError) as caught:
        tsa.validate_token_time(
            {"recordedAt": valid.isoformat()},
            **arguments,
            max_future_seconds=10**40,
            max_token_lead_seconds=10**40,
        )
    assert str(caught.value) == f"{label} is outside the representable UTC range: {value!r}"


# ---------------------------------------------------------------------------
# The pending-only election (#50). For every shape the classifier admits, a
# class nothing trusts yet contributes exactly one candidate, its newest
# occurrence, whatever keys its other occurrences carry; and the candidates
# do not depend on the order the pending updates arrive in. Bundles are
# synthetic: ``_anchor_occurrences`` is the one place they are read, so
# replacing it runs the real graph, classification and election on any
# layout. The oracle below rebuilds the classes independently.

ANCHOR_IDS = ("A", "B", "C", "D")
ROOTS = ("r1", "r2")


def bundle_layouts(signers: tuple[str, ...]):
    """One bundle's anchors: distinct ids, no signer shared between two of
    them, which ``_load_trust_bundle`` already refuses within a bundle."""

    anchor = st.tuples(
        st.sampled_from(ANCHOR_IDS),
        st.sampled_from(ROOTS),
        st.frozensets(st.sampled_from(signers), min_size=1, max_size=3),
    )
    return st.lists(
        anchor, min_size=1, max_size=2, unique_by=lambda layout: layout[0]
    ).filter(
        lambda anchors: all(
            not first[2] & second[2]
            for index, first in enumerate(anchors)
            for second in anchors[index + 1:]
        )
    )


# Active and pending bundles overlap in one key only, so most draws leave some
# class with no active member, and pending bundles share keys among
# themselves often enough to give such a class several occurrences.
active_layouts = bundle_layouts(("s1", "s2"))
pending_layouts = bundle_layouts(("s2", "s3", "s4", "s5"))
REVIEWER_ACTIVE = [[("A", "r1", frozenset({"s1"}))]]
SHAPE_ONE = [
    [("C", "r2", frozenset({"s3"}))],
    [("D", "r2", frozenset({"s3", "s4"}))],
    [("E", "r2", frozenset({"s3"}))],
]
ROTATION = [[("C", "r2", frozenset({"s3"}))], [("C", "r2", frozenset({"s4"}))]]


def bundle_reference(version: int) -> dict[str, str]:
    return {
        "bundleId": f"tsa-anchors-v{version}",
        "path": f"records/trust/tsa-anchors-v{version}.json",
    }


def elected_by_oracle(
    bundles: list[tuple[int, bool, list[tuple[str, str, frozenset[str]]]]],
) -> set[tuple[str, str]]:
    """Connected authorities through shared keys; newest of each untrusted class."""

    parent: dict[tuple[str, str], tuple[str, str]] = {}

    def find(node: tuple[str, str]) -> tuple[str, str]:
        parent.setdefault(node, node)
        while parent[node] != node:
            node = parent[node]
        return node

    owner: dict[str, tuple[str, str]] = {}
    occurrences = []
    for version, active, anchors in bundles:
        for anchor_id, root, signers in anchors:
            node = (anchor_id, root)
            find(node)
            for signer in signers:
                if signer in owner:
                    parent[find(node)] = find(owner[signer])
                else:
                    owner[signer] = node
            occurrences.append((version, anchor_id, root, active))
    classes: dict[tuple[str, str], list[tuple[int, str, str, bool]]] = {}
    for occurrence in occurrences:
        classes.setdefault(find(occurrence[1:3]), []).append(occurrence)
    elected = set()
    for members in classes.values():
        if any(active for *_rest, active in members):
            continue
        version, anchor_id, _root, _active = max(members)
        elected.add((bundle_reference(version)["path"], anchor_id))
    return elected


@settings(PROPERTY, max_examples=300)
@given(
    active=st.lists(active_layouts, min_size=1, max_size=2),
    pending=st.lists(pending_layouts, min_size=2, max_size=4),
    order=st.randoms(use_true_random=False),
)
@example(active=REVIEWER_ACTIVE, pending=SHAPE_ONE, order=random.Random(0))
@example(active=REVIEWER_ACTIVE, pending=ROTATION, order=random.Random(0))
def test_a_pending_only_class_elects_exactly_its_newest_occurrence(
    active: list, pending: list, order
) -> None:
    """The reviewer's two shapes are examples: E@v4 alone, then C@v3 alone."""

    from unittest import mock

    layouts = {}
    bundles = []
    for version, anchors in enumerate([*active, *pending], start=1):
        layouts[bundle_reference(version)["path"]] = anchors
        bundles.append((version, version <= len(active), anchors))
    trusted = {
        bundle_reference(version)["path"]: bundle_reference(version)
        for version in range(1, len(active) + 1)
    }
    updates = [
        bundle_reference(version)
        for version in range(len(active) + 1, len(active) + len(pending) + 1)
    ]

    def occurrences(_records, reference, *, active, spec):
        del spec
        built = [
            tsa._AnchorOccurrence(
                reference=reference,
                anchor={"id": anchor_id},
                path=reference["path"],
                version=tsa._pending_bundle_version(reference),
                authority=(anchor_id, root),
                signers=signers,
                active=active,
            )
            for anchor_id, root, signers in layouts[reference["path"]]
        ]
        return tuple(sorted(built, key=lambda occurrence: occurrence.order))

    def elected(walked: list[dict[str, str]]) -> set[tuple[str, str]] | str:
        try:
            return set(tsa._supplemental_candidates(None, trusted, walked, spec=None))
        except tsa.TsaError as exc:
            return str(exc)

    with mock.patch.object(tsa, "_anchor_occurrences", occurrences):
        result = elected(updates)
        shuffled = list(updates)
        order.shuffle(shuffled)
        assert elected(shuffled) == result
    if isinstance(result, set):
        assert result == elected_by_oracle(bundles)
