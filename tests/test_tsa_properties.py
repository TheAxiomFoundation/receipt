"""Properties of ``receipt.tsa``'s parsers and time checks, for every input.

Each test states one property over a whole input domain and lets Hypothesis
search it. They come from the full Opus 5.5 review of 0.6.2 (leg L2), which
ran them against 0.6.1's code and found the counterexamples that the example
tests in ``tests/test_tsa.py`` now pin one by one. Runs are derandomized, so
CI explores the same examples every time and a failure is reproducible.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone, tzinfo

import pytest
from hypothesis import HealthCheck, event, example, given, settings, strategies as st

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


@st.composite
def bundle_layouts(draw, signers: tuple[str, ...]):
    """One bundle's anchors: distinct ids, and disjoint signer sets, since
    ``_load_trust_bundle`` already refuses two anchors of one bundle that
    allow one signer. Built disjoint rather than filtered, so no draw is
    thrown away."""

    count = draw(st.integers(min_value=1, max_value=2))
    anchor_ids = draw(
        st.lists(st.sampled_from(ANCHOR_IDS), min_size=count, max_size=count, unique=True)
    )
    pool = list(draw(st.permutations(signers)))
    anchors = []
    for index, anchor_id in enumerate(anchor_ids):
        left_for_the_rest = count - index - 1
        size = draw(st.integers(min_value=1, max_value=min(3, len(pool) - left_for_the_rest)))
        taken, pool = pool[:size], pool[size:]
        anchors.append((anchor_id, draw(st.sampled_from(ROOTS)), frozenset(taken)))
    return anchors


# Active and pending bundles share one key only, which leaves most pending keys
# unowned by any active class, and pending bundles share keys among themselves
# often enough to give an untrusted class several occurrences. What a run
# actually reached is reported as Hypothesis events
# (``--hypothesis-show-statistics``), and the reviewer's two shapes are pinned
# by a separate test, so a refusal cannot stand in for an election.
active_layouts = bundle_layouts(("s1", "s2"))
pending_layouts = bundle_layouts(("s2", "s3", "s4", "s5"))
REVIEWER_ACTIVE = [[("A", "r1", frozenset({"s1"}))]]
SHAPE_ONE = [
    [("C", "r2", frozenset({"s3"}))],
    [("D", "r2", frozenset({"s3", "s4"}))],
    [("E", "r2", frozenset({"s3"}))],
]
ROTATION = [[("C", "r2", frozenset({"s3"}))], [("C", "r2", frozenset({"s4"}))]]
# Version numbers start at 1, 7, 8 or 9, so runs cross from one digit to two
# and the bundle path that sorts last as a string is not always the newest.
FIRST_VERSIONS = (1, 7, 8, 9)


def bundle_reference(version: int) -> dict[str, str]:
    return {
        "bundleId": f"tsa-anchors-v{version}",
        "path": f"records/trust/tsa-anchors-v{version}.json",
    }


def elected_by_oracle(
    bundles: list[tuple[int, bool, list[tuple[str, str, frozenset[str]]]]],
) -> dict[tuple[str, str], tuple[dict[str, str], dict[str, str]]]:
    """Connected authorities through shared keys; newest of each untrusted class.

    Returns what ``_supplemental_candidates`` returns: for each candidate's
    ``(bundle path, anchor ID)``, that occurrence's own bundle reference and
    anchor, which is what a supplemental outcome is then verified against.
    """

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
    elected = {}
    for members in classes.values():
        if any(active for *_rest, active in members):
            continue
        version, anchor_id, _root, _active = max(members)
        reference = bundle_reference(version)
        elected[(reference["path"], anchor_id)] = (reference, {"id": anchor_id})
    return elected


def run_election(active: list, pending: list, *, first_version: int, order=None):
    """The real graph, classification and election over synthetic bundles.

    Returns the candidates (or the refusal text), the same for the pending
    updates in shuffled order when ``order`` is given, the classification's
    own answer (``None`` when it admits the layout, else its refusal text),
    and the layout the oracle reads.

    The classification is run on its own so a caller decides admission from
    it, never from the election: an election that refuses a layout the
    classification admits is a broken election, not a refused shape.
    """

    from unittest import mock

    layouts = {}
    bundles = []
    for version, anchors in enumerate([*active, *pending], start=first_version):
        layouts[bundle_reference(version)["path"]] = anchors
        bundles.append((version, version < first_version + len(active), anchors))
    trusted = {
        bundle_reference(version)["path"]: bundle_reference(version)
        for version in range(first_version, first_version + len(active))
    }
    updates = [
        bundle_reference(version)
        for version in range(
            first_version + len(active), first_version + len(active) + len(pending)
        )
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

    def elected(walked: list[dict[str, str]]) -> dict | str:
        try:
            return dict(tsa._supplemental_candidates(None, trusted, walked, spec=None))
        except tsa.TsaError as exc:
            return str(exc)

    def classified(walked: list[dict[str, str]]) -> str | None:
        try:
            tsa._build_authority_history(None, trusted, walked, spec=None)
        except tsa.TsaError as exc:
            return str(exc)
        return None

    with mock.patch.object(tsa, "_anchor_occurrences", occurrences):
        result = elected(updates)
        refusal = classified(updates)
        reordered = None
        if order is not None:
            shuffled = list(updates)
            order.shuffle(shuffled)
            reordered = elected(shuffled)
    return result, reordered, refusal, bundles


@settings(PROPERTY, max_examples=300)
@given(
    active=st.lists(active_layouts, min_size=1, max_size=2),
    pending=st.lists(pending_layouts, min_size=2, max_size=4),
    first_version=st.sampled_from(FIRST_VERSIONS),
    order=st.randoms(use_true_random=False),
)
# Shapes run first on every Hypothesis version, so the mutants they catch do
# not depend on what a derandomized run happens to draw. The first is a
# pending-only class spanning two roots: a reused ID under a new root, then a
# rename onto the old root. The second is one class in two pending bundles,
# versions 9 and 10, where the bundle path that sorts last is not the newest.
@example(
    active=[[("A", "r1", frozenset({"s1"}))]],
    pending=[[("A", "r2", frozenset({"s2"}))], [("B", "r1", frozenset({"s2"}))]],
    first_version=1,
    order=random.Random(0),
)
@example(
    active=[[("A", "r2", frozenset({"s1"}))], [("A", "r2", frozenset({"s1"}))]],
    pending=[[("A", "r1", frozenset({"s2"}))], [("A", "r1", frozenset({"s2"}))]],
    first_version=7,
    order=random.Random(0),
)
def test_a_pending_only_class_elects_exactly_its_newest_occurrence(
    active: list, pending: list, first_version: int, order
) -> None:
    """Each untrusted class's one candidate is its newest occurrence, whole.

    The key, and the bundle and anchor it carries, agree with the oracle for
    every shape the classification admits; a shape it refuses is refused in
    the same words in any update order.

    Admission is the classification's answer, asked separately. The election
    may refuse only with the classification's own refusal, so an election
    that wrongly refuses an admitted shape fails here rather than being
    counted as a refused shape.
    """

    result, reordered, refusal, bundles = run_election(
        active, pending, first_version=first_version, order=order
    )
    assert reordered == result
    if refusal is not None:
        event("refused by the classification")
        assert result == refusal
        return
    assert isinstance(result, dict), f"election refused an admitted shape: {result}"
    expected = elected_by_oracle(bundles)
    event(f"admitted with {len(expected)} candidate(s)")
    assert result == expected


@pytest.mark.parametrize("first_version", FIRST_VERSIONS)
@pytest.mark.parametrize(
    ("pending", "newest"),
    [(SHAPE_ONE, "E"), (ROTATION, "C")],
    ids=["three-bundle-class", "rotation"],
)
def test_the_reviewer_shapes_are_admitted_and_elect_their_newest_occurrence(
    pending: list, newest: str, first_version: int
) -> None:
    """#50's two shapes: E alone, then C at its newest version alone.

    Asserted outright, so the property's admitted-shapes-only comparison
    cannot hide a classification that refuses them.
    """

    result, _reordered, refusal, bundles = run_election(
        REVIEWER_ACTIVE, pending, first_version=first_version
    )
    assert refusal is None
    reference = bundle_reference(first_version + len(REVIEWER_ACTIVE) + len(pending) - 1)
    assert result == {(reference["path"], newest): (reference, {"id": newest})}
    assert result == elected_by_oracle(bundles)


# ---------------------------------------------------------------------------
# One reading of each offset decides the instant (delta review of #83,
# findings 7 and 10).


class ScriptedZone(tzinfo):
    """A tzinfo whose ``utcoffset`` gives ``answers`` in turn, then the last
    one ever after; ``calls`` counts how often it was asked."""

    def __init__(self, *answers: object) -> None:
        self.answers = answers
        self.calls = 0

    def utcoffset(self, dt: datetime | None) -> object:
        answer = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        return answer

    def dst(self, dt: datetime | None) -> None:
        return None

    def tzname(self, dt: datetime | None) -> str:
        return "scripted"

    def __repr__(self) -> str:
        return f"ScriptedZone{self.answers!r}"


DAY = timedelta(hours=24)
valid_offsets = st.timedeltas(
    min_value=-DAY + timedelta(microseconds=1), max_value=DAY - timedelta(microseconds=1)
)
offset_answers = (
    valid_offsets
    | st.none()
    | st.timedeltas(min_value=DAY, max_value=3 * DAY)
    | st.timedeltas(min_value=-3 * DAY, max_value=-DAY)
    | st.integers(min_value=-(10**6), max_value=10**6)
    | st.text(max_size=8)
)
walls = st.datetimes(
    min_value=datetime(1, 1, 1),
    max_value=datetime(9999, 12, 31, 23, 59, 59, 999999),
)


@PROPERTY
@given(
    st.sampled_from(["now", "gen_time"]),
    walls,
    st.lists(offset_answers, min_size=1, max_size=4),
    mid_range,
    allowances,
    allowances,
)
def test_validate_token_time_decides_on_one_reading_of_each_offset(
    field: str,
    wall: datetime,
    answers: list[object],
    other: datetime,
    future: int,
    lead: int,
) -> None:
    """However a tzinfo's answers change from call to call,
    ``validate_token_time`` asks it once, raises nothing but TsaError, and
    decides exactly as it does for a fixed zone carrying that one answer: a
    ``None`` refuses as naive and an answer ``datetime`` rejects refuses by
    name. Before, the aware check and ``astimezone`` each asked, a second
    ``None`` read the time as the process's local time, and a rejected
    answer escaped as ``ValueError`` or ``TypeError``."""

    def decide(value: datetime) -> str | None:
        arguments = {"now": other, "gen_time": other, field: value}
        try:
            tsa.validate_token_time(
                {"recordedAt": other.isoformat()},
                **arguments,
                max_future_seconds=future,
                max_token_lead_seconds=lead,
            )
        except tsa.TsaError as exc:
            return str(exc)
        return None

    zone = ScriptedZone(*answers)
    value = wall.replace(tzinfo=zone)
    actual = decide(value)
    assert zone.calls == 1
    label = "verification time" if field == "now" else "RFC 3161 genTime"
    first = answers[0]
    if first is None:
        assert actual == f"{label} must be a timezone-aware datetime: {value!r}"
    elif not isinstance(first, timedelta) or abs(first) >= DAY:
        assert actual == f"{label} has no valid UTC offset: {value!r}"
    else:
        fixed = wall.replace(tzinfo=timezone(first))
        expected = decide(fixed)
        if expected is not None:
            expected = expected.replace(repr(fixed), repr(value))
        assert actual == expected
