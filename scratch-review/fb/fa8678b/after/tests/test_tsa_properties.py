"""Properties of ``receipt.tsa``'s parsers and time checks, for every input.

Each test states one property over a whole input domain and lets Hypothesis
search it. They come from the full Opus 5.5 review of 0.6.2 (leg L2), which
ran them against 0.6.1's code and found the counterexamples that the example
tests in ``tests/test_tsa.py`` now pin one by one. Runs are derandomized, so
CI explores the same examples every time and a failure is reproducible.
"""

from __future__ import annotations

from datetime import datetime, timezone

from hypothesis import HealthCheck, given, settings, strategies as st

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
