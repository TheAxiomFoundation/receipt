"""Exhaustive small-domain checks of tsa's time helpers."""
import sys
import os
sys.path.insert(0, "/Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-crash-refusal-review/scratch-review/trees/" + os.environ["TREE"] + "/src")
from datetime import datetime, timedelta, timezone
from collections import Counter
from receipt import tsa
import receipt; print('# receipt loaded from', receipt.__file__)
from receipt.tsa import TsaError
UTC = timezone.utc

# E1: _format_utc -> _parse_rfc3339 round trip, every microsecond value of one second.
base = datetime(2026, 9, 27, 12, 0, 0, tzinfo=UTC)
bad = [us for us in range(1_000_000) if not tsa._format_utc(base.replace(microsecond=us)).endswith(("Z",))]
print(f"E1 _format_utc over 1,000,000 microsecond values: {len(bad)} outputs not ending in 'Z' "
      f"(first {bad[:3]}, e.g. {(tsa._format_utc(base.replace(microsecond=bad[0])) if bad else None)!r}); microsecond 0 -> {tsa._format_utc(base)!r}")
rt = Counter()
for us in range(0, 1_000_000, 997):
    d = base.replace(microsecond=us)
    try:
        rt["round-trips" if tsa._parse_rfc3339(tsa._format_utc(d), "x") == d else "differs"] += 1
    except TsaError:
        rt["TsaError"] += 1
print("E1b round trip on 1004 sampled microsecond values:", dict(rt))

# E2: _parse_generalized_time over every 14-digit string whose fields are 2-digit-bounded:
# month 00..19, day 00..39, hour 00..29, minute 00..69, second 00..69 (year 2026 and 0000).
res = Counter(); examples = {}
for year in ("2026", "0000"):
    for mo in range(20):
        for dd in range(40):
            for hh in (0, 23, 24, 29):
                for mi in (0, 59, 60):
                    for ss in (0, 59, 60, 61, 69):
                        s = f"{year}{mo:02d}{dd:02d}{hh:02d}{mi:02d}{ss:02d}Z"
                        try:
                            tsa._parse_generalized_time(s); k = "parsed"
                        except TsaError:
                            k = "TsaError"
                        except Exception as e:
                            k = type(e).__name__
                        res[k] += 1; examples.setdefault(k, s)
print("E2 _parse_generalized_time over", sum(res.values()), "field combinations:", dict(res), "examples:", examples)

# E3: validate_token_time near datetime.min: recordedAt = 0001-01-01 + k seconds, lead 300.
res = Counter()
for k in range(0, 601):
    claim = (datetime(1, 1, 1, tzinfo=UTC) + timedelta(seconds=k)).isoformat()
    try:
        tsa.validate_token_time({"recordedAt": claim}, datetime(2026, 1, 1, tzinfo=UTC), now=datetime(2026, 9, 27, tzinfo=UTC), max_future_seconds=0, max_token_lead_seconds=300)
        res["accepted"] += 1
    except TsaError:
        res["TsaError"] += 1
    except Exception as e:
        res[type(e).__name__] += 1
print("E3 recordedAt in the first 601 s of year 1, lead 300:", dict(res))

# E4: _parse_rfc3339 at both ends of the range, every whole-hour offset -23..+23.
res = Counter()
for stamp in ("0001-01-01T00:00:00", "9999-12-31T23:59:59"):
    for h in range(-23, 24):
        v = f"{stamp}{'+' if h >= 0 else '-'}{abs(h):02d}:00"
        try:
            tsa._parse_rfc3339(v, "recordedAt"); res["parsed"] += 1
        except TsaError:
            res["TsaError"] += 1
        except Exception as e:
            res[type(e).__name__] += 1
print("E4 _parse_rfc3339 at the range ends, 94 offsets:", dict(res))
