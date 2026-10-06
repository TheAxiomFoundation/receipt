"""Generate differential inputs for the append-gate pure functions.

Run once (under either tree; only the fixture rows are used, and those rows'
addresses are the same at both trees). Writes inputs.jsonl: one case per line,
{"id", "fn", ...args}. Lines/rows are carried as JSON text (ensure_ascii, so
lone surrogates survive the round trip).
"""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import os
import pathlib
import random
import sys

HERE = pathlib.Path(__file__).resolve().parent
TREE = pathlib.Path(os.environ["TREE"])
sys.path.insert(0, str(TREE / "tests"))
import test_append_gate as t  # noqa: E402
import receipt  # noqa: E402

print("receipt from", receipt.__file__, file=sys.stderr)

SPEC = t.GATE_SPEC
SCHEMA = SPEC.prefix_schema_version
OUT = HERE / "inputs.jsonl"
cases: list[dict] = []


def add(fn: str, **kw) -> None:
    kw["id"] = f"{fn}:{len(cases)}"
    kw["fn"] = fn
    cases.append(kw)


def dumps(v) -> str:
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"), allow_nan=True)


def nested(levels, leaf=0, kind="list"):
    v = leaf
    for _ in range(levels):
        v = [v] if kind == "list" else {"k": v}
    return v


def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()


ROWS = [t.observation_row(n) for n in range(1, 5)]
LINES = [t.jsonl_line(r) for r in ROWS]

# --------------------------------------------------------------- check_prefix
COUNTS = [
    0, 1, 2, 3, -1, True, False, 1.0, 1.9, 0.5, 2.5, -0.0, 0.0, "1", " 1 ", "\uff11",
    "1_0", "0", "-0", "+1", "\u0662", "01", 1e0, None, "x", [], {}, [1], {"n": 1},
    float("nan"), float("inf"), float("-inf"), 10**20, "1.0", "2", "0x1", "1\n",
    "\t2\t", "0_1", "  0  ", "\u0660", 2**63, -(2**63), 1e-300,
]


def as_count(c):
    try:
        k = int(c)
    except Exception:
        return None
    return k


def hash_forms(k: int, lines: list[str]):
    good = [sha(x) for x in lines[:max(k, 0)]]
    forms = {
        "correct": good,
        "upper": [h.upper() for h in good],
        "short": good[:-1] if good else [],
        "long": good + ["0" * 64],
        "wrong0": (["0" * 64] + good[1:]) if good else [],
        "wronglast": (good[:-1] + ["0" * 64]) if good else [],
        "string": "a" * max(k, 0),
        "string_hash_concat": "".join(good),
        "object": {str(i): h for i, h in enumerate(good)},
        "null": None,
        "number": 5,
        "true": True,
        "nonstr": [1] * max(k, 0),
        "nested": [[h] for h in good],
    }
    return forms


def cum_forms(k: int, lines: list[str]):
    k = max(k, 0)
    sel = lines[:k]
    new = hashlib.sha256(b"".join(x.encode("utf-8", "surrogatepass") + b"\n" for x in sel)).hexdigest()
    old = hashlib.sha256(("\n".join(sel) + "\n").encode("utf-8", "surrogatepass")).hexdigest()
    return {
        "new": new,
        "old": old,
        "empty": hashlib.sha256(b"").hexdigest(),
        "wrong": "0" * 64,
        "upper": new.upper(),
        "null": None,
        "number": 0,
        "__absent__": "__absent__",
    }


line_sets = {
    "base2": LINES[:2],
    "one": LINES[:1],
    "zero": [],
    "three": LINES[:3],
}
for (ls_name, lines), count in itertools.product(line_sets.items(), COUNTS):
    k = as_count(count)
    kk = k if k is not None else 1
    kk = max(min(kk, 5), -1)
    for hname, hashes in hash_forms(kk, lines).items():
        for cname, cum in cum_forms(kk, lines).items():
            manifest = {"schemaVersion": SCHEMA, "prefixLineCount": count, "lineSha256s": hashes}
            if cum != "__absent__":
                manifest["prefixSha256"] = cum
            add("check_prefix", lines=lines, prefix_text=dumps(manifest) + "\n",
                note=f"{ls_name}/count={count!r}/hashes={hname}/cum={cname}")

# key-order / key-absence variants
for missing in ("schemaVersion", "prefixLineCount", "lineSha256s", "prefixSha256"):
    for count in (0, 1, 2):
        manifest = {"schemaVersion": SCHEMA, "prefixLineCount": count,
                    "lineSha256s": [sha(x) for x in LINES[:count]],
                    "prefixSha256": cum_forms(count, LINES)["new"]}
        manifest.pop(missing)
        add("check_prefix", lines=LINES[:2], prefix_text=dumps(manifest), note=f"missing {missing} count={count}")

# schema variants
for schema in (None, 1, [SCHEMA], SCHEMA + " ", SCHEMA.upper(), {"a": 1}, nested(127), nested(130)):
    manifest = {"schemaVersion": schema, "prefixLineCount": 1, "lineSha256s": [sha(LINES[0])],
                "prefixSha256": cum_forms(1, LINES)["new"]}
    add("check_prefix", lines=LINES[:2], prefix_text=dumps(manifest), note=f"schema={str(schema)[:30]}")

# non-object manifests and malformed text
for text in ["", " ", "null", "[]", "[1,2]", "1", "\"x\"", "true", "{", "{}", "{}{}", "NaN", "Infinity",
             "[" * 129 + "]" * 129, "[" * 128 + "]" * 128, "[" * 5000 + "]" * 5000, "[" * 5000,
             "9" * 5000, "{\"schemaVersion\":" + "9" * 4301 + "}", "{\"a\":1}\n\n", "\ufeff{}",
             dumps({"schemaVersion": SCHEMA, "prefixLineCount": 1, "lineSha256s": [sha(LINES[0])],
                    "prefixSha256": cum_forms(1, LINES)["new"], "extra": nested(128)}),
             dumps({"schemaVersion": SCHEMA, "prefixLineCount": 1, "lineSha256s": [sha(LINES[0])],
                    "prefixSha256": cum_forms(1, LINES)["new"], "extra": nested(127)}),
             dumps({"schemaVersion": SCHEMA, "prefixLineCount": 1, "lineSha256s": [sha(LINES[0])],
                    "prefixSha256": cum_forms(1, LINES)["new"], "extra": int("9" * 4300)}),
             dumps({"schemaVersion": SCHEMA, "prefixLineCount": 1, "lineSha256s": [sha(LINES[0])],
                    "prefixSha256": cum_forms(1, LINES)["new"]}).replace("1,", "1 ,", 1),
             ]:
    add("check_prefix", lines=LINES[:2], prefix_text=text, note=f"text={text[:40]!r}")

# Rewritten prefix line labels: manifest pins LINES[0], lines[0] replaced.
m1 = dumps({"schemaVersion": SCHEMA, "prefixLineCount": 1, "lineSha256s": [sha(LINES[0])],
            "prefixSha256": cum_forms(1, LINES)["new"]})
m2 = dumps({"schemaVersion": SCHEMA, "prefixLineCount": 2, "lineSha256s": [sha(x) for x in LINES[:2]],
            "prefixSha256": cum_forms(2, LINES)["new"]})
REWRITES = [
    "garbage", "[1]", "null", "1", "\"s\"", "true", "{\"x\":1}", "{}",
    "{\"source_record_id\":null}", "{\"source_record_id\":5}", "{\"source_record_id\":\"\"}",
    "{\"source_record_id\":{\"a\":[1]}}", "{\"source_record_id\":[1,2]}",
    "{\"source_record_id\":\"a\",\"source_record_id\":\"b\"}",
    "{\"source_record_id\":1e400}", "{\"source_record_id\":NaN}", "{\"source_record_id\":-0}",
    "{\"source_record_id\":" + "9" * 4300 + "}",
    "{\"source_record_id\":" + "9" * 4301 + "}",
    "{\"source_record_id\":\"id\",\"n\":" + "9" * 5000 + "}",
    "{\"source_record_id\":\"id\",\"deep\":" + "[" * 200 + "]" * 200 + "}",
    "{\"source_record_id\":\"id\",\"deep\":" + "[" * 5000 + "]" * 5000 + "}",
    "{\"source_record_id\":\"id\",\"deep\":" + "[" * 100000 + "]" * 100000 + "}",
    "[" * 100000 + "]" * 100000,
    "{\"source_record_id\":\"id\"} trailing",
    " {\"source_record_id\":\"id\"}",
    "{\"source_record_id\":\"\\ud800\"}",
    "{\"source_record_id\":\"\ud800\"}",
    "\ud800",
    "{\"source_record_id\":\"id\",\"x\":\"" + "a" * 1_000_000 + "\"}",
    LINES[0] + " ",
    LINES[0].replace("fixture.series.observation_1", "fixture.series.observation_X"),
    LINES[1],
]
for rw in REWRITES:
    for idx, manifest in ((0, m1), (0, m2), (1, m2)):
        lines = list(LINES[:3])
        lines[idx] = rw
        add("check_prefix", lines=lines, prefix_text=manifest, note=f"rewrite idx={idx} {rw[:40]!r}")

# ----------------------------------------------------------- check_append_only
for rw in REWRITES:
    base_lines = list(LINES[:2])
    base_lines[1] = rw
    cand = list(LINES[:3])
    add("check_append_only", base_text="".join(x + "\n" for x in base_lines), lines=cand,
        note=f"base line 2 {rw[:40]!r}")
    add("check_append_only", base_text="".join(x + "\n" for x in base_lines), lines=base_lines + [LINES[2]],
        note=f"base line 2 unchanged {rw[:40]!r}")

# ----------------------------------------------------------------- check_rows
FIELD_VALUES = [
    None, 0, 0.0, -0.0, "", [], {}, False, True, 1, -1, 1.5, "x", [1], ["x"], {"a": 1},
    {"unit": "percent"}, {"sha256": "0" * 64}, float("nan"), float("inf"), float("-inf"),
    2**53 + 1, 2**1100, -(2**1100), int("9" * 4300), 1e308, nested(126), nested(127), nested(128),
    nested(200), {"unit": float("nan")}, {"unit": 2**1100}, {"sha256": float("nan")},
    {"source_sha256": float("inf")}, {"concept": nested(126, kind="dict")},
    "\ud800",
]
FIELDS = [
    "source_record_id", "value", "observed_at", "measure", "source", "responseArchive",
    "assertionVersion", "retrievedAt", "ledgerRepoSha", "sourceVintage", "sourceBindingProjection",
    "targetContentHash", "filters", "period", "source_row_keys", "source_cell_keys", "note",
]


def eavi_or_none(row):
    from receipt.append_gate import expected_assertion_version_id, AppendError
    try:
        return expected_assertion_version_id(row, SPEC)
    except Exception:
        return None


def encode_line(row):
    try:
        return json.dumps(row, ensure_ascii=False, separators=(",", ":"), allow_nan=True)
    except Exception:
        return None


for field, value, position, recompute in itertools.product(FIELDS, FIELD_VALUES, (1, 3), (True, False)):
    row = copy.deepcopy(ROWS[position - 1])
    row[field] = value
    if recompute and field != "assertionVersion":
        rid = eavi_or_none(row)
        row["assertionVersion"] = {"id": rid if rid else "av2:" + "0" * 64}
    line = encode_line(row)
    if line is None:
        continue
    lines = list(LINES[:3])
    lines[position - 1] = line
    for pc in (1, 3) if position == 1 else (1,):
        add("check_rows", lines=lines, prefix_count=pc, note=f"{field}={str(value)[:30]} pos={position} rc={recompute}")

# two-field combos, to probe refusal order
PAIRS_FIELDS = ["value", "observed_at", "measure", "source", "responseArchive", "assertionVersion", "source_record_id", "filters"]
PAIR_VALUES = [None, 0, "", [], True, "x", [1], float("nan"), 2**1100, nested(128), {"a": 1}]
for (f1, f2) in itertools.combinations(PAIRS_FIELDS, 2):
    for v1, v2 in itertools.product(PAIR_VALUES, PAIR_VALUES):
        row = copy.deepcopy(ROWS[2])
        row[f1] = v1
        row[f2] = v2
        line = encode_line(row)
        if line is None:
            continue
        add("check_rows", lines=[*LINES[:2], line], prefix_count=1, note=f"{f1}={str(v1)[:20]} {f2}={str(v2)[:20]}")

# raw lines
RAW = REWRITES + ["", " ", "{", "[]", "{}", "{\"source_record_id\":\"a\"}", "9" * 5000, "[" * 129 + "]" * 129,
                  "{\"source_record_id\":\"a\",\"value\":1,\"observed_at\":\"2026-01-01\",\"measure\":\"u\"}",
                  "{\"source_record_id\":\"a\",\"value\":1,\"observed_at\":\"2026-01-01\",\"measure\":{\"unit\":\"u\"},\"source\":1}",
                  "{\"source_record_id\":\"a\",\"value\":1,\"observed_at\":\"2026-01-01\",\"measure\":{\"unit\":\"u\"},\"responseArchive\":1}",
                  "{\"source_record_id\":\"a\",\"value\":NaN,\"observed_at\":\"2026-01-01\",\"measure\":{\"unit\":\"u\"}}",
                  "{\"source_record_id\":\"a\",\"value\":1,\"observed_at\":\"2026-01-01\",\"measure\":{\"unit\":\"u\"},\"assertionVersion\":1,\"source\":1}",
                  ]
for raw in RAW:
    for pos in (1, 3):
        lines = list(LINES[:3])
        lines[pos - 1] = raw
        add("check_rows", lines=lines, prefix_count=1, note=f"raw pos={pos} {raw[:40]!r}")

# random rows: seeded random mutation of many fields at once
rng = random.Random(20260928)
for i in range(6000):
    row = copy.deepcopy(ROWS[2])
    for _ in range(rng.randint(1, 4)):
        f = rng.choice(FIELDS + ["measure.unit", "measure.concept", "source.url", "responseArchive.sha256", "assertionVersion.supersedes"])
        v = rng.choice(FIELD_VALUES)
        if "." in f:
            outer, inner = f.split(".")
            if isinstance(row.get(outer), dict):
                row[outer][inner] = v
            else:
                row[outer] = {inner: v}
        else:
            row[f] = v
    if rng.random() < 0.6 and not isinstance(row.get("assertionVersion"), (int, float, str, list, bool)):
        rid = eavi_or_none(row)
        if rid:
            av = row.get("assertionVersion") if isinstance(row.get("assertionVersion"), dict) else {}
            av = dict(av)
            av["id"] = rid
            row["assertionVersion"] = av
    line = encode_line(row)
    if line is None:
        continue
    add("check_rows", lines=[*LINES[:2], line], prefix_count=rng.choice([0, 1, 2, 3]), note=f"random {i}")

# ------------------------------------------------ expected_assertion_version_id
for field, value in itertools.product(FIELDS, FIELD_VALUES):
    row = copy.deepcopy(ROWS[0])
    row[field] = value
    line = encode_line(row)
    if line is None:
        continue
    add("eavi", row_text=line, note=f"{field}={str(value)[:30]}")
for mv, sv, av in itertools.product([None, 0, "", [], {}, 1, "x", [1], True], repeat=3):
    row = copy.deepcopy(ROWS[0])
    row["measure"], row["source"], row["responseArchive"] = mv, sv, av
    add("eavi", row_text=encode_line(row), note=f"m={mv!r} s={sv!r} a={av!r}")
for extra in ([{"value": float("nan"), "source": 1}], [{"source": 1, "measure": 1}]):
    for e in extra:
        row = copy.deepcopy(ROWS[0])
        row.update(e)
        add("eavi", row_text=encode_line(row), note=f"combo {e}")

# ---------------------------------------------------- effective_current_rows
for av1, av2 in itertools.product(
    [None, {}, {"id": ""}, {"id": "x"}, {"id": 0}, {"id": [1]}, {"supersedes": "x"}, {"id": "y", "supersedes": "x"}, 1, "s", [1], True],
    repeat=2,
):
    r1 = copy.deepcopy(ROWS[0])
    r2 = copy.deepcopy(ROWS[1])
    r1["assertionVersion"] = av1
    r2["assertionVersion"] = av2
    for m in (None, "x", {"unit": "u"}):
        r1b = copy.deepcopy(r1)
        if m is not None:
            r1b["measure"] = m
        add("ecr", rows_text=[encode_line(r1b), encode_line(r2)], note=f"av1={av1!r} av2={av2!r} m={m!r}")

with OUT.open("w") as fh:
    for c in cases:
        fh.write(json.dumps(c, ensure_ascii=True, allow_nan=True) + "\n")
print(len(cases), "cases", file=sys.stderr)
from collections import Counter
print(Counter(c["fn"] for c in cases), file=sys.stderr)
