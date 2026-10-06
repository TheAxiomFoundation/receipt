"""Generate manifest byte cases for the base/head load_manifest differential.

Tree-agnostic (imports nothing from receipt): canonical bytes are produced by
a tiny local serializer valid for the value shapes used here (dict/str/int/None;
ints <= 2**53-1 or deliberately out of range written as digits).
Writes chain/manifest_cases/<id>.bin and chain/manifest_cases/index.json.
"""

from __future__ import annotations

import copy
import json
import pathlib
import random

HERE = pathlib.Path(__file__).parent
OUT = HERE / "manifest_cases"
OUT.mkdir(exist_ok=True)
for p in OUT.iterdir():
    p.unlink()

M = HERE / "fixture/repo/releases/manifests"
GEN_RAW = next(M.glob("0000-*.json")).read_bytes()
REL_RAW = next(M.glob("0001-*.json")).read_bytes()
GEN = json.loads(GEN_RAW)
REL = json.loads(REL_RAW)


def canon(value) -> str:
    """Canonical JSON for dict/list/str/int/None/bool (keys sorted; all keys ASCII here)."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(canon(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canon(value[k]) for k in sorted(value)) + "}"
    raise TypeError(type(value))


assert canon(GEN).encode() + b"\n" == GEN_RAW
assert canon(REL).encode() + b"\n" == REL_RAW

cases: dict[str, bytes] = {}


def add(name: str, data: bytes | str) -> None:
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogatepass")
    assert name not in cases, name
    cases[name] = data


def with_field(doc, path, raw_value: str) -> str:
    """canonical doc with the field at `path` replaced by raw JSON text `raw_value`."""
    marker = "\u0000MARK\u0000"
    d = copy.deepcopy(doc)
    cur = d
    for key in path[:-1]:
        cur = cur[key]
    cur[path[-1]] = marker
    return canon(d).replace(json.dumps(marker), raw_value) + "\n"


add("ok-genesis", GEN_RAW)
add("ok-release1", REL_RAW)

COUNT_FIELDS = {
    "gen": (GEN, [("state", "lineCount"), ("releaseIndex",)]),
    "rel": (REL, [("state", "lineCount"), ("append", "previousLineCount"), ("append", "appendedRowCount"), ("releaseIndex",)]),
}
INT_LITERALS = {
    "0": "0", "1": "1", "neg1": "-1", "negzero": "-0", "2p53m1": str(2**53 - 1), "2p53": str(2**53),
    "2p53p1": str(2**53 + 1), "1e20": str(10**20), "1e21": str(10**21), "2p1023": str(2**1023),
    "1e308": str(10**308), "2p1024": str(2**1024), "1e309": str(10**309), "1e400": str(10**400),
    "d4300": "9" * 4300, "d4301": "9" * 4301, "d5000": "9" * 5000, "negd4300": "-" + "9" * 4300,
    "negd4301": "-" + "9" * 4301, "negd5000": "-" + "9" * 5000,
    "f1.0": "1.0", "f1e400": "1e400", "fneg1e400": "-1e400", "f1e2": "1e2", "f0.5": "0.5",
    "true": "true", "false": "false", "null": "null", "str": '"7"',
    "NaN": "NaN", "Infinity": "Infinity", "negInfinity": "-Infinity",
}
for tag, (doc, fields) in COUNT_FIELDS.items():
    for path in fields:
        for lname, literal in INT_LITERALS.items():
            add(f"count|{tag}|{'.'.join(path)}|{lname}", with_field(doc, path, literal))

# Same literals in non-count positions
for lname, literal in INT_LITERALS.items():
    add(f"pos|gen|producer.repo|{lname}", with_field(GEN, ("producer", "repo"), literal))
    add(f"pos|gen|schemaVersion|{lname}", with_field(GEN, ("schemaVersion",), literal))
    add(f"pos|gen|createdAtUtc|{lname}", with_field(GEN, ("createdAtUtc",), literal))
    add(f"pos|gen|previousManifestSha256|{lname}", with_field(GEN, ("previousManifestSha256",), literal))
    add(f"pos|gen|extra-key|{lname}", GEN_RAW.decode()[:-2] + ',"zzz":' + literal + "}\n")
    add(f"pos|gen|toplevel|{lname}", literal + "\n")
    add(f"pos|gen|toplevel-noNL|{lname}", literal)

# Depth: total container depth D. producer object is depth 2, so D-2 arrays in producer.repo
for D in (3, 64, 126, 127, 128, 129, 130, 200, 1000, 5000, 100_000):
    k = max(D - 2, 0)
    add(f"depth|producer.repo|{D}", with_field(GEN, ("producer", "repo"), "[" * k + "]" * k))
    add(f"depth|producer.repo-str|{D}", with_field(GEN, ("producer", "repo"), "[" * k + '"x"' + "]" * k))
    add(f"depth|extra-key|{D}", GEN_RAW.decode()[:-2] + ',"zzz":' + "[" * (D - 1) + "]" * (D - 1) + "}\n")
    add(f"depth|wrap|{D}", "[" * (D - 1) + GEN_RAW.decode()[:-1] + "]" * (D - 1) + "\n")
    add(f"depth|objects|{D}", GEN_RAW.decode()[:-2] + ',"zzz":' + '{"a":' * (D - 1) + "1" + "}" * (D - 1) + "}\n")
    add(f"depth|unclosed|{D}", with_field(GEN, ("producer", "repo"), "[" * k))
    add(f"depth|malformed-after|{D}", with_field(GEN, ("producer", "repo"), "[" * k + "]" * k + ",,"))
    # combined with duplicate keys and constants, before and after the deep part
    deep = "[" * k + "]" * k
    add(f"depth|dup-before|{D}", '{"a":1,"a":2,"b":' + deep + "}\n")
    add(f"depth|dup-after|{D}", '{"b":' + deep + ',"a":1,"a":2}\n')
    add(f"depth|dup-inside|{D}", '{"b":' + "[" * k + '{"a":1,"a":2}' + "]" * k + "}\n")
    add(f"depth|nan-before|{D}", '{"a":NaN,"b":' + deep + "}\n")
    add(f"depth|nan-after|{D}", '{"b":' + deep + ',"a":NaN}\n')
    add(f"depth|nan-inside|{D}", '{"b":' + "[" * k + "NaN" + "]" * k + "}\n")
    add(f"depth|bigint-before|{D}", '{"a":' + "9" * 5000 + ',"b":' + deep + "}\n")
    add(f"depth|bigint-after|{D}", '{"b":' + deep + ',"a":' + "9" * 5000 + "}\n")
    add(f"depth|bigint-inside|{D}", '{"b":' + "[" * k + "9" * 5000 + "]" * k + "}\n")
    add(f"depth|dupdeep-objects|{D}", '{"a":' * k + '{"x":1,"x":2}' + "}" * k + "\n")

# Duplicate keys in schema positions
add("dup|top|releaseIndex", GEN_RAW.decode()[:-2] + ',"releaseIndex":0}\n')
add("dup|state|lineCount", GEN_RAW.decode().replace('"lineCount":', '"lineCount":1,"lineCount":', 1))
add("dup|producer|repo", GEN_RAW.decode().replace('"repo":', '"repo":"x","repo":', 1))

# Encoding and framing
add("bom", b"\xef\xbb\xbf" + GEN_RAW)
add("no-newline", GEN_RAW[:-1])
add("crlf", GEN_RAW[:-1] + b"\r\n")
add("two-newlines", GEN_RAW + b"\n")
add("leading-space", b" " + GEN_RAW)
add("not-utf8", GEN_RAW[:-2] + b"\xff}\n")
add("empty", b"")
add("lone-surrogate-repo", with_field(GEN, ("producer", "repo"), '"\\ud800"'))
add("lone-surrogate-repo-upper", with_field(GEN, ("producer", "repo"), '"\\uD800"'))
add("pair-repo", with_field(GEN, ("producer", "repo"), '"\\ud83d\\ude00"'))
add("escaped-slash-repo", with_field(GEN, ("producer", "repo"), '"a\\/b"'))
add("createdAt-year1", with_field(GEN, ("createdAtUtc",), '"0001-01-01T00:00:00Z"'))
add("createdAt-year9999", with_field(GEN, ("createdAtUtc",), '"9999-12-31T23:59:59.999999Z"'))
add("createdAt-year0", with_field(GEN, ("createdAtUtc",), '"0000-01-01T00:00:00Z"'))
add("createdAt-24h", with_field(GEN, ("createdAtUtc",), '"2026-01-01T24:00:00Z"'))
add("createdAt-feb30", with_field(GEN, ("createdAtUtc",), '"2026-02-30T00:00:00Z"'))
add("createdAt-7frac", with_field(GEN, ("createdAtUtc",), '"2026-01-01T00:00:00.1234567Z"'))

# Seeded random byte mutations of the two real manifests
rng = random.Random(4242)
POOL = [b"[", b"]", b"{", b"}", b'"', b"\\", b"9" * 4301, b"NaN", b"-", b"1e400", b",", b":", b"\x00", b"\xff", b" ", b"\n", b"true", b"[" * 200, b"]" * 200]
for n in range(6000):
    data = bytearray(rng.choice([GEN_RAW, REL_RAW]))
    for _ in range(rng.randint(1, 3)):
        pos = rng.randint(0, len(data))
        piece = rng.choice(POOL)
        r = rng.random()
        if r < 0.5:
            data[pos:pos] = piece
        elif r < 0.8:
            data[pos : pos + len(piece)] = piece
        else:
            del data[pos : pos + rng.randint(1, 8)]
    add(f"rnd|{n}", bytes(data))

index = {}
for i, (name, data) in enumerate(cases.items()):
    fname = f"c{i:05d}.bin"
    (OUT / fname).write_bytes(data)
    index[fname] = name
(OUT / "index.json").write_text(json.dumps(index, indent=0))
print(f"wrote {len(cases)} manifest cases to {OUT}")
