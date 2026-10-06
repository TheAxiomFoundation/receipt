"""Gate-level differential: real committed candidates through verify_append_gate.

Run once per tree (TREE env); prints one JSON line per case to OUT.
Cases target inputs that did NOT crash at base, plus a few crash controls.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sys
import tempfile
import traceback

HERE = pathlib.Path(__file__).resolve().parent
TREE = pathlib.Path(os.environ["TREE"])
sys.path.insert(0, str(TREE / "tests"))
import test_append_gate as t  # noqa: E402
import receipt  # noqa: E402
from receipt.append_gate import AppendError, expected_assertion_version_id  # noqa: E402

print("receipt from", receipt.__file__, file=sys.stderr)
TMP = HERE / "tmp"
OUT = pathlib.Path(os.environ["OUT"])
ONLY = os.environ.get("ONLY")
SHARD, NSHARDS = (int(x) for x in os.environ.get("SHARD", "0/1").split("/"))
_counter = [0]
LEDGER = t.CHAIN_SPEC.state_relative
PREFIX = t.CHAIN_SPEC.prefix_relative
results = []


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def rows(n):
    return [t.observation_row(i) for i in range(1, n + 1)]


def lines_of(rs):
    return [t.jsonl_line(r) for r in rs]


def write_lines(root, lines):
    (root / LEDGER).write_text("".join(x + "\n" for x in lines), encoding="utf-8")


def manifest_for(lines, count, **over):
    m = {
        "schemaVersion": t.GATE_SPEC.prefix_schema_version,
        "prefixLineCount": count,
        "lineSha256s": [sha(x) for x in lines[: int(count)]],
        "prefixSha256": hashlib.sha256(("\n".join(lines[: int(count)]) + "\n").encode()).hexdigest(),
    }
    m.update(over)
    return m


def write_manifest(root, m, raw=None):
    (root / PREFIX).write_text(raw if raw is not None else json.dumps(m, indent=2, allow_nan=True) + "\n", encoding="utf-8")


def case(name, *, prefix_line_count=1, base_row_count=2, push=False, base_mutate=None):
    def deco(mutate):
        if ONLY and ONLY not in name:
            return mutate
        _counter[0] += 1
        if (_counter[0] - 1) % NSHARDS != SHARD:
            return mutate
        t.PREFIX_LINE_COUNT = prefix_line_count
        t.BASE_ROW_COUNT = base_row_count
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            try:
                candidate = t.base_repository(pathlib.Path(tmp))
                if base_mutate is not None:
                    base_mutate(candidate.root)
                    new_base = t.commit_candidate(candidate, "rewritten base")
                    candidate = t.Candidate(root=candidate.root, base=new_base)
                mutate(candidate.root)
                summary = t.run_push_gate(candidate) if push else t.run_gate(candidate)
                rec = {"kind": "OK", "msg": summary}
            except AppendError as exc:
                rec = {"kind": "AppendError", "msg": str(exc)}
            except Exception as exc:  # noqa: BLE001
                frame = traceback.extract_tb(exc.__traceback__)[-1]
                rec = {"kind": f"CRASH:{type(exc).__name__}", "msg": str(exc)[:300],
                       "at": f"{pathlib.Path(frame.filename).name}:{frame.lineno}"}
        t.PREFIX_LINE_COUNT, t.BASE_ROW_COUNT = 1, 2
        rec["case"] = name
        print(json.dumps(rec, ensure_ascii=True), file=sys.stderr)
        results.append(rec)
        return mutate
    return deco


def appended_three(root):
    write_lines(root, lines_of(rows(3)))


# --- prefixLineCount spellings, both paths (base manifest has 1)
for push in (False, True):
    for count in (True, 1.0, 1.9, "1", " 1 ", "１", "1_0", "+1", 1):
        @case(f"count={count!r} push={push}", push=push)
        def _(root, count=count):
            lines = lines_of(rows(3))
            write_lines(root, lines)
            write_manifest(root, manifest_for(lines, 1, prefixLineCount=count))

# --- lineSha256s shapes of matching length, both paths
for push in (False, True):
    @case(f"lineSha256s string len1 push={push}", push=push)
    def _(root):
        lines = lines_of(rows(3))
        write_lines(root, lines)
        write_manifest(root, manifest_for(lines, 1, lineSha256s="a"))

    @case(f"lineSha256s string = the hash itself, count 64 push={push}", push=push)
    def _(root):
        lines = lines_of(rows(3))
        write_lines(root, lines)
        write_manifest(root, manifest_for(lines, 1, prefixLineCount=64, lineSha256s=sha(lines[0])))

    @case(f"lineSha256s object len1 push={push}", push=push)
    def _(root):
        lines = lines_of(rows(3))
        write_lines(root, lines)
        write_manifest(root, manifest_for(lines, 1, lineSha256s={"0": sha(lines[0])}))

    @case(f"lineSha256s longer push={push}", push=push)
    def _(root):
        lines = lines_of(rows(3))
        write_lines(root, lines)
        write_manifest(root, manifest_for(lines, 1, lineSha256s=[sha(lines[0]), "0" * 64]))

    @case(f"count 5 > rows push={push}", push=push)
    def _(root):
        lines = lines_of(rows(3))
        write_lines(root, lines)
        write_manifest(root, manifest_for(lines, 1, prefixLineCount=5, lineSha256s=["0" * 64] * 5))

    @case(f"manifest extra key 128 deep push={push}", push=push)
    def _(root):
        lines = lines_of(rows(3))
        write_lines(root, lines)
        v = 0
        for _ in range(127):
            v = [v]
        write_manifest(root, manifest_for(lines, 1, extra=v))

# --- multi-line prefix (PREFIX_LINE_COUNT=2, BASE_ROW_COUNT=3): line 2 rewritten
for text in ("[1]", "{\"a\":1}", "{\"source_record_id\":null}", "{\"source_record_id\":\"\"}", "null", "garbage",
             "{\"source_record_id\":\"id\",\"d\":" + "[" * 200 + "]" * 200 + "}",
             "{\"source_record_id\":\"id\",\"n\":" + "9" * 5000 + "}"):
    for push in (False, True):
        @case(f"prefix2 line2 rewritten {text[:30]!r} push={push}", prefix_line_count=2, base_row_count=3, push=push)
        def _(root, text=text):
            lines = lines_of(rows(4))
            lines[1] = text
            write_lines(root, lines)

# --- rewritten base line outside the prefix (check_append_only label)
@case("base line 2 rewritten (object with id)")
def _(root):
    lines = lines_of(rows(3))
    lines[1] = lines[1].replace("\"value\":2.0", "\"value\":22.0")
    write_lines(root, lines)


def deep_base_line2(root):
    lines = lines_of(rows(2))
    lines[1] = lines[1][:-1] + ",\"note\":" + "[" * 200 + "]" * 200 + "}"
    write_lines(root, lines)


@case("base line 2 is 201 deep (json.loads-readable), candidate rewrites it", base_mutate=deep_base_line2)
def _(root):
    write_lines(root, lines_of(rows(3)))


@case("base line 2 is 201 deep, candidate appends one row", base_mutate=deep_base_line2)
def _(root):
    lines = (root / LEDGER).read_text().splitlines()
    write_lines(root, lines + [t.jsonl_line(t.observation_row(3))])


def nonobject_base_line2(root):
    lines = lines_of(rows(2))
    lines[1] = "[1]"
    write_lines(root, lines)


@case("base line 2 is [1], candidate rewrites it", base_mutate=nonobject_base_line2)
def _(root):
    write_lines(root, lines_of(rows(3)))


def idless_base_line2(root):
    lines = lines_of(rows(2))
    lines[1] = "{\"a\":1}"
    write_lines(root, lines)


@case("base line 2 is {a:1}, candidate rewrites it", base_mutate=idless_base_line2)
def _(root):
    write_lines(root, lines_of(rows(3)))


# --- falsy / truthy non-dict measure, source, responseArchive in the appended row
for field in ("measure", "source", "responseArchive"):
    for value in (0, "", [], False, None, {}, 1, "x", [0], True):
        @case(f"appended {field}={value!r}")
        def _(root, field=field, value=value):
            row = t.observation_row(3)
            row[field] = value
            try:
                row["assertionVersion"] = {"id": expected_assertion_version_id(row, t.GATE_SPEC)}
            except Exception:
                pass
            lines = lines_of(rows(2)) + [json.dumps(row, ensure_ascii=False, separators=(",", ":"))]
            write_lines(root, lines)

# --- controls
@case("ordinary append")
def _(root):
    appended_three(root)


@case("ordinary append, push", push=True)
def _(root):
    appended_three(root)


OUT.write_text("".join(json.dumps(r, ensure_ascii=True) + "\n" for r in results))
print("done", len(results), file=sys.stderr)
