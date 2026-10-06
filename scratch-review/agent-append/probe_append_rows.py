"""L6 probes: append_gate row/prefix validation over committed fixture trees.

Uses the repository's own fixture helpers (tests/test_append_gate.py): a base
with two ledger rows and a one-line frozen prefix, no release chain. Each case
writes the candidate state, commits it, and runs verify_append_gate against the
base. Outcome classes:

  ACCEPT   the gate returned a success summary
  REFUSE   AppendError (the module's own refusal type)
  CRASH    any other exception escaping verify_append_gate
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sys
import tempfile
import traceback

TESTS = pathlib.Path(os.environ.get("RECEIPT_WORKTREE", "/Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-062-review-L6")) / "tests"
sys.path.insert(0, str(TESTS))

import test_append_gate as t  # noqa: E402
import receipt as _receipt  # noqa: E402
print("receipt from", _receipt.__file__)
SCRATCH_TMP = pathlib.Path(__file__).resolve().parent / "tmp"
from receipt.append_gate import AppendError, expected_assertion_version_id  # noqa: E402

LEDGER = t.CHAIN_SPEC.state_relative
PREFIX = t.CHAIN_SPEC.prefix_relative


def base_rows() -> list[dict]:
    return [t.observation_row(n) for n in range(1, t.BASE_ROW_COUNT + 1)]


def base_bytes() -> bytes:
    return "".join(f"{t.jsonl_line(r)}\n" for r in base_rows()).encode()


def with_id(row: dict) -> dict:
    row = dict(row)
    row.pop("assertionVersion", None)
    row["assertionVersion"] = {"id": expected_assertion_version_id(row, t.GATE_SPEC)}
    return row


def run(label: str, mutate, *, push: bool = False) -> str:
    with tempfile.TemporaryDirectory(dir=SCRATCH_TMP) as tmp:
        candidate = t.base_repository(pathlib.Path(tmp))
        mutate(candidate.root)
        try:
            if push:
                summary = t.run_push_gate(candidate)
            else:
                summary = t.run_gate(candidate)
            outcome = f"ACCEPT  {summary}"
        except AppendError as exc:
            outcome = f"REFUSE  {str(exc)}"
        except Exception as exc:  # noqa: BLE001
            frame = traceback.extract_tb(exc.__traceback__)[-1]
            where = f"{pathlib.Path(frame.filename).name}:{frame.lineno}"
            outcome = f"CRASH   {type(exc).__name__} at {where}: {str(exc)[:200]}"
    print(f"[{label}] {outcome}")
    return outcome


def write_ledger_bytes(root: pathlib.Path, data: bytes) -> None:
    (root / LEDGER).write_bytes(data)


def append_raw(line: str, terminator: str = "\n"):
    def mutate(root: pathlib.Path) -> None:
        write_ledger_bytes(root, base_bytes() + (line + terminator).encode("utf-8"))
    return mutate


def append_row(**overrides):
    row = t.observation_row(t.BASE_ROW_COUNT + 1)
    row.pop("assertionVersion")
    row.update(overrides)
    try:
        row = with_id(row)
    except Exception:  # the id itself cannot be computed; ship a placeholder
        row["assertionVersion"] = {"id": "av2:" + "0" * 64}
    return append_raw(json.dumps(row, ensure_ascii=False, separators=(",", ":"), allow_nan=True))


def rewrite_prefix_line(new_line: str):
    def mutate(root: pathlib.Path) -> None:
        lines = base_bytes().decode().splitlines()
        lines[0] = new_line
        write_ledger_bytes(root, ("\n".join(lines) + "\n").encode())
    return mutate


def prefix_manifest(text: str):
    def mutate(root: pathlib.Path) -> None:
        (root / PREFIX).write_text(text)
        t.append_one_row(t.Candidate(root=root, base=""))
    return mutate


def prefix_field(**fields):
    def mutate(root: pathlib.Path) -> None:
        manifest = json.loads((root / PREFIX).read_text())
        manifest.update(fields)
        (root / PREFIX).write_text(json.dumps(manifest, allow_nan=True))
        t.append_one_row(t.Candidate(root=root, base=""))
    return mutate


def main() -> None:
    print("== control")
    run("ordinary append", lambda root: t.append_one_row(t.Candidate(root=root, base="")))

    print("== candidate-controlled bytes that escape as non-AppendError")
    run("prefix line 1 rewritten to non-JSON", rewrite_prefix_line("garbage"))
    run("prefix line 1 rewritten to a JSON array", rewrite_prefix_line("[1]"))
    run("prefix manifest not JSON", prefix_manifest("not json\n"))
    run("prefix manifest a JSON array", prefix_manifest("[]\n"))
    run("prefix manifest without prefixLineCount", prefix_manifest(json.dumps({
        "schemaVersion": t.GATE_SPEC.prefix_schema_version})))
    run("prefixLineCount = 1e400", prefix_field(prefixLineCount=float("inf")))
    run("prefixLineCount = null", prefix_field(prefixLineCount=None))
    run("prefixLineCount = 'x'", prefix_field(prefixLineCount="x"))
    run("lineSha256s = 5", prefix_field(lineSha256s=5))
    run("appended measure is a string", append_row(measure="percent"))
    run("appended source is a list", append_row(source=["x"]))
    run("appended responseArchive is a string", append_row(responseArchive="abc"))
    run("appended value NaN", append_row(value=float("nan")))
    run("appended value Infinity", append_row(value=float("inf")))
    deep: object = 0
    for _ in range(5000):
        deep = [deep]
    run("appended filters nested 5000 deep", append_row(filters=deep))

    print("== values the row checks accept")
    run("appended value true (bool)", append_row(value=True))
    run("appended observed_at fullwidth digits",
        append_row(observed_at="２０２６-０７-０１"))
    run("appended observed_at Arabic-Indic digits",
        append_row(observed_at="٢٠٢٦-٠٧-٠١"))
    run("appended observed_at 2026-99-99", append_row(observed_at="2026-99-99"))
    run("appended source_record_id = true", append_row(source_record_id=True))
    run("appended source_record_id = {'a': 1}", append_row(source_record_id={"a": 1}))

    # Duplicate keys: the id binds the LAST value; the bytes carry both.
    row = t.observation_row(t.BASE_ROW_COUNT + 1)
    row.pop("assertionVersion")
    row["value"] = 999.0
    row = with_id(row)
    dup = json.dumps(row, separators=(",", ":"))
    dup = dup.replace('"value":999.0', '"value":3.0,"value":999.0', 1)
    run("appended row with duplicate 'value' keys (3.0 then 999.0)", append_raw(dup))

    # Record identity aliasing through str(): "7" and 7 are one record.
    def alias(supersede: bool):
        def mutate(root: pathlib.Path) -> None:
            first = t.observation_row(3)
            first.pop("assertionVersion")
            first["source_record_id"] = "7"
            first = with_id(first)
            second = t.observation_row(4)
            second.pop("assertionVersion")
            second["source_record_id"] = 7
            second = with_id(second)
            if supersede:
                second["assertionVersion"]["supersedes"] = first["assertionVersion"]["id"]
            write_ledger_bytes(root, base_bytes() + "".join(
                f"{t.jsonl_line(r)}\n" for r in (first, second)).encode())
        return mutate
    run("row id '7' then row id 7, no supersedes", alias(False))
    run("row id 7 supersedes row id '7'", alias(True))

    print("== newline handling")
    good = json.dumps(t.observation_row(t.BASE_ROW_COUNT + 1), separators=(",", ":"))
    run("appended row terminated by CRLF", append_raw(good, "\r\n"))
    run("appended row terminated by lone CR", append_raw(good, "\r"))
    run("appended row, no trailing newline", append_raw(good, ""))
    run("appended row followed by a blank line", append_raw(good, "\n\n"))
    run("appended row with trailing tab", append_raw(good + "\t"))
    run("appended row with U+2028 after it", append_raw(good + " "))
    run("appended row preceded by NBSP", append_raw(" " + good))

    print("== prefix manifest equality under Python ==")
    run("candidate prefixLineCount true (base 1)", prefix_field(prefixLineCount=True))
    run("candidate prefixLineCount 1.0 (base 1)", prefix_field(prefixLineCount=1.0))

    print("== empty ledger")
    def empty(root: pathlib.Path) -> None:
        write_ledger_bytes(root, b"")
        (root / PREFIX).write_text(json.dumps({
            "schemaVersion": t.GATE_SPEC.prefix_schema_version,
            "prefixLineCount": 0, "lineSha256s": [],
            "prefixSha256": hashlib.sha256(b"\n").hexdigest()}))
    run("push path: zero-byte ledger, zero-line prefix", empty, push=True)


if __name__ == "__main__":
    main()
