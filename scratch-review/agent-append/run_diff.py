"""Run every case in inputs.jsonl against ONE tree (TREE env) and emit JSONL.

Outcome kinds: OK (with a repr of the return value), AppendError (message),
CRASH:<type> (message + innermost frame).
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import traceback
from types import SimpleNamespace

HERE = pathlib.Path(__file__).resolve().parent
TREE = pathlib.Path(os.environ["TREE"])
sys.path.insert(0, str(TREE / "tests"))
import test_append_gate as t  # noqa: E402
import receipt  # noqa: E402
from receipt import append_gate as ag  # noqa: E402

print("receipt from", receipt.__file__, file=sys.stderr)
SPEC = t.GATE_SPEC
CAND = SimpleNamespace(spec=SPEC, ledger_relative="ledger/official_observations.jsonl")
INPUTS = pathlib.Path(os.environ.get("INPUTS", HERE / "inputs.jsonl"))
OUT = pathlib.Path(os.environ["OUT"])


def fake_base(text: str):
    tree = SimpleNamespace(entry=lambda path: path, blob=lambda entry, limit: text.encode("utf-8", "surrogatepass"))
    return SimpleNamespace(tree=tree, ref="base", commit="0" * 40)


def safe_repr(v) -> str:
    try:
        r = repr(v)
    except Exception as exc:  # noqa: BLE001
        return f"<repr failed {type(exc).__name__}>"
    return r if len(r) < 400 else r[:400] + f"...<{len(r)}>"


def run_case(case: dict):
    fn = case["fn"]
    if fn == "check_prefix":
        return ag.check_prefix(case["lines"], case["prefix_text"], CAND)
    if fn == "check_rows":
        return ag.check_rows(case["lines"], case["prefix_count"], SPEC)
    if fn == "check_append_only":
        return ag.check_append_only(fake_base(case["base_text"]), case["lines"], CAND)
    if fn == "eavi":
        row = json.loads(case["row_text"])
        return ag.expected_assertion_version_id(row, SPEC)
    if fn == "ecr":
        rows = [json.loads(x) for x in case["rows_text"]]
        return [r.get("source_record_id") for r in ag.effective_current_rows(rows, SPEC)]
    raise SystemExit(f"unknown fn {fn}")


with INPUTS.open() as src, OUT.open("w") as dst:
    for raw in src:
        case = json.loads(raw)
        try:
            value = run_case(case)
            rec = {"kind": "OK", "msg": safe_repr(value)}
        except ag.AppendError as exc:
            rec = {"kind": "AppendError", "msg": str(exc)[:2000]}
        except BaseException as exc:  # noqa: BLE001
            if isinstance(exc, KeyboardInterrupt):
                raise
            frame = traceback.extract_tb(exc.__traceback__)[-1]
            rec = {
                "kind": f"CRASH:{type(exc).__name__}",
                "msg": (str(exc)[:300] if not isinstance(exc, RecursionError) else "recursion"),
                "at": f"{pathlib.Path(frame.filename).name}:{frame.lineno}",
            }
        rec["id"] = case["id"]
        rec["note"] = case.get("note", "")[:120]
        dst.write(json.dumps(rec, ensure_ascii=True) + "\n")
print("done", file=sys.stderr)
