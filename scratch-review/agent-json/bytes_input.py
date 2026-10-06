"""Bytes / bytearray / str-subclass inputs to the public append_gate row checks.

Usage: python bytes_input.py <tree-dir>   (run once per tree, diff the output)
"""
import json
import pathlib
import sys
import types

tree = pathlib.Path(sys.argv[1]).resolve()
sys.path[:0] = [str(tree / "src"), str(tree / "tests")]
import receipt  # noqa: E402

print("receipt:", receipt.__file__)
import test_append_gate as t  # noqa: E402
from receipt import append_gate as ag  # noqa: E402

row = t.observation_row(1)
text = json.dumps(row, sort_keys=True, separators=(",", ":"))


class S(str):
    pass


def run(label, fn):
    try:
        out = fn()
        print(f"{label}: OK {out!r}"[:300])
    except Exception as e:  # noqa: BLE001
        print(f"{label}: {type(e).__name__}: {e}"[:300])


for kind, conv in (("bytes", lambda s: s.encode()), ("bytearray", lambda s: bytearray(s.encode())), ("str-subclass", S), ("str", str)):
    run(f"check_rows[{kind}]", lambda: ag.check_rows([conv(text)], 0, t.GATE_SPEC))
    prefix = {"schemaVersion": t.GATE_SPEC.prefix_schema_version, "prefixLineCount": 1,
              "lineSha256s": [__import__("hashlib").sha256(text.encode()).hexdigest()]}
    cand = types.SimpleNamespace(spec=t.GATE_SPEC)
    run(f"check_prefix[{kind}]", lambda: ag.check_prefix([text], conv(json.dumps(prefix)), cand))
