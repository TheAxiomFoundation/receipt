"""CPU cost of _bounded_json.loads (head) vs json.loads (base behaviour).

Usage: python perf.py <tree-dir> <MiB> [shape ...]
Times with time.process_time(); best of 3 for sizes <= 8 MiB, 1 run above.
"""
import gc
import json
import pathlib
import sys
import time

tree = pathlib.Path(sys.argv[1]).resolve()
sys.path[:0] = [str(tree / "src")]
import receipt  # noqa: E402

print("receipt:", receipt.__file__, flush=True)
from receipt import _bounded_json as bj  # noqa: E402

MIB = float(sys.argv[2])
N = int(MIB * 1024 * 1024)


def fill(unit, head="[", tail="0]"):
    k = max(1, (N - len(head) - len(tail)) // len(unit))
    return head + unit * k + tail


SHAPES = {
    # valid documents, densest structure tokens first
    "brackets [[],[],...]": lambda: fill("[],", "[", "[]]"),
    "objects [{},{},...]": lambda: fill("{},", "[", "{}]"),
    "strings [\"\",\"\",...]": lambda: fill('"",', "[", '""]'),
    "shallow nested [1,[2,[3]]],...": lambda: fill("[1,[2,[3]]],", "[", "0]"),
    "numbers [0,0,...] (no tokens)": lambda: fill("0,", "[", "0]"),
    "escaped strings [\"\\\\\\\"\",...]": lambda: fill('"\\\\\\"",', "[", '""]'),
    # malformed at the first character: json.loads stops at once, the scan reads all
    "malformed-first-char x[][]...": lambda: "x" + "[]" * (N // 2),
    "malformed-first-char x\"\"\"\"...": lambda: "x" + '""' * (N // 2),
    # unterminated strings with backslash patterns (regex backtracking probes)
    "unterminated \"\\a\\a...": lambda: '"' + "\\a" * (N // 2),
    "unterminated \"\\\\n repeated": lambda: '"\\\n' * (N // 3),
    "unterminated \"aaaa...\\\\n": lambda: '"' + "a" * (N - 3) + "\\\n",
    "quote-bs-quote \"\\\"\"\\\"...": lambda: '"\\"' * (N // 3),
}
wanted = sys.argv[3:] or list(SHAPES)
reps = 3 if MIB <= 8 else 1


def cpu(fn, text):
    best = None
    outcome = None
    for _ in range(reps):
        gc.collect()
        t0 = time.process_time()
        try:
            v = fn(text)
            outcome = "value"
            del v
        except Exception as e:  # noqa: BLE001
            outcome = type(e).__name__
        dt = time.process_time() - t0
        best = dt if best is None else min(best, dt)
    return best, outcome


for name in SHAPES:
    if not any(w in name for w in wanted):
        continue
    text = SHAPES[name]()
    t_scan, _ = cpu(bj._first_excess, text)
    t_base, o_base = cpu(json.loads, text)
    t_head, o_head = cpu(bj.loads, text)
    ratio = t_head / t_base if t_base > 0 else float("inf")
    print(
        f"{MIB:>5} MiB | {name:<40} | len={len(text):>10} | json.loads {t_base:8.3f}s ({o_base}) | "
        f"bounded {t_head:8.3f}s ({o_head}) | scan alone {t_scan:8.3f}s | ratio {ratio:8.1f}",
        flush=True,
    )
    del text
