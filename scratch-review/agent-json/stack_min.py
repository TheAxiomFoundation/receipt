"""json.loads / _bounded_json.loads / canonical at the minimum thread stack (53,248 B)."""
import json, pathlib, sys, threading
tree = pathlib.Path(sys.argv[1]).resolve(); sys.path[:0] = [str(tree / "src")]
import receipt; print("receipt:", receipt.__file__)
from receipt import _bounded_json as bj
from receipt.canonical import canonical_bytes
res = {}
def body():
    for n in (100, 128, 129, 200, 250, 300):
        t = "[" * n + "1" + "]" * n
        for name, fn in (("json.loads", json.loads), ("bj.loads", bj.loads)):
            try: fn(t); r = "ACCEPT"
            except Exception as e: r = f"{type(e).__name__}: {str(e)[:70]}"
            res[f"{name} depth {n}"] = r
    for n in (40, 52, 64, 128):
        v = 0
        for _ in range(n): v = [v]
        try: canonical_bytes(v); r = "ACCEPT"
        except Exception as e: r = f"{type(e).__name__}: {str(e)[:60]}"
        res[f"canonical list depth {n}"] = r
threading.stack_size(53248)
t = threading.Thread(target=body); t.start(); t.join()
for k, v in res.items(): print(k, "->", v)
