"""Does the verdict of tsa.load_json / _bounded_json.loads depend on the caller's stack?

Usage: python stack_probe.py <tree-dir> <workdir> <part>
part A: main thread, caller at (recursion limit - k) frames, k = 1..40, through
        tsa.load_json on four small valid documents (run once per tree, diff).
part B: threads with small threading.stack_size: deepest json.loads parse,
        verdict of loads/load_json on a 128-deep document, canonical re-encode.
part C: receipt.canonical frames per level at the default recursion limit.
"""
import json
import pathlib
import sys
import tempfile
import threading

tree = pathlib.Path(sys.argv[1]).resolve()
sys.path[:0] = [str(tree / "src")]
import receipt  # noqa: E402

print("receipt:", receipt.__file__, "limit:", sys.getrecursionlimit(), flush=True)
from receipt import tsa  # noqa: E402
from receipt.canonical import canonical_bytes  # noqa: E402

work = pathlib.Path(tempfile.mkdtemp(prefix="stack-", dir=sys.argv[2]))
PART = sys.argv[3]

DOCS = {
    "obj_int": '{"a": 1}',
    "obj_str": '{"a": "x"}',
    "deep128_noint": '{"a":' + "[" * 127 + "]" * 127 + "}",
    "deep128_int": '{"a":' + "[" * 127 + "1" + "]" * 127 + "}",
}
paths = {}
for name, text in DOCS.items():
    p = work / f"{name}.json"
    p.write_text(text)
    paths[name] = p


def frames() -> int:
    f = sys._getframe(1)
    n = 0
    while f is not None:
        n += 1
        f = f.f_back
    return n


def outcome(fn):
    try:
        r = fn()
        return "ACCEPT" if isinstance(r, (dict, list, bytes)) else f"ACCEPT {type(r).__name__}"
    except RecursionError as e:
        return f"RecursionError: {str(e)[:80]}"
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {str(e).replace(str(work), '<W>')[:120]}"


def at_depth(target: int, fn, arg):
    """Call fn(arg) from a frame that is the `target`-th Python frame; the
    exception is classified in that same frame (no wrapper frames)."""
    def rec():
        if frames() < target:
            return rec()
        try:
            r = fn(arg)
            return "ACCEPT" if isinstance(r, (dict, list, bytes)) else "ACCEPT?"
        except RecursionError as e:
            return "RecursionError"
        except Exception as e:  # noqa: BLE001
            return f"{type(e).__name__}: {str(e).replace(str(work), '<W>')[:90]}"
    return rec()


if PART == "A":
    limit = sys.getrecursionlimit()
    for k in range(1, 41):  # the calling frame is frame (limit - k)
        row = {}
        for name, p in paths.items():
            row[name] = at_depth(limit - k, tsa.load_json, p)
        print(f"k={k:2d} " + " | ".join(f"{n}={v}" for n, v in row.items()), flush=True)

elif PART == "B":
    from receipt import _bounded_json as bj  # noqa: E402  (head only)

    def deepest(fn, lo=1, hi=200_000):
        # largest n such that fn('['*n + ']'*n) succeeds
        while lo < hi:
            mid = (lo + hi + 1) // 2
            try:
                fn("[" * mid + "]" * mid)
                lo = mid
            except RecursionError:
                hi = mid - 1
        return lo

    def deepest_canon(kind, lo=1, hi=5000):
        def build(n):
            v = 0
            for _ in range(n):
                v = [v] if kind == "list" else {"k": v}
            return v
        while lo < hi:
            mid = (lo + hi + 1) // 2
            try:
                canonical_bytes(build(mid))
                lo = mid
            except RecursionError:
                hi = mid - 1
        return lo

    doc128 = "[" * 128 + "1" + "]" * 128
    for size in (0, 32 * 1024, 48 * 1024, 64 * 1024, 96 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024):
        result = {}

        def body():
            result["json.loads deepest"] = deepest(json.loads)
            result["bounded loads(128-deep)"] = outcome(lambda: bj.loads(doc128))
            result["json.loads(128-deep)"] = outcome(lambda: json.loads(doc128))
            result["load_json(128-deep obj)"] = outcome(lambda: tsa.load_json(paths["deep128_int"]))
            result["canonical deepest list"] = deepest_canon("list")
            result["canonical deepest dict"] = deepest_canon("dict")
            v = json.loads(doc128) if result["json.loads(128-deep)"] == "ACCEPT" else None
            result["canonical(128-deep list)"] = outcome(lambda: canonical_bytes(v)) if v is not None else "n/a"

        try:
            threading.stack_size(size)
        except ValueError as e:
            print(f"stack_size {size}: {e}")
            continue
        t = threading.Thread(target=body)
        t.start()
        t.join()
        threading.stack_size(0)
        print(f"stack_size={size // 1024}KiB {result}", flush=True)

elif PART == "C":
    def build(n, kind):
        v = 0
        for i in range(n):
            if kind == "list":
                v = [v]
            elif kind == "dict":
                v = {"k": v}
            else:
                v = [v] if i % 2 else {"k": v}
        return v

    for kind in ("list", "dict", "mixed"):
        v = build(128, kind)
        # minimal recursion limit that re-encodes a 128-deep value from here
        base = frames()
        lo, hi = base + 1, 5000
        while lo < hi:
            mid = (lo + hi) // 2
            sys.setrecursionlimit(mid)
            try:
                canonical_bytes(v)
                hi = mid
            except RecursionError:
                lo = mid + 1
        sys.setrecursionlimit(1000)
        # deepest value encodable at the default limit from here
        lo2, hi2 = 1, 5000
        while lo2 < hi2:
            mid = (lo2 + hi2 + 1) // 2
            try:
                canonical_bytes(build(mid, kind))
                lo2 = mid
            except RecursionError:
                hi2 = mid - 1
        print(f"{kind}: frames at call site={base}, minimal recursion limit for 128 deep={lo} "
              f"(={lo - base} frames for 128 levels, {(lo - base) / 128:.2f}/level); "
              f"deepest at default limit 1000 = {lo2}", flush=True)
    # decoded 128-deep values from _bounded_json itself, re-encoded at default limit
    try:
        from receipt import _bounded_json as bj  # noqa: E402
        for text in ("[" * 128 + "]" * 128, '{"a":' * 128 + "0" + "}" * 128,
                     '[{"a":' * 64 + "0" + "}]" * 64):
            print("decode+canonical 128:", outcome(lambda: canonical_bytes(bj.loads(text))))
    except ImportError:
        pass
