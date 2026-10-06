"""Audit the numeric claims of 7d32d0f for one tree (RECEIPT_SRC=<tree>/src).

1. CPU of _canonical_commit at 200k/400k/800k one-byte continuations under tree.
2. Header lines read (bytes-subclass find counter) for 10,000 continuations
   under tree and under parent (the author's test shape).
3. Linear scan claim: 800k/1.6M/3.2M continuations under gpgsig and under an
   extra header, which must PARSE, CPU per size.
4. zlib size of a commit at MAX_TREE_OBJECT_BYTES at levels 1, 6, 9 and the
   real loose object git writes (hash-object -w) for it.
"""
import os, sys, time, zlib, json
sys.path.insert(0, os.environ["RECEIPT_SRC"])
import receipt.snapshot as S
print("receipt.snapshot from", S.__file__)
MODE = sys.argv[1] if len(sys.argv) > 1 else "all"
TAIL = b"author a <a> 0 +0000\ncommitter a <a> 0 +0000\n\nm\n"
ONE = "1" * 40
ZERO = "0" * 40

def cpu(fn):
    t = time.process_time()
    try:
        fn(); v = "parsed"
    except S.SnapshotError as e:
        v = f"SnapshotError: {e}"
    return time.process_time() - t, v

if MODE in ("all", "quad"):
    for n in (200_000, 400_000, 800_000):
        p = f"tree {ONE}\n".encode() + b" \n" * n + TAIL
        dt, v = cpu(lambda: S._canonical_commit("f" * 40, p, object_format="sha1"))
        print(f"tree-continuations N={n:,}: CPU {dt:.3f}s -> {v[:70]}")

if MODE in ("all", "count"):
    class Counting(bytes):
        lines = 0
        def find(self, sub, *args):
            if sub == b"\n" and args:
                type(self).lines += 1
            return super().find(sub, *args)
    for which in ("tree", "parent"):
        headers = f"tree {ONE}\n".encode()
        if which == "parent":
            headers += f"parent {ZERO}\n".encode()
        p = Counting(headers + b" \n" * 10_000 + b"author A\ncommitter C\n\nmessage\n")
        Counting.lines = 0
        dt, v = cpu(lambda: S._canonical_commit("f" * 40, p, object_format="sha1"))
        print(f"count[{which}]: header lines read = {Counting.lines} -> {v[:60]}")

if MODE in ("all", "linear"):
    for hdr in (b"gpgsig -----BEGIN PGP SIGNATURE-----", b"x-extra v"):
        prev = None
        for n in (800_000, 1_600_000, 3_200_000):
            p = f"tree {ONE}\n".encode() + b"author a <a> 0 +0000\ncommitter a <a> 0 +0000\n" + hdr + b"\n" + b" \n" * n + b"\nm\n"
            dt, v = cpu(lambda: S._canonical_commit("f" * 40, p, object_format="sha1"))
            r = f" ({dt/prev:.2f}x prev)" if prev else ""
            print(f"{hdr.split()[0].decode()} continuations N={n:,}: CPU {dt:.3f}s{r} -> {v[:40]}")
            prev = dt
    # continuations under author (in 'committer' phase): also parse
    n = 800_000
    p = f"tree {ONE}\n".encode() + b"author a <a> 0 +0000\n" + b" \n" * n + b"committer a <a> 0 +0000\n\nm\n"
    dt, v = cpu(lambda: S._canonical_commit("f" * 40, p, object_format="sha1"))
    print(f"author continuations N={n:,}: CPU {dt:.3f}s -> {v[:40]}")

if MODE in ("all", "zlib"):
    n_max = (S.MAX_TREE_OBJECT_BYTES - 200) // 2
    big = b"tree " + b"a" * 40 + b"\n" + b" \n" * n_max + TAIL
    header = f"commit {len(big)}\0".encode()
    for level in (1, 6, 9):
        print(f"ceiling commit payload {len(big):,} B, zlib level {level}: {len(zlib.compress(header + big, level)):,} B")
