"""P09: _canonical_commit rejoins continuation lines of `tree`/`parent` headers
with bytes `+=`, which is quadratic. A commit whose tree header is followed by
N one-byte continuation lines (" \\n") is refused only after O(N^2) copying.

Part 1: in-process timing of _canonical_commit for growing N (shows ~4x per 2x).
Part 2: end-to-end TreeSnapshot.select on such a commit (N=200,000), with its
zlib-compressed loose-object size, to show the refusal arrives late.
"""
import hashlib, os, time, zlib
from common import *
import receipt.snapshot as S
print('receipt.snapshot from', S.__file__)
from receipt.snapshot import TreeSnapshot, SnapshotError

def payload(n):
    return (b"tree " + b"a" * 40 + b"\n" + b" \n" * n +
            b"author a <a> 0 +0000\ncommitter a <a> 0 +0000\n\nm\n")

prev = None
for n in (25_000, 50_000, 100_000, 200_000):
    p = payload(n)
    t = time.process_time()
    try:
        S._canonical_commit("0" * 40, p, object_format="sha1")
        verdict = "accepted"
    except S.SnapshotError as e:
        verdict = f"SnapshotError({e})"[:60]
    dt = time.process_time() - t
    ratio = f" ({dt / prev:.1f}x previous)" if prev else ""
    print(f"N={n:>7,} payload={len(p)/1e6:5.2f} MB  CPU={dt:7.2f}s{ratio}  -> {verdict}")
    prev = dt
per_n2 = prev / 200_000 ** 2
n_max = (S.MAX_TREE_OBJECT_BYTES - 200) // 2
print(f"extrapolated CPU at the 64 MiB object ceiling (N={n_max:,}): ~{per_n2 * n_max ** 2 / 3600:,.0f} hours")

root = new_repo()
tree = mktree(root, [(b"100644", b"x", hash_object(root, "blob", b"x\n"))])
body = b"tree " + tree.encode() + b"\n" + b" \n" * 200_000 + b"author a <a> 0 +0000\ncommitter a <a> 0 +0000\n\nm\n"
c = hash_object(root, "commit", body)
git(root, "update-ref", "refs/heads/main", c)
loose = root / ".git/objects" / c[:2] / c[2:]
t = time.time()
try:
    TreeSnapshot.select(root)
    print("select: accepted")
except SnapshotError as e:
    print(f"select (N=200,000; loose object {loose.stat().st_size:,} bytes on disk): refused after "
          f"{time.time() - t:.1f}s wall: {e}")
