"""P09b: end-to-end select() on a commit with N=1,600,000 continuation lines,
plus the zlib size of a commit at the 64 MiB MAX_TREE_OBJECT_BYTES ceiling."""
import resource, time, zlib
from common import *
import receipt.snapshot as S
print('receipt.snapshot from', S.__file__)
from receipt.snapshot import TreeSnapshot, SnapshotError

N = 1_600_000
root = new_repo()
tree = mktree(root, [(b"100644", b"x", hash_object(root, "blob", b"x\n"))])
tail = b"author a <a> 0 +0000\ncommitter a <a> 0 +0000\n\nm\n"
c = hash_object(root, "commit", b"tree " + tree.encode() + b"\n" + b" \n" * N + tail)
git(root, "update-ref", "refs/heads/main", c)
loose = root / ".git/objects" / c[:2] / c[2:]
cpu0 = resource.getrusage(resource.RUSAGE_SELF).ru_utime
t = time.time()
try:
    TreeSnapshot.select(root)
    print("select: accepted")
except SnapshotError as e:
    cpu = resource.getrusage(resource.RUSAGE_SELF).ru_utime - cpu0
    print(f"select N={N:,} (payload {3.2:.1f} MB, loose object {loose.stat().st_size:,} bytes): refused after "
          f"{time.time()-t:.0f}s wall / {cpu:.0f}s CPU: {e}")
n_max = (S.MAX_TREE_OBJECT_BYTES - 200) // 2
big = b"tree " + b"a" * 40 + b"\n" + b" \n" * n_max + tail
print(f"commit at the ceiling: {len(big):,} payload bytes -> {len(zlib.compress(big, 9)):,} bytes as a loose object")
