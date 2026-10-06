"""Real on-disk sizes of the MAX_TREE_OBJECT_BYTES continuation commit: loose (git's
default core.looseCompression) and packed (git pack-objects default compression)."""
import os, subprocess, sys, pathlib, tempfile
sys.path.insert(0, os.environ["RECEIPT_SRC"])
import receipt.snapshot as S
env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
root = pathlib.Path(tempfile.mkdtemp(prefix="sizes-", dir=pathlib.Path(__file__).parent / "tmp")) / "r"
root.mkdir()
run = lambda *a, **k: subprocess.run(["git", "-C", str(root), *a], env=env, check=True, capture_output=True, **k)
run("init", "-q")
print("core.looseCompression:", subprocess.run(["git", "-C", str(root), "config", "--get", "core.looseCompression"], env=env, capture_output=True, text=True).stdout.strip() or "(unset -> git default)")
tail = b"author a <a> 0 +0000\ncommitter a <a> 0 +0000\n\nm\n"
n_max = (S.MAX_TREE_OBJECT_BYTES - 200) // 2
big = b"tree " + b"a" * 40 + b"\n" + b" \n" * n_max + tail
oid = run("hash-object", "--literally", "-t", "commit", "-w", "--stdin", input=big).stdout.decode().strip()
loose = root / ".git/objects" / oid[:2] / oid[2:]
print(f"payload {len(big):,} B (MAX_TREE_OBJECT_BYTES={S.MAX_TREE_OBJECT_BYTES:,}); loose object {loose.stat().st_size:,} B")
pack = subprocess.run(["git", "-C", str(root), "pack-objects", "--stdout"], input=(oid + "\n").encode(), env=env, capture_output=True, check=True).stdout
print(f"pack-objects --stdout (one object): {len(pack):,} B")
