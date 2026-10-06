"""Shared fixture helpers for L3 probes (scratch only)."""
from __future__ import annotations
import hashlib, os, pathlib, subprocess, sys, tempfile, zlib

# Source under test: $RECEIPT_SRC, else this job's workspace, else the caller's
# worktree (both detached at 8b24e57 = receipt 0.6.2 candidate).
_CANDIDATES = [os.environ.get("RECEIPT_SRC"),
               "/Users/maxghenis/.subfleet/worktrees/20260927-213857-receipt-062-l3/src",
               "/Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-062-review-L3/src"]
SRC = os.environ["RECEIPT_SRC"]  # repointed: must be set (agent-chain)
assert (pathlib.Path(SRC) / "receipt" / "snapshot.py").exists(), SRC
sys.path.insert(0, SRC)

CLEAN_ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
CLEAN_ENV.update({
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.test",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.test",
    "GIT_AUTHOR_DATE": "1700000000 +0000", "GIT_COMMITTER_DATE": "1700000000 +0000",
})

def git(root, *args, input_bytes=None, check=True, env=None):
    p = subprocess.run(["git", "-C", os.fspath(root), *args], input=input_bytes,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env or CLEAN_ENV)
    if check and p.returncode:
        raise RuntimeError(f"git {args} failed: {p.stderr.decode(errors='replace')}")
    return p

def out(root, *args, **kw):
    return git(root, *args, **kw).stdout.decode().strip()

def hash_object(root, kind, payload):
    return out(root, "hash-object", "--literally", "-t", kind, "-w", "--stdin", input_bytes=payload)

def tree_entry(mode, name, oid):
    return mode + b" " + name + b"\0" + bytes.fromhex(oid)

def mktree(root, entries):
    ordered = sorted(entries, key=lambda e: e[1] + (b"/" if e[0] == b"40000" else b""))
    return hash_object(root, "tree", b"".join(tree_entry(*e) for e in ordered))

def mkcommit(root, tree, parents=(), message=b"m\n"):
    p = bytearray(f"tree {tree}\n".encode())
    for parent in parents:
        p += f"parent {parent}\n".encode()
    p += b"author t <t@example.test> 0 +0000\ncommitter t <t@example.test> 0 +0000\n\n" + message
    return hash_object(root, "commit", bytes(p))

def new_repo(parent=None, name="repo"):
    base = pathlib.Path(tempfile.mkdtemp(prefix="l3-", dir=parent or os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp")))
    root = base / name
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    return root

def write_loose(root, oid, kind, payload):
    """Overwrite the loose object file for `oid` with different content (tamper)."""
    path = root / ".git" / "objects" / oid[:2] / oid[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.chmod(0o644)
    path.write_bytes(zlib.compress(f"{kind} {len(payload)}\0".encode() + payload))
