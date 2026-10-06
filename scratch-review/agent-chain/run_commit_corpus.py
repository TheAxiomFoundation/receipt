"""Run one tree's _canonical_commit over commit_corpus.jsonl.

Usage: python run_commit_corpus.py <tree_dir> <out.jsonl>
Imports receipt from <tree_dir>/src only (one tree per process).
Each output line: {"id", "outcome"} where outcome is
  "OK tree=<t> parents=<p>" or "<ExcType>: <message>".
For the head tree it also writes "new_site": true when a source-transformed
copy of the head parser refuses at the new first-continuation raise.
"""

from __future__ import annotations

import collections
import inspect
import json
import pathlib
import sys
import time

tree = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(tree / "src"))
import receipt.snapshot as S  # noqa: E402

assert pathlib.Path(S.__file__).resolve().is_relative_to(tree), S.__file__
print("receipt.snapshot from", S.__file__, file=sys.stderr)

marked = None
Marker = None
source = inspect.getsource(S._canonical_commit)
if "Refused here, at the first continuation" in source:
    needle = '            if current_name in {b"tree", b"parent"}:\n'
    before, after = source.split(needle, 1)
    old = 'raise SnapshotError(\n                    f"commit {oid} is not a canonical commit object"\n                )'
    assert old in after
    after = after.replace(old, old.replace("SnapshotError", "_Marker"), 1)
    patched = (before + needle + after).replace("def _canonical_commit(", "def _marked(", 1)

    class _Marker(S.SnapshotError):
        pass

    ns = dict(vars(S))
    ns["_Marker"] = _Marker
    exec(compile(patched, "<marked>", "exec"), ns)
    marked, Marker = ns["_marked"], _Marker

counts = collections.Counter()
corpus = pathlib.Path(__file__).with_name("commit_corpus.jsonl")
started = time.process_time()
with corpus.open() as src, open(sys.argv[2], "w") as out:
    for line in src:
        case = json.loads(line)
        payload = bytes.fromhex(case["hex"])
        oid = "f" * (40 if case["fmt"] == "sha1" else 64)
        try:
            result = S._canonical_commit(
                oid, payload, object_format=case["fmt"], parent_limit=case["limit"]
            )
            outcome = f"OK tree={result.tree} parents={','.join(result.parents)} oid={result.oid}"
            counts["parse"] += 1
        except BaseException as exc:  # noqa: BLE001 - record everything
            outcome = f"{type(exc).__name__}: {exc}"
            counts[type(exc).__name__] += 1
            if "ancestry walk exceeds" in str(exc):
                counts["budget"] += 1
        record = {"id": case["id"], "outcome": outcome}
        if marked is not None:
            try:
                marked(oid, payload, object_format=case["fmt"], parent_limit=case["limit"])
            except Marker:
                record["new_site"] = True
                counts["new_site"] += 1
            except BaseException:  # noqa: BLE001
                pass
        out.write(json.dumps(record) + "\n")
counts["cases"] = sum(1 for _ in corpus.open())
print(json.dumps({"file": S.__file__, "cpu_s": round(time.process_time() - started, 2), "counts": dict(counts)}))
