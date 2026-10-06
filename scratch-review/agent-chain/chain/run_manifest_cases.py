"""Run one tree's release_chain.load_manifest over chain/manifest_cases.

Usage: python run_manifest_cases.py <tree_dir> <out.jsonl>
One tree per process; the fixture spec is loaded with that tree's load_spec.
Output per case: {"file", "name", "outcome"} with the manifest path replaced by <P>.
"""

from __future__ import annotations

import collections
import json
import pathlib
import sys
import time

TREE = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(TREE / "src"))
from receipt import release_chain  # noqa: E402
from receipt.verify import load_spec  # noqa: E402

assert pathlib.Path(release_chain.__file__).resolve().is_relative_to(TREE)
print("release_chain from", release_chain.__file__, file=sys.stderr)
HERE = pathlib.Path(__file__).parent
SPEC = load_spec(HERE / "fixture/repo/verification/spec.py").verification.chain
CASES = HERE / "manifest_cases"
index = json.loads((CASES / "index.json").read_text())
WORK = HERE / f"work_lm_{TREE.name}"
WORK.mkdir(exist_ok=True)
target = WORK / "0000-0000000000000000.json"
counts = collections.Counter()
t0 = time.process_time()
with open(sys.argv[2], "w") as out:
    for fname, name in index.items():
        target.write_bytes((CASES / fname).read_bytes())
        try:
            payload, raw, digest = release_chain.load_manifest(target, SPEC)
            outcome = f"ACCEPT {digest}"
            counts["accept"] += 1
        except release_chain.ReleaseChainError as exc:
            outcome = "ReleaseChainError: " + str(exc).replace(str(target), "<P>")
            counts["ReleaseChainError"] += 1
        except BaseException as exc:  # noqa: BLE001
            outcome = f"CRASH {type(exc).__name__}: " + str(exc).replace(str(target), "<P>")[:300]
            counts["CRASH " + type(exc).__name__] += 1
        out.write(json.dumps({"file": fname, "name": name, "outcome": outcome}) + "\n")
print(json.dumps({"tree": TREE.name, "cpu_s": round(time.process_time() - t0, 1), "counts": dict(counts)}))
