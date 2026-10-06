"""Compare base vs head outcome JSONL files from run_diff.py.

Buckets:
  same                 identical kind and message
  crash->refusal       base CRASH, head AppendError (the intended change)
  crash->crash         both crash (report head crashes separately)
  crash->ok            base CRASH, head OK
  CHANGED              base was OK or AppendError and head differs (verdict or text)
Also lists every head CRASH (totality).
"""

from __future__ import annotations

import collections
import json
import sys

base_path, head_path = sys.argv[1], sys.argv[2]
base = [json.loads(x) for x in open(base_path)]
head = [json.loads(x) for x in open(head_path)]
assert len(base) == len(head)
buckets: dict[str, list] = collections.defaultdict(list)
head_crashes = []
for b, h in zip(base, head):
    assert b["id"] == h["id"]
    if h["kind"].startswith("CRASH"):
        head_crashes.append(h)
    if b["kind"] == h["kind"] and b["msg"] == h["msg"]:
        buckets["same"].append(b)
        continue
    bc, hc = b["kind"].startswith("CRASH"), h["kind"].startswith("CRASH")
    if bc and h["kind"] == "AppendError":
        buckets["crash->refusal"].append((b, h))
    elif bc and hc:
        buckets["crash->crash"].append((b, h))
    elif bc and h["kind"] == "OK":
        buckets["crash->ok"].append((b, h))
    elif "JSON nesting exceeds 128 levels" in h["msg"] and "JSON nesting exceeds 128 levels" not in b["msg"]:
        buckets["changed:depth-bound(c)"].append((b, h))
    elif b["id"].startswith("check_prefix") and "cumulative hash mismatch" in (b["msg"] + h["msg"]):
        buckets["changed:cumulative(K1?)"].append((b, h))
    else:
        buckets["CHANGED"].append((b, h))

print({k: len(v) for k, v in buckets.items()})
print("head crashes:", len(head_crashes))
for h in head_crashes[:50]:
    print("  HEAD CRASH", h["id"], h["kind"], h.get("at"), h["msg"][:150], "|", h["note"])

print("\n=== CHANGED (base OK/refusal, head differs) ===")
groups = collections.Counter()
for b, h in buckets["CHANGED"]:
    key = (b["kind"], b["msg"][:70], h["kind"], h["msg"][:70])
    groups[key] += 1
for key, n in groups.most_common():
    print(n, "x", key)
print("\n--- CHANGED examples ---")
seen = set()
for b, h in buckets["CHANGED"]:
    key = (b["kind"], b["msg"][:70], h["kind"], h["msg"][:70])
    if key in seen:
        continue
    seen.add(key)
    print(b["id"], "|", ascii(b["note"]))
    print("   base:", b["kind"], ascii(b["msg"][:300]))
    print("   head:", h["kind"], ascii(h["msg"][:300]))

print("\n=== cumulative-hash changes: notes ===")
cn = collections.Counter()
for b, h in buckets["changed:cumulative(K1?)"]:
    n = b["note"]
    cn[(n.split("/")[1], n.split("/")[3], b["kind"], h["kind"])] += 1
for key, n in sorted(cn.items(), key=str):
    print(n, "x", ascii(key))
print("\n=== crash->refusal summary (by base crash type / head msg head) ===")
g2 = collections.Counter()
for b, h in buckets["crash->refusal"]:
    g2[(b["kind"], b.get("at"), h["msg"][:60])] += 1
for key, n in g2.most_common():
    print(n, "x", key)
for name in ("crash->crash", "crash->ok"):
    print(f"\n=== {name} ===")
    for b, h in buckets[name][:20]:
        print(b["id"], b["note"], "|", b["kind"], b["msg"][:100], "->", h["kind"], h["msg"][:100])
