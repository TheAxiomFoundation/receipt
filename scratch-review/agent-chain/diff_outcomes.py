"""Compare base and head JSONL outcomes by id.  Usage: diff_outcomes.py base.jsonl head.jsonl"""

import collections
import json
import sys

base = {}
for line in open(sys.argv[1]):
    r = json.loads(line)
    base[r["id"]] = r["outcome"]
head = {}
new_site = 0
new_site_ids = []
for line in open(sys.argv[2]):
    r = json.loads(line)
    head[r["id"]] = r["outcome"]
    if r.get("new_site"):
        new_site += 1
        new_site_ids.append(r["id"])
assert base.keys() == head.keys(), (len(base), len(head))
diffs = [(k, base[k], head[k]) for k in base if base[k] != head[k]]
kinds = collections.Counter(v.split(":")[0].split(" ")[0] for v in head.values())
print(json.dumps({
    "cases": len(base),
    "mismatches": len(diffs),
    "head_outcome_kinds": dict(kinds),
    "head_new_site_hits": new_site,
    "adversarial_new_site_hits": sum(1 for i in new_site_ids if not i.startswith("rnd")),
    "random_new_site_hits": sum(1 for i in new_site_ids if i.startswith("rnd")),
}, indent=2))
for k, b, h in diffs[:50]:
    print("MISMATCH", k, "\n  base:", b, "\n  head:", h)
