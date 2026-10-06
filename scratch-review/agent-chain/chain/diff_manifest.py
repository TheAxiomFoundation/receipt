import json, sys, collections
b = {json.loads(l)["file"]: json.loads(l) for l in open("lm_out_9c47a3d.jsonl")}
h = {json.loads(l)["file"]: json.loads(l) for l in open("lm_out_f8b1ddc.jsonl")}
assert b.keys() == h.keys()
cat = collections.Counter()
rows = []
for f in b:
    bo, ho, name = b[f]["outcome"], h[f]["outcome"], b[f]["name"]
    if bo == ho:
        cat["same"] += 1
        continue
    if bo.startswith("CRASH"):
        kind = "base-crash->head-" + ("refuse" if ho.startswith("ReleaseChainError") else ho[:10])
    elif "nesting exceeds 128" in ho:
        kind = "depth>128-textchange(base " + ("accept" if bo.startswith("ACCEPT") else "refuse") + ")"
    else:
        kind = "OTHER-CHANGE"
    cat[kind] += 1
    rows.append((kind, name, bo[:160], ho[:200]))
print(json.dumps(dict(cat), indent=1))
acc = collections.Counter(b[f]["name"].split("|")[0] for f in b if b[f]["outcome"].startswith("ACCEPT"))
print("accepted (base) by family:", dict(acc))
print("accepted non-rnd:", [b[f]["name"] for f in b if b[f]["outcome"].startswith("ACCEPT") and not b[f]["name"].startswith("rnd")])
for r in sorted(rows):
    if not r[1].startswith("rnd"):
        print(" | ".join(r))
print("--- rnd changes:", sum(1 for r in rows if r[1].startswith("rnd")))
for r in rows:
    if r[1].startswith("rnd"):
        print(" | ".join(r)[:400])
