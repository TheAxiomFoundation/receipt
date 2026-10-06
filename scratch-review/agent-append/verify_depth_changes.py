"""For every base-vs-head change attributed to the depth bound, confirm the
refused line/manifest really nests more than 128 containers (json.loads view)."""
import json, sys, collections
sys.setrecursionlimit(100000)
inputs = {}
for raw in open("inputs.jsonl"):
    c = json.loads(raw)
    inputs[c["id"]] = c
base = [json.loads(x) for x in open("out/diff.9c47a3d.jsonl")]
head = [json.loads(x) for x in open("out/diff.f8b1ddc.jsonl")]

def depth(v):
    if isinstance(v, list):
        return 1 + max((depth(x) for x in v), default=0)
    if isinstance(v, dict):
        return 1 + max((depth(x) for x in v.values()), default=0)
    return 0

bad = 0; n = 0; exhausted = 0
for b, h in zip(base, head):
    if "exhausted the interpreter" in h["msg"]:
        exhausted += 1
    if "JSON nesting exceeds 128 levels" in h["msg"] and "JSON nesting exceeds 128 levels" not in b["msg"]:
        n += 1
        c = inputs[b["id"]]
        # which text was refused?
        msg = h["msg"]
        if msg.startswith("prefix manifest"):
            text = c["prefix_text"]
        else:
            num = int(msg.split()[1])
            text = c["lines"][num - 1]
        try:
            d = depth(json.loads(text))
        except Exception as exc:
            d = f"unparseable:{type(exc).__name__}"
        if not (isinstance(d, int) and d > 128):
            bad += 1
            print("NOT DEEP", b["id"], d, b["msg"][:80], "->", h["msg"][:80])
print(f"depth-bound changes: {n}; with json.loads depth <= 128: {bad}; head 'exhausted' messages: {exhausted}")
