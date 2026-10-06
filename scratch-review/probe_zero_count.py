import hashlib, json, sys, os
which = sys.argv[1]
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "trees", which, "src"))
import receipt.append_gate as ag
print(ag.__file__)
class Spec: prefix_schema_version = "v1"
class Cand: spec = Spec()
empty_nl = hashlib.sha256(b"\n").hexdigest()
empty = hashlib.sha256(b"").hexdigest()
for label, h in (("sha256(b'\\n')", empty_nl), ("sha256(b'')", empty)):
    manifest = json.dumps({"schemaVersion": "v1", "prefixLineCount": 0, "lineSha256s": [], "prefixSha256": h})
    try:
        ag.check_prefix(["{}"], manifest, Cand())
        print(label, "-> PASS")
    except Exception as e:
        print(label, "->", type(e).__name__, e)
