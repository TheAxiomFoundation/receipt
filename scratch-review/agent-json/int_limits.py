"""Integer-literal bound under the process int-string limit, per tree.

Run under PYTHONINTMAXSTRDIGITS unset / 0 / 640, once per tree:
    PYTHONINTMAXSTRDIGITS=0 python int_limits.py <tree-dir> <workdir>
Entry points: tsa.load_json, release_chain.load_manifest, tsa.verify_witness
(genuinely stamped record, via the tree's own test fixtures).
"""
import json
import pathlib
import sys
import tempfile
import types

tree = pathlib.Path(sys.argv[1]).resolve()
sys.path[:0] = [str(tree / "src"), str(tree / "tests")]
import receipt  # noqa: E402

work = pathlib.Path(tempfile.mkdtemp(prefix="int-", dir=sys.argv[2]))
print("receipt:", receipt.__file__, "int_max_str_digits:", sys.get_int_max_str_digits())
from receipt import release_chain as rc, tsa  # noqa: E402


def outcome(fn):
    try:
        r = fn()
        if isinstance(r, dict):
            return "ACCEPT dict keys=" + ",".join(sorted(r))
        if hasattr(r, "status"):
            return f"VERIFIED ({r.status})"
        return f"ACCEPT {type(r).__name__}"
    except Exception as exc:  # noqa: BLE001
        text = str(exc).replace(str(work), "<W>")
        return f"{type(exc).__name__}: {text[:220]}"


D = lambda n: "9" * n  # noqa: E731
json_cases = {
    "obj_int4300": '{"x": %s}' % D(4300),
    "obj_int4301": '{"x": %s}' % D(4301),
    "obj_int5000": '{"x": %s}' % D(5000),
    "obj_negint5000": '{"x": -%s}' % D(5000),
    "obj_int700": '{"x": %s}' % D(700),
    "obj_int640": '{"x": %s}' % D(640),
    "obj_neg0": '{"x": -0}',
    "obj_float5000": '{"x": %s.5}' % D(5000),
    "obj_1e400": '{"x": 1e400}',
    "obj_int5000_then_syntax_error": '{"x": %s, }' % D(5000),
    "obj_int700_then_syntax_error": '{"x": %s, }' % D(700),
    "arr_int5000": "[%s]" % D(5000),
    "arr_int700": "[%s]" % D(700),
}
for name, text in json_cases.items():
    p = work / f"{name}.json"
    p.write_text(text)
    print(f"load_json {name}: {outcome(lambda: tsa.load_json(p))}")

# load_manifest: refusal order reaches releaseIndex / schemaVersion first.
spec = types.SimpleNamespace(schema_version="receipt_test_manifest_v1")
base_manifest = {
    "schemaVersion": "receipt_test_manifest_v1",
    "releaseIndex": "@@",
    "previousManifestSha256": None,
    "state": {},
    "append": None,
    "createdAtUtc": "2026-09-28T00:00:00Z",
    "producer": {"repo": "r", "branch": "b"},
}
for name, field, lit in (
    ("releaseIndex5000", "releaseIndex", D(5000)),
    ("releaseIndex700", "releaseIndex", D(700)),
    ("releaseIndex4300", "releaseIndex", D(4300)),
    ("schemaVersion5000", "schemaVersion", D(5000)),
):
    m = dict(base_manifest)
    m[field] = "@@"
    if field != "releaseIndex":
        m["releaseIndex"] = 0
    text = json.dumps(m).replace('"@@"', lit) + "\n"
    p = work / f"m-{name}.json"
    p.write_text(text)
    print(f"load_manifest {name}: {outcome(lambda: rc.load_manifest(p, spec))}")

# verify_witness over a genuinely stamped record carrying a big integer.
import test_tsa as T  # noqa: E402
from corpus_fixture import build_local_tsa, certificate_pins  # noqa: E402

authority = build_local_tsa(work / "alpha", "alpha", "1.3.6.1.4.1.99999.1.1")
alpha = T.LocalAnchor(
    anchor_id="alpha-root-2026",
    endpoint="https://alpha.timestamp.invalid/tsr",
    tsa=authority,
    root_pins=certificate_pins(authority.root_pem),
    signer_pins=certificate_pins(authority.signer_pem),
)
for name, extra in (
    ("control", b""),
    ("big5000", b', "big": ' + D(5000).encode()),
    ("big700", b', "big": ' + D(700).encode()),
    ("big5000_then_syntax_error", b', "big": ' + D(5000).encode() + b", "),
):
    wt = T.build_witness_tree(work / f"rec-{name}", (alpha,))
    payload = json.loads(wt.record.read_text())
    data = json.dumps(payload)[:-1].encode() + extra + b"}\n"
    wt.record.write_bytes(data)
    digest = T.sha256_bytes(data)
    token = wt.tokens[alpha.anchor_id]
    alpha.tsa.stamp(digest, token)

    def refresh(witness, digest=digest, token=token):
        witness["digestSha256"] = digest
        witness["anchorOutcomes"][0]["tokenSha256"] = T.sha256_bytes(token.read_bytes())

    T.rewrite_witness(wt, refresh)
    print(f"verify_witness {name}: {outcome(lambda: T.verify_tree(wt))}")
