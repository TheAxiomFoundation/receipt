"""End-to-end: attacker-writable files in the records tree that make
verify_witness raise an interpreter exception instead of TsaError.
Each case starts from a fresh, verifying tree and changes one input."""
import json, sys, pathlib, re
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import harness as H
from harness import T, sha256_bytes

def case(label, mutate, count=1, **kw):
    t = H.tree(count, **kw)
    assert H.verdict(lambda: T.verify_tree(t)).startswith("ACCEPTED")
    mutate(t)
    print(f"[{label}]\n    {H.verdict(lambda: T.verify_tree(t))}")

# 1. genTime patched in place in a genuine response (same length, signature now invalid)
def bad_gentime(value: bytes):
    def m(t):
        a = next(iter(t.tokens)); data = t.tokens[a].read_bytes()
        found = re.search(rb"\x18\x0f(\d{14}Z)", data)
        assert found, "genTime not found"
        patched = data[:found.start(1)] + value + data[found.end(1):]
        H.set_token(t, a, patched)
    return m
case("token genTime 20261301000000Z (month 13), bytes patched, unsigned", bad_gentime(b"20261301000000Z"))
case("token genTime 20260230000000Z (Feb 30)", bad_gentime(b"20260230000000Z"))
case("token genTime 20261231235960Z (leap second)", bad_gentime(b"20261231235960Z"))

# 2. policy OID with a 2100-octet subidentifier, in a TSTInfo signed by an arbitrary key
def huge_policy(t):
    a = H.anchors(1)[0]
    record_digest = bytes.fromhex(sha256_bytes(t.record.read_bytes()))
    body = bytes([0x2B]) + bytes([0xFF]) * 2100 + bytes([0x7F])
    tst = H.tst_info(policy_body=body, digest=record_digest, gen_time=b"20260927120000Z")
    resp = H.sign_tst_info(tst, a.tsa.directory / "signer.pem", a.tsa.directory / "signer.key")
    H.set_token(t, a.anchor_id, resp)
case("token policy OID with a 2100-octet subidentifier", huge_policy)

# 3. the record's own recordedAt at the bottom of datetime's range
def record_claim(value):
    def m(t):
        payload = json.loads(t.record.read_text()); payload["recordedAt"] = value
        t.record.write_bytes(H.canonical_bytes(payload) + b"\n")
        digest = sha256_bytes(t.record.read_bytes())
        T.rewrite_witness(t, lambda p: p.__setitem__("digestSha256", digest))
    return m
case("record recordedAt 0001-01-01T00:00:00Z (lead 300)", record_claim("0001-01-01T00:00:00Z"))
case("record recordedAt 0001-01-01T00:00:00+14:00", record_claim("0001-01-01T00:00:00+14:00"))

# 4. the witness sidecar
def sidecar(data: bytes):
    return lambda t: t.witness.write_bytes(data)
case("sidecar nested 100000 deep", sidecar(b"[" * 100000 + b"]" * 100000))
case("sidecar holding a 5000-digit integer", sidecar(b'{"x": ' + b"9" * 5000 + b"}"))

# 5. the record under witness (sidecar digest updated to match)
def record_bytes(data: bytes):
    def m(t):
        t.record.write_bytes(data)
        digest = sha256_bytes(data)
        T.rewrite_witness(t, lambda p: p.__setitem__("digestSha256", digest))
    return m
case("record nested 100000 deep", record_bytes(b"[" * 100000 + b"]" * 100000))
case("record holding a 5000-digit integer", record_bytes(b'{"x": ' + b"9" * 5000 + b"}"))

# 6. CHAIN_GENESIS.json
case("genesis nested 100000 deep", lambda t: (t.records / "CHAIN_GENESIS.json").write_bytes(b"[" * 100000 + b"]" * 100000))

# 7. the trust bundle file (byte-pinned by the consumer, but read and canonicalised
#    before the pin is compared)
HDR = b'{"schemaVersion":"thesis_tsa_trust_bundle_v1","bundleId":"tsa-anchors-v1",'
case("bundle file with NaN", lambda t: t.bundle.write_bytes(HDR + b'"x":NaN}'))
case("bundle file nested 600 deep", lambda t: t.bundle.write_bytes(HDR + b'"x":' + b"[" * 600 + b"]" * 600 + b"}"))
case("bundle file holding a 5000-digit integer", lambda t: t.bundle.write_bytes(HDR + b'"x":' + b"9" * 5000 + b"}"))
# control: an ordinary tampered bundle gets the named refusal
case("control: bundle file with an extra ordinary key", lambda t: t.bundle.write_bytes(HDR + b'"x":1}'))
