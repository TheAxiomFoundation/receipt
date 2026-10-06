import sys, pathlib, subprocess, tempfile
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import harness as H
from harness import T, sha256_bytes
a = H.anchors(1)[0]
def try_policy(label, body):
    t = H.tree(1)
    d = bytes.fromhex(sha256_bytes(t.record.read_bytes()))
    tst = H.tst_info(policy_body=body, digest=d, gen_time=b"20260927120000Z")
    resp = H.sign_tst_info(tst, a.tsa.directory / "signer.pem", a.tsa.directory / "signer.key")
    H.set_token(t, a.anchor_id, resp)
    v = H.verdict(lambda: T.verify_tree(t))
    print(f"[{label}] {v[:160]}")
    with tempfile.TemporaryDirectory() as dd:
        p = pathlib.Path(dd) / "r.tsr"; p.write_bytes(resp)
        c = subprocess.run(["openssl", "ts", "-reply", "-config", "/dev/null", "-in", str(p), "-token_out", "-out", str(pathlib.Path(dd)/"t.der")], capture_output=True)
        print("    ts -reply rc", c.returncode, c.stderr.decode()[-300:].strip().replace("\n", " | "))
try_policy("control: normal policy (the anchor's own)", H.oid_body(a.tsa.policy_oid))
for n in (10, 100, 500, 1000, 2100):
    try_policy(f"subidentifier of {n} octets", bytes([0x2B]) + bytes([0xFF]) * n + bytes([0x7F]))
