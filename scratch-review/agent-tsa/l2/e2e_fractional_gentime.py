"""A genuine token from the pinned signer whose genTime carries fractional seconds
(OpenSSL TSA config `clock_precision_digits = 3`). OpenSSL verifies it; receipt.tsa
refuses the witness and returns a malformed gen_time from the public token verifier."""
import sys, pathlib, subprocess, re
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import harness as H
from harness import T, sha256_bytes
from receipt import tsa

alpha = H.anchors(1)[0]
d = alpha.tsa.directory
frac = d / "frac.cnf"
frac.write_text((d / "tsa.cnf").read_text() + "clock_precision_digits = 3\n")

print("_format_utc on 12:00:00.5 UTC ->", repr(tsa._format_utc(H.T.datetime(2026, 9, 27, 12, 0, 0, 500000, tzinfo=H.T.UTC))))

for attempt in range(20):
    t = H.tree(1)
    digest = sha256_bytes(t.record.read_bytes())
    q = d / "frac.tsq"; out = d / "frac.tsr"
    subprocess.run(["openssl", "ts", "-query", "-digest", digest, "-sha256", "-cert", "-out", str(q)], check=True, capture_output=True)
    subprocess.run(["openssl", "ts", "-reply", "-config", str(frac), "-section", "tsa_config", "-queryfile", str(q), "-out", str(out)], check=True, capture_output=True, cwd=d)
    text = subprocess.run(["openssl", "ts", "-reply", "-in", str(out), "-text"], capture_output=True, text=True).stdout
    stamp = re.search(r"Time stamp: (.*)", text).group(1)
    if re.search(r"\.\d*[1-9]", stamp):
        break
print("genTime per `openssl ts -reply -text`:", stamp)
data = out.read_bytes()
H.set_token(t, alpha.anchor_id, data)
tok = t.tokens[alpha.anchor_id]
ok = T.openssl_ts_verifies(t.record, tok, alpha.tsa.root_pem)
print("control: `openssl ts -verify` against the pinned root accepts:", ok)
print("verify_witness:", H.verdict(lambda: T.verify_tree(t)))
claim = T.token_claim(t, alpha)
ev = tsa.verify_timestamp_token(t.record, claim, t.reference, spec=t.spec, records=t.records)
print("verify_timestamp_token accepted; evidence.gen_time =", repr(ev.gen_time))
# and a witness that declares the genTime correctly is refused as a mismatch
good = re.sub(r"\+00:$", "Z", ev.gen_time)
T.rewrite_witness(t, lambda p: [o.__setitem__("tsaGenTime", good) for o in p["anchorOutcomes"]])
print(f"declaring tsaGenTime={good!r}:", H.verdict(lambda: T.verify_tree(t)))
