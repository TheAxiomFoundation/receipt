"""Shared harness: a real local RFC 3161 authority and a witness tree, built with
the package's own test fixtures (tests/test_tsa.py, tests/corpus_fixture.py)."""
from __future__ import annotations
import json, os, pathlib, subprocess, sys, tempfile, hashlib, dataclasses
TREES = pathlib.Path("/Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-crash-refusal-review/scratch-review/trees")
TREE_NAME = os.environ["TREE"]
WS = TREES / TREE_NAME
AGENT = pathlib.Path("/Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-crash-refusal-review/scratch-review/agent-tsa")
tempfile.tempdir = str(AGENT / "tmp")
sys.path.insert(0, str(WS / "src"))
sys.path.insert(0, str(WS / "tests"))
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
sys.dont_write_bytecode = True
import test_tsa as T  # noqa: E402
from corpus_fixture import build_local_tsa, certificate_pins, sha256_bytes  # noqa: E402
from receipt import tsa  # noqa: E402
from receipt.tsa import TsaError  # noqa: E402
from receipt.canonical import canonical_bytes  # noqa: E402
import receipt as _receipt_pkg  # noqa: E402
print("# receipt loaded from", _receipt_pkg.__file__, flush=True)

SCRATCH = pathlib.Path(__file__).parent
_CACHE = AGENT / "tmp" / f"_authorities_{TREE_NAME}"


def anchors(count: int = 1):
    out = []
    for index, name in enumerate(("alpha", "beta")[:count], start=1):
        d = _CACHE / name
        if not (d / "signer.pem").exists():
            authority = build_local_tsa(d, name, f"1.3.6.1.4.1.99999.{index}.1")
        else:
            authority = T.LocalTsa(name=name, directory=d, root_pem=d / f"{name}-root.pem",
                                   policy_oid=f"1.3.6.1.4.1.99999.{index}.1",
                                   signer_certificate_sha256="", signer_spki_sha256="")
        out.append(T.LocalAnchor(anchor_id=f"{name}-root-2026",
                                 endpoint=f"https://{name}.timestamp.invalid/tsr",
                                 tsa=authority,
                                 root_pins=certificate_pins(authority.root_pem),
                                 signer_pins=certificate_pins(authority.signer_pem)))
    return tuple(out)


def tree(count: int = 1, **kw):
    root = pathlib.Path(tempfile.mkdtemp(prefix="l2-tree-")).resolve()
    return T.build_witness_tree(root, anchors(count), **kw)


def verdict(fn):
    """Run fn and describe how it ended: accepted, TsaError, or another exception."""
    try:
        r = fn()
        return f"ACCEPTED status={getattr(r, 'status', r)!r}"
    except TsaError as e:
        return f"TsaError: {str(e)[:220]}"
    except BaseException as e:  # noqa: BLE001
        return f"** {type(e).__module__}.{type(e).__name__} (NOT TsaError): {str(e)[:220]}"


def set_token(t, anchor_id, data: bytes):
    token = t.tokens[anchor_id]
    token.write_bytes(data)
    def refresh(p):
        for o in p.get("anchorOutcomes", [p]):
            if o.get("tsaAnchorId") == anchor_id:
                o["tokenSha256"] = sha256_bytes(data)
    T.rewrite_witness(t, refresh)


# ---- minimal DER --------------------------------------------------------------
def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b

def tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body

def oid_body(text: str) -> bytes:
    arcs = [int(a) for a in text.split(".")]
    subs = [arcs[0] * 40 + arcs[1], *arcs[2:]]
    out = b""
    for s in subs:
        chunk = [s & 0x7F]
        s >>= 7
        while s:
            chunk.append(0x80 | (s & 0x7F)); s >>= 7
        out += bytes(reversed(chunk))
    return out

def tst_info(*, policy_body: bytes, digest: bytes, gen_time: bytes, serial: int = 7) -> bytes:
    alg = tlv(0x30, tlv(0x06, oid_body("2.16.840.1.101.3.4.2.1")) + b"\x05\x00")
    imprint = tlv(0x30, alg + tlv(0x04, digest))
    return tlv(0x30, tlv(0x02, b"\x01") + tlv(0x06, policy_body) + imprint
               + tlv(0x02, bytes([serial])) + tlv(0x18, gen_time))


def sign_tst_info(tst: bytes, cert: pathlib.Path, key: pathlib.Path) -> bytes:
    """CMS-sign a TSTInfo as eContent (id-smime-ct-TSTInfo) and wrap it in a
    granted TimeStampResp. The signer is whatever key is given -- the parse
    under test runs before any signature is checked."""
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        (d / "tst.der").write_bytes(tst)
        subprocess.run(["openssl", "cms", "-sign", "-binary", "-nodetach", "-in", str(d / "tst.der"),
                        "-econtent_type", "1.2.840.113549.1.9.16.1.4", "-signer", str(cert),
                        "-inkey", str(key), "-outform", "DER", "-out", str(d / "tok.der"),
                        "-md", "sha256"], check=True, capture_output=True)
        token = (d / "tok.der").read_bytes()
    return tlv(0x30, tlv(0x30, tlv(0x02, b"\x00")) + token)
