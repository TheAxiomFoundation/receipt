"""verify_release_chain lets OverflowError out for times at the ends of the range.

Case A (file input): a genesis manifest whose createdAtUtc is within the first
clock_skew_seconds of year 1 ("0001-01-01T00:00:00Z"). The manifest is
canonical, schema-valid (parse_created_at accepts it), producer-signed and
witnessed by both TSAs; verify_release_receipts then computes
`created_at - timedelta(seconds=clock_skew_seconds)` and raises OverflowError.

Case B (argument): a genuine chain verified with clock_skew_seconds=10**15
(an int >= 0, which is all verify_release_chain checks) -> timedelta overflow.

Case C (argument): a genuine chain verified with now=datetime.max (UTC)
-> `current + timedelta(seconds=MAX_FUTURE_SECONDS)` overflows in verify_receipt.

Usage: PYTHONPATH=<tree>/src python repro_created_at.py <fixture_dir> <work_dir>
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import sys
import traceback
from datetime import datetime, timezone

import os
TREE = pathlib.Path(os.environ["RECEIPT_TREE"]).resolve()  # repointed (agent-chain)
sys.path.insert(0, str(TREE / "tests"))
sys.path.insert(0, str(TREE / "src"))
from corpus_fixture import LocalTsa  # noqa: E402
from receipt import release_chain  # noqa: E402
from receipt.canonical import canonical_bytes  # noqa: E402
from receipt.sign import sign_payload  # noqa: E402
from receipt.verify import load_spec  # noqa: E402

FIXTURE = pathlib.Path(sys.argv[1])
WORK = pathlib.Path(sys.argv[2])
print("release_chain module:", release_chain.__file__)


def fresh() -> pathlib.Path:
    if WORK.exists():
        shutil.rmtree(WORK)
    shutil.copytree(FIXTURE / "repo", WORK / "repo", symlinks=True)
    return WORK / "repo"


def attempt(label: str, root: pathlib.Path, **kwargs) -> None:
    spec = load_spec(root / "verification/spec.py").verification.chain
    try:
        result = release_chain.verify_release_chain(root, spec=spec, **kwargs)
        print(f"{label}: VERIFIED ({len(result.releases)} releases)")
    except release_chain.ReleaseChainError as exc:
        print(f"{label}: ReleaseChainError: {exc}")
    except BaseException as exc:  # noqa: BLE001
        print(f"{label}: {type(exc).__name__}: {exc}")
        print("   at", traceback.format_exception(exc)[-2].strip().splitlines()[0])


# Case A -------------------------------------------------------------------
root = fresh()
manifests = root / "releases/manifests"
genesis = sorted(manifests.glob("0000-*.json"))[0]
payload = json.loads(genesis.read_bytes())
for p in list(manifests.iterdir()):
    p.unlink()  # keep a genesis-only chain; the crash is before state checks
for created in ("0001-01-01T00:00:00Z", "0001-01-01T00:04:59Z", "0001-01-01T00:05:00Z"):
    for p in list(manifests.iterdir()):
        p.unlink()
    payload["createdAtUtc"] = created
    raw = canonical_bytes(payload) + b"\n"
    digest = hashlib.sha256(raw).hexdigest()
    stem = f"0000-{digest[:16]}"
    (manifests / f"{stem}.json").write_bytes(raw)
    (manifests / f"{stem}.producer.sig").write_bytes(
        sign_payload((FIXTURE / "workspace/producer.key").read_bytes(), raw, domain=b"")
    )
    for name in ("alpha", "beta"):
        directory = FIXTURE / "workspace" / name
        LocalTsa(
            name=name,
            directory=directory,
            root_pem=directory / f"{name}-root.pem",
            policy_oid="",
            signer_certificate_sha256="",
            signer_spki_sha256="",
        ).stamp(digest, manifests / f"{stem}.{name}.tsr")
    spec = load_spec(root / "verification/spec.py").verification.chain
    loaded = release_chain.load_manifest(manifests / f"{stem}.json", spec)
    print(f"A load_manifest accepts createdAtUtc={created}: {loaded[0]['createdAtUtc']}")
    attempt(f"A verify_release_chain createdAtUtc={created}", root)

# Case B -------------------------------------------------------------------
root = fresh()
attempt("B verify_release_chain clock_skew_seconds=10**15", root, clock_skew_seconds=10**15)
attempt("B verify_release_chain clock_skew_seconds=10**6", root, clock_skew_seconds=10**6)

# Case C -------------------------------------------------------------------
attempt("C verify_release_chain now=datetime.max(UTC)", root,
        now=datetime.max.replace(tzinfo=timezone.utc))
attempt("C verify_release_chain now=9999-12-31T23:55:00Z", root,
        now=datetime(9999, 12, 31, 23, 55, tzinfo=timezone.utc))

# Added by agent-chain: more admitted skews and verdict-preservation probes ----
root = fresh()
for skew in (0, 1, 10**30, 10**400, 86400 * 999_999_999 + 86_399, 86400 * 999_999_999 + 86_400):
    attempt(f"B2 verify_release_chain clock_skew_seconds={str(skew)[:24]}", root, clock_skew_seconds=skew)
for bad in (True, 1.5, -1, float("inf")):
    attempt(f"B3 verify_release_chain clock_skew_seconds={bad!r}", root, clock_skew_seconds=bad)
attempt("C2 verify_release_chain now=datetime.min(UTC)", root,
        now=datetime.min.replace(tzinfo=timezone.utc))
attempt("C3 verify_release_chain now=9999-12-31T23:54:59Z", root,
        now=datetime(9999, 12, 31, 23, 54, 59, tzinfo=timezone.utc))
root = fresh()
manifests = root / "releases/manifests"
genesis = sorted(manifests.glob("0000-*.json"))[0]
payload = json.loads(genesis.read_bytes())
for created in ("9999-12-31T23:59:59.999999Z",):
    for p in list(manifests.iterdir()):
        p.unlink()
    payload["createdAtUtc"] = created
    raw = canonical_bytes(payload) + b"\n"
    digest = hashlib.sha256(raw).hexdigest()
    stem = f"0000-{digest[:16]}"
    (manifests / f"{stem}.json").write_bytes(raw)
    (manifests / f"{stem}.producer.sig").write_bytes(
        sign_payload((FIXTURE / "workspace/producer.key").read_bytes(), raw, domain=b"")
    )
    for name in ("alpha", "beta"):
        directory = FIXTURE / "workspace" / name
        LocalTsa(name=name, directory=directory, root_pem=directory / f"{name}-root.pem",
                 policy_oid="", signer_certificate_sha256="", signer_spki_sha256="",
                 ).stamp(digest, manifests / f"{stem}.{name}.tsr")
    attempt(f"D verify_release_chain createdAtUtc={created}", root)
    attempt(f"D verify_release_chain createdAtUtc={created} skew=10**30", root, clock_skew_seconds=10**30)
