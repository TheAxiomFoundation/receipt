"""Non-authorizing, emission-time evidence records beside a release chain.

A release manifest is authorizing: `receipt.verify` composes history, custody,
binding and declaration into a verdict, and a manifest's producer signature is
one of the things that verdict rests on. An evidence record is the opposite by
construction. It records that something happened at emission time — a domain
event a producer wants to be able to show later — and it is built so that no
verifier can mistake it for custody evidence.

Two invariants carry that claim, and both are properties of the bytes rather
than of any caller's discipline (tests/test_evidence.py):

1. **An evidence record is not a manifest.** Its top-level keys are not the
   manifest's, so `release_chain.validate_manifest_schema` refuses it at
   `_exact_keys` before it reads a single value. The refusal is structural: a
   manifest is closed-world at every level, and no evidence record can satisfy
   it.
2. **An evidence record's signature is not a manifest signature.** Manifest
   producer signatures are verified by `sign.verify_signature_bytes` over the
   exact manifest bytes with no domain — that function takes no domain
   parameter at all. An evidence record is signed over ``DOMAIN + raw``, so
   presenting one to the authorizing verifier fails the signature check even if
   the schema check were somehow passed.

Either failure alone is sufficient. Both hold, and neither depends on a
consumer remembering to keep the two apart.

Records also live outside the release directory. Note what does *not* keep them
apart: this module's `RECORD_RE` and `PRODUCER_SIGNATURE_RE` are deliberately the
same patterns as `release_chain`'s, because a record mirrors a manifest's
filename layout on purpose. A record dropped into a release directory is
therefore refused, but by three different mechanisms depending on what travels
with it (tests/test_evidence.py):

- record, body and signature together — `_enumerate_manifest_files` raises
  "unknown file in closed release manifest directory", because `{stem}.body.json`
  matches no pattern it knows.
- record and signature alone — enumeration *accepts* them as a manifest/signature
  pair, and the refusal lands one step later at `validate_manifest_schema`. This
  is invariant 1 doing exactly the job it exists for.
- record alone — enumeration raises for a missing producer signature.

The safety property holds in every arrangement; it is the closed-world schema
check, not the filename grammar, that carries it. The release directory is
closed; this module's directory is closed too, over its own three filename
shapes.

Shape
-----

A record mirrors a manifest's frame so the two project the same way::

    {
      "schemaVersion": "receipt/evidence-record/v1",
      "standing": "non-authorizing",
      "recordIndex": 0,
      "previousRecordSha256": null,
      "emittedAtUtc": "2026-08-27T14:05:00Z",
      "producer": {"repo": "...", "branch": "..."},
      "body": {"schema": "<domain event schema id>", "sha256": "<64 hex>"},
      "refs": [{"kind": "release-manifest", "sha256": "<64 hex>"}]
    }

`recordIndex`, `previousRecordSha256`, `emittedAtUtc` and `producer` mirror
`releaseIndex`, `previousManifestSha256`, `createdAtUtc` and `producer`
exactly: same regexes, same genesis rule, same four-digit filename limit.
`standing` is a literal constant checked for equality, which puts the words
"non-authorizing" inside the signed bytes.

`body` binds a domain event **by digest**; the body's own bytes sit beside the
record as `{stem}.body.json`, canonical, and verification recomputes the
digest. This is how the record schema stays closed while the body schema stays
the domain's — the same move `state.jsonlSha256` makes for a journal. This
module has no opinion about what a body contains.

`refs[]` is sorted and strictly unique on `(kind, sha256)`, with `kind` drawn
from a small closed enum. It is how a record sits *beside* a chain without the
chain referencing it: a record may name the release manifest it was emitted
under, and the manifest never learns it exists.

What v1 does not do
-------------------

RFC 3161 witnessing is deliberately out of v1. Because `emittedAtUtc` is a
claim by the producer and nothing else, this module parses it and refuses a
malformed one, but never uses it in a refusal — mirroring the release chain,
where a claimed `createdAtUtc` is only ever checked *against* a witness's
gen_time and is never trusted on its own. Adding `{stem}.{tsa}.tsr` sidecars
later is expected to be additive — the filename and digest layout already
matches the one `receipt.tsa` verifies for manifests — though no witness path
is implemented or tested here, so that is a design expectation rather than a
demonstrated one.

`verify_evidence_records` is not wired into `receipt.verify.run_verification`,
and must not be. `VerifyResult.verdict` cannot depend on it; that is the whole
point of the standing.

Consumers and projection
------------------------

Any consumer can project these records one-way into its own envelope, because
serialization here is deterministic and digests are stable: the record bytes
are canonical JSON plus one newline, the digest is SHA-256 of exactly those
bytes, and the signature covers ``DOMAIN`` followed by exactly those bytes
including the trailing newline. A projection that wants to remain checkable
must therefore carry the original bytes verbatim rather than re-serializing
from parsed JSON. The projection is the consumer's; this package neither
defines nor blesses one.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
from dataclasses import dataclass
from typing import Any

from receipt import sign as _sign
from receipt.canonical import canonical_bytes
from receipt.release_chain import (
    MAX_RELEASE_INDEX,
    SHA256_RE,
    ReleaseChainError,
    parse_created_at,
)
from receipt.sign import SignError

#: The domain string every evidence-record signature is made under. Its
#: trailing NUL keeps it unambiguously separated from the payload that follows.
DOMAIN = b"receipt/evidence-record/v1\x00"
SCHEMA_VERSION = "receipt/evidence-record/v1"
#: A literal, checked for equality, so the standing is inside the signed bytes.
STANDING = "non-authorizing"
MAX_RECORD_INDEX = MAX_RELEASE_INDEX
REF_KINDS = frozenset({"release-manifest", "record", "draw-set", "other"})

RECORD_RE = re.compile(r"(?P<index>[0-9]{4})-(?P<digest>[0-9a-f]{16})\.json\Z")
BODY_RE = re.compile(r"(?P<stem>[0-9]{4}-[0-9a-f]{16})\.body\.json\Z")
PRODUCER_SIGNATURE_RE = re.compile(
    r"(?P<stem>[0-9]{4}-[0-9a-f]{16})\.producer\.sig\Z"
)


class EvidenceRecordError(ValueError):
    """An evidence record is malformed, inconsistent, or untrusted."""


@dataclass(frozen=True)
class EvidenceSpec:
    """Consumer-committed constants for one evidence-record directory.

    Like `ChainSpec`, this module ships machinery only: the directory, the
    schema name, the producer fingerprint and the domain all arrive from the
    consumer's own committed code, never from package defaults.
    """

    records_relative: pathlib.PurePosixPath
    schema_version: str = SCHEMA_VERSION
    producer_public_key_filename: str = "producer.pem"
    producer_spki_sha256: str | None = None
    domain: bytes = DOMAIN
    #: The release root this directory must stay outside of, when the consumer
    #: also runs a release chain. Supplying it turns the "records live outside
    #: the closed release directory" rule into a construction-time refusal.
    release_root_relative: pathlib.PurePosixPath | None = None

    def __post_init__(self) -> None:
        records = self.records_relative
        if records.is_absolute() or not records.parts or ".." in records.parts:
            raise EvidenceRecordError(
                f"records_relative must be a relative path without '..': {records}"
            )
        if type(self.domain) is not bytes or not self.domain:
            raise EvidenceRecordError("domain must be non-empty bytes")
        root = self.release_root_relative
        if root is not None and (records == root or root in records.parents):
            raise EvidenceRecordError(
                "evidence records must live outside the release directory: "
                f"{records} is inside {root}"
            )


@dataclass(frozen=True)
class EvidenceRecord:
    path: pathlib.Path
    raw: bytes
    sha256: str
    record: dict[str, Any]
    body_path: pathlib.Path
    body_raw: bytes
    producer_signature_path: pathlib.Path

    @property
    def record_index(self) -> int:
        return int(self.record["recordIndex"])


@dataclass(frozen=True)
class EvidenceVerification:
    records: tuple[EvidenceRecord, ...]

    @property
    def head(self) -> EvidenceRecord | None:
        return self.records[-1] if self.records else None


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


# The closed-world helpers below are deliberate near-copies of release_chain's
# private ones rather than imports of them. An evidence record is defined by its
# shape and its domain string and by nothing else, so this module stays liftable
# into another project without carrying release_chain's internals with it. Only
# release_chain's public surface is imported.
def _fail_json_constant(value: str) -> None:
    raise EvidenceRecordError(f"evidence record contains non-JSON number {value!r}")


def _object_without_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceRecordError(
                f"evidence record has duplicate key {key!r}"
            )
        result[key] = value
    return result


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise EvidenceRecordError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise EvidenceRecordError(
            f"{label} keys are not closed-world: missing={missing}, unknown={unknown}"
        )
    return value


def _strict_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int:
        raise EvidenceRecordError(f"{label} must be an integer, not a boolean")
    if value < minimum:
        raise EvidenceRecordError(f"{label} must be >= {minimum}")
    return value


def _strict_string(value: Any, label: str, *, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value):
        suffix = " and non-empty" if nonempty else ""
        raise EvidenceRecordError(f"{label} must be a string{suffix}")
    return value


def _sha256(value: Any, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise EvidenceRecordError(
            f"{label} must be exactly 64 lowercase hexadecimal characters"
        )
    return value


def _validate_refs(value: Any) -> list[dict[str, Any]]:
    if type(value) is not list:
        raise EvidenceRecordError("refs must be an array")
    seen: list[tuple[str, str]] = []
    for position, entry in enumerate(value):
        ref = _exact_keys(entry, {"kind", "sha256"}, f"refs[{position}]")
        kind = _strict_string(ref["kind"], f"refs[{position}].kind")
        if kind not in REF_KINDS:
            raise EvidenceRecordError(
                f"refs[{position}].kind must be one of {sorted(REF_KINDS)}: {kind!r}"
            )
        seen.append((kind, _sha256(ref["sha256"], f"refs[{position}].sha256")))
    # Both `kind` and a lowercase-hex digest are drawn from ASCII alphabets, so
    # Python's tuple ordering and canonical.py's UTF-16 code-unit ordering agree
    # here; sorting is required so one set of refs has exactly one serialization.
    if seen != sorted(seen):
        raise EvidenceRecordError("refs must be sorted by (kind, sha256)")
    if len(set(seen)) != len(seen):
        raise EvidenceRecordError("refs must be strictly unique on (kind, sha256)")
    return value


def validate_evidence_record_schema(
    record: Any, spec: EvidenceSpec
) -> dict[str, Any]:
    """Validate the closed-world evidence-record schema named by ``spec``."""

    payload = _exact_keys(
        record,
        {
            "schemaVersion",
            "standing",
            "recordIndex",
            "previousRecordSha256",
            "emittedAtUtc",
            "producer",
            "body",
            "refs",
        },
        "evidence record",
    )
    if payload["schemaVersion"] != spec.schema_version:
        raise EvidenceRecordError(
            f"unsupported evidence-record schema {payload['schemaVersion']!r}"
        )
    if payload["standing"] != STANDING:
        raise EvidenceRecordError(
            f"standing must be exactly {STANDING!r}, not {payload['standing']!r}"
        )
    index = _strict_int(payload["recordIndex"], "recordIndex")
    if index > MAX_RECORD_INDEX:
        raise EvidenceRecordError(
            f"recordIndex {index} exceeds the four-digit filename limit"
        )

    previous = payload["previousRecordSha256"]
    if index == 0:
        if previous is not None:
            raise EvidenceRecordError("genesis previousRecordSha256 must be null")
    else:
        _sha256(previous, "previousRecordSha256")

    # Parsed for well-formedness only. The producer's claimed emission time is
    # never used in a refusal: with no witness to check it against there is
    # nothing it could establish, and treating it as evidence is exactly the
    # mistake the release chain avoids.
    try:
        parse_created_at(payload["emittedAtUtc"], "emittedAtUtc")
    except ReleaseChainError as exc:
        # Reuse the release chain's timestamp grammar, but never leak its
        # exception type: every refusal from this module is an
        # EvidenceRecordError.
        raise EvidenceRecordError(str(exc)) from exc

    producer = _exact_keys(payload["producer"], {"repo", "branch"}, "producer")
    _strict_string(producer["repo"], "producer.repo")
    _strict_string(producer["branch"], "producer.branch")

    body = _exact_keys(payload["body"], {"schema", "sha256"}, "body")
    _strict_string(body["schema"], "body.schema")
    _sha256(body["sha256"], "body.sha256")

    _validate_refs(payload["refs"])
    return payload


def record_filename(index: int, raw: bytes) -> str:
    _strict_int(index, "recordIndex")
    if index > MAX_RECORD_INDEX:
        raise EvidenceRecordError(
            f"recordIndex {index} exceeds the four-digit filename limit"
        )
    return f"{index:04d}-{sha256_bytes(raw)[:16]}.json"


def body_path_for_record(path: pathlib.Path) -> pathlib.Path:
    return path.with_name(f"{path.stem}.body.json")


def producer_signature_path_for_record(path: pathlib.Path) -> pathlib.Path:
    return path.with_name(f"{path.stem}.producer.sig")


def canonical_document_bytes(payload: Any) -> bytes:
    """The one byte stream this module signs and digests: canonical JSON + LF."""

    return canonical_bytes(payload) + b"\n"


def _load_canonical_json(
    path: pathlib.Path, label: str
) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise EvidenceRecordError(f"{label} is not a regular file: {path}")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceRecordError(f"{label} is not UTF-8: {path}") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_fail_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise EvidenceRecordError(
            f"{label} is not valid JSON: {path}: {exc}"
        ) from exc
    return parsed, raw


def load_evidence_record(
    path: pathlib.Path, spec: EvidenceSpec
) -> tuple[dict[str, Any], bytes, str]:
    parsed, raw = _load_canonical_json(path, "evidence record")
    payload = validate_evidence_record_schema(parsed, spec)
    if raw != canonical_document_bytes(payload):
        raise EvidenceRecordError(
            f"evidence-record bytes are not canonical JSON plus one newline: {path}"
        )
    return payload, raw, sha256_bytes(raw)


def _enumerate_record_files(
    root: pathlib.Path, spec: EvidenceSpec
) -> list[tuple[pathlib.Path, pathlib.Path, pathlib.Path]]:
    directory = root / spec.records_relative
    if not directory.exists():
        return []
    if directory.is_symlink() or not directory.is_dir():
        raise EvidenceRecordError(
            f"evidence-record path is not a regular directory: {directory}"
        )

    records: dict[str, pathlib.Path] = {}
    bodies: dict[str, pathlib.Path] = {}
    signatures: dict[str, pathlib.Path] = {}
    for entry in directory.iterdir():
        if entry.is_symlink() or not entry.is_file():
            raise EvidenceRecordError(
                f"evidence-record directory contains a non-regular entry: {entry}"
            )
        body_match = BODY_RE.fullmatch(entry.name)
        if body_match is not None:
            bodies[body_match.group("stem")] = entry
            continue
        signature_match = PRODUCER_SIGNATURE_RE.fullmatch(entry.name)
        if signature_match is not None:
            signatures[signature_match.group("stem")] = entry
            continue
        # Checked last: `0000-<16 hex>.body.json` also ends in `.json`, so the
        # body pattern must win before the record pattern is consulted.
        if RECORD_RE.fullmatch(entry.name) is not None:
            records[entry.stem] = entry
            continue
        raise EvidenceRecordError(
            f"unknown file in closed evidence-record directory: {entry.name}"
        )

    orphan_bodies = sorted(set(bodies) - set(records))
    if orphan_bodies:
        raise EvidenceRecordError(
            f"orphan evidence bodies for record stems: {orphan_bodies}"
        )
    orphan_signatures = sorted(set(signatures) - set(records))
    if orphan_signatures:
        raise EvidenceRecordError(
            f"orphan producer signatures for record stems: {orphan_signatures}"
        )

    result: list[tuple[pathlib.Path, pathlib.Path, pathlib.Path]] = []
    seen_indices: dict[int, str] = {}
    for stem, path in records.items():
        match = RECORD_RE.fullmatch(path.name)
        assert match is not None
        index = int(match.group("index"))
        if index in seen_indices:
            raise EvidenceRecordError(
                f"duplicate record index {index}: {seen_indices[index]}, {path.name}"
            )
        seen_indices[index] = path.name
        if stem not in bodies:
            raise EvidenceRecordError(f"evidence record {path.name} has no body")
        if stem not in signatures:
            raise EvidenceRecordError(
                f"evidence record {path.name} has no producer signature"
            )
        result.append((path, bodies[stem], signatures[stem]))
    result.sort(key=lambda item: item[0].name)
    return result


def verify_evidence_records(
    root: pathlib.Path,
    *,
    spec: EvidenceSpec,
    anchor_dir: pathlib.Path,
) -> EvidenceVerification:
    """Verify a directory of evidence records, fail-closed.

    This function can never contribute to an authorizing verdict. It is not
    called by `receipt.verify.run_verification`, and `VerifyResult.verdict`
    does not depend on it. A green result here says the records are
    well-formed, chained, and signed by the pinned producer under this
    module's domain — and says nothing about the custody of any release.
    """

    key_spec = _sign.ProducerKeySpec(
        public_key_filename=spec.producer_public_key_filename,
        spki_sha256=spec.producer_spki_sha256,
    )
    records: list[EvidenceRecord] = []
    previous_sha256: str | None = None
    for position, (path, body_path, signature_path) in enumerate(
        _enumerate_record_files(root, spec)
    ):
        payload, raw, digest = load_evidence_record(path, spec)

        index = int(payload["recordIndex"])
        if index != position:
            raise EvidenceRecordError(
                f"evidence records are not contiguous from 0: expected index "
                f"{position}, found {index} in {path.name}"
            )
        if path.name != record_filename(index, raw):
            raise EvidenceRecordError(
                f"evidence-record filename does not match its own digest: "
                f"{path.name}"
            )
        if payload["previousRecordSha256"] != previous_sha256:
            raise EvidenceRecordError(
                f"evidence record {path.name} does not link to its predecessor"
            )

        _, body_raw = _load_canonical_json(body_path, "evidence body")
        body_digest = sha256_bytes(body_raw)
        if body_digest != payload["body"]["sha256"]:
            raise EvidenceRecordError(
                f"evidence body digest mismatch for {path.name}: "
                f"recorded {payload['body']['sha256']}, computed {body_digest}"
            )

        if signature_path.is_symlink() or not signature_path.is_file():
            raise EvidenceRecordError(
                f"producer signature is not a regular file: {signature_path}"
            )
        signature = signature_path.read_bytes()
        public_key_pem = _sign.read_producer_public_key(anchor_dir, key_spec)
        try:
            # The domain is what makes this signature unusable as a manifest
            # signature: the authorizing verifier checks exact bytes with no
            # domain at all, so it can never accept these.
            _sign.verify_signature_bytes(
                spec.domain + raw,
                signature,
                public_key_pem,
                public_key_filename=str(anchor_dir / key_spec.public_key_filename),
                spki_sha256=key_spec.spki_sha256,
                label=f"evidence record {path.name}",
            )
        except SignError as exc:
            raise EvidenceRecordError(str(exc)) from exc

        records.append(
            EvidenceRecord(
                path=path,
                raw=raw,
                sha256=digest,
                record=payload,
                body_path=body_path,
                body_raw=body_raw,
                producer_signature_path=signature_path,
            )
        )
        previous_sha256 = digest
    return EvidenceVerification(records=tuple(records))


def emit_evidence_record(
    root: pathlib.Path,
    *,
    spec: EvidenceSpec,
    private_key_pem: bytes,
    body: Any,
    body_schema: str,
    refs: list[dict[str, Any]],
    producer: dict[str, Any],
    emitted_at_utc: str,
) -> pathlib.Path:
    """Write the next evidence record, its body, and its signature.

    This is the producer-side half: the record is signed when it is emitted,
    not when some later release happens to sweep it up.
    """

    directory = root / spec.records_relative
    directory.mkdir(parents=True, exist_ok=True)
    existing = _enumerate_record_files(root, spec)
    if existing:
        previous_path = existing[-1][0]
        previous_payload, previous_raw, previous_sha256 = load_evidence_record(
            previous_path, spec
        )
        index = int(previous_payload["recordIndex"]) + 1
    else:
        index = 0
        previous_sha256 = None

    body_raw = canonical_document_bytes(body)
    payload = {
        "schemaVersion": spec.schema_version,
        "standing": STANDING,
        "recordIndex": index,
        "previousRecordSha256": previous_sha256,
        "emittedAtUtc": emitted_at_utc,
        "producer": producer,
        "body": {"schema": body_schema, "sha256": sha256_bytes(body_raw)},
        "refs": sorted(refs, key=lambda ref: (ref["kind"], ref["sha256"])),
    }
    # Validate before writing anything: a refusal must not leave a partial
    # record on disk for the verifier to trip over.
    validate_evidence_record_schema(payload, spec)
    raw = canonical_document_bytes(payload)
    record_path = directory / record_filename(index, raw)
    signature = _sign.sign_payload(private_key_pem, raw, domain=spec.domain)

    body_path_for_record(record_path).write_bytes(body_raw)
    record_path.write_bytes(raw)
    producer_signature_path_for_record(record_path).write_bytes(signature)
    return record_path
