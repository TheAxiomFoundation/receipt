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

import contextlib
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from receipt import sign as _sign
from receipt.canonical import canonical_bytes
from receipt.release_chain import (
    MAX_RELEASE_INDEX,
    SHA256_RE,
    ReleaseChainError,
    assert_no_symlinked_state_component,
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
    #: The producer key these records must be signed by. Required, and second
    #: so that it can be: a field with no default cannot follow one that has
    #: one. Every caller already writes these by keyword.
    producer_spki_sha256: str
    schema_version: str = SCHEMA_VERSION
    producer_public_key_filename: str = "producer.pem"
    domain: bytes = DOMAIN
    #: The release root this directory must stay outside of, when the consumer
    #: also runs a release chain. Supplying it turns the "records live outside
    #: the closed release directory" rule into a construction-time refusal.
    release_root_relative: pathlib.PurePosixPath | None = None

    def __post_init__(self) -> None:
        """Refuse a spec whose pin cannot pin anything.

        The demonstrated hole, and the one `ChainSpec` had: this pin is handed
        to `sign.verify_signature_bytes`, which reads ``None`` as *no pin
        requested* and skips the SPKI comparison entirely. A default of
        ``None`` therefore did not mean "unset" to anything downstream — it
        meant a directory of records signed by any key at all verifying green,
        with the one line of consumer code that was supposed to say who may
        write them never consulted. The pin is checked where it is written
        instead.
        """

        records = self.records_relative
        if records.is_absolute() or not records.parts or ".." in records.parts:
            raise EvidenceRecordError(
                f"records_relative must be a relative path without '..': {records}"
            )
        _sha256(self.producer_spki_sha256, "EvidenceSpec producer_spki_sha256")
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
    #: Whether the records directory is itself on disk. A zero-record result
    #: is reached two ways — an absent directory and an existing empty one —
    #: and this is the only thing that tells a caller which one it has.
    directory_present: bool

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


def _validate_ref_entries(value: Any) -> list[tuple[str, str]]:
    """Check the container and every entry, and answer with the sort keys.

    Split from the sorted-and-strictly-unique half because the two halves are
    asked at different moments. The schema check asks both of a record that
    already exists. Emission can only be asked this half: it is emission that
    establishes the order, by sorting the caller's refs on ``(kind, sha256)``
    — and a sort key is not a place to discover that an entry has no
    ``sha256``, or that a ``kind`` is not a string.
    """

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
    return seen


def _validate_refs(value: Any) -> list[dict[str, Any]]:
    """Check every entry, then require the list sorted and strictly unique."""

    seen = _validate_ref_entries(value)
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


def _assert_records_directory_is_confined(
    root: pathlib.Path, spec: EvidenceSpec
) -> pathlib.Path:
    """Answer where the records directory really is, before anything reads it.

    `EvidenceSpec.__post_init__` compares two `PurePosixPath`s, which is all a
    spec can do: it never sees a filesystem. So the rule it enforces — records
    live outside the release directory — is a rule about spellings, and a
    spelling is not where a directory is. An ``evidence/`` that is a link to an
    ambient directory satisfies it while the records read and written under it
    are no part of the tree the spec names; a ``releases/`` that is a link to
    the evidence directory satisfies it while every record sits inside the
    closed release directory. Enumeration checked only the final component and
    caught neither.

    Both halves are answered here, where the root is known and the join has
    already happened: `release_chain`'s own component walk, refusing a link at
    any component in its words rather than in words of this module's own, and
    then the two directories compared as the filesystem resolves them.
    """

    try:
        assert_no_symlinked_state_component(root, spec.records_relative)
    except ReleaseChainError as exc:
        raise EvidenceRecordError(str(exc)) from exc

    directory = root / spec.records_relative
    release_root_relative = spec.release_root_relative
    if release_root_relative is not None:
        records_real = pathlib.Path(os.path.realpath(directory))
        release_real = pathlib.Path(
            os.path.realpath(root / release_root_relative)
        )
        if records_real == release_real or release_real in records_real.parents:
            raise EvidenceRecordError(
                "evidence records must live outside the release directory: "
                f"{spec.records_relative} resolves to {records_real}, which is "
                f"inside {release_real}"
            )
    return directory


def _enumerate_record_files(
    root: pathlib.Path, spec: EvidenceSpec
) -> list[tuple[pathlib.Path, pathlib.Path, pathlib.Path]]:
    """Enumerate one closed records directory, after placing it on disk.

    The confinement check stands here rather than in either caller so that
    reading and writing get the same answer about the same directory, and it
    stands ahead of the "does it exist" question because a dangling link is
    still a link and an absent directory is not a reason to stop asking.
    """

    directory = _assert_records_directory_is_confined(root, spec)
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
    module's domain — and says nothing about the custody of any release. It
    also says the body beside each record is canonical, not merely that those
    bytes hash to what the record recorded.

    An absent records directory is the zero-record chain, not a refusal. This
    directory is closed-world, so a placeholder file cannot be put in it to
    keep it alive, and git tracks no empty directory: absence is therefore the
    only empty state a checkout can carry, and refusing it would refuse every
    consumer's state before its first emission.
    `release_chain._enumerate_manifest_files` answers the same way about an
    absent manifest directory. What absence and an existing empty directory
    could not be told apart by is now `EvidenceVerification.directory_present`
    — the one thing a zero-record result does not otherwise say, and what a
    caller needs to refuse a mistyped `records_relative` on its own terms.
    """

    key_spec = _sign.ProducerKeySpec(
        public_key_filename=spec.producer_public_key_filename,
        spki_sha256=spec.producer_spki_sha256,
    )
    return _verify_records(
        root,
        spec,
        _sign.read_producer_public_key(anchor_dir, key_spec),
        public_key_filename=str(anchor_dir / key_spec.public_key_filename),
    )


def _verify_records(
    root: pathlib.Path,
    spec: EvidenceSpec,
    public_key_pem: bytes,
    *,
    public_key_filename: str,
) -> EvidenceVerification:
    """Verify one records directory against one already-read producer key.

    The loop `verify_evidence_records` held inline. It is separated from where
    the key comes from because that is the only thing its two callers differ
    on: a consumer reads the pinned public key out of its anchor directory,
    and the producer already holds the private half of it at emission time.
    Everything after that is one implementation, so the producer refuses to
    extend a directory for exactly the reasons, and in exactly the words, an
    auditor would refuse to accept it.

    ``public_key_filename`` names the key in the two refusals that can only
    come from an unreadable one. It is a path for the consumer and a
    description for the producer, which has no file to name.
    """

    # Asked before enumeration, which cannot answer it: enumeration returns
    # the empty list for an absent directory and for an existing empty one
    # alike. The confinement check runs first either way, so a linked
    # component still refuses here in the same words it refuses there.
    directory_present = _assert_records_directory_is_confined(root, spec).is_dir()
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

        parsed_body, body_raw = _load_canonical_json(body_path, "evidence body")
        # The digest below binds a byte stream, and every stream that hashes
        # to it satisfies the record. The rule the body is stored under is the
        # record's own — canonical JSON plus one newline — and it has to be
        # checked to hold, or a reserialized body with a recomputed digest is
        # bytes no emission of this module could have written, verifying green.
        if body_raw != canonical_document_bytes(parsed_body):
            raise EvidenceRecordError(
                "evidence-body bytes are not canonical JSON plus one newline: "
                f"{body_path}"
            )
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
        try:
            # The domain is what makes this signature unusable as a manifest
            # signature: the authorizing verifier checks exact bytes with no
            # domain at all, so it can never accept these.
            _sign.verify_signature_bytes(
                spec.domain + raw,
                signature,
                public_key_pem,
                public_key_filename=public_key_filename,
                spki_sha256=spec.producer_spki_sha256,
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
    return EvidenceVerification(
        records=tuple(records), directory_present=directory_present
    )


def _signing_key_public_pem(private_key_pem: bytes) -> bytes:
    """Return the public half of a signing key, in PEM.

    Reached through `receipt.sign`'s own loader rather than a second import of
    the signing library, so emission depends on exactly what `sign_payload`
    depends on and refuses in the same words when it is absent.

    Split out from `_signing_key_spki_sha256`, which used to be the only
    caller that wanted it. Emission now verifies the records already in the
    directory before it appends to them, and the key it has to verify them
    under is the public half of the one it is about to sign with — which the
    producer holds already, so it needs no anchor directory to ask.
    """

    if type(private_key_pem) is not bytes:
        raise EvidenceRecordError("Ed25519 private key PEM must be bytes")
    if not _sign.CRYPTOGRAPHY_AVAILABLE:
        raise EvidenceRecordError("Ed25519 signing requires cryptography")
    try:
        private_key = _sign.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError, _sign.UnsupportedAlgorithm) as exc:
        raise EvidenceRecordError("cannot decode Ed25519 private key") from exc
    if not isinstance(private_key, _sign.Ed25519PrivateKey):
        raise EvidenceRecordError("private key is not Ed25519")
    return private_key.public_key().public_bytes(
        _sign.Encoding.PEM,
        _sign.PublicFormat.SubjectPublicKeyInfo,
    )


def _signing_key_spki_sha256(private_key_pem: bytes) -> str:
    """Return the SPKI digest of the public half of a signing key."""

    try:
        return _sign.spki_sha256(_signing_key_public_pem(private_key_pem))
    except SignError as exc:
        raise EvidenceRecordError(str(exc)) from exc


@contextlib.contextmanager
def _exclusive_records_directory(directory: pathlib.Path) -> Iterator[None]:
    """Hold the records directory for one emitter, enumeration through write.

    The next index is the last enumerated one plus one, so two emitters that
    enumerate the same state compute the same index. Creating the record
    exclusively does not close that on its own: the filename carries the
    record's own digest, so two different payloads at one index are two
    different filenames, both creates succeed, and the directory is refused at
    verification for a duplicate index — with both emitters having been told
    they wrote it. The whole read-decide-write is what has to be exclusive.

    The lock is advisory and non-blocking, which is the fail-closed reading:
    a second emitter is told another one holds the directory rather than
    queueing behind it or, worse, proceeding. `fcntl.flock` is POSIX, which
    this package already requires (README): its state reads open through
    directory descriptors.

    Only ``EAGAIN`` (``EWOULDBLOCK`` is the same number) says a second emitter
    holds it. A filesystem with no advisory locks answers ``ENOTSUP``, a
    descriptor the kernel will not lock answers something else again, and
    every one of those refuses too — in words that do not assert a competitor
    nobody observed.
    """

    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
                raise EvidenceRecordError(
                    "another emitter holds the evidence-record directory: "
                    f"{directory}"
                ) from exc
            raise EvidenceRecordError(
                f"cannot hold the evidence-record directory: {directory}: "
                f"{exc.strerror}"
            ) from exc
        yield
    finally:
        os.close(descriptor)


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

    Three things are settled before any byte is written. The signing key is
    compared to the spec's pin, because a key the verifier will refuse is a
    fact the producer can know at emission time rather than one an auditor
    discovers later; that comparison stands ahead of the `mkdir`, so a refused
    emission leaves no directory behind. The records directory is placed on
    disk, so a linked component cannot receive the write. And the directory is
    held exclusively from enumeration through the last write, so the index
    this emission claims is still free when it claims it.

    A fourth is settled inside that lock, before the index is: every record
    already in the directory is verified exactly as `verify_evidence_records`
    verifies it — the chain, canonical bytes for each record and its body, the
    body digest, the filename, and every signature under the pin — through the
    same `_verify_records` the consumer runs, under the public half of the key
    this emission signs with, so no anchor directory is needed. Only the last
    record was read before, and only far enough to take its index and digest.
    The producer is the one party that can refuse to sign a
    `previousRecordSha256` it has not checked: signing one lifted out of a
    record whose own signature nobody verified extends a chain this producer
    cannot vouch for, and every later reader inherits that. A directory that
    does not verify is refused in the verifier's own words and nothing is
    written. The cost is one signature verification per record already there,
    bounded by the four-digit filename limit.

    The record is created exclusively and written last: a record on disk
    therefore implies its body and signature are already there, which is the
    order enumeration reads them in.
    """

    signing_spki_sha256 = _signing_key_spki_sha256(private_key_pem)
    if signing_spki_sha256 != spec.producer_spki_sha256:
        raise EvidenceRecordError(
            f"producer signing key is not code-pinned: {signing_spki_sha256}"
        )

    directory = _assert_records_directory_is_confined(root, spec)
    directory.mkdir(parents=True, exist_ok=True)
    with _exclusive_records_directory(directory):
        return _write_evidence_record(
            root,
            directory,
            spec=spec,
            private_key_pem=private_key_pem,
            body=body,
            body_schema=body_schema,
            refs=refs,
            producer=producer,
            emitted_at_utc=emitted_at_utc,
        )


def _write_evidence_record(
    root: pathlib.Path,
    directory: pathlib.Path,
    *,
    spec: EvidenceSpec,
    private_key_pem: bytes,
    body: Any,
    body_schema: str,
    refs: list[dict[str, Any]],
    producer: dict[str, Any],
    emitted_at_utc: str,
) -> pathlib.Path:
    """The emitter's critical section: verify, decide the index, write.

    The caller's refs are checked entry by entry before they are sorted. The
    sort below reads ``kind`` and ``sha256`` out of every entry to build its
    key, so a malformed one reached that key first and left this module as a
    `KeyError` or a `TypeError` rather than as a refusal naming ``refs[i]``;
    and a caller's tuple was already a list by the time the schema check asked
    whether refs is an array. Ordering is the one thing not asked here, since
    the sort is what establishes it.
    """

    # Everything already in the directory is verified before the index is
    # decided. The index and the digest this record will link to are then the
    # verifier's own answer about the head, rather than a schema check of
    # whichever file happened to sort last.
    verification = _verify_records(
        root,
        spec,
        _signing_key_public_pem(private_key_pem),
        public_key_filename="<the signing key handed to emit_evidence_record>",
    )
    head = verification.head
    if head is None:
        index = 0
        previous_sha256 = None
    else:
        index = head.record_index + 1
        previous_sha256 = head.sha256

    _validate_ref_entries(refs)
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
    if record_path.exists() or record_path.is_symlink():
        raise EvidenceRecordError(
            f"evidence record {record_path.name} already exists at index {index}"
        )
    signature = _sign.sign_payload(private_key_pem, raw, domain=spec.domain)

    body_path_for_record(record_path).write_bytes(body_raw)
    producer_signature_path_for_record(record_path).write_bytes(signature)
    # Exclusive, and last: the create is the one step that cannot be racing a
    # writer outside this lock, and a record's presence implies its sidecars'.
    try:
        descriptor = os.open(
            record_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666
        )
    except FileExistsError as exc:
        raise EvidenceRecordError(
            f"evidence record {record_path.name} already exists at index {index}"
        ) from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
    return record_path
