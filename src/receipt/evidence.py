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
   parameter at all. An evidence record is signed over ``PAE(schema id, record
   bytes)``: DSSE pre-authentication framing, with a detached Ed25519 signature
   beside the record. So presenting one to the authorizing verifier fails the
   signature check even if the schema check were somehow passed.

Either failure alone is sufficient. Both hold, and neither depends on a
consumer remembering to keep the two apart.

Records also live outside the release directory. Note what does *not* keep them
apart: this module's `RECORD_RE` and `PRODUCER_SIGNATURE_RE` are deliberately the
same patterns as `release_chain`'s, because a record mirrors a manifest's
filename layout on purpose. A record dropped into a release directory is
therefore refused — in four arrangements, by three mechanisms, depending on
what travels with it (tests/test_evidence.py):

- record, body and signature together — `_enumerate_manifest_files` raises
  "unknown file in closed release manifest directory", because `{stem}.body.json`
  matches no pattern it knows
  (`test_planted_record_with_body_is_refused_at_enumeration`).
- record alone — enumeration requires one witness receipt per configured
  anchor, and asks for that before it looks for a producer signature, so a
  record alone stops there
  (`test_planted_record_alone_is_refused_for_a_missing_receipt`).
- record and signature — the pair satisfies both filename patterns, and is
  refused in the same place for the same missing receipts
  (`test_planted_record_and_signature_are_refused_for_a_missing_receipt`).
- record, signature and a correctly named witness sidecar — enumeration
  *accepts* all three, counting the receipt without opening it, and the refusal
  lands one step later at `validate_manifest_schema`. This is invariant 1 doing
  exactly the job it exists for
  (`test_planted_record_signature_and_receipt_die_at_the_schema`).

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
module does not validate domain-specific body schemas. What it does enforce is
the rule the body is stored under — canonical JSON plus one newline, checked at
verification rather than merely hashed — and strict canonical input.

Strict canonical input is what every body and every record is held to, at
emission and at verification alike (`_canonical_strict`). Every value is walked,
and every object key with it: canonical.py escapes a key exactly as it escapes a
value, so a key holding a lone surrogate is refused for the reason a value is.
Numbers are held by their canonical token rather than by the Python type that
produced it — a token that reads as an integer outside ±(2**53 - 1) is refused
whatever produced it, because an out-of-range integer *may* round (``2**53 + 1``
does; ``2**53`` serializes exactly, and is outside the accepted range all the
same) and no reader can be held to carry such a token exactly. Not every refusal
the serializer can raise is translated into this module's words: a type
canonical.py refuses outright — a tuple, a bytes value — leaves as its own
``TypeError``, and a pathological depth leaves as Python's ``RecursionError``
— a cyclic body at emission recurses in `_canonical_strict` before
canonical.py can say "circular", and a body on disk nested deeper than the
recursion limit recurses in ``json.loads`` itself. Both fail closed.

`refs[]` is sorted and strictly unique on `(kind, sha256)`, with `kind` drawn
from a small closed enum. It is how a record sits *beside* a chain without the
chain referencing it: a record may name the release manifest it was emitted
under, and the manifest never learns it exists.

What v1 does not do
-------------------

RFC 3161 witnessing is deliberately out of v1. Because `emittedAtUtc` is a
claim by the producer and nothing else, this module checks it for syntax and
calendar validity and refuses a malformed one
(`test_malformed_emitted_at_is_refused`), but never uses it in a chronology or
custody decision — mirroring the release chain, where a claimed `createdAtUtc`
is only ever checked *against* a witness's gen_time and is never trusted on its
own. Adding `{stem}.{tsa}.tsr` sidecars later is expected to be additive — the
filename and digest layout already matches the one `receipt.tsa` verifies for
manifests — though no witness path is implemented or tested here, so that is a
design expectation rather than a demonstrated one. What the directory does with
one today is refuse it, rather than ignore it
(`test_tsa_sidecar_is_not_yet_accepted`).

`verify_evidence_records` is not wired into `receipt.verify.run_verification`,
and must not be. `VerifyResult.verdict` cannot depend on it; that is the whole
point of the standing.

It also reads a different subject. 0.6 puts the authorizing verdict on the tree
object a commit names: `verify.run_verification` and
`append_gate.verify_append_gate` take their bytes from `snapshot.TreeSnapshot`,
for which the working tree and the index are never subjects.
`verify_evidence_records` reads the checkout. That is right for an emission-side
tool standing outside every verdict — the producer verifies and extends what it
has just written, and no commit names those bytes yet — and it is what
`_regular_file_bytes` bounds: a read-once contract, not a lock against a writer
outside the emitter's own. A snapshot-reading verifier for records is later
work, not a condition of this one.

Consumers and projection
------------------------

Any consumer can project these records one-way into its own envelope, because
serialization here is deterministic and digests are stable: the record bytes
are canonical JSON plus one newline, the digest is SHA-256 of exactly those
bytes, and the signature covers ``PAE(schema id, record bytes)`` — those same
bytes, trailing newline included, inside DSSE's pre-authentication framing. A
consumer reconstructs the signed bytes as
``b"DSSEv1 26 receipt/evidence-record/v1 " + LEN(raw) + b" " + raw``, where
``LEN`` is the ASCII decimal byte length with no leading zeros
(`test_the_frame_is_the_dsse_pre_authentication_encoding`). A projection that
wants to remain checkable must therefore carry the original bytes verbatim
rather than re-serializing from parsed JSON. The projection is the consumer's;
this package neither defines nor blesses one.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import json
import math
import os
import pathlib
import re
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, NoReturn

from receipt import sign as _sign
from receipt.canonical import canonical_bytes, canonical_stringify
from receipt.release_chain import (
    MAX_RELEASE_INDEX,
    SHA256_RE,
    ReleaseChainError,
    assert_no_symlinked_state_component,
    parse_created_at,
)
from receipt.sign import SignError

#: The schema id, and the one value that says which record type a signature
#: is for. It is the ``schemaVersion`` field inside every record, which the
#: schema check requires to equal the spec's, and it is the payload type of the
#: frame every signature is made over (`_pae`), so a signature under any other
#: type does not verify. The two cannot be paired with anything but each other.
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
#: A canonical JSON number token a reader parses as an integer. What
#: `_canonical_strict` holds to ±(2**53 - 1) is this token, not the Python
#: type that produced it.
_INTEGER_TOKEN_RE = re.compile(r"-?[0-9]+")


class EvidenceRecordError(ValueError):
    """An evidence record is malformed, inconsistent, or untrusted."""


@dataclass(frozen=True)
class EvidenceSpec:
    """Consumer-committed constants for one evidence-record directory.

    Like `ChainSpec`, this module ships machinery only, and the two anchors
    are required consumer inputs with no defaults: where the records live, and
    which producer key may write them. The other two fields do carry defaults,
    and neither is a trust anchor — ``schema_version`` to this record type's
    own v1 schema id, ``producer_public_key_filename`` to ``producer.pem``.

    ``schema_version`` is also the payload type of the frame every signature
    is made over (`_pae`). It used to sit beside a separate ``domain`` field,
    a NUL-terminated byte string prefixed to the record before signing, so a
    spec could name one schema and sign under another and nothing in the bytes
    said which pair applied. There is one value now: the schema check requires
    the record's ``schemaVersion`` to equal it, and the signature verifies
    under no other payload type.
    """

    records_relative: pathlib.PurePosixPath
    #: The producer key these records must be signed by. Required, and second
    #: so that it can be: a field with no default cannot follow one that has
    #: one. Every caller already writes these by keyword.
    producer_spki_sha256: str
    schema_version: str = SCHEMA_VERSION
    producer_public_key_filename: str = "producer.pem"
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

        The schema id is checked here for the same reason. It is the frame's
        payload type and the record's own ``schemaVersion``, so an empty one
        frames every record under no type at all — and did, emitting and
        verifying green — while ``None`` reached `_pae` as a bare
        ``AttributeError`` at signing time. Only a non-empty string is asked
        for: the frame's length prefix makes any content unambiguous, so a NUL
        or a newline inside the id is not a fact this module can refuse on.
        """

        records = self.records_relative
        if records.is_absolute() or not records.parts or ".." in records.parts:
            raise EvidenceRecordError(
                f"records_relative must be a relative path without '..': {records}"
            )
        _sha256(self.producer_spki_sha256, "EvidenceSpec producer_spki_sha256")
        if type(self.schema_version) is not str or not self.schema_version:
            raise EvidenceRecordError(
                "EvidenceSpec schema_version must be a non-empty string: "
                f"{self.schema_version!r}"
            )
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
# shape and its schema id and by nothing else, so this module stays liftable
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
    """Require ``value`` to be an object whose keys are exactly ``expected``.

    A key that is not a string is refused first, in this module's words. The
    closed-world refusal below sorts the unknown keys to name them, and a set
    holding an ``int`` beside strings has no order — so a caller's ref of
    ``{"kind": ..., "sha256": ..., 1: 0, "extra": 0}`` left this module as a
    bare ``TypeError`` from that sort, with the records directory created and
    empty, because emission checks every ref here ahead of the payload's
    strict guard. The same refusal now stands at each of the four objects this
    closes — the record, ``producer``, ``body`` and every ref — so every
    caller gets it, whichever layer is asked first.
    """

    if type(value) is not dict:
        raise EvidenceRecordError(f"{label} must be an object")
    for key in value:
        if not isinstance(key, str):
            raise EvidenceRecordError(
                f"{label} has an object key that is not a string: {key!r}"
            )
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

    # Checked for syntax and calendar validity, and for nothing else. A
    # malformed one is refused here; a well-formed one is never read into a
    # chronology or custody decision, because with no witness to check it
    # against there is nothing it could establish, and treating it as evidence
    # is exactly the mistake the release chain avoids.
    try:
        parse_created_at(payload["emittedAtUtc"], "emittedAtUtc")
    except ReleaseChainError as exc:
        # Reuse the release chain's timestamp grammar, but never leak its
        # exception type: this module's own schema and strict-input checks
        # refuse with an EvidenceRecordError. Not everything that leaves this
        # module does — the producer key read in `verify_evidence_records`
        # refuses in `sign`'s words, IO errors escape as raised, and a body
        # type canonical.py refuses outright leaves as its own TypeError.
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
    """The one byte stream this module digests, and frames for signing: canonical
    JSON + LF."""

    return canonical_bytes(payload) + b"\n"


def _canonical_strict(value: Any, label: str) -> None:
    """Refuse a value `receipt.canonical` would alter, or fall over on, rather
    than carry.

    `canonical.py` is a hash-pinned port of the upstream serializer and is not
    edited here. Four things it does to a value are exactly what signed bytes
    cannot afford. An integer outside ±(2**53 - 1) is rendered through
    ``float()``, so it may round (``2**53 + 1`` does; ``2**53`` happens to
    render exactly) and in either case leaves an integer token no reader can
    be held to carry exactly — this module's own reader refuses it. The rule
    is therefore on the token, not the type: a float is rendered in fixed
    form below 1e21, so an integral float from ``2**53`` up renders as that
    same bare integer token, and while the guard asked only the type of an
    ``int``, ``1e20`` passed as a finite float, was written as
    ``100000000000000000000``, and the directory then refused at verification
    and at every emission after. Any number whose canonical token fullmatches
    ``-?[0-9]+`` outside ±(2**53 - 1) is refused, whatever produced it; the
    ``int`` rule stands beside it, since an ``int`` at or beyond 1e21 renders
    in exponent form and would slip a token-only rule. ``1e21`` and beyond
    render in exponent form, round-trip as floats, and stay accepted, as does
    ``float(2**53 - 1)``. A non-finite float raises the serializer's own bare
    ``ValueError``, not a refusal of this module's. ``-0.0`` is folded to
    ``0``. And a string holding a lone surrogate — which JSON text can spell as
    ``"\\ud800"`` and Python will parse — is re-escaped rather than refused,
    so the bytes carry a value no UTF-8 consumer can hold, and round-trip
    equal on this side. An object key that is not a string leaves the
    serializer as an ``AttributeError`` from its sort key. A key that *is* a
    string is escaped exactly as a value is, so a key holding a lone surrogate
    is re-escaped too — and until this guard walked keys, the dict branch
    checked a key's type and walked only its value, so ``{"\\ud800": 1}``
    emitted, signed and verified green at every depth. Every key is now held
    to the same string rule as every value, ahead of its value.

    Per #34's second half this is one validator applied at every boundary
    rather than a check per site. Emission runs it on the body and on the
    payload before either is serialized; verification runs it on the parsed
    record and the parsed body before anything else reads them, so the schema
    check and the canonical-equality check only ever see strict input. Each
    refusal is an `EvidenceRecordError` naming the path to the value, rooted at
    the value handed in — ``evidence body: count``, ``evidence record:
    producer.repo``, ``evidence record: refs[1].sha256`` — and the class.
    Everything else passes: ``True``, ``False``, ``None``, integers in range,
    finite floats whose canonical token is not an out-of-range integer token
    and that are not negative zero, strings without surrogates. Types
    canonical.py refuses outright are left to it. So is recursion: a cyclic
    body recurses in this
    walk before canonical.py could say "circular", and leaves as Python's
    ``RecursionError`` — fail-closed, stated here, and not translated. And no
    refusal here asks the interpreter to spell an integer it will not: past
    ``sys.get_int_max_str_digits()`` (4300 digits by default) CPython raises
    a ``ValueError`` of its own from ``str()`` and from an f-string alike,
    which is how ``10**5000`` left emission in place of its refusal; such an
    integer is described by its width instead.

    Module-local until the package's ``canonical_strict`` exists; then imported.
    """

    def refuse(path: str, reason: str) -> NoReturn:
        where = path if path else "the top-level value"
        raise EvidenceRecordError(f"{label}: {where} {reason}")

    def spell(item: int) -> str:
        """An integer for a refusal, spelled when the interpreter will spell
        it. Past ``sys.get_int_max_str_digits()`` (4300 digits by default)
        CPython raises a ``ValueError`` of its own from ``str()`` and from an
        f-string alike; that limit is the bound, and past it the width is
        stated instead of the value."""
        try:
            return str(item)
        except ValueError:
            return f"an integer of {item.bit_length()} bits"

    def out_of_range_token(item: int | float) -> str | None:
        """The fact about a number whose canonical token is an integer token
        outside ±(2**53 - 1), or None. Asked after the type rules, so the
        serializer is only ever handed a finite float it will not raise on, or
        an ``int`` within ±(2**53 - 1) that it spells in at most sixteen
        digits — the ``int`` rule has already refused every wider one."""
        token = canonical_stringify(item)
        if _INTEGER_TOKEN_RE.fullmatch(token) is None or abs(int(token)) <= 2**53 - 1:
            return None
        return (
            f"renders as the integer token {token}, outside ±(2**53 - 1), which "
            f"a reader takes for an integer canonical JSON cannot carry exactly: "
            f"{item!r}"
        )

    def lone_surrogate(text: str) -> str | None:
        """The fact about the first surrogate code point in ``text``, or None."""
        for position, char in enumerate(text):
            if 0xD800 <= ord(char) <= 0xDFFF:
                return (
                    f"contains a lone surrogate U+{ord(char):04X} at index "
                    f"{position}, which no UTF-8 consumer can hold"
                )
        return None

    def walk(item: Any, path: str) -> None:
        if item is None or item is True or item is False:
            return
        if isinstance(item, int):
            if abs(item) > 2**53 - 1:
                refuse(
                    path,
                    "is an integer outside ±(2**53 - 1), which canonical JSON "
                    f"cannot carry exactly: {spell(item)}",
                )
            # Reached only within ±(2**53 - 1): the rule above has refused
            # every wider int, so canonical_stringify is never handed one it
            # would render through float() or spell past the interpreter's
            # digit limit.
            fact = out_of_range_token(item)
            if fact is not None:
                refuse(path, fact)
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                refuse(path, f"is not a finite number: {item}")
            if item == 0 and math.copysign(1.0, item) < 0:
                refuse(path, "is negative zero, which canonical JSON folds to 0")
            fact = out_of_range_token(item)
            if fact is not None:
                refuse(path, fact)
            return
        if isinstance(item, str):
            fact = lone_surrogate(item)
            if fact is not None:
                refuse(path, fact)
            return
        if isinstance(item, list):
            for position, entry in enumerate(item):
                walk(entry, f"{path}[{position}]")
            return
        if isinstance(item, dict):
            for key, entry in item.items():
                if not isinstance(key, str):
                    refuse(path, f"has an object key that is not a string: {key!r}")
                # The key first, through the same check as a value: the path
                # the refusal names is the container's, and the key is named
                # in it, since a surrogate cannot be spelled into a path.
                fact = lone_surrogate(key)
                if fact is not None:
                    refuse(path, f"has an object key {key!r} that {fact}")
                walk(entry, f"{path}.{key}" if path else key)
            return

    walk(value, "")


def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE's pre-authentication encoding: the bytes every signature covers.

    ``PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body``
    (secure-systems-lab/dsse, protocol.md): ``SP`` is one ASCII space, ``LEN``
    the ASCII decimal byte length with no leading zeros, ``type`` the UTF-8 of
    the payload type. Every field is preceded by its own length, so the
    encoding is self-delimiting: a signature made for one type over one body is
    not a signature for any other split of the same bytes.

    An evidence-record signature is made over ``PAE(schema id, record bytes)``
    and never over the record bytes, so the authorizing verifier's exact-bytes
    check over a record fails by construction (invariant 2), and the schema id
    inside the signed bytes says which record type the signature is for.

    This is an inline copy, kept to the stdlib so this PR takes no dependency:
    the frame #34 gives the package, written out here ahead of the package
    primitive so this record type's wire format is #34's from its first merge.
    It is to be replaced by that primitive when #34 lands.
    """

    type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode("ascii")
        + b" "
        + type_bytes
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


#: How a record, body or signature is opened: read-only, never through a link
#: at the leaf, never blocking on whatever stands there, and not inherited by
#: a child process. Each flag is guarded the way `release_chain` guards its
#: ``STATE_OPEN_FLAGS``; `_regular_file_bytes` refuses outright when the one
#: that matters, ``O_NOFOLLOW``, is not there.
_RECORD_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def _regular_file_bytes(
    root: pathlib.Path, relative: pathlib.PurePosixPath, label: str
) -> bytes:
    """Read one record, body or signature: a component ``lstat`` walk, one
    open of the leaf, and a descriptor held to the inode the walk approved.

    A deliberate near-copy of `release_chain._regular_file_bytes` in this
    module's words rather than an import of it, for the reason given above
    `_fail_json_constant`. What it replaces was check-then-open:
    ``path.is_symlink() or not path.is_file()`` and then ``path.read_bytes()``,
    which opened the path by name a second time. A writer outside the lock
    that swapped an approved record, body or signature for a link to a file
    outside the root between the check and the read had the link followed,
    and the directory verified green over bytes that were no part of it.

    What it does. Refuses when ``os.O_NOFOLLOW`` is unavailable — the package
    requires a POSIX platform. ``lstat``s every component of ``relative``
    below ``root``, refusing a symlink or reparse point at any of them and a
    non-directory at an intermediate one; requires the leaf's ``lstat`` to be
    a regular file. Opens the leaf once with `_RECORD_OPEN_FLAGS`. ``fstat``s
    the descriptor and requires a regular file with the ``(st_dev, st_ino)``
    the walk approved. Reads exactly ``st_size`` bytes in bounded chunks and
    requires one more read to return nothing. Closes in ``finally``. Two
    refusals: the leaf is missing or is not a regular file — which is also
    where a link planted at the leaf after the walk lands, as ``ELOOP`` from
    the open — and the leaf was replaced while being read, which is where a
    FIFO planted there lands, without blocking on it.

    What it is not. It is not an ``openat`` walk through retained directory
    descriptors: each component is ``lstat``-ed by path, the leaf is opened
    by path once, and the ``fstat`` comparison is what ties the open to the
    walk. It therefore does not cover an ancestor renamed between the walk
    and the open; a write in place to the approved inode (same ``(st_dev,
    st_ino)``, different bytes); the directory inode itself under the
    advisory lock; or a sidecar write that follows a symlink planted after
    enumeration, since emission's writes are by name. The lock in
    `_exclusive_records_directory` rests on the assumption it always rested
    on: every writer to this directory is an emitter, and takes it. Spelling
    is not bound here; the directory's components are spelled by
    `_assert_records_directory_is_confined`'s walk, and the leaf's name is the
    directory listing's own.
    """

    path = root / relative
    if not getattr(os, "O_NOFOLLOW", 0):
        raise EvidenceRecordError(
            f"{label} cannot be read without following links on this platform "
            "(os.O_NOFOLLOW is unavailable); receipt requires a POSIX platform"
        )
    missing = f"{label} is missing or is not a regular file: {path}"
    replaced = f"{label} was replaced while being read: {path}"
    components = relative.parts
    current = root
    approved: os.stat_result | None = None
    try:
        for depth, segment in enumerate(components, start=1):
            current = current / segment
            approved = os.lstat(current)
            if stat.S_ISLNK(approved.st_mode) or getattr(approved, "st_reparse_tag", 0):
                raise EvidenceRecordError(missing)
            if depth < len(components) and not stat.S_ISDIR(approved.st_mode):
                raise EvidenceRecordError(missing)
        if approved is None or not stat.S_ISREG(approved.st_mode):
            raise EvidenceRecordError(missing)
        descriptor = os.open(path, _RECORD_OPEN_FLAGS)
    except EvidenceRecordError:
        raise
    except OSError as exc:
        raise EvidenceRecordError(missing) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev,
            opened.st_ino,
        ) != (approved.st_dev, approved.st_ino):
            raise EvidenceRecordError(replaced)
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1 << 20, remaining))
            if not chunk:
                raise EvidenceRecordError(replaced)
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise EvidenceRecordError(replaced)
        return b"".join(chunks)
    except OSError as exc:
        raise EvidenceRecordError(missing) from exc
    finally:
        os.close(descriptor)


def _load_canonical_json(
    root: pathlib.Path, relative: pathlib.PurePosixPath, label: str
) -> tuple[dict[str, Any], bytes]:
    """Parse one record or body, its bytes taken through `_regular_file_bytes`.

    Takes the root and the leaf's path below it, rather than one joined path,
    because the reader walks the components and the walk has to know where
    the root is. The refusals below name the joined path as they always did.

    An integer literal wider than the interpreter will convert —
    ``sys.get_int_max_str_digits()``, 4300 digits by default since CPython
    3.11 — leaves ``json.loads`` as a plain ``ValueError`` rather than a
    ``JSONDecodeError``, and used to leave this module the same way. It is
    refused here in the module's words, naming the limit for what it is: the
    interpreter's, not JSON's. The module's own hooks raise
    `EvidenceRecordError`, itself a ``ValueError``, from inside the parse, so
    those pass through first and unchanged.
    """

    path = root / relative
    raw = _regular_file_bytes(root, relative, label)
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
    except EvidenceRecordError:
        raise
    except json.JSONDecodeError as exc:
        raise EvidenceRecordError(
            f"{label} is not valid JSON: {path}: {exc}"
        ) from exc
    except ValueError as exc:
        raise EvidenceRecordError(
            f"{label} holds an integer literal wider than this interpreter will "
            f"convert: {path}: {exc}"
        ) from exc
    return parsed, raw


def load_evidence_record(
    path: pathlib.Path, spec: EvidenceSpec
) -> tuple[dict[str, Any], bytes, str]:
    """Read one record: parse, hold the parsed value to strict canonical input,
    validate the schema, then hold the bytes to the canonical rule.

    The strict check stands first because it is about the value and not about
    the shape: a lone surrogate in ``producer.repo`` is a non-empty string to
    the schema and re-escapes to the bytes it was read from, so before this
    check it verified green; a hand-written ``1e999`` in a numeric field was
    refused for being "not an integer" rather than for being infinite.

    The record is read through `_regular_file_bytes`, which walks the path
    below the root, so the root is derived here from the path handed in: it
    has to end in the records directory the spec names followed by the
    record's own name, and a path that does not is refused rather than
    guessed at. Every caller in the package hands over exactly that path.
    """

    relative = spec.records_relative / path.name
    if tuple(path.parts[-len(relative.parts) :]) != relative.parts:
        raise EvidenceRecordError(
            f"evidence record is not in the records directory the spec names: {path}"
        )
    root = path.parents[len(relative.parts) - 1]
    parsed, raw = _load_canonical_json(root, relative, "evidence record")
    _canonical_strict(parsed, "evidence record")
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
    """Enumerate one closed records directory, after checking its filesystem
    confinement.

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
        # Checked last, and harmlessly: `RECORD_RE` is anchored and does not
        # match `0000-<16 hex>.body.json`, so the order the three patterns are
        # consulted in is free
        # (`test_record_filename_grammar_is_deliberately_a_manifest_grammar`).
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
    well-formed, chained, and signed by the pinned producer over this record
    type's frame — and says nothing about the custody of any release. It
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

    The pinned public key is read out of ``anchor_dir`` by `sign`, which
    refuses a missing or non-regular one in its own words, as a `SignError`.
    What else leaves this entry point in words other than this module's: IO
    errors, as raised, and a ``RecursionError`` on a record or body nested
    deeper than the interpreter's recursion limit, which recurses in
    ``json.loads`` itself and is not translated.
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

    The signature is checked over ``_pae(spec.schema_version, raw)``, the same
    frame emission signs. It used to be checked over a NUL-terminated domain
    string prefixed to the record; the frame puts the schema id inside the
    signed bytes with its own length, so a signature under another schema id,
    under the old prefix, or over the bare record is refused here alike.

    The record, the body and the signature are each read through
    `_regular_file_bytes` — one open of the leaf, held to the inode a
    component walk approved — where they used to be checked by name and then
    read by name. See that function for what the change covers and does not.
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

        parsed_body, body_raw = _load_canonical_json(
            root, spec.records_relative / body_path.name, "evidence body"
        )
        # Held to strict canonical input before the canonical-equality check
        # below, which would otherwise pass a body carrying 2**53 or a lone
        # surrogate (canonical.py renders each back to the bytes it was read
        # from) and would leave the module as canonical.py's own bare
        # ValueError on a hand-written 1e999.
        _canonical_strict(parsed_body, "evidence body")
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

        signature = _regular_file_bytes(
            root, spec.records_relative / signature_path.name, "producer signature"
        )
        try:
            # What makes this signature unusable as a manifest signature is
            # that the signed bytes are the frame, not the record: the
            # authorizing verifier checks a manifest's exact bytes, and no
            # record's exact bytes are what was signed here. The frame's
            # payload type is the schema id, so this one check also refuses a
            # signature made for any other record type.
            _sign.verify_signature_bytes(
                _pae(spec.schema_version, raw),
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
    queueing behind it or, worse, proceeding. It is advisory in the strict
    sense: it binds the writers that take it, and every claim made here about
    a second writer rests on the assumption that every writer to this directory
    is an emitter that does. `fcntl.flock` is not standardized by POSIX, but it
    is available on the POSIX platforms this package requires (README) — the
    same platforms its guarded reader requires, and that reader is a component
    ``lstat`` walk, one open of the leaf with ``O_NOFOLLOW | O_NONBLOCK``, an
    ``fstat`` held to the regular inode the walk approved, and reads through
    that descriptor (`release_chain._regular_file_bytes`, and this module's
    near-copy of it).

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

    Three things are settled before any byte of a record is written. The
    signing key is compared to the spec's pin, because a key the verifier will
    refuse is a fact the producer can know at emission time rather than one an
    auditor discovers later. The records directory is checked for confinement —
    no symlinked component, and not inside the release root as the filesystem
    resolves it — before it is created, so a linked component is refused rather
    than written through. The signing-key checks — decoding and the pin — and
    the confinement check are the only ones ahead of the `mkdir`: a refusal
    from any of them leaves no directory behind, while every later refusal
    leaves the directory — possibly created empty by this call — and writes no
    record or sidecar bytes. And the directory is held exclusively from
    enumeration through the last write, so no second emitter that takes the
    same lock can claim the index this one claims; the lock is advisory, so
    that holds for the writers that take it, which every emitter does and
    nothing else is assumed to.

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

    The record is created exclusively and written last, after both sidecars,
    so a record's presence implies its body and its signature were written
    before it. It does not imply a complete or durable record: nothing here
    fsyncs, and the exclusive create refuses an existing leaf and nothing more.
    Nor is it the order enumeration reads them in — enumeration collects
    whatever names the directory lists, in no specified order, and sorts the
    records at the end.
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

    The signature is made over ``_pae(spec.schema_version, raw)`` with the
    signing primitive's deliberately empty domain — the frame is the whole
    message — and `_verify_records` checks exactly those bytes.

    The body and the payload are each held to strict canonical input before
    they are serialized (`_canonical_strict`): the body because this module
    does not validate what a domain event contains and canonical.py would
    round, fold, re-escape or raise on some of it without a word; the payload
    because ``producer`` and ``body_schema`` are the caller's verbatim. Both
    stand ahead of the first write, and so does the verification of what is
    already in the directory: every input and chain refusal is complete before
    a sidecar byte is written. What is not ahead of the writes is the exclusive
    create that binds the index — it comes after both sidecars — and the
    sidecar writes themselves, which can fail on IO. A crash in that window
    leaves an orphan body or signature, and the directory then refuses to
    enumerate at all until they are cleared by hand
    (`test_orphan_body_is_refused`, `test_orphan_signature_is_refused`):
    fail-closed, and not self-healing.
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
    _canonical_strict(body, "evidence body")
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
    # Validate before writing anything: no input refusal leaves a partial
    # record on disk for the verifier to trip over. A crash after the sidecar
    # writes below still can, and the directory refuses those orphans rather
    # than reading past them.
    _canonical_strict(payload, "evidence record")
    validate_evidence_record_schema(payload, spec)
    raw = canonical_document_bytes(payload)
    record_path = directory / record_filename(index, raw)
    if record_path.exists() or record_path.is_symlink():
        raise EvidenceRecordError(
            f"evidence record {record_path.name} already exists at index {index}"
        )
    signature = _sign.sign_payload(
        private_key_pem, _pae(spec.schema_version, raw), domain=b""
    )

    body_path_for_record(record_path).write_bytes(body_raw)
    producer_signature_path_for_record(record_path).write_bytes(signature)
    # Exclusive, and last: `O_EXCL` refuses an existing leaf, which is all it
    # refuses — it is no bar against a writer outside this lock — and a
    # record's presence implies its sidecars were written before it.
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
