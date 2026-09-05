"""Refusal battery for non-authorizing evidence records.

`receipt.evidence` is new composition rather than an extraction, so it has no
upstream oracle and no port-diff gate. Its gate is this file: a round trip, the
chain rules, one test per way a record can fail to be what it claims, and the
non-authorization invariant that gives the record type its name.
"""

from __future__ import annotations

import errno
import fcntl
import json
import pathlib
from dataclasses import FrozenInstanceError

import pytest

from receipt.canonical import canonical_bytes
from receipt.evidence import (
    RECORD_RE,
    SCHEMA_VERSION,
    STANDING,
    EvidenceRecordError,
    EvidenceSpec,
    canonical_document_bytes,
    emit_evidence_record,
    load_evidence_record,
    record_filename,
    sha256_bytes,
    validate_evidence_record_schema,
    verify_evidence_records,
)
from receipt.evidence import _enumerate_record_files
from receipt.release_chain import (
    MANIFEST_RE,
    AnchorSpec,
    ChainSpec,
    ReleaseChainError,
    _enumerate_manifest_files,
    validate_manifest_schema,
)
from receipt.sign import (
    SignError,
    generate_signing_keypair,
    spki_sha256,
    verify_signature_bytes,
)

RECORDS = pathlib.PurePosixPath("evidence/records")
ANCHORS = "anchors"
BODY = {"event": "generation", "generation": 7, "populationRootSha256": "a" * 64}
BODY_SCHEMA = "example.org/generation-event/v1"
PRODUCER = {"repo": "example/consumer", "branch": "main"}
EMITTED = "2026-08-27T14:05:00Z"
#: A well-formed producer pin for specs that are only ever constructed. Tests
#: that verify a signature pin the real key through the `spec` fixture.
PIN = "c" * 64
#: ChainSpec requires a configured witness, and these tests build one only to
#: hand it to the authorizing verifier, which never reaches the anchor.
CHAIN_ANCHORS = {
    "alpha": AnchorSpec(
        filename="alpha.pem",
        pem_sha256="1" * 64,
        policy_oid="1.2.3.4",
        signer_certificate_sha256="2" * 64,
        signer_spki_sha256="3" * 64,
    )
}


@pytest.fixture
def keys() -> tuple[bytes, bytes]:
    return generate_signing_keypair()


@pytest.fixture
def anchor_dir(tmp_path: pathlib.Path, keys: tuple[bytes, bytes]) -> pathlib.Path:
    private_pem, public_pem = keys
    directory = tmp_path / ANCHORS
    directory.mkdir()
    (directory / "producer.pem").write_bytes(public_pem)
    return directory


@pytest.fixture
def spec(keys: tuple[bytes, bytes]) -> EvidenceSpec:
    _, public_pem = keys
    return EvidenceSpec(
        records_relative=RECORDS,
        producer_spki_sha256=spki_sha256(public_pem),
        release_root_relative=pathlib.PurePosixPath("releases"),
    )


@pytest.fixture
def emitted(
    tmp_path: pathlib.Path, spec: EvidenceSpec, keys: tuple[bytes, bytes]
) -> pathlib.Path:
    private_pem, _ = keys
    return emit_evidence_record(
        tmp_path,
        spec=spec,
        private_key_pem=private_pem,
        body=BODY,
        body_schema=BODY_SCHEMA,
        refs=[{"kind": "release-manifest", "sha256": "b" * 64}],
        producer=PRODUCER,
        emitted_at_utc=EMITTED,
    )


def _rewrite(path: pathlib.Path, mutate) -> None:
    """Rewrite a record in place, canonically, after mutating its payload."""

    payload = json.loads(path.read_text())
    mutate(payload)
    path.write_bytes(canonical_document_bytes(payload))


def _framed(spec: EvidenceSpec, raw: bytes) -> bytes:
    """The bytes an evidence-record signature covers: ``PAE(schema id, raw)``."""

    from receipt.evidence import _pae

    return _pae(spec.schema_version, raw)


# --------------------------------------------------------------------------
# The invariant this record type exists for.
# --------------------------------------------------------------------------


def test_an_evidence_record_is_refused_by_the_authorizing_verifier(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
    keys: tuple[bytes, bytes],
) -> None:
    """Both halves of non-authorization, asserted together.

    (a) an evidence record raises in validate_manifest_schema, and (b) its
    signature fails the exact-bytes check the authorizing verifier uses. Either
    failure alone would be enough; both hold.
    """

    _, public_pem = keys
    payload, raw, _ = load_evidence_record(emitted, spec)
    signature = emitted.with_name(f"{emitted.stem}.producer.sig").read_bytes()

    chain_spec = ChainSpec(
        manifest_relative=pathlib.PurePosixPath("releases/manifests"),
        state_relative=pathlib.PurePosixPath("releases/state.jsonl"),
        prefix_relative=pathlib.PurePosixPath("releases/prefix"),
        anchor_relative=pathlib.PurePosixPath("releases/anchors"),
        release_root_relative=pathlib.PurePosixPath("releases"),
        schema_version="example.org/release-manifest/v1",
        producer_public_key_filename="producer.pem",
        producer_spki_sha256=spki_sha256(public_pem),
        anchors=CHAIN_ANCHORS,
    )

    # (a) The schema refusal is structural: closed-world keys, so it lands
    # before any value is inspected.
    with pytest.raises(ReleaseChainError) as schema_exc:
        validate_manifest_schema(payload, chain_spec)
    assert "closed-world" in str(schema_exc.value)

    # (b) The authorizing verifier checks the exact bytes of what it is handed,
    # and no evidence record's exact bytes are what was signed.
    with pytest.raises(SignError):
        verify_signature_bytes(
            raw,
            signature,
            public_pem,
            public_key_filename="producer.pem",
            spki_sha256=spec.producer_spki_sha256,
            label="as-if-a-manifest",
        )

    # ...and the same signature is valid over this record type's frame — the
    # DSSE pre-authentication encoding of the schema id and the record bytes —
    # so (b) is a framing result and not a broken signature.
    verify_signature_bytes(
        _framed(spec, raw),
        signature,
        public_pem,
        public_key_filename="producer.pem",
        spki_sha256=spec.producer_spki_sha256,
        label="evidence record",
    )
    assert verify_evidence_records(
        tmp_path, spec=spec, anchor_dir=anchor_dir
    ).records[0].sha256 == sha256_bytes(raw)


# --------------------------------------------------------------------------
# The frame the signature is made over.
# --------------------------------------------------------------------------


def test_the_frame_is_the_dsse_pre_authentication_encoding(
    emitted: pathlib.Path,
) -> None:
    """Byte-level pin of PAE as DSSE defines it, for this record type.

    ``"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body``: the schema id is
    26 bytes, the record's length is written in ASCII decimal, and the record
    bytes follow verbatim, trailing newline included.
    """

    from receipt.evidence import _pae

    raw = emitted.read_bytes()
    assert SCHEMA_VERSION == "receipt/evidence-record/v1"
    assert _pae("receipt/evidence-record/v1", raw) == (
        b"DSSEv1 26 receipt/evidence-record/v1 "
        + str(len(raw)).encode("ascii")
        + b" "
        + raw
    )


def test_the_frame_is_self_delimiting(keys: tuple[bytes, bytes]) -> None:
    """A signature for one payload type over one body is for no other split.

    ``"a" + "bc"`` and ``"ab" + "c"`` are the same bytes concatenated. Under
    the frame each field carries its own length, so the two encodings differ
    and a signature over the first does not verify over the second.
    """

    from receipt.evidence import _pae
    from receipt.sign import sign_payload

    private_pem, public_pem = keys
    assert _pae("a", b"bc") != _pae("ab", b"c")
    signature = sign_payload(private_pem, _pae("a", b"bc"), domain=b"")
    verify_signature_bytes(
        _pae("a", b"bc"),
        signature,
        public_pem,
        public_key_filename="producer.pem",
        spki_sha256=spki_sha256(public_pem),
        label="type a over bc",
    )
    with pytest.raises(SignError):
        verify_signature_bytes(
            _pae("ab", b"c"),
            signature,
            public_pem,
            public_key_filename="producer.pem",
            spki_sha256=spki_sha256(public_pem),
            label="type ab over c",
        )


def _chain_spec(public_pem: bytes) -> ChainSpec:
    return ChainSpec(
        manifest_relative=pathlib.PurePosixPath("releases/manifests"),
        state_relative=pathlib.PurePosixPath("releases/state.jsonl"),
        prefix_relative=pathlib.PurePosixPath("releases/prefix"),
        anchor_relative=pathlib.PurePosixPath("releases/anchors"),
        release_root_relative=pathlib.PurePosixPath("releases"),
        schema_version="example.org/release-manifest/v1",
        producer_public_key_filename="producer.pem",
        producer_spki_sha256=spki_sha256(public_pem),
        anchors=CHAIN_ANCHORS,
    )


def _plant_in_release_directory(
    tmp_path: pathlib.Path, emitted: pathlib.Path, suffixes: list[str]
) -> pathlib.Path:
    directory = tmp_path / "releases" / "manifests"
    directory.mkdir(parents=True, exist_ok=True)
    for suffix in suffixes:
        name = f"{emitted.stem}{suffix}"
        (directory / name).write_bytes((emitted.parent / name).read_bytes())
    return directory


def test_record_filename_grammar_is_deliberately_a_manifest_grammar(
    emitted: pathlib.Path,
) -> None:
    """The filename does NOT keep the two apart, and the docstring says so.

    A record mirrors a manifest's filename layout on purpose, so
    release_chain's own pattern matches it. Anything claiming the separation
    is carried by the filename grammar is wrong; this test pins that.
    """

    assert RECORD_RE.pattern == MANIFEST_RE.pattern
    assert MANIFEST_RE.fullmatch(emitted.name) is not None
    assert MANIFEST_RE.fullmatch(f"{emitted.stem}.body.json") is None


def test_planted_record_with_body_is_refused_at_enumeration(
    tmp_path: pathlib.Path, emitted: pathlib.Path, keys: tuple[bytes, bytes]
) -> None:
    _, public_pem = keys
    _plant_in_release_directory(
        tmp_path, emitted, [".json", ".body.json", ".producer.sig"]
    )
    with pytest.raises(ReleaseChainError, match="unknown file in closed"):
        _enumerate_manifest_files(tmp_path, _chain_spec(public_pem))


def test_planted_record_alone_is_refused_for_a_missing_receipt(
    tmp_path: pathlib.Path, emitted: pathlib.Path, keys: tuple[bytes, bytes]
) -> None:
    """A record alone carries a manifest's filename and nothing else a closed
    release directory holds. Enumeration wants a receipt for every configured
    anchor, and asks for that before it looks for the producer signature, so
    this is where a record alone now stops."""

    _, public_pem = keys
    _plant_in_release_directory(tmp_path, emitted, [".json"])
    with pytest.raises(ReleaseChainError, match="must have exactly"):
        _enumerate_manifest_files(tmp_path, _chain_spec(public_pem))


def test_planted_record_and_signature_are_refused_for_a_missing_receipt(
    tmp_path: pathlib.Path, emitted: pathlib.Path, keys: tuple[bytes, bytes]
) -> None:
    """This module's producer signature is spelled exactly as a manifest's, so
    the pair satisfies both filename patterns — and is still refused one
    requirement earlier than the signature: the receipt set is checked
    first."""

    _, public_pem = keys
    _plant_in_release_directory(tmp_path, emitted, [".json", ".producer.sig"])
    with pytest.raises(ReleaseChainError, match="must have exactly"):
        _enumerate_manifest_files(tmp_path, _chain_spec(public_pem))


def test_planted_record_signature_and_receipt_die_at_the_schema(
    tmp_path: pathlib.Path, emitted: pathlib.Path, keys: tuple[bytes, bytes]
) -> None:
    """The arrangement that gets furthest — and where invariant 1 earns its keep.

    Record, signature and one receipt sidecar carry manifest-shaped filenames,
    so enumeration accepts all three: the receipt is counted here and not
    opened, which makes its grammar one more thing the filename layout does
    not keep apart. Nothing about the filenames stops the arrangement; the
    closed-world schema check does.
    """

    _, public_pem = keys
    chain_spec = _chain_spec(public_pem)
    directory = _plant_in_release_directory(
        tmp_path, emitted, [".json", ".producer.sig"]
    )
    (directory / f"{emitted.stem}.alpha.tsr").write_bytes(b"not a receipt")
    enumerated = _enumerate_manifest_files(tmp_path, chain_spec)
    assert len(enumerated) == 1

    payload = json.loads((directory / emitted.name).read_text())
    with pytest.raises(ReleaseChainError, match="closed-world"):
        validate_manifest_schema(payload, chain_spec)


def test_standing_is_inside_the_signed_bytes(
    spec: EvidenceSpec, emitted: pathlib.Path
) -> None:
    raw = emitted.read_bytes()
    assert b'"standing":"non-authorizing"' in raw
    payload, _, _ = load_evidence_record(emitted, spec)
    assert payload["standing"] == STANDING


def test_evidence_verifier_is_not_wired_into_the_authorizing_verdict() -> None:
    """The authorizing verdict must not be able to see this module at all."""

    import ast

    import receipt.verify as verify_module

    tree = ast.parse(pathlib.Path(verify_module.__file__).read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert not any(name.startswith("receipt.evidence") for name in imported)
    assert not hasattr(verify_module, "verify_evidence_records")


# --------------------------------------------------------------------------
# Round trip and chain rules.
# --------------------------------------------------------------------------


def test_round_trip(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    result = verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)
    assert len(result.records) == 1
    record = result.records[0]
    assert record.record_index == 0
    assert record.record["previousRecordSha256"] is None
    assert record.record["body"]["schema"] == BODY_SCHEMA
    assert json.loads(record.body_raw) == BODY
    assert result.head is record
    assert emitted.name == record_filename(0, record.raw)


def test_genesis_and_chain_link(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    keys: tuple[bytes, bytes],
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    private_pem, _ = keys
    second = emit_evidence_record(
        tmp_path,
        spec=spec,
        private_key_pem=private_pem,
        body={"event": "generation", "generation": 8},
        body_schema=BODY_SCHEMA,
        refs=[],
        producer=PRODUCER,
        emitted_at_utc="2026-08-27T15:05:00Z",
    )
    result = verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)
    assert [r.record_index for r in result.records] == [0, 1]
    first_digest = sha256_bytes(emitted.read_bytes())
    assert result.records[1].record["previousRecordSha256"] == first_digest
    assert second.name.startswith("0001-")


def test_an_absent_records_directory_verifies_as_the_zero_record_chain(
    tmp_path: pathlib.Path, spec: EvidenceSpec, anchor_dir: pathlib.Path
) -> None:
    """The empty state a checkout can actually carry.

    This test never made the directory, so absence is what it has always
    exercised — under a name that said the opposite. Both are the zero-record
    chain, and the result said nothing that told them apart.
    """

    assert not (tmp_path / RECORDS).exists()
    result = verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)
    assert result.records == ()
    assert result.head is None
    assert result.directory_present is False


def test_an_existing_empty_records_directory_verifies_as_the_zero_record_chain(
    tmp_path: pathlib.Path, spec: EvidenceSpec, anchor_dir: pathlib.Path
) -> None:
    """The other way to reach zero records, and the field that says which."""

    (tmp_path / RECORDS).mkdir(parents=True)
    result = verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)
    assert result.records == ()
    assert result.head is None
    assert result.directory_present is True


def _resign_in_place(
    path: pathlib.Path, spec: EvidenceSpec, private_key_pem: bytes, mutate
) -> pathlib.Path:
    """Mutate a record on disk and re-file it under its new digest.

    Everything downstream of the mutation is made self-consistent — canonical
    bytes, filename, signature — so verification has to reach the check the
    test is actually aiming at rather than tripping on the filename first.
    """

    payload = json.loads(path.read_text())
    mutate(payload)
    return _refile(
        path,
        spec,
        private_key_pem,
        int(payload["recordIndex"]),
        canonical_document_bytes(payload),
    )


def _refile(
    path: pathlib.Path,
    spec: EvidenceSpec,
    private_key_pem: bytes,
    index: int,
    raw: bytes,
) -> pathlib.Path:
    """Replace the record at ``path`` with ``raw``: filed under its own digest,
    its body kept beside it, and signed over the frame."""

    from receipt.sign import sign_payload

    body_raw = path.with_name(f"{path.stem}.body.json").read_bytes()

    for stale in path.parent.glob(f"{path.stem}.*"):
        stale.unlink()
    path.unlink(missing_ok=True)

    new_path = path.with_name(record_filename(index, raw))
    new_path.write_bytes(raw)
    new_path.with_name(f"{new_path.stem}.body.json").write_bytes(body_raw)
    new_path.with_name(f"{new_path.stem}.producer.sig").write_bytes(
        sign_payload(private_key_pem, _framed(spec, raw), domain=b"")
    )
    return new_path


#: Stands in for a value that has to be spelled by hand, below.
SENTINEL = "__hand_written__"
_QUOTED_SENTINEL = f'"{SENTINEL}"'.encode("ascii")


def _refile_with_literal(
    path: pathlib.Path,
    spec: EvidenceSpec,
    private_key_pem: bytes,
    mutate,
    literal: bytes,
) -> pathlib.Path:
    """Re-file a record with one value spelled as a hand-written JSON literal.

    `_resign_in_place` serializes through canonical.py, which is exactly the
    code that rounds, folds or raises on the values these tests plant — so a
    record carrying one has to be written the way a person would write it.
    ``mutate`` sets the target field to `SENTINEL`; the record is canonicalized;
    the quoted sentinel is then replaced by ``literal`` and the result filed
    and signed like any other record, so verification reaches the strict-input
    check rather than the filename or the signature.
    """

    payload = json.loads(path.read_text())
    mutate(payload)
    raw = canonical_document_bytes(payload)
    assert raw.count(_QUOTED_SENTINEL) == 1
    return _refile(
        path,
        spec,
        private_key_pem,
        int(payload["recordIndex"]),
        raw.replace(_QUOTED_SENTINEL, literal),
    )


def _body_with_literal(literal: bytes) -> bytes:
    """A canonical one-field body, with the field's value spelled by hand."""

    raw = canonical_document_bytes({"count": SENTINEL})
    assert raw.count(_QUOTED_SENTINEL) == 1
    return raw.replace(_QUOTED_SENTINEL, literal)


def test_broken_predecessor_link_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    keys: tuple[bytes, bytes],
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    private_pem, _ = keys
    second = emit_evidence_record(
        tmp_path,
        spec=spec,
        private_key_pem=private_pem,
        body={"event": "generation", "generation": 8},
        body_schema=BODY_SCHEMA,
        refs=[],
        producer=PRODUCER,
        emitted_at_utc="2026-08-27T15:05:00Z",
    )
    # Point record 1 at a predecessor that is not record 0, then make the
    # record wholly self-consistent again: valid schema, canonical bytes,
    # filename matching its own digest, a good signature over those bytes.
    _resign_in_place(
        second,
        spec,
        private_pem,
        lambda payload: payload.__setitem__("previousRecordSha256", "c" * 64),
    )
    with pytest.raises(EvidenceRecordError, match="does not link to its predecessor"):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_a_hole_in_the_index_sequence_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    keys: tuple[bytes, bytes],
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    private_pem, _ = keys
    emit_evidence_record(
        tmp_path,
        spec=spec,
        private_key_pem=private_pem,
        body={"event": "generation", "generation": 8},
        body_schema=BODY_SCHEMA,
        refs=[],
        producer=PRODUCER,
        emitted_at_utc="2026-08-27T15:05:00Z",
    )
    # Remove the genesis record: record 1 is now the first file in the
    # directory, and a chain that does not start at 0 is not a chain.
    for stale in (tmp_path / RECORDS).glob(f"{emitted.stem}*"):
        stale.unlink()
    with pytest.raises(EvidenceRecordError, match="not contiguous from 0"):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


# --------------------------------------------------------------------------
# Closed-world schema refusals.
# --------------------------------------------------------------------------


def test_unknown_top_level_key_is_refused(spec: EvidenceSpec) -> None:
    payload = _valid_payload()
    payload["extra"] = 1
    with pytest.raises(EvidenceRecordError) as exc:
        validate_evidence_record_schema(payload, spec)
    assert "unknown=['extra']" in str(exc.value)


def test_missing_top_level_key_is_refused(spec: EvidenceSpec) -> None:
    payload = _valid_payload()
    del payload["refs"]
    with pytest.raises(EvidenceRecordError) as exc:
        validate_evidence_record_schema(payload, spec)
    assert "missing=['refs']" in str(exc.value)


@pytest.mark.parametrize(
    "standing", ["authorizing", "", "non authorizing", "NON-AUTHORIZING"]
)
def test_wrong_standing_is_refused(spec: EvidenceSpec, standing: str) -> None:
    payload = _valid_payload()
    payload["standing"] = standing
    with pytest.raises(EvidenceRecordError, match="standing must be exactly"):
        validate_evidence_record_schema(payload, spec)


def test_wrong_schema_version_is_refused(spec: EvidenceSpec) -> None:
    payload = _valid_payload()
    payload["schemaVersion"] = "receipt/evidence-record/v2"
    with pytest.raises(EvidenceRecordError, match="unsupported evidence-record"):
        validate_evidence_record_schema(payload, spec)


def test_genesis_must_have_null_predecessor(spec: EvidenceSpec) -> None:
    payload = _valid_payload()
    payload["previousRecordSha256"] = "c" * 64
    with pytest.raises(EvidenceRecordError, match="genesis"):
        validate_evidence_record_schema(payload, spec)


def test_non_genesis_must_have_a_predecessor_digest(spec: EvidenceSpec) -> None:
    payload = _valid_payload()
    payload["recordIndex"] = 1
    with pytest.raises(EvidenceRecordError, match="previousRecordSha256"):
        validate_evidence_record_schema(payload, spec)


def test_boolean_is_not_an_integer_index(spec: EvidenceSpec) -> None:
    payload = _valid_payload()
    payload["recordIndex"] = True
    with pytest.raises(EvidenceRecordError, match="not a boolean"):
        validate_evidence_record_schema(payload, spec)


def test_index_beyond_the_filename_limit_is_refused(spec: EvidenceSpec) -> None:
    payload = _valid_payload()
    payload["recordIndex"] = 10_000
    payload["previousRecordSha256"] = "c" * 64
    with pytest.raises(EvidenceRecordError, match="four-digit"):
        validate_evidence_record_schema(payload, spec)


@pytest.mark.parametrize(
    "emitted_at",
    ["2026-08-27 14:05:00Z", "2026-08-27T14:05:00+00:00", "2026-02-30T00:00:00Z", ""],
)
def test_malformed_emitted_at_is_refused(spec: EvidenceSpec, emitted_at: str) -> None:
    payload = _valid_payload()
    payload["emittedAtUtc"] = emitted_at
    # An EvidenceRecordError, never release_chain's own exception type.
    with pytest.raises(EvidenceRecordError):
        validate_evidence_record_schema(payload, spec)


def test_producer_block_is_closed_world(spec: EvidenceSpec) -> None:
    payload = _valid_payload()
    payload["producer"] = {"repo": "a", "branch": "b", "commit": "c"}
    with pytest.raises(EvidenceRecordError, match="producer keys"):
        validate_evidence_record_schema(payload, spec)


def test_body_block_is_closed_world(spec: EvidenceSpec) -> None:
    payload = _valid_payload()
    payload["body"] = {"schema": "x", "sha256": "a" * 64, "inline": {}}
    with pytest.raises(EvidenceRecordError, match="body keys"):
        validate_evidence_record_schema(payload, spec)


def test_body_digest_must_be_hex(spec: EvidenceSpec) -> None:
    payload = _valid_payload()
    payload["body"]["sha256"] = "A" * 64
    with pytest.raises(EvidenceRecordError, match="64 lowercase"):
        validate_evidence_record_schema(payload, spec)


# --------------------------------------------------------------------------
# refs: closed enum, sorted, strictly unique.
# --------------------------------------------------------------------------


def test_unknown_ref_kind_is_refused(spec: EvidenceSpec) -> None:
    payload = _valid_payload()
    payload["refs"] = [{"kind": "invoice", "sha256": "a" * 64}]
    with pytest.raises(EvidenceRecordError, match="kind must be one of"):
        validate_evidence_record_schema(payload, spec)


def test_ref_entry_is_closed_world(spec: EvidenceSpec) -> None:
    payload = _valid_payload()
    payload["refs"] = [{"kind": "record", "sha256": "a" * 64, "note": "x"}]
    with pytest.raises(EvidenceRecordError, match=r"refs\[0\] keys"):
        validate_evidence_record_schema(payload, spec)


def test_unsorted_refs_are_refused(spec: EvidenceSpec) -> None:
    payload = _valid_payload()
    payload["refs"] = [
        {"kind": "record", "sha256": "a" * 64},
        {"kind": "draw-set", "sha256": "a" * 64},
    ]
    with pytest.raises(EvidenceRecordError, match="sorted"):
        validate_evidence_record_schema(payload, spec)


def test_duplicate_refs_are_refused(spec: EvidenceSpec) -> None:
    payload = _valid_payload()
    payload["refs"] = [
        {"kind": "record", "sha256": "a" * 64},
        {"kind": "record", "sha256": "a" * 64},
    ]
    with pytest.raises(EvidenceRecordError, match="strictly unique"):
        validate_evidence_record_schema(payload, spec)


def test_refs_must_be_an_array(spec: EvidenceSpec) -> None:
    payload = _valid_payload()
    payload["refs"] = {"kind": "record", "sha256": "a" * 64}
    with pytest.raises(EvidenceRecordError, match="refs must be an array"):
        validate_evidence_record_schema(payload, spec)


def test_emission_refuses_a_ref_with_no_digest_by_name(
    tmp_path: pathlib.Path, spec: EvidenceSpec, keys: tuple[bytes, bytes]
) -> None:
    """The sort key read `sha256` out of an entry nothing had checked.

    Emission sorts the caller's refs on ``(kind, sha256)`` to build the
    record, and it did that before the schema saw them — so a ref with no
    digest left this module as a `KeyError`, not as the refusal that names
    `refs[0]`.
    """

    private_pem, _ = keys
    with pytest.raises(EvidenceRecordError, match=r"refs\[0\]"):
        emit_evidence_record(
            tmp_path,
            spec=spec,
            private_key_pem=private_pem,
            body=BODY,
            body_schema=BODY_SCHEMA,
            refs=[{"kind": "record"}],
            producer=PRODUCER,
            emitted_at_utc=EMITTED,
        )
    assert list((tmp_path / RECORDS).iterdir()) == []


def test_emission_refuses_refs_that_are_not_an_array(
    tmp_path: pathlib.Path, spec: EvidenceSpec, keys: tuple[bytes, bytes]
) -> None:
    """`sorted` takes any iterable and hands back a list.

    A caller's tuple was therefore already a list by the time the schema
    check asked whether refs is an array: the one line that enforces the
    container type was answering about this module's own output rather than
    about what the caller passed.
    """

    private_pem, _ = keys
    with pytest.raises(EvidenceRecordError, match="refs must be an array"):
        emit_evidence_record(
            tmp_path,
            spec=spec,
            private_key_pem=private_pem,
            body=BODY,
            body_schema=BODY_SCHEMA,
            refs=({"kind": "record", "sha256": "a" * 64},),  # type: ignore[arg-type]
            producer=PRODUCER,
            emitted_at_utc=EMITTED,
        )
    assert list((tmp_path / RECORDS).iterdir()) == []


def test_emission_refuses_a_non_string_ref_kind_by_name(
    tmp_path: pathlib.Path, spec: EvidenceSpec, keys: tuple[bytes, bytes]
) -> None:
    """Two entries whose keys are not the same type are not comparable.

    The sort key is a tuple built from values nothing has checked, so a
    `kind` that is not a string reached `sorted` and left as a `TypeError`
    about `int` and `str` — a refusal from Python rather than from this
    module, naming neither the entry nor the field.
    """

    private_pem, _ = keys
    with pytest.raises(EvidenceRecordError, match=r"refs\[1\]\.kind must be a string"):
        emit_evidence_record(
            tmp_path,
            spec=spec,
            private_key_pem=private_pem,
            body=BODY,
            body_schema=BODY_SCHEMA,
            refs=[
                {"kind": "record", "sha256": "a" * 64},
                {"kind": 3, "sha256": "b" * 64},
            ],
            producer=PRODUCER,
            emitted_at_utc=EMITTED,
        )
    assert list((tmp_path / RECORDS).iterdir()) == []


# --------------------------------------------------------------------------
# On-disk refusals.
# --------------------------------------------------------------------------


def test_tampered_body_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    body_path = emitted.with_name(f"{emitted.stem}.body.json")
    body_path.write_bytes(canonical_document_bytes({"event": "tampered"}))
    with pytest.raises(EvidenceRecordError, match="body digest mismatch"):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_tampered_record_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    _rewrite(emitted, lambda p: p.__setitem__("producer", {"repo": "x", "branch": "y"}))
    # The filename carries the record's own digest, so the edit is caught
    # before any signature check.
    with pytest.raises(EvidenceRecordError, match="does not match its own digest"):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_non_canonical_bytes_are_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    payload = json.loads(emitted.read_text())
    emitted.write_bytes(json.dumps(payload, indent=2).encode("utf-8") + b"\n")
    with pytest.raises(EvidenceRecordError, match="canonical JSON plus one newline"):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_missing_trailing_newline_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    emitted.write_bytes(emitted.read_bytes().rstrip(b"\n"))
    with pytest.raises(EvidenceRecordError, match="canonical JSON plus one newline"):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_a_reserialized_body_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    keys: tuple[bytes, bytes],
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    """The body was only ever hashed, never held to the rule it is stored by.

    A digest binds a byte stream, and any byte stream that hashes to it
    satisfies the record — so a body reserialized with different whitespace,
    with its digest recomputed into the record and the record re-signed,
    verified green while being bytes no emission of this module could have
    written. The record's own bytes have always been checked this way.
    """

    private_pem, _ = keys
    body_path = emitted.with_name(f"{emitted.stem}.body.json")
    parsed = json.loads(body_path.read_text())
    loose = json.dumps(parsed, indent=2).encode("utf-8") + b"\n"
    body_path.write_bytes(loose)
    _resign_in_place(
        emitted,
        spec,
        private_pem,
        lambda payload: payload["body"].__setitem__("sha256", sha256_bytes(loose)),
    )
    with pytest.raises(
        EvidenceRecordError, match="evidence-body bytes are not canonical"
    ):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_a_body_missing_its_trailing_newline_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    keys: tuple[bytes, bytes],
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    """One byte, and the same reasoning as the record's own refusal."""

    private_pem, _ = keys
    body_path = emitted.with_name(f"{emitted.stem}.body.json")
    stripped = body_path.read_bytes().rstrip(b"\n")
    body_path.write_bytes(stripped)
    _resign_in_place(
        emitted,
        spec,
        private_pem,
        lambda payload: payload["body"].__setitem__("sha256", sha256_bytes(stripped)),
    )
    with pytest.raises(
        EvidenceRecordError, match="evidence-body bytes are not canonical"
    ):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_duplicate_json_key_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    # Canonical JSON orders keys by UTF-16 code unit, so "body" is first.
    text = emitted.read_text()
    assert text.startswith('{"body"')
    emitted.write_bytes(text.replace('{"body"', '{"body":1,"body"', 1).encode())
    with pytest.raises(EvidenceRecordError, match="duplicate key"):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_tampered_signature_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    signature_path = emitted.with_name(f"{emitted.stem}.producer.sig")
    signature = bytearray(signature_path.read_bytes())
    signature[0] ^= 0xFF
    signature_path.write_bytes(bytes(signature))
    with pytest.raises(EvidenceRecordError):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_signature_from_another_key_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    other_private, _ = generate_signing_keypair()
    from receipt.sign import sign_payload

    signature_path = emitted.with_name(f"{emitted.stem}.producer.sig")
    signature_path.write_bytes(
        sign_payload(other_private, _framed(spec, emitted.read_bytes()), domain=b"")
    )
    with pytest.raises(EvidenceRecordError):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_signature_over_the_bare_record_bytes_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
    keys: tuple[bytes, bytes],
) -> None:
    """The mirror of the invariant: a manifest-style signature, made over the
    record's exact bytes with no frame, is not accepted."""

    from receipt.sign import sign_payload

    private_pem, _ = keys
    signature_path = emitted.with_name(f"{emitted.stem}.producer.sig")
    signature_path.write_bytes(
        sign_payload(private_pem, emitted.read_bytes(), domain=b"")
    )
    with pytest.raises(EvidenceRecordError):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_signature_under_the_old_nul_domain_convention_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
    keys: tuple[bytes, bytes],
) -> None:
    """What this module signed before the frame: a NUL-terminated domain string
    prefixed to the record bytes. Nothing was published under it, and it is
    refused like any other signature over bytes that are not the frame."""

    from receipt.sign import sign_payload

    private_pem, _ = keys
    signature_path = emitted.with_name(f"{emitted.stem}.producer.sig")
    signature_path.write_bytes(
        sign_payload(
            private_pem,
            emitted.read_bytes(),
            domain=b"receipt/evidence-record/v1\x00",
        )
    )
    with pytest.raises(EvidenceRecordError):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_signature_under_another_payload_type_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
    keys: tuple[bytes, bytes],
) -> None:
    """The payload type is the schema id, inside the signed bytes. A signature
    framed under any other type is a signature for some other record type, and
    the spec's own schema id is the only one this directory verifies under."""

    from receipt.evidence import _pae
    from receipt.sign import sign_payload

    private_pem, _ = keys
    signature_path = emitted.with_name(f"{emitted.stem}.producer.sig")
    signature_path.write_bytes(
        sign_payload(
            private_pem,
            _pae("receipt/evidence-record/v2", emitted.read_bytes()),
            domain=b"",
        )
    )
    with pytest.raises(EvidenceRecordError):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_unknown_file_in_the_record_directory_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    (tmp_path / RECORDS / "notes.txt").write_text("hello")
    with pytest.raises(EvidenceRecordError, match="unknown file in closed"):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_tsa_sidecar_is_not_yet_accepted(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    """v1 has no witness layer, so the directory refuses one rather than
    silently ignoring it."""

    (tmp_path / RECORDS / f"{emitted.stem}.freetsa.tsr").write_bytes(b"\x30\x00")
    with pytest.raises(EvidenceRecordError, match="unknown file in closed"):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_orphan_body_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    (tmp_path / RECORDS / "0009-abcdef0123456789.body.json").write_bytes(b"{}\n")
    with pytest.raises(EvidenceRecordError, match="orphan evidence bodies"):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_orphan_signature_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    (tmp_path / RECORDS / "0009-abcdef0123456789.producer.sig").write_bytes(b"\x00" * 64)
    with pytest.raises(EvidenceRecordError, match="orphan producer signatures"):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_missing_body_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    emitted.with_name(f"{emitted.stem}.body.json").unlink()
    with pytest.raises(EvidenceRecordError, match="has no body"):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_symlinked_record_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    target = tmp_path / "elsewhere.json"
    target.write_bytes(emitted.read_bytes())
    emitted.unlink()
    emitted.symlink_to(target)
    with pytest.raises(EvidenceRecordError, match="non-regular entry"):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_spki_pin_mismatch_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    _, other_public = generate_signing_keypair()
    (anchor_dir / "producer.pem").write_bytes(other_public)
    with pytest.raises(EvidenceRecordError):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_a_symlinked_path_component_cannot_serve_records_from_outside_the_tree(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    anchor_dir: pathlib.Path,
    keys: tuple[bytes, bytes],
) -> None:
    """Only the final component was ever checked for a link.

    With ``evidence/`` pointed at an ambient directory the records verified —
    and the records written — are no part of the tree the spec names, while
    every path in the refusal still reads as if they were.
    """

    private_pem, _ = keys
    outside = tmp_path / "outside"
    (outside / "records").mkdir(parents=True)
    (tmp_path / "evidence").symlink_to(outside)

    with pytest.raises(EvidenceRecordError) as refusal:
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'evidence': evidence/records"
    )

    with pytest.raises(EvidenceRecordError, match="traverses a symlink"):
        emit_evidence_record(
            tmp_path,
            spec=spec,
            private_key_pem=private_pem,
            body=BODY,
            body_schema=BODY_SCHEMA,
            refs=[],
            producer=PRODUCER,
            emitted_at_utc=EMITTED,
        )
    assert list((outside / "records").iterdir()) == []


def test_records_that_resolve_inside_the_release_root_are_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    anchor_dir: pathlib.Path,
    keys: tuple[bytes, bytes],
) -> None:
    """The construction-time rule is lexical, and the link can be on the other
    side: ``releases/`` pointed at the evidence directory puts the records
    inside the closed release directory while two PurePosixPaths still compare
    as siblings. Only where the root is joined can the two be compared as the
    filesystem answers them."""

    private_pem, _ = keys
    (tmp_path / "evidence" / "records").mkdir(parents=True)
    (tmp_path / "releases").symlink_to(tmp_path / "evidence")

    with pytest.raises(EvidenceRecordError, match="outside the release directory"):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)
    with pytest.raises(EvidenceRecordError, match="outside the release directory"):
        emit_evidence_record(
            tmp_path,
            spec=spec,
            private_key_pem=private_pem,
            body=BODY,
            body_schema=BODY_SCHEMA,
            refs=[],
            producer=PRODUCER,
            emitted_at_utc=EMITTED,
        )
    assert list((tmp_path / "evidence" / "records").iterdir()) == []


# --------------------------------------------------------------------------
# Emission: the pin the signer is checked against, one emitter at a time.
# --------------------------------------------------------------------------


def test_emission_with_an_unpinned_key_refuses_before_it_touches_disk(
    tmp_path: pathlib.Path, spec: EvidenceSpec
) -> None:
    """Emission signed with whatever private key it was handed.

    The pin is the consumer's committed statement of who may write these
    records, and it was read only by the verifier — so a swapped key produced
    a directory that verified as broken custody long after the bytes landed.
    """

    other_private, _ = generate_signing_keypair()
    with pytest.raises(EvidenceRecordError, match="not code-pinned"):
        emit_evidence_record(
            tmp_path,
            spec=spec,
            private_key_pem=other_private,
            body=BODY,
            body_schema=BODY_SCHEMA,
            refs=[],
            producer=PRODUCER,
            emitted_at_utc=EMITTED,
        )
    assert not (tmp_path / spec.records_relative).exists()
    assert list(tmp_path.iterdir()) == []


def test_a_competing_emitter_at_the_same_index_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    anchor_dir: pathlib.Path,
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Index was last-enumerated plus one, then three plain writes.

    Two emitters that enumerate the same state both compute the same index.
    An exclusive create of the record alone does not close that: the filename
    carries the record's own digest, so two different payloads at one index
    are two different filenames, both creates succeed, and the directory is
    refused for a duplicate index with both emitters believing they wrote it.
    The competitor is injected between enumeration and creation, which is
    exactly where the window was.
    """

    private_pem, _ = keys
    raced: list[str] = []

    def enumerate_and_race(
        root: pathlib.Path, spec_: EvidenceSpec
    ) -> list[tuple[pathlib.Path, pathlib.Path, pathlib.Path]]:
        result = _enumerate_record_files(root, spec_)
        if not raced:
            raced.append("attempted")
            with pytest.raises(EvidenceRecordError, match="another emitter"):
                emit_evidence_record(
                    root,
                    spec=spec_,
                    private_key_pem=private_pem,
                    body={
                        "event": "generation",
                        "generation": 8,
                        "populationRootSha256": "b" * 64,
                    },
                    body_schema=BODY_SCHEMA,
                    refs=[],
                    producer=PRODUCER,
                    emitted_at_utc=EMITTED,
                )
        return result

    monkeypatch.setattr(
        "receipt.evidence._enumerate_record_files", enumerate_and_race
    )
    emitted = emit_evidence_record(
        tmp_path,
        spec=spec,
        private_key_pem=private_pem,
        body=BODY,
        body_schema=BODY_SCHEMA,
        refs=[],
        producer=PRODUCER,
        emitted_at_utc=EMITTED,
    )
    monkeypatch.undo()

    assert raced == ["attempted"]
    assert emitted.name.startswith("0000-")
    verification = verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)
    assert [record.record_index for record in verification.records] == [0]


def test_a_directory_that_cannot_be_locked_is_refused_in_its_own_words(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only EAGAIN means a second emitter.

    A filesystem that does not implement advisory locks, or a descriptor the
    kernel refuses, is a refusal too — but saying "another emitter holds it"
    about one would put a fact in the message that nobody established. Both
    fail closed; only the words differ.
    """

    private_pem, _ = keys

    def unsupported(descriptor: int, operation: int) -> None:
        raise OSError(errno.ENOTSUP, "Operation not supported")

    monkeypatch.setattr(fcntl, "flock", unsupported)
    with pytest.raises(EvidenceRecordError) as refusal:
        emit_evidence_record(
            tmp_path,
            spec=spec,
            private_key_pem=private_pem,
            body=BODY,
            body_schema=BODY_SCHEMA,
            refs=[],
            producer=PRODUCER,
            emitted_at_utc=EMITTED,
        )
    assert "cannot hold the evidence-record directory" in str(refusal.value)
    assert "another emitter" not in str(refusal.value)
    assert list((tmp_path / spec.records_relative).iterdir()) == []


def test_a_repeat_emission_of_the_same_record_does_not_overwrite_it(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    anchor_dir: pathlib.Path,
    keys: tuple[bytes, bytes],
) -> None:
    """Byte-identical is the case a digest-named file hides.

    Same index and same payload means the same three filenames, and three
    plain writes land on top of the record already there without a word. An
    enumeration that returns nothing — a wedged reader, a directory read
    before a sibling's writes are visible — is all it takes to recompute an
    index that is already taken.
    """

    private_pem, _ = keys
    arguments = dict(
        spec=spec,
        private_key_pem=private_pem,
        body=BODY,
        body_schema=BODY_SCHEMA,
        refs=[],
        producer=PRODUCER,
        emitted_at_utc=EMITTED,
    )
    first = emit_evidence_record(tmp_path, **arguments)  # type: ignore[arg-type]
    before = first.read_bytes()

    with pytest.MonkeyPatch.context() as patched:
        patched.setattr(
            "receipt.evidence._enumerate_record_files",
            lambda root, spec_: [],
        )
        with pytest.raises(EvidenceRecordError, match="already"):
            emit_evidence_record(tmp_path, **arguments)  # type: ignore[arg-type]

    assert first.read_bytes() == before
    verification = verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)
    assert [record.record_index for record in verification.records] == [0]


def test_emission_refuses_to_extend_a_directory_with_a_broken_signature(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    keys: tuple[bytes, bytes],
    emitted: pathlib.Path,
) -> None:
    """Emission read the last record's index and digest and nothing else.

    That record's signature was never checked, so the producer signed a
    `previousRecordSha256` taken out of a record it had not verified — and
    the directory then carried a fresh, valid signature over a link to a
    record nobody could vouch for.
    """

    private_pem, _ = keys
    signature_path = emitted.with_name(f"{emitted.stem}.producer.sig")
    signature_path.write_bytes(b"\x00" * len(signature_path.read_bytes()))
    with pytest.raises(EvidenceRecordError) as refusal:
        emit_evidence_record(
            tmp_path,
            spec=spec,
            private_key_pem=private_pem,
            body={"event": "generation", "generation": 8},
            body_schema=BODY_SCHEMA,
            refs=[],
            producer=PRODUCER,
            emitted_at_utc="2026-08-27T15:05:00Z",
        )
    assert "signature verification failed" in str(refusal.value)
    assert emitted.name in str(refusal.value)
    assert not list((tmp_path / RECORDS).glob("0001-*"))


def test_emission_refuses_to_extend_a_directory_with_a_tampered_body(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    keys: tuple[bytes, bytes],
    emitted: pathlib.Path,
) -> None:
    """The bodies beside the existing records were never opened either."""

    private_pem, _ = keys
    body_path = emitted.with_name(f"{emitted.stem}.body.json")
    body_path.write_bytes(canonical_document_bytes({"event": "tampered"}))
    with pytest.raises(EvidenceRecordError, match="body digest mismatch"):
        emit_evidence_record(
            tmp_path,
            spec=spec,
            private_key_pem=private_pem,
            body={"event": "generation", "generation": 8},
            body_schema=BODY_SCHEMA,
            refs=[],
            producer=PRODUCER,
            emitted_at_utc="2026-08-27T15:05:00Z",
        )
    assert not list((tmp_path / RECORDS).glob("0001-*"))


def test_a_directory_that_verifies_still_takes_the_next_record(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    keys: tuple[bytes, bytes],
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
) -> None:
    """The green path, held.

    This one passes before the change as well as after, and is here for that
    reason: verifying before appending is only worth having if a genuine
    directory still extends, and a producer that cannot write is a worse
    failure than the one being closed.
    """

    private_pem, _ = keys
    second = emit_evidence_record(
        tmp_path,
        spec=spec,
        private_key_pem=private_pem,
        body={"event": "generation", "generation": 8},
        body_schema=BODY_SCHEMA,
        refs=[],
        producer=PRODUCER,
        emitted_at_utc="2026-08-27T15:05:00Z",
    )
    third = emit_evidence_record(
        tmp_path,
        spec=spec,
        private_key_pem=private_pem,
        body={"event": "generation", "generation": 9},
        body_schema=BODY_SCHEMA,
        refs=[],
        producer=PRODUCER,
        emitted_at_utc="2026-08-27T16:05:00Z",
    )
    assert second.name.startswith("0001-")
    assert third.name.startswith("0002-")
    result = verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)
    assert [record.record_index for record in result.records] == [0, 1, 2]


# --------------------------------------------------------------------------
# Strict canonical input: what canonical.py would round, fold, or raise on.
# --------------------------------------------------------------------------

#: One case per class the guard refuses, as a Python value a caller can hand
#: to emission, with the fragment of the refusal that names the class.
STRICT_VALUES = [
    pytest.param(2**53, "is an integer outside", id="int-2^53"),
    pytest.param(-(2**53), "is an integer outside", id="int-minus-2^53"),
    pytest.param(float("inf"), "is not a finite number", id="inf"),
    pytest.param(float("nan"), "is not a finite number", id="nan"),
    pytest.param(-0.0, "is negative zero", id="negative-zero"),
    pytest.param("\ud800", "lone surrogate", id="lone-surrogate"),
]
#: The same classes as JSON text a person could write into a file. There is no
#: literal for NaN that the loader does not already refuse.
STRICT_LITERALS = [
    pytest.param(b"9007199254740992", "is an integer outside", id="int-2^53"),
    pytest.param(b"-9007199254740992", "is an integer outside", id="int-minus-2^53"),
    pytest.param(b"1e999", "is not a finite number", id="1e999"),
    pytest.param(b"-0.0", "is negative zero", id="negative-zero"),
    pytest.param(b'"\\ud800"', "lone surrogate", id="lone-surrogate"),
]


def _names(directory: pathlib.Path) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir())


@pytest.mark.parametrize("value, reason", STRICT_VALUES)
def test_emission_refuses_a_body_value_canonical_json_would_alter(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    keys: tuple[bytes, bytes],
    emitted: pathlib.Path,
    value: object,
    reason: str,
) -> None:
    """The body is serialized through canonical.py, a hash-pinned port that
    rounds an integer beyond 2**53 - 1 through ``float()``, folds ``-0.0`` to
    ``0``, re-escapes a lone surrogate, and raises a bare ``ValueError`` on a
    non-finite float. Each is refused before anything is written, in this
    module's own words, naming the path to the value."""

    private_pem, _ = keys
    directory = tmp_path / RECORDS
    before = _names(directory)
    with pytest.raises(EvidenceRecordError) as exc:
        emit_evidence_record(
            tmp_path,
            spec=spec,
            private_key_pem=private_pem,
            body={"count": value},
            body_schema=BODY_SCHEMA,
            refs=[],
            producer=PRODUCER,
            emitted_at_utc=EMITTED,
        )
    message = str(exc.value)
    assert message.startswith("evidence body: count ")
    assert reason in message
    assert _names(directory) == before


@pytest.mark.parametrize("value, reason", STRICT_VALUES)
def test_emission_refuses_a_record_value_canonical_json_would_alter(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    keys: tuple[bytes, bytes],
    emitted: pathlib.Path,
    value: object,
    reason: str,
) -> None:
    """The same guard on the payload, which carries the caller's ``producer``
    and ``body_schema`` verbatim. It stands ahead of the schema check, so the
    refusal names the value for what it is rather than for the type the schema
    wanted there."""

    private_pem, _ = keys
    directory = tmp_path / RECORDS
    before = _names(directory)
    with pytest.raises(EvidenceRecordError) as exc:
        emit_evidence_record(
            tmp_path,
            spec=spec,
            private_key_pem=private_pem,
            body=BODY,
            body_schema=BODY_SCHEMA,
            refs=[],
            producer={"repo": value, "branch": "main"},
            emitted_at_utc=EMITTED,
        )
    message = str(exc.value)
    assert message.startswith("evidence record: producer.repo ")
    assert reason in message
    assert _names(directory) == before


def test_emission_refuses_an_object_key_that_is_not_a_string(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    keys: tuple[bytes, bytes],
    emitted: pathlib.Path,
) -> None:
    """canonical.py sorts object keys as UTF-16 before it checks their type, so
    an integer key left this module as ``AttributeError`` from the sort key."""

    private_pem, _ = keys
    directory = tmp_path / RECORDS
    before = _names(directory)
    arguments = dict(
        spec=spec,
        private_key_pem=private_pem,
        body_schema=BODY_SCHEMA,
        refs=[],
        emitted_at_utc=EMITTED,
    )
    bad_body = {"count": 1, 2: "two"}
    bad_producer = {"repo": "example/consumer", "branch": "main", 3: "x"}
    with pytest.raises(EvidenceRecordError) as body_exc:
        emit_evidence_record(
            tmp_path, body=bad_body, producer=PRODUCER, **arguments  # type: ignore[arg-type]
        )
    assert str(body_exc.value).startswith(
        "evidence body: the top-level value has an object key that is not a string"
    )
    with pytest.raises(EvidenceRecordError) as record_exc:
        emit_evidence_record(
            tmp_path, body=BODY, producer=bad_producer, **arguments  # type: ignore[arg-type]
        )
    assert str(record_exc.value).startswith(
        "evidence record: producer has an object key that is not a string"
    )
    assert _names(directory) == before


@pytest.mark.parametrize("literal, reason", STRICT_LITERALS)
def test_a_hand_written_record_value_canonical_json_would_alter_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    keys: tuple[bytes, bytes],
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
    literal: bytes,
    reason: str,
) -> None:
    """The verifier's side of the same guard, on the parsed record, ahead of
    the schema check and the canonical-equality check. A lone surrogate in
    ``producer.repo`` passed both and verified green before this change: the
    schema saw a non-empty string, and canonical.py re-escaped it to the same
    bytes it was read from. The refusal is the strict-input one, by name."""

    private_pem, _ = keys
    _refile_with_literal(
        emitted,
        spec,
        private_pem,
        lambda payload: payload["producer"].__setitem__("repo", SENTINEL),
        literal,
    )
    with pytest.raises(EvidenceRecordError) as exc:
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)
    message = str(exc.value)
    assert message.startswith("evidence record: producer.repo ")
    assert reason in message
    assert "canonical JSON plus one newline" not in message
    assert "digest mismatch" not in message


@pytest.mark.parametrize("literal, reason", STRICT_LITERALS)
def test_a_hand_written_body_value_canonical_json_would_alter_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    keys: tuple[bytes, bytes],
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
    literal: bytes,
    reason: str,
) -> None:
    """The guard on the parsed body, ahead of its canonical-equality check.

    Before this change ``9007199254740992`` and ``"\\ud800"`` verified green
    — canonical.py renders each back to the bytes it was read from — ``-0.0``
    was refused as a canonical mismatch, and ``1e999`` left the module as the
    serializer's own bare ``ValueError``. Each is now the strict-input refusal,
    naming the path.
    """

    private_pem, _ = keys
    body_raw = _body_with_literal(literal)
    emitted.with_name(f"{emitted.stem}.body.json").write_bytes(body_raw)
    _resign_in_place(
        emitted,
        spec,
        private_pem,
        lambda payload: payload["body"].__setitem__("sha256", sha256_bytes(body_raw)),
    )
    with pytest.raises(EvidenceRecordError) as exc:
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)
    message = str(exc.value)
    assert message.startswith("evidence body: count ")
    assert reason in message
    assert "canonical JSON plus one newline" not in message
    assert "digest mismatch" not in message


@pytest.mark.parametrize(
    "value",
    [2**53 - 1, -(2**53 - 1), 0, 0.5, True],
    ids=["int-2^53-1", "int-minus-2^53-1", "zero", "half", "true"],
)
def test_values_at_the_edge_of_strict_input_are_accepted(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    keys: tuple[bytes, bytes],
    anchor_dir: pathlib.Path,
    value: object,
) -> None:
    """The guard refuses exactly what canonical.py alters and nothing beside it.
    These pass before this change as well as after, and are here for that
    reason: a guard that refused a representable value would be a worse
    failure than the one being closed."""

    private_pem, _ = keys
    emit_evidence_record(
        tmp_path,
        spec=spec,
        private_key_pem=private_pem,
        body={"count": value},
        body_schema=BODY_SCHEMA,
        refs=[],
        producer=PRODUCER,
        emitted_at_utc=EMITTED,
    )
    result = verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)
    assert result.records[0].body_raw == canonical_document_bytes({"count": value})


# --------------------------------------------------------------------------
# Spec construction.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "d" * 63,
        "d" * 65,
        "D" * 64,
        "g" * 64,
        b"d" * 64,
        64,
    ],
)
def test_a_producer_pin_that_cannot_pin_refuses_at_construction(
    value: object,
) -> None:
    """The hole ChainSpec had, in this module's own spec: a pin of ``None``
    reaches verify_signature_bytes, which reads it as no pin requested, skips
    the SPKI comparison, and accepts a substituted producer key."""

    with pytest.raises(EvidenceRecordError, match="producer_spki_sha256"):
        EvidenceSpec(
            records_relative=RECORDS,
            producer_spki_sha256=value,  # type: ignore[arg-type]
        )


def test_a_spec_with_no_producer_pin_cannot_be_constructed() -> None:
    """The unpinned spec is not expressible: the field carries no default, so
    the consumer states the pin or writes no spec at all."""

    with pytest.raises(TypeError, match="producer_spki_sha256"):
        EvidenceSpec(records_relative=RECORDS)  # type: ignore[call-arg]


def test_records_inside_the_release_root_are_refused_at_construction() -> None:
    with pytest.raises(EvidenceRecordError, match="outside the release directory"):
        EvidenceSpec(
            records_relative=pathlib.PurePosixPath("releases/manifests/evidence"),
            producer_spki_sha256=PIN,
            release_root_relative=pathlib.PurePosixPath("releases"),
        )


def test_records_equal_to_the_release_root_are_refused() -> None:
    with pytest.raises(EvidenceRecordError, match="outside the release directory"):
        EvidenceSpec(
            records_relative=pathlib.PurePosixPath("releases"),
            producer_spki_sha256=PIN,
            release_root_relative=pathlib.PurePosixPath("releases"),
        )


@pytest.mark.parametrize("bad", ["/evidence", "../evidence", ""])
def test_unsafe_records_path_is_refused(bad: str) -> None:
    with pytest.raises(EvidenceRecordError, match="records_relative"):
        EvidenceSpec(
            records_relative=pathlib.PurePosixPath(bad), producer_spki_sha256=PIN
        )


@pytest.mark.parametrize(
    "value",
    ["", None, b"receipt/evidence-record/v1"],
    ids=["empty", "none", "bytes"],
)
def test_a_schema_version_that_names_no_type_is_refused(value: object) -> None:
    """The schema id is the frame's payload type and the record's own
    ``schemaVersion``, so a spec with none frames every record under no type
    at all. An empty string emitted and verified green before this change;
    ``None`` left emission as an ``AttributeError`` from the frame, and bytes
    as canonical.py's ``TypeError`` from the payload."""

    with pytest.raises(EvidenceRecordError, match="schema_version"):
        EvidenceSpec(
            records_relative=RECORDS,
            producer_spki_sha256=PIN,
            schema_version=value,  # type: ignore[arg-type]
        )


def test_spec_is_frozen(spec: EvidenceSpec) -> None:
    with pytest.raises(FrozenInstanceError):
        spec.schema_version = "other"  # type: ignore[misc]


def test_sibling_directory_is_permitted() -> None:
    EvidenceSpec(
        records_relative=pathlib.PurePosixPath("evidence/records"),
        producer_spki_sha256=PIN,
        release_root_relative=pathlib.PurePosixPath("releases"),
    )


def _valid_payload() -> dict:
    return {
        "schemaVersion": "receipt/evidence-record/v1",
        "standing": STANDING,
        "recordIndex": 0,
        "previousRecordSha256": None,
        "emittedAtUtc": EMITTED,
        "producer": dict(PRODUCER),
        "body": {"schema": BODY_SCHEMA, "sha256": "a" * 64},
        "refs": [],
    }
