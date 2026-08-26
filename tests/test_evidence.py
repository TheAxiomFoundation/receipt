"""Refusal battery for non-authorizing evidence records.

`receipt.evidence` is new composition rather than an extraction, so it has no
upstream oracle and no port-diff gate. Its gate is this file: a round trip, the
chain rules, one test per way a record can fail to be what it claims, and the
non-authorization invariant that gives the record type its name.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import FrozenInstanceError

import pytest

from receipt.canonical import canonical_bytes
from receipt.evidence import (
    DOMAIN,
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
from receipt.release_chain import (
    AnchorSpec,
    ChainSpec,
    ReleaseChainError,
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
    signature fails the no-domain check the authorizing verifier uses. Either
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
        anchors={},
    )

    # (a) The schema refusal is structural: closed-world keys, so it lands
    # before any value is inspected.
    with pytest.raises(ReleaseChainError) as schema_exc:
        validate_manifest_schema(payload, chain_spec)
    assert "closed-world" in str(schema_exc.value)

    # (b) The authorizing verifier checks exact bytes with no domain at all.
    with pytest.raises(SignError):
        verify_signature_bytes(
            raw,
            signature,
            public_pem,
            public_key_filename="producer.pem",
            spki_sha256=None,
            label="as-if-a-manifest",
        )

    # ...and the same signature is valid under this module's domain, so (b) is
    # a domain separation result and not a broken signature.
    verify_signature_bytes(
        DOMAIN + raw,
        signature,
        public_pem,
        public_key_filename="producer.pem",
        spki_sha256=None,
        label="evidence record",
    )
    assert verify_evidence_records(
        tmp_path, spec=spec, anchor_dir=anchor_dir
    ).records[0].sha256 == sha256_bytes(raw)


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


def test_empty_directory_verifies_empty(
    tmp_path: pathlib.Path, spec: EvidenceSpec, anchor_dir: pathlib.Path
) -> None:
    result = verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)
    assert result.records == ()
    assert result.head is None


def _resign_in_place(
    path: pathlib.Path, spec: EvidenceSpec, private_key_pem: bytes, mutate
) -> pathlib.Path:
    """Mutate a record on disk and re-file it under its new digest.

    Everything downstream of the mutation is made self-consistent — canonical
    bytes, filename, signature — so verification has to reach the check the
    test is actually aiming at rather than tripping on the filename first.
    """

    from receipt.sign import sign_payload

    payload = json.loads(path.read_text())
    mutate(payload)
    raw = canonical_document_bytes(payload)
    body_raw = path.with_name(f"{path.stem}.body.json").read_bytes()

    for stale in path.parent.glob(f"{path.stem}.*"):
        stale.unlink()
    path.unlink(missing_ok=True)

    new_path = path.with_name(record_filename(int(payload["recordIndex"]), raw))
    new_path.write_bytes(raw)
    new_path.with_name(f"{new_path.stem}.body.json").write_bytes(body_raw)
    new_path.with_name(f"{new_path.stem}.producer.sig").write_bytes(
        sign_payload(private_key_pem, raw, domain=spec.domain)
    )
    return new_path


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
        sign_payload(other_private, emitted.read_bytes(), domain=DOMAIN)
    )
    with pytest.raises(EvidenceRecordError):
        verify_evidence_records(tmp_path, spec=spec, anchor_dir=anchor_dir)


def test_signature_made_without_the_domain_is_refused(
    tmp_path: pathlib.Path,
    spec: EvidenceSpec,
    emitted: pathlib.Path,
    anchor_dir: pathlib.Path,
    keys: tuple[bytes, bytes],
) -> None:
    """The mirror of the invariant: a manifest-style signature is not accepted."""

    from receipt.sign import sign_payload

    private_pem, _ = keys
    signature_path = emitted.with_name(f"{emitted.stem}.producer.sig")
    signature_path.write_bytes(
        sign_payload(private_pem, emitted.read_bytes(), domain=b"")
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


# --------------------------------------------------------------------------
# Spec construction.
# --------------------------------------------------------------------------


def test_records_inside_the_release_root_are_refused_at_construction() -> None:
    with pytest.raises(EvidenceRecordError, match="outside the release directory"):
        EvidenceSpec(
            records_relative=pathlib.PurePosixPath("releases/manifests/evidence"),
            release_root_relative=pathlib.PurePosixPath("releases"),
        )


def test_records_equal_to_the_release_root_are_refused() -> None:
    with pytest.raises(EvidenceRecordError, match="outside the release directory"):
        EvidenceSpec(
            records_relative=pathlib.PurePosixPath("releases"),
            release_root_relative=pathlib.PurePosixPath("releases"),
        )


@pytest.mark.parametrize("bad", ["/evidence", "../evidence", ""])
def test_unsafe_records_path_is_refused(bad: str) -> None:
    with pytest.raises(EvidenceRecordError, match="records_relative"):
        EvidenceSpec(records_relative=pathlib.PurePosixPath(bad))


def test_empty_domain_is_refused() -> None:
    with pytest.raises(EvidenceRecordError, match="domain"):
        EvidenceSpec(records_relative=RECORDS, domain=b"")


def test_spec_is_frozen(spec: EvidenceSpec) -> None:
    with pytest.raises(FrozenInstanceError):
        spec.domain = b"other"  # type: ignore[misc]


def test_sibling_directory_is_permitted() -> None:
    EvidenceSpec(
        records_relative=pathlib.PurePosixPath("evidence/records"),
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
