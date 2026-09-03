"""Spec invariants for the TSA machinery, and a witness battery with real tokens.

The second half stands up what a witnessed record actually has — a root
certificate authority, a signing certificate carrying the timestamping extended
key usage, a canonical trust bundle, a genuine RFC 3161 response over the
record's own digest, and the sidecar that claims it — and drives
``verify_witness`` over it. Without that, the offline suite would exercise the
dataclasses and leave every cryptographic refusal to the networked differential
harness, so a clone with no network could not tell whether the witness lane
still refuses anything at all.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from receipt import tsa as tsa_module
from receipt.canonical import canonical_bytes, canonical_sha256
from receipt.tsa import (
    _certificate_count,
    _decode_oid,
    _load_trust_bundle,
    _read_der_tlv,
    _BUNDLE_CLAIM_FIELDS,
    TokenEvidence,
    TrustBundleSpec,
    TsaError,
    TsaIdentitySpec,
    TsaSpec,
    WitnessEvidence,
    activate_trust_bundles,
    logical_path,
    preferred_active_trust_bundle,
    trust_bundle_updates_for_snapshot,
    validate_token_time,
    verify_timestamp_token,
    verify_witness,
)

from corpus_fixture import (
    LocalTsa,
    build_local_tsa,
    certificate_pins,
    rotate_tsa_signer,
    sha256_bytes,
)

UTC = timezone.utc
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


def bundle(*, bundle_id: str = "tsa-anchors-v1", version: int = 1) -> TrustBundleSpec:
    return TrustBundleSpec(
        bundle_id=bundle_id,
        path=f"records/trust/tsa-anchors-v{version}.json",
        sha256=HASH_A,
        size=123,
        canonical_json_sha256=HASH_B,
    )


def identity(
    *, bundle_id: str = "tsa-anchors-v1", anchor_id: str = "anchor-one"
) -> TsaIdentitySpec:
    return TsaIdentitySpec(
        bundle_id=bundle_id,
        anchor_id=anchor_id,
        root_spki_sha256=HASH_B,
        signer_spki_sha256=frozenset({HASH_C}),
        max_future_seconds=0,
        max_token_lead_seconds=300,
    )


def spec() -> TsaSpec:
    return TsaSpec(
        trust_bundles=(bundle(),),
        tsa_identities=(identity(),),
        legacy_witness_bundle_id="tsa-anchors-v1",
    )


def test_spec_is_deeply_frozen_and_has_no_trust_defaults() -> None:
    configured = spec()
    with pytest.raises(dataclasses.FrozenInstanceError):
        configured.legacy_witness_bundle_id = "other"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        configured.trust_bundles[0].sha256 = HASH_C  # type: ignore[misc]
    assert all(
        parameter.default is inspect.Parameter.empty
        for parameter in inspect.signature(TsaSpec).parameters.values()
    )


def test_bundle_reference_retains_oracle_shape_and_key_order() -> None:
    assert bundle().reference() == {
        "bundleId": "tsa-anchors-v1",
        "path": "records/trust/tsa-anchors-v1.json",
        "sha256": HASH_A,
        "size": 123,
        "canonicalJsonSha256": HASH_B,
    }
    assert list(bundle().reference()) == [
        "bundleId",
        "path",
        "sha256",
        "size",
        "canonicalJsonSha256",
    ]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"path": "records/trust/current.json"},
            "trust bundle path is not immutable/versioned: "
            "'records/trust/current.json'",
        ),
        (
            {"sha256": "A" * 64},
            "trust bundle records/trust/tsa-anchors-v1.json sha256 must be "
            "exactly 64 lowercase hexadecimal characters",
        ),
        (
            {"size": True},
            "trust bundle records/trust/tsa-anchors-v1.json size must be a "
            "non-negative integer",
        ),
    ],
)
def test_trust_bundle_spec_validation(
    kwargs: dict[str, object], message: str
) -> None:
    values: dict[str, object] = {
        "bundle_id": "tsa-anchors-v1",
        "path": "records/trust/tsa-anchors-v1.json",
        "sha256": HASH_A,
        "size": 123,
        "canonical_json_sha256": HASH_B,
    }
    values.update(kwargs)
    with pytest.raises(TsaError) as caught:
        TrustBundleSpec(**values)  # type: ignore[arg-type]
    assert str(caught.value) == message


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"signer_spki_sha256": frozenset()},
            "TSA identity tsa-anchors-v1/anchor-one must contain at least one "
            "signer SPKI",
        ),
        (
            {"max_future_seconds": -1},
            "TSA identity tsa-anchors-v1/anchor-one max_future_seconds must be "
            "a non-negative integer",
        ),
        (
            {"max_token_lead_seconds": False},
            "TSA identity tsa-anchors-v1/anchor-one max_token_lead_seconds must "
            "be a non-negative integer",
        ),
    ],
)
def test_tsa_identity_spec_validation(
    kwargs: dict[str, object], message: str
) -> None:
    values: dict[str, object] = {
        "bundle_id": "tsa-anchors-v1",
        "anchor_id": "anchor-one",
        "root_spki_sha256": HASH_B,
        "signer_spki_sha256": frozenset({HASH_C}),
        "max_future_seconds": 0,
        "max_token_lead_seconds": 300,
    }
    values.update(kwargs)
    with pytest.raises(TsaError) as caught:
        TsaIdentitySpec(**values)  # type: ignore[arg-type]
    assert str(caught.value) == message


def test_tsa_spec_rejects_duplicate_paths_ids_and_missing_identities() -> None:
    with pytest.raises(TsaError, match="^duplicate trust bundle path in TSA spec"):
        TsaSpec(
            trust_bundles=(bundle(), bundle(bundle_id="other")),
            tsa_identities=(identity(),),
            legacy_witness_bundle_id="tsa-anchors-v1",
        )
    with pytest.raises(TsaError, match="^duplicate trust bundle ID in TSA spec"):
        TsaSpec(
            trust_bundles=(bundle(), bundle(version=2)),
            tsa_identities=(identity(),),
            legacy_witness_bundle_id="tsa-anchors-v1",
        )
    with pytest.raises(
        TsaError,
        match="^TSA spec trust bundle has no independently pinned identities",
    ):
        TsaSpec(
            trust_bundles=(bundle(), bundle(bundle_id="v2", version=2)),
            tsa_identities=(identity(),),
            legacy_witness_bundle_id="tsa-anchors-v1",
        )


def test_validate_token_time_retains_oracle_refusals() -> None:
    now = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
    with pytest.raises(TsaError) as future:
        validate_token_time(
            {"recordedAt": "2026-07-22T12:00:00Z"},
            datetime(2026, 7, 22, 12, 0, 1, tzinfo=UTC),
            now=now,
            max_future_seconds=0,
            max_token_lead_seconds=300,
        )
    assert str(future.value) == (
        "RFC 3161 genTime 2026-07-22T12:00:01Z postdates verification "
        "time 2026-07-22T12:00:00Z"
    )

    with pytest.raises(TsaError) as lead:
        validate_token_time(
            {"recordedAt": "2026-07-22T12:10:01Z"},
            datetime(2026, 7, 22, 12, 5, tzinfo=UTC),
            now=datetime(2026, 7, 22, 13, 0, tzinfo=UTC),
            max_future_seconds=0,
            max_token_lead_seconds=300,
        )
    assert str(lead.value) == (
        "RFC 3161 genTime 2026-07-22T12:05:00Z impossibly precedes "
        "recordedAt=2026-07-22T12:10:01Z"
    )


def test_bundle_lifecycle_helpers_keep_version_and_pending_semantics() -> None:
    v1 = bundle().reference()
    v2_spec = bundle(bundle_id="tsa-anchors-v2", version=2)
    configured = TsaSpec(
        trust_bundles=(bundle(), v2_spec),
        tsa_identities=(
            identity(),
            identity(bundle_id="tsa-anchors-v2", anchor_id="anchor-two"),
        ),
        legacy_witness_bundle_id="tsa-anchors-v1",
    )
    active = {str(v1["path"]): v1}
    assert trust_bundle_updates_for_snapshot(active, (), spec=configured) == [
        v2_spec.reference()
    ]
    activate_trust_bundles(active, [v2_spec.reference()])
    assert preferred_active_trust_bundle(active) == v2_spec.reference()
    assert trust_bundle_updates_for_snapshot(active, (), spec=configured) == []


def test_tsa_has_no_release_chain_dependency() -> None:
    source = pathlib.Path(__file__).parents[1] / "src" / "receipt" / "tsa.py"
    assert "receipt.release_chain" not in source.read_text()


#: ``TokenEvidence``'s fields, in order, as 0.5.1 shipped them.
RELEASED_TOKEN_EVIDENCE_FIELDS = (
    "anchor_id",
    "trust_bundle_id",
    "trust_bundle_path",
    "token_path",
    "token_sha256",
    "policy_oid",
    "imprint_algorithm_oid",
    "gen_time",
    "tsa_subject",
    "tsa_certificate_sha256",
    "tsa_spki_sha256",
)


def test_token_evidence_is_the_released_dataclass_unchanged() -> None:
    """S5-F5: a bug-fix release does not move a public dataclass.

    A revision of this branch added the signed timestamp's digest as a
    required field of ``TokenEvidence`` -- public, frozen, and shipped in
    0.5.1. Required, so a keyword construction that omitted it raised;
    positional, so every argument after ``token_sha256`` shifted by one; and
    a field, so anything walking ``dataclasses.fields`` gained a key. That is
    a compatibility break with nothing announcing it, in a release whose
    whole claim is that it fixes bugs.

    The digest is a counting aid that lets ``_v2_witness_evidence`` tell two
    outcomes resting on one timestamp from two outcomes resting on two, and
    it now travels beside the evidence in a private ``_TimestampIdentity``
    rather than inside it. Nothing public moved: this pins the field names
    and their order against 0.5.1's, builds the dataclass by keyword without
    the field that was added, and checks the entry point still returns a
    ``TokenEvidence`` -- with 0.5.1's parameters, plus the keyword-only
    ``record`` this branch added with a default, which is additive.
    """

    names = tuple(field.name for field in dataclasses.fields(TokenEvidence))
    assert names == RELEASED_TOKEN_EVIDENCE_FIELDS
    # The construction the added field would have broken.
    evidence = TokenEvidence(**{name: name for name in names})
    assert dataclasses.asdict(evidence) == {name: name for name in names}
    # And it is not there under some other spelling.
    assert not [name for name in names if "timestamp" in name]

    signature = inspect.signature(verify_timestamp_token)
    assert signature.return_annotation == "TokenEvidence"
    assert [
        (name, parameter.kind.name, parameter.default is inspect.Parameter.empty)
        for name, parameter in signature.parameters.items()
    ] == [
        ("path", "POSITIONAL_OR_KEYWORD", True),
        ("token_claim", "POSITIONAL_OR_KEYWORD", True),
        ("bundle_reference", "POSITIONAL_OR_KEYWORD", True),
        ("spec", "KEYWORD_ONLY", True),
        ("records", "KEYWORD_ONLY", True),
        ("now", "KEYWORD_ONLY", False),
        ("record", "KEYWORD_ONLY", False),
    ]
    # The identity exists, privately, and carries what the rule counts.
    assert tuple(
        field.name for field in dataclasses.fields(tsa_module._TimestampIdentity)
    ) == ("tst_info_sha256",)


# --- end-to-end verification against a locally generated RFC 3161 authority --

SHA256_IMPRINT_OID = "2.16.840.1.101.3.4.2.1"
BUNDLE_ID = "tsa-anchors-v1"
BUNDLE_LOGICAL = "records/trust/tsa-anchors-v1.json"
RECORD_DAY = "2026-09-02"
RECORD_NAME = "record-0001.json"


@dataclasses.dataclass(frozen=True)
class LocalAnchor:
    """A locally generated authority and the pins a trust bundle must carry."""

    anchor_id: str
    endpoint: str
    tsa: LocalTsa
    root_pins: dict[str, str]
    signer_pins: dict[str, str]

    def entry(
        self,
        *,
        policy_oids: list[str] | None = None,
        signer_spki: str | None = None,
        extra_signers: Sequence[dict[str, str]] = (),
    ) -> dict[str, Any]:
        """One ``anchors`` member of a ``thesis_tsa_trust_bundle_v1`` bundle."""

        signer = dict(self.signer_pins)
        if signer_spki is not None:
            signer["spkiSha256"] = signer_spki
        return {
            "id": self.anchor_id,
            "endpoint": self.endpoint,
            "rootCertificate": {
                "path": f"records/trust/{self.tsa.root_pem.name}",
                "pemSha256": sha256_bytes(self.tsa.root_pem.read_bytes()),
                "certificateSha256": self.root_pins["certificateSha256"],
                "spkiSha256": self.root_pins["spkiSha256"],
            },
            "allowedPolicyOids": list(policy_oids or [self.tsa.policy_oid]),
            "allowedImprintAlgorithmOids": [SHA256_IMPRINT_OID],
            "allowedSigners": [signer, *(dict(extra) for extra in extra_signers)],
        }


@dataclasses.dataclass(frozen=True)
class WitnessTree:
    """A records tree an auditor could verify: bundle, record, token, sidecar."""

    records: pathlib.Path
    record: pathlib.Path
    witness: pathlib.Path
    bundle: pathlib.Path
    reference: dict[str, Any]
    spec: TsaSpec
    tokens: dict[str, pathlib.Path]


@pytest.fixture(scope="module")
def local_anchors(tmp_path_factory: pytest.TempPathFactory) -> tuple[LocalAnchor, ...]:
    """Two authorities, generated once: the RSA keygen is the expensive part."""

    workspace = tmp_path_factory.mktemp("tsa-authorities")
    anchors: list[LocalAnchor] = []
    for index, name in enumerate(("alpha", "beta"), start=1):
        authority = build_local_tsa(
            workspace / name, name, f"1.3.6.1.4.1.99999.{index}.1"
        )
        anchors.append(
            LocalAnchor(
                anchor_id=f"{name}-root-2026",
                endpoint=f"https://{name}.timestamp.invalid/tsr",
                tsa=authority,
                root_pins=certificate_pins(authority.root_pem),
                signer_pins=certificate_pins(authority.signer_pem),
            )
        )
    return tuple(anchors)


@pytest.fixture(scope="module")
def rotated_alpha(
    tmp_path_factory: pytest.TempPathFactory, local_anchors: tuple[LocalAnchor, ...]
) -> LocalTsa:
    """A second signing certificate for the first authority, same root."""

    return rotate_tsa_signer(
        local_anchors[0].tsa, tmp_path_factory.mktemp("tsa-rotated") / "alpha"
    )


def build_witness_tree(
    root: pathlib.Path,
    anchors: Sequence[LocalAnchor],
    *,
    schema: str = "thesis_rfc3161_witness_v2",
    pinned: Sequence[str] | None = None,
    policy_oids: Mapping[str, list[str]] | None = None,
    pinned_signer_spki: Mapping[str, str] | None = None,
    extra_signers: Mapping[str, LocalTsa] | None = None,
    stamp_with: Mapping[str, LocalTsa] | None = None,
    available: bool = True,
    recorded_at: datetime | None = None,
    max_future_seconds: int = 0,
    max_token_lead_seconds: int = 300,
) -> WitnessTree:
    """Write a records tree whose tokens are real stamps over its own record.

    ``pinned`` names the anchors the consumer spec carries an identity for.
    ``pinned_signer_spki`` substitutes a signer SPKI in the bundle and in the
    spec at once, which is what reaches the token's own signer: substituting it
    in only one of them stops at the earlier bundle-versus-code comparison.
    ``extra_signers`` allows a second signing certificate for an anchor, in the
    bundle and in the spec identity together, and ``stamp_with`` makes that
    certificate the one that actually signs -- the two knobs are separate so a
    superseded signer can be left allowed while a rotated one does the work.
    """

    extra_authorities = dict(extra_signers or {})
    stamping = dict(stamp_with or {})
    extra_pins = {
        anchor_id: certificate_pins(authority.signer_pem)
        for anchor_id, authority in extra_authorities.items()
    }
    stamper_pins = {
        anchor_id: certificate_pins(authority.signer_pem)
        for anchor_id, authority in stamping.items()
    }

    records = root / "records"
    day = records / RECORD_DAY
    trust = records / "trust"
    day.mkdir(parents=True)
    trust.mkdir(parents=True)

    recorded = (recorded_at or datetime.now(UTC) - timedelta(seconds=60)).astimezone(UTC)
    record = day / RECORD_NAME
    record.write_bytes(
        canonical_bytes(
            {
                "schemaVersion": "receipt_test_record_v1",
                "recordedAt": recorded.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "observation": "the record this witness is about",
            }
        )
        + b"\n"
    )
    digest = sha256_bytes(record.read_bytes())

    tokens: dict[str, pathlib.Path] = {}
    for anchor in anchors:
        (trust / anchor.tsa.root_pem.name).write_bytes(anchor.tsa.root_pem.read_bytes())
        if available:
            token = day / f"{record.stem}.{anchor.anchor_id}.tsr"
            stamping.get(anchor.anchor_id, anchor.tsa).stamp(digest, token)
            tokens[anchor.anchor_id] = token

    policy_oids = policy_oids or {}
    pinned_signer_spki = pinned_signer_spki or {}
    payload = {
        "schemaVersion": "thesis_tsa_trust_bundle_v1",
        "bundleId": BUNDLE_ID,
        "anchors": [
            anchor.entry(
                policy_oids=policy_oids.get(anchor.anchor_id),
                signer_spki=pinned_signer_spki.get(anchor.anchor_id),
                extra_signers=[extra_pins[anchor.anchor_id]]
                if anchor.anchor_id in extra_pins
                else [],
            )
            for anchor in anchors
        ],
    }
    bundle_path = trust / "tsa-anchors-v1.json"
    bundle_path.write_bytes(canonical_bytes(payload) + b"\n")
    reference: dict[str, Any] = {
        "bundleId": BUNDLE_ID,
        "path": BUNDLE_LOGICAL,
        "sha256": sha256_bytes(bundle_path.read_bytes()),
        "size": bundle_path.stat().st_size,
        "canonicalJsonSha256": canonical_sha256(payload),
    }
    (records / "CHAIN_GENESIS.json").write_bytes(
        canonical_bytes({"tsaTrustBundle": reference}) + b"\n"
    )

    pinned_ids = (
        set(pinned) if pinned is not None else {anchor.anchor_id for anchor in anchors}
    )
    configured = TsaSpec(
        trust_bundles=(
            TrustBundleSpec(
                bundle_id=BUNDLE_ID,
                path=BUNDLE_LOGICAL,
                sha256=str(reference["sha256"]),
                size=int(reference["size"]),
                canonical_json_sha256=str(reference["canonicalJsonSha256"]),
            ),
        ),
        tsa_identities=tuple(
            TsaIdentitySpec(
                bundle_id=BUNDLE_ID,
                anchor_id=anchor.anchor_id,
                root_spki_sha256=anchor.root_pins["spkiSha256"],
                signer_spki_sha256=frozenset(
                    {
                        pinned_signer_spki.get(
                            anchor.anchor_id, anchor.signer_pins["spkiSha256"]
                        ),
                        *(
                            [extra_pins[anchor.anchor_id]["spkiSha256"]]
                            if anchor.anchor_id in extra_pins
                            else []
                        ),
                    }
                ),
                max_future_seconds=max_future_seconds,
                max_token_lead_seconds=max_token_lead_seconds,
            )
            for anchor in anchors
            if anchor.anchor_id in pinned_ids
        ),
        legacy_witness_bundle_id=BUNDLE_ID,
    )

    def claim(anchor: LocalAnchor) -> dict[str, Any]:
        selection = {"tsaAnchorId": anchor.anchor_id, "tsa": anchor.endpoint}
        if not available:
            return selection
        token = tokens[anchor.anchor_id]
        signer = stamper_pins.get(anchor.anchor_id, anchor.signer_pins)
        return {
            **selection,
            "tokenPath": logical_path(records, token),
            "tokenSha256": sha256_bytes(token.read_bytes()),
            "tsaPolicyOid": anchor.tsa.policy_oid,
            "tsaImprintAlgorithmOid": SHA256_IMPRINT_OID,
            "tsaSignerCertificateSha256": signer["certificateSha256"],
            "tsaSignerSpkiSha256": signer["spkiSha256"],
        }

    status = "available" if available else "unavailable"
    witness_payload: dict[str, Any] = {
        "schemaVersion": schema,
        "digestSha256": digest,
        "status": status,
        "trustBundleId": BUNDLE_ID,
        "trustBundlePath": BUNDLE_LOGICAL,
        "trustBundleSha256": reference["sha256"],
    }
    if not available:
        witness_payload["reason"] = "no configured authority answered"
    if schema == "thesis_rfc3161_witness_v2":
        outcomes: list[dict[str, Any]] = []
        for anchor in anchors:
            outcome = {**claim(anchor), "status": status}
            if not available:
                outcome["reason"] = "authority unreachable from this fixture"
            outcomes.append(outcome)
        witness_payload["anchorOutcomes"] = outcomes
    else:
        witness_payload.update(claim(anchors[0]))
    witness = record.with_suffix(".witness.json")
    witness.write_bytes(canonical_bytes(witness_payload) + b"\n")
    return WitnessTree(
        records=records,
        record=record,
        witness=witness,
        bundle=bundle_path,
        reference=reference,
        spec=configured,
        tokens=tokens,
    )


def verify_tree(tree: WitnessTree, **overrides: Any) -> WitnessEvidence:
    return verify_witness(
        tree.record, spec=tree.spec, records=tree.records, **overrides
    )


def token_claim(tree: WitnessTree, anchor: LocalAnchor) -> dict[str, Any]:
    """The claim ``verify_witness`` composes for one anchor: witness, then outcome."""

    payload = json.loads(tree.witness.read_text())
    outcome = next(
        entry
        for entry in payload.get("anchorOutcomes", [payload])
        if entry.get("tsaAnchorId") == anchor.anchor_id
    )
    return {**payload, **outcome}


def claim_against(
    tree: WitnessTree,
    reference: Mapping[str, Any],
    anchor: LocalAnchor,
    token: pathlib.Path,
    *,
    signer: Mapping[str, str] | None = None,
    policy_oid: str | None = None,
) -> dict[str, Any]:
    """The claim ``verify_timestamp_token`` takes, against a named bundle.

    ``token_claim`` reads what a witness already says; this composes a claim
    for a bundle version no witness in the tree names, which is how a test
    reaches ``verify_timestamp_token`` for one anchor of one bundle without
    also arranging the activation and transition state ``verify_witness``
    would demand of the whole tree.
    """

    pins = dict(signer or anchor.signer_pins)
    return {
        "tsaAnchorId": anchor.anchor_id,
        "tsa": anchor.endpoint,
        "trustBundleId": reference["bundleId"],
        "trustBundlePath": reference["path"],
        "trustBundleSha256": reference["sha256"],
        "tokenPath": logical_path(tree.records, token),
        "tokenSha256": sha256_bytes(token.read_bytes()),
        "tsaPolicyOid": policy_oid or anchor.tsa.policy_oid,
        "tsaImprintAlgorithmOid": SHA256_IMPRINT_OID,
        "tsaSignerCertificateSha256": pins["certificateSha256"],
        "tsaSignerSpkiSha256": pins["spkiSha256"],
    }


def openssl_ts_verifies(
    record: pathlib.Path, token: pathlib.Path, ca_file: pathlib.Path
) -> bool:
    """Whether ``openssl ts -verify`` accepts ``token`` against ``ca_file``.

    The control the module's own refusals cannot state: what OpenSSL does
    with a given ``-CAfile``, asked directly, so a test can show that the
    file the verifier declines to pass would have been accepted.
    """

    completed = subprocess.run(
        [
            "openssl", "ts", "-verify", "-config", "/dev/null",
            "-data", str(record), "-in", str(token), "-CAfile", str(ca_file),
        ],
        capture_output=True,
        env={**os.environ, "OPENSSL_CONF": "/dev/null", "LC_ALL": "C"},
    )
    return completed.returncode == 0


#: The ``openssl ts -verify`` invocation up to its first path argument.
#:
#: Everything after it is a private snapshot -- the record read once, the
#: token read once, the pinned root read once -- so no assertion here may
#: quote a path OpenSSL was given, and none of them is a file in the records
#: tree.
TS_VERIFY_COMMAND = "openssl ts -verify -config /dev/null -data"


def openssl_command(message: str) -> str:
    """The command text out of a ported ``OpenSSL command failed`` message."""

    return message.split("(", 1)[1].split("): ", 1)[0]


def rewrite_witness(
    tree: WitnessTree, mutate: Callable[[dict[str, Any]], None]
) -> None:
    payload = json.loads(tree.witness.read_text())
    mutate(payload)
    tree.witness.write_bytes(canonical_bytes(payload) + b"\n")


def flip_last_byte(payload: bytes) -> bytes:
    """Corrupt the signature at the tail of the response and nothing else.

    A flip further in could land in the policy OID or the message imprint and
    bind one of those refusals instead of the signature check this exercises.
    """

    return payload[:-1] + bytes([payload[-1] ^ 0x01])


def token_time(evidence: TokenEvidence) -> datetime:
    return datetime.fromisoformat(evidence.gen_time.replace("Z", "+00:00"))


def test_verifies_a_real_rfc3161_witness_end_to_end(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """The whole auditor path: OpenSSL, the bundle, the code pins, the sidecar."""

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    evidence = verify_tree(tree)
    assert evidence.status == "available"
    assert evidence.digest_sha256 == sha256_bytes(tree.record.read_bytes())
    assert evidence.trust_bundle_id == BUNDLE_ID
    assert evidence.trust_bundle_path == BUNDLE_LOGICAL
    assert evidence.supplemental_tokens == ()
    assert len(evidence.tokens) == 1
    token = evidence.tokens[0]
    assert token.anchor_id == alpha.anchor_id
    assert token.policy_oid == alpha.tsa.policy_oid
    assert token.imprint_algorithm_oid == SHA256_IMPRINT_OID
    assert token.tsa_certificate_sha256 == alpha.signer_pins["certificateSha256"]
    assert token.tsa_spki_sha256 == alpha.signer_pins["spkiSha256"]
    assert token.tsa_subject == alpha.signer_pins["subject"]


def test_verify_timestamp_token_binds_one_token_to_the_bundle_it_names(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """The token verifier on its own, and the bundle pin only it enforces.

    ``verify_witness`` compares the witness-level bundle claims before it ever
    reaches a token, so this check is unreachable through that door. An auditor
    calling the token verifier directly has no such earlier comparison, and a
    claim naming a bundle other than the one it is verified against is how a
    token from another trust era would be presented as covered by this one.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    claim = token_claim(tree, alpha)
    evidence = verify_timestamp_token(
        tree.record,
        claim,
        tree.reference,
        spec=tree.spec,
        records=tree.records,
    )
    assert evidence == verify_tree(tree).tokens[0]

    claim["trustBundleSha256"] = "0" * 64
    with pytest.raises(TsaError) as caught:
        verify_timestamp_token(
            tree.record,
            claim,
            tree.reference,
            spec=tree.spec,
            records=tree.records,
        )
    assert str(caught.value) == (
        "timestamp token trustBundleSha256 does not match its bundle pin"
    )


def test_verifies_two_anchors_and_reports_the_earliest_token(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    tree = build_witness_tree(tmp_path, local_anchors)
    evidence = verify_tree(tree)
    assert evidence.status == "available"
    assert {token.anchor_id for token in evidence.tokens} == {
        anchor.anchor_id for anchor in local_anchors
    }
    earliest = min(evidence.tokens, key=lambda token: (token_time(token), token.anchor_id))
    assert evidence.anchor_id == earliest.anchor_id
    assert evidence.gen_time == earliest.gen_time


def test_one_bundle_may_allow_several_signers_at_once(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """Concurrent authorization within one immutable bundle, not rotation.

    ``signer_spki_sha256`` is a frozenset with no singleton constraint, and it
    must equal the bundle anchor's ``allowedSigners`` as a set, so a bundle
    that lists two signers is verified against an identity holding both, and
    tokens from either verify. That is what a set buys. It is not how a
    rotation is carried, because the bundle is immutable: the two tests
    below show a rotation as a new bundle version and what version order
    retires. (The first draft of this test called this a rotation; peer
    review corrected it.)
    """

    alpha = local_anchors[0]
    rotated_pins = certificate_pins(rotated_alpha.signer_pem)
    assert rotated_pins["spkiSha256"] != alpha.signer_pins["spkiSha256"]

    rotated = build_witness_tree(
        tmp_path / "rotated",
        local_anchors[:1],
        extra_signers={alpha.anchor_id: rotated_alpha},
        stamp_with={alpha.anchor_id: rotated_alpha},
    )
    assert len(rotated.spec.tsa_identities) == 1
    assert rotated.spec.tsa_identities[0].signer_spki_sha256 == frozenset(
        {alpha.signer_pins["spkiSha256"], rotated_pins["spkiSha256"]}
    )
    assert verify_tree(rotated).tokens[0].tsa_spki_sha256 == rotated_pins["spkiSha256"]

    superseded = build_witness_tree(
        tmp_path / "superseded",
        local_anchors[:1],
        extra_signers={alpha.anchor_id: rotated_alpha},
    )
    assert (
        verify_tree(superseded).tokens[0].tsa_spki_sha256
        == alpha.signer_pins["spkiSha256"]
    )


def test_verifies_a_legacy_v1_witness_over_a_single_anchor_bundle(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    tree = build_witness_tree(
        tmp_path, local_anchors[:1], schema="thesis_rfc3161_witness_v1"
    )
    evidence = verify_tree(tree)
    assert evidence.status == "available"
    assert len(evidence.tokens) == 1
    assert evidence.tokens[0].anchor_id == local_anchors[0].anchor_id


def test_refuses_a_legacy_v1_witness_over_a_multi_anchor_bundle(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """One producer-selected token must not stand in for a whole bundle.

    The legacy schema carries a single token and no per-anchor outcomes. Left
    to cover a bundle configuring two authorities it would report ``available``
    on whichever one answered and say nothing about the other, so a corpus
    could claim dual witness while only ever reaching one authority.
    """

    tree = build_witness_tree(
        tmp_path, local_anchors, schema="thesis_rfc3161_witness_v1"
    )
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == (
        "legacy witness schema requires a single-anchor bundle; "
        f"{BUNDLE_ID} has {len(local_anchors)}"
    )


def test_refuses_a_bundle_anchor_the_verifier_code_does_not_pin(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """A bundle enters the trusted set before any witness is read.

    The spec requires one identity per bundle, not one per anchor, so a bundle
    can configure an authority the consumer never pinned. Its root and signer
    would then be checked against the bundle alone -- the producer-side file --
    rather than against code the consumer committed. The refusal belongs at
    bundle load, not at whichever later check a witness happens to reach.
    """

    beta = local_anchors[1]
    tree = build_witness_tree(
        tmp_path, local_anchors, pinned=(local_anchors[0].anchor_id,)
    )
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == (
        f"TSA anchor {beta.anchor_id} in bundle {BUNDLE_ID} has no "
        "verifier code identity"
    )


def test_refuses_a_token_whose_policy_the_anchor_does_not_allow(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    alpha = local_anchors[0]
    tree = build_witness_tree(
        tmp_path,
        local_anchors[:1],
        policy_oids={alpha.anchor_id: ["1.3.6.1.4.1.99999.9.9"]},
    )
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == (
        f"RFC 3161 policy {alpha.tsa.policy_oid!r} is not allowed for TSA anchor "
        f"{alpha.anchor_id!r}"
    )


def test_refuses_a_token_from_a_signer_the_anchor_does_not_pin(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """The branch a real corpus cannot reach: a valid token, an unpinned signer."""

    alpha = local_anchors[0]
    tree = build_witness_tree(
        tmp_path, local_anchors[:1], pinned_signer_spki={alpha.anchor_id: "0" * 64}
    )
    with pytest.raises(
        TsaError, match="^RFC 3161 token signer is not pinned for TSA anchor"
    ):
        verify_tree(tree)


def test_refuses_a_token_whose_bytes_no_longer_match_the_witness(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    token = tree.tokens[local_anchors[0].anchor_id]
    token.write_bytes(flip_last_byte(token.read_bytes()))
    with pytest.raises(TsaError, match="^witness token hash mismatch for "):
        verify_tree(tree)


def test_refuses_a_tampered_token_whose_hash_the_witness_was_updated_to_match(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """Rehashing hides the edit from the digest check; the signature still refuses."""

    tree = build_witness_tree(tmp_path, local_anchors[:1])
    token = tree.tokens[local_anchors[0].anchor_id]
    token.write_bytes(flip_last_byte(token.read_bytes()))
    rewrite_witness(
        tree,
        lambda payload: payload["anchorOutcomes"][0].__setitem__(
            "tokenSha256", sha256_bytes(token.read_bytes())
        ),
    )
    with pytest.raises(TsaError, match=r"OpenSSL command failed \(openssl ts -verify"):
        verify_tree(tree)


def test_refuses_a_token_whose_imprint_is_over_other_bytes(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """Only ``-data`` ties a token to the record it witnesses (peer review, F2).

    The witness's digest claim is checked against the record and the token's
    bytes against the witness, but the message imprint inside the token is
    only length-checked in Python; whether it is an imprint *of this record*
    is settled by handing ``openssl ts -verify`` the record itself with
    ``-data``. A genuinely signed, correctly pinned, in-date token over some
    other payload is the input that check exists for, and no test presented
    one -- every token refusal here was a tampered or missing token, which
    the signature or the digest catches first. This one is intact: the
    pinned authority signs it, the witness carries its hash, every other
    claim still holds, and OpenSSL accepts it against the payload it is
    actually about, asserted below. Remove ``-data`` and nothing refuses it.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    token = tree.tokens[alpha.anchor_id]
    other = tmp_path / "the-payload-this-token-is-about.json"
    other.write_bytes(canonical_bytes({"observation": "a different record"}) + b"\n")
    assert sha256_bytes(other.read_bytes()) != sha256_bytes(tree.record.read_bytes())
    alpha.tsa.stamp(sha256_bytes(other.read_bytes()), token)
    rewrite_witness(
        tree,
        lambda payload: payload["anchorOutcomes"][0].__setitem__(
            "tokenSha256", sha256_bytes(token.read_bytes())
        ),
    )
    assert openssl_ts_verifies(other, token, alpha.tsa.root_pem)
    assert not openssl_ts_verifies(tree.record, token, alpha.tsa.root_pem)

    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    message = str(caught.value)
    # Pinned to where the message stops being reproducible: the ported
    # wrapper and the command up to its first path argument, then OpenSSL's
    # own reason. Every path in the command is a private snapshot -- the
    # record, the token, the pinned root -- so none of them is stable across
    # runs and none of them is a file in the records tree.
    assert message.startswith(f"OpenSSL command failed ({TS_VERIFY_COMMAND} ")
    assert str(tree.records) not in openssl_command(message)
    assert "ts_check_imprints:message imprint mismatch" in message


def test_refuses_a_token_that_postdates_the_verification_time(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    with pytest.raises(
        TsaError, match="^RFC 3161 genTime .* postdates verification time"
    ):
        verify_tree(tree, now=datetime.now(UTC) - timedelta(hours=1))


def test_refuses_a_token_that_precedes_the_record_it_witnesses(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    tree = build_witness_tree(
        tmp_path,
        local_anchors[:1],
        recorded_at=datetime.now(UTC) + timedelta(hours=1),
    )
    with pytest.raises(
        TsaError, match="^RFC 3161 genTime .* impossibly precedes recordedAt="
    ):
        verify_tree(tree)


def test_refuses_a_legacy_unavailable_witness_whose_reason_is_not_a_string(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """An unreadable reason is not a reason.

    The ported verifier tested the reason for truth, not for type, so a number
    or a list passed -- and the one thing an auditor gets when no token exists
    is the producer's account of why. The v2 per-anchor outcome has required a
    non-empty string since it shipped.
    """

    tree = build_witness_tree(
        tmp_path,
        local_anchors[:1],
        schema="thesis_rfc3161_witness_v1",
        available=False,
    )
    assert verify_tree(tree).status == "unavailable"

    rewrite_witness(tree, lambda payload: payload.__setitem__("reason", 503))
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == f"unavailable witness lacks a reason for {tree.record}"


def test_refuses_a_legacy_unavailable_witness_that_carries_token_evidence(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """A witness must not describe a token it declines to stand behind.

    Token fields beside ``status: unavailable`` are never verified -- the
    legacy path returns before any of them is read -- so they would travel
    with the record as unchecked provenance that reads exactly like the
    checked kind. The v2 per-anchor outcome refuses them; the legacy path
    ignored them.
    """

    tree = build_witness_tree(
        tmp_path,
        local_anchors[:1],
        schema="thesis_rfc3161_witness_v1",
        available=False,
    )
    rewrite_witness(
        tree,
        lambda payload: payload.update(
            {
                "tokenPath": f"records/{RECORD_DAY}/never-fetched.tsr",
                "tokenSha256": "0" * 64,
            }
        ),
    )
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == (
        f"unavailable witness contains token evidence for {tree.record}: "
        "['tokenPath', 'tokenSha256']"
    )


def test_a_witness_with_every_authority_unavailable_carries_no_tokens(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    tree = build_witness_tree(tmp_path, local_anchors, available=False)
    evidence = verify_tree(tree)
    assert evidence.status == "unavailable"
    assert evidence.tokens == ()
    assert evidence.gen_time is None
    assert evidence.digest_sha256 == sha256_bytes(tree.record.read_bytes())


def test_refuses_a_v2_unavailable_witness_whose_reason_is_not_a_string(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """The witness level holds the rule its own outcomes have always held.

    Each per-anchor outcome of a v2 witness required a non-empty string reason
    from the day it shipped; the witness-level field beside them was tested for
    truth alone, so ``"reason": 503`` at the top passed while the same value in
    an outcome refused. Peer review found the asymmetry.
    """

    tree = build_witness_tree(
        tmp_path,
        local_anchors[:1],
        schema="thesis_rfc3161_witness_v2",
        available=False,
    )
    assert verify_tree(tree).status == "unavailable"

    rewrite_witness(tree, lambda payload: payload.__setitem__("reason", 503))
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == f"unavailable witness lacks a reason for {tree.record}"


def test_refuses_a_v2_unavailable_witness_that_carries_token_evidence(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """Token fields at the witness level are not read by any outcome check.

    The per-anchor rule looks only inside each outcome, so a v2 witness that
    declared no verified token could still carry ``tokenSha256`` beside its
    ``status`` and travel as unchecked provenance that reads like the checked
    kind. The witness level now refuses them the way the outcomes do.
    """

    tree = build_witness_tree(
        tmp_path,
        local_anchors[:1],
        schema="thesis_rfc3161_witness_v2",
        available=False,
    )
    rewrite_witness(
        tree,
        lambda payload: payload.update(
            {
                "tokenPath": f"records/{RECORD_DAY}/never-fetched.tsr",
                "tokenSha256": "0" * 64,
            }
        ),
    )
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == (
        f"unavailable witness contains token evidence for {tree.record}: "
        "['tokenPath', 'tokenSha256']"
    )


def add_bundle_version(
    tree: WitnessTree,
    anchors: Sequence[LocalAnchor],
    *,
    version: int,
    signers: Mapping[str, dict[str, str]] | None = None,
    mutate_anchor: Callable[[dict[str, Any]], None] | None = None,
    base: TsaSpec | None = None,
) -> tuple[dict[str, Any], TsaSpec]:
    """Write a further immutable bundle version into the tree.

    Returns its reference and a spec that pins every bundle in the tree with a
    bundle-scoped identity for every anchor, the shape a consumer commits when
    it carries a trust transition. ``signers`` replaces an anchor's allowed
    signer with the given certificate pins, in the bundle and in the new
    identity together, which is how a rotated signing key enters: as a new
    version, never as an edit. ``base`` is the spec to extend, for a test that
    writes two versions and needs one spec pinning both; without it each call
    extends the tree's own spec and the second would drop the first.
    """

    from receipt.canonical import canonical_sha256

    base = base or tree.spec
    signers = signers or {}
    bundle_id = f"tsa-anchors-v{version}"
    logical = f"records/trust/{bundle_id}.json"
    payload: dict[str, Any] = {
        "schemaVersion": "thesis_tsa_trust_bundle_v1",
        "bundleId": bundle_id,
        "anchors": [anchor.entry() for anchor in anchors],
    }
    for entry in payload["anchors"]:
        if entry["id"] in signers:
            entry["allowedSigners"] = [dict(signers[entry["id"]])]
        if mutate_anchor is not None:
            mutate_anchor(entry)
    path = tree.records / "trust" / f"{bundle_id}.json"
    path.write_bytes(canonical_bytes(payload) + b"\n")
    reference = {
        "bundleId": bundle_id,
        "path": logical,
        "sha256": sha256_bytes(path.read_bytes()),
        "size": path.stat().st_size,
        "canonicalJsonSha256": canonical_sha256(payload),
    }
    identities = tuple(
        TsaIdentitySpec(
            bundle_id=bundle_id,
            anchor_id=anchor.anchor_id,
            root_spki_sha256=anchor.root_pins["spkiSha256"],
            signer_spki_sha256=frozenset(
                {signers.get(anchor.anchor_id, anchor.signer_pins)["spkiSha256"]}
            ),
            max_future_seconds=0,
            max_token_lead_seconds=300,
        )
        for anchor in anchors
    )
    spec = TsaSpec(
        trust_bundles=(
            *base.trust_bundles,
            TrustBundleSpec(
                bundle_id=bundle_id,
                path=logical,
                sha256=str(reference["sha256"]),
                size=int(reference["size"]),
                canonical_json_sha256=str(reference["canonicalJsonSha256"]),
            ),
        ),
        tsa_identities=(*base.tsa_identities, *identities),
        legacy_witness_bundle_id=base.legacy_witness_bundle_id,
    )
    return reference, spec


def test_a_legacy_witness_is_measured_against_the_bundle_it_names(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """The single-anchor rule counts the bundle the witness selects.

    Every activated bundle stays selectable by a legacy witness, and the rule
    was first checked against the newest one. So with a single-anchor bundle
    newest and named as the legacy bundle, a v1 witness could still name the
    older two-anchor bundle, verify one token against one of its authorities,
    and pass. Found by peer review; the count now runs on the bundle the
    witness actually resolved to.
    """

    tree = build_witness_tree(
        tmp_path, local_anchors, schema="thesis_rfc3161_witness_v1"
    )
    reference, spec = add_bundle_version(tree, local_anchors[:1], version=2)
    spec = dataclasses.replace(spec, legacy_witness_bundle_id="tsa-anchors-v2")
    active = {BUNDLE_LOGICAL: tree.reference, str(reference["path"]): reference}
    with pytest.raises(TsaError) as caught:
        verify_witness(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles=active,
            transition_bundle_updates=[],
        )
    assert str(caught.value) == (
        "legacy witness schema requires a single-anchor bundle; tsa-anchors-v1 has 2"
    )


def test_a_superseded_bundle_stops_vouching_for_new_records(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """Version order is the retirement mechanism, and it is prospective.

    A record witnessed under bundle v1 keeps verifying under v1 for as long as
    that is the newest active bundle. Once v2 -- here carrying a rotated
    signer -- is active, a v2-schema witness that names v1 is refused: the
    old signer no longer vouches for new records. History that named v1
    before the transition is unaffected, because the verifier replays which
    bundles were active at each record.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    rotated = certificate_pins(rotated_alpha.signer_pem)
    reference, spec = add_bundle_version(
        tree, local_anchors[:1], version=2, signers={alpha.anchor_id: rotated}
    )
    before = {BUNDLE_LOGICAL: tree.reference}
    assert (
        verify_witness(
            tree.record, spec=spec, records=tree.records, trusted_bundles=before,
            transition_bundle_updates=[],
        ).tokens[0].tsa_spki_sha256
        == alpha.signer_pins["spkiSha256"]
    )
    after = {**before, str(reference["path"]): reference}
    with pytest.raises(TsaError) as caught:
        verify_witness(
            tree.record, spec=spec, records=tree.records, trusted_bundles=after,
            transition_bundle_updates=[],
        )
    assert str(caught.value) == (
        "multi-token witness does not use the newest active TSA trust bundle"
    )


def test_a_rotated_signer_verifies_under_the_bundle_version_that_names_it(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """A rotation is a new bundle version plus a bundle-scoped identity.

    The bundle is immutable and its anchor's ``allowedSigners`` must equal the
    identity's set, so the rotated key cannot be added beside the old one in
    place. A token from the rotated signer fails under v1, which never named
    it, and verifies under v2, which does -- with v1 still active for the
    records that predate the transition.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(
        tmp_path, local_anchors[:1], stamp_with={alpha.anchor_id: rotated_alpha}
    )
    with pytest.raises(TsaError):
        verify_tree(tree)
    rotated = certificate_pins(rotated_alpha.signer_pem)
    reference, spec = add_bundle_version(
        tree, local_anchors[:1], version=2, signers={alpha.anchor_id: rotated}
    )
    rewrite_witness(
        tree,
        lambda payload: payload.update(
            {
                "trustBundleId": "tsa-anchors-v2",
                "trustBundlePath": str(reference["path"]),
                "trustBundleSha256": reference["sha256"],
            }
        ),
    )
    active = {BUNDLE_LOGICAL: tree.reference, str(reference["path"]): reference}
    evidence = verify_witness(
        tree.record, spec=spec, records=tree.records, trusted_bundles=active,
        transition_bundle_updates=[],
    )
    assert evidence.trust_bundle_id == "tsa-anchors-v2"
    assert evidence.tokens[0].tsa_spki_sha256 == rotated["spkiSha256"]


def test_refuses_an_unavailable_legacy_witness_over_a_multi_anchor_bundle(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """The unavailable path returned before any bundle was resolved.

    An unavailable v1 marker names no bundle, so counting only the bundle an
    available witness selects left it unmeasured: it verified over a
    two-anchor legacy bundle while the PR said such witnesses refuse (peer
    review, round two). The newest active bundle, which the legacy schema is
    already required to match, is counted before dispatch.
    """

    tree = build_witness_tree(
        tmp_path,
        local_anchors,
        schema="thesis_rfc3161_witness_v1",
        available=False,
    )
    # Genuinely bundle-less, as the pinned genesis marker is: the fixture
    # writes the three claim fields, and with them present the claim path
    # would refuse on its own, leaving the pre-dispatch count untested (peer
    # review, round four).
    rewrite_witness(
        tree,
        lambda payload: [
            payload.pop(field, None)
            for field in ("trustBundleId", "trustBundlePath", "trustBundleSha256")
        ],
    )
    assert not _BUNDLE_CLAIM_FIELDS.intersection(json.loads(tree.witness.read_text()))
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == (
        "legacy witness schema requires a single-anchor bundle; tsa-anchors-v1 has 2"
    )


def test_refuses_an_unavailable_legacy_witness_naming_an_older_multi_anchor_bundle(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """The unavailable marker's own bundle claim is resolved and counted.

    With a single-anchor bundle newest and named as the legacy bundle, the
    pre-dispatch count passes; an unavailable v1 marker that names the older
    two-anchor bundle returned before that claim was resolved (peer review,
    round three). The claim is resolved like an available witness's and the
    bundle it names is counted.
    """

    tree = build_witness_tree(
        tmp_path,
        local_anchors,
        schema="thesis_rfc3161_witness_v1",
        available=False,
    )
    reference, spec = add_bundle_version(tree, local_anchors[:1], version=2)
    spec = dataclasses.replace(spec, legacy_witness_bundle_id="tsa-anchors-v2")
    active = {BUNDLE_LOGICAL: tree.reference, str(reference["path"]): reference}
    with pytest.raises(TsaError) as caught:
        verify_witness(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles=active,
            transition_bundle_updates=[],
        )
    assert str(caught.value) == (
        "legacy witness schema requires a single-anchor bundle; tsa-anchors-v1 has 2"
    )


def test_decodes_a_policy_oid_whose_first_subidentifier_spans_octets() -> None:
    """The baseline read one octet as the combined first two arcs.

    DER encodes the first subidentifier (X*40+Y, or 80+Y for X = 2) in
    base-128 like every other, so 2.999.3 is 88 37 03 and decoded as
    2.56.55.3: a legitimate policy refused, or a disallowed one aliased onto
    an allowed spelling. Found by peer review; a corrected defect.
    """

    assert _decode_oid(bytes([0x88, 0x37, 0x03])) == "2.999.3"
    assert _decode_oid(bytes([0x2A, 0x03])) == "1.2.3"
    assert _decode_oid(bytes([0x88, 0x37, 0x81, 0x00])) == "2.999.128"
    with pytest.raises(TsaError, match="truncated policy OID"):
        _decode_oid(bytes([0x88]))


def test_verifies_a_real_token_under_a_policy_whose_first_arc_spans_octets(
    tmp_path: pathlib.Path,
) -> None:
    """A genuine token stamped under policy 2.999.3 verifies end to end.

    On the previous decoder the token's policy read as 2.56.55.3, outside the
    anchor's allowed policies, and the witness was refused.
    """

    authority = build_local_tsa(tmp_path / "gamma", "gamma", "2.999.3")
    gamma = LocalAnchor(
        anchor_id="gamma-root-2026",
        endpoint="https://gamma.timestamp.invalid/tsr",
        tsa=authority,
        root_pins=certificate_pins(authority.root_pem),
        signer_pins=certificate_pins(authority.signer_pem),
    )
    tree = build_witness_tree(tmp_path / "tree", [gamma])
    evidence = verify_tree(tree)
    assert evidence.status == "available"
    assert evidence.tokens[0].policy_oid == "2.999.3"


def test_refuses_at_load_a_bundle_anchor_that_contradicts_its_identity(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """Existence of an identity is not agreement with it.

    _select_anchor compares root and signers with the identity only for the
    anchor a witness selects. A rotation bundle reuses the active anchor id,
    so a transition could activate a bundle whose anchor lists a signer its
    pinned identity does not, without any selection comparing the two (peer
    review). Every anchor is compared at load, on its declared values.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    rotated = certificate_pins(rotated_alpha.signer_pem)
    reference, honest = add_bundle_version(
        tree, local_anchors[:1], version=2, signers={alpha.anchor_id: rotated}
    )
    # The v2 identity pins the OLD signer while the v2 bundle lists the new one.
    contradictory = TsaSpec(
        trust_bundles=honest.trust_bundles,
        tsa_identities=(
            *honest.tsa_identities[:-1],
            dataclasses.replace(
                honest.tsa_identities[-1],
                signer_spki_sha256=frozenset({alpha.signer_pins["spkiSha256"]}),
            ),
        ),
        legacy_witness_bundle_id=honest.legacy_witness_bundle_id,
    )
    with pytest.raises(TsaError) as loading:
        _load_trust_bundle(tree.records, reference, spec=contradictory)
    assert str(loading.value) == (
        "TSA anchor alpha-root-2026 in bundle tsa-anchors-v2 declares allowed "
        "signers that differ from its verifier code identity"
    )
    # The pending-rotation path: the same bundle offered as a transition
    # update is refused before anything activates.
    with pytest.raises(TsaError, match="declares allowed signers that differ"):
        verify_witness(
            tree.record,
            spec=contradictory,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            transition_bundle_updates=[reference],
        )
    # A root contradiction is caught the same way.
    wrong_root = TsaSpec(
        trust_bundles=honest.trust_bundles,
        tsa_identities=(
            *honest.tsa_identities[:-1],
            dataclasses.replace(honest.tsa_identities[-1], root_spki_sha256="0" * 64),
        ),
        legacy_witness_bundle_id=honest.legacy_witness_bundle_id,
    )
    with pytest.raises(TsaError, match="declares a root SPKI that differs"):
        _load_trust_bundle(tree.records, reference, spec=wrong_root)


@pytest.mark.parametrize(
    ("kept", "message"),
    [
        ("trustBundleId", "witness lacks a TSA trust-bundle path"),
        ("trustBundlePath", "witness TSA trust-bundle hash mismatch"),
        ("trustBundleSha256", "witness lacks a TSA trust-bundle path"),
    ],
)
def test_an_unavailable_legacy_witness_with_a_partial_bundle_claim_is_refused(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    kept: str,
    message: str,
) -> None:
    """The divergence, bound for each field that triggers it (peer review, F3).

    An unavailable v1 marker naming a bundle by *any* of the three claim
    fields has that claim resolved like an available witness's, so a partial
    claim refuses where the baseline accepted it. The rule is written over
    the set of three and only ``trustBundleId`` was bound, which left the
    other two asserting nothing; each field alone is what the rule promises,
    so each is here on the message it actually produces -- two of them stop
    at the missing path, ``trustBundlePath`` alone gets further and refuses
    on the hash it does not carry. A complete claim is accepted, which
    ``test_refuses_a_legacy_unavailable_witness_whose_reason_is_not_a_string``
    relies on, and a marker naming nothing is accepted just below. Without
    the resolution rule all three of these verify ``unavailable``.
    """

    tree = build_witness_tree(
        tmp_path,
        local_anchors[:1],
        schema="thesis_rfc3161_witness_v1",
        available=False,
    )
    dropped = sorted(_BUNDLE_CLAIM_FIELDS - {kept})
    rewrite_witness(
        tree, lambda payload: [payload.pop(field, None) for field in dropped]
    )
    claimed = json.loads(tree.witness.read_text())
    assert _BUNDLE_CLAIM_FIELDS.intersection(claimed) == {kept}
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == message


def test_an_unavailable_legacy_marker_naming_no_bundle_is_accepted(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """The other side of the same rule: nothing named, nothing resolved (F3).

    The three fields above are the whole of what naming a bundle means, and
    that is asserted here, so a fourth claim field would fail this test
    rather than quietly escape the parametrization. A marker carrying none of
    them names no bundle, is measured against the newest active one instead,
    and must still verify -- it is the shape of the pinned tree's own genesis
    witness, and the case the port must not start refusing.
    """

    assert _BUNDLE_CLAIM_FIELDS == {
        "trustBundleId",
        "trustBundlePath",
        "trustBundleSha256",
    }
    tree = build_witness_tree(
        tmp_path,
        local_anchors[:1],
        schema="thesis_rfc3161_witness_v1",
        available=False,
    )
    rewrite_witness(
        tree,
        lambda payload: [
            payload.pop(field, None) for field in sorted(_BUNDLE_CLAIM_FIELDS)
        ],
    )
    evidence = verify_tree(tree)
    assert evidence.status == "unavailable"
    assert evidence.tokens == ()
    assert evidence.trust_bundle_id is None


def test_refuses_at_load_a_bundle_whose_root_material_is_missing_or_tampered(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """Declared values agreeing with the identity is not the root agreeing.

    The root material checks lived only in _select_anchor, which a pending
    rotation never reaches: the new bundle reuses the active anchor id and
    _supplemental_candidates skips it, so a transition could activate a
    bundle whose root file is missing or tampered (peer review, fresh gate
    round two). The material is validated at load for every anchor.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    rotated = certificate_pins(rotated_alpha.signer_pem)

    def point_at_a_missing_root(entry: dict[str, Any]) -> None:
        entry["rootCertificate"]["path"] = "records/trust/never-written-root.pem"

    reference, spec = add_bundle_version(
        tree,
        local_anchors[:1],
        version=2,
        signers={alpha.anchor_id: rotated},
        mutate_anchor=point_at_a_missing_root,
    )
    with pytest.raises(TsaError) as loading:
        _load_trust_bundle(tree.records, reference, spec=spec)
    message = str(loading.value)
    assert message.startswith(
        "TSA anchor alpha-root-2026 in bundle tsa-anchors-v2 references root "
        "material that fails validation: pinned TSA root is missing or not a "
        "regular file: "
    )
    # The reused-id pending transition: offered as an update, refused before
    # anything activates.
    with pytest.raises(TsaError, match="references root material that fails"):
        verify_witness(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            transition_bundle_updates=[reference],
        )

    # Tampered rather than missing: a different root PEM under the declared
    # hashes fails the PEM hash check inside the same load-time message.
    def point_at_the_wrong_root(entry: dict[str, Any]) -> None:
        entry["rootCertificate"]["path"] = f"records/trust/{local_anchors[1].tsa.root_pem.name}"

    (tree.records / "trust" / local_anchors[1].tsa.root_pem.name).write_bytes(
        local_anchors[1].tsa.root_pem.read_bytes()
    )
    reference, spec = add_bundle_version(
        tree,
        local_anchors[:1],
        version=3,
        signers={alpha.anchor_id: rotated},
        mutate_anchor=point_at_the_wrong_root,
    )
    with pytest.raises(TsaError, match="fails validation: pinned TSA root PEM hash mismatch"):
        _load_trust_bundle(tree.records, reference, spec=spec)


def test_refuses_a_pinned_root_pem_that_carries_a_second_authority(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """A root PEM must hold exactly one certificate (peer review, F1).

    ``_certificate_identity`` reads the file's first certificate, so the
    bundle's ``certificateSha256`` and ``spkiSha256`` describe that one alone,
    while ``verify_timestamp_token`` hands the whole file to ``openssl ts
    -verify -CAfile`` and ``openssl cms -verify -CAfile``, which trust every
    certificate in it. A PEM holding the pinned root followed by a second
    authority's root therefore satisfies all three declared hashes -- asserted
    below -- and the SPKI comparison against the code identity, while a token
    chaining to that second authority verifies against it. Without the
    single-certificate rule the bundle loads clean and neither call raises.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    combined = tree.records / "trust" / "alpha-root-and-a-second-authority.pem"
    combined.write_bytes(
        alpha.tsa.root_pem.read_bytes() + beta.tsa.root_pem.read_bytes()
    )
    # A second authority is genuinely in the file, and what the pins can see
    # is the first certificate alone, which is alpha's root.
    assert beta.tsa.root_pem.read_bytes() in combined.read_bytes()
    assert certificate_pins(combined) == alpha.root_pins
    # The premise, asked of OpenSSL directly: a token from the second
    # authority chains against the combined file and not against the pinned
    # certificate alone, so ``storeutl``'s count of two is the count of what
    # ``-CAfile`` would trust (peer review, fourth gate).
    digest = sha256_bytes(tree.record.read_bytes())
    beta_token = tree.records / "trust" / "beta-over-the-record.tsr"
    beta.tsa.stamp(digest, beta_token)
    assert openssl_ts_verifies(tree.record, beta_token, combined)
    assert not openssl_ts_verifies(tree.record, beta_token, alpha.tsa.root_pem)

    def point_at_the_two_certificate_pem(entry: dict[str, Any]) -> None:
        entry["rootCertificate"] = {
            "path": logical_path(tree.records, combined),
            "pemSha256": sha256_bytes(combined.read_bytes()),
            "certificateSha256": alpha.root_pins["certificateSha256"],
            "spkiSha256": alpha.root_pins["spkiSha256"],
        }

    reference, spec = add_bundle_version(
        tree,
        local_anchors[:1],
        version=2,
        mutate_anchor=point_at_the_two_certificate_pem,
    )
    with pytest.raises(TsaError) as loading:
        _load_trust_bundle(tree.records, reference, spec=spec)
    assert str(loading.value) == (
        "TSA anchor alpha-root-2026 in bundle tsa-anchors-v2 references root "
        "material that fails validation: pinned TSA root PEM must hold exactly "
        f"one certificate: {combined}"
    )
    # And through the verifier, on the pending-transition path that reaches
    # the bundle before anything activates.
    with pytest.raises(TsaError, match="must hold exactly one certificate"):
        verify_witness(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            transition_bundle_updates=[reference],
        )


def test_refuses_a_bundle_missing_an_anchor_its_identities_pin(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """Bundle-to-identity agreement runs both ways (peer review, F2).

    The per-anchor loop refuses a bundle anchor the spec carries no identity
    for; the reverse was ignored. An identity scoped to this bundle whose
    anchor the bundle does not configure means a consumer that committed to
    two authorities verifies a corpus whose bundle configures one, and the
    second never has to answer for anything -- the same one-token-stands-for-
    the-bundle weakness the legacy count refuses, arrived at from the spec
    side. Without the set comparison this bundle loads clean and the witness
    verifies ``available`` on alpha alone.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    pins_an_absent_authority = TsaSpec(
        trust_bundles=tree.spec.trust_bundles,
        tsa_identities=(
            *tree.spec.tsa_identities,
            TsaIdentitySpec(
                bundle_id=BUNDLE_ID,
                anchor_id=beta.anchor_id,
                root_spki_sha256=beta.root_pins["spkiSha256"],
                signer_spki_sha256=frozenset({beta.signer_pins["spkiSha256"]}),
                max_future_seconds=0,
                max_token_lead_seconds=300,
            ),
        ),
        legacy_witness_bundle_id=tree.spec.legacy_witness_bundle_id,
    )
    message = (
        f"TSA bundle {BUNDLE_ID} configures anchors ['{alpha.anchor_id}'] but "
        f"verifier code pins identities for "
        f"['{alpha.anchor_id}', '{beta.anchor_id}']"
    )
    with pytest.raises(TsaError) as loading:
        _load_trust_bundle(tree.records, tree.reference, spec=pins_an_absent_authority)
    assert str(loading.value) == message
    with pytest.raises(TsaError) as verifying:
        verify_witness(
            tree.record, spec=pins_an_absent_authority, records=tree.records
        )
    assert str(verifying.value) == message


def test_requires_a_supplemental_outcome_for_a_reused_id_under_a_new_root(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """An anchor ID is a slot, not an authority (peer review, F3).

    ``_supplemental_candidates`` skipped a pending anchor whose ID was already
    active, so a pending bundle could reuse an active ID while putting a
    different code-pinned root behind it. Both bundles pass their own load
    checks -- each anchor agrees with the identity scoped to its own bundle --
    and the new authority was admitted at activation without ever being asked
    for a supplemental outcome, which is the ported mechanism for admitting
    one. Keyed by ID and declared root SPKI, it is a candidate, and a witness
    carrying no supplemental outcome for it is refused by the ported message.

    Without the fix the pair below is skipped exactly as the control is, and
    the witness verifies. The control is what keeps the rule narrow: a signer
    rotation reuses the ID under the same root and is still skipped.

    The second authority arrives with its own signing certificate as well as
    its own root, because the later signer rule (S5-F2) reads an anchor whose
    signing key is already active as that active authority under a new name
    and skips it whatever root it is filed under. So a root swapped alone is
    no longer the shape either rule calls new; a whole authority behind a
    familiar ID is, and it is still this rule that has to notice, since the
    signer rule only ever skips.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    (tree.records / "trust" / beta.tsa.root_pem.name).write_bytes(
        beta.tsa.root_pem.read_bytes()
    )

    def put_betas_root_behind_alphas_id(entry: dict[str, Any]) -> None:
        entry["rootCertificate"] = beta.entry()["rootCertificate"]

    reference, spec = add_bundle_version(
        tree,
        local_anchors[:1],
        version=2,
        signers={alpha.anchor_id: certificate_pins(beta.tsa.signer_pem)},
        mutate_anchor=put_betas_root_behind_alphas_id,
    )
    # The v2 identity pins the root the v2 bundle actually declares, so the
    # bundle and the spec agree with each other and both load clean.
    spec = TsaSpec(
        trust_bundles=spec.trust_bundles,
        tsa_identities=(
            *spec.tsa_identities[:-1],
            dataclasses.replace(
                spec.tsa_identities[-1],
                root_spki_sha256=beta.root_pins["spkiSha256"],
            ),
        ),
        legacy_witness_bundle_id=spec.legacy_witness_bundle_id,
    )
    pending = json.loads((tree.records / "trust" / "tsa-anchors-v2.json").read_text())
    active = json.loads(tree.bundle.read_text())
    # The premise: the ID is reused, so keying by ID alone skips this anchor.
    assert {anchor["id"] for anchor in pending["anchors"]} == {
        anchor["id"] for anchor in active["anchors"]
    }
    assert pending["anchors"][0]["rootCertificate"]["spkiSha256"] != (
        active["anchors"][0]["rootCertificate"]["spkiSha256"]
    )
    # And a signing key of its own, so the signer rule has nothing to skip on.
    assert pending["anchors"][0]["allowedSigners"] != (
        active["anchors"][0]["allowedSigners"]
    )
    with pytest.raises(TsaError) as caught:
        verify_witness(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            transition_bundle_updates=[reference],
        )
    assert str(caught.value) == (
        "supplemental TSA outcome mismatch: "
        f"missing=[('{reference['path']}', '{alpha.anchor_id}')], extra=[]"
    )

    # The control: a genuine signer rotation reuses the ID under the same
    # root, is not a new authority, and needs no supplemental outcome.
    rotation, rotation_spec = add_bundle_version(
        tree,
        local_anchors[:1],
        version=3,
        signers={alpha.anchor_id: certificate_pins(rotated_alpha.signer_pem)},
    )
    rotated_pending = json.loads(
        (tree.records / "trust" / "tsa-anchors-v3.json").read_text()
    )
    assert rotated_pending["anchors"][0]["rootCertificate"]["spkiSha256"] == (
        active["anchors"][0]["rootCertificate"]["spkiSha256"]
    )
    evidence = verify_witness(
        tree.record,
        spec=rotation_spec,
        records=tree.records,
        trusted_bundles={BUNDLE_LOGICAL: tree.reference},
        transition_bundle_updates=[rotation],
    )
    assert evidence.status == "available"
    assert evidence.supplemental_tokens == ()


#: The pattern OpenSSL's own count replaced (peer review, F1): a PEM BEGIN
#: marker that ends its own line. It lives here, and nowhere in ``receipt``,
#: so the tests below can state exactly which files it used to accept.
SUPERSEDED_PEM_BEGIN_RE = re.compile(rb"^-----BEGIN ([A-Z0-9 ]+)-----[ \t]*\r?$", re.M)

#: Everything a witness outcome says about the response it stands behind.
_TOKEN_FIELDS = (
    "tokenPath",
    "tokenSha256",
    "tsaPolicyOid",
    "tsaImprintAlgorithmOid",
    "tsaSignerCertificateSha256",
    "tsaSignerSpkiSha256",
)


def relabel(pem: bytes, label: str) -> bytes:
    """The same certificate under another PEM label ``-CAfile`` also loads."""

    return pem.replace(b"BEGIN CERTIFICATE", f"BEGIN {label}".encode()).replace(
        b"END CERTIFICATE", f"END {label}".encode()
    )


def bundle_over_root_file(
    tree: WitnessTree,
    anchor: LocalAnchor,
    *,
    name: str,
    content: bytes,
    version: int = 2,
    signers: Mapping[str, dict[str, str]] | None = None,
    mutate_anchor: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[pathlib.Path, dict[str, Any], TsaSpec]:
    """Write ``content`` as a root file and pin a fresh bundle version at it.

    Only the path and the PEM hash move; the anchor keeps the certificate and
    SPKI hashes it already declares. That is the construction every root-file
    test below needs, and the reason the rule exists: a file whose *first*
    certificate is the pinned one satisfies all three declared hashes however
    much else it holds.
    """

    root_path = tree.records / "trust" / name
    root_path.write_bytes(content)

    def point_at_it(entry: dict[str, Any]) -> None:
        entry["rootCertificate"]["path"] = logical_path(tree.records, root_path)
        entry["rootCertificate"]["pemSha256"] = sha256_bytes(content)
        if mutate_anchor is not None:
            mutate_anchor(entry)

    reference, spec = add_bundle_version(
        tree,
        [anchor],
        version=version,
        signers=signers,
        mutate_anchor=point_at_it,
    )
    return root_path, reference, spec


def load_refusal(tree: WitnessTree, anchor: LocalAnchor, detail: str) -> str:
    """The load-time wrapper a root-material refusal arrives inside."""

    return (
        f"TSA anchor {anchor.anchor_id} in bundle tsa-anchors-v2 references "
        f"root material that fails validation: {detail}"
    )


@pytest.mark.parametrize(
    "label", ["TRUSTED CERTIFICATE", "X509 CERTIFICATE"], ids=["trusted", "x509"]
)
def test_refuses_a_root_pem_whose_second_authority_wears_another_pem_label(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...], label: str
) -> None:
    """OpenSSL's -CAfile loads more PEM labels than CERTIFICATE (F1).

    Counting only ``-----BEGIN CERTIFICATE-----`` blocks let the pinned root
    be followed by a second authority spelled as a ``TRUSTED CERTIFICATE`` or
    a legacy ``X509 CERTIFICATE`` object, which the count did not see and the
    ``-CAfile`` verifications trust (peer review, fresh gate round four).
    Now counted by ``openssl storeutl``, which finds two here -- asserted,
    because the count agreeing with what ``-CAfile`` loads is the whole basis
    of the rule. Without the count the bundle loads clean.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    combined = alpha.tsa.root_pem.read_bytes() + relabel(
        beta.tsa.root_pem.read_bytes(), label
    )
    assert combined.count(b"-----BEGIN CERTIFICATE-----") == 1
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    root_path, reference, spec = bundle_over_root_file(
        tree,
        alpha,
        name=f"combined-{label.split()[0].lower()}.pem",
        content=combined,
    )
    assert _certificate_count(root_path) == 2
    with pytest.raises(TsaError) as caught:
        _load_trust_bundle(tree.records, reference, spec=spec)
    assert str(caught.value) == load_refusal(
        tree,
        alpha,
        f"pinned TSA root PEM must hold exactly one certificate: {root_path}",
    )


@pytest.mark.parametrize(
    "whitespace", [b"\x0b", b"\x0c"], ids=["vertical-tab", "form-feed"]
)
def test_refuses_a_root_pem_whose_second_begin_marker_trails_whitespace(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...], whitespace: bytes
) -> None:
    """OpenSSL strips whitespace an end-of-line anchor does not (peer review, F1).

    The superseded pattern required a BEGIN marker to end its line, allowing
    a space or a tab after it and nothing else; OpenSSL's PEM reader also
    strips a vertical tab and a form feed. A second authority whose BEGIN
    line carries one was therefore invisible to the count -- asserted below
    by running that pattern over these very bytes -- while ``-CAfile`` loaded
    its certificate all the same. Without OpenSSL doing the counting this
    file loads clean, its declared hashes describing alpha alone while the
    verifications trust beta too.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    hidden = relabel(beta.tsa.root_pem.read_bytes(), "TRUSTED CERTIFICATE").replace(
        b"-----BEGIN TRUSTED CERTIFICATE-----\n",
        b"-----BEGIN TRUSTED CERTIFICATE-----" + whitespace + b"\n",
        1,
    )
    combined = alpha.tsa.root_pem.read_bytes() + hidden
    assert SUPERSEDED_PEM_BEGIN_RE.findall(combined) == [b"CERTIFICATE"]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    root_path, reference, spec = bundle_over_root_file(
        tree,
        alpha,
        name=f"trailing-{whitespace.hex()}.pem",
        content=combined,
    )
    assert _certificate_count(root_path) == 2
    assert certificate_pins(root_path) == alpha.root_pins
    with pytest.raises(TsaError) as caught:
        _load_trust_bundle(tree.records, reference, spec=spec)
    assert str(caught.value) == load_refusal(
        tree,
        alpha,
        f"pinned TSA root PEM must hold exactly one certificate: {root_path}",
    )


def test_refuses_a_root_pem_whose_byte_order_mark_hides_the_first_marker(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """A UTF-8 BOM pushes the first BEGIN marker off the start of its line (F1).

    OpenSSL skips the mark and reads both certificates. A pattern anchored to
    line starts saw only the *second* certificate's boundary, counted one
    object, found it labelled CERTIFICATE and accepted -- asserted below --
    while ``openssl x509`` still read the first certificate, so the anchor's
    declared hashes describe alpha, also asserted, and ``-CAfile`` trusts
    beta as well. The mirror image of the trailing-whitespace case: there the
    second boundary was hidden, here the first. Without OpenSSL doing the
    counting the bundle loads clean.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    combined = (
        b"\xef\xbb\xbf"
        + alpha.tsa.root_pem.read_bytes()
        + beta.tsa.root_pem.read_bytes()
    )
    assert SUPERSEDED_PEM_BEGIN_RE.findall(combined) == [b"CERTIFICATE"]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    root_path, reference, spec = bundle_over_root_file(
        tree, alpha, name="byte-order-mark.pem", content=combined
    )
    assert _certificate_count(root_path) == 2
    assert certificate_pins(root_path) == alpha.root_pins
    with pytest.raises(TsaError) as caught:
        _load_trust_bundle(tree.records, reference, spec=spec)
    assert str(caught.value) == load_refusal(
        tree,
        alpha,
        f"pinned TSA root PEM must hold exactly one certificate: {root_path}",
    )


@pytest.mark.parametrize(
    "kind", ["no-pem-object", "certificate-and-key"], ids=["no-object", "with-key"]
)
def test_refuses_a_root_pem_whose_certificates_openssl_cannot_count(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...], kind: str
) -> None:
    """A count that did not happen is not a count of one (peer review, F1).

    ``openssl storeutl`` 3.6 prints no total at all for a file holding no PEM
    object (3.0 prints ``Total found: 0``, and the load then refuses on the
    one-certificate rule instead), and fails outright on one holding an
    object its store loader cannot decode -- a certificate beside its private
    key is the ordinary way to meet the second. The superseded pattern refused both too, by counting
    zero objects in one and two in the other, so what this binds is narrower
    and worth saying plainly: where OpenSSL returns no total, the refusal
    says the certificates could not be counted instead of substituting a
    number of ours. Both assertions below are on the counting message and not
    on the one-certificate message, so a ``_certificate_count`` that fell
    back to zero -- refusing these two by the wrong rule, and trusting
    whatever the next uncountable file turned out to hold -- fails here.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    content = (
        b"nothing here is a PEM object\n"
        if kind == "no-pem-object"
        else alpha.tsa.root_pem.read_bytes()
        + (alpha.tsa.directory / "ca.key").read_bytes()
    )
    root_path, reference, spec = bundle_over_root_file(
        tree, alpha, name=f"uncountable-{kind}.pem", content=content
    )
    uncounted = f"pinned TSA root PEM certificates could not be counted: {root_path}: "
    if kind == "no-pem-object":
        # OpenSSL 3.0 (CI's Ubuntu) prints "Total found: 0" for a file holding
        # no PEM object, so the count is zero and the load refuses on the
        # one-certificate rule; OpenSSL 3.6 prints no total at all, so the
        # count refuses. Both refuse the file; which message depends on the
        # OpenSSL the verifier runs, and the test accepts either.
        try:
            counted = _certificate_count(root_path)
        except TsaError as exc:
            assert str(exc).startswith(uncounted)
        else:
            assert counted == 0
        with pytest.raises(TsaError) as caught:
            _load_trust_bundle(tree.records, reference, spec=spec)
        one = f"pinned TSA root PEM must hold exactly one certificate: {root_path}"
        assert str(caught.value).startswith(load_refusal(tree, alpha, uncounted)) or str(
            caught.value
        ).startswith(load_refusal(tree, alpha, one))
        return
    with pytest.raises(TsaError) as counting:
        _certificate_count(root_path)
    assert str(counting.value).startswith(uncounted)
    with pytest.raises(TsaError) as caught:
        _load_trust_bundle(tree.records, reference, spec=spec)
    assert str(caught.value).startswith(load_refusal(tree, alpha, uncounted))


@pytest.mark.parametrize(
    "label", ["TRUSTED CERTIFICATE", "X509 CERTIFICATE"], ids=["trusted", "x509"]
)
def test_accepts_a_root_pem_whose_one_object_wears_another_certificate_label(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...], label: str
) -> None:
    """The label stopped deciding anything once OpenSSL did the counting (F1).

    The superseded pattern could not tell a lone ``TRUSTED CERTIFICATE`` from
    the second object of a two-authority file, so it had to refuse both;
    ``openssl storeutl`` counts one here and two there. What such a file
    authorizes is settled by that count: ``openssl x509`` reads this one
    object as the certificate whose hashes the anchor declares -- asserted
    against the untouched root's pins -- and ``verify_timestamp_token``
    trusts the pinned file, which holds that object and nothing else, as
    the genuine token verified below exercises end to end.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    root_path, reference, spec = bundle_over_root_file(
        tree,
        alpha,
        name=f"single-{label.split()[0].lower()}.pem",
        content=relabel(alpha.tsa.root_pem.read_bytes(), label),
    )
    assert _certificate_count(root_path) == 1
    assert certificate_pins(root_path) == alpha.root_pins
    evidence = verify_timestamp_token(
        tree.record,
        claim_against(tree, reference, alpha, tree.tokens[alpha.anchor_id]),
        reference,
        spec=spec,
        records=tree.records,
    )
    assert evidence.trust_bundle_id == "tsa-anchors-v2"
    assert evidence.tsa_spki_sha256 == alpha.signer_pins["spkiSha256"]


def test_accepts_a_root_pem_whose_preamble_mentions_a_marker_mid_line(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """A marker inside a preamble line is text OpenSSL ignores (peer review, F1).

    An unanchored pattern counted "# Example: -----BEGIN PRIVATE KEY-----"
    as a second object and refused a valid single-certificate file (third
    gate). Nothing is pattern-matched now: OpenSSL reads the file and finds
    the one certificate, so the human-readable preamble distributors prepend
    to a published root costs nothing.
    """

    alpha = local_anchors[0]
    with_preamble = (
        b"# Example: -----BEGIN PRIVATE KEY----- is not an object here\n"
        + alpha.tsa.root_pem.read_bytes()
    )
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    root_path, reference, spec = bundle_over_root_file(
        tree, alpha, name="preamble-root.pem", content=with_preamble
    )
    assert _certificate_count(root_path) == 1
    _path, payload = _load_trust_bundle(tree.records, reference, spec=spec)
    assert payload["bundleId"] == "tsa-anchors-v2"


def _trusted_root(source: pathlib.Path, destination: pathlib.Path, flag: str) -> bytes:
    """Write ``source``'s certificate as a TRUSTED CERTIFICATE carrying one
    purpose setting (``-addtrust`` or ``-addreject``) for id-kp-timeStamping."""

    subprocess.run(
        [
            "openssl", "x509", "-in", str(source), flag, "1.3.6.1.5.5.7.3.8",
            "-trustout", "-out", str(destination),
        ],
        check=True,
        capture_output=True,
    )
    return destination.read_bytes()


@pytest.mark.parametrize(
    ("flag", "outcome"), [("-addreject", "refused"), ("-addtrust", "verified")]
)
def test_a_pinned_roots_auxiliary_trust_settings_apply_as_pinned(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...], flag: str, outcome: str
) -> None:
    """R4 (third gate, round three): the CAfile is the pinned bytes themselves.

    A pinned root written as a TRUSTED CERTIFICATE may carry X509_AUX purpose
    settings; ``openssl x509 -in ... -out ...`` emits a plain certificate and
    drops them, so re-encoding the root for the ``-CAfile`` laundered a root
    that explicitly rejects the timestamping purpose into one that permits
    it, and a token chained through it verified. With exactly one object
    counted by OpenSSL, the pinned file is handed to the verifications as it
    is: a root rejecting id-kp-timeStamping refuses the token, and one
    trusting it verifies.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    root_name = f"alpha-{outcome}.pem"
    trusted = _trusted_root(alpha.tsa.root_pem, tree.records / "trust" / root_name, flag)
    assert b"BEGIN TRUSTED CERTIFICATE" in trusted

    def point_at_the_trusted_root(entry: dict[str, Any]) -> None:
        entry["rootCertificate"]["path"] = f"records/trust/{root_name}"
        entry["rootCertificate"]["pemSha256"] = sha256_bytes(trusted)

    reference, spec = add_bundle_version(
        tree, local_anchors[:1], version=2, mutate_anchor=point_at_the_trusted_root
    )
    rewrite_witness(
        tree,
        lambda payload: payload.update(
            {
                "trustBundleId": "tsa-anchors-v2",
                "trustBundlePath": str(reference["path"]),
                "trustBundleSha256": reference["sha256"],
            }
        ),
    )
    active = {BUNDLE_LOGICAL: tree.reference, str(reference["path"]): reference}
    if outcome == "refused":
        with pytest.raises(TsaError, match="OpenSSL command failed"):
            verify_witness(
                tree.record, spec=spec, records=tree.records, trusted_bundles=active,
                transition_bundle_updates=[],
            )
    else:
        evidence = verify_witness(
            tree.record, spec=spec, records=tree.records, trusted_bundles=active,
            transition_bundle_updates=[],
        )
        assert evidence.status == "available"


def _plain_certificate(source: pathlib.Path, destination: pathlib.Path) -> bytes:
    """``source``'s certificate re-encoded plain: any X509_AUX settings dropped."""

    subprocess.run(
        ["openssl", "x509", "-in", str(source), "-out", str(destination)],
        check=True,
        capture_output=True,
    )
    return destination.read_bytes()


def swap_at_the_first_cafile(
    monkeypatch: pytest.MonkeyPatch, target: pathlib.Path, content: bytes
) -> list[str]:
    """Overwrite ``target`` the instant OpenSSL is about to be given a -CAfile.

    The concurrent writer the two regressions below model, arriving at the one
    moment that separates the fix from the head that lacked it: after every
    check on the pinned root has passed, and before the file is trusted.

    Interposed on ``_run_openssl`` rather than on a validation read, for two
    reasons. After the fix no validation read touches the repository path at
    all -- ``_certificate_count`` and ``_certificate_identity`` are handed the
    private snapshot -- so there is no longer a read there to interpose on.
    And the pinned root is validated afresh by every ``_root_material`` call,
    of which one verification makes several, so a swap installed at any
    earlier read is caught by the next call's PEM-hash refusal: a different
    refusal, and a weaker test than the one the finding asks for. The
    ``-CAfile`` command is the point of use, and the gap between validation
    and use is the whole of the finding.
    """

    original = tsa_module._run_openssl
    commands: list[str] = []

    def swapping(arguments: list[str], **keywords: Any) -> Any:
        if "-CAfile" in arguments:
            target.write_bytes(content)
            commands.append(arguments[0])
        return original(arguments, **keywords)

    monkeypatch.setattr(tsa_module, "_run_openssl", swapping)
    return commands


def openssl_failure_detail(message: str) -> str:
    """The OpenSSL diagnostic out of a ported ``OpenSSL command failed`` text.

    Each ``error:`` line OpenSSL prints is prefixed with the id of the thread
    that raised it -- sixteen hex digits on 3.0, which Ubuntu's CI runners
    carry, and a decimal on 1.1.1 -- so two runs of the same failure differ
    there and nowhere else. The prefix is stripped so the comparison is of
    what OpenSSL said, not of which thread said it.
    """

    detail = message.split("): ", 1)[1]
    return re.sub(r"^[0-9A-Fa-f]+:(?=error:)", "", detail, flags=re.MULTILINE)


def test_a_root_swapped_after_validation_is_not_what_gets_trusted(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S3-F1: the -CAfile is the validated bytes, not the path they came from.

    ``_root_material`` counted, hashed and described the pinned root through
    separate opens of a repository path, and ``verify_timestamp_token`` then
    handed that same path to ``openssl ts -verify -CAfile`` and ``openssl cms
    -verify -CAfile``. A writer with access to the repository could replace a
    validated ``TRUSTED CERTIFICATE`` that rejects the timestamping purpose
    with the plain form of the very same certificate: the PEM hash is the only
    pin that moves, and by then it has already been checked, so the
    certificate hash, the SPKI and the code identity all still describe the
    file -- and the rejection is gone. Asserted below from OpenSSL directly:
    the plain form accepts the token the pinned form refuses.

    Without the one-read snapshot the swapped file is the ``-CAfile``, the
    token verifies, and ``verify_timestamp_token`` returns evidence for a
    token the pinned root explicitly refuses to vouch for. With it the
    verification is given a private copy of the bytes it validated, and the
    swap changes what is on disk and nothing else: the refusal is the same
    one the file produces with no writer at all.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    rejecting = _trusted_root(
        alpha.tsa.root_pem, tmp_path / "rejecting.pem", "-addreject"
    )
    plain = _plain_certificate(tmp_path / "rejecting.pem", tmp_path / "plain.pem")
    root_path, reference, spec = bundle_over_root_file(
        tree, alpha, name="alpha-rejects-timestamping.pem", content=rejecting
    )
    token = tree.tokens[alpha.anchor_id]
    # The premise, from OpenSSL directly: the purpose rejection is the whole
    # difference between the two files, and it decides the token.
    assert b"BEGIN TRUSTED CERTIFICATE" in rejecting
    assert b"BEGIN TRUSTED CERTIFICATE" not in plain
    assert certificate_pins(tmp_path / "plain.pem") == certificate_pins(
        tmp_path / "rejecting.pem"
    )
    assert not openssl_ts_verifies(tree.record, token, tmp_path / "rejecting.pem")
    assert openssl_ts_verifies(tree.record, token, tmp_path / "plain.pem")

    claim = claim_against(tree, reference, alpha, token)
    with pytest.raises(TsaError) as unswapped:
        verify_timestamp_token(
            tree.record, claim, reference, spec=spec, records=tree.records
        )

    swapped_commands = swap_at_the_first_cafile(monkeypatch, root_path, plain)
    with pytest.raises(TsaError) as swapped:
        verify_timestamp_token(
            tree.record, claim, reference, spec=spec, records=tree.records
        )
    # The writer really did run, and really did change the pinned file.
    assert swapped_commands == ["ts"]
    assert root_path.read_bytes() == plain
    prefix = f"OpenSSL command failed ({TS_VERIFY_COMMAND} "
    assert str(unswapped.value).startswith(prefix)
    assert str(swapped.value).startswith(prefix)
    assert str(tree.records) not in openssl_command(str(swapped.value))
    assert openssl_failure_detail(str(swapped.value)) == openssl_failure_detail(
        str(unswapped.value)
    )


def test_a_second_authority_appended_after_the_count_is_not_trusted(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S3-F1: the count and the trust decision are about the same bytes.

    The other half of the same gap. ``openssl storeutl`` counted one
    certificate in the pinned file, and the two ``-CAfile`` verifications
    then re-read that path; a writer who appends a second authority in
    between gets a file that trusts two authorities and was counted as
    trusting one. The bundle here pins the first authority's root and allows
    the *second* authority's signer and policy, which is the shape that turns
    the swap into an acceptance rather than a later refusal -- every check but
    the chain passes, and the chain is exactly what the appended certificate
    supplies.

    Without the snapshot ``verify_timestamp_token`` returns evidence for a
    token issued by an authority the pinned root never vouched for. With it
    the ported chain refusal fires, because the file OpenSSL is given holds
    the one certificate that was counted.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    beta_signer = certificate_pins(beta.tsa.signer_pem)
    root_path, reference, spec = bundle_over_root_file(
        tree,
        alpha,
        name="alpha-root-alone.pem",
        content=alpha.tsa.root_pem.read_bytes(),
        signers={alpha.anchor_id: beta_signer},
        mutate_anchor=lambda entry: entry.__setitem__(
            "allowedPolicyOids", [beta.tsa.policy_oid]
        ),
    )
    combined = tmp_path / "alpha-root-and-a-second-authority.pem"
    combined.write_bytes(
        alpha.tsa.root_pem.read_bytes() + beta.tsa.root_pem.read_bytes()
    )
    beta_token = tree.records / RECORD_DAY / "record-0001.beta.tsr"
    beta.tsa.stamp(sha256_bytes(tree.record.read_bytes()), beta_token)
    # The premise, from OpenSSL and from the count directly.
    assert _certificate_count(root_path) == 1
    assert _certificate_count(combined) == 2
    assert not openssl_ts_verifies(tree.record, beta_token, root_path)
    assert openssl_ts_verifies(tree.record, beta_token, combined)

    claim = claim_against(
        tree,
        reference,
        alpha,
        beta_token,
        signer=beta_signer,
        policy_oid=beta.tsa.policy_oid,
    )
    with pytest.raises(TsaError) as unswapped:
        verify_timestamp_token(
            tree.record, claim, reference, spec=spec, records=tree.records
        )

    swapped_commands = swap_at_the_first_cafile(
        monkeypatch, root_path, combined.read_bytes()
    )
    with pytest.raises(TsaError) as swapped:
        verify_timestamp_token(
            tree.record, claim, reference, spec=spec, records=tree.records
        )
    assert swapped_commands == ["ts"]
    assert _certificate_count(root_path) == 2
    prefix = f"OpenSSL command failed ({TS_VERIFY_COMMAND} "
    assert str(unswapped.value).startswith(prefix)
    assert str(swapped.value).startswith(prefix)
    assert str(tree.records) not in openssl_command(str(swapped.value))
    assert openssl_failure_detail(str(swapped.value)) == openssl_failure_detail(
        str(unswapped.value)
    )


def swap_the_record_at_the_data_read(
    monkeypatch: pytest.MonkeyPatch, target: pathlib.Path, content: bytes
) -> list[bytes]:
    """Substitute ``content`` for ``target`` across ``openssl ts -verify``.

    The writer the record regression models: the witnessed record is left
    alone while its digest is taken, its creation claims are read and its
    sidecar is checked, replaced for exactly the read that decides whether
    the token covers it -- ``-data`` -- and restored the moment that read is
    over, so an auditor looking afterwards sees the record the evidence
    names. Returns what was put back, so a test can show the writer ran.
    """

    original = tsa_module._run_openssl
    restored: list[bytes] = []

    def swapping(arguments: list[str], **keywords: Any) -> Any:
        if arguments[:2] != ["ts", "-verify"]:
            return original(arguments, **keywords)
        kept = target.read_bytes()
        target.write_bytes(content)
        try:
            return original(arguments, **keywords)
        finally:
            target.write_bytes(kept)
            restored.append(kept)

    monkeypatch.setattr(tsa_module, "_run_openssl", swapping)
    return restored


def test_a_record_swapped_at_the_data_read_is_not_what_the_token_covered(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S4-F1: the imprint is recomputed over the bytes the witness digests.

    The witnessed record was consumed through four separate opens of one
    pathname -- hashed for the digest claim, parsed for the trust-bundle
    updates, parsed again for the creation claims, and finally read by
    ``openssl ts -verify -data`` to recompute the imprint the token signs.
    Only that last read decides whether the token is about the record at all,
    and it was the only one a writer had to catch. Here the token is a
    genuine stamp by the pinned authority over a *different* record, and the
    substitution lasts exactly as long as the ``-data`` read: everything the
    module checked before it saw the real record, and an auditor looking
    afterwards sees the real record too.

    Asserted from OpenSSL directly below: the token verifies over the
    substitute and not over the witnessed record. Without the one read the
    ``-data`` argument is the pathname, so OpenSSL is handed the substitute,
    every check passes and ``verify_timestamp_token`` returns ``TokenEvidence``
    for the record it was called about -- evidence that a record was
    timestamped, from a verification of some other bytes. With it the
    ``-data`` argument is the read the digest was taken from, the imprint
    disagrees, and no evidence is returned at all.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    witnessed = tree.record.read_bytes()
    substitute = (
        canonical_bytes(
            {
                "schemaVersion": "receipt_test_record_v1",
                "recordedAt": (datetime.now(UTC) - timedelta(seconds=90)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "observation": "the record this token is really about",
            }
        )
        + b"\n"
    )
    assert substitute != witnessed
    elsewhere = tmp_path / "the-substituted-record.json"
    elsewhere.write_bytes(substitute)
    token = tree.records / RECORD_DAY / "record-0001.substitute.tsr"
    alpha.tsa.stamp(sha256_bytes(substitute), token)
    # The premise, from OpenSSL directly: this token covers one of the two
    # records and it is not the witnessed one.
    assert openssl_ts_verifies(elsewhere, token, alpha.tsa.root_pem)
    assert not openssl_ts_verifies(tree.record, token, alpha.tsa.root_pem)

    claim = claim_against(tree, tree.reference, alpha, token)
    restored = swap_the_record_at_the_data_read(monkeypatch, tree.record, substitute)
    with pytest.raises(TsaError) as caught:
        verify_timestamp_token(
            tree.record, claim, tree.reference, spec=tree.spec, records=tree.records
        )
    # The writer really did run, and really did put the record back.
    assert restored == [witnessed]
    assert tree.record.read_bytes() == witnessed
    message = str(caught.value)
    assert message.startswith(f"OpenSSL command failed ({TS_VERIFY_COMMAND} ")
    assert str(tree.records) not in openssl_command(message)
    assert "ts_check_imprints:message imprint mismatch" in message


def test_a_direct_token_caller_takes_the_one_read_itself(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """S4-F1: ``record=`` is the witness path's read, not a new requirement.

    ``verify_witness`` reads the record once and hands the bytes down, so the
    digest it publishes and the imprint OpenSSL recomputes are the same read.
    A caller that verifies one token on its own has no such read to pass, and
    gets exactly the same evidence: the keyword is where the one read comes
    from, never a second contract. Without it there would be nothing for a
    direct caller to verify against at all.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    claim = token_claim(tree, alpha)
    evidence = verify_timestamp_token(
        tree.record, claim, tree.reference, spec=tree.spec, records=tree.records
    )
    assert evidence.anchor_id == alpha.anchor_id
    assert evidence.token_sha256 == sha256_bytes(
        tree.tokens[alpha.anchor_id].read_bytes()
    )
    assert evidence == verify_timestamp_token(
        tree.record,
        claim,
        tree.reference,
        spec=tree.spec,
        records=tree.records,
        record=tree.record.read_bytes(),
    )
    # And the read is a read: a record that is not there is refused by name.
    absent = tree.records / RECORD_DAY / "record-9999.json"
    with pytest.raises(TsaError) as caught:
        verify_timestamp_token(
            absent, claim, tree.reference, spec=tree.spec, records=tree.records
        )
    assert str(caught.value) == (
        f"witnessed record is missing or not a regular file: {absent}"
    )


def test_the_witness_digest_and_the_verified_imprint_come_from_one_read(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S4-F1: ``verify_witness``'s read is the read ``-data`` recomputes over.

    The regression above drives ``verify_timestamp_token`` directly, which
    proves the ``-data`` argument is a snapshot but says nothing about *whose*
    snapshot. What closes the finding is the hand-down: the bytes
    ``verify_witness`` hashed for the sidecar's ``digestSha256`` are the bytes
    the imprint is checked against, so the two cannot describe different
    files. Nothing binds that without this test -- ``record=`` can be dropped
    from every call site and the rest of the suite stays green.

    The witness here is exactly what a producer would write to exploit that:
    its ``digestSha256`` is the real record's, its declared token is a genuine
    stamp over a substitute, and the substitute is on disk for the duration of
    ``verify_timestamp_token`` and gone afterwards. With the hand-down the
    imprint is checked against the record the digest describes and the witness
    is refused; without it ``verify_timestamp_token`` re-reads the path, gets
    the substitute, and returns evidence whose ``digest_sha256`` names a
    record the timestamp was never over.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    witnessed = tree.record.read_bytes()
    substitute = (
        canonical_bytes(
            {
                "schemaVersion": "receipt_test_record_v1",
                "recordedAt": (datetime.now(UTC) - timedelta(seconds=90)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "observation": "the record the declared token is really about",
            }
        )
        + b"\n"
    )
    token = tree.tokens[alpha.anchor_id]
    alpha.tsa.stamp(sha256_bytes(substitute), token)
    rewrite_witness(
        tree,
        lambda payload: payload["anchorOutcomes"][0].__setitem__(
            "tokenSha256", sha256_bytes(token.read_bytes())
        ),
    )
    # The sidecar still describes the real record, so the digest check passes.
    assert json.loads(tree.witness.read_text())["digestSha256"] == sha256_bytes(
        witnessed
    )

    original = tsa_module._verify_timestamp_token

    def substituting(*arguments: Any, **keywords: Any) -> tuple[TokenEvidence, Any]:
        tree.record.write_bytes(substitute)
        try:
            return original(*arguments, **keywords)
        finally:
            tree.record.write_bytes(witnessed)

    monkeypatch.setattr(tsa_module, "_verify_timestamp_token", substituting)
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert tree.record.read_bytes() == witnessed
    message = str(caught.value)
    assert message.startswith(f"OpenSSL command failed ({TS_VERIFY_COMMAND} ")
    assert "ts_check_imprints:message imprint mismatch" in message


def test_verify_witness_refuses_a_record_it_cannot_read_once(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """S4-F1: the round's one new refusal, where both docstrings place it.

    ``verify_witness``'s read is the one the baseline let raise ``OSError``
    out of the hash, and it is the site the module and harness docstrings
    describe. Bound here rather than only through ``verify_timestamp_token``:
    reverting this read to ``path.read_bytes()`` otherwise leaves the whole
    offline suite green.

    The symlink is the second half of the rule. ``O_NOFOLLOW`` means the read
    is of the file the path names, not of whatever it points at, and the
    path-level check in front of it says so with the same words -- so a record
    that is a link to a record which verifies is refused all the same.
    """

    tree = build_witness_tree(tmp_path, local_anchors[:1])
    assert verify_tree(tree).status == "available"

    absent = tree.records / RECORD_DAY / "record-9999.json"
    with pytest.raises(TsaError) as missing:
        verify_witness(absent, spec=tree.spec, records=tree.records)
    assert str(missing.value) == (
        f"witnessed record is missing or not a regular file: {absent}"
    )

    linked = tree.records / RECORD_DAY / "record-0002.json"
    linked.symlink_to(tree.record.name)
    linked.with_suffix(".witness.json").write_bytes(tree.witness.read_bytes())
    assert linked.is_file() and linked.read_bytes() == tree.record.read_bytes()
    with pytest.raises(TsaError) as symlinked:
        verify_witness(linked, spec=tree.spec, records=tree.records)
    assert str(symlinked.value) == (
        f"witnessed record is missing or not a regular file: {linked}"
    )


def replace_with_a_fifo_after_the_path_check(
    monkeypatch: pytest.MonkeyPatch, victim: pathlib.Path
) -> list[str]:
    """Answer the path-level check about the real file, then make it a FIFO.

    The race the non-blocking open exists for, arriving at the one moment
    that opens it: ``Path.is_file`` is asked about a regular file and says so,
    and by the time ``os.open`` runs on that same name a FIFO is there
    instead. Every later check of the name is answered as the first one was,
    because the finding is about what the descriptor turns out to be and not
    about a screen that gets a second look. Returns the swap, so a test can
    show the writer ran.
    """

    real_is_file = pathlib.Path.is_file
    target = os.path.realpath(victim)
    swapped: list[str] = []

    def answering_then_swapping(self: pathlib.Path) -> bool:
        answer = real_is_file(self)
        if os.path.realpath(self) != target:
            return answer
        if not swapped:
            assert answer, "the victim was not a regular file to begin with"
            victim.unlink()
            os.mkfifo(victim)
            swapped.append(str(victim))
        return True

    monkeypatch.setattr(pathlib.Path, "is_file", answering_then_swapping)
    return swapped


@pytest.mark.parametrize("victim", ["record", "token", "root"])
def test_a_fifo_raced_in_after_the_path_check_refuses_without_blocking(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
    victim: str,
) -> None:
    """S5-F3: the one read opens without waiting, so a refusal arrives at all.

    ``_read_file_once`` opens before ``fstat`` can say what it opened, and the
    path-level check in front of it answers about a name rather than about the
    object the open will find. So a regular file replaced by a FIFO in that
    window is opened as a FIFO -- and a read-only open of a FIFO waits for a
    writer with no timeout. Without ``O_NONBLOCK`` the open never returns, the
    regular-file refusal below is never reached, and a verification that
    should have failed hangs; the alarm here is what turns that into a loud
    failure instead of a hung suite. With it the open returns a descriptor at
    once, ``fstat`` sees a FIFO, and the caller's own words come back.

    All three files this module reads once, because all three have the same
    window: the record, the claimed response, and the pinned root. The root's
    refusal arrives inside the load-time wrapper, which is where every root
    material failure has been carried since the anchors were validated at
    load; the wording it carries is the caller's, unchanged.
    """

    if not hasattr(os, "mkfifo"):
        pytest.skip("platform has no FIFOs")
    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    assert verify_tree(tree).status == "available"
    records = tree.records.resolve()
    root_path = records / "trust" / alpha.tsa.root_pem.name
    token_path = records / RECORD_DAY / tree.tokens[alpha.anchor_id].name
    targets = {
        "record": (
            tree.record,
            f"witnessed record is missing or not a regular file: {tree.record}",
        ),
        "token": (
            tree.tokens[alpha.anchor_id],
            f"witness token is missing for {tree.record}: {token_path}",
        ),
        "root": (
            tree.records / "trust" / alpha.tsa.root_pem.name,
            f"TSA anchor {alpha.anchor_id} in bundle {BUNDLE_ID} references root "
            "material that fails validation: pinned TSA root is missing or not "
            f"a regular file: {root_path}",
        ),
    }
    victim_path, expected = targets[victim]
    swapped = replace_with_a_fifo_after_the_path_check(monkeypatch, victim_path)

    def blocked(_signal: int, _frame: Any) -> None:
        raise RuntimeError("the open blocked: the non-blocking flag is gone")

    previous = signal.signal(signal.SIGALRM, blocked)
    signal.alarm(30)
    try:
        with pytest.raises(TsaError) as caught:
            verify_tree(tree)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    # The writer really did run, and what was opened really was a FIFO.
    assert swapped == [str(victim_path)]
    assert stat.S_ISFIFO(os.lstat(victim_path).st_mode)
    assert str(caught.value) == expected


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("crlf-broken.json", b'{\r\n  "a": 1,\r\n  oops\r\n}\r\n'),
        ("lf-broken.json", b'{\n  "a": 1,\n  oops\n}\n'),
        ("cr-only-broken.json", b'{\r  "a": 1,\r  oops\r}\r'),
        ("not-an-object.json", b"[1, 2]\n"),
        ("not-utf8.json", b'{"a": "\xff"}\n'),
    ],
    ids=["crlf", "lf", "cr", "array", "invalid-utf8"],
)
def test_the_one_reads_parse_refuses_exactly_as_the_ported_reader_does(
    tmp_path: pathlib.Path, name: str, payload: bytes
) -> None:
    """S4-F1: parsing the one read is ``load_json``'s parse, byte for byte.

    ``verify_witness`` reads the record once and parses those bytes where the
    ported reader opened the path a second time, so the two have to refuse a
    record in the same words. ``cannot read JSON`` carries ``json``'s own
    offset into the decoded string, and ``Path.read_text`` translates
    universal newlines before ``json`` counts: a ``bytes.decode`` that only
    resembled it moved the offset by one per CR, which is why the parse now
    goes through the same ``TextIOWrapper``. The CR cases are where the two
    came apart; the rest are the other branches of the same two refusals.
    """

    path = tmp_path / name
    path.write_bytes(payload)
    with pytest.raises(TsaError) as ported:
        tsa_module.load_json(path)
    with pytest.raises(TsaError) as one_read:
        tsa_module._record_payload(payload, path)
    assert str(one_read.value) == str(ported.value)


def alias_of(anchor: LocalAnchor, *, anchor_id: str) -> LocalAnchor:
    """The same authority under a second anchor id and endpoint.

    Everything a bundle declares about the two is identical -- root path, root
    hashes, allowed signer -- which is exactly the shape a bundle uses to look
    like two authorities while being one.
    """

    return dataclasses.replace(
        anchor,
        anchor_id=anchor_id,
        endpoint=f"https://{anchor_id}.timestamp.invalid/tsr",
    )


def record_token_verifications(
    monkeypatch: pytest.MonkeyPatch,
) -> list[dict[str, Any]]:
    """Watch every token a witness actually puts to OpenSSL.

    Interposed on the private ``_verify_timestamp_token``, which is where the
    body lives and which the public function delegates to, so one recorder
    sees the v2 path (which calls it for the timestamp identity beside the
    evidence) and the v1 path (which goes through the public function) alike.
    """

    original = tsa_module._verify_timestamp_token
    verified: list[dict[str, Any]] = []

    def recording(
        path: pathlib.Path,
        token_claim: dict[str, Any],
        bundle_reference: dict[str, Any],
        **keywords: Any,
    ) -> tuple[TokenEvidence, Any]:
        verified.append(dict(token_claim))
        return original(path, token_claim, bundle_reference, **keywords)

    monkeypatch.setattr(tsa_module, "_verify_timestamp_token", recording)
    return verified


def test_refuses_a_bundle_whose_two_anchors_allow_the_same_signer(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S3-F2: two anchor ids over one authority are not two witnesses.

    A v2 witness de-duplicated its outcomes by anchor id alone, so two anchors
    with distinct ids and endpoints but the same root and the same allowed
    signer both passed load -- each agrees with the identity scoped to it --
    and one RFC 3161 response, supplied under both outcomes, verified for
    both. The replay premise is executed below against a bundle version that
    configures the alias alone: the token stamped for the first id verifies,
    unaltered, as the second id's. Without this rule that same token under
    both outcomes of the two-anchor bundle is verified twice and reported as
    two independent ``TokenEvidence`` entries, which is precisely the
    coverage a multi-anchor bundle exists to require.

    Refused at load, before any outcome is read: the recorder below sees no
    token verification at all. A shared *root* with disjoint signers stays
    allowed, because the ported allowed-signer check binds a token to the
    signers of the anchor its outcome selects -- sharing the signer is what
    lets one token satisfy two anchors, and sharing the root alone does not.
    """

    alpha = local_anchors[0]
    alias = alias_of(alpha, anchor_id="alpha-alias-2026")
    tree = build_witness_tree(tmp_path, (alpha, alias))
    configured = json.loads(tree.bundle.read_text())["anchors"]
    assert [entry["id"] for entry in configured] == [alpha.anchor_id, alias.anchor_id]
    assert {entry["endpoint"] for entry in configured} == {
        alpha.endpoint,
        alias.endpoint,
    }
    assert configured[0]["rootCertificate"] == configured[1]["rootCertificate"]
    assert configured[0]["allowedSigners"] == configured[1]["allowedSigners"]

    # The replay itself, executed: one token, verified as the alias anchor's,
    # against a bundle version that configures the alias and nothing else.
    alias_only, alias_spec = add_bundle_version(tree, [alias], version=3)
    replayed = verify_timestamp_token(
        tree.record,
        claim_against(tree, alias_only, alias, tree.tokens[alpha.anchor_id]),
        alias_only,
        spec=alias_spec,
        records=tree.records,
    )
    assert replayed.anchor_id == alias.anchor_id
    assert replayed.token_sha256 == sha256_bytes(
        tree.tokens[alpha.anchor_id].read_bytes()
    )

    # And the witness that would have banked it twice.
    def put_one_token_under_both_outcomes(payload: dict[str, Any]) -> None:
        first, second = payload["anchorOutcomes"]
        for field in ("tokenPath", "tokenSha256"):
            second[field] = first[field]

    rewrite_witness(tree, put_one_token_under_both_outcomes)
    verified = record_token_verifications(monkeypatch)
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == (
        "TSA anchors share an allowed signer: "
        f"{alias.anchor_id}, {alpha.anchor_id}: {alpha.signer_pins['spkiSha256']}"
    )
    assert verified == []


def test_a_shared_root_with_disjoint_signers_is_still_two_anchors(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """S3-F2: the rule is about the signer, and stops exactly there.

    Two anchors issued under one root, each allowing a signing certificate the
    other does not, are two authorities for the purpose that matters: the
    ported allowed-signer check binds a token to the signers of the anchor its
    outcome selects, so neither anchor's outcome can be satisfied by the
    other's response. The bundle loads, each anchor verifies its own token,
    and each refuses the other's. The control that keeps the shared-signer
    rule from silently becoming a shared-root rule.
    """

    alpha = local_anchors[0]
    sibling = alias_of(alpha, anchor_id="alpha-sibling-2026")
    rotated = certificate_pins(rotated_alpha.signer_pem)
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    reference, spec = add_bundle_version(
        tree, [alpha, sibling], version=2, signers={sibling.anchor_id: rotated}
    )
    configured = json.loads(
        (tree.records / "trust" / "tsa-anchors-v2.json").read_text()
    )["anchors"]
    assert configured[0]["rootCertificate"] == configured[1]["rootCertificate"]
    assert configured[0]["allowedSigners"] != configured[1]["allowedSigners"]
    _path, payload = _load_trust_bundle(tree.records, reference, spec=spec)
    assert [entry["id"] for entry in payload["anchors"]] == [
        alpha.anchor_id,
        sibling.anchor_id,
    ]

    rotated_token = tree.records / RECORD_DAY / "record-0001.alpha-sibling-2026.tsr"
    rotated_alpha.stamp(sha256_bytes(tree.record.read_bytes()), rotated_token)
    own = ((alpha, tree.tokens[alpha.anchor_id], alpha.signer_pins),
           (sibling, rotated_token, rotated))

    def verified_by(
        anchor: LocalAnchor, token: pathlib.Path, signer: dict[str, str]
    ) -> TokenEvidence:
        return verify_timestamp_token(
            tree.record,
            claim_against(tree, reference, anchor, token, signer=signer),
            reference,
            spec=spec,
            records=tree.records,
        )

    for anchor, token, signer in own:
        assert verified_by(anchor, token, signer).anchor_id == anchor.anchor_id
    # And neither anchor's outcome can be met by the other's response.
    for anchor, (_owner, token, signer) in ((alpha, own[1]), (sibling, own[0])):
        with pytest.raises(TsaError, match="RFC 3161 token signer is not pinned"):
            verified_by(anchor, token, signer)


def test_refuses_one_token_supplied_under_two_anchor_outcomes(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S3-F2: an outcome is covered by its own response or by none.

    Outcomes were de-duplicated by anchor id and the token was left free, so
    one response could be offered under every outcome of a bundle. The rule is
    about coverage, not about cryptography, and that is what this binds: the
    refusal names the reused digest and fires at the second outcome, before
    that outcome's token is put to OpenSSL at all -- the recorder sees one
    verification, the first outcome's. It is the file rule that fires here,
    because both outcomes name the same bytes; the signed-token rule below is
    the one for two files carrying one token. Two authorities with distinct roots is
    the case where the reuse would have been caught later anyway, though by a
    check about the token rather than about coverage (with the rule removed
    this witness refuses on the policy the copied claim declares), and binding
    the earlier refusal is what says the rule does not depend on that
    accident; the cases where reuse would otherwise be *accepted* are the
    shared-signer bundle above and the supplemental outcome below.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    tree = build_witness_tree(tmp_path, local_anchors[:2])
    assert verify_tree(tree).status == "available"
    reused = sha256_bytes(tree.tokens[alpha.anchor_id].read_bytes())

    def put_alphas_token_under_betas_outcome(payload: dict[str, Any]) -> None:
        first, second = payload["anchorOutcomes"]
        assert (first["tsaAnchorId"], second["tsaAnchorId"]) == (
            alpha.anchor_id,
            beta.anchor_id,
        )
        for field in _TOKEN_FIELDS:
            second[field] = first[field]

    rewrite_witness(tree, put_alphas_token_under_betas_outcome)
    verified = record_token_verifications(monkeypatch)
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == (
        f"duplicate TSA response file across anchor outcomes: {reused}"
    )
    assert [claim["tsaAnchorId"] for claim in verified] == [alpha.anchor_id]


def record_one_reads(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every path ``_read_file_once`` is asked for, in the order it is asked."""

    original = tsa_module._read_file_once

    def recording(path: pathlib.Path, missing: str) -> bytes:
        reads.append(str(path))
        return original(path, missing)

    reads: list[str] = []
    monkeypatch.setattr(tsa_module, "_read_file_once", recording)
    return reads


def serve_a_second_response_from_one_path(
    monkeypatch: pytest.MonkeyPatch, target: pathlib.Path, content: bytes
) -> list[str]:
    """Rewrite ``target`` once the first outcome has finished reading it.

    The concurrent writer the path regression models. Each outcome reads the
    response path for itself, so a writer between the two reads decides what
    the second one finds; this arrives at the first ``openssl ts -verify``,
    which is after the first outcome has taken its one read and snapshotted
    it, so nothing about that outcome's verification moves. Returns the write,
    so a test can show the writer ran.
    """

    original = tsa_module._run_openssl
    writes: list[str] = []

    def writing(arguments: list[str], **keywords: Any) -> Any:
        if arguments[:2] == ["ts", "-verify"] and not writes:
            target.write_bytes(content)
            writes.append(str(target))
        return original(arguments, **keywords)

    monkeypatch.setattr(tsa_module, "_run_openssl", writing)
    return writes


def without_the_records_prefix(logical: str) -> str:
    """The second spelling ``physical_path`` maps onto the same file.

    A declared token path may or may not carry the leading ``records``
    component; ``physical_path`` strips it when it is there, so one file has
    two logical spellings a witness could use for it.
    """

    parts = pathlib.PurePosixPath(logical).parts
    assert parts[0] == "records"
    return str(pathlib.PurePosixPath(*parts[1:]))


@pytest.mark.parametrize("spelling", ["as-declared", "without-records-prefix"])
def test_refuses_two_outcomes_that_name_one_response_path(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
    spelling: str,
) -> None:
    """S5-F4: one file cannot be two outcomes' evidence, whatever it holds.

    The digest rule counts what outcomes *say* is in their files, so two
    outcomes naming one path with two different digests passed it. Each
    outcome then reads that path for itself, and a writer with access to the
    records tree serves one valid response to the first read and another to
    the second: here the first outcome reads the first authority's genuine
    stamp, the writer arrives while that outcome is being verified, and the
    second outcome reads the second authority's genuine stamp from the same
    name. Both declared digests are true of what was read, both tokens verify
    under their own anchors, and the evidence describes a repository state
    that never existed -- one file holding two responses at once.

    Without the path rule that witness returns two ``TokenEvidence`` entries
    covering a two-anchor bundle out of one file. With it the second outcome
    is refused on the path before its response is read at all: the read
    recorder below shows one read of the shared name, and the verification
    recorder shows one outcome verified. The control is the same tree
    untouched -- two outcomes at two paths are still two tokens.

    The second parameter is the same attack spelling the shared path the
    other way ``physical_path`` accepts it, which is what says the rule
    compares the file a claim resolves to and not the string it is written
    as: comparing the declared strings lets that spelling through.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    tree = build_witness_tree(tmp_path, local_anchors[:2])
    shared = tree.tokens[alpha.anchor_id]
    betas_response = tree.tokens[beta.anchor_id].read_bytes()

    # The control: two outcomes, two files, two tokens.
    control = verify_tree(tree)
    assert [token.anchor_id for token in control.tokens] == [
        alpha.anchor_id,
        beta.anchor_id,
    ]
    assert control.tokens[0].token_path != control.tokens[1].token_path
    # The premise, from OpenSSL directly: what the writer serves at the second
    # read is a genuine stamp over this record by the second authority.
    assert openssl_ts_verifies(
        tree.record, tree.tokens[beta.anchor_id], beta.tsa.root_pem
    )
    assert betas_response != shared.read_bytes()

    def point_betas_outcome_at_alphas_file(payload: dict[str, Any]) -> None:
        first, second = payload["anchorOutcomes"]
        assert (first["tsaAnchorId"], second["tsaAnchorId"]) == (
            alpha.anchor_id,
            beta.anchor_id,
        )
        declared = first["tokenPath"]
        second["tokenPath"] = (
            declared
            if spelling == "as-declared"
            else without_the_records_prefix(declared)
        )
        second["tokenSha256"] = sha256_bytes(betas_response)

    rewrite_witness(tree, point_betas_outcome_at_alphas_file)
    writes = serve_a_second_response_from_one_path(monkeypatch, shared, betas_response)
    reads = record_one_reads(monkeypatch)
    verified = record_token_verifications(monkeypatch)
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    # The writer really did run, and really did change the shared file.
    assert writes == [str(shared)]
    assert shared.read_bytes() == betas_response
    physical = tree.records.resolve() / RECORD_DAY / shared.name
    assert str(caught.value) == (
        f"duplicate TSA token path across anchor outcomes: {physical}"
    )
    # Refused before the second read, and before the second verification.
    assert reads.count(str(physical)) == 1
    assert [claim["tsaAnchorId"] for claim in verified] == [alpha.anchor_id]


def pending_authority(
    tree: WitnessTree,
    anchor: LocalAnchor,
    *,
    version: int,
    base: TsaSpec | None = None,
) -> tuple[dict[str, Any], TsaSpec]:
    """A further bundle version introducing ``anchor`` as a pending authority.

    Its root goes into the tree's trust directory, which the tree stocked for
    its active anchors alone. A pending anchor is a supplemental candidate
    only where the chain does not already trust it -- neither under its
    ``(id, root SPKI)`` pair nor through a signer an active anchor allows --
    so every caller here passes an authority with a root and a signing
    certificate of its own.
    """

    (tree.records / "trust" / anchor.tsa.root_pem.name).write_bytes(
        anchor.tsa.root_pem.read_bytes()
    )
    return add_bundle_version(tree, [anchor], version=version, base=base)


def supplemental_outcome(
    tree: WitnessTree,
    pending: Mapping[str, Any],
    anchor: LocalAnchor,
    token: pathlib.Path,
) -> dict[str, Any]:
    """One ``supplementalOutcomes`` member offering ``token`` for ``anchor``.

    Everything a witness says about a response, for the anchor a pending
    bundle introduces: the bundle it belongs to, the anchor it answers for,
    the file, and what that anchor's own authority stamped it with.
    """

    return {
        "role": "pending_trust_bundle",
        "status": "available",
        "trustBundleId": pending["bundleId"],
        "trustBundlePath": pending["path"],
        "trustBundleSha256": pending["sha256"],
        "tsaAnchorId": anchor.anchor_id,
        "tsa": anchor.endpoint,
        "tokenPath": logical_path(tree.records, token),
        "tokenSha256": sha256_bytes(token.read_bytes()),
        "tsaPolicyOid": anchor.tsa.policy_oid,
        "tsaImprintAlgorithmOid": SHA256_IMPRINT_OID,
        "tsaSignerCertificateSha256": anchor.signer_pins["certificateSha256"],
        "tsaSignerSpkiSha256": anchor.signer_pins["spkiSha256"],
    }


def test_refuses_a_token_reused_between_a_primary_and_a_supplemental_outcome(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S3-F2: the rules span the primary and supplemental outcomes together.

    A supplemental outcome answers for an authority a pending trust transition
    is about to activate, and it is evidence about the same record, so a
    response that has already stood for a primary outcome cannot stand for it
    too. The control below is the transition as it should arrive: the pending
    authority answers with a response of its own, and the witness verifies
    with one token and one supplemental token. Offer the primary outcome's
    response instead and, without a rule counting across both lists, the
    pending authority is admitted on evidence it never produced.

    Two of the three rules see this reuse -- one file named twice, one digest
    declared twice -- and the digest rule speaks, because it is checked first
    and both are checked before either outcome's response is read. What
    neither would see if they were scoped to one list is the point: the seen
    sets are built across the primary loop and the supplemental one.

    The pending anchor is the *second* authority, root and signing certificate
    both, because a pending anchor whose signer an active anchor already
    allows is that active authority under a new name and is no longer a
    candidate at all (S5-F2). That also means the reused response cannot
    verify under the pending anchor even if the rules let it through -- its
    signer is not pinned there -- so what this binds is the coverage rule and
    the point in the sequence it fires at, which is before any of that.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    incoming = alias_of(beta, anchor_id="beta-incoming-2026")
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    pending, spec = pending_authority(tree, incoming, version=2)
    primary = json.loads(tree.witness.read_text())["anchorOutcomes"][0]

    def supplemental_over(token: pathlib.Path) -> dict[str, Any]:
        return supplemental_outcome(tree, pending, incoming, token)

    def transition() -> WitnessEvidence:
        return verify_witness(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            transition_bundle_updates=[pending],
        )

    # The control: the pending authority answers with a response of its own,
    # and the transition verifies.
    own_token = tree.records / RECORD_DAY / "record-0001.beta-incoming-2026.tsr"
    beta.tsa.stamp(sha256_bytes(tree.record.read_bytes()), own_token)
    assert sha256_bytes(own_token.read_bytes()) != primary["tokenSha256"]
    rewrite_witness(
        tree,
        lambda payload: payload.__setitem__(
            "supplementalOutcomes", [supplemental_over(own_token)]
        ),
    )
    evidence = transition()
    assert evidence.status == "available"
    assert [token.anchor_id for token in evidence.tokens] == [alpha.anchor_id]
    assert [token.anchor_id for token in evidence.supplemental_tokens] == [
        incoming.anchor_id
    ]
    # Two authorities' stamps of one digest are two tokens by every identity:
    # distinct paths, distinct files, and -- asked of OpenSSL rather than of
    # the module under test -- distinct signed TSTInfos.
    assert evidence.tokens[0].token_path != evidence.supplemental_tokens[0].token_path
    assert (
        evidence.tokens[0].token_sha256
        != evidence.supplemental_tokens[0].token_sha256
    )
    assert signed_timestamp_of(
        tmp_path, tree.tokens[alpha.anchor_id]
    ) != signed_timestamp_of(tmp_path, own_token)

    # And the reuse the rules refuse.
    rewrite_witness(
        tree,
        lambda payload: payload.__setitem__(
            "supplementalOutcomes",
            [supplemental_over(tree.tokens[alpha.anchor_id])],
        ),
    )
    verified = record_token_verifications(monkeypatch)
    with pytest.raises(TsaError) as caught:
        transition()
    assert str(caught.value) == (
        f"duplicate TSA response file across anchor outcomes: {primary['tokenSha256']}"
    )
    assert [claim["tsaAnchorId"] for claim in verified] == [alpha.anchor_id]


def test_a_pending_anchor_renaming_an_active_authority_is_not_supplemental(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S5-F2: a new name over an active signing key is not a new authority.

    ``_supplemental_candidates`` keyed the active set by ``(anchor id, root
    SPKI)``, so a pending bundle putting the active root and the active signer
    behind a *new* id was a candidate. ``_load_trust_bundle`` already refuses
    two anchors of one bundle that allow the same signer -- one authority
    under two names -- and this is that same shape spread across an active
    bundle and a pending one: the transition then demanded a supplemental
    outcome the active authority could satisfy by stamping twice, and one
    authority's two stamps read as coverage by two.

    Without the signer half of the rule, the witness below is refused for
    carrying no supplemental outcome for the rename, and a witness that offers
    one -- with a second genuine stamp by the active authority -- verifies and
    reports two authorities' worth of evidence. With it the rename is skipped,
    the witness needs nothing extra, and an offered supplemental outcome is
    refused by the ported message for an outcome no pending transition
    introduces. The recorder shows that refusal arrives before the second
    stamp is put to OpenSSL at all.
    """

    alpha = local_anchors[0]
    renamed = alias_of(alpha, anchor_id="alpha-renamed-2026")
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    pending, spec = add_bundle_version(tree, [renamed], version=2)
    active = json.loads(tree.bundle.read_text())["anchors"]
    incoming = json.loads(
        (tree.records / "trust" / "tsa-anchors-v2.json").read_text()
    )["anchors"]
    # The premise: a new id over the active root and the active signer.
    assert incoming[0]["id"] != active[0]["id"]
    assert incoming[0]["rootCertificate"] == active[0]["rootCertificate"]
    assert incoming[0]["allowedSigners"] == active[0]["allowedSigners"]

    def transition() -> WitnessEvidence:
        return verify_witness(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            transition_bundle_updates=[pending],
        )

    # Nothing supplemental is required of the witness as it stands.
    evidence = transition()
    assert evidence.status == "available"
    assert [token.anchor_id for token in evidence.tokens] == [alpha.anchor_id]
    assert evidence.supplemental_tokens == ()

    # And a second genuine stamp by the active authority, offered as the
    # rename's own evidence, is refused as an outcome no transition introduces.
    second_stamp = tree.records / RECORD_DAY / "record-0001.alpha-renamed-2026.tsr"
    alpha.tsa.stamp(sha256_bytes(tree.record.read_bytes()), second_stamp)
    rewrite_witness(
        tree,
        lambda payload: payload.__setitem__(
            "supplementalOutcomes",
            [supplemental_outcome(tree, pending, renamed, second_stamp)],
        ),
    )
    verified = record_token_verifications(monkeypatch)
    with pytest.raises(TsaError) as caught:
        transition()
    assert str(caught.value) == (
        "supplemental TSA outcome is not introduced by a pending trust "
        f"transition: ('{pending['path']}', '{renamed.anchor_id}')"
    )
    assert [claim["tsaAnchorId"] for claim in verified] == [alpha.anchor_id]


def test_a_genuinely_new_authority_is_still_a_supplemental_candidate(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """S5-F2: the signer rule skips a rename, and stops exactly there.

    Three pending anchors, one per shape the rule has to tell apart. A second
    authority with a root and a signing certificate of its own shares no
    signer with anything active and is a candidate, so the transition is
    refused until the witness answers for it -- which is the whole mechanism
    the rename above must not be able to walk around. A signer rotation
    reuses the active id under the active root and is skipped by the
    ``(id, root SPKI)`` half, as it always was; that half is why the signer
    rule cannot simply be "any signer not already active is new", because a
    rotation's signer is exactly that and every rotation would then demand a
    supplemental outcome. And a new id over the active root with a *rotated*
    signer is a candidate too: the id and root pair is new, and the signing
    key is one no active anchor allows.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    rotated = certificate_pins(rotated_alpha.signer_pem)
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    stranger = alias_of(beta, anchor_id="beta-arriving-2026")
    unrelated, spec = pending_authority(tree, stranger, version=2)
    rotation, rotation_spec = add_bundle_version(
        tree,
        local_anchors[:1],
        version=3,
        signers={alpha.anchor_id: rotated},
        base=spec,
    )
    renamed_and_rotated, spec = add_bundle_version(
        tree,
        [alias_of(alpha, anchor_id="alpha-renamed-2026")],
        version=4,
        signers={"alpha-renamed-2026": rotated},
        base=rotation_spec,
    )

    def candidates_for(*pending: dict[str, Any]) -> set[tuple[str, str]]:
        return set(
            tsa_module._supplemental_candidates(
                tree.records,
                {BUNDLE_LOGICAL: tree.reference},
                list(pending),
                spec=spec,
            )
        )

    assert candidates_for(unrelated) == {(unrelated["path"], stranger.anchor_id)}
    assert candidates_for(rotation) == set()
    assert candidates_for(renamed_and_rotated) == {
        (renamed_and_rotated["path"], "alpha-renamed-2026")
    }
    # And the candidate really does reach the ported refusal.
    with pytest.raises(TsaError) as caught:
        verify_witness(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            transition_bundle_updates=[unrelated],
        )
    assert str(caught.value) == (
        "supplemental TSA outcome mismatch: "
        f"missing=[('{unrelated['path']}', '{stranger.anchor_id}')], extra=[]"
    )


def swap_the_token_at_the_first_read(
    monkeypatch: pytest.MonkeyPatch, target: pathlib.Path, content: bytes
) -> list[str]:
    """Overwrite ``target`` the instant OpenSSL is about to read a response.

    ``openssl ts -reply`` is the first thing done with a claimed token, and it
    used to be done to the pathname the declared digest had been taken from
    through an earlier open. This is the writer who arrives in that gap.
    """

    original = tsa_module._run_openssl
    reads: list[str] = []

    def swapping(arguments: list[str], **keywords: Any) -> Any:
        if arguments[:2] == ["ts", "-reply"]:
            target.write_bytes(content)
            reads.append(arguments[1])
        return original(arguments, **keywords)

    monkeypatch.setattr(tsa_module, "_run_openssl", swapping)
    return reads


def test_a_token_swapped_after_its_hash_check_is_not_what_gets_verified(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S4-F2: the response OpenSSL reads is the one the digest was taken from.

    ``tokenSha256`` was computed from one open of the response's pathname and
    ``openssl ts -reply`` and ``openssl ts -verify`` then made two more, so
    the digest an auditor is shown described the file at an earlier instant
    than the one the verification read. A writer with access to the records
    tree could let the hash check pass on the response the witness declares
    and hand the verifications a different one -- and both responses here are
    genuine stamps by the pinned authority over this very record, so the
    substituted one verifies just as well and nothing downstream objects.

    The two are distinguishable, asserted below: a second issuance carries its
    own serial, so its signed token has its own digest, which is the private
    identity ``_verify_timestamp_token`` returns beside the evidence. Without
    the one read the swap moves that identity while ``token_sha256`` goes on
    naming the file the witness declared, which is evidence about two
    different responses in one record. With it the verifications are given a
    private copy of the bytes that were hashed, and the swap changes what is
    on disk and nothing else -- the evidence and the identity both come back
    unmoved.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    claimed = tree.tokens[alpha.anchor_id]
    substitute = tree.records / RECORD_DAY / "record-0001.second-issuance.tsr"
    alpha.tsa.stamp(sha256_bytes(tree.record.read_bytes()), substitute)
    assert sha256_bytes(substitute.read_bytes()) != sha256_bytes(claimed.read_bytes())

    claim = token_claim(tree, alpha)

    def verified(against: dict[str, Any]) -> tuple[TokenEvidence, Any]:
        return tsa_module._verify_timestamp_token(
            tree.record, against, tree.reference, spec=tree.spec, records=tree.records
        )

    unswapped, unswapped_identity = verified(claim)
    # The public entry point returns exactly that evidence, and only it.
    assert (
        verify_timestamp_token(
            tree.record, claim, tree.reference, spec=tree.spec, records=tree.records
        )
        == unswapped
    )
    # The premise: the substitute is a response of its own, and the identity
    # of what it carries says so.
    _substituted, substituted_identity = verified(
        claim_against(tree, tree.reference, alpha, substitute)
    )
    assert substituted_identity != unswapped_identity

    reads = swap_the_token_at_the_first_read(
        monkeypatch, claimed, substitute.read_bytes()
    )
    swapped, swapped_identity = verified(claim)
    # The writer really did run, and really did change the declared file.
    assert reads == ["-reply"]
    assert claimed.read_bytes() == substitute.read_bytes()
    assert swapped == unswapped
    assert swapped_identity == unswapped_identity
    assert swapped.token_sha256 == claim["tokenSha256"]


def der_length(length: int) -> bytes:
    """A DER definite-length octet string for ``length``."""

    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + der_length(len(content)) + content


def rewrap_timestamp_response(response: bytes, note: str) -> bytes:
    """The same signed token in a second ``TimeStampResp``, carrying ``note``.

    ::

        TimeStampResp  ::= SEQUENCE { status PKIStatusInfo,
                                      timeStampToken TimeStampToken OPTIONAL }
        PKIStatusInfo  ::= SEQUENCE { status PKIStatus,
                                      statusString PKIFreeText OPTIONAL,
                                      failInfo PKIFailureInfo OPTIONAL }
        PKIFreeText    ::= SEQUENCE SIZE (1..MAX) OF UTF8String

    Nothing signed is touched: the ``TimeStampToken`` is copied across byte
    for byte and only the wrapper's optional ``statusString`` is added, which
    is exactly the freedom a producer has. The result is a second file, with
    its own SHA-256, that ``openssl ts -reply -token_out`` extracts the
    identical token from -- asserted in the test below rather than assumed.
    """

    tag, body, end = _read_der_tlv(response, 0)
    assert tag == 0x30 and end == len(response), "not one complete SEQUENCE"
    status_tag, status, offset = _read_der_tlv(body, 0)
    assert status_tag == 0x30, "PKIStatusInfo is not a SEQUENCE"
    token = body[offset:]
    integer_tag, _status_value, integer_end = _read_der_tlv(status, 0)
    assert integer_tag == 0x02, "PKIStatus is not an INTEGER"
    assert integer_end == len(status), "PKIStatusInfo already carries an option"
    free_text = der_tlv(0x30, der_tlv(0x0C, note.encode("utf-8")))
    return der_tlv(0x30, der_tlv(0x30, status[:integer_end] + free_text) + token)


def run_openssl_here(arguments: list[str]) -> None:
    """One OpenSSL call, for the premises a test asks OpenSSL directly."""

    subprocess.run(
        ["openssl", *arguments],
        check=True,
        capture_output=True,
        env={**os.environ, "OPENSSL_CONF": "/dev/null", "LC_ALL": "C"},
    )


def extracted_token_of(directory: pathlib.Path, response: pathlib.Path) -> bytes:
    """The ``TimeStampToken`` OpenSSL extracts from a ``TimeStampResp`` file."""

    extracted = directory / f"{response.stem}.token.der"
    run_openssl_here(
        ["ts", "-reply", "-config", "/dev/null",
         "-in", str(response), "-token_out", "-out", str(extracted)]
    )
    return extracted.read_bytes()


def signed_timestamp_of(directory: pathlib.Path, response: pathlib.Path) -> bytes:
    """The DER ``TSTInfo`` the authority signed, out of a response file.

    What the private ``_TimestampIdentity`` is a digest of, obtained the way
    an auditor would: two OpenSSL calls, with no help from the module under
    test.
    """

    token = directory / f"{response.stem}.token.der"
    extracted = directory / f"{response.stem}.tstinfo.der"
    run_openssl_here(
        ["ts", "-reply", "-config", "/dev/null",
         "-in", str(response), "-token_out", "-out", str(token)]
    )
    run_openssl_here(
        ["cms", "-verify", "-inform", "DER", "-in", str(token),
         "-noverify", "-nosigs", "-out", str(extracted)]
    )
    return extracted.read_bytes()


def der_certificate(pem: pathlib.Path, out: pathlib.Path) -> bytes:
    """One certificate's DER, for splicing into a token's certificate bag."""

    run_openssl_here(["x509", "-in", str(pem), "-outform", "DER", "-out", str(out)])
    return out.read_bytes()


def der_elements(content: bytes) -> list[tuple[int, bytes, bytes]]:
    """Every ``(tag, value, whole)`` triple in one DER SEQUENCE's content."""

    found: list[tuple[int, bytes, bytes]] = []
    offset = 0
    while offset < len(content):
        tag, value, end = _read_der_tlv(content, offset)
        found.append((tag, value, content[offset:end]))
        offset = end
    return found


def add_certificate_to_token_bag(response: bytes, certificate: bytes) -> bytes:
    """The same signed ``TSTInfo``, in a token carrying one more certificate.

    ::

        TimeStampToken ::= ContentInfo { contentType, [0] EXPLICIT SignedData }
        SignedData     ::= SEQUENCE { version, digestAlgorithms,
                                      encapContentInfo,
                                      certificates [0] IMPLICIT OPTIONAL,
                                      crls [1] IMPLICIT OPTIONAL, signerInfos }

    ``certificates`` sits outside the ``SignerInfo`` signature, as ``crls``
    and ``unsignedAttrs`` do, so appending to the bag is a producer's to do
    and leaves the signature, the signer and the ``TSTInfo`` untouched. The
    response file's digest moves, the extracted token's digest moves, and the
    timestamp does not -- which is the whole of why the coverage rule counts
    the ``TSTInfo``. The test below asks OpenSSL for each half of that rather
    than assuming it.
    """

    tag, body, end = _read_der_tlv(response, 0)
    assert tag == 0x30 and end == len(response), "not one complete SEQUENCE"
    status_tag, _status, offset = _read_der_tlv(body, 0)
    assert status_tag == 0x30, "PKIStatusInfo is not a SEQUENCE"
    status_bytes, token = body[:offset], body[offset:]
    tag, content_info, _end = _read_der_tlv(token, 0)
    assert tag == 0x30, "TimeStampToken is not a SEQUENCE"
    (oid_tag, _oid, oid_raw), (explicit_tag, explicit, _raw) = der_elements(content_info)[:2]
    assert oid_tag == 0x06 and explicit_tag == 0xA0, "not a CMS ContentInfo"
    tag, signed_data, _end = _read_der_tlv(explicit, 0)
    assert tag == 0x30, "SignedData is not a SEQUENCE"
    parts = der_elements(signed_data)
    tags = [tag for tag, _value, _raw in parts]
    assert 0xA0 in tags, "the token carries no certificates to add to"
    index = tags.index(0xA0)
    bag = der_tlv(0xA0, parts[index][1] + certificate)
    rebuilt = der_tlv(
        0x30,
        b"".join(bag if i == index else raw for i, (_t, _v, raw) in enumerate(parts)),
    )
    return der_tlv(
        0x30, status_bytes + der_tlv(0x30, oid_raw + der_tlv(0xA0, rebuilt))
    )


def two_pending_authorities(
    tree: WitnessTree, anchor: LocalAnchor
) -> tuple[dict[str, Any], LocalAnchor, dict[str, Any], LocalAnchor, TsaSpec]:
    """Two pending bundles, each introducing ``anchor`` under its own id.

    The one shape in which two outcomes of one witness can both be satisfied
    by one response and both verify. A bundle may not allow one signer under
    two of its anchors, and a pending anchor whose signer an active anchor
    already allows is that authority renamed and never becomes a candidate at
    all (S5-F2) -- so the two outcomes that can share a signer are two
    *supplemental* ones, introduced by two separate pending bundles, neither
    of which the active chain knows. Both are candidates, both demand their
    own response, and whether they get two is what the duplicate rules decide.
    """

    first = alias_of(anchor, anchor_id=f"{anchor.anchor_id}-first")
    second = alias_of(anchor, anchor_id=f"{anchor.anchor_id}-second")
    pending_first, spec = pending_authority(tree, first, version=2)
    pending_second, spec = pending_authority(tree, second, version=3, base=spec)
    return pending_first, first, pending_second, second, spec


def test_refuses_a_re_wrapped_response_offered_as_a_second_token(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S4-F2: what covers an outcome is the signed token, not the file.

    A ``TimeStampResp`` is a signed ``TimeStampToken`` inside an unsigned
    ``PKIStatusInfo`` wrapper, and the wrapper is the producer's to write: an
    optional ``statusString`` inserted into it changes the file's SHA-256 and
    nothing the authority signed. So counting responses by ``tokenSha256``
    counted files, and one genuine token in two wrappers was two tokens by
    that count -- enough to cover two pending authorities' outcomes with one
    response, which is the case the coverage rules exist for. The path rule
    cannot see it either: two files, two paths.

    Both halves of the premise are asked of OpenSSL directly below: the two
    files have different digests, and ``ts -reply -token_out`` extracts
    identical bytes from them. Without the signed-token identity the
    transition verifies with two supplemental tokens resting on one response;
    with it the second is refused by the digest of what was actually signed,
    after its token is verified because that is the earliest the identity is
    known -- the recorder shows all three verifications ran.
    """

    beta = local_anchors[1]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    pending_first, first, pending_second, second, spec = two_pending_authorities(
        tree, beta
    )
    claimed = tree.records / RECORD_DAY / "record-0001.beta-first.tsr"
    beta.tsa.stamp(sha256_bytes(tree.record.read_bytes()), claimed)
    rewrapped = tree.records / RECORD_DAY / "record-0001.beta-second.tsr"
    rewrapped.write_bytes(
        rewrap_timestamp_response(
            claimed.read_bytes(), "re-wrapped, and signed by nobody"
        )
    )
    # The premise, from OpenSSL directly: two files, one signed token.
    assert sha256_bytes(rewrapped.read_bytes()) != sha256_bytes(claimed.read_bytes())
    assert extracted_token_of(tmp_path, rewrapped) == extracted_token_of(
        tmp_path, claimed
    )
    signed = signed_timestamp_of(tmp_path, claimed)
    assert signed_timestamp_of(tmp_path, rewrapped) == signed

    rewrite_witness(
        tree,
        lambda payload: payload.__setitem__(
            "supplementalOutcomes",
            [
                supplemental_outcome(tree, pending_first, first, claimed),
                supplemental_outcome(tree, pending_second, second, rewrapped),
            ],
        ),
    )
    verified = record_token_verifications(monkeypatch)
    with pytest.raises(TsaError) as caught:
        verify_witness(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            transition_bundle_updates=[pending_first, pending_second],
        )
    assert str(caught.value) == (
        f"duplicate TSA timestamp across anchor outcomes: {sha256_bytes(signed)}"
    )
    # Neither earlier rule can see this one: two paths, two file digests.
    assert [claim["tsaAnchorId"] for claim in verified] == [
        local_anchors[0].anchor_id,
        first.anchor_id,
        second.anchor_id,
    ]


def test_refuses_a_re_bagged_token_offered_as_a_second_timestamp(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S4-F2: the identity is what was signed, not how it was packaged.

    The re-wrapping above is the easy half. A ``TimeStampToken``'s own
    ``SignedData`` also carries fields the ``SignerInfo`` signature does not
    cover -- ``certificates``, ``crls``, ``unsignedAttrs`` -- so a producer
    can change the token itself and keep the signature: here an unrelated
    root is appended to the certificate bag. Both the response file's digest
    and the digest of the token ``ts -reply -token_out`` extracts move with
    it, so a coverage rule keyed on either counts encodings rather than
    issuances, and one stamp covers two pending authorities' outcomes.

    The ``TSTInfo`` is the one thing that cannot move: it is the signed
    content, so any change to it breaks the signature the ``-CAfile``
    verification checks. All four halves of that are asked of OpenSSL
    directly below -- different file, different extracted token, identical
    ``TSTInfo``, and both files still verifying against the pinned root --
    and the refusal names the digest of what the authority signed.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    pending_first, first, pending_second, second, spec = two_pending_authorities(
        tree, beta
    )
    claimed = tree.records / RECORD_DAY / "record-0001.beta-first.tsr"
    beta.tsa.stamp(sha256_bytes(tree.record.read_bytes()), claimed)
    rebagged = tree.records / RECORD_DAY / "record-0001.beta-second.tsr"
    rebagged.write_bytes(
        add_certificate_to_token_bag(
            claimed.read_bytes(),
            der_certificate(alpha.tsa.root_pem, tmp_path / "alpha-root.der"),
        )
    )
    # The premise, from OpenSSL directly.
    assert sha256_bytes(rebagged.read_bytes()) != sha256_bytes(claimed.read_bytes())
    assert extracted_token_of(tmp_path, rebagged) != extracted_token_of(
        tmp_path, claimed
    )
    signed = signed_timestamp_of(tmp_path, claimed)
    assert signed_timestamp_of(tmp_path, rebagged) == signed
    assert openssl_ts_verifies(tree.record, claimed, beta.tsa.root_pem)
    assert openssl_ts_verifies(tree.record, rebagged, beta.tsa.root_pem)

    rewrite_witness(
        tree,
        lambda payload: payload.__setitem__(
            "supplementalOutcomes",
            [
                supplemental_outcome(tree, pending_first, first, claimed),
                supplemental_outcome(tree, pending_second, second, rebagged),
            ],
        ),
    )
    verified = record_token_verifications(monkeypatch)
    with pytest.raises(TsaError) as caught:
        verify_witness(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            transition_bundle_updates=[pending_first, pending_second],
        )
    assert str(caught.value) == (
        f"duplicate TSA timestamp across anchor outcomes: {sha256_bytes(signed)}"
    )
    assert [claim["tsaAnchorId"] for claim in verified] == [
        alpha.anchor_id,
        first.anchor_id,
        second.anchor_id,
    ]


@pytest.fixture
def openssl_preflight_uncached() -> Any:
    """Run the ``openssl version`` gate afresh, and leave it that way.

    ``_require_supported_openssl`` caches its verdict for the process, so a
    test that substitutes a version banner has to clear what earlier tests
    cached, and clear its own substituted answer on the way out.
    """

    tsa_module._require_supported_openssl.cache_clear()
    yield
    tsa_module._require_supported_openssl.cache_clear()


def substitute_openssl_version(monkeypatch: pytest.MonkeyPatch, banner: str) -> None:
    """Answer ``openssl version`` with ``banner`` and pass everything else on."""

    original = tsa_module._run_openssl

    def versioned(arguments: list[str], **keywords: Any) -> Any:
        if arguments == ["version"]:
            return banner
        return original(arguments, **keywords)

    monkeypatch.setattr(tsa_module, "_run_openssl", versioned)


@pytest.mark.parametrize(
    ("banner", "supported"),
    [
        ("OpenSSL 3.0.0 7 sep 2021", True),
        ("OpenSSL 3.0.13 30 Jan 2024", True),
        ("OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)", True),
        ("OpenSSL 1.1.1w  11 Sep 2023", False),
        ("OpenSSL 1.1.0h  27 Mar 2018", False),
        ("OpenSSL 1.0.2u  20 Dec 2019", False),
        ("LibreSSL 3.3.6", False),
        ("LibreSSL 4.1.0", False),
        ("", False),
        ("openssl 3.0.13", False),
    ],
)
def test_the_openssl_version_gate_reads_the_banner(banner: str, supported: bool) -> None:
    """S4-F3: what the preflight accepts, stated one banner at a time.

    The floor is 3.0, and 3.0.0 exactly is on the accepting side of it.
    ``storeutl`` arrived earlier, in 1.1.1, so it is not what sets the floor:
    verifying a token passes ``-no-CAstore``, whose store the OpenSSL 3.0
    release notes introduce, and 1.1.1 -- the floor until this round, and the
    version the README named as the minimum -- passed the gate and then
    refused every valid witness on an unknown option. The letter suffix real
    releases carry (``1.1.1w``) is not part of the comparison, and an
    implementation that is not OpenSSL is refused on its name however high its
    own version runs: LibreSSL 4.1.0 has neither the subcommand nor the
    option.
    """

    assert tsa_module._supported_openssl_version(banner) is supported


def test_refuses_an_openssl_that_is_not_openssl_before_reading_a_bundle(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
    openssl_preflight_uncached: Any,
) -> None:
    """S3-F3: LibreSSL is refused by name, not by a message blaming the file.

    Bundle loading always counts a pinned root's certificates with ``openssl
    storeutl``, which LibreSSL does not have. On a machine whose ``openssl``
    is the stock macOS ``/usr/bin/openssl``, that count failed, and the
    failure surfaced as ``pinned TSA root PEM certificates could not be
    counted`` -- a valid one-certificate bundle, and an unavailable witness
    that verifies no token at all, refused with a message about the file. The
    witness here is exactly that case: genuinely unavailable, no token to
    check, and nothing wrong with its bundle. The preflight refuses first, and
    the recorder shows it happens before any root certificate is read.
    """

    tree = build_witness_tree(tmp_path, local_anchors[:1], available=False)
    assert verify_tree(tree).status == "unavailable"

    read_roots: list[str] = []
    original_identity = tsa_module._certificate_identity
    monkeypatch.setattr(
        tsa_module,
        "_certificate_identity",
        lambda path: (read_roots.append(str(path)), original_identity(path))[1],
    )
    tsa_module._require_supported_openssl.cache_clear()
    substitute_openssl_version(monkeypatch, "LibreSSL 3.3.6\n")
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == (
        "receipt requires OpenSSL 3.0 or newer as `openssl` on the path; "
        "found: LibreSSL 3.3.6"
    )
    assert read_roots == []


def test_refuses_the_openssl_that_used_to_be_the_documented_minimum(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
    openssl_preflight_uncached: Any,
) -> None:
    """S4-F3: the gate admits only what the whole token path can run on.

    The gate is a version floor and not a LibreSSL blocklist. It used to sit
    at 1.1.1, which the README then named as the supported minimum -- but
    verifying an available token passes ``openssl cms -verify -no-CAstore``,
    an OpenSSL 3.0 option, so a machine at that documented minimum was
    admitted here and then refused every valid witness on an unknown option
    somewhere much deeper. 1.1.1 is now refused by name, before any bundle is
    read, and by the same message every unusable build gets.

    A substituted banner is all a test can do about a version this machine
    does not have; what it cannot show is that the accepted floor works. The
    project's CI job does that instead, running this whole suite against the
    real ``openssl`` the ``ubuntu-latest`` image carries.
    """

    tree = build_witness_tree(tmp_path, local_anchors[:1])
    substitute_openssl_version(monkeypatch, "OpenSSL 1.1.1w  11 Sep 2023\n")
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == (
        "receipt requires OpenSSL 3.0 or newer as `openssl` on the path; "
        "found: OpenSSL 1.1.1w  11 Sep 2023"
    )
