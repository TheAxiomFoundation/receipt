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
import pathlib
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from receipt.canonical import canonical_bytes, canonical_sha256
from receipt.tsa import (
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
) -> tuple[dict[str, Any], TsaSpec]:
    """Write a further immutable bundle version into the tree.

    Returns its reference and a spec that pins every bundle in the tree with a
    bundle-scoped identity for every anchor, the shape a consumer commits when
    it carries a trust transition. ``signers`` replaces an anchor's allowed
    signer with the given certificate pins, in the bundle and in the new
    identity together, which is how a rotated signing key enters: as a new
    version, never as an edit.
    """

    from receipt.canonical import canonical_sha256

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
            *tree.spec.trust_bundles,
            TrustBundleSpec(
                bundle_id=bundle_id,
                path=logical,
                sha256=str(reference["sha256"]),
                size=int(reference["size"]),
                canonical_json_sha256=str(reference["canonicalJsonSha256"]),
            ),
        ),
        tsa_identities=(*tree.spec.tsa_identities, *identities),
        legacy_witness_bundle_id=tree.spec.legacy_witness_bundle_id,
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
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == (
        "legacy witness schema requires a single-anchor bundle; tsa-anchors-v1 has 2"
    )
