"""Focused invariants for the spec-parameterized TSA machinery."""

from __future__ import annotations

import dataclasses
import inspect
import pathlib
from datetime import datetime, timezone

import pytest

from receipt.tsa import (
    TrustBundleSpec,
    TsaError,
    TsaIdentitySpec,
    TsaSpec,
    activate_trust_bundles,
    preferred_active_trust_bundle,
    trust_bundle_updates_for_snapshot,
    validate_token_time,
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
