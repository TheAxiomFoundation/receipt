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

import builtins
import collections
import dataclasses
import inspect
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
import unicodedata
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
    stamp_anonymously,
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
    ``TokenEvidence`` -- with 0.5.1's parameters and no others.

    S5R3-F5: "and no others" is the second half. This branch briefly added a
    keyword-only ``record`` here, which let a caller supply bytes that were
    not what ``path`` held; it is gone, and the parameter list pinned below
    is 0.5.1's exactly.
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
    ]
    # The identity exists, privately, and carries what the rule counts.
    assert tuple(
        field.name for field in dataclasses.fields(tsa_module._TimestampIdentity)
    ) == ("signer_certificate_sha256", "tst_info_sha256")


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


@pytest.fixture(scope="module")
def rotated_beta(
    tmp_path_factory: pytest.TempPathFactory, local_anchors: tuple[LocalAnchor, ...]
) -> LocalTsa:
    """A second signing certificate for the second authority, same root.

    The first authority's rotation is what an *active* anchor's rotation is
    tested with; this is for rotating an authority that is still pending, one
    bundle version after the version that introduced it.
    """

    return rotate_tsa_signer(
        local_anchors[1].tsa, tmp_path_factory.mktemp("tsa-rotated-beta") / "beta"
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


def verify_step(path: pathlib.Path, **keywords: Any) -> WitnessEvidence:
    """Return the evidence from the safe public chain-step entry point."""

    return tsa_module.verify_witness_step(path, **keywords).evidence


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
    """S5R2-F6: the witness-level fields are the earliest token's, chosen.

    A witness carrying several tokens reports one token's genTime, anchor and
    signer at the witness level, and which one is the guarantee: the earliest,
    because that is the moment the record is proved to have existed by. The
    tree builder writes the outcomes in bundle order and the builder stamps in
    that order too, so the earliest token was also the first one in the list
    and a summary that returned ``tokens[0]`` passed unremarked. Here the
    outcomes are reversed before verification, so the earliest is last and
    only a summary that actually compares the times can report it.

    The comparison is by ``(genTime, anchor id)``: two stamps taken a moment
    apart can land in one second, and the tie-break has to be something, so
    it is the same key the module uses.
    """

    tree = build_witness_tree(tmp_path, local_anchors)
    rewrite_witness(
        tree,
        lambda payload: payload["anchorOutcomes"].reverse(),
    )
    evidence = verify_tree(tree)
    assert evidence.status == "available"
    assert {token.anchor_id for token in evidence.tokens} == {
        anchor.anchor_id for anchor in local_anchors
    }
    earliest = min(evidence.tokens, key=lambda token: (token_time(token), token.anchor_id))
    # The earliest is genuinely not the one a summary reading tokens[0] would
    # report: the builder stamped it first and the witness now lists it last.
    assert earliest.anchor_id == local_anchors[0].anchor_id
    assert evidence.tokens[0].anchor_id == local_anchors[1].anchor_id
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
    extra_signers: Mapping[str, Sequence[dict[str, str]]] | None = None,
    mutate_anchor: Callable[[dict[str, Any]], None] | None = None,
    base: TsaSpec | None = None,
) -> tuple[dict[str, Any], TsaSpec]:
    """Write a further immutable bundle version into the tree.

    Returns its reference and a spec that pins every bundle in the tree with a
    bundle-scoped identity for every anchor, the shape a consumer commits when
    it carries a trust transition. ``signers`` replaces an anchor's allowed
    signer with the given certificate pins, in the bundle and in the new
    identity together, which is how a rotated signing key enters: as a new
    version, never as an edit. ``extra_signers`` adds further pins beside it,
    again in the bundle and the identity together, which is the only way an
    anchor can allow two signing keys at once -- the load requires the two
    sets to be equal, so adding to one alone stops there. ``base`` is the spec
    to extend, for a test that writes two versions and needs one spec pinning
    both; without it each call extends the tree's own spec and the second
    would drop the first.
    """

    from receipt.canonical import canonical_sha256

    base = base or tree.spec
    signers = signers or {}
    extra_signers = extra_signers or {}
    bundle_id = f"tsa-anchors-v{version}"
    logical = f"records/trust/{bundle_id}.json"
    payload: dict[str, Any] = {
        "schemaVersion": "thesis_tsa_trust_bundle_v1",
        "bundleId": bundle_id,
        "anchors": [
            anchor.entry(extra_signers=extra_signers.get(anchor.anchor_id, ()))
            for anchor in anchors
        ],
    }
    for entry in payload["anchors"]:
        if entry["id"] in signers:
            entry["allowedSigners"] = [
                dict(signers[entry["id"]]),
                *(dict(extra) for extra in extra_signers.get(entry["id"], ())),
            ]
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
                {
                    signers.get(anchor.anchor_id, anchor.signer_pins)["spkiSha256"],
                    *(
                        extra["spkiSha256"]
                        for extra in extra_signers.get(anchor.anchor_id, ())
                    ),
                }
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
        verify_step(
            tree.record,
            spec=contradictory,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[reference],
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
    ("fingerprint", "reason"),
    [
        ([], "unhashable"),
        ({}, "unhashable-mapping"),
        (5, "non-string"),
        (None, "absent"),
        ("not sixty-four lowercase hexadecimal characters at all", "not-hex"),
        ("A" * 64, "upper-case"),
    ],
    ids=["list", "mapping", "int", "null", "not-hex", "upper-case"],
)
def test_a_malformed_allowed_signer_entry_is_refused_by_index(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    fingerprint: Any,
    reason: str,
) -> None:
    """S6-R2-F5: a malformed fingerprint is refused, not raised through.

    The load put every entry's ``spkiSha256`` into a set and compared that set
    with the identity the verifier code pins, so the values were hashed before
    anything asked what they were. A pinned bundle carrying an unhashable one
    -- ``{"spkiSha256": []}`` or ``{"spkiSha256": {}}`` -- therefore raised
    ``TypeError`` out of the set comprehension rather than ``TsaError``: a
    verifier that catches this module's own error saw an exception it does not
    handle, and a malformed bundle crashed the verification instead of being
    refused by it. The other shapes reached a refusal, but the wrong one --
    "declares allowed signers that differ from its verifier code identity",
    which says the producer picked the wrong key when what it did was write a
    value that is not a key at all.

    Each entry's type, length and alphabet are now asked before any set is
    built, in the bundle's own order, and the refusal names the index because
    an index is what a producer edits. The malformed entry below is the second
    of two, so the index is part of what is asserted rather than a constant;
    the first entry is the honest one and is not what the message names.

    Without the fix the two unhashable cases raise ``TypeError`` here (which
    ``pytest.raises(TsaError)`` does not catch) and the other four reach the
    identity-disagreement message instead.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])

    def add_a_malformed_signer(entry: dict[str, Any]) -> None:
        entry["allowedSigners"] = [
            dict(alpha.signer_pins),
            {"spkiSha256": fingerprint},
        ]

    reference, spec = add_bundle_version(
        tree,
        local_anchors[:1],
        version=2,
        mutate_anchor=add_a_malformed_signer,
    )
    # The premise: the bundle really is pinned by the spec it is loaded
    # against, and really does carry the malformed value at index 1 -- so the
    # refusal below is about the entry and not about the commitment.
    written = json.loads(
        (tree.records / "trust" / "tsa-anchors-v2.json").read_text()
    )["anchors"][0]["allowedSigners"]
    assert written[0]["spkiSha256"] == alpha.signer_pins["spkiSha256"]
    assert written[1] == {"spkiSha256": fingerprint}
    assert spec.bundle_reference(str(reference["path"])) == reference

    with pytest.raises(TsaError) as caught:
        _load_trust_bundle(tree.records, reference, spec=spec)
    assert str(caught.value) == (
        f"TSA anchor {alpha.anchor_id} in bundle tsa-anchors-v2 declares a "
        "malformed allowedSigners entry at index 1"
    )
    # And through the pending-transition path, which is how a bundle like this
    # would arrive: refused before anything activates it.
    with pytest.raises(TsaError) as pending:
        verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[reference],
        )
    assert str(pending.value) == str(caught.value)


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
        verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[reference],
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
        verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[reference],
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
        verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[reference],
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
    evidence = verify_step(
        tree.record,
        spec=rotation_spec,
        records=tree.records,
        trusted_bundles={BUNDLE_LOGICAL: tree.reference},
        prior_pending_updates=[rotation],
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


def substitute_the_storeutl_listing(
    monkeypatch: pytest.MonkeyPatch, listing: str
) -> None:
    """Answer every ``openssl storeutl`` with ``listing`` and pass the rest on.

    The version gate runs ``openssl version`` through the same function, and
    every other OpenSSL call in a verification runs through it too, so only
    the listing is substituted.
    """

    original = tsa_module._run_openssl

    def counting(arguments: list[str], **keywords: Any) -> Any:
        if arguments[:1] == ["storeutl"]:
            return listing
        return original(arguments, **keywords)

    monkeypatch.setattr(tsa_module, "_run_openssl", counting)


def test_a_listing_with_no_total_is_refused_rather_than_counted_as_zero(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S5R2-F6: no total is not a count, and must not become a count of zero.

    ``_certificate_count`` reads the total off the end of ``openssl storeutl
    -noout -certs`` and refuses when there is none, rather than substituting a
    number of its own. Which OpenSSL prints a total for which file is a
    version difference -- 3.0 prints ``Total found: 0`` for a file holding no
    PEM object and 3.6 prints nothing -- so on any one machine the branch is
    reachable for some files and not others, and the case above can only
    assert whichever its own OpenSSL takes. Nothing bound the branch itself,
    and a helper that returned zero where there is no total would pass every
    test in the suite: the pinned roots would still count one, and an
    uncountable file would be refused by the one-certificate rule instead --
    the wrong rule, and the right answer by accident.

    Here the listing is substituted, so the branch is reached whatever OpenSSL
    is on the path. The refusal has to be the counting one, on a bundle whose
    root is genuinely a single valid certificate: with a zero fallback the
    load refuses too, but for holding no certificate, which is a false
    statement about the file.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    root_path = tree.records / "trust" / alpha.tsa.root_pem.name
    assert _certificate_count(root_path) == 1
    substitute_the_storeutl_listing(monkeypatch, "0: Certificate\n")
    uncounted = (
        f"pinned TSA root PEM certificates could not be counted: {root_path}: "
        "openssl storeutl reported no total"
    )
    with pytest.raises(TsaError) as counting:
        _certificate_count(root_path)
    assert str(counting.value) == uncounted
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == (
        f"TSA anchor {alpha.anchor_id} in bundle {BUNDLE_ID} references root "
        f"material that fails validation: {uncounted}"
    )
    assert "must hold exactly one certificate" not in str(caught.value)


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

    S5R2-F6: the ``no-object`` half of that is only true where OpenSSL prints
    no total, which is 3.6 here and not 3.0 on CI, so the branch each version
    takes is decided by asking the count what it did rather than by accepting
    either message from the load. The version-independent statement -- no
    total is not a count of zero -- is bound separately, on a substituted
    listing, in the test below.
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
        one = f"pinned TSA root PEM must hold exactly one certificate: {root_path}"
        try:
            counted = _certificate_count(root_path)
        except TsaError as exc:
            assert str(exc).startswith(uncounted)
            expected = load_refusal(tree, alpha, uncounted)
        else:
            assert counted == 0
            expected = load_refusal(tree, alpha, one)
        with pytest.raises(TsaError) as caught:
            _load_trust_bundle(tree.records, reference, spec=spec)
        assert str(caught.value).startswith(expected)
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
    """S4-F1: a direct caller has no read to hand down, so this takes one.

    ``verify_witness`` reads the record once and hands the bytes down, so the
    digest it publishes and the imprint OpenSSL recomputes are the same read.
    A caller that verifies one token on its own has no such read to pass, and
    gets exactly the same evidence: the public function takes that one read
    itself, from the ``path`` it was given. Without it there would be nothing
    for a direct caller to verify against at all.

    S5R3-F5: and there is no way to hand it other bytes. The hand-down was a
    ``record=`` keyword on this function for two rounds, which let a caller
    supply bytes that were not what ``path`` held -- the evidence naming one
    record while the imprint was checked against another. The keyword is gone
    from the public function (it was added on this branch, so no release
    carried it) and lives on the private one, whose only callers are in this
    module and pass their own read of ``path``. Asserted here as the
    ``TypeError`` a call with it now gets: a keyword silently ignored would
    be the same defect wearing a different failure.
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
    with pytest.raises(TypeError):
        verify_timestamp_token(
            tree.record,
            claim,
            tree.reference,
            spec=tree.spec,
            records=tree.records,
            record=tree.record.read_bytes(),
        )
    # The private entry point still takes it, and returns what the public one
    # returns: the keyword moved, and nothing about the verification did.
    private, _identity = tsa_module._verify_timestamp_token(
        tree.record,
        claim,
        tree.reference,
        spec=tree.spec,
        records=tree.records,
        record=tree.record.read_bytes(),
    )
    assert private == evidence
    # And the read is a read: a record that is not there is refused by name.
    absent = tree.records / RECORD_DAY / "record-9999.json"
    with pytest.raises(TsaError) as caught:
        verify_timestamp_token(
            absent, claim, tree.reference, spec=tree.spec, records=tree.records
        )
    assert str(caught.value) == (
        f"witnessed record is missing or not a regular file: {absent}"
    )


def test_the_public_token_verifier_measures_the_token_against_its_own_path(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """S5R3-F5: the bytes a token is checked against are ``path``'s bytes.

    The released ``verify_timestamp_token`` bound the token to the record it
    was given: it read ``path``, and ``openssl ts -verify -data`` recomputed
    the imprint over that read. The ``record=`` keyword this branch added for
    the hand-down took that binding away, because nothing compared the bytes
    supplied with the bytes at ``path`` -- a caller passing a record the token
    really is over, while naming a record it is not, got evidence for a
    timestamp over a file this call never looked at.

    The keyword is gone from the public function, which takes its own read.
    The token below is a genuine stamp over another record entirely, asked of
    OpenSSL directly in both directions, and the call naming the witnessed
    record is refused on the imprint. What the keyword bought is then shown
    through the private door it now lives behind: the same claim, with the
    other record's bytes supplied, returns evidence -- which is exactly the
    call a public keyword let any caller make.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_bytes(
        canonical_bytes(
            {
                "schemaVersion": "receipt_test_record_v1",
                "recordedAt": (datetime.now(UTC) - timedelta(seconds=90)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "observation": "the record the token is really over",
            }
        )
        + b"\n"
    )
    other = elsewhere.read_bytes()
    token = tree.records / RECORD_DAY / "record-0001.elsewhere.tsr"
    alpha.tsa.stamp(sha256_bytes(other), token)
    claim = claim_against(tree, tree.reference, alpha, token)
    # The premise, from OpenSSL directly: one record, and not the other.
    assert openssl_ts_verifies(elsewhere, token, alpha.tsa.root_pem)
    assert not openssl_ts_verifies(tree.record, token, alpha.tsa.root_pem)

    with pytest.raises(TsaError) as caught:
        verify_timestamp_token(
            tree.record, claim, tree.reference, spec=tree.spec, records=tree.records
        )
    message = str(caught.value)
    assert message.startswith(f"OpenSSL command failed ({TS_VERIFY_COMMAND} ")
    assert "ts_check_imprints:message imprint mismatch" in message
    # And nothing restores it: the keyword that used to accept the other
    # record's bytes here is gone, so that refusal is the only answer this
    # function has for this claim.
    assert "record" not in inspect.signature(verify_timestamp_token).parameters
    with pytest.raises(TypeError):
        verify_timestamp_token(
            tree.record,
            claim,
            tree.reference,
            spec=tree.spec,
            records=tree.records,
            record=other,
        )

    # And the call the removed keyword allowed, made where it now lives.
    evidence, _identity = tsa_module._verify_timestamp_token(
        tree.record,
        claim,
        tree.reference,
        spec=tree.spec,
        records=tree.records,
        record=other,
    )
    assert evidence.token_sha256 == sha256_bytes(token.read_bytes())
    assert tree.record.read_bytes() != other


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
    files. Nothing binds that without this test: the private verifier requires
    the bytes, but nothing about requiring them says they are the bytes the
    digest was taken over -- hand it a fresh ``_read_witnessed_record(path)``
    at either call site and the rest of the suite stays green.

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


@pytest.mark.parametrize(
    "victim", ["record", "token", "root", "bundle", "sidecar", "genesis"]
)
def test_a_fifo_raced_in_after_the_path_check_refuses_without_blocking(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
    victim: str,
) -> None:
    """S5-F3, S5R3-F6: every read opens without waiting, so a refusal arrives.

    ``_read_file_once`` opens before ``fstat`` can say what it opened, and the
    path-level check in front of it answers about a name rather than about the
    object the open will find. So a regular file replaced by a FIFO in that
    window is opened as a FIFO -- and a read-only open of a FIFO waits for a
    writer with no timeout. Without ``O_NONBLOCK`` the open never returns, the
    regular-file refusal below is never reached, and a verification that
    should have failed hangs; the alarm here is what turns that into a loud
    failure instead of a hung suite. With it the open returns a descriptor at
    once, ``fstat`` sees a FIFO, and the caller's own words come back.

    Six files, because every file this verification depends on has that same
    window. Three were read once from the start: the record, the claimed
    response, and the pinned root. The root's refusal arrives inside the
    load-time wrapper, which is where every root material failure has been
    carried since the anchors were validated at load; the wording it carries
    is the caller's, unchanged.

    The other three are the JSON inputs, and they were still read
    check-then-blocking-open through ``load_json`` -- ``is_file`` about a
    pathname, ``Path.read_text`` opening it again -- although each of them
    decides what is trusted: the trust bundle is the anchor set, the sidecar
    is the claim, and the genesis file is the root of the whole transition
    (S5R3-F6). Each now goes through ``_load_json_once``, so each hangs
    without the flag and refuses with it. The bundle's and the sidecar's
    words are the ones their path-level checks already had; genesis had no
    check at all and gets one in the same form.
    """

    if not hasattr(os, "mkfifo"):
        pytest.skip("platform has no FIFOs")
    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    assert verify_tree(tree).status == "available"
    records = tree.records.resolve()
    root_path = records / "trust" / alpha.tsa.root_pem.name
    token_path = records / RECORD_DAY / tree.tokens[alpha.anchor_id].name
    bundle_path = records / "trust" / tree.bundle.name
    genesis_path = records / "CHAIN_GENESIS.json"
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
        "bundle": (
            tree.bundle,
            f"TSA trust bundle is missing or not regular: {bundle_path}",
        ),
        "sidecar": (
            tree.witness,
            f"missing explicit witness marker for {tree.record}",
        ),
        "genesis": (
            tree.records / "CHAIN_GENESIS.json",
            f"chain genesis is missing or not a regular file: {genesis_path}",
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


def race_a_fifo_in_after_the_one_read(
    monkeypatch: pytest.MonkeyPatch, victim: pathlib.Path
) -> list[str]:
    """Put a FIFO at ``victim`` for exactly the window after its one read.

    The other side of the window ``replace_with_a_fifo_after_the_path_check``
    opens. That one arrives between a caller's path-level check and the open
    the check was about; this one arrives after the guarded open has already
    returned every byte, which is where a second open of the same pathname
    would be -- and a read-only open of a FIFO waits for a writer with no
    timeout, so a load that re-reads its own path hangs here rather than
    refusing. The FIFO is taken away again when that load returns, so nothing
    after it is about a file that is not there; what the window covers is one
    load, which is the unit the finding is about. Returns the swap, so a test
    can show the writer ran.
    """

    real_read = tsa_module._read_file_once
    real_load = tsa_module._load_trust_bundle
    original = victim.read_bytes()
    swapped: list[str] = []

    def reading(
        path: pathlib.Path, missing: str, **keywords: Any
    ) -> tuple[bytes, tuple[int, int]]:
        answer = real_read(path, missing, **keywords)
        if os.fspath(path) == os.fspath(victim) and not swapped:
            victim.unlink()
            os.mkfifo(victim)
            swapped.append(str(victim))
        return answer

    def loading(
        records: pathlib.Path, reference: dict[str, Any], **keywords: Any
    ) -> Any:
        try:
            return real_load(records, reference, **keywords)
        finally:
            if swapped and stat.S_ISFIFO(os.lstat(victim).st_mode):
                victim.unlink()
                victim.write_bytes(original)

    monkeypatch.setattr(tsa_module, "_read_file_once", reading)
    monkeypatch.setattr(tsa_module, "_load_trust_bundle", loading)
    return swapped


def test_the_bundle_load_asks_nothing_of_its_path_after_the_one_read(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S6-F2: the canonicality, the hash and the size come from the one read.

    ``_load_json_once`` captured the bundle's bytes and parsed them, and then
    the load went back to the repository path three more times -- two further
    opens and a ``stat``: ``read_bytes`` for the canonical-JSON comparison,
    ``sha256_file`` for the commitment hash and ``Path.stat`` for the size. So the anchor set came from one instant of a
    mutable file and its three commitments from three later ones -- and a
    writer replacing the bundle with a FIFO in any of those windows had the
    re-reads waiting for a writer with no timeout, which is the hang the
    non-blocking one-read discipline exists to prevent, reached through the
    one input that had not been given it.

    Everything now comes from the captured bytes, so this load asks the path
    for nothing at all after its read: a FIFO occupying the pathname for
    exactly that window changes nothing, and the alarm is what turns a
    re-read into a loud failure rather than a hung suite. Run at the head
    with the canonical comparison put back to ``path.read_bytes()`` and the
    alarm fires there; put back with ``sha256_file`` instead and it fires
    there. The premises are asserted rather than assumed: the writer really
    ran, what stood at the pathname really was a FIFO, and the bundle's own
    commitment -- the hash and the size a ``TrustBundleSpec`` pins -- is still
    checked, because a bundle whose bytes disagree with it is still refused.
    """

    if not hasattr(os, "mkfifo"):
        pytest.skip("platform has no FIFOs")
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    assert verify_tree(tree).status == "available"
    bundle = tree.records.resolve() / "trust" / tree.bundle.name

    def blocked(_signal: int, _frame: Any) -> None:
        raise RuntimeError("the load re-read its own path and blocked")

    swapped = race_a_fifo_in_after_the_one_read(monkeypatch, bundle)
    previous = signal.signal(signal.SIGALRM, blocked)
    signal.alarm(30)
    try:
        evidence = verify_tree(tree)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    # The writer really did run, and the load carried on regardless.
    assert swapped == [str(bundle)]
    assert evidence.status == "available"
    assert evidence.trust_bundle_id == BUNDLE_ID

    # And the commitment those bytes are measured against still binds: a
    # bundle whose contents disagree with the pinned hash and size refuses,
    # so what moved is where the two values are read from and not whether
    # they are compared.
    payload = json.loads(tree.bundle.read_text())
    payload["anchors"][0]["allowedPolicyOids"].append("1.3.6.1.4.1.99999.9.9")
    tree.bundle.write_bytes(canonical_bytes(payload) + b"\n")
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value).startswith(
        f"TSA trust bundle commitment mismatch for {BUNDLE_LOGICAL}: "
    )
    assert f"'sha256': '{tree.reference['sha256']}'" in str(caught.value)
    assert f"'size': {tree.reference['size']}" in str(caught.value)


def test_a_genesis_path_that_is_not_a_regular_file_is_refused_by_name(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """S5R3-F6: the chain genesis is judged like everything else read here.

    The bundle and the sidecar each had a path-level check saying what they
    have to be; the genesis file had none. It went straight to ``load_json``,
    so a genesis path that was a directory came back as ``cannot read JSON``
    quoting an ``errno`` -- a message about a parse that never happened, about
    a file that is not a file. It is read through ``_load_json_once`` now,
    which judges it a regular file first and says so in the same form the
    other five reads use.

    Without the change this is still a ``TsaError``, so what binds the fix is
    the message: run at the head with the genesis read back through
    ``load_json`` and the refusal is ``cannot read JSON ...: [Errno 21] Is a
    directory``.
    """

    tree = build_witness_tree(tmp_path, local_anchors[:1])
    assert verify_tree(tree).status == "available"
    genesis = tree.records / "CHAIN_GENESIS.json"
    genesis.unlink()
    genesis.mkdir()
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == (
        "chain genesis is missing or not a regular file: "
        f"{tree.records.resolve() / 'CHAIN_GENESIS.json'}"
    )


def flag_expression(name: str) -> str:
    """The source of one of the module's parenthesised ``os.open`` flag sets.

    ``O_BINARY`` is zero on every platform this suite runs on, so no runtime
    assertion can tell a flag set that includes it from one that does not.
    What can be told apart is the expression itself, which is why the two sets
    are named constants: this reads the source of one and the test below
    requires the term to be there.
    """

    source = inspect.getsource(tsa_module)
    _before, separator, after = source.partition(f"\n{name} = (\n")
    assert separator, f"{name} is not a parenthesised flag expression"
    return after.split("\n)\n", 1)[0]


def test_the_one_read_and_the_snapshot_write_open_in_binary(
    tmp_path: pathlib.Path,
) -> None:
    """S5R2-F3: nothing between the disk and the digest may translate a byte.

    Both of this module's ``os.open`` calls omitted ``O_BINARY``. It is absent
    on POSIX and contributes nothing there, but on Windows a descriptor opened
    without it is a *text* descriptor in the C runtime's sense: reading turns
    ``\r\n`` into ``\n`` and stops at the first ``0x1A``, and writing turns
    ``\n`` back into ``\r\n``. Every file the one read returns is hashed and
    then trusted, so a byte the read never returns is a byte the digest does
    not cover -- a pinned root, a DER response or a record truncated at a
    ``0x1A`` would be hashed and trusted as the whole file. And the pinned
    root's private copy is written through the second call, so a text write
    would hand OpenSSL something other than what was hashed and counted: the
    substitution the copy exists to prevent, performed by the copy.

    Two halves, and only one of them binds on this platform. The round trip
    below is byte-exact here whether or not the flag is set, because the flag
    is zero here; it is the case that would fail on Windows, and it is stated
    so a port to a platform with the flag runs it. What binds here is the
    source of the two flag sets, which is the only place the difference is
    visible on POSIX: remove the term from either and this fails.
    """

    for name in ("_ONE_READ_FLAGS", "_SNAPSHOT_WRITE_FLAGS"):
        assert 'getattr(os, "O_BINARY", 0)' in flag_expression(name)
    # True on Windows, and vacuously true here, which is the whole of what a
    # runtime assertion can say about a flag the platform defines as zero.
    binary = getattr(os, "O_BINARY", 0)
    assert tsa_module._ONE_READ_FLAGS & binary == binary
    assert tsa_module._SNAPSHOT_WRITE_FLAGS & binary == binary

    # A CRLF line ending and a 0x1A, the two bytes CRT text mode moves.
    payload = (
        b"-----BEGIN CERTIFICATE-----\r\n"
        b"not really base64\x1anor is this\r\n"
        b"-----END CERTIFICATE-----\r\n"
    )
    source = tmp_path / "crlf-and-substitute.pem"
    source.write_bytes(payload)
    assert tsa_module._read_pinned_root(source) == payload
    snapshot = tsa_module._write_root_snapshot(tmp_path, payload)
    assert snapshot.read_bytes() == payload
    assert tsa_module._read_pinned_root(snapshot) == payload


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
    # S5R3-F6: and through the helper the trust bundle, the witness sidecar
    # and the genesis file now go through, which is that same parse over one
    # non-blocking read rather than over a second open of the path.  What its
    # ``label`` answers for is a path that is not a readable regular file;
    # these are all readable regular files, so what comes back is the ported
    # reader's own words.
    with pytest.raises(TsaError) as once:
        tsa_module._load_json_once(path, label="never reached for this file")
    assert str(once.value) == str(ported.value)


def record_opens(monkeypatch: pytest.MonkeyPatch) -> collections.Counter[str]:
    """Count every open of every path, by each door Python opens files through.

    Three doors, and the test below proves all three are watched rather than
    assuming it: ``os.open``, which ``_read_file_once`` uses; the built-in
    ``open``; and ``pathlib.Path.open``, which ``read_bytes`` and
    ``read_text`` are written in terms of and which reaches the file through
    ``io.open`` -- a binding in the ``io`` module that a patched ``builtins``
    never sees, so the three counts do not overlap. Nothing here can see a
    subprocess opening a file, which is what the OpenSSL recorder is for.
    """

    opens: collections.Counter[str] = collections.Counter()
    real_os_open = os.open
    real_builtin_open = builtins.open
    real_path_open = pathlib.Path.open

    def counting_os_open(path: Any, *arguments: Any, **keywords: Any) -> int:
        opens[os.fsdecode(path)] += 1
        return real_os_open(path, *arguments, **keywords)

    def counting_builtin_open(file: Any, *arguments: Any, **keywords: Any) -> Any:
        if isinstance(file, (str, bytes, os.PathLike)):
            opens[os.fsdecode(file)] += 1
        return real_builtin_open(file, *arguments, **keywords)

    def counting_path_open(self: pathlib.Path, *arguments: Any, **keywords: Any) -> Any:
        opens[str(self)] += 1
        return real_path_open(self, *arguments, **keywords)

    monkeypatch.setattr(os, "open", counting_os_open)
    monkeypatch.setattr(builtins, "open", counting_builtin_open)
    monkeypatch.setattr(pathlib.Path, "open", counting_path_open)
    return opens


def record_root_validations(
    monkeypatch: pytest.MonkeyPatch,
) -> collections.Counter[str]:
    """Count how often each pinned root is put through ``_root_material``."""

    original = tsa_module._root_material
    validated: collections.Counter[str] = collections.Counter()

    def recording(
        records: pathlib.Path, anchor: dict[str, Any], **keywords: Any
    ) -> Any:
        declared = str(anchor["rootCertificate"]["path"])
        validated[str(tsa_module.physical_path(records, declared))] += 1
        return original(records, anchor, **keywords)

    monkeypatch.setattr(tsa_module, "_root_material", recording)
    return validated


def record_bundle_loads(
    monkeypatch: pytest.MonkeyPatch,
) -> collections.Counter[str]:
    """Count how often each trust bundle is put through ``_load_trust_bundle``."""

    original = tsa_module._load_trust_bundle
    loaded: collections.Counter[str] = collections.Counter()

    def recording(
        records: pathlib.Path, reference: dict[str, Any], **keywords: Any
    ) -> Any:
        loaded[str(tsa_module.physical_path(records, str(reference["path"])))] += 1
        return original(records, reference, **keywords)

    monkeypatch.setattr(tsa_module, "_load_trust_bundle", recording)
    return loaded


def record_openssl_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> list[list[str]]:
    """Every argument list ``_run_openssl`` is given, in order."""

    original = tsa_module._run_openssl
    invocations: list[list[str]] = []

    def recording(arguments: list[str], **keywords: Any) -> Any:
        invocations.append(list(arguments))
        return original(arguments, **keywords)

    monkeypatch.setattr(tsa_module, "_run_openssl", recording)
    return invocations


def test_one_verification_opens_each_judged_file_exactly_as_often_as_it_judges_it(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S5-F6: bind the one-read rules by observation, not one swap each.

    The swap regressions show that a writer arriving at one moment cannot
    change what is trusted, but each of them binds one consumer of the
    captured bytes: revert the certificate count, or the identity
    extraction, or the record parse, or only the CMS ``-CAfile`` to the
    repository path, and every one of them stays green. The rule they are
    all instances of is simpler than any of them -- nothing reads a
    repository path twice, and OpenSSL is never given one -- and it is
    observable directly.

    Three recorders, because descriptor-relative opens carry only a component
    name rather than the full path. The first counts all three Python open
    doors, the second counts successful one-read snapshots by their lexical
    paths, and the third reads every argument ``_run_openssl`` is given.
    Together they see both halves without pretending an ``openat`` leaf name
    is an absolute path. Each of the four reverts trips one of them, and nothing else in the
    suite: the certificate count handed the repository path puts 14 of its
    paths into OpenSSL arguments, the identity extraction 42, the CMS
    ``-CAfile`` alone 2, and the record parse re-reading its path takes the
    record's open count from one to three.

    What the counts are and why. The record and each token are read once for
    the whole verification: one descriptor each, whose bytes are hashed,
    parsed, and copied for OpenSSL. Each root is read once per
    ``_root_material`` call and no more -- which is seven times per root
    here, not once, because validating a root is what ``_root_material``
    does and a two-anchor witness asks for it seven times. Five are bundle
    loads, each of which validates every anchor of the bundle: the genesis
    bootstrap, the witness's own bundle claim, one inside each of the two
    token verifications, and the scan for supplemental candidates. Two are
    selections that land on this particular root: the outcome's own
    ``_select_anchor`` and the one inside its ``verify_timestamp_token``.
    The rule is not "one open per file" but "one open per judgement", and
    this asserts the two numbers are equal, which is what makes the bytes
    judged the bytes used. A refactor that changes the seven should recount
    it here rather than loosen the equality beside it.

    S6R1-F2 brings the trust bundle under the same equality. It opened three
    times per load -- ``_load_json_once`` for the payload, ``read_bytes`` for
    the canonical comparison and ``sha256_file`` for the commitment hash, with
    a ``Path.stat`` beside them for the size -- so the anchors came from one
    instant of the file and its three commitments from three others. Five
    loads here, and now five opens.
    """

    tree = build_witness_tree(tmp_path, local_anchors[:2])
    roots = {
        str(tree.records.resolve() / "trust" / anchor.tsa.root_pem.name)
        for anchor in local_anchors[:2]
    }
    bundle = str(tree.records.resolve() / "trust" / tree.bundle.name)
    tokens = {
        str(tree.records.resolve() / RECORD_DAY / token.name)
        for token in tree.tokens.values()
    }
    probe = tmp_path / "probe-every-door.txt"
    probe.write_bytes(b"counted three times")

    validated = record_root_validations(monkeypatch)
    loaded = record_bundle_loads(monkeypatch)
    invocations = record_openssl_arguments(monkeypatch)
    opens = record_opens(monkeypatch)
    one_reads = record_one_reads(monkeypatch)

    # The recorder watches all three doors, and each of them exactly once.
    assert probe.read_bytes() == b"counted three times"
    with open(probe, "rb") as handle:
        handle.read()
    os.close(os.open(probe, os.O_RDONLY))
    assert opens[str(probe)] == 3
    opens.clear()

    evidence = verify_tree(tree)
    assert [token.anchor_id for token in evidence.tokens] == [
        anchor.anchor_id for anchor in local_anchors[:2]
    ]

    read_counts = collections.Counter(one_reads)
    assert read_counts[str(tree.record)] == 1
    assert {token: read_counts[token] for token in tokens} == dict.fromkeys(tokens, 1)
    assert {root: read_counts[root] for root in roots} == {
        root: validated[root] for root in roots
    }
    assert set(validated) == roots
    assert {validated[root] for root in roots} == {7}
    # S6R1-F2: and the bundle, which used to open three times per load -- for
    # the payload, for the canonical comparison and for the commitment hash,
    # with a ``stat`` beside them for the size -- opens once per load.
    assert set(loaded) == {bundle}
    assert loaded[bundle] == 5
    assert read_counts[bundle] == loaded[bundle]

    # And no file under the records tree ever reaches OpenSSL by name.
    named = [
        argument
        for invocation in invocations
        for argument in invocation
        if str(tree.records) in argument
    ]
    assert named == []
    # Not vacuous: OpenSSL really did run, and really was given files.
    assert len(invocations) > 10
    assert any(argument == "-CAfile" for invocation in invocations
               for argument in invocation)


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
    body lives and which every caller reaches -- the v2 path for the
    timestamp identity beside the evidence, the v1 path for the record
    snapshot it has already read, and the public function by delegation -- so
    one recorder sees all three.
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


def test_a_claim_declaring_a_non_string_digest_reaches_the_ported_refusal(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """S5R2-F6: the duplicate rules read a claim, and a claim can be anything.

    A witness is a document a producer writes, so a field the rules read may
    hold anything JSON can express. The response-file rule tests its argument
    for ``str`` before looking it up, which is not decoration: the seen
    responses are a ``set``, and looking a list up in one raises ``TypeError``
    -- an unhandled exception out of a verifier whose whole contract is to
    raise ``TsaError`` for anything it will not accept, and out of the rules
    the branch is *newest* in. Nothing supplied a non-string, so nothing bound
    it.

    What a non-string ``tokenSha256`` should get is the refusal the port
    inherited for a claim whose declared digest is not the digest of the file:
    the rule declines to remember it, and ``verify_timestamp_token`` compares
    it with the bytes it read and refuses in the baseline's words. Without the
    type test this raises ``TypeError: unhashable type: 'list'`` instead.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    tree = build_witness_tree(tmp_path, local_anchors[:2])
    assert verify_tree(tree).status == "available"

    def declare_a_list_of_digests(payload: dict[str, Any]) -> None:
        first, second = payload["anchorOutcomes"]
        assert (first["tsaAnchorId"], second["tsaAnchorId"]) == (
            alpha.anchor_id,
            beta.anchor_id,
        )
        # A list holding the first outcome's digest: the value the rule would
        # have to remember, wrapped in the one type that cannot be remembered.
        second["tokenSha256"] = [first["tokenSha256"]]

    rewrite_witness(tree, declare_a_list_of_digests)
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == f"witness token hash mismatch for {tree.record}"


def file_identity(path: pathlib.Path) -> tuple[int, int]:
    """``(st_dev, st_ino)`` for a path, as a test's own answer about a file."""

    info = path.stat()
    return (info.st_dev, info.st_ino)


def record_one_reads(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every path ``_read_file_once`` successfully reads, in read order."""

    original = tsa_module._read_file_once

    def recording(
        path: pathlib.Path, missing: str, **keywords: Any
    ) -> tuple[bytes, tuple[int, int]]:
        answer = original(path, missing, **keywords)
        reads.append(str(path))
        return answer

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


def one_file_under_a_second_name(
    tree: WitnessTree, token: pathlib.Path, alias: str
) -> pathlib.Path:
    """A second path in the records tree reaching ``token``'s own object.

    ``symlinked-parent`` puts a symlink to the day directory beside it, so the
    alias differs only in a component ``physical_path`` never resolves;
    ``hardlink`` gives the file a second name in the directory it is already
    in. Both are ordinary things to find in a repository, and neither is a
    symlink at the final component -- which is the one form the token read
    already refuses, before ``O_NOFOLLOW`` would.
    """

    if alias == "symlinked-parent":
        linked_day = tree.records / "day-alias"
        linked_day.symlink_to(token.parent, target_is_directory=True)
        return linked_day / token.name
    second = token.parent / f"{token.stem}.linked.tsr"
    os.link(token, second)
    return second


@pytest.mark.parametrize("alias", ["symlinked-parent", "hardlink"])
def test_refuses_two_outcomes_whose_paths_reach_one_response_file(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
    alias: str,
) -> None:
    """S5R2-F2: the rule is about the file, and a path is not the file.

    The path rule keys the lexical path a claim resolves to -- the string
    ``physical_path`` returns -- while the containment check inside
    ``physical_path`` resolves symlinks. So one object under two names is two
    paths to the rule and one file to the filesystem: a symlink to the token
    directory, or a second hard link to the response, and the two outcomes
    are distinct by every comparison the module made. The declared-digest
    rule does not see it either, because with a writer arriving between the
    two reads the outcomes read different bytes out of that one object and
    each declares truly what it read -- which is the same evidence the path
    rule exists to refuse, reached by a spelling it cannot compare.

    So the identity is taken from the ``fstat`` that judges the descriptor
    the bytes came out of, which names the object rather than the name it was
    asked for; a second ``stat`` of the pathname would be exactly the race
    being refused. Without the rule this witness returns two ``TokenEvidence``
    entries covering a two-anchor bundle out of one file. With it the second
    outcome is refused at its read, before its bytes reach OpenSSL: the
    recorder below shows ``ts -reply`` ran once. The control is the tree
    untouched -- two genuinely distinct files are still two tokens, and the
    two objects behind them are two.

    S6-F1 puts a rule upstream of this one, and the two shapes part company
    there. A symlinked parent is now refused by the component walk before the
    aliased outcome is read at all, so that shape asserts the walk's refusal
    and a read count of zero; what still binds the object rule is the hard
    link, which is a second name in a directory with no link in it anywhere.
    Both shapes are kept, because the object rule is what stands if the walk
    is ever lost, and the walk is what stands if a repository grows a link
    the object rule cannot see through -- an entry *replaced* between the two
    reads, which
    ``test_a_witness_token_path_may_not_traverse_a_symlink`` is about.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    tree = build_witness_tree(tmp_path, local_anchors[:2])
    shared = tree.tokens[alpha.anchor_id]
    betas_response = tree.tokens[beta.anchor_id].read_bytes()

    # The control: two outcomes, two files, two objects, two tokens.
    control = verify_tree(tree)
    assert [token.anchor_id for token in control.tokens] == [
        alpha.anchor_id,
        beta.anchor_id,
    ]
    assert file_identity(shared) != file_identity(tree.tokens[beta.anchor_id])

    second_name = one_file_under_a_second_name(tree, shared, alias)
    # The premise: two paths no lexical comparison joins, one object.
    first_physical = tsa_module.physical_path(
        tree.records.resolve(), logical_path(tree.records, shared)
    )
    second_physical = tsa_module.physical_path(
        tree.records.resolve(), logical_path(tree.records, second_name)
    )
    assert str(first_physical) != str(second_physical)
    assert file_identity(first_physical) == file_identity(second_physical)
    assert not second_physical.is_symlink()

    def point_betas_outcome_at_the_second_name(payload: dict[str, Any]) -> None:
        first, second = payload["anchorOutcomes"]
        assert (first["tsaAnchorId"], second["tsaAnchorId"]) == (
            alpha.anchor_id,
            beta.anchor_id,
        )
        second["tokenPath"] = logical_path(tree.records, second_name)
        second["tokenSha256"] = sha256_bytes(betas_response)

    rewrite_witness(tree, point_betas_outcome_at_the_second_name)
    writes = serve_a_second_response_from_one_path(monkeypatch, shared, betas_response)
    reads = record_one_reads(monkeypatch)
    invocations = record_openssl_arguments(monkeypatch)
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    # The writer really did run, and both declared digests are true of what
    # their own outcome read out of the one object.
    assert writes == [str(shared)]
    assert shared.read_bytes() == betas_response
    if alias == "symlinked-parent":
        # Pre-empted by the component walk, which is upstream of every
        # identity rule and refuses before this outcome is read at all.
        assert str(caught.value) == (
            "witness token path traverses a symlink at "
            f"{tree.records.resolve() / 'day-alias'}: {second_physical}"
        )
        assert reads.count(str(second_physical)) == 0
    else:
        assert str(caught.value) == (
            f"duplicate TSA token file across anchor outcomes: {second_physical} "
            f"is the same file as {first_physical}"
        )
        # Read twice, because the identity is what the second read reports.
        assert reads.count(str(second_physical)) == 1
    # Put to OpenSSL once, because the refusal arrives before that read is used.
    assert reads.count(str(first_physical)) == 1
    assert [arguments[:2] for arguments in invocations].count(["ts", "-reply"]) == 1


def replace_the_response_between_the_reads(
    monkeypatch: pytest.MonkeyPatch, target: pathlib.Path, content: bytes
) -> list[str]:
    """Unlink ``target`` and put ``content`` at that name, once.

    The writer the fold rule exists for.
    ``serve_a_second_response_from_one_path`` truncates and rewrites, which
    leaves the inode alone, so the object rule still sees one file. This
    replaces the *directory entry*, so a second read of that same entry opens
    a different object: the object rule sees two files, the digest rule sees
    two true digests, and only a rule about the name is left. It arrives at
    the first ``ts -verify``, which is after the first outcome has taken its
    one read and snapshotted it, so nothing about that outcome moves. Returns
    the write, so a test can show the writer ran.
    """

    original = tsa_module._run_openssl
    writes: list[str] = []

    def writing(arguments: list[str], **keywords: Any) -> Any:
        if arguments[:2] == ["ts", "-verify"] and not writes:
            target.unlink()
            target.write_bytes(content)
            writes.append(str(target))
        return original(arguments, **keywords)

    monkeypatch.setattr(tsa_module, "_run_openssl", writing)
    return writes


def spelled_the_other_way(logical: str, alias: str) -> str:
    """One declared token path, spelled the way a folding filesystem folds.

    ``case`` upper-cases the final component; ``normalisation`` decomposes the
    whole string. Both name the same directory entry on APFS or NTFS -- and
    HFS+ stores only the decomposed form -- while differing from the original
    by every comparison of the strings themselves.
    """

    if alias == "case":
        parts = pathlib.PurePosixPath(logical).parts
        return str(pathlib.PurePosixPath(*parts[:-1], parts[-1].upper()))
    return unicodedata.normalize("NFD", logical)


@pytest.mark.parametrize("alias", ["case", "normalisation"])
def test_refuses_two_outcomes_whose_paths_fold_to_one_directory_entry(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
    alias: str,
) -> None:
    """S5R3-F4: a spelling is not a directory entry either.

    The path rule keyed the raw spelling ``physical_path`` returns, so
    ``Token.tsr`` and ``token.tsr`` -- or a precomposed name and its
    decomposed spelling -- were two paths to the rule and one directory entry
    to APFS, NTFS or HFS+. The object rule does not close it: a writer that
    *replaces* the entry between the two reads gives the second read a
    different inode, so the two outcomes read two objects out of one name.
    Nor does the declared-digest rule, because each outcome then declares
    truly what it read. Every identity behind the name is blind, and the name
    is what the two outcomes share.

    So the rule is keyed on a portable fold of the physical path -- NFC, then
    ``casefold``, component by component, the fold ``receipt.corpus`` computes
    over its own declared paths -- and fold-equal spellings are refused before
    either response is read. Without it the witness below returns two
    ``TokenEvidence`` entries covering a two-anchor bundle out of one
    directory entry, on any filesystem that folds; the rule itself is lexical,
    so it holds on filesystems that do not, which is the point -- a witness
    whose meaning depends on which filesystem an auditor cloned onto is not
    one an auditor can act on.

    The control is the untouched tree: two outcomes at two paths that do not
    fold together are still two tokens.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    tree = build_witness_tree(tmp_path, local_anchors[:2])
    shared = tree.tokens[alpha.anchor_id]
    betas_response = tree.tokens[beta.anchor_id].read_bytes()

    # The control: two outcomes, two paths that fold to two, two tokens.
    control = verify_tree(tree)
    assert [token.anchor_id for token in control.tokens] == [
        alpha.anchor_id,
        beta.anchor_id,
    ]
    assert tsa_module._path_fold(shared) != tsa_module._path_fold(
        tree.tokens[beta.anchor_id]
    )

    if alias == "normalisation":
        # A name the two Unicode spellings of which differ at all.
        renamed = shared.parent / unicodedata.normalize(
            "NFC", f"réponse-alpha.{alpha.anchor_id}.tsr"
        )
        shared.rename(renamed)
        tree.tokens[alpha.anchor_id] = renamed
        shared = renamed

    declared = logical_path(tree.records, shared)
    second_spelling = spelled_the_other_way(declared, alias)
    first_physical = tsa_module.physical_path(tree.records.resolve(), declared)
    second_physical = tsa_module.physical_path(tree.records.resolve(), second_spelling)
    # The premise: two spellings no comparison of the strings joins, one key.
    assert second_spelling != declared
    assert str(second_physical) != str(first_physical)
    assert tsa_module._path_fold(second_physical) == tsa_module._path_fold(
        first_physical
    )

    def point_both_outcomes_at_one_entry(payload: dict[str, Any]) -> None:
        first, second = payload["anchorOutcomes"]
        assert (first["tsaAnchorId"], second["tsaAnchorId"]) == (
            alpha.anchor_id,
            beta.anchor_id,
        )
        first["tokenPath"] = declared
        second["tokenPath"] = second_spelling
        second["tokenSha256"] = sha256_bytes(betas_response)

    rewrite_witness(tree, point_both_outcomes_at_one_entry)
    writes = replace_the_response_between_the_reads(
        monkeypatch, shared, betas_response
    )
    reads = record_one_reads(monkeypatch)
    invocations = record_openssl_arguments(monkeypatch)
    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    # The writer really did run, and really did put a second object there.
    assert writes == [str(shared)]
    assert shared.read_bytes() == betas_response
    assert str(caught.value) == (
        f"duplicate TSA token path across anchor outcomes: {second_physical} "
        f"and {first_physical} are one path on a case- or "
        "normalisation-insensitive filesystem"
    )
    # Refused before the second read, and before the second verification.
    assert reads.count(str(first_physical)) == 1
    assert reads.count(str(second_physical)) == 0
    assert [arguments[:2] for arguments in invocations].count(["ts", "-reply"]) == 1


def link_a_directory_over(target: pathlib.Path) -> pathlib.Path:
    """Move ``target`` aside and leave a symlink to it at its own name.

    The component the walk exists for, in the form a repository grows one:
    every path through ``target`` still resolves to the same files, still
    passes ``is_file``, and still has no link at its final component. What
    changed is one directory in the middle, and nothing downstream of a name
    can see it.
    """

    moved = target.with_name(f"{target.name}.real")
    target.rename(moved)
    target.symlink_to(moved.name, target_is_directory=True)
    assert target.is_symlink() and target.is_dir()
    return moved


def replace_a_parent_after_its_component_check(
    monkeypatch: pytest.MonkeyPatch,
    parent: pathlib.Path,
    *,
    subject: str,
    replacement: str,
) -> list[str]:
    """Replace ``parent`` after the lexical preflight for ``subject`` returns."""

    original = tsa_module._refuse_a_linked_component
    swapped: list[str] = []

    def checking(
        root: pathlib.Path, path: pathlib.Path, *, subject: str
    ) -> tuple[pathlib.Path, ...]:
        components = original(root, path, subject=subject)
        if subject == expected_subject and not swapped:
            moved = parent.with_name(f"{parent.name}.checked")
            parent.rename(moved)
            if replacement == "symlink":
                parent.symlink_to(moved.name, target_is_directory=True)
            else:
                parent.write_bytes(b"the checked directory is a file now\n")
            swapped.append(str(parent))
        return components

    expected_subject = subject
    monkeypatch.setattr(tsa_module, "_refuse_a_linked_component", checking)
    return swapped


def test_descriptor_walk_refuses_a_parent_swapped_to_a_symlink_after_preflight(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S6-R2-F1: the checked parent must be the parent used by the read.

    The pathname walk returned while the token's day directory was real, then
    this writer replaced it with a symlink before the leaf open.  Without
    descriptor-anchored descent, the later whole-path open follows the link
    and the valid aliased response verifies; the old preflight has proved a
    fact about an object the read never uses.  The fixed read refuses in the
    established traversal words, and the successful-read recorder proves no
    byte of the aliased target reached the one-read snapshot.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    assert verify_tree(tree).status == "available"
    parent = tree.records / RECORD_DAY
    token = tree.tokens[alpha.anchor_id]
    swapped = replace_a_parent_after_its_component_check(
        monkeypatch,
        parent,
        subject="witness token path",
        replacement="symlink",
    )
    reads = record_one_reads(monkeypatch)

    with pytest.raises(TsaError) as caught:
        verify_tree(tree)

    assert swapped == [str(parent)]
    assert parent.is_symlink()
    assert str(caught.value) == (
        f"witness token path traverses a symlink at {parent}: "
        f"{token}"
    )
    assert str(token) not in reads


def test_descriptor_walk_refuses_a_parent_swapped_to_a_regular_file(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S6-R2-F1: an interior component must still be a directory at open.

    The lexical check sees the record's day directory and this writer replaces
    it with a regular file before the read.  A whole-path open merely reaches
    ``ENOTDIR`` and collapses that fact into the generic missing-record text;
    the descriptor walk instead refuses the changed component by name as not
    a directory, before any leaf can be opened or read.
    """

    tree = build_witness_tree(tmp_path, local_anchors[:1])
    assert verify_tree(tree).status == "available"
    parent = tree.records / RECORD_DAY
    swapped = replace_a_parent_after_its_component_check(
        monkeypatch,
        parent,
        subject="witnessed record path",
        replacement="file",
    )
    reads = record_one_reads(monkeypatch)

    with pytest.raises(TsaError) as caught:
        verify_tree(tree)

    assert swapped == [str(parent)]
    assert parent.is_file() and not parent.is_dir()
    assert str(caught.value) == (
        f"witnessed record path component is not a directory at {parent}: "
        f"{tree.record}"
    )
    assert str(tree.record) not in reads


def test_a_witness_token_path_may_not_traverse_a_symlink(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S6-F1: a symlinked parent plus a replaced entry defeats all four rules.

    The token-path rule keys the fold of the lexical path ``physical_path``
    returns and throws away the resolved path the containment check inside it
    computed, so a direct path and an alias of the token's *directory* are two
    keys. Each of the other three rules is downstream of a name that has
    already come apart from its object: with the shared entry *replaced*
    between the two reads -- not rewritten -- the second read opens a new
    inode, so the object rule sees two files; each outcome declares truly what
    it read, so the digest rule sees two digests; and the two responses are
    genuine issuances by two different authorities, so the timestamp rule sees
    two timestamps. Every identity passes, and the witness returns two
    ``TokenEvidence`` entries covering a two-anchor bundle for responses the
    repository never held at both paths at once.

    Four blind rules is a statement about where the rule belongs, not about
    which of them to strengthen: no component of a path this module reads may
    be a link. Checked with ``lstat`` from the records root down for the cheap
    established verdict, then opened through descriptors anchored there so a
    checked component cannot be exchanged before the leaf read. The preflight
    remains behind the path-level check so that a link at the final component
    keeps the refusal it already had.
    Without the walk this tree verifies with two tokens; the premises below
    are asserted rather than assumed, one per rule the walk stands in front
    of, and the control is the untouched tree.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    tree = build_witness_tree(tmp_path, local_anchors[:2])
    shared = tree.tokens[alpha.anchor_id]
    betas_response = tree.tokens[beta.anchor_id].read_bytes()
    alphas_response = shared.read_bytes()

    # The control: two outcomes, two entries, two objects, two tokens.
    control = verify_tree(tree)
    assert [token.anchor_id for token in control.tokens] == [
        alpha.anchor_id,
        beta.anchor_id,
    ]
    original_object = file_identity(shared)
    # Hold the original object open for the rest of the test. The writer
    # below unlinks the entry and creates a new file at the name; a filesystem
    # that hands a freed inode number straight back to the next file it
    # creates -- ext4 does, APFS does not -- then makes the replacement report
    # the very identity it replaced, and the object-rule premise asserted after
    # the run fails on Linux while passing on macOS. Holding the first object
    # keeps its number allocated, so "a second object at the one entry" is
    # observable by number wherever the test runs. It is also the honest
    # statement of the object rule's reach: a number can only be relied on to
    # tell two objects apart while one of them is held.
    held_original = os.open(shared, os.O_RDONLY)
    try:

        linked_day = tree.records.resolve() / "day-alias"
        linked_day.symlink_to(shared.parent, target_is_directory=True)
        second_name = linked_day / shared.name
        declared = logical_path(tree.records, shared)
        second_spelling = logical_path(tree.records, second_name)
        first_physical = tsa_module.physical_path(tree.records.resolve(), declared)
        second_physical = tsa_module.physical_path(
            tree.records.resolve(), second_spelling
        )
        # The premises, one per rule the walk stands in front of. The fold rule:
        # two spellings no fold joins. The object rule: one object now, and a
        # different one once the entry is replaced, asserted after the run. The
        # digest rule: two different declared digests. The timestamp rule: two
        # genuine issuances by two authorities. And the check that is already
        # there sees nothing -- the alias is a file, and not a link itself.
        assert tsa_module._path_fold(second_physical) != tsa_module._path_fold(
            first_physical
        )
        assert file_identity(second_physical) == file_identity(first_physical)
        assert sha256_bytes(alphas_response) != sha256_bytes(betas_response)
        assert second_physical.is_file() and not second_physical.is_symlink()

        def point_betas_outcome_through_the_alias(payload: dict[str, Any]) -> None:
            first, second = payload["anchorOutcomes"]
            assert (first["tsaAnchorId"], second["tsaAnchorId"]) == (
                alpha.anchor_id,
                beta.anchor_id,
            )
            second["tokenPath"] = second_spelling
            second["tokenSha256"] = sha256_bytes(betas_response)

        rewrite_witness(tree, point_betas_outcome_through_the_alias)
        writes = replace_the_response_between_the_reads(
            monkeypatch, shared, betas_response
        )
        reads = record_one_reads(monkeypatch)
        invocations = record_openssl_arguments(monkeypatch)
        with pytest.raises(TsaError) as caught:
            verify_tree(tree)
        assert str(caught.value) == (
            f"witness token path traverses a symlink at {linked_day}: "
            f"{second_physical}"
        )
        # The writer really did run, and really did put a second object at the
        # one entry: the object rule would have counted two files.
        assert writes == [str(shared)]
        assert shared.read_bytes() == betas_response
        assert file_identity(shared) != original_object
        assert file_identity(second_physical) == file_identity(first_physical)
        # Refused before the aliased outcome is read, and before its verification.
        assert reads.count(str(first_physical)) == 1
        assert reads.count(str(second_physical)) == 0
        assert [arguments[:2] for arguments in invocations].count(["ts", "-reply"]) == 1
    finally:
        os.close(held_original)


@pytest.mark.parametrize("victim", ["record", "root"])
def test_no_read_this_module_makes_traverses_a_symlinked_component(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...], victim: str
) -> None:
    """S6-F1: the same walk in front of the other two reads of the tree.

    The token path is where the harm was found, and it is not the only path
    this module resolves out of the repository and then reads. The record
    under witness and each anchor's pinned root are read the same way -- a
    path-level check about a name, ``O_NOFOLLOW`` about the object opened, and
    nothing at all about the components between the records root and the final
    one. A directory replaced by a link to itself leaves every one of those
    checks answering exactly as it did, which is what the premises below
    assert: the file is still a regular file, still not a link, and still
    holds the same bytes.

    Without the guarded descent both cases verify unchanged, so what binds the fix is
    the refusal. Each keeps the wording of the read it guards -- the record's
    is its own, the root's arrives inside the load-time wrapper that carries
    every root material failure -- and the control is the tree before the
    directory is moved.

    The residual, deliberately: the trust bundle, the witness sidecar and the
    chain genesis are read through ``_load_json_once``, which refuses a link
    at the final component but walks no components. The sidecar's are the
    record's, and genesis sits directly under the records root, so the only
    component this module reads through that no walk covers is
    ``records/trust`` -- which the ``root`` case here puts a link at, and
    which the bundle load then reads through without complaint. Benign, and
    not silently so: a bundle's bytes are pinned by ``TrustBundleSpec``
    entire, so whatever a link leads to must be the pinned bytes or the
    commitment mismatch refuses it.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    assert verify_tree(tree).status == "available"
    records = tree.records.resolve()
    root_path = records / "trust" / alpha.tsa.root_pem.name

    if victim == "record":
        component = records / RECORD_DAY
        before = tree.record.read_bytes()
        link_a_directory_over(tree.records / RECORD_DAY)
        expected = (
            f"witnessed record path traverses a symlink at {component}: "
            f"{tree.record}"
        )
    else:
        component = records / "trust"
        before = root_path.read_bytes()
        link_a_directory_over(tree.records / "trust")
        expected = (
            f"TSA anchor {alpha.anchor_id} in bundle {BUNDLE_ID} references "
            "root material that fails validation: pinned TSA root path "
            f"traverses a symlink at {component}: {root_path}"
        )

    # The premise: everything the existing checks look at is unchanged.
    victim_path = tree.record if victim == "record" else root_path
    assert component.is_symlink()
    assert victim_path.is_file() and not victim_path.is_symlink()
    assert victim_path.read_bytes() == before

    with pytest.raises(TsaError) as caught:
        verify_tree(tree)
    assert str(caught.value) == expected


def pending_authority(
    tree: WitnessTree,
    anchor: LocalAnchor,
    *,
    version: int,
    base: TsaSpec | None = None,
    extra_signers: Mapping[str, Sequence[dict[str, str]]] | None = None,
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
    return add_bundle_version(
        tree,
        [anchor],
        version=version,
        base=base,
        extra_signers=extra_signers,
    )


def supplemental_outcome(
    tree: WitnessTree,
    pending: Mapping[str, Any],
    anchor: LocalAnchor,
    token: pathlib.Path,
    *,
    signer: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """One ``supplementalOutcomes`` member offering ``token`` for ``anchor``.

    Everything a witness says about a response, for the anchor a pending
    bundle introduces: the bundle it belongs to, the anchor it answers for,
    the file, and what stamped it. ``signer`` names the certificate that did,
    for a pending anchor whose allowed signer is not the one its
    ``LocalAnchor`` was built around -- a rotated key filed under a new name;
    without it the anchor's own pins are declared, which is every other case.
    """

    pins = dict(signer or anchor.signer_pins)
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
        "tsaSignerCertificateSha256": pins["certificateSha256"],
        "tsaSignerSpkiSha256": pins["spkiSha256"],
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
        return verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[pending],
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
        return verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[pending],
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
        verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[unrelated],
        )
    assert str(caught.value) == (
        "supplemental TSA outcome mismatch: "
        f"missing=[('{unrelated['path']}', '{stranger.anchor_id}')], extra=[]"
    )


def test_a_pending_anchor_may_not_mix_an_active_signer_with_a_new_one(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
) -> None:
    """S5R2-F4: partly-active is not active, and it is not new either.

    The signer half of the skip asked whether *any* of a pending anchor's
    allowed signers was already active, which reads a set as though it had one
    member. An anchor declaring an active signer beside a new one -- a
    genuinely new authority with an old key listed next to its own -- was
    therefore skipped wholesale: the transition demanded nothing of it and
    activated it with no supplemental evidence at all, which is the whole of
    what the supplemental outcome exists to require.

    Nor can it simply be called new. The supplemental outcome is supposed to
    show that whoever holds the new key answered, and an anchor that also
    allows the old key satisfies it with a stamp by the authority the chain
    already trusts -- the same one-authority-two-stamps the rename rule
    refuses. Neither reading is true of such an anchor, so it is refused and
    the producer is told what to do about it: split the rotation from the new
    authority. The three shapes are asserted here together, because what the
    rule has to do is tell them apart -- a signer set already active entire is
    a rename and is skipped, a disjoint one is a candidate, and one that is
    partly both is refused before any outcome is looked at.

    Reverted to "any overlap is a rename", the mixed anchor below is skipped
    and the witness verifies with no supplemental evidence for it.

    S5R3-F2: the words it is refused in are the family's, not this shape's.
    An anchor allowing an active key beside a new one is one of three ways a
    pending anchor can carry part of an active authority and not the whole of
    it -- the others are a split and a merge, in the two tests below -- and
    all three have one fix, which the message states: a pending anchor carries
    one active anchor's signers exactly, or none of them.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    renamed = alias_of(alpha, anchor_id="alpha-renamed-2026")
    rename, spec = add_bundle_version(tree, [renamed], version=2)
    stranger = alias_of(beta, anchor_id="beta-arriving-2026")
    arrival, spec = pending_authority(tree, stranger, version=3, base=spec)
    mixed = alias_of(beta, anchor_id="beta-mixed-2026")
    mixture, spec = pending_authority(
        tree,
        mixed,
        version=4,
        base=spec,
        extra_signers={mixed.anchor_id: [alpha.signer_pins]},
    )
    # The premise: one pending anchor allowing the active signing key and a
    # key no active anchor allows, both.
    declared = json.loads(
        (tree.records / "trust" / "tsa-anchors-v4.json").read_text()
    )["anchors"][0]["allowedSigners"]
    assert {signer["spkiSha256"] for signer in declared} == {
        alpha.signer_pins["spkiSha256"],
        beta.signer_pins["spkiSha256"],
    }

    def candidates_for(pending: dict[str, Any]) -> set[tuple[str, str]]:
        return set(
            tsa_module._supplemental_candidates(
                tree.records,
                {BUNDLE_LOGICAL: tree.reference},
                [pending],
                spec=spec,
            )
        )

    assert candidates_for(rename) == set()
    assert candidates_for(arrival) == {(arrival["path"], stranger.anchor_id)}
    mixes = (
        f"pending TSA anchor {mixed.anchor_id} splits or merges active "
        "authorities' signers; a pending anchor must carry one active "
        "anchor's signers exactly, or none of them"
    )
    with pytest.raises(TsaError) as caught:
        candidates_for(mixture)
    assert str(caught.value) == mixes
    # And the whole witness is refused, rather than verifying with nothing
    # supplemental required of the anchor that is about to activate.
    with pytest.raises(TsaError) as whole:
        verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[mixture],
        )
    assert str(whole.value) == mixes


def test_a_pending_anchor_carries_one_active_authoritys_signers_or_none(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """S5R3-F2: a rename carries a whole equivalence class, not a piece of one.

    The skip asked whether a pending anchor's signers were a subset of *the*
    active signers, flattened into one set. Ownership is exactly what that
    flattening throws away, and ownership is the whole of what a rename is: an
    anchor carrying one active authority's keys under a new name, so that
    stamping again would prove nothing the chain has not already asked about.

    An active anchor may allow more than one signing key at once -- a
    frozenset with no singleton constraint, which is what
    ``test_one_bundle_may_allow_several_signers_at_once`` is about -- and a
    pending bundle could then split it in two, one key each, both anchors
    subsets of the flattened set and both skipped as renames. Two authorities
    activate where the chain had asked about one, neither having answered for
    itself, and each holding a key the other does not: they can sign
    independently from that point on, which is the difference the supplemental
    outcome exists to make somebody demonstrate.

    Three shapes over one active authority allowing two keys, because telling
    them apart is what the rule does: an anchor carrying one of the two keys
    is a split and is refused; an anchor carrying both is that authority
    renamed and is skipped; and an authority whose keys are its own is a
    candidate, which is the mechanism a split must not be able to walk around.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    rotated = certificate_pins(rotated_alpha.signer_pem)
    tree = build_witness_tree(
        tmp_path, local_anchors[:1], extra_signers={alpha.anchor_id: rotated_alpha}
    )
    assert verify_tree(tree).status == "available"
    renamed = alias_of(alpha, anchor_id="alpha-renamed-2026")
    split, spec = add_bundle_version(tree, [renamed], version=2)
    whole, spec = add_bundle_version(
        tree,
        [renamed],
        version=3,
        extra_signers={renamed.anchor_id: [rotated]},
        base=spec,
    )
    stranger = alias_of(beta, anchor_id="beta-arriving-2026")
    arrival, spec = pending_authority(tree, stranger, version=4, base=spec)
    # The premise: one active anchor allowing two keys, and a pending anchor
    # over the same root carrying one of them.
    active = json.loads(tree.bundle.read_text())["anchors"][0]
    assert {signer["spkiSha256"] for signer in active["allowedSigners"]} == {
        alpha.signer_pins["spkiSha256"],
        rotated["spkiSha256"],
    }
    halved = json.loads((tree.records / "trust" / "tsa-anchors-v2.json").read_text())
    assert {
        signer["spkiSha256"] for signer in halved["anchors"][0]["allowedSigners"]
    } == {alpha.signer_pins["spkiSha256"]}
    assert halved["anchors"][0]["rootCertificate"] == active["rootCertificate"]

    def candidates_for(pending: dict[str, Any]) -> set[tuple[str, str]]:
        return set(
            tsa_module._supplemental_candidates(
                tree.records,
                {BUNDLE_LOGICAL: tree.reference},
                [pending],
                spec=spec,
            )
        )

    splits = (
        f"pending TSA anchor {renamed.anchor_id} splits or merges active "
        "authorities' signers; a pending anchor must carry one active "
        "anchor's signers exactly, or none of them"
    )
    with pytest.raises(TsaError) as caught:
        candidates_for(split)
    assert str(caught.value) == splits
    assert candidates_for(whole) == set()
    assert candidates_for(arrival) == {(arrival["path"], stranger.anchor_id)}
    # And the whole witness is refused, rather than verifying with nothing
    # required of the half-authority that is about to activate.
    with pytest.raises(TsaError) as witness:
        verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[split],
        )
    assert str(witness.value) == splits


def test_a_pending_anchor_may_not_merge_two_active_authorities(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
) -> None:
    """S5R3-F2: and it may not gather two active authorities into one anchor.

    The inverse of the split, and misclassified for the same reason. With the
    active signers flattened into one set, an anchor allowing the keys of two
    different active authorities is a subset of that set and is skipped as a
    rename -- so two authorities the chain trusts separately become one anchor
    that either of them can stamp for, and every outcome that anchor answers
    thereafter is satisfied by whichever of the two happens to be reachable.
    A merge is a claim about who is who, and nothing here is in a position to
    take a producer's word for it.

    Both shapes are asserted over the same two active authorities: an anchor
    carrying one authority's keys entire is that authority renamed and is
    skipped, and an anchor carrying both authorities' keys is refused.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    tree = build_witness_tree(tmp_path, local_anchors[:2])
    assert verify_tree(tree).status == "available"
    merged = alias_of(beta, anchor_id="beta-merged-2026")
    merger, spec = add_bundle_version(
        tree,
        [merged],
        version=2,
        extra_signers={merged.anchor_id: [alpha.signer_pins]},
    )
    renamed = alias_of(beta, anchor_id="beta-renamed-2026")
    rename, spec = add_bundle_version(tree, [renamed], version=3, base=spec)
    # The premise: two active authorities with a key each, and a pending
    # anchor allowing both keys at once.
    active = json.loads(tree.bundle.read_text())["anchors"]
    assert [
        {signer["spkiSha256"] for signer in entry["allowedSigners"]}
        for entry in active
    ] == [{alpha.signer_pins["spkiSha256"]}, {beta.signer_pins["spkiSha256"]}]
    gathered = json.loads((tree.records / "trust" / "tsa-anchors-v2.json").read_text())
    assert {
        signer["spkiSha256"] for signer in gathered["anchors"][0]["allowedSigners"]
    } == {alpha.signer_pins["spkiSha256"], beta.signer_pins["spkiSha256"]}

    def candidates_for(pending: dict[str, Any]) -> set[tuple[str, str]]:
        return set(
            tsa_module._supplemental_candidates(
                tree.records,
                {BUNDLE_LOGICAL: tree.reference},
                [pending],
                spec=spec,
            )
        )

    assert candidates_for(rename) == set()
    merges = (
        f"pending TSA anchor {merged.anchor_id} splits or merges active "
        "authorities' signers; a pending anchor must carry one active "
        "anchor's signers exactly, or none of them"
    )
    with pytest.raises(TsaError) as caught:
        candidates_for(merger)
    assert str(caught.value) == merges
    with pytest.raises(TsaError) as witness:
        verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[merger],
        )
    assert str(witness.value) == merges


def test_a_rename_and_a_rotation_leave_one_class_a_further_rename_may_carry(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """S6-F3: an authority is its class, and a class outlives its names.

    The active signer sets were unioned per ``(anchor id, root SPKI)`` and no
    further, so what a rename joined at one transition was apart again at the
    next. Rename A to B and the two anchors are one authority, which is the
    whole reason the rename was skipped; rotate B's key and that one
    authority has two, one filed under each of its names. The per-anchor maps
    are then A's ``{S1}`` and B's ``{S1, S2}``, and a further rename -- an
    anchor carrying ``{S1, S2}``, which is the whole of what that authority
    now is, and a rename by exactly the rule that admitted the first one --
    equals neither of them and is refused. A chain that renamed an authority
    once and rotated its key could never rename it again, and the transition
    that tried was unwitnessable: no supplemental outcome can satisfy a
    refusal at the candidate walk.

    So the classes are the connected components of the active anchors, joined
    by a shared ``(id, root SPKI)`` or a shared signing key, and the rename
    test compares a pending anchor's signers with the class of every active
    anchor it touches. Transitive because the two joins say one thing at two
    moments: an activated rename made two anchors one authority, and a
    rotation under either name extended that one authority's keys.

    The change is a loosening and only a loosening. Where every touched
    anchor's own set equalled the pending signers, the class does too -- a
    component is connected through shared keys, so an anchor holding a key
    outside the pending set cannot be joined to one holding only keys inside
    it -- so nothing this used to skip is now refused. What it stops refusing
    is exactly the anchor that carries a whole class. The guard below is the
    other direction: an anchor carrying a proper subset of the merged class
    is the split it always was.

    Both the candidate walk and the whole witness are asserted, and the
    premises are read back out of the bundles that were written.
    """

    alpha = local_anchors[0]
    rotated = certificate_pins(rotated_alpha.signer_pem)
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    assert verify_tree(tree).status == "available"

    # The rename, activated: a second name over the active root and key.
    renamed = alias_of(alpha, anchor_id="alpha-renamed-2026")
    rename, spec = add_bundle_version(tree, [renamed], version=2)
    # The rotation, activated under that new name: the authority's second key.
    rotation, spec = add_bundle_version(
        tree,
        [renamed],
        version=3,
        extra_signers={renamed.anchor_id: [rotated]},
        base=spec,
    )
    active = {
        BUNDLE_LOGICAL: tree.reference,
        str(rename["path"]): rename,
        str(rotation["path"]): rotation,
    }
    # The further rename, pending: the whole of what that authority now is.
    again = alias_of(alpha, anchor_id="alpha-renamed-again-2026")
    whole, spec = add_bundle_version(
        tree,
        [again],
        version=4,
        extra_signers={again.anchor_id: [rotated]},
        base=spec,
    )
    # And the guard, pending: a proper subset of that same class.
    part = alias_of(alpha, anchor_id="alpha-halved-2026")
    subset, spec = add_bundle_version(
        tree, [part], version=5, signers={part.anchor_id: rotated}, base=spec
    )

    # The premises, read back out of the bundles that were written: one
    # authority spelled three ways, with one key under the first name and two
    # under the second, and a pending anchor carrying both.
    written = {
        version: json.loads(
            (tree.records / "trust" / f"tsa-anchors-v{version}.json").read_text()
        )["anchors"][0]
        for version in (1, 2, 3, 4, 5)
    }
    keys = {
        version: {signer["spkiSha256"] for signer in entry["allowedSigners"]}
        for version, entry in written.items()
    }
    assert keys[1] == {alpha.signer_pins["spkiSha256"]}
    assert keys[2] == {alpha.signer_pins["spkiSha256"]}
    assert keys[3] == {alpha.signer_pins["spkiSha256"], rotated["spkiSha256"]}
    assert keys[4] == keys[3]
    assert keys[5] == {rotated["spkiSha256"]}
    assert {written[version]["id"] for version in (1, 2, 3, 4, 5)} == {
        alpha.anchor_id,
        renamed.anchor_id,
        renamed.anchor_id,
        again.anchor_id,
        part.anchor_id,
    }
    assert (
        written[1]["rootCertificate"]
        == written[2]["rootCertificate"]
        == written[3]["rootCertificate"]
        == written[4]["rootCertificate"]
    )

    # And the class itself: two active authorities, one class, whose set is
    # neither of their own -- which is what "transitive" means here.
    authorities, class_of = tsa_module._active_anchor_identities(
        tree.records, active, spec=spec
    )
    first = (alpha.anchor_id, alpha.root_pins["spkiSha256"])
    second = (renamed.anchor_id, alpha.root_pins["spkiSha256"])
    assert authorities == {first, second}
    assert class_of[first] == class_of[second] == keys[3]
    assert class_of[first] != keys[1]

    def candidates_for(pending: dict[str, Any]) -> set[tuple[str, str]]:
        return set(
            tsa_module._supplemental_candidates(
                tree.records, active, [pending], spec=spec
            )
        )

    # The further rename is a rename: nothing to prove by stamping again.
    assert candidates_for(whole) == set()
    # The proper subset is the split it always was.
    splits = (
        f"pending TSA anchor {part.anchor_id} splits or merges active "
        "authorities' signers; a pending anchor must carry one active "
        "anchor's signers exactly, or none of them"
    )
    with pytest.raises(TsaError) as caught:
        candidates_for(subset)
    assert str(caught.value) == splits

    # And the whole witness, against the newest active bundle, which is the
    # one a v2 witness has to name.
    rewrite_witness(
        tree,
        lambda payload: payload.update(
            {
                "trustBundleId": str(rotation["bundleId"]),
                "trustBundlePath": str(rotation["path"]),
                "trustBundleSha256": str(rotation["sha256"]),
                "anchorOutcomes": [
                    {
                        **payload["anchorOutcomes"][0],
                        "tsaAnchorId": renamed.anchor_id,
                        "tsa": renamed.endpoint,
                    }
                ],
            }
        ),
    )

    def transition(pending: dict[str, Any]) -> WitnessEvidence:
        return verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles=active,
            prior_pending_updates=[pending],
        )

    evidence = transition(whole)
    assert evidence.status == "available"
    assert [token.anchor_id for token in evidence.tokens] == [renamed.anchor_id]
    assert evidence.supplemental_tokens == ()
    with pytest.raises(TsaError) as witness:
        transition(subset)
    assert str(witness.value) == splits


def test_a_skipped_pending_rotation_is_history_for_a_later_rename(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """S6-R2-F3: even a skipped rotation contributes its signer edge.

    A/S1 is active, pending v2 rotates A to S2, and pending v3 files S2
    under the new name B.  The rolling implementation skips A/S2 before it
    records anything, so B/S2 looks disjoint and becomes a new supplemental
    candidate.  In the persistent graph the skipped rotation joins S2 to A's
    historical class and B is the alias it is, leaving no new candidate.
    """

    alpha = local_anchors[0]
    rotated = certificate_pins(rotated_alpha.signer_pem)
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    rotation, spec = add_bundle_version(
        tree,
        [alpha],
        version=2,
        signers={alpha.anchor_id: rotated},
    )
    renamed = alias_of(alpha, anchor_id="alpha-after-rotation-2026")
    rename, spec = add_bundle_version(
        tree,
        [renamed],
        version=3,
        signers={renamed.anchor_id: rotated},
        base=spec,
    )

    assert tsa_module._supplemental_candidates(
        tree.records,
        {BUNDLE_LOGICAL: tree.reference},
        [rotation, rename],
        spec=spec,
    ) == {}


def test_a_pending_bundle_may_not_present_one_historical_class_twice(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """S6-R2-F2: the class, not either active identity, is the unit.

    A/S1 is activated under the rename B/S1, so the two active identities are
    one historical class.  A pending bundle then rotates them independently
    to A/S2 and B/S3.  Its current signer sets are disjoint, so the local
    shared-signer check passes, and the old active-identity shortcuts skip both
    anchors.  Without the class guard the bundle therefore makes one authority
    current twice; the completed graph must instead refuse both anchor slots
    by name and show the class that makes them one.
    """

    alpha = local_anchors[0]
    first_rotation = certificate_pins(rotated_alpha.signer_pem)
    second_rotation = certificate_pins(
        rotate_tsa_signer(alpha.tsa, tmp_path / "alpha-third").signer_pem
    )
    assert first_rotation["spkiSha256"] != second_rotation["spkiSha256"]
    tree = build_witness_tree(tmp_path / "tree", [alpha])
    renamed = alias_of(alpha, anchor_id="alpha-renamed-2026")
    rename, spec = add_bundle_version(tree, [renamed], version=2)
    pending, spec = add_bundle_version(
        tree,
        [alpha, renamed],
        version=3,
        signers={
            alpha.anchor_id: first_rotation,
            renamed.anchor_id: second_rotation,
        },
        base=spec,
    )
    written = json.loads(
        (tree.records / "trust" / "tsa-anchors-v3.json").read_text()
    )["anchors"]
    assert [
        {signer["spkiSha256"] for signer in anchor["allowedSigners"]}
        for anchor in written
    ] == [
        {first_rotation["spkiSha256"]},
        {second_rotation["spkiSha256"]},
    ]

    active = {BUNDLE_LOGICAL: tree.reference, str(rename["path"]): rename}
    class_members = ", ".join(
        f"{anchor_id}/{root_spki}"
        for anchor_id, root_spki in sorted(
            (
                (alpha.anchor_id, alpha.root_pins["spkiSha256"]),
                (renamed.anchor_id, alpha.root_pins["spkiSha256"]),
            )
        )
    )
    with pytest.raises(TsaError) as caught:
        tsa_module._supplemental_candidates(
            tree.records, active, [pending], spec=spec
        )
    assert str(caught.value) == (
        f"pending TSA bundle anchors {pending['path']}/{renamed.anchor_id} and "
        f"{pending['path']}/{alpha.anchor_id} resolve to one historical "
        f"authority class: {class_members}"
    )


def test_a_rotation_may_not_import_another_classs_historical_signer(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_beta: LocalTsa,
) -> None:
    """S6-R2-F2: importing another class's signer joins both anchor slots.

    Active A/S1 and B/S2 are separate classes.  The pending A anchor rotates
    to B's historical S2 while pending B rotates to fresh S3.  The new bundle
    again has disjoint current signer sets, but A's imported signer joins its
    identity to B's history.  Without the completed-graph bundle guard both
    active-identity shortcuts skip; with it the two slots resolve to the one
    class named by the refusal.
    """

    alpha, beta = local_anchors[:2]
    rotated = certificate_pins(rotated_beta.signer_pem)
    tree = build_witness_tree(tmp_path, [alpha, beta])
    pending, spec = add_bundle_version(
        tree,
        [alpha, beta],
        version=2,
        signers={
            alpha.anchor_id: beta.signer_pins,
            beta.anchor_id: rotated,
        },
    )
    class_members = ", ".join(
        f"{anchor_id}/{root_spki}"
        for anchor_id, root_spki in sorted(
            (
                (alpha.anchor_id, alpha.root_pins["spkiSha256"]),
                (beta.anchor_id, beta.root_pins["spkiSha256"]),
            )
        )
    )

    with pytest.raises(TsaError) as caught:
        tsa_module._supplemental_candidates(
            tree.records,
            {BUNDLE_LOGICAL: tree.reference},
            [pending],
            spec=spec,
        )
    assert str(caught.value) == (
        f"pending TSA bundle anchors {pending['path']}/{alpha.anchor_id} and "
        f"{pending['path']}/{beta.anchor_id} resolve to one historical "
        f"authority class: {class_members}"
    )


def test_a_rotation_may_not_adopt_another_active_classs_signer(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
) -> None:
    """S6-R3-R1: the class test asks the anchors it used to exempt.

    The residual round two's verification left behind. Active A/S1 and B/S2
    are separate classes. A pending bundle keeps A under its own ID and root
    and allows B's key beside A's own, and drops B's anchor slot altogether.
    Every rule looked away: A's ``(ID, root SPKI)`` is already active, so the
    split-or-merge test skipped it while ``history.add`` still ran and joined
    the two classes, and the per-bundle collision guard needs two slots in one
    bundle to see anything, so with B's slot gone there was nothing to pair A
    with. The merge the ``_supplemental_candidates`` docstring says is refused
    -- one anchor allowing both keys, which either authority can then stamp
    for -- was therefore accepted.

    Being already active settles what an anchor must prove, not whose keys it
    may hold, so the test now runs for it too, and both merged authorities
    have names the history can give.

    The premise asserted first is that the bundle really does let A's anchor
    answer with B's key and that B's own anchor is gone from it. Run with the
    ``already_known`` branch reduced to the bare ``continue`` it replaced, the
    call below returns candidates instead of refusing.
    """

    alpha, beta = local_anchors[:2]
    tree = build_witness_tree(tmp_path, [alpha, beta])
    pending, spec = add_bundle_version(
        tree,
        [alpha],
        version=2,
        extra_signers={alpha.anchor_id: [beta.signer_pins]},
    )
    # The premise: alpha's anchor may answer with beta's key, and beta's own
    # anchor is not in this bundle for the collision guard to pair it with.
    written = json.loads(
        (tree.records / "trust" / "tsa-anchors-v2.json").read_text()
    )["anchors"]
    assert [entry["id"] for entry in written] == [alpha.anchor_id]
    assert {
        signer["spkiSha256"] for signer in written[0]["allowedSigners"]
    } == {
        alpha.signer_pins["spkiSha256"],
        beta.signer_pins["spkiSha256"],
    }

    with pytest.raises(TsaError) as caught:
        tsa_module._supplemental_candidates(
            tree.records,
            {BUNDLE_LOGICAL: tree.reference},
            [pending],
            spec=spec,
        )
    assert str(caught.value) == (
        f"pending TSA anchor {pending['path']}/{alpha.anchor_id} merges "
        f"authority {alpha.anchor_id}/{alpha.root_pins['spkiSha256']} with "
        f"{beta.anchor_id}/{beta.root_pins['spkiSha256']}; an anchor whose "
        "(ID, root SPKI) the history already holds may rotate its own "
        "class's keys, but may not adopt another authority's signer"
    )


def test_a_rotation_may_not_take_another_active_classs_signer_outright(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
) -> None:
    """S6-R3-R1: the same merge, with the adopted key the only one allowed.

    The shape above leaves A's own key in place, so the merged anchor can be
    read as A with an extra key. Here A's anchor allows B's key and not its
    own, which is the same union of two classes reached by substitution
    rather than addition -- and it is not a rename, because a rename carries
    a new ID, while this keeps A's own ``(ID, root SPKI)``. Both went through
    the one door that did not ask.

    The premise asserted first is that the bundle's only anchor is A's, that
    it allows B's key alone, and that A's identity is the active one -- so it
    is the exempted door and not the rename path that is under test.
    """

    alpha, beta = local_anchors[:2]
    tree = build_witness_tree(tmp_path, [alpha, beta])
    pending, spec = add_bundle_version(
        tree,
        [alpha],
        version=2,
        signers={alpha.anchor_id: beta.signer_pins},
    )
    # The premise: one anchor, filed under alpha's active identity, allowing
    # beta's key and nothing else.
    written = json.loads(
        (tree.records / "trust" / "tsa-anchors-v2.json").read_text()
    )["anchors"]
    assert [entry["id"] for entry in written] == [alpha.anchor_id]
    assert written[0]["rootCertificate"]["spkiSha256"] == (
        alpha.root_pins["spkiSha256"]
    )
    assert {
        signer["spkiSha256"] for signer in written[0]["allowedSigners"]
    } == {beta.signer_pins["spkiSha256"]}

    with pytest.raises(TsaError) as caught:
        tsa_module._supplemental_candidates(
            tree.records,
            {BUNDLE_LOGICAL: tree.reference},
            [pending],
            spec=spec,
        )
    assert str(caught.value) == (
        f"pending TSA anchor {pending['path']}/{alpha.anchor_id} merges "
        f"authority {alpha.anchor_id}/{alpha.root_pins['spkiSha256']} with "
        f"{beta.anchor_id}/{beta.root_pins['spkiSha256']}; an anchor whose "
        "(ID, root SPKI) the history already holds may rotate its own "
        "class's keys, but may not adopt another authority's signer"
    )


def test_succession_keeps_the_predecessors_signer_in_pending_history(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_beta: LocalTsa,
) -> None:
    """S6-R2-F3: succession changes the candidate, not its class history.

    Pending B/S1 is succeeded by B/S2 and a later C/S1 names the first era
    again.  The rolling maps delete S1 when B/S2 replaces B/S1, so C/S1 is
    admitted as a second candidate.  A persistent component never deletes
    that signer edge: all three occurrences are one class and only its newest
    representation survives as the single candidate.
    """

    beta = local_anchors[1]
    rotated = certificate_pins(rotated_beta.signer_pem)
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    incoming = alias_of(beta, anchor_id="beta-history-2026")
    first, spec = pending_authority(tree, incoming, version=2)
    successor, spec = add_bundle_version(
        tree,
        [incoming],
        version=3,
        signers={incoming.anchor_id: rotated},
        base=spec,
    )
    renamed = alias_of(beta, anchor_id="charlie-history-2026")
    latest, spec = add_bundle_version(
        tree, [renamed], version=4, base=spec
    )

    assert set(
        tsa_module._supplemental_candidates(
            tree.records,
            {BUNDLE_LOGICAL: tree.reference},
            [first, successor, latest],
            spec=spec,
        )
    ) == {(latest["path"], renamed.anchor_id)}


def test_pending_anchor_array_order_does_not_change_the_class_verdict(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_beta: LocalTsa,
) -> None:
    """S6-R2-F3/F2: one prebuilt history makes array order irrelevant.

    After pending B/S1, one bundle contains successor B/S2 and alias C/S1.
    The rolling implementation accepts two candidates when B is visited first
    because succession deletes S1, but raises the pending-alias refusal when C
    is visited first because S1 still has an owner.  Sorting cannot repair a
    state machine whose answer depends on deletion.  Both permutations must
    instead produce the same class verdict; F2 then refuses because B and C
    occupy two slots of this one pending bundle while resolving to that class.
    """

    beta = local_anchors[1]
    rotated = certificate_pins(rotated_beta.signer_pem)
    incoming = alias_of(beta, anchor_id="beta-ordered-2026")
    renamed = alias_of(beta, anchor_id="charlie-ordered-2026")

    def verdict(order: Sequence[LocalAnchor], name: str) -> tuple[str, Any]:
        tree = build_witness_tree(tmp_path / name, local_anchors[:1])
        first, spec = pending_authority(tree, incoming, version=2)
        latest, spec = add_bundle_version(
            tree,
            order,
            version=3,
            signers={incoming.anchor_id: rotated},
            base=spec,
        )
        try:
            candidates = tsa_module._supplemental_candidates(
                tree.records,
                {BUNDLE_LOGICAL: tree.reference},
                [first, latest],
                spec=spec,
            )
        except TsaError as exc:
            return "refused", str(exc)
        return "accepted", tuple(sorted(candidates))

    forward = verdict([incoming, renamed], "forward")
    reverse = verdict([renamed, incoming], "reverse")
    assert forward == reverse
    class_members = ", ".join(
        f"{anchor_id}/{root_spki}"
        for anchor_id, root_spki in sorted(
            (
                (incoming.anchor_id, beta.root_pins["spkiSha256"]),
                (renamed.anchor_id, beta.root_pins["spkiSha256"]),
            )
        )
    )
    assert forward == (
        "refused",
        "pending TSA bundle anchors "
        f"records/trust/tsa-anchors-v3.json/{incoming.anchor_id} and "
        f"records/trust/tsa-anchors-v3.json/{renamed.anchor_id} resolve to "
        f"one historical authority class: {class_members}",
    )


def test_two_pending_bundles_contribute_one_candidate_for_one_class(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S5R2-F5/S6-R2-F3: one historical class contributes one candidate.

    Every equivalence the walk computed was against the *active* bundles, so
    two pending bundles were measured against nothing but those and against
    nothing at all with respect to each other. One authority introduced under
    two ids by two pending bundles was therefore two candidates: the
    transition demanded a supplemental outcome from each, and the authority
    satisfied both by stamping twice. Two genuine, distinct issuances -- no
    reuse for any duplicate rule to see -- and a transition that counted one
    new authority twice, which is the thing supplemental outcomes exist to
    count.

    The rolling fix refused the second name.  The persistent graph makes the
    stronger statement directly: both occurrences are one pending-only class,
    and only its newest representation is the candidate.  The witness below
    first answers for that survivor and verifies once.  With the graph's
    signer edges blinded, both names become candidates and two genuine stamps
    by one authority are counted, demonstrating the old harm rather than
    assuming it.

    The control is the case the rule must not touch: two pending bundles
    introducing two genuinely different authorities -- a stranger with a root
    and a key of its own, and a new id over the active root with a signing
    key no active anchor allows -- are still two candidates when walked
    together.
    """

    beta = local_anchors[1]
    tree = build_witness_tree(tmp_path / "one-authority", local_anchors[:1])
    pending_first, first, pending_second, second, spec = two_pending_authorities(
        tree, beta
    )
    digest = sha256_bytes(tree.record.read_bytes())
    responses = {}
    for alias in (first, second):
        response = tree.records / RECORD_DAY / f"record-0001.{alias.anchor_id}.tsr"
        beta.tsa.stamp(digest, response)
        responses[alias.anchor_id] = response
    # The premise: two genuine issuances, distinct by every identity the
    # duplicate rules count, so nothing but the walk can refuse this.
    assert sha256_bytes(responses[first.anchor_id].read_bytes()) != sha256_bytes(
        responses[second.anchor_id].read_bytes()
    )
    assert signed_timestamp_of(
        tmp_path, responses[first.anchor_id]
    ) != signed_timestamp_of(tmp_path, responses[second.anchor_id])

    first_outcome = supplemental_outcome(
        tree, pending_first, first, responses[first.anchor_id]
    )
    second_outcome = supplemental_outcome(
        tree, pending_second, second, responses[second.anchor_id]
    )
    rewrite_witness(
        tree,
        lambda payload: payload.__setitem__(
            "supplementalOutcomes", [second_outcome]
        ),
    )

    def transition() -> WitnessEvidence:
        return verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[pending_first, pending_second],
        )

    assert set(
        tsa_module._supplemental_candidates(
            tree.records,
            {BUNDLE_LOGICAL: tree.reference},
            [pending_first, pending_second],
            spec=spec,
        )
    ) == {(pending_second["path"], second.anchor_id)}
    evidence = transition()
    assert [token.anchor_id for token in evidence.supplemental_tokens] == [
        second.anchor_id
    ]

    # The harm, with the rule's input taken away: one authority, counted twice.
    rewrite_witness(
        tree,
        lambda payload: payload.__setitem__(
            "supplementalOutcomes", [first_outcome, second_outcome]
        ),
    )
    blind_the_pending_signer_reader(monkeypatch)
    evidence = transition()
    assert evidence.status == "available"
    assert [token.anchor_id for token in evidence.supplemental_tokens] == [
        first.anchor_id,
        second.anchor_id,
    ]
    assert len(
        {token.tsa_certificate_sha256 for token in evidence.supplemental_tokens}
    ) == 1


def test_a_rename_may_carry_the_classs_newest_era_and_not_a_superseded_one(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """S6-R2-F3: an era the class has left behind is not a name it may take.

    Keeping every historical edge is what lets a rename follow a rotation the
    walk skipped: A is active with S1, a pending bundle rotates it to S2, and
    a further pending bundle filing S2 under a new name is that authority
    renamed rather than a new one. The graph has to answer for the second
    bundle with the first bundle's skipped rotation in it, which is the whole
    of S6-R2-F3.

    But "some occurrence of this class once carried exactly these signers" is
    a weaker question than the rule it replaced, and the difference shows when
    a class rotates twice. Below, A rotates to S2 and then to S3, both skipped,
    and a new-id anchor then carries S2 -- an era the class left a version ago.
    Asked of every era, that anchor is a rename and activates a new anchor slot
    with no supplemental outcome at all, on the strength of a key the class no
    longer answers under; asked of the newest era, it is the split it is. The
    control is the same tree with the same anchor carrying S3, which is what
    the class currently answers under and is skipped.

    Reverted to ``occurrence.signers in {every era}``, the refusal below does
    not fire and the superseded name becomes a silent skip.
    """

    alpha = local_anchors[0]
    second = certificate_pins(rotated_alpha.signer_pem)
    third = certificate_pins(
        rotate_tsa_signer(alpha.tsa, tmp_path / "alpha-third").signer_pem
    )
    assert second["spkiSha256"] != third["spkiSha256"]
    tree = build_witness_tree(tmp_path / "tree", [alpha])
    to_second, spec = add_bundle_version(
        tree, [alpha], version=2, signers={alpha.anchor_id: second}
    )
    to_third, spec = add_bundle_version(
        tree, [alpha], version=3, signers={alpha.anchor_id: third}, base=spec
    )
    superseded = alias_of(alpha, anchor_id="alpha-superseded-2026")
    stale, spec = add_bundle_version(
        tree, [superseded], version=4, signers={superseded.anchor_id: second},
        base=spec,
    )
    current = alias_of(alpha, anchor_id="alpha-current-2026")
    fresh, spec = add_bundle_version(
        tree, [current], version=5, signers={current.anchor_id: third}, base=spec
    )
    # The premise: one active key, and two pending rotations of it, the second
    # of which is what the class now answers under.
    assert {
        signer["spkiSha256"]
        for signer in json.loads(tree.bundle.read_text())["anchors"][0][
            "allowedSigners"
        ]
    } == {alpha.signer_pins["spkiSha256"]}

    def candidates_for(*pending: dict[str, Any]) -> set[tuple[str, str]]:
        return set(
            tsa_module._supplemental_candidates(
                tree.records,
                {BUNDLE_LOGICAL: tree.reference},
                list(pending),
                spec=spec,
            )
        )

    # The name the class currently answers under is the rename it is.
    assert candidates_for(to_second, to_third, fresh) == set()
    # The name it answered under one rotation ago is not.
    with pytest.raises(TsaError) as caught:
        candidates_for(to_second, to_third, stale)
    assert str(caught.value) == (
        f"pending TSA anchor {superseded.anchor_id} splits or merges active "
        "authorities' signers; a pending anchor must carry one active "
        "anchor's signers exactly, or none of them"
    )


def test_a_later_bundles_merge_does_not_convict_an_earlier_bundle(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_beta: LocalTsa,
) -> None:
    """S6-R2-F2: the class guard asks the graph as of the bundle it judges.

    The guard refuses two anchors of one pending bundle that resolve to one
    historical class. Asked of the *finished* graph it can convict the wrong
    bundle: two genuinely distinct new authorities in one bundle become one
    class the moment a later bundle merges them, and the earlier bundle -- the
    honest one -- is then refused for the later one's defect, naming its two
    anchor slots for a collision it did not commit.

    The graph is therefore asked as of each bundle: the collision check runs
    inside the walk, immediately after that bundle's own edges are added and
    before any later bundle's are. The merge below is still refused, and the
    refusal names the anchor that merges rather than the two it merged.

    Run with the check moved back after the walk, the verdict below becomes
    the collision message naming the two anchors of the earlier bundle.
    """

    beta = local_anchors[1]
    rotated = certificate_pins(rotated_beta.signer_pem)
    tree = build_witness_tree(tmp_path / "tree", local_anchors[:1])
    (tree.records / "trust" / beta.tsa.root_pem.name).write_bytes(
        beta.tsa.root_pem.read_bytes()
    )
    first = alias_of(beta, anchor_id="beta-first-2026")
    second = alias_of(beta, anchor_id="beta-second-2026")
    distinct, spec = add_bundle_version(
        tree,
        [first, second],
        version=2,
        signers={second.anchor_id: rotated},
    )
    merger = alias_of(beta, anchor_id="beta-merger-2026")
    merging, spec = add_bundle_version(
        tree,
        [merger],
        version=3,
        extra_signers={merger.anchor_id: [rotated]},
        base=spec,
    )
    # The premise: two pending authorities with a key each, and a third anchor
    # in a later bundle carrying both keys.
    written = json.loads(
        (tree.records / "trust" / "tsa-anchors-v2.json").read_text()
    )["anchors"]
    assert [
        {signer["spkiSha256"] for signer in anchor["allowedSigners"]}
        for anchor in written
    ] == [{beta.signer_pins["spkiSha256"]}, {rotated["spkiSha256"]}]

    def candidates_for(*pending: dict[str, Any]) -> set[tuple[str, str]]:
        return set(
            tsa_module._supplemental_candidates(
                tree.records,
                {BUNDLE_LOGICAL: tree.reference},
                list(pending),
                spec=spec,
            )
        )

    # The earlier bundle alone is two authorities, and is not refused.
    assert candidates_for(distinct) == {
        (distinct["path"], first.anchor_id),
        (distinct["path"], second.anchor_id),
    }
    # Walked with the merger, the refusal names the merger.
    with pytest.raises(TsaError) as caught:
        candidates_for(distinct, merging)
    assert str(caught.value) == (
        f"pending TSA anchor {merger.anchor_id} splits or merges active "
        "authorities' signers; a pending anchor must carry one active "
        "anchor's signers exactly, or none of them"
    )


def test_an_elected_class_survivor_cannot_be_credited_twice_once_active(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
) -> None:
    """S6-R2-F3: what the withdrawn refusal guarded, guarded by the count.

    Round two withdrew the refusal for two pending bundles introducing one
    authority under two anchors: one class now contributes one candidate, its
    newest occurrence, and the other name is simply not a candidate. The
    refusal existed so that one new authority could not demand and receive two
    supplemental outcomes and be counted twice, and this is the assertion that
    the count does that work on its own -- both pending bundles activate, so
    the class ends up with two anchor slots the chain trusts, proven once. The
    transition is carried in through the step API, because this record carries
    no updates of its own and S6-R2-F4 refuses a supplied entry the one read
    did not derive.

    Two rules leave no witness that credits both. A v2 witness must name the
    newest active bundle, so a witness naming the older of the two is refused
    for that alone; and an outcome may only select an anchor that bundle
    configures, so an outcome for the other name is refused as an anchor the
    named bundle does not pin -- one version of the class per bundle is what
    makes that true. The only
    shape that could hold both names at once is one bundle carrying both, and
    that is what the class guard added by S6-R2-F2 refuses. So the withdrawal
    costs the producer a diagnosis and costs the verification nothing.
    """

    beta = local_anchors[1]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    pending_first, first, pending_second, second, spec = two_pending_authorities(
        tree, beta
    )
    # The premise: two names, one class, one candidate -- the newest.
    assert set(
        tsa_module._supplemental_candidates(
            tree.records,
            {BUNDLE_LOGICAL: tree.reference},
            [pending_first, pending_second],
            spec=spec,
        )
    ) == {(pending_second["path"], second.anchor_id)}

    digest = sha256_bytes(tree.record.read_bytes())
    proof = tree.records / RECORD_DAY / f"record-0001.{second.anchor_id}.tsr"
    beta.tsa.stamp(digest, proof)
    rewrite_witness(
        tree,
        lambda payload: payload.__setitem__(
            "supplementalOutcomes",
            [supplemental_outcome(tree, pending_second, second, proof)],
        ),
    )
    evidence = verify_step(
        tree.record,
        spec=spec,
        records=tree.records,
        trusted_bundles={BUNDLE_LOGICAL: tree.reference},
        prior_pending_updates=[pending_first, pending_second],
    )
    assert evidence.status == "available"
    assert [token.anchor_id for token in evidence.supplemental_tokens] == [
        second.anchor_id
    ]

    # Both bundles activate, so the class holds two anchor slots the chain
    # trusts. Neither can be credited beside the other.
    active = {
        BUNDLE_LOGICAL: tree.reference,
        str(pending_first["path"]): pending_first,
        str(pending_second["path"]): pending_second,
    }

    def outcome(anchor: LocalAnchor, token: pathlib.Path) -> dict[str, Any]:
        return {
            "tsaAnchorId": anchor.anchor_id,
            "tsa": anchor.endpoint,
            "status": "available",
            "tokenPath": logical_path(tree.records, token),
            "tokenSha256": sha256_bytes(token.read_bytes()),
            "tsaPolicyOid": anchor.tsa.policy_oid,
            "tsaImprintAlgorithmOid": SHA256_IMPRINT_OID,
            "tsaSignerCertificateSha256": anchor.signer_pins["certificateSha256"],
            "tsaSignerSpkiSha256": anchor.signer_pins["spkiSha256"],
        }

    other = tree.records / RECORD_DAY / f"record-0001.{first.anchor_id}.tsr"
    beta.tsa.stamp(digest, other)
    # The premise for the pair: two genuine, distinct issuances by the one
    # authority, so nothing but the rules below separates them.
    assert sha256_bytes(other.read_bytes()) != sha256_bytes(proof.read_bytes())

    def against(bundle: dict[str, Any], outcomes: list[dict[str, Any]]) -> None:
        rewrite_witness(
            tree,
            lambda payload: payload.update(
                {
                    "trustBundleId": str(bundle["bundleId"]),
                    "trustBundlePath": str(bundle["path"]),
                    "trustBundleSha256": str(bundle["sha256"]),
                    "anchorOutcomes": outcomes,
                    "supplementalOutcomes": [],
                }
            ),
        )
        verify_witness(
            tree.record, spec=spec, records=tree.records, trusted_bundles=active
        )

    # Both names at once, against the newest bundle: the older name is extra.
    with pytest.raises(TsaError) as both:
        against(pending_second, [outcome(second, proof), outcome(first, other)])
    assert str(both.value) == (
        "witness does not select exactly one pinned TSA anchor: "
        f"id={first.anchor_id!r}, endpoint={first.endpoint!r}"
    )
    # The older name alone, against its own bundle: not the newest active one.
    with pytest.raises(TsaError) as older:
        against(pending_first, [outcome(first, other)])
    assert str(older.value) == (
        "multi-token witness does not use the newest active TSA trust bundle"
    )


def test_two_pending_bundles_may_introduce_two_authorities(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """S5R2-F5/S6-R2-F3: graph components collapse aliases and nothing else.

    The persistent graph leaves one candidate per pending-only class, so the
    case it must not collapse is two pending bundles that introduce two
    authorities. A stranger with a root and a signing key of its own shares
    nothing with anything; a new id over the *active* root with a rotated
    signing key shares its root certificate with the active anchor and its id
    with nobody, and its key is one no active anchor allows. Neither is the
    other, and walked together both are candidates.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    rotated = certificate_pins(rotated_alpha.signer_pem)
    tree = build_witness_tree(tmp_path / "two-authorities", local_anchors[:1])
    stranger = alias_of(beta, anchor_id="beta-arriving-2026")
    arrival, spec = pending_authority(tree, stranger, version=2)
    renamed_and_rotated, spec = add_bundle_version(
        tree,
        [alias_of(alpha, anchor_id="alpha-renamed-2026")],
        version=3,
        signers={"alpha-renamed-2026": rotated},
        base=spec,
    )
    walked = tsa_module._supplemental_candidates(
        tree.records,
        {BUNDLE_LOGICAL: tree.reference},
        [arrival, renamed_and_rotated],
        spec=spec,
    )
    assert set(walked) == {
        (arrival["path"], stranger.anchor_id),
        (renamed_and_rotated["path"], "alpha-renamed-2026"),
    }


def test_a_later_pending_bundle_succeeds_the_authority_an_earlier_one_introduced(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_beta: LocalTsa,
) -> None:
    """S5R3-F3: v2 and v3 in one catch-up are one authority, not two.

    ``trust_bundle_updates`` enumerates every consumer-pinned bundle the chain
    has not introduced yet, so a record that catches up over several versions
    carries v2 and v3 together -- and v3 legitimately retains, or rotates, the
    authority v2 introduces. The walk's memory of what it had admitted keyed
    an anchor by ``(id, root SPKI)`` and refused a second anchor carrying the
    same pair, which is exactly that shape: a producer whose transition spans
    two versions could not write a witness at all, because the second version
    of an authority it had just introduced was refused as a second name for
    it.

    Succession is the answer, and it is what says the duplicate rule is about
    identities and not versions. Pending bundles are walked in version order;
    a later one's anchor carrying an admitted anchor's ``(id, root SPKI)``
    replaces it in the candidate set without releasing any historical signer
    edge, so a rotation between two pending versions remains one class.
    The anchor kept is the highest version's, because that is the anchor that
    will verify tokens once the transition activates -- a v2 witness must use
    the newest active bundle -- so it is the one whose key a supplemental
    outcome should demonstrate, and the witness below is refused when it
    answers for the superseded version instead.

    A rename in a later version is the same class too.  It supersedes the
    earlier representation just as a same-name rotation does; without the
    persistent graph it was instead treated as a second authority.
    """

    beta = local_anchors[1]
    rotated = certificate_pins(rotated_beta.signer_pem)
    incoming = alias_of(beta, anchor_id="beta-arriving-2026")

    def catch_up(
        name: str,
        third: Sequence[LocalAnchor],
        *,
        signers: Mapping[str, dict[str, str]] | None = None,
    ) -> tuple[WitnessTree, dict[str, Any], dict[str, Any], TsaSpec]:
        """v1 active, v2 introducing ``incoming``, v3 as the caller describes."""

        tree = build_witness_tree(tmp_path / name, local_anchors[:1])
        second, spec = pending_authority(tree, incoming, version=2)
        for anchor in third:
            (tree.records / "trust" / anchor.tsa.root_pem.name).write_bytes(
                anchor.tsa.root_pem.read_bytes()
            )
        latest, spec = add_bundle_version(
            tree, third, version=3, base=spec, signers=signers
        )
        return tree, second, latest, spec

    def candidates(
        tree: WitnessTree, spec: TsaSpec, *pending: dict[str, Any]
    ) -> set[tuple[str, str]]:
        return set(
            tsa_module._supplemental_candidates(
                tree.records,
                {BUNDLE_LOGICAL: tree.reference},
                list(pending),
                spec=spec,
            )
        )

    # v3 retains the authority v2 introduced: one candidate, and it is v3's.
    tree, second, latest, spec = catch_up("retained", [incoming])
    assert candidates(tree, spec, second, latest) == {
        (latest["path"], incoming.anchor_id)
    }
    # The order the caller happens to supply them in decides nothing; the
    # version order does, and it is the same walk either way.
    assert candidates(tree, spec, latest, second) == {
        (latest["path"], incoming.anchor_id)
    }
    # And either version alone is its own candidate.
    assert candidates(tree, spec, second) == {(second["path"], incoming.anchor_id)}

    # The witness answers for the surviving anchor, and only for that one.
    supplemental_token = (
        tree.records / RECORD_DAY / f"record-0001.{incoming.anchor_id}.tsr"
    )
    beta.tsa.stamp(sha256_bytes(tree.record.read_bytes()), supplemental_token)

    def answering(pending: dict[str, Any]) -> WitnessEvidence:
        rewrite_witness(
            tree,
            lambda payload: payload.__setitem__(
                "supplementalOutcomes",
                [supplemental_outcome(tree, pending, incoming, supplemental_token)],
            ),
        )
        return verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[second, latest],
        )

    evidence = answering(latest)
    assert evidence.status == "available"
    assert [token.anchor_id for token in evidence.supplemental_tokens] == [
        incoming.anchor_id
    ]
    with pytest.raises(TsaError) as superseded:
        answering(second)
    assert str(superseded.value) == (
        "supplemental TSA outcome is not introduced by a pending trust "
        f"transition: ('{second['path']}', '{incoming.anchor_id}')"
    )

    # v3 rotates the authority's signing key: still one candidate, still v3's.
    tree, second, latest, spec = catch_up(
        "rotated", [incoming], signers={incoming.anchor_id: rotated}
    )
    rotating = json.loads(
        (tree.records / "trust" / "tsa-anchors-v3.json").read_text()
    )["anchors"][0]
    # The premise: same anchor, same root, a signing key the earlier version
    # does not allow.
    assert rotating["id"] == incoming.anchor_id
    assert {signer["spkiSha256"] for signer in rotating["allowedSigners"]} == {
        rotated["spkiSha256"]
    }
    assert rotated["spkiSha256"] != beta.signer_pins["spkiSha256"]
    assert candidates(tree, spec, second, latest) == {
        (latest["path"], incoming.anchor_id)
    }

    # v3 files v2's signing key under a new (id, root SPKI): one historical
    # class, represented by the newest anchor.
    elsewhere = alias_of(beta, anchor_id="beta-elsewhere-2026")
    tree, second, latest, spec = catch_up("aliased", [elsewhere])
    assert candidates(tree, spec, second, latest) == {
        (latest["path"], elsewhere.anchor_id)
    }


def give_the_record_its_own_updates(
    tree: WitnessTree,
    anchors: Sequence[LocalAnchor],
    updates: Sequence[Mapping[str, Any]],
) -> str:
    """Put ``updates`` in the witnessed record, re-stamp, and return the digest.

    A record that carries a trust transition is the only input the caller
    comparison has anything to say about, and the tree builder writes records
    that carry none. Changing the record changes its digest, so every token
    over it has to be signed again and the sidecar's ``digestSha256`` and
    every declared ``tokenSha256`` moved with it -- which is what this does,
    leaving a tree that verifies exactly as the builder's did.
    """

    payload = json.loads(tree.record.read_text())
    payload["trustBundleUpdates"] = [dict(update) for update in updates]
    tree.record.write_bytes(canonical_bytes(payload) + b"\n")
    digest = sha256_bytes(tree.record.read_bytes())
    for anchor in anchors:
        anchor.tsa.stamp(digest, tree.tokens[anchor.anchor_id])

    def refresh(witness: dict[str, Any]) -> None:
        witness["digestSha256"] = digest
        for outcome in witness.get("anchorOutcomes", [witness]):
            token = tree.tokens.get(str(outcome.get("tsaAnchorId")))
            if token is not None:
                outcome["tokenSha256"] = sha256_bytes(token.read_bytes())

    rewrite_witness(tree, refresh)
    return digest


def add_record(
    tree: WitnessTree,
    anchors: Sequence[LocalAnchor],
    *,
    name: str,
    observation: str,
    updates: Sequence[Mapping[str, Any]] = (),
    available: bool = True,
    supplemental: Sequence[tuple[Mapping[str, Any], LocalAnchor, LocalTsa]] = (),
) -> pathlib.Path:
    """A further record in the tree's day directory, with its own v2 witness.

    The tree builder writes one record, and a chain is several. What only a
    chain has is a record whose transition was still pending when the next
    record was written -- an unavailable witness does not activate what it
    carries -- so the walk that carries pending updates forward cannot be
    shown on one record at all.

    ``updates`` goes into the record's own ``trustBundleUpdates``, ``anchors``
    are the active bundle's anchors the witness answers for (stamped by their
    own authorities, or declared unavailable), and ``supplemental`` is one
    entry per pending anchor the transition introduces: the pending bundle's
    reference, the anchor, and the authority whose key stamps for it.
    """

    day = tree.records / RECORD_DAY
    record = day / name
    payload: dict[str, Any] = {
        "schemaVersion": "receipt_test_record_v1",
        "recordedAt": (datetime.now(UTC) - timedelta(seconds=60)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "observation": observation,
    }
    if updates:
        payload["trustBundleUpdates"] = [dict(update) for update in updates]
    record.write_bytes(canonical_bytes(payload) + b"\n")
    digest = sha256_bytes(record.read_bytes())

    status = "available" if available else "unavailable"
    outcomes: list[dict[str, Any]] = []
    for anchor in anchors:
        outcome: dict[str, Any] = {
            "tsaAnchorId": anchor.anchor_id,
            "tsa": anchor.endpoint,
            "status": status,
        }
        if available:
            token = day / f"{record.stem}.{anchor.anchor_id}.tsr"
            anchor.tsa.stamp(digest, token)
            outcome.update(
                {
                    "tokenPath": logical_path(tree.records, token),
                    "tokenSha256": sha256_bytes(token.read_bytes()),
                    "tsaPolicyOid": anchor.tsa.policy_oid,
                    "tsaImprintAlgorithmOid": SHA256_IMPRINT_OID,
                    "tsaSignerCertificateSha256": anchor.signer_pins[
                        "certificateSha256"
                    ],
                    "tsaSignerSpkiSha256": anchor.signer_pins["spkiSha256"],
                }
            )
        else:
            outcome["reason"] = "authority unreachable from this fixture"
        outcomes.append(outcome)

    witness: dict[str, Any] = {
        "schemaVersion": "thesis_rfc3161_witness_v2",
        "digestSha256": digest,
        "status": status,
        "trustBundleId": BUNDLE_ID,
        "trustBundlePath": BUNDLE_LOGICAL,
        "trustBundleSha256": tree.reference["sha256"],
        "anchorOutcomes": outcomes,
    }
    if not available:
        witness["reason"] = "no configured authority answered"
    if supplemental:
        offered: list[dict[str, Any]] = []
        for pending, anchor, authority in supplemental:
            token = day / f"{record.stem}.supplemental.{anchor.anchor_id}.tsr"
            authority.stamp(digest, token)
            offered.append(
                supplemental_outcome(
                    tree,
                    pending,
                    anchor,
                    token,
                    signer=certificate_pins(authority.signer_pem),
                )
            )
        witness["supplementalOutcomes"] = offered
    record.with_suffix(".witness.json").write_bytes(canonical_bytes(witness) + b"\n")
    return record


def a_record_carrying_its_own_transition(
    root: pathlib.Path,
    local_anchors: Sequence[LocalAnchor],
    rotated_alpha: LocalTsa,
) -> tuple[WitnessTree, dict[str, Any], dict[str, Any], LocalAnchor, TsaSpec]:
    """The chain-walk shape: one pending bundle before this record, one in it.

    ``rotation`` is a bundle version an earlier record introduced and no
    witness has activated yet -- a signer rotation, so it is skipped as a
    supplemental candidate and demands nothing of this witness. ``arrival``
    is the bundle this record's own ``trustBundleUpdates`` carries, and it
    introduces an authority the chain does not know, so it demands a
    supplemental outcome. A chain walker supplies both: the pending updates
    it has accumulated, and this record's own.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    tree = build_witness_tree(root, local_anchors[:1])
    rotation, spec = add_bundle_version(
        tree,
        local_anchors[:1],
        version=2,
        signers={alpha.anchor_id: certificate_pins(rotated_alpha.signer_pem)},
    )
    incoming = alias_of(beta, anchor_id="beta-arriving-2026")
    arrival, spec = pending_authority(tree, incoming, version=3, base=spec)
    give_the_record_its_own_updates(tree, local_anchors[:1], [arrival])
    return tree, rotation, arrival, incoming, spec


def replace_an_update_record_with_a_witnessed_snapshot(
    root: pathlib.Path,
    local_anchors: Sequence[LocalAnchor],
    rotated_alpha: LocalTsa,
) -> tuple[WitnessTree, dict[str, Any], TsaSpec, str]:
    """Read A's update, then leave valid update-free B at the same path."""

    alpha = local_anchors[0]
    tree = build_witness_tree(root, local_anchors[:1])
    rotation, spec = add_bundle_version(
        tree,
        local_anchors[:1],
        version=2,
        signers={alpha.anchor_id: certificate_pins(rotated_alpha.signer_pem)},
    )
    record_b = tree.record.read_bytes()
    digest_b = sha256_bytes(record_b)
    payload_a = json.loads(record_b)
    payload_a["trustBundleUpdates"] = [rotation]
    tree.record.write_bytes(canonical_bytes(payload_a) + b"\n")
    supplied = tsa_module.trust_bundle_updates(
        tree.records, json.loads(tree.record.read_text()), spec=spec
    )
    assert supplied == [rotation]
    tree.record.write_bytes(record_b)
    assert "trustBundleUpdates" not in json.loads(tree.record.read_text())
    assert json.loads(tree.witness.read_text())["digestSha256"] == digest_b
    return tree, rotation, spec, digest_b


def test_refuses_a_supplied_transition_that_omits_the_snapshots_own_updates(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """S5R2-F1: the record's updates come from the bytes the token covered.

    ``verify_witness`` read the record once and derived everything from that
    snapshot -- except the trust transition, which it took from the caller
    whenever the caller offered one. So the token evidence described the
    bytes this call read while the transition described a different, earlier
    read of the same path: a writer replacing the record between the caller's
    read and this one made the evidence cover record B and the transition
    cover record A, and the authorities record B activates were never
    considered at all.

    The record here carries a bundle introducing an authority the chain does
    not know, and the witness answers for none of it. The premise, asserted
    first, is that the record's own updates really do demand something this
    witness has not got: combined by the safe step API, the transition is
    refused for a missing supplemental outcome. Supplied as an earlier read of the record
    would have produced them -- the accumulated pending update and nothing of
    this record's -- it used to verify, because nothing looked at the record
    it had just hashed. Now the snapshot's own updates are derived either way
    and a supplied list that omits one is refused.
    """

    tree, rotation, arrival, incoming, spec = a_record_carrying_its_own_transition(
        tmp_path, local_anchors, rotated_alpha
    )

    def transition(supplied: list[dict[str, Any]]) -> WitnessEvidence:
        return verify_witness(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            transition_bundle_updates=supplied,
        )

    # The premise: the record's own update demands a supplemental outcome.
    with pytest.raises(TsaError) as truthful:
        verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[rotation],
        )
    assert str(truthful.value) == (
        "supplemental TSA outcome mismatch: "
        f"missing=[('{arrival['path']}', '{incoming.anchor_id}')], extra=[]"
    )
    # And the stale list, which used to make that demand disappear.
    for stale in ([], [rotation]):
        with pytest.raises(TsaError) as caught:
            transition(stale)
        assert str(caught.value) == (
            "transition bundle updates supplied by the caller omit the "
            "witnessed record's own"
        )


def test_a_chain_step_accepts_prior_and_returns_current_updates(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """S5R2-F1/S6-R2-F4: the public step keeps prior and current apart.

    A chain walker supplies only the pending updates returned by earlier
    steps.  ``verify_witness_step`` derives this record's update from the one
    authenticated read, evaluates the two kinds together, and returns only
    the current kind.  The compatibility API still accepts the exact derived
    set (or derives it when omitted), but now refuses the old combined list:
    its prior entry is stale with respect to this record rather than silently
    evaluated as though the caller had proved where it came from.
    """

    tree, rotation, arrival, incoming, spec = a_record_carrying_its_own_transition(
        tmp_path, local_anchors, rotated_alpha
    )
    beta = local_anchors[1]
    supplemental_token = tree.records / RECORD_DAY / f"record-0001.{incoming.anchor_id}.tsr"
    beta.tsa.stamp(sha256_bytes(tree.record.read_bytes()), supplemental_token)
    rewrite_witness(
        tree,
        lambda payload: payload.__setitem__(
            "supplementalOutcomes",
            [supplemental_outcome(tree, arrival, incoming, supplemental_token)],
        ),
    )

    step = tsa_module.verify_witness_step(
        tree.record,
        spec=spec,
        records=tree.records,
        trusted_bundles={BUNDLE_LOGICAL: tree.reference},
        prior_pending_updates=[rotation],
    )
    accumulated = step.evidence
    assert accumulated.status == "available"
    assert [token.anchor_id for token in accumulated.supplemental_tokens] == [
        incoming.anchor_id
    ]
    own_only = verify_witness(
        tree.record,
        spec=spec,
        records=tree.records,
        trusted_bundles={BUNDLE_LOGICAL: tree.reference},
        transition_bundle_updates=[arrival],
    )
    derived = verify_witness(
        tree.record,
        spec=spec,
        records=tree.records,
        trusted_bundles={BUNDLE_LOGICAL: tree.reference},
    )
    assert own_only == accumulated
    assert derived == accumulated

    # What the verification returns is the snapshot's own updates, not prior.
    assert step.trust_bundle_updates == (arrival,)
    assert list(step.trust_bundle_updates) == json.loads(
        tree.record.read_text()
    )["trustBundleUpdates"]
    with pytest.raises(TsaError) as stale:
        verify_witness(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            transition_bundle_updates=[rotation, arrival],
        )
    assert str(stale.value) == (
        f"stale transition bundle update supplied for {tree.record}: "
        f"'{rotation['path']}'"
    )


def test_verify_witness_refuses_an_update_from_the_replaced_record(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """S6-R2-F4: B's sidecar cannot evidence A's stale transition update.

    An honest walker reads record A carrying a signer rotation, then a writer
    replaces that path with valid witnessed record B carrying no update before
    ``verify_witness`` takes its one read.  The old one-way subset check accepts
    A's update as an extra and evaluates it through B; because a rotation is
    already-active authority history, B returns available and the stale update
    acquires evidence from a record that never carried it.  Exact comparison
    must instead name and refuse A's update before candidate evaluation.
    """

    tree, stale, spec, _digest_b = replace_an_update_record_with_a_witnessed_snapshot(
        tmp_path, local_anchors, rotated_alpha
    )
    with pytest.raises(TsaError) as caught:
        verify_witness(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            transition_bundle_updates=[stale],
        )
    assert str(caught.value) == (
        f"stale transition bundle update supplied for {tree.record}: "
        f"'{stale['path']}'"
    )


def test_verify_witness_step_returns_only_the_replaced_records_updates(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """S6-R2-F4: the step result derives evidence and updates from B alone.

    The same A-to-B replacement leaves A's update in the walker's stale local
    value and an update-free, valid witnessed B at the path.  Without the new
    public API there is no result that couples the evidence with the updates
    from its one read.  The step must report B's digest and empty derived set;
    A's rotation appears in neither, so a caller can safely carry the result.
    """

    tree, stale, spec, digest_b = replace_an_update_record_with_a_witnessed_snapshot(
        tmp_path, local_anchors, rotated_alpha
    )
    step = tsa_module.verify_witness_step(
        tree.record,
        spec=spec,
        records=tree.records,
        trusted_bundles={BUNDLE_LOGICAL: tree.reference},
        prior_pending_updates=[],
    )
    assert isinstance(step, tsa_module.WitnessStep)
    assert step.evidence.status == "available"
    assert step.evidence.digest_sha256 == digest_b
    assert step.trust_bundle_updates == ()
    assert stale not in step.trust_bundle_updates


def test_a_chain_walk_takes_each_records_updates_from_its_own_verification(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    rotated_alpha: LocalTsa,
) -> None:
    """S5R3-F1/S6-R2-F4: three public steps, each returning its own updates.

    The safe public shape, walked. Each record is verified with the
    pending updates of the records *before* it and nothing else; its own come
    back from the verification, from the bytes that call hashed, and go into
    the accumulator. Nothing in the walk ever reads a record, so there is no
    second read of one to be stale, and no entry in any transition the witness
    did not either derive or attribute to an earlier record.

    The middle record's witness is unavailable, which is the only way one
    record's transition is still pending when the next is written: an
    available witness activates what has accumulated. So the third record is
    measured against the second's pending update as well as its own, and
    answers for both authorities -- which is what says the walk really carried
    it. Verified with ``prior_pending_updates=[]`` instead, the third record's
    supplemental outcome for the second record's authority is refused as one
    no transition introduces.

    The compatibility shape cannot safely carry the accumulator: on the third
    record its combined list is refused by name because the second record's
    update is not derived from the third.  That is what forces a chain walker
    onto the step result instead of parsing each record beside verification.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    rotated = certificate_pins(rotated_alpha.signer_pem)
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    stranger = alias_of(beta, anchor_id="beta-arriving-2026")
    arrival, spec = pending_authority(tree, stranger, version=2)
    renamed = dataclasses.replace(
        alpha,
        anchor_id="alpha-renamed-2026",
        endpoint="https://alpha-renamed-2026.timestamp.invalid/tsr",
        tsa=rotated_alpha,
        signer_pins=rotated,
    )
    later, spec = add_bundle_version(tree, [renamed], version=3, base=spec)

    second = add_record(
        tree,
        local_anchors[:1],
        name="record-0002.json",
        observation="the record whose authority is still pending after it",
        updates=[arrival],
        available=False,
        supplemental=[(arrival, stranger, beta.tsa)],
    )
    third = add_record(
        tree,
        local_anchors[:1],
        name="record-0003.json",
        observation="the record measured against the one before it too",
        updates=[later],
        supplemental=[
            (arrival, stranger, beta.tsa),
            (later, renamed, rotated_alpha),
        ],
    )
    chain = [tree.record, second, third]
    carried_by_the_records = [
        json.loads(record.read_text()).get("trustBundleUpdates", [])
        for record in chain
    ]
    assert carried_by_the_records == [[], [arrival], [later]]

    def walk(
    ) -> tuple[list[WitnessEvidence], dict[str, Any], list[list[dict[str, Any]]]]:
        active: dict[str, Any] = {BUNDLE_LOGICAL: dict(tree.reference)}
        pending: list[dict[str, Any]] = []
        seen: list[WitnessEvidence] = []
        carried: list[list[dict[str, Any]]] = []
        for record in chain:
            step = tsa_module.verify_witness_step(
                record,
                spec=spec,
                records=tree.records,
                trusted_bundles=active,
                prior_pending_updates=list(pending),
            )
            evidence = step.evidence
            own = list(step.trust_bundle_updates)
            seen.append(evidence)
            carried.append(own)
            pending.extend(own)
            if evidence.status == "available":
                activate_trust_bundles(active, pending)
                pending.clear()
        assert not pending
        return seen, active, carried

    evidence, active, carried = walk()
    assert [entry.status for entry in evidence] == [
        "available",
        "unavailable",
        "available",
    ]
    # Each record's own updates came back from its own verification, and they
    # are the updates that record carries.
    assert carried == carried_by_the_records
    # And exactly those bundles activated, none of them twice or at a path
    # the chain never introduced.
    assert set(active) == {BUNDLE_LOGICAL, arrival["path"], later["path"]}
    assert active[arrival["path"]] == arrival
    assert active[later["path"]] == later
    # The third record answered for both authorities, the earlier record's
    # included, which is what the accumulator carried forward.
    assert [token.anchor_id for token in evidence[2].supplemental_tokens] == [
        stranger.anchor_id,
        renamed.anchor_id,
    ]

    # Without the earlier record's update, that outcome answers for nothing.
    with pytest.raises(TsaError) as dropped:
        tsa_module._verify_witness_with_updates(
            third,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: dict(tree.reference)},
            prior_pending_updates=[],
        )
    assert str(dropped.value) == (
        "supplemental TSA outcome is not introduced by a pending trust "
        f"transition: ('{arrival['path']}', '{stranger.anchor_id}')"
    )

    # The combined compatibility shape now names the earlier record's update
    # instead of evaluating it through this record's sidecar.
    with pytest.raises(TsaError) as stale:
        verify_witness(
            third,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: dict(tree.reference)},
            transition_bundle_updates=[arrival, later],
        )
    assert str(stale.value) == (
        f"stale transition bundle update supplied for {third}: "
        f"'{arrival['path']}'"
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
            tree.record,
            against,
            tree.reference,
            spec=tree.spec,
            records=tree.records,
            record=tree.record.read_bytes(),
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

    The shape in which two outcomes of one witness could both be satisfied by
    one response and both verify. A bundle may not allow one signer under two
    of its anchors, and a pending anchor whose signers an active anchor
    already allows is that authority renamed and never becomes a candidate at
    all (S5-F2) -- so the two outcomes that could share a signer were two
    *supplemental* ones, introduced by two separate pending bundles, neither
    of which the active chain knows.

    The rolling walk used to refuse that shape when it reached the second
    anchor (S5R2-F5).  The persistent graph states the same identity directly:
    both occurrences form one class, whose newest occurrence is its only
    candidate (S6-R2-F3).  So this builds a witness whose obsolete first
    outcome is refused; the two tests that bind the duplicate-timestamp rule
    reach it by blinding the graph's signer edges -- see
    ``blind_the_pending_signer_reader``.
    """

    first = alias_of(anchor, anchor_id=f"{anchor.anchor_id}-first")
    second = alias_of(anchor, anchor_id=f"{anchor.anchor_id}-second")
    pending_first, spec = pending_authority(tree, first, version=2)
    pending_second, spec = pending_authority(tree, second, version=3, base=spec)
    return pending_first, first, pending_second, second, spec


def blind_the_pending_signer_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every anchor look as though it allowed no signer at all.

    ``_anchor_signer_fingerprints`` is what the authority-history graph reads
    an anchor's signers through, and nothing else in the module uses it: the
    bundle load computes its own set inline, and the ported allowed-signer
    check reads ``allowedSigners`` off the anchor directly. So blinding it
    removes exactly the graph's signer edges and leaves every verification of
    a token as it was.

    Which is the only way left to reach the duplicate-timestamp rule. Two
    outcomes rest on one authority's signature only if two anchors both pin
    the certificate that response was signed with, and every pairing of
    anchors that could is collapsed into one historical class before an
    outcome is read (and two such anchors in one bundle are refused). The
    timestamp rule is therefore defence in depth, kept for the same reason
    ``_select_anchor``'s identity refusal is kept, and these two tests say
    what it would catch if one of the rules in front of it were lost.
    """

    monkeypatch.setattr(tsa_module, "_anchor_signer_fingerprints", lambda anchor: set())


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

    S5R2-F5 and S6-R2-F3 put a rule in front of this one: two pending bundles
    introducing one authority form one class and therefore one candidate.
    The extra outcome for the superseded representation is refused first.
    The timestamp rule is what remains if those signer edges are lost, so the
    second half reaches it through ``blind_the_pending_signer_reader``.
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

    def transition() -> WitnessEvidence:
        return verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[pending_first, pending_second],
        )

    # The rule in front: two pending bundles, one class, one survivor.
    with pytest.raises(TsaError) as first_refusal:
        transition()
    assert str(first_refusal.value) == (
        "supplemental TSA outcome is not introduced by a pending trust "
        f"transition: ('{pending_first['path']}', '{first.anchor_id}')"
    )

    blind_the_pending_signer_reader(monkeypatch)
    verified = record_token_verifications(monkeypatch)
    with pytest.raises(TsaError) as caught:
        transition()
    assert str(caught.value) == (
        "duplicate TSA timestamp across anchor outcomes: signer "
        f"{beta.signer_pins['certificateSha256']}, timestamp {sha256_bytes(signed)}"
    )
    # Neither earlier rule can see this one: two paths, two file digests, and
    # two objects.
    assert [claim["tsaAnchorId"] for claim in verified] == [
        local_anchors[0].anchor_id,
        first.anchor_id,
        second.anchor_id,
    ]


def test_two_authorities_may_sign_one_timestamp_and_both_count(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
) -> None:
    """S5-F1: a timestamp is identified by its signer as well as its bytes.

    A ``TSTInfo`` need not say whose it is. RFC 3161 requires its serial
    number to be unique within one TSA and no further, and its nonce and its
    ``tsa`` general name are both optional -- so two independent authorities
    answering for one digest, in one second, with the same policy and the
    same serial and neither naming itself, sign the same bytes. Nothing here
    is forged: both responses below are ``openssl ts -reply``'s own work
    under its own signing key, and each verifies against its own pinned root
    and against no other, asserted from OpenSSL directly.

    Counting the signed ``TSTInfo`` alone made that pair one timestamp, and
    the second anchor's perfectly valid outcome was refused as a duplicate --
    a chain rejected for having two authorities that agreed too exactly.
    Qualified by the certificate ``openssl cms -verify`` authenticated the
    signature with, the two are two, and the witness verifies with a token
    for each anchor. The control the qualification must not weaken is the
    re-bagged token below: one signer, one ``TSTInfo``, two encodings, still
    refused.
    """

    alpha, beta = local_anchors[0], local_anchors[1]
    shared_policy = alpha.tsa.policy_oid
    tree = build_witness_tree(
        tmp_path,
        local_anchors[:2],
        policy_oids={beta.anchor_id: [beta.tsa.policy_oid, shared_policy]},
    )
    assert verify_tree(tree).status == "available"

    digest = sha256_bytes(tree.record.read_bytes())
    responses = {
        anchor.anchor_id: tree.records / RECORD_DAY / f"record-0001.{anchor.anchor_id}.same.tsr"
        for anchor in local_anchors[:2]
    }
    # Both authorities answer for one digest, each under its own key. The
    # retry is for the one thing a test has to arrange rather than declare:
    # that the two stamps land in the same second.
    for attempt in range(20):
        for anchor in local_anchors[:2]:
            stamp_anonymously(
                anchor.tsa,
                digest,
                responses[anchor.anchor_id],
                policy_oid=shared_policy,
                serial="7f",
            )
        signed = {
            anchor_id: signed_timestamp_of(tmp_path, response)
            for anchor_id, response in responses.items()
        }
        if signed[alpha.anchor_id] == signed[beta.anchor_id]:
            break
    else:  # pragma: no cover - twenty crossings of a second boundary
        pytest.fail("the two authorities never stamped within one second")

    # The premise, from OpenSSL directly: two files, one signed timestamp,
    # and each file verifying against its own authority's root alone.
    alphas, betas = responses[alpha.anchor_id], responses[beta.anchor_id]
    assert sha256_bytes(alphas.read_bytes()) != sha256_bytes(betas.read_bytes())
    assert openssl_ts_verifies(tree.record, alphas, alpha.tsa.root_pem)
    assert openssl_ts_verifies(tree.record, betas, beta.tsa.root_pem)
    assert not openssl_ts_verifies(tree.record, alphas, beta.tsa.root_pem)
    assert not openssl_ts_verifies(tree.record, betas, alpha.tsa.root_pem)

    def point_each_outcome_at_its_own_new_response(payload: dict[str, Any]) -> None:
        for outcome in payload["anchorOutcomes"]:
            response = responses[outcome["tsaAnchorId"]]
            outcome["tokenPath"] = logical_path(tree.records, response)
            outcome["tokenSha256"] = sha256_bytes(response.read_bytes())
            outcome["tsaPolicyOid"] = shared_policy

    rewrite_witness(tree, point_each_outcome_at_its_own_new_response)
    evidence = verify_tree(tree)
    assert evidence.status == "available"
    assert [token.anchor_id for token in evidence.tokens] == [
        alpha.anchor_id,
        beta.anchor_id,
    ]
    # Two authorities, one timestamp between them, and two outcomes covered.
    assert (
        evidence.tokens[0].tsa_certificate_sha256
        != evidence.tokens[1].tsa_certificate_sha256
    )
    assert evidence.tokens[0].token_sha256 != evidence.tokens[1].token_sha256
    assert signed_timestamp_of(tmp_path, alphas) == signed_timestamp_of(tmp_path, betas)


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

    As with the re-wrapping above, S5R2-F5 and S6-R2-F3 collapse this
    witness's two pending occurrences to one class and refuse the obsolete
    outcome first; the timestamp rule is reached through
    ``blind_the_pending_signer_reader``, which is what is left of the defence
    if the rule in front of it is lost.
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

    def transition() -> WitnessEvidence:
        return verify_step(
            tree.record,
            spec=spec,
            records=tree.records,
            trusted_bundles={BUNDLE_LOGICAL: tree.reference},
            prior_pending_updates=[pending_first, pending_second],
        )

    with pytest.raises(TsaError) as first_refusal:
        transition()
    assert str(first_refusal.value) == (
        "supplemental TSA outcome is not introduced by a pending trust "
        f"transition: ('{pending_first['path']}', '{first.anchor_id}')"
    )

    blind_the_pending_signer_reader(monkeypatch)
    verified = record_token_verifications(monkeypatch)
    with pytest.raises(TsaError) as caught:
        transition()
    assert str(caught.value) == (
        "duplicate TSA timestamp across anchor outcomes: signer "
        f"{beta.signer_pins['certificateSha256']}, timestamp {sha256_bytes(signed)}"
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
