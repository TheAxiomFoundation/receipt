"""RFC 3161 witness verification with consumer-committed trust specifications.

The witness and trust-transition machinery is a mechanical port of
``MaxGhenis/brier``'s ``scripts/verify_record_chain.py`` at commit
``4b9e7be22debc8349e76b8bdfe5a0fe18ed31a3f``.  Refusal text is retained
verbatim.  The extraction changes only where trust enters: bundle byte pins,
TSA identities, anchor membership, and clock-skew limits arrive through a
frozen :class:`TsaSpec` supplied by consumer code.  This module ships no
repository-specific trust defaults and performs no chain walk or producer
signature verification.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from receipt.canonical import canonical_bytes, canonical_sha256

TRUST_BUNDLE_RE = re.compile(r"records/trust/tsa-anchors-v[1-9][0-9]*\.json")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
UTC = timezone.utc
SHA256_OID = "2.16.840.1.101.3.4.2.1"


class TsaError(ValueError):
    """A timestamp token, witness, or trust transition is invalid."""


def _spec_string(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise TsaError(f"{label} must be a non-empty string")
    return value


def _spec_sha256(value: Any, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise TsaError(
            f"{label} must be exactly 64 lowercase hexadecimal characters"
        )
    return value


def _spec_nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise TsaError(f"{label} must be a non-negative integer")
    return value


@dataclass(frozen=True)
class TrustBundleSpec:
    """The exact code-side commitment to one immutable trust-bundle file."""

    bundle_id: str
    path: str
    sha256: str
    size: int
    canonical_json_sha256: str

    def __post_init__(self) -> None:
        _spec_string(self.bundle_id, "trust bundle bundle_id")
        _spec_string(self.path, "trust bundle path")
        if TRUST_BUNDLE_RE.fullmatch(self.path) is None:
            raise TsaError(
                f"trust bundle path is not immutable/versioned: {self.path!r}"
            )
        _spec_sha256(self.sha256, f"trust bundle {self.path} sha256")
        _spec_nonnegative_int(self.size, f"trust bundle {self.path} size")
        _spec_sha256(
            self.canonical_json_sha256,
            f"trust bundle {self.path} canonical_json_sha256",
        )

    def reference(self) -> dict[str, Any]:
        """Return the oracle's committed JSON-reference shape and key order."""

        return {
            "bundleId": self.bundle_id,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "canonicalJsonSha256": self.canonical_json_sha256,
        }


@dataclass(frozen=True)
class TsaIdentitySpec:
    """Independent code pins and skew limits for one bundle anchor."""

    bundle_id: str
    anchor_id: str
    root_spki_sha256: str
    signer_spki_sha256: frozenset[str]
    max_future_seconds: int
    max_token_lead_seconds: int

    def __post_init__(self) -> None:
        _spec_string(self.bundle_id, "TSA identity bundle_id")
        _spec_string(self.anchor_id, "TSA identity anchor_id")
        _spec_sha256(
            self.root_spki_sha256,
            f"TSA identity {self.bundle_id}/{self.anchor_id} root_spki_sha256",
        )
        if type(self.signer_spki_sha256) is not frozenset or not self.signer_spki_sha256:
            raise TsaError(
                f"TSA identity {self.bundle_id}/{self.anchor_id} must contain "
                "at least one signer SPKI"
            )
        for fingerprint in self.signer_spki_sha256:
            _spec_sha256(
                fingerprint,
                f"TSA identity {self.bundle_id}/{self.anchor_id} signer SPKI",
            )
        _spec_nonnegative_int(
            self.max_future_seconds,
            f"TSA identity {self.bundle_id}/{self.anchor_id} max_future_seconds",
        )
        _spec_nonnegative_int(
            self.max_token_lead_seconds,
            f"TSA identity {self.bundle_id}/{self.anchor_id} "
            "max_token_lead_seconds",
        )


@dataclass(frozen=True)
class TsaSpec:
    """All repository-specific TSA trust, committed in consumer code."""

    trust_bundles: tuple[TrustBundleSpec, ...]
    tsa_identities: tuple[TsaIdentitySpec, ...]
    legacy_witness_bundle_id: str

    def __post_init__(self) -> None:
        if type(self.trust_bundles) is not tuple or not self.trust_bundles:
            raise TsaError("TSA spec must contain at least one trust bundle")
        if type(self.tsa_identities) is not tuple or not self.tsa_identities:
            raise TsaError("TSA spec must contain at least one TSA identity")
        legacy = _spec_string(
            self.legacy_witness_bundle_id, "legacy_witness_bundle_id"
        )
        paths: set[str] = set()
        bundle_ids: set[str] = set()
        for bundle in self.trust_bundles:
            if not isinstance(bundle, TrustBundleSpec):
                raise TsaError("TSA spec trust_bundles must contain TrustBundleSpec")
            if bundle.path in paths:
                raise TsaError(f"duplicate trust bundle path in TSA spec: {bundle.path}")
            if bundle.bundle_id in bundle_ids:
                raise TsaError(
                    f"duplicate trust bundle ID in TSA spec: {bundle.bundle_id}"
                )
            paths.add(bundle.path)
            bundle_ids.add(bundle.bundle_id)
        if legacy not in bundle_ids:
            raise TsaError(
                "legacy_witness_bundle_id is absent from TSA spec trust bundles: "
                f"{legacy}"
            )
        identities: set[tuple[str, str]] = set()
        identity_bundles: set[str] = set()
        for identity in self.tsa_identities:
            if not isinstance(identity, TsaIdentitySpec):
                raise TsaError(
                    "TSA spec tsa_identities must contain TsaIdentitySpec"
                )
            if identity.bundle_id not in bundle_ids:
                raise TsaError(
                    "TSA identity names an unknown trust bundle: "
                    f"{identity.bundle_id}/{identity.anchor_id}"
                )
            key = (identity.bundle_id, identity.anchor_id)
            if key in identities:
                raise TsaError(
                    "duplicate TSA identity in TSA spec: "
                    f"{identity.bundle_id}/{identity.anchor_id}"
                )
            identities.add(key)
            identity_bundles.add(identity.bundle_id)
        missing_identities = sorted(bundle_ids - identity_bundles)
        if missing_identities:
            raise TsaError(
                "TSA spec trust bundle has no independently pinned identities: "
                f"{missing_identities[0]}"
            )

    def bundle_reference(self, path: str) -> dict[str, Any] | None:
        for bundle in self.trust_bundles:
            if bundle.path == path:
                return bundle.reference()
        return None

    def identity(
        self, bundle_id: str, anchor_id: str
    ) -> TsaIdentitySpec | None:
        for identity in self.tsa_identities:
            if identity.bundle_id == bundle_id and identity.anchor_id == anchor_id:
                return identity
        return None

    def identity_claim(
        self, bundle_id: str, anchor_id: str
    ) -> dict[str, Any] | None:
        identity = self.identity(bundle_id, anchor_id)
        if identity is None:
            return None
        return {
            "rootSpkiSha256": identity.root_spki_sha256,
            "signerSpkiSha256": set(identity.signer_spki_sha256),
        }


@dataclass(frozen=True)
class TokenEvidence:
    anchor_id: str
    trust_bundle_id: str
    trust_bundle_path: str
    token_path: str
    token_sha256: str
    policy_oid: str
    imprint_algorithm_oid: str
    gen_time: str
    tsa_subject: str
    tsa_certificate_sha256: str
    tsa_spki_sha256: str


@dataclass(frozen=True)
class WitnessEvidence:
    status: str
    digest_sha256: str
    tokens: tuple[TokenEvidence, ...] = ()
    supplemental_tokens: tuple[TokenEvidence, ...] = ()
    anchor_id: str | None = None
    trust_bundle_id: str | None = None
    trust_bundle_path: str | None = None
    policy_oid: str | None = None
    imprint_algorithm_oid: str | None = None
    gen_time: str | None = None
    tsa_subject: str | None = None
    tsa_certificate_sha256: str | None = None
    tsa_spki_sha256: str | None = None


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def logical_path(records: Path, path: Path) -> str:
    return str(Path("records") / path.relative_to(records))


def physical_path(records: Path, value: str) -> Path:
    logical = Path(value)
    if (
        logical.is_absolute()
        or ".." in logical.parts
        or "\\" in value
        or not logical.parts
    ):
        raise TsaError(f"unsafe record path in genesis/chain: {value!r}")
    if logical.parts[0] == "records":
        logical = Path(*logical.parts[1:])
    path = records / logical
    try:
        path.resolve().relative_to(records.resolve())
    except ValueError as exc:
        raise TsaError(f"record path escapes records root: {value!r}") from exc
    return path


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TsaError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise TsaError(f"record must be a JSON object: {path}")
    return value


def _run_openssl(
    arguments: list[str],
    *,
    input_bytes: bytes | None = None,
    binary: bool = False,
    env: dict[str, str] | None = None,
) -> bytes | str:
    command = ["openssl", *arguments]
    process_env = os.environ.copy()
    process_env.update({"OPENSSL_CONF": "/dev/null", "LC_ALL": "C"})
    if env:
        process_env.update(env)
    try:
        completed = subprocess.run(
            command,
            input=input_bytes,
            capture_output=True,
            check=False,
            env=process_env,
        )
    except FileNotFoundError as exc:
        raise TsaError("openssl is required to verify RFC 3161 tokens") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(errors="replace").strip()
        raise TsaError(f"OpenSSL command failed ({' '.join(command)}): {detail}")
    if binary:
        return completed.stdout
    return completed.stdout.decode(errors="strict")


def _certificate_identity(path: Path) -> dict[str, str]:
    certificate_der = _run_openssl(
        ["x509", "-in", str(path), "-outform", "DER"], binary=True
    )
    assert isinstance(certificate_der, bytes)
    public_key_pem = _run_openssl(
        ["x509", "-in", str(path), "-pubkey", "-noout"], binary=True
    )
    assert isinstance(public_key_pem, bytes)
    public_key_der = _run_openssl(
        ["pkey", "-pubin", "-outform", "DER"],
        input_bytes=public_key_pem,
        binary=True,
    )
    assert isinstance(public_key_der, bytes)
    description = _run_openssl(
        [
            "x509",
            "-in",
            str(path),
            "-noout",
            "-serial",
            "-subject",
            "-nameopt",
            "RFC2253",
        ]
    )
    assert isinstance(description, str)
    fields: dict[str, str] = {}
    for line in description.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key] = value
    return {
        "certificateSha256": hashlib.sha256(certificate_der).hexdigest(),
        "spkiSha256": hashlib.sha256(public_key_der).hexdigest(),
        "serial": fields.get("serial", "").upper(),
        "subject": fields.get("subject", ""),
    }


def _read_der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise TsaError("truncated DER value in RFC 3161 TSTInfo")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise TsaError("truncated DER length in RFC 3161 TSTInfo")
    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise TsaError("invalid DER length in RFC 3161 TSTInfo")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    else:
        length = first
    end = offset + length
    if end > len(data):
        raise TsaError("truncated DER content in RFC 3161 TSTInfo")
    return tag, data[offset:end], end


def _decode_oid(data: bytes) -> str:
    if not data:
        raise TsaError("empty policy OID in RFC 3161 token")
    first = data[0]
    values = [min(first // 40, 2), first - min(first // 40, 2) * 40]
    current = 0
    continuation = False
    for byte in data[1:]:
        current = (current << 7) | (byte & 0x7F)
        continuation = bool(byte & 0x80)
        if not continuation:
            values.append(current)
            current = 0
    if continuation:
        raise TsaError("truncated policy OID in RFC 3161 token")
    return ".".join(str(value) for value in values)


def _parse_generalized_time(value: str) -> datetime:
    match = re.fullmatch(r"(\d{14})(?:\.(\d+))?Z", value)
    if not match:
        raise TsaError(f"unsupported RFC 3161 genTime: {value!r}")
    parsed = datetime.strptime(match.group(1), "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    fraction = match.group(2)
    if fraction:
        parsed = parsed.replace(microsecond=int((fraction + "000000")[:6]))
    return parsed


def _format_utc(value: datetime) -> str:
    value = value.astimezone(UTC)
    if value.microsecond:
        return (
            value.isoformat(timespec="microseconds")
            .rstrip("0")
            .rstrip(".")
            .replace("+00:00", "Z")
        )
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_tst_info(data: bytes) -> tuple[str, str, bytes, datetime]:
    tag, sequence, end = _read_der_tlv(data, 0)
    if tag != 0x30 or end != len(data):
        raise TsaError("RFC 3161 TSTInfo is not one complete DER sequence")
    offset = 0
    tag, _version, offset = _read_der_tlv(sequence, offset)
    if tag != 0x02:
        raise TsaError("RFC 3161 TSTInfo lacks a version")
    tag, policy, offset = _read_der_tlv(sequence, offset)
    if tag != 0x06:
        raise TsaError("RFC 3161 TSTInfo lacks a policy OID")
    tag, message_imprint, offset = _read_der_tlv(sequence, offset)
    if tag != 0x30:
        raise TsaError("RFC 3161 TSTInfo lacks a message imprint")
    imprint_offset = 0
    tag, algorithm_identifier, imprint_offset = _read_der_tlv(
        message_imprint, imprint_offset
    )
    if tag != 0x30:
        raise TsaError("RFC 3161 message imprint lacks AlgorithmIdentifier")
    algorithm_offset = 0
    tag, algorithm_oid, algorithm_offset = _read_der_tlv(
        algorithm_identifier, algorithm_offset
    )
    if tag != 0x06:
        raise TsaError("RFC 3161 message imprint lacks an algorithm OID")
    if algorithm_offset < len(algorithm_identifier):
        tag, parameters, algorithm_offset = _read_der_tlv(
            algorithm_identifier, algorithm_offset
        )
        if tag != 0x05 or parameters:
            raise TsaError("unsupported RFC 3161 imprint algorithm parameters")
    if algorithm_offset != len(algorithm_identifier):
        raise TsaError("trailing RFC 3161 imprint AlgorithmIdentifier data")
    tag, hashed_message, imprint_offset = _read_der_tlv(message_imprint, imprint_offset)
    if tag != 0x04 or imprint_offset != len(message_imprint):
        raise TsaError("invalid RFC 3161 hashed message")
    tag, _serial, offset = _read_der_tlv(sequence, offset)
    if tag != 0x02:
        raise TsaError("RFC 3161 TSTInfo lacks a serial number")
    tag, gen_time, _offset = _read_der_tlv(sequence, offset)
    if tag != 0x18:
        raise TsaError("RFC 3161 TSTInfo lacks a genTime")
    try:
        gen_time_text = gen_time.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TsaError("RFC 3161 genTime is not ASCII") from exc
    return (
        _decode_oid(policy),
        _decode_oid(algorithm_oid),
        hashed_message,
        _parse_generalized_time(gen_time_text),
    )


def _parse_rfc3339(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise TsaError(f"missing or invalid timestamp claim {label}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TsaError(f"invalid timestamp claim {label}: {value!r}") from exc
    if parsed.tzinfo is None:
        raise TsaError(f"timestamp claim lacks a timezone {label}: {value!r}")
    return parsed.astimezone(UTC)


def _creation_claims(payload: dict[str, Any]) -> list[tuple[str, datetime]]:
    claims: list[tuple[str, datetime]] = []
    for key in ("recordedAt", "createdAt"):
        if key in payload:
            claims.append((key, _parse_rfc3339(payload[key], key)))
    dependencies = payload.get("dependencies")
    if isinstance(dependencies, dict):
        stack: list[tuple[str, dict[str, Any]]] = [("dependencies", dependencies)]
        while stack:
            prefix, current = stack.pop()
            for key, value in current.items():
                label = f"{prefix}.{key}"
                if isinstance(value, dict):
                    stack.append((label, value))
                elif key in {"builtAt", "createdAt", "recordedAt", "fetchedAt"}:
                    claims.append((label, _parse_rfc3339(value, label)))
    if not any(label == "recordedAt" for label, _ in claims):
        raise TsaError("snapshot lacks top-level recordedAt creation claim")
    return claims


def validate_token_time(
    payload: dict[str, Any],
    gen_time: datetime,
    *,
    now: datetime,
    max_future_seconds: int,
    max_token_lead_seconds: int,
) -> None:
    """Validate signed time against wall time and internal creation claims."""

    current = now.astimezone(UTC)
    if gen_time > current + timedelta(seconds=max_future_seconds):
        raise TsaError(
            f"RFC 3161 genTime {_format_utc(gen_time)} postdates verification "
            f"time {_format_utc(current)}"
        )
    for label, claim in _creation_claims(payload):
        if gen_time < claim - timedelta(seconds=max_token_lead_seconds):
            raise TsaError(
                f"RFC 3161 genTime {_format_utc(gen_time)} impossibly precedes "
                f"{label}={_format_utc(claim)}"
            )


def _trust_bundle_reference(
    records: Path, path: Path, payload: dict[str, Any]
) -> dict[str, Any]:
    return {
        "bundleId": payload.get("bundleId"),
        "path": logical_path(records, path),
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
        "canonicalJsonSha256": canonical_sha256(payload),
    }


def _load_trust_bundle(
    records: Path, reference: dict[str, Any], *, spec: TsaSpec
) -> tuple[Path, dict[str, Any]]:
    logical = reference.get("path")
    if not isinstance(logical, str) or not TRUST_BUNDLE_RE.fullmatch(logical):
        raise TsaError(f"TSA trust bundle path is not immutable/versioned: {logical!r}")
    if spec.bundle_reference(logical) != reference:
        raise TsaError(
            f"TSA trust bundle is not independently pinned by verifier code: {logical}"
        )
    path = physical_path(records, logical)
    if not path.is_file() or path.is_symlink():
        raise TsaError(f"TSA trust bundle is missing or not regular: {path}")
    payload = load_json(path)
    if payload.get("schemaVersion") != "thesis_tsa_trust_bundle_v1":
        raise TsaError(f"unsupported TSA trust schema: {payload.get('schemaVersion')!r}")
    if not isinstance(payload.get("bundleId"), str) or not payload["bundleId"]:
        raise TsaError(f"TSA trust bundle lacks bundleId: {path}")
    if path.read_bytes() not in {canonical_bytes(payload), canonical_bytes(payload) + b"\n"}:
        raise TsaError(f"TSA trust configuration is not canonical JSON: {path}")
    anchors = payload.get("anchors")
    if not isinstance(anchors, list) or not anchors:
        raise TsaError("TSA trust bundle must contain at least one anchor")
    anchor_ids: set[str] = set()
    endpoints: set[str] = set()
    for anchor in anchors:
        if not isinstance(anchor, dict):
            raise TsaError("TSA trust bundle anchor is not an object")
        anchor_id = anchor.get("id")
        endpoint = anchor.get("endpoint")
        if not isinstance(anchor_id, str) or not anchor_id:
            raise TsaError("TSA trust bundle anchor lacks an ID")
        if not isinstance(endpoint, str) or not endpoint:
            raise TsaError(f"TSA anchor {anchor_id!r} lacks an endpoint")
        if anchor_id in anchor_ids:
            raise TsaError(f"duplicate TSA anchor ID in trust bundle: {anchor_id}")
        if endpoint in endpoints:
            raise TsaError(f"duplicate TSA endpoint in trust bundle: {endpoint}")
        anchor_ids.add(anchor_id)
        endpoints.add(endpoint)
    actual_reference = _trust_bundle_reference(records, path, payload)
    if reference != actual_reference:
        raise TsaError(
            f"TSA trust bundle commitment mismatch for {logical}: "
            f"expected {reference}, got {actual_reference}"
        )
    return path, payload


def bootstrap_trust_bundles(
    records: Path,
    genesis: dict[str, Any],
    *,
    spec: TsaSpec,
    required: bool,
) -> dict[str, dict[str, Any]]:
    reference = genesis.get("tsaTrustBundle")
    if reference is None and not required:
        return {}
    if not isinstance(reference, dict):
        raise TsaError("chain genesis lacks the pinned TSA trust bundle")
    path, _payload = _load_trust_bundle(records, reference, spec=spec)
    return {logical_path(records, path): reference}


_bootstrap_trust_bundles = bootstrap_trust_bundles


def trust_bundle_updates(
    records: Path, payload: dict[str, Any], *, spec: TsaSpec
) -> list[dict[str, Any]]:
    updates = payload.get("trustBundleUpdates", [])
    if not isinstance(updates, list):
        raise TsaError("snapshot trustBundleUpdates must be a list")
    validated: list[dict[str, Any]] = []
    for reference in updates:
        if not isinstance(reference, dict):
            raise TsaError("snapshot trust bundle update is not an object")
        _load_trust_bundle(records, reference, spec=spec)
        validated.append(reference)
    return validated


_trust_bundle_updates = trust_bundle_updates


def activate_trust_bundles(
    active: dict[str, dict[str, Any]], updates: list[dict[str, Any]]
) -> None:
    ids = {str(reference.get("bundleId")): path for path, reference in active.items()}
    for reference in updates:
        path = str(reference["path"])
        bundle_id = str(reference["bundleId"])
        if path in active and active[path] != reference:
            raise TsaError(f"TSA trust bundle path was reused with new bytes: {path}")
        if bundle_id in ids and ids[bundle_id] != path:
            raise TsaError(f"TSA trust bundle ID was reused at a new path: {bundle_id}")
        active[path] = reference
        ids[bundle_id] = path


_activate_trust_bundles = activate_trust_bundles


def trust_bundle_updates_for_snapshot(
    active_trust_bundles: Mapping[str, dict[str, Any]],
    pending_trust_bundle_updates: Iterable[dict[str, Any]],
    *,
    spec: TsaSpec,
) -> list[dict[str, Any]]:
    """Return consumer-pinned bundles not active or replay-pending."""

    introduced = set(active_trust_bundles)
    introduced.update(
        str(reference["path"]) for reference in pending_trust_bundle_updates
    )
    return [
        bundle.reference()
        for bundle in spec.trust_bundles
        if bundle.path not in introduced
    ]


def preferred_active_trust_bundle(
    active: Mapping[str, dict[str, Any]],
) -> dict[str, Any]:
    """Select the highest immutable bundle version already authorized."""

    candidates: list[tuple[int, dict[str, Any]]] = []
    for path, reference in active.items():
        match = re.fullmatch(r"records/trust/tsa-anchors-v([1-9][0-9]*)\.json", path)
        if match:
            candidates.append((int(match.group(1)), reference))
    if not candidates:
        raise TsaError("verified chain has no active versioned TSA trust bundle")
    return dict(max(candidates, key=lambda item: item[0])[1])


def _select_anchor(
    records: Path,
    witness: dict[str, Any],
    trust: dict[str, Any],
    *,
    spec: TsaSpec,
) -> dict[str, Any]:
    anchor_id = witness.get("tsaAnchorId")
    endpoint = witness.get("tsa")
    candidates = [
        anchor
        for anchor in trust["anchors"]
        if isinstance(anchor, dict)
        and (
            (anchor_id and anchor.get("id") == anchor_id)
            or (not anchor_id and endpoint and anchor.get("endpoint") == endpoint)
        )
    ]
    if len(candidates) != 1:
        raise TsaError(
            "witness does not select exactly one pinned TSA anchor: "
            f"id={anchor_id!r}, endpoint={endpoint!r}"
        )
    anchor = candidates[0]
    if anchor_id and endpoint != anchor.get("endpoint"):
        raise TsaError("witness TSA endpoint does not match its pinned anchor")
    root = anchor.get("rootCertificate")
    if not isinstance(root, dict):
        raise TsaError(f"TSA anchor {anchor.get('id')!r} lacks rootCertificate")
    root_path = physical_path(records, str(root.get("path", "")))
    if not root_path.is_file() or root_path.is_symlink():
        raise TsaError(f"pinned TSA root is missing or not a regular file: {root_path}")
    if sha256_file(root_path) != root.get("pemSha256"):
        raise TsaError(f"pinned TSA root PEM hash mismatch: {root_path}")
    identity = _certificate_identity(root_path)
    if identity["certificateSha256"] != root.get("certificateSha256"):
        raise TsaError(f"pinned TSA root certificate hash mismatch: {root_path}")
    if identity["spkiSha256"] != root.get("spkiSha256"):
        raise TsaError(f"pinned TSA root SPKI hash mismatch: {root_path}")
    bundle_id = str(trust.get("bundleId"))
    code_identity = spec.identity_claim(bundle_id, str(anchor.get("id")))
    if not isinstance(code_identity, dict):
        raise TsaError(
            "TSA identity is not independently pinned in verifier code: "
            f"{bundle_id}/{anchor.get('id')}"
        )
    if identity["spkiSha256"] != code_identity.get("rootSpkiSha256"):
        raise TsaError("TSA root SPKI differs from the verifier code pin")
    configured_signers = anchor.get("allowedSigners")
    configured_spkis = (
        {
            signer.get("spkiSha256")
            for signer in configured_signers
            if isinstance(signer, dict)
        }
        if isinstance(configured_signers, list)
        else set()
    )
    if configured_spkis != code_identity.get("signerSpkiSha256"):
        raise TsaError("TSA signer SPKIs differ from the verifier code pins")
    return anchor


def _bundle_for_claim(
    records: Path,
    claim: dict[str, Any],
    trusted_bundles: Mapping[str, dict[str, Any]],
    *,
    spec: TsaSpec,
    active_required: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    bundle_path = claim.get("trustBundlePath")
    if not isinstance(bundle_path, str):
        raise TsaError("witness lacks a TSA trust-bundle path")
    if active_required:
        bundle_reference = trusted_bundles.get(bundle_path)
        if bundle_reference is None:
            raise TsaError(f"witness selects an untrusted TSA bundle: {bundle_path!r}")
    else:
        bundle_reference = spec.bundle_reference(bundle_path)
        if bundle_reference is None:
            raise TsaError(
                "witness selects a bundle absent from verifier code pins: "
                f"{bundle_path!r}"
            )
    if claim.get("trustBundleSha256") != bundle_reference.get("sha256"):
        raise TsaError("witness TSA trust-bundle hash mismatch")
    _trust_path, trust = _load_trust_bundle(records, bundle_reference, spec=spec)
    if claim.get("trustBundleId") != trust.get("bundleId"):
        raise TsaError("witness TSA trust-bundle ID mismatch")
    return bundle_reference, trust


def verify_timestamp_token(
    path: Path,
    token_claim: dict[str, Any],
    bundle_reference: dict[str, Any],
    *,
    spec: TsaSpec,
    records: Path,
    now: datetime | None = None,
) -> TokenEvidence:
    """Verify one claimed RFC 3161 token against one consumer-pinned anchor."""

    bundle_path = str(bundle_reference["path"])
    expected_bundle_claims = {
        "trustBundleId": bundle_reference["bundleId"],
        "trustBundlePath": bundle_path,
        "trustBundleSha256": bundle_reference["sha256"],
    }
    for key, expected in expected_bundle_claims.items():
        if token_claim.get(key) != expected:
            raise TsaError(f"timestamp token {key} does not match its bundle pin")
    _trust_path, trust = _load_trust_bundle(records, bundle_reference, spec=spec)
    anchor = _select_anchor(records, token_claim, trust, spec=spec)
    token_logical = token_claim.get("tokenPath")
    if not isinstance(token_logical, str):
        raise TsaError("witness token lacks tokenPath")
    token_path = physical_path(records, token_logical)
    if not token_path.is_file() or token_path.is_symlink():
        raise TsaError(f"witness token is missing for {path}: {token_path}")
    token_sha256 = sha256_file(token_path)
    if token_sha256 != token_claim.get("tokenSha256"):
        raise TsaError(f"witness token hash mismatch for {path}")
    root_path = physical_path(records, str(anchor["rootCertificate"]["path"]))

    with tempfile.TemporaryDirectory(prefix="thesis-tsa-") as temporary:
        temp = Path(temporary)
        token_der = temp / "token.der"
        tst_info = temp / "tst-info.der"
        signer = temp / "signer.pem"
        empty_ca_dir = temp / "empty-ca"
        empty_ca_dir.mkdir()
        _run_openssl(
            [
                "ts",
                "-reply",
                "-config",
                "/dev/null",
                "-in",
                str(token_path),
                "-token_out",
                "-out",
                str(token_der),
            ]
        )
        _run_openssl(
            [
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                str(token_der),
                "-noverify",
                "-nosigs",
                "-out",
                str(tst_info),
            ]
        )
        policy_oid, imprint_algorithm_oid, hashed_message, gen_time = _parse_tst_info(
            tst_info.read_bytes()
        )

        allowed_policies = anchor.get("allowedPolicyOids")
        if not isinstance(allowed_policies, list) or policy_oid not in allowed_policies:
            raise TsaError(
                f"RFC 3161 policy {policy_oid!r} is not allowed for TSA anchor "
                f"{anchor.get('id')!r}"
            )
        allowed_imprints = anchor.get("allowedImprintAlgorithmOids")
        if (
            not isinstance(allowed_imprints, list)
            or imprint_algorithm_oid not in allowed_imprints
        ):
            raise TsaError(
                f"RFC 3161 imprint algorithm {imprint_algorithm_oid!r} is not "
                f"allowed for TSA anchor {anchor.get('id')!r}"
            )
        if imprint_algorithm_oid != SHA256_OID or len(hashed_message) != 32:
            raise TsaError("RFC 3161 witness must use a 32-byte SHA-256 message imprint")
        payload = load_json(path)
        identity_spec = spec.identity(str(trust.get("bundleId")), str(anchor.get("id")))
        assert identity_spec is not None
        validate_token_time(
            payload,
            gen_time,
            now=now or datetime.now(UTC),
            max_future_seconds=identity_spec.max_future_seconds,
            max_token_lead_seconds=identity_spec.max_token_lead_seconds,
        )

        verification_env = {
            "SSL_CERT_DIR": str(empty_ca_dir),
            "SSL_CERT_FILE": "/dev/null",
        }
        verification_time = str(int(gen_time.timestamp()))
        _run_openssl(
            [
                "ts",
                "-verify",
                "-config",
                "/dev/null",
                "-data",
                str(path),
                "-in",
                str(token_path),
                "-CAfile",
                str(root_path),
                "-CApath",
                str(empty_ca_dir),
                "-attime",
                verification_time,
            ],
            env=verification_env,
        )
        _run_openssl(
            [
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                str(token_der),
                "-CAfile",
                str(root_path),
                "-no-CApath",
                "-no-CAstore",
                "-purpose",
                "timestampsign",
                "-attime",
                verification_time,
                "-signer",
                str(signer),
                "-out",
                str(tst_info),
            ],
            env=verification_env,
        )
        signer_identity = _certificate_identity(signer)

    allowed_signers = anchor.get("allowedSigners")
    if not isinstance(allowed_signers, list) or signer_identity not in allowed_signers:
        raise TsaError(
            "RFC 3161 token signer is not pinned for TSA anchor "
            f"{anchor.get('id')!r}: {signer_identity}"
        )
    declared = {
        "tsaPolicyOid": policy_oid,
        "tsaImprintAlgorithmOid": imprint_algorithm_oid,
        "tsaGenTime": _format_utc(gen_time),
        "tsaSignerCertificateSha256": signer_identity["certificateSha256"],
        "tsaSignerSpkiSha256": signer_identity["spkiSha256"],
    }
    for key, actual in declared.items():
        if key in token_claim and token_claim[key] != actual:
            raise TsaError(
                f"witness {key} mismatch for {path}: expected {actual}, "
                f"got {token_claim[key]}"
            )
    return TokenEvidence(
        anchor_id=str(anchor["id"]),
        trust_bundle_id=str(trust["bundleId"]),
        trust_bundle_path=bundle_path,
        token_path=token_logical,
        token_sha256=token_sha256,
        policy_oid=policy_oid,
        imprint_algorithm_oid=imprint_algorithm_oid,
        gen_time=_format_utc(gen_time),
        tsa_subject=signer_identity["subject"],
        tsa_certificate_sha256=signer_identity["certificateSha256"],
        tsa_spki_sha256=signer_identity["spkiSha256"],
    )


_TOKEN_EVIDENCE_FIELDS = {
    "tokenPath",
    "tokenSha256",
    "tsaPolicyOid",
    "tsaImprintAlgorithmOid",
    "tsaGenTime",
    "tsaSignerCertificateSha256",
    "tsaSignerSpkiSha256",
}


def _unavailable_outcome(outcome: dict[str, Any], *, label: str) -> None:
    reason = outcome.get("reason")
    if not isinstance(reason, str) or not reason:
        raise TsaError(f"{label} unavailable outcome lacks a reason")
    forbidden = sorted(_TOKEN_EVIDENCE_FIELDS.intersection(outcome))
    if forbidden:
        raise TsaError(f"{label} unavailable outcome contains token evidence: {forbidden}")


def _summarize_witness(
    *,
    status: str,
    digest_sha256: str,
    tokens: list[TokenEvidence],
    supplemental_tokens: list[TokenEvidence] | None = None,
) -> WitnessEvidence:
    if not tokens:
        return WitnessEvidence(
            status=status,
            digest_sha256=digest_sha256,
            supplemental_tokens=tuple(supplemental_tokens or ()),
        )
    earliest = min(
        tokens,
        key=lambda token: (
            _parse_rfc3339(token.gen_time, "token genTime"),
            token.anchor_id,
        ),
    )
    return WitnessEvidence(
        status=status,
        digest_sha256=digest_sha256,
        tokens=tuple(tokens),
        supplemental_tokens=tuple(supplemental_tokens or ()),
        anchor_id=earliest.anchor_id,
        trust_bundle_id=earliest.trust_bundle_id,
        trust_bundle_path=earliest.trust_bundle_path,
        policy_oid=earliest.policy_oid,
        imprint_algorithm_oid=earliest.imprint_algorithm_oid,
        gen_time=earliest.gen_time,
        tsa_subject=earliest.tsa_subject,
        tsa_certificate_sha256=earliest.tsa_certificate_sha256,
        tsa_spki_sha256=earliest.tsa_spki_sha256,
    )


def _v1_witness_evidence(
    path: Path,
    witness: dict[str, Any],
    *,
    spec: TsaSpec,
    records: Path,
    digest_sha256: str,
    trusted_bundles: Mapping[str, dict[str, Any]],
    now: datetime | None,
) -> WitnessEvidence:
    status = witness.get("status")
    if status not in {"available", "unavailable"}:
        raise TsaError(f"invalid witness status for {path}: {status!r}")
    if status == "unavailable":
        if not witness.get("reason"):
            raise TsaError(f"unavailable witness lacks a reason for {path}")
        return WitnessEvidence(status=status, digest_sha256=digest_sha256)
    bundle_reference, _trust = _bundle_for_claim(
        records,
        witness,
        trusted_bundles,
        spec=spec,
        active_required=True,
    )
    token = verify_timestamp_token(
        path,
        witness,
        bundle_reference,
        spec=spec,
        records=records,
        now=now,
    )
    return _summarize_witness(
        status=status,
        digest_sha256=digest_sha256,
        tokens=[token],
    )


def _active_anchor_ids(
    records: Path,
    trusted_bundles: Mapping[str, dict[str, Any]],
    *,
    spec: TsaSpec,
) -> set[str]:
    active: set[str] = set()
    for reference in trusted_bundles.values():
        _path, trust = _load_trust_bundle(records, reference, spec=spec)
        active.update(str(anchor["id"]) for anchor in trust["anchors"])
    return active


def _supplemental_candidates(
    records: Path,
    trusted_bundles: Mapping[str, dict[str, Any]],
    transition_bundle_updates: list[dict[str, Any]],
    *,
    spec: TsaSpec,
) -> dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]]:
    active_ids = _active_anchor_ids(records, trusted_bundles, spec=spec)
    candidates: dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
    for reference in transition_bundle_updates:
        bundle_path = str(reference["path"])
        if bundle_path in trusted_bundles:
            continue
        _path, trust = _load_trust_bundle(records, reference, spec=spec)
        for anchor in trust["anchors"]:
            anchor_id = str(anchor["id"])
            if anchor_id not in active_ids:
                candidates[(bundle_path, anchor_id)] = (reference, anchor)
    return candidates


def _v2_witness_evidence(
    path: Path,
    witness: dict[str, Any],
    *,
    spec: TsaSpec,
    records: Path,
    digest_sha256: str,
    trusted_bundles: Mapping[str, dict[str, Any]],
    transition_bundle_updates: list[dict[str, Any]],
    now: datetime | None,
) -> WitnessEvidence:
    status = witness.get("status")
    if status not in {"available", "unavailable"}:
        raise TsaError(f"invalid witness status for {path}: {status!r}")
    preferred = preferred_active_trust_bundle(trusted_bundles)
    if witness.get("trustBundlePath") != preferred["path"]:
        raise TsaError("multi-token witness does not use the newest active TSA trust bundle")
    bundle_reference, trust = _bundle_for_claim(
        records,
        witness,
        trusted_bundles,
        spec=spec,
        active_required=True,
    )
    outcomes = witness.get("anchorOutcomes")
    if not isinstance(outcomes, list):
        raise TsaError("multi-token witness anchorOutcomes must be a list")
    expected_anchor_ids = {str(anchor["id"]) for anchor in trust["anchors"]}
    seen_anchor_ids: set[str] = set()
    tokens: list[TokenEvidence] = []
    for outcome in outcomes:
        if not isinstance(outcome, dict):
            raise TsaError("multi-token witness outcome is not an object")
        anchor = _select_anchor(records, outcome, trust, spec=spec)
        anchor_id = str(anchor["id"])
        if anchor_id in seen_anchor_ids:
            raise TsaError(f"duplicate TSA anchor outcome: {anchor_id}")
        seen_anchor_ids.add(anchor_id)
        outcome_status = outcome.get("status")
        if outcome_status == "available":
            claim = {**witness, **outcome}
            tokens.append(
                verify_timestamp_token(
                    path,
                    claim,
                    bundle_reference,
                    spec=spec,
                    records=records,
                    now=now,
                )
            )
        elif outcome_status == "unavailable":
            _unavailable_outcome(outcome, label=f"TSA anchor {anchor_id}")
        else:
            raise TsaError(
                f"invalid TSA anchor outcome status for {anchor_id}: "
                f"{outcome_status!r}"
            )
    if seen_anchor_ids != expected_anchor_ids:
        raise TsaError(
            "multi-token witness anchor outcome mismatch: "
            f"missing={sorted(expected_anchor_ids - seen_anchor_ids)}, "
            f"extra={sorted(seen_anchor_ids - expected_anchor_ids)}"
        )

    candidates = _supplemental_candidates(
        records,
        trusted_bundles,
        transition_bundle_updates,
        spec=spec,
    )
    supplemental = witness.get("supplementalOutcomes", [])
    if not isinstance(supplemental, list):
        raise TsaError("multi-token witness supplementalOutcomes must be a list")
    seen_supplemental: set[tuple[str, str]] = set()
    supplemental_tokens: list[TokenEvidence] = []
    for outcome in supplemental:
        if not isinstance(outcome, dict):
            raise TsaError("supplemental TSA outcome is not an object")
        if outcome.get("role") != "pending_trust_bundle":
            raise TsaError("supplemental TSA outcome has the wrong role")
        bundle_path = outcome.get("trustBundlePath")
        anchor_id = outcome.get("tsaAnchorId")
        key = (str(bundle_path), str(anchor_id))
        if key in seen_supplemental:
            raise TsaError(f"duplicate supplemental TSA outcome: {key}")
        seen_supplemental.add(key)
        candidate = candidates.get(key)
        if candidate is None:
            raise TsaError(
                "supplemental TSA outcome is not introduced by a pending "
                f"trust transition: {key}"
            )
        reference, trust_anchor = candidate
        _reference, pending_trust = _bundle_for_claim(
            records,
            outcome,
            trusted_bundles,
            spec=spec,
            active_required=False,
        )
        selected = _select_anchor(records, outcome, pending_trust, spec=spec)
        if selected != trust_anchor:
            raise TsaError(f"supplemental TSA anchor mismatch: {key}")
        outcome_status = outcome.get("status")
        if outcome_status == "available":
            supplemental_tokens.append(
                verify_timestamp_token(
                    path,
                    outcome,
                    reference,
                    spec=spec,
                    records=records,
                    now=now,
                )
            )
        elif outcome_status == "unavailable":
            _unavailable_outcome(outcome, label=f"supplemental TSA anchor {anchor_id}")
        else:
            raise TsaError(
                f"invalid supplemental TSA outcome status: {outcome_status!r}"
            )
    if seen_supplemental != set(candidates):
        raise TsaError(
            "supplemental TSA outcome mismatch: "
            f"missing={sorted(set(candidates) - seen_supplemental)}, "
            f"extra={sorted(seen_supplemental - set(candidates))}"
        )

    expected_status = "available" if tokens else "unavailable"
    if status != expected_status:
        raise TsaError(
            f"multi-token witness status {status!r} disagrees with verified "
            f"token evidence {expected_status!r}"
        )
    if status == "unavailable" and not witness.get("reason"):
        raise TsaError(f"unavailable witness lacks a reason for {path}")
    return _summarize_witness(
        status=status,
        digest_sha256=digest_sha256,
        tokens=tokens,
        supplemental_tokens=supplemental_tokens,
    )


def verify_witness(
    path: Path,
    *,
    spec: TsaSpec,
    records: Path | None = None,
    now: datetime | None = None,
    trusted_bundles: Mapping[str, dict[str, Any]] | None = None,
    transition_bundle_updates: list[dict[str, Any]] | None = None,
) -> WitnessEvidence:
    records = (records or path.parents[1]).resolve()
    digest_sha = sha256_file(path)
    witness_path = path.with_suffix(".witness.json")
    if not witness_path.is_file():
        raise TsaError(f"missing explicit witness marker for {path}")
    witness = load_json(witness_path)
    if witness.get("digestSha256") != digest_sha:
        raise TsaError(
            f"witness digest mismatch for {path}: expected {digest_sha}, "
            f"got {witness.get('digestSha256')}"
        )
    if trusted_bundles is None:
        genesis = load_json(records / "CHAIN_GENESIS.json")
        trusted_bundles = bootstrap_trust_bundles(
            records, genesis, spec=spec, required=True
        )
    if transition_bundle_updates is None:
        transition_bundle_updates = trust_bundle_updates(
            records, load_json(path), spec=spec
        )
    schema = witness.get("schemaVersion")
    if schema == "thesis_rfc3161_witness_v1":
        preferred = (
            preferred_active_trust_bundle(trusted_bundles)
            if trusted_bundles
            else None
        )
        if transition_bundle_updates or (
            preferred is not None
            and preferred["bundleId"] != spec.legacy_witness_bundle_id
        ):
            raise TsaError(
                "legacy witness schema cannot cover a TSA trust transition "
                "or a chain with v2 active"
            )
        return _v1_witness_evidence(
            path,
            witness,
            spec=spec,
            records=records,
            digest_sha256=digest_sha,
            trusted_bundles=trusted_bundles,
            now=now,
        )
    if schema == "thesis_rfc3161_witness_v2":
        return _v2_witness_evidence(
            path,
            witness,
            spec=spec,
            records=records,
            digest_sha256=digest_sha,
            trusted_bundles=trusted_bundles,
            transition_bundle_updates=transition_bundle_updates,
            now=now,
        )
    raise TsaError(f"unsupported witness schema for {path}")
