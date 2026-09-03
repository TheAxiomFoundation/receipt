"""Offline verification for an append-only witnessed release chain.

The verifier treats manifest, signature, and receipt bytes as an append-only
journal. It does not trust manifest provenance or timestamps supplied by the
producer: each manifest is canonical and content-addressed, every state and
append digest is recomputed from the current append-only JSONL, every manifest
has a valid signature from the pinned producer key, and every RFC 3161 receipt
in the consumer's configured anchor set is verified against its committed trust
anchor. (Byte-pin enforcement follows the effective pin mode: when not set
explicitly, it is inferred on exactly when the effective anchor directory
resolves to the spec's own, and independently overrideable in either
direction. With pins off, verification establishes signatures against
whatever material the effective anchor directory holds — the caller's own
trust choice.)

Extracted nearly verbatim from PolicyEngine/ledger scripts/verify_release_chain.py
at commit 07984278503b8e06c48c539327f6f1d01c035510 (branch
codex/thesis-ledger-facts); see receipts/ledger-pin-source-hashes.txt. The only
intended change is parameterization: every repo-specific constant moved into
ChainSpec, supplied by the consumer's committed code. Behavior is gated by the
differential harness in tests/test_ledger_equivalence.py. Additions since the
extraction (the base-ref history pass with its checkout and index guards,
which include requiring every base release file to still be an entry in the
candidate index, since both of that pass's comparisons read the working tree
and ``git rm --cached`` leaves it untouched; the release-root guard, which
reconciles that root's index entries with the working tree in both
directions, by the spelling the traversal returns and after walking an
indexed path's parents, because a filesystem traversal does not descend a
symlinked directory while resolving the whole name does — and because a
case- or normalisation-insensitive filesystem answers one entry's question
with another entry's file; the state-path guards ``append_gate`` calls;
the anchor-set digest in the result) run beside the extracted checks without
altering any of their refusals, and carry their own tests. Every one of those
index reads names its path as a literal pathspec, so git is asked about the
exact path rather than handed a name to interpret as a pattern, and every git
read here runs with git's four pathspec-mode environment variables dropped, so
that literal pathspec means what it says instead of whatever an ambient
``GIT_LITERAL_PATHSPECS`` or ``GIT_ICASE_PATHSPECS`` would make of it. Each
also reads the entry's own flag word, because mode and object id do not say
whether an entry records content: an intent-to-add entry (``git add -N``) is
stage 0 at the working tree's mode with the empty blob's object id, which is
what every check here took for a tracked file while the commit made from that
index deletes the path. The state
reads themselves changed shape but not their refusals: ``_regular_file_bytes``
keeps both of its messages and their order, and opens the file it accepts
through directory descriptors so no component of the path is resolved twice.
That descent returns the identity of every directory it opened, so a caller
can ask afterwards whether the file is still reached through the same ones,
optionally pins the root against an identity the caller recorded earlier, and
refuses outright rather than falling back to a pathname open where ``os.open``
takes no ``dir_fd``. ``assert_index_agrees_with_tree`` likewise accepts a
category the caller has already observed, so a caller holding the file open
need not resolve its name again.
``verify_release_chain`` takes an optional ``state_bytes`` mapping that stands
in for reading a state path, so a caller that has already read those files can
hold one verdict to one read of each; omitted, both files are read exactly as
before. Every git subprocess here runs with ``refs/replace`` disabled
(``_git_environment``); those additions are its only callers, and a
replacement object would otherwise change what a base commit, tree, or blob
reads as behind the OID a verdict names.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any

from receipt import sign as _sign
from receipt.canonical import canonical_bytes, canonical_sha256

# One availability gate for the whole package: producer-signature verification
# lives in receipt.sign, and this module's only remaining cryptography use is
# choosing between sign's cryptography and OpenSSL 3 CLI paths.
from receipt.sign import CRYPTOGRAPHY_AVAILABLE, SignError, _openssl_environment

MAX_RELEASE_INDEX = 9_999
DEFAULT_CLOCK_SKEW_SECONDS = 300
MAX_FUTURE_SECONDS = 300
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
MANIFEST_RE = re.compile(r"(?P<index>[0-9]{4})-(?P<digest>[0-9a-f]{16})\.json\Z")
PRODUCER_SIGNATURE_RE = re.compile(
    r"(?P<stem>[0-9]{4}-[0-9a-f]{16})\.producer\.sig\Z"
)
PRODUCER_SIGNATURE_BYTES = _sign.PRODUCER_SIGNATURE_BYTES
STRICT_UTC_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:"
    r"[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z"
)
# A well-formed surrogate pair spelled explicitly inside a Python string:
# JSON parsing rewrites it into the astral character, so a filename carrying
# one could never be reproduced from JSON output (see _combined_anchor_digest).
_SURROGATE_PAIR_RE = re.compile("[\ud800-\udbff][\udc00-\udfff]")
TIME_STAMP_RE = re.compile(
    r"(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>[0-9]{1,2})\s+"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):"
    r"(?P<second>[0-9]{2})(?P<fraction>\.[0-9]+)?\s+"
    r"(?P<year>[0-9]{4})\s+GMT\Z"
)


@dataclass(frozen=True)
class AnchorSpec:
    filename: str
    pem_sha256: str
    policy_oid: str
    signer_certificate_sha256: str
    signer_spki_sha256: str


@dataclass(frozen=True)
class ChainSpec:
    """Repo-specific custody constants, pinned in the consumer's committed code.

    The package ships machinery only. Every trust anchor — manifest layout,
    schema name, producer SPKI fingerprint, TSA anchor identities — arrives
    from the consumer's own committed code, never from package defaults, so a
    producer can never swap a pin at runtime.
    """

    manifest_relative: pathlib.PurePosixPath
    state_relative: pathlib.PurePosixPath
    prefix_relative: pathlib.PurePosixPath
    anchor_relative: pathlib.PurePosixPath
    release_root_relative: pathlib.PurePosixPath
    schema_version: str
    producer_public_key_filename: str
    producer_spki_sha256: str
    anchors: Mapping[str, AnchorSpec]

    @property
    def state_path(self) -> str:
        return self.state_relative.as_posix()


def _receipt_re(spec: ChainSpec) -> re.Pattern[str]:
    tsa_alternation = "|".join(re.escape(tsa) for tsa in sorted(spec.anchors))
    return re.compile(
        r"(?P<stem>[0-9]{4}-[0-9a-f]{16})"
        rf"\.(?P<tsa>{tsa_alternation})\.tsr\Z"
    )


class ReleaseChainError(ValueError):
    """The release journal is malformed, inconsistent, or untrusted."""


@dataclass(frozen=True)
class GitEntry:
    mode: str
    object_type: str
    object_id: str
    path: str


@dataclass(frozen=True)
class ReleaseRecord:
    path: pathlib.Path
    raw: bytes
    sha256: str
    manifest: dict[str, Any]
    receipt_paths: dict[str, pathlib.Path]
    receipt_times: dict[str, datetime]
    producer_signature_path: pathlib.Path

    @property
    def release_index(self) -> int:
        return int(self.manifest["releaseIndex"])


@dataclass(frozen=True)
class ChainVerification:
    releases: tuple[ReleaseRecord, ...]
    #: One SHA-256 naming the anchor bytes this run consumed — captured at
    #: the read sites signature and receipt verification actually used, not
    #: re-read for that consumption (later releases and roles deliberately
    #: re-read and re-observe). None when the caller did not request it
    #: (compute_anchor_set_digest=False, the default) or no chain was
    #: verified. Canonical form and the exact claim are documented on
    #: _combined_anchor_digest. What the digests establish depends on the
    #: run's pin mode: with production pins enforced (always true under
    #: receipt.verify's spanning verifier), TSA anchor bytes are code-pinned
    #: exactly while producer identity is pinned by SPKI with its
    #: serialization recorded; with pins off — a caller's own trust choice —
    #: the mapping records consumed bytes and establishes no pin claim.
    anchor_set_sha256: str | None = None
    #: The per-file digests behind anchor_set_sha256 as a sorted tuple of
    #: (filename, sha256) pairs — immutable, and adding no hashability or
    #: reflection constraint beyond 0.5.0's (the empty result stays hashable;
    #: a populated result was already unhashable through ReleaseRecord's
    #: dictionaries). ``dict(...)`` it for mapping access. Keys are the
    #: spec's configured filenames coerced with os.fsdecode — the pathname
    #: the path joins consumed, not resolved path identities.
    anchor_file_sha256s: tuple[tuple[str, str], ...] = ()

    @property
    def head(self) -> ReleaseRecord | None:
        return self.releases[-1] if self.releases else None


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _fail_json_constant(value: str) -> None:
    raise ReleaseChainError(f"manifest contains non-JSON number {value!r}")


def _object_without_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseChainError(f"manifest has duplicate key {key!r}")
        result[key] = value
    return result


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ReleaseChainError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise ReleaseChainError(
            f"{label} keys are not closed-world: missing={missing}, unknown={unknown}"
        )
    return value


def _strict_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int:
        raise ReleaseChainError(f"{label} must be an integer, not a boolean")
    if value < minimum:
        raise ReleaseChainError(f"{label} must be >= {minimum}")
    return value


def _strict_string(value: Any, label: str, *, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value):
        suffix = " and non-empty" if nonempty else ""
        raise ReleaseChainError(f"{label} must be a string{suffix}")
    return value


def _sha256(value: Any, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise ReleaseChainError(
            f"{label} must be exactly 64 lowercase hexadecimal characters"
        )
    return value


def parse_created_at(value: Any, label: str = "createdAtUtc") -> datetime:
    text = _strict_string(value, label)
    if STRICT_UTC_RE.fullmatch(text) is None:
        raise ReleaseChainError(f"{label} must be a strict UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ReleaseChainError(f"{label} is not a real UTC time: {text!r}") from exc
    return parsed.astimezone(timezone.utc)


def validate_manifest_schema(manifest: Any, spec: ChainSpec) -> dict[str, Any]:
    """Validate the closed-world release-manifest schema named by ``spec``."""

    payload = _exact_keys(
        manifest,
        {
            "schemaVersion",
            "releaseIndex",
            "previousManifestSha256",
            "state",
            "append",
            "createdAtUtc",
            "producer",
        },
        "manifest",
    )
    if payload["schemaVersion"] != spec.schema_version:
        raise ReleaseChainError(
            f"unsupported manifest schema {payload['schemaVersion']!r}"
        )
    index = _strict_int(payload["releaseIndex"], "releaseIndex")
    if index > MAX_RELEASE_INDEX:
        raise ReleaseChainError(
            f"releaseIndex {index} exceeds the four-digit filename limit"
        )

    previous = payload["previousManifestSha256"]
    if index == 0:
        if previous is not None:
            raise ReleaseChainError("genesis previousManifestSha256 must be null")
    else:
        _sha256(previous, "previousManifestSha256")

    state = _exact_keys(
        payload["state"],
        {
            "path",
            "jsonlSha256",
            "lineCount",
            "immutablePrefixSha256",
        },
        "state",
    )
    if state["path"] != spec.state_path:
        raise ReleaseChainError(f"state.path must be exactly {spec.state_path!r}")
    _sha256(state["jsonlSha256"], "state.jsonlSha256")
    _strict_int(state["lineCount"], "state.lineCount")
    _sha256(
        state["immutablePrefixSha256"],
        "state.immutablePrefixSha256",
    )

    append = payload["append"]
    if index == 0:
        if append is not None:
            raise ReleaseChainError("genesis append must be null")
    else:
        append_block = _exact_keys(
            append,
            {
                "previousLineCount",
                "appendedRowCount",
                "appendedBytesSha256",
            },
            "append",
        )
        _strict_int(
            append_block["previousLineCount"],
            "append.previousLineCount",
        )
        _strict_int(
            append_block["appendedRowCount"],
            "append.appendedRowCount",
            minimum=1,
        )
        _sha256(
            append_block["appendedBytesSha256"],
            "append.appendedBytesSha256",
        )

    parse_created_at(payload["createdAtUtc"])
    producer = _exact_keys(payload["producer"], {"repo", "branch"}, "producer")
    _strict_string(producer["repo"], "producer.repo")
    _strict_string(producer["branch"], "producer.branch")
    return payload


def load_manifest(
    path: pathlib.Path, spec: ChainSpec
) -> tuple[dict[str, Any], bytes, str]:
    if path.is_symlink() or not path.is_file():
        raise ReleaseChainError(f"manifest is not a regular file: {path}")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseChainError(f"manifest is not UTF-8: {path}") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_fail_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise ReleaseChainError(f"manifest is not valid JSON: {path}: {exc}") from exc
    payload = validate_manifest_schema(parsed, spec)
    expected = canonical_bytes(payload) + b"\n"
    if raw != expected:
        raise ReleaseChainError(
            f"manifest bytes are not canonical JSON plus one newline: {path}"
        )
    return payload, raw, sha256_bytes(raw)


def manifest_filename(index: int, raw: bytes) -> str:
    _strict_int(index, "releaseIndex")
    if index > MAX_RELEASE_INDEX:
        raise ReleaseChainError(
            f"releaseIndex {index} exceeds the four-digit filename limit"
        )
    return f"{index:04d}-{sha256_bytes(raw)[:16]}.json"


def receipt_paths_for_manifest(
    path: pathlib.Path, spec: ChainSpec
) -> dict[str, pathlib.Path]:
    stem = path.stem
    return {tsa: path.with_name(f"{stem}.{tsa}.tsr") for tsa in spec.anchors}


def producer_signature_path_for_manifest(path: pathlib.Path) -> pathlib.Path:
    return path.with_name(f"{path.stem}.producer.sig")


def _enumerate_manifest_files(
    root: pathlib.Path, spec: ChainSpec
) -> list[tuple[pathlib.Path, dict[str, pathlib.Path], pathlib.Path]]:
    directory = root / spec.manifest_relative
    if not directory.exists():
        return []
    if directory.is_symlink() or not directory.is_dir():
        raise ReleaseChainError(
            f"release manifest path is not a regular directory: {directory}"
        )

    receipt_re = _receipt_re(spec)
    manifests: dict[str, pathlib.Path] = {}
    receipts: dict[str, dict[str, pathlib.Path]] = {}
    producer_signatures: dict[str, pathlib.Path] = {}
    for entry in directory.iterdir():
        if entry.is_symlink() or not entry.is_file():
            raise ReleaseChainError(
                f"release manifest directory contains a non-regular entry: {entry}"
            )
        manifest_match = MANIFEST_RE.fullmatch(entry.name)
        if manifest_match is not None:
            manifests[entry.stem] = entry
            continue
        receipt_match = receipt_re.fullmatch(entry.name)
        if receipt_match is not None:
            stem = receipt_match.group("stem")
            tsa = receipt_match.group("tsa")
            receipts.setdefault(stem, {})[tsa] = entry
            continue
        signature_match = PRODUCER_SIGNATURE_RE.fullmatch(entry.name)
        if signature_match is not None:
            producer_signatures[signature_match.group("stem")] = entry
            continue
        raise ReleaseChainError(
            f"unknown file in closed release manifest directory: {entry.name}"
        )

    orphan_receipts = sorted(set(receipts) - set(manifests))
    if orphan_receipts:
        raise ReleaseChainError(
            f"orphan release receipts for manifest stems: {orphan_receipts}"
        )
    orphan_signatures = sorted(set(producer_signatures) - set(manifests))
    if orphan_signatures:
        raise ReleaseChainError(
            "orphan producer signatures for manifest stems: "
            f"{orphan_signatures}"
        )
    result: list[
        tuple[pathlib.Path, dict[str, pathlib.Path], pathlib.Path]
    ] = []
    seen_indices: dict[int, str] = {}
    for stem, path in manifests.items():
        match = MANIFEST_RE.fullmatch(path.name)
        assert match is not None
        index = int(match.group("index"))
        if index in seen_indices:
            raise ReleaseChainError(
                f"duplicate release index {index}: {seen_indices[index]}, {path.name}"
            )
        seen_indices[index] = path.name
        actual_receipts = receipts.get(stem, {})
        if set(actual_receipts) != set(spec.anchors):
            raise ReleaseChainError(
                f"manifest {path.name} must have exactly "
                f"{' and '.join(spec.anchors)} "
                f"receipts; found={sorted(actual_receipts)}"
            )
        producer_signature = producer_signatures.get(stem)
        if producer_signature is None:
            raise ReleaseChainError(
                f"manifest {path.name} is missing its producer signature "
                f"{stem}.producer.sig"
            )
        result.append((path, actual_receipts, producer_signature))
    return sorted(
        result,
        key=lambda item: int(MANIFEST_RE.fullmatch(item[0].name).group("index")),
    )


def _command_error(completed: subprocess.CompletedProcess[str]) -> str:
    details = (completed.stderr or completed.stdout).strip()
    return details[-1000:] if details else "no OpenSSL diagnostic"


def _parse_receipt_text(output: str, receipt: pathlib.Path) -> tuple[datetime, str]:
    status_lines = [
        line.strip() for line in output.splitlines() if line.startswith("Status:")
    ]
    if status_lines != ["Status: Granted."]:
        raise ReleaseChainError(
            f"RFC 3161 receipt is not granted for {receipt}: {status_lines}"
        )
    hash_lines = [
        line.split(":", 1)[1].strip()
        for line in output.splitlines()
        if line.startswith("Hash Algorithm:")
    ]
    if hash_lines != ["sha256"]:
        raise ReleaseChainError(
            f"RFC 3161 receipt does not use SHA-256 for {receipt}: {hash_lines}"
        )
    policy_lines = [
        line.split(":", 1)[1].strip()
        for line in output.splitlines()
        if line.startswith("Policy OID:")
    ]
    if len(policy_lines) != 1:
        raise ReleaseChainError(
            f"RFC 3161 receipt has no unique policy OID for {receipt}"
        )
    time_lines = [
        line.split(":", 1)[1].strip()
        for line in output.splitlines()
        if line.startswith("Time stamp:")
    ]
    if len(time_lines) != 1:
        raise ReleaseChainError(f"RFC 3161 receipt has no unique genTime for {receipt}")
    match = TIME_STAMP_RE.fullmatch(time_lines[0])
    if match is None:
        raise ReleaseChainError(
            f"unsupported RFC 3161 genTime for {receipt}: {time_lines[0]!r}"
        )
    timestamp = (
        f"{match.group('month')} {match.group('day')} "
        f"{match.group('hour')}:{match.group('minute')}:"
        f"{match.group('second')} {match.group('year')} GMT"
    )
    try:
        parsed = datetime.strptime(timestamp, "%b %d %H:%M:%S %Y GMT").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ReleaseChainError(
            f"invalid RFC 3161 genTime for {receipt}: {timestamp!r}"
        ) from exc
    fraction = match.group("fraction")
    if fraction:
        parsed = parsed.replace(microsecond=int((fraction[1:] + "000000")[:6]))
    return parsed, policy_lines[0]


def _openssl_binary(
    arguments: list[str],
    *,
    environment: dict[str, str],
    label: str,
) -> bytes:
    try:
        completed = subprocess.run(
            ["openssl", *arguments],
            check=False,
            capture_output=True,
            env=environment,
        )
    except FileNotFoundError as exc:
        raise ReleaseChainError(
            "openssl is required for RFC 3161 verification"
        ) from exc
    if completed.returncode != 0:
        diagnostic = (completed.stderr or completed.stdout).decode(
            "utf-8", errors="replace"
        )
        raise ReleaseChainError(
            f"OpenSSL {label} failed (exit {completed.returncode}): "
            f"{diagnostic.strip()[-1000:]}"
        )
    return completed.stdout


def _producer_openssl_binary(
    arguments: list[str],
    *,
    environment: dict[str, str],
    label: str,
) -> bytes:
    try:
        return _sign._producer_openssl_binary(
            arguments,
            environment=environment,
            label=label,
        )
    except SignError as exc:
        raise ReleaseChainError(str(exc)) from exc


def _verify_producer_signature_with_openssl(
    manifest: bytes,
    signature: bytes,
    public_key_pem: bytes,
    *,
    spec: ChainSpec,
    enforce_production_pin: bool,
    label: str,
) -> None:
    try:
        _sign._verify_producer_signature_with_openssl(
            manifest,
            signature,
            public_key_pem,
            public_key_filename=spec.producer_public_key_filename,
            temporary_public_key_filename=spec.producer_public_key_filename,
            spki_sha256=(
                spec.producer_spki_sha256 if enforce_production_pin else None
            ),
            label=label,
        )
    except SignError as exc:
        raise ReleaseChainError(str(exc)) from exc


def verify_producer_signature_bytes(
    manifest: bytes,
    signature: bytes,
    *,
    spec: ChainSpec,
    anchor_dir: pathlib.Path,
    enforce_production_pin: bool,
    label: str,
    anchor_observer: dict[str, str] | None = None,
) -> None:
    """Verify one raw Ed25519 signature over exact manifest bytes."""

    key_spec = _sign.ProducerKeySpec(
        # When observing, normalized once here: the join below,
        # read_producer_public_key's own join, the observer key, and the
        # fallback's temporary filename all flow from this one value, so no
        # later __fspath__ call exists for a stateful PathLike to answer
        # differently. When not observing, the raw configured value flows
        # exactly as it always has.
        public_key_filename=(
            _exact_filename(spec.producer_public_key_filename)
            if anchor_observer is not None
            else spec.producer_public_key_filename
        ),
        spki_sha256=spec.producer_spki_sha256,
    )
    public_key_path = anchor_dir / key_spec.public_key_filename
    try:
        # Preserve the upstream branch order: bad payload/signature inputs
        # refuse before a missing producer-key path is inspected.
        _sign._validate_signature_inputs(manifest, signature, label)
        public_key_pem = _sign.read_producer_public_key(anchor_dir, key_spec)
        # These exact bytes feed both verification branches below, so the
        # observed digest is the digest of the key material actually used.
        _observe_anchor_bytes(
            anchor_observer, key_spec.public_key_filename, public_key_pem
        )
        if not CRYPTOGRAPHY_AVAILABLE:
            # When observing, the temporary key file must be a private leaf:
            # a configured filename that is absolute would survive the
            # temporary-directory join and hand OpenSSL (and the write
            # before it) the original path, breaking the snapshot guarantee
            # the observed digest depends on.
            temporary_key_name = (
                "producer-key-snapshot.pem"
                if anchor_observer is not None
                else key_spec.public_key_filename
            )
            _sign._verify_producer_signature_with_openssl(
                manifest,
                signature,
                public_key_pem,
                public_key_filename=str(public_key_path),
                temporary_public_key_filename=temporary_key_name,
                spki_sha256=(
                    key_spec.spki_sha256 if enforce_production_pin else None
                ),
                label=label,
            )
            return
        _sign.verify_signature_bytes(
            manifest,
            signature,
            public_key_pem,
            public_key_filename=str(public_key_path),
            spki_sha256=(key_spec.spki_sha256 if enforce_production_pin else None),
            label=label,
        )
    except SignError as exc:
        raise ReleaseChainError(str(exc)) from exc


def verify_producer_signature(
    manifest: bytes,
    signature_path: pathlib.Path,
    *,
    spec: ChainSpec,
    anchor_dir: pathlib.Path,
    enforce_production_pin: bool,
    anchor_observer: dict[str, str] | None = None,
) -> None:
    if signature_path.is_symlink() or not signature_path.is_file():
        raise ReleaseChainError(
            f"missing or non-regular producer signature: {signature_path}"
        )
    verify_producer_signature_bytes(
        manifest,
        signature_path.read_bytes(),
        spec=spec,
        anchor_dir=anchor_dir,
        enforce_production_pin=enforce_production_pin,
        label=signature_path.name,
        anchor_observer=anchor_observer,
    )


def _verify_production_signer(
    receipt: pathlib.Path,
    anchor: pathlib.Path,
    anchor_spec: AnchorSpec,
    gen_time: datetime,
    temporary: pathlib.Path,
    environment: dict[str, str],
) -> None:
    token = temporary / "token.der"
    signer = temporary / "signer.pem"
    content = temporary / "tst-info.der"
    _openssl_binary(
        [
            "ts",
            "-reply",
            "-config",
            "/dev/null",
            "-in",
            str(receipt),
            "-token_out",
            "-out",
            str(token),
        ],
        environment=environment,
        label=f"token extraction for {receipt.name}",
    )
    _openssl_binary(
        [
            "cms",
            "-verify",
            "-inform",
            "DER",
            "-in",
            str(token),
            "-CAfile",
            str(anchor),
            "-no-CApath",
            "-no-CAstore",
            "-purpose",
            "timestampsign",
            "-attime",
            str(int(gen_time.timestamp())),
            "-signer",
            str(signer),
            "-out",
            str(content),
        ],
        environment=environment,
        label=f"signer extraction for {receipt.name}",
    )
    certificate_der = _openssl_binary(
        ["x509", "-in", str(signer), "-outform", "DER"],
        environment=environment,
        label=f"signer certificate decoding for {receipt.name}",
    )
    public_key_pem = _openssl_binary(
        ["x509", "-in", str(signer), "-pubkey", "-noout"],
        environment=environment,
        label=f"signer public-key extraction for {receipt.name}",
    )
    public_key = temporary / "signer-public-key.pem"
    public_key.write_bytes(public_key_pem)
    public_key_der = _openssl_binary(
        ["pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
        environment=environment,
        label=f"signer SPKI decoding for {receipt.name}",
    )
    certificate_sha256 = sha256_bytes(certificate_der)
    spki_sha256 = sha256_bytes(public_key_der)
    if certificate_sha256 != anchor_spec.signer_certificate_sha256:
        raise ReleaseChainError(
            f"RFC 3161 signer certificate is not pinned for {receipt.name}: "
            f"{certificate_sha256}"
        )
    if spki_sha256 != anchor_spec.signer_spki_sha256:
        raise ReleaseChainError(
            f"RFC 3161 signer SPKI is not pinned for {receipt.name}: {spki_sha256}"
        )


def verify_receipt(
    manifest_digest: str,
    receipt: pathlib.Path,
    tsa: str,
    *,
    spec: ChainSpec,
    anchor_dir: pathlib.Path,
    enforce_production_pins: bool,
    now: datetime | None = None,
    anchor_observer: dict[str, str] | None = None,
) -> datetime:
    """Cryptographically verify one receipt and return its signed genTime."""

    if tsa not in spec.anchors:
        raise ReleaseChainError(f"unknown TSA receipt kind {tsa!r}")
    _sha256(manifest_digest, "manifest digest")
    if receipt.is_symlink() or not receipt.is_file():
        raise ReleaseChainError(f"missing or non-regular RFC 3161 receipt: {receipt}")
    anchor_spec = spec.anchors[tsa]
    # When observing: one normalization for the join and the observer key
    # alike — a stateful PathLike gets exactly one __fspath__ call per
    # consumption. When not observing: the raw configured value joins
    # exactly as it always has.
    anchor_filename = (
        _exact_filename(anchor_spec.filename)
        if anchor_observer is not None
        else anchor_spec.filename
    )
    anchor = anchor_dir / anchor_filename
    if anchor.is_symlink() or not anchor.is_file():
        raise ReleaseChainError(f"missing or non-regular TSA anchor: {anchor}")
    anchor_bytes: bytes | None = None
    if enforce_production_pins or anchor_observer is not None:
        anchor_bytes = anchor.read_bytes()
    if enforce_production_pins:
        assert anchor_bytes is not None
        anchor_digest = sha256_bytes(anchor_bytes)
        if anchor_digest != anchor_spec.pem_sha256:
            raise ReleaseChainError(
                f"production TSA anchor bytes are not code-pinned for {tsa}: "
                f"{anchor_digest}"
            )
    if anchor_observer is not None:
        assert anchor_bytes is not None
        _observe_anchor_bytes(anchor_observer, anchor_filename, anchor_bytes)

    with tempfile.TemporaryDirectory(prefix="thesis-release-tsa-") as name:
        temporary = pathlib.Path(name)
        empty_ca_dir = temporary / "empty-ca"
        empty_ca_dir.mkdir()
        environment = _openssl_environment(empty_ca_dir)
        # When observing, OpenSSL must consume exactly the bytes that were
        # just digested — not whatever the anchor path holds by the time each
        # subprocess independently reopens it — so the snapshot is written
        # into this run's private directory and used as the trust anchor for
        # every OpenSSL call below.
        if anchor_observer is not None:
            assert anchor_bytes is not None
            snapshot = temporary / f"anchor-{tsa}.pem"
            snapshot.write_bytes(anchor_bytes)
            anchor = snapshot
        try:
            text_result = subprocess.run(
                [
                    "openssl",
                    "ts",
                    "-reply",
                    "-config",
                    "/dev/null",
                    "-in",
                    str(receipt),
                    "-text",
                ],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
        except FileNotFoundError as exc:
            raise ReleaseChainError(
                "openssl is required for RFC 3161 verification"
            ) from exc
        if text_result.returncode != 0:
            raise ReleaseChainError(
                f"cannot inspect RFC 3161 receipt {receipt} "
                f"(exit {text_result.returncode}): {_command_error(text_result)}"
            )
        gen_time, policy_oid = _parse_receipt_text(text_result.stdout, receipt)
        if enforce_production_pins and policy_oid != anchor_spec.policy_oid:
            raise ReleaseChainError(
                f"RFC 3161 policy is not pinned for {tsa}: {policy_oid!r}"
            )
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if gen_time > current + timedelta(seconds=MAX_FUTURE_SECONDS):
            raise ReleaseChainError(
                f"RFC 3161 genTime {gen_time.isoformat()} for {receipt.name} "
                f"postdates verifier time {current.isoformat()}"
            )

        verify_result = subprocess.run(
            [
                "openssl",
                "ts",
                "-verify",
                "-config",
                "/dev/null",
                "-digest",
                manifest_digest,
                "-in",
                str(receipt),
                "-CAfile",
                str(anchor),
                "-CApath",
                str(empty_ca_dir),
                "-attime",
                str(int(gen_time.timestamp())),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        if verify_result.returncode != 0:
            raise ReleaseChainError(
                f"RFC 3161 verification failed for {receipt.name} "
                f"(exit {verify_result.returncode}): "
                f"{_command_error(verify_result)}"
            )
        if enforce_production_pins:
            _verify_production_signer(
                receipt,
                anchor,
                anchor_spec,
                gen_time,
                temporary,
                environment,
            )
    return gen_time


def verify_release_receipts(
    manifest: dict[str, Any],
    manifest_digest: str,
    receipt_paths: dict[str, pathlib.Path],
    *,
    spec: ChainSpec,
    anchor_dir: pathlib.Path,
    enforce_production_pins: bool,
    clock_skew_seconds: int,
    previous_times: dict[str, datetime] | None = None,
    now: datetime | None = None,
    anchor_observer: dict[str, str] | None = None,
) -> dict[str, datetime]:
    """Verify both receipts and their chronology for one manifest."""

    if set(receipt_paths) != set(spec.anchors):
        raise ReleaseChainError(
            f"release must have exactly {' and '.join(spec.anchors)} receipt paths"
        )
    if anchor_observer is not None:
        # Shared stateful filename objects across roles must yield one
        # pathname; the memoized rewrite asks each object exactly once.
        # Producer excluded: this function consumes only TSA anchors.
        spec = _normalized_spec(spec, include_producer=False)
    receipt_times = {
        tsa: verify_receipt(
            manifest_digest,
            receipt_path,
            tsa,
            spec=spec,
            anchor_dir=anchor_dir,
            enforce_production_pins=enforce_production_pins,
            now=now,
            anchor_observer=anchor_observer,
        )
        for tsa, receipt_path in receipt_paths.items()
    }
    created_at = parse_created_at(manifest["createdAtUtc"])
    earliest_allowed = created_at - timedelta(seconds=clock_skew_seconds)
    release_index = manifest["releaseIndex"]
    for tsa, gen_time in receipt_times.items():
        if gen_time < earliest_allowed:
            raise ReleaseChainError(
                f"release {release_index} {tsa} genTime "
                f"{gen_time.isoformat()} impossibly precedes createdAtUtc "
                f"{created_at.isoformat()}"
            )
    if previous_times is not None:
        lower_bound = max(previous_times.values()) - timedelta(
            seconds=clock_skew_seconds
        )
        current_earliest = min(receipt_times.values())
        if current_earliest < lower_bound:
            raise ReleaseChainError(
                f"release {release_index} receipt chronology regresses: "
                f"earliest current genTime {current_earliest.isoformat()} "
                f"precedes latest prior genTime "
                f"{max(previous_times.values()).isoformat()} beyond "
                f"{clock_skew_seconds}s skew"
            )
    return receipt_times


def jsonl_line_offsets(payload: bytes, label: str) -> list[int]:
    """Return exact byte offsets after each non-empty LF-terminated row."""

    try:
        payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseChainError(f"{label} is not UTF-8") from exc
    if not payload.endswith(b"\n"):
        raise ReleaseChainError(
            f"{label} must end with exactly one LF after its final JSONL row"
        )
    rows = payload.split(b"\n")
    if rows[-1] != b"":
        raise AssertionError("split invariant")
    rows = rows[:-1]
    offsets = [0]
    position = 0
    for number, row in enumerate(rows, start=1):
        if not row.strip():
            raise ReleaseChainError(f"{label} row {number} is blank")
        if row.endswith(b"\r"):
            raise ReleaseChainError(f"{label} row {number} uses CRLF, not exact LF")
        position += len(row) + 1
        offsets.append(position)
    return offsets


def _symlinked_component_error(
    relative: pathlib.PurePosixPath, walked: tuple[str, ...]
) -> ReleaseChainError:
    """The one refusal both confinement checks give for a linked component.

    The component walk below and the descriptor walk that opens the file
    raise this same text for the same fact, so a component that becomes a
    link between them is refused in the words the walk already used rather
    than in words of its own.
    """

    return ReleaseChainError(
        "state path traverses a symlink at "
        f"{'/'.join(walked)!r}: {relative.as_posix()}"
    )


def _is_reparse_point(path: pathlib.Path) -> bool:
    """Whether one component is a symlink or, on Windows, a junction.

    A junction is not a symlink but redirects exactly like one, so both
    walks below refuse either. A component that cannot be ``lstat``-ed is
    not one of them, and is left to the check that follows the walk.
    """

    try:
        entry = path.lstat()
    except OSError:
        return False
    return stat.S_ISLNK(entry.st_mode) or bool(getattr(entry, "st_reparse_tag", 0))


def assert_no_symlinked_state_component(
    root: pathlib.Path, relative: pathlib.PurePosixPath
) -> None:
    """Walk every component of a state path, refusing a symlink at any of them.

    Checking only the final component lets an intermediate directory symlink
    serve the accepted state from outside the candidate tree entirely: replace
    ``ledger/`` with a link to an ambient directory and the JSONL beneath it is
    still a regular file, still hashes, and still satisfies every manifest —
    while being no part of what the auditor cloned, and no part of what the
    base commit can be diffed against. An in-tree link is the same hole: the
    bytes under audit are then a directory the surface patterns never name.
    The anchor path is walked this way at the top of ``verify_release_chain``;
    this is the same walk for the two state paths. (Mirrors
    ``corpus._assert_no_symlinked_component``.)
    """

    current = root
    walked: tuple[str, ...] = ()
    for segment in relative.parts:
        current = current / segment
        walked = (*walked, segment)
        # A dangling link is still a link, and still refuses.
        if _is_reparse_point(current):
            raise _symlinked_component_error(relative, walked)


STATE_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_BINARY", 0)
)


def _is_symlink_at(name: str, parent: int) -> bool:
    """Whether one directory entry is a symlink, asked of the open parent.

    Only ever used to choose the words for an open that has already failed,
    so a further change underneath it costs a diagnosis, never a decision.
    """

    try:
        return stat.S_ISLNK(os.lstat(name, dir_fd=parent).st_mode)
    except OSError:
        return False


@dataclass(frozen=True)
class ConfinedState:
    """One open state file, and the identity of every directory walked to it.

    ``ancestors`` holds the ``(st_dev, st_ino)`` of each directory descriptor
    the walk opened, root first, taken from the descriptor rather than from
    the name. A caller that records them can ask at the end of its run
    whether the file it read is still reached through the same directories,
    which the leaf's own identity cannot answer: ``ledger/`` can be exchanged
    for another directory holding a hard link to the same inode, and every
    field of the leaf's stat — device, inode, size, modification time, even
    the inode change time, since linking happens before the read — still
    agrees.
    """

    descriptor: int
    ancestors: tuple[tuple[int, int], ...]


def confined_state_descriptor(
    root: pathlib.Path,
    relative: pathlib.PurePosixPath,
    *,
    root_identity: tuple[int, int] | None = None,
) -> ConfinedState:
    """Open a state file component by component, never by whole pathname.

    ``assert_no_symlinked_state_component`` inspects each component and the
    reader then opens the pathname, which resolves every one of them again:
    a parent the walk found to be a real directory can be replaced by a
    symlink in that gap and the open follows it, so the walk's guarantee is
    undone by the read it was taken for. Descriptors close the gap. The root
    is opened once; each intermediate component is opened relative to the
    descriptor of the component the walk actually reached, with
    ``O_NOFOLLOW`` so a component that became a link fails instead of being
    followed and ``O_DIRECTORY`` so one that became a file fails too; the
    leaf is opened relative to the last of those, with ``O_NOFOLLOW`` and
    ``O_NONBLOCK``. No name is resolved twice, and the caller ``fstat``s the
    descriptor rather than the name.

    A component that fails the no-follow open because it is now a link is
    refused in the walk's own words, since it is the walk's own fact. Every
    other failure is raised as it stands, with the errno the pathname open
    would have given: ``ENOTDIR`` for a component that is a file rather than
    a directory, ``ENOENT`` for one that is gone.

    Where ``dir_fd`` is unsupported — Windows, where ``os.open`` is not in
    ``os.supports_dir_fd`` — this refuses rather than falling back to the
    pathname open. The fallback silently returned the reader to exactly the
    behaviour every check above exists to replace: the whole path resolved
    again, with the walk's findings about the parents already stale. A
    verifier that quietly weakens its confinement on some platforms states
    an invariant it does not hold there, so it says instead that it cannot
    read the state files here.

    The root itself is opened with ``O_NOFOLLOW`` and ``O_DIRECTORY`` like
    every component below it — it was opened without either, so a candidate
    root that had become a symlink was followed by the one open the walk
    never checked — and, when the caller has recorded what the root was, the
    root descriptor's identity must still be that. ``append_gate`` records
    it once, when the candidate tree is set up. A root open that fails at all
    is the same answer for such a caller, since the directory it recorded was
    there and openable when it recorded it; with no identity recorded the
    failure is raised as it stands.

    The identity of every directory descriptor opened is returned alongside
    the leaf, because a caller holding only the leaf's identity cannot say
    the file is still the same file *in the same place*: a parent exchanged
    for a directory holding a hard link to the same inode leaves every field
    of the leaf's stat untouched.
    """

    if os.open not in os.supports_dir_fd:
        raise ReleaseChainError(
            "state files cannot be read with secure descent on this platform "
            "(os.open lacks dir_fd support)"
        )
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent = os.open(root, directory_flags)
    except OSError as exc:
        if root_identity is None:
            raise
        # A caller that recorded an identity established this directory when
        # its run began. An open that fails now — a link standing where the
        # directory was, the directory gone, its mode no longer allowing the
        # open — says the root is not the one that was recorded, which is the
        # same answer as an identity that does not match.
        raise ReleaseChainError("candidate root changed during verification") from exc
    walked: tuple[str, ...] = ()
    ancestors: list[tuple[int, int]] = []
    try:
        opened = os.fstat(parent)
        identity = (opened.st_dev, opened.st_ino)
        if root_identity is not None and identity != root_identity:
            raise ReleaseChainError("candidate root changed during verification")
        ancestors.append(identity)
        *components, leaf = relative.parts
        for segment in components:
            walked = (*walked, segment)
            try:
                child = os.open(segment, directory_flags, dir_fd=parent)
            except OSError as exc:
                if _is_symlink_at(segment, parent):
                    raise _symlinked_component_error(relative, walked) from exc
                raise
            os.close(parent)
            parent = child
            # Asked of the descriptor the walk is standing on, so it names the
            # directory this open actually reached, not the one its name
            # resolves to afterwards.
            opened = os.fstat(parent)
            ancestors.append((opened.st_dev, opened.st_ino))
        walked = (*walked, leaf)
        try:
            descriptor = os.open(leaf, STATE_OPEN_FLAGS, dir_fd=parent)
        except OSError as exc:
            if _is_symlink_at(leaf, parent):
                raise _symlinked_component_error(relative, walked) from exc
            raise
        return ConfinedState(descriptor=descriptor, ancestors=tuple(ancestors))
    finally:
        os.close(parent)


def read_state_descriptor(descriptor: int) -> bytes:
    """Read one open state file to the end, through that descriptor alone."""

    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1 << 20)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _regular_file_bytes(root: pathlib.Path, relative: pathlib.PurePosixPath) -> bytes:
    # The final-component check keeps its own refusal and runs first, so every
    # input it already rejected is rejected identically; the component walk
    # below only ever fires for a path this reader used to accept. Both state
    # reads in _verify_state_history come through here, so the walk covers the
    # ledger and the immutable prefix alike. The read itself then goes through
    # the descriptor walk rather than the pathname, so a component swapped
    # between the walk and the open cannot be followed; every input either
    # check already refused still gets that check's message, in its place.
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise ReleaseChainError(
            f"required state file is missing or non-regular: {path}"
        )
    assert_no_symlinked_state_component(root, relative)
    confined = confined_state_descriptor(root, relative)
    try:
        if not stat.S_ISREG(os.fstat(confined.descriptor).st_mode):
            raise ReleaseChainError(
                f"required state file is missing or non-regular: {path}"
            )
        return read_state_descriptor(confined.descriptor)
    finally:
        os.close(confined.descriptor)


def _exact_state_bytes(state_bytes: Mapping[str, bytes] | None) -> dict[str, bytes]:
    """Normalize a caller-supplied state snapshot to exact strs and bytes.

    ChainSpec-style paranoia applied to the new parameter: a str subclass
    could compare equal to a state path while rendering as something else,
    and a bytes-like view could change under the verification that digests
    it. Both are refused rather than coerced. ``None`` — every caller that
    predates the parameter — yields an empty mapping, so every state read
    below is exactly the read it always was.
    """

    if state_bytes is None:
        return {}
    if not isinstance(state_bytes, Mapping):
        raise ReleaseChainError("state_bytes must be a mapping of state path to bytes")
    exact: dict[str, bytes] = {}
    for key, value in state_bytes.items():
        if type(key) is not str or type(value) is not bytes:
            raise ReleaseChainError(
                "state_bytes must map exact str state paths to exact bytes"
            )
        exact[key] = value
    return exact


def _state_file_bytes(
    root: pathlib.Path,
    relative: pathlib.PurePosixPath,
    supplied: Mapping[str, bytes],
) -> bytes:
    """One state file's bytes: the caller's snapshot, or a fresh read.

    ``append_gate`` reads each state file once, records the file's identity,
    and feeds those bytes to every consumer it owns. This verifier was not
    one of them: it re-opened both paths by name, so a candidate could
    satisfy the row checks with one ledger and the release chain with
    another inside a single verdict — and restore the first before the
    closing re-read looked, since that comparison saw the same device,
    inode, size, and mtime it started with. A caller that has already read a
    state path supplies its bytes and this path is not opened again at all.
    With nothing supplied the read is the one it always was, in the same
    place, with the same refusals.
    """

    key = relative.as_posix()
    if key in supplied:
        return supplied[key]
    return _regular_file_bytes(root, relative)


def _verify_state_history(
    records: list[ReleaseRecord],
    root: pathlib.Path,
    *,
    spec: ChainSpec,
    require_head_current: bool,
    state_bytes: Mapping[str, bytes],
) -> None:
    ledger = _state_file_bytes(root, spec.state_relative, state_bytes)
    prefix = _state_file_bytes(root, spec.prefix_relative, state_bytes)
    offsets = jsonl_line_offsets(ledger, spec.state_path)
    total_lines = len(offsets) - 1
    prefix_digest = sha256_bytes(prefix)

    previous_line_count: int | None = None
    for record in records:
        state = record.manifest["state"]
        line_count = int(state["lineCount"])
        if line_count > total_lines:
            raise ReleaseChainError(
                f"release {record.release_index} lineCount {line_count} exceeds "
                f"working-tree line count {total_lines}"
            )
        historical_bytes = ledger[: offsets[line_count]]
        historical_digest = sha256_bytes(historical_bytes)
        if historical_digest != state["jsonlSha256"]:
            raise ReleaseChainError(
                f"release {record.release_index} state.jsonlSha256 does not "
                "match the exact historical JSONL prefix"
            )
        if state["immutablePrefixSha256"] != prefix_digest:
            raise ReleaseChainError(
                f"release {record.release_index} immutablePrefixSha256 does "
                "not match ledger/immutable_prefix.json"
            )

        if previous_line_count is not None:
            append = record.manifest["append"]
            assert isinstance(append, dict)
            if line_count <= previous_line_count:
                raise ReleaseChainError(
                    f"release {record.release_index} lineCount must strictly increase"
                )
            if append["previousLineCount"] != previous_line_count:
                raise ReleaseChainError(
                    f"release {record.release_index} append.previousLineCount "
                    "does not match the previous manifest"
                )
            row_delta = line_count - previous_line_count
            if append["appendedRowCount"] != row_delta:
                raise ReleaseChainError(
                    f"release {record.release_index} appendedRowCount "
                    f"{append['appendedRowCount']} does not match line delta "
                    f"{row_delta}"
                )
            suffix = ledger[offsets[previous_line_count] : offsets[line_count]]
            suffix_digest = sha256_bytes(suffix)
            if append["appendedBytesSha256"] != suffix_digest:
                raise ReleaseChainError(
                    f"release {record.release_index} appendedBytesSha256 does "
                    "not match the exact byte suffix"
                )
        previous_line_count = line_count

    if require_head_current:
        head = records[-1]
        if head.manifest["state"]["lineCount"] != total_lines:
            raise ReleaseChainError(
                f"HEAD release lineCount {head.manifest['state']['lineCount']} "
                f"does not match working-tree line count {total_lines}"
            )
        if head.manifest["state"]["jsonlSha256"] != sha256_bytes(ledger):
            raise ReleaseChainError(
                "HEAD release state.jsonlSha256 does not match working-tree bytes"
            )


def _exact_filename(filename: Any) -> str:
    """Normalize a configured anchor filename to one exact built-in str.

    ChainSpec does not enforce its annotations, so runtime-accepted values
    include PathLike objects and str subclasses. os.fsdecode consumes a
    PathLike through ``__fspath__`` exactly once — a stateful object cannot
    show one pathname to a path join and another to the observer if every
    consumer shares this single normalization — and the forced built-in str
    strips subclasses whose overridden methods could diverge between
    hashing, sorting, and encoding.

    Applied only on observing paths: default-mode joins consume the raw
    configured values exactly as they always have (including parts-based
    PurePath joining), so non-observing behavior never changes. Observing
    mode's stated filename domain is ``str | os.PathLike`` — an exotic
    object that default-mode joins would accept through ``__rtruediv__``
    alone has no pathname to digest under, and refuses here rather than
    escaping as a TypeError.
    """

    if not isinstance(filename, (str, os.PathLike)):
        # Exactly the stated domain: bare bytes, which os.fsdecode would
        # happily decode, are refused along with everything else.
        raise ReleaseChainError(
            "anchor filenames must be str or os.PathLike when the anchor-set "
            f"digest is computed; got {type(filename).__name__}"
        )
    try:
        # Both steps inside the boundary: a hostile __fspath__ can raise
        # anything, and a bytes subclass whose decode() returns a non-string
        # makes the exact-string conversion itself raise. The refusal message
        # is built from type names alone — an exception whose own __str__
        # raises must not be able to leak a second exception from here.
        decoded = os.fsdecode(filename)
        return decoded if type(decoded) is str else str.__str__(decoded)
    except Exception as exc:  # noqa: BLE001 - any failure here is a refusal
        raise ReleaseChainError(
            "anchor filename could not be decoded to a pathname: "
            f"{type(filename).__name__} ({type(exc).__name__})"
        ) from exc


def _normalized_spec(spec: ChainSpec, *, include_producer: bool = True) -> ChainSpec:
    """Rewrite a spec's configured filenames to exact built-in strings.

    Memoized by object identity: a single stateful PathLike shared between
    the producer field and any number of TSA roles is asked for its pathname
    exactly once, so shared-filename collision detection cannot be defeated
    by per-role re-invocation. Idempotent — exact strings pass through
    unchanged. A caller that consumes only TSA anchors (standalone receipt
    verification) passes ``include_producer=False`` so an irrelevant
    producer filename is neither touched nor able to refuse.
    """

    # The memo retains each filename object beside its pathname: an id is
    # only reusable after its object is collected, and a retained object is
    # never collected while the rewrite runs — so a lazy spec mapping that
    # materializes fresh filename objects per access cannot alias an earlier
    # entry through id reuse. The identity comparison is then exact.
    memo: dict[int, tuple[Any, str]] = {}

    def normalize(filename: Any) -> str:
        entry = memo.get(id(filename))
        if entry is not None and entry[0] is filename:
            return entry[1]
        pathname = _exact_filename(filename)
        memo[id(filename)] = (filename, pathname)
        return pathname

    normalized = replace(
        spec,
        anchors={
            tsa: replace(anchor, filename=normalize(anchor.filename))
            for tsa, anchor in spec.anchors.items()
        },
    )
    if include_producer:
        normalized = replace(
            normalized,
            producer_public_key_filename=normalize(
                spec.producer_public_key_filename
            ),
        )
    return normalized


def _observe_anchor_bytes(
    observer: dict[str, str] | None, filename: str, payload: bytes
) -> None:
    """Record the digest of anchor bytes at the moment verification consumes
    them.

    One filename must resolve to one byte sequence for the whole run —
    including two TSA roles that share a filename. A later read that disagrees
    is a mid-run change and refuses, rather than letting the verdict report
    bytes the run did not uniformly use.
    """

    if observer is None:
        return
    filename = _exact_filename(filename)
    digest = sha256_bytes(payload)
    previous = observer.get(filename)
    if previous is not None and previous != digest:
        raise ReleaseChainError(
            f"anchor file {filename!r} bytes changed during verification: "
            f"{digest} after {previous}"
        )
    observer[filename] = digest


def _combined_anchor_digest(per_file: Mapping[str, str]) -> str:
    """One digest naming a whole consumed anchor set.

    SHA-256 over the receipt-canonical JSON object mapping each configured
    anchor filename to the SHA-256 of the bytes verification consumed for it.
    Canonical JSON is an injective encoding of that mapping for any accepted
    filename strings, so — up to SHA-256 collision resistance — two runs
    share this value only if their filename-to-consumed-bytes mappings were
    identical.
    The keys are the spec's configured filename strings: specs that name the
    same file differently (``key.pem`` against ``./key.pem``) produce
    different mappings by design, because the mapping commits to the
    configuration, not to resolved path identity.

    One edge is refused rather than encoded: a filename containing an
    explicit well-formed surrogate pair is a different Python string from
    the astral character it spells, but one and the same string after any
    JSON round trip — a verdict carrying it could never be reproduced from
    ``--json`` output. Such a pair cannot come from ``os.fsdecode`` (its
    escapes are unpaired low surrogates, which round-trip faithfully); only
    a spec literally configuring one is refused, and the fix is to
    configure the astral character directly.
    """

    from receipt.canonical import utf16_sort_key

    for name in per_file:
        if _SURROGATE_PAIR_RE.search(name):
            raise ReleaseChainError(
                "anchor filename spells an astral character as an explicit "
                "surrogate pair, which JSON parsing would rewrite; configure "
                f"the character directly: {name!r}"
            )
    # With well-formed pairs refused, UTF-16 code units are injective over
    # the remaining strings; a tie would mean the refusal above regressed.
    sort_keys = [utf16_sort_key(name) for name in per_file]
    if len(set(sort_keys)) != len(sort_keys):
        raise ReleaseChainError(
            "two configured anchor filenames are distinct in Python but "
            "identical as JSON strings; the verdict cannot report them "
            "faithfully"
        )
    return canonical_sha256(dict(per_file))


def verify_release_chain(
    root: pathlib.Path,
    *,
    spec: ChainSpec,
    anchor_dir: pathlib.Path | None = None,
    require_chain: bool = True,
    verify_state: bool = True,
    allow_pending_append: bool = False,
    enforce_production_pins: bool | None = None,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    now: datetime | None = None,
    compute_anchor_set_digest: bool = False,
    state_bytes: Mapping[str, bytes] | None = None,
) -> ChainVerification:
    """Verify all manifests, signatures, receipts, links, and state bytes.

    With ``compute_anchor_set_digest=True`` the result additionally names the
    anchor set the run consumed: every signature and receipt verification
    digests the anchor bytes at its own read site (OpenSSL calls are then fed
    a private snapshot of those exact bytes), a filename whose bytes differ
    between two consumptions refuses, and the combined digest is documented
    on _combined_anchor_digest. Observing mode consumes each configured
    filename as the single pathname ``os.fsdecode`` yields for it, asked of
    the object exactly once per run — a cross-flavour PurePath whose
    parts-based join would address a different file is consumed by pathname
    here, by parts in default mode. Off by default: existing callers keep
    identical verification behavior — the same reads through the same raw
    configured values, the same acceptances, the same refusals in the same
    order with the same messages. The returned object does carry the two new
    (unset) fields, which is visible to reflection such as
    ``dataclasses.asdict``.

    ``state_bytes`` maps a relative POSIX state path to the bytes a caller
    has already read for it, and those bytes are used in place of reading
    that path. It exists for a caller that reads each state file once and
    holds the verdict to that one read: without it this verifier opened the
    ledger and the frozen prefix again by name, so an A-to-B-to-A
    replacement could show the caller's checks one file and the release
    history another. Omitted (the default, and every pre-existing caller),
    both files are read here exactly as before.
    """

    root = root.resolve()
    default_anchor_dir = root / spec.anchor_relative
    if anchor_dir is None:
        # The spec-pinned anchor path must be physically canonical: a
        # symlinked component would let the tree under audit substitute a
        # sibling directory of internally valid but unpinned trust material
        # (and, before this walk existed, flip pin enforcement off via the
        # resolved-vs-lexical comparison below). Caller-supplied anchor
        # directories are exempt — they are the caller's own trust choice
        # and legitimately live behind symlinks (temp dirs, materialized
        # base trees).
        probe = root
        for part in pathlib.PurePosixPath(spec.anchor_relative).parts:
            probe = probe / part
            if probe.is_symlink():
                raise ReleaseChainError(
                    f"anchor path component is a symlink or reparse point: {probe}"
                )
    selected_anchors = (anchor_dir or default_anchor_dir).resolve()
    if enforce_production_pins is None:
        enforce_production_pins = selected_anchors == default_anchor_dir.resolve()
    if type(clock_skew_seconds) is not int or clock_skew_seconds < 0:
        raise ReleaseChainError("clock_skew_seconds must be a non-negative integer")
    if type(compute_anchor_set_digest) is not bool:
        raise ReleaseChainError("compute_anchor_set_digest must be a boolean")
    supplied_state = _exact_state_bytes(state_bytes)
    anchor_observer: dict[str, str] | None = (
        {} if compute_anchor_set_digest else None
    )

    enumerated = _enumerate_manifest_files(root, spec)
    if not enumerated:
        if require_chain:
            raise ReleaseChainError("release chain is absent; genesis is required")
        return ChainVerification(())

    if anchor_observer is not None:
        # Observing only, and only once a chain exists: every configured
        # filename is normalized exactly once for the whole run — each
        # PathLike gets one __fspath__ call (memoized by object identity, so
        # an object shared across roles is asked once), and every downstream
        # join, observer key, and the completeness check below reuse the
        # same plain strings. Default mode touches none of this: raw values
        # flow to the joins exactly as on every earlier release.
        spec = _normalized_spec(spec)

    records: list[ReleaseRecord] = []
    previous_hash: str | None = None
    previous_times: dict[str, datetime] | None = None
    verification_now = now or datetime.now(timezone.utc)
    for expected_index, (path, receipt_paths, producer_signature_path) in enumerate(
        enumerated
    ):
        manifest, raw, digest = load_manifest(path, spec)
        filename_match = MANIFEST_RE.fullmatch(path.name)
        assert filename_match is not None
        filename_index = int(filename_match.group("index"))
        if filename_index != expected_index:
            raise ReleaseChainError(
                f"release indices are not contiguous from 0: expected "
                f"{expected_index:04d}, found {filename_index:04d}"
            )
        if manifest["releaseIndex"] != expected_index:
            raise ReleaseChainError(
                f"manifest releaseIndex {manifest['releaseIndex']} does not "
                f"match filename index {expected_index}"
            )
        if filename_match.group("digest") != digest[:16]:
            raise ReleaseChainError(
                f"manifest filename hash does not match exact file bytes: {path.name}"
            )
        if manifest["previousManifestSha256"] != previous_hash:
            raise ReleaseChainError(
                f"release {expected_index} previousManifestSha256 does not "
                "match the previous manifest file bytes"
            )
        verify_producer_signature(
            raw,
            producer_signature_path,
            spec=spec,
            anchor_dir=selected_anchors,
            enforce_production_pin=enforce_production_pins,
            anchor_observer=anchor_observer,
        )
        if records:
            previous_line_count = records[-1].manifest["state"]["lineCount"]
            line_count = manifest["state"]["lineCount"]
            append = manifest["append"]
            assert isinstance(append, dict)
            if line_count <= previous_line_count:
                raise ReleaseChainError(
                    f"release {expected_index} lineCount must strictly increase"
                )
            if append["previousLineCount"] != previous_line_count:
                raise ReleaseChainError(
                    f"release {expected_index} append.previousLineCount does "
                    "not match the previous manifest"
                )
            row_delta = line_count - previous_line_count
            if append["appendedRowCount"] != row_delta:
                raise ReleaseChainError(
                    f"release {expected_index} appendedRowCount "
                    f"{append['appendedRowCount']} does not match line delta "
                    f"{row_delta}"
                )

        receipt_times = verify_release_receipts(
            manifest,
            digest,
            receipt_paths,
            spec=spec,
            anchor_dir=selected_anchors,
            enforce_production_pins=enforce_production_pins,
            clock_skew_seconds=clock_skew_seconds,
            previous_times=previous_times,
            now=verification_now,
            anchor_observer=anchor_observer,
        )

        records.append(
            ReleaseRecord(
                path=path,
                raw=raw,
                sha256=digest,
                manifest=manifest,
                receipt_paths=receipt_paths,
                receipt_times=receipt_times,
                producer_signature_path=producer_signature_path,
            )
        )
        previous_hash = digest
        previous_times = receipt_times

    if type(allow_pending_append) is not bool:
        raise ReleaseChainError("allow_pending_append must be a boolean")
    if allow_pending_append and not verify_state:
        raise ReleaseChainError(
            "allow_pending_append requires historical state verification"
        )
    if verify_state:
        _verify_state_history(
            records,
            root,
            spec=spec,
            require_head_current=not allow_pending_append,
            state_bytes=supplied_state,
        )
    anchor_set_sha256: str | None = None
    anchor_file_sha256s: tuple[tuple[str, str], ...] = ()
    if anchor_observer is not None:
        # The spec's filenames were normalized to exact strings at the top of
        # this function; these are byte-for-byte the observer's keys.
        configured = {spec.producer_public_key_filename} | {
            anchor.filename for anchor in spec.anchors.values()
        }
        never_consumed = sorted(configured - set(anchor_observer))
        if never_consumed:
            # Unreachable with a non-empty chain — every release verifies the
            # producer signature and every configured receipt — but a digest
            # that silently omitted a configured anchor would misname the set,
            # so the invariant is enforced rather than assumed.
            raise ReleaseChainError(
                "anchor files configured but never consumed by verification: "
                + ", ".join(never_consumed)
            )
        anchor_file_sha256s = tuple(sorted(anchor_observer.items()))
        anchor_set_sha256 = _combined_anchor_digest(dict(anchor_file_sha256s))
    return ChainVerification(
        tuple(records),
        anchor_set_sha256=anchor_set_sha256,
        anchor_file_sha256s=anchor_file_sha256s,
    )


# The four variables git reads as a global pathspec mode. Each one rewrites
# how every pathspec on every command line is interpreted, including the ones
# this package writes; see _git_environment.
PATHSPEC_ENVIRONMENT = (
    "GIT_LITERAL_PATHSPECS",
    "GIT_GLOB_PATHSPECS",
    "GIT_NOGLOB_PATHSPECS",
    "GIT_ICASE_PATHSPECS",
)


def _git_environment() -> dict[str, str]:
    """The environment every git read in this package runs under.

    ``refs/replace`` rewrites what git returns for an object while every
    command still prints the original OID, so a replacement placed in the
    candidate repository changes the base commit, tree, or blob these checks
    read behind the name the verdict names — a base resolved to one OID and
    read as another. ``GIT_NO_REPLACE_OBJECTS`` turns the mechanism off for
    the read.

    The pathspec semantics these reads rely on are the ones they write, not
    the caller's. ``GIT_LITERAL_PATHSPECS`` makes git take every pathspec
    exactly as typed — the ``:(literal)`` prefix ``_index_entries`` writes
    included, which then becomes part of the path being looked for, matches
    nothing, and exits zero: every tracked state file reported absent from
    the index, and every check that reads "absent" as untracked refusing or
    returning on it. ``GIT_ICASE_PATHSPECS`` is the other direction — an
    index read about one path answers with records for differently cased
    siblings, and ``git ls-tree`` refuses the magic outright, so the base
    tree cannot be enumerated at all — and ``GIT_GLOB_PATHSPECS`` and
    ``GIT_NOGLOB_PATHSPECS`` likewise decide what a name means before the
    command line is read. All four are dropped, so a pathspec written here
    means here what it says. Everything else in the ambient environment is
    carried through, so ``GIT_DIR``, credentials, and the caller's own
    isolation still apply.
    """

    environment = {**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"}
    for name in PATHSPEC_ENVIRONMENT:
        environment.pop(name, None)
    return environment


def _git_run(
    root: pathlib.Path,
    arguments: list[str],
    *,
    text: bool = False,
) -> subprocess.CompletedProcess[Any]:
    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=False,
            capture_output=True,
            text=text,
            env=_git_environment(),
        )
    except FileNotFoundError as exc:
        raise ReleaseChainError("git is required for --base-ref verification") from exc


def resolve_base_commit(root: pathlib.Path, base_ref: str) -> str:
    completed = _git_run(
        root,
        ["rev-parse", "--verify", "--end-of-options", f"{base_ref}^{{commit}}"],
        text=True,
    )
    if completed.returncode != 0:
        raise ReleaseChainError(
            f"cannot resolve base ref {base_ref!r} to a commit: "
            f"{completed.stderr.strip()}"
        )
    commit = completed.stdout.strip()
    ancestor = _git_run(root, ["merge-base", "--is-ancestor", commit, "HEAD"])
    if ancestor.returncode != 0:
        raise ReleaseChainError(f"base commit {commit} is not an ancestor of HEAD")
    return commit


def git_tree_entries(
    root: pathlib.Path, commit: str, pathspec: str
) -> dict[str, GitEntry]:
    completed = _git_run(
        root,
        ["ls-tree", "-r", "-z", "--full-tree", commit, "--", pathspec],
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ReleaseChainError(
            f"cannot enumerate {pathspec} at base {commit}: {diagnostic}"
        )
    entries: dict[str, GitEntry] = {}
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ReleaseChainError(
                f"cannot parse git tree entry under {pathspec}"
            ) from exc
        if path in entries:
            raise ReleaseChainError(f"duplicate git tree entry for {path}")
        entries[path] = GitEntry(mode, object_type, object_id, path)
    return entries


def git_blob_bytes(root: pathlib.Path, entry: GitEntry) -> bytes:
    if entry.object_type != "blob":
        raise ReleaseChainError(
            f"base release entry is not a blob: {entry.path} ({entry.object_type})"
        )
    completed = _git_run(root, ["cat-file", "blob", entry.object_id])
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ReleaseChainError(f"cannot read base blob for {entry.path}: {diagnostic}")
    return completed.stdout


def git_file_entry(root: pathlib.Path, commit: str, path: str) -> GitEntry:
    entries = git_tree_entries(root, commit, path)
    entry = entries.get(path)
    if entry is None:
        raise ReleaseChainError(f"required file {path} is absent at base {commit}")
    return entry


def _working_release_files(
    root: pathlib.Path, spec: ChainSpec
) -> dict[str, pathlib.Path]:
    release_root = root / spec.release_root_relative
    if not release_root.exists():
        return {}
    if release_root.is_symlink() or not release_root.is_dir():
        raise ReleaseChainError("releases must be a real directory, not a symlink")
    files: dict[str, pathlib.Path] = {}
    for path in release_root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ReleaseChainError(f"release path is a symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ReleaseChainError(f"release path is not regular: {relative}")
        files[relative] = path
    return files


def _git_bool(root: pathlib.Path, key: str) -> bool | None:
    """One boolean git setting, or None when unset."""

    result = subprocess.run(
        ["git", "-C", str(root), "config", "--bool", key],
        capture_output=True,
        text=True,
        check=False,
        env=_git_environment(),
    )
    if result.returncode == 1 and not result.stdout.strip():
        return None
    if result.returncode != 0:
        raise ReleaseChainError(
            f"cannot read {key} for {root}: {result.stderr.strip()[-500:]}"
        )
    return result.stdout.strip() == "true"


def assert_file_modes_authoritative(root: pathlib.Path) -> None:
    """Refuse to compare modes and types on a checkout that does not carry them.

    The comparisons read the candidate's executable bit and file type from
    ``stat``. With ``core.fileMode`` false — set by git itself on a
    filesystem that cannot materialise the bit, or by hand — the working
    tree says nothing about the mode git records, so a comparison would
    accept any index-side change while the verdict claimed mode identity.
    With ``core.symlinks`` false, git materialises a symlink entry as a
    plain file holding the link target, so a symlink blob whose target text
    equals a prior regular file's bytes would pass the byte comparison, the
    component walk (which sees no link), and the synthesised mode, and turn
    into a link on the next checkout that honours symlinks (peer review,
    rounds two and three). Both settings default to true when unset.

    These are properties of the checkout, not of any file, so they are
    checked before any file-level comparison, deliberately: a checkout that
    cannot be verified says so before any verdict about its files.
    ``append_gate.verify_append_gate`` calls this once at entry, so the push
    path (no base ref, and therefore no release-history pass and no state
    mode comparison) is covered too; the two callers below keep their own
    calls so each is safe to use on its own.
    """

    if _git_bool(root, "core.fileMode") is False:
        raise ReleaseChainError(
            "file modes cannot be verified: core.fileMode is false in this "
            "checkout, so the working tree does not carry the executable bit "
            "git records"
        )
    if _git_bool(root, "core.symlinks") is False:
        raise ReleaseChainError(
            "file types cannot be verified: core.symlinks is false in this "
            "checkout, so a symlink entry is materialised as a plain file"
        )


def _observed_git_category(path: pathlib.Path) -> str:
    """The git mode a working-tree entry would be recorded as, or why not."""

    try:
        entry = path.lstat()
    except FileNotFoundError:
        return "absent"
    if stat.S_ISLNK(entry.st_mode):
        return "120000"
    if stat.S_ISDIR(entry.st_mode):
        return "040000"
    if not stat.S_ISREG(entry.st_mode):
        return "non-regular"
    # Git keys the executable category on the owner bit alone; see
    # append_gate.check_state_modes for the reasoning.
    return "100755" if entry.st_mode & 0o100 else "100644"


# git's in-memory cache-entry flag for an intent-to-add entry (CE_INTENT_TO_ADD,
# 1 << 29), as ``git ls-files --debug`` prints it. See _index_entries.
CE_INTENT_TO_ADD = 0x2000_0000
# ``git ls-files --debug`` prints exactly these five lines per entry, in this
# order, whatever the entry is; the last carries the flag word.
INDEX_DEBUG_LINES = 5
_INDEX_DEBUG_FLAGS_RE = re.compile(rb"  size: [0-9]+\tflags: ([0-9a-fA-F]+)\n\Z")


def _split_index_debug(chunk: bytes, pathspec: str) -> tuple[bytes, bytes]:
    """Take one ``--debug`` block off the front of a chunk, and return the rest.

    With ``-z`` the record's path is NUL-terminated and its debug block is
    not, so everything between one NUL and the next is one entry's block
    followed by the next entry's ``<mode> <oid> <stage>\t<path>``. The block
    is a fixed five lines, so the split is by newline count rather than by
    content: a path may hold newlines, tabs, or the word ``flags``, and none
    of that can be mistaken for the block because the block comes first.
    """

    position = 0
    for _ in range(INDEX_DEBUG_LINES):
        newline = chunk.find(b"\n", position)
        if newline < 0:
            raise ReleaseChainError(f"cannot parse the index entry for {pathspec}")
        position = newline + 1
    return chunk[:position], chunk[position:]


def _index_entries(
    root: pathlib.Path, pathspec: str
) -> list[tuple[str, str, str, bool]]:
    """Every ``git ls-files -s`` record under one path.

    Each is ``(mode, stage, path, intent_to_add)``. The one place this package
    parses the index, shared by the checks below so they read it the same way
    and report an unreadable or unparseable index in the same words.

    The path is passed as a literal pathspec. Given to git bare it is a
    *pattern*: a filename carrying glob magic globs, and one beginning with
    ``:`` is read as pathspec magic and silently becomes a different path
    (``:odd/x`` asks about ``odd/x``, matches nothing, and exits zero), so a
    tracked file could be reported as absent from the index — which every
    caller below reads as "this path is untracked" and either returns on or
    refuses over. The other direction is as wrong: ``a[b]c`` also returns a
    sibling ``abc``, so a read about one path answers with records for
    others, and the checks that ask about exactly one path are correct only
    because each filters the records afterwards — a filter the release
    root's scan, which reads every record under a directory, does not have.
    ``:(literal)`` says what is meant: this exact path, matched as written,
    and ``_git_environment`` drops the four variables that would reinterpret
    it. The diagnostics keep naming the path itself, not the magic.

    ``--debug`` is read alongside ``-s`` because mode, stage and object id do
    not say whether an entry records any content. ``git add -N`` — and every
    porcelain that runs it, ``git add -p`` on an untracked file included —
    writes an *intent-to-add* entry: stage 0, mode 100644, the empty blob's
    object id, and no content at all. Every check below took that for a
    tracked file, so a ``git rm --cached`` of a protected path followed by
    ``git add -N`` of it passed the tracked-state check, passed the index
    agreement check (the working tree really does hold a regular 100644
    file), passed the still-indexed check, and produced a commit that
    *deletes* the path. The flag is what says so: ``--debug`` prints the
    cache entry's flag word, and ``CE_INTENT_TO_ADD`` is set in it. The
    empty blob is not the test — a file whose content really is empty has the
    same object id and is an ordinary entry.

    One command answers both, so the mode and the flag word describe the same
    read of the same index rather than two reads a write could fall between.
    ``-z`` applies to the path, so a path holding a newline is still exact;
    the debug block that follows it is a fixed five lines and is split off by
    counting them.
    """

    completed = _git_run(
        root, ["ls-files", "-s", "--debug", "-z", "--", f":(literal){pathspec}"]
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ReleaseChainError(
            f"cannot read the index entry for {pathspec}: {diagnostic}"
        )
    entries: list[tuple[str, str, str, bool]] = []
    chunks = completed.stdout.split(b"\0")
    record = chunks[0]
    for chunk in chunks[1:]:
        debug, next_record = _split_index_debug(chunk, pathspec)
        flags = _INDEX_DEBUG_FLAGS_RE.search(debug)
        try:
            if flags is None:
                raise ValueError("no flag word")
            metadata, raw_path = record.split(b"\t", 1)
            mode, _object_id, stage = metadata.decode("ascii").split(" ")
            listed = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ReleaseChainError(
                f"cannot parse the index entry for {pathspec}"
            ) from exc
        intent = bool(int(flags.group(1), 16) & CE_INTENT_TO_ADD)
        entries.append((mode, stage, listed, intent))
        record = next_record
    # Every record is followed by its own block, so what is left after the
    # last one is nothing. Anything else is output this parse does not
    # understand, and an index this cannot read is not one to compare against.
    if record:
        raise ReleaseChainError(f"cannot parse the index entry for {pathspec}")
    return entries


def _exact_relative(relative: pathlib.PurePosixPath | str) -> str:
    return (
        relative.as_posix()
        if isinstance(relative, pathlib.PurePosixPath)
        else str(relative)
    )


def assert_state_path_tracked(
    root: pathlib.Path, relative: pathlib.PurePosixPath | str
) -> None:
    """Require a state path to be tracked, with no gitlink standing over it.

    ``assert_index_agrees_with_tree`` compares a path the index holds against
    the working tree and returns when the index holds nothing for it, because
    a proposal that adds files must be able to add them. The two state files
    are not in that class: they are the files the whole verdict is about, and
    an untracked one is not part of the commit under review at all — its
    bytes are not what a merge would take, and no diff against the base can
    reach it. Worse, nothing looked at the path's ancestors. A directory only
    appears in the index as a gitlink, and a gitlink at ``ledger`` is a
    submodule boundary: the files beneath it belong to another repository,
    are not this commit's content, and yet arrive in the working tree as
    perfectly regular files that hash, parse, and satisfy every byte
    comparison here.

    So: every ancestor of the path must be absent from the index, whatever
    mode it carries, and the leaf must have exactly one stage-0 entry whose
    mode is 100644 or 100755. Ancestors are checked first, because a gitlink
    at ``ledger`` is why the leaf beneath it has no entry of its own.

    This says a comparison cannot be made rather than making one, so
    ``append_gate.verify_append_gate`` calls it at entry, ahead of the checks
    that would otherwise compare bytes git never recorded. That precedence is
    stated in that module's docstring and pinned by a test.
    """

    path = _exact_relative(relative)
    parts = pathlib.PurePosixPath(path).parts
    for depth in range(1, len(parts)):
        ancestor = "/".join(parts[:depth])
        for mode, _stage, listed, _intent in _index_entries(root, ancestor):
            if listed == ancestor:
                raise ReleaseChainError(
                    f"state path {path} has an indexed ancestor {ancestor} ({mode})"
                )
    entries = [
        (mode, stage, intent)
        for mode, stage, listed, intent in _index_entries(root, path)
        if listed == path
    ]
    if not entries:
        raise ReleaseChainError(
            f"state path {path} is absent from the candidate index"
        )
    # The same fact assert_index_agrees_with_tree refuses, in its words: a
    # conflicted merge records stages 1-3 and no single mode for the path.
    if len(entries) > 1 or entries[0][1] != "0":
        raise ReleaseChainError(f"candidate index holds an unmerged entry at {path}")
    if entries[0][0] not in {"100644", "100755"}:
        raise ReleaseChainError(
            f"state path {path} has a non-regular index entry: {entries[0][0]}"
        )
    # Last, because an intent-to-add entry is stage 0 at 100644 and passes
    # every question above: there is nothing else left to say about it. It
    # records no content, and a commit made from this index deletes the path.
    if entries[0][2]:
        raise ReleaseChainError(
            f"index entry for {path} is intent-to-add and records no content"
        )


def assert_index_agrees_with_tree(
    root: pathlib.Path,
    relative: pathlib.PurePosixPath | str,
    *,
    observed: str | None = None,
) -> None:
    """Require a working-tree entry to be the mode and type the index records.

    ``core.fileMode`` and ``core.symlinks`` state what the checkout claims,
    not how it was materialised: either can be set after the checkout, and a
    filesystem that drops mode bits leaves ``core.fileMode`` true while the
    working tree carries nothing. Neither setting is evidence about this
    file. The index is: git wrote it from the same checkout every comparison
    here reads, and it records the mode and type this path is supposed to
    have. A disagreement means the stat these comparisons read describes
    something other than what git would record — a dropped executable bit
    read as a mode change the proposal never made, or an ambient one read as
    the mode the proposal claims — so refuse instead of comparing.

    A path with no index entry is a new, untracked file with nothing to
    compare against, and returns.

    ``observed`` is a git category a caller has already established for this
    path — from a descriptor it holds open, rather than from the pathname —
    and stands in for the ``lstat`` below. Without it the name is resolved
    here, which for the two state files is a second resolution after the
    mode comparison that precedes this call and a third after the read: the
    shared parent can be exchanged between any two of them, so each answer
    is about a possibly different file. ``append_gate`` supplies the
    category its one read of the file recorded. Omitted — every caller that
    predates the parameter, including the per-release-file loop, which holds
    no descriptor — the comparison is exactly the one it always was.

    Unlike the checkout guard, this runs after the comparisons it qualifies:
    an unstaged chmod is both a mode change and an index disagreement, and
    the upstream verifier's mode-change refusal is what the differential
    harness pins for it. A comparison that passed while the working tree
    was not carrying what git recorded is caught here, afterwards; nothing
    pre-existing is pre-empted.
    """

    path = _exact_relative(relative)
    # A pathspec can match more than the path asked about (a directory, or a
    # name carrying glob magic), so only entries for this exact path count.
    entries = [
        (mode, stage)
        for mode, stage, listed, _intent in _index_entries(root, path)
        if listed == path
    ]
    if not entries:
        return
    # Stages 1-3 are a conflicted merge: the index records no single mode for
    # this path, so there is nothing for the working tree to agree with.
    if len(entries) > 1 or entries[0][1] != "0":
        raise ReleaseChainError(f"candidate index holds an unmerged entry at {path}")
    index_mode = entries[0][0]

    if observed is None:
        observed = _observed_git_category(root / pathlib.PurePosixPath(path))
    if index_mode == "120000":
        if observed != "120000":
            raise ReleaseChainError(
                f"candidate index records a symlink at {path} but the working "
                "tree holds a regular file"
            )
        return
    if index_mode not in {"100644", "100755"}:
        raise ReleaseChainError(
            f"candidate index records a non-regular entry at {path}: {index_mode}"
        )
    if observed != index_mode:
        raise ReleaseChainError(
            f"candidate working tree mode for {path} disagrees with its index "
            f"entry ({index_mode} vs {observed})"
        )


def assert_release_file_still_indexed(
    root: pathlib.Path, relative: pathlib.PurePosixPath | str
) -> None:
    """Require a base release file to still be an entry in the candidate index.

    ``assert_index_agrees_with_tree`` returns when the index holds nothing
    for a path, because a proposal that adds files must be able to add them.
    A file the base already carries is not in that class. Every comparison
    the release-history pass makes about it — its mode, its bytes — is a
    comparison against the working tree, and ``git rm --cached`` touches
    neither: the file stays on disk, byte-identical and at the mode the base
    recorded, while the entry that makes it part of this commit is gone. So
    the mode matched, the bytes matched, the agreement check found no entry
    to disagree with, the whole pass passed — and the commit under review
    deletes a release file this package calls immutable.

    The index must therefore hold exactly one stage-0 entry for the path, at
    100644 or 100755. Like the agreement check beside it this runs after the
    comparisons for that path, so nothing pre-existing is pre-empted; the two
    failures the two checks share are refused there first and in its words,
    including the more specific message a 120000 entry gets, so what is left
    to say here is that the entry is gone.
    """

    path = _exact_relative(relative)
    entries = [
        (mode, stage, intent)
        for mode, stage, listed, intent in _index_entries(root, path)
        if listed == path
    ]
    if not entries:
        raise ReleaseChainError(
            f"existing release file was removed from the candidate index: {path}"
        )
    if len(entries) > 1 or entries[0][1] != "0":
        raise ReleaseChainError(f"candidate index holds an unmerged entry at {path}")
    if entries[0][0] not in {"100644", "100755"}:
        raise ReleaseChainError(
            f"candidate index records a non-regular entry at {path}: {entries[0][0]}"
        )
    # After those, for the reason the tracked-state check has it last: an
    # intent-to-add entry answers every one of them like an ordinary tracked
    # file, and records nothing. ``git rm --cached`` followed by ``git add
    # -N`` leaves an entry where the check above looks for one, and a commit
    # made from this index still deletes the release file.
    if entries[0][2]:
        raise ReleaseChainError(
            f"index entry for {path} is intent-to-add and records no content"
        )


def _assert_no_symlinked_release_component(root: pathlib.Path, listed: str) -> None:
    """Refuse an indexed release path reached through a linked directory.

    The reconciliation below asks whether an indexed path is a regular file
    on disk, and ``is_file()`` answers about whatever the whole name resolves
    to — every intermediate component followed. The traversal that would have
    seen those components does not follow them: ``rglob`` yields a symlinked
    directory and does not descend it, and the scan skips it. So an index
    entry under ``releases/vendor``, with ``vendor`` a link to a directory
    outside the checkout, was in no walk, was reported as present and
    regular, and its content — no part of the candidate tree, no part of what
    the base can be diffed against — stood in for the release file the commit
    records. Walk the parents with ``lstat`` first, in the words the state
    paths' walk uses for the same fact.
    """

    current = root
    walked: tuple[str, ...] = ()
    for segment in pathlib.PurePosixPath(listed).parts[:-1]:
        current = current / segment
        walked = (*walked, segment)
        if _is_reparse_point(current):
            raise ReleaseChainError(
                "release path traverses a symlink at "
                f"{'/'.join(walked)!r}: {listed}"
            )


def assert_release_root_index_regular(root: pathlib.Path, spec: ChainSpec) -> None:
    """Refuse an index entry under the release root that is not a regular file.

    ``_working_release_files`` derives the release files from a filesystem
    walk and skips directories, so a gitlink under ``releases/`` that is
    empty or uninitialised — the ordinary state of a submodule in a fresh
    checkout — appears in neither the enumerated files nor the new-file set
    that the release-proposal rules are applied to. Nothing named it, nothing
    classified it, and no refusal spoke for it: the release root was asserted
    to hold exactly the files the walk found while the index recorded a
    boundary into another repository inside it. The base-tree scan refuses a
    non-regular mode only once the entry is in the base; this refuses it in
    the candidate.

    So the index is read directly. Any entry under the release root whose
    mode is not 100644 or 100755 refuses, as does an unmerged one, and as
    does one that records only an intent to add; and so does a directory the
    walk does find that the index holds an entry for — a gitlink already
    populated, or a blob entry standing where a directory is, which the mode
    scan alone would call supported.

    A mode scan is only half of it, though, because it says nothing about
    what is on disk. Two shapes got through. The scan returned early when
    the release root was not a directory, so a commit that replaces
    ``releases/`` with a tracked regular file passed with the chain gone:
    the manifest directory does not exist, chain initialisation is false,
    and on the push path the verdict is an acceptance that names no release
    at all. And a stage-0 regular entry the working tree does not carry —
    deleted from disk, or never checked out, as a sparse checkout leaves it
    — is in no filesystem walk either, so ``_working_release_files`` reported
    a release root holding fewer files than the commit under review does.
    So the index and the filesystem are reconciled in both directions: with
    any entry under the root, the root must be a directory on disk, and
    every entry must be there as a regular file.

    The second direction is settled by the walk's own spelling, not by the
    filesystem's resolution of the entry's name. Asking ``is_file()`` about
    each indexed path lets a case-insensitive or normalisation-insensitive
    filesystem — APFS, HFS+, NTFS — answer for a differently spelled entry:
    with ``releases/README.md`` and ``releases/readme.md`` both in the index
    and one file on disk, one file answered both questions, so one committed
    release object was in no enumeration and was never verified while the
    reconciliation called the two sides agreed. The traversal that has to
    find them all is the authority on what is there: it yields each regular
    file spelled as the directory spells it, and an index entry has to appear
    in that set exactly. An entry the walk does not spell is absent *under
    that spelling*, which is what the refusal says, and it says it on every
    filesystem — where two names collide only one of them can be the file,
    and where they do not the other one is simply not on disk.

    Both callers run this after every comparison that existed before it, for
    the reason the per-file index check does: an entry that is also a mode or
    byte change against the base gets the refusal the upstream verifier
    gives, and a comparison that passed fail-open is caught afterwards. The
    two reconciliation refusals sit inside that same placement, and after the
    two scans above, so a tree that is wrong in more than one way keeps the
    most specific answer: an unsupported mode is named as a mode, a directory
    the index records a blob for is named as a directory, and only what is
    left is reported as absent.
    """

    release_root = spec.release_root_relative.as_posix()
    modes: dict[str, str] = {}
    for mode, stage, listed, intent in sorted(
        _index_entries(root, release_root), key=lambda record: (record[2], record[1])
    ):
        if stage != "0":
            raise ReleaseChainError(
                f"candidate index holds an unmerged entry at {listed}"
            )
        if mode not in {"100644", "100755"}:
            raise ReleaseChainError(
                f"release root carries an unsupported index entry: {listed} ({mode})"
            )
        # Beside the mode check, because an intent-to-add entry passes it: a
        # release path added with ``git add -N`` is recorded at 100644 with
        # no content, so the reconciliation below would find it on disk and
        # call the pair agreed while the commit carries nothing for it.
        if intent:
            raise ReleaseChainError(
                f"index entry for {listed} is intent-to-add and records no content"
            )
        modes[listed] = mode
    directory = root / spec.release_root_relative
    if directory.is_symlink() or not directory.is_dir():
        # Not a directory, but the index records content under it: a tracked
        # regular file standing where releases/ was, or a root deleted from
        # the working tree without being removed from the index. Returning
        # here made the whole release surface vanish from the verdict.
        if modes:
            raise ReleaseChainError(
                "release root is not a directory while the index records "
                f"{len(modes)} {'entry' if len(modes) == 1 else 'entries'} under it"
            )
        return
    # rglob does not descend through symlinked directories, and a symlink the
    # walk does reach is the enumeration's own refusal, not this one's. The
    # regular files it reaches are collected here, spelled as the directory
    # spells them, because that spelling is what the reconciliation below
    # compares against.
    walked: set[str] = set()
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            continue
        listed = path.relative_to(root).as_posix()
        if path.is_dir():
            if listed in modes:
                raise ReleaseChainError(
                    f"release path is a directory with an index entry: "
                    f"{listed} ({modes[listed]})"
                )
            continue
        if path.is_file():
            walked.add(listed)
    # The other direction, last: an entry the walk cannot find because the
    # working tree does not hold it as a regular file under that spelling.
    # A symlink counts as not holding it — the enumeration refuses one it
    # reaches, and this is the same fact for an entry it never reaches at
    # all. Its parents are walked first, because a name resolves through
    # every component while the traversal above resolves none of it:
    # ``rglob`` does not descend a symlinked directory, so a release path
    # served through one was in no walk and yet answered "regular file"
    # here, from wherever the link points. The leaf keeps its own refusal,
    # below.
    for listed in sorted(modes):
        _assert_no_symlinked_release_component(root, listed)
        if listed not in walked:
            raise ReleaseChainError(
                "release file recorded in the index is absent or not a "
                f"regular file: {listed}"
            )


def verify_release_history_immutable(
    root: pathlib.Path, base_ref: str, spec: ChainSpec
) -> tuple[str, set[str], dict[str, GitEntry]]:
    """Compare every base ``releases/`` file byte and mode to the candidate."""

    root = root.resolve()
    # The base ref is resolved first so a checkout the guard would refuse
    # cannot mask a base that names nothing; the guard then runs ahead of
    # every file-level comparison below, which is the one place a refusal
    # added after the extraction precedes a pre-existing one.
    commit = resolve_base_commit(root, base_ref)
    assert_file_modes_authoritative(root)
    base_entries = git_tree_entries(root, commit, str(spec.release_root_relative))
    current_files = _working_release_files(root, spec)
    for relative, entry in base_entries.items():
        if entry.mode not in {"100644", "100755"}:
            raise ReleaseChainError(
                f"base release entry has non-regular git mode {entry.mode}: {relative}"
            )
        current = current_files.get(relative)
        if current is None:
            raise ReleaseChainError(
                f"existing release file was deleted relative to {commit}: {relative}"
            )
        # Git keys the executable category on the owner bit alone; see
        # append_gate.check_state_modes for the reasoning.
        candidate_mode = "100755" if current.stat().st_mode & 0o100 else "100644"
        if candidate_mode != entry.mode:
            raise ReleaseChainError(
                f"existing release file mode changed relative to {commit}: "
                f"{relative} ({entry.mode} -> {candidate_mode})"
            )
        if current.read_bytes() != git_blob_bytes(root, entry):
            raise ReleaseChainError(
                f"existing release file bytes changed relative to {commit}: {relative}"
            )
        # After the two comparisons it qualifies, deliberately. The mode read
        # above is only evidence if the working tree carries what git
        # recorded, which the config settings alone do not establish; but a
        # file whose mode or bytes already differ from the base gets the
        # refusal the upstream verifier gives, which the differential harness
        # pins (an unstaged chmod is both a mode change and an index
        # disagreement). A comparison that passed fail-open is caught here.
        assert_index_agrees_with_tree(root, relative)
        # And the entry has to still be there. Both comparisons above read the
        # working tree, which `git rm --cached` leaves exactly as it found it,
        # so a proposal that drops an existing release file from the index
        # alone passed every one of them while deleting release history.
        assert_release_file_still_indexed(root, relative)
    # After every per-file comparison, and for the same reason: the release
    # root's own index entries, which the working-tree enumeration above
    # cannot see when they are directories it skips or gitlinks nothing
    # checked out.
    assert_release_root_index_regular(root, spec)
    return commit, set(current_files) - set(base_entries), base_entries


def materialize_base_tree(
    root: pathlib.Path,
    commit: str,
    destination: pathlib.Path,
    release_entries: dict[str, GitEntry],
    spec: ChainSpec,
) -> None:
    entries = dict(release_entries)
    for relative in (
        spec.state_relative.as_posix(),
        spec.prefix_relative.as_posix(),
    ):
        entries[relative] = git_file_entry(root, commit, relative)
    for relative, entry in entries.items():
        if entry.mode not in {"100644", "100755"}:
            raise ReleaseChainError(
                f"base tree entry has non-regular mode {entry.mode}: {relative}"
            )
        output = destination / pathlib.PurePosixPath(relative)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(git_blob_bytes(root, entry))


def verify_base_release_chain(
    root: pathlib.Path,
    commit: str,
    release_entries: dict[str, GitEntry],
    *,
    spec: ChainSpec,
    anchor_dir: pathlib.Path | None = None,
    enforce_production_pins: bool = True,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> ChainVerification:
    with tempfile.TemporaryDirectory(prefix="thesis-release-base-") as name:
        base_root = pathlib.Path(name)
        materialize_base_tree(root, commit, base_root, release_entries, spec)
        base_anchor_dir = anchor_dir or (base_root / spec.anchor_relative)
        return verify_release_chain(
            base_root,
            spec=spec,
            anchor_dir=base_anchor_dir,
            require_chain=True,
            verify_state=True,
            enforce_production_pins=enforce_production_pins,
            clock_skew_seconds=clock_skew_seconds,
        )


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
