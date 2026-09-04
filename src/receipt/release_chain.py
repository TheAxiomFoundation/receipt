"""Offline verification for an append-only witnessed release chain.

The verifier treats manifest, signature, and receipt bytes as an append-only
journal. It does not trust producer provenance or timestamps: manifests are
canonical and content-addressed, state and append digests are recomputed,
every manifest is signed by the pinned producer key, and each RFC 3161 receipt
is verified against the configured anchor set.

``verify_release_chain(root)`` is deliberately a public directory verifier. It
speaks for the directory as it was read once by this process and does not claim
to lock out a concurrent writer. Callers that need a verdict about a commit use
``run_verification`` or the append gate, which select immutable git objects and
hand this function a private materialization. Release-history comparison is
likewise over two entered :class:`receipt.snapshot.TreeSnapshot` instances.
This directory verifier performs no Git reads, so redirecting Git environment
variables cannot change its verdict; ``run_verification`` and
``verify_append_gate`` retain that refusal before their snapshot reads. Its
three subprocess call sites invoke OpenSSL only.

The cryptographic and serialization behavior remains gated against the
PolicyEngine/ledger source recorded in
``receipts/ledger-pin-source-hashes.txt`` and the differential harness in
``tests/test_ledger_equivalence.py``.
"""
from __future__ import annotations

import errno
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
from typing import Any, Literal

from receipt import sign as _sign
from receipt import tsa as _tsa
from receipt._names import NamePolicyError, validate_repertoire
from receipt.canonical import canonical_bytes, canonical_sha256
from receipt.snapshot import GitEntry, TreeSnapshot

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
#: A dotted-decimal object identifier as OpenSSL prints one. Arcs carry no
#: leading zeros, because a spec pinning "1.02" would be comparing against a
#: spelling no RFC 3161 receipt ever reports. The pin is compared against the
#: ``Policy OID:`` line OpenSSL prints, and OpenSSL renders an OID in its own
#: table by name rather than in dotted decimal; no timestamping policy arc is
#: in that table, so dotted decimal is the whole domain in practice, but that
#: coupling is what this pattern assumes.
OID_RE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))+\Z")


def _spec_relative_path(value: Any, label: str) -> pathlib.PurePosixPath:
    """Require a spec path that can only ever address the tree under audit.

    Every one of these is joined onto the auditor's root. A string joins by
    a different rule than a path does, a ``PureWindowsPath`` joins by parts
    that address a different file than its spelling suggests, and an
    absolute path or one carrying ``..`` leaves the tree altogether — so a
    spec could name manifests, anchors, or the witnessed journal somewhere
    the audit never looked. None of that is detectable later: the join
    simply succeeds against the wrong file.
    """

    if not isinstance(value, pathlib.PurePosixPath):
        raise ReleaseChainError(
            f"{label} must be a pathlib.PurePosixPath, not "
            f"{type(value).__name__}"
        )
    if not value.parts or value.is_absolute() or ".." in value.parts:
        raise ReleaseChainError(
            f"{label} must be a relative path naming at least one component, "
            f"with no '..': {value.as_posix()!r}"
        )
    return value


@dataclass(frozen=True)
class AnchorSpec:
    filename: str
    pem_sha256: str
    policy_oid: str
    signer_certificate_sha256: str
    signer_spki_sha256: str

    def __post_init__(self) -> None:
        """Refuse an anchor whose pins cannot pin anything.

        Each field here is compared against a value recomputed from real
        bytes during verification. A pin that is None, empty, or the wrong
        shape never matches — but nothing downstream says so, because the
        comparison runs normally and simply names the computed digest. The
        consumer reads a refusal about the authority's certificate when the
        actual fault is a line of their own spec, or (with the comparison
        never reached, as an unset producer pin once did) reads a PASS. The
        configuration is checked where it is written instead.
        """

        _sha256(self.pem_sha256, "AnchorSpec pem_sha256")
        _sha256(
            self.signer_certificate_sha256,
            "AnchorSpec signer_certificate_sha256",
        )
        _sha256(self.signer_spki_sha256, "AnchorSpec signer_spki_sha256")
        if (
            type(self.policy_oid) is not str
            or OID_RE.fullmatch(self.policy_oid) is None
        ):
            raise ReleaseChainError(
                "AnchorSpec policy_oid must be a dotted-decimal OID: "
                f"{self.policy_oid!r}"
            )


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
    name_repertoire: Literal["portable", "posix-bytes"] = "portable"

    def __post_init__(self) -> None:
        """Refuse a spec that cannot pin what it claims to pin.

        The threat is a pin that is absent rather than wrong. An unset
        ``producer_spki_sha256`` was passed straight through to the signing
        module, which reads ``None`` as "no pin requested" and skips the
        comparison entirely — so a chain re-signed under a substituted key
        verified, and the command failed only downstream, where the verdict
        text tried to slice a prefix off ``None``. An empty ``anchors``
        mapping is the same shape of hole: the receipt-set equality check
        passes vacuously, no witness is ever verified, and the verdict
        reports "the 0 pinned RFC 3161 authorities". A spec that pins
        nothing is a configuration error, not a policy, and it refuses here
        rather than producing a verdict that reads like custody.
        """

        for name in (
            "manifest_relative",
            "state_relative",
            "prefix_relative",
            "anchor_relative",
            "release_root_relative",
        ):
            _spec_relative_path(getattr(self, name), f"ChainSpec {name}")
        try:
            validate_repertoire(self.name_repertoire)
        except NamePolicyError as exc:
            raise ReleaseChainError(str(exc)) from exc
        _sha256(self.producer_spki_sha256, "ChainSpec producer_spki_sha256")
        if not isinstance(self.anchors, Mapping) or not self.anchors:
            raise ReleaseChainError(
                "ChainSpec anchors must be a non-empty mapping of TSA name to "
                "AnchorSpec; a chain with no configured witness cannot be "
                "witnessed"
            )
        for tsa, anchor in self.anchors.items():
            if type(tsa) is not str or not tsa:
                raise ReleaseChainError(
                    f"ChainSpec anchor names must be non-empty strings: {tsa!r}"
                )
            if not isinstance(anchor, AnchorSpec):
                raise ReleaseChainError(
                    f"ChainSpec anchor {tsa!r} must be an AnchorSpec, not "
                    f"{type(anchor).__name__}"
                )

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
    raw = _regular_file_bytes(
        path.parent,
        pathlib.PurePosixPath(path.name),
        nonregular=f"manifest is not a regular file: {path}",
    )
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


def assert_manifest_directory_regular(root: pathlib.Path, spec: ChainSpec) -> None:
    """Decide what the manifest path *is*, for a caller about to ask if it has one.

    ``verify_release_chain`` calls this guard itself before enumeration, after
    the configured path walk has bound the manifest leaf's spelling but
    deliberately left its type to this check. The append gate's push path also
    calls it before asking whether a chain is initialized. Without that guard,
    ``manifest_directory.is_dir() and any(iterdir())`` gets ``False`` for every
    way the path can be something other than a directory: a 100644 blob
    standing where the manifest directory was, an empty symlink there, or a
    dangling one. Each would become "this tree has no chain", and the
    enumeration that says otherwise would never run. The configured path walk
    reaches this leaf to bind its spelling but deliberately leaves its type to
    this check.

    So the type is decided first, in the enumeration's own words and for the
    same three shapes — an ``lstat``, so a symlink is not a directory here
    however it resolves, which is the enumeration's ``is_symlink() or not
    is_dir()`` in one question. A path that is not there at all is not this
    check's business: an absent chain is legal, and "no chain" is the true
    answer for it.

    Absence is the only thing that returns, and it is asked component by
    component so that it can be told apart from the two facts that used to be
    folded into it. One ``lstat`` of the whole path answers ``ENOTDIR`` when an
    *ancestor* is a regular file — a release root that is a blob,
    or any component of a multi-component manifest path — and ``EACCES`` when
    an ancestor is unsearchable, and catching ``OSError`` turned both into "no
    manifest directory here". On the push path that is an acceptance with no
    chain: ``initialized`` is false, nothing is enumerated, and
    ``verify_release_chain`` is never called, while the commit under review may
    carry the whole chain.

    So the components are walked. ``FileNotFoundError`` at any of them is
    absence — nothing stands there, so nothing stands at the leaf either, and
    an absent chain is legal — and every other outcome is named for what it
    is: a component above the leaf that is not a directory refuses ``release
    manifest path ancestor is not a directory``, and a component this verifier
    cannot ``lstat`` at all refuses ``cannot stat release manifest path``,
    carrying the ``strerror`` so a permission answer is not reported as a type
    answer. The ``ENOTDIR`` branch below is reachable only as a race — the
    walk asks each ancestor's type directly, so a file standing at one is
    refused by type before its child is ``lstat``-ed — and it is kept because
    an ancestor that becomes a file between two of those calls is the same
    fact arriving late.

    The leaf keeps exactly the refusal it had, in the same words, for the same
    three shapes: an ``lstat``, so a symlink is not a directory here however it
    resolves, which is the enumeration's ``is_symlink() or not is_dir()`` in
    one question.
    """

    relative = spec.manifest_relative
    parts = relative.parts
    current = root
    walked: tuple[str, ...] = ()
    for depth, segment in enumerate(parts, start=1):
        current = current / segment
        walked = (*walked, segment)
        try:
            entry = os.lstat(current)
        except FileNotFoundError:
            return
        except NotADirectoryError as exc:
            raise ReleaseChainError(
                "release manifest path ancestor is not a directory: "
                f"{'/'.join(walked)}"
            ) from exc
        except OSError as exc:
            raise ReleaseChainError(
                "cannot stat release manifest path: "
                f"{'/'.join(walked)} ({exc.strerror})"
            ) from exc
        if stat.S_ISDIR(entry.st_mode):
            continue
        if depth == len(parts):
            raise ReleaseChainError(
                f"release manifest path is not a regular directory: {current}"
            )
        raise ReleaseChainError(
            "release manifest path ancestor is not a directory: "
            f"{'/'.join(walked)}"
        )


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
        digits = fraction[1:]
        if len(digits) > 6 and digits[6:].strip("0"):
            # Keeping six digits and dropping the rest moves the parsed time
            # EARLIER than the instant the authority actually signed, and that
            # time is not merely reported: it is compared against createdAtUtc
            # and against the previous release's witnesses, and it becomes the
            # -attime the signer certificate is validated at. A verdict must
            # not quote, or reason from, a time no receipt carries — so a
            # precision this verifier cannot represent refuses instead of
            # being silently rounded down. Digits beyond the sixth that are
            # all zero carry no precision and are accepted.
            raise ReleaseChainError(
                f"RFC 3161 genTime for {receipt} is finer than a microsecond, "
                f"which this verifier cannot represent exactly: "
                f"{time_lines[0]!r}"
            )
        parsed = parsed.replace(microsecond=int((digits + "000000")[:6]))
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


_ANCHOR_SNAPSHOT_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_BINARY", 0)
)


def _write_anchor_snapshot(
    directory: pathlib.Path, payload: bytes, *, tsa: str
) -> pathlib.Path:
    """Write one private byte-for-byte ``-CAfile`` copy for OpenSSL."""

    snapshot = directory / f"anchor-{tsa}.pem"
    descriptor = os.open(snapshot, _ANCHOR_SNAPSHOT_WRITE_FLAGS, 0o600)
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OSError("anchor snapshot write made no progress")
            written += count
    finally:
        os.close(descriptor)
    return snapshot


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
        public_key_relative = pathlib.PurePosixPath(
            public_key_path.relative_to(anchor_dir).as_posix()
        )
        public_key_root = anchor_dir
    except ValueError:
        # An absolute configured filename historically overrides anchor_dir.
        # Keep that direct-caller behavior while still giving its leaf the
        # non-following regular-file read.
        public_key_relative = pathlib.PurePosixPath(public_key_path.name)
        public_key_root = public_key_path.parent
    try:
        # Preserve the upstream branch order: bad payload/signature inputs
        # refuse before a missing producer-key path is inspected.
        _sign._validate_signature_inputs(manifest, signature, label)
        public_key_pem = _regular_file_bytes(
            public_key_root,
            public_key_relative,
            nonregular=(
                f"missing or non-regular producer public key: {public_key_path}"
            ),
        )
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
    signature = _regular_file_bytes(
        signature_path.parent,
        pathlib.PurePosixPath(signature_path.name),
        nonregular=(
            f"missing or non-regular producer signature: {signature_path}"
        ),
    )
    verify_producer_signature_bytes(
        manifest,
        signature,
        spec=spec,
        anchor_dir=anchor_dir,
        enforce_production_pin=enforce_production_pin,
        label=signature_path.name,
        anchor_observer=anchor_observer,
    )


def _receipt_bytes(receipt: pathlib.Path) -> bytes:
    """Read one RFC 3161 receipt through a single descriptor.

    Three OpenSSL invocations consume each receipt — the ``-text`` inspection
    that yields its genTime and policy OID, the ``-verify`` that binds it to
    the manifest digest, and the token extraction the signer pins run over —
    and each one reopened the path by name. Nothing held the path still
    between them, so the tree under audit could present a different file to
    each call: a token inspected for its genTime and policy, and a different
    token verified and pinned, with the verdict reporting a time no verified
    token ever carried. The bytes are read once here and every call below is
    fed a private snapshot of them.

    The lstat below refuses a symlink present at check time; ``O_NOFOLLOW``,
    where the platform offers it, refuses one swapped in between that check
    and the open; and the descriptor is stat'ed after opening, so a regular
    file swapped in the same window addresses a different (device, inode)
    pair, which says so where the pathname cannot.
    """

    return _regular_file_bytes(
        receipt.parent,
        pathlib.PurePosixPath(receipt.name),
        nonregular=f"missing or non-regular RFC 3161 receipt: {receipt}",
        unreadable=lambda exc: (
            f"cannot read RFC 3161 receipt {receipt}: {type(exc).__name__}"
        ),
        replaced=f"RFC 3161 receipt was replaced while it was being read: {receipt}",
    )


def _verify_production_signer(
    receipt: pathlib.Path,
    anchor: pathlib.Path,
    anchor_spec: AnchorSpec,
    gen_time: datetime,
    temporary: pathlib.Path,
    environment: dict[str, str],
    *,
    # The snapshot the caller already read; the receipt path itself is kept
    # for the labels and refusals, which name the file an auditor has.
    source: pathlib.Path | None = None,
) -> None:
    token = temporary / "token.der"
    signer = temporary / "signer.pem"
    content = temporary / "tst-info.der"
    read_from = receipt if source is None else source
    _openssl_binary(
        [
            "ts",
            "-reply",
            "-config",
            "/dev/null",
            "-in",
            str(read_from),
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
    """Cryptographically verify one receipt and return its signed genTime.

    The receipt bytes are read exactly once, through one descriptor, and every
    OpenSSL invocation is fed a private snapshot of them, so the token whose
    genTime and policy are reported is the same token that verified against
    the anchor and satisfied the signer pins (see _receipt_bytes).
    """

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
    # OpenSSL accepts only a pathname for -CAfile. Read the selected anchor
    # once and hand every OpenSSL child a private copy of these exact bytes,
    # including when production pins and digest observation are both off.
    try:
        anchor_relative = pathlib.PurePosixPath(
            anchor.relative_to(anchor_dir).as_posix()
        )
        anchor_root = anchor_dir
    except ValueError:
        anchor_relative = pathlib.PurePosixPath(anchor.name)
        anchor_root = anchor.parent
    anchor_bytes = _regular_file_bytes(
        anchor_root,
        anchor_relative,
        nonregular=f"missing or non-regular TSA anchor: {anchor}",
    )
    if enforce_production_pins:
        anchor_digest = sha256_bytes(anchor_bytes)
        if anchor_digest != anchor_spec.pem_sha256:
            raise ReleaseChainError(
                f"production TSA anchor bytes are not code-pinned for {tsa}: "
                f"{anchor_digest}"
            )
    if anchor_observer is not None:
        _observe_anchor_bytes(anchor_observer, anchor_filename, anchor_bytes)

    with tempfile.TemporaryDirectory(prefix="thesis-release-tsa-") as name:
        temporary = pathlib.Path(name)
        empty_ca_dir = temporary / "empty-ca"
        empty_ca_dir.mkdir()
        environment = _openssl_environment(empty_ca_dir)
        # The private copy closes the pathname re-open window regardless of
        # whether this caller asks to report or code-pin the anchor bytes.
        anchor = _write_anchor_snapshot(temporary, anchor_bytes, tsa=tsa)
        # The receipt gets the same treatment, unconditionally: read once
        # through one descriptor, snapshotted here, and handed to all three
        # OpenSSL invocations below. Reopening the path per call let the
        # inspected token and the verified token be different files — see
        # _receipt_bytes. The original path is still what every label and
        # refusal names.
        receipt_source = temporary / f"receipt-{tsa}.tsr"
        receipt_source.write_bytes(_receipt_bytes(receipt))
        try:
            text_result = subprocess.run(
                [
                    "openssl",
                    "ts",
                    "-reply",
                    "-config",
                    "/dev/null",
                    "-in",
                    str(receipt_source),
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
                str(receipt_source),
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
                source=receipt_source,
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
    if anchor_observer is not None and not _anchor_filenames_are_exact(
        spec, include_producer=False
    ):
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


def _assert_component_spelled(
    parent: pathlib.Path,
    segment: str,
    walked: tuple[str, ...],
    relative: pathlib.PurePosixPath,
) -> None:
    """Require a directory to spell the component this walk is descending to.

    Both walks below check what each component *is*, which they learn by
    resolving the name — and resolution is where a case- or
    normalisation-insensitive filesystem answers about a directory this
    package never named. ``releases`` resolves to a ``Releases`` on disk, every
    check that follows reads that directory, and the verdict is about a
    release tree whose name is not the exact one the spec pins. The directory's
    own listing is the question that does not go
    through resolution: a directory holds the spelling it holds, and a
    component that resolves but is not in the listing is a component this
    verifier reached by a name the filesystem folded onto another.

    A component that is not there at all is not this check's business — an
    absent release root is legal, and an absent state file is the reader's
    refusal — so it returns and lets the check after the walk say so. That
    covers the parent as well as the component: a listing that fails because
    the parent is absent or is a file has no directory to withhold, and it is
    the checks after the walk that answer for what stands there.

    A directory this verifier cannot list cannot answer the question, which is
    a different thing from answering it favourably, so it refuses. That is a
    requirement about every directory above a protected path — the two state
    paths, the release root, and the configured paths under it — and it is
    stated as one in ``README.md`` and in both module docstrings: this
    verifier must be able to list them.

    It was once separated from the listable case by asking whether the parent
    folded this name, on the reasoning that where names are compared exactly
    resolution and listing agree, so nothing is lost by descending. Two things
    are wrong with that. The probe could only ask about the spellings a
    filesystem can be *shown* to conflate — a whole-string swapcase, the other
    of NFC and NFD — and a filesystem that folds part of a mixed-case name, or
    by any rule those two do not spell, answers no to all of them while
    folding the name all the same; the test that reproduced the case
    reproduced the probe's own assumption along with it. And the cost of
    asking is paid by the verifier, while the cost of not asking is paid by
    the verdict: making a parent search-only — mode 0o111, traversable and not
    listable — is all a proposal has to arrange to turn the one check that
    binds a spelling off. So this fails closed. What it takes back is the
    round-one allowance of a search-only directory above a state file, which
    is measured in ``append_gate``'s module docstring; the descent's
    search-only flags stay, because they are still the right rights for the
    open it makes.

    On a filesystem that compares names exactly the *misspelling* refusal
    below is unreachable by construction — a name that resolves is a name the
    directory lists — while this one is reachable everywhere, which is what
    gives the check regression protection on every runner. Both walks stand
    ahead of the read they guard, so either refusal stands where a pre-existing
    refusal about the content behind that name would have; ``append_gate``'s
    module docstring states that with the cases measured.
    """

    try:
        names = set(os.listdir(parent))
    except OSError as exc:
        if exc.errno in {errno.ENOENT, errno.ENOTDIR}:
            # There is no directory here to withhold a listing: the parent is
            # absent, or is a file. Neither is this check's business, for the
            # reason an absent component is not — an absent release root is
            # legal, a state path that is not there is the reader's refusal,
            # and a regular file standing where a directory should be is
            # answered by the checks after the walk, in their own words.
            return
        raise ReleaseChainError(
            f"cannot bind the spelling of {'/'.join(walked)}: its directory "
            f"cannot be listed: {relative.as_posix()}"
        ) from None
    if segment in names:
        return
    try:
        os.lstat(parent / segment)
    except OSError:
        return
    raise ReleaseChainError(
        f"path component {'/'.join(walked)} is not spelled by its directory: "
        f"{relative.as_posix()}"
    )


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

    Each component's spelling is bound here too, after its own symlink check
    so that a linked component keeps that answer: what a component *is* comes
    from resolving its name, and resolution is what a name-folding filesystem
    answers with another directory's entry. See ``_assert_component_spelled``.
    """

    current = root
    walked: tuple[str, ...] = ()
    for segment in relative.parts:
        child = current / segment
        walked = (*walked, segment)
        # A dangling link is still a link, and still refuses.
        if _is_reparse_point(child):
            raise _symlinked_component_error(relative, walked)
        _assert_component_spelled(current, segment, walked, relative)
        current = child


def assert_no_symlinked_release_root(root: pathlib.Path, spec: ChainSpec) -> None:
    """Bind all configured release-path components before directory reads.

    Symlinks and reparse points refuse without being followed. Every component,
    including each configured leaf, is also required to be spelled exactly as
    its parent directory lists it. Manifest and anchor leaf type checks remain
    with their existing direct readers so their refusal texts do not move.
    """

    for relative, leaf_is_the_release_root in (
        (spec.release_root_relative, True),
        (spec.manifest_relative, False),
        (spec.anchor_relative, False),
    ):
        _walk_release_path(
            root, relative, leaf_is_the_release_root=leaf_is_the_release_root
        )


def _walk_release_path(
    root: pathlib.Path,
    relative: pathlib.PurePosixPath,
    *,
    leaf_is_the_release_root: bool,
) -> None:
    """One configured path under the release tree, component by component.

    Every component's spelling is bound, the leaf's included. What stands at
    the end of a configured path is decided by resolving its whole name, and a
    name-folding filesystem answers the last component as readily as any
    other: a spec naming ``releases/manifests`` over a directory spelled
    ``releases/Manifests`` on disk has the chain in *that* directory verified
    on APFS or any case-insensitive mount, and no chain at all — an
    acceptance, since an absent manifest directory is legal — on a filesystem
    that compares names exactly. One commit, two verdicts, and neither of them
    about the path the spec pins. The walk of each path used to stop one
    component short, so the leaf was the one component nothing bound.

    What stops one component short now is the *type* judgement, and only for
    the two paths below the root. A manifest path that is a symlink, or is
    anything but a directory, is ``assert_manifest_directory_regular``'s and
    ``_enumerate_manifest_files``'s to refuse, and against a base the base
    enumeration's; a non-directory anchor path is the walk at the top of
    ``verify_release_chain``. Refusing either here would replace their
    sentences with this one's, and for an anchor directory a caller has
    overridden it would refuse a tree over a directory this verdict never
    reads. The two questions are separable because they are asked of different
    things: a component's type comes from ``lstat``-ing it, its spelling from
    listing the directory that holds it, and the second is available for a leaf
    whose type is somebody else's business.

    The release root's own leaf keeps both, as it always has: the enumeration's
    words for a symlinked root are this walk's to give.
    """

    current = root
    walked: tuple[str, ...] = ()
    parts = relative.parts
    for depth, segment in enumerate(parts, start=1):
        child = current / segment
        walked = (*walked, segment)
        at_the_leaf = depth == len(parts)
        if leaf_is_the_release_root or not at_the_leaf:
            if _is_reparse_point(child):
                if leaf_is_the_release_root and at_the_leaf:
                    raise ReleaseChainError(
                        "releases must be a real directory, not a symlink"
                    )
                raise ReleaseChainError(
                    "release root path traverses a symlink at "
                    f"{'/'.join(walked)!r}: {relative.as_posix()}"
                )
        _assert_component_spelled(current, segment, walked, relative)
        current = child


STATE_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_BINARY", 0)
)


def _regular_file_bytes(
    root: pathlib.Path,
    relative: pathlib.PurePosixPath,
    *,
    nonregular: str | None = None,
    unreadable: Any | None = None,
    replaced: str | None = None,
) -> bytes:
    """Read a regular file after component ``lstat`` and one bounded open.

    Every component is checked without following links and has its spelling
    bound before the leaf is opened once with ``O_NOFOLLOW | O_NONBLOCK``.
    The opened descriptor must still name the regular inode approved by the
    walk. This is deliberately a read-once directory contract, not a lock
    against a concurrent writer. ``O_NOFOLLOW`` is mandatory even for private
    materializations, so commit-addressed verification retains the POSIX
    requirement.
    """

    if not getattr(os, "O_NOFOLLOW", 0):
        raise ReleaseChainError(
            "state files cannot be read with secure descent on this platform "
            "(os.O_NOFOLLOW is unavailable); receipt requires a POSIX platform"
        )
    if relative.is_absolute():
        path = pathlib.Path(relative)
        current = pathlib.Path(relative.anchor)
        components = relative.parts[1:]
    else:
        path = root / relative
        current = root
        components = relative.parts
    missing = nonregular or f"required state file is missing or non-regular: {path}"
    # Four non-state callers omit replaced=, so they report a state file here.
    changed = replaced or f"required state file was replaced while being read: {path}"
    approved: os.stat_result | None = None
    walked: tuple[str, ...] = ()
    try:
        for depth, segment in enumerate(components, start=1):
            current = current / segment
            walked = (*walked, segment)
            approved = os.lstat(current)
            linked = stat.S_ISLNK(approved.st_mode) or bool(
                getattr(approved, "st_reparse_tag", 0)
            )
            if linked:
                if nonregular is None and depth < len(components):
                    raise _symlinked_component_error(relative, walked)
                raise ReleaseChainError(missing)
            _assert_component_spelled(current.parent, segment, walked, relative)
            if depth < len(components) and not stat.S_ISDIR(approved.st_mode):
                raise ReleaseChainError(missing)
        if approved is None or not stat.S_ISREG(approved.st_mode):
            raise ReleaseChainError(missing)
        descriptor = os.open(path, STATE_OPEN_FLAGS)
    except ReleaseChainError:
        raise
    except OSError as exc:
        message = unreadable(exc) if unreadable is not None else missing
        raise ReleaseChainError(message) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev,
            opened.st_ino,
        ) != (approved.st_dev, approved.st_ino):
            raise ReleaseChainError(changed)
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1 << 20, remaining))
            if not chunk:
                raise ReleaseChainError(changed)
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ReleaseChainError(changed)
        return b"".join(chunks)
    except OSError as exc:
        message = unreadable(exc) if unreadable is not None else missing
        raise ReleaseChainError(message) from exc
    finally:
        os.close(descriptor)


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


def _anchor_filenames_are_exact(
    spec: ChainSpec, *, include_producer: bool = True
) -> bool:
    """Whether normalization would preserve every configured filename."""

    return (
        not include_producer
        or type(spec.producer_public_key_filename) is str
    ) and all(
        type(anchor.filename) is str for anchor in spec.anchors.values()
    )


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

    Breaking contract: ``verify_release_chain(root)`` speaks for the
    directory as it was read, once, by this process. A caller that needs a
    verdict about a commit uses ``verify_append_gate`` or
    ``run_verification``, which read only objects. A caller on a directory it
    does not own carries the concurrent-writer residual.

    Every input file is opened once through :func:`_regular_file_bytes` after
    the configured path walks. With ``compute_anchor_set_digest=True`` the
    result additionally names the exact configured anchor bytes consumed;
    OpenSSL always receives a private byte-for-byte ``-CAfile`` copy.
    Caller-supplied ``state_bytes`` replace the two state-file reads.
    """

    if type(clock_skew_seconds) is not int or clock_skew_seconds < 0:
        raise ReleaseChainError("clock_skew_seconds must be a non-negative integer")
    if type(compute_anchor_set_digest) is not bool:
        raise ReleaseChainError("compute_anchor_set_digest must be a boolean")
    supplied_state = _exact_state_bytes(state_bytes)
    if type(allow_pending_append) is not bool:
        raise ReleaseChainError("allow_pending_append must be a boolean")
    if allow_pending_append and not verify_state:
        raise ReleaseChainError(
            "allow_pending_append requires historical state verification"
        )

    try:
        _tsa._require_supported_openssl()
    except _tsa.TsaError as exc:
        raise ReleaseChainError(str(exc)) from exc

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
    anchor_observer: dict[str, str] | None = (
        {} if compute_anchor_set_digest else None
    )

    # Bind every component of all three configured paths after the anchor
    # probe and before enumeration. An anchor override changes the bytes read,
    # not the requirement that the spec's own path be non-redirecting and use
    # the directory's exact spelling.
    assert_no_symlinked_release_root(root, spec)

    assert_manifest_directory_regular(root, spec)

    enumerated = _enumerate_manifest_files(root, spec)
    if not enumerated:
        if require_chain:
            raise ReleaseChainError("release chain is absent; genesis is required")
        return ChainVerification(())

    if anchor_observer is not None and not _anchor_filenames_are_exact(spec):
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


# The five variables that decide which repository, working tree, index and
# object store a git command answers about, whatever directory it is run in
# and whatever path is named on its command line. See
# ``assert_no_redirecting_git_environment``; they are refused rather than
# dropped, and the order here is the order a refusal reports them in.
REDIRECTING_GIT_ENVIRONMENT = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
)


def assert_no_redirecting_git_environment() -> None:
    """Refuse before snapshot selection when Git reads could be redirected.

    The commit-addressed public entry points bind their own repository and
    object environment, but retain this 0.5.2 refusal at entry. The first set
    variable wins in the stable order above, preserving the existing text.
    """

    for name in REDIRECTING_GIT_ENVIRONMENT:
        if name in os.environ:
            raise ReleaseChainError(
                f"{name} is set in the environment and would redirect git "
                "reads; unset it"
            )


def verify_release_history_immutable(
    spec: ChainSpec,
    *,
    candidate: TreeSnapshot,
    base: TreeSnapshot,
) -> tuple[str, set[str], dict[str, GitEntry]]:
    """Compare release entries in two entered, authenticated tree snapshots."""

    release_root = spec.release_root_relative.as_posix()
    base_entries = base.entries(release_root).as_dict()
    candidate_entries = candidate.entries(release_root).as_dict()

    # The old working-directory enumeration refused every candidate link or
    # non-regular entry before comparing base bytes. Preserve that ordering
    # over the tree's modes, without opening any blob.
    for relative, entry in sorted(candidate_entries.items()):
        if entry.mode == "120000":
            raise ReleaseChainError(f"release path is a symlink: {relative}")
        if entry.mode not in {"100644", "100755"}:
            raise ReleaseChainError(f"release path is not regular: {relative}")

    for relative, prior in sorted(base_entries.items()):
        if prior.mode not in {"100644", "100755"}:
            raise ReleaseChainError(
                f"base release entry has non-regular git mode {prior.mode}: {relative}"
            )
        current = candidate_entries.get(relative)
        if current is None:
            raise ReleaseChainError(
                f"existing release file was deleted relative to "
                f"{base.commit}: {relative}"
            )
        if current.mode != prior.mode:
            raise ReleaseChainError(
                f"existing release file mode changed relative to {base.commit}: "
                f"{relative} ({prior.mode} -> {current.mode})"
            )
        if current.object_id != prior.object_id:
            raise ReleaseChainError(
                f"existing release file bytes changed relative to "
                f"{base.commit}: {relative}"
            )
    return (
        base.commit,
        set(candidate_entries) - set(base_entries),
        base_entries,
    )


def verify_base_release_chain(
    spec: ChainSpec,
    *,
    base: TreeSnapshot,
    anchor_dir: pathlib.Path | None = None,
    enforce_production_pins: bool = True,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> ChainVerification:
    """Materialize and verify one entered base snapshot's release chain.

    By default every configured anchor must belong to the materialized tree.
    An explicit ``anchor_dir`` supplies the caller's trust material instead,
    as the append gate requires; those anchors are not bound to the base tree.
    """

    normalized = _normalized_spec(spec)
    prefixes = (
        normalized.release_root_relative,
        normalized.manifest_relative,
        normalized.state_relative,
        normalized.prefix_relative,
        normalized.anchor_relative,
    )
    with tempfile.TemporaryDirectory(prefix="receipt-release-base-") as name:
        destination = pathlib.Path(name)
        with base.materialize(
            prefixes,
            destination,
            repertoire=normalized.name_repertoire,
        ) as materialized:
            if anchor_dir is None:
                materialized.anchor_set_sha256(normalized)
            return verify_release_chain(
                materialized.path,
                spec=normalized,
                anchor_dir=(
                    materialized.path / normalized.anchor_relative
                    if anchor_dir is None
                    else anchor_dir
                ),
                require_chain=True,
                verify_state=True,
                enforce_production_pins=enforce_production_pins,
                clock_skew_seconds=clock_skew_seconds,
            )


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
