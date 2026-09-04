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

Extracted nearly verbatim from PolicyEngine/ledger
scripts/verify_release_chain.py at commit
07984278503b8e06c48c539327f6f1d01c035510 (branch codex/thesis-ledger-facts);
see receipts/ledger-pin-source-hashes.txt. The only intended change is
parameterization: every repo-specific constant moved into ChainSpec, supplied
by the consumer's committed code. Behavior is gated by the differential
harness in tests/test_ledger_equivalence.py. Additions since the extraction
(the base-ref history pass with its checkout and index guards, which include
requiring every base release file to still be an entry in the candidate index,
since both of that pass's comparisons read the working tree and ``git rm
--cached`` leaves it untouched; the release-root guard, which reconciles that
root's index entries with the working tree in both directions, by the spelling
the traversal returns and after walking an indexed path's parents, because a
filesystem traversal does not descend a symlinked directory while resolving
the whole name does — and because a case- or normalisation-insensitive
filesystem answers one entry's question with another entry's file; the
whole-index read that refuses an entry spelled as another spelling of a
protected path — the five this module reads for itself, and every path a
caller's own configured surfaces name, which it passes in — since every one of
those reconciliations is blind to such an entry because each compares by exact
spelling, and so is a caller's surface classification; its sibling read,
which refuses an entry marked assume-unchanged or skip-worktree, since that
tells git to stop comparing the path against the working tree and so hides a
rewrite from the ``git diff`` a caller's surface classification is built on —
a separate function from the alias refusal because it is about that
classification and is asked only where one happens, which in ``append_gate``
is the base-ref path; the content
binding, which requires the blob the index records for a path to be either the
base's — the commit under review
does not change it — or the git blob id of the bytes the caller just verified,
because every comparison here reads the working tree and none of them ever
looked at what the commit would carry; the release root's own path walk,
which the gate runs before anything reads through that root — and once more
before it returns a gate-only verdict, the one exit that claims a confinement
over that root while reading nothing through it — and
``verify_release_chain`` runs again at its own top — so the public verifier
and ``receipt verify`` are confined by it too, rather than certifying a chain
reached through a symlinked interior component of a configured path — since
every check
that
would meet a link there is downstream of following it — and which now hands
the gate the approved directory held open, opened from the candidate root's
own descriptor with ``O_NOFOLLOW``, so that after every read through that root
the gate can ask whether the root it read through is still the one the walk
approved, a walk on its own being a pathname preflight every later read
resolves again; the manifest path's own type, decided for a caller that
decides whether a tree has a chain by asking the filesystem, because
``is_dir()`` is false for a blob standing where that directory was, for an
empty link and for a dangling one alike, and the enumeration whose words
refuse such a path only runs once something has decided to enumerate — and
decided component by component, so that absence, a non-directory *ancestor*
and a path this verifier cannot ``lstat`` at all are three answers rather than
one: a single ``lstat`` of the whole path answers ``ENOTDIR`` below an
untracked regular file at the release root and ``EACCES`` below an
unsearchable one, and a bare ``except OSError`` read both as "there is no
manifest directory here", which on the push path is an acceptance with no
chain over a tree whose release history is a text file; the
state-path guards
``append_gate`` calls, whose walk — like the release root's — now also
requires each component to be spelled by the directory holding it, because
what a component *is* is learned by resolving its name and a name-folding
filesystem resolves a name this package never wrote, and refuses a directory
that cannot be listed rather than descending it, since the listing was the
only thing that could have bound the spelling and a search-only mode — 0o111,
traversable and not listable — is all it takes to withhold it. That last is a
requirement about every directory above a protected path rather than a
property of one, and it is stated in ``README.md``: this verifier must be
able to list them. It was once narrowed to directories that could be *shown*
to fold the name, by probing a whole-string swapcase and the other of NFC and
NFD, which is not the set of names a filesystem may fold — one that folds
part of a mixed-case name answers no to every probe and folds the name all
the same — so it fails closed instead, and the search-only descent below is
no longer reached with such a parent through either reader; the anchor-set
digest in the result; spec validation at construction; reading each receipt
through one descriptor; and refusing a genTime finer than a microsecond) run
beside the extracted checks without altering any of their refusals, and carry
their own tests. None of the additions reworded an extracted refusal or moved
one in the order they fire; the new refusals cover inputs the upstream battery
never presents. Every one of those index reads names its
path as a literal pathspec, so git is asked about the exact path rather than
handed a name to interpret as a pattern — and so does the base tree's own
enumeration, which is not an addition but was still handing git a configured
path to interpret: a release root beginning with ``:`` was read as pathspec
magic and the magic stripped, so the whole root enumerated as empty, an
existing genesis tree was taken for newly added files, and its byte and mode
immutability was never compared. What that enumeration returns is now required
to be the path asked for or to lie under it. Every git read here runs with
git's four pathspec-mode environment variables dropped, so that literal
pathspec means what it says instead of whatever an ambient
``GIT_LITERAL_PATHSPECS`` or ``GIT_ICASE_PATHSPECS`` would make of it, and
with ``WORKING_TREE_SCAN_OPTIONS`` spelled on its own command line, so that no
read consults a stat cache, an untracked cache or a file-system monitor
whatever the checkout configures, whatever its ``feature.*`` shorthands imply,
and whatever extensions its index already carries. That replaces a refusal
that read those settings and believed them: git keeps an untracked-cache index
extension in use when ``core.untrackedCache`` is unset, which is its
documented default, so a cache written by any earlier command was in use in a
checkout the refusal called clean — and a checkout that names a monitor is not
thereby a proposal this package has any quarrel with. An option on a command
line says the same thing about the read itself, on every checkout, and none of
these reads writes the candidate's index, so an extension already in it is
left as found. Each
also reads the entry's own flag word, because mode and object id do not say
whether an entry records content: an intent-to-add entry (``git add -N``) is
stage 0 at the working tree's mode with the empty blob's object id, which is
what every check here took for a tracked file while the commit made from that
index deletes the path. The state reads themselves changed shape but not their
refusals: ``_regular_file_bytes`` keeps both of its messages and their order,
and opens the file it accepts through directory descriptors so no component of
the path is resolved twice. That descent returns the identity of every
directory it opened, so a caller can ask afterwards whether the file is still
reached through the same ones, optionally pins the root against an identity
the caller recorded earlier, and refuses outright rather than falling back to
a pathname open where ``os.open`` takes no ``dir_fd`` — a requirement of the
package rather than of any one caller, since every state read in it comes
through here: on Windows ``verify_release_chain``, and so ``receipt verify``'s
custody pass, refuses exactly as the append gate does, and ``README.md``
states it. Both of that root open's refusals are named here rather than at
either caller, because ``append_gate._set_root`` performs the same open for
the same confinement — it holds the candidate root open for the whole of a
verdict, so the identity it records is a directory it still has rather than a
number the filesystem may hand to the next directory created in that root's
place. It opens each directory component with search rights alone where the
platform offers them (``O_PATH`` on Linux, ``O_SEARCH`` on Darwin), which is
all it uses them for and all it asks for; where the platform offers neither,
the read permission the descent then needs is stated in the refusal rather
than escaping as a bare ``PermissionError``. (A search-only directory above a
state file was once descended this way as the pathname open used to descend
it. The component walk refuses one now — its listing was the only thing
binding the spelling — so what the flags buy is the right rights for this
open rather than that acceptance.)
``assert_index_agrees_with_tree`` likewise accepts a category the caller has
already observed, so a caller holding the file open need not resolve its name
again. ``verify_release_chain`` takes an optional ``state_bytes`` mapping that
stands in for reading a state path, so a caller that has already read those
files can hold one verdict to one read of each; omitted, both files are read
exactly as before. Every git subprocess here runs with ``refs/replace``
disabled (``_git_environment``); those additions are its only callers, and a
replacement object would otherwise change what a base commit, tree, or blob
reads as behind the OID a verdict names.
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
import unicodedata
from collections.abc import Iterable, Mapping
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


def assert_manifest_directory_regular(root: pathlib.Path, spec: ChainSpec) -> None:
    """Decide what the manifest path *is*, for a caller about to ask if it has one.

    ``_enumerate_manifest_files`` below answers this for itself, but only once
    something has decided to enumerate. A caller that decides whether a chain
    exists by asking the filesystem — ``append_gate``'s push path, whose
    ``initialized`` is ``manifest_directory.is_dir() and any(iterdir())`` —
    gets ``False`` for every way the path can be something other than a
    directory: a tracked 100644 blob standing where the manifest directory
    was, an empty untracked symlink there, a dangling one. Each of those is
    then "this tree has no chain", which is an acceptance, and the enumeration
    that would have said otherwise never runs. Nothing else on that path says
    it either: the release root's walk stops one component short of this leaf,
    and the root's index scan reconciles a tracked blob here with the walk that
    finds a regular file, which is exactly what it is.

    So the type is decided first, in the enumeration's own words and for the
    same three shapes — an ``lstat``, so a symlink is not a directory here
    however it resolves, which is the enumeration's ``is_symlink() or not
    is_dir()`` in one question. A path that is not there at all is not this
    check's business: an absent chain is legal, and "no chain" is the true
    answer for it.

    Absence is the only thing that returns, and it is asked component by
    component so that it can be told apart from the two facts that used to be
    folded into it. One ``lstat`` of the whole path answers ``ENOTDIR`` when an
    *ancestor* is a regular file — a release root that is an untracked blob,
    or any component of a multi-component manifest path — and ``EACCES`` when
    an ancestor is unsearchable, and catching ``OSError`` turned both into "no
    manifest directory here". On the push path that is an acceptance with no
    chain: ``initialized`` is false, nothing is enumerated, the index scan has
    no entry under an untracked root to object to, and ``verify_release_chain``
    is never called, while the commit under review may carry the whole chain.

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

    # O_NOFOLLOW is POSIX but not universal; where it is absent the lstat
    # below plus the descriptor comparison still catch a swap, they simply
    # catch it one step later.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        before = os.lstat(receipt)
        if not stat.S_ISREG(before.st_mode):
            raise ReleaseChainError(
                f"missing or non-regular RFC 3161 receipt: {receipt}"
            )
        descriptor = os.open(receipt, flags)
    except OSError as exc:
        raise ReleaseChainError(
            f"cannot read RFC 3161 receipt {receipt}: {type(exc).__name__}"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev,
            opened.st_ino,
        ) != (before.st_dev, before.st_ino):
            raise ReleaseChainError(
                f"RFC 3161 receipt was replaced while it was being read: {receipt}"
            )
        with open(descriptor, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(descriptor)


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
    release tree whose name is not the one the spec pins or the one the index
    records. The directory's own listing is the question that does not go
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
        names = os.listdir(parent)
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
    """Refuse a release root reached through a link, before anything reads it.

    Everything this package knows about a candidate's release tree it learns
    by joining the configured root onto the candidate root and reading what
    the join lands on. Nothing asked what the join went through. On the push
    path that was the whole of it: ``initialized`` is
    ``manifest_directory.is_dir()``, which follows links, so an untracked
    ``releases`` pointing at a directory outside the checkout made the chain
    inside *that* directory the one ``verify_release_chain`` verified, and the
    verdict spoke for a release history no part of which is in the tree under
    review, in the commit under review, or diffable against any base. The
    root's index scan does not catch it: it refuses a symlinked root only when
    the index holds entries under that root, and an untracked one holds none,
    so it returns.

    So every component of the release root, the root itself included, is
    walked from the candidate root with ``lstat`` before anything reads
    through it, and a link at any of them refuses. The leaf is refused in
    ``_working_release_files``'s own words, because that is the same fact this
    package has always refused a symlinked ``releases`` for, and where the link
    resolves that is the refusal the base-ref path reaches there anyway; a component above the leaf gets the shape
    the state-path walk uses, naming the component that redirects.

    Each component's spelling is bound as well, for the reason the state
    walk's is: ``lstat`` resolves a name, and on a name-folding filesystem a
    root the spec spells one way is answered for by a directory spelled
    another. See ``_assert_component_spelled``. That holds for a configured
    path's *leaf* as much as for the components above it — the leaf is where
    the manifest directory's own name is — so the spelling check runs at every
    component of all three paths.

    Three callers reach this, at three depths, and all three are wanted.
    ``verify_release_chain`` runs it at its own top, before any manifest is
    enumerated, so the public verifier and ``receipt verify`` get it with no
    append gate in the picture — without which a chain behind a symlinked
    interior component of a multi-component manifest path was verified and
    reported as a pass. The gate reaches it earlier, through
    ``hold_release_root`` at the top of both of
    its release-proposal paths, ahead of the reads, rather than after the
    comparisons the way the index checks run: a root that is not in the
    candidate tree is not a release root this verdict can be about, so there
    is nothing for a later refusal to be more specific about. And the gate
    reaches it once more on the exit that takes neither of those paths: a
    gate-only verdict returns a confinement over the release root without
    reading anything through it, so nothing there would otherwise have walked
    it, and the confinement would have spoken for whatever an untracked link
    at a component of the root pointed at. It runs a second
    time at the end of each path, from ``assert_release_root_unchanged``,
    because a walk on its own is a preflight every later read resolves again.
    For a single-component root — every consumer's, and every fixture's but
    the two the gate's tests build for a nested root — a
    link the enumeration would itself have met is answered word for word as
    the enumeration answers it. The one link it would not have met is a
    dangling one, which ``_working_release_files`` answers by returning
    nothing at all, so against a base it was refused a file later as a release
    file deleted relative to the base commit; that refusal is pre-empted here,
    deliberately. So is whatever the content behind a folded name would have
    been refused for, wherever ``_assert_component_spelled`` fires: standing
    ahead of the read is the whole point of both walks, and the read is what
    the folded name would have answered. ``append_gate``'s module docstring
    enumerates all of it with the cases measured, and tests pin them.

    The release root is not the only path that has to be walked, because it is
    not the only one joined onto the candidate root. ``manifest_relative`` and
    ``anchor_relative`` are configured whole, and a spec whose manifest
    directory sits more than one component below the release root —
    ``releases/journal/manifests`` — reaches it through components that
    walking the root alone never looks at. A link at one of those is followed
    by ``is_dir()``, by ``iterdir()`` and by the chain verification, and the
    index reconciliation cannot see it either: ``rglob`` yields a symlinked
    directory without descending it and the release root's scan skips it, so
    an untracked link there is in no walk at all. That is the same escape as a
    linked root, one component lower down, and it is stable rather than a
    race. So every component of both paths is walked here too, with the same
    ``lstat`` and the same spelling check, in the same words.

    What stops one component short for those two is the *type* judgement, not
    the walk. Their leaves keep the refusals that already exist for them: a
    symlinked manifest directory is ``assert_manifest_directory_regular``'s
    and ``_enumerate_manifest_files``'s own refusal (``release manifest path
    is not a regular directory``), and against a base it is the enumeration's
    (``release path is a symlink``); a symlinked spec-pinned anchor directory
    is the walk at the top of ``verify_release_chain``. Both are reached
    wherever anything is read through those directories at all, and refusing
    here instead would replace their sentences with this one's and, for an
    anchor directory a caller has overridden, refuse a tree over a directory
    this verdict never reads. Nothing above a leaf has an answer like that,
    which is exactly the gap the walk fills.

    The leaf's *spelling* is a different question and nothing else asks it. A
    type refusal is about what the resolved name landed on; a spelling refusal
    is about whether the name resolved to something the directory holds under
    that name at all, which only the directory's listing can say. So the
    spelling check runs at the leaf while the type judgement does not, and the
    two paths below the root are walked whole. Round 9's stopping short bound
    neither for a leaf, which left ``releases/manifests`` verifying a chain
    stored at ``releases/Manifests`` wherever names fold and finding no chain
    there at all wherever they do not — the same commit, two verdicts.
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

# The descent below needs a directory descriptor it can ``openat`` and
# ``fstat`` through, and nothing else. ``O_PATH`` (Linux) and ``O_SEARCH``
# (POSIX 2008; Darwin defines it and CPython exposes it there, checked from
# 3.9 to 3.14) both give exactly that without asking for read permission on
# the directory. Where
# neither exists the open has to ask for read, and a POSIX search-only
# directory — mode 0o111, traversable but not listable — above a perfectly
# readable state file then fails with EACCES; see confined_state_descriptor.
#
# What these flags no longer buy is that search-only directory itself: the
# component walk requires every directory above a protected path to be
# listable, and both readers run it before descending, so a state file under
# such a directory is refused by the walk on every platform now. They stay
# because they are still the rights this open needs — it does ``openat`` and
# ``fstat``, nothing more, and asking for read permission it does not use is
# a claim on the checkout this package has no reason to make — and because
# the two opens no walk precedes still meet the fact: ``append_gate._set_root``
# on the candidate root, and hold_release_root on the release root.
SEARCH_ONLY_DIRECTORY_FLAG = getattr(os, "O_PATH", 0) or getattr(os, "O_SEARCH", 0)
DIRECTORY_OPEN_FLAGS = (
    (SEARCH_ONLY_DIRECTORY_FLAG or os.O_RDONLY)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
DESCENT_REQUIRES_DIRECTORY_READ = not SEARCH_ONLY_DIRECTORY_FLAG


def assert_secure_descent_supported() -> None:
    """Refuse where ``os.open`` takes no ``dir_fd``, in the descent's words.

    One sentence for one fact, said wherever it is found: the descent below
    asks it before opening anything, and ``append_gate._set_root`` asks it
    before opening the candidate root, which it holds open for the whole
    verdict with the same flags and for the same confinement. Neither can be
    done on a platform without ``dir_fd``, and a verifier that quietly
    weakens its confinement there states an invariant it does not hold.
    """

    if os.open not in os.supports_dir_fd:
        raise ReleaseChainError(
            "state files cannot be read with secure descent on this platform "
            "(os.open lacks dir_fd support); receipt requires a POSIX platform"
        )


def unreadable_directory_error(
    named: object, relative: pathlib.PurePosixPath
) -> ReleaseChainError:
    """The refusal for a directory the descent may traverse but not read.

    Only reachable where the platform offers neither ``O_PATH`` nor
    ``O_SEARCH`` and the open therefore has to ask for read permission it
    does not use. Shared by the descent and by the root open that precedes
    it, so the candidate root gets this answer rather than one about having
    changed — it did not change, it cannot be read.
    """

    return ReleaseChainError(
        f"state path component {named} is not readable by this verifier; "
        "secure descent requires read permission on every directory above a "
        f"state file on this platform: {relative.as_posix()}"
    )


def hold_release_root(
    root: pathlib.Path, spec: ChainSpec, *, root_descriptor: int
) -> int | None:
    """Walk the release root, then hold the directory the walk approved open.

    ``assert_no_symlinked_release_root`` is a pathname preflight: it looks at
    every component and returns, and everything that reads through the root
    afterwards resolves the whole name again. On the push path that is
    ``manifest_directory.is_dir()``, ``iterdir()`` and the chain verification;
    against a base it is the working-tree enumeration and the release-history
    comparisons. So a root replaced by a symlink *after* the walk passed was
    followed by all of them, and the verdict spoke for a chain outside the
    tree — the index scan at the end cannot say so, because an untracked root
    holds no index entries and it returns.

    Holding a descriptor is what turns the walk's finding into something that
    can be checked again at the end. It is opened from the candidate root's own
    held descriptor, component by component with ``O_NOFOLLOW`` and
    ``O_DIRECTORY`` and search rights where the platform offers them, so no
    component is resolved by name a second time and a link that appeared since
    the walk fails rather than being followed.

    ``None`` means the walk found no directory to hold: the release root is
    absent, which is legal, or it is not a directory, which the walk permits
    and the checks after it answer for (a tracked regular file standing where
    the root was is refused by the release root's index scan, in its own
    words). ``assert_release_root_unchanged`` requires that to still be true,
    so a directory moved into the root's place mid-run is a change either way.

    What this does not do is make the reads themselves go through the
    descriptor: they stay by pathname, because they are ``rglob``, ``is_dir``
    and a manifest enumeration rather than one open of one file. So the
    guarantee is a comparison at two instants, not a lock — a root swapped
    after the walk and swapped back before the re-check is not seen. That is
    the same residual the closing state re-reads leave, and it closes the same
    way: by verifying the committed tree object rather than a working tree,
    which is tracked as follow-up work.
    """

    assert_no_symlinked_release_root(root, spec)
    assert_secure_descent_supported()
    # A release root with no components at all — ``PurePosixPath('.')`` and
    # the empty path both give that — would leave this loop with nothing held
    # and nothing to hold. It is refused before the gate gets here, by
    # ``append_gate``: `git ls-tree` names entries under ``.`` without the
    # prefix, so the base enumeration refuses the first of them as outside the
    # root, and the gate-only confinement finds no path inside it. The assert
    # below is that refusal's invariant rather than a hope.
    parent = root_descriptor
    held: int | None = None
    for segment in spec.release_root_relative.parts:
        try:
            child = os.open(segment, DIRECTORY_OPEN_FLAGS, dir_fd=parent)
        except OSError as exc:
            if held is not None:
                os.close(held)
            # Absent, not a directory, or — where the flags make a link an
            # ``ELOOP`` rather than an ``ENOTDIR`` — a link that arrived since
            # the walk said there was none. Nothing to hold for any of them:
            # the walk permits the first two, and the third is a change
            # ``assert_release_root_unchanged`` refuses at the end, in the
            # walk's own words, because with nothing held its requirement is
            # that there still be no directory here.
            if exc.errno in {errno.ENOENT, errno.ENOTDIR, errno.ELOOP}:
                return None
            if DESCENT_REQUIRES_DIRECTORY_READ and exc.errno == errno.EACCES:
                # The same fact ``_set_root`` meets at the candidate root on a
                # platform with no search-only flag, answered in the same
                # words: this directory has not changed, it cannot be read.
                raise unreadable_directory_error(
                    root / spec.release_root_relative, spec.release_root_relative
                ) from exc
            # Everything else -- ``EACCES`` on a platform whose search-only
            # flag makes reading unnecessary but searching still required, an
            # ``EPERM``, an I/O error -- is an open this verifier could not
            # make, and a verdict cannot be built on a directory it could not
            # hold. Refused in the verifier's own words rather than escaping
            # as the platform's exception (a bare ``PermissionError`` reached
            # the gate's caller from a mode-0o444 release root, measured on
            # Darwin, where ``O_SEARCH`` exists).
            raise ReleaseChainError(
                "cannot open a release root component to hold it: "
                f"{spec.release_root_relative.as_posix()} "
                f"({exc.strerror})"
            ) from exc
        if held is not None:
            os.close(held)
        held = child
        parent = child
    assert held is not None
    # ``O_PATH`` with ``O_NOFOLLOW`` opens a symlink itself rather than
    # failing, and it is ``O_DIRECTORY`` that turns that back into ENOTDIR.
    # Assert what the flag is relied on for: a descriptor that is not a
    # directory here can only be a link that arrived since the walk.
    if not stat.S_ISDIR(os.fstat(held).st_mode):
        os.close(held)
        raise ReleaseChainError("release root changed during verification")
    return held


def assert_release_root_unchanged(
    root: pathlib.Path, spec: ChainSpec, descriptor: int | None
) -> None:
    """Require the release root to be what ``hold_release_root`` approved.

    The walk is re-run first, so a link left standing at any component of any
    configured path under that root is answered in the walk's own words rather
    than as a bare identity mismatch — the more specific of the two true things
    to say. Then the path's ``lstat`` is compared against the ``fstat`` of the
    descriptor this run still holds, which is what makes the comparison one
    about a directory: an open descriptor holds its inode, so no directory
    created at that path since can have been given its number.

    With nothing held, the walk found no directory there and the requirement is
    that there still is none.
    """

    assert_no_symlinked_release_root(root, spec)
    path = root / spec.release_root_relative
    if descriptor is None:
        try:
            present = stat.S_ISDIR(os.lstat(path).st_mode)
        except OSError:
            return
        if present:
            raise ReleaseChainError("release root changed during verification")
        return
    try:
        current = os.lstat(path)
        held = os.fstat(descriptor)
    except OSError as exc:
        raise ReleaseChainError("release root changed during verification") from exc
    if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
        raise ReleaseChainError("release root changed during verification")


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

    The directories are opened with search rights alone where the platform
    offers them. All this walk does with a directory descriptor is ``openat``
    and ``fstat`` through it, and ``O_PATH`` (Linux) and ``O_SEARCH`` (POSIX
    2008; Darwin defines it and CPython exposes it there, checked from 3.9 to
    3.14) both give exactly that without asking for read permission on the
    directory.
    ``O_RDONLY | O_DIRECTORY`` asks for read, which the pathname open this
    replaced never needed: a POSIX search-only directory — mode 0o111,
    traversable but not listable, which is how a directory above a published
    state file is often locked down — was read from happily before and fails
    with ``EACCES`` here. Both readers in this package now refuse such a
    directory in the component walk before reaching this open, because a
    directory that cannot be listed cannot bind the spelling of what it
    holds; the flags stay because asking for permission this open does not
    use is a claim on the checkout with nothing behind it, and because
    ``append_gate._set_root``'s open of the candidate root precedes every
    walk. Where neither flag exists the requirement is stated
    rather than raised as a bare ``PermissionError``: the component is named,
    and the refusal says that secure descent needs read permission on every
    directory above a state file on this platform. That covers the root as
    well, and is asked of it before the identity comparison below, because an
    unreadable root is not a changed one and saying so would misname the fact.
    A caller that recorded an identity does establish that the root was
    openable with these flags when it recorded one — ``append_gate._set_root``
    performs this same open — but permissions can change between that moment
    and this one, so the two answers stay in this order and this one stays
    first: it names the fact it finds rather than the fact that would have
    been true a moment earlier.

    Where ``dir_fd`` is unsupported — Windows, where ``os.open`` is not in
    ``os.supports_dir_fd`` — this refuses rather than falling back to the
    pathname open. The fallback silently returned the reader to exactly the
    behaviour every check above exists to replace: the whole path resolved
    again, with the walk's findings about the parents already stale. A
    verifier that quietly weakens its confinement on some platforms states
    an invariant it does not hold there, so it says instead that it cannot
    read the state files here.

    That refusal is the whole package's, not the append gate's alone: this
    is the reader ``_regular_file_bytes`` uses, so ``verify_release_chain``
    and therefore ``receipt verify``'s custody pass stop here too. The
    message says so, and ``README.md`` states the requirement under Install.

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

    assert_secure_descent_supported()
    directory_flags = DIRECTORY_OPEN_FLAGS
    try:
        parent = os.open(root, directory_flags)
    except OSError as exc:
        if DESCENT_REQUIRES_DIRECTORY_READ and exc.errno == errno.EACCES:
            # Before the identity answer below: a root this verifier cannot
            # open for want of read permission is unreadable, not changed.
            raise unreadable_directory_error(root, relative) from exc
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
                if DESCENT_REQUIRES_DIRECTORY_READ and exc.errno == errno.EACCES:
                    raise unreadable_directory_error(
                        "/".join(walked), relative
                    ) from exc
                raise
            os.close(parent)
            parent = child
            # Asked of the descriptor the walk is standing on, so it names the
            # directory this open actually reached, not the one its name
            # resolves to afterwards.
            opened = os.fstat(parent)
            if not stat.S_ISDIR(opened.st_mode):
                # ``O_PATH`` with ``O_NOFOLLOW`` opens a symlink itself rather
                # than failing, and it is ``O_DIRECTORY`` that turns that back
                # into ENOTDIR. Assert what the flag is relied on for instead
                # of trusting it: a descriptor that is not a directory here
                # can only be the link this walk refuses.
                raise _symlinked_component_error(relative, walked)
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

    The release tree's own confinement walk runs at the top of this function,
    before any manifest is enumerated: every component of the release root,
    the manifest path and the anchor path is required to be spelled by the
    directory that holds it and to be reached through no symlink. It was
    added for the append gate and reached only from there, through
    ``hold_release_root``, which left this function — and so ``receipt
    verify``, whose custody pass is this function — verifying a chain reached
    through a symlinked interior component of a multi-component manifest path,
    and one stored under a leaf spelled some other way wherever names fold.
    Measured before the move: ``receipt verify`` over a clone whose
    ``releases/journal`` is a link to a directory outside it returned
    ``VERDICT: PASS — custody and corpus binding``, for a release history no
    part of which was in the tree the auditor had been handed.

    The gate's own call is kept rather than removed as a duplicate, because it
    is not one. It reaches the walk through ``hold_release_root``, which opens
    and holds the directory the walk approved for the whole of a proposal, and
    it stands at the top of both release-proposal paths, ahead of the
    release-history pass and the push path's type decision. This one stands
    inside the chain verification those paths eventually call. Moving the
    gate's to here would move every pre-emption round 12 established and
    pinned — a dangling release-root link answered as a link rather than as a
    deleted release file, a folded ``Releases`` answered as a spelling rather
    than as changed bytes — and would leave ``hold_release_root`` holding a
    descriptor for a root nothing had walked.

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

    # Every component of all three configured paths, before anything reads
    # through any of them. This walk was added for the append gate and reached
    # only from there, through ``hold_release_root``, so the public verifier —
    # and ``receipt verify``, whose custody pass is this function — verified a
    # chain reached through a symlinked interior component of a
    # multi-component manifest path, and one stored under a leaf spelled some
    # other way wherever names fold. Neither is the path the spec pins, and
    # both are outside the tree the auditor was handed. It runs here, after the
    # arguments are validated and the anchor probe has had its say, and before
    # the enumeration, because everything below resolves these names again.
    #
    # It walks all three paths whatever ``anchor_dir`` says. An override
    # replaces the directory the anchors are *read* from; it does not make the
    # spec's own anchor path something this root may reach through a link, and
    # the walk asks only what each component is and how it is spelled — never
    # about the leaf's type, which is where a caller's override legitimately
    # differs.
    assert_no_symlinked_release_root(root, spec)

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


# Every git read in this package spells these five settings out on its own
# command line, so that no read of it consults a stat cache, an untracked
# cache, or a file-system monitor whatever the checkout's configuration, its
# ``feature.*`` shorthands, or the extensions already written into its index
# say.
#
# A caller that classifies a proposal from ``git diff`` and ``git ls-files
# --others`` is taking git's answer for what changed, and four settings decide
# how much of that answer is a cache: ``core.fsmonitor`` names a monitor whose
# "unchanged" git trusts instead of re-stating a path — a stale daemon, a hook
# a proposal can point anywhere — and keeps ``CE_FSMONITOR_VALID`` on a file
# however it was rewritten; ``core.trustctime=false`` drops the inode change
# time from the stat comparison and ``core.checkStat=minimal`` drops all but
# size and whole-second mtime, so a same-size rewrite that restores the mtime
# is not a change git looks for; ``core.untrackedCache`` answers a directory
# listing from a cached scan. ``feature.manyFiles`` is a fifth, because it
# turns the untracked cache on by itself.
#
# Refusing the settings was the earlier answer and it was the wrong shape
# twice over. It read the configuration and believed it, while git keeps an
# untracked-cache index extension in use when ``core.untrackedCache`` is unset
# — ``keep`` is the documented default — so an extension written by any
# earlier command was trusted by a checkout the refusal called clean. And it
# refused checkouts this verifier has no quarrel with: a developer's monitor
# is not a proposal's, and the reads here are the only thing it could have
# affected. Overriding says the same thing about the read itself, on every
# checkout, without asking the checkout anything.
#
# They are spelled on every read rather than on the three that scan the
# working tree, because which reads consult which cache is git's business and
# not a property of a subcommand's name: a read that gains a cache in a later
# git is a read this verifier would otherwise silently begin to trust. The one
# place they are deliberately absent is ``_git_bool`` below, which asks git
# what a setting *is*: overriding a setting while asking about it would answer
# with the override.
WORKING_TREE_SCAN_OPTIONS = (
    "-c",
    "core.untrackedCache=false",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.trustctime=true",
    "-c",
    "core.checkStat=default",
    "-c",
    "feature.manyFiles=false",
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
    means here what it says.

    Everything else in the ambient environment is carried through, and this
    function is not a sanitizer: it turns off the two mechanisms named above
    and nothing else. Other variables git reads can still decide what these
    commands answer about — ``GIT_DIR`` and ``GIT_INDEX_FILE`` were each
    checked and each make ``ls-files`` report another repository's entry for
    the path asked about, from this repository's working directory — so a
    caller that does not control the environment it invokes this package in
    has a problem larger than this function's scope. That is stated rather
    than fixed here; narrowing the environment to an allowlist is a change to
    what every consumer's git reads see, not a check added to one of them.
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
    stdin: bytes | None = None,
) -> subprocess.CompletedProcess[Any]:
    # ``stdin`` feeds bytes to a command that reads them rather than a path:
    # only ``git hash-object --stdin`` uses it, so that the bytes a verdict
    # read are what git is asked to name. Omitted, the child gets no input at
    # all, exactly as every read here always has.
    try:
        return subprocess.run(
            ["git", *WORKING_TREE_SCAN_OPTIONS, *arguments],
            cwd=root,
            check=False,
            capture_output=True,
            text=text,
            env=_git_environment(),
            input=stdin,
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
    """Every base-tree entry at or under one configured path.

    The path is named as a literal pathspec, for the reason ``_index_entries``
    names one: handed to git bare it is a pathspec, and a configured path is
    not. A release root beginning with ``:`` is read as pathspec magic, and
    the magic is stripped: ``git ls-tree -- :releases`` asks about
    ``releases``, which in a tree holding a ``:releases`` directory and no
    ``releases`` matches nothing and exits zero. Every file the base carries
    under that root is then absent from this enumeration, so the release
    history pass has nothing to compare, an existing genesis tree is
    classified as newly added files, and the byte and mode immutability that
    pass exists to enforce is skipped entirely. Where a ``releases`` does
    exist alongside it, the enumeration answers about that one instead — a
    base subtree the spec never named.

    Glob magic is the other half of what a pathspec means, and this command
    is where the two callers differ: ``git ls-tree`` does not glob a bare
    pathspec, while ``git ls-files`` does. Both checked on the git this
    repository is verified with, in a tree holding a directory ``rel[e]ases``
    beside a top-level file named ``releases``: ``ls-files`` returns the file
    too, ``ls-tree`` returns only the directory's own entries. Neither command
    matches a *sibling directory's* contents that way — a wildcard pathspec is
    matched against whole index paths, and ``rel[e]ases`` cannot match
    ``releases/unrelated.md``. What globs and what does not is a property of
    one command's default in one version of git, not of anything this package
    controls, and git's pathspec-mode variables rewrite it for every command —
    ``_git_environment`` drops those, and ``:(literal)`` then says what is
    meant here whatever the default is: this exact path, matched as written.
    ``git ls-tree`` accepts the magic, checked the same way. The diagnostics
    keep naming the path itself, not the magic.

    What comes back is then held to the same claim: every entry must be the
    requested path or lie under it. Nothing git returns for a literal pathspec
    can be anything else, so this is a check on the answer rather than on the
    tree — an enumeration that names a path outside the root the caller asked
    about is one no comparison below should be built on, whatever produced it.
    """

    completed = _git_run(
        root,
        [
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            commit,
            "--",
            f":(literal){pathspec}",
        ],
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
        if path != pathspec and not path.startswith(f"{pathspec}/"):
            raise ReleaseChainError(
                f"git tree enumeration returned a path outside {pathspec}: {path}"
            )
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
# The two flags that tell git to stop comparing an entry against the working
# tree: CE_VALID (the "assume unchanged" bit, 1 << 15, the low half of the
# on-disk flag word) and CE_SKIP_WORKTREE (1 << 30). Either one makes ``git
# diff`` report nothing for a path whose file has been rewritten. See
# assert_index_carries_no_protected_alias.
CE_VALID = 0x8000
CE_SKIP_WORKTREE = 0x4000_0000
# ``git ls-files --debug`` prints exactly these five lines per entry, in this
# order, whatever the entry is; the last carries the flag word.
INDEX_DEBUG_LINES = 5
_INDEX_DEBUG_FLAGS_RE = re.compile(rb"  size: [0-9]+\tflags: ([0-9a-fA-F]+)\n\Z")


@dataclass(frozen=True)
class _IndexRecord:
    """One ``git ls-files -s --debug`` record, as this package reads it.

    A tuple carried the first three of these and grew a fourth; six positional
    fields unpacked at seven call sites is a shape that mis-reads silently, so
    they are named. ``object_id`` is the blob the index records for the path —
    the content the commit under review would carry — which the parse used to
    discard, leaving every reconciliation here a comparison of mode, stage and
    type with nothing said about bytes. See ``assert_index_content_bound``.
    """

    mode: str
    object_id: str
    stage: str
    path: str
    intent_to_add: bool
    hidden: bool


def _split_index_debug(chunk: bytes, unparseable: str) -> tuple[bytes, bytes]:
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
            raise ReleaseChainError(unparseable)
        position = newline + 1
    return chunk[:position], chunk[position:]


def _parse_index_records(
    stdout: bytes, unparseable: str, *, path_errors: str = "strict"
) -> list[_IndexRecord]:
    """Parse ``git ls-files -s --debug -z`` output into its records.

    Split from ``_index_entries`` so the read of one path and the read of the
    whole index are the same parse, reporting an index this cannot read in the
    same words. Two things differ: the sentence naming what was read, and how
    a path that is not valid UTF-8 is treated, which is the one thing the two
    reads cannot share. Git stores index paths as bytes and ``-z`` emits them
    verbatim. A read *about* a configured path answers with records for that
    path or for paths under it, so one this cannot decode is a record about
    the thing being asked after, and refusing is right; the whole-index read
    answers with every path in the repository, where refusing would be a
    refusal about a file no check here is about. See ``_all_index_entries``.
    """

    entries: list[_IndexRecord] = []
    chunks = stdout.split(b"\0")
    record = chunks[0]
    for chunk in chunks[1:]:
        debug, next_record = _split_index_debug(chunk, unparseable)
        flags = _INDEX_DEBUG_FLAGS_RE.search(debug)
        try:
            if flags is None:
                raise ValueError("no flag word")
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_id, stage = metadata.decode("ascii").split(" ")
            listed = raw_path.decode("utf-8", path_errors)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ReleaseChainError(unparseable) from exc
        word = int(flags.group(1), 16)
        entries.append(
            _IndexRecord(
                mode=mode,
                object_id=object_id,
                stage=stage,
                path=listed,
                intent_to_add=bool(word & CE_INTENT_TO_ADD),
                hidden=bool(word & (CE_VALID | CE_SKIP_WORKTREE)),
            )
        )
        record = next_record
    # Every record is followed by its own block, so what is left after the
    # last one is nothing. Anything else is output this parse does not
    # understand, and an index this cannot read is not one to compare against.
    if record:
        raise ReleaseChainError(unparseable)
    return entries


def _index_entries(root: pathlib.Path, pathspec: str) -> list[_IndexRecord]:
    """Every ``git ls-files -s`` record under one path.

    Each is an ``_IndexRecord``. The one place this package parses the index,
    shared by the checks below so they read it the same way and report an
    unreadable or unparseable index in the same words.

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
    not say whether an entry records any content. ``git add -N`` (``git add
    --intent-to-add``) writes an *intent-to-add* entry: stage 0, the working
    tree's mode (100644 for an ordinary file), the empty blob's object id, and
    no content at all — a tree written from such an index does not carry the
    path.
    Every check below took that for a tracked file, so a ``git rm --cached``
    of a protected path followed by ``git add -N`` of it passed the
    tracked-state check, passed the index agreement check (the working tree
    really does hold a regular 100644 file), passed the still-indexed check,
    and produced a commit that *deletes* the path. The flag is what says so:
    ``--debug`` prints the cache entry's flag word, and ``CE_INTENT_TO_ADD``
    is set in it. The empty blob is not the test — a file whose content really
    is empty has the same object id and is an ordinary entry.

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
    return _parse_index_records(
        completed.stdout, f"cannot parse the index entry for {pathspec}"
    )


def _all_index_entries(root: pathlib.Path) -> list[_IndexRecord]:
    """Every record in the candidate index, with no pathspec at all.

    The reads above ask about one configured path, which is the right question
    for every check that compares that path against something. It is the wrong
    question for asking what *else* the index holds: a pathspec answers with
    the entries matching it, and an entry that is not the path asked about
    never appears however close to it it is spelled. This is the whole index,
    parsed exactly as those reads are but for one thing: a path that is not
    valid UTF-8 is carried through with ``surrogateescape`` rather than
    refused. Git stores index paths as bytes, one undecodable filename
    anywhere in a repository is legal and ordinary in a history authored under
    a non-UTF-8 locale, and this read is about every path there is — so
    refusing over one would refuse every proposal at entry over a file no
    check here is about. It cannot hide an alias either: the only caller
    compares against paths the spec supplies, which are ``str``, and a
    name-folding filesystem is one that requires valid UTF-8 filenames, so a
    record this cannot decode is not a spelling of a protected path on any
    tree that could exist.
    """

    completed = _git_run(root, ["ls-files", "-s", "--debug", "-z"])
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ReleaseChainError(f"cannot read the candidate index: {diagnostic}")
    return _parse_index_records(
        completed.stdout,
        "cannot parse the candidate index",
        path_errors="surrogateescape",
    )


def _fold_component(component: str) -> str:
    """One path component as a name-folding filesystem may compare it.

    NFKC and then ``casefold``, normalized again because casefolding can leave
    a string unnormalized. This is deliberately wider than any one filesystem:
    APFS and HFS+ compare case-insensitively and normalization-insensitively,
    other mounts compare case-insensitively alone, and compatibility
    equivalence is wider than either. The comparison below is only ever used
    to refuse, and refusing a spelling no filesystem would actually conflate
    costs a proposal nothing it can legitimately want — a path that folds onto
    a protected path and is not that path has no reason to be in this index.
    """

    return unicodedata.normalize(
        "NFC", unicodedata.normalize("NFKC", component).casefold()
    )


def _folded_parts(path: str) -> tuple[str, ...]:
    return tuple(_fold_component(component) for component in path.split("/"))


def _surface_alias_paths(surfaces: Iterable[str]) -> list[str]:
    """The protected paths one caller's configured surface patterns name.

    A pattern is either an exact path — ``scripts/check_append.py`` — or a
    ``dir/**`` prefix, which puts every file anywhere beneath ``dir`` on the
    surface. The first is protected as itself, the second as its directory,
    and the alias scan compares every prefix depth of each, so their ancestors
    come with them. This is the same derivation ``append_gate``'s
    ``_surface_directories`` makes for the enumeration, asked for names rather
    than for directories to walk: there it is the *holding* directory of an
    exact pattern that has to be listable, here it is the exact path itself
    that must not be spelled two ways in one index.
    """

    paths = set()
    for pattern in surfaces:
        named = pattern[: -len("/**")] if pattern.endswith("/**") else pattern
        if named:
            paths.add(named)
    return sorted(paths)


def assert_index_carries_no_protected_alias(
    root: pathlib.Path, spec: ChainSpec, *, surfaces: Iterable[str] = ()
) -> None:
    """The whole-index read, and the fact only it can establish about a path.

    A refusal at entry, because it says a comparison cannot be made in this
    repository rather than making one. It is asked on every path a caller
    verifies — the alias it refuses is a second committed object standing over
    a protected path, which is as true of a push as of a proposal against a
    base. ``assert_index_hides_no_working_tree_change`` below is the other
    refusal this read used to make, and it is not asked on every path; see its
    own docstring for why.

    Every reconciliation this package makes between the index and the working
    tree is by exact spelling, which is what makes it a comparison at all: the
    release root's scan matches index entries against the traversal's own
    names, and the two state paths are looked up in the index by the name the
    spec pins. Both are correct about the path they name and blind to the rest
    of the index. On a filesystem that compares names case- or
    normalization-insensitively — APFS and HFS+ by default, and any
    case-insensitive mount — an entry spelled ``Releases/README.md`` is a
    second committed object resolving to the same directory as
    ``releases/README.md``: it is under no protected path by name, so the
    release root's scan never reads it and no check reconciles it, while the
    commit under review carries it and a checkout materializes it over the
    same file. ``Ledger/official_observations.jsonl`` is the same fact for a
    state path, where the leaf's own spelling can differ too.

    Refusing is the only answer available, and it is why this runs at entry
    beside ``assert_state_path_tracked`` rather than after the comparisons:
    like that check it says a comparison cannot be made here rather than
    making one. Reconciling an alias would mean deciding which of two entries
    the one file on disk answers for, and there is nothing in the index or the
    tree that decides it. It shares that check's exception in
    ``append_gate``'s stated precedence rather than adding another.

    Fold-equality is ``_fold_component``'s, applied per component, and it is
    the protected path's own components that are compared: an entry is an
    alias when it is fold-equal to a protected path, or lies under a fold-
    equal prefix of one, while not being spelled identically there. An entry
    genuinely under a protected path keeps its own refusals — a second cased
    spelling of a release *file* is the release root's scan to answer, in the
    words it already uses, because the root itself is spelled correctly.

    ``surfaces`` is how a caller with configured surfaces of its own — the
    append gate's gate and data patterns — adds them to that set, and it is
    the whole of the difference between the two. The five paths a
    ``ChainSpec`` carries — the release root, the two state paths, the
    manifest directory and the anchor directory — are the ones this module
    reads for itself, and they are what this scan compares against on its own; a caller that classifies a proposal
    by surface patterns protects more paths than that. An index entry spelled
    ``Scripts/check_append.py`` under a gate pattern of
    ``scripts/check_append.py`` is a second committed object over the gate
    surface, and exact classification — which every surface match is — reads
    it as merely unclassified, so beside a ledger change it did not make the
    proposal mixed and the run went down the data path with the alias in the
    commit. The same holds for a ``dir/**`` prefix, whose directory is what
    the pattern protects. Nothing else changes: the paths are compared by the
    same rule at the same place, and the sentence names both spellings as it
    always did.

    Order is the five ``ChainSpec`` paths first and the surface-derived paths
    after them, sorted. An entry that aliases two protected paths at once is
    named for the first of them, and that is the sentence the trees already
    pinned before ``surfaces`` existed — ``Ledger`` is an alias of
    ``ledger/official_observations.jsonl`` at ``ledger``, not of the ``ledger``
    that ``ledger/**`` names, and it keeps saying so.

    Every prefix depth is compared, not the protected path's own depth alone.
    A protected path names each of its ancestors as much as its leaf: the
    directory ``ledger`` is where the state file is read from, and an entry
    spelled ``Ledger`` — a file standing where that directory is, or
    ``Ledger/notes.txt`` under a second spelling of it — is a second committed
    object that a name-folding checkout materialises in the same directory the
    state path is read through, or over it. Comparing only at the full depth
    saw neither: ``Ledger`` is shorter than the state path and
    ``Ledger/notes.txt`` differs from it at the leaf, so both folded onto no
    protected path at that one depth and no other check names them, since
    every one of them asks the index about a path by its exact spelling. The
    refusal names the prefix the alias is of, which is the shallowest one the
    entry misspells; an entry spelled exactly right that far down is compared
    one component deeper instead, so an ordinary path under a protected
    directory is untouched.
    """

    protected = tuple(
        dict.fromkeys(
            (
                spec.release_root_relative.as_posix(),
                spec.state_relative.as_posix(),
                spec.prefix_relative.as_posix(),
                # The manifest and anchor directories are read by this module
                # too, and on a name-folding checkout an index entry spelled
                # ``releases/Manifests/…`` beside ``releases/manifests/…`` is
                # one present file the release root's own scan passes twice
                # (peer review, Opus round one on gate g).
                spec.manifest_relative.as_posix(),
                spec.anchor_relative.as_posix(),
                *_surface_alias_paths(surfaces),
            )
        )
    )
    folded = {path: _folded_parts(path) for path in protected}
    exact = {path: tuple(path.split("/")) for path in protected}
    records = sorted(
        _all_index_entries(root), key=lambda entry: (entry.path, entry.stage)
    )
    for record in records:
        listed = record.path
        parts = tuple(listed.split("/"))
        listed_folded = _folded_parts(listed)
        for path in protected:
            for depth in range(1, len(folded[path]) + 1):
                if (
                    len(parts) < depth
                    or listed_folded[:depth] != folded[path][:depth]
                ):
                    # A prefix that does not fold onto this one cannot have a
                    # longer prefix that does, and an entry shorter than the
                    # depth has no components left to compare.
                    break
                if parts[:depth] == exact[path][:depth]:
                    # Spelled exactly right this far down; the question is
                    # whether the next component is.
                    continue
                prefix = "/".join(exact[path][:depth])
                raise ReleaseChainError(
                    f"index carries an alias of a protected path: {listed} "
                    f"(for {path} at {prefix})"
                )


def assert_index_hides_no_working_tree_change(root: pathlib.Path) -> None:
    """Refuse an index entry that tells git to stop comparing it to the tree.

    An entry marked *assume-unchanged* (``CE_VALID``) or *skip-worktree*
    (``CE_SKIP_WORKTREE``) tells git to stop comparing that path against the
    working tree. ``git diff`` then reports nothing for a file that has been
    rewritten on disk, and a caller that classifies a proposal from ``git
    diff`` is taking that silence for evidence: the ledger could be rewritten
    under an assume-unchanged entry, a gate file added beside it, and the
    proposal classified as gate-only — which returns before the ledger, the
    frozen prefix, the row bindings and the release history are read at all.
    Neither bit is something a proposal can want here: both exist to let a
    working copy diverge from the index on purpose, and this verifier's whole
    subject is whether they agree. Any entry carrying either refuses, because
    the classification ``git diff`` performs covers every path in the tree and
    not only the protected ones — which is why this is a whole-index read and
    could not have been a check on a path.

    What it is *about* is that classification, and nothing else here consults
    ``git diff`` at all. ``append_gate`` runs it on the path that classifies —
    the base-ref path — and not on the push path, which has no base to diff
    against, performs no classification, and answers for the two state files
    and the release tree by reading them. Running it there refused a valid
    push verification for a mechanism that path never uses. The index flags
    cannot be turned off per command the way the caching settings can
    (``WORKING_TREE_SCAN_OPTIONS``), because they are recorded in the index
    itself, so this stays a refusal rather than becoming an override.

    It is a separate function from the alias refusal above for that reason and
    that reason alone: the two are asked on different paths, and a docstring
    that has to say which is which cannot say it about one function. The cost
    is a second read of the same index on the path that runs both, which is
    where the caller wants both anyway. Ordering is unchanged: the alias
    refusal is asked first, so a tree an alias already refused keeps that
    refusal and this adds nothing to a message anyone has seen.
    """

    for record in sorted(
        _all_index_entries(root), key=lambda entry: (entry.path, entry.stage)
    ):
        if record.hidden:
            raise ReleaseChainError(
                f"index entry for {record.path} is marked assume-unchanged or "
                "skip-worktree, which hides working-tree changes from git"
            )


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
        for record in _index_entries(root, ancestor):
            if record.path == ancestor:
                raise ReleaseChainError(
                    f"state path {path} has an indexed ancestor {ancestor} "
                    f"({record.mode})"
                )
    entries = [
        record for record in _index_entries(root, path) if record.path == path
    ]
    if not entries:
        raise ReleaseChainError(
            f"state path {path} is absent from the candidate index"
        )
    # The same fact assert_index_agrees_with_tree refuses, in its words: a
    # conflicted merge records stages 1-3 and no single mode for the path.
    if len(entries) > 1 or entries[0].stage != "0":
        raise ReleaseChainError(f"candidate index holds an unmerged entry at {path}")
    if entries[0].mode not in {"100644", "100755"}:
        raise ReleaseChainError(
            f"state path {path} has a non-regular index entry: {entries[0].mode}"
        )
    # Last, because an intent-to-add entry is stage 0 at 100644 and passes
    # every question above: there is nothing else left to say about it. It
    # records no content, and a commit made from this index deletes the path.
    if entries[0].intent_to_add:
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
        record for record in _index_entries(root, path) if record.path == path
    ]
    if not entries:
        return
    # Stages 1-3 are a conflicted merge: the index records no single mode for
    # this path, so there is nothing for the working tree to agree with.
    if len(entries) > 1 or entries[0].stage != "0":
        raise ReleaseChainError(f"candidate index holds an unmerged entry at {path}")
    index_mode = entries[0].mode

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
        record for record in _index_entries(root, path) if record.path == path
    ]
    if not entries:
        raise ReleaseChainError(
            f"existing release file was removed from the candidate index: {path}"
        )
    if len(entries) > 1 or entries[0].stage != "0":
        raise ReleaseChainError(f"candidate index holds an unmerged entry at {path}")
    if entries[0].mode not in {"100644", "100755"}:
        raise ReleaseChainError(
            f"candidate index records a non-regular entry at {path}: "
            f"{entries[0].mode}"
        )
    # After those, for the reason the tracked-state check has it last: an
    # intent-to-add entry answers every one of them like an ordinary tracked
    # file, and records nothing. ``git rm --cached`` followed by ``git add
    # -N`` leaves an entry where the check above looks for one, and a commit
    # made from this index still deletes the release file.
    if entries[0].intent_to_add:
        raise ReleaseChainError(
            f"index entry for {path} is intent-to-add and records no content"
        )


def _blob_id(root: pathlib.Path, payload: bytes) -> str:
    """The object id git would record for exactly these bytes as a blob.

    Asked of git in the repository under review rather than computed here, so
    the repository's own object format decides: a SHA-256 repository names its
    blobs with SHA-256, and a digest this package chose would compare against
    nothing. ``--stdin`` with no ``--path`` applies no filter — the bytes are
    named as they stand, which is the comparison ``assert_index_content_bound``
    wants and the one this package's byte comparisons already assume (an
    existing release file must equal its base blob byte for byte, so a checkout
    whose content is filtered on the way into the index refuses there already).
    """

    completed = _git_run(root, ["hash-object", "-t", "blob", "--stdin"], stdin=payload)
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ReleaseChainError(f"cannot hash the verified bytes: {diagnostic}")
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:  # pragma: no cover - git prints hex
        raise ReleaseChainError("cannot hash the verified bytes") from exc


def assert_index_content_bound(
    root: pathlib.Path,
    base_commit: str,
    relative: pathlib.PurePosixPath | str,
    verified: bytes,
) -> None:
    """Require the index to record the content this verdict actually read.

    Every reconciliation above compares stage, mode and type. None of them
    compares *content*: the parse discarded the object id, and the ledger, the
    frozen prefix, the base release files and the release verification all read
    the working tree. So a protected file could be rewritten, staged, and then
    restored on disk — the rewrite is in the index and nowhere else — and the
    whole data path ran over the restored bytes and returned an acceptance,
    while the commit made from that index carries the rewrite nothing here ever
    looked at. ``git diff`` sees it (the index differs from the base), which is
    why the surface classification catches it for the gate-only exit; but on
    the data path the classification is not a verdict about content, and every
    check that is a verdict about content read the disk.

    So, for one path: let ``I`` be the blob the index records for it, ``B`` the
    blob the base tree records (absent for a file this proposal adds), and
    ``H`` the blob id of the bytes the caller verified. ``I == B`` means the
    commit under review does not change this path at all and the working tree's
    difference from it is the proposal — the upstream verifier's model, and the
    shape of every differential-harness case, where the fixture commits with
    ``git add -A`` and then mutates the working tree alone. ``I == H`` means
    the commit carries exactly the bytes this verdict read. Anything else is a
    third content no check here has seen, and it refuses.

    ``verified`` must be the bytes the caller's own comparison consumed, not a
    fresh read: re-reading the path here would bind the index to a second read
    and leave the first unbound, which is the hole rather than the fix.

    The caller supplies a base commit, so this runs only where there is a
    commit under review to compare against — the base-ref path. On the push
    path there is no base, no ``B``, and no diff this could qualify; nothing
    calls it there.

    Exactly one stage-0 entry is required, and every caller has already
    established that (``assert_state_path_tracked`` for the state files,
    ``assert_release_file_still_indexed`` for a base release file,
    ``assert_release_root_index_regular`` for the release root's own entries).
    A path with no entry at all is an untracked file the proposal adds without
    staging, which is what the harness's own release files are; there is no
    recorded content to disagree with, and the checks that care about a missing
    entry refuse in their own words. Both return here rather than inventing a
    second answer for a fact already answered.

    Like the two index checks beside it this runs after the comparisons it
    qualifies, so a file whose working-tree bytes or mode already differ from
    the base keeps the upstream verifier's refusal and nothing pre-existing is
    pre-empted.
    """

    path = _exact_relative(relative)
    entries = [
        record for record in _index_entries(root, path) if record.path == path
    ]
    if len(entries) != 1 or entries[0].stage != "0":
        return
    recorded = entries[0].object_id
    base_entry = git_tree_entries(root, base_commit, path).get(path)
    if base_entry is not None and recorded == base_entry.object_id:
        return
    if recorded == _blob_id(root, verified):
        return
    raise ReleaseChainError(
        f"candidate index records different content for {path} than the "
        "working tree this verdict read"
    )


def _assert_no_symlinked_release_component(root: pathlib.Path, listed: str) -> None:
    """Refuse an indexed release path reached through a linked directory.

    The reconciliation below used to ask whether an indexed path is a regular
    file on disk, and ``is_file()`` answers about whatever the whole name
    resolves to — every intermediate component followed. The traversal that
    would have seen those components does not follow them: ``rglob`` yields a
    symlinked directory and does not descend it, and the scan skips it. So an
    index entry under ``releases/vendor``, with ``vendor`` a link to a
    directory outside the checkout, was in no walk, was reported as present
    and regular, and its content — no part of the candidate tree, no part of
    what the base can be diffed against — stood in for the release file the
    commit records.

    That reconciliation now compares the traversal's own spellings and
    resolves nothing, so such an entry is refused either way. This walk is
    kept, and kept first, because the fact it names is the specific one: the
    path is served through a link, which is why no walk reached it, and that
    is worth saying instead of reporting the entry as absent. It is said in
    the words the state paths' walk uses for the same fact.
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
    filesystem — APFS and HFS+ by default, and any case-insensitive mount —
    answer for a differently spelled entry:
    with ``releases/README.md`` and ``releases/README.MD`` both in the index
    and one file on disk, one file answered both questions, so one committed
    release object was in no enumeration and was never verified while the
    reconciliation called the two sides agreed. The traversal that has to
    find them all is what the comparison is against: it yields each regular
    file spelled as the directory spells it, and an index entry has to appear
    in that set exactly.

    That is the standard this package already holds release files to, rather
    than a new one. ``_working_release_files`` keys the base comparison by
    the same traversal's spellings, and ``verify_release_history_immutable``
    looks a base entry up by the name git recorded, so a release path the
    walk spells differently from the index — a name the checkout stored in
    another Unicode normalisation, or one under a directory the walk cannot
    list — is already refused against a base, as ``existing release file was
    deleted relative to {commit}``, before any of this. What this brings to
    the same standard is the candidate index and the push path, which had
    neither comparison.

    So the refusal means what it says under the spelling this package
    compares by, and it is deliberately fail-closed: a checkout whose release
    tree the traversal cannot match to the commit, whichever way round, is
    not one this verifier can answer for. The two rights are not in tension
    with the descent above, either. Enumerating a directory needs read
    permission because listing it is the operation; descending a known path
    needs only the right to traverse, which is why the state walk asks for no
    more than that.

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
    for record in sorted(
        _index_entries(root, release_root),
        key=lambda entry: (entry.path, entry.stage),
    ):
        listed = record.path
        if record.stage != "0":
            raise ReleaseChainError(
                f"candidate index holds an unmerged entry at {listed}"
            )
        if record.mode not in {"100644", "100755"}:
            raise ReleaseChainError(
                "release root carries an unsupported index entry: "
                f"{listed} ({record.mode})"
            )
        # Beside the mode check, because an intent-to-add entry passes it: a
        # release path added with ``git add -N`` is recorded at 100644 with
        # no content, so the reconciliation below would find it on disk and
        # call the pair agreed while the commit carries nothing for it.
        if record.intent_to_add:
            raise ReleaseChainError(
                f"index entry for {listed} is intent-to-add and records no content"
            )
        modes[listed] = record.mode
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
    # all. Its parents are walked first so an entry served through a
    # symlinked directory is named as that rather than reported as absent,
    # which is the more specific of the two true things to say about it.
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
        candidate_bytes = current.read_bytes()
        if candidate_bytes != git_blob_bytes(root, entry):
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
        # And what it records has to be the bytes just compared. Both
        # comparisons above read the working tree; the index is what the
        # commit carries, and a rewrite staged and then restored on disk left
        # the mode equal, the bytes equal, the entry present, and the commit
        # under review changing a file this pass calls immutable.
        assert_index_content_bound(root, commit, relative, candidate_bytes)
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
