"""RFC 3161 witness verification with consumer-committed trust specifications.

The witness and trust-transition machinery is a mechanical port of
``MaxGhenis/brier``'s ``scripts/verify_record_chain.py`` at commit
``4b9e7be22debc8349e76b8bdfe5a0fe18ed31a3f``.  Ported refusal text is
retained verbatim.  The extraction changes only where trust enters: bundle
byte pins, TSA identities, anchor membership, and clock-skew limits arrive
through a frozen :class:`TsaSpec` supplied by consumer code.  This module
ships no repository-specific trust defaults and performs no chain walk or
producer signature verification.

The port is stricter than the baseline in fourteen places, each refusing an
input the pinned tree never presents and so each outside the differential
contract: a record under witness that is not a readable regular file, which
the baseline let raise out of the hash; a legacy witness over a bundle
configuring more than one anchor; a bundle configuring an anchor the spec
carries no identity for, or one whose
declared root SPKI or allowed signers differ from that identity, or whose
referenced root material fails the ported material checks or carries an SPKI
other than the identity's (all compared at load for every anchor, not only
the one a witness selects); a pinned root PEM that OpenSSL's own parser
(``openssl storeutl -noout -certs``) does not count exactly one certificate
in, or whose certificates it cannot count at all -- the declared certificate
hash and SPKI describe only the first certificate, while a ``-CAfile`` trusts
every certificate it is given, so with exactly one counted what the identity
pins is the whole of what the two verifications trust; a bundle whose
configured anchors are not exactly the anchors the spec's identities for that
bundle name, so an identity the consumer scoped to it cannot be quietly
absent from it; a bundle two of whose anchors allow the same signer, which is
one authority under two names -- the ported allowed-signer check binds a
token to the signers of the anchor its outcome selects, so a shared signer is
exactly what lets one RFC 3161 response satisfy two outcomes, while a shared
root with disjoint signers does not and stays allowed (one check on the
anchors covers the identities the spec scopes to the bundle as well, whose
signer sets each anchor's has just been required to equal); a pending bundle
anchor reusing an active anchor ID under a different code-pinned root, which
is a new authority and so must carry a supplemental outcome before the
transition can activate it -- the ported supplemental-outcome refusal,
reaching a case the baseline let through because it took the ID alone for the
identity; an unavailable witness of either schema whose reason is not a
string, or that carries token evidence at the witness level (the v2
per-anchor outcome has always refused both); an unavailable legacy witness
that names a bundle by any of its three claim fields, whose claim is then
resolved and counted where the baseline ignored those fields; and a v2
witness that offers one RFC 3161 timestamp under two of its outcomes, counted
across the primary and supplemental outcomes together so that one response
cannot stand for a bundle configuring more than one anchor -- counted twice
over: the file an outcome names, refused before that outcome's token is
verified and so ahead of the ported refusals inside
``verify_timestamp_token``, and the ``TSTInfo`` the authority signed, refused
where that verification returns.  The second rule is what the first cannot
be: nearly everything around a signed ``TSTInfo`` is the producer's to
rewrite -- the unsigned ``PKIStatusInfo`` wrapper, and the ``certificates``,
``crls`` and ``unsignedAttrs`` a ``SignedData`` carries outside its signature
-- so one issuance has many valid encodings and a rule counting files counts
encodings.  Both are admissible because no witness in the pinned tree offers
one timestamp twice.

The pinned root behind the two counting refusals is read from the repository
exactly once, and every check runs on those bytes: the PEM hash over the
bytes themselves, the count and the certificate identity by running OpenSSL
on a private byte-for-byte copy of them, and the two ``-CAfile``
verifications on that same copy rather than on the path.  So a writer who
substitutes another file between validation and use -- the plain form of a
``TRUSTED CERTIFICATE`` that rejects the timestamping purpose, or a second
authority appended after the count -- changes what is on disk and not what is
trusted; and because nothing is re-encoded, a pinned root's auxiliary trust
settings apply exactly as pinned.  This module's own refusals go on naming
the repository path.

The record under witness is read exactly once as well, and those same bytes
answer every question asked about it: the digest its sidecar has to match,
the trust-bundle updates it carries, the creation claims a token's genTime is
measured against, and -- through a private copy handed to ``-data`` -- the
imprint ``openssl ts -verify`` recomputes.  Four opens of one pathname
described four instants of a mutable file, and only the last of them decided
whether a token covered the record at all: a writer could leave the witnessed
record in place for the digest and the time checks, substitute another for
that read with a token genuinely stamped over the substitute, and put the
first back, and the evidence then named a record OpenSSL had never seen.

The claimed response is read once for the same reason.  Its ``tokenSha256``
was taken from one open of its pathname and ``openssl ts -reply`` and
``openssl ts -verify`` then made two more, so the digest reported as evidence
described the file at an earlier instant than the one the verifications read;
the bytes that were hashed are now the bytes both of them are given.  That
digest identifies a file and not a timestamp, which is why
:class:`TokenEvidence` also carries the digest of the signed ``TSTInfo``.

Because OpenSSL is given the copies and never a repository path, the command
text quoted in a failure names temporary files; every refusal of this
module's own still names the record, the token and the root as the repository
spells them.

The port also corrects one baseline defect: ``_decode_oid`` read only the
first octet of a policy OID as its combined first two arcs, so a first
subidentifier spanning several octets (2.999.3) decoded wrongly.

And it has a prerequisite the baseline did not: ``openssl`` on the path must
be OpenSSL 3.0 or newer, checked once per process before any trust bundle is
read.  The certificate count above is OpenSSL's own ``storeutl``, and
verifying an available token passes ``openssl cms -verify -no-CAstore``,
whose default CA store arrived in OpenSSL 3.0; LibreSSL -- the stock
``/usr/bin/openssl`` on macOS -- has neither at any version.  A machine that
fails the check is refused there, on the banner it reports, rather than told
that its root PEM cannot be counted or that OpenSSL does not know an option;
no portable count is offered in its place.  The floor was 1.1.1 until a
review observed that ``-no-CAstore`` made the documented minimum a version
which passed the check and then refused every valid witness.

``tests/test_tsa.py`` binds all of these.  Because every bundle anchor is now
identity-checked at load, ``_select_anchor``'s own identity refusal can no
longer fire from within this module; its text is kept verbatim, as ported,
and as defence in depth.
"""

from __future__ import annotations

import functools
import hashlib
import io
import json
import os
import re
import stat
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
    """All repository-specific TSA trust, committed in consumer code.

    How a timestamp authority's own signer rotation is carried.  An
    identity's :attr:`TsaIdentitySpec.signer_spki_sha256` must equal, as a
    set, the ``allowedSigners`` of the anchor in the bundle it is scoped to
    (see ``_select_anchor``), and a bundle is immutable: pinned by bytes, at
    a versioned path that refuses reuse with new bytes.  So a fingerprint
    cannot be added beside the old one in an existing identity without
    invalidating the bundle already committed.  A rotation is a new bundle
    version whose anchor lists the new signer, plus a new identity scoped to
    that bundle with the same set, activated by a trust transition.  Version
    order does the retiring: a v2-schema witness must use the newest active
    bundle, so the superseded signer stops vouching for new records once the
    new bundle is active, while records that named the old bundle keep
    verifying under it.  Verification therefore splits into eras by bundle
    version, each carried explicitly in the consumer spec.  Within one
    bundle several signers may be allowed at once -- the set has no
    singleton constraint -- which is concurrent authorization, not
    rotation.  What is absent is any time interval: nothing records when a
    signer was valid, only which bundle allowed it.  Compare producer-key
    legacy generations in :mod:`receipt.sign`, where retired keys are named
    separately and vouch only where the caller asks for immutable
    pre-rotation history.
    """

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

    def identities_for(self, bundle_id: str) -> set[str]:
        """Return the anchor IDs of every identity scoped to one bundle."""

        return {
            identity.anchor_id
            for identity in self.tsa_identities
            if identity.bundle_id == bundle_id
        }

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
    #: SHA-256 of the DER ``TSTInfo`` the authority signed, as ``openssl cms
    #: -verify`` wrote it out -- the timestamp itself, not the file it arrived
    #: in and not the CMS envelope around it.  Both of those are largely
    #: unauthenticated: a ``TimeStampResp``'s ``PKIStatusInfo`` wrapper is
    #: unsigned, and a ``SignedData``'s ``certificates``, ``crls`` and
    #: ``unsignedAttrs`` are outside the signature, so one issuance has many
    #: valid encodings with different digests.  Its ``TSTInfo`` has one, and
    #: two issuances differ in it by serial number and genTime.
    signed_timestamp_sha256: str
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


def _record_payload(data: bytes, path: Path) -> dict[str, Any]:
    """``load_json``'s parse and its two refusals, over bytes already read.

    The record under witness is read once and then asked several questions --
    its digest, its creation claims, the trust-bundle updates it carries -- so
    the parse has to happen over that one read rather than through a fresh
    open each time.  Both refusals are ``load_json``'s own, word for word, and
    ``path`` is still the repository file every one of them names.

    The decode is ``Path.read_text``'s own -- a default ``TextIOWrapper`` over
    the bytes, so the same locale encoding and the same universal-newline
    translation, rather than a ``bytes.decode`` that would resemble it.  A
    ``json`` error reports an offset into the decoded string, so a record with
    CRLF endings rendered a different ``cannot read JSON`` message under
    ``bytes.decode`` than ``load_json`` gives for the same file (peer review,
    fourth gate round four); imitating a decoder is how the two came apart,
    and using it is how they stay together.
    """

    try:
        value = json.loads(io.TextIOWrapper(io.BytesIO(data)).read())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
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


#: The first line of ``openssl version`` for a build this module can use.
_OPENSSL_VERSION_RE = re.compile(r"\AOpenSSL ([0-9]+)\.([0-9]+)\.([0-9]+)")

#: OpenSSL 3.0 or newer, for two reasons.  Verifying an available token runs
#: ``openssl cms -verify ... -no-CAstore``, and the default CA store that
#: option turns off is the OSSL_STORE-backed ``X509_LOOKUP_store`` added in
#: OpenSSL 3.0 (its own CHANGES file), so an older ``openssl`` has no such
#: option: with the floor at 1.1.1 this module's documented minimum was a
#: version that passed the check and then refused every valid witness on an
#: unknown option (peer review, fourth gate round four).  And
#: ``_certificate_count`` reads a pinned root through ``openssl storeutl``,
#: whose answer for a file holding no PEM object this module pins from
#: behaviour observed on 3.0 and 3.6 and never on 1.1.1.  ``storeutl`` itself
#: arrived in 1.1.1 (``openssl-storeutl(1)``'s own HISTORY), so it is not what
#: sets the floor either.
_MINIMUM_OPENSSL = (3, 0, 0)


def _supported_openssl_version(line: str) -> bool:
    """Whether ``line`` is an ``openssl version`` banner this module can use.

    True only for OpenSSL 3.0 or newer.  LibreSSL -- the stock
    ``/usr/bin/openssl`` on macOS -- announces itself as ``LibreSSL 3.3.6``
    and never matches whatever its version number, because it is a different
    implementation and has neither ``storeutl`` nor ``-no-CAstore`` at any
    version.
    """

    match = _OPENSSL_VERSION_RE.match(line)
    if match is None:
        return False
    return tuple(int(part) for part in match.groups()) >= _MINIMUM_OPENSSL


@functools.cache
def _require_supported_openssl() -> None:
    """Refuse, once per process, an ``openssl`` this module cannot rely on.

    Loading any trust bundle counts a pinned root's certificates with
    ``openssl storeutl``, which LibreSSL does not have.  Without this a
    machine whose ``openssl`` is LibreSSL refused a perfectly good
    one-certificate bundle -- and an unavailable witness that verifies no
    token at all -- with a message that blamed the file (peer review, fourth
    gate round three).  Gated on the version line rather than by probing for a
    subcommand or an option, so the refusal names the real problem, and run
    before any bundle is trusted rather than at the point a count is wanted.

    The floor is what ``_MINIMUM_OPENSSL`` says and not what ``storeutl``
    alone would need: verifying a token also passes ``-no-CAstore``, so a
    check that admitted 1.1.1 admitted a build that then refused every valid
    witness on an unknown option (peer review, fourth gate round four).

    No portable counting path is offered instead: a pattern of ours miscounted
    three review rounds running, and the count has to be the same parser
    ``-CAfile`` loads.

    Cached because it is a property of the machine and not of the input.  Run
    from ``_certificate_count``, so that no path to a count can skip it, and
    from the top of ``_load_trust_bundle``, so that the refusal reaches an
    auditor as itself rather than wrapped in that function's message about an
    anchor's root material.  A missing ``openssl`` raises the ported
    "openssl is required to verify RFC 3161 tokens" from ``_run_openssl``,
    which is left to propagate.

    ``tests/test_tsa.py`` binds the parser one banner at a time by
    substituting the answer to ``openssl version``, which says what this
    module accepts but nothing about what the accepted build can do.  The
    exercise of the floor itself is the project's CI job: it runs the whole
    offline suite -- every token path in it -- against whatever ``openssl``
    the ``ubuntu-latest`` image carries, which is a real build (3.0.13 on the
    image at the time of writing) and not a substituted banner.
    """

    banner = _run_openssl(["version"])
    assert isinstance(banner, str)
    lines = banner.splitlines()
    line = lines[0].strip() if lines else ""
    if not _supported_openssl_version(line):
        raise TsaError(
            "receipt requires OpenSSL 3.0 or newer as `openssl` on the path; "
            f"found: {line}"
        )


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
    # Every subidentifier, the first included, is base-128 with continuation
    # bits, and the first one carries the first two arcs combined (X*40+Y for
    # X in 0..1, 80+Y for X = 2). The baseline read only the first octet as
    # that combined value, so 2.999.3 (88 37 03) decoded as 2.56.55.3: a
    # legitimate policy refused, or a disallowed one aliased onto an allowed
    # spelling (peer review). Decoded in full here; a corrected defect, not a
    # stricter rule, and recorded as such in the module docstring.
    subidentifiers: list[int] = []
    current = 0
    continuation = False
    for byte in data:
        current = (current << 7) | (byte & 0x7F)
        continuation = bool(byte & 0x80)
        if not continuation:
            subidentifiers.append(current)
            current = 0
    if continuation:
        raise TsaError("truncated policy OID in RFC 3161 token")
    first = subidentifiers[0]
    if first < 40:
        values = [0, first]
    elif first < 80:
        values = [1, first - 40]
    else:
        values = [2, first - 80]
    values.extend(subidentifiers[1:])
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
    # Before anything about the bundle is read.  Every anchor's root is
    # counted by `openssl storeutl` below, so _certificate_count runs this
    # too and no caller of it can skip the check; running it first here as
    # well is what keeps the refusal from arriving wrapped in a message about
    # an anchor's root material, which is the message the finding was about.
    _require_supported_openssl()
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
    # Every anchor the bundle configures must also be pinned in verifier code.
    # The spec only requires one identity per bundle, so a producer who could
    # append an anchor to a bundle -- or ship a bundle the consumer pinned
    # loosely -- would otherwise get an authority the consumer never named,
    # whose root and signer are checked against the bundle alone.  Checked
    # last, so an altered bundle still binds the commitment mismatch above.
    bundle_id = str(payload["bundleId"])
    # One private directory for the whole loop: _root_material writes each
    # anchor's root snapshot into it, reads the identity out, and this call
    # never needs the copy again.
    with tempfile.TemporaryDirectory(prefix="thesis-tsa-bundle-") as snapshots:
        _check_bundle_anchors(
            records, anchors, bundle_id, Path(snapshots), spec=spec
        )
    return path, payload


def _check_bundle_anchors(
    records: Path,
    anchors: list[Any],
    bundle_id: str,
    snapshot_dir: Path,
    *,
    spec: TsaSpec,
) -> None:
    """Bind every anchor of one bundle to the verifier code's own pins."""

    anchor_ids: set[str] = set()
    declared_signers_by_anchor: dict[str, set[str]] = {}
    for anchor in anchors:
        anchor_id = str(anchor["id"])
        anchor_ids.add(anchor_id)
        identity = spec.identity(bundle_id, anchor_id)
        if identity is None:
            raise TsaError(
                f"TSA anchor {anchor_id} in bundle {bundle_id} has no "
                "verifier code identity"
            )
        # Existence is not agreement. _select_anchor compares an anchor's
        # root SPKI and allowed signers with its identity, but only for the
        # anchor a witness selects; a rotation bundle reuses the active
        # anchor id and root, which _supplemental_candidates then skips, and
        # a transition could activate a bundle whose anchor contradicts the
        # identity pinned for it without any selection ever comparing the
        # two (peer review). Compared here for every anchor, at load, on the
        # declared values; _select_anchor still checks the certificate itself.
        root = anchor.get("rootCertificate")
        declared_root = root.get("spkiSha256") if isinstance(root, dict) else None
        if declared_root != identity.root_spki_sha256:
            raise TsaError(
                f"TSA anchor {anchor_id} in bundle {bundle_id} declares a root "
                "SPKI that differs from its verifier code identity"
            )
        signers = anchor.get("allowedSigners")
        declared_signers = (
            {signer.get("spkiSha256") for signer in signers if isinstance(signer, dict)}
            if isinstance(signers, list)
            else set()
        )
        if declared_signers != set(identity.signer_spki_sha256):
            raise TsaError(
                f"TSA anchor {anchor_id} in bundle {bundle_id} declares allowed "
                "signers that differ from its verifier code identity"
            )
        declared_signers_by_anchor[anchor_id] = {
            str(fingerprint) for fingerprint in declared_signers
        }
        # Declared values agreeing with the identity is not the root material
        # agreeing with either. The material checks lived only in
        # _select_anchor, which a pending rotation's reused anchor id never
        # reaches (peer review, fresh gate round two). Run here for every
        # anchor; the ported refusal text is carried inside a new load-time
        # message so the ported message itself neither moves nor changes.
        try:
            material = _root_material(records, anchor, snapshot_dir=snapshot_dir)
        except TsaError as exc:
            raise TsaError(
                f"TSA anchor {anchor_id} in bundle {bundle_id} references root "
                f"material that fails validation: {exc}"
            ) from exc
        if material.identity["spkiSha256"] != identity.root_spki_sha256:
            raise TsaError(
                f"TSA anchor {anchor_id} in bundle {bundle_id} references a root "
                "whose SPKI differs from its verifier code identity"
            )
    # The loop above binds the bundle's anchors to the spec; this binds the
    # spec's identities to the bundle. Without it the agreement is one-way:
    # an identity scoped to this bundle whose anchor the bundle does not
    # configure is simply ignored, so a consumer that pins two authorities
    # verifies a corpus whose bundle carries one, and the second authority it
    # committed to never has to answer for anything (peer review).
    identity_ids = spec.identities_for(bundle_id)
    if anchor_ids != identity_ids:
        raise TsaError(
            f"TSA bundle {bundle_id} configures anchors {sorted(anchor_ids)} "
            f"but verifier code pins identities for {sorted(identity_ids)}"
        )
    # No two anchors of one bundle may allow the same signer.  The ported
    # allowed-signer check binds a token to the signers of the anchor its
    # outcome selects, so a token signed under one anchor's signer cannot
    # satisfy another whose signers do not include it -- and a shared signer
    # is exactly what lets it.  Two anchors with distinct ids and endpoints
    # but the same root and the same allowed signer are one authority under
    # two names, and one RFC 3161 response, offered under both outcomes,
    # covered a two-anchor bundle on its own (peer review, fourth gate round
    # three).  A shared *root* with disjoint signers stays allowed for that
    # same reason: the signer, not the root, is what a token is bound to.
    #
    # Checked on the anchors only.  Each anchor's declared signer set was
    # just compared with its identity's, and the anchor set and the identity
    # set were just required to be equal, so the identities the spec scopes
    # to this bundle carry exactly these signer sets and one check covers
    # both.
    signer_owner: dict[str, str] = {}
    for anchor_id, fingerprints in declared_signers_by_anchor.items():
        for fingerprint in sorted(fingerprints):
            other = signer_owner.setdefault(fingerprint, anchor_id)
            if other != anchor_id:
                first, second = sorted((other, anchor_id))
                raise TsaError(
                    "TSA anchors share an allowed signer: "
                    f"{first}, {second}: {fingerprint}"
                )


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


#: The line ``openssl storeutl`` ends a listing with.
_STOREUTL_TOTAL_RE = re.compile(r"Total found: ([0-9]+)\Z")


def _certificate_count(path: Path, *, pinned_path: Path | None = None) -> int:
    """Return how many certificates OpenSSL itself reads out of ``path``.

    The question a pinned root has to answer is how many certificates
    ``-CAfile`` will trust, and only OpenSSL's own parser answers it.  Two
    review rounds each found a construction a pattern of ours miscounted --
    labels ``-CAfile`` loads besides ``CERTIFICATE``, then a BEGIN marker
    followed by a vertical tab or a form feed, which OpenSSL strips and an
    end-of-line anchor does not, and a UTF-8 byte-order mark before the first
    marker, which OpenSSL skips -- so this asks ``openssl storeutl -noout
    -certs``, whose ``-certs`` filter is the same population ``-CAfile``
    loads, and reads the total off the end of its listing.

    Refuses rather than guesses when there is no total to read.  A file
    holding no PEM object at all gets ``Total found: 0`` from OpenSSL 3.0
    (so the count is zero and the caller's one-certificate rule refuses)
    and no total at all from OpenSSL 3.6 (so this refuses as uncountable);
    a file holding an object the store loader cannot decode fails
    outright on both.  None of these is a file a pinned root may be.

    ``path`` is the private snapshot ``_root_material`` took of the pinned
    root, so ``pinned_path`` says which repository file the refusals should
    name; the OpenSSL command quoted inside a wrapped failure still names the
    snapshot, because that is the file OpenSSL was given.
    """

    _require_supported_openssl()
    blamed = path if pinned_path is None else pinned_path
    try:
        listing = _run_openssl(["storeutl", "-noout", "-certs", str(path)])
    except TsaError as exc:
        raise TsaError(
            f"pinned TSA root PEM certificates could not be counted: {blamed}: {exc}"
        ) from exc
    assert isinstance(listing, str)
    match = _STOREUTL_TOTAL_RE.search(listing.strip())
    if match is None:
        raise TsaError(
            f"pinned TSA root PEM certificates could not be counted: {blamed}: "
            "openssl storeutl reported no total"
        )
    return int(match.group(1))


#: Flags for the one read of a file this module goes on to judge and trust: no
#: descriptor inherited across an exec, and no symlink followed at open time
#: where the platform has the flag.
_ONE_READ_FLAGS = (
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
)


def _read_file_once(path: Path, missing: str) -> bytes:
    """Read every byte of ``path`` through one descriptor, or refuse.

    The three files this module both checks and then acts on -- a pinned root,
    the record under witness, and a claimed RFC 3161 response -- are each read
    exactly once through this, so that the bytes an auditor is told about are
    the bytes that were judged.  Reading a pathname twice tells an auditor what
    it held at two separate instants and no more.

    ``missing`` is the caller's own refusal for a path that is not a readable
    regular file, so this adds no message of its own and no caller's wording
    moves.  The descriptor is opened with ``O_NOFOLLOW`` where the platform
    defines it and ``fstat``ed rather than ``stat``ed, so the regular-file rule
    is decided about the same object the bytes come from; each caller keeps its
    path-level check in front, which means a race can change which of the two
    identical refusals fires but never the message.
    """

    try:
        descriptor = os.open(path, _ONE_READ_FLAGS)
    except OSError as exc:
        raise TsaError(missing) from exc
    chunks: list[bytes] = []
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise TsaError(missing)
        while True:
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError as exc:
        raise TsaError(missing) from exc
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _read_witnessed_record(path: Path) -> bytes:
    """Read the record under witness once, and return what the token is about.

    The witnessed record was consumed through four separate opens of one
    pathname: ``verify_witness`` hashed it for the digest the sidecar has to
    match and parsed it for the trust-bundle updates it carries,
    ``verify_timestamp_token`` parsed it again for its creation claims, and
    ``openssl ts -verify -data`` then read it a fourth time to recompute the
    imprint the token signs.  Only that last read decides whether the token
    covers the record; a writer who left the witnessed record in place for the
    digest and the time checks and substituted another for the ``-data`` read
    -- with a token genuinely stamped over the substitute -- got evidence
    naming the first record for a timestamp OpenSSL took over the second
    (peer review, fourth gate round four).  One read closes the gap: these
    bytes are hashed, parsed, and handed to OpenSSL, and nothing re-reads the
    path.

    The refusal is new: the baseline let a missing record raise ``OSError``
    out of the hash, and the pinned tree presents no such record because the
    chain walk enumerates the files it then verifies.
    """

    missing = f"witnessed record is missing or not a regular file: {path}"
    if not path.is_file() or path.is_symlink():
        raise TsaError(missing)
    return _read_file_once(path, missing)


def _read_pinned_root(path: Path) -> bytes:
    """Read a pinned root once, and return the only bytes anything may judge.

    ``_root_material`` used to open this repository path five separate times
    -- once to count its certificates, once to hash it, and three times to
    describe its first certificate -- and ``verify_timestamp_token`` then
    opened it twice more as a ``-CAfile``.  Between any two of those a writer
    with access to the repository could substitute another file, so what was
    validated need not
    be what was trusted: a ``TRUSTED CERTIFICATE`` that rejects the
    timestamping purpose could become the plain form of the same certificate
    with the rejection gone (every declared hash still matching), or a
    counted one-certificate file could become a two-certificate one, and the
    verifications trusted whatever was on disk at that instant (peer review,
    fourth gate round three).  One read closes the gap: the bytes returned
    here are what gets hashed, counted, described and trusted, and nothing
    re-reads the path.

    The path-level check in ``_root_material`` stays in front of this and
    keeps its wording, which ``_read_file_once`` repeats for the descriptor.
    """

    return _read_file_once(
        path, f"pinned TSA root is missing or not a regular file: {path}"
    )


def _write_root_snapshot(directory: Path, pem: bytes) -> Path:
    """Copy the bytes read from a pinned root into a private file.

    OpenSSL takes a path, not bytes, so the count, the certificate identity
    and the two ``-CAfile`` verifications all need a file; this is the only
    file any of them is given.  ``directory`` is a private temporary
    directory (``tempfile.mkdtemp`` makes it 0700) owned by the caller, and
    the copy is written 0600.  It is a byte-for-byte copy: nothing is
    re-encoded, so a pinned ``TRUSTED CERTIFICATE``'s auxiliary trust
    settings survive into it exactly as pinned.
    """

    snapshot = directory / "pinned-root.pem"
    descriptor = os.open(
        snapshot,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        written = 0
        while written < len(pem):
            written += os.write(descriptor, pem[written:])
    finally:
        os.close(descriptor)
    return snapshot


@dataclass(frozen=True)
class PinnedRootSnapshot:
    """One pinned root as read once, and what those bytes were found to be.

    ``pem`` is the exact byte string every check in ``_root_material`` ran
    on, ``identity`` is ``_certificate_identity`` over it, and ``path`` names
    the private copy of it the OpenSSL calls saw -- the file
    ``verify_timestamp_token`` goes on to hand both its ``-CAfile``
    arguments.  ``path`` is ``None`` when ``_root_material`` owned the
    temporary directory and has already removed it, which is every caller
    that wanted only the identity.
    """

    pem: bytes
    identity: dict[str, str]
    path: Path | None


def _root_material(
    records: Path,
    anchor: dict[str, Any],
    *,
    snapshot_dir: Path | None = None,
) -> PinnedRootSnapshot:
    """Validate an anchor's referenced root and return it as it was read.

    The ported checks, verbatim: the root path is a regular file, its PEM
    hash, certificate hash, and SPKI hash match what the bundle declares.
    Factored out of ``_select_anchor`` so that ``_load_trust_bundle`` can run
    them for every anchor at load: a pending rotation reuses the active
    anchor id and root, which ``_supplemental_candidates`` then skips, and so
    no selection ever validated the new bundle's root before a transition
    activated it (peer review).

    Two checks are not ported: the file must hold exactly one certificate, as
    OpenSSL counts them, and a file OpenSSL cannot count is refused rather
    than assumed.

    Every check runs on one read of the repository path, and OpenSSL sees
    only a private copy of those bytes -- never the path itself.  Pass
    ``snapshot_dir`` to keep that copy, which is what
    ``verify_timestamp_token`` trusts as its ``-CAfile``; without it the
    directory is this function's own and goes away, and the returned
    ``path`` is ``None``.
    """

    root = anchor.get("rootCertificate")
    if not isinstance(root, dict):
        raise TsaError(f"TSA anchor {anchor.get('id')!r} lacks rootCertificate")
    root_path = physical_path(records, str(root.get("path", "")))
    if not root_path.is_file() or root_path.is_symlink():
        raise TsaError(f"pinned TSA root is missing or not a regular file: {root_path}")
    pem = _read_pinned_root(root_path)
    if snapshot_dir is not None:
        return _judge_pinned_root(root_path, root, pem, snapshot_dir)
    with tempfile.TemporaryDirectory(prefix="thesis-tsa-root-") as owned:
        material = _judge_pinned_root(root_path, root, pem, Path(owned))
    return PinnedRootSnapshot(pem=material.pem, identity=material.identity, path=None)


def _judge_pinned_root(
    root_path: Path, root: dict[str, Any], pem: bytes, snapshot_dir: Path
) -> PinnedRootSnapshot:
    """Run every root check over ``pem``, with OpenSSL reading a private copy."""

    snapshot = _write_root_snapshot(snapshot_dir, pem)
    # The certificate hash and SPKI below describe the file's *first*
    # certificate, which is all _certificate_identity reads, while
    # verify_timestamp_token gives `openssl ts -verify` and `openssl cms
    # -verify` a -CAfile, and they trust every certificate in whatever they
    # are given.  So a PEM holding the pinned root followed by a second
    # authority satisfies all three pins while a token chaining through that
    # second authority verifies (peer review).  One certificate per pinned
    # root makes what the SPKI pin names the whole of what the file
    # authorizes.  A new refusal, placed before the ported PEM-hash refusal
    # because the file it describes is not one the pinned tree presents: both
    # its roots hold exactly one certificate.
    #
    # Counted by OpenSSL, not by a pattern of ours.  Two rounds of review each
    # broke the pattern -- first on PEM labels besides CERTIFICATE, then on a
    # BEGIN marker trailed by a vertical tab or a form feed, and on a
    # byte-order mark before the first one -- and matching a parser by
    # imitation has no end, so _certificate_count asks the parser (peer
    # review, third gate round two).  The label no longer matters: whatever
    # label the one object wears, `openssl x509` reads it as the certificate
    # _certificate_identity hashes below, and verify_timestamp_token trusts
    # the snapshot of these very bytes, exactly one object by this count, so
    # any auxiliary trust settings they carry apply as pinned rather than
    # being dropped by a re-encoding (peer review, third gate round three).
    #
    # And every one of these checks judges `pem`, read from the repository
    # once, rather than re-opening the path: counting, hashing and describing
    # the same mutable file across five opens told an auditor what it held at
    # five separate instants and no more (peer review, fourth gate round
    # three).
    if _certificate_count(snapshot, pinned_path=root_path) != 1:
        raise TsaError(
            f"pinned TSA root PEM must hold exactly one certificate: {root_path}"
        )
    if hashlib.sha256(pem).hexdigest() != root.get("pemSha256"):
        raise TsaError(f"pinned TSA root PEM hash mismatch: {root_path}")
    identity = _certificate_identity(snapshot)
    if identity["certificateSha256"] != root.get("certificateSha256"):
        raise TsaError(f"pinned TSA root certificate hash mismatch: {root_path}")
    if identity["spkiSha256"] != root.get("spkiSha256"):
        raise TsaError(f"pinned TSA root SPKI hash mismatch: {root_path}")
    return PinnedRootSnapshot(pem=pem, identity=identity, path=snapshot)


def _select_anchor(
    records: Path,
    witness: dict[str, Any],
    trust: dict[str, Any],
    *,
    spec: TsaSpec,
    snapshot_dir: Path | None = None,
) -> tuple[dict[str, Any], PinnedRootSnapshot]:
    """Pick the one anchor a claim selects, and return it with its root as read.

    ``snapshot_dir`` is passed straight to ``_root_material``: a caller that
    goes on to trust the root -- ``verify_timestamp_token`` -- supplies the
    private directory the validated copy stays in, and a caller that only
    needs the anchor supplies nothing.
    """

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
    material = _root_material(records, anchor, snapshot_dir=snapshot_dir)
    identity = material.identity
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
    return anchor, material


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
    record: bytes | None = None,
) -> TokenEvidence:
    """Verify one claimed RFC 3161 token against one consumer-pinned anchor.

    ``record`` is the one read of ``path`` the caller has already taken and
    judged -- ``verify_witness`` derives the witness digest from it and passes
    it down here, so that the bytes the sidecar's ``digestSha256`` describes
    are the bytes OpenSSL recomputes the token's imprint over.  A direct
    caller may leave it out, in which case this takes that one read itself;
    either way ``path`` is read at most once and never again.
    """

    if record is None:
        record = _read_witnessed_record(path)
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

    # The temporary directory opens before the anchor is selected, so that
    # _root_material can keep its snapshot of the pinned root here: the same
    # bytes it validated are the bytes the two -CAfile verifications below
    # are given.  Nothing else moves -- the checks between still run in the
    # order they did, and every refusal keeps its place.
    with tempfile.TemporaryDirectory(prefix="thesis-tsa-") as temporary:
        temp = Path(temporary)
        anchor, pinned_root = _select_anchor(
            records, token_claim, trust, spec=spec, snapshot_dir=temp
        )
        token_logical = token_claim.get("tokenPath")
        if not isinstance(token_logical, str):
            raise TsaError("witness token lacks tokenPath")
        token_path = physical_path(records, token_logical)
        # One read of the claimed response, and both OpenSSL invocations that
        # want it are given a private copy of those bytes.  The declared
        # digest was taken from one open of the pathname and `openssl ts
        # -reply` and `openssl ts -verify` then made two more, so a writer
        # could let the hash check pass on a decoy and hand the verifications
        # something else (peer review, fourth gate round four).  The
        # path-level check keeps its ported wording and stays in front.
        token_missing = f"witness token is missing for {path}: {token_path}"
        if not token_path.is_file() or token_path.is_symlink():
            raise TsaError(token_missing)
        token_bytes = _read_file_once(token_path, token_missing)
        token_sha256 = hashlib.sha256(token_bytes).hexdigest()
        if token_sha256 != token_claim.get("tokenSha256"):
            raise TsaError(f"witness token hash mismatch for {path}")
        # The two private copies OpenSSL is given in place of the two paths.
        # Neither is re-encoded: `openssl ts -reply` and `openssl ts -verify`
        # read the response exactly as the digest above was taken over it, and
        # `-data` hashes the record exactly as it would have hashed the file
        # in the repository.
        token_response = temp / "token.tsr"
        token_response.write_bytes(token_bytes)
        record_snapshot = temp / "record.bin"
        record_snapshot.write_bytes(record)
        root_snapshot = pinned_root.path
        assert root_snapshot is not None
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
                str(token_response),
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
        payload = _record_payload(record, path)
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
        # The -CAfile below is _root_material's private snapshot of the
        # pinned root: a byte-for-byte copy, in a directory only this process
        # can reach, of the one read whose bytes it hashed, had OpenSSL count
        # exactly one certificate in, and read the anchor's certificate and
        # SPKI out of.  So the trust anchor these verifications are given is
        # the one object the anchor's certificateSha256 and spkiSha256
        # describe, given as pinned: nothing is re-encoded, and a pinned
        # TRUSTED CERTIFICATE's auxiliary trust settings apply.  A
        # re-encoding through `openssl x509` was tried and withdrawn -- it
        # emits a plain certificate, laundering a root that rejects the
        # timestamping purpose into one that permits it (peer review, third
        # gate round three) -- and handing over the repository path itself
        # was withdrawn after it too: the path is mutable, so a writer could
        # substitute that plain form, or a second authority appended after
        # the count, between validation and use (fourth gate round three).
        # Diagnostics still name the pinned path; only OpenSSL sees the copy.
        #
        # -data is the record snapshot for the same reason: it is the one read
        # the witness digest was taken from, so the imprint OpenSSL recomputes
        # is over the bytes the sidecar claims and not over whatever the record
        # path holds at this instant (fourth gate round four).  The command
        # text quoted in a failure therefore names temporary files; the
        # module's own refusals go on naming the record and the token as the
        # repository spells them.
        _run_openssl(
            [
                "ts",
                "-verify",
                "-config",
                "/dev/null",
                "-data",
                str(record_snapshot),
                "-in",
                str(token_response),
                "-CAfile",
                str(root_snapshot),
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
                str(root_snapshot),
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
        # What the file digest above cannot identify: the timestamp itself.
        # Almost everything between the two is the producer's to rewrite
        # without touching a signature -- a TimeStampResp's PKIStatusInfo
        # wrapper is unsigned, and inside the token a SignedData's
        # certificates, crls and unsignedAttrs are outside it too -- so one
        # issuance has many valid encodings, and both the file digest and the
        # digest of the extracted token move with the encoding.  The TSTInfo
        # does not: it is the signed content, so any change to it breaks the
        # signature the -CAfile verification just checked.  Its digest is
        # therefore what _v2_witness_evidence counts to decide whether two
        # outcomes rest on one timestamp (peer review, fourth gate round
        # four).  Taken from the authenticated run above, not from the
        # -nosigs extraction that preceded it.
        signed_timestamp_sha256 = hashlib.sha256(tst_info.read_bytes()).hexdigest()
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
        signed_timestamp_sha256=signed_timestamp_sha256,
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


#: The fields by which a witness names its trust bundle.
_BUNDLE_CLAIM_FIELDS = frozenset({"trustBundleId", "trustBundlePath", "trustBundleSha256"})


def _require_single_anchor(trust: dict[str, Any]) -> None:
    """Refuse a legacy witness over a bundle that configures several anchors.

    The legacy schema carries one producer-selected token and no per-anchor
    outcomes, so against such a bundle it would let a producer satisfy the
    whole bundle with whichever single authority happened to answer -- and
    say nothing about the rest.  Dual witness is only dual under v2.  Applied
    to the newest active bundle before dispatch (the only measure for a
    marker naming no bundle), to the bundle an available witness selects,
    and to the bundle an unavailable witness names; three review rounds
    found each of the three in turn.
    """

    anchor_count = len(trust["anchors"])
    if anchor_count > 1:
        raise TsaError(
            "legacy witness schema requires a single-anchor bundle; "
            f"{trust['bundleId']} has {anchor_count}"
        )


def _v1_witness_evidence(
    path: Path,
    witness: dict[str, Any],
    *,
    spec: TsaSpec,
    records: Path,
    record: bytes,
    digest_sha256: str,
    trusted_bundles: Mapping[str, dict[str, Any]],
    now: datetime | None,
) -> WitnessEvidence:
    status = witness.get("status")
    if status not in {"available", "unavailable"}:
        raise TsaError(f"invalid witness status for {path}: {status!r}")
    if status == "unavailable":
        # The v2 per-anchor outcome has held these two rules since it shipped;
        # the legacy path enforced neither.  A truthy non-string reason -- a
        # number, a list -- records nothing an auditor can read, and token
        # evidence beside a claim of no token means the witness is describing
        # a token it is simultaneously not standing behind.  Both are stricter
        # than the ported verifier, which accepts either.
        reason = witness.get("reason")
        if not isinstance(reason, str) or not reason:
            raise TsaError(f"unavailable witness lacks a reason for {path}")
        forbidden = sorted(_TOKEN_EVIDENCE_FIELDS.intersection(witness))
        if forbidden:
            raise TsaError(
                f"unavailable witness contains token evidence for {path}: "
                f"{forbidden}"
            )
        # An unavailable legacy witness may still name a bundle, and every
        # activated bundle stays selectable, so a claim naming an older,
        # wider bundle was returned before the count ran (peer review,
        # round three). A named bundle is resolved and counted here; a
        # marker naming none is measured against the newest bundle in
        # verify_witness.
        if _BUNDLE_CLAIM_FIELDS.intersection(witness):
            _reference, trust = _bundle_for_claim(
                records,
                witness,
                trusted_bundles,
                spec=spec,
                active_required=True,
            )
            _require_single_anchor(trust)
        return WitnessEvidence(status=status, digest_sha256=digest_sha256)
    bundle_reference, trust = _bundle_for_claim(
        records,
        witness,
        trusted_bundles,
        spec=spec,
        active_required=True,
    )
    # Counted on the bundle the witness actually selected (peer review):
    # every active bundle stays selectable here, so counting only the newest
    # one let a witness name an older, wider bundle and pass.
    _require_single_anchor(trust)
    token = verify_timestamp_token(
        path,
        witness,
        bundle_reference,
        spec=spec,
        records=records,
        now=now,
        record=record,
    )
    return _summarize_witness(
        status=status,
        digest_sha256=digest_sha256,
        tokens=[token],
    )


def _anchor_authority(anchor: dict[str, Any]) -> tuple[str, str]:
    """The authority an anchor stands for: its ID and its declared root SPKI.

    An ID alone names a slot in a bundle, not an authority.  A new bundle
    version reuses the ID -- that is how a signer rotation is carried -- and
    so could a bundle that puts a different root behind it, which is a
    different authority under a familiar name.  ``_load_trust_bundle`` has
    already compared both halves with the anchor's code identity and with the
    root material itself before any caller reads this pair.
    """

    root = anchor.get("rootCertificate")
    declared_root = root.get("spkiSha256") if isinstance(root, dict) else None
    return str(anchor["id"]), str(declared_root)


def _active_anchor_identities(
    records: Path,
    trusted_bundles: Mapping[str, dict[str, Any]],
    *,
    spec: TsaSpec,
) -> set[tuple[str, str]]:
    active: set[tuple[str, str]] = set()
    for reference in trusted_bundles.values():
        _path, trust = _load_trust_bundle(records, reference, spec=spec)
        active.update(_anchor_authority(anchor) for anchor in trust["anchors"])
    return active


def _supplemental_candidates(
    records: Path,
    trusted_bundles: Mapping[str, dict[str, Any]],
    transition_bundle_updates: list[dict[str, Any]],
    *,
    spec: TsaSpec,
) -> dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]]:
    active_authorities = _active_anchor_identities(
        records, trusted_bundles, spec=spec
    )
    candidates: dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
    for reference in transition_bundle_updates:
        bundle_path = str(reference["path"])
        if bundle_path in trusted_bundles:
            continue
        _path, trust = _load_trust_bundle(records, reference, spec=spec)
        for anchor in trust["anchors"]:
            anchor_id = str(anchor["id"])
            # Skipped by ID and root together, not by ID alone.  A pending
            # bundle that reuses an active anchor ID under a different
            # code-pinned root is a new authority wearing a familiar name;
            # taking the ID as the identity let both bundles pass their own
            # checks while the new authority was never asked for a
            # supplemental outcome before the transition activated it (peer
            # review).  A signer rotation keeps the root and is still
            # skipped, as it was.
            if _anchor_authority(anchor) not in active_authorities:
                candidates[(bundle_path, anchor_id)] = (reference, anchor)
    return candidates


def _v2_witness_evidence(
    path: Path,
    witness: dict[str, Any],
    *,
    spec: TsaSpec,
    records: Path,
    record: bytes,
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
    # One RFC 3161 response may stand for one anchor outcome and no other.
    # De-duplicating outcomes by anchor id alone left the token free: the same
    # tokenPath and tokenSha256 supplied under two outcomes verified twice and
    # were reported as two independent witnesses, which is the whole of what a
    # multi-anchor bundle is meant to prevent.  Counted across the primary and
    # supplemental outcomes together, because a supplemental outcome is
    # evidence about the same record from a pending authority and a reused
    # token covers neither (peer review, fourth gate round three).
    #
    # Two rules, because the response file and the timestamp inside it are
    # different things.  One is the file an outcome points at, refused before
    # that outcome's token is verified so that a duplicate is never put to
    # OpenSSL at all.  It is not enough on its own: nearly everything between
    # the file and the signature is the producer's to rewrite -- a
    # TimeStampResp's PKIStatusInfo wrapper is unsigned, and inside the token
    # a SignedData's certificates, crls and unsignedAttrs are outside the
    # signature -- so one issuance has many valid encodings with different
    # file digests, and any of them satisfies a rule that counts files.  The
    # other rule counts what the authority signed: TokenEvidence's
    # signed_timestamp_sha256, the digest of the TSTInfo, which no re-encoding
    # can move without breaking the signature the -CAfile verification checks.
    # It is knowable only once that verification has run, so it is checked
    # where verify_timestamp_token returns (peer review, fourth gate round
    # four).  The file rule therefore fires when two outcomes name the same
    # bytes, and the timestamp rule when they name different bytes carrying
    # one timestamp.
    #
    # Both refusals are new, and the file rule precedes the ported refusals
    # inside verify_timestamp_token for the outcome it stops.  Admissible
    # because the inputs they refuse are ones the pinned tree cannot present:
    # its 53 witnesses declare 91 tokens with 91 distinct file digests and 91
    # distinct signed TSTInfos.  The file rule reads the outcome's declared
    # tokenSha256 and records TokenEvidence.token_sha256 -- the digest of the
    # bytes that were actually read and verified -- so a declared digest that
    # lies is caught by the ported witness-token-hash refusal first and the
    # rule only ever remembers a true one.
    seen_response_files: set[str] = set()
    seen_timestamps: set[str] = set()

    def refuse_a_reused_response_file(declared: Any) -> None:
        # Only a string can have been recorded, and a claim carrying anything
        # else is left to the ported witness-token-hash refusal below.
        if isinstance(declared, str) and declared in seen_response_files:
            raise TsaError(
                f"duplicate TSA response file across anchor outcomes: {declared}"
            )

    def refuse_a_reused_timestamp(evidence: TokenEvidence) -> None:
        if evidence.signed_timestamp_sha256 in seen_timestamps:
            raise TsaError(
                "duplicate TSA timestamp across anchor outcomes: "
                f"{evidence.signed_timestamp_sha256}"
            )

    for outcome in outcomes:
        if not isinstance(outcome, dict):
            raise TsaError("multi-token witness outcome is not an object")
        anchor, _outcome_root = _select_anchor(records, outcome, trust, spec=spec)
        anchor_id = str(anchor["id"])
        if anchor_id in seen_anchor_ids:
            raise TsaError(f"duplicate TSA anchor outcome: {anchor_id}")
        seen_anchor_ids.add(anchor_id)
        outcome_status = outcome.get("status")
        if outcome_status == "available":
            claim = {**witness, **outcome}
            refuse_a_reused_response_file(claim.get("tokenSha256"))
            evidence = verify_timestamp_token(
                path,
                claim,
                bundle_reference,
                spec=spec,
                records=records,
                now=now,
                record=record,
            )
            refuse_a_reused_timestamp(evidence)
            seen_response_files.add(evidence.token_sha256)
            seen_timestamps.add(evidence.signed_timestamp_sha256)
            tokens.append(evidence)
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
        selected, _pending_root = _select_anchor(
            records, outcome, pending_trust, spec=spec
        )
        if selected != trust_anchor:
            raise TsaError(f"supplemental TSA anchor mismatch: {key}")
        outcome_status = outcome.get("status")
        if outcome_status == "available":
            refuse_a_reused_response_file(outcome.get("tokenSha256"))
            evidence = verify_timestamp_token(
                path,
                outcome,
                reference,
                spec=spec,
                records=records,
                now=now,
                record=record,
            )
            refuse_a_reused_timestamp(evidence)
            seen_response_files.add(evidence.token_sha256)
            seen_timestamps.add(evidence.signed_timestamp_sha256)
            supplemental_tokens.append(evidence)
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
    if status == "unavailable":
        # The same two rules the per-anchor outcomes above and the legacy
        # path apply.  The witness-level check tested the reason for truth
        # alone, so a v2 witness could carry a numeric reason, or token
        # fields beside a claim of no token, that its own outcomes could
        # not.  Peer review found the asymmetry; message and position are
        # kept, the type rule is added, and the field rule is new here.
        reason = witness.get("reason")
        if not isinstance(reason, str) or not reason:
            raise TsaError(f"unavailable witness lacks a reason for {path}")
        forbidden = sorted(_TOKEN_EVIDENCE_FIELDS.intersection(witness))
        if forbidden:
            raise TsaError(
                f"unavailable witness contains token evidence for {path}: "
                f"{forbidden}"
            )
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
    # One read of the record, and every question about it is asked of these
    # bytes: the digest the sidecar has to match, the trust-bundle updates it
    # carries, the creation claims the token's genTime is measured against,
    # and the imprint `openssl ts -verify -data` recomputes.  Reading the
    # pathname once per question described four instants of a mutable file
    # (peer review, fourth gate round four).
    record = _read_witnessed_record(path)
    digest_sha = hashlib.sha256(record).hexdigest()
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
            records, _record_payload(record, path), spec=spec
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
        # The legacy bundle -- the newest active one, just checked to be the
        # spec's legacy_witness_bundle_id -- must configure a single anchor.
        # Counted here, before dispatch, because an unavailable legacy
        # witness names no bundle and returns before any is resolved, so
        # this is the only bundle it can be measured against (peer review,
        # round two). _v1_witness_evidence counts again on the bundle an
        # available witness actually selects, which may be an older one
        # still active (round one).
        if preferred is not None:
            _legacy_path, legacy_trust = _load_trust_bundle(
                records, preferred, spec=spec
            )
            _require_single_anchor(legacy_trust)
        return _v1_witness_evidence(
            path,
            witness,
            spec=spec,
            records=records,
            record=record,
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
            record=record,
            digest_sha256=digest_sha,
            trusted_bundles=trusted_bundles,
            transition_bundle_updates=transition_bundle_updates,
            now=now,
        )
    raise TsaError(f"unsupported witness schema for {path}")
