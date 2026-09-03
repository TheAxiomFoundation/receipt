"""RFC 3161 witness verification with consumer-committed trust specifications.

The witness and trust-transition machinery is a mechanical port of
``MaxGhenis/brier``'s ``scripts/verify_record_chain.py`` at commit
``4b9e7be22debc8349e76b8bdfe5a0fe18ed31a3f``.  Ported refusal text is
retained verbatim.  The extraction changes only where trust enters: bundle
byte pins, TSA identities, anchor membership, and clock-skew limits arrive
through a frozen :class:`TsaSpec` supplied by consumer code.  This module
ships no repository-specific trust defaults and performs no chain walk or
producer signature verification.

The port is stricter than the baseline in nineteen places, each refusing an
input the pinned tree never presents and so each outside the differential
contract: a record under witness that is not a readable regular file, which
the baseline let raise out of the hash; a legacy witness over a bundle
configuring more than one anchor; a bundle configuring an anchor the spec
carries no identity for, or one whose declared root SPKI or allowed signers
differ from that identity, or whose referenced root material fails the
ported material checks or carries an SPKI other than the identity's (all
compared at load for every anchor, not only the one a witness selects); a
pinned root PEM that OpenSSL's own parser (``openssl storeutl -noout
-certs``) does not count exactly one certificate in, or whose certificates
it cannot count at all -- the declared certificate hash and SPKI describe
only the first certificate, while a ``-CAfile`` trusts every certificate it
is given, so with exactly one counted what the identity pins is the whole of
what the two verifications trust; a bundle whose configured anchors are not
exactly the anchors the spec's identities for that bundle name, so an
identity the consumer scoped to it cannot be quietly absent from it; a
bundle two of whose anchors allow the same signer, which is one authority
under two names -- the ported allowed-signer check binds a token to the
signers of the anchor its outcome selects, so a shared signer is exactly
what lets one RFC 3161 response satisfy two outcomes, while a shared root
with disjoint signers does not and stays allowed (one check on the anchors
covers the identities the spec scopes to the bundle as well, whose signer
sets each anchor's has just been required to equal); a pending bundle anchor
reusing an active anchor ID under a different code-pinned root, which is a
new authority and so must carry a supplemental outcome before the transition
can activate it -- the ported supplemental-outcome refusal, reaching a case
the baseline let through because it took the ID alone for the identity,
while a pending anchor whose signers are exactly one active anchor's signers
is that active authority under a new name and is skipped for the same reason
a bundle may not allow one signer under two of its anchors; a pending anchor
carrying part of an active authority and not the whole of it -- a piece of
one active anchor's signers (a split), the signers of two of them together
(a merge), or an active anchor's signers beside a key that is nobody's --
which is neither a rename nor a new authority and so is refused rather than
skipped or admitted, since skipping it activates something with no
supplemental evidence and admitting it lets an authority the chain already
trusts produce the very token the new key is supposed to prove; two pending
bundles that introduce one authority under two anchors, sharing a signer,
which is one new authority demanding and receiving two supplemental outcomes
and so counted twice -- every equivalence above is computed against the
active bundles, and each candidate the walk admits now joins the sets the
next is measured against, except that a later pending bundle's anchor
carrying an admitted anchor's ``(ID, root SPKI)`` succeeds it rather than
colliding with it, one authority keeping its name across two versions of a
catch-up; a caller-supplied trust transition that omits an update the
witnessed record itself carries, which is a transition read from one instant
of the record and evidence taken from another; a chain genesis file or a
witness sidecar that is not a readable regular file -- genesis had no
path-level check at all, so the baseline let a directory there raise into a
message about a parse that never happened, and a sidecar that was a symlink
was followed rather than refused; an unavailable witness of either schema
whose reason is not a string, or that carries token
evidence at the witness level (the v2 per-anchor outcome has always refused
both); an unavailable legacy witness that names a bundle by any of its three
claim fields, whose claim is then resolved and counted where the baseline
ignored those fields; and a v2 witness that offers one RFC 3161 response
under two of its outcomes, counted across the primary and supplemental
outcomes together so that one response cannot stand for a bundle configuring
more than one anchor -- counted four ways over: the physical path an
outcome points at, keyed on a portable fold of it so that two spellings a
case- or normalisation-insensitive filesystem cannot tell apart are one
path, refused before that outcome's response is read at all; the file
digest that outcome declares, refused before its token is verified
and so ahead of the ported refusals inside ``verify_timestamp_token``; the
object the read actually opened, as ``(st_dev, st_ino)`` off the descriptor
the bytes came out of, refused at the read; and the pair of the ``TSTInfo``
an authority signed and the certificate that signed it, refused where that
verification returns.  Each reaches what the one before it cannot.  Two
outcomes may name one path and declare two digests, and each outcome reads
the path for itself, so a writer serving a different valid response to each
read satisfies both from a repository that never held both; two outcomes may
spell one directory entry two ways, which such a writer turns into the same
evidence with the entry *replaced* between the reads rather than rewritten,
so that even the object behind the name is two -- which is why the first
identity is a fold and not a spelling, deliberately refusing two genuinely
distinct files whose names fold together on the filesystems that keep them
apart, because a witness whose meaning depends on which filesystem an
auditor cloned onto is not one an auditor can act on; and two outcomes may
name one file under two paths that do not fold together, because a symlinked
parent directory or a second hard link gives one object two names that no
comparison of names separates -- which is why the third identity is taken
from the descriptor and not from a second look at the name, that look being
the race itself.  And nearly everything around a signed ``TSTInfo`` is the
producer's to rewrite -- the unsigned ``PKIStatusInfo`` wrapper, and the
``certificates``, ``crls`` and ``unsignedAttrs`` a ``SignedData`` carries
outside its signature -- so one issuance has many valid encodings and a rule
counting files counts encodings.  The signer is half of that last identity
because a ``TSTInfo`` need not say whose it is: RFC 3161 makes its serial
unique within one TSA and no further, and its nonce and its ``tsa`` name
optional, so two independent pinned authorities can sign byte-identical
``TSTInfo``s with no forgery at all.  All four are admissible because no
witness in the pinned tree names one path twice, spells one path two ways
(its 91 declared token paths have 91 distinct fold keys), reaches one file
by two paths, or offers one authority's timestamp twice.

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

The trust transition the record carries comes from that snapshot too, and it
is the one thing that used to come from somewhere else.  ``verify_witness``
takes a ``transition_bundle_updates`` list, and a chain walker legitimately
supplies the accumulated pending updates of earlier records together with
this record's own -- so the list was taken entire and the record was not
consulted at all, which put the evidence and the transition at two different
instants of one mutable path.  The record's own updates are now always
derived here, and a supplied list is compared with them: every derived update
must appear in it, or this refuses.  The comparison is one-way because the
list is a superset by design, and that bounds what it closes -- a caller
supplying this record's updates from a second read of *this* record, beside
the snapshot's own, is indistinguishable from one supplying earlier records',
since both are extra entries, and the stale one is then evaluated.

Which is a property of the one list and not of the machinery, so the two
kinds of update are separate at the module-level entry point.
``_verify_witness_with_updates`` takes ``prior_pending_updates`` -- the
pending updates of *earlier* records and nothing else -- combines them with
the snapshot's own itself (prior first, then the snapshot's, each mapping
admitted once, since a reference repeated across the two describes one
bundle), and returns the snapshot-derived list beside the evidence.  A chain
walker supplies only the earlier records' updates and takes this record's
from the verification, so no entry in the transition is one this call did not
either derive or attribute to a record before this one, and there is no stale
extra to attribute at all.  The two shapes are mutually exclusive; supplying
both is a ``TypeError`` rather than a refusal, because no call means "these
are the earlier records' updates" and "these are the earlier records' updates
and this one's" at once.  ``verify_witness`` keeps the one list, with 0.5.1's
signature, because the upstream integration this is a port of walks its chain
that way; what it leaves is said above and said again in its own docstring.

The claimed response is read once for the same reason.  Its ``tokenSha256``
was taken from one open of its pathname and ``openssl ts -reply`` and
``openssl ts -verify`` then made two more, so the digest reported as evidence
described the file at an earlier instant than the one the verifications read;
the bytes that were hashed are now the bytes both of them are given.  That
digest identifies a file and not a timestamp, which is why the private
``_verify_timestamp_token`` returns the identity of the timestamp -- the
signed ``TSTInfo`` and the certificate that signed it -- beside its
evidence.  That private entry point is also where the record snapshot is
handed down.  The keyword was on the public ``verify_timestamp_token`` for
two rounds, and a caller supplying bytes that were not what ``path`` holds
undid the binding the released function had: the evidence named one record
while the imprint was checked against another, which is the substitution the
one read exists to prevent, offered as a parameter.  The public function
takes its own one read of ``path`` and hands it down; the private one
requires the bytes, because its only callers are in this module and every one
of them has read ``path`` already -- a caller that could omit them is a
caller that could substitute them.

Beside, and not inside: :class:`TokenEvidence` is the public dataclass 0.5.1
shipped, field for field and in order, because that identity is a counting
aid one caller in this module needs and adding it as a required field would
break a keyword construction that omitted it, shift a positional one, and
change what serializing the fields produces -- none of them things a
maintenance release may do.  A later minor version can expose it if a
consumer asks for it.

The three JSON inputs are read the same way, and for the same reason: the
trust bundle, which is the anchor set; the witness sidecar, which is the
claim; and the chain genesis, which is the root of the whole transition.
Each went through ``load_json`` -- ``is_file`` about a pathname, then
``Path.read_text`` opening that pathname again -- and each now goes through
``_load_json_once``, which is the caller's own path-level refusal in front of
one ``_read_file_once`` and ``load_json``'s parse over those bytes.  The two
parse refusals come out byte for byte and name the same file; what changes
besides is ``load_json``'s ``OSError`` branch, which becomes the caller's own
words, and a symlink at the final component, which ``O_NOFOLLOW`` now
refuses.  Genesis had no path-level check at all, so its refusal is the new
one counted above.

All six of those reads open without waiting.  Each has a path-level check
in front of it, and the check answers about a pathname while the descriptor
is opened from that pathname again, so what is opened need not be what was
checked: a regular file replaced by a FIFO in between is opened as a FIFO,
and a read-only open of a FIFO waits for a writer with no timeout.  The
refusal that ``fstat`` would then give is never reached, and a verification
that should have failed hangs instead.  So the open carries ``O_NONBLOCK``
where the platform has the flag, ``fstat`` refuses the descriptor in the
caller's own words, and the flag is cleared before any byte is read -- it
governs the open and nothing after it.

The record, the response and the pinned root open in binary too, and so does
the private copy of the pinned root.
``O_BINARY`` is absent on POSIX and contributes nothing there, and on Windows
a descriptor opened without it is a text descriptor in the C runtime's sense:
the read turns ``\r\n`` into ``\n`` and stops at the first ``0x1A``.  Each of
these files is hashed and then trusted, so a byte the read never returns is a
byte the digest does not cover, and a copy written through a text descriptor
would hand OpenSSL something other than what was hashed -- the substitution
the copy exists to prevent, performed by the copy.  ``receipt.corpus`` sets
the flag on its own bound-file read for the same reason.

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

``tests/test_tsa.py`` binds all of these.  Two of them can no longer fire
from within this module, and both texts are kept as defence in depth.
``_select_anchor``'s own identity refusal is one: every bundle anchor is
identity-checked at load, so the selection never finds a disagreement, and
its text is kept verbatim as ported.  The duplicate-timestamp refusal is the
other, and what closed it is the pending-authority rules above: two outcomes
rest on one authority's signature only if two anchors both pin the
certificate that response was signed with, and no pairing of anchors that
could reaches two outcomes -- inside one bundle they are refused at load;
across an active and a pending bundle the pending one is skipped as a rename
or refused as a split or a merge, so it never becomes a candidate at all; and
across two pending bundles they are refused as an alias, or, where the two
are one authority under one name, the later succeeds the earlier and only
one of them is a candidate.  Its text is new to this branch rather than
ported, and it is kept because it is the last thing standing if one of those
rules is lost; its tests reach it by blinding
``_anchor_signer_fingerprints``, and say so.
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
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:  # pragma: no cover - exercised by whichever platform runs the suite
    import fcntl
except ImportError:  # pragma: no cover - Windows has no fcntl, and no O_NONBLOCK
    fcntl = None  # type: ignore[assignment]

from receipt.canonical import canonical_bytes, canonical_sha256

TRUST_BUNDLE_RE = re.compile(r"records/trust/tsa-anchors-v[1-9][0-9]*\.json")

#: The same path, with the immutable version it carries captured.
_BUNDLE_VERSION_RE = re.compile(r"records/trust/tsa-anchors-v([1-9][0-9]*)\.json")
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
    policy_oid: str
    imprint_algorithm_oid: str
    gen_time: str
    tsa_subject: str
    tsa_certificate_sha256: str
    tsa_spki_sha256: str


@dataclass(frozen=True)
class _TimestampIdentity:
    """Which timestamp a verified response carries, for counting purposes.

    Private, and returned beside the evidence rather than carried inside it.
    An earlier revision of this branch added the ``TSTInfo`` digest as a
    required field of :class:`TokenEvidence`, which is public and frozen and
    part of a maintenance release: a keyword construction that omitted it
    would have raised, a positional one would have shifted, and anything
    serializing the fields would have gained a key.  None of that is
    something a bug-fix release may do to a consumer, and no consumer needs
    the identity to read the evidence -- it exists so that
    ``_v2_witness_evidence`` can tell two outcomes resting on one timestamp
    from two outcomes resting on two (peer review, fifth gate round one).  A
    0.6 that a consumer asks for it can expose it; until then it stays here.

    ``tst_info_sha256`` is the SHA-256 of the DER ``TSTInfo`` the authority
    signed, as the authenticated ``openssl cms -verify`` wrote it out -- the
    timestamp itself, not the file it arrived in and not the CMS envelope
    around it.  Both of those are largely unauthenticated: a
    ``TimeStampResp``'s ``PKIStatusInfo`` wrapper is unsigned, and a
    ``SignedData``'s ``certificates``, ``crls`` and ``unsignedAttrs`` are
    outside the signature, so one issuance has many valid encodings with
    different digests.  Its ``TSTInfo`` has one, and two issuances by one
    authority differ in it by serial number and genTime.

    ``signer_certificate_sha256`` is what says *whose* timestamp it is: the
    certificate ``openssl cms -verify`` authenticated the signature with, as
    ``_certificate_identity`` reports it.  Without it the pair is not an
    identity at all.  A ``TSTInfo`` carries nothing that must name its
    authority -- RFC 3161 requires the serial number to be unique within one
    TSA and no further, and the nonce and the ``tsa`` name are both optional
    -- so two independent pinned authorities can sign byte-identical
    ``TSTInfo``s, legitimately and with no forgery, and a rule counting the
    signed content alone refuses the second of two valid outcomes (peer
    review, fifth gate round one).  Qualified by the signer, one authority
    cannot present its own timestamp twice and two authorities are never
    confused for one.
    """

    signer_certificate_sha256: str
    tst_info_sha256: str


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


def _path_fold(path: Path) -> tuple[str, ...]:
    """A key two spellings of one filesystem path share.

    NFC folds the decomposed and precomposed spellings of one character
    together; ``casefold`` folds case together.  A path is folded component
    by component, so nothing a fold produces can be read as a separator.

    Two distinct spellings with one key are one directory entry on a case- or
    normalisation-insensitive filesystem -- APFS and NTFS both, and HFS+
    normalises besides -- which is why a rule about "the same path" has to be
    asked over this and not over the spelling.  ``receipt.corpus`` computes
    the same fold for the same reason, over its declared corpus paths; this
    module carries its own rather than importing that one, because
    :mod:`receipt.tsa` depends on nothing in the package but
    :mod:`receipt.canonical` and a witness verifier has no business needing a
    corpus.

    Deliberately conservative in the same way: a case-sensitive filesystem can
    hold two genuinely distinct files whose names fold together, and a witness
    naming both is refused here even though the two really are two.  A witness
    whose meaning depends on which filesystem the auditor cloned onto is not
    one an auditor can act on.
    """

    return tuple(
        unicodedata.normalize("NFC", part).casefold() for part in path.parts
    )


def load_json(path: Path) -> dict[str, Any]:
    """Read and parse one JSON object, as the baseline reads one.

    Public, ported, and no longer called from inside this module: every JSON
    input the verification depends on goes through ``_load_json_once``
    instead, which takes one non-blocking ``fstat``-judged read and then
    raises these same two refusals over those bytes through
    ``_record_payload``.  This stays for consumer code and for the
    differential harness's own chain walk, which reads the genesis file the
    way the baseline does.
    """

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
    payload = _load_json_once(
        path, label=f"TSA trust bundle is missing or not regular: {path}"
    )
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
#: descriptor inherited across an exec, no symlink followed at open time, no
#: open that waits, and no translation of what is read -- each where the
#: platform has the flag.
#:
#: ``O_BINARY`` is the one that only matters off POSIX, where it is absent and
#: contributes nothing.  On Windows a descriptor opened without it is a *text*
#: descriptor in the C runtime's sense: the CRT turns ``\r\n`` into ``\n`` and
#: stops the read at the first ``0x1A``.  Every file read here is judged by its
#: SHA-256 and then handed to OpenSSL, so a byte the read never returns is a
#: byte the digest does not cover -- a pinned root, a DER response or a record
#: silently truncated at a ``0x1A`` would be hashed and trusted as the whole
#: file (peer review, fifth gate round two).  ``receipt.corpus`` sets the same
#: flag on its own bound-file read for the same reason.
#:
#: ``O_NONBLOCK`` is what decides whether a refusal arrives at all.  The open
#: has to happen before ``fstat`` can say what was opened, so a regular file
#: replaced by a FIFO between a caller's path-level check and this open is
#: opened as a FIFO -- and a blocking read-only open of a FIFO waits for a
#: writer with no timeout, so the refusal that would follow is never reached
#: and the verification hangs instead of failing (peer review, fifth gate
#: round one).  A non-blocking open returns a descriptor at once and the
#: ``fstat`` below refuses it.  ``_clear_nonblocking`` then takes the flag
#: back off, so it governs the open and nothing else.
_ONE_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_BINARY", 0)
)

#: Flags for the private copy of a pinned root the OpenSSL calls are given.
#:
#: Named beside ``_ONE_READ_FLAGS`` because the two have to agree about
#: ``O_BINARY``: a copy written through a text descriptor is not a copy.  The
#: read would return the pinned bytes and the write would put ``\r\n`` where
#: the original had ``\n``, so what OpenSSL was handed would differ from what
#: was hashed and counted -- the substitution the snapshot exists to prevent,
#: performed by the snapshot itself.  Everything else here is the private-file
#: discipline the snapshot has always had: create or truncate, write only,
#: no descriptor inherited across an exec.
_SNAPSHOT_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_TRUNC
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_BINARY", 0)
)


def _clear_nonblocking(descriptor: int) -> None:
    """Take ``O_NONBLOCK`` back off a descriptor ``fstat`` has just judged.

    The flag is set for the open, where it is the difference between a
    refusal and a hang, and it is wanted for nothing after it: ``open(2)``
    says it "also has the effect of making all subsequent I/O on the open
    file non-blocking", so leaving it set would change the reads too.  Only a
    regular file is ever read here -- the caller's ``fstat`` rule refuses
    everything else before this is called -- and a regular file's reads do not
    block, so clearing it is what keeps the read exactly the read it was
    rather than a read that has to be prepared for ``EAGAIN``.  Chosen over
    tolerating ``EAGAIN`` in the read loop for that reason: a retry loop would
    be a second reading mode with no input in the pinned tree to exercise it.

    Nothing to do where the platform has neither ``fcntl`` nor ``O_NONBLOCK``,
    which is also where ``_ONE_READ_FLAGS`` did not set it.
    """

    if fcntl is None or not hasattr(os, "O_NONBLOCK"):
        return
    flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    fcntl.fcntl(descriptor, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)


def _read_file_once(path: Path, missing: str) -> tuple[bytes, tuple[int, int]]:
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

    That race is why the open is non-blocking: the caller's check answers
    about a pathname and this opens the pathname again, so what is opened may
    be a FIFO the check never saw, and opening one to read blocks until a
    writer arrives.  See ``_ONE_READ_FLAGS``.

    Returned beside the bytes is ``(st_dev, st_ino)`` from the very ``fstat``
    that judged the descriptor -- the identity of the object the bytes came
    out of, rather than of the name they were asked for.  A pathname is not
    a file: a symlinked parent directory or a second hard link gives one
    object two names, and a caller that has to tell two of its own reads
    apart can only do it by what was opened.  ``_v2_witness_evidence`` is the
    caller that does; the record and the pinned root drop it.
    """

    try:
        descriptor = os.open(path, _ONE_READ_FLAGS)
    except OSError as exc:
        raise TsaError(missing) from exc
    chunks: list[bytes] = []
    try:
        judged = os.fstat(descriptor)
        if not stat.S_ISREG(judged.st_mode):
            raise TsaError(missing)
        _clear_nonblocking(descriptor)
        while True:
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError as exc:
        raise TsaError(missing) from exc
    finally:
        os.close(descriptor)
    return b"".join(chunks), (judged.st_dev, judged.st_ino)


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
    record, _identity = _read_file_once(path, missing)
    return record


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

    pem, _identity = _read_file_once(
        path, f"pinned TSA root is missing or not a regular file: {path}"
    )
    return pem


def _load_json_once(path: Path, *, label: str) -> dict[str, Any]:
    """``load_json`` over one non-blocking, ``fstat``-judged read of ``path``.

    The three JSON inputs this module both checks and then acts on -- a trust
    bundle, a witness sidecar, and the chain genesis -- were read the way the
    record, the response and the pinned root used to be: a path-level check
    answering about a pathname, then ``Path.read_text`` opening that pathname
    again and waiting on the open.  So a regular file replaced by a FIFO in
    between was opened as a FIFO and the read blocked with no timeout, and a
    verification that should have failed hung instead (peer review, fifth gate
    round three).  Each of these decides what is trusted -- a bundle is the
    anchor set, a sidecar is the claim, genesis is the root of the whole
    transition -- so each gets the discipline the other three have: one
    descriptor, opened without waiting, judged a regular file by the ``fstat``
    of that descriptor, and parsed from the bytes it returned.

    ``label`` is the caller's own refusal for a path that is not a readable
    regular file, used both for the path-level check in front and for the
    descriptor behind it, so a race can change which of the two identical
    refusals fires but never the message.  Everything else is ``load_json``'s:
    ``_record_payload`` raises its two refusals, ``cannot read JSON {path}``
    and ``record must be a JSON object: {path}``, word for word and naming the
    same file, over the bytes of the one read.

    What is not ``load_json``'s is what it did with ``OSError``.  ``load_json``
    reports one as ``cannot read JSON``; here an unreadable path is the
    caller's own refusal, which is the same trade ``_read_witnessed_record``
    and ``_read_pinned_root`` already made, and what makes it possible for the
    check and the read to say one thing.  ``O_NOFOLLOW`` comes with the
    discipline too, so a symlink at the final component is refused where
    ``read_text`` would have followed it.
    """

    if not path.is_file() or path.is_symlink():
        raise TsaError(label)
    data, _identity = _read_file_once(path, label)
    return _record_payload(data, path)


def _write_root_snapshot(directory: Path, pem: bytes) -> Path:
    """Copy the bytes read from a pinned root into a private file.

    OpenSSL takes a path, not bytes, so the count, the certificate identity
    and the two ``-CAfile`` verifications all need a file; this is the only
    file any of them is given.  ``directory`` is a private temporary
    directory (``tempfile.mkdtemp`` makes it 0700) owned by the caller, and
    the copy is written 0600 through ``_SNAPSHOT_WRITE_FLAGS``.  It is a
    byte-for-byte copy: nothing is re-encoded, and the flags include
    ``O_BINARY`` where the platform has it, so a pinned ``TRUSTED
    CERTIFICATE``'s auxiliary trust settings survive into it exactly as
    pinned and no line ending is rewritten on the way.
    """

    snapshot = directory / "pinned-root.pem"
    descriptor = os.open(snapshot, _SNAPSHOT_WRITE_FLAGS, 0o600)
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
) -> TokenEvidence:
    """Verify one claimed RFC 3161 token against one consumer-pinned anchor.

    ``path`` is the record the token has to be over, and this takes the one
    read of it itself: the bytes it hashes for the creation claims and the
    bytes ``openssl ts -verify -data`` recomputes the imprint over are that
    read and nothing else.  A ``record`` keyword briefly let a caller supply
    those bytes here, and a caller supplying bytes that are not what ``path``
    holds undid the binding the released function had -- the evidence named
    one record and the imprint was checked against another, which is the
    substitution the one read exists to prevent, offered as a parameter
    (peer review, fifth gate round three).  The keyword was added on this
    branch and is gone again; the witness flow hands its snapshot to the
    private ``_verify_timestamp_token`` instead, where the caller is this
    module and the bytes are the ones its own read of ``path`` produced.

    Signature and return are the package's 0.5.1 ones exactly.  The work is
    ``_verify_timestamp_token``, which returns the same evidence and, beside
    it, the private identity of the timestamp that was verified; this drops
    that identity, because it is a counting aid ``_v2_witness_evidence``
    needs and not something a public dataclass may grow a field for in a
    maintenance release (peer review, fifth gate round one).
    """

    evidence, _identity = _verify_timestamp_token(
        path,
        token_claim,
        bundle_reference,
        spec=spec,
        records=records,
        now=now,
        record=_read_witnessed_record(path),
    )
    return evidence


def _verify_timestamp_token(
    path: Path,
    token_claim: dict[str, Any],
    bundle_reference: dict[str, Any],
    *,
    spec: TsaSpec,
    records: Path,
    now: datetime | None = None,
    record: bytes,
    on_token_read: Callable[[Path, tuple[int, int]], None] | None = None,
) -> tuple[TokenEvidence, _TimestampIdentity]:
    """``verify_timestamp_token``, and which timestamp it verified.

    Every refusal, every check and every check's place belong to the public
    function; this is where its body lives, so that the one caller who needs
    to tell two outcomes' timestamps apart can have that answer without it
    appearing in :class:`TokenEvidence`.

    ``record`` is required, and is the one read of ``path`` its caller has
    already taken and judged: ``verify_witness`` derives the witness digest
    from it and hands it down, so that the bytes the sidecar's
    ``digestSha256`` describes are the bytes OpenSSL recomputes the imprint
    over, and the public function above hands down the read it takes itself.
    There is no default, because there is no caller of this that has not read
    ``path`` already, and a caller that could omit the bytes is a caller that
    could substitute them -- which is why the keyword is here and not on the
    public function (peer review, fifth gate round three).

    ``on_token_read`` is given the resolved response path and the identity of
    the object that read actually opened, at the moment the read returns.  A
    caller taking several reads is handed it there rather than told afterwards
    because that is the earliest it is knowable and the last moment before the
    bytes are put to OpenSSL: ``_v2_witness_evidence`` refuses a second outcome
    whose response is the same file as an earlier one's, and refusing it here
    means the duplicate is never verified at all.  Raising out of the callback
    is how it does that, so this must not swallow one.
    """

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
        token_bytes, token_file = _read_file_once(token_path, token_missing)
        if on_token_read is not None:
            on_token_read(token_path, token_file)
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
        tst_info_sha256 = hashlib.sha256(tst_info.read_bytes()).hexdigest()
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
    evidence = TokenEvidence(
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
    return evidence, _TimestampIdentity(
        signer_certificate_sha256=signer_identity["certificateSha256"],
        tst_info_sha256=tst_info_sha256,
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
    # The private entry point, because the public one takes its own read of
    # the record and this path already has the read verify_witness hashed;
    # every refusal and every check's place is the public function's either
    # way, since that is where its body lives.
    token, _identity = _verify_timestamp_token(
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


def _anchor_signer_fingerprints(anchor: dict[str, Any]) -> set[str]:
    """The signer SPKI fingerprints an anchor allows.

    Read off ``allowedSigners``, which ``_load_trust_bundle`` has already
    required to equal the fingerprints of the identity the verifier code pins
    for that anchor.  An entry carrying no fingerprint is dropped rather than
    kept as a value of its own: an anchor with one has already been refused at
    load, because the identity's fingerprints are strings and the two sets
    have to be equal.
    """

    signers = anchor.get("allowedSigners")
    if not isinstance(signers, list):
        return set()
    return {
        signer["spkiSha256"]
        for signer in signers
        if isinstance(signer, dict) and isinstance(signer.get("spkiSha256"), str)
    }


def _pending_bundle_version(reference: Mapping[str, Any]) -> int:
    """The version a pending bundle reference's path carries, or ``0``.

    Pending bundles are walked in this order, because succession between two
    of them is a question about which came later.  A reference whose path is
    not a versioned trust bundle path sorts first and is refused by
    ``_load_trust_bundle`` the moment it is reached, in that function's own
    words, so no ordering here decides anything but the order of two refusals
    that would both fire.
    """

    path = reference.get("path")
    match = _BUNDLE_VERSION_RE.fullmatch(path) if isinstance(path, str) else None
    return int(match.group(1)) if match else 0


def _active_anchor_identities(
    records: Path,
    trusted_bundles: Mapping[str, dict[str, Any]],
    *,
    spec: TsaSpec,
) -> tuple[set[tuple[str, str]], dict[tuple[str, str], set[str]]]:
    """What the active bundles already stand for: authorities, and whose keys.

    Two answers because a pending anchor can be an authority already active
    in two different ways -- under the same name, or under a new one with the
    same signing key.  ``_supplemental_candidates`` says why each is needed.

    The second answer is a mapping and not a set.  Flattening every active
    anchor's signers into one set loses which authority each key belongs to,
    and that is the whole of what a rename is: an anchor carrying *one*
    active authority's keys.  With the ownership gone, an active anchor
    allowing two keys could be split by a pending bundle into two anchors
    allowing one each, and two active anchors could be merged into one
    allowing both -- every key in every case already active, so every case
    skipped as a rename, and one authority became two or two became one with
    no supplemental evidence anywhere (peer review, fifth gate round three).

    Keyed by ``(id, root SPKI)``, and the signer sets of anchors sharing that
    pair are unioned: a rotation leaves both bundle versions active, so one
    authority is described by two anchors whose keys are both trusted for it,
    and its equivalence class is both of them together.
    """

    active: set[tuple[str, str]] = set()
    signers_by_authority: dict[tuple[str, str], set[str]] = {}
    for reference in trusted_bundles.values():
        _path, trust = _load_trust_bundle(records, reference, spec=spec)
        for anchor in trust["anchors"]:
            authority = _anchor_authority(anchor)
            active.add(authority)
            signers_by_authority.setdefault(authority, set()).update(
                _anchor_signer_fingerprints(anchor)
            )
    return active, signers_by_authority


def _supplemental_candidates(
    records: Path,
    trusted_bundles: Mapping[str, dict[str, Any]],
    transition_bundle_updates: list[dict[str, Any]],
    *,
    spec: TsaSpec,
) -> dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]]:
    """The pending anchors a transition must produce a supplemental token for.

    An anchor is skipped -- already active, so it has nothing new to prove --
    when either half of its identity says it is one the chain already trusts,
    and both halves are needed.

    By ``(id, root SPKI)``, because an ID alone names a slot.  A pending
    bundle that reuses an active anchor ID under a different code-pinned root
    is a new authority wearing a familiar name; taking the ID as the identity
    let both bundles pass their own checks while that authority was never
    asked for a supplemental outcome before the transition activated it (peer
    review, fresh gate).  A signer rotation reuses the ID under the same root,
    so this half is also what keeps a rotation from demanding one.

    And by signer, because a name is not an authority either.  A pending
    anchor with a new ID over the active root and the active signer is the
    active authority renamed: ``_load_trust_bundle`` already refuses two
    anchors of one bundle that allow the same signer for exactly that reason,
    and here the same shape spread across an active bundle and a pending one
    made one authority's two stamps look like coverage by two (peer review,
    fifth gate round one).  The signing key is what a token is bound to -- the
    ported allowed-signer check compares the certificate a verified token was
    signed with against the anchor's pins -- so an already-active key has
    nothing left to demonstrate, whatever root or ID a pending bundle files it
    under.

    Neither half alone would do.  Signer overlap alone would make every
    rotation a new authority, because a rotation is precisely a new signer
    under an active ID and root, and the ported refusal would then demand a
    supplemental outcome for every one of them.  ``(id, root SPKI)`` alone
    lets a renamed anchor pose as new.

    Which is why the signer half asks whether the anchor's signer set is one
    active anchor's set *exactly*, and refuses everything between that and
    disjoint.  Two rounds found the two ways a looser test goes wrong.
    Skipping on any overlap took an anchor declaring an active signer beside a
    new one -- a genuinely new authority with an old key listed beside its own
    -- for a rename, and it activated with no supplemental evidence at all
    (peer review, fifth gate round two).  Skipping on a subset of the active
    signers *flattened into one set* threw away which authority each key
    belongs to, and that ownership is the whole of what a rename is: an active
    anchor allowing two keys at once could be split by a pending bundle into
    two anchors allowing one each, both subsets and both skipped, so two
    authorities activated where the chain had asked about one and each held a
    key the other did not; and two active anchors could be merged into one
    anchor allowing both keys, which either of them can then stamp for, so
    every outcome it answers thereafter is satisfied by whichever happens to
    be reachable (fifth gate round three).  A split and a merge are claims
    about who is who, and nothing here can take a producer's word for one.

    So the classes are kept.  ``_active_anchor_identities`` reports each
    active authority's own signer set; a pending anchor whose signers touch
    none of them is a candidate; one whose signers are exactly the class of
    every active anchor it touches is that authority renamed and is skipped;
    and anything else -- a piece of one class, several classes together, or a
    class with a key that is nobody's -- is refused.  One message for all
    three, because all three have one fix: file the authority so that a
    pending anchor carries one active anchor's signers exactly, or none of
    them.  ("Exactly the class of every anchor it touches" rather than "of
    exactly one anchor" because two active anchors can legitimately carry one
    class -- an activated rename is precisely that -- and a further rename of
    such an authority is still a rename.)

    Nor may an anchor that is partly one thing and partly another simply be
    treated as new: the supplemental outcome is supposed to show that whoever
    holds the new key answered, and an anchor that also allows an active key
    can satisfy it with a stamp by the authority the chain already trusts.
    Neither reading is true of it, so it is refused and the producer is told
    what to do about it: a rotation belongs under the active ID and root, and
    a new authority belongs in an anchor whose signers are its own.  A pending
    anchor whose (ID, root SPKI) is already active is a rotation and is
    skipped before any of this, which is what keeps a bundle that legitimately
    allows a superseded signer beside its replacement from reaching the
    refusal.

    All of that measures a pending anchor against the active bundles, and two
    pending bundles were measured against nothing but those -- so one
    authority introduced under two IDs by two pending bundles was two
    candidates, each demanding and receiving a supplemental outcome of its
    own, and the transition counted one new authority twice (peer review,
    fifth gate round two).  What the second outcome shows is that the holder
    of a key the chain has already asked about can stamp twice, which is what
    the rename rule refuses when the key is an active one and is no more
    evidence when it is a pending one.  So each candidate admitted here joins
    the set the next is measured against, and a later pending anchor sharing a
    signer with an admitted one is refused, under any overlap and not only a
    subset: two pending anchors under two names have no rotation relationship
    to preserve, and a bundle that means to rotate a key can say so under the
    anchor's own ID and root.

    Under its *own* ID and root, which is what a pending anchor carrying an
    admitted anchor's ``(ID, root SPKI)`` is doing, and that was refused for a
    round and should not have been (fifth gate round three).
    ``trust_bundle_updates`` enumerates every consumer-pinned bundle the chain
    has not introduced yet, so a record catching up over several versions
    carries v2 and v3 together, and v3 legitimately retains -- or rotates --
    the authority v2 introduces.  That is one authority under one name, and
    the answer is succession: pending bundles are walked in version order, and
    a later one's anchor replaces its predecessor in the candidate set and
    releases its predecessor's keys, so a rotation between two pending
    versions is not read as two anchors sharing a signer.  The highest
    version's anchor is the one kept, because it is the anchor that will
    verify tokens once the transition activates -- a v2 witness must use the
    newest active bundle -- so its key is the one a supplemental outcome
    should demonstrate.

    Which is the shape of the duplicate rule generally: it is about
    identities, not versions.  Two pending anchors are one authority when they
    carry one ``(ID, root SPKI)`` or one signing key, and one authority is
    either succession, where it keeps its name, or a refusal, where it does
    not; it is never two candidates.  Version numbers decide nothing about
    that -- all they say is which of two anchors of one authority is the
    survivor, and which of two bundles is "later" at all.

    The refusal names both anchors, because the producer's fix is to decide
    which of the two the authority is filed under.  A pending bundle already
    active is skipped before any of this (it is in ``trusted_bundles``), and
    an anchor skipped as a rename is admitted to nothing, so neither can make
    a later bundle collide.

    Between them these rules leave no shape in which two outcomes of one
    witness rest on one authority's signature, which is why
    ``_v2_witness_evidence``'s duplicate-timestamp refusal is now defence in
    depth: to reach it, two outcomes would have to select two anchors that
    both pin the certificate one response was signed with, and every pairing
    of anchors that could is refused before an outcome is read.  Its text is
    kept, and the tests that bind it reach it by blinding this function's
    view of the pending anchors' signers.
    """

    active_authorities, active_signers_by_authority = _active_anchor_identities(
        records, trusted_bundles, spec=spec
    )
    candidates: dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
    admitted_authorities: dict[tuple[str, str], tuple[str, str]] = {}
    admitted_anchor_signers: dict[tuple[str, str], set[str]] = {}
    admitted_signers: dict[str, str] = {}

    def admit_a_pending_anchor(
        authority: tuple[str, str],
        signers: set[str],
        key: tuple[str, str],
        here: str,
    ) -> None:
        superseded = admitted_authorities.get(authority)
        if superseded is not None:
            # A later pending bundle's anchor with the same (ID, root SPKI):
            # the same authority, carried forward.  It replaces its
            # predecessor in the candidate set and releases its predecessor's
            # keys, so that a rotation between two pending versions is not
            # read as two anchors sharing a signer.
            candidates.pop(superseded, None)
            for fingerprint in admitted_anchor_signers.pop(superseded, set()):
                admitted_signers.pop(fingerprint, None)
        earlier = next(
            (
                admitted_signers[fingerprint]
                for fingerprint in sorted(signers)
                if fingerprint in admitted_signers
            ),
            None,
        )
        if earlier is not None:
            raise TsaError(
                "pending TSA bundles introduce one authority under two "
                f"anchors: {earlier} and {here}"
            )
        admitted_authorities[authority] = key
        admitted_anchor_signers[key] = set(signers)
        for fingerprint in signers:
            admitted_signers[fingerprint] = here

    for reference in sorted(transition_bundle_updates, key=_pending_bundle_version):
        bundle_path = str(reference["path"])
        if bundle_path in trusted_bundles:
            continue
        _path, trust = _load_trust_bundle(records, reference, spec=spec)
        for anchor in trust["anchors"]:
            anchor_id = str(anchor["id"])
            authority = _anchor_authority(anchor)
            if authority in active_authorities:
                continue
            signers = _anchor_signer_fingerprints(anchor)
            owners = [
                owner
                for owner, active in active_signers_by_authority.items()
                if active & signers
            ]
            if owners:
                if all(
                    active_signers_by_authority[owner] == signers
                    for owner in owners
                ):
                    continue
                raise TsaError(
                    f"pending TSA anchor {anchor_id} splits or merges active "
                    "authorities' signers; a pending anchor must carry one "
                    "active anchor's signers exactly, or none of them"
                )
            admit_a_pending_anchor(
                authority,
                signers,
                (bundle_path, anchor_id),
                f"{bundle_path}/{anchor_id}",
            )
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
    # Four rules, because the name an outcome points at, the object that name
    # reaches, the bytes it claims are there and the timestamp inside them are
    # four different things.  The first is the physical path itself.  Two
    # outcomes may not name one file, whatever they say is in it: each outcome
    # reads the path for itself, so a writer with access to the records tree
    # can serve one valid response to the first read and another to the
    # second, and both outcomes verify over evidence no single state of the
    # repository ever held -- the two declared digests describe two files, and
    # there is one (peer review, fifth gate round one).  Compared as the
    # module resolves a claim into a file, so the two spellings physical_path
    # maps together -- with and without the leading ``records`` component --
    # are one path and not two.  And compared over _path_fold rather than over
    # the resolved spelling, because a spelling is not a directory entry
    # either: on a case- or normalisation-insensitive filesystem Token.tsr and
    # token.tsr, or a precomposed name and its decomposed spelling, name one
    # entry while comparing distinct, and a writer replacing that entry
    # between the two reads then defeats the object rule as well -- two reads,
    # two inodes, one name (fifth gate round three).  Refusing fold-equal
    # spellings is deliberately conservative: a case-sensitive filesystem can
    # hold two genuinely distinct files whose names fold together, and a
    # witness whose meaning depends on which filesystem an auditor cloned onto
    # is not one an auditor can act on.  Two outcomes spelling one path
    # identically keep the plainer message they had; two spelling it two ways
    # are told why the two are one.
    #
    # What that comparison is about is a name, and a name is not a file.  The
    # containment check inside physical_path resolves, but the value it
    # returns and the value compared here do not, so a symlinked parent
    # directory or a second hard link gives one object two paths that are
    # distinct by every lexical measure (peer review, fifth gate round two).
    # The declared-digest rule below does not close that either: with the same
    # writer arriving between the two reads, the two outcomes read different
    # bytes out of one object and each declares truly what it read.  So the
    # second rule is the object.  Every response is read through one
    # descriptor, and the fstat that judges that descriptor also says which
    # object it is -- (st_dev, st_ino), taken from the descriptor the bytes
    # came out of rather than from a second look at the name, which would be
    # the very race being refused.  The refusal names both spellings, because
    # what a producer has to fix is that two of its outcomes point at one
    # file.  It fires at the read, inside the token verifier, which is the
    # earliest the identity exists and still before those bytes reach OpenSSL.
    #
    # Then the file an outcome claims, refused before that outcome's token is
    # verified so that a duplicate is never put to
    # OpenSSL at all.  It is not enough on its own: nearly everything between
    # the file and the signature is the producer's to rewrite -- a
    # TimeStampResp's PKIStatusInfo wrapper is unsigned, and inside the token
    # a SignedData's certificates, crls and unsignedAttrs are outside the
    # signature -- so one issuance has many valid encodings with different
    # file digests, and any of them satisfies a rule that counts files.  The
    # other rule counts what an authority signed: the _TimestampIdentity
    # _verify_timestamp_token returns beside its evidence, which pairs the
    # digest of the TSTInfo -- unmovable by any re-encoding, because moving it
    # breaks the signature the -CAfile verification checks -- with the digest
    # of the certificate that verification authenticated the signature with.
    # Both halves, because a TSTInfo does not have to say whose it is: RFC
    # 3161 makes its serial unique within one TSA and no further, and its
    # nonce and its tsa name optional, so two independent pinned authorities
    # can sign byte-identical TSTInfos with no forgery at all, and counting
    # the signed content alone refuses the second of two valid outcomes (peer
    # review, fifth gate round one).  The pair is knowable only once the
    # verification has run, so it is checked where _verify_timestamp_token
    # returns (fourth gate round four).  The file rule therefore fires when
    # two outcomes name the same bytes, and the timestamp rule when they name
    # different bytes carrying one authority's one timestamp.
    #
    # All four refusals are new, and the path, object and digest rules precede
    # the ported refusals inside verify_timestamp_token for the outcome they
    # stop.  Admissible because the inputs they refuse are ones the pinned
    # tree cannot present: its 53 witnesses declare 91 tokens at 91 distinct
    # physical paths naming 91 distinct files, with 91 distinct file digests
    # and 91 distinct signed TSTInfos -- distinct before the signer qualifies
    # them, so distinct after -- and no witness names one path twice.  The
    # file rule reads the
    # outcome's declared tokenSha256 and records TokenEvidence.token_sha256 --
    # the digest of the bytes that were actually read and verified -- so a
    # declared digest that lies is caught by the ported witness-token-hash
    # refusal first and the rule only ever remembers a true one.  The path
    # rule has no such gap to mind: the path an outcome declares is the file
    # this module goes on to open, so it is remembered where it is checked.
    #
    # Order among them is the order they were added, and it decides only which
    # message a witness that breaks two rules at once gets.  Two outcomes
    # naming one file with one digest are the plainer reuse and keep the
    # digest rule's message, as they had it; what the path rule reaches is the
    # case the digest rule cannot see, two different digests over one path,
    # fold-equal spellings included; and what the object rule reaches is the
    # case neither can, two paths that are not fold-equal over one file.
    seen_token_paths: dict[tuple[str, ...], Path] = {}
    seen_token_files: dict[tuple[int, int], Path] = {}
    seen_response_files: set[str] = set()
    seen_timestamps: set[_TimestampIdentity] = set()

    def refuse_a_reused_response_file(declared: Any) -> None:
        # Only a string can have been recorded, and a claim carrying anything
        # else is left to the ported witness-token-hash refusal below.
        if isinstance(declared, str) and declared in seen_response_files:
            raise TsaError(
                f"duplicate TSA response file across anchor outcomes: {declared}"
            )

    def refuse_a_reused_token_path(declared: Any) -> None:
        # A claim with no tokenPath, or one physical_path refuses, is left
        # alone: verify_timestamp_token raises those refusals itself, in the
        # place it has always raised them, and moving one here would move a
        # ported message relative to the checks around it.
        if not isinstance(declared, str):
            return
        try:
            physical = physical_path(records, declared)
        except TsaError:
            return
        earlier = seen_token_paths.get(_path_fold(physical))
        if earlier is not None:
            if earlier == physical:
                raise TsaError(
                    f"duplicate TSA token path across anchor outcomes: {physical}"
                )
            # Two spellings, one directory entry wherever this tree is
            # cloned onto a case- or normalisation-insensitive filesystem.
            # Both are named, because what a producer has to fix is that two
            # of its outcomes spell one path two ways.
            raise TsaError(
                f"duplicate TSA token path across anchor outcomes: {physical} "
                f"and {earlier} are one path on a case- or "
                "normalisation-insensitive filesystem"
            )
        seen_token_paths[_path_fold(physical)] = physical

    def refuse_a_reused_token_file(physical: Path, identity: tuple[int, int]) -> None:
        # Handed to the read inside the token verifier, so it speaks before
        # the duplicate's bytes are put to OpenSSL.  Both spellings are named:
        # the point of the refusal is that two outcomes reach one file, and a
        # producer cannot act on being told only about the second.
        earlier = seen_token_files.get(identity)
        if earlier is not None:
            raise TsaError(
                f"duplicate TSA token file across anchor outcomes: {physical} "
                f"is the same file as {earlier}"
            )
        seen_token_files[identity] = physical

    def refuse_a_reused_timestamp(identity: _TimestampIdentity) -> None:
        if identity in seen_timestamps:
            raise TsaError(
                "duplicate TSA timestamp across anchor outcomes: signer "
                f"{identity.signer_certificate_sha256}, timestamp "
                f"{identity.tst_info_sha256}"
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
            refuse_a_reused_token_path(claim.get("tokenPath"))
            evidence, identity = _verify_timestamp_token(
                path,
                claim,
                bundle_reference,
                spec=spec,
                records=records,
                now=now,
                record=record,
                on_token_read=refuse_a_reused_token_file,
            )
            refuse_a_reused_timestamp(identity)
            seen_response_files.add(evidence.token_sha256)
            seen_timestamps.add(identity)
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
            refuse_a_reused_token_path(outcome.get("tokenPath"))
            evidence, identity = _verify_timestamp_token(
                path,
                outcome,
                reference,
                spec=spec,
                records=records,
                now=now,
                record=record,
                on_token_read=refuse_a_reused_token_file,
            )
            refuse_a_reused_timestamp(identity)
            seen_response_files.add(evidence.token_sha256)
            seen_timestamps.add(identity)
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
    """Verify one record's RFC 3161 witness against a consumer-pinned spec.

    ``transition_bundle_updates`` is the trust transition in flight when this
    record was written: the pending bundle updates of the records before it,
    plus this record's own.  A caller walking a chain accumulates the first
    kind and cannot be asked to leave them out, so the argument stays a list
    of both -- but this record's own are derived here, from the bytes this
    call read and hashed, and never taken from the caller's word for them.

    Deriving them and comparing is the whole of the fix.  A supplied list was
    trusted entire, so the token evidence covered the snapshot this call read
    while the updates evaluated beside it came from a different, earlier read
    of the same path: a concurrent replacement made the evidence describe
    record B and the transition describe record A (peer review, fifth gate
    round two).  Every update the snapshot carries must now appear in the
    supplied list -- by equality of the update mapping, which is the whole of
    what a bundle reference is -- or this refuses.

    Say plainly what that does and does not close.  The comparison is one-way
    -- every derived update must be in the supplied list, and the supplied
    list may hold more -- because a supplied list is a superset by design.  So
    a caller that supplies this record's updates *from an earlier read of this
    record*, beside the snapshot's own, cannot be told apart from one
    supplying earlier records' pending updates: both are extra entries, and
    nothing in this shape says which record an extra entry came from.  A
    stale extra is therefore evaluated -- the transition the verification
    weighs is the supplied list -- and what the comparison guarantees is only
    that nothing the snapshot carries is missing.

    That residual belongs to this shape and not to the machinery, and it is
    why the module-level ``_verify_witness_with_updates`` takes
    ``prior_pending_updates`` instead: the pending updates of *earlier*
    records only, which it combines with the snapshot's own rather than
    trusting a list that mixes the two.  It returns the snapshot-derived
    updates beside the evidence, so a chain walker accumulates this record's
    from the verification rather than from a read of its own and never has
    both kinds to hand at once -- and there is then no extra entry to
    attribute, because the caller supplies no entry that could be this
    record's.  This shape stays because the upstream integration this module
    is a port of walks its chain exactly this way, and its signature is
    0.5.1's.
    """

    evidence, _updates = _verify_witness_with_updates(
        path,
        spec=spec,
        records=records,
        now=now,
        trusted_bundles=trusted_bundles,
        transition_bundle_updates=transition_bundle_updates,
    )
    return evidence


def _verify_witness_with_updates(
    path: Path,
    *,
    spec: TsaSpec,
    records: Path | None = None,
    now: datetime | None = None,
    trusted_bundles: Mapping[str, dict[str, Any]] | None = None,
    transition_bundle_updates: list[dict[str, Any]] | None = None,
    prior_pending_updates: list[dict[str, Any]] | None = None,
) -> tuple[WitnessEvidence, list[dict[str, Any]]]:
    """``verify_witness``, and the record's own trust-bundle updates.

    Every refusal and every check's place belongs to the public function; this
    is where its body lives.  The second return value is the list derived from
    the bytes this call read -- validated, in the record's own order -- so a
    caller that has to carry this record's pending updates forward takes them
    from the verification instead of reading the record again.

    The two kinds of update are separate here, which is what the public
    function's one list cannot do.  ``prior_pending_updates`` is the pending
    updates of *earlier* records and nothing else; this record's own are
    derived from the snapshot, and the transition the verification weighs is
    the two combined -- prior first, then the snapshot's, each mapping
    admitted once, since a reference repeated across the two describes one
    bundle and walking it twice would refuse it as its own alias.  So there is
    no entry in the transition this call did not either derive or attribute to
    a record before this one, and the stale extra the supplied-list shape
    cannot see has nowhere to enter (peer review, fifth gate round three).

    ``transition_bundle_updates`` is the other shape, the public function's:
    prior and current together from the caller's own read, checked to contain
    every derived update and then used entire.  The two are mutually
    exclusive, and supplying both is a ``TypeError`` rather than a refusal --
    there is no reading of a call that says "these are the earlier records'
    updates" and "these are the earlier records' updates and this one's" at
    once, and quietly preferring one of them is how a caller ends up believing
    the other was honoured.
    """

    if transition_bundle_updates is not None and prior_pending_updates is not None:
        raise TypeError(
            "supply transition_bundle_updates or prior_pending_updates, not both"
        )
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
    # The ported refusal, in its ported words and its ported place; what is
    # new is that it now also answers for a sidecar the read cannot have --
    # a FIFO raced in behind the check, or a symlink -- rather than the
    # check passing and the read waiting or following.
    witness = _load_json_once(
        witness_path, label=f"missing explicit witness marker for {path}"
    )
    if witness.get("digestSha256") != digest_sha:
        raise TsaError(
            f"witness digest mismatch for {path}: expected {digest_sha}, "
            f"got {witness.get('digestSha256')}"
        )
    if trusted_bundles is None:
        genesis_path = records / "CHAIN_GENESIS.json"
        genesis = _load_json_once(
            genesis_path,
            label=f"chain genesis is missing or not a regular file: {genesis_path}",
        )
        trusted_bundles = bootstrap_trust_bundles(
            records, genesis, spec=spec, required=True
        )
    # The record's own updates, from the snapshot, always.  When the caller
    # supplied a list this used to be skipped entirely, and the list was taken
    # on trust; now it is derived either way, in the same place, and a
    # supplied list is compared with it rather than believed.
    supplied = transition_bundle_updates
    updates = trust_bundle_updates(records, _record_payload(record, path), spec=spec)
    if supplied is None:
        # The shape with nothing left over: the earlier records' pending
        # updates, and this record's own from the snapshot.  Combined here so
        # that no caller ever has to hold both kinds and hand them over as
        # one.  Deduplicated by mapping equality, which is the whole of what a
        # bundle reference is: one reference named twice is one bundle, and
        # walking it twice would refuse it as an alias of itself.
        transition_bundle_updates = []
        for update in (*(prior_pending_updates or ()), *updates):
            if update not in transition_bundle_updates:
                transition_bundle_updates.append(update)
    else:
        if any(update not in supplied for update in updates):
            raise TsaError(
                "transition bundle updates supplied by the caller omit the "
                "witnessed record's own"
            )
        # Used as given: it carries the pending updates of earlier records,
        # which this call has no way to derive and no business dropping --
        # and, indistinguishably, whatever else the caller put in it, which
        # is the residual verify_witness's docstring states.
        transition_bundle_updates = supplied
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
        return (
            _v1_witness_evidence(
                path,
                witness,
                spec=spec,
                records=records,
                record=record,
                digest_sha256=digest_sha,
                trusted_bundles=trusted_bundles,
                now=now,
            ),
            updates,
        )
    if schema == "thesis_rfc3161_witness_v2":
        return (
            _v2_witness_evidence(
                path,
                witness,
                spec=spec,
                records=records,
                record=record,
                digest_sha256=digest_sha,
                trusted_bundles=trusted_bundles,
                transition_bundle_updates=transition_bundle_updates,
                now=now,
            ),
            updates,
        )
    raise TsaError(f"unsupported witness schema for {path}")
