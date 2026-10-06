"""The consumer's committed spec must refuse to describe a pin it has not set.

Every value in a ``ChainSpec`` is a trust anchor, and the failure mode these
tests bind is the anchor that is absent rather than wrong. An absent pin does
not announce itself: ``producer_spki_sha256=None`` was handed to the signing
module, which reads ``None`` as "no pin requested" and skips the comparison, so
a chain re-signed under a substituted key verified end to end; an empty
``anchors`` mapping satisfies the receipt-set equality check vacuously, so no
witness is verified and the verdict still reads like custody. Both are refused
at construction now, which is the only place the consumer can see that the
fault is in their own configuration.

The valid spec below is the one the fixture builds, so a refusal here is
always about the single field the test overrode.
"""

from __future__ import annotations

import pathlib

import pytest

from receipt.release_chain import AnchorSpec, ChainSpec, ReleaseChainError

VALID_ANCHOR = dict(
    filename="alpha-root.pem",
    pem_sha256="a" * 64,
    policy_oid="1.3.6.1.4.1.99999.1.1",
    signer_certificate_sha256="b" * 64,
    signer_spki_sha256="c" * 64,
)

VALID_CHAIN = dict(
    manifest_relative=pathlib.PurePosixPath("releases/manifests"),
    state_relative=pathlib.PurePosixPath("receipt/journal.jsonl"),
    prefix_relative=pathlib.PurePosixPath("receipt/prefix.json"),
    anchor_relative=pathlib.PurePosixPath("releases/anchors"),
    release_root_relative=pathlib.PurePosixPath("releases"),
    schema_version="t",
    producer_public_key_filename="producer-ed25519.pub",
    producer_spki_sha256="d" * 64,
    anchors={"alpha": AnchorSpec(**VALID_ANCHOR)},  # type: ignore[arg-type]
)


def anchor(**overrides: object) -> AnchorSpec:
    return AnchorSpec(**{**VALID_ANCHOR, **overrides})  # type: ignore[arg-type]


def chain(**overrides: object) -> ChainSpec:
    return ChainSpec(**{**VALID_CHAIN, **overrides})  # type: ignore[arg-type]


def test_the_fixture_values_still_construct() -> None:
    """The refusals below mean nothing unless a real spec still builds."""

    built = chain()
    assert built.state_path == "receipt/journal.jsonl"
    assert set(built.anchors) == {"alpha"}


# --- the producer pin -------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "d" * 63,
        "d" * 65,
        "D" * 64,
        "g" * 64,
        b"d" * 64,
        64,
    ],
)
def test_a_producer_pin_that_cannot_pin_refuses_at_construction(
    value: object,
) -> None:
    """The demonstrated hole: with ``None`` here the SPKI comparison was
    skipped entirely, a substituted producer key verified, and the command
    failed only in the verdict text, where a prefix was sliced off ``None``."""

    with pytest.raises(ReleaseChainError, match="producer_spki_sha256"):
        chain(producer_spki_sha256=value)


# --- the anchor set ---------------------------------------------------------


def test_a_spec_with_no_anchors_refuses_at_construction() -> None:
    """A chain with no configured witness cannot be witnessed: the receipt-set
    equality check passes vacuously, every manifest verifies with zero
    receipts, and the verdict claims custody it never established."""

    with pytest.raises(ReleaseChainError, match="non-empty mapping"):
        chain(anchors={})


@pytest.mark.parametrize("value", [None, (), [], "alpha", 1])
def test_an_anchors_field_that_is_not_a_mapping_refuses(value: object) -> None:
    with pytest.raises(ReleaseChainError, match="non-empty mapping"):
        chain(anchors=value)


@pytest.mark.parametrize("name", ["", b"alpha", 1, None])
def test_an_anchor_name_that_is_not_a_name_refuses(name: object) -> None:
    with pytest.raises(ReleaseChainError, match="anchor names"):
        chain(anchors={name: anchor()})


@pytest.mark.parametrize("value", [None, "alpha-root.pem", {"pem_sha256": "a" * 64}])
def test_an_anchor_value_that_is_not_an_AnchorSpec_refuses(value: object) -> None:
    with pytest.raises(ReleaseChainError, match="must be an AnchorSpec"):
        chain(anchors={"alpha": value})


# --- each anchor's own pins -------------------------------------------------


@pytest.mark.parametrize(
    "field",
    ["pem_sha256", "signer_certificate_sha256", "signer_spki_sha256"],
)
@pytest.mark.parametrize("value", [None, "", "a" * 63, "A" * 64, "z" * 64, 0])
def test_an_anchor_digest_pin_that_is_not_a_digest_refuses(
    field: str, value: object
) -> None:
    with pytest.raises(ReleaseChainError, match=field):
        anchor(**{field: value})


@pytest.mark.parametrize(
    "value",
    [None, "", "1", "1.", ".1", "1..2", "1.2.a", "1.02", " 1.2", "1.2 ", 12],
)
def test_a_policy_oid_that_is_not_a_dotted_decimal_oid_refuses(
    value: object,
) -> None:
    """The pin is compared against the OID OpenSSL prints. A spelling OpenSSL
    never emits — a leading-zero arc, a single arc, trailing space — can only
    ever mismatch, and the refusal would name the receipt rather than the
    spec line that is actually wrong."""

    with pytest.raises(ReleaseChainError, match="policy_oid"):
        anchor(policy_oid=value)


@pytest.mark.parametrize("value", ["1.2", "0.0", "2.16.840.1.114412.7.1"])
def test_real_policy_oids_are_accepted(value: str) -> None:
    assert anchor(policy_oid=value).policy_oid == value


# --- the five relative paths ------------------------------------------------

PATH_FIELDS = (
    "manifest_relative",
    "state_relative",
    "prefix_relative",
    "anchor_relative",
    "release_root_relative",
)


@pytest.mark.parametrize("field", PATH_FIELDS)
@pytest.mark.parametrize(
    "value",
    [
        "releases/manifests",
        pathlib.PureWindowsPath("releases/manifests"),
        None,
        b"releases",
    ],
)
def test_a_path_field_that_is_not_a_posix_pure_path_refuses(
    field: str, value: object
) -> None:
    """A string joins by a different rule than a path, and a Windows pure path
    joins by parts that address a file its spelling does not name."""

    with pytest.raises(ReleaseChainError, match="PurePosixPath"):
        chain(**{field: value})


@pytest.mark.parametrize("field", PATH_FIELDS)
@pytest.mark.parametrize(
    "spelling",
    ["/etc/anchors", "../outside", "releases/../../outside", "", "."],
)
def test_a_path_field_that_leaves_the_tree_refuses(
    field: str, spelling: str
) -> None:
    """Each of these is joined onto the auditor's root. An absolute path or a
    ``..`` component addresses a file outside the tree under audit, and the
    join reports nothing unusual when it lands there."""

    with pytest.raises(ReleaseChainError, match="relative path"):
        chain(**{field: pathlib.PurePosixPath(spelling)})
