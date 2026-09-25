"""An anchor may pin more than one responder certificate under its root.

Timestamp authorities replace their responder certificate periodically, and
receipts already in a chain stay signed by the old one. DigiCert did so in
2026 ("DigiCert SHA256 RSA4096 Timestamp Responder 2026 1"); a chain pinning
only the old responder refused every new release, and a chain pinning only the
new one would refuse every old release. ``AnchorSpec.additional_signers`` lets
the consumer keep the old pin and add the new one.

These tests use locally generated authorities (tests/corpus_fixture.py): the
rotated responder is issued from the same root key, as a real rotation is, so
every value checked is a real certificate and SPKI digest.
"""

from __future__ import annotations

import dataclasses
import itertools
import pathlib
import shutil

import pytest

from corpus_fixture import (
    LocalTsa,
    append_release,
    build_corpus,
    rotate_tsa_signer,
)
from receipt.release_chain import (
    AnchorSpec,
    ChainSpec,
    PinnedSigner,
    ReleaseChainError,
    _check_signer_pins,
    verify_release_chain,
)
from receipt.verify import load_spec

OTHER = PinnedSigner(certificate_sha256="a" * 64, spki_sha256="b" * 64)


@pytest.fixture
def rotated_chain(tmp_path: pathlib.Path) -> tuple[pathlib.Path, ChainSpec, LocalTsa]:
    """Release 0 signed by alpha's first responder, release 1 by its second."""

    root = tmp_path / "corpus"
    workspace = tmp_path / "workspace"
    build_corpus(root, workspace, commit=False)
    spec = load_spec(root / "verification" / "spec.py").verification.chain
    original = workspace / "alpha"
    source = LocalTsa(
        name="alpha",
        directory=original,
        root_pem=original / "alpha-root.pem",
        policy_oid=spec.anchors["alpha"].policy_oid,
        signer_certificate_sha256=spec.anchors["alpha"].signer_certificate_sha256,
        signer_spki_sha256=spec.anchors["alpha"].signer_spki_sha256,
    )
    rotated = rotate_tsa_signer(source, tmp_path / "alpha-rotated")
    # append_release stamps with whatever responder workspace/alpha holds; the
    # rotated directory carries the same root and policy, only a new signer.
    shutil.move(str(original), str(tmp_path / "alpha-first"))
    shutil.copytree(rotated.directory, original)
    append_release(
        root,
        workspace,
        content={"rules/tax/rate.yaml": "name: rate\nvalue: 0.16\n"},
        commit=False,
    )
    return root, spec, rotated


def _with_alpha(spec: ChainSpec, **changes: object) -> ChainSpec:
    anchors = dict(spec.anchors)
    anchors["alpha"] = dataclasses.replace(anchors["alpha"], **changes)
    return dataclasses.replace(spec, anchors=anchors)


def _verify(root: pathlib.Path, spec: ChainSpec):
    return verify_release_chain(
        root,
        spec=spec,
        require_chain=True,
        verify_state=True,
        enforce_production_pins=True,
    )


def test_a_single_pin_refuses_the_rotated_responder_with_the_061_text(
    rotated_chain,
) -> None:
    """Without the new entry nothing changes: the 0.6.1 refusal, byte for byte."""

    root, spec, rotated = rotated_chain
    with pytest.raises(ReleaseChainError) as refusal:
        _verify(root, spec)
    assert str(refusal.value).startswith("RFC 3161 signer certificate is not pinned for 0001-")
    assert str(refusal.value).endswith(f".alpha.tsr: {rotated.signer_certificate_sha256}")


def test_keeping_the_old_pin_and_adding_the_new_one_verifies_both_eras(
    rotated_chain,
) -> None:
    root, spec, rotated = rotated_chain
    widened = _with_alpha(
        spec,
        additional_signers=(
            PinnedSigner(
                certificate_sha256=rotated.signer_certificate_sha256,
                spki_sha256=rotated.signer_spki_sha256,
            ),
        ),
    )
    verification = _verify(root, widened)
    assert len(verification.releases) == 2


def test_replacing_the_old_pin_refuses_the_old_era(rotated_chain) -> None:
    """Substituting the pin is the wrong fix: release 0 stops verifying."""

    root, spec, rotated = rotated_chain
    old_certificate = spec.anchors["alpha"].signer_certificate_sha256
    replaced = _with_alpha(
        spec,
        signer_certificate_sha256=rotated.signer_certificate_sha256,
        signer_spki_sha256=rotated.signer_spki_sha256,
    )
    with pytest.raises(ReleaseChainError) as refusal:
        _verify(root, replaced)
    assert str(refusal.value).startswith("RFC 3161 signer certificate is not pinned for 0000-")
    assert str(refusal.value).endswith(f".alpha.tsr: {old_certificate}")


def test_certificate_and_key_are_one_entry(rotated_chain) -> None:
    """The rotated certificate with some other entry's key is not a pin."""

    root, spec, rotated = rotated_chain
    crossed = _with_alpha(
        spec,
        additional_signers=(
            PinnedSigner(
                certificate_sha256=rotated.signer_certificate_sha256,
                spki_sha256=spec.anchors["alpha"].signer_spki_sha256,
            ),
        ),
    )
    with pytest.raises(ReleaseChainError) as refusal:
        _verify(root, crossed)
    assert str(refusal.value) == (
        "RFC 3161 signer SPKI is not pinned for "
        f"{sorted(root.glob('releases/manifests/0001-*.alpha.tsr'))[0].name}: "
        f"{rotated.signer_spki_sha256}"
    )


# --- construction ------------------------------------------------------------

BASE = dict(
    filename="alpha-root.pem",
    pem_sha256="1" * 64,
    policy_oid="1.3.6.1.4.1.99999.1.1",
    signer_certificate_sha256="2" * 64,
    signer_spki_sha256="3" * 64,
)


def test_the_061_spelling_constructs_unchanged() -> None:
    anchor = AnchorSpec(**BASE)  # type: ignore[arg-type]
    assert anchor.additional_signers == ()
    assert anchor.signers == (PinnedSigner("2" * 64, "3" * 64),)


def test_the_061_positional_spelling_constructs_unchanged() -> None:
    anchor = AnchorSpec(*BASE.values())  # type: ignore[arg-type]
    assert anchor == AnchorSpec(**BASE)  # type: ignore[arg-type]


def test_signers_lists_the_primary_first() -> None:
    anchor = AnchorSpec(**BASE, additional_signers=(OTHER,))  # type: ignore[arg-type]
    assert anchor.signers == (PinnedSigner("2" * 64, "3" * 64), OTHER)


@pytest.mark.parametrize("value", [[OTHER], {OTHER}, frozenset({OTHER}), None, OTHER])
def test_additional_signers_must_be_a_tuple(value: object) -> None:
    with pytest.raises(ReleaseChainError, match="additional_signers must be a tuple"):
        AnchorSpec(**BASE, additional_signers=value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["a" * 64, ("a" * 64, "b" * 64), {"certificate_sha256": "a" * 64}])
def test_additional_signers_entries_must_be_pinned_signers(value: object) -> None:
    with pytest.raises(ReleaseChainError, match="entries must be PinnedSigner"):
        AnchorSpec(**BASE, additional_signers=(value,))  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["certificate_sha256", "spki_sha256"])
@pytest.mark.parametrize("value", [None, "", "a" * 63, "A" * 64, "z" * 64, 0])
def test_a_pinned_signer_digest_that_is_not_a_digest_refuses(field: str, value: object) -> None:
    good = {"certificate_sha256": "a" * 64, "spki_sha256": "b" * 64}
    with pytest.raises(ReleaseChainError, match=f"PinnedSigner {field}"):
        PinnedSigner(**{**good, field: value})  # type: ignore[arg-type]


def test_a_repeated_certificate_refuses() -> None:
    with pytest.raises(ReleaseChainError, match="more than once"):
        AnchorSpec(  # type: ignore[arg-type]
            **BASE, additional_signers=(PinnedSigner("2" * 64, "3" * 64),)
        )
    with pytest.raises(ReleaseChainError, match="more than once"):
        AnchorSpec(**BASE, additional_signers=(OTHER, OTHER))  # type: ignore[arg-type]


def test_an_anchor_with_additional_signers_is_hashable_and_replaceable() -> None:
    anchor = AnchorSpec(**BASE, additional_signers=(OTHER,))  # type: ignore[arg-type]
    assert hash(anchor) == hash(dataclasses.replace(anchor))
    assert dataclasses.replace(anchor, filename="x.pem").additional_signers == (OTHER,)


# --- invariants, exhaustively over a small digest domain ----------------------
#
# The pin decision is a pure function of the anchor and the two digests OpenSSL
# computed, so it is checked here for every anchor whose signers are drawn from
# a three-certificate, three-key domain (the primary pin plus zero, one or two
# additional entries in every order, certificates distinct as construction
# requires) against every presented pair, including a certificate outside the
# domain. That is 225 anchors by 12 pairs. The invariants:
#
#   I1  acceptance: a pair is accepted if and only if it is one entry of
#       ``anchor.signers``; the certificate of one entry with the key of
#       another is refused.
#   I2  refusal text: an unknown certificate is refused naming the
#       certificate, and a known certificate with an unpinned key is refused
#       naming the key.
#   I3  0.6.1 equivalence: with no additional signers every verdict, refusal
#       text included, is the one the 0.6.1 pair of comparisons returns.
#   I4  order: permuting ``additional_signers`` never changes a verdict.

CERTIFICATES = ("c" * 64, "d" * 64, "e" * 64)
KEYS = ("1" * 64, "2" * 64, "3" * 64)
UNKNOWN_CERTIFICATE = "f" * 64
RECEIPT = "0021-7834dc471863e2a2.digicert.tsr"


def _anchor(primary: PinnedSigner, additional: tuple[PinnedSigner, ...]) -> AnchorSpec:
    return AnchorSpec(  # type: ignore[arg-type]
        **{
            **BASE,
            "signer_certificate_sha256": primary.certificate_sha256,
            "signer_spki_sha256": primary.spki_sha256,
        },
        additional_signers=additional,
    )


def _all_anchors():
    pairs = [PinnedSigner(c, k) for c in CERTIFICATES for k in KEYS]
    for primary in pairs:
        others = [p for p in pairs if p.certificate_sha256 != primary.certificate_sha256]
        for size in (0, 1, 2):
            for additional in itertools.permutations(others, size):
                if len({p.certificate_sha256 for p in additional}) != size:
                    continue
                yield _anchor(primary, additional)


def _presented():
    return [(c, k) for c in (*CERTIFICATES, UNKNOWN_CERTIFICATE) for k in KEYS]


def _verdict(anchor: AnchorSpec, certificate: str, key: str) -> str | None:
    try:
        _check_signer_pins(
            anchor, RECEIPT, certificate_sha256=certificate, spki_sha256=key
        )
    except ReleaseChainError as refusal:
        return str(refusal)
    return None


def _verdict_061(anchor: AnchorSpec, certificate: str, key: str) -> str | None:
    """The 0.6.1 check, transcribed: two comparisons against one pin."""

    if certificate != anchor.signer_certificate_sha256:
        return f"RFC 3161 signer certificate is not pinned for {RECEIPT}: {certificate}"
    if key != anchor.signer_spki_sha256:
        return f"RFC 3161 signer SPKI is not pinned for {RECEIPT}: {key}"
    return None


ANCHORS = list(_all_anchors())


def test_the_domain_is_the_one_described() -> None:
    assert len(ANCHORS) == 225
    assert len(_presented()) == 12
    assert len({anchor.signers for anchor in ANCHORS}) == 225


def test_i1_accepted_exactly_when_the_pair_is_one_entry() -> None:
    for anchor in ANCHORS:
        entries = {(p.certificate_sha256, p.spki_sha256) for p in anchor.signers}
        for certificate, key in _presented():
            accepted = _verdict(anchor, certificate, key) is None
            assert accepted == ((certificate, key) in entries), (anchor, certificate, key)


def test_i2_each_refusal_names_what_was_not_pinned() -> None:
    for anchor in ANCHORS:
        pinned = {p.certificate_sha256 for p in anchor.signers}
        for certificate, key in _presented():
            verdict = _verdict(anchor, certificate, key)
            if verdict is None:
                continue
            if certificate not in pinned:
                assert verdict == (
                    f"RFC 3161 signer certificate is not pinned for {RECEIPT}: "
                    f"{certificate}"
                )
            else:
                assert verdict == f"RFC 3161 signer SPKI is not pinned for {RECEIPT}: {key}"


def test_i3_without_additional_signers_every_verdict_is_the_061_verdict() -> None:
    single = [anchor for anchor in ANCHORS if not anchor.additional_signers]
    assert len(single) == 9
    for anchor in single:
        for certificate, key in _presented():
            assert _verdict(anchor, certificate, key) == _verdict_061(
                anchor, certificate, key
            )


def test_i4_the_order_of_additional_signers_never_changes_a_verdict() -> None:
    for anchor in ANCHORS:
        for order in itertools.permutations(anchor.additional_signers):
            reordered = dataclasses.replace(anchor, additional_signers=order)
            for certificate, key in _presented():
                assert _verdict(reordered, certificate, key) == _verdict(
                    anchor, certificate, key
                )
