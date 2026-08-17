"""The anchor-set digest: a verdict names which anchors were in force.

receipt#24's second half. The digest computes only after every extracted check
has passed, so these tests own its whole behavior: the canonical form, the
refusals, and the property an auditor actually wants — a substituted anchor
set cannot share a digest with the production one.
"""

from __future__ import annotations

import hashlib
import pathlib
import shutil

import pytest

from receipt.release_chain import (
    ReleaseChainError,
    _anchor_set_digests,
    verify_release_chain,
)
from receipt.verify import load_spec

from corpus_fixture import build_corpus

ANCHOR_DIR = "releases/anchors"


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """One expensive build (RSA keygen ×2, two TSAs); copied per test."""

    base = tmp_path_factory.mktemp("chain-origin")
    root = base / "repo"
    root.mkdir()
    build_corpus(root, base / "tsa-workspace")
    return root


@pytest.fixture()
def repo(built: pathlib.Path, tmp_path: pathlib.Path) -> pathlib.Path:
    destination = tmp_path / "repo"
    shutil.copytree(built, destination, symlinks=True)
    return destination


def independent_digests(repo: pathlib.Path) -> tuple[str, dict[str, str]]:
    """Recompute the digest from the tree alone, sharing no code with the
    implementation — the exact recomputation an auditor would script."""

    per_file = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (repo / ANCHOR_DIR).iterdir()
    }
    combined = hashlib.sha256(
        "".join(
            f"{name} {digest}\n" for name, digest in sorted(per_file.items())
        ).encode("ascii")
    ).hexdigest()
    return combined, per_file


def spec_anchor_filenames(repo: pathlib.Path) -> set[str]:
    spec, _ = load_spec(repo / "verification/spec.py")
    return {
        spec.chain.producer_public_key_filename,
        *(anchor.filename for anchor in spec.chain.anchors.values()),
    }


def test_a_verified_chain_reports_the_anchor_set(repo: pathlib.Path) -> None:
    spec, _ = load_spec(repo / "verification/spec.py")
    verification = verify_release_chain(repo, spec=spec.chain)
    combined, per_file = independent_digests(repo)
    assert verification.anchor_set_sha256 == combined
    assert dict(verification.anchor_file_sha256s) == per_file
    # The set digested is exactly the set the spec configures — nothing an
    # extra file in the directory could smuggle in, nothing dropped.
    assert set(per_file) == spec_anchor_filenames(repo)


def test_a_substituted_anchor_set_cannot_share_the_digest(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """The auditing story: production verdict digests differ from any verdict
    produced against altered anchor material."""

    spec, _ = load_spec(repo / "verification/spec.py")
    substituted = tmp_path / "anchors"
    shutil.copytree(repo / ANCHOR_DIR, substituted)
    filename = sorted(anchor.filename for anchor in spec.chain.anchors.values())[0]
    target = substituted / filename
    data = bytearray(target.read_bytes())
    data[len(data) // 2] ^= 0x01
    target.write_bytes(bytes(data))

    production, _ = _anchor_set_digests(
        repo / ANCHOR_DIR, spec.chain, enforce_production_pins=True
    )
    altered, _ = _anchor_set_digests(
        substituted, spec.chain, enforce_production_pins=False
    )
    assert production != altered


def test_changed_pinned_anchor_bytes_are_a_refusal_not_a_misreport(
    repo: pathlib.Path,
) -> None:
    """With pins enforced, bytes that no longer match the code pin at digest
    time fail closed instead of being reported as the set in force."""

    spec, _ = load_spec(repo / "verification/spec.py")
    filename = sorted(anchor.filename for anchor in spec.chain.anchors.values())[0]
    target = repo / ANCHOR_DIR / filename
    data = bytearray(target.read_bytes())
    data[len(data) // 2] ^= 0x01
    target.write_bytes(bytes(data))

    with pytest.raises(ReleaseChainError, match="changed after verification"):
        _anchor_set_digests(
            repo / ANCHOR_DIR, spec.chain, enforce_production_pins=True
        )


def test_a_symlinked_anchor_file_refuses(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    spec, _ = load_spec(repo / "verification/spec.py")
    target = repo / ANCHOR_DIR / spec.chain.producer_public_key_filename
    aside = tmp_path / "aside.pub"
    aside.write_bytes(target.read_bytes())
    target.unlink()
    target.symlink_to(aside)

    with pytest.raises(ReleaseChainError, match="missing or non-regular anchor"):
        _anchor_set_digests(
            repo / ANCHOR_DIR, spec.chain, enforce_production_pins=False
        )


def test_an_anchor_filename_embedding_a_newline_refuses(
    repo: pathlib.Path,
) -> None:
    """The canonical form is newline-delimited lines; a filename that embeds
    a newline could let two different sets share one canonical string."""

    import dataclasses

    spec, _ = load_spec(repo / "verification/spec.py")
    tsa = sorted(spec.chain.anchors)[0]
    anchors = dict(spec.chain.anchors)
    anchors[tsa] = dataclasses.replace(anchors[tsa], filename="a\nb.pem")
    chain = dataclasses.replace(spec.chain, anchors=anchors)

    with pytest.raises(ReleaseChainError, match="embeds a newline"):
        _anchor_set_digests(
            repo / ANCHOR_DIR, chain, enforce_production_pins=False
        )


def test_a_missing_anchor_file_refuses(repo: pathlib.Path) -> None:
    spec, _ = load_spec(repo / "verification/spec.py")
    (repo / ANCHOR_DIR / spec.chain.producer_public_key_filename).unlink()

    with pytest.raises(ReleaseChainError, match="missing or non-regular anchor"):
        _anchor_set_digests(
            repo / ANCHOR_DIR, spec.chain, enforce_production_pins=False
        )


def test_an_absent_chain_names_no_anchor_set(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """No chain verified means no anchors consulted — the field must say so
    rather than digest anchor files nothing was checked against."""

    spec, _ = load_spec(repo / "verification/spec.py")
    empty = tmp_path / "empty"
    empty.mkdir()
    verification = verify_release_chain(
        empty, spec=spec.chain, require_chain=False, verify_state=False
    )
    assert verification.releases == ()
    assert verification.anchor_set_sha256 is None
    assert dict(verification.anchor_file_sha256s) == {}
