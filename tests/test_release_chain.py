"""The anchor-set digest: a verdict names the anchor bytes the run consumed.

receipt#24's second half, in its post-review shape: digests are captured at
the verification read sites themselves (OpenSSL is fed a snapshot of the
digested bytes), the computation is opt-in so pre-existing callers keep
byte-identical behavior, and the combined digest is receipt-canonical JSON —
an injective encoding for any filename strings.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess

import pytest

from receipt.canonical import canonical_sha256
from receipt.release_chain import (
    ReleaseChainError,
    _combined_anchor_digest,
    _observe_anchor_bytes,
    verify_release_chain,
)
from receipt.verify import load_spec, run_verification

from corpus_fixture import CONTENT, append_release, build_corpus

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


def configured_filenames(repo: pathlib.Path) -> set[str]:
    spec, _ = load_spec(repo / "verification/spec.py")
    return {
        spec.chain.producer_public_key_filename,
        *(anchor.filename for anchor in spec.chain.anchors.values()),
    }


def independent_digests(repo: pathlib.Path) -> tuple[str, dict[str, str]]:
    """Recompute from the tree alone, sharing no package code: hash exactly
    the spec-configured files, then SHA-256 the compact sorted-key JSON of
    the mapping (equal to receipt-canonical JSON for these ASCII names)."""

    per_file = {
        name: hashlib.sha256((repo / ANCHOR_DIR / name).read_bytes()).hexdigest()
        for name in configured_filenames(repo)
    }
    combined = hashlib.sha256(
        json.dumps(per_file, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return combined, per_file


def test_a_verified_chain_names_the_consumed_anchor_set(
    repo: pathlib.Path,
) -> None:
    # An unconfigured file in the anchor directory must not enter the set:
    # the digest commits to what the spec configures and the run consumes,
    # not to a directory listing.
    (repo / ANCHOR_DIR / "unrelated.pem").write_bytes(b"not part of the set\n")

    spec, _ = load_spec(repo / "verification/spec.py")
    verification = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )
    combined, per_file = independent_digests(repo)
    assert verification.anchor_set_sha256 == combined
    # The exact public shape: a sorted tuple of pairs, not any mapping-like.
    assert verification.anchor_file_sha256s == tuple(sorted(per_file.items()))
    assert "unrelated.pem" not in dict(verification.anchor_file_sha256s)


def test_by_default_no_digest_is_computed(repo: pathlib.Path) -> None:
    """The invariant pre-existing callers rely on: without the flag, the
    fields stay unset and no anchor file is read beyond the old checks."""

    spec, _ = load_spec(repo / "verification/spec.py")
    verification = verify_release_chain(repo, spec=spec.chain)
    assert verification.anchor_set_sha256 is None
    assert dict(verification.anchor_file_sha256s) == {}


def test_openssl_is_fed_the_digested_bytes(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The digest describes bytes OpenSSL actually consumed: every -CAfile
    the run passes must be a private snapshot — never the repository path a
    concurrent writer could swap between the hash and the subprocess — and
    the snapshot's bytes at call time must hash to the digest the verdict
    reports for that anchor."""

    import receipt.release_chain as module

    repo_anchor_dir = (repo / ANCHOR_DIR).resolve()
    consumed: list[tuple[pathlib.Path, str]] = []
    real_run = subprocess.run

    def spying_run(arguments, *args, **kwargs):  # type: ignore[no-untyped-def]
        if isinstance(arguments, list) and "-CAfile" in arguments:
            path = pathlib.Path(arguments[arguments.index("-CAfile") + 1])
            consumed.append(
                (path, hashlib.sha256(path.read_bytes()).hexdigest())
            )
        return real_run(arguments, *args, **kwargs)

    monkeypatch.setattr(module.subprocess, "run", spying_run)
    spec, _ = load_spec(repo / "verification/spec.py")
    verification = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )

    assert consumed, "the run must have verified RFC 3161 receipts"
    reported = set(dict(verification.anchor_file_sha256s).values())
    for path, digest in consumed:
        assert path.resolve().parent != repo_anchor_dir
        assert digest in reported


def test_the_producer_openssl_fallback_uses_a_private_leaf(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A configured producer filename that is absolute would survive the
    temporary-directory join in the OpenSSL fallback and hand the original
    path to the subprocess. When observing, the temporary name must be a
    fixed private leaf regardless of configuration."""

    import dataclasses

    import receipt.release_chain as module
    from receipt import sign as sign_module

    spec, _ = load_spec(repo / "verification/spec.py")
    absolute_name = str((repo / ANCHOR_DIR / "producer-ed25519.pub").resolve())
    chain = dataclasses.replace(
        spec.chain, producer_public_key_filename=absolute_name
    )
    manifests = sorted((repo / "releases/manifests").glob("*.json"))
    manifest_bytes = manifests[0].read_bytes()
    signature = manifests[0].with_name(
        manifests[0].name.replace(".json", ".producer.sig")
    ).read_bytes()

    captured: list[str | None] = []

    def spying_fallback(*args, **kwargs):  # type: ignore[no-untyped-def]
        captured.append(kwargs.get("temporary_public_key_filename"))

    monkeypatch.setattr(module, "CRYPTOGRAPHY_AVAILABLE", False)
    monkeypatch.setattr(
        sign_module, "_verify_producer_signature_with_openssl", spying_fallback
    )
    observer: dict[str, str] = {}
    module.verify_producer_signature_bytes(
        manifest_bytes,
        signature,
        spec=chain,
        anchor_dir=repo / ANCHOR_DIR,
        enforce_production_pin=False,
        label="0000.producer.sig",
        anchor_observer=observer,
    )
    assert captured == ["producer-key-snapshot.pem"]
    assert absolute_name in observer

    # Non-observing mode must keep origin's behavior exactly: the configured
    # name is forwarded as the temporary filename, absolute or not.
    captured.clear()
    module.verify_producer_signature_bytes(
        manifest_bytes,
        signature,
        spec=chain,
        anchor_dir=repo / ANCHOR_DIR,
        enforce_production_pin=False,
        label="0000.producer.sig",
    )
    assert captured == [absolute_name]


def test_a_reserialized_producer_key_is_accepted_and_recorded(
    repo: pathlib.Path,
) -> None:
    """The stated split semantics, pinned: producer identity is SPKI-pinned,
    so a byte-different serialization of the same key verifies — and the
    verdict records the serialization that was actually consumed."""

    spec, _ = load_spec(repo / "verification/spec.py")
    key_name = spec.chain.producer_public_key_filename
    key_path = repo / ANCHOR_DIR / key_name
    original = key_path.read_bytes()
    reserialized = original.rstrip(b"\n") + b"\n\n"
    assert reserialized != original
    key_path.write_bytes(reserialized)

    verification = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )
    recorded = dict(verification.anchor_file_sha256s)[key_name]
    assert recorded == hashlib.sha256(reserialized).hexdigest()
    assert recorded != hashlib.sha256(original).hexdigest()


def test_the_producer_openssl_fallback_verifies_while_observing(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fallback path runs for real — the private snapshot leaf must be
    what OpenSSL consumes, in both observing and non-observing modes."""

    import receipt.release_chain as module

    monkeypatch.setattr(module, "CRYPTOGRAPHY_AVAILABLE", False)
    spec, _ = load_spec(repo / "verification/spec.py")
    manifests = sorted((repo / "releases/manifests").glob("*.json"))
    manifest_bytes = manifests[0].read_bytes()
    signature = manifests[0].with_name(
        manifests[0].name.replace(".json", ".producer.sig")
    ).read_bytes()

    observer: dict[str, str] = {}
    module.verify_producer_signature_bytes(
        manifest_bytes,
        signature,
        spec=spec.chain,
        anchor_dir=repo / ANCHOR_DIR,
        enforce_production_pin=True,
        label="genesis.producer.sig",
        anchor_observer=observer,
    )
    key_name = spec.chain.producer_public_key_filename
    expected = hashlib.sha256(
        (repo / ANCHOR_DIR / key_name).read_bytes()
    ).hexdigest()
    assert observer == {key_name: expected}

    # Non-observing mode keeps the original configured-name behavior.
    module.verify_producer_signature_bytes(
        manifest_bytes,
        signature,
        spec=spec.chain,
        anchor_dir=repo / ANCHOR_DIR,
        enforce_production_pin=True,
        label="genesis.producer.sig",
    )


def test_a_caller_supplied_anchor_directory_still_gets_a_digest(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """Pins off (the caller's own trust choice), digest still computed —
    and byte-identical anchor material yields the production digest, since
    the mapping commits to configured names and consumed bytes, not paths."""

    spec, _ = load_spec(repo / "verification/spec.py")
    production = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )
    aside = tmp_path / "anchors-copy"
    shutil.copytree(repo / ANCHOR_DIR, aside)
    substituted = verify_release_chain(
        repo,
        spec=spec.chain,
        anchor_dir=aside,
        compute_anchor_set_digest=True,
    )
    assert substituted.anchor_set_sha256 == production.anchor_set_sha256


def test_the_reported_pairs_cannot_be_mutated(repo: pathlib.Path) -> None:
    """ChainVerification is frozen; mutable state inside it could drift
    from the combined digest it backs."""

    spec, _ = load_spec(repo / "verification/spec.py")
    verification = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )
    with pytest.raises(TypeError):
        verification.anchor_file_sha256s[0] = ("x", "y")  # type: ignore[index]


def test_chain_verification_stays_reflection_safe(repo: pathlib.Path) -> None:
    """Adding the anchor-set fields must not tighten 0.5.0's reflection
    contract: asdict, deepcopy, and pickle work in every mode, and the
    empty result stays hashable. (A populated result was already unhashable
    on 0.5.0 through ReleaseRecord's dictionaries — the new fields must not
    be what makes anything unhashable.)"""

    import copy
    import dataclasses
    import pickle

    from receipt.release_chain import ChainVerification

    spec, _ = load_spec(repo / "verification/spec.py")
    computed = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )
    for verification in (ChainVerification(()), computed):
        assert dataclasses.asdict(verification) is not None
        assert copy.deepcopy(verification) == verification
        assert pickle.loads(pickle.dumps(verification)) == verification
    hash(ChainVerification(()))
    hash(
        ChainVerification(
            (),
            anchor_set_sha256="ab" * 32,
            anchor_file_sha256s=(("a.pem", "cd" * 32),),
        )
    )


def test_bytes_that_change_between_consumptions_refuse() -> None:
    observer: dict[str, str] = {}
    _observe_anchor_bytes(observer, "root.pem", b"first bytes")
    _observe_anchor_bytes(observer, "root.pem", b"first bytes")
    with pytest.raises(ReleaseChainError, match="changed during verification"):
        _observe_anchor_bytes(observer, "root.pem", b"second bytes")


def test_pathlike_filenames_key_by_consumed_pathname() -> None:
    """A custom PathLike names the file through __fspath__; str() could be a
    repr. Two roles naming one file through distinct PathLike objects must
    collapse to one observer key — the consumed pathname."""

    from receipt.release_chain import _observe_anchor_bytes as observe

    class Configured:
        def __init__(self, pathname: str) -> None:
            self._pathname = pathname

        def __fspath__(self) -> str:
            return self._pathname

        def __repr__(self) -> str:  # deliberately address-like
            return f"<Configured at {id(self):#x}>"

    observer: dict[str, str] = {}
    observe(observer, Configured("shared.pem"), b"bytes")  # type: ignore[arg-type]
    observe(observer, Configured("shared.pem"), b"bytes")  # type: ignore[arg-type]
    assert set(observer) == {"shared.pem"}
    with pytest.raises(ReleaseChainError, match="changed during verification"):
        observe(observer, Configured("shared.pem"), b"other")  # type: ignore[arg-type]


@pytest.mark.parametrize("role", ["tsa-anchor", "producer-key"])
def test_a_mid_run_anchor_change_refuses_end_to_end(
    role: str, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One observer spans releases and roles: over a two-release chain each
    anchor file is consumed once per release, and bytes that differ between
    those consumptions refuse — proving the wiring for both consumption
    sites, not just the helper."""

    root = tmp_path / "repo"
    root.mkdir()
    workspace = tmp_path / "tsa-workspace"
    build_corpus(root, workspace)
    corrected = dict(CONTENT)
    corrected["rules/tax/rate.yaml"] = "name: rate\nvalue: 0.175\n"
    append_release(root, workspace, content=corrected)

    spec, _ = load_spec(root / "verification/spec.py")
    if role == "tsa-anchor":
        target = sorted(a.filename for a in spec.chain.anchors.values())[0]
    else:
        target = spec.chain.producer_public_key_filename
    aside = tmp_path / "anchors-copy"
    shutil.copytree(root / ANCHOR_DIR, aside)

    reads = {"count": 0}
    original_read_bytes = pathlib.Path.read_bytes

    def flipping_read_bytes(self: pathlib.Path) -> bytes:
        data = original_read_bytes(self)
        if self.name == target and self.parent.name == aside.name:
            reads["count"] += 1
            if reads["count"] >= 2:
                return data + b"# drifted between consumptions\n"
        return data

    monkeypatch.setattr(pathlib.Path, "read_bytes", flipping_read_bytes)
    with pytest.raises(ReleaseChainError, match="changed during verification"):
        # The caller-supplied anchor directory turns pins off, so the
        # observer — not the byte pin — must be what catches the drift.
        verify_release_chain(
            root,
            spec=spec.chain,
            anchor_dir=aside,
            compute_anchor_set_digest=True,
        )
    assert reads["count"] >= 2, "the run must have consumed the anchor twice"


def test_the_combined_digest_is_injective_and_filename_agnostic() -> None:
    digest_a = "ab" * 32
    digest_b = "cd" * 32
    assert _combined_anchor_digest({"x.pem": digest_a}) != _combined_anchor_digest(
        {"x.pem": digest_b}
    )
    assert _combined_anchor_digest(
        {"x.pem": digest_a, "y.pem": digest_b}
    ) != _combined_anchor_digest({"x.pem": digest_b, "y.pem": digest_a})
    # Any filename string encodes: non-ASCII, spaces, newlines. The encoding
    # is the package's own canonical JSON, so it never raises on the
    # filename domain the older checks accepted.
    exotic = {"ключ\nанкер .pem": digest_a}
    assert _combined_anchor_digest(exotic) == canonical_sha256(exotic)
    # And the canonical rule is pinned against an independently hand-built
    # encoding for the case where key orders diverge: canonical JSON sorts
    # keys by UTF-16 code units, so an astral-plane key (surrogates D800…)
    # precedes U+FF61 even though its code point is higher. A drift to
    # code-point ordering (plain sort_keys) would flip these keys.
    astral, halfwidth = "\U00010000k", "｡k"
    expected = (
        b'{"' + astral.encode() + b'":"' + digest_a.encode()
        + b'","' + halfwidth.encode() + b'":"' + digest_b.encode() + b'"}'
    )
    assert _combined_anchor_digest(
        {halfwidth: digest_b, astral: digest_a}
    ) == hashlib.sha256(expected).hexdigest()


def test_verify_result_exposes_the_anchor_set(repo: pathlib.Path) -> None:
    spec_path = repo / "verification/spec.py"
    spec, spec_sha256 = load_spec(spec_path)
    result = run_verification(
        repo, spec, spec_path=spec_path, spec_sha256=spec_sha256
    )
    assert result.ok
    combined, per_file = independent_digests(repo)
    assert result.anchor_set_sha256 == combined
    assert result.anchor_file_sha256s == per_file


def test_an_absent_chain_names_no_anchor_set(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """No chain verified means no anchors consumed — the field must say so
    rather than digest anchor files nothing was checked against."""

    spec, _ = load_spec(repo / "verification/spec.py")
    empty = tmp_path / "empty"
    empty.mkdir()
    anchor_reads = {"count": 0}
    original_read_bytes = pathlib.Path.read_bytes

    def counting_read_bytes(self: pathlib.Path) -> bytes:
        if self.parent.name == "anchors":
            anchor_reads["count"] += 1
        return original_read_bytes(self)

    import pytest as _pytest

    monkeypatch = _pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(pathlib.Path, "read_bytes", counting_read_bytes)
        verification = verify_release_chain(
            empty,
            spec=spec.chain,
            require_chain=False,
            verify_state=False,
            compute_anchor_set_digest=True,
        )
    finally:
        monkeypatch.undo()
    assert verification.releases == ()
    assert verification.anchor_set_sha256 is None
    assert dict(verification.anchor_file_sha256s) == {}
    assert anchor_reads["count"] == 0
