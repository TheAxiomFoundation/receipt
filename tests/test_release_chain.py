"""The anchor-set digest: a verdict names the anchor bytes the run consumed.

receipt#24's second half, in its post-review shape: digests are captured at
the verification read sites themselves (OpenSSL is fed a snapshot of the
digested bytes), the computation is opt-in so pre-existing callers keep
byte-identical behavior, and the combined digest is receipt-canonical JSON —
an injective encoding for any accepted filename strings.

Two tests at the end are labelled S4-F6 and belong to a fourth review gate's
first round on the append-gate branch: the ``dir_fd`` requirement was
documented as the append gate's, and this is where it is shown to be the
package's — ``verify_release_chain`` and ``receipt verify``'s custody pass
refuse on the same platforms, in the same words, with no append gate in the
picture.

Two more are labelled S5-R2-F3 and belong to that branch's fifth gate, second
round, for the same reason: the release tree's confinement walk was added for
the append gate and reached only from there, so the public verifier had none
of it.

One at the end is labelled S5-G1-F2 and belongs to a fresh gate's first round:
the whole-index alias scan compared each entry against the three paths a
``ChainSpec`` carries and against nothing else, and a caller with configured
surfaces of its own protects more than that. It is the package-level half —
that the widening is the caller's to ask for and changes nothing for a caller
that does not.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
from dataclasses import replace

import pytest

from receipt import release_chain
from receipt.canonical import canonical_sha256
from receipt.release_chain import (
    ReleaseChainError,
    TIME_STAMP_RE,
    _combined_anchor_digest,
    _observe_anchor_bytes,
    _parse_receipt_text,
    _receipt_bytes,
    assert_index_carries_no_protected_alias,
    verify_receipt,
    verify_release_chain,
    verify_release_history_immutable,
)
from receipt.cli import EXIT_FAIL, main
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
    assert verification.anchor_file_sha256s == ()


def test_chain_spec_defaults_to_the_portable_name_repertoire(
    repo: pathlib.Path,
) -> None:
    spec, _ = load_spec(repo / "verification/spec.py")

    assert spec.chain.name_repertoire == "portable"
    assert replace(spec.chain, name_repertoire="posix-bytes").name_repertoire == (
        "posix-bytes"
    )
    with pytest.raises(
        ReleaseChainError,
        match="name repertoire must be 'portable' or 'posix-bytes'",
    ):
        replace(spec.chain, name_repertoire="unknown")


def test_verification_spec_anchor_set_pin_is_defaulted_and_validated(
    repo: pathlib.Path,
) -> None:
    spec, _ = load_spec(repo / "verification/spec.py")

    assert spec.anchor_set_sha256 is None
    assert replace(spec, anchor_set_sha256="0" * 64).anchor_set_sha256 == "0" * 64
    with pytest.raises(
        ValueError,
        match="VerificationSpec anchor_set_sha256 must be a lowercase SHA-256 digest",
    ):
        replace(spec, anchor_set_sha256="A" * 64)


def test_observing_adds_no_anchor_reads(built: pathlib.Path, tmp_path: pathlib.Path) -> None:
    """Default mode reads each anchor exactly as 0.5.0 did (producer key once
    per release for the signature, each TSA anchor once per receipt for the
    byte pin); observing must ride those same reads, adding none."""

    import pytest as _pytest

    counts = {}
    for mode, flag in (("default", False), ("observing", True)):
        repo = tmp_path / mode
        shutil.copytree(built, repo, symlinks=True)
        spec, _ = load_spec(repo / "verification/spec.py")
        reads = {"count": 0}
        original_read_bytes = pathlib.Path.read_bytes

        def counting_read_bytes(self: pathlib.Path) -> bytes:
            if self.parent.name == "anchors":
                reads["count"] += 1
            return original_read_bytes(self)

        monkeypatch = _pytest.MonkeyPatch()
        try:
            monkeypatch.setattr(pathlib.Path, "read_bytes", counting_read_bytes)
            verify_release_chain(
                repo, spec=spec.chain, compute_anchor_set_digest=flag
            )
        finally:
            monkeypatch.undo()
        counts[mode] = reads["count"]
    # One release, one producer key, two TSA roles: three reads.
    assert counts == {"default": 3, "observing": 3}


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

    # Same property with pins off (a caller-supplied anchor directory):
    # snapshots, never the caller's directory.
    aside = repo.parent / "anchors-aside"
    shutil.copytree(repo / ANCHOR_DIR, aside)
    consumed.clear()
    verification = verify_release_chain(
        repo, spec=spec.chain, anchor_dir=aside, compute_anchor_set_digest=True
    )
    reported = set(dict(verification.anchor_file_sha256s).values())
    assert consumed
    for path, digest in consumed:
        assert path.resolve().parent not in (repo_anchor_dir, aside.resolve())
        assert digest in reported

    # A caller that requests neither byte pins nor an observed digest still
    # gets the same private -CAfile discipline.
    consumed.clear()
    verify_release_chain(
        repo,
        spec=spec.chain,
        anchor_dir=aside,
        enforce_production_pins=False,
    )
    expected = {
        hashlib.sha256((aside / anchor.filename).read_bytes()).hexdigest()
        for anchor in spec.chain.anchors.values()
    }
    assert consumed
    for path, digest in consumed:
        assert path.resolve().parent not in (repo_anchor_dir, aside.resolve())
        assert digest in expected


def test_release_chain_runs_the_openssl_floor_preflight_before_paths(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from receipt import tsa

    calls: list[str] = []

    def refuse() -> None:
        calls.append("preflight")
        raise tsa.TsaError(
            "receipt requires OpenSSL 3.0 or newer as `openssl` on the path; "
            "found: LibreSSL 3.3.6"
        )

    monkeypatch.setattr(tsa, "_require_supported_openssl", refuse)
    spec, _ = load_spec(repo / "verification/spec.py")
    shutil.rmtree(repo / "releases")

    with pytest.raises(ReleaseChainError) as refusal:
        verify_release_chain(repo, spec=spec.chain)

    assert calls == ["preflight"]
    assert str(refusal.value) == (
        "receipt requires OpenSSL 3.0 or newer as `openssl` on the path; "
        "found: LibreSSL 3.3.6"
    )


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
    fed_pems: list[bytes] = []

    def spying_fallback(*args, **kwargs):  # type: ignore[no-untyped-def]
        captured.append(kwargs.get("temporary_public_key_filename"))
        fed_pems.append(args[2])

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
    # The bytes handed to the fallback are the observed bytes exactly.
    assert hashlib.sha256(fed_pems[0]).hexdigest() == observer[absolute_name]

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

    key_name = spec.chain.producer_public_key_filename
    expected = hashlib.sha256(
        (repo / ANCHOR_DIR / key_name).read_bytes()
    ).hexdigest()
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


def test_the_in_process_verifier_receives_the_observed_producer_bytes(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The producer digest must describe the bytes the signature check
    consumed, not merely bytes read near it."""

    import receipt.release_chain as module

    seen: list[bytes] = []
    real_verify = module._sign.verify_signature_bytes

    def spying_verify(payload, signature, public_key_pem, **kwargs):  # type: ignore[no-untyped-def]
        seen.append(public_key_pem)
        return real_verify(payload, signature, public_key_pem, **kwargs)

    monkeypatch.setattr(module._sign, "verify_signature_bytes", spying_verify)
    spec, _ = load_spec(repo / "verification/spec.py")
    verification = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )
    key_name = spec.chain.producer_public_key_filename
    reported = dict(verification.anchor_file_sha256s)[key_name]
    assert seen, "the run must have verified a producer signature"
    for pem in seen:
        assert hashlib.sha256(pem).hexdigest() == reported


def test_pins_off_observing_accepts_a_substitute_producer_identity(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """Pins off establishes no pin claim — a re-signed chain under a fresh
    key verifies against a caller-supplied anchor set, and the verdict
    records the substitute serialization. A regression that re-enabled the
    SPKI pin whenever digests are computed would fail here."""

    from receipt.sign import generate_signing_keypair, sign_payload

    private_pem, public_pem = generate_signing_keypair()
    for manifest in sorted((repo / "releases/manifests").glob("*.json")):
        signature = manifest.with_name(
            manifest.name.replace(".json", ".producer.sig")
        )
        signature.write_bytes(
            sign_payload(private_pem, manifest.read_bytes(), domain=b"")
        )
    aside = tmp_path / "anchors-substitute"
    shutil.copytree(repo / ANCHOR_DIR, aside)
    spec, _ = load_spec(repo / "verification/spec.py")
    key_name = spec.chain.producer_public_key_filename
    (aside / key_name).write_bytes(public_pem)

    verification = verify_release_chain(
        repo, spec=spec.chain, anchor_dir=aside, compute_anchor_set_digest=True
    )
    recorded = dict(verification.anchor_file_sha256s)[key_name]
    assert recorded == hashlib.sha256(public_pem).hexdigest()


def test_pathlike_configurations_traverse_end_to_end(
    repo: pathlib.Path,
) -> None:
    """PurePosixPath filenames — runtime-accepted by every older check —
    must produce the same digest as the equivalent plain-string spec, with
    exact built-in str keys in the output."""

    import dataclasses

    spec, _ = load_spec(repo / "verification/spec.py")
    plain = verify_release_chain(
        repo, spec=spec.chain, compute_anchor_set_digest=True
    )
    pathlike_chain = dataclasses.replace(
        spec.chain,
        producer_public_key_filename=pathlib.PurePosixPath(  # type: ignore[arg-type]
            spec.chain.producer_public_key_filename
        ),
        anchors={
            tsa: dataclasses.replace(
                anchor,
                filename=pathlib.PurePosixPath(anchor.filename),  # type: ignore[arg-type]
            )
            for tsa, anchor in spec.chain.anchors.items()
        },
    )
    pathlike = verify_release_chain(
        repo, spec=pathlike_chain, compute_anchor_set_digest=True
    )
    assert pathlike.anchor_set_sha256 == plain.anchor_set_sha256
    assert pathlike.anchor_file_sha256s == plain.anchor_file_sha256s
    for name, _digest in pathlike.anchor_file_sha256s:
        assert type(name) is str


def test_a_stateful_pathlike_gets_exactly_one_pathname_call(
    tmp_path: pathlib.Path,
) -> None:
    """The attack round 5 named: a PathLike that answers __fspath__
    differently per call could show one pathname to the join and another to
    the observer. Normalizing once per run — not once per release — means
    the object is asked exactly once over a multi-release chain, and every
    consumer shares that single answer."""

    import dataclasses

    root = tmp_path / "repo"
    root.mkdir()
    workspace = tmp_path / "tsa-workspace"
    build_corpus(root, workspace)
    corrected = dict(CONTENT)
    corrected["rules/tax/rate.yaml"] = "name: rate\nvalue: 0.175\n"
    append_release(root, workspace, content=corrected)

    spec, _ = load_spec(root / "verification/spec.py")
    real_name = spec.chain.producer_public_key_filename
    calls = {"count": 0}

    class TwoFaced:
        def __fspath__(self) -> str:
            calls["count"] += 1
            return real_name if calls["count"] == 1 else "reported.pem"

    chain = dataclasses.replace(
        spec.chain, producer_public_key_filename=TwoFaced()  # type: ignore[arg-type]
    )
    verification = verify_release_chain(
        root, spec=chain, compute_anchor_set_digest=True
    )
    assert len(verification.releases) == 2
    assert calls["count"] == 1
    assert real_name in dict(verification.anchor_file_sha256s)
    assert "reported.pem" not in dict(verification.anchor_file_sha256s)


def test_default_mode_fspath_counts_match_origin(
    repo: pathlib.Path,
) -> None:
    """Origin's default-mode joins ask a PathLike for its pathname a fixed
    number of times per release: twice for the producer key (the diagnostic
    path and read_producer_public_key's own join) and once per TSA receipt.
    Observing-mode normalization must not change any of these counts."""

    import dataclasses

    spec, _ = load_spec(repo / "verification/spec.py")
    counts: dict[str, int] = {}

    class Counting:
        def __init__(self, label: str, name: str) -> None:
            self._label, self._name = label, name

        def __fspath__(self) -> str:
            counts[self._label] = counts.get(self._label, 0) + 1
            return self._name

    chain = dataclasses.replace(
        spec.chain,
        producer_public_key_filename=Counting(  # type: ignore[arg-type]
            "producer", spec.chain.producer_public_key_filename
        ),
        anchors={
            tsa: dataclasses.replace(
                anchor,
                filename=Counting(tsa, anchor.filename),  # type: ignore[arg-type]
            )
            for tsa, anchor in spec.chain.anchors.items()
        },
    )
    verify_release_chain(repo, spec=chain)
    tsa_labels = sorted(spec.chain.anchors)
    assert counts == {"producer": 2, tsa_labels[0]: 1, tsa_labels[1]: 1}


def test_standalone_receipts_shared_filename_divergence_refuses(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two TSA roles sharing one stateful filename object, whose bytes
    change between their consumptions: the standalone entry point's
    memoized rewrite asks the object once, and the observer — not the
    later OpenSSL failure — refuses the divergence."""

    import dataclasses
    import json as _json

    import receipt.release_chain as module

    spec, _ = load_spec(repo / "verification/spec.py")
    first_role = sorted(spec.chain.anchors)[0]
    shared_name = spec.chain.anchors[first_role].filename
    calls = {"count": 0}

    class Shared:
        def __fspath__(self) -> str:
            calls["count"] += 1
            return shared_name

    shared = Shared()
    chain = dataclasses.replace(
        spec.chain,
        anchors={
            tsa: dataclasses.replace(anchor, filename=shared)  # type: ignore[arg-type]
            for tsa, anchor in spec.chain.anchors.items()
        },
    )
    manifest_path = sorted((repo / "releases/manifests").glob("*.json"))[0]
    manifest_bytes = manifest_path.read_bytes()
    manifest = _json.loads(manifest_bytes)
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    receipt_paths = {
        tsa: manifest_path.with_name(
            manifest_path.name.replace(".json", f".{tsa}.tsr")
        )
        for tsa in chain.anchors
    }

    reads = {"count": 0}
    original_read_bytes = pathlib.Path.read_bytes

    def flipping_read_bytes(self: pathlib.Path) -> bytes:
        data = original_read_bytes(self)
        if self.name == shared_name and self.parent.name == "anchors":
            reads["count"] += 1
            if reads["count"] >= 2:
                return data + b"# diverged between roles\n"
        return data

    monkeypatch.setattr(pathlib.Path, "read_bytes", flipping_read_bytes)
    observer: dict[str, str] = {}
    with pytest.raises(ReleaseChainError, match="changed during verification"):
        module.verify_release_receipts(
            manifest,
            digest,
            receipt_paths,
            spec=chain,
            anchor_dir=repo / ANCHOR_DIR,
            enforce_production_pins=False,
            clock_skew_seconds=300,
            anchor_observer=observer,
        )
    assert calls["count"] == 1
    assert reads["count"] == 2


def test_a_receipt_swapped_mid_verification_cannot_mix_two_tokens(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One receipt, three OpenSSL invocations, and one file between them.

    ``-text`` reads the genTime and the policy OID, ``-verify`` binds the
    token to the manifest digest, and the signer pins run over a token
    extracted a third time. Each reopened the path by name, so the tree under
    audit could hand a different file to each call and the verdict would
    report a time no verified token carried. Here the alpha receipt becomes
    the beta receipt the instant the inspection returns — a token from an
    authority whose root is not the CAfile in force, which the later calls
    cannot verify.

    With the bytes snapshotted once, the swap is inert: the reported genTime
    is the inspected token's, and it is the token that verified. Before the
    snapshot, the same swap refused instead — a refusal is a sound outcome
    too, but the mixed genTime between them is not, and only reading once
    rules it out.
    """

    spec, _ = load_spec(repo / "verification/spec.py")
    manifests = repo / "releases/manifests"
    manifest_path = sorted(manifests.glob("*.json"))[0]
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    alpha = manifest_path.with_name(f"{manifest_path.stem}.alpha.tsr")
    beta = manifest_path.with_name(f"{manifest_path.stem}.beta.tsr")

    def check() -> object:
        return verify_receipt(
            digest,
            alpha,
            "alpha",
            spec=spec.chain,
            anchor_dir=repo / ANCHOR_DIR,
            enforce_production_pins=True,
        )

    expected = check()

    real_run = subprocess.run
    swaps = {"count": 0}

    def swapping(arguments: object, **kwargs: object) -> object:
        completed = real_run(arguments, **kwargs)  # type: ignore[arg-type]
        if isinstance(arguments, list) and "-text" in arguments:
            swaps["count"] += 1
            alpha.write_bytes(beta.read_bytes())
        return completed

    monkeypatch.setattr("receipt.release_chain.subprocess.run", swapping)
    observed = check()
    assert swaps["count"] == 1, "the inspection ran, so the swap landed"
    assert alpha.read_bytes() == beta.read_bytes(), "the file really was swapped"
    assert observed == expected


def test_a_receipt_that_is_not_a_regular_file_refuses_before_opening(
    tmp_path: pathlib.Path,
) -> None:
    """The lstat runs before the open, deliberately: opening a fifo for
    reading blocks until a writer arrives, so what kind of file this is has to
    be decided from the directory entry rather than from the descriptor."""

    import os

    fifo = tmp_path / "receipt.tsr"
    os.mkfifo(fifo)
    with pytest.raises(ReleaseChainError, match="non-regular RFC 3161 receipt"):
        _receipt_bytes(fifo)


def test_a_receipt_replaced_between_the_lstat_and_the_open_refuses(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The descriptor is what gets read, so the descriptor is what gets
    checked. A path that named one file at the lstat and another by the time
    it was opened addresses a different file, and its (device, inode) pair
    says so where the pathname cannot."""

    import os

    receipt = tmp_path / "receipt.tsr"
    receipt.write_bytes(b"the inspected token")
    other = tmp_path / "other.tsr"
    other.write_bytes(b"a different token")

    real_lstat = os.lstat

    def lying(path: object, **kwargs: object) -> object:
        if str(path) == str(receipt):
            return real_lstat(other)
        return real_lstat(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("receipt.release_chain.os.lstat", lying)
    with pytest.raises(ReleaseChainError, match="replaced while it was being read"):
        _receipt_bytes(receipt)


def receipt_text(repo: pathlib.Path) -> tuple[str, pathlib.Path]:
    """The real `openssl ts -reply -text` output the verifier parses."""

    manifest_path = sorted((repo / "releases/manifests").glob("*.json"))[0]
    alpha = manifest_path.with_name(f"{manifest_path.stem}.alpha.tsr")
    completed = subprocess.run(
        ["openssl", "ts", "-reply", "-config", "/dev/null", "-in", str(alpha), "-text"],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout, alpha


def with_fraction(text: str, fraction: str) -> str:
    """Rewrite only the genTime's fractional part, leaving the rest as OpenSSL
    printed it — a locally generated authority stamps whole seconds, but a
    production one need not."""

    lines = []
    for line in text.splitlines():
        if line.startswith("Time stamp:"):
            match = TIME_STAMP_RE.fullmatch(line.split(":", 1)[1].strip())
            assert match is not None
            line = (
                f"Time stamp: {match.group('month')} {match.group('day')} "
                f"{match.group('hour')}:{match.group('minute')}:"
                f"{match.group('second')}{fraction} {match.group('year')} GMT"
            )
        lines.append(line)
    return "\n".join(lines)


@pytest.mark.parametrize(
    ("fraction", "microsecond"),
    [("", 0), (".1", 100_000), (".123456", 123_456)],
)
def test_a_fractional_genTime_keeps_every_digit_it_can_represent(
    repo: pathlib.Path, fraction: str, microsecond: int
) -> None:
    """``.1`` is a tenth of a second, not a microsecond: the digits are the
    fraction's leading digits, right-padded, never read as a count."""

    text, alpha = receipt_text(repo)
    parsed, _ = _parse_receipt_text(with_fraction(text, fraction), alpha)
    assert parsed.microsecond == microsecond


def test_a_genTime_finer_than_a_microsecond_refuses(repo: pathlib.Path) -> None:
    """Truncating to six digits moves the parsed time earlier than the instant
    the authority signed — and that time is not merely reported. It is
    compared against createdAtUtc and against the previous release's
    witnesses, and it selects the -attime the signer certificate is validated
    at. A precision this verifier cannot hold refuses rather than rounding
    down into a time no receipt carries."""

    text, alpha = receipt_text(repo)
    with pytest.raises(ReleaseChainError, match="finer than a microsecond"):
        _parse_receipt_text(with_fraction(text, ".1234567"), alpha)


def test_a_genTime_with_zeros_beyond_the_sixth_digit_is_exact(
    repo: pathlib.Path,
) -> None:
    """Seven digits ending in zero name the same instant six digits do.

    The refusal exists for precision the parser cannot hold; a trailing zero
    holds none, so refusing it would be over-refusal in the fail-closed
    direction for no gain. A seventh digit that is not zero still refuses."""

    text, alpha = receipt_text(repo)
    parsed, _ = _parse_receipt_text(with_fraction(text, ".1234560"), alpha)
    assert parsed.microsecond == 123456
    with pytest.raises(ReleaseChainError, match="finer than a microsecond"):
        _parse_receipt_text(with_fraction(text, ".1234561"), alpha)


def test_default_mode_keeps_parts_based_purepath_joins(
    repo: pathlib.Path,
) -> None:
    """Origin joins a PurePath filename by its parts (a PureWindowsPath's
    backslash component splits), and default mode must keep doing exactly
    that — observing-mode pathname semantics never leak into it."""

    import dataclasses

    spec, _ = load_spec(repo / "verification/spec.py")
    key_name = spec.chain.producer_public_key_filename
    nested = repo / ANCHOR_DIR / "sub"
    nested.mkdir()
    (nested / key_name).write_bytes(
        (repo / ANCHOR_DIR / key_name).read_bytes()
    )
    chain = dataclasses.replace(
        spec.chain,
        producer_public_key_filename=pathlib.PureWindowsPath(  # type: ignore[arg-type]
            f"sub\\{key_name}"
        ),
    )
    # Parts semantics address anchors/sub/<key>; pathname semantics would
    # address a single "sub\<key>" component that does not exist. Default
    # mode must verify — proving the raw value still reaches the join.
    verification = verify_release_chain(repo, spec=chain)
    assert verification.anchor_set_sha256 is None


def test_a_filename_object_shared_across_roles_is_asked_once(
    repo: pathlib.Path,
) -> None:
    """The memoized rewrite: producer and TSA roles sharing one stateful
    object must collapse to a single pathname answer."""

    from receipt.release_chain import _normalized_spec

    calls = {"count": 0}

    class Shared:
        def __fspath__(self) -> str:
            calls["count"] += 1
            return "shared.pem" if calls["count"] == 1 else "other.pem"

    import dataclasses

    shared = Shared()
    base, _ = load_spec(repo / "verification/spec.py")
    base = base.chain
    chain = dataclasses.replace(
        base,
        producer_public_key_filename=shared,  # type: ignore[arg-type]
        anchors={
            tsa: dataclasses.replace(anchor, filename=shared)  # type: ignore[arg-type]
            for tsa, anchor in base.anchors.items()
        },
    )
    normalized = _normalized_spec(chain)
    assert calls["count"] == 1
    names = {normalized.producer_public_key_filename} | {
        anchor.filename for anchor in normalized.anchors.values()
    }
    assert names == {"shared.pem"}


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
    default_mode = verify_release_chain(repo, spec=spec.chain)
    for verification in (ChainVerification(()), computed, default_mode):
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
    # A lone surrogate — what os.fsdecode yields for undecodable bytes in a
    # filename — encodes as a JSON escape rather than raising.
    surrogate = {"a\udc80b.pem": digest_a}
    expected_surrogate = (
        b'{"a\\udc80b.pem":"' + digest_a.encode() + b'"}'
    )
    assert _combined_anchor_digest(surrogate) == hashlib.sha256(
        expected_surrogate
    ).hexdigest()


def test_explicit_surrogate_pair_filenames_refuse() -> None:
    """A filename spelling an astral character as an explicit surrogate pair
    is a different Python string from the astral spelling but one and the
    same string after any JSON round trip — with or without the astral twin
    present, a verdict carrying it could never be reproduced from --json,
    so the digest refuses."""

    astral, pair = "\U00010000", "\ud800\udc00"
    assert astral != pair
    with pytest.raises(ReleaseChainError, match="explicit\\s+surrogate pair"):
        _combined_anchor_digest({pair: "cd" * 32})
    with pytest.raises(ReleaseChainError, match="explicit\\s+surrogate pair"):
        _combined_anchor_digest({astral: "ab" * 32, pair: "cd" * 32})
    # The astral spelling alone is fine — it round-trips as itself.
    _combined_anchor_digest({astral: "ab" * 32})


def test_the_reported_mapping_survives_a_json_round_trip() -> None:
    """The auditor-facing property behind the refusals: for every mapping
    the digest accepts — including lone surrogateescape names from
    undecodable filesystem bytes — parsing the JSON rendering back
    reproduces the exact mapping, and its recomputed digest matches."""

    import json as _json

    mapping = {
        "plain.pem": "ab" * 32,
        "ключ.pem": "cd" * 32,
        "escape-a\udc80b.pem": "ef" * 32,
        "\U00010000.pem": "12" * 32,
    }
    digest = _combined_anchor_digest(mapping)
    round_tripped = _json.loads(_json.dumps(mapping))
    assert round_tripped == mapping
    assert _combined_anchor_digest(round_tripped) == digest


def test_out_of_domain_filenames_refuse_cleanly() -> None:
    """The observing-mode domain is exactly str | os.PathLike: bare bytes
    (which os.fsdecode would happily decode) and malformed PathLike objects
    refuse with the package's own error, never an escaping TypeError."""

    from receipt.release_chain import _exact_filename

    with pytest.raises(ReleaseChainError, match="must be str or os.PathLike"):
        _exact_filename(b"anchor.pem")

    class Malformed:
        def __fspath__(self) -> str:
            return 42  # type: ignore[return-value]

    with pytest.raises(ReleaseChainError, match="could not be decoded"):
        _exact_filename(Malformed())

    class Exploding:
        def __fspath__(self) -> str:
            raise RuntimeError("deliberately hostile")

    with pytest.raises(ReleaseChainError, match="could not be decoded"):
        _exact_filename(Exploding())

    class DecodesToNonsense(bytes):
        def decode(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            return 42

    class PathLikeToHostileBytes:
        def __fspath__(self) -> str:
            return DecodesToNonsense(b"x.pem")  # type: ignore[return-value]

    with pytest.raises(ReleaseChainError, match="could not be decoded"):
        _exact_filename(PathLikeToHostileBytes())

    class Unprintable(Exception):
        def __str__(self) -> str:
            raise RuntimeError("even the message is hostile")

    class RaisesUnprintable:
        def __fspath__(self) -> str:
            raise Unprintable()

    with pytest.raises(ReleaseChainError, match="could not be decoded"):
        _exact_filename(RaisesUnprintable())


def test_a_lazy_spec_mapping_cannot_alias_through_id_reuse(
    repo: pathlib.Path,
) -> None:
    """The memo retains each filename object: a mapping that materializes
    fresh filename objects on every access cannot have an early object
    collected mid-rewrite and its id reused for a different filename."""

    import dataclasses
    from collections.abc import Mapping as MappingABC

    from receipt.release_chain import _normalized_spec

    spec, _ = load_spec(repo / "verification/spec.py")
    base_anchors = dict(spec.chain.anchors)
    roles = {f"role{i:03d}": f"anchor-{i:03d}.pem" for i in range(200)}

    class FreshName:
        def __init__(self, name: str) -> None:
            self._name = name

        def __fspath__(self) -> str:
            return self._name

    template = next(iter(base_anchors.values()))

    class LazyAnchors(MappingABC):
        def __getitem__(self, tsa: str):  # fresh objects per access
            return dataclasses.replace(
                template, filename=FreshName(roles[tsa])  # type: ignore[arg-type]
            )

        def __iter__(self):
            return iter(roles)

        def __len__(self) -> int:
            return len(roles)

    chain = dataclasses.replace(
        spec.chain, anchors=LazyAnchors()  # type: ignore[arg-type]
    )
    normalized = _normalized_spec(chain, include_producer=False)
    observed = {
        tsa: anchor.filename for tsa, anchor in normalized.anchors.items()
    }
    assert observed == roles


def test_a_pathlike_yielding_a_str_subclass_is_normalized_exact() -> None:
    from receipt.release_chain import _exact_filename

    class Sneaky(str):
        def encode(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            raise AssertionError("subclass method must never be reachable")

        __hash__ = None  # type: ignore[assignment]

    class Wrapper:
        def __fspath__(self) -> str:
            return Sneaky("anchor.pem")

    normalized = _exact_filename(Wrapper())
    assert type(normalized) is str
    assert normalized == "anchor.pem"
    normalized.encode("ascii")


def test_an_empty_optional_chain_asks_no_pathnames(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """require_chain=False on an empty tree returned before touching any
    configured filename on origin, and still must — even when observing."""

    import dataclasses

    spec, _ = load_spec(repo / "verification/spec.py")
    calls = {"count": 0}

    class Counting:
        def __init__(self, name: str) -> None:
            self._name = name

        def __fspath__(self) -> str:
            calls["count"] += 1
            return self._name

    chain = dataclasses.replace(
        spec.chain,
        producer_public_key_filename=Counting(  # type: ignore[arg-type]
            spec.chain.producer_public_key_filename
        ),
    )
    empty = tmp_path / "empty"
    empty.mkdir()
    verification = verify_release_chain(
        empty,
        spec=chain,
        require_chain=False,
        compute_anchor_set_digest=True,
    )
    assert verification.releases == ()
    assert calls["count"] == 0


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
            compute_anchor_set_digest=True,
        )
    finally:
        monkeypatch.undo()
    assert verification.releases == ()
    assert verification.anchor_set_sha256 is None
    assert verification.anchor_file_sha256s == ()
    assert anchor_reads["count"] == 0


def test_standalone_receipts_never_touch_the_producer_filename(
    repo: pathlib.Path,
) -> None:
    """verify_release_receipts consumes only TSA anchors; a producer
    filename that would refuse normalization must be neither asked nor able
    to fail the call."""

    import dataclasses
    import json as _json

    import receipt.release_chain as module

    spec, _ = load_spec(repo / "verification/spec.py")
    chain = dataclasses.replace(
        spec.chain,
        producer_public_key_filename=b"not-in-domain",  # type: ignore[arg-type]
    )
    manifest_path = sorted((repo / "releases/manifests").glob("*.json"))[0]
    manifest_bytes = manifest_path.read_bytes()
    manifest = _json.loads(manifest_bytes)
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    receipt_paths = {
        tsa: manifest_path.with_name(
            manifest_path.name.replace(".json", f".{tsa}.tsr")
        )
        for tsa in chain.anchors
    }
    observer: dict[str, str] = {}
    times = module.verify_release_receipts(
        manifest,
        digest,
        receipt_paths,
        spec=chain,
        anchor_dir=repo / ANCHOR_DIR,
        enforce_production_pins=True,
        clock_skew_seconds=300,
        anchor_observer=observer,
    )
    assert set(times) == set(chain.anchors)
    assert set(observer) == {
        anchor.filename for anchor in spec.chain.anchors.values()
    }


def test_verify_result_accessors_before_custody() -> None:
    from receipt.verify import VerifyResult

    result = VerifyResult(
        spec_name="x",
        spec_path=pathlib.Path("spec.py"),
        spec_sha256="ab" * 32,
        root=pathlib.Path("."),
        receipt_version="0.0.0",
        producer_spki_sha256="cd" * 32,
        passes=(),
        chain=None,
        corpus=None,
    )
    assert result.anchor_set_sha256 is None
    assert result.anchor_file_sha256s == {}
    # And it is not a PASS. "No pass failed" is not "the verdict's passes
    # ran": all() over an empty tuple is true, and this result rendered as
    # "ESTABLISHED OFFLINE, FROM THIS CLONE ALONE" with exit status 0.
    assert result.ok is False


def test_a_verdict_needs_all_three_of_its_passes() -> None:
    """Custody, binding, and declaration each carry part of the claim, so a
    result holding only some of them — every one of them ok — is still not a
    verdict. The one holding all three is."""

    import dataclasses

    from receipt.verify import REQUIRED_PASSES, PassResult, VerifyResult

    def built(*names: str) -> VerifyResult:
        return VerifyResult(
            spec_name="x",
            spec_path=pathlib.Path("spec.py"),
            spec_sha256="ab" * 32,
            root=pathlib.Path("."),
            receipt_version="0.0.0",
            producer_spki_sha256="cd" * 32,
            passes=tuple(PassResult(name, True, "detail") for name in names),
            chain=None,
            corpus=None,
        )

    assert REQUIRED_PASSES == ("custody", "binding", "declaration")
    for missing in REQUIRED_PASSES:
        partial = [name for name in REQUIRED_PASSES if name != missing]
        assert built(*partial).ok is False, missing
    assert built(*REQUIRED_PASSES).ok is True
    # A recorded failure still overrides a complete set.
    complete = built(*REQUIRED_PASSES)
    failed = dataclasses.replace(
        complete,
        passes=complete.passes + (PassResult("history", False, "", "no"),),
    )
    assert failed.ok is False


def test_module_version_matches_project_metadata() -> None:
    import re

    import receipt

    pyproject = (
        pathlib.Path(receipt.__file__).resolve().parents[2] / "pyproject.toml"
    ).read_text()
    declared = re.search(
        r'^version = "([^"]+)"', pyproject, flags=re.MULTILINE
    )
    assert declared is not None
    assert receipt.__version__ == declared.group(1)


def test_pin_inference_follows_resolution_not_spelling(
    repo: pathlib.Path,
) -> None:
    """A caller-supplied anchor directory that merely spells the default
    directory differently still resolves equal, so pin inference keeps
    enforcement on — proven by the pin refusal firing through the alternate
    spelling once an anchor byte is flipped."""

    spec, _ = load_spec(repo / "verification/spec.py")
    spelled = repo / ANCHOR_DIR / ".." / "anchors"
    verification = verify_release_chain(
        repo, spec=spec.chain, anchor_dir=spelled, compute_anchor_set_digest=True
    )
    assert verification.anchor_set_sha256 is not None

    target = sorted(a.filename for a in spec.chain.anchors.values())[0]
    data = bytearray((repo / ANCHOR_DIR / target).read_bytes())
    data[len(data) // 2] ^= 0x01
    (repo / ANCHOR_DIR / target).write_bytes(bytes(data))
    with pytest.raises(ReleaseChainError, match="not code-pinned"):
        verify_release_chain(
            repo,
            spec=spec.chain,
            anchor_dir=spelled,
            compute_anchor_set_digest=True,
        )


def state_paths(
    repo: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path, dict[str, bytes]]:
    """The two state files of a built chain, and their bytes keyed as supplied."""

    spec, _ = load_spec(repo / "verification/spec.py")
    ledger = repo / spec.chain.state_relative
    prefix = repo / spec.chain.prefix_relative
    return ledger, prefix, {
        spec.chain.state_relative.as_posix(): ledger.read_bytes(),
        spec.chain.prefix_relative.as_posix(): prefix.read_bytes(),
    }


def test_supplied_state_bytes_are_used_instead_of_reading_the_state_paths(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds round five's first finding: the verdict's one read of each file.

    ``append_gate`` reads the ledger and the frozen prefix once, records what
    it read, and feeds every consumer it owns from that snapshot. This
    verifier was not one of them — it opened both paths again by name — so a
    candidate could show the row checks one ledger and the release history
    another inside a single verdict, then restore the first before the
    closing re-read. Given the bytes, the paths are not opened here at all:
    the reader is replaced with one that fails if it is called, and a decoy
    is left on disk for anything that resolves the name anyway.
    """

    spec, _ = load_spec(repo / "verification/spec.py")
    ledger, prefix, supplied = state_paths(repo)
    ledger.write_bytes(b'{"decoy":true}\n')
    prefix.write_bytes(b"{}\n")

    def refuse(root: pathlib.Path, relative: pathlib.PurePosixPath) -> bytes:
        raise AssertionError(f"state path was read by name: {relative}")

    monkeypatch.setattr(release_chain, "_regular_file_bytes", refuse)

    verification = verify_release_chain(repo, spec=spec.chain, state_bytes=supplied)
    assert len(verification.releases) == 1


def test_without_supplied_bytes_the_state_paths_are_read_exactly_as_before(
    repo: pathlib.Path
) -> None:
    """The control the same finding requires: omitting the parameter changes
    nothing. The identical decoy is refused, because the reader that predates
    the parameter is the one that ran, on the same paths, in the same place."""

    spec, _ = load_spec(repo / "verification/spec.py")
    ledger, _prefix, _supplied = state_paths(repo)
    ledger.write_bytes(b'{"decoy":true}\n')

    with pytest.raises(ReleaseChainError) as refusal:
        verify_release_chain(repo, spec=spec.chain)
    assert "lineCount" in str(refusal.value)


def test_state_bytes_must_map_exact_strings_to_exact_bytes(
    repo: pathlib.Path
) -> None:
    """The parameter is trusted in place of a read, so it is checked the way
    this module checks everything else it is handed: a str subclass could
    compare equal to a state path while rendering as something else, and a
    bytes-like view could change under the digests taken from it."""

    spec, _ = load_spec(repo / "verification/spec.py")
    _ledger, _prefix, supplied = state_paths(repo)

    with pytest.raises(ReleaseChainError) as not_a_mapping:
        verify_release_chain(repo, spec=spec.chain, state_bytes=[("a", b"b")])
    assert str(not_a_mapping.value) == (
        "state_bytes must be a mapping of state path to bytes"
    )

    key = next(iter(supplied))
    with pytest.raises(ReleaseChainError) as not_exact:
        verify_release_chain(
            repo,
            spec=spec.chain,
            state_bytes={**supplied, key: bytearray(supplied[key])},
        )
    assert str(not_exact.value) == (
        "state_bytes must map exact str state paths to exact bytes"
    )


PLATFORM_REFUSAL = (
    "state files cannot be read with secure descent on this platform "
    "(os.open lacks dir_fd support); receipt requires a POSIX platform"
)


def without_dir_fd(monkeypatch: pytest.MonkeyPatch) -> None:
    """Present a platform whose ``os.open`` takes no ``dir_fd``, as Windows is."""

    monkeypatch.setattr(
        os, "supports_dir_fd", frozenset(os.supports_dir_fd) - {os.open}
    )


def test_the_custody_state_read_refuses_a_platform_without_dir_fd(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S4-F6: the ``dir_fd`` requirement was documented as the append
    gate's, but ``_regular_file_bytes`` is where it lives and this verifier is
    that function's other caller — so ``verify_release_chain`` stops on the
    same refusal, on the public path, with no append gate anywhere in the
    picture. The restriction is the package's, and the refusal now says so.
    Without that sentence the message names only ``os.open`` and a reader is
    left to infer how far it reaches."""

    spec, _ = load_spec(repo / "verification/spec.py")
    without_dir_fd(monkeypatch)

    with pytest.raises(ReleaseChainError) as refusal:
        verify_release_chain(repo, spec=spec.chain)
    assert str(refusal.value) == PLATFORM_REFUSAL


def test_receipt_verify_reports_the_platform_refusal_as_the_custody_failure(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """S4-F6 end to end. ``receipt verify`` is the outside auditor's command
    and its first pass is custody, which reads both state files through the
    same descent — so on Windows the default verification stops there too,
    not only the append gate. The verdict names the pass and carries the
    refusal verbatim, so an auditor is told what the platform costs rather
    than left with a failure they cannot place."""

    without_dir_fd(monkeypatch)

    assert main(
        ["verify", "--spec", str(repo / "verification/spec.py"), "--root", str(repo)]
    ) == EXIT_FAIL
    # A failing verdict is rendered on stderr; the text is the same either way.
    rendered = capsys.readouterr().err
    assert "VERDICT: FAIL — custody" in rendered
    assert PLATFORM_REFUSAL in rendered


def test_a_symlinked_interior_manifest_component_is_refused(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """Binds S5-R2-F3. The release tree's confinement walk —
    ``assert_no_symlinked_release_root``, which since round 12 walks all three
    configured paths whole — was added for the append gate and was reached
    only from there, through ``hold_release_root``. The public verifier ran
    none of it, so a spec whose manifest directory sits below an interior
    component (``releases/journal/manifests``) had that component resolved
    like any other name: an untracked symlink at ``releases/journal`` pointing
    outside the tree made the chain in *that* directory the one this function
    verified, and the verdict spoke for a release history no part of which is
    in the tree the auditor was handed.

    Measured at this round's head with ``assert_no_symlinked_release_root``
    removed from ``verify_release_chain``, on this exact arrangement: the call
    returns a verification whose head manifest is the one stored outside the
    root, ``0000-<digest>.json``, and returns it as a pass. Nothing else here
    would have said otherwise — the index reconciliation that catches a linked
    component in the append gate is not on this path at all, and there is no
    base to compare against.

    The walk runs at the top now, after the arguments are validated and the
    anchor probe has had its say and before the enumeration, so both the gate
    and ``receipt verify`` reach it."""

    outside = tmp_path / "elsewhere"
    outside.mkdir()
    shutil.move(str(repo / "releases" / "manifests"), str(outside / "manifests"))
    (repo / "releases" / "journal").symlink_to(outside)
    spec, _ = load_spec(repo / "verification/spec.py")
    nested = replace(
        spec.chain,
        manifest_relative=pathlib.PurePosixPath("releases/journal/manifests"),
    )
    # The link really does deliver the chain: this is a confinement question,
    # not a question about whether the manifests are valid.
    assert (repo / "releases/journal/manifests").is_dir()

    with pytest.raises(ReleaseChainError) as refusal:
        verify_release_chain(repo, spec=nested)
    assert str(refusal.value) == (
        "release root path traverses a symlink at 'releases/journal': "
        "releases/journal/manifests"
    )


def test_a_folded_manifest_leaf_is_refused_by_the_public_verifier(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S5-R2-F3's other half, and the reason the walk binds spellings as well
    as types. Round 12 bound the configured leaf's spelling, so a spec naming
    ``releases/manifests`` over a ``releases/Manifests`` on disk is refused
    rather than verified out of a directory the spec never named — but only
    where the walk ran, which was the append gate alone. ``receipt verify``,
    whose custody pass is this function, verified it.

    Simulated the way round 12's own spelling cases are, because a
    name-folding filesystem produces one pair of facts and only one of them
    can be arranged everywhere: the ``lstat`` of the requested spelling
    succeeds (real here — the directory is spelled exactly as the spec pins
    it), and the holding directory's listing does not contain that spelling
    (simulated, by answering the one ``os.listdir`` of the release root with a
    folded name and delegating every other listing, which is the whole of what
    ``_assert_component_spelled`` reads).

    Measured at this round's head with ``assert_no_symlinked_release_root``
    removed from ``verify_release_chain``, under the same simulated listing:
    the chain verifies and the head manifest is returned as a pass."""

    spec, _ = load_spec(repo / "verification/spec.py")
    release_root = (repo / "releases").resolve()
    real_listdir = os.listdir

    def a_listing_that_folds(where: object) -> list[str]:
        listed = real_listdir(where)  # type: ignore[arg-type]
        if pathlib.Path(os.fspath(where)).resolve() == release_root:
            return [
                "Manifests" if name == "manifests" else name for name in listed
            ]
        return listed

    monkeypatch.setattr(os, "listdir", a_listing_that_folds)
    # The other half of the pair is real: the pinned spelling still resolves.
    assert (release_root / "manifests").is_dir()

    with pytest.raises(ReleaseChainError) as refusal:
        verify_release_chain(repo, spec=spec.chain)
    assert str(refusal.value) == (
        "path component releases/manifests is not spelled by its directory: "
        "releases/manifests"
    )


def a_repository_holding(tmp_path: pathlib.Path, *listed: str) -> pathlib.Path:
    """A git repository whose index records exactly ``listed``.

    Ambient user configuration is isolated the way ``tests/test_append_gate``'s
    own fixture git isolates it, so the entries are this test's and nothing
    else's.
    """

    root = tmp_path / "index-repo"
    root.mkdir()
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    subprocess.run(
        ["git", "-C", str(root), "init", "--quiet"], check=True, env=environment
    )
    for name in listed:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(root), "add", "-A"], check=True, env=environment
    )
    return root


def test_the_alias_scan_covers_the_manifest_and_anchor_directories(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """Opus peer review, round one on gate g: the scan's own protected set
    named the release root and the two state paths, but not the manifest and
    anchor directories this module also reads for itself. An index entry
    spelled ``releases/Manifests/…`` beside the spec's ``releases/manifests``
    folds onto a directory this module reads for itself, and with no surfaces
    named nothing in this scan asked about it; the release root's own index
    scan answers only where it runs, which the append gate's push path is and
    a direct caller of this function is not. Both directories are protected on
    their own now, so the alias is refused with no ``surfaces`` argument at
    all."""

    spec, _ = load_spec(repo / "verification/spec.py")
    for alias, protected in (
        ("releases/Manifests/0000-alias.json", "releases/manifests"),
        ("releases/Anchors/root.pem", "releases/anchors"),
    ):
        scratch = tmp_path / alias.split("/")[1]
        scratch.mkdir()
        root = a_repository_holding(scratch, alias)
        with pytest.raises(ReleaseChainError) as refusal:
            assert_index_carries_no_protected_alias(root, spec.chain)
        assert str(refusal.value) == (
            f"index carries an alias of a protected path: {alias} "
            f"(for {protected} at {protected})"
        )


def test_the_alias_scan_protects_only_what_its_caller_names(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """Binds S5-G1-F2 where the widening is decided: the package's own scan.

    ``assert_index_carries_no_protected_alias`` compared every index entry
    against three of the five paths a ``ChainSpec`` carries (the manifest and
    anchor directories joined them later in this round), the paths this
    module reads for itself. A caller that also classifies proposals by
    surface patterns protects more than that, and every surface match is by
    exact spelling, so an entry folding onto one of them was invisible on both
    sides — which is the finding, bound end to end in
    tests/test_append_gate.py, where the same tree is accepted as
    ``thesis-facts append check OK: 3 rows, immutable prefix 1, +1 appended vs
    base`` without the fix.

    Widening it stays the caller's decision, and the default is what pins
    that. ``append_gate`` is this function's only caller in the package —
    ``verify_release_chain`` and ``receipt verify`` never reach it, so the
    public verifier's own confinement is the release tree's component walk
    and the release root's index scan rather than this — which is why the
    widening travels no further than the argument, and why a later change
    giving ``surfaces`` a non-empty default would silently change what every
    direct caller of this function is refused for. Same index, same spec,
    refused when the surface is named and untouched when it is not. Without
    the ``surfaces`` argument the second call is the first, and neither
    refuses."""

    spec, _ = load_spec(repo / "verification/spec.py")
    root = a_repository_holding(tmp_path, "Tools/helper.py")

    assert_index_carries_no_protected_alias(root, spec.chain)

    with pytest.raises(ReleaseChainError) as refusal:
        assert_index_carries_no_protected_alias(
            root, spec.chain, surfaces=frozenset({"tools/**"})
        )
    assert str(refusal.value) == (
        "index carries an alias of a protected path: Tools/helper.py "
        "(for tools at tools)"
    )


# #45, the cheap half, at the public verifier rather than at the gate. Five
# variables can each decide which repository, working tree, index or object
# store some git read this package makes — the base resolution, an index read
# behind the state and release checks, the release-root scan — resolves in,
# rather than the checkout named as ``root`` (not every read moves under every
# variable; the refusal's docstring says which), while the verdict is still
# phrased about the checkout named. They are refused at the entry rather
# than dropped for the child processes: a drop would leave the verifier's own
# environment redirected while its children's was not, and this module reads
# the candidate tree directly as well as through git. The full pin — GIT_DIR
# stated explicitly for every read — is 0.6.
def redirecting_refusal(name: str) -> str:
    return f"{name} is set in the environment and would redirect git reads; unset it"


@pytest.mark.parametrize("name", release_chain.REDIRECTING_GIT_ENVIRONMENT)
def test_a_redirecting_git_variable_refuses_the_custody_verdict(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """One case per variable, over a chain that verifies without it.

    The same call is made twice against the same tree: once with the variable
    set and once without. Only the environment differs, so the refusal is the
    environment's and not the tree's.
    """

    spec, _ = load_spec(repo / "verification/spec.py")

    monkeypatch.setenv(name, str(repo / "elsewhere"))
    with pytest.raises(ReleaseChainError) as refusal:
        verify_release_chain(repo, spec=spec.chain)
    assert str(refusal.value) == redirecting_refusal(name)

    monkeypatch.delenv(name)
    assert verify_release_chain(repo, spec=spec.chain).releases


def test_the_ordinary_environment_still_reaches_a_custody_verdict(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal's negative side: only those five names refuse.

    The environment carries the four pathspec-mode variables these reads
    already drop, git's configuration isolation, and a name that merely begins
    with ``GIT_DIR`` — the prefix, not the variable — and the chain verifies
    exactly as it does with none of them set.
    """

    spec, _ = load_spec(repo / "verification/spec.py")
    for name in release_chain.PATHSPEC_ENVIRONMENT:
        monkeypatch.setenv(name, "1")
    monkeypatch.setenv("GIT_DIR_FIXTURE_MARKER", "not the variable")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in release_chain.REDIRECTING_GIT_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)

    assert verify_release_chain(repo, spec=spec.chain).releases


def test_the_redirecting_refusal_precedes_resolving_the_root(
    repo: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It is asked before the argument is even resolved, so nothing about the
    tree can pre-empt it: the root here does not exist."""

    spec, _ = load_spec(repo / "verification/spec.py")
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "elsewhere"))

    with pytest.raises(ReleaseChainError) as refusal:
        verify_release_chain(tmp_path / "no-such-tree", spec=spec.chain)
    assert str(refusal.value) == redirecting_refusal("GIT_WORK_TREE")


def test_the_git_environment_still_carries_the_redirecting_names_through(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_git_environment`` is unchanged, and the docstring says why.

    Dropping the five here would sanitize the child processes while leaving
    the verifier's own environment redirected, and both this module and the
    append gate read the candidate tree directly as well as through git — so
    the two halves of one verdict would be about two trees. The entries refuse
    instead, which is why a run that reaches this function has already been
    told none of the five is set.
    """

    for name in release_chain.REDIRECTING_GIT_ENVIRONMENT:
        monkeypatch.setenv(name, "carried through")

    environment = release_chain._git_environment()

    for name in release_chain.REDIRECTING_GIT_ENVIRONMENT:
        assert environment[name] == "carried through"
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert not set(environment) & set(release_chain.PATHSPEC_ENVIRONMENT)


def test_the_history_comparison_is_refused_under_a_redirecting_environment(
    repo: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``verify_release_history_immutable`` asks at its own entry, before the
    root is resolved, so a direct caller is answered as ``run_verification``
    is (peer review of the 0.5.2 release PR)."""

    spec, _ = load_spec(repo / "verification/spec.py")
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "elsewhere-index"))

    with pytest.raises(ReleaseChainError) as refusal:
        verify_release_history_immutable(
            tmp_path / "no-such-tree", "HEAD", spec=spec.chain
        )
    assert str(refusal.value) == redirecting_refusal("GIT_INDEX_FILE")
