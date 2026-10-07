"""Tests for the standalone signing layers.

Layer 1 is differential-gated through the release-chain harness. Layers 2–3
are additive capability with no upstream CLI oracle, so they are covered by
unit, property, and round-trip tests only.
"""

from __future__ import annotations

import hashlib
import inspect
import itertools
import os
import pathlib
import os
import shutil
import subprocess
from collections.abc import Callable, Iterator, Mapping
from dataclasses import FrozenInstanceError, dataclass, replace
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import receipt.sign as sign_module
from receipt.sign import (
    KeyringSpec,
    KeySpec,
    ProducerKeySpec,
    SignError,
    ThresholdVerification,
    generate_signing_keypair,
    raw_public_key_sha256,
    read_producer_public_key,
    sign_payload,
    spki_sha256,
    verify_any_generation,
    verify_signature_bytes,
    verify_threshold,
)


def _spki_pin(public_key_pem: bytes) -> str:
    public_key = serialization.load_pem_public_key(public_key_pem)
    assert isinstance(public_key, Ed25519PublicKey)
    spki_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()


def _verify(
    payload: bytes,
    signature: bytes,
    public_key_pem: bytes,
    *,
    pin: str | None,
    label: str = "artifact.sig",
) -> None:
    verify_signature_bytes(
        payload,
        signature,
        public_key_pem,
        public_key_filename="producer-ed25519.pub",
        spki_sha256=pin,
        label=label,
    )


def _outcome(callable_: Callable[[], None]) -> tuple[str, str]:
    try:
        callable_()
    except SignError as exc:
        return "refused", str(exc)
    return "accepted", ""


def test_sign_round_trip_pinned_and_explicitly_unpinned() -> None:
    private_key_pem, public_key_pem = generate_signing_keypair()
    payload = b"exact payload bytes\n"
    signature = sign_payload(private_key_pem, payload, domain=b"")

    assert type(signature) is bytes
    assert len(signature) == 64
    _verify(payload, signature, public_key_pem, pin=_spki_pin(public_key_pem))
    _verify(payload, signature, public_key_pem, pin=None)

    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
    )
    public_key = serialization.load_pem_public_key(public_key_pem)
    assert isinstance(private_key, Ed25519PrivateKey)
    assert isinstance(public_key, Ed25519PublicKey)
    assert private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ) == public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def test_sign_payload_domain_is_part_of_the_verified_message() -> None:
    private_key_pem, public_key_pem = generate_signing_keypair()
    payload = b"payload"
    domain = b"consumer/v1\0"
    signature = sign_payload(private_key_pem, payload, domain=domain)

    _verify(domain + payload, signature, public_key_pem, pin=None)
    with pytest.raises(SignError) as caught:
        _verify(payload, signature, public_key_pem, pin=None)
    assert str(caught.value) == (
        "producer Ed25519 signature verification failed for artifact.sig"
    )


def test_verify_refusal_messages_retain_ported_shapes() -> None:
    private_key_pem, public_key_pem = generate_signing_keypair()
    _, wrong_public_key_pem = generate_signing_keypair()
    payload = b"payload"
    signature = sign_payload(private_key_pem, payload, domain=b"")

    with pytest.raises(SignError) as caught:
        _verify(payload, signature, wrong_public_key_pem, pin=None)
    assert str(caught.value) == (
        "producer Ed25519 signature verification failed for artifact.sig"
    )

    with pytest.raises(SignError) as caught:
        _verify(b"wrong payload", signature, public_key_pem, pin=None)
    assert str(caught.value) == (
        "producer Ed25519 signature verification failed for artifact.sig"
    )

    with pytest.raises(SignError) as caught:
        _verify(payload, signature[:-1], public_key_pem, pin=None)
    assert str(caught.value) == (
        "producer signature for artifact.sig must be exactly 64 raw bytes; "
        "found=63"
    )

    with pytest.raises(SignError) as caught:
        verify_signature_bytes(
            bytearray(payload),  # type: ignore[arg-type]
            signature,
            public_key_pem,
            public_key_filename="producer-ed25519.pub",
            spki_sha256=None,
            label="artifact.sig",
        )
    assert str(caught.value) == "producer-signed manifest payload must be bytes"

    with pytest.raises(SignError) as caught:
        verify_signature_bytes(
            payload,
            bytearray(signature),  # type: ignore[arg-type]
            public_key_pem,
            public_key_filename="producer-ed25519.pub",
            spki_sha256=None,
            label="artifact.sig",
        )
    assert str(caught.value) == (
        "producer signature for artifact.sig must be exactly 64 raw bytes; "
        "found=non-bytes"
    )

    with pytest.raises(SignError) as caught:
        verify_signature_bytes(
            payload,
            signature,
            "not-bytes",  # type: ignore[arg-type]
            public_key_filename="producer-ed25519.pub",
            spki_sha256=None,
            label="artifact.sig",
        )
    assert str(caught.value) == (
        "cannot decode producer Ed25519 public key: producer-ed25519.pub"
    )


def test_verify_pin_decode_and_key_type_refusals() -> None:
    private_key_pem, public_key_pem = generate_signing_keypair()
    _, wrong_public_key_pem = generate_signing_keypair()
    payload = b"payload"
    signature = sign_payload(private_key_pem, payload, domain=b"")

    computed_wrong_pin = _spki_pin(wrong_public_key_pem)
    with pytest.raises(SignError) as caught:
        _verify(
            payload,
            signature,
            wrong_public_key_pem,
            pin=_spki_pin(public_key_pem),
        )
    assert str(caught.value) == (
        f"producer public-key SPKI is not code-pinned: {computed_wrong_pin}"
    )

    with pytest.raises(SignError) as caught:
        _verify(payload, signature, b"not a PEM key", pin=None)
    assert str(caught.value) == (
        "cannot decode producer Ed25519 public key: producer-ed25519.pub"
    )

    ec_public_pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(SignError) as caught:
        _verify(payload, signature, ec_public_pem, pin=None)
    assert str(caught.value) == (
        "producer public key is not Ed25519: producer-ed25519.pub"
    )


def test_unpinned_mode_is_required_and_has_no_default() -> None:
    parameter = inspect.signature(verify_signature_bytes).parameters["spki_sha256"]
    assert parameter.default is inspect.Parameter.empty

    private_key_pem, public_key_pem = generate_signing_keypair()
    signature = sign_payload(private_key_pem, b"payload", domain=b"")
    with pytest.raises(TypeError, match="spki_sha256"):
        verify_signature_bytes(  # type: ignore[call-arg]
            b"payload",
            signature,
            public_key_pem,
            public_key_filename="producer-ed25519.pub",
            label="artifact.sig",
        )


def test_read_producer_public_key_regular_file_and_refusals(
    tmp_path: pathlib.Path,
) -> None:
    spec = ProducerKeySpec("producer-ed25519.pub", "0" * 64)
    path = tmp_path / spec.public_key_filename

    with pytest.raises(SignError) as caught:
        read_producer_public_key(tmp_path, spec)
    assert str(caught.value) == (
        f"missing or non-regular producer public key: {path}"
    )

    path.write_bytes(b"key bytes")
    assert read_producer_public_key(tmp_path, spec) == b"key bytes"

    path.unlink()
    target = tmp_path / "target.pub"
    target.write_bytes(b"key bytes")
    path.symlink_to(target)
    with pytest.raises(SignError) as caught:
        read_producer_public_key(tmp_path, spec)
    assert str(caught.value) == (
        f"missing or non-regular producer public key: {path}"
    )


def test_sign_payload_input_and_key_refusals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key_pem, _ = generate_signing_keypair()

    with pytest.raises(SignError, match="^Ed25519 private key PEM must be bytes$"):
        sign_payload(bytearray(private_key_pem), b"payload", domain=b"")  # type: ignore[arg-type]
    with pytest.raises(SignError, match="^signature payload must be bytes$"):
        sign_payload(private_key_pem, bytearray(b"payload"), domain=b"")  # type: ignore[arg-type]
    with pytest.raises(SignError, match="^signature domain must be bytes$"):
        sign_payload(private_key_pem, b"payload", domain=bytearray())  # type: ignore[arg-type]
    with pytest.raises(SignError, match="^cannot decode Ed25519 private key$"):
        sign_payload(b"not a private key", b"payload", domain=b"")

    ec_private_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(SignError, match="^private key is not Ed25519$"):
        sign_payload(ec_private_pem, b"payload", domain=b"")

    monkeypatch.setattr(sign_module, "CRYPTOGRAPHY_AVAILABLE", False)
    with pytest.raises(SignError, match="^Ed25519 signing requires cryptography$"):
        sign_payload(private_key_pem, b"payload", domain=b"")
    with pytest.raises(
        SignError,
        match="^Ed25519 key generation requires cryptography$",
    ):
        generate_signing_keypair()


def test_forced_openssl_path_matches_stable_crypto_outcomes(
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")

    private_key_pem, public_key_pem = generate_signing_keypair()
    _, wrong_public_key_pem = generate_signing_keypair()
    payload = b"payload"
    signature = sign_payload(private_key_pem, payload, domain=b"")
    pin = _spki_pin(public_key_pem)

    cases = {
        "pinned": lambda: _verify(payload, signature, public_key_pem, pin=pin),
        "unpinned": lambda: _verify(payload, signature, public_key_pem, pin=None),
        "wrong_payload": lambda: _verify(
            b"wrong", signature, public_key_pem, pin=None
        ),
        "wrong_key": lambda: _verify(
            payload, signature, wrong_public_key_pem, pin=None
        ),
        "truncated": lambda: _verify(
            payload, signature[:-1], public_key_pem, pin=None
        ),
        "nonbytes_payload": lambda: verify_signature_bytes(
            bytearray(payload),  # type: ignore[arg-type]
            signature,
            public_key_pem,
            public_key_filename="producer-ed25519.pub",
            spki_sha256=None,
            label="artifact.sig",
        ),
        "nonbytes_signature": lambda: verify_signature_bytes(
            payload,
            bytearray(signature),  # type: ignore[arg-type]
            public_key_pem,
            public_key_filename="producer-ed25519.pub",
            spki_sha256=None,
            label="artifact.sig",
        ),
        "pin_mismatch": lambda: _verify(
            payload,
            signature,
            wrong_public_key_pem,
            pin=pin,
        ),
    }
    cryptography_outcomes = {name: _outcome(call) for name, call in cases.items()}

    monkeypatch.setattr(sign_module, "CRYPTOGRAPHY_AVAILABLE", False)
    openssl_outcomes = {name: _outcome(call) for name, call in cases.items()}
    assert openssl_outcomes == cryptography_outcomes

    with pytest.raises(SignError) as caught:
        _verify(payload, signature, b"not a PEM key", pin=None)
    assert str(caught.value).startswith(
        "OpenSSL producer public-key decoding for artifact.sig failed (exit "
    )
    captured = capfd.readouterr()
    assert (captured.out, captured.err) == ("", "")


def _fallback_verdict(
    payload: bytes, signature: bytes, public_key_pem: bytes, filename: str, *, pin: str | None
) -> str:
    try:
        verify_signature_bytes(
            payload,
            signature,
            public_key_pem,
            public_key_filename=filename,
            spki_sha256=pin,
            label="0001-x.producer.sig",
        )
    except SignError as exc:
        return f"REFUSE {exc}"
    return "ACCEPT"


@pytest.mark.parametrize(
    "filename",
    ["manifest.json", "anchors/manifest.json", "/tmp/elsewhere/manifest.json"],
)
@pytest.mark.parametrize("pinned", [True, False])
def test_openssl_fallback_verifies_the_payload_whatever_the_key_is_named(
    monkeypatch: pytest.MonkeyPatch, filename: str, pinned: bool
) -> None:
    """A key file named like the payload must not become the signed bytes.

    The only signature here is the pinned key's signature over its own PEM
    bytes, not over the payload.
    """

    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    private_key_pem, public_key_pem = generate_signing_keypair()
    signature_over_key = sign_payload(private_key_pem, public_key_pem, domain=b"")
    pin = _spki_pin(public_key_pem) if pinned else None
    payload = b'{"releaseIndex": 1, "forged": true}\n'

    expected = _fallback_verdict(
        payload, signature_over_key, public_key_pem, filename, pin=pin
    )
    monkeypatch.setattr(sign_module, "CRYPTOGRAPHY_AVAILABLE", False)
    actual = _fallback_verdict(
        payload, signature_over_key, public_key_pem, filename, pin=pin
    )

    assert expected == actual == (
        "REFUSE producer Ed25519 signature verification failed for "
        "0001-x.producer.sig"
    )


@pytest.mark.parametrize(
    "filename",
    ["producer.sig", "empty-ca", "", "..", "keys/producer.pub", "../escape-probe.pem"],
)
def test_openssl_fallback_accepts_a_valid_signature_whatever_the_key_is_named(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path, filename: str
) -> None:
    """The configured name decides nothing: no collision, crash or escape."""

    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    private_key_pem, public_key_pem = generate_signing_keypair()
    payload = b"payload"
    signature = sign_payload(private_key_pem, payload, domain=b"")
    monkeypatch.setattr(sign_module, "CRYPTOGRAPHY_AVAILABLE", False)
    monkeypatch.setattr(sign_module.tempfile, "tempdir", str(tmp_path / "tmp"))
    (tmp_path / "tmp").mkdir()

    assert _fallback_verdict(
        payload, signature, public_key_pem, filename, pin=_spki_pin(public_key_pem)
    ) == "ACCEPT"
    # Nothing was written beside the private directory.
    assert sorted(path.name for path in (tmp_path / "tmp").iterdir()) == []


def test_openssl_fallback_verdict_is_independent_of_the_key_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Differential, enumerated: for every configured name and every input
    shape, the fallback's verdict equals the ``cryptography`` path's."""

    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    private_key_pem, public_key_pem = generate_signing_keypair()
    payload = b"payload"
    shapes = {
        "valid": (payload, sign_payload(private_key_pem, payload, domain=b"")),
        "over the key": (payload, sign_payload(private_key_pem, public_key_pem, domain=b"")),
        "other payload": (b"other", sign_payload(private_key_pem, payload, domain=b"")),
    }
    names = (
        "producer-ed25519.pub", "manifest.json", "producer.sig", "empty-ca",
        "producer-public-key.pem", "", "..", "keys/manifest.json",
    )
    pin = _spki_pin(public_key_pem)
    for name in names:
        for shape, (message, signature) in shapes.items():
            monkeypatch.setattr(sign_module, "CRYPTOGRAPHY_AVAILABLE", True)
            expected = _fallback_verdict(message, signature, public_key_pem, name, pin=pin)
            monkeypatch.setattr(sign_module, "CRYPTOGRAPHY_AVAILABLE", False)
            actual = _fallback_verdict(message, signature, public_key_pem, name, pin=pin)
            assert actual == expected, (name, shape)
            assert actual.startswith("ACCEPT" if shape == "valid" else "REFUSE"), (name, shape)


def test_openssl_fallback_never_writes_to_an_absolute_configured_key_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    private_key_pem, public_key_pem = generate_signing_keypair()
    payload = b"payload"
    signature = sign_payload(private_key_pem, payload, domain=b"")
    anchor = tmp_path / "producer-ed25519.pub"
    anchor.write_bytes(public_key_pem)
    os.utime(anchor, (1_000_000_000, 1_000_000_000))
    monkeypatch.setattr(sign_module, "CRYPTOGRAPHY_AVAILABLE", False)

    assert _fallback_verdict(
        payload, signature, public_key_pem, str(anchor), pin=_spki_pin(public_key_pem)
    ) == "ACCEPT"
    assert anchor.stat().st_mtime == 1_000_000_000
    assert anchor.read_bytes() == public_key_pem


def test_sign_payload_cross_checks_with_openssl_cli(
    tmp_path: pathlib.Path,
) -> None:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is not installed")

    private_key_pem, public_key_pem = generate_signing_keypair()
    payload = b"independent OpenSSL cross-check\n"
    signature = sign_payload(private_key_pem, payload, domain=b"")
    public_key_path = tmp_path / "public.pem"
    payload_path = tmp_path / "payload.bin"
    signature_path = tmp_path / "signature.bin"
    public_key_path.write_bytes(public_key_pem)
    payload_path.write_bytes(payload)
    signature_path.write_bytes(signature)

    completed = subprocess.run(
        [
            openssl,
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(public_key_path),
            "-rawin",
            "-in",
            str(payload_path),
            "-sigfile",
            str(signature_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        diagnostic = (completed.stderr or completed.stdout).strip()
        if (
            "not supported" in diagnostic.lower()
            or "unsupported" in diagnostic.lower()
        ):
            pytest.skip(f"openssl lacks Ed25519 pkeyutl support: {diagnostic}")
        pytest.fail(f"openssl rejected the generated signature: {diagnostic}")


def _raw_public_key(public_key_pem: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(public_key_pem)
    assert isinstance(public_key, Ed25519PublicKey)
    return public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _three_keyring() -> tuple[
    dict[str, tuple[bytes, bytes]],
    KeyringSpec,
]:
    material = {
        key_id: generate_signing_keypair()
        for key_id in ("key-a", "key-b", "key-c")
    }
    # Deliberately non-lexical: result tuples must still be sorted.
    keyring = KeyringSpec(
        keys=tuple(
            KeySpec(key_id, spki_sha256(material[key_id][1]), "spki-sha256")
            for key_id in ("key-c", "key-a", "key-b")
        ),
        threshold=2,
    )
    return material, keyring


def _present_subset(
    material: Mapping[str, tuple[bytes, bytes]],
    subset: tuple[str, ...],
    *,
    payload: bytes,
    domain: bytes,
) -> tuple[dict[str, bytes], dict[str, bytes]]:
    signatures = {
        key_id: sign_payload(material[key_id][0], payload, domain=domain)
        for key_id in reversed(subset)
    }
    public_keys = {key_id: material[key_id][1] for key_id in subset}
    return signatures, public_keys


def test_fingerprint_helpers_normalize_pem_and_raw() -> None:
    _, public_key_pem = generate_signing_keypair()
    raw = _raw_public_key(public_key_pem)
    public_key = serialization.load_pem_public_key(public_key_pem)
    assert isinstance(public_key, Ed25519PublicKey)
    spki_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    expected_spki = hashlib.sha256(spki_der).hexdigest()
    expected_raw = hashlib.sha256(raw).hexdigest()
    assert spki_sha256(public_key_pem) == expected_spki
    assert spki_sha256(raw) == expected_spki
    assert raw_public_key_sha256(public_key_pem) == expected_raw
    assert raw_public_key_sha256(raw) == expected_raw


def test_fingerprint_helper_refusals() -> None:
    with pytest.raises(SignError, match="^Ed25519 public key must be bytes$"):
        spki_sha256(bytearray(32))  # type: ignore[arg-type]
    with pytest.raises(SignError, match="^cannot decode Ed25519 public key$"):
        spki_sha256(b"not a public key")

    ec_public_pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(SignError, match="^public key is not Ed25519$"):
        raw_public_key_sha256(ec_public_pem)


def test_keyring_construction_refusals_and_frozen_specs() -> None:
    assert issubclass(SignError, ValueError)

    with pytest.raises(
        SignError,
        match="^unsupported key fingerprint scheme: 'sha256'$",
    ):
        KeySpec("root", "fingerprint", "sha256")

    with pytest.raises(SignError, match="^keyring must contain at least one key$"):
        KeyringSpec((), 1)

    key_a = KeySpec("key-a", "a" * 64, "spki-sha256")
    for threshold in (0, -1):
        with pytest.raises(SignError) as caught:
            KeyringSpec((key_a,), threshold)
        assert str(caught.value) == (
            f"keyring threshold must be at least 1; found={threshold}"
        )

    with pytest.raises(SignError) as caught:
        KeyringSpec((key_a,), 2)
    assert str(caught.value) == "keyring threshold 2 exceeds key count 1"

    duplicate_id = KeySpec("key-a", "b" * 64, "raw-sha256")
    with pytest.raises(SignError) as caught:
        KeyringSpec((key_a, duplicate_id), 1)
    assert str(caught.value) == "duplicate key_id in keyring: 'key-a'"

    duplicate_fingerprint = KeySpec(
        "key-b",
        "a" * 64,
        "raw-sha256",
    )
    with pytest.raises(SignError) as caught:
        KeyringSpec((key_a, duplicate_fingerprint), 1)
    assert str(caught.value) == (
        f"duplicate fingerprint in keyring: {'a' * 64!r}"
    )

    keyring = KeyringSpec((key_a,), 1)
    verification = ThresholdVerification(("key-a",), (), ())
    producer = ProducerKeySpec("producer.pub", "fingerprint")
    for instance, attribute, replacement in (
        (key_a, "key_id", "changed"),
        (keyring, "threshold", 2),
        (verification, "satisfied", ()),
        (producer, "public_key_filename", "changed.pub"),
    ):
        with pytest.raises(FrozenInstanceError):
            setattr(instance, attribute, replacement)


def test_keyring_threshold_must_be_an_exact_int() -> None:
    """A threshold counts signatures, so only an exact int is one.

    Before 0.6.1 the constructor compared the threshold numerically and did
    nothing else, so ``True``, ``1.5``, ``float("nan")`` and any other value
    that survives ``<`` and ``>`` against an int constructed a keyring.
    """

    key_a = KeySpec("key-a", "a" * 64, "spki-sha256")
    key_b = KeySpec("key-b", "b" * 64, "raw-sha256")

    for threshold in (
        True,
        False,
        1.5,
        1.0,
        float("nan"),
        float("inf"),
        "1",
        None,
    ):
        with pytest.raises(SignError) as caught:
            KeyringSpec((key_a, key_b), threshold)  # type: ignore[arg-type]
        assert str(caught.value) == (
            "keyring threshold must be an integer between 1 and the number "
            f"of current keys; found={threshold!r}"
        )

    # Integer thresholds are untouched: in-range constructs, and out-of-range
    # keeps the refusal it has always had.
    assert KeyringSpec((key_a, key_b), 1).threshold == 1
    assert KeyringSpec((key_a, key_b), 2).threshold == 2
    for threshold in (0, -1):
        with pytest.raises(SignError) as caught:
            KeyringSpec((key_a, key_b), threshold)
        assert str(caught.value) == (
            f"keyring threshold must be at least 1; found={threshold}"
        )
    with pytest.raises(SignError) as caught:
        KeyringSpec((key_a,), 2)
    assert str(caught.value) == "keyring threshold 2 exceeds key count 1"


def test_nan_threshold_can_no_longer_reach_verify_threshold() -> None:
    """The hole the exact-int check closes, probed from both sides.

    ``len(satisfied) < nan`` is false, so a NaN-threshold keyring passed
    verification with zero satisfied signatures: a keyring that vouched for
    anything, including an empty signature map. The check runs at
    construction, which ``dataclasses.replace`` repeats, and again at
    verification, because construction is not the only door:
    ``object.__setattr__`` reaches past a frozen dataclass.
    """

    _, public_key_pem = generate_signing_keypair()
    key = KeySpec("root", spki_sha256(public_key_pem), "spki-sha256")
    nan = float("nan")
    refusal = (
        "keyring threshold must be an integer between 1 and the number "
        "of current keys; found=nan"
    )

    with pytest.raises(SignError) as caught:
        KeyringSpec((key,), nan)  # type: ignore[arg-type]
    assert str(caught.value) == refusal

    with pytest.raises(SignError) as caught:
        replace(KeyringSpec((key,), 1), threshold=nan)
    assert str(caught.value) == refusal

    # Forced into the rejected state with object.__setattr__: the verifier
    # re-checks the keyring, so an empty signature map no longer clears a NaN.
    forced = KeyringSpec((key,), 1)
    object.__setattr__(forced, "threshold", nan)
    with pytest.raises(SignError) as caught:
        verify_threshold(
            b"payload",
            {},
            {},
            forced,
            domain=b"consumer/v1\0",
            label="record",
            allow_legacy=False,
        )
    assert str(caught.value) == refusal


def _two_keys() -> tuple[tuple[bytes, bytes], tuple[bytes, bytes], KeySpec, KeySpec]:
    first = generate_signing_keypair()
    second = generate_signing_keypair()
    return (
        first,
        second,
        KeySpec("a", spki_sha256(first[1]), "spki-sha256"),
        KeySpec("b", spki_sha256(second[1]), "spki-sha256"),
    )


def _verify_one_signer(keyring: object, key_pair: tuple[bytes, bytes], *, legacy: bool):
    private_pem, public_pem = key_pair
    payload, domain = b"payload", b"consumer/v1\0"
    return verify_threshold(
        payload,
        {"a": sign_payload(private_pem, payload, domain=domain)},
        {"a": public_pem},
        keyring,  # type: ignore[arg-type]
        domain=domain,
        label="record",
        allow_legacy=legacy,
    )


@pytest.mark.parametrize("generation", ["keys", "legacy_keys"])
def test_a_keyring_list_mutated_after_construction_changes_nothing(
    generation: str,
) -> None:
    """One signer must not satisfy a 2-of-2 by a list the caller kept."""

    first, _second, key_a, key_b = _two_keys()
    if generation == "keys":
        keys = [key_a, key_b]
        keyring = KeyringSpec(keys, 2)  # type: ignore[arg-type]
        keys[1] = key_a
    else:
        legacy: list[KeySpec] = []
        keyring = KeyringSpec((key_a, key_b), 2, legacy_keys=legacy)  # type: ignore[arg-type]
        legacy.append(key_a)

    assert type(keyring.keys) is tuple and type(keyring.legacy_keys) is tuple
    assert keyring == KeyringSpec((key_a, key_b), 2)
    hash(keyring)
    with pytest.raises(SignError) as caught:
        _verify_one_signer(keyring, first, legacy=generation == "legacy_keys")
    assert str(caught.value) == (
        "signature threshold not satisfied for record: threshold=2; "
        "satisfied=('a',); failed=(); absent=('b',)"
    )


def test_every_mutation_of_the_callers_lists_leaves_the_keyring_unchanged() -> None:
    """Property, enumerated: for each generation list and each mutation a list
    supports (item assignment, append, insert, remove, clear, reverse, extend),
    the constructed keyring's generations and its equality and hash stay put."""

    _first, _second, key_a, key_b = _two_keys()
    key_c = KeySpec("c", "c" * 64, "spki-sha256")
    mutations = (
        lambda items: items.__setitem__(0, key_a),
        lambda items: items.__setitem__(-1, key_a),
        lambda items: items.append(key_a),
        lambda items: items.insert(0, key_c),
        lambda items: items.remove(items[0]) if items else None,
        lambda items: items.clear(),
        lambda items: items.reverse(),
        lambda items: items.extend([key_a, key_b]),
    )
    for mutate in mutations:
        keys, legacy = [key_a, key_b], [key_c]
        keyring = KeyringSpec(keys, 2, legacy_keys=legacy)  # type: ignore[arg-type]
        snapshot = (keyring.keys, keyring.legacy_keys, hash(keyring))
        mutate(keys)
        mutate(legacy)
        assert (keyring.keys, keyring.legacy_keys, hash(keyring)) == snapshot
        assert keyring == KeyringSpec((key_a, key_b), 2, legacy_keys=(key_c,))


def test_a_keyring_subclass_or_stand_in_cannot_reach_a_verifier() -> None:
    first, _second, key_a, _key_b = _two_keys()

    @dataclass(frozen=True)
    class LaxKeyring(KeyringSpec):
        def __post_init__(self) -> None:  # a subclass "extending" the spec
            pass

    stand_ins: list[object] = [
        LaxKeyring((key_a,), 0),
        LaxKeyring((key_a,), float("nan")),  # type: ignore[arg-type]
        SimpleNamespace(keys=(key_a,), legacy_keys=(), threshold=0),
    ]
    for keyring in stand_ins:
        name = type(keyring).__name__
        with pytest.raises(SignError) as caught:
            verify_threshold(
                b"anything",
                {},
                {},
                keyring,  # type: ignore[arg-type]
                domain=b"d",
                label="r",
                allow_legacy=False,
            )
        assert str(caught.value) == f"keyring must be a KeyringSpec, not {name}"
        with pytest.raises(SignError) as caught:
            verify_any_generation(
                b"anything",
                bytes(64),
                {"a": first[1]},
                keyring,  # type: ignore[arg-type]
                domain=b"d",
                label="r",
            )
        assert str(caught.value) == f"keyring must be a KeyringSpec, not {name}"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("threshold", 0, "keyring threshold must be at least 1; found=0"),
        ("keys", (), "keyring must contain at least one key"),
        ("keys", "dup", "duplicate key_id in keyring: 'a'"),
        ("legacy_keys", "dup", "duplicate key_id in keyring: 'a'"),
        ("keys", "list", "keyring keys must be a tuple of KeySpec; found=list"),
    ],
)
def test_verifiers_recheck_a_keyring_mutated_past_its_frozen_fields(
    field: str, value: object, message: str
) -> None:
    first, _second, key_a, key_b = _two_keys()
    keyring = KeyringSpec((key_a, key_b), 2)
    if value == "dup":
        value = (key_a, key_a) if field == "keys" else (key_a,)
    elif value == "list":
        value = [key_a, key_b]
    object.__setattr__(keyring, field, value)

    for verify in (
        lambda: _verify_one_signer(keyring, first, legacy=True),
        lambda: verify_any_generation(
            b"payload", bytes(64), {}, keyring, domain=b"d", label="r"
        ),
    ):
        with pytest.raises(SignError) as caught:
            verify()
        assert str(caught.value) == message


@pytest.mark.parametrize(
    ("keys", "legacy", "message"),
    [
        ("subclass", (), "keyring entries must be KeySpec, not NamedKey"),
        ("current", "subclass", "keyring entries must be KeySpec, not NamedKey"),
        ("current", ("a",), "keyring entries must be KeySpec, not str"),
        ("current", None, "keyring legacy_keys must be an iterable of KeySpec; found=NoneType"),
        ("text", (), "keyring keys must be an iterable of KeySpec; found=str"),
    ],
)
def test_keyring_construction_refuses_entries_it_cannot_freeze(
    keys: str, legacy: object, message: str
) -> None:
    _first, _second, key_a, key_b = _two_keys()

    @dataclass(frozen=True)
    class NamedKey(KeySpec):
        pass

    named = NamedKey(key_b.key_id, key_b.fingerprint, key_b.scheme)
    current: object = {
        "subclass": (key_a, named),
        "current": (key_a,),
        "text": "ab",
    }[keys]
    if legacy == "subclass":
        legacy = (named,)
    with pytest.raises(SignError) as caught:
        KeyringSpec(current, 1, legacy_keys=legacy)  # type: ignore[arg-type]
    assert str(caught.value) == message


@pytest.mark.parametrize("generation", ["keys", "legacy_keys"])
@pytest.mark.parametrize("threshold", [0, False])
def test_keyring_scalar_threshold_refusal_precedes_generation_freezing(
    generation: str, threshold: object
) -> None:
    """Old scalar-count refusals still win over unusable generations."""

    key = KeySpec("a", "a" * 64, "spki-sha256")
    keys, legacy = (("ab", ()) if generation == "keys" else ((key,), None))
    with pytest.raises(SignError) as caught:
        KeyringSpec(keys, threshold, legacy_keys=legacy)  # type: ignore[arg-type]
    if type(threshold) is int:
        expected = "keyring threshold must be at least 1; found=0"
    else:
        expected = (
            "keyring threshold must be an integer between 1 and the number "
            "of current keys; found=False"
        )
    assert str(caught.value) == expected


def test_keyring_key_count_refusal_precedes_legacy_generation_freezing() -> None:
    key = KeySpec("a", "a" * 64, "spki-sha256")
    with pytest.raises(SignError) as caught:
        KeyringSpec((key,), 2, legacy_keys=None)  # type: ignore[arg-type]
    assert str(caught.value) == "keyring threshold 2 exceeds key count 1"


def test_keyring_generation_refusal_precedes_count_for_unusable_current_keys() -> None:
    """A text generation is refused before using its characters as keys."""

    with pytest.raises(SignError) as caught:
        KeyringSpec("ab", 3)  # type: ignore[arg-type]
    assert str(caught.value) == "keyring keys must be an iterable of KeySpec; found=str"


@pytest.mark.parametrize("duplicate", ["key_id", "fingerprint"])
def test_keyspec_subclass_refusal_precedes_keyring_duplicate_refusals(
    duplicate: str,
) -> None:
    """A subclass is refused before its fields enter duplicate checks."""

    @dataclass(frozen=True)
    class NamedKey(KeySpec):
        pass

    key = KeySpec("a", "a" * 64, "spki-sha256")
    named = NamedKey(
        "a" if duplicate == "key_id" else "b",
        "b" * 64 if duplicate == "key_id" else "a" * 64,
        "spki-sha256",
    )
    with pytest.raises(SignError) as caught:
        KeyringSpec((key, named), 1)
    assert str(caught.value) == "keyring entries must be KeySpec, not NamedKey"


@pytest.mark.parametrize("verifier", ["threshold", "any_generation"])
def test_a_keyspec_subclass_is_refused_before_it_can_mutate_the_outer_ring(
    verifier: str,
) -> None:
    """An unvalidated entry cannot change the ring during its own checks."""

    target: list[KeyringSpec] = []
    reads: list[str] = []

    class MutatingKey(KeySpec):
        def __getattribute__(self, name: str) -> object:
            if target and name in {"key_id", "fingerprint"}:
                reads.append(name)
                object.__setattr__(target[0], "keys", ())
                object.__setattr__(target[0], "threshold", 0)
            return super().__getattribute__(name)

    trusted = KeySpec("a", "a" * 64, "spki-sha256")
    unvalidated = MutatingKey("a", "a" * 64, "spki-sha256")
    keyring = KeyringSpec((trusted,), 1)
    object.__setattr__(keyring, "keys", (unvalidated,))
    target.append(keyring)

    with pytest.raises(SignError) as caught:
        if verifier == "threshold":
            verify_threshold(
                b"payload", {}, {}, keyring,
                domain=b"domain", label="r", allow_legacy=False,
            )
        else:
            verify_any_generation(
                b"payload", bytes(64), {}, keyring,
                domain=b"domain", label="r", allow_legacy=False,
            )
    assert str(caught.value) == "keyring entries must be KeySpec, not MutatingKey"
    assert reads == []
    assert keyring.keys[0] is unvalidated
    assert keyring.threshold == 1


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("payload", "payload", "signature payload must be bytes"),
        ("domain", "domain", "signature domain must be bytes"),
        ("allow_legacy", 0, "allow_legacy must be a bool"),
        ("signatures", {0: bytes(64)}, "presented signature key_id must be a str: 0"),
        ("public_keys", {0: bytes(32)}, "presented public key key_id must be a str: 0"),
    ],
)
def test_threshold_independent_input_refusal_precedes_keyring_refusal(
    field: str, value: object, expected: str
) -> None:
    @dataclass(frozen=True)
    class LaxKeyring(KeyringSpec):
        def __post_init__(self) -> None:
            pass

    key = KeySpec("a", "a" * 64, "spki-sha256")
    inputs = dict(
        payload=b"payload", signatures={}, public_keys={},
        domain=b"domain", allow_legacy=False,
    )
    inputs[field] = value
    with pytest.raises(SignError) as caught:
        verify_threshold(**inputs, keyring=LaxKeyring((key,), 1), label="r")
    assert str(caught.value) == expected


@pytest.mark.parametrize("verifier", ["threshold", "any_generation"])
@pytest.mark.parametrize(
    "later_refusal",
    [
        "unknown_id", "legacy_id", "nonbyte_key", "malformed_key",
        "non_ed25519_key", "fingerprint_mismatch", "duplicate_material",
        "cryptography_unavailable", "no_signature", "signature_mismatch",
    ],
)
def test_keyring_type_refusal_precedes_ring_dependent_verification(
    monkeypatch: pytest.MonkeyPatch, verifier: str, later_refusal: str
) -> None:
    """An outer ring is validated before its trust material is consulted."""

    first, second, key_a, key_b = _two_keys()

    @dataclass(frozen=True)
    class Ring(KeyringSpec):
        pass

    keys, legacy = (key_a,), ()
    material = {"a": first[1]}
    if later_refusal == "unknown_id":
        material = {"z": first[1]}
    elif later_refusal == "legacy_id":
        legacy, material = (key_b,), {"b": second[1]}
    elif later_refusal == "nonbyte_key":
        material = {"a": "PEM"}
    elif later_refusal == "malformed_key":
        material = {"a": b"invalid"}
    elif later_refusal == "non_ed25519_key":
        material = {"a": ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        )}
    elif later_refusal == "fingerprint_mismatch":
        material = {"a": second[1]}
    elif later_refusal == "duplicate_material":
        keys = (key_a, KeySpec("c", raw_public_key_sha256(first[1]), "raw-sha256"))
        material = {"a": first[1], "c": first[1]}
    elif later_refusal == "cryptography_unavailable":
        monkeypatch.setattr(sign_module, "CRYPTOGRAPHY_AVAILABLE", False)
    elif later_refusal == "no_signature":
        material = {}

    def verify(keyring: KeyringSpec) -> None:
        if verifier == "threshold":
            verify_threshold(
                b"payload", {"a": bytes(64)} if later_refusal == "signature_mismatch" else {},
                material, keyring,
                domain=b"domain", label="r", allow_legacy=False,
            )
        else:
            verify_any_generation(
                b"payload", bytes(64), material, keyring,
                domain=b"domain", label="r", allow_legacy=False,
            )

    with pytest.raises(SignError) as caught:
        verify(Ring(keys, 1, legacy_keys=legacy))
    assert str(caught.value) == "keyring must be a KeyringSpec, not Ring"
    # The same envelope with an exact ring really reaches the named later
    # family, so each combined-invalidity case pins its first refusal.
    expected = {
        "unknown_id": "unknown key_id:",
        "legacy_id": "legacy key_id refused for new material:",
        "nonbyte_key": "Ed25519 public key must be bytes",
        "malformed_key": "cannot decode Ed25519 public key",
        "non_ed25519_key": "public key is not Ed25519",
        "fingerprint_mismatch": "public key fingerprint mismatch",
        "duplicate_material": "duplicate key material presented",
        "cryptography_unavailable": "Ed25519 public-key normalization requires cryptography",
        "no_signature": (
            "signature threshold not satisfied" if verifier == "threshold"
            else "verify_any_generation requires key material for every keyring key"
        ),
        "signature_mismatch": (
            "signature threshold not satisfied" if verifier == "threshold"
            else "signature does not verify under any keyring generation"
        ),
    }[later_refusal]
    with pytest.raises(SignError) as caught:
        verify(KeyringSpec(keys, 1, legacy_keys=legacy))
    assert str(caught.value).startswith(expected)


@pytest.mark.parametrize(
    "later_refusal",
    ["threshold", "payload", "domain", "allow_legacy", "signature", "public_key_id"],
)
def test_any_generation_keyring_refusal_precedes_envelope_checks(
    later_refusal: str,
) -> None:
    @dataclass(frozen=True)
    class Ring(KeyringSpec):
        pass

    key_a = KeySpec("a", "a" * 64, "spki-sha256")
    key_b = KeySpec("b", "b" * 64, "spki-sha256")
    keyring = Ring((key_a, key_b), 2) if later_refusal == "threshold" else Ring((key_a,), 1)
    inputs = dict(
        payload=b"payload", signature=bytes(64), public_keys={},
        domain=b"domain", allow_legacy=False,
    )
    changes = {
        "payload": ("payload", "payload"),
        "domain": ("domain", "domain"),
        "allow_legacy": ("allow_legacy", 0),
        "signature": ("signature", b"short"),
        "public_key_id": ("public_keys", {0: bytes(32)}),
    }
    if later_refusal in changes:
        field, value = changes[later_refusal]
        inputs[field] = value
    with pytest.raises(SignError) as caught:
        verify_any_generation(**inputs, keyring=keyring, label="r")
    assert str(caught.value) == "keyring must be a KeyringSpec, not Ring"


THRESHOLD_KEY_IDS = ("key-a", "key-b", "key-c")
ACCEPTING_SUBSETS = tuple(
    subset
    for size in (2, 3)
    for subset in itertools.combinations(THRESHOLD_KEY_IDS, size)
)


@pytest.mark.parametrize("subset", ACCEPTING_SUBSETS)
def test_two_of_three_accepts_every_satisfying_subset(
    subset: tuple[str, ...],
) -> None:
    material, keyring = _three_keyring()
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    signatures, public_keys = _present_subset(
        material,
        subset,
        payload=payload,
        domain=domain,
    )

    verification = verify_threshold(
        payload,
        signatures,
        public_keys,
        keyring,
        domain=domain,
        label="record",
        allow_legacy=False,
    )
    assert verification == ThresholdVerification(
        satisfied=tuple(sorted(subset)),
        failed=(),
        absent=tuple(sorted(set(THRESHOLD_KEY_IDS) - set(subset))),
    )


@pytest.mark.parametrize("key_id", THRESHOLD_KEY_IDS)
def test_two_of_three_refuses_every_one_key_subset(key_id: str) -> None:
    material, keyring = _three_keyring()
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    signatures, public_keys = _present_subset(
        material,
        (key_id,),
        payload=payload,
        domain=domain,
    )

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            signatures,
            public_keys,
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    message = str(caught.value)
    assert "threshold=2" in message
    assert f"satisfied={(key_id,)!r}" in message
    assert "failed=()" in message
    absent = tuple(sorted(set(THRESHOLD_KEY_IDS) - {key_id}))
    assert f"absent={absent!r}" in message


class _DuplicatePresentation(Mapping[str, bytes]):
    def __init__(self, key_id: str, value: bytes) -> None:
        self.key_id = key_id
        self.value = value

    def __getitem__(self, key: str) -> bytes:
        if key != self.key_id:
            raise KeyError(key)
        return self.value

    def __iter__(self) -> Iterator[str]:
        yield self.key_id
        yield self.key_id

    def __len__(self) -> int:
        return 2


def test_duplicate_presentation_counts_one_key_once() -> None:
    material, keyring = _three_keyring()
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    key_id = "key-a"
    signature = sign_payload(material[key_id][0], payload, domain=domain)

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            _DuplicatePresentation(key_id, signature),
            _DuplicatePresentation(key_id, material[key_id][1]),
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    message = str(caught.value)
    assert "satisfied=('key-a',)" in message
    assert "absent=('key-b', 'key-c')" in message


@pytest.mark.parametrize("unknown_mapping", ("signatures", "public_keys"))
def test_unknown_key_id_refuses_even_when_threshold_is_met(
    unknown_mapping: str,
) -> None:
    material, keyring = _three_keyring()
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    signatures, public_keys = _present_subset(
        material,
        ("key-a", "key-b"),
        payload=payload,
        domain=domain,
    )
    if unknown_mapping == "signatures":
        signatures["unknown-root"] = b"0" * 64
    else:
        public_keys["unknown-root"] = material["key-c"][1]

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            signatures,
            public_keys,
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    assert str(caught.value) == "unknown key_id: 'unknown-root'"


def test_fingerprint_mismatch_refuses_with_computed_value_after_threshold_met() -> None:
    material, keyring = _three_keyring()
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    signatures, public_keys = _present_subset(
        material,
        ("key-a", "key-b"),
        payload=payload,
        domain=domain,
    )
    public_keys["key-c"] = material["key-a"][1]
    computed = spki_sha256(material["key-a"][1])

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            signatures,
            public_keys,
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    message = str(caught.value)
    assert "public key fingerprint mismatch for 'key-c' (spki-sha256)" in message
    assert f"computed={computed}" in message


def test_spki_and_raw_fingerprint_keyrings_verify_the_same_key() -> None:
    private_key_pem, public_key_pem = generate_signing_keypair()
    raw_public_key = _raw_public_key(public_key_pem)
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    signature = sign_payload(private_key_pem, payload, domain=domain)

    cases = (
        (
            "spki-sha256",
            spki_sha256(public_key_pem),
            public_key_pem,
        ),
        (
            "raw-sha256",
            raw_public_key_sha256(public_key_pem),
            raw_public_key,
        ),
    )
    for scheme, fingerprint, supplied_key in cases:
        keyring = KeyringSpec(
            (KeySpec("root", fingerprint, scheme),),
            threshold=1,
        )
        verification = verify_threshold(
            payload,
            {"root": signature},
            {"root": supplied_key},
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
        assert verification == ThresholdVerification(("root",), (), ())


def test_threshold_reports_failed_and_absent_keys() -> None:
    material, keyring = _three_keyring()
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    signatures, public_keys = _present_subset(
        material,
        ("key-a", "key-b"),
        payload=payload,
        domain=domain,
    )
    signatures["key-c"] = b"0" * 64
    public_keys["key-c"] = material["key-c"][1]
    verification = verify_threshold(
        payload,
        signatures,
        public_keys,
        keyring,
        domain=domain,
        label="record",
        allow_legacy=False,
    )
    assert verification == ThresholdVerification(
        ("key-a", "key-b"),
        ("key-c",),
        (),
    )

    signatures = {
        "key-a": sign_payload(material["key-a"][0], payload, domain=domain),
        "key-b": b"0" * 64,
    }
    public_keys = {
        "key-a": material["key-a"][1],
        "key-b": material["key-b"][1],
    }
    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            signatures,
            public_keys,
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    message = str(caught.value)
    assert "satisfied=('key-a',)" in message
    assert "failed=('key-b',)" in message
    assert "absent=('key-c',)" in message


def test_signature_or_public_key_alone_counts_as_absent() -> None:
    material, keyring = _three_keyring()
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    signature = sign_payload(material["key-a"][0], payload, domain=domain)

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            {"key-a": signature},
            {"key-b": material["key-b"][1]},
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    message = str(caught.value)
    assert "satisfied=()" in message
    assert "failed=()" in message
    assert "absent=('key-a', 'key-b', 'key-c')" in message


def test_threshold_domain_separation() -> None:
    private_key_pem, public_key_pem = generate_signing_keypair()
    payload = b"threshold payload"
    domain_a = b"consumer/a\0"
    domain_b = b"consumer/b\0"
    signature = sign_payload(private_key_pem, payload, domain=domain_a)
    keyring = KeyringSpec(
        (KeySpec("root", spki_sha256(public_key_pem), "spki-sha256"),),
        threshold=1,
    )

    assert verify_threshold(
        payload,
        {"root": signature},
        {"root": public_key_pem},
        keyring,
        domain=domain_a,
        label="record",
        allow_legacy=False,
    ) == ThresholdVerification(("root",), (), ())

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            {"root": signature},
            {"root": public_key_pem},
            keyring,
            domain=domain_b,
            label="record",
            allow_legacy=False,
        )
    message = str(caught.value)
    assert "satisfied=()" in message
    assert "failed=('root',)" in message
    assert "absent=()" in message


def test_threshold_requires_exact_bytes_and_explicit_domain() -> None:
    _, public_key_pem = generate_signing_keypair()
    keyring = KeyringSpec(
        (KeySpec("root", spki_sha256(public_key_pem), "spki-sha256"),),
        threshold=1,
    )
    parameter = inspect.signature(verify_threshold).parameters["domain"]
    assert parameter.default is inspect.Parameter.empty

    with pytest.raises(SignError, match="^signature payload must be bytes$"):
        verify_threshold(
            bytearray(),  # type: ignore[arg-type]
            {},
            {},
            keyring,
            domain=b"",
            label="record",
            allow_legacy=False,
        )
    with pytest.raises(SignError, match="^signature domain must be bytes$"):
        verify_threshold(
            b"",
            {},
            {},
            keyring,
            domain=bytearray(),  # type: ignore[arg-type]
            label="record",
            allow_legacy=False,
        )
    with pytest.raises(TypeError, match="domain"):
        verify_threshold(  # type: ignore[call-arg]
            b"",
            {},
            {},
            keyring,
            label="record",
            allow_legacy=False,
        )


# --- key generations (0.3.0): legacy verification sets + required domains ---
#
# Modeled on the semantics a production rotation incident fixed upstream:
# current keys sign and verify new material; retired keys verify immutable
# pre-rotation history only, explicitly; malformed key material is always
# fatal; only a clean signature mismatch under a validated key falls through
# to an older generation.


def test_sign_payload_requires_explicit_domain() -> None:
    parameter = inspect.signature(sign_payload).parameters["domain"]
    assert parameter.default is inspect.Parameter.empty

    private_key_pem, _ = generate_signing_keypair()
    with pytest.raises(TypeError, match="domain"):
        sign_payload(private_key_pem, b"payload")  # type: ignore[call-arg]


def test_verify_threshold_requires_explicit_allow_legacy() -> None:
    parameter = inspect.signature(verify_threshold).parameters["allow_legacy"]
    assert parameter.default is inspect.Parameter.empty

    _, public_key_pem = generate_signing_keypair()
    keyring = KeyringSpec(
        (KeySpec("root", spki_sha256(public_key_pem), "spki-sha256"),),
        threshold=1,
    )
    with pytest.raises(TypeError, match="allow_legacy"):
        verify_threshold(  # type: ignore[call-arg]
            b"",
            {},
            {},
            keyring,
            domain=b"",
            label="record",
        )
    with pytest.raises(SignError, match="^allow_legacy must be a bool$"):
        verify_threshold(
            b"",
            {},
            {},
            keyring,
            domain=b"",
            label="record",
            allow_legacy=1,  # type: ignore[arg-type]
        )


def _rotated_keyring() -> tuple[
    dict[str, tuple[bytes, bytes]],
    KeyringSpec,
]:
    """One current key ("new-root") over one retired key ("old-root")."""

    material = {
        "new-root": generate_signing_keypair(),
        "old-root": generate_signing_keypair(),
    }
    keyring = KeyringSpec(
        keys=(
            KeySpec("new-root", spki_sha256(material["new-root"][1]), "spki-sha256"),
        ),
        threshold=1,
        legacy_keys=(
            KeySpec("old-root", spki_sha256(material["old-root"][1]), "spki-sha256"),
        ),
    )
    return material, keyring


def test_keyring_legacy_construction_refusals() -> None:
    current = KeySpec("root", "c" * 64, "spki-sha256")

    with pytest.raises(SignError) as caught:
        KeyringSpec(
            (current,),
            1,
            legacy_keys=(KeySpec("root", "d" * 64, "spki-sha256"),),
        )
    assert str(caught.value) == "duplicate key_id in keyring: 'root'"

    with pytest.raises(SignError) as caught:
        KeyringSpec(
            (current,),
            1,
            legacy_keys=(KeySpec("old", "c" * 64, "raw-sha256"),),
        )
    assert str(caught.value) == f"duplicate fingerprint in keyring: {'c' * 64!r}"

    with pytest.raises(SignError) as caught:
        KeyringSpec(
            (current,),
            1,
            legacy_keys=(
                KeySpec("old-a", "d" * 64, "spki-sha256"),
                KeySpec("old-b", "d" * 64, "spki-sha256"),
            ),
        )
    assert str(caught.value) == f"duplicate fingerprint in keyring: {'d' * 64!r}"

    # Threshold is defined over current keys alone; legacy keys never raise it.
    with pytest.raises(SignError) as caught:
        KeyringSpec(
            (current,),
            2,
            legacy_keys=(KeySpec("old", "d" * 64, "spki-sha256"),),
        )
    assert str(caught.value) == "keyring threshold 2 exceeds key count 1"


def test_legacy_key_refused_for_new_material() -> None:
    material, keyring = _rotated_keyring()
    payload = b"new material"
    domain = b"consumer/v1\0"
    signature = sign_payload(material["old-root"][0], payload, domain=domain)

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            {"old-root": signature},
            {"old-root": material["old-root"][1]},
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    assert str(caught.value) == "legacy key_id refused for new material: 'old-root'"

    # Supplying only the legacy PUBLIC KEY (no signature) refuses identically:
    # a legacy key has no business anywhere near new-material verification.
    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            {},
            {"old-root": material["old-root"][1]},
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    assert str(caught.value) == "legacy key_id refused for new material: 'old-root'"

    # Supplying only the legacy SIGNATURE (no public key) refuses too — an
    # implementation guarding just public_keys would miss this branch.
    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            {"old-root": signature},
            {},
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    assert str(caught.value) == "legacy key_id refused for new material: 'old-root'"

    # An extra legacy signature refuses even when the CURRENT key already
    # forms a valid quorum: legacy presence on new material is itself the
    # refusal, not merely a failure to count.
    current_signature = sign_payload(material["new-root"][0], payload, domain=domain)
    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            {"new-root": current_signature, "old-root": signature},
            {"new-root": material["new-root"][1]},
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    assert str(caught.value) == "legacy key_id refused for new material: 'old-root'"


def test_legacy_counts_for_history_and_is_reported() -> None:
    material, keyring = _rotated_keyring()
    payload = b"immutable pre-rotation artifact"
    domain = b"consumer/v1\0"
    signature = sign_payload(material["old-root"][0], payload, domain=domain)

    verification = verify_threshold(
        payload,
        {"old-root": signature},
        {"old-root": material["old-root"][1]},
        keyring,
        domain=domain,
        label="record",
        allow_legacy=True,
    )
    assert verification == ThresholdVerification(
        satisfied=("old-root",),
        failed=(),
        absent=("new-root",),
        legacy_satisfied=("old-root",),
    )

    # A current-key signature on history reports no legacy involvement.
    current_signature = sign_payload(material["new-root"][0], payload, domain=domain)
    verification = verify_threshold(
        payload,
        {"new-root": current_signature},
        {"new-root": material["new-root"][1]},
        keyring,
        domain=domain,
        label="record",
        allow_legacy=True,
    )
    assert verification == ThresholdVerification(
        satisfied=("new-root",),
        failed=(),
        absent=("old-root",),
        legacy_satisfied=(),
    )


def test_duplicate_key_material_refused() -> None:
    private_key_pem, public_key_pem = generate_signing_keypair()
    raw_public_key = _raw_public_key(public_key_pem)
    payload = b"payload"
    domain = b"consumer/v1\0"
    signature = sign_payload(private_key_pem, payload, domain=domain)
    # Same physical key pinned as current (spki scheme) AND legacy (raw
    # scheme): fingerprints differ, so construction passes — the material-level
    # duplicate must be caught when the keys are supplied.
    keyring = KeyringSpec(
        keys=(KeySpec("current", spki_sha256(public_key_pem), "spki-sha256"),),
        threshold=1,
        legacy_keys=(
            KeySpec("shadow", raw_public_key_sha256(public_key_pem), "raw-sha256"),
        ),
    )

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            {"current": signature},
            {"current": public_key_pem, "shadow": raw_public_key},
            keyring,
            domain=domain,
            label="record",
            allow_legacy=True,
        )
    assert str(caught.value) == (
        "duplicate key material presented for 'current' and 'shadow'"
    )


def test_verify_any_generation_current_first_then_legacy() -> None:
    material, keyring = _rotated_keyring()
    payload = b"artifact"
    domain = b"consumer/v1\0"
    public_keys = {
        "new-root": material["new-root"][1],
        "old-root": material["old-root"][1],
    }

    current_signature = sign_payload(material["new-root"][0], payload, domain=domain)
    assert (
        verify_any_generation(
            payload,
            current_signature,
            public_keys,
            keyring,
            domain=domain,
            label="record",
        )
        == "new-root"
    )

    legacy_signature = sign_payload(material["old-root"][0], payload, domain=domain)
    assert (
        verify_any_generation(
            payload,
            legacy_signature,
            public_keys,
            keyring,
            domain=domain,
            label="record",
        )
        == "old-root"
    )

    # A signature by an unrelated key exhausts every generation; the refusal
    # lists the try order: current first, then legacy.
    stranger_private, _ = generate_signing_keypair()
    stranger_signature = sign_payload(stranger_private, payload, domain=domain)
    with pytest.raises(SignError) as caught:
        verify_any_generation(
            payload,
            stranger_signature,
            public_keys,
            keyring,
            domain=domain,
            label="record",
        )
    assert str(caught.value) == (
        "signature does not verify under any keyring generation for record: "
        "tried=['new-root', 'old-root']"
    )


def test_verify_any_generation_malformed_is_fatal() -> None:
    material, keyring = _rotated_keyring()
    payload = b"artifact"
    domain = b"consumer/v1\0"
    legacy_signature = sign_payload(material["old-root"][0], payload, domain=domain)
    public_keys = {
        "new-root": material["new-root"][1],
        "old-root": material["old-root"][1],
    }

    with pytest.raises(SignError) as caught:
        verify_any_generation(
            payload,
            legacy_signature[:-1],
            public_keys,
            keyring,
            domain=domain,
            label="record",
        )
    assert str(caught.value) == (
        "signature for record must be exactly 64 raw bytes; found=63"
    )

    # Mispinned CURRENT key while the LEGACY key would cleanly verify: fatal.
    # Bad key material is never skipped in favor of a key that vouches (the
    # regression a production rotation review caught).
    _, wrong_public_key = generate_signing_keypair()
    computed = spki_sha256(wrong_public_key)
    with pytest.raises(SignError) as caught:
        verify_any_generation(
            payload,
            legacy_signature,
            {"new-root": wrong_public_key, "old-root": material["old-root"][1]},
            keyring,
            domain=domain,
            label="record",
        )
    assert str(caught.value) == (
        "public key fingerprint mismatch for 'new-root' (spki-sha256): "
        f"expected={keyring.keys[0].fingerprint}, computed={computed}"
    )


def test_verify_any_generation_validates_all_material_eagerly() -> None:
    """A VALID current signature with mispinned LEGACY material must refuse.

    This is the discriminating direction (cross-family review of this PR): a
    lazy implementation that validated keys only as the fallback reached them
    would verify the current signature and return without ever touching the
    bad legacy key. Eager validation rejects the keyring wholesale — bad key
    material is never carried, even when nothing needed it."""

    material, keyring = _rotated_keyring()
    payload = b"artifact"
    domain = b"consumer/v1\0"
    current_signature = sign_payload(material["new-root"][0], payload, domain=domain)
    _, wrong_public_key = generate_signing_keypair()
    computed = spki_sha256(wrong_public_key)

    with pytest.raises(SignError) as caught:
        verify_any_generation(
            payload,
            current_signature,
            {"new-root": material["new-root"][1], "old-root": wrong_public_key},
            keyring,
            domain=domain,
            label="record",
        )
    assert str(caught.value) == (
        "public key fingerprint mismatch for 'old-root' (spki-sha256): "
        f"expected={keyring.legacy_keys[0].fingerprint}, computed={computed}"
    )


def test_verify_any_generation_requires_material_and_threshold_one() -> None:
    material, keyring = _rotated_keyring()
    payload = b"artifact"
    domain = b"consumer/v1\0"
    signature = sign_payload(material["new-root"][0], payload, domain=domain)

    with pytest.raises(SignError) as caught:
        verify_any_generation(
            payload,
            signature,
            {"new-root": material["new-root"][1]},
            keyring,
            domain=domain,
            label="record",
        )
    assert str(caught.value) == (
        "verify_any_generation requires key material for every keyring key; "
        "missing=['old-root']"
    )

    with pytest.raises(SignError, match="^unknown key_id: 'stranger'$"):
        verify_any_generation(
            payload,
            signature,
            {
                "new-root": material["new-root"][1],
                "old-root": material["old-root"][1],
                "stranger": material["new-root"][1],
            },
            keyring,
            domain=domain,
            label="record",
        )

    wide = KeyringSpec(
        keys=(
            KeySpec("a", "a" * 64, "spki-sha256"),
            KeySpec("b", "b" * 64, "spki-sha256"),
        ),
        threshold=2,
    )
    with pytest.raises(
        SignError,
        match="^verify_any_generation requires a threshold-1 keyring; found=2$",
    ):
        verify_any_generation(
            payload,
            signature,
            {},
            wide,
            domain=domain,
            label="record",
        )


def test_verify_any_generation_allow_legacy_defaults_to_true() -> None:
    """The keyword is additive: every 0.6.0 call site keeps its behavior.

    ``verify_any_generation`` exists for immutable pre-rotation history, so
    trying the retired generations is the default; the keyword only lets a
    caller say the artifact is new material.
    """

    parameter = inspect.signature(verify_any_generation).parameters["allow_legacy"]
    assert parameter.default is True
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY

    material, keyring = _rotated_keyring()
    payload = b"artifact"
    domain = b"consumer/v1\0"
    public_keys = {
        "new-root": material["new-root"][1],
        "old-root": material["old-root"][1],
    }
    legacy_signature = sign_payload(material["old-root"][0], payload, domain=domain)

    # Unstated and stated True are the same call.
    for call in (
        lambda: verify_any_generation(
            payload,
            legacy_signature,
            public_keys,
            keyring,
            domain=domain,
            label="record",
        ),
        lambda: verify_any_generation(
            payload,
            legacy_signature,
            public_keys,
            keyring,
            domain=domain,
            label="record",
            allow_legacy=True,
        ),
    ):
        assert call() == "old-root"


def test_verify_any_generation_allow_legacy_false_refuses_retired_keys() -> None:
    """``allow_legacy=False`` puts the retired generation out of reach.

    A retired signature no longer falls through to the key that would vouch
    for it, and a presented retired key_id refuses with the wording
    ``verify_threshold`` already uses for one — before any signature is
    tried, so an accompanying valid current signature cannot mask it.
    """

    material, keyring = _rotated_keyring()
    payload = b"new material"
    domain = b"consumer/v1\0"
    current_only = {"new-root": material["new-root"][1]}
    both_keys = {
        "new-root": material["new-root"][1],
        "old-root": material["old-root"][1],
    }

    # A retired signature: only the current generation is tried, and the
    # refusal names exactly what was tried.
    legacy_signature = sign_payload(material["old-root"][0], payload, domain=domain)
    with pytest.raises(SignError) as caught:
        verify_any_generation(
            payload,
            legacy_signature,
            current_only,
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    assert str(caught.value) == (
        "signature does not verify under any keyring generation for record: "
        "tried=['new-root']"
    )

    # A retired PUBLIC KEY refuses on presence alone, exactly as
    # verify_threshold refuses one, even though the signature is current and
    # the current key material is present and correct.
    current_signature = sign_payload(material["new-root"][0], payload, domain=domain)
    with pytest.raises(SignError) as caught:
        verify_any_generation(
            payload,
            current_signature,
            both_keys,
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    assert str(caught.value) == "legacy key_id refused for new material: 'old-root'"

    # ... and with a retired signature too, presence still decides first.
    with pytest.raises(SignError) as caught:
        verify_any_generation(
            payload,
            legacy_signature,
            both_keys,
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    assert str(caught.value) == "legacy key_id refused for new material: 'old-root'"

    # An unknown key_id still outranks the legacy refusal, as in
    # verify_threshold: the caller is told about the key nobody pinned first.
    with pytest.raises(SignError, match="^unknown key_id: 'stranger'$"):
        verify_any_generation(
            payload,
            current_signature,
            {**both_keys, "stranger": material["new-root"][1]},
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )

    # The required-material check narrows to the current generation, so the
    # retired key's absence is no longer missing material — and a current
    # signature verifies without the retired key ever being loaded.
    assert (
        verify_any_generation(
            payload,
            current_signature,
            current_only,
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
        == "new-root"
    )
    with pytest.raises(SignError) as caught:
        verify_any_generation(
            payload,
            current_signature,
            {},
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    assert str(caught.value) == (
        "verify_any_generation requires key material for every keyring "
        "key; missing=['new-root']"
    )


def test_verify_any_generation_allow_legacy_must_be_a_bool() -> None:
    """Exactly the bool discipline verify_threshold holds allow_legacy to.

    ``1`` and ``0`` would otherwise silently read as True and False, which is
    how a caller means to refuse retired keys and gets them tried anyway.
    """

    material, keyring = _rotated_keyring()
    payload = b"artifact"
    domain = b"consumer/v1\0"
    signature = sign_payload(material["new-root"][0], payload, domain=domain)
    public_keys = {
        "new-root": material["new-root"][1],
        "old-root": material["old-root"][1],
    }

    for allow_legacy in (1, 0, None, "false"):
        with pytest.raises(SignError, match="^allow_legacy must be a bool$"):
            verify_any_generation(
                payload,
                signature,
                public_keys,
                keyring,
                domain=domain,
                label="record",
                allow_legacy=allow_legacy,  # type: ignore[arg-type]
            )


def test_rotation_round_trip_story() -> None:
    """The corpus-shaped lifecycle: sign, rotate, history stays verifiable."""

    domain = b"consumer/v1\0"
    first_private, first_public = generate_signing_keypair()
    artifact = b"released under the first key"
    artifact_signature = sign_payload(first_private, artifact, domain=domain)

    ring_v1 = KeyringSpec(
        (KeySpec("root-2026a", spki_sha256(first_public), "spki-sha256"),),
        threshold=1,
    )
    assert (
        verify_any_generation(
            artifact,
            artifact_signature,
            {"root-2026a": first_public},
            ring_v1,
            domain=domain,
            label="release",
        )
        == "root-2026a"
    )

    # Rotation: reviewed replacement moves the retired key into legacy_keys.
    second_private, second_public = generate_signing_keypair()
    ring_v2 = KeyringSpec(
        keys=(KeySpec("root-2026b", spki_sha256(second_public), "spki-sha256"),),
        threshold=1,
        legacy_keys=(
            KeySpec("root-2026a", spki_sha256(first_public), "spki-sha256"),
        ),
    )
    both_keys = {"root-2026a": first_public, "root-2026b": second_public}

    # Immutable history remains verifiable, attributed to the retired key.
    assert (
        verify_any_generation(
            artifact,
            artifact_signature,
            both_keys,
            ring_v2,
            domain=domain,
            label="release",
        )
        == "root-2026a"
    )

    # New material must come from the current key.
    fresh = b"released after rotation"
    with pytest.raises(SignError):
        verify_threshold(
            fresh,
            {"root-2026a": sign_payload(first_private, fresh, domain=domain)},
            {"root-2026a": first_public},
            ring_v2,
            domain=domain,
            label="release",
            allow_legacy=False,
        )
    fresh_signature = sign_payload(second_private, fresh, domain=domain)
    verification = verify_threshold(
        fresh,
        {"root-2026b": fresh_signature},
        {"root-2026b": second_public},
        ring_v2,
        domain=domain,
        label="release",
        allow_legacy=False,
    )
    assert verification.satisfied == ("root-2026b",)
    assert verification.legacy_satisfied == ()


class _RecordingKey:
    """Delegating wrapper that logs which key_id attempted verification."""

    def __init__(self, inner: Ed25519PublicKey, key_id: str, calls: list[str]) -> None:
        self._inner = inner
        self._key_id = key_id
        self._calls = calls

    def verify(self, signature: bytes, message: bytes) -> None:
        self._calls.append(self._key_id)
        self._inner.verify(signature, message)


def test_verify_any_generation_attempt_order_is_declaration_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pin the actual verify-call order with spies and NON-lexical ids.

    The ids are chosen so declaration order (current "zz-current" before
    legacy "aa-legacy") is the reverse of sorted order — a reimplementation
    that iterated a sorted or set-ordered collection would log the wrong
    sequence even while returning identical results (cross-family review of
    this PR: results alone cannot distinguish loop order, because each
    signature verifies under exactly one key)."""

    material = {
        "zz-current": generate_signing_keypair(),
        "aa-legacy": generate_signing_keypair(),
    }
    keyring = KeyringSpec(
        keys=(
            KeySpec("zz-current", spki_sha256(material["zz-current"][1]), "spki-sha256"),
        ),
        threshold=1,
        legacy_keys=(
            KeySpec("aa-legacy", spki_sha256(material["aa-legacy"][1]), "spki-sha256"),
        ),
    )
    public_keys = {
        "zz-current": material["zz-current"][1],
        "aa-legacy": material["aa-legacy"][1],
    }
    payload = b"artifact"
    domain = b"consumer/v1\0"

    calls: list[str] = []
    real_normalize = sign_module._normalize_pinned_public_keys

    def recording_normalize(supplied, specs):  # type: ignore[no-untyped-def]
        normalized = real_normalize(supplied, specs)
        return {
            key_id: _RecordingKey(key, key_id, calls)
            for key_id, key in normalized.items()
        }

    monkeypatch.setattr(
        sign_module, "_normalize_pinned_public_keys", recording_normalize
    )

    # Legacy-signed artifact: the current key is genuinely attempted first
    # and cleanly mismatches before the legacy key vouches.
    legacy_signature = sign_payload(
        material["aa-legacy"][0], payload, domain=domain
    )
    assert (
        verify_any_generation(
            payload,
            legacy_signature,
            public_keys,
            keyring,
            domain=domain,
            label="record",
        )
        == "aa-legacy"
    )
    assert calls == ["zz-current", "aa-legacy"]

    # Exhaustion visits every generation in declaration order, not sorted.
    calls.clear()
    stranger_private, _ = generate_signing_keypair()
    stranger_signature = sign_payload(stranger_private, payload, domain=domain)
    with pytest.raises(SignError) as caught:
        verify_any_generation(
            payload,
            stranger_signature,
            public_keys,
            keyring,
            domain=domain,
            label="record",
        )
    assert calls == ["zz-current", "aa-legacy"]
    assert str(caught.value) == (
        "signature does not verify under any keyring generation for record: "
        "tried=['zz-current', 'aa-legacy']"
    )

    # Current-signed artifact stops at the first (current) attempt.
    calls.clear()
    current_signature = sign_payload(
        material["zz-current"][0], payload, domain=domain
    )
    assert (
        verify_any_generation(
            payload,
            current_signature,
            public_keys,
            keyring,
            domain=domain,
            label="record",
        )
        == "zz-current"
    )
    assert calls == ["zz-current"]


# --- 0.6.2 review, L7 finding 7: a KeySpec pin is a lowercase SHA-256 hex digest


@pytest.mark.parametrize(
    "fingerprint",
    [
        "A" * 64,
        "a" * 64 + "\n",
        b"a" * 64,
        "sha256:" + "a" * 64,
        "a" * 63,
        None,
    ],
    ids=["uppercase", "newline", "bytes", "prefixed", "short", "none"],
)
def test_key_spec_refuses_a_fingerprint_that_can_never_match(
    fingerprint: object,
) -> None:
    """Only ``scheme`` was checked, so each of these constructed and then
    refused every key as a "mismatch" printing the same digest."""

    with pytest.raises(SignError, match="must be 64 lowercase hex characters"):
        KeySpec("k", fingerprint, "spki-sha256")  # type: ignore[arg-type]


@pytest.mark.parametrize("key_id", [["k"], {"k": 1}, 1, None])
def test_key_spec_refuses_a_key_id_that_is_not_a_str(key_id: object) -> None:
    with pytest.raises(SignError, match="^key_id must be a str"):
        KeySpec(key_id, "a" * 64, "spki-sha256")  # type: ignore[arg-type]


def test_a_str_subclass_pin_cannot_accept_a_stranger_key() -> None:
    """A pin whose ``__ne__`` always answered False compared equal to any
    computed fingerprint, so a stranger's key and signature satisfied the
    keyring."""

    class Agreeable(str):
        def __ne__(self, other: object) -> bool:
            return False

    with pytest.raises(SignError, match="must be 64 lowercase hex characters"):
        KeySpec("k", Agreeable("a" * 64), "spki-sha256")


def test_presented_key_ids_of_mixed_type_refuse_as_sign_errors() -> None:
    private_a, public_a = generate_signing_keypair()
    ring = KeyringSpec((KeySpec("a", spki_sha256(public_a), "spki-sha256"),), 1)
    signature = sign_payload(private_a, b"p", domain=b"")
    with pytest.raises(SignError, match="presented signature key_id must be a str"):
        verify_threshold(
            b"p", {7: bytes(64), "z": bytes(64)}, {}, ring,  # type: ignore[dict-item]
            domain=b"", label="r", allow_legacy=False,
        )
    with pytest.raises(SignError, match="presented public key key_id must be a str"):
        verify_threshold(
            b"p", {"a": signature}, {"a": public_a, 1: public_a},  # type: ignore[dict-item]
            ring, domain=b"", label="r", allow_legacy=False,
        )
    with pytest.raises(SignError, match="presented public key key_id must be a str"):
        verify_any_generation(
            b"p", signature, {1: public_a},  # type: ignore[dict-item]
            ring, domain=b"", label="r",
        )


def test_a_bytes_subclass_signature_is_refused_for_its_type() -> None:
    """0.6.2 review, L7 finding 8: "must be exactly 64 raw bytes; found=64"."""

    class Signature(bytes):
        pass

    private_key, public_key = generate_signing_keypair()
    signature = Signature(sign_payload(private_key, b"p", domain=b""))
    with pytest.raises(SignError) as caught:
        verify_signature_bytes(
            b"p",
            signature,
            public_key,
            public_key_filename="producer.pub",
            spki_sha256=None,
            label="x",
        )
    assert str(caught.value) == (
        "producer signature for x must be exactly 64 raw bytes; "
        "found=Signature (a bytes subclass)"
    )
    ring = KeyringSpec((KeySpec("a", spki_sha256(public_key), "spki-sha256"),), 1)
    with pytest.raises(SignError) as caught:
        verify_any_generation(
            b"p", signature, {"a": public_key}, ring, domain=b"", label="r"
        )
    assert str(caught.value) == (
        "signature for r must be exactly 64 raw bytes; "
        "found=Signature (a bytes subclass)"
    )
    # The ported texts are unchanged for exact bytes and for non-bytes.
    with pytest.raises(SignError, match="found=3$"):
        verify_signature_bytes(
            b"p", b"abc", public_key, public_key_filename="p", spki_sha256=None,
            label="x",
        )
    with pytest.raises(SignError, match="found=non-bytes$"):
        verify_signature_bytes(
            b"p", "abc", public_key, public_key_filename="p",  # type: ignore[arg-type]
            spki_sha256=None, label="x",
        )


# --- 0.6.2 review, L7 finding 5: the OpenSSL fallback accepts what the
# cryptography path accepts, and nothing else


def _p224_key_with_a_64_byte_signature(payload: bytes) -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives import hashes

    key = ec.generate_private_key(ec.SECP224R1())
    for _attempt in range(200):
        signature = key.sign(payload, ec.ECDSA(hashes.SHA256()))
        if len(signature) == 64:
            public_pem = key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return public_pem, signature
    raise AssertionError("no 64-byte P-224 signature in 200 tries")


def test_forced_openssl_path_refuses_what_the_cryptography_path_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")

    private_key_pem, public_key_pem = generate_signing_keypair()
    payload = b"payload"
    signature = sign_payload(private_key_pem, payload, domain=b"")
    public_key = serialization.load_pem_public_key(public_key_pem)
    der_spki = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    p224_pem, p224_signature = _p224_key_with_a_64_byte_signature(payload)
    cases = {
        "der_spki": (signature, der_spki),
        "private_key_pem": (signature, private_key_pem),
        "p224_unpinned": (p224_signature, p224_pem),
    }
    for name, (candidate_signature, key_bytes) in cases.items():
        crypto = _outcome(
            lambda: _verify(payload, candidate_signature, key_bytes, pin=None)
        )
        with monkeypatch.context() as patch:
            patch.setattr(sign_module, "CRYPTOGRAPHY_AVAILABLE", False)
            fallback = _outcome(
                lambda: _verify(payload, candidate_signature, key_bytes, pin=None)
            )
        assert crypto[0] == "refused", name
        assert fallback[0] == "refused", (name, fallback)
    with monkeypatch.context() as patch:
        patch.setattr(sign_module, "CRYPTOGRAPHY_AVAILABLE", False)
        assert _outcome(
            lambda: _verify(payload, p224_signature, p224_pem, pin=None)
        ) == ("refused", "producer public key is not Ed25519: producer-ed25519.pub")
        assert _outcome(
            lambda: _verify(payload, signature, private_key_pem, pin=None)
        ) == (
            "refused",
            "cannot decode producer Ed25519 public key: producer-ed25519.pub",
        )
        # The Ed25519 control still verifies on the fallback.
        assert _outcome(
            lambda: _verify(payload, signature, public_key_pem, pin=None)
        ) == ("accepted", "")


def test_forced_openssl_path_names_why_it_cannot_verify_the_empty_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """0.6.2 review, L7 finding 6: ``pkeyutl -rawin`` cannot take zero bytes.

    The fallback refused a valid signature over ``b""`` as "signature
    verification failed", blaming the signature for a tool limit, while the
    cryptography path accepted it. No OpenSSL command the fallback can rely
    on verifies the empty message (``dgst -verify`` did with OpenSSL 3.6 and
    refused a valid signature on the CI runners), so it still refuses, on
    every version, and says why.
    """

    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    private_key_pem, public_key_pem = generate_signing_keypair()
    _, other_public_key_pem = generate_signing_keypair()
    signature = sign_payload(private_key_pem, b"", domain=b"")
    assert _outcome(lambda: _verify(b"", signature, public_key_pem, pin=None)) == (
        "accepted",
        "",
    )
    monkeypatch.setattr(sign_module, "CRYPTOGRAPHY_AVAILABLE", False)
    reason = (
        "producer Ed25519 signature over an empty message for artifact.sig "
        "cannot be verified without the cryptography package"
    )
    for key in (public_key_pem, other_public_key_pem):
        for candidate in (signature, bytes(64)):
            assert _outcome(lambda: _verify(b"", candidate, key, pin=None)) == (
                "refused",
                reason,
            )
    # A pin mismatch is still reported first, as on the cryptography path.
    assert _outcome(
        lambda: _verify(b"", signature, other_public_key_pem, pin=_spki_pin(public_key_pem))
    )[1].startswith("producer public-key SPKI is not code-pinned")


def test_forced_openssl_path_agrees_with_cryptography_over_short_payloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Differential over the payload sizes beside the empty-message edge:
    every size from one byte up, signature and tamper answers the same on
    both paths. The empty message is the test above."""

    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    private_key_pem, public_key_pem = generate_signing_keypair()
    calls: dict[tuple[int, str], Callable[[], None]] = {}
    for size in (1, 2, 3, 31, 32, 33, 64):
        payload = bytes((index * 37 + 11) % 256 for index in range(size))
        signature = sign_payload(private_key_pem, payload, domain=b"")
        flipped = bytes([signature[0] ^ 1]) + signature[1:]
        tampered_payload = payload + b"\x00"
        for tamper, arguments in {
            "none": (payload, signature),
            "signature": (payload, flipped),
            "payload": (tampered_payload, signature),
        }.items():
            calls[(size, tamper)] = (
                lambda arguments=arguments: _verify(
                    *arguments, public_key_pem, pin=None
                )
            )
    crypto = {key: _outcome(call) for key, call in calls.items()}
    monkeypatch.setattr(sign_module, "CRYPTOGRAPHY_AVAILABLE", False)
    fallback = {key: _outcome(call) for key, call in calls.items()}
    assert fallback == crypto
    assert all(
        outcome[0] == ("accepted" if tamper == "none" else "refused")
        for (_size, tamper), outcome in crypto.items()
    )


# --- 0.6.2 review, L7 finding 9: the key is read from inside anchor_dir only


def test_read_producer_public_key_stays_inside_the_anchor_directory(
    tmp_path: pathlib.Path,
) -> None:
    anchors = tmp_path / "anchors"
    anchors.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "producer.pub").write_bytes(b"outside bytes")
    (anchors / "linked").symlink_to(outside, target_is_directory=True)
    nested = anchors / "keys"
    nested.mkdir()
    (nested / "producer.pub").write_bytes(b"nested bytes")

    for filename in (
        "linked/producer.pub",
        "../outside/producer.pub",
        str(outside / "producer.pub"),
        "keys/../../outside/producer.pub",
        "",
        "keys/./producer.pub",
    ):
        spec = ProducerKeySpec(filename, "0" * 64)
        with pytest.raises(SignError) as caught:
            read_producer_public_key(anchors, spec)
        assert str(caught.value) == (
            f"missing or non-regular producer public key: {anchors / filename}"
        ), filename

    assert (
        read_producer_public_key(anchors, ProducerKeySpec("keys/producer.pub", "0" * 64))
        == b"nested bytes"
    )


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads files mode 000")
def test_an_unreadable_producer_public_key_is_a_sign_error(
    tmp_path: pathlib.Path,
) -> None:
    anchors = tmp_path / "anchors"
    anchors.mkdir()
    key = anchors / "unreadable.pub"
    key.write_bytes(b"key")
    key.chmod(0)
    try:
        with pytest.raises(
            SignError, match="^cannot read producer public key: "
        ):
            read_producer_public_key(anchors, ProducerKeySpec("unreadable.pub", "0" * 64))
    finally:
        key.chmod(0o600)


def test_the_retired_key_claim_names_the_default_that_makes_it_conditional() -> None:
    """0.6.2 review, L7 finding 12: "retired keys verify immutable history
    only" was unconditional, but ``verify_any_generation`` tries retired keys
    unless the caller says ``allow_legacy=False`` (the default is intended
    and pinned elsewhere). The README and the module now say the condition."""

    readme = (pathlib.Path(__file__).resolve().parents[1] / "README.md").read_text(
        encoding="utf-8"
    )
    line = next(item for item in readme.splitlines() if item.startswith("- `receipt.sign`"))
    assert "retired keys verify immutable history only" not in line
    assert "`verify_any_generation` takes as its default" in line
    module_doc = " ".join((sign_module.__doc__ or "").split())
    assert "Legacy keys can vouch only where the caller explicitly" not in module_doc
    assert "a caller who says nothing gets legacy verification" in module_doc
