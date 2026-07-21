"""Tests for the standalone signing layers.

Layer 1 is differential-gated through the release-chain harness. Layers 2–3
are additive capability with no upstream CLI oracle, so they are covered by
unit, property, and round-trip tests only.
"""

from __future__ import annotations

import hashlib
import inspect
import pathlib
import shutil
import subprocess
from collections.abc import Callable

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import vidimus.sign as sign_module
from vidimus.sign import (
    ProducerKeySpec,
    SignError,
    generate_signing_keypair,
    read_producer_public_key,
    sign_payload,
    verify_signature_bytes,
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
    signature = sign_payload(private_key_pem, payload)

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
    signature = sign_payload(private_key_pem, payload)

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
    signature = sign_payload(private_key_pem, payload)

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
    signature = sign_payload(private_key_pem, b"payload")
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
        sign_payload(bytearray(private_key_pem), b"payload")  # type: ignore[arg-type]
    with pytest.raises(SignError, match="^signature payload must be bytes$"):
        sign_payload(private_key_pem, bytearray(b"payload"))  # type: ignore[arg-type]
    with pytest.raises(SignError, match="^signature domain must be bytes$"):
        sign_payload(private_key_pem, b"payload", domain=bytearray())  # type: ignore[arg-type]
    with pytest.raises(SignError, match="^cannot decode Ed25519 private key$"):
        sign_payload(b"not a private key", b"payload")

    ec_private_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(SignError, match="^private key is not Ed25519$"):
        sign_payload(ec_private_pem, b"payload")

    monkeypatch.setattr(sign_module, "CRYPTOGRAPHY_AVAILABLE", False)
    with pytest.raises(SignError, match="^Ed25519 signing requires cryptography$"):
        sign_payload(private_key_pem, b"payload")
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
    signature = sign_payload(private_key_pem, payload)
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


def test_sign_payload_cross_checks_with_openssl_cli(
    tmp_path: pathlib.Path,
) -> None:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is not installed")

    private_key_pem, public_key_pem = generate_signing_keypair()
    payload = b"independent OpenSSL cross-check\n"
    signature = sign_payload(private_key_pem, payload)
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
