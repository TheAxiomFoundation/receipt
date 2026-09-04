from __future__ import annotations

import builtins
import hashlib
import pathlib
from dataclasses import FrozenInstanceError

import pytest

from receipt.verify import LoadedSpec, VerifySpecError, load_spec


SPEC_SOURCE = b'''\
import pathlib

from receipt.corpus import CorpusSpec
from receipt.release_chain import AnchorSpec, ChainSpec
from receipt.verify import VerificationSpec

SPEC = VerificationSpec(
    name="loaded-spec-test",
    chain=ChainSpec(
        manifest_relative=pathlib.PurePosixPath("releases/manifests"),
        state_relative=pathlib.PurePosixPath("receipt/journal.jsonl"),
        prefix_relative=pathlib.PurePosixPath("receipt/prefix.json"),
        anchor_relative=pathlib.PurePosixPath("releases/anchors"),
        release_root_relative=pathlib.PurePosixPath("releases"),
        schema_version="test-v1",
        producer_public_key_filename="producer.pub",
        producer_spki_sha256="a" * 64,
        anchors={
            "alpha": AnchorSpec(
                filename="alpha-root.pem",
                pem_sha256="b" * 64,
                policy_oid="1.3.6.1.4.1.99999.1.1",
                signer_certificate_sha256="c" * 64,
                signer_spki_sha256="d" * 64,
            ),
        },
    ),
    corpus=CorpusSpec(
        schema_version="test-v1",
        content_roots=(pathlib.PurePosixPath("rules"),),
        content_suffixes=(".yaml",),
        required_attested_paths=frozenset(),
        accepted_gate_tiers=frozenset({"public"}),
        required_gates=frozenset(),
    ),
)
'''


def _spec_file(tmp_path: pathlib.Path) -> pathlib.Path:
    path = tmp_path / "spec.py"
    path.write_bytes(SPEC_SOURCE)
    return path


def test_load_spec_returns_frozen_loader_owned_record(
    tmp_path: pathlib.Path,
) -> None:
    path = _spec_file(tmp_path)
    digest = hashlib.sha256(SPEC_SOURCE).hexdigest()

    loaded = load_spec(path, expect_sha256=digest)

    assert loaded.verification.name == "loaded-spec-test"
    assert loaded.path == path.resolve()
    assert loaded.sha256 == digest
    assert loaded.pinned is True
    with pytest.raises(FrozenInstanceError):
        loaded.pinned = False  # type: ignore[misc]
    with pytest.raises(TypeError, match="created by load_spec"):
        LoadedSpec()  # type: ignore[call-arg]


def test_load_spec_without_expectation_is_unpinned(tmp_path: pathlib.Path) -> None:
    loaded = load_spec(_spec_file(tmp_path))

    assert loaded.pinned is False


def test_load_spec_reads_source_bytes_once(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _spec_file(tmp_path)
    original = pathlib.Path.read_bytes
    reads = 0

    def counted(candidate: pathlib.Path) -> bytes:
        nonlocal reads
        if candidate == path.resolve():
            reads += 1
        return original(candidate)

    monkeypatch.setattr(pathlib.Path, "read_bytes", counted)

    loaded = load_spec(path)

    assert loaded.sha256 == hashlib.sha256(SPEC_SOURCE).hexdigest()
    assert reads == 1


def test_expected_digest_refuses_before_compile_or_exec(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "spec-executed"
    source = (
        "import pathlib\n"
        f"pathlib.Path({str(marker)!r}).write_text('ran')\n"
    ).encode()
    path = tmp_path / "hostile-spec.py"
    path.write_bytes(source)
    digest = hashlib.sha256(source).hexdigest()
    expected = "0" * 64
    assert digest != expected

    def compile_would_be_a_bug(*args: object, **kwargs: object) -> object:
        del args, kwargs
        pytest.fail("load_spec compiled source before refusing its digest")

    monkeypatch.setattr(builtins, "compile", compile_would_be_a_bug)

    with pytest.raises(VerifySpecError) as caught:
        load_spec(path, expect_sha256=expected)

    assert str(caught.value) == f"spec {digest} is not the expected spec {expected}"
    assert not marker.exists()
