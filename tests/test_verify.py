from __future__ import annotations

import builtins
import hashlib
import pathlib
import types
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from typing import Any

import pytest

import receipt.verify as verify_module
from receipt.corpus import CorpusVerification
from receipt.release_chain import ChainVerification, ReleaseChainError, ReleaseRecord
from receipt.snapshot import ObjectStoreReport, SnapshotError
from receipt.verify import (
    LoadedSpec,
    VerifySpecError,
    load_spec,
    result_to_dict,
    run_verification,
)


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


def _spec_file(
    tmp_path: pathlib.Path, source: bytes = SPEC_SOURCE
) -> pathlib.Path:
    path = tmp_path / "spec.py"
    path.write_bytes(source)
    return path


def _source_with_anchor_pin(digest: str) -> bytes:
    return SPEC_SOURCE.replace(
        b"    corpus=CorpusSpec(",
        f'    anchor_set_sha256="{digest}",\n    corpus=CorpusSpec('.encode(),
        1,
    )


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
    assert not hasattr(verify_module, "_loaded_spec")


@pytest.mark.parametrize("expectation", [object(), "A" * 64, "0" * 63, "g" * 64])
def test_load_spec_refuses_a_non_digest_expectation_without_comparing_it(
    tmp_path: pathlib.Path, expectation: object
) -> None:
    with pytest.raises(
        VerifySpecError,
        match="expected spec SHA-256 must be a lowercase 64-character hex digest",
    ):
        load_spec(_spec_file(tmp_path), expect_sha256=expectation)  # type: ignore[arg-type]


def test_load_spec_cannot_be_pinned_by_a_forged_equality_object(
    tmp_path: pathlib.Path,
) -> None:
    class EqualToEverything:
        def __eq__(self, other: object) -> bool:
            del other
            return True

    with pytest.raises(
        VerifySpecError,
        match="expected spec SHA-256 must be a lowercase 64-character hex digest",
    ):
        load_spec(
            _spec_file(tmp_path),
            expect_sha256=EqualToEverything(),  # type: ignore[arg-type]
        )


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


JOURNAL_BYTES = b'{"one":"row"}\n'
PREFIX_BYTES = b'{"prefix":true}\n'
CANDIDATE_COMMIT = "c" * 40
CANDIDATE_TREE = "d" * 40
BASE_COMMIT = "b" * 40
BASE_TREE = "e" * 40
ANCHOR_DIGEST = "f" * 64


def _install_verification_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    *,
    materialized_anchor: str = ANCHOR_DIGEST,
    verified_anchor: str | None = None,
    object_failure: str | None = None,
) -> dict[str, Any]:
    """Install a recording snapshot around the spanning composition.

    These are intentionally protocol fakes rather than forged TreeSnapshots:
    this file tests which immutable-reader operations ``run_verification``
    composes and in what order. The reader's object authentication is tested
    at its own public boundary.
    """

    calls: dict[str, Any] = {
        "select": [],
        "blobs": [],
        "release": [],
        "binding": [],
        "history": [],
        "objects": [],
        "attributes": [],
        "anchor_specs": [],
    }

    class FakeMaterialization:
        def __init__(self, path: pathlib.Path) -> None:
            self.path = path
            self.entries = {
                "releases/manifest": types.SimpleNamespace(
                    mode="100644", path="releases/manifest"
                )
            }

        def __enter__(self) -> FakeMaterialization:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def anchor_set_sha256(self, chain_spec: object) -> str:
            calls["anchor_specs"].append(chain_spec)
            return materialized_anchor

    class FakeSnapshot:
        def __init__(self, revision: str) -> None:
            if revision == "base-ref":
                self.commit = BASE_COMMIT
                self.tree = BASE_TREE
            else:
                self.commit = CANDIDATE_COMMIT
                self.tree = CANDIDATE_TREE
            self.object_format = "sha1"

        @classmethod
        def select(
            cls,
            root: pathlib.Path,
            revision: str = "HEAD",
            **kwargs: object,
        ) -> FakeSnapshot:
            calls["select"].append((root, revision, kwargs))
            if revision != "base-ref":
                expected_commit = kwargs.get("expect_commit")
                expected_tree = kwargs.get("expect_tree")
                if expected_commit not in {None, CANDIDATE_COMMIT}:
                    raise SnapshotError(
                        f"commit {CANDIDATE_COMMIT} is not the expected commit "
                        f"{expected_commit}"
                    )
                if expected_tree not in {None, CANDIDATE_TREE}:
                    raise SnapshotError(
                        f"tree {CANDIDATE_TREE} is not the expected tree "
                        f"{expected_tree}"
                    )
            return cls(revision)

        def __enter__(self) -> FakeSnapshot:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def assert_ancestor(self, base: FakeSnapshot) -> str:
            calls["ancestor"] = (self, base)
            return base.commit

        def verify_object_store(
            self, heads: tuple[str, ...]
        ) -> ObjectStoreReport:
            calls["objects"].append(heads)
            if object_failure is not None:
                raise SnapshotError(object_failure)
            return ObjectStoreReport(objects=17, store_kib=23, seconds=0.25)

        def entry(self, path: str) -> types.SimpleNamespace:
            return types.SimpleNamespace(mode="100644", path=path)

        def blob(
            self, entry: types.SimpleNamespace, *, limit: int
        ) -> bytes:
            calls["blobs"].append((entry.path, limit))
            if entry.path == "receipt/journal.jsonl":
                return JOURNAL_BYTES
            assert entry.path == "receipt/prefix.json"
            return PREFIX_BYTES

        def materialize(
            self,
            prefixes: tuple[pathlib.PurePosixPath, ...],
            destination: pathlib.Path,
            *,
            repertoire: str,
        ) -> FakeMaterialization:
            calls["materialize"] = (prefixes, destination, repertoire)
            return FakeMaterialization(destination)

        def refuse_transforming_attributes(self, entries: object) -> None:
            calls["attributes"].append(tuple(entries))

    def fake_history(chain_spec: object, **kwargs: object) -> object:
        calls["history"].append((chain_spec, kwargs))
        return BASE_COMMIT, set(), {}

    def fake_release(path: pathlib.Path, **kwargs: object) -> ChainVerification:
        calls["release"].append((path, kwargs))
        record = ReleaseRecord(
            path=pathlib.Path("0000-0123456789abcdef.json"),
            raw=b"{}",
            sha256="1" * 64,
            manifest={
                "releaseIndex": 0,
                "state": {"jsonlSha256": hashlib.sha256(JOURNAL_BYTES).hexdigest()},
            },
            receipt_paths={},
            receipt_times={"alpha": datetime(2026, 1, 1, tzinfo=timezone.utc)},
            producer_signature_path=pathlib.Path("producer.sig"),
        )
        return ChainVerification(
            (record,),
            anchor_set_sha256=(
                materialized_anchor if verified_anchor is None else verified_anchor
            ),
            anchor_file_sha256s=(("alpha-root.pem", "2" * 64),),
        )

    def fake_binding(
        snapshot: object, journal: bytes, *, spec: object
    ) -> CorpusVerification:
        calls["binding"].append((snapshot, journal, spec))
        return CorpusVerification((), (), (), (), "portable")

    monkeypatch.setattr(verify_module, "TreeSnapshot", FakeSnapshot)
    monkeypatch.setattr(
        verify_module, "verify_release_history_immutable", fake_history
    )
    monkeypatch.setattr(verify_module, "verify_release_chain", fake_release)
    monkeypatch.setattr(verify_module, "verify_corpus_binding", fake_binding)
    monkeypatch.setattr(
        verify_module, "verify_declarations", lambda verification, *, spec: ()
    )
    monkeypatch.setattr(
        verify_module, "assert_no_redirecting_git_environment", lambda: None
    )
    return calls


def test_run_verification_composes_one_normalized_tree_subject(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _install_verification_pipeline(monkeypatch)
    spec_path = _spec_file(tmp_path)
    loaded = load_spec(
        spec_path, expect_sha256=hashlib.sha256(SPEC_SOURCE).hexdigest()
    )

    result = run_verification(
        tmp_path,
        loaded,
        base_ref="base-ref",
        commit="candidate-ref",
        expect_commit=CANDIDATE_COMMIT,
        expect_tree=CANDIDATE_TREE,
        expect_anchor_set=ANCHOR_DIGEST,
        verify_objects=True,
    )

    assert result.ok
    assert result.commit == CANDIDATE_COMMIT
    assert result.tree == CANDIDATE_TREE
    assert result.object_format == "sha1"
    assert result.base_commit == BASE_COMMIT
    assert result.base_tree == BASE_TREE
    assert result.name_repertoire == "portable"
    assert result.object_store == ObjectStoreReport(17, 23, 0.25)
    assert result._spec_pinned is True
    assert result._object_store_requested is True
    assert result._anchor_set_pinned is True
    assert [item.name for item in result.passes] == [
        "history",
        "custody",
        "binding",
        "declaration",
    ]

    candidate_select, base_select = calls["select"]
    assert candidate_select == (
        tmp_path.resolve(),
        "candidate-ref",
        {
            "verify_objects": True,
            "expect_commit": CANDIDATE_COMMIT,
            "expect_tree": CANDIDATE_TREE,
        },
    )
    assert base_select == (tmp_path.resolve(), "base-ref", {})
    assert calls["objects"] == [(CANDIDATE_COMMIT, BASE_COMMIT)]
    normalized = calls["anchor_specs"][0]
    assert calls["history"][0][0] is normalized
    assert calls["release"][0][1]["spec"] is normalized
    assert calls["release"][0][1]["state_bytes"] == {
        "receipt/journal.jsonl": JOURNAL_BYTES,
        "receipt/prefix.json": PREFIX_BYTES,
    }
    assert calls["binding"][0][1] is JOURNAL_BYTES
    assert calls["binding"][0][0].commit == CANDIDATE_COMMIT

    payload = result_to_dict(result)
    assert payload["commit"] == CANDIDATE_COMMIT
    assert payload["tree"] == CANDIDATE_TREE
    assert payload["objectFormat"] == "sha1"
    assert payload["base"] == {"commit": BASE_COMMIT, "tree": BASE_TREE}
    assert payload["nameRepertoire"] == "portable"
    assert payload["objectStore"] == {
        "objects": 17,
        "storeKiB": 23,
        "seconds": 0.25,
    }
    assert payload["scope"]["established"][1] == "custody of the release chain"
    assert (
        f"binding of the witnessed journal to tree {CANDIDATE_TREE[:12]}"
        in payload["scope"]["established"]
    )
    assert (
        "that the files in any checkout equal the verified tree"
        in payload["scope"]["notEstablished"]
    )
    assert (
        "that the anchor set is one the auditor trusts"
        not in payload["scope"]["notEstablished"]
    )


def test_unpinned_anchor_narrows_custody_claim(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_verification_pipeline(monkeypatch)
    result = run_verification(tmp_path, load_spec(_spec_file(tmp_path)))

    assert result.ok
    assert result._spec_pinned is False
    assert result._anchor_set_pinned is False
    payload = result_to_dict(result)
    assert (
        f"custody under the anchor set {ANCHOR_DIGEST} the verified tree carries"
        in payload["scope"]["established"]
    )
    assert (
        "that the anchor set is one the auditor trusts"
        in payload["scope"]["notEstablished"]
    )


def test_anchor_mismatch_refuses_before_release_crypto(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    carried = "7" * 64
    calls = _install_verification_pipeline(
        monkeypatch, materialized_anchor=carried
    )
    loaded = load_spec(
        _spec_file(tmp_path),
        expect_sha256=hashlib.sha256(SPEC_SOURCE).hexdigest(),
    )

    result = run_verification(
        tmp_path,
        loaded,
        expect_anchor_set=ANCHOR_DIGEST,
    )

    assert not result.ok
    assert calls["release"] == []
    assert result.passes[0].name == "custody"
    assert result.passes[0].failure == (
        f"anchor set {carried} is not the pinned anchor set {ANCHOR_DIGEST}"
    )


def test_post_crypto_anchor_digest_must_equal_the_materialized_digest(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verified = "8" * 64
    calls = _install_verification_pipeline(
        monkeypatch,
        verified_anchor=verified,
    )

    result = run_verification(tmp_path, load_spec(_spec_file(tmp_path)))

    assert not result.ok
    assert len(calls["release"]) == 1
    assert result.passes[0].failure == (
        f"verified anchor set {verified} is not the materialized anchor set "
        f"{ANCHOR_DIGEST}"
    )


def test_candidate_expectations_refuse_commit_before_tree(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_verification_pipeline(monkeypatch)
    loaded = load_spec(_spec_file(tmp_path))
    wrong_commit = "1" * 40
    wrong_tree = "2" * 40

    commit_result = run_verification(
        tmp_path,
        loaded,
        expect_commit=wrong_commit,
        expect_tree=wrong_tree,
    )
    assert commit_result.passes[0].failure == (
        f"commit {CANDIDATE_COMMIT} is not the expected commit {wrong_commit}"
    )

    tree_result = run_verification(
        tmp_path,
        loaded,
        expect_commit=CANDIDATE_COMMIT,
        expect_tree=wrong_tree,
    )
    assert tree_result.passes[0].failure == (
        f"tree {CANDIDATE_TREE} is not the expected tree {wrong_tree}"
    )


def test_object_store_refusal_keeps_the_requested_failure_shape(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    message = "object database failed git's own verification: corrupt object"
    calls = _install_verification_pipeline(
        monkeypatch,
        object_failure=message,
    )

    result = run_verification(
        tmp_path,
        load_spec(_spec_file(tmp_path)),
        verify_objects=True,
    )

    assert not result.ok
    assert calls["objects"] == [(CANDIDATE_COMMIT,)]
    assert result.object_store is None
    assert result._object_store_requested is True
    assert result.passes[0].failure == message
    assert result_to_dict(result)["objectStore"] == {
        "requested": True,
        "report": None,
    }


def test_unpinned_spec_anchor_field_is_a_producer_proposal(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declared = "6" * 64
    carried = "7" * 64
    _install_verification_pipeline(monkeypatch, materialized_anchor=carried)
    source = _source_with_anchor_pin(declared)

    result = run_verification(
        tmp_path,
        load_spec(_spec_file(tmp_path, source)),
    )

    assert result.ok
    assert result.anchor_set_sha256 == carried
    assert result._anchor_set_pinned is False


def test_pinned_spec_anchor_field_is_enforced_before_release_crypto(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declared = "6" * 64
    carried = "7" * 64
    calls = _install_verification_pipeline(
        monkeypatch, materialized_anchor=carried
    )
    source = _source_with_anchor_pin(declared)
    loaded = load_spec(
        _spec_file(tmp_path, source),
        expect_sha256=hashlib.sha256(source).hexdigest(),
    )

    result = run_verification(tmp_path, loaded)

    assert not result.ok
    assert calls["release"] == []
    assert result.passes[0].failure == (
        f"anchor set {carried} is not the pinned anchor set {declared}"
    )


def test_two_anchor_pins_disagree_in_a_fail_verdict_before_snapshot_selection(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declared = "6" * 64
    expected = "7" * 64
    source = _source_with_anchor_pin(declared)
    loaded = load_spec(
        _spec_file(tmp_path, source),
        expect_sha256=hashlib.sha256(source).hexdigest(),
    )
    monkeypatch.setattr(
        verify_module.TreeSnapshot,
        "select",
        lambda *args, **kwargs: pytest.fail("snapshot selection followed pin conflict"),
    )

    result = run_verification(
        tmp_path,
        loaded,
        expect_anchor_set=expected,
    )

    assert not result.ok
    assert result.passes[0].failure == (
        f"anchor pins disagree: command expects {expected}, spec expects {declared}"
    )


def test_run_verification_requirement_rules_are_entry_refusals(
    tmp_path: pathlib.Path,
) -> None:
    unpinned = load_spec(_spec_file(tmp_path))

    with pytest.raises(ValueError) as base_caught:
        run_verification(tmp_path, unpinned, base_ref="base-ref")
    assert str(base_caught.value) == "base_ref requires expect_commit"

    with pytest.raises(ValueError) as anchor_caught:
        run_verification(
            tmp_path,
            unpinned,
            expect_anchor_set=ANCHOR_DIGEST,
        )
    assert str(anchor_caught.value) == "an anchor pin requires a pinned spec"

    mismatched_source = SPEC_SOURCE.replace(
        b'        producer_public_key_filename="producer.pub",',
        b'        name_repertoire="posix-bytes",\n'
        b'        producer_public_key_filename="producer.pub",',
    )
    mismatched = load_spec(_spec_file(tmp_path, mismatched_source))
    with pytest.raises(ValueError) as repertoire_caught:
        run_verification(tmp_path, mismatched)
    assert str(repertoire_caught.value) == "spec declares two name repertoires"


@pytest.mark.parametrize(
    "invalid",
    ["", "0" * 63, "A" * 64, 0],
    ids=["empty", "short", "uppercase", "non-string"],
)
def test_direct_anchor_pin_must_be_an_exact_lowercase_sha256(
    tmp_path: pathlib.Path,
    invalid: object,
) -> None:
    source = SPEC_SOURCE
    loaded = load_spec(
        _spec_file(tmp_path, source),
        expect_sha256=hashlib.sha256(source).hexdigest(),
    )

    with pytest.raises(ValueError) as caught:
        run_verification(
            tmp_path,
            loaded,
            expect_anchor_set=invalid,  # type: ignore[arg-type]
        )
    assert str(caught.value) == (
        "expected anchor-set SHA-256 must be a lowercase 64-character hex digest"
    )


def test_redirecting_environment_keeps_custody_failure_shape(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loaded = load_spec(_spec_file(tmp_path))

    def redirected() -> None:
        raise ReleaseChainError(
            "GIT_DIR is set in the environment and would redirect git reads; unset it"
        )

    monkeypatch.setattr(
        verify_module, "assert_no_redirecting_git_environment", redirected
    )
    monkeypatch.setattr(
        verify_module.TreeSnapshot,
        "select",
        lambda *args, **kwargs: pytest.fail("snapshot selection followed refusal"),
    )

    result = run_verification(tmp_path, loaded)

    assert result.commit is None
    assert result.tree is None
    assert [(item.name, item.ok, item.failure) for item in result.passes] == [
        (
            "custody",
            False,
            "GIT_DIR is set in the environment and would redirect git reads; unset it",
        ),
        ("binding", False, "not reached"),
    ]

    declared = "6" * 64
    source = _source_with_anchor_pin(declared)
    pinned = load_spec(
        _spec_file(tmp_path, source),
        expect_sha256=hashlib.sha256(source).hexdigest(),
    )
    conflict = run_verification(
        tmp_path,
        pinned,
        expect_anchor_set="7" * 64,
    )
    assert conflict.passes[0].failure == result.passes[0].failure
