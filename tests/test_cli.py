"""End-to-end battery for ``receipt verify`` over a real witnessed corpus.

The fixture builds an actual hash-linked manifest chain, an actual Ed25519
producer signature, and two actual RFC 3161 tokens from two locally generated
authorities — so ``enforce_production_pins`` is live in every test here, and the
anchor bytes, policy OIDs, signer certificates, and signer SPKIs are all pinned
and checked for real.

The battery has two halves. The refusals prove the command fails closed on each
way a published corpus can be wrong. The verdict-text assertions prove the
command does not overclaim when everything is right — which, for an artifact
whose whole purpose is to be handed to a skeptic, is the more important half.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil

import pytest

from receipt.cli import EXIT_FAIL, EXIT_OK, EXIT_USAGE, main
from receipt.sign import generate_signing_keypair, sign_payload
from receipt.verify import load_spec

from corpus_fixture import CONTENT, append_release, build_corpus


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """One expensive build (RSA keygen ×2, two TSAs); copied per test."""

    base = tmp_path_factory.mktemp("corpus-origin")
    root = base / "repo"
    root.mkdir()
    build_corpus(root, base / "tsa-workspace")
    return root


@pytest.fixture()
def repo(built: pathlib.Path, tmp_path: pathlib.Path) -> pathlib.Path:
    destination = tmp_path / "repo"
    shutil.copytree(built, destination, symlinks=True)
    return destination


def run(repo: pathlib.Path, *extra: str) -> int:
    return main(["verify", "--spec", str(repo / "verification/spec.py"),
                 "--root", str(repo), *extra])


def manifest_stem(repo: pathlib.Path) -> pathlib.Path:
    manifests = sorted((repo / "releases/manifests").glob("*.json"))
    assert len(manifests) == 1
    return manifests[0]


# --- the command accepts a corpus that is exactly what it claims to be -------


def test_verifies_a_published_corpus_from_a_clone(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo) == EXIT_OK
    out = capsys.readouterr().out
    assert "VERDICT: PASS" in out
    assert "custody" in out and "binding" in out


def test_the_verdict_states_what_it_did_not_establish(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A passing verdict a reader can over-read is a failure of the artifact."""

    assert run(repo) == EXIT_OK
    out = capsys.readouterr().out
    assert "NOT RE-RUN BY THIS COMMAND" in out
    assert "does NOT prove" in out
    assert "correct reading of the law" in out


def test_gate_tiers_are_reported_separately(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo) == EXIT_OK
    out = capsys.readouterr().out
    assert "public: you can re-run these yourself" in out
    assert "restricted: reproducible only with restricted pinned inputs" in out
    assert "ci-attested: not reproducible" in out
    assert "oracle/licensed-parity" in out


def test_json_output_marks_gates_as_not_re_run(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo, "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "PASS"
    assert payload["gateDeclarations"]["reRunByThisCommand"] is False
    assert set(payload["gateDeclarations"]["byTier"]) == {
        "public",
        "restricted",
        "ci-attested",
    }
    assert payload["scope"]["notEstablished"] == [
        "that any declared gate actually passed",
        "that the encoded rules are a correct reading of the law",
        "that this clone holds the producer's newest release "
        "(--base-ref only bounds staleness against a head the auditor "
        "recorded; newest needs an out-of-band comparison)",
        "that this is the only history the producer maintains "
        "(equivocation is undetectable from a single clone; compare "
        "head digests out of band)",
    ]
    assert payload["scope"]["established"] == [
        "custody of the release chain",
        "binding of the witnessed journal to this working tree",
    ]
    assert payload["chain"]["releases"] == 1
    assert len(payload["chain"]["witnesses"]) == 2
    assert payload["binding"]["contentFiles"] == 3


def anchor_set_recomputed(repo: pathlib.Path) -> tuple[str, dict[str, str]]:
    """The recomputation an auditor would script, sharing no package code:
    hash the spec-configured anchor files, then SHA-256 the compact
    sorted-key JSON of the mapping (receipt-canonical JSON for these
    ASCII filenames)."""

    spec, _ = load_spec(repo / "verification/spec.py")
    names = {
        spec.chain.producer_public_key_filename,
        *(anchor.filename for anchor in spec.chain.anchors.values()),
    }
    per_file = {
        name: hashlib.sha256(
            (repo / "releases/anchors" / name).read_bytes()
        ).hexdigest()
        for name in names
    }
    combined = hashlib.sha256(
        json.dumps(per_file, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return combined, per_file


def test_the_json_verdict_names_the_anchor_set_in_force(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """receipt#24: an auditor confirms from the verdict alone which anchor
    bytes custody consumed. TSA anchors are byte-pinned; producer identity
    is SPKI-pinned, so its entry records the serialization that verified."""

    assert run(repo, "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    combined, per_file = anchor_set_recomputed(repo)
    assert payload["chain"]["anchorSetSha256"] == combined
    assert payload["chain"]["anchorFiles"] == per_file


def test_the_text_verdict_carries_the_full_anchor_set_digest(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The digest exists to be quoted from the verdict alone, and it is
    pinned nowhere else — a prefix would not be quotable evidence."""

    combined, _ = anchor_set_recomputed(repo)
    assert run(repo) == EXIT_OK
    out = capsys.readouterr().out
    assert f"anchor set {combined}" in out


def test_a_gate_that_did_not_run_is_shouted_not_hidden(
    built: pathlib.Path, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The failure mode this schema exists to stop: a disabled gate that reads
    like a passing one."""

    root = tmp_path / "repo"
    build_corpus(
        root,
        tmp_path / "tsa",
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "pass",
                "evidence": {"command": "make validate"},
            },
            {
                "gateId": "guard/manual-rulespec-changes",
                "tier": "ci-attested",
                "outcome": "not-run",
                "evidence": {"reason": "run-generated-guard: false in the caller"},
            },
        ],
    )
    assert main(["verify", "--spec", str(root / "verification/spec.py"),
                 "--root", str(root)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "1 of 2 declared gate(s) did not pass cleanly" in out
    assert "DID NOT RUN — run-generated-guard: false in the caller" in out


def test_json_output_carries_the_spec_digest(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An auditor must be able to quote the exact configuration they ran under."""

    assert run(repo, "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    import hashlib

    expected = hashlib.sha256((repo / "verification/spec.py").read_bytes()).hexdigest()
    assert payload["spec"]["sha256"] == expected


# --- a chain that has actually been appended to ------------------------------


@pytest.fixture(scope="module")
def two_releases(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """Genesis plus one real append: manifest linking, strictly increasing line
    counts, byte-exact append digests, and a sealed prefix that did NOT move."""

    base = tmp_path_factory.mktemp("corpus-appended")
    root = base / "repo"
    root.mkdir()
    workspace = base / "tsa-workspace"
    build_corpus(root, workspace)
    corrected = dict(CONTENT)
    corrected["rules/tax/rate.yaml"] = "name: rate\nvalue: 0.175\n"
    corrected["rules/benefit/supplement.yaml"] = "name: supplement\nvalue: 40\n"
    append_release(root, workspace, content=corrected)
    return root


def test_verifies_a_chain_with_a_second_release(
    two_releases: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(two_releases) == EXIT_OK
    out = capsys.readouterr().out
    assert "2 release(s)" in out
    assert "VERDICT: PASS" in out


def test_a_corrected_encoding_binds_to_its_new_bytes(
    two_releases: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Supersession is real: the tree holds the corrected value and verifies,
    while the superseded row stays in the witnessed history."""

    assert run(two_releases, "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["binding"]["contentFiles"] == 4

    rows = [
        json.loads(line)
        for line in (two_releases / "receipt/corpus-journal.jsonl").read_text().splitlines()
    ]
    rate_rows = [r for r in rows if r.get("path") == "rules/tax/rate.yaml"]
    assert len(rate_rows) == 2, "the superseded row must survive in the history"
    assert rate_rows[0]["sha256"] != rate_rows[1]["sha256"]

    import hashlib

    on_disk = hashlib.sha256(
        (two_releases / "rules/tax/rate.yaml").read_bytes()
    ).hexdigest()
    assert on_disk == rate_rows[1]["sha256"], "the tree must hold the corrected bytes"


def test_refuses_a_rewritten_prefix_seal(two_releases: pathlib.Path, tmp_path: pathlib.Path) -> None:
    """The genesis seal is immutable; moving it invalidates every manifest."""

    repo = tmp_path / "repo"
    shutil.copytree(two_releases, repo, symlinks=True)
    prefix = repo / "receipt/immutable-prefix.json"
    prefix.write_bytes(prefix.read_bytes().replace(b'"prefixLineCount":7', b'"prefixLineCount":9'))
    assert main(["verify", "--spec", str(repo / "verification/spec.py"),
                 "--root", str(repo)]) == EXIT_FAIL


def test_refuses_a_removed_head_release(
    two_releases: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """Rolling the chain back to hide the latest state must not verify."""

    repo = tmp_path / "repo"
    shutil.copytree(two_releases, repo, symlinks=True)
    for path in (repo / "releases/manifests").glob("0001-*"):
        path.unlink()
    assert main(["verify", "--spec", str(repo / "verification/spec.py"),
                 "--root", str(repo)]) == EXIT_FAIL


# --- refusals: the corpus is not what it claims to be -----------------------


def test_refuses_an_edited_rule_file(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "rules/tax/rate.yaml").write_text("name: rate\nvalue: 0.99\n")
    assert run(repo) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "VERDICT: FAIL" in err
    assert "witnessed digest" in err


def test_refuses_a_rule_file_added_without_witnessing(repo: pathlib.Path) -> None:
    (repo / "rules/tax/extra.yaml").write_text("name: extra\n")
    assert run(repo) == EXIT_FAIL


def test_refuses_a_symlinked_directory_under_a_content_root(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """End-to-end regression for the demonstrated symlinked-directory false
    PASS: the full command must fail closed, not just the library."""

    outside = tmp_path / "smuggled"
    outside.mkdir()
    (outside / "evil.yaml").write_text("name: evil\n")
    (repo / "rules/injected").symlink_to(outside)
    assert run(repo) == EXIT_FAIL


def test_scope_established_on_failure_json(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A FAIL verdict must not carry an "established" list claiming the
    binding it never proved (cross-family review finding)."""

    (repo / "rules/tax/rate.yaml").write_text("tampered\n")
    assert run(repo, "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["scope"]["established"] == ["custody of the release chain"]
    assert any("newest release" in item for item in payload["scope"]["notEstablished"])


def test_pass_verdict_derives_the_witness_clause(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The witness sentence names the anchors that actually verified, rather
    than asserting a hardcoded count."""

    assert run(repo) == EXIT_OK
    out = capsys.readouterr().out
    assert "the 2 pinned RFC 3161 authorities (alpha, beta)" in out
    assert "newest release" in out  # staleness is named, not implied away


def test_refuses_an_edited_attested_file(repo: pathlib.Path) -> None:
    """The toolchain pin is bound too: swapping the corpus release must refuse."""

    (repo / ".axiom/toolchain.toml").write_text(
        '[toolchain]\ncorpus_release = "something-else"\n'
    )
    assert run(repo) == EXIT_FAIL


def test_refuses_an_edited_journal(repo: pathlib.Path) -> None:
    """Editing the journal to match a tampered tree breaks custody instead."""

    journal = repo / "receipt/corpus-journal.jsonl"
    journal.write_bytes(journal.read_bytes().replace(b"rules/tax", b"rules/tex"))
    assert run(repo) == EXIT_FAIL


def test_refuses_a_forged_manifest(repo: pathlib.Path) -> None:
    path = manifest_stem(repo)
    path.write_bytes(path.read_bytes().replace(b'"lineCount":7', b'"lineCount":8'))
    assert run(repo) == EXIT_FAIL


def test_refuses_a_corrupt_producer_signature(repo: pathlib.Path) -> None:
    signature = manifest_stem(repo).with_suffix(".producer.sig")
    if not signature.exists():
        signature = next((repo / "releases/manifests").glob("*.producer.sig"))
    payload = bytearray(signature.read_bytes())
    payload[0] ^= 0xFF
    signature.write_bytes(bytes(payload))
    assert run(repo) == EXIT_FAIL


def test_refuses_a_missing_witness(repo: pathlib.Path) -> None:
    """Dual witnesses means dual: one authority alone is not a verdict."""

    next((repo / "releases/manifests").glob("*.beta.tsr")).unlink()
    assert run(repo) == EXIT_FAIL


def test_refuses_a_swapped_trust_anchor(
    repo: pathlib.Path, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The anchor is pinned by digest in committed code, so substituting a
    different root — even a valid one — refuses."""

    anchor = next((repo / "releases/anchors").glob("alpha-root.pem"))
    beta = next((repo / "releases/anchors").glob("beta-root.pem"))
    anchor.write_bytes(beta.read_bytes())
    assert run(repo) == EXIT_FAIL
    assert "not code-pinned" in capsys.readouterr().err


def test_refuses_substituted_key_behind_symlinked_anchor_parent(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A symlinked anchor parent must not turn production pinning off.

    The replacement directory contains a valid alternate producer key and the
    original TSA roots, so every cryptographic operation is internally valid.
    Only the consumer's out-of-band pins and path-confinement policy distinguish
    it from the committed trust configuration.
    """

    private_pem, public_pem = generate_signing_keypair()
    anchors = repo / "releases/anchors"
    (anchors / "producer-ed25519.pub").write_bytes(public_pem)
    manifest = manifest_stem(repo)
    manifest.with_suffix(".producer.sig").write_bytes(
        sign_payload(private_pem, manifest.read_bytes(), domain=b"")
    )
    substituted = repo / "releases/substituted-anchors"
    anchors.rename(substituted)
    anchors.symlink_to(substituted.name, target_is_directory=True)

    assert run(repo) == EXIT_FAIL
    assert "symlink or reparse point" in capsys.readouterr().err


def test_refuses_a_deleted_release_chain(repo: pathlib.Path) -> None:
    shutil.rmtree(repo / "releases/manifests")
    assert run(repo) == EXIT_FAIL


def test_refuses_a_journal_swapped_between_passes(repo: pathlib.Path) -> None:
    """Custody proves a digest; binding must prove the SAME bytes."""

    journal = repo / "receipt/corpus-journal.jsonl"
    journal.unlink()
    journal.symlink_to(repo / ".axiom/toolchain.toml")
    assert run(repo) == EXIT_FAIL


# --- refusals: the invocation itself is not usable ---------------------------


def test_refuses_a_missing_spec(tmp_path: pathlib.Path) -> None:
    assert main(["verify", "--spec", str(tmp_path / "nope.py")]) == EXIT_USAGE


def test_refuses_a_spec_module_without_SPEC(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "spec.py"
    path.write_text("VALUE = 1\n")
    assert main(["verify", "--spec", str(path), "--root", str(tmp_path)]) == EXIT_USAGE


def test_refuses_a_spec_that_is_not_a_verification_spec(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "spec.py"
    path.write_text("SPEC = {'chain': 'trust me'}\n")
    assert main(["verify", "--spec", str(path), "--root", str(tmp_path)]) == EXIT_USAGE


SPEC_TEMPLATE = '''
import pathlib
from receipt.corpus import CorpusSpec
from receipt.release_chain import AnchorSpec, ChainSpec
from receipt.verify import VerificationSpec

SPEC = VerificationSpec(
    name="{name}",
    chain=ChainSpec(
        manifest_relative=pathlib.PurePosixPath("releases/manifests"),
        state_relative=pathlib.PurePosixPath("receipt/journal.jsonl"),
        prefix_relative=pathlib.PurePosixPath("receipt/prefix.json"),
        anchor_relative=pathlib.PurePosixPath("releases/anchors"),
        release_root_relative=pathlib.PurePosixPath("releases"),
        schema_version="t",
        producer_public_key_filename="p.pub",
        producer_spki_sha256="{spki}",
        anchors={{}},
    ),
    corpus=CorpusSpec(
        schema_version="t",
        content_roots=(pathlib.PurePosixPath("rules"),),
        content_suffixes=(".yaml",),
        required_attested_paths=frozenset(),
        accepted_gate_tiers=frozenset({{"public"}}),
        required_gates=frozenset(),
    ),
)
'''

FROZEN_MTIME = 1_800_000_000


def test_the_spec_that_runs_is_always_the_spec_that_was_hashed(
    tmp_path: pathlib.Path,
) -> None:
    """Regression, found from a clean clone.

    `__pycache__` judges staleness on (source mtime, source size) at
    one-second granularity. Going through the import system therefore let a
    spec edited to weaken a pin, loaded once, then restored to a file of
    identical length within the same second, keep executing the weakened pins
    while the verdict printed the honest file's digest — a false PASS under a
    truthful-looking fingerprint. This test reproduces the exact conditions:
    same length, same mtime, different bytes.
    """

    import hashlib
    import os

    path = tmp_path / "spec.py"

    honest = SPEC_TEMPLATE.format(name="honest", spki="a" * 64)
    path.write_text(honest)
    os.utime(path, (FROZEN_MTIME, FROZEN_MTIME))
    first, first_digest = load_spec(path)
    assert first.chain.producer_spki_sha256 == "a" * 64
    assert first_digest == hashlib.sha256(honest.encode()).hexdigest()

    weakened = SPEC_TEMPLATE.format(name="weaken", spki="0" * 64)
    assert len(weakened) == len(honest)
    path.write_text(weakened)
    os.utime(path, (FROZEN_MTIME, FROZEN_MTIME))

    second, second_digest = load_spec(path)
    assert second.chain.producer_spki_sha256 == "0" * 64, (
        "the loader executed stale bytecode instead of the file on disk"
    )
    assert second_digest == hashlib.sha256(weakened.encode()).hexdigest()
    assert second_digest != first_digest


def test_loading_a_spec_leaves_no_bytecode_behind(tmp_path: pathlib.Path) -> None:
    """Nothing cacheable is written next to an audited repository's spec."""

    path = tmp_path / "spec.py"
    path.write_text(SPEC_TEMPLATE.format(name="clean", spki="b" * 64))
    load_spec(path)
    assert not (tmp_path / "__pycache__").exists()


def test_refuses_a_root_that_is_not_a_directory(repo: pathlib.Path) -> None:
    assert main(
        [
            "verify",
            "--spec",
            str(repo / "verification/spec.py"),
            "--root",
            str(repo / "rules/tax/rate.yaml"),
        ]
    ) == EXIT_USAGE


def test_failure_output_goes_to_stderr_not_stdout(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A pipeline that reads stdout must not see a failure as a clean verdict."""

    (repo / "rules/tax/rate.yaml").write_text("tampered\n")
    assert run(repo) == EXIT_FAIL
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "VERDICT: FAIL" in captured.err


@pytest.mark.parametrize(
    "target",
    [
        "verify_release_chain",
        "_custody_detail",
        "verify_corpus_binding",
        "_binding_detail",
        "verify_declarations",
        "_declaration_detail",
    ],
)
def test_unexpected_exception_in_any_pass_is_a_fail_verdict_not_an_escape(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    """The documented fail-closed contract: any exception a pass or its detail
    builder raises becomes a FAIL verdict object, never an escape that leaves a
    --json consumer with no verdict at all."""

    def boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("injected surprise")

    monkeypatch.setattr(f"receipt.verify.{target}", boom)

    assert run(repo, "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    # The surprising type is surfaced, not swallowed.
    failed = [p for p in payload["passes"] if not p["ok"]]
    assert failed
    assert any("RuntimeError: injected surprise" in p["failure"] for p in failed)


# --- second cross-family round: the coverage it found missing ----------------


def test_run_verification_passes_production_pins_explicitly(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The literal True is load-bearing. Drop the keyword and path inference
    decides instead — the exact discretion the spanning command exists to
    remove — while every test on the default anchor layout still passes.
    This spy is the removal detector."""

    import receipt.verify as verify_module

    seen: dict[str, object] = {}
    real = verify_module.verify_release_chain

    def spy(*args: object, **kwargs: object) -> object:
        seen.update(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr("receipt.verify.verify_release_chain", spy)
    assert run(repo) == EXIT_OK
    assert seen.get("enforce_production_pins") is True


def test_pin_inference_yields_only_to_an_explicit_choice(repo: pathlib.Path) -> None:
    """The None fallback is exactly a fallback. A chain re-signed under a
    substituted (internally valid) key refuses when enforcement is inferred on
    the default anchor path, and verifies when a caller explicitly opts out —
    so the boundary sits on "was a value supplied", nowhere else."""

    from receipt.release_chain import ReleaseChainError, verify_release_chain

    spec, _ = load_spec(repo / "verification/spec.py")
    private_pem, public_pem = generate_signing_keypair()
    (repo / "releases/anchors/producer-ed25519.pub").write_bytes(public_pem)
    manifest = manifest_stem(repo)
    manifest.with_suffix(".producer.sig").write_bytes(
        sign_payload(private_pem, manifest.read_bytes(), domain=b"")
    )

    with pytest.raises(ReleaseChainError):
        verify_release_chain(
            repo, spec=spec.chain, require_chain=True, verify_state=True
        )
    verify_release_chain(
        repo,
        spec=spec.chain,
        require_chain=True,
        verify_state=True,
        enforce_production_pins=False,
    )


def _git(repo: pathlib.Path, *args: str) -> None:
    import subprocess

    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t",
            "HOME": str(repo),
        },
    )


@pytest.fixture()
def committed_repo(repo: pathlib.Path) -> pathlib.Path:
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    return repo


def test_history_pass_exception_is_a_fail_verdict_not_an_escape(
    committed_repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The optional pass sits inside the same fail-closed boundary as the
    mandatory ones."""

    def boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("injected surprise")

    monkeypatch.setattr("receipt.verify.verify_release_history_immutable", boom)
    assert run(committed_repo, "--base-ref", "HEAD", "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    failed = [p for p in payload["passes"] if not p["ok"]]
    assert failed
    assert any("RuntimeError: injected surprise" in p["failure"] for p in failed)


def test_pass_text_with_base_ref_claims_only_the_snapshot_comparison(
    committed_repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """With a base ref the verdict claims byte- and mode-identity for objects
    present at that ref — never blanket immutability, which the comparison
    does not establish for objects added after the ref."""

    assert run(committed_repo, "--base-ref", "HEAD") == EXIT_OK
    out = capsys.readouterr().out
    assert "VERDICT: PASS" in out
    assert "present at the supplied base" in out
    assert "byte- and mode-identical in this tree" in out
    assert "no published release object changed" not in out
    # The base ref cannot stand in for freshness or uniqueness.
    assert "comparing head\n  digests out of band" in out
    assert "or via\n  --base-ref" not in out


def test_pass_text_without_base_ref_names_the_first_contact_limit(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo) == EXIT_OK
    out = capsys.readouterr().out
    assert "NOT prove the history was never rewritten" in out
    assert "regenerate and re-witness" in out
    assert "comparing head\n  digests out of band" in out


def test_base_ref_json_reports_the_history_pass(
    committed_repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(committed_repo, "--base-ref", "HEAD", "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "PASS"
    assert "history" in payload["passesCompleted"]
    claimed = " ".join(payload["scope"]["established"])
    assert "present at the given base ref" in claimed
    assert "outside this claim" in claimed


def test_base_ref_refusal_is_a_fail_verdict(
    committed_repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An edited release file refuses the history pass through the CLI."""

    stem = manifest_stem(committed_repo)
    stem.write_bytes(stem.read_bytes() + b"\n")
    assert run(committed_repo, "--base-ref", "HEAD", "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert "history" not in payload["passesCompleted"]


# --- the --json contract holds on every exit path ----------------------------


def test_json_verdict_on_a_missing_spec(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(["verify", "--spec", str(tmp_path / "absent.py"), "--json"])
        == EXIT_USAGE
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["stage"] == "spec"


def test_json_verdict_when_reading_the_spec_raises_unexpectedly(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_args: object, **_kwargs: object) -> object:
        raise OSError("disk said no")

    monkeypatch.setattr("receipt.cli.load_spec", boom)
    assert run(repo, "--json") == EXIT_USAGE
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["stage"] == "spec"
    assert "OSError" in payload["failure"]


def test_json_verdict_on_a_root_that_is_not_a_directory(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "verify",
                "--spec",
                str(repo / "verification/spec.py"),
                "--root",
                str(repo / "rules/tax/rate.yaml"),
                "--json",
            ]
        )
        == EXIT_USAGE
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["stage"] == "root"


def test_json_verdict_when_verification_itself_aborts(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("outer surprise")

    monkeypatch.setattr("receipt.cli.run_verification", boom)
    assert run(repo, "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["stage"] == "verification"
    assert "RuntimeError: outer surprise" in payload["failure"]


def test_json_verdict_when_the_result_cannot_be_rendered(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A PASS the command cannot serialize is not a deliverable PASS."""

    def boom(*_args: object, **_kwargs: object) -> object:
        raise TypeError("unserializable")

    monkeypatch.setattr("receipt.cli.result_to_dict", boom)
    assert run(repo, "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["stage"] == "render"
    assert "treat the run as unverified" in payload["failure"]


def test_text_render_failure_refuses_instead_of_escaping(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_args: object, **_kwargs: object) -> object:
        raise ValueError("no words")

    monkeypatch.setattr("receipt.cli._format_text", boom)
    assert run(repo) == EXIT_FAIL
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "treat the run as unverified" in captured.err


# --- third round: isolating each boundary the second round left shared -------


def test_base_ref_help_is_snapshot_scoped(capsys: pytest.CaptureFixture[str]) -> None:
    """The help text is part of the claim surface: bytes and modes, nothing
    broader."""

    with pytest.raises(SystemExit):
        main(["verify", "--help"])
    assert "byte- and mode-identical" in capsys.readouterr().out


def test_json_verdict_when_the_root_check_raises(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Root resolution has its own boundary; this is its removal detector."""

    def boom(*_args: object, **_kwargs: object) -> object:
        raise PermissionError("stat denied")

    monkeypatch.setattr("receipt.cli._default_root", boom)
    assert (
        main(["verify", "--spec", str(repo / "verification/spec.py"), "--json"])
        == EXIT_USAGE
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["stage"] == "root"
    assert "PermissionError" in payload["failure"]


def test_json_verdict_when_serialization_itself_fails(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """result_to_dict succeeds and json.dumps of the full payload fails; the
    fallback object must still reach stdout via the second dumps call. This
    isolates the dumps leg of the render boundary from the dict-construction
    leg the earlier test covers."""

    real = json.dumps
    state = {"calls": 0}

    def flaky(obj: object, **kwargs: object) -> str:
        state["calls"] += 1
        if state["calls"] == 1:
            raise TypeError("unserializable payload")
        return real(obj, **kwargs)

    monkeypatch.setattr("receipt.cli.json.dumps", flaky)
    assert run(repo, "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["stage"] == "render"
    assert "treat the run as unverified" in payload["failure"]


def test_history_pass_detail_is_snapshot_scoped(
    committed_repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """passes[].detail carries the claim independently of the PASS paragraph."""

    assert run(committed_repo, "--base-ref", "HEAD", "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    (history,) = [p for p in payload["passes"] if p["name"] == "history"]
    assert history["ok"] is True
    assert "byte- and mode-identical in this tree" in history["detail"]
    assert "HEAD" in history["detail"]


def test_base_ref_refuses_a_deleted_release_object(
    committed_repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Deletion is inside the snapshot claim: an object present at the base
    must still exist."""

    manifest_stem(committed_repo).unlink()
    assert run(committed_repo, "--base-ref", "HEAD", "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    (history,) = [p for p in payload["passes"] if p["name"] == "history"]
    assert history["ok"] is False
    assert "deleted" in history["failure"]


def test_post_base_additions_are_outside_the_history_claim(
    built: pathlib.Path,
    committed_repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A release appended after the base ref verifies — the pass compares
    objects present at the base and nothing newer, exactly as worded."""

    corrected = dict(CONTENT)
    corrected["rules/tax/rate.yaml"] = "name: rate\nvalue: 0.20\n"
    append_release(
        committed_repo, built.parent / "tsa-workspace", content=corrected
    )
    assert run(committed_repo, "--base-ref", "HEAD", "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert "history" in payload["passesCompleted"]
    assert payload["chain"]["releases"] == 2


def test_a_tree_name_cannot_forge_a_verdict_line(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Binds F4, end to end: the verdict is the product, so it must be intact.

    The text renderer prints the refusal a failing pass carried. Filesystem
    names reached those refusals unescaped, and nothing screens a filesystem
    name — so a file planted under a content root and named
    ``\\x1b[2K\\rVERDICT: PASS`` erased the line the command had just written
    and redrew it as a pass. The library refuses the symlink either way;
    what this asserts is that the bytes an auditor's terminal receives are
    not the producer's to choose. Without the fix the raw ESC is in the
    output.
    """

    forged = "\x1b[2K\rVERDICT: PASS"
    (repo / "rules/tax" / forged).symlink_to(repo / "rules/tax/rate.yaml")
    assert run(repo) == EXIT_FAIL
    captured = capsys.readouterr()
    assert "\x1b" not in captured.out and "\x1b" not in captured.err
    assert "\r" not in captured.out and "\r" not in captured.err
    # The failing verdict renders on stderr, where the forged line would have
    # landed; stdout must stay empty so a pipeline reading it sees nothing.
    assert captured.out == ""
    assert "VERDICT: FAIL" in captured.err
    assert "\\x1b[2K\\rVERDICT: PASS" in captured.err


# --- fourth round: the verdict boundary escapes what it renders --------------


FORGED_TERMINAL_NAME = "\x1b[A\r\x1b[2K  VERDICT: PASS"
ESCAPED_TERMINAL_NAME = "\\x1b[A\\r\\x1b[2K  VERDICT: PASS"


def test_a_release_manifest_name_cannot_forge_a_verdict_line(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Binds S4-F4: the custody half of the verdict rendered filenames raw.

    ``receipt.release_chain`` refuses an unknown file in the closed release
    manifest directory and names it, and that message reaches the text
    verdict as the custody pass's failure. Nothing screened it: the name is
    whatever the filesystem holds. One spelled ``ESC [ A`` (cursor up),
    ``CR``, ``ESC [ 2 K`` (erase line) and then ``VERDICT: PASS`` overwrites
    the line the command has just printed to say FAIL — the auditor reads a
    pass off a run that failed.

    The library's message is not the place to fix it: those strings are
    pinned byte for byte by a differential harness against the source
    verifier, and an unknown file in the manifest directory is exactly the
    kind of mutation that harness presents. So the escaping is at the
    renderer, and this asserts what the terminal receives: no raw code point
    from any class that can move a cursor, exactly one line beginning
    ``VERDICT``, and the forged name visible in its escaped spelling.

    Without the fix the raw ESC and CR are in the output and a second line
    reading ``VERDICT: PASS`` is painted over the first.
    """

    (repo / "releases/manifests" / FORGED_TERMINAL_NAME).write_text("{}\n")
    assert run(repo) == EXIT_FAIL
    captured = capsys.readouterr()
    assert captured.out == ""
    assert not _terminal_controls(captured.err)
    verdict_lines = [
        line for line in captured.err.splitlines() if line.startswith("VERDICT")
    ]
    assert verdict_lines == ["VERDICT: FAIL — custody"]
    assert ESCAPED_TERMINAL_NAME in captured.err


def test_a_content_path_in_a_corpus_refusal_is_escaped_exactly_once(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Binds S4-F4: the binding half was already escaped, and stays so once.

    ``receipt.corpus`` quotes every path it names through ``_quoted``, which
    is ``repr`` under the length bound, so a tree name arrives at the
    renderer already carrying ``\\x1b`` and ``\\r`` as text rather than as
    code points. ``_terminal_safe`` maps code points and nothing else, so it
    finds nothing left to escape and the name appears escaped once, not
    twice — which is what an auditor has to be able to read back as the name
    that is really on disk.

    Pinned deliberately rather than left to whichever the renderer happened
    to produce: a helper that escaped backslashes as well would turn every
    such refusal into an unreadable ladder, and one that escaped nothing
    would depend on the library's quoting for the CLI's own guarantee. This
    is the boundary between the two, stated.

    This test passes without the S4-F4 fix, and says so rather than
    pretending otherwise: ``_quoted`` was already covering this path, which
    is precisely why the finding is about the *other* one. It is here so
    that the renderer's escaping cannot be strengthened into double-escaping
    without something failing.
    """

    forged = FORGED_TERMINAL_NAME + ".yaml"
    (repo / "rules/tax" / forged).write_text("name: smuggled\n")
    assert run(repo) == EXIT_FAIL
    captured = capsys.readouterr()
    assert captured.out == ""
    assert not _terminal_controls(captured.err)
    verdict_lines = [
        line for line in captured.err.splitlines() if line.startswith("VERDICT")
    ]
    assert verdict_lines == ["VERDICT: FAIL — binding"]
    assert f"rules/tax/{ESCAPED_TERMINAL_NAME}.yaml" in captured.err
    # Escaped once: the library quoted it, the renderer found no code point
    # left to map, and neither doubled the other's backslashes.
    assert "\\\\x1b" not in captured.err


def _terminal_controls(text: str) -> list[int]:
    """Every code point in ``text`` that can move a cursor or split a line."""

    return sorted(
        {
            ord(character)
            for character in text
            if ord(character) < 0x20
            or ord(character) == 0x7F
            or 0x80 <= ord(character) <= 0x9F
            or ord(character) in (0x2028, 0x2029)
        }
        - {0x0A}  # the renderer's own line breaks
    )


def test_terminal_safe_escapes_every_class_and_nothing_else() -> None:
    """Binds S4-F4: the helper's coverage is the CLI's whole guarantee.

    Four classes, each of which can change what a terminal shows without
    printing a visible character: the C0 controls, DEL, the C1 controls
    (which an 8-bit-clean terminal decodes as two-character ESC sequences),
    and the Unicode line and paragraph separators, which split one verdict
    line into two in any renderer that honours them.

    Every one of them must leave as its Python escape and everything else
    must survive untouched — the verdict is meant to be read, and a helper
    that mangled ordinary text would cost legibility for nothing. Without
    the helper the CLI has no screen at all and every assertion below fails
    on the first class.
    """

    from receipt.cli import _terminal_safe

    covered = [*range(0x00, 0x20), 0x7F, *range(0x80, 0xA0), 0x2028, 0x2029]
    for code in covered:
        escaped = _terminal_safe(chr(code))
        assert escaped == repr(chr(code))[1:-1]
        assert not _terminal_controls(escaped)
        assert chr(code) not in escaped
    assert _terminal_safe("\x1b") == "\\x1b"
    assert _terminal_safe("\r") == "\\r"
    assert _terminal_safe("\n") == "\\n"
    assert _terminal_safe("\x7f") == "\\x7f"
    assert _terminal_safe("\x9b") == "\\x9b"
    assert _terminal_safe(chr(0x2028)) == "\\u2028"
    assert _terminal_safe(chr(0x2029)) == "\\u2029"
    # Untouched: printable ASCII, punctuation the escaping could have been
    # tempted to double, and text outside the BMP.
    for text in ("rules/tax/rate.yaml", "a\\b", "café", "中文", "\U0001F600", ""):
        assert _terminal_safe(text) == text
    assert _terminal_safe("a\x1bb\rc") == "a\\x1bb\\rc"


def test_the_json_renderer_escapes_the_same_classes_by_itself() -> None:
    """Binds S4-F4, the other renderer: ``--json`` needs no helper.

    The JSON verdict is written by ``json.dumps`` with ``ensure_ascii`` at
    its default, which spells every code point above as ``\\uXXXX`` inside
    the quoted string. So a machine consumer receives them as data and no
    terminal downstream of ``--json`` sees them raw. Pinned here because the
    CLI's module docstring makes that claim, and a claim about a mechanism
    is worth exactly as much as the test under it.

    Passes without the S4-F4 fix, necessarily — it is about ``json.dumps``
    and not about anything this round changed. Its job is to keep the
    docstring's reason for leaving the JSON renderer alone true.
    """

    covered = "".join(
        chr(code)
        for code in (*range(0x00, 0x20), 0x7F, *range(0x80, 0xA0), 0x2028, 0x2029)
    )
    rendered = json.dumps({"failure": covered}, indent=2, sort_keys=True)
    assert not _terminal_controls(rendered)
