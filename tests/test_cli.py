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
        "(freshness needs an out-of-band reference or --base-ref)",
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
