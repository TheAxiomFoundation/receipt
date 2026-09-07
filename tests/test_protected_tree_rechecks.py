"""Local M1 release gates; external consumer checkouts remain maintainer gates."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from receipt import append_gate, corpus, release_chain, snapshot, verify
from m1_append_fixture import append_repo, GATE_SPEC
from m1_fixture import signed_repo


@pytest.mark.parametrize("operation", ("composed", "base", "binding", "directory", "append"))
@pytest.mark.parametrize("refused", (False, True))
def test_public_verifier_libraries_are_silent(request, tmp_path, capfd, operation, refused):
    repo = request.getfixturevalue("append_repo" if operation == "append" else "signed_repo")
    commit = repo.base
    directory = tmp_path / "direct-directory"
    if operation == "directory":
        shutil.copytree(repo.root, directory, ignore=shutil.ignore_patterns(".git"))
        assert not (directory / ".git").exists()
        if refused:
            state = directory / repo.chain.state_relative
            state.unlink()
            state.symlink_to("missing-state")
    elif refused:
        extras = (((GATE_SPEC.chain.state_relative.as_posix(), "120000"),)
                  if operation == "append" else
                  (("releases/link.txt", "120000"), ("rules/link.yaml", "120000")))
        commit = repo.commit(extras)

    def call():
        if operation == "composed":
            result = verify.run_verification(repo.root, repo.loaded, commit=commit)
            assert all(stage.ok for stage in result.passes) == (not refused)
        elif operation == "append":
            assert "OK" in append_gate.verify_append_gate(repo.root, spec=GATE_SPEC, commit=commit)
        elif operation == "directory":
            assert release_chain.verify_release_chain(
                directory, spec=repo.chain, require_chain=True, verify_state=True,
                enforce_production_pins=True).head is not None
        else:
            with repo.snapshot(commit) as subject:
                if operation == "base":
                    assert release_chain.verify_base_release_chain(repo.chain, base=subject).head is not None
                else:
                    assert corpus.verify_corpus_binding(subject, repo.journal, spec=repo.corpus).content

    capfd.readouterr()
    if refused and operation != "composed":
        with pytest.raises((append_gate.AppendError, corpus.CorpusError,
                            release_chain.ReleaseChainError, snapshot.SnapshotError)):
            call()
    else:
        call()
    captured = capfd.readouterr()
    assert (captured.out, captured.err) == ("", "")


@pytest.mark.parametrize("symbols", (
    ("KeyringSpec", "KeySpec", "raw_public_key_sha256", "verify_threshold", "SignError"),
    ("SignError", "sign_payload", "spki_sha256", "verify_signature_bytes", "generate_signing_keypair"),
), ids=("axiom-encode-import-surface", "thesis-import-surface"))
def test_sign_only_import_surface_does_not_load_tree_policy(symbols):
    # M1 consumer census: package-only isolation, not adoption tests against checkouts.
    root = Path(__file__).resolve().parents[1]
    code = (
        f"from receipt.sign import {', '.join(symbols)}\n"
        "import sys\n"
        f"assert all(callable(value) for value in [{', '.join(symbols)}])\n"
        "assert 'receipt.protected_tree' not in sys.modules\n"
    )
    result = subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True,
                            timeout=30, env=os.environ | {"PYTHONPATH": str(root / "src")})
    assert (result.returncode, result.stdout, result.stderr) == (0, b"", b"")
