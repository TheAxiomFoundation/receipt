"""The composed command's binding seam.

Composition shares its candidate policy with corpus's private implementation only
while the name bound in ``receipt.verify`` is still corpus's original definition.
A public ``verify_corpus_binding`` patched at any time keeps governing the binding
pass: before ``receipt.verify`` is imported, after it, or through both module
attributes at once (M1 PR5, round 1, medium: the earlier identity check compared
two mutable references and let an import-time patch be bypassed, turning FAIL
into PASS).
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import textwrap
from dataclasses import asdict

from receipt import corpus, verify
from m1_fixture import signed_repo  # noqa: F401  (pytest fixture)

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATCHED_TEXT = "audit patched binding refusal"


def _rejecting(calls):
    def binding(*args, **kwargs):
        calls.append(1)
        raise corpus.CorpusError(PATCHED_TEXT)
    return binding


def _phases(result):
    return [(item.name, item.ok, item.failure) for item in result.passes]


def test_public_patch_installed_before_verify_import_governs(signed_repo):
    code = textwrap.dedent(
        """
        import io, json, sys
        from contextlib import redirect_stdout, redirect_stderr
        from receipt import corpus
        assert "receipt.verify" not in sys.modules
        calls = []
        def binding(*args, **kwargs):
            calls.append(1)
            raise corpus.CorpusError(%r)
        corpus.verify_corpus_binding = binding
        from receipt import verify, cli
        assert verify.verify_corpus_binding is corpus.verify_corpus_binding is binding
        assert corpus._VERIFY_CORPUS_BINDING_ORIGINAL is not binding
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = cli.main(["verify", "--spec", sys.argv[1], "--root", sys.argv[2],
                               "--commit", sys.argv[3], "--json"])
        payload = json.loads(out.getvalue())
        print(json.dumps({"calls": len(calls), "status": status, "verdict": payload["verdict"],
                          "passes": [[p["name"], p["ok"], p["failure"]] for p in payload["passes"]],
                          "stderr": err.getvalue()}))
        """ % PATCHED_TEXT
    )
    completed = subprocess.run(
        [sys.executable, "-c", code, str(signed_repo.root / "verification/spec.py"),
         str(signed_repo.root), signed_repo.base],
        cwd=ROOT, capture_output=True, text=True, timeout=300,
        env=os.environ | {"PYTHONPATH": str(ROOT / "src")},
    )
    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout.strip().splitlines()[-1])
    # record: risk 7 and step 4's late-patched hooks rule; the composed verdict is
    # fail-closed on the patched pass, exactly as at v0.6.1
    assert (observed["calls"], observed["status"], observed["verdict"]) == (1, 1, "FAIL")
    assert observed["passes"][0][:2] == ["custody", True]
    assert observed["passes"][1][:2] == ["binding", False]
    assert PATCHED_TEXT in observed["passes"][1][2]
    assert observed["passes"][2][:2] == ["declaration", False]
    assert observed["stderr"] == ""


def test_simultaneous_public_references_patched_govern(signed_repo, monkeypatch):
    calls = []
    binding = _rejecting(calls)
    monkeypatch.setattr(corpus, "verify_corpus_binding", binding)
    monkeypatch.setattr(verify, "verify_corpus_binding", binding)
    result = verify.run_verification(signed_repo.root, signed_repo.loaded, commit=signed_repo.base)
    assert calls == [1]
    assert not result.ok
    phases = _phases(result)
    assert phases[0][:2] == ("custody", True)
    assert phases[1][:2] == ("binding", False) and PATCHED_TEXT in phases[1][2]
    assert phases[2][:2] == ("declaration", False)


def test_verify_side_patch_governs(signed_repo, monkeypatch):
    calls = []
    monkeypatch.setattr(verify, "verify_corpus_binding", _rejecting(calls))
    result = verify.run_verification(signed_repo.root, signed_repo.loaded, commit=signed_repo.base)
    assert calls == [1] and not result.ok
    assert _phases(result)[1][:2] == ("binding", False)


def test_unpatched_shared_and_public_paths_agree(signed_repo, monkeypatch):
    shared = verify.run_verification(signed_repo.root, signed_repo.loaded, commit=signed_repo.base)
    # Forcing the public path by making the sentinel a different object: the
    # composed verdict, its phases and the pass detail must not move.
    monkeypatch.setattr(corpus, "_VERIFY_CORPUS_BINDING_ORIGINAL", object())
    public = verify.run_verification(signed_repo.root, signed_repo.loaded, commit=signed_repo.base)
    assert shared.ok and public.ok
    assert [asdict(item) for item in shared.passes] == [asdict(item) for item in public.passes]
