"""Retained input-selection and bounded rendering boundaries in the census."""
import pathlib

import pytest

from receipt import corpus, release_chain
from receipt.verify import load_spec, run_verification
from m1_fixture import signed_repo, outcome, assert_golden


@pytest.mark.parametrize("shape", ("missing", "directory", "symlink"))
def test_spec_path_shape_golden(signed_repo, tmp_path, shape):
    path = tmp_path / "spec.py"
    if shape == "directory":
        path.mkdir()
    elif shape == "symlink":
        path.symlink_to(signed_repo.root / "verification/spec.py")
    # record: retained boundary verify.py 336-345 (user spec path, not Git tree policy)
    assert_golden("input/spec/" + shape, outcome(lambda: load_spec(path)), ((tmp_path, "<ROOT>"),))


@pytest.mark.parametrize("variable", release_chain.REDIRECTING_GIT_ENVIRONMENT)
def test_redirecting_environment_golden(signed_repo, tmp_path, monkeypatch, variable):
    for name in release_chain.REDIRECTING_GIT_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(variable, "unused-probe-location")
    direct = outcome(release_chain.assert_no_redirecting_git_environment)
    composed = signed_repo.cli(signed_repo.base, tmp_path)
    # record: retained boundary release_chain.py 2160-2182; verify.py 781-795 wrapper
    assert_golden("input/environment/" + variable, {"direct": direct, "cli": composed})


def test_long_corpus_diagnostic_retains_bounded_quoting():
    # record: census corpus.py 539-561 and 738-760; _quoted is not unrestricted repr
    value = "bad?" + "x" * 1200
    assert_golden("input/long_quote", outcome(lambda: corpus._assert_portable_name(value, "fixture")))
