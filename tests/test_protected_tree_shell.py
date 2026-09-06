"""PR1 exposes frozen contracts only; no production migration starts here."""
from __future__ import annotations

import ast
import dataclasses
import inspect
import os
import pathlib
import subprocess
import sys

import pytest

from receipt import protected_tree as policy
from m1_fixture import raw_repo


@pytest.mark.parametrize("name", ("ProtectionPlan", "TreePolicy", "ProtectedTreeView", "ProtectedSelection", "DirectoryEvidence"))
def test_policy_shell_dataclasses_are_frozen(name):
    cls = getattr(policy, name)
    # record: proposed module surface, all shell records are frozen contracts
    assert dataclasses.is_dataclass(cls)
    assert cls.__dataclass_params__.frozen
    assert cls.__doc__
    value = object.__new__(cls)
    with pytest.raises(dataclasses.FrozenInstanceError):
        value.unexpected = "mutation"


def test_tree_policy_constructor_surface():
    signature = inspect.signature(policy.TreePolicy)
    # record: proposed module TreePolicy(snapshot, *, policy_version, work)
    assert list(signature.parameters) == ["snapshot", "policy_version", "work"]
    assert signature.parameters["snapshot"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert signature.parameters["policy_version"].kind is inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["work"].kind is inspect.Parameter.KEYWORD_ONLY
    assert policy.TreePolicy.__annotations__["snapshot"] == "snapshot.TreeSnapshot"


@pytest.mark.parametrize("method", ("evaluate", "finding_for", "require"))
def test_policy_methods_are_unimplemented(raw_repo, method):
    with raw_repo.snapshot() as snap:
        evaluator = policy.TreePolicy(snap, policy_version="v0.6", work=snap.work)
        view = policy.ProtectedTreeView()
        calls = {"evaluate": lambda: evaluator.evaluate(policy.ProtectionPlan(), stage="custody", previous=view),
                 "finding_for": lambda: view.finding_for("custody"),
                 "require": lambda: view.require("custody", render=lambda finding: pytest.fail("renderer ran"))}
        # record: migration step 1: shell only, PR2 owns evaluation
        with pytest.raises(NotImplementedError) as caught:
            calls[method]()
        assert type(caught.value) is NotImplementedError
        assert str(caught.value) == "receipt 0.7 M1 PR2 introduces the evaluator"


def test_production_callers_do_not_import_shell():
    root = pathlib.Path(__file__).resolve().parents[1]
    completed = subprocess.run(["git", "grep", "-l", "protected_tree", "--", "src"], cwd=root,
                               capture_output=True, check=True, timeout=30)
    # record: migration step 1: no production caller switches. The literal
    # requested grep also matches the retained _screen_protected_tree_names
    # symbol; it cannot yield only the shell without breaking compatibility.
    assert completed.stdout.splitlines() == [
        b"src/receipt/append_gate.py", b"src/receipt/protected_tree.py",
        b"src/receipt/release_chain.py", b"src/receipt/verify.py",
    ]
    assert completed.stderr == b""
    exact = subprocess.run(["git", "grep", "-lw", "protected_tree", "--", "src"], cwd=root,
                           capture_output=True, check=True, timeout=30)
    assert exact.stdout.splitlines() == [b"src/receipt/protected_tree.py"]
    for source in (root / "src/receipt").glob("*.py"):
        if source.name == "protected_tree.py":
            continue
        for node in ast.walk(ast.parse(source.read_text())):
            if isinstance(node, ast.Import):
                assert all(alias.name != "receipt.protected_tree" for alias in node.names), source
            elif isinstance(node, ast.ImportFrom):
                assert node.module not in {"receipt.protected_tree", "protected_tree"}, source
                assert all(alias.name != "protected_tree" for alias in node.names), source


@pytest.mark.parametrize("first,second", (("receipt.snapshot", "receipt.protected_tree"),
                                         ("receipt.protected_tree", "receipt.snapshot")))
def test_shell_imports_in_either_order(first, second):
    root = pathlib.Path(__file__).resolve().parents[1]
    code = (f"import {first}\nimport {second}\n"
            "from receipt.protected_tree import TreePolicy\n"
            "from receipt.snapshot import TreeSnapshot\n")
    # record: proposed module import-cycle design; later facades must defer reverse imports
    result = subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True, timeout=30,
                            env=os.environ | {"PYTHONPATH": str(root / "src")})
    assert (result.returncode, result.stdout, result.stderr) == (0, b"", b"")
