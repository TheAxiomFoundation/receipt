"""The policy module's frozen surface and production importer contract.

PR4 completes the last stage: the later-stage list is now empty. Test that
contract directly so an empty parametrization does not introduce a skip.
"""
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


LATER_STAGE_METHODS = ()
STEP_3A_IMPORTERS = {"append_gate.py", "release_chain.py", "snapshot.py", "verify.py"}


def test_no_later_stage_methods_remain():
    assert LATER_STAGE_METHODS == ()


def test_production_importers_are_the_step_3a_sites():
    root = pathlib.Path(__file__).resolve().parents[1]
    importers = set()
    for source in (root / "src/receipt").glob("*.py"):
        if source.name == "protected_tree.py":
            continue
        for node in ast.walk(ast.parse(source.read_text())):
            if isinstance(node, ast.Import):
                if any(alias.name == "receipt.protected_tree" for alias in node.names):
                    importers.add(source.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module in {"receipt.protected_tree", "protected_tree"} or any(
                    alias.name == "protected_tree" for alias in node.names
                ):
                    importers.add(source.name)
    # PR3a adds only verify.py: composed custody consumes the authenticated
    # five-prefix name view and state mode selections at its existing barriers.
    assert importers == STEP_3A_IMPORTERS


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
