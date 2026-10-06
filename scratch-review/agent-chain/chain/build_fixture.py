"""Build one witnessed corpus (genesis + one appended release).

Copied from the sweep's chain/build_fixture.py and repointed: the tests dir is
taken from RECEIPT_TREE (one tree per process).
Usage: RECEIPT_TREE=<tree> python build_fixture.py <out_dir>
"""
from __future__ import annotations
import os, pathlib, sys
TREE = pathlib.Path(os.environ["RECEIPT_TREE"]).resolve()
sys.path.insert(0, str(TREE / "tests"))
sys.path.insert(0, str(TREE / "src"))
import receipt
print("receipt from", receipt.__file__)
from corpus_fixture import append_release, build_corpus  # noqa: E402

out = pathlib.Path(sys.argv[1])
root = out / "repo"
root.mkdir(parents=True)
workspace = out / "workspace"
build_corpus(root, workspace, commit=False)
append_release(root, workspace, content={"rules/extra.yaml": "extra: 1\n"}, commit=False)
print("built", root)
