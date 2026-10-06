"""An empty frozen prefix (prefixLineCount 0), written by the fixture's own
writer formula sha256("\\n".join(lines) + "\\n"), through verify_append_gate.

Usage: python empty_prefix_gate.py <tree-dir> <tmpdir>
Imports the tree's own src and tests (so the fixture is that tree's)."""
import pathlib, sys, tempfile
tree = pathlib.Path(sys.argv[1]).resolve()
sys.path[:0] = [str(tree / "src"), str(tree / "tests")]
import test_append_gate as t
import receipt.append_gate as ag
print("module:", ag.__file__)
t.PREFIX_LINE_COUNT = 0
for push in (False, True):
    tmp = pathlib.Path(tempfile.mkdtemp(dir=sys.argv[2]))
    cand = t.base_repository(tmp)
    t.append_one_row(cand)
    try:
        out = t.run_push_gate(cand) if push else t.run_gate(cand)
        print("push" if push else "pr  ", "->", out)
    except Exception as e:
        print("push" if push else "pr  ", "->", type(e).__name__, e)
