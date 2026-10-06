"""With MAX_GIT_SECONDS = 0 (documented as also the graceful-close budget), does
closing a clean, non-abandoned snapshot always refuse? Run on the fix's source."""
import sys, pathlib, subprocess, tempfile, collections, os
root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))
import receipt.snapshot as sm
from receipt.snapshot import TreeSnapshot, SnapshotError
repo = pathlib.Path(tempfile.mkdtemp(dir=root / "scratch")) / "r"
repo.mkdir()
g = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)
g("init", "-q"); g("config", "user.name", "x"); g("config", "user.email", "x@x")
(repo / "f.txt").write_text("x\n"); g("add", "f.txt"); g("commit", "-qm", "m")
outcomes = collections.Counter()
N = int(sys.argv[1])
for i in range(N):
    selected = TreeSnapshot.select(repo)
    selected.__enter__()
    selected.header(selected.tree)          # one real batch response, accepted at 60 s
    batch = selected._state.batch
    if i % 2:                               # let git exit on stdin EOF before close polls
        orig = batch.process.wait
        def wait(timeout=None, _orig=orig):
            if timeout is not None:
                _orig()
            return _orig(timeout=timeout)
        batch.process.wait = wait
    sm.MAX_GIT_SECONDS = 0
    try:
        selected.__exit__(None, None, None)
        outcomes["exited-first: accepted" if i % 2 else "natural: accepted"] += 1
    except SnapshotError as exc:
        outcomes[("exited-first: " if i % 2 else "natural: ") + str(exc)[:60]] += 1
    finally:
        sm.MAX_GIT_SECONDS = 60
print(dict(outcomes))
