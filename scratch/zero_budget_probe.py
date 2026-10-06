"""Count zero-budget `git version` calls accepted by _git_run (real children)."""
import sys, os, pathlib, time
sys.path.insert(0, str(pathlib.Path(sys.argv[1]) / "src"))
import receipt.snapshot as sm
N = int(sys.argv[2]); accepted = 0; t0 = time.time()
for _ in range(N):
    try:
        sm._git_run(["version"], cwd=None, environment=os.environ, seconds=0)
        accepted += 1
    except sm.SnapshotError as exc:
        assert str(exc) == "git command exceeded its 0 second budget", exc
print(f"{sys.argv[1].split('/')[-1] or 'fix'} {sys.version.split()[0]}: {accepted}/{N} zero-budget calls accepted ({time.time()-t0:.0f}s)")
