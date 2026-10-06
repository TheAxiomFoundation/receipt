import sys, pathlib, time
root = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(root / "tests"), str(root / "src")]
import test_snapshot_acceptance as t
from _pytest.monkeypatch import MonkeyPatch
N = int(sys.argv[1]); fails = 0; start = time.time()
for i in range(N):
    for seconds in (0.0, 1.0, 2.0, 3.0):
        mp = MonkeyPatch()
        try:
            t.test_git_seconds_budget_accepts_only_a_child_observed_before_its_deadline(mp, seconds)
        except AssertionError:
            fails += 1
        finally:
            mp.undo()
print(f"{sys.version.split()[0]}: {fails}/{4*N} failed in {time.time()-start:.1f}s")
