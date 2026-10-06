"""Run the unmodified batch grid test N times; count and show failures."""
import sys, pathlib, collections, time
root = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(root / "tests"), str(root / "src")]
import test_snapshot as t
from _pytest.monkeypatch import MonkeyPatch
N = int(sys.argv[1])
fails = collections.Counter()
start = time.time()
for i in range(N):
    mp = MonkeyPatch()
    try:
        t.test_batch_response_budget_accepts_only_reads_observed_before_the_deadline(mp)
    except AssertionError as exc:
        tb = exc.__traceback__
        while tb.tb_next is not None:
            tb = tb.tb_next
        outcomes = tb.tb_frame.f_locals.get("outcomes", {})
        wrong = tuple(sorted(k for k, v in outcomes.items() if v != (k[1] < k[0])))
        fails[wrong or ("other", tb.tb_lineno)] += 1
    finally:
        mp.undo()
print(f"{sys.version.split()[0]} {'t' if not getattr(sys, '_is_gil_enabled', lambda: True)() else ''}: {sum(fails.values())}/{N} failed in {time.time()-start:.1f}s; {dict(fails)}")
