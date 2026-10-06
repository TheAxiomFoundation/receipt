import sys, threading, time, pathlib
root = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(root / "tests"), str(root / "src")]
import test_snapshot as t
import receipt.snapshot as sm
from _pytest.monkeypatch import MonkeyPatch
counter = {"n": 0}
lock = threading.Lock()
original_run = threading.Thread.run
log = []
def delayed_run(self):
    if self.name == "receipt-git-batch-stdout":
        with lock:
            index = counter["n"]; counter["n"] += 1
        d = {5: 0.2, 6: 1.0}.get(index, 0.0)
        log.append((index, "start", d))
        time.sleep(d)
        r = original_run(self)
        log.append((index, "ran", sm.time.monotonic() if hasattr(sm.time, "now") else None))
        return r
    return original_run(self)
threading.Thread.run = delayed_run
mp = MonkeyPatch()
try:
    t.test_batch_response_budget_accepts_only_reads_observed_before_the_deadline(mp)
    print("PASSED")
except AssertionError:
    print("FAILED")
finally:
    mp.undo(); threading.Thread.run = original_run
print(log)
