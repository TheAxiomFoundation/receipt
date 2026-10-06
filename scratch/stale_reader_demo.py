"""Deterministic demo: a zero-deadline reader thread that is descheduled after
start() returns writes the shared scripted clock during a later grid case.

Only thread scheduling is changed: the reader thread of grid case #5
(deadline 0.0, completes_at 75.0) sleeps 0.2 s before its target runs, and the
reader of case #6 (deadline 30.0, completes_at 0.0) sleeps 1.0 s, as a loaded
scheduler could impose. The test body is imported and run unmodified.
"""
import sys, threading, time, pathlib
root = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(root / "tests"), str(root / "src")]
import test_snapshot as t
from _pytest.monkeypatch import MonkeyPatch

DELAYS = {5: 0.2, 6: 1.0}
counter = {"n": 0}
original_start, original_run = threading.Thread.start, threading.Thread.run

def indexed_start(self):
    if self.name == "receipt-git-batch-stdout":
        self._demo_index = counter["n"]; counter["n"] += 1   # main thread, grid order
    return original_start(self)

def delayed_run(self):
    time.sleep(DELAYS.get(getattr(self, "_demo_index", -1), 0.0))
    return original_run(self)

threading.Thread.start, threading.Thread.run = indexed_start, delayed_run
mp = MonkeyPatch()
try:
    t.test_batch_response_budget_accepts_only_reads_observed_before_the_deadline(mp)
    print("PASSED")
except AssertionError as exc:
    tb = exc.__traceback__
    while tb.tb_next is not None:
        tb = tb.tb_next
    outcomes = tb.tb_frame.f_locals["outcomes"]
    wrong = {k: v for k, v in outcomes.items() if v != (k[1] < k[0])}
    print("FAILED: (deadline, completes_at) cases contradicting the predicate:", wrong)
finally:
    mp.undo()
    threading.Thread.start, threading.Thread.run = original_start, original_run
