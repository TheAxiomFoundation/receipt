import sys, threading, time, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import variant_grid as vg
from _pytest.monkeypatch import MonkeyPatch
DELAYS = {5: 0.2, 6: 1.0}
counter = {"n": 0}
original_start, original_run = threading.Thread.start, threading.Thread.run
def indexed_start(self):
    if self.name == "receipt-git-batch-stdout":
        self._demo_index = counter["n"]; counter["n"] += 1
    return original_start(self)
def delayed_run(self):
    time.sleep(DELAYS.get(getattr(self, "_demo_index", -1), 0.0))
    return original_run(self)
inject = "--inject" in sys.argv
if inject:
    threading.Thread.start, threading.Thread.run = indexed_start, delayed_run
mp = MonkeyPatch()
try:
    vg.variant(mp); print("inject" if inject else "plain", vg.snapshot_module.__file__.split("/scratch/")[-1] if "/scratch/" in vg.snapshot_module.__file__ else "fix", "PASSED")
except AssertionError as exc:
    print("inject" if inject else "plain", vg.snapshot_module.__file__, "FAILED", exc)
finally:
    mp.undo(); threading.Thread.start, threading.Thread.run = original_start, original_run
