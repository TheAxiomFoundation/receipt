"""Proposed fix for the batch grid: one scripted clock per case, captured by
that case's read, so a reader thread still pending from a zero-deadline case
can only move a clock that is no longer installed."""
import sys, pathlib
SRC = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[1]
root = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(root / "tests"), str(SRC / "src")]
import receipt.snapshot as snapshot_module
from receipt.snapshot import SnapshotError
from test_snapshot import _fake_batch, _ScriptedClock, _KillRecorder

def variant(monkeypatch) -> None:
    outcomes = {}
    for deadline in (0.0, 30.0, 60.0):
        for completes_at in (0.0, 15.0, 30.0, 45.0, 60.0, 75.0):
            # A fresh clock per case: a zero-deadline read's thread can still
            # be pending when its case refuses, and must not move this one.
            clock = _ScriptedClock()
            monkeypatch.setattr(snapshot_module, "time", clock)
            batch = _fake_batch(b"")
            killer = _KillRecorder()
            batch._process = killer

            def read(_completes_at: float = completes_at, _clock: _ScriptedClock = clock) -> bytes:
                _clock.now = max(_clock.now, _completes_at)
                return b"frame"

            try:
                result = batch._read_with_deadline(read, deadline=deadline)
            except SnapshotError as exc:
                assert str(exc) == ("Git batch child exceeded the budget of "
                                    f"{snapshot_module.MAX_GIT_SECONDS} seconds")
                assert batch.abandoned and killer.kills >= 1
                outcomes[deadline, completes_at] = False
            else:
                assert result == b"frame"
                assert not batch.abandoned and killer.kills == 0
                outcomes[deadline, completes_at] = True
    assert outcomes == {(d, c): c < d for d, c in outcomes}, {k: v for k, v in outcomes.items() if v != (k[1] < k[0])}
    assert len(outcomes) == 18
