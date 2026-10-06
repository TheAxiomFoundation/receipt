"""Run every generated case through its public receipt.tsa entry point.

usage: run_cases.py SRC OUT.jsonl [WORKERS] [ID ...]

SRC is the src/ directory to import receipt from (the frozen tree or the
77ff9c5 archive). Each case runs in a worker process under a 150 s alarm; the
outcome is "ok" (verified), "refused" (TsaError), "crash" (anything else) or
"timeout". Messages are normalised (case dir, private temp dirs, wall-clock
verification time) so two trees' outputs over the same cases compare.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import pathlib
import pickle
import re
import signal
import sys
import time
import traceback

S = pathlib.Path("/Users/maxghenis/chief-of-staff/state/receipt-07/crash-refusal/sweep/tsa")
CASES = S / "cases"
MINE = pathlib.Path("/Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-crash-refusal-review/scratch-review/agent-tsa/sweep")
REC_REL = "records/2026-09-02/record-0001.json"
ALARM = 150


class Timeout(BaseException):
    pass


def _alarm(_signum, _frame):
    raise Timeout()


def init(src: str) -> None:
    sys.path.insert(0, src)
    sys.setrecursionlimit(1000)
    global tsa, SPECS
    from receipt import tsa as _tsa
    import receipt as _r
    assert _r.__file__.startswith(src), (_r.__file__, src)

    tsa = _tsa
    SPECS = pickle.loads((S / "specs.pickle").read_bytes())
    signal.signal(signal.SIGALRM, _alarm)


def normalise(text: str, case: pathlib.Path) -> str:
    for spelling in {str(case.resolve()), str(case)}:
        text = text.replace(spelling, "<CASE>")
    text = re.sub(r"(/private)?/[^\s'\"]*?/thesis-tsa-[A-Za-z0-9_]+", "<TMP>", text)
    text = re.sub(r"verification time \S+", "verification time <NOW>", text)
    return text


def run_one(case_id: str) -> dict:
    case = CASES / case_id
    info = pickle.loads((case / "case.pickle").read_bytes())
    spec = SPECS[info["base"]]["spec"]
    records = case / "records"
    record = case / REC_REL
    kwargs = dict(info["kwargs"])
    entry = info["entry"]
    result = {"id": case_id, "desc": info["desc"], "entry": entry}
    started = time.perf_counter()
    cpu = time.process_time()
    signal.alarm(ALARM)
    try:
        if entry == "verify_witness":
            if kwargs.get("now") == "NOW":
                kwargs.pop("now")
            value = tsa.verify_witness(record, spec=spec, records=records, **kwargs)
        elif entry == "verify_witness_step":
            value = tsa.verify_witness_step(
                record, spec=spec, records=records,
                prior_pending_updates=kwargs["prior_pending_updates"],
            ).evidence
        elif entry == "verify_timestamp_token":
            value = tsa.verify_timestamp_token(
                record, kwargs["claim"], kwargs["reference"], spec=spec, records=records
            )
        else:
            raise AssertionError(entry)
        signal.alarm(0)
        result["outcome"] = "ok"
        if hasattr(value, "tokens"):
            result["detail"] = {
                "status": value.status,
                "tokens": [t.gen_time for t in value.tokens],
                "gen_time": value.gen_time,
                "anchor_id": value.anchor_id,
            }
        else:
            result["detail"] = {"gen_time": value.gen_time, "anchor_id": value.anchor_id}
    except Timeout:
        result["outcome"] = "timeout"
        result["type"] = "Timeout"
        result["message"] = f"no verdict after {ALARM} s"
        result["where"] = traceback.format_exc()[-1500:]
    except tsa.TsaError as exc:
        signal.alarm(0)
        result["outcome"] = "refused"
        result["message"] = normalise(str(exc), case)[:3000]
    except BaseException as exc:  # noqa: BLE001
        signal.alarm(0)
        result["outcome"] = "crash"
        result["type"] = type(exc).__name__
        result["message"] = normalise(str(exc), case)[:1000]
        frames = traceback.extract_tb(exc.__traceback__)
        result["where"] = [f"{pathlib.Path(f.filename).name}:{f.lineno}:{f.name}" for f in frames][-6:]
    finally:
        signal.alarm(0)
    result["seconds"] = round(time.perf_counter() - started, 3)
    result["cpu"] = round(time.process_time() - cpu, 3)
    return result


def main() -> None:
    src, out = sys.argv[1], pathlib.Path(sys.argv[2])
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    ids = (MINE / sys.argv[4]).read_text().split() if len(sys.argv) > 4 else sorted(p.name for p in CASES.iterdir() if p.is_dir())
    if len(sys.argv) > 5:
        ids = ids[: int(sys.argv[5])]
    done = set()
    if out.exists():
        for line in out.read_text().splitlines():
            done.add(json.loads(line)["id"])
    ids = [i for i in ids if i not in done]
    context = multiprocessing.get_context("spawn")
    with context.Pool(workers, initializer=init, initargs=(src,), maxtasksperchild=200) as pool, out.open("a") as handle:
        for count, result in enumerate(pool.imap_unordered(run_one, ids, chunksize=4), start=1):
            handle.write(json.dumps(result) + "\n")
            handle.flush()
            if count % 200 == 0:
                print(time.strftime("%H:%M:%S"), count, "/", len(ids), flush=True)
    print("done", len(ids), flush=True)


if __name__ == "__main__":
    main()
