"""pytest plugin: tally the outcomes the author's 3,000-example differential sees.

Wraps the test module's global ``_canonical_commit`` (the head parser, looked
up at call time by the test body) so every payload the derandomized Hypothesis
run feeds it is recorded, then classifies:

* parse          -- head parser returned a _CommitObject
* budget         -- refusal text "ancestry walk exceeds the budget ..."
* new_site       -- head refused at the NEW raise (first continuation of a
                    tree/parent header), detected with a source-transformed
                    copy of the head function whose new raise uses a marker
                    subclass
* any_cont_tp    -- payload has, before its first blank line, a continuation
                    line whose current header is tree or parent (whether or
                    not an earlier refusal fired first)

Writes JSON to $TALLY_OUT.
"""

from __future__ import annotations

import ast
import collections
import inspect
import json
import os
import textwrap

import pytest

RECORDS: list[tuple[bytes, object, str]] = []


def _marker_parser(module):
    import receipt.snapshot as S

    source = inspect.getsource(S._canonical_commit)
    needle = (
        "            if current_name in {b\"tree\", b\"parent\"}:\n"
    )
    assert needle in source
    head_block = source.split(needle, 1)[1]
    # the first raise after the needle is the new raise site
    old = "raise SnapshotError(\n                    f\"commit {oid} is not a canonical commit object\"\n                )"
    assert old in head_block, head_block[:600]
    new_block = head_block.replace(old, "raise _Marker(\n                    f\"commit {oid} is not a canonical commit object\"\n                )", 1)
    patched = source.split(needle, 1)[0] + needle + new_block
    patched = patched.replace("def _canonical_commit(", "def _canonical_commit_marked(", 1)

    class _Marker(S.SnapshotError):
        pass

    namespace = dict(vars(S))
    namespace["_Marker"] = _Marker
    exec(compile(patched, "<marked>", "exec"), namespace)
    return namespace["_canonical_commit_marked"], _Marker


def _any_cont_tp(payload: bytes) -> bool:
    sep = payload.find(b"\n\n")
    if sep < 0:
        return False
    current = None
    for line in payload[:sep].split(b"\n"):
        if line.startswith(b" "):
            if current in (b"tree", b"parent"):
                return True
            continue
        current = line.partition(b" ")[0]
    return False


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(session, config, items):
    for item in items:
        module = item.module
        if getattr(module, "_tally_wrapped", False):
            continue
        original = module._canonical_commit

        def wrapped(oid, payload, *, object_format, parent_limit=None, _orig=original):
            try:
                result = _orig(oid, payload, object_format=object_format, parent_limit=parent_limit)
            except Exception as exc:  # noqa: BLE001
                RECORDS.append((bytes(payload), parent_limit, "E:" + str(exc)))
                raise
            RECORDS.append((bytes(payload), parent_limit, "OK:" + repr(result)))
            return result

        module._canonical_commit = wrapped
        module._tally_wrapped = True


def pytest_sessionfinish(session, exitstatus):
    import receipt.snapshot as S

    marked, Marker = _marker_parser(S)
    counts = collections.Counter()
    distinct = set()
    for payload, limit, outcome in RECORDS:
        distinct.add((payload, limit))
        counts["calls"] += 1
        if outcome.startswith("OK:"):
            counts["parse"] += 1
        elif "ancestry walk exceeds the budget" in outcome:
            counts["budget"] += 1
        else:
            counts["refused_noncanonical"] += 1
        try:
            marked("f" * 40, payload, object_format="sha1", parent_limit=limit)
        except Marker:
            counts["new_site"] += 1
        except S.SnapshotError:
            pass
        if _any_cont_tp(payload):
            counts["any_cont_tp"] += 1
    counts["distinct_inputs"] = len(distinct)
    out = os.environ.get("TALLY_OUT")
    data = {"receipt_file": S.__file__, "counts": dict(counts)}
    if out:
        with open(out, "w") as fh:
            json.dump(data, fh, indent=2)
    print("\nTALLY", json.dumps(data))
