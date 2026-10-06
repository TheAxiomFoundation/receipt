"""In-process Hypothesis differential: head _canonical_commit vs a VERBATIM copy of
the base (9c47a3d) function, extracted from the base file's text with ast (the
base package is never imported).  Head tree is put on sys.path by HEAD_TREE.

Run: HEAD_TREE=trees/f8b1ddc BASE_TREE=trees/9c47a3d pytest test_commit_hypothesis_diff.py
"""

from __future__ import annotations

import ast
import hashlib
import os
import pathlib
import sys

from hypothesis import given, settings, strategies as st, HealthCheck

HERE = pathlib.Path(__file__).parent
HEAD = (HERE / os.environ.get("HEAD_TREE", "trees/f8b1ddc")).resolve()
BASE = (HERE / os.environ.get("BASE_TREE", "trees/9c47a3d")).resolve()
sys.path.insert(0, str(HEAD / "src"))
import receipt.snapshot as S  # noqa: E402

assert pathlib.Path(S.__file__).resolve().is_relative_to(HEAD)

base_text = (BASE / "src/receipt/snapshot.py").read_text()
tree = ast.parse(base_text)
fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_canonical_commit")
base_src = ast.get_source_segment(base_text, fn)
assert "current_value += b\"\\n\" + line[1:]" in base_src
# base constants used by the function must equal head's
for name in ("MAX_ANCESTRY_COMMITS",):
    base_val = next(
        ast.literal_eval(n.value) if not isinstance(n.value, ast.BinOp) else eval(compile(ast.Expression(n.value), "x", "eval"))
        for n in tree.body
        if isinstance(n, ast.Assign) and any(getattr(t, "id", None) == name for t in n.targets)
    )
    assert base_val == getattr(S, name), (name, base_val)
assert 'rb"[0-9a-f]+\\Z"' in base_text
ns = {
    "hashlib": hashlib,
    "SnapshotError": S.SnapshotError,
    "MAX_ANCESTRY_COMMITS": S.MAX_ANCESTRY_COMMITS,
    "_OID_RE": S._OID_RE,
    "_CommitObject": S._CommitObject,
    "annotations": None,
}
exec(compile("from __future__ import annotations\n" + base_src, "<base-verbatim>", "exec"), ns)
BASE_PARSE = ns["_canonical_commit"]

OIDS1 = [b"0" * 40, b"1" * 40, b"a" * 40, b"f" * 40, b"1" * 39, b"A" * 40, b"g" * 40, b""]
OIDS256 = [b"0" * 64, b"1" * 64, b"1" * 40]
NAMES = [b"tree", b"parent", b"author", b"committer", b"gpgsig", b"mergetag", b"encoding", b"x-extra", b"Tree", b"tree\x00", b"\xff", b"a\x7f"]

header_line = st.builds(
    lambda name, sp, val: name + sp + val,
    st.sampled_from(NAMES),
    st.sampled_from([b" ", b"", b"  ", b"\t"]),
    st.one_of(st.sampled_from(OIDS1 + OIDS256), st.binary(max_size=6), st.just(b"a <a> 0 +0000")),
)
cont_line = st.builds(lambda tail: b" " + tail, st.one_of(st.sampled_from([b"", b"x", b"1" * 39, b"1" * 40, b"\r", b"\x00", b" "]), st.binary(max_size=4)))
any_line = st.one_of(header_line, cont_line, st.binary(max_size=5))


@st.composite
def payloads(draw):
    fmt = draw(st.sampled_from(["sha1", "sha1", "sha256"]))
    oids = OIDS1 if fmt == "sha1" else OIDS256
    lines = [b"tree " + draw(st.sampled_from(oids))]
    lines += [b"parent " + draw(st.sampled_from(oids)) for _ in range(draw(st.integers(0, 3)))]
    lines += [b"author a <a> 0 +0000", b"committer c <c> 0 +0000"]
    lines += draw(st.lists(st.sampled_from([b"gpgsig -----BEGIN-----", b"mergetag object " + oids[0], b"encoding UTF-8"]), max_size=2))
    for _ in range(draw(st.integers(0, 4))):
        lines.insert(draw(st.integers(0, len(lines))), draw(cont_line))
    for _ in range(draw(st.integers(0, 2))):
        lines.insert(draw(st.integers(0, len(lines))), draw(any_line))
    if draw(st.booleans()) and len(lines) > 1:
        del lines[draw(st.integers(0, len(lines) - 1))]
    sep = draw(st.sampled_from([b"\n\n", b"\n\n", b"\n", b"", b"\r\n\r\n", b"\n\n \n"]))
    body = draw(st.binary(max_size=6))
    return fmt, b"\n".join(lines) + sep + body


def outcome(parse, oid, payload, fmt, limit):
    try:
        r = parse(oid, payload, object_format=fmt, parent_limit=limit)
        return ("ok", r.oid, r.tree, r.parents)
    except BaseException as exc:  # noqa: BLE001
        return (type(exc).__name__, str(exc))


@settings(max_examples=3000, deadline=None, suppress_health_check=list(HealthCheck))
@given(payloads(), st.one_of(st.none(), st.integers(0, 3)))
def test_structured(fp, limit):
    fmt, payload = fp
    oid = "e" * (40 if fmt == "sha1" else 64)
    assert outcome(S._canonical_commit, oid, payload, fmt, limit) == outcome(BASE_PARSE, oid, payload, fmt, limit)


@settings(max_examples=3000, deadline=None, suppress_health_check=list(HealthCheck))
@given(
    st.lists(st.sampled_from([b"tree ", b"parent ", b"author ", b"committer ", b"1" * 40, b"0" * 40, b" ", b"\n", b"\n ", b"\n\n", b"\r", b"\x00", b"x", b"gpgsig "]), max_size=25),
    st.one_of(st.none(), st.integers(0, 2)),
)
def test_token_soup(tokens, limit):
    payload = b"".join(tokens)
    oid = "e" * 40
    assert outcome(S._canonical_commit, oid, payload, "sha1", limit) == outcome(BASE_PARSE, oid, payload, "sha1", limit)
