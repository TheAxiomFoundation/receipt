"""Generate the commit-payload corpus for the base/head _canonical_commit differential.

Writes commit_corpus.jsonl: one JSON object per case,
  {"id": str, "fmt": "sha1"|"sha256", "limit": int|null, "hex": payload.hex()}

Part 1 is a hand-built adversarial set (cases a-j of the brief).
Part 2 is seeded random structure + byte mutations (deterministic).
No receipt import: this script is tree-agnostic.
"""

from __future__ import annotations

import json
import pathlib
import random
import sys

OUT = pathlib.Path(__file__).with_name("commit_corpus.jsonl")
N_RANDOM = int(sys.argv[1]) if len(sys.argv) > 1 else 60_000

O1 = b"1" * 40
O2 = b"2" * 40
O0 = b"0" * 40
OA = b"a" * 40
S1 = b"1" * 64
T = b"tree " + O1
P = b"parent " + O0
P2 = b"parent " + O2
A = b"author a <a@x> 0 +0000"
C = b"committer c <c@x> 0 +0000"
BODY = b"\n\nmessage\n"

cases: list[tuple[str, str, int | None, bytes]] = []


def add(name: str, payload: bytes, *, fmt: str = "sha1", limits=(None,)) -> None:
    for limit in limits:
        cases.append((f"{name}|limit={limit}|{fmt}", fmt, limit, payload))


def j(*lines: bytes) -> bytes:
    return b"\n".join(lines)


ALL_LIMITS = (None, 0, 1, 2, 3)

# Baselines that must parse
add("ok-plain", j(T, A, C) + BODY, limits=ALL_LIMITS)
add("ok-parents", j(T, P, P2, A, C) + BODY, limits=ALL_LIMITS)
add("ok-gpgsig", j(T, P, A, C, b"gpgsig -----BEGIN PGP SIGNATURE-----", b" ", b" abc", b" -----END PGP SIGNATURE-----") + BODY, limits=ALL_LIMITS)
add("ok-mergetag", j(T, P, P2, A, C, b"mergetag object " + O2, b" type commit", b" tag v1", b" ", b" sig") + BODY, limits=ALL_LIMITS)
add("ok-encoding", j(T, A, C, b"encoding ISO-8859-1") + BODY)
add("ok-author-cont", j(T, A, b" continued", C, b" continued") + BODY)
add("ok-sha256", j(b"tree " + S1, b"parent " + S1, A, C) + BODY, fmt="sha256", limits=ALL_LIMITS)

# The continued tree/parent header in every position and followed by everything
continued_heads = {
    "tree": [T],
    "parent1": [T, P],
    "parent2": [T, P, P2],
    "tree-later": [T, A, C, T],
    "parent-later": [T, A, C, P],
    "tree-second": [T, T],
    "parent-after-author": [T, A, P],
    "parent-after-committer": [T, A, C, P],
    "tree-in-parents": [T, P, T],
    "parent-first": [P],
    "tree-emptyval": [b"tree "],
    "tree-badoid": [b"tree " + b"g" * 40],
    "tree-upper": [b"tree " + b"A" * 40],
    "tree-short": [b"tree " + b"1" * 39],
    "parent-emptyval": [T, b"parent "],
    "tree-cr": [T + b"\r"],
    "tree-nul": [T + b"\x00"],
    "tree-trailing-space": [T + b" "],
}
continuations = {
    "space": [b" "],
    "x": [b" x"],
    "oid39": [b" " + b"1" * 39],
    "oid40": [b" " + O1],
    "two": [b" a", b" b"],
    "many": [b" "] * 50,
    "cr": [b" \r"],
    "nul": [b" \x00"],
    "doublespace": [b"  two"],
    "tab-after-space": [b" \t"],
}
followers = {
    "eof-nosep": None,  # handled specially: no blank line at all
    "eof-onenl": None,
    "sep-direct": [],
    "author-committer": [A, C],
    "malformed": [b"malformed", A, C],
    "emptyname": [b" nothing" , A, C],  # actually another continuation
    "nameless": [b"\x00x y", A, C],
    "ctrlname": [b"a\x7fb y", A, C],
    "highname": [b"\xff y", A, C],
    "order-violation": [C, A],
    "second-tree": [T, A, C],
    "parent-after": [P, A, C],
    "gpgsig": [A, C, b"gpgsig x", b" y"],
    "crlf": [A + b"\r", C + b"\r"],
    "committer-only": [C],
    "tree-only": [T],
    "bare-tree": [b"tree"],
}
for hname, head in continued_heads.items():
    for cname, cont in continuations.items():
        for fname, follow in followers.items():
            if fname == "eof-nosep":
                payload = j(*head, *cont)
            elif fname == "eof-onenl":
                payload = j(*head, *cont) + b"\n"
            else:
                payload = j(*head, *cont, *follow) + BODY
            add(f"adv|{hname}|{cname}|{fname}", payload, limits=ALL_LIMITS)
            if hname in ("tree", "parent1"):
                add(
                    f"adv256|{hname}|{cname}|{fname}",
                    payload.replace(O1, S1).replace(O0, b"0" * 64).replace(O2, b"2" * 64),
                    fmt="sha256",
                    limits=(None, 0),
                )

# Budget interplay: overflow first, then a continued parent / tree
add("budget-then-cont-parent", j(T, P, P2, b" x", A, C) + BODY, limits=ALL_LIMITS)
add("budget-then-bad-parent", j(T, P, P2, b"parent zz", A, C) + BODY, limits=ALL_LIMITS)
add("budget-only", j(T, P, P2, P, A, C) + BODY, limits=ALL_LIMITS)
add("budget-then-order", j(T, P, P2, C, A) + BODY, limits=ALL_LIMITS)
add("budget-then-cont-then-eof", j(T, P, P2, b" x"), limits=ALL_LIMITS)

# (g) continuation first / after blank line
add("cont-first", j(b" x", T, A, C) + BODY)
add("cont-first-space", j(b" ", T, A, C) + BODY)
add("cont-after-blank", j(T, A, C) + b"\n\n x\n y\n")
add("cont-after-blank-2", j(T, P) + b"\n\n x\n")
add("blank-first", b"\n\n" + j(T, A, C))
add("blank-first-cont", b"\n" + j(b" x", T, A, C) + BODY)
add("empty", b"")
add("only-sep", b"\n\n")
add("only-nl", b"\n")
add("tree-cont-sep-cont", j(T, b" x") + b"\n\n x\n")

# (h) CR/LF variants
add("crlf-all", b"\r\n".join([T, b" x", A, C]) + b"\r\n\r\nmsg")
add("crlf-mixed", j(T + b"\r", b" x", A, C) + BODY)
add("cr-continuation", j(T, b"\r x", A, C) + BODY)
add("lfcr-sep", j(T, b" x", A, C) + b"\n\r\nmsg")

# (i) space-only continuation lines in bulk
add("space-cont-1000", j(T, *([b" "] * 1000), A, C) + BODY)
add("space-cont-parent-1000", j(T, P, *([b" "] * 1000), A, C) + BODY, limits=ALL_LIMITS)

# Random part --------------------------------------------------------------
rng = random.Random(20260928)

LINE_POOL = [
    T, P, P2, A, C,
    b"tree " + O2, b"tree " + OA, b"parent " + OA,
    b"tree", b"parent", b"tree ", b"parent ",
    b"gpgsig -----BEGIN-----", b"mergetag object " + O2, b"encoding UTF-8",
    b"future-header x", b"malformed", b"", b" ", b" x", b" " + O1, b"  y",
    b" \r", b"\r", b"\x00", b"tree\x00" + O1, b"tree  " + O1, b"tree " + O1 + b" ",
    b"author", b"committer", b"a\x7f b", b"\xc3\xa9 b", b"tree " + b"1" * 39,
    b"tree " + b"F" * 40, b"parent " + b"f" * 41,
]
BYTE_POOL = [b" ", b"\n", b"\r", b"\x00", b"\t", b"a", b"0", b"f", b"g", b"\x7f", b"\xff", b"\n\n", b"\n "]
SEEDS = [
    [T, A, C],
    [T, P, A, C],
    [T, P, P2, A, C],
    [T, P, A, C, b"gpgsig -----BEGIN-----", b" a", b" b", b" -----END-----"],
    [T, P, P2, A, C, b"mergetag object " + O2, b" type commit", b" ", b" sig"],
    [T, A, b" cont", C, b"encoding UTF-8"],
]


def mutate_lines(lines: list[bytes]) -> list[bytes]:
    lines = list(lines)
    for _ in range(rng.randint(1, 4)):
        op = rng.random()
        if op < 0.45:
            lines.insert(rng.randint(0, len(lines)), rng.choice(LINE_POOL))
        elif op < 0.6 and lines:
            del lines[rng.randrange(len(lines))]
        elif op < 0.75 and lines:
            lines[rng.randrange(len(lines))] = rng.choice(LINE_POOL)
        elif op < 0.85 and lines:
            i = rng.randrange(len(lines))
            lines.insert(i, lines[i])
        elif len(lines) >= 2:
            a, b = rng.sample(range(len(lines)), 2)
            lines[a], lines[b] = lines[b], lines[a]
    # frequently add a run of continuations under a tree/parent header
    if rng.random() < 0.4:
        idx = [i for i, l in enumerate(lines) if l.startswith((b"tree", b"parent"))]
        if idx:
            i = rng.choice(idx)
            run = [rng.choice([b" ", b" x", b" " + O1, b"  y", b" \r", b" \x00"]) for _ in range(rng.randint(1, 5))]
            lines[i + 1 : i + 1] = run
    return lines


def mutate_bytes(payload: bytes) -> bytes:
    data = bytearray(payload)
    for _ in range(rng.randint(1, 3)):
        op = rng.random()
        pos = rng.randint(0, len(data)) if data else 0
        piece = rng.choice(BYTE_POOL)
        if op < 0.4:
            data[pos:pos] = piece
        elif op < 0.7 and data:
            pos = min(pos, len(data) - 1)
            data[pos : pos + 1] = piece
        elif data:
            pos = min(pos, len(data) - 1)
            del data[pos : pos + rng.randint(1, 3)]
    return bytes(data)


for n in range(N_RANDOM):
    seed = rng.choice(SEEDS)
    lines = mutate_lines(seed)
    tail = rng.choice([BODY, BODY, BODY, b"\n", b"", b"\n\n", b"\n\n \n x"])
    payload = b"\n".join(lines) + tail
    if rng.random() < 0.3:
        payload = mutate_bytes(payload)
    fmt = "sha1"
    if rng.random() < 0.1:
        fmt = "sha256"
        payload = payload.replace(O1, S1).replace(O0, b"0" * 64).replace(O2, b"2" * 64)
    limit = rng.choice([None, None, 0, 1, 2, 3])
    cases.append((f"rnd{n}", fmt, limit, payload))

with OUT.open("w") as fh:
    for cid, fmt, limit, payload in cases:
        fh.write(json.dumps({"id": cid, "fmt": fmt, "limit": limit, "hex": payload.hex()}) + "\n")
print(f"wrote {len(cases)} cases to {OUT}")
