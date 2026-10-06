"""Exhaustive small-body differential at the depth boundary (head tree).

text = "[" * P + body + suffix, body over a small alphabet up to length L,
P in (126, 127), suffixes closing with/without a quote. Every text is compared
with difflib_bj.compare (value / same JSONDecodeError message / bound only
where permitted, and exact depth offset for accepted deep text).

Usage: python exhaustive.py <tree-dir> <L>
"""
import collections
import itertools
import pathlib
import sys

tree = pathlib.Path(sys.argv[1]).resolve()
sys.path[:0] = [str(tree / "src"), str(pathlib.Path(__file__).parent)]
import receipt  # noqa: E402

print("receipt:", receipt.__file__, flush=True)
import difflib_bj as D  # noqa: E402

L = int(sys.argv[2])
ALPHA = ['[', ']', '{', '}', '"', '\\', '\n', ':', ',', '0']
counts = collections.Counter()
fails = []
n = 0
for P in (126, 127):
    for length in range(L + 1):
        for body in itertools.product(ALPHA, repeat=length):
            b = "".join(body)
            for suffix in ("]" * P, '"' + "]" * P, "]" * (P + 1), "}" + "]" * P):
                text = "[" * P + b + suffix
                n += 1
                r = D.compare(text)
                if r is not None:
                    fails.append((text, r))
                    if len(fails) < 5:
                        print("DISAGREE", repr(b), repr(suffix[:3]), r, flush=True)
print(f"texts={n} disagreements={len(fails)}")
