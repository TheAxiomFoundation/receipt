"""Shared helpers: outcome classification of json.loads vs _bounded_json.loads.

Import after putting <tree>/src first on sys.path.
"""
from __future__ import annotations

import json
import math
import sys

from receipt import _bounded_json as bj

MAX_DEPTH = bj.MAX_DEPTH
MAX_DIGITS = bj.MAX_INTEGER_DIGITS


def same(a, b):
    if isinstance(a, float) and isinstance(b, float):
        return a == b or (math.isnan(a) and math.isnan(b))
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return list(a.keys()) == list(b.keys()) and all(same(a[k], b[k]) for k in a)
    return type(a) is type(b) and a == b


def value_depth(v) -> int:
    """Container depth of a decoded value, iteratively. [[]] -> 2."""
    best = 0
    stack = [(v, 1)]
    while stack:
        x, d = stack.pop()
        if isinstance(x, list):
            best = max(best, d)
            stack.extend((y, d + 1) for y in x)
        elif isinstance(x, dict):
            best = max(best, d)
            stack.extend((y, d + 1) for y in x.values())
    return best


def max_int_digits(v) -> int:
    best = 0
    stack = [v]
    while stack:
        x = stack.pop()
        if isinstance(x, bool):
            continue
        if isinstance(x, int):
            # digits without converting to str (may exceed the int limit)
            n = abs(x)
            d = 1 if n == 0 else len(str(n)) if n.bit_length() < 14000 else 99999
            best = max(best, d)
        elif isinstance(x, list):
            stack.extend(x)
        elif isinstance(x, dict):
            stack.extend(x.values())
    return best


def ref_first_excess_valid(text: str) -> int | None:
    """Reference scan, correct for text json.loads ACCEPTS (strict JSON)."""
    depth = 0
    i = 0
    n = len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c in "[{":
                depth += 1
                if depth > MAX_DEPTH:
                    return i
            elif c in "]}":
                depth -= 1
        i += 1
    return None


def outcome(fn, text, **kw):
    try:
        return ("value", fn(text, **kw))
    except bj.JsonBoundError as e:
        return ("bound", str(e))
    except json.JSONDecodeError as e:
        return ("error", str(e))
    except RecursionError as e:
        return ("recursion", str(e))
    except Exception as e:  # noqa: BLE001
        if type(e) is ValueError:
            return ("valueerror", str(e))
        return ("other:" + type(e).__name__, str(e))


def compare(text: str, **kw):
    """Return None if the pair is permitted, else a description dict."""
    ref = outcome(json.loads, text, **kw)
    got = outcome(bj.loads, text, **kw)
    if ref[0] == "value":
        d = value_depth(ref[1])
        if d > MAX_DEPTH:
            if got[0] != "bound":
                return {"why": "deep value accepted", "ref": ref[0], "got": got}
            exp = ref_first_excess_valid(text)
            want = f"JSON nesting exceeds {MAX_DEPTH} levels at char {exp}"
            if got[1] != want:
                return {"why": "depth message offset", "got": got[1], "want": want}
            return None
        if got[0] != "value" or not same(got[1], ref[1]):
            return {"why": "value mismatch", "ref": repr(ref[1])[:200], "got": (got[0], repr(got[1])[:300])}
        return None
    if ref[0] == "error":
        if got != ref:
            return {"why": "decode error mismatch", "ref": ref, "got": got}
        return None
    if ref[0] in ("recursion", "valueerror"):
        if got[0] != "bound":
            return {"why": "crash not bound", "ref": ref, "got": got}
        return None
    # hook exceptions etc: must pass through identically
    if got != ref:
        return {"why": "other mismatch", "ref": ref, "got": got}
    return None
