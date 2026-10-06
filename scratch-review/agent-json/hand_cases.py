"""Hand-built differential cases: _bounded_json.loads vs json.loads (head tree).

Usage: python hand_cases.py <tree-dir>
"""
import json
import pathlib
import sys

tree = pathlib.Path(sys.argv[1]).resolve()
sys.path[:0] = [str(tree / "src"), str(pathlib.Path(__file__).parent)]
import receipt  # noqa: E402

print("receipt:", receipt.__file__)
import difflib_bj as D  # noqa: E402
from receipt import _bounded_json as bj  # noqa: E402

M = D.MAX_DEPTH
cases: dict[str, str] = {}


def add(name, text):
    cases[name] = text


def nest(depth, leaf="0", kind="["):
    if kind == "[":
        return "[" * depth + leaf + "]" * depth
    return '{"k":' * depth + leaf + "}" * depth


# Boundary depth with brackets inside strings, escapes of every shape
leaves = {
    "plain": "0",
    "str_brackets": '"[[[[{{{{"',
    "str_closers": '"]]]]}}}}"',
    "esc_quote": '"\\"[[[["',
    "esc_bs": '"\\\\"',
    "esc_bs_then_brackets": '"\\\\", "[[[["',
    "u_quote": '"\\u0022[[[["',
    "u_bs": '"\\u005c"',
    "u_bs_bracket": '"\\u005c[[[["',
    "odd_bs_run": '"' + "\\\\" * 7 + '\\"[[["',
    "even_bs_run": '"' + "\\\\" * 8 + '", "[[["',
    "u2028": '" [[ ]]"',
    "surrogate": '"\ud800[[[["',
    "u_surrogate": '"\\ud800[[[["',
    "nan": "NaN",
    "neg_inf": "-Infinity",
    "big_float": "1" * 5000 + ".5",
    "exp400": "1e400",
    "neg0": "-0",
}
for d in (M - 1, M, M + 1):
    for lname, leaf in leaves.items():
        add(f"arr{d}_{lname}", nest(d, leaf))
        add(f"obj{d}_{lname}", nest(d, leaf, "{"))
    # object keys with brackets and escapes
    add(f"keys{d}", '{"[[[\\"{{":' * d + "0" + "}" * d)
    add(f"mixed{d}", '[{"a":' * (d // 2) + ("[0]" if d % 2 else "0") + "}]" * (d // 2))
    # whitespace variants
    for ws in (" ", "\t", "\n", "\r", "\r\n"):
        add(f"ws{d}_{ws!r}", ws.join("[" * d) + ws + "0" + ws + ws.join("]" * d) + ws)

# Malformed text: json.loads must decide, bound only if it crashed
deep_tail = "[" * 300
mal = {
    "bs_newline_in_string": '"\\\n' + deep_tail,
    "bs_cr_in_string": '"\\\r' + deep_tail,
    "raw_newline_in_string": '"a\n' + deep_tail + '"',
    "raw_cr_in_string": '"a\r' + deep_tail + '"',
    "nul_in_string": '"a\x00' + deep_tail + '"',
    "ctl_1f": '"a\x1f' + deep_tail + '"',
    "tab_in_string": '"a\t' + deep_tail + '"',
    "bom_prefix": "﻿" + nest(5),
    "bom_prefix_deep": "﻿" + nest(200),
    "unterminated_brackets": '["' + deep_tail,
    "unterminated_bs": '["\\' + deep_tail,
    "extra_data": "[]" + deep_tail,
    "extra_data_ws": "[] " + nest(200),
    "extra_string": '"a" "' + deep_tail,
    "nan_deep": nest(200, "NaN"),
    "minus": "[" * 200 + "-",
    "one_e": "[" * 200 + "1e",
    "leading_zero": "[" * 200 + "01",
    "leading_zero_shallow": "[01]",
    "minus_shallow": "[-]",
    "one_e_shallow": "[1e]",
    "bad_escape_x": '"\\x' + deep_tail + '"',
    "bad_u": '"\\u12' + deep_tail + '"',
    "deep_then_bad": nest(129)[:-1] + "x",
    "deep_close_mismatch": "[" * 200 + "}" * 200,
    "just_closers": "]" * 300 + "[" * 300,
    "closers_then_value": "]]]] 0",
    "u2028_ws": " " + nest(3),
    "nbsp_ws": " " + nest(3),
    "vt_ws": "\x0b" + nest(3),
    "empty": "",
    "ws_only": " \n\t\r",
    "deep_1000": nest(1000),
    "deep_100000": nest(100000),
    "deep_100000_bad": "[" * 100000 + "x",
    "deep_100000_unterminated_str": "[" * 100000 + '"abc',
    "deep_obj_100000": '{"a":' * 100000,
    "string_then_deep_closers": '"' + "\\" * 1001 + '"' + "[" * 200,
}
cases.update(mal)

# 4300-digit integer boundaries
for sign in ("", "-"):
    for n in (1, 4299, 4300, 4301, 5000):
        lit = sign + ("9" * n if n > 1 else "0")
        add(f"int{sign}{n}", lit)
        add(f"int{sign}{n}_in_arr", f"[{lit}]")
add("int_then_decode_error", "[" + "9" * 5000 + ", x]")
add("decode_error_then_int", "[x, " + "9" * 5000 + "]")
add("int4301_deep", nest(200, "9" * 4301))
add("float_5000", "0." + "1" * 5000)
add("int_exp", "9" * 5000 + "e1")

bad = 0
out = {}
for name, text in cases.items():
    r = D.compare(text)
    ref = D.outcome(json.loads, text)
    got = D.outcome(bj.loads, text)
    out[name] = {"ref": [ref[0], ref[1] if ref[0] != "value" else "<value>"], "got": [got[0], got[1] if got[0] != "value" else "<value>"], "problem": r}
    if r is not None:
        bad += 1
        print("DISAGREE", name, r)
print(f"{len(cases)} cases, {bad} disagreements")
json.dump(out, open(pathlib.Path(__file__).parent / "out" / "hand_cases.json", "w"), indent=1, default=str)
