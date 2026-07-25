"""``receipt verify`` — the outside auditor's command.

A clone, commodity tools, one offline fail-closed verdict. No network, no
credentials, no service to ask. Everything the command trusts arrives from the
consumer's committed spec, named on the command line, and the spec's own
SHA-256 is printed with the verdict so the configuration can be quoted.

The output is deliberately two-part. What the command *established* is stated
without hedging. What it *did not* establish — that any declared gate actually
passed, that the encoded rules read the law correctly — is stated just as
plainly, because a verdict that lets a reader infer more than was checked is
worse than no verdict.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Sequence

from receipt import __version__
from receipt.corpus import GATE_TIERS
from receipt.verify import (
    TIER_MEANING,
    VerifyResult,
    VerifySpecError,
    load_spec,
    result_to_dict,
    run_verification,
)

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="receipt",
        description=(
            "Verify custody of a published record set from a clone, offline."
        ),
    )
    parser.add_argument("--version", action="version", version=f"receipt {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser(
        "verify",
        help="verify a published corpus against its committed trust anchors",
        description=(
            "Run every offline pass the consumer's committed spec configures, "
            "and print one fail-closed verdict."
        ),
    )
    verify.add_argument(
        "--spec",
        required=True,
        type=pathlib.Path,
        help=(
            "path to the repository's committed verification spec (a short "
            "Python module defining SPEC = receipt.verify.VerificationSpec(...))"
        ),
    )
    verify.add_argument(
        "--root",
        type=pathlib.Path,
        default=None,
        help="repository root to verify (default: the spec's parent repository)",
    )
    verify.add_argument(
        "--base-ref",
        default=None,
        help=(
            "additionally prove no published release object changed since this "
            "git ref (requires git and a repository)"
        ),
    )
    verify.add_argument(
        "--json",
        action="store_true",
        help="emit the verdict as JSON instead of text",
    )
    return parser


def _default_root(spec_path: pathlib.Path) -> pathlib.Path:
    """Walk up from the spec to the enclosing repository root."""

    current = spec_path.resolve().parent
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return current


def _format_text(result: VerifyResult) -> str:
    lines: list[str] = []
    lines.append(f"receipt {result.receipt_version} — {result.spec_name}")
    lines.append(f"  root  {result.root}")
    lines.append(f"  spec  {result.spec_path}")
    lines.append(f"        sha256 {result.spec_sha256}")
    lines.append("")

    if result.ok:
        lines.append("ESTABLISHED OFFLINE, FROM THIS CLONE ALONE")
    else:
        lines.append("PASSES")
    for item in result.passes:
        mark = "ok  " if item.ok else "FAIL"
        lines.append(f"  [{mark}] {item.name}")
        if item.ok:
            lines.append(f"         {item.detail}")
        else:
            lines.append(f"         {item.failure}")

    corpus = result.corpus
    if corpus is not None and corpus.gates:
        lines.append("")
        lines.append("DECLARED IN THE WITNESSED JOURNAL — NOT RE-RUN BY THIS COMMAND")
        skipped = [gate for gate in corpus.gates if gate.outcome != "pass"]
        if skipped:
            lines.append(
                f"  {len(skipped)} of {len(corpus.gates)} declared gate(s) did not "
                "pass cleanly; each is marked below."
            )
        for tier in GATE_TIERS:
            gates = corpus.gates_in_tier(tier)
            if not gates:
                continue
            lines.append(f"  {tier}: {TIER_MEANING[tier]}")
            for gate in gates:
                suffix = ""
                if gate.outcome == "waived":
                    waiver = gate.evidence.get("waiverSetSha256", "")
                    suffix = f"  [WAIVED under waiver set {waiver[:16]}…]"
                elif gate.outcome == "not-run":
                    suffix = f"  [DID NOT RUN — {gate.evidence.get('reason', '')}]"
                lines.append(f"    - {gate.gate_id}{suffix}")

    lines.append("")
    if result.ok:
        lines.append("VERDICT: PASS — custody and corpus binding")
        lines.append(
            "  This proves the published rule files are exactly the bytes a "
            "code-pinned"
        )
        lines.append(
            "  producer key signed and two independent RFC 3161 authorities "
            "witnessed,"
        )
        lines.append(
            "  and that nothing in the recorded history was rewritten. It does "
            "NOT prove"
        )
        lines.append(
            "  that any declared gate passed, and it does NOT prove the "
            "encodings are a"
        )
        lines.append("  correct reading of the law.")
    else:
        failure = next((item for item in result.passes if not item.ok), None)
        detail = failure.failure if failure is not None else "unknown failure"
        lines.append(f"VERDICT: FAIL — {failure.name if failure else 'verification'}")
        lines.append(f"  {detail}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "verify":  # pragma: no cover - argparse enforces this
        parser.error(f"unknown command {args.command!r}")

    try:
        spec, spec_sha256 = load_spec(args.spec)
    except VerifySpecError as exc:
        print(f"receipt verify: {exc}", file=sys.stderr)
        return EXIT_USAGE

    root = args.root if args.root is not None else _default_root(args.spec)
    if not root.is_dir():
        print(f"receipt verify: root is not a directory: {root}", file=sys.stderr)
        return EXIT_USAGE

    try:
        result = run_verification(
            root,
            spec,
            spec_path=args.spec.resolve(),
            spec_sha256=spec_sha256,
            base_ref=args.base_ref,
        )
    except Exception as exc:  # noqa: BLE001 - an unhandled error is still a refusal
        print(
            "receipt verify: verification aborted, refusing to return a verdict: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return EXIT_FAIL

    if args.json:
        print(json.dumps(result_to_dict(result), indent=2, sort_keys=True))
    else:
        stream = sys.stdout if result.ok else sys.stderr
        print(_format_text(result), file=stream)
    return EXIT_OK if result.ok else EXIT_FAIL


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
