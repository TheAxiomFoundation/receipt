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

With ``--json``, every exit path after argument parsing prints exactly one
JSON object bearing a ``verdict`` key — a refused spec, an unusable root, an
aborted run, and a result that cannot be rendered all included. A machine
consumer that keys on ``verdict`` therefore fails closed with the command.
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
            "additionally prove every release object present at this git ref "
            "is byte- and mode-identical in the working tree (requires git "
            "and a repository)"
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
        # The witness clause is derived from what was actually verified, not
        # asserted: a spec pinning one anchor must not be described as two.
        witnesses = sorted(result.witness_times())
        count = len(witnesses)
        noun = "authorities" if count != 1 else "authority"
        # Whether a trusted base reference was verified changes what the
        # timing clause may claim: without one, the witnessed times bound
        # only when each recorded prefix existed, not that the history was
        # never rewritten (a producer holding the signing key can regenerate
        # and re-witness a whole chain, and a first-contact check passes).
        history = next(
            (p for p in result.passes if p.name == "history" and p.ok), None
        )
        lines.append("VERDICT: PASS — custody and corpus binding")
        lines.append(
            "  This proves the published rule files are exactly the bytes a "
            "code-pinned"
        )
        lines.append(
            f"  producer key signed, and the {count} pinned RFC 3161 {noun} "
            f"({', '.join(witnesses)})"
        )
        if history is not None:
            lines.append(
                "  witnessed that each recorded prefix existed no later than "
                "those times,"
            )
            # Scoped to what verify_release_history_immutable compares: release
            # objects present at the base ref, byte and mode. Objects added
            # after the base, and any state between then and now, are outside
            # the claim — the wording must not stretch past the check.
            lines.append(
                "  and every release object present at the supplied base "
                "reference is"
            )
            lines.append("  byte- and mode-identical in this tree. It does")
        else:
            lines.append(
                "  witnessed that each recorded prefix existed no later than "
                "those times."
            )
            lines.append(
                "  It does NOT prove the history was never rewritten — a "
                "producer holding"
            )
            lines.append(
                "  the signing key can regenerate and re-witness a whole "
                "chain, and this"
            )
            lines.append(
                "  first-contact check would still pass; supply --base-ref "
                "against a head"
            )
            lines.append("  you recorded earlier to bind against that. It does")
        lines.append(
            "  NOT prove that any declared gate passed, it does NOT prove the "
            "encodings"
        )
        lines.append(
            "  are a correct reading of the law, it does NOT prove this clone "
            "holds the"
        )
        lines.append(
            "  producer's newest release, and it does NOT prove this is the "
            "only history"
        )
        lines.append(
            "  the producer maintains — a stale or equivocated but honestly "
            "witnessed"
        )
        # A base ref binds this clone against a checkpoint the auditor chose;
        # it cannot make this clone the newest or the only history. Freshness
        # and uniqueness have exactly one remedy, so name only that.
        lines.append(
            "  clone also passes. Check freshness and uniqueness by comparing "
            "head"
        )
        lines.append("  digests out of band.")
    else:
        failure = next((item for item in result.passes if not item.ok), None)
        detail = failure.failure if failure is not None else "unknown failure"
        lines.append(f"VERDICT: FAIL — {failure.name if failure else 'verification'}")
        lines.append(f"  {detail}")
    return "\n".join(lines)


def _fail_payload(stage: str, message: str) -> dict[str, object]:
    """A minimal machine verdict for aborts outside a completed verification.

    Built from plain strings only, so its construction cannot itself raise.
    It leads with the same ``verdict`` key as the full payload: a consumer
    keying on that field sees fail-closed behavior on every exit path after
    argument parsing, whether the run refused a spec, aborted mid-pass, or
    could not render its own result.
    """

    return {
        "verdict": "FAIL",
        "stage": stage,
        "failure": message,
        "passesCompleted": [],
    }


def _refuse(as_json: bool, stage: str, message: str, code: int) -> int:
    """Print a refusal, honoring the JSON contract, and return the exit code."""

    print(f"receipt verify: {message}", file=sys.stderr)
    if as_json:
        print(json.dumps(_fail_payload(stage, message), indent=2, sort_keys=True))
    return code


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "verify":  # pragma: no cover - argparse enforces this
        parser.error(f"unknown command {args.command!r}")

    # From here down the contract is: with --json, exactly one JSON object
    # bearing a "verdict" key is printed on every path — spec refusals, root
    # refusals, an aborted run, even a result that cannot be rendered. The
    # only exits without one are argparse's own, before --json is knowable.
    as_json = bool(args.json)

    try:
        spec, spec_sha256 = load_spec(args.spec)
    except VerifySpecError as exc:
        return _refuse(as_json, "spec", str(exc), EXIT_USAGE)
    except Exception as exc:  # noqa: BLE001 - reading the spec is fail-closed too
        return _refuse(
            as_json,
            "spec",
            f"unable to read the spec: {type(exc).__name__}: {exc}",
            EXIT_USAGE,
        )

    try:
        root = args.root if args.root is not None else _default_root(args.spec)
        root_ok = root.is_dir()
    except Exception as exc:  # noqa: BLE001 - resolving the root is fail-closed too
        return _refuse(
            as_json,
            "root",
            f"unable to resolve the root: {type(exc).__name__}: {exc}",
            EXIT_USAGE,
        )
    if not root_ok:
        return _refuse(as_json, "root", f"root is not a directory: {root}", EXIT_USAGE)

    try:
        result = run_verification(
            root,
            spec,
            spec_path=args.spec.resolve(),
            spec_sha256=spec_sha256,
            base_ref=args.base_ref,
        )
    except Exception as exc:  # noqa: BLE001 - an unhandled error is still a refusal
        return _refuse(
            as_json,
            "verification",
            "verification aborted, refusing to return a verdict: "
            f"{type(exc).__name__}: {exc}",
            EXIT_FAIL,
        )

    # A verdict that cannot be rendered is not a deliverable PASS: refuse,
    # even when the passes themselves succeeded.
    if as_json:
        try:
            rendered = json.dumps(result_to_dict(result), indent=2, sort_keys=True)
        except Exception as exc:  # noqa: BLE001 - rendering is inside the contract
            return _refuse(
                as_json,
                "render",
                "verdict could not be rendered; treat the run as unverified: "
                f"{type(exc).__name__}: {exc}",
                EXIT_FAIL,
            )
        print(rendered)
    else:
        try:
            text = _format_text(result)
        except Exception as exc:  # noqa: BLE001 - rendering is inside the contract
            return _refuse(
                False,
                "render",
                "verdict could not be rendered; treat the run as unverified: "
                f"{type(exc).__name__}: {exc}",
                EXIT_FAIL,
            )
        stream = sys.stdout if result.ok else sys.stderr
        print(text, file=stream)
    return EXIT_OK if result.ok else EXIT_FAIL


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
