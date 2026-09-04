"""The spanning verification pass: custody, then binding, then declaration.

This is the library half of ``receipt verify``. It composes modules that were
each extracted under their own differential harness — it introduces no new
cryptography and no new trust anchors — and it enforces one rule the individual
modules cannot enforce on their own:

    A gate the command did not re-run is never reported as verified.

The three passes, in the order a skeptic should want them:

1. **Custody** (:mod:`receipt.release_chain`) — the release manifests are
   contiguous from genesis, canonically serialized, hash-linked, signed by the
   Ed25519 key whose SPKI is pinned in the consumer's committed spec, and
   witnessed by the consumer's configured RFC 3161 anchor set. The journal's
   historical byte prefixes match every manifest that ever described them.

2. **Binding** (:mod:`receipt.corpus`) — the journal the chain just proved
   custody of describes *this* tree, closed-world: every content file bound,
   every bound file present, every digest exact.

3. **Declaration** — the gates recorded in the journal are separated by
   reproducibility tier and reported as claims, per axiom-encode#1192
   requirement 6. Passing this pass means the declarations are well formed and
   cover what the consumer's spec requires. It does not mean the gates passed.

A verdict is fail-closed in the strict sense: it is ``PASS`` only if passes 1
and 2 both completed without raising and pass 3 found every required
declaration. Anything else — including an exception this module did not
anticipate, and including ``SystemExit``, which is not an ``Exception`` and
once unwound straight out of the interpreter from inside a consumer's spec —
is ``FAIL``. Only ``KeyboardInterrupt`` passes through: the operator
interrupted the run, and that is not a verdict about the corpus.
"""

from __future__ import annotations

import hashlib
import pathlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from receipt import __version__
from receipt.corpus import (
    CI_ATTESTED_TIER,
    GATE_TIERS,
    PUBLIC_TIER,
    RESTRICTED_TIER,
    CorpusError,
    CorpusSpec,
    CorpusVerification,
    verify_corpus_binding,
    verify_declarations,
)
from receipt.release_chain import (
    ChainSpec,
    ChainVerification,
    ReleaseChainError,
    assert_no_redirecting_git_environment,
    verify_release_chain,
    verify_release_history_immutable,
)

#: What each tier means to a third party, in the verdict's own words. Stated
#: once, here, so the CLI cannot drift into a friendlier phrasing.
TIER_MEANING = {
    PUBLIC_TIER: "you can re-run these yourself from public inputs",
    RESTRICTED_TIER: "reproducible only with restricted pinned inputs this "
    "command cannot obtain",
    CI_ATTESTED_TIER: "not reproducible; only the CI run's identity vouches",
}


class VerifySpecError(ValueError):
    """The consumer's committed spec is missing, malformed, or not a spec."""


def _exception_detail(exc: BaseException) -> str:
    """Quote a failure, naming anything that is not an ordinary exception.

    ``str(SystemExit(0))`` is the bare string ``"0"``, which inside a refusal
    reads as a stray token rather than as a spec that tried to exit the
    interpreter. Ordinary exceptions already carry their own message and are
    quoted unchanged.
    """

    if isinstance(exc, Exception):
        return str(exc)
    return f"{type(exc).__name__}: {exc}"


#: The passes a PASS verdict is made of. A verdict is a claim about custody,
#: binding, and declaration; a result missing any of them has no verdict to
#: report, whatever else it recorded. Named here so ``ok`` states the
#: requirement rather than inferring it from whatever happened to run.
REQUIRED_PASSES = ("custody", "binding", "declaration")

#: What each completed pass establishes, in the verdict's own words. Keyed by
#: pass name so the JSON scope block can be built from actual results.
_PASS_CLAIMS = {
    "history": "that every release object present at the given base ref is "
    "byte- and mode-identical in this tree (objects added after that ref are "
    "outside this claim)",
    "custody": "custody of the release chain",
    "binding": "binding of the witnessed journal to this working tree",
}


@dataclass(frozen=True)
class VerificationSpec:
    """Everything the consumer's committed code pins, in one object.

    A repository publishes exactly one of these, in a short module of
    constants, and an auditor reads it before trusting a verdict produced with
    it. It is the whole trust configuration: there is nowhere else for an
    anchor to hide.
    """

    name: str
    chain: ChainSpec
    corpus: CorpusSpec
    # Derived, never supplied: init=False so a consumer cannot even appear to
    # set it. See __post_init__ for why it is not a choice.
    journal_relative: pathlib.PurePosixPath = field(init=False, default=None)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name:
            raise VerifySpecError("VerificationSpec name must be a non-empty string")
        if not isinstance(self.chain, ChainSpec):
            raise VerifySpecError("VerificationSpec chain must be a ChainSpec")
        if not isinstance(self.corpus, CorpusSpec):
            raise VerifySpecError("VerificationSpec corpus must be a CorpusSpec")
        # The journal the corpus binds IS the state file the chain witnesses.
        # Allowing them to differ would let a repository witness one file and
        # bind another, which is precisely the substitution the chain exists to
        # prevent, so it is not configurable.
        object.__setattr__(self, "journal_relative", self.chain.state_relative)


@dataclass(frozen=True)
class PassResult:
    name: str
    ok: bool
    detail: str
    failure: str | None = None


@dataclass(frozen=True)
class VerifyResult:
    spec_name: str
    spec_path: pathlib.Path
    spec_sha256: str
    root: pathlib.Path
    receipt_version: str
    producer_spki_sha256: str
    passes: tuple[PassResult, ...]
    chain: ChainVerification | None
    corpus: CorpusVerification | None
    #: The full object id ``--base-ref`` resolved to, or None when no base ref
    #: was supplied. A ref spelling is not evidence: "HEAD", a branch name, or
    #: a tag names whatever it points at when the command runs, and the same
    #: verdict text is reproducible at a later commit. The commit is.
    base_commit: str | None = None

    @property
    def ok(self) -> bool:
        """Every recorded pass succeeded, and the three that make a verdict ran.

        ``all()`` on its own is vacuously true. A result carrying no passes —
        a run that fell over before reaching the first one, or a result built
        by a caller composing this library — reported PASS, and the command
        printed "ESTABLISHED OFFLINE, FROM THIS CLONE ALONE" and exited 0 over
        an empty list of passes. Absence of a failure is not the same as
        presence of a verdict, so the required passes are named and checked.
        """

        completed = {item.name for item in self.passes if item.ok}
        return all(item.ok for item in self.passes) and completed.issuperset(
            REQUIRED_PASSES
        )

    @property
    def head_name(self) -> str | None:
        if self.chain is None or self.chain.head is None:
            return None
        return self.chain.head.path.name

    @property
    def anchor_set_sha256(self) -> str | None:
        """One digest naming the anchor bytes custody consumed.

        Captured at the read sites signature and receipt verification used
        (OpenSSL is fed a snapshot of those exact bytes), under this
        command's unconditional production pins. Pin semantics differ by
        role: TSA anchor bytes are code-pinned exactly, while producer
        identity is pinned by SPKI — a byte-different serialization of the
        same producer key verifies and is recorded at its own digest here.
        None unless custody completed successfully.
        """
        if self.chain is None:
            return None
        return self.chain.anchor_set_sha256

    @property
    def anchor_file_sha256s(self) -> dict[str, str]:
        """The per-file digests behind anchor_set_sha256, keyed by the
        spec's configured filename strings; empty unless custody completed
        successfully."""
        if self.chain is None:
            return {}
        return dict(self.chain.anchor_file_sha256s)

    def witness_times(self) -> dict[str, datetime]:
        if self.chain is None or self.chain.head is None:
            return {}
        return dict(self.chain.head.receipt_times)


def load_spec(spec_path: pathlib.Path) -> tuple[VerificationSpec, str]:
    """Load the consumer's committed spec module and return it with its digest.

    The spec is Python because the package's trust anchors are Python objects;
    it is expected to be a short module of constants. Executing it is a
    deliberate part of the model — an auditor is verifying a repository they
    have already cloned, and the spec's own SHA-256 is returned so the exact
    configuration a verdict was produced under can be quoted and re-pinned.

    Trust direction, stated plainly: a spec committed in the *producer's*
    repository is the producer's proposal, not the auditor's trust root.
    Verified against a producer-shipped spec as found, a verdict establishes
    only internal consistency with a policy the producer chose. For independent
    custody the auditor reads the spec once, out of band, and pins it — at
    minimum the ``spec_sha256`` this function returns — in the auditor's own
    records, after which every later verdict is against anchors the producer
    cannot silently swap. Reading the spec is part of that one-time review;
    a future inert, schema-validated spec format would remove even the need to
    execute it, and is tracked as follow-up work.

    The path's final component is required to be a regular file, not a
    symlink to one, checked as supplied rather than after resolution: a link
    can be repointed at other bytes without the path the auditor pinned
    changing at all. Parent components are not walked. An absolute path
    legitimately crosses ambient links (``/tmp`` on macOS), and the
    component walk the anchor check does runs under a resolved root, which a
    spec path does not have; a symlinked parent of the spec is therefore not
    caught here, and the same final-component rule governs every other read
    in the package.

    The source is read once and compiled from those exact bytes, deliberately
    bypassing the import system. Going through ``importlib`` would consult
    ``__pycache__``, whose staleness check is (source mtime, source size) at
    one-second granularity — so an edited spec restored within the same second,
    to a file of the same length, keeps executing the edited bytecode. The
    digest reported beside the verdict would then describe a file that was not
    the one used to verify. Compiling the hashed bytes makes the two identical
    by construction.
    """

    import types

    # Before resolving, deliberately. Every other read in this package refuses
    # a symlink in the final component — manifests, receipts, anchors, the
    # witnessed journal — and the
    # spec is the trust configuration itself, so it gets the same treatment.
    # The check ran after ``resolve()``, which follows every link on the way,
    # so nothing was ever left for it to catch. A symlink also breaks the one
    # thing an auditor pins: they read the spec out of band and record its
    # digest against a path, and the link can be repointed at other bytes
    # afterwards without that path changing at all.
    if spec_path.is_symlink():
        raise VerifySpecError(
            f"spec is a symlink; supply the regular file's path: {spec_path}"
        )
    spec_path = spec_path.resolve()
    if spec_path.is_symlink() or not spec_path.is_file():
        raise VerifySpecError(f"spec is missing or not a regular file: {spec_path}")
    source = spec_path.read_bytes()
    digest = hashlib.sha256(source).hexdigest()

    module = types.ModuleType("_receipt_consumer_spec")
    module.__file__ = str(spec_path)
    try:
        code = compile(source, str(spec_path), "exec")
        exec(code, module.__dict__)  # noqa: S102 - the audited repo's own pins
    except KeyboardInterrupt:  # the operator's interrupt, never a verdict
        raise
    except BaseException as exc:  # noqa: BLE001 - any failure here is fail-closed
        # BaseException deliberately, not Exception. A spec containing
        # ``raise SystemExit(0)`` unwound straight through an Exception-only
        # boundary, past every pass below, and out of the interpreter with
        # status 0 and no verdict printed at all — the producer's own spec
        # choosing the command's exit code. SystemExit and GeneratorExit are
        # load failures like any other; only the operator's interrupt is
        # allowed through, because it is not the spec's to report.
        raise VerifySpecError(
            f"spec module raised on load: {spec_path}: {_exception_detail(exc)}"
        ) from exc

    candidate = getattr(module, "SPEC", None)
    if candidate is None:
        raise VerifySpecError(
            f"spec module does not define SPEC: {spec_path}"
        )
    if not isinstance(candidate, VerificationSpec):
        raise VerifySpecError(
            f"SPEC is {type(candidate).__name__}, not a receipt.verify."
            f"VerificationSpec: {spec_path}"
        )
    return candidate, digest


def _witness_time(value: datetime) -> str:
    """Render a witnessed genTime without discarding what the token signed.

    An RFC 3161 authority may sign a fractional genTime, and whole-second
    formatting printed a token witnessed at ``…:59.750000Z`` as ``…:59Z`` —
    an instant strictly earlier than the one the receipt carries, quoted in a
    verdict as though it were exact. Microseconds are printed whenever there
    are any; when there are none they are omitted, so the ordinary case reads
    as the authority wrote it.
    """

    if value.microsecond:
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _custody_detail(verification: ChainVerification, spec: VerificationSpec) -> str:
    head = verification.head
    assert head is not None
    witnesses = " · ".join(
        f"{anchor} {_witness_time(value)}"
        for anchor, value in sorted(head.receipt_times.items())
    )
    anchor_set = verification.anchor_set_sha256
    assert anchor_set is not None
    return (
        f"{len(verification.releases)} release(s), HEAD {head.path.name}; "
        # The filename carries only the first 16 hex of the head manifest's
        # digest, and that digest is exactly the value an auditor compares out
        # of band — freshness and uniqueness are the two things this command
        # states it cannot establish from one clone, and comparing head
        # digests is the remedy it names for both. A prefix is not quotable
        # evidence for that comparison, so the full digest gets its own
        # segment beside the filename an auditor can find on disk.
        f"head {head.sha256}; "
        f"producer SPKI {spec.chain.producer_spki_sha256[:16]}…; "
        # Full digest, deliberately: the anchor-set digest exists so an
        # assessment can quote it from the verdict alone, and unlike the
        # SPKI it is pinned nowhere else. A prefix would not be quotable
        # evidence.
        f"anchor set {anchor_set}; "
        f"witnesses {witnesses}"
    )


def _binding_detail(verification: CorpusVerification) -> str:
    removed = len(verification.removed_paths)
    removed_text = f", {removed} superseded-removed" if removed else ""
    return (
        f"{len(verification.content)} content file(s) and "
        f"{len(verification.attested)} attested file(s) match the witnessed "
        f"journal exactly, closed-world{removed_text}"
    )


def _declaration_detail(verification: CorpusVerification) -> str:
    if not verification.gates:
        return "no gate declarations in the journal"
    counts = []
    for tier in GATE_TIERS:
        gates = verification.gates_in_tier(tier)
        if gates:
            counts.append(f"{len(gates)} {tier}")
    return (
        f"{len(verification.gates)} gate declaration(s) well formed and complete "
        f"against the pinned spec ({', '.join(counts)}); none re-run here"
    )


def run_verification(
    root: pathlib.Path,
    spec: VerificationSpec,
    *,
    spec_path: pathlib.Path,
    spec_sha256: str,
    base_ref: str | None = None,
) -> VerifyResult:
    """Run every pass, stopping at the first failure. Never raises on a
    verification failure — the failure is the return value."""

    root = root.resolve()
    passes: list[PassResult] = []
    chain: ChainVerification | None = None
    corpus: CorpusVerification | None = None
    base_commit: str | None = None

    def result(*, incomplete: str | None = None) -> VerifyResult:
        items = list(passes)
        if incomplete is not None:
            items.append(PassResult(incomplete, False, "", "not reached"))
        return VerifyResult(
            spec_name=spec.name,
            spec_path=spec_path,
            spec_sha256=spec_sha256,
            root=root,
            receipt_version=__version__,
            producer_spki_sha256=spec.chain.producer_spki_sha256,
            passes=tuple(items),
            chain=chain,
            corpus=corpus,
            base_commit=base_commit,
        )

    # Every pass — the verification call AND the detail builder that reports
    # it — runs inside a boundary that converts *any* raise, expected or not,
    # into a failed pass. The documented contract is that a verification
    # failure is the return value and never an escaping exception (so a --json
    # consumer always receives a {"verdict": "FAIL"} object); an unforeseen
    # exception here would otherwise leave the CLI to exit 1 with no verdict at
    # all. The boundaries below catch BaseException rather than Exception,
    # because SystemExit is neither: raised anywhere under a pass it unwound
    # past an Exception-only boundary and out of the interpreter, choosing the
    # command's exit status with no verdict printed. KeyboardInterrupt alone is
    # re-raised — it is the operator's, not the verification's, to report.
    # Expected domain errors carry their own message; anything else names its
    # type so the surprise is legible.
    def failed(name: str, exc: BaseException, expected: type[Exception]) -> str:
        if isinstance(exc, expected):
            return str(exc)
        return f"{type(exc).__name__}: {exc}"

    # Before any pass runs git: an environment that would redirect git's reads
    # is refused here rather than met by the custody pass after the optional
    # history pass has already resolved a base and printed an OID from
    # whichever repository the environment pointed at (peer review of the
    # 0.5.2 release PR). It is reported as the custody pass's refusal, in that
    # pass's own words, so the verdict reads the same with or without
    # ``--base-ref``.
    try:
        assert_no_redirecting_git_environment()
    except KeyboardInterrupt:  # the operator's interrupt, never a verdict
        raise
    except BaseException as exc:  # noqa: BLE001 - any raise is a FAIL verdict
        passes.append(
            PassResult("custody", False, "", failed("custody", exc, ReleaseChainError))
        )
        return result(incomplete="binding")

    # Pass 0 (optional): the published history is immutable relative to a base
    # git ref. Needs git and a repository; requested explicitly, never implied.
    if base_ref is not None:
        try:
            # The commit the ref resolved to, from the one resolution the
            # comparison itself used. Quoting only the spelling left the
            # verdict unfalsifiable: "HEAD", a branch, or a tag names whatever
            # it pointed at while the command ran, so the same sentence is
            # reproducible at a different base later, and a reader cannot tell
            # which snapshot was compared. The object id is the evidence.
            base_commit, _, _ = verify_release_history_immutable(
                root, base_ref, spec=spec.chain
            )
            history_detail = (
                f"every release object present at {base_ref} ({base_commit}) "
                "is byte- and mode-identical in this tree"
            )
        except KeyboardInterrupt:  # the operator's interrupt, never a verdict
            raise
        except BaseException as exc:  # noqa: BLE001 - any raise is a FAIL verdict
            passes.append(
                PassResult(
                    "history",
                    False,
                    "",
                    f"release history is not immutable: "
                    f"{failed('history', exc, ReleaseChainError)}",
                )
            )
            return result(incomplete="custody")
        passes.append(PassResult("history", True, history_detail))

    # Pass 1: custody.
    try:
        chain = verify_release_chain(
            root,
            spec=spec.chain,
            require_chain=True,
            verify_state=True,
            # Never inferred: the spanning verifier exists for outside
            # auditors, and its pins are on unconditionally regardless of
            # how the anchor path resolves on this machine.
            enforce_production_pins=True,
            # The verdict names the anchor bytes this run consumed, so an
            # auditor can confirm from the verdict alone which trust
            # material was in force (receipt#24).
            compute_anchor_set_digest=True,
        )
        custody_detail = _custody_detail(chain, spec)
    except KeyboardInterrupt:  # the operator's interrupt, never a verdict
        raise
    except BaseException as exc:  # noqa: BLE001 - any raise is a FAIL verdict
        passes.append(
            PassResult("custody", False, "", failed("custody", exc, ReleaseChainError))
        )
        return result(incomplete="binding")
    passes.append(PassResult("custody", True, custody_detail))

    # Pass 2: binding. Read the journal once, here, and hand the same bytes to
    # the binding pass that the custody pass just proved the digest of.
    journal_path = root / spec.journal_relative
    try:
        if journal_path.is_symlink() or not journal_path.is_file():
            raise CorpusError(
                f"witnessed journal is missing or not a regular file: "
                f"{spec.journal_relative}"
            )
        journal_bytes = journal_path.read_bytes()
        head = chain.head
        assert head is not None
        witnessed_digest = head.manifest["state"]["jsonlSha256"]
        actual_digest = hashlib.sha256(journal_bytes).hexdigest()
        if actual_digest != witnessed_digest:
            # verify_release_chain already proved this for the bytes it read;
            # re-proving it for the bytes THIS pass read closes the window
            # between the two reads.
            raise CorpusError(
                "journal bytes changed between the custody and binding passes: "
                f"{actual_digest} != witnessed {witnessed_digest}"
            )
        corpus = verify_corpus_binding(root, journal_bytes, spec=spec.corpus)
        binding_detail = _binding_detail(corpus)
    except KeyboardInterrupt:  # the operator's interrupt, never a verdict
        raise
    except BaseException as exc:  # noqa: BLE001 - any raise is a FAIL verdict
        passes.append(
            PassResult("binding", False, "", failed("binding", exc, CorpusError))
        )
        return result(incomplete="declaration")
    passes.append(PassResult("binding", True, binding_detail))

    # Pass 3: declaration completeness. Row-level tier and outcome validity was
    # enforced during parsing; this checks the journal covers every gate the
    # consumer requires, and records what was declared so the verdict can
    # report it without ever claiming it ran.
    try:
        verify_declarations(corpus, spec=spec.corpus)
        declaration_detail = _declaration_detail(corpus)
    except KeyboardInterrupt:  # the operator's interrupt, never a verdict
        raise
    except BaseException as exc:  # noqa: BLE001 - any raise is a FAIL verdict
        passes.append(
            PassResult("declaration", False, "", failed("declaration", exc, CorpusError))
        )
        return result()
    passes.append(PassResult("declaration", True, declaration_detail))
    return result()


def result_to_dict(result: VerifyResult) -> dict[str, Any]:
    """Machine-readable verdict. Mirrors the text exactly, including its limits."""

    payload: dict[str, Any] = {
        "verdict": "PASS" if result.ok else "FAIL",
        # Named for what it is: passes that completed. "verifiedOffline" would
        # invite a reader to hear "the gates were verified", which is the one
        # thing this command never does.
        "passesCompleted": [item.name for item in result.passes if item.ok],
        "spec": {
            "name": result.spec_name,
            "path": str(result.spec_path),
            "sha256": result.spec_sha256,
        },
        "root": str(result.root),
        "receiptVersion": result.receipt_version,
        "passes": [
            {
                "name": item.name,
                "ok": item.ok,
                "detail": item.detail,
                "failure": item.failure,
            }
            for item in result.passes
        ],
        "scope": {
            # Built from the passes that actually completed — a FAIL run must
            # not carry a field named "established" listing things it did not
            # establish (cross-family review finding).
            "established": [
                _PASS_CLAIMS[item.name]
                for item in result.passes
                if item.ok and item.name in _PASS_CLAIMS
            ],
            "notEstablished": [
                "that any declared gate actually passed",
                "that the encoded rules are a correct reading of the law",
                "that this clone holds the producer's newest release "
                "(--base-ref only bounds staleness against a head the auditor "
                "recorded; newest needs an out-of-band comparison)",
                "that this is the only history the producer maintains "
                "(equivocation is undetectable from a single clone; compare "
                "head digests out of band)",
            ],
        },
    }
    if result.base_commit is not None:
        # The object id the comparison actually ran against. The ref spelling
        # stays in the history pass detail beside it; only one of the two is
        # evidence a reader can re-check.
        payload["history"] = {"baseCommit": result.base_commit}
    if result.chain is not None and result.chain.head is not None:
        payload["chain"] = {
            "releases": len(result.chain.releases),
            "head": result.chain.head.path.name,
            "headSha256": result.chain.head.sha256,
            "producerSpkiSha256": result.producer_spki_sha256,
            # Which anchor bytes this run consumed, from the verdict alone:
            # digests captured at the verification read sites themselves,
            # with the per-file digests behind the combined one (receipt#24).
            "anchorSetSha256": result.chain.anchor_set_sha256,
            "anchorFiles": dict(result.chain.anchor_file_sha256s),
            "witnesses": {
                anchor: _witness_time(value)
                for anchor, value in sorted(result.chain.head.receipt_times.items())
            },
        }
    if result.corpus is not None:
        payload["binding"] = {
            "contentFiles": len(result.corpus.content),
            "attestedFiles": len(result.corpus.attested),
            "removedPaths": list(result.corpus.removed_paths),
        }
        payload["gateDeclarations"] = {
            "reRunByThisCommand": False,
            "byTier": {
                tier: [
                    {
                        "gateId": gate.gate_id,
                        "outcome": gate.outcome,
                        "evidence": dict(gate.evidence),
                    }
                    for gate in result.corpus.gates_in_tier(tier)
                ]
                for tier in GATE_TIERS
                if result.corpus.gates_in_tier(tier)
            },
            "tierMeaning": {
                tier: TIER_MEANING[tier]
                for tier in GATE_TIERS
                if result.corpus.gates_in_tier(tier)
            },
        }
    return payload
