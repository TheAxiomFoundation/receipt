"""The spanning verification pass: custody, then binding, then declaration.

This is the library half of ``receipt verify``. It composes modules that were
each extracted under their own differential harness — it introduces no new
cryptography and no new trust anchors — and it enforces one rule the individual
modules cannot enforce on their own:

    A gate the command did not re-run is never reported as verified.

The three passes, in the order a skeptic should want them:

1. **Custody** (:mod:`receipt.release_chain`) — the release manifests are
   contiguous from genesis, canonically serialized, hash-linked, signed by the
   Ed25519 key selected by the loaded spec, and witnessed by the anchor set the
   verified tree carries. Those become auditor-owned pins only when the spec's
   source digest was itself pinned. The journal's historical byte prefixes
   match every manifest that ever described them.

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
import tempfile
from contextlib import ExitStack
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
    MAX_JOURNAL_BYTES,
    verify_corpus_binding,
    verify_declarations,
)
from receipt.release_chain import (
    ChainSpec,
    ChainVerification,
    ReleaseChainError,
    _normalized_spec,
    assert_no_redirecting_git_environment,
    verify_release_chain,
    verify_release_history_immutable,
)
from receipt.snapshot import ObjectStoreReport, SnapshotError, TreeSnapshot

#: What each tier means to a third party, in the verdict's own words. Stated
#: once, here, so the CLI cannot drift into a friendlier phrasing.
TIER_MEANING = {
    PUBLIC_TIER: "you can re-run these yourself from public inputs",
    RESTRICTED_TIER: "reproducible only with restricted pinned inputs this "
    "command cannot obtain",
    CI_ATTESTED_TIER: "not reproducible; only the CI run's identity vouches",
}


class VerifySpecError(ValueError):
    """The loaded verification spec is missing, malformed, or not a spec."""


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
    "binding": "binding of the witnessed journal to tree {tree}",
}


@dataclass(frozen=True)
class VerificationSpec:
    """Everything one loaded verification policy binds, in one object.

    A repository publishes exactly one of these in a short module of constants.
    It is the whole configured trust surface: there is nowhere else for an
    anchor to hide. An auditor makes it trusted by reviewing and pinning the
    module's source digest before execution.
    """

    name: str
    chain: ChainSpec
    corpus: CorpusSpec
    anchor_set_sha256: str | None = None
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
        if self.anchor_set_sha256 is not None and (
            type(self.anchor_set_sha256) is not str
            or len(self.anchor_set_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.anchor_set_sha256)
        ):
            raise VerifySpecError(
                "VerificationSpec anchor_set_sha256 must be a lowercase SHA-256 "
                f"digest or None: {self.anchor_set_sha256!r}"
            )
        # The journal the corpus binds IS the state file the chain witnesses.
        # Allowing them to differ would let a repository witness one file and
        # bind another, which is precisely the substitution the chain exists to
        # prevent, so it is not configurable.
        object.__setattr__(self, "journal_relative", self.chain.state_relative)


@dataclass(frozen=True, init=False)
class LoadedSpec:
    """A validated spec together with the exact source bytes that selected it.

    Instances come only from :func:`load_spec`: accepting arbitrary caller-built
    instances would let ``pinned=True`` become an assertion instead of evidence
    that this loader compared the source digest before executing the spec.
    """

    verification: VerificationSpec
    path: pathlib.Path
    sha256: str
    pinned: bool

    def __new__(cls, *args: object, **kwargs: object) -> LoadedSpec:
        del args, kwargs
        raise TypeError("LoadedSpec instances are created by load_spec")


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
    #: The selected, authenticated candidate identity. Both are None only
    #: when snapshot selection itself refused before an identity existed.
    commit: str | None = None
    tree: str | None = None
    object_format: str | None = None
    #: The full object id ``--base-ref`` resolved to, or None when no base ref
    #: was supplied. A ref spelling is not evidence: "HEAD", a branch name, or
    #: a tag names whatever it points at when the command runs, and the same
    #: verdict text is reproducible at a later commit. The commit is.
    base_commit: str | None = None
    base_tree: str | None = None
    name_repertoire: str = "portable"
    object_store: ObjectStoreReport | None = None
    _spec_pinned: bool = field(default=False, repr=False)
    #: Whether the caller asked for whole-store verification. A missing report
    #: on a failed run must not be rendered as "not requested".
    _object_store_requested: bool = field(default=False, repr=False)
    #: Whether custody's anchor-set digest was compared with an auditor-owned
    #: pin. Private because it qualifies a claim rather than adding another
    #: public datum to the result contract.
    _anchor_set_pinned: bool = field(default=False, repr=False)

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
        role: TSA anchor bytes are spec-bound exactly, while producer identity
        is bound by SPKI — a byte-different serialization of the
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


def load_spec(
    spec_path: pathlib.Path, *, expect_sha256: str | None = None
) -> LoadedSpec:
    """Load a consumer spec, optionally requiring its exact source digest.

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
    by construction. When ``expect_sha256`` is supplied, its comparison happens
    immediately after hashing and before either compiling or executing those
    bytes; a mismatched spec therefore has no opportunity to run.
    """

    import types

    if expect_sha256 is not None and (
        type(expect_sha256) is not str
        or len(expect_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expect_sha256)
    ):
        raise VerifySpecError(
            "expected spec SHA-256 must be a lowercase 64-character hex digest"
        )

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
    if expect_sha256 is not None and digest != expect_sha256:
        raise VerifySpecError(
            f"spec {digest} is not the expected spec {expect_sha256}"
        )

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
    loaded = object.__new__(LoadedSpec)
    object.__setattr__(loaded, "verification", candidate)
    object.__setattr__(loaded, "path", spec_path)
    object.__setattr__(loaded, "sha256", digest)
    object.__setattr__(loaded, "pinned", expect_sha256 is not None)
    return loaded


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
        f"against the loaded spec ({', '.join(counts)}); none re-run here"
    )


def run_verification(
    root: pathlib.Path,
    spec: LoadedSpec,
    *,
    base_ref: str | None = None,
    commit: str = "HEAD",
    expect_commit: str | None = None,
    expect_tree: str | None = None,
    expect_anchor_set: str | None = None,
    verify_objects: bool = False,
) -> VerifyResult:
    """Verify one authenticated commit, stopping at the first failed pass.

    Verification failures are returned, never raised. Entry-contract
    violations are different: comparing history without pinning the candidate,
    presenting an anchor pin without first pinning the executable spec, or
    declaring two name repertoires raises :class:`ValueError`.

    The 0.5.2 refusal of redirecting Git environment variables is deliberately
    retained before snapshot selection. The underlying ``TreeSnapshot`` reader
    remains invariant under those variables through its frozen Git environment
    and explicit repository selection.
    """

    if not isinstance(spec, LoadedSpec):
        raise TypeError("spec must be a LoadedSpec returned by load_spec")
    if base_ref is not None and expect_commit is None:
        raise ValueError("base_ref requires expect_commit")

    verification_spec = spec.verification
    chain_repertoire = verification_spec.chain.name_repertoire
    # Compatibility for the short merge window in which Lane D's defaulted
    # CorpusSpec field may not yet be present. Lane B removes this getattr.
    corpus_repertoire = getattr(
        verification_spec.corpus, "name_repertoire", "portable"
    )
    if chain_repertoire != corpus_repertoire:
        raise ValueError("spec declares two name repertoires")

    spec_anchor_pin = verification_spec.anchor_set_sha256
    if expect_anchor_set is not None and not spec.pinned:
        raise ValueError("an anchor pin requires a pinned spec")
    if expect_anchor_set is not None and (
        type(expect_anchor_set) is not str
        or len(expect_anchor_set) != 64
        or any(character not in "0123456789abcdef" for character in expect_anchor_set)
    ):
        raise ValueError(
            "expected anchor-set SHA-256 must be a lowercase 64-character hex digest"
        )
    anchor_pin_conflict = (
        expect_anchor_set is not None
        and spec_anchor_pin is not None
        and expect_anchor_set != spec_anchor_pin
    )
    anchor_pin = (
        expect_anchor_set if expect_anchor_set is not None else spec_anchor_pin
    ) if spec.pinned else None

    root = root.resolve()
    passes: list[PassResult] = []
    chain: ChainVerification | None = None
    corpus: CorpusVerification | None = None
    candidate_commit: str | None = None
    candidate_tree: str | None = None
    object_format: str | None = None
    base_commit: str | None = None
    base_tree: str | None = None
    object_store: ObjectStoreReport | None = None

    def result(*, incomplete: str | None = None) -> VerifyResult:
        items = list(passes)
        if incomplete is not None:
            items.append(PassResult(incomplete, False, "", "not reached"))
        return VerifyResult(
            spec_name=verification_spec.name,
            spec_path=spec.path,
            spec_sha256=spec.sha256,
            root=root,
            receipt_version=__version__,
            producer_spki_sha256=verification_spec.chain.producer_spki_sha256,
            passes=tuple(items),
            chain=chain,
            corpus=corpus,
            commit=candidate_commit,
            tree=candidate_tree,
            object_format=object_format,
            base_commit=base_commit,
            base_tree=base_tree,
            name_repertoire=chain_repertoire,
            object_store=object_store,
            _spec_pinned=spec.pinned,
            _object_store_requested=verify_objects,
            _anchor_set_pinned=anchor_pin is not None,
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
    def failed(
        name: str,
        exc: BaseException,
        expected: type[Exception] | tuple[type[Exception], ...],
    ) -> str:
        del name
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

    if anchor_pin_conflict:
        passes.append(
            PassResult(
                "custody",
                False,
                "",
                "anchor pins disagree: "
                f"command expects {expect_anchor_set}, spec expects {spec_anchor_pin}",
            )
        )
        return result(incomplete="binding")

    phase = "custody"
    try:
        # A single normalized ChainSpec instance is shared by the pre-crypto
        # anchor digest and the directory verifier. Stateful PathLike values
        # cannot answer those two consumers with different spellings.
        normalized_chain = _normalized_spec(verification_spec.chain)
        selected = TreeSnapshot.select(
            root,
            commit,
            verify_objects=verify_objects,
            expect_commit=expect_commit,
            expect_tree=expect_tree,
        )
        candidate_commit = selected.commit
        candidate_tree = selected.tree
        object_format = selected.object_format

        with ExitStack() as stack:
            candidate = stack.enter_context(selected)
            base: TreeSnapshot | None = None
            if base_ref is not None:
                phase = "history"
                base = stack.enter_context(TreeSnapshot.select(root, base_ref))
                base_commit = base.commit
                base_tree = base.tree
                candidate.assert_ancestor(base)

            # Object-store verification is about the primary store, not one
            # logical pass, and runs over exactly the already-resolved heads.
            if verify_objects:
                phase = "custody"
                heads = (
                    (candidate.commit,)
                    if base is None
                    else (candidate.commit, base.commit)
                )
                object_store = candidate.verify_object_store(heads)

            # Pass 0 (optional): history comparison consumes tree entries only.
            if base is not None:
                phase = "history"
                verify_release_history_immutable(
                    normalized_chain,
                    candidate=candidate,
                    base=base,
                )
                passes.append(
                    PassResult(
                        "history",
                        True,
                        f"every release object present at {base_ref} "
                        f"({base.commit}) is byte- and mode-identical in tree "
                        f"{candidate.tree[:12]}",
                    )
                )

            phase = "custody"

            def state_blob(relative: pathlib.PurePosixPath) -> bytes:
                display = relative.as_posix()
                try:
                    entry = candidate.entry(display)
                except SnapshotError as exc:
                    if str(exc) == f"tree entry does not exist: {display}":
                        raise ReleaseChainError(
                            f"state file is missing or not a regular file: {display}"
                        ) from exc
                    raise
                if entry.mode == "120000":
                    raise ReleaseChainError(f"state file is a symlink: {display}")
                if entry.mode not in {"100644", "100755"}:
                    raise ReleaseChainError(
                        f"state file is not a regular file: {display}"
                    )
                return candidate.blob(entry, limit=MAX_JOURNAL_BYTES)

            journal_bytes = state_blob(verification_spec.journal_relative)
            prefix_bytes = state_blob(normalized_chain.prefix_relative)
            state_bytes = {
                verification_spec.journal_relative.as_posix(): journal_bytes,
                normalized_chain.prefix_relative.as_posix(): prefix_bytes,
            }
            prefixes = (
                normalized_chain.release_root_relative,
                normalized_chain.manifest_relative,
                normalized_chain.state_relative,
                normalized_chain.prefix_relative,
                normalized_chain.anchor_relative,
            )
            with tempfile.TemporaryDirectory(
                prefix="receipt-verification-materialization-"
            ) as directory:
                with candidate.materialize(
                    prefixes,
                    pathlib.Path(directory),
                    repertoire=chain_repertoire,
                ) as materialized:
                    candidate.refuse_transforming_attributes(
                        materialized.entries.values()
                    )
                    materialized_anchor_set = materialized.anchor_set_sha256(
                        normalized_chain
                    )
                    if (
                        anchor_pin is not None
                        and materialized_anchor_set != anchor_pin
                    ):
                        raise ReleaseChainError(
                            f"anchor set {materialized_anchor_set} is not the "
                            f"pinned anchor set {anchor_pin}"
                        )
                    chain = verify_release_chain(
                        materialized.path,
                        spec=normalized_chain,
                        require_chain=True,
                        verify_state=True,
                        enforce_production_pins=True,
                        compute_anchor_set_digest=True,
                        state_bytes=state_bytes,
                    )
                    if chain.anchor_set_sha256 != materialized_anchor_set:
                        raise ReleaseChainError(
                            f"verified anchor set {chain.anchor_set_sha256} is not "
                            f"the materialized anchor set {materialized_anchor_set}"
                        )
                    custody_detail = _custody_detail(chain, verification_spec)
            passes.append(PassResult("custody", True, custody_detail))

            # Pass 2: the immutable journal blob already supplied to custody is
            # handed to binding. Its SHA-256 is repeated against the witnessed
            # value so the composition remains explicit and independently
            # reviewable even though an immutable snapshot cannot race itself.
            phase = "binding"
            head = chain.head
            assert head is not None
            witnessed_digest = head.manifest["state"]["jsonlSha256"]
            actual_digest = hashlib.sha256(journal_bytes).hexdigest()
            if actual_digest != witnessed_digest:
                raise CorpusError(
                    "journal bytes do not match the custody pass: "
                    f"{actual_digest} != witnessed {witnessed_digest}"
                )
            corpus = verify_corpus_binding(
                candidate,
                journal_bytes,
                spec=verification_spec.corpus,
            )
            binding_detail = _binding_detail(corpus)
            passes.append(PassResult("binding", True, binding_detail))

            # Pass 3: declarations are claims recorded in the authenticated
            # journal, not gates this command re-runs.
            phase = "declaration"
            verify_declarations(corpus, spec=verification_spec.corpus)
            declaration_detail = _declaration_detail(corpus)
            passes.append(PassResult("declaration", True, declaration_detail))
            phase = "finalize"
    except KeyboardInterrupt:  # the operator's interrupt, never a verdict
        raise
    except BaseException as exc:  # noqa: BLE001 - every other raise is a FAIL
        if phase == "history":
            passes.append(
                PassResult(
                    "history",
                    False,
                    "",
                    "release history is not immutable: "
                    f"{failed('history', exc, (ReleaseChainError, SnapshotError))}",
                )
            )
            return result(incomplete="custody")
        if phase in {"custody", "finalize"}:
            # A close-time repository re-audit invalidates every tree-derived
            # pass even if its body happened to finish first.
            passes[:] = [item for item in passes if item.name == "history"]
            chain = None
            corpus = None
            passes.append(
                PassResult(
                    "custody",
                    False,
                    "",
                    failed("custody", exc, (ReleaseChainError, SnapshotError)),
                )
            )
            return result(incomplete="binding")
        if phase == "binding":
            corpus = None
            passes.append(
                PassResult(
                    "binding",
                    False,
                    "",
                    failed("binding", exc, (CorpusError, SnapshotError)),
                )
            )
            return result(incomplete="declaration")
        assert phase == "declaration"
        passes.append(
            PassResult(
                "declaration",
                False,
                "",
                failed("declaration", exc, CorpusError),
            )
        )
        return result()
    return result()


def result_to_dict(result: VerifyResult) -> dict[str, Any]:
    """Machine-readable verdict, including the text's three object-store states.

    ``objectStore: null`` means verification was not requested, a requested
    run that did not complete carries ``requested: true`` with a null report,
    and a completed run carries the measured report.
    """

    def established_claim(item: PassResult) -> str:
        if item.name == "binding":
            assert result.tree is not None
            return _PASS_CLAIMS["binding"].format(tree=result.tree[:12])
        if item.name == "custody" and not result._anchor_set_pinned:
            anchor_set = result.anchor_set_sha256
            assert anchor_set is not None
            return (
                f"custody under the anchor set {anchor_set} the verified tree "
                "carries"
            )
        return _PASS_CLAIMS[item.name]

    base: dict[str, str] | None = None
    if result.base_commit is not None:
        assert result.base_tree is not None
        base = {"commit": result.base_commit, "tree": result.base_tree}
    object_store: dict[str, Any] | None = None
    if result.object_store is not None:
        object_store = {
            "objects": result.object_store.objects,
            "storeKiB": result.object_store.store_kib,
            "seconds": result.object_store.seconds,
        }
    elif result._object_store_requested:
        object_store = {"requested": True, "report": None}

    not_established = [
        "that any declared gate actually passed",
        "that the encoded rules are a correct reading of the law",
        "that this clone holds the producer's newest release "
        "(--base-ref only bounds staleness against a head the auditor "
        "recorded; newest needs an out-of-band comparison)",
        "that this is the only history the producer maintains "
        "(equivocation is undetectable from a single clone; compare "
        "head digests out of band)",
        "that the files in any checkout equal the verified tree",
    ]
    if not result._anchor_set_pinned:
        not_established.append("that the anchor set is one the auditor trusts")
    if not result._spec_pinned:
        not_established.append("that the spec's code was trusted")

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
            "pinned": result._spec_pinned,
        },
        "root": str(result.root),
        "commit": result.commit,
        "tree": result.tree,
        "objectFormat": result.object_format,
        "base": base,
        "nameRepertoire": result.name_repertoire,
        "objectStore": object_store,
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
                established_claim(item)
                for item in result.passes
                if item.ok and item.name in _PASS_CLAIMS
            ],
            "notEstablished": not_established,
        },
    }
    if result.base_commit is not None:
        # The object id the comparison actually ran against. The ref spelling
        # stays in the history pass detail beside it; only one of the two is
        # evidence a reader can re-check.
        payload["history"] = {
            "baseCommit": result.base_commit,
            "baseTree": result.base_tree,
        }
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
