"""Frozen PR1 name helpers: reference only, never used by production.

Copied from f220c77 (PR1 merge). The bodies below remain verbatim so comparisons
exercise the old nested loops independently of the new indexed evaluator.
"""
from __future__ import annotations

import pathlib
from collections.abc import Mapping
from receipt._names import (NamePolicyError, ascii_fold_text, assert_no_merging_entries,
    assert_portable_name, short_name_carries_pinned_suffix, validate_component_text)
from receipt.snapshot import GitEntry, SnapshotError
from receipt.release_chain import ReleaseChainError
from receipt.append_gate import (AppendError, _CandidateTree, _protected_paths,
    _materialization_prefixes)

def _folded_parts(path: str) -> tuple[str, ...]:
    return tuple(ascii_fold_text(component) for component in path.split("/"))


def _screen_protected_tree_names(
    entries: Mapping[str, GitEntry],
    prefixes: tuple[pathlib.PurePosixPath, ...],
    *,
    repertoire: str,
    release_directories: tuple[pathlib.PurePosixPath, ...],
    alias_paths: tuple[str, ...] | None = None,
) -> None:
    """Screen protected listings and ancestor siblings before writing files.

    The authenticated listing includes files and trees, including empty trees.
    Only selected subtrees and the immediate listings of their ancestors are
    screened; a disjoint unused trust subtree is not traversed by this policy.
    The release-suffix screen applies only below release/manifest directories.
    Configured spellings are compared at every depth even without an exact
    counterpart. The append gate supplies its wider ``alias_paths`` policy,
    which also requires every listing component to be foldable.
    """

    selected = tuple(relative.as_posix() for relative in prefixes)
    descendants = tuple(f"{relative}/" for relative in selected)
    ancestors = {
        "/".join(relative.parts[:depth])
        for relative in prefixes
        for depth in range(len(relative.parts))
    }
    by_directory: dict[str, list[str]] = {}
    screened: list[str] = []
    try:
        protected = selected if alias_paths is None else alias_paths
        folded = {path: _folded_parts(path) for path in protected}
        exact = {path: tuple(path.split("/")) for path in protected}
        # Keep the legacy diagnostic's complete non-tree path when present;
        # an empty tree alias is still covered after all non-tree entries.
        for listed in sorted(
            entries, key=lambda path: (entries[path].mode == "040000", path),
        ):
            parts = tuple(listed.split("/"))
            listed_folded = _folded_parts(listed) if alias_paths is not None else ()
            for path in protected:
                for depth in range(1, len(folded[path]) + 1):
                    if len(parts) < depth:
                        break
                    if len(listed_folded) < depth:
                        # Do not fold unused descendants once their ancestor
                        # differs from every selected protected prefix.
                        listed_folded += (ascii_fold_text(parts[depth - 1]),)
                    if listed_folded[:depth] != folded[path][:depth]:
                        break
                    if parts[:depth] == exact[path][:depth]:
                        continue
                    _folded_parts(listed)  # A quoted full path must be strict UTF-8 too.
                    prefix = "/".join(exact[path][:depth])
                    # "index" is retained wording for an authenticated tree entry.
                    raise ReleaseChainError(
                        f"index carries an alias of a protected path: {listed} "
                        f"(for {path} at {prefix})"
                    )
        for relative in sorted(entries):
            directory, _, name = relative.rpartition("/")
            if not (
                directory in ancestors
                or relative in selected
                or relative.startswith(descendants)
            ):
                continue
            ascii_fold_text(name)
            if repertoire == "portable":
                assert_portable_name(name, f"tree entry {relative!r}")
            else:
                validate_component_text(
                    name, repertoire=repertoire, label=f"tree entry {relative!r}"
                )
            by_directory.setdefault(directory, []).append(name)
            screened.append(relative)
        for directory, names in sorted(by_directory.items()):
            assert_no_merging_entries(
                names, repertoire=repertoire,
                label=f"tree directory {directory or '.'!r}",
            )
        if repertoire == "portable":
            suffixes = (".json", ".sig", ".tsr")
            release_prefixes = tuple(f"{path.as_posix()}/" for path in release_directories)
            for relative in screened:
                if not relative.startswith(release_prefixes):
                    continue
                name = relative.rpartition("/")[2]
                if not ascii_fold_text(name).endswith(suffixes) and (
                    short_name_carries_pinned_suffix(name, suffixes)
                ):
                    raise ReleaseChainError(
                        "release root contains an entry whose short-name alias "
                        f"would carry a pinned suffix: {relative}"
                    )
    except NamePolicyError as exc:
        raise ReleaseChainError(str(exc)) from exc

def _screen_candidate_tree_aliases(
    candidate: _CandidateTree,
) -> dict[str, GitEntry]:
    """Screen protected shapes, aliases and names over the complete tree."""

    entries = candidate.snapshot.entries("").as_dict(include_trees=True)
    protected = _protected_paths(candidate)
    for path in protected:
        parts = path.split("/")
        for depth in range(1, len(parts)):
            prefix = "/".join(parts[:depth])
            entry = entries.get(prefix)
            if entry is None or entry.mode == "040000":
                continue
            if entry.mode == "120000":
                raise SnapshotError(f"state path has a symlinked component: {prefix}")
            raise SnapshotError(f"tree path ancestor is not a directory: {prefix}")

    # Gate-only proposals need the same listing screen before their early return.
    try:
        _screen_protected_tree_names(
            entries,
            _materialization_prefixes(candidate),
            repertoire=candidate.spec.chain.name_repertoire,
            release_directories=(
                candidate.spec.chain.release_root_relative,
                candidate.spec.chain.manifest_relative,
            ),
            alias_paths=protected,
        )
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc
    return entries


# PR3a bodies copied verbatim from origin/main before migration.
import tempfile
from receipt.snapshot import TreeSnapshot, TreeListing, _TreeNode, _ListingRecord, _tree_path_decode
from receipt.release_chain import (ChainSpec, ChainVerification, DEFAULT_CLOCK_SKEW_SECONDS,
    _normalized_spec, verify_release_chain, assert_no_redirecting_git_environment)
from receipt.corpus import MAX_JOURNAL_BYTES, CorpusError, verify_corpus_binding, verify_declarations
from receipt.append_gate import _BaseCommit
from contextlib import ExitStack
import hashlib
from receipt import __version__
from receipt.verify import (LoadedSpec, VerifyResult, PassResult, _custody_detail,
    _binding_detail, _declaration_detail)


def entry(self, path: str | bytes) -> GitEntry:
    """Look up one path by its exact component bytes."""

    self._batch()
    parts = self._path_parts(path, allow_empty=False)
    tree_oid = self.tree
    count = [0]
    for index, component in enumerate(parts):
        records = self._tree_object(tree_oid)
        self._charge_walk_records(records, count)
        raw = self._find_raw_entry(records, component)
        if raw is None:
            raise SnapshotError(
                "tree entry does not exist: "
                f"{_tree_path_decode(b'/'.join(parts))}"
            )
        last = index == len(parts) - 1
        if raw.mode != b"160000":
            self._batch().info(raw.oid, role=raw.object_type)
        if last:
            return self._public_entry(parts, raw)
        if raw.mode != b"40000":
            prefix = _tree_path_decode(b"/".join(parts[: index + 1]))
            if raw.mode == b"120000":
                raise SnapshotError(f"state path has a symlinked component: {prefix}")
            raise SnapshotError(f"tree path ancestor is not a directory: {prefix}")
        tree_oid = raw.oid
    raise AssertionError("a non-empty path has at least one component")



def entries(self, prefix: str | bytes = "") -> TreeListing:
    """Walk a subtree into a hierarchical listing under the walk budgets."""

    self._batch()
    parts = self._path_parts(prefix, allow_empty=True)
    if not parts:
        node = self._build_listing(self.tree, depth=0, count=[0])
        return TreeListing(self, (), node)
    tree_oid = self.tree
    count = [0]
    for index, component in enumerate(parts):
        records = self._tree_object(tree_oid)
        self._charge_walk_records(records, count)
        raw = self._find_raw_entry(records, component)
        if raw is None:
            return TreeListing(self, parts, _TreeNode((), None))
        last = index == len(parts) - 1
        if raw.mode != b"160000":
            self._batch().info(raw.oid, role=raw.object_type)
        if last:
            if raw.mode == b"40000":
                node = self._build_listing(
                    raw.oid, depth=len(parts), count=count
                )
                return TreeListing(self, parts, node)
            return TreeListing(
                self,
                parts[:-1],
                _TreeNode((_ListingRecord(raw=raw),), None),
            )
        if raw.mode != b"40000":
            prefix_text = _tree_path_decode(b"/".join(parts[: index + 1]))
            if raw.mode == b"120000":
                raise SnapshotError(
                    f"state path has a symlinked component: {prefix_text}"
                )
            raise SnapshotError(
                f"tree path ancestor is not a directory: {prefix_text}"
            )
        tree_oid = raw.oid
    raise AssertionError("a non-empty path has at least one component")



def _raw_entry_at(self, parts: tuple[bytes, ...]) -> _RawTreeEntry | None:
    tree_oid = self.tree
    count = [0]
    for index, component in enumerate(parts):
        records = self._tree_object(tree_oid)
        self._charge_walk_records(records, count)
        raw = self._find_raw_entry(records, component)
        if raw is None:
            return None
        if raw.mode != b"160000":
            self._batch().info(raw.oid, role=raw.object_type)
        if index == len(parts) - 1:
            return raw
        if raw.mode != b"40000":
            ancestor = _tree_path_decode(b"/".join(parts[: index + 1]))
            raise SnapshotError(
                f"protected path ancestor is not a directory: {ancestor}"
            )
        tree_oid = raw.oid
    return None



def verify_release_history_immutable(
    spec: ChainSpec,
    *,
    candidate: TreeSnapshot,
    base: TreeSnapshot,
) -> tuple[str, set[str], dict[str, GitEntry]]:
    """Compare release entries in two entered, authenticated tree snapshots."""

    release_root = spec.release_root_relative.as_posix()
    base_entries = base.entries(release_root).as_dict()
    candidate_entries = candidate.entries(release_root).as_dict()

    # The old working-directory enumeration refused every candidate link or
    # non-regular entry before comparing base bytes. Preserve that ordering
    # over the tree's modes, without opening any blob.
    for relative, entry in sorted(candidate_entries.items()):
        if entry.mode == "120000":
            raise ReleaseChainError(f"release path is a symlink: {relative}")
        if entry.mode not in {"100644", "100755"}:
            raise ReleaseChainError(f"release path is not regular: {relative}")

    for relative, prior in sorted(base_entries.items()):
        if prior.mode not in {"100644", "100755"}:
            raise ReleaseChainError(
                f"base release entry has non-regular git mode {prior.mode}: {relative}"
            )
        current = candidate_entries.get(relative)
        if current is None:
            raise ReleaseChainError(
                f"existing release file was deleted relative to "
                f"{base.commit}: {relative}"
            )
        if current.mode != prior.mode:
            raise ReleaseChainError(
                f"existing release file mode changed relative to {base.commit}: "
                f"{relative} ({prior.mode} -> {current.mode})"
            )
        if current.object_id != prior.object_id:
            raise ReleaseChainError(
                f"existing release file bytes changed relative to "
                f"{base.commit}: {relative}"
            )
    return (
        base.commit,
        set(candidate_entries) - set(base_entries),
        base_entries,
    )



def verify_base_release_chain(
    spec: ChainSpec,
    *,
    base: TreeSnapshot,
    anchor_dir: pathlib.Path | None = None,
    enforce_production_pins: bool = True,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> ChainVerification:
    """Materialize and verify one entered base snapshot's release chain.

    By default every configured anchor must belong to the materialized tree.
    An explicit ``anchor_dir`` supplies the caller's trust material instead,
    as the append gate requires; a disjoint tree anchor subtree is then neither
    materialized nor screened, and caller anchors are not bound to the base tree.
    """

    normalized = _normalized_spec(spec)
    prefixes = (
        normalized.release_root_relative,
        normalized.manifest_relative,
        normalized.state_relative,
        normalized.prefix_relative,
    )
    if anchor_dir is None:
        prefixes += (normalized.anchor_relative,)
    _screen_protected_tree_names(
        base.entries("").as_dict(include_trees=True),
        prefixes,
        repertoire=normalized.name_repertoire,
        release_directories=(
            normalized.release_root_relative, normalized.manifest_relative
        ),
    )
    with tempfile.TemporaryDirectory(prefix="receipt-release-base-") as name:
        destination = pathlib.Path(name)
        with base.materialize(
            prefixes,
            destination,
            repertoire=normalized.name_repertoire,
        ) as materialized:
            base.refuse_transforming_attributes(materialized.entries.values())
            if anchor_dir is None:
                materialized.anchor_set_sha256(normalized)
            return verify_release_chain(
                materialized.path,
                spec=normalized,
                anchor_dir=(
                    materialized.path / normalized.anchor_relative
                    if anchor_dir is None
                    else anchor_dir
                ),
                require_chain=True,
                verify_state=True,
                enforce_production_pins=enforce_production_pins,
                clock_skew_seconds=clock_skew_seconds,
            )



def check_state_modes(
    base: _BaseCommit,
    candidate: _CandidateTree,
    *,
    entries: Mapping[str, GitEntry] | None = None,
) -> None:
    """Require both selected state entries to retain their base modes."""

    selected = entries or {}
    for relative in (
        candidate.spec.chain.state_relative,
        candidate.spec.chain.prefix_relative,
    ):
        path = relative.as_posix()
        candidate_entry = selected.get(path) or candidate.snapshot.entry(path)
        base_entry = base.tree.entry(path)
        if candidate_entry.mode != base_entry.mode:
            raise AppendError(f"state file mode changed relative to base: {path}")



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
    corpus_repertoire = verification_spec.corpus.name_repertoire
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

            prefixes = (
                normalized_chain.release_root_relative,
                normalized_chain.manifest_relative,
                normalized_chain.state_relative,
                normalized_chain.prefix_relative,
                normalized_chain.anchor_relative,
            )
            _screen_protected_tree_names(
                candidate.entries("").as_dict(include_trees=True),
                prefixes,
                repertoire=chain_repertoire,
                release_directories=(
                    normalized_chain.release_root_relative,
                    normalized_chain.manifest_relative,
                ),
            )

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


PR3A_BODY_SHA256 = {'entry': '59229d84bfab0635b368bfc959d8441a78c2e87c4eb5388144f9d1bf0c9b00fc', 'entries': 'ef35faaa3340c61da980fd7aabc01cea017877e7a21b9e8598a6cb6c093c0370', '_raw_entry_at': 'cd0c10ac57d90e4541863429973493867376c46c165cb71776d19dde9d1f780c', 'verify_release_history_immutable': '4eaf64dfd926a57330eb8eadae815a16949e6737708bf888733a44a6666e383d', 'verify_base_release_chain': '4ad7b328dc953bb625c4fe125b9a5fa8639c44699b93b32d88550bce4dd5698f', 'check_state_modes': 'a25b7fd45e8b3c7523313fd7a31df3cf187cfe5f1c0cd15eb1537d7261e591c4', 'run_verification': '11495ec44fb71bdd10dffc73472cb4e9738c629ba7436bd55e2fcb204613296c'}


# PR3b: verbatim origin/main (6c1a3f3) materializer selection and prefix admission.
def _deduplicated_prefixes(self) -> tuple[tuple[bytes, ...], ...]:
    parts: set[tuple[bytes, ...]] = set()
    for prefix in self._prefixes:
        parsed = self._snapshot._path_parts(prefix, allow_empty=True)
        path_bytes = b"/".join(parsed)
        self._snapshot._charge_path_bytes(path_bytes)
        parts.add(parsed)
    # Lexicographic tuple order places an ancestor immediately before all
    # of its descendants. Keeping only the last retained prefix therefore
    # avoids the quadratic all-parents scan for many disjoint prefixes.
    ordered = sorted(parts)
    kept: list[tuple[bytes, ...]] = []
    for candidate in ordered:
        if kept and candidate[: len(kept[-1])] == kept[-1]:
            continue
        kept.append(candidate)
    return tuple(kept)


def _selected_entries(self) -> dict[str, GitEntry]:
    selected: dict[str, GitEntry] = {}
    for parts in self._deduplicated_prefixes():
        if not parts:
            for entry in self._snapshot.entries(""):
                selected[entry.path] = entry
                if len(selected) > MAX_TREE_ENTRIES:
                    raise SnapshotError(
                        f"tree walk exceeds the budget of "
                        f"{MAX_TREE_ENTRIES} entries"
                    )
            continue
        raw = self._snapshot._raw_entry_at(parts)
        if raw is None:
            continue
        if raw.mode == b"40000":
            for entry in self._snapshot.entries(b"/".join(parts)):
                selected[entry.path] = entry
                if len(selected) > MAX_TREE_ENTRIES:
                    raise SnapshotError(
                        f"tree walk exceeds the budget of "
                        f"{MAX_TREE_ENTRIES} entries"
                    )
        else:
            entry = self._snapshot._public_entry(parts, raw)
            selected[entry.path] = entry
            if len(selected) > MAX_TREE_ENTRIES:
                raise SnapshotError(
                    f"tree walk exceeds the budget of "
                    f"{MAX_TREE_ENTRIES} entries"
                )

    sibling_names: dict[tuple[bytes, ...], set[bytes]] = {}
    for path, entry in sorted(selected.items()):
        if entry.mode not in _CONTENT_MODES:
            # "base tree" is legacy text; this may be any selected snapshot.
            raise SnapshotError(
                f"base tree entry has non-regular mode {entry.mode}: {path}"
            )
        raw_parts = self._snapshot._path_parts(path, allow_empty=False)
        for index, name in enumerate(raw_parts):
            sibling_names.setdefault(raw_parts[:index], set()).add(name)
    for parent, names in sibling_names.items():
        label = (
            _tree_path_decode(b"/".join(parent)) if parent else "tree root"
        )
        try:
            assert_no_merging_entries(
                sorted(names),
                repertoire=self._repertoire,
                materializing=True,
                label=label,
            )
        except NamePolicyError as exc:
            raise SnapshotError(str(exc)) from exc
    return selected


PR3B_BODY_SHA256 = {'_deduplicated_prefixes': '1fa613697f8175b89a4636b4d7461022abb04a35a1fa6b706c17b31c04fcce3f', '_selected_entries': '00fc70ddda9e48f7513d8db2ff064a0d0da04266ab4b5a44f563253c3f941ffc'}


# PR4 snapshot attribute bodies, frozen from origin/main before forwarding.
def _unsupported_attribute(path: str, line: int, construct: str) -> SnapshotError:
    return SnapshotError(
        f"unsupported .gitattributes construct at {path}:{line}: {construct}"
    )


def _attribute_pattern(
    token: bytes, *, path: str, line: int
) -> tuple[bytes, tuple[bytes, ...], bool]:
    try:
        shown = token.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise _unsupported_attribute(path, line, "non-ASCII pattern") from exc
    if not token:
        raise _unsupported_attribute(path, line, "empty pattern")
    if token.startswith(b'"'):
        raise _unsupported_attribute(path, line, "C-quoted pattern")
    if token.startswith(b"!"):
        raise _unsupported_attribute(path, line, "negative pattern")
    for byte, description in (
        (b"?", "?"),
        (b"[", "bracket expression"),
        (b"]", "bracket expression"),
        (b"\\", "backslash escape"),
    ):
        if byte in token:
            raise _unsupported_attribute(path, line, description)
    if token.endswith(b"/"):
        raise _unsupported_attribute(path, line, "trailing slash")
    if re.fullmatch(rb"[A-Za-z0-9._*/-]+", token) is None:
        raise _unsupported_attribute(path, line, f"pattern {shown!r}")
    anchored = token[1:] if token.startswith(b"/") else token
    if not anchored:
        raise _unsupported_attribute(path, line, "empty pattern")
    segments = anchored.split(b"/")
    if any(not segment for segment in segments):
        raise _unsupported_attribute(path, line, "empty pattern segment")
    for segment in segments:
        if b"**" in segment and segment != b"**":
            raise _unsupported_attribute(path, line, "misplaced **")
    if token == b"**":
        raise _unsupported_attribute(path, line, "misplaced **")
    return anchored, tuple(segments), token.startswith(b"/") or b"/" in anchored


def _parse_attribute_file(
    path: str, payload: bytes, *, rule_limit: int
) -> tuple[_AttributeRule, ...]:
    rules: list[_AttributeRule] = []
    rule_overflow = False
    line_number = 0
    position = 0
    while True:
        line_number += 1
        line_end = payload.find(b"\n", position)
        if line_end < 0:
            original = payload[position:]
        else:
            original = payload[position:line_end]
        # Git 2.53.0's read_attr_from_buf() stops reading the blob at an
        # embedded NUL, so every rule after one is unseen by git: refuse the
        # blob on any line rather than honour rules git never reads.
        if b"\0" in original:
            raise _unsupported_attribute(path, line_number, "control byte")
        # attr.c's parse_attr_line() skips leading blanks (space, tab and CR,
        # measured on git 2.53.0) and returns before any other test on an
        # empty line or a '#' comment, whatever the line's length or contents;
        # the reader skips those lines the same way (peer review, round 4).
        line = original.strip(b" \t\r")
        if line and not line.startswith(b"#"):
            # attr.h fixes ATTR_MAX_LINE_LENGTH at 2048 and parse_attr_line()
            # drops a rule line whose strlen(), leading blanks included, is at
            # least that; parse_attr() drops the whole rule when
            # attr_name_valid() or attr_name_reserved() rejects one state
            # name; and git splits fields at CR as well as at space and tab
            # (measured). Refuse these cases rather than disagreeing about
            # precedence.
            if len(original) >= 2048:
                raise _unsupported_attribute(
                    path, line_number, "line longer than 2048 bytes"
                )
            if any(byte < 0x20 and byte != 0x09 for byte in original):
                raise _unsupported_attribute(path, line_number, "control byte")
            fields = re.split(rb"[ \t]+", line)
            if len(fields) < 2:
                raise _unsupported_attribute(
                    path, line_number, "line has no attribute state"
                )
            if fields[0].startswith(b"[attr]"):
                raise _unsupported_attribute(
                    path, line_number, "attribute macro definition"
                )
            pattern, segments, has_slash = _attribute_pattern(
                fields[0], path=path, line=line_number
            )
            states: list[tuple[str, str]] = []

            def add_states(additions: tuple[tuple[str, str], ...]) -> None:
                if len(states) + len(additions) > MAX_ATTRIBUTE_STATES_PER_LINE:
                    raise SnapshotError(
                        f"attribute states at {path}:{line_number} exceed the "
                        f"per-line budget of {MAX_ATTRIBUTE_STATES_PER_LINE} states"
                    )
                states.extend(additions)

            for raw_state in fields[1:]:
                try:
                    state = raw_state.decode("ascii", errors="strict")
                except UnicodeDecodeError as exc:
                    raise _unsupported_attribute(
                        path, line_number, "non-ASCII attribute state"
                    ) from exc
                if state == "binary":
                    add_states(
                        (
                            ("diff", "unset"),
                            ("merge", "unset"),
                            ("text", "unset"),
                        )
                    )
                    continue
                disposition = "set"
                name = state
                if state.startswith("-"):
                    disposition, name = "unset", state[1:]
                elif state.startswith("!"):
                    disposition, name = "unspecified", state[1:]
                elif "=" in state:
                    name, value = state.split("=", 1)
                    disposition = "value"
                if name.startswith(("-", "builtin_")) or re.fullmatch(
                    r"[A-Za-z0-9_.-]+", name
                ) is None:
                    raise _unsupported_attribute(
                        path, line_number, f"attribute name {name!r}"
                    )
                add_states(((name, disposition),))
            trailing_globstars = 0
            for segment in reversed(segments):
                if segment != b"**":
                    break
                trailing_globstars += 1
            trailing_descendants = bool(
                trailing_globstars and trailing_globstars < len(segments)
            )
            match_segments = (
                segments[:-trailing_globstars]
                if trailing_descendants
                else segments
            )
            rule = _AttributeRule(
                pattern,
                segments,
                match_segments,
                has_slash,
                trailing_descendants,
                tuple(states),
            )
            if len(rules) >= rule_limit:
                rule_overflow = True
            else:
                rules.append(rule)
        if line_end < 0:
            break
        position = line_end + 1
    if rule_overflow:
        raise SnapshotError(
            f"attribute rules exceed the snapshot budget of "
            f"{MAX_ATTRIBUTE_RULES_TOTAL} rules"
        )
    return tuple(rules)


def _segment_matches(
    pattern: bytes, value: bytes, step: Callable[[], None]
) -> bool:
    pattern_index = value_index = 0
    star = -1
    retry = 0
    while value_index < len(value):
        step()
        if (
            pattern_index < len(pattern)
            and pattern[pattern_index] != ord("*")
            and pattern[pattern_index] == value[value_index]
        ):
            pattern_index += 1
            value_index += 1
        elif pattern_index < len(pattern) and pattern[pattern_index] == ord("*"):
            star = pattern_index
            pattern_index += 1
            retry = value_index
        elif star >= 0:
            retry += 1
            value_index = retry
            pattern_index = star + 1
        else:
            return False
    while pattern_index < len(pattern) and pattern[pattern_index] == ord("*"):
        step()
        pattern_index += 1
    return pattern_index == len(pattern)


def _attribute_matches(
    rule: _AttributeRule, relative: tuple[bytes, ...], step: Callable[[], None]
) -> bool:
    if not rule.has_slash:
        return bool(relative) and _segment_matches(
            rule.segments[0], relative[-1], step
        )
    pattern_index = value_index = 0
    globstar = -1
    retry = 0
    while value_index < len(relative):
        if (
            rule.trailing_descendants
            and pattern_index == len(rule.match_segments)
        ):
            # The non-globstar prefix matched and at least one descendant
            # remains. Git's trailing ``/**`` excludes the directory itself.
            return True
        step()
        if (
            pattern_index < len(rule.match_segments)
            and rule.match_segments[pattern_index] == b"**"
        ):
            globstar = pattern_index
            pattern_index += 1
            retry = value_index
        elif (
            pattern_index < len(rule.match_segments)
            and _segment_matches(
                rule.match_segments[pattern_index],
                relative[value_index],
                step,
            )
        ):
            pattern_index += 1
            value_index += 1
        elif globstar >= 0:
            retry += 1
            value_index = retry
            pattern_index = globstar + 1
        else:
            return False
    while (
        pattern_index < len(rule.match_segments)
        and rule.match_segments[pattern_index] == b"**"
    ):
        step()
        pattern_index += 1
    if rule.trailing_descendants:
        return False
    return pattern_index == len(rule.match_segments)


def _attribute_rules(
    self, parts: tuple[bytes, ...]
) -> tuple[_AttributeRule, ...]:
    path_bytes = b"/".join(parts)
    path = _tree_path_decode(path_bytes)
    cached = self._state.attribute_cache.get(path)
    if cached is not None:
        return cached
    raw = self._raw_entry_at(parts)
    if raw is None:
        self._state.attribute_cache[path] = ()
        return ()
    if raw.mode not in {b"100644", b"100755"}:
        raise SnapshotError(
            f"unsupported .gitattributes entry at {path}: mode {raw.display_mode}"
        )
    _kind, size = self._batch().info(raw.oid, role="blob")
    if self._verification_total("attribute_bytes") + size > MAX_ATTRIBUTE_BYTES_TOTAL:
        raise SnapshotError(
            f"attribute bytes exceed the snapshot budget of "
            f"{MAX_ATTRIBUTE_BYTES_TOTAL} bytes"
        )
    entry = self._public_entry(parts, raw)
    payload = self.blob(entry, limit=MAX_ATTRIBUTE_BYTES)
    self._charge_verification(
        "attribute_bytes",
        size,
        ceiling=MAX_ATTRIBUTE_BYTES_TOTAL,
        message=f"attribute bytes exceed the snapshot budget of {MAX_ATTRIBUTE_BYTES_TOTAL} bytes",
    )
    remaining_rules = (
        MAX_ATTRIBUTE_RULES_TOTAL
        - self._verification_total("attribute_rules")
    )
    rules = _parse_attribute_file(
        path, payload, rule_limit=max(0, remaining_rules)
    )
    if self._verification_total("attribute_rules") + len(rules) > MAX_ATTRIBUTE_RULES_TOTAL:
        raise SnapshotError(
            f"attribute rules exceed the snapshot budget of "
            f"{MAX_ATTRIBUTE_RULES_TOTAL} rules"
        )
    self._charge_verification(
        "attribute_rules",
        len(rules),
        ceiling=MAX_ATTRIBUTE_RULES_TOTAL,
        message=f"attribute rules exceed the snapshot budget of {MAX_ATTRIBUTE_RULES_TOTAL} rules",
    )
    self._state.attribute_cache[path] = rules
    return rules


def _attribute_step(self) -> None:
    self._charge_verification(
        "attribute_match_work",
        1,
        ceiling=MAX_ATTRIBUTE_MATCH_WORK,
        message=(
            f"attribute matching exceeds the work budget of "
            f"{MAX_ATTRIBUTE_MATCH_WORK} steps"
        ),
    )


def refuse_transforming_attributes(
    self, paths: Iterable[str | bytes | GitEntry]
) -> None:
    """Evaluate the fail-closed committed-attribute subset over paths.

    Only ``filter``, ``ident`` and ``working-tree-encoding`` transform raw
    blob bytes: their set and valued states refuse, while unset, absent
    and an explicit unspecified state are harmless. ``text`` and ``eol``
    are accepted in every state, and the built-in ``binary`` macro expands
    to ``-diff -merge -text``. Each path's final attribute states are
    computed independently under exact matching and ASCII-folded matching,
    with last-rule-wins precedence in each reading; a transform in either
    reading refuses, regardless of repository configuration. Git uses
    ``WM_CASEFOLD`` on case-insensitive clones, so the folded reading also
    catches transforms an exact reading would miss. An unsupported
    ``core.ignoreCase`` boolean still refuses at selection. No non-tree
    attribute source is consulted.
    """

    self._batch()
    if isinstance(paths, (str, bytes, GitEntry)):
        raise SnapshotError("attribute paths must be an iterable of paths")
    try:
        iterator = iter(paths)
    except TypeError as exc:
        raise SnapshotError("attribute paths must be an iterable of paths") from exc
    unique: dict[bytes, tuple[bytes, ...]] = {}
    for count, supplied in enumerate(iterator, start=1):
        if count > MAX_TREE_ENTRIES:
            raise SnapshotError(
                f"attribute paths exceed the budget of {MAX_TREE_ENTRIES} entries"
            )
        value: str | bytes
        if isinstance(supplied, GitEntry):
            value = supplied.path
        else:
            value = supplied
        parts = self._path_parts(value, allow_empty=False)
        path_bytes = b"/".join(parts)
        self._charge_path_bytes(path_bytes)
        unique.setdefault(path_bytes, parts)

    transforms = {"filter", "ident", "working-tree-encoding"}
    # bytes.lower folds only ASCII letters, as git's WM_CASEFOLD does.
    # Keep the readings separate so a fold-only reset cannot cancel an
    # exact transforming rule before the refusal is decided.
    folded_rules: dict[int, _AttributeRule] = {}
    for path_bytes, parts in unique.items():
        readings: list[dict[str, str]] = []
        for fold in (False, True):
            final: dict[str, str] = {}
            for depth in range(len(parts)):
                attribute_parts = (*parts[:depth], b".gitattributes")
                rules = self._attribute_rules(attribute_parts)
                relative = parts[depth:]
                if fold:
                    relative = tuple(segment.lower() for segment in relative)
                for rule in rules:
                    if fold:
                        candidate_rule = folded_rules.get(id(rule))
                        if candidate_rule is None:
                            candidate_rule = _AttributeRule(
                                rule.pattern.lower(),
                                tuple(s.lower() for s in rule.segments),
                                tuple(s.lower() for s in rule.match_segments),
                                rule.has_slash,
                                rule.trailing_descendants,
                                rule.states,
                            )
                            folded_rules[id(rule)] = candidate_rule
                        rule = candidate_rule
                    if _attribute_matches(rule, relative, self._attribute_step):
                        for name, disposition in rule.states:
                            self._attribute_step()
                            final[name] = disposition
            readings.append(final)
        for name in sorted(transforms):
            if any(final.get(name) in {"set", "value"} for final in readings):
                try:
                    path = path_bytes.decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    raise SnapshotError(
                        "tree entry name is not valid UTF-8 for quoting"
                    ) from exc
                raise SnapshotError(
                    f"transforming attribute {name} applies to protected "
                    f"path {path}"
                )


PR4_BODY_SHA256 = {'_unsupported_attribute': '8f3c08c4f49d8048fd28b0e3439cfcb5b74f2d5780304dae552c1f42ddf17b12', '_attribute_pattern': 'a1e0544c431baf5d8645e59016e979888a753301523397ebe6c1178b18d462b3', '_parse_attribute_file': '1cb73b995ff3fd2269cc230222c8eedfd62ab3e9e7aaf16223776734259ddd98', '_segment_matches': '00c5b18ab3b52d136e3b175af9618d5edb7f97a104ba28edfbf672f3d043eeb9', '_attribute_matches': '3a41087cba394989bbdd3efc37c0b0e02e22bed67ea33f139892284825fdf8bb', '_attribute_rules': '36b1d410c7e5d40b3dd2c68771f6d2c3052af8cc5466472197d0d08693bb8c5e', '_attribute_step': 'a0dcb636dd37a36a2c11003087a697c1b433702f19705840c0ac9750943a1ae9', 'refuse_transforming_attributes': '184012d440939ff2b9c15eca1858d54317969952cc962d8e5b0e460baf6d4f9d'}


# PR5 baseline bodies, verbatim from 22132516b623e9f095b93f52aae33df2eaadd7ea.
class PR5Append:
    def _state_entry(
        candidate: _CandidateTree,
        relative: pathlib.PurePosixPath,
    ) -> GitEntry:
        """Select one regular state entry without fetching its payload."""

        display = relative.as_posix()
        try:
            entry = candidate.snapshot.entry(display)
        except SnapshotError as exc:
            if str(exc) == f"tree entry does not exist: {display}":
                raise AppendError(
                    f"state file is missing or not a regular file: {display}"
                ) from exc
            raise
        if entry.mode == "120000":
            raise AppendError(f"state file is a symlink: {display}")
        if entry.mode not in {"100644", "100755"}:
            raise AppendError(f"state file is not a regular file: {display}")
        return entry

    def _screen_candidate_tree_aliases(
        candidate: _CandidateTree,
    ) -> dict[str, GitEntry]:
        """Screen protected shapes, aliases and names over the complete tree."""

        from dataclasses import replace
        from receipt.protected_tree import POLICY_VERSION, ProtectionPlan, TreePolicy
        from receipt.release_chain import _protected_name_error

        policy = TreePolicy(candidate.snapshot, policy_version=POLICY_VERSION,
                            work=candidate.snapshot.work)
        entries = policy.read_listing("")
        protected = _protected_paths(candidate)
        for path in protected:
            parts = path.split("/")
            for depth in range(1, len(parts)):
                prefix = "/".join(parts[:depth])
                entry = entries.get(prefix)
                if entry is None or entry.mode == "040000":
                    continue
                if entry.mode == "120000":
                    raise SnapshotError(f"state path has a symlinked component: {prefix}")
                raise SnapshotError(f"tree path ancestor is not a directory: {prefix}")

        # Gate-only proposals need the same name obligations before their return.
        plan = ProtectionPlan.chain_names(
            _materialization_prefixes(candidate),
            repertoire=candidate.spec.chain.name_repertoire,
            release_directories=(candidate.spec.chain.release_root_relative,
                                 candidate.spec.chain.manifest_relative),
            alias_paths=protected, use="append-names", anchor_origin="caller",
        )
        plan = replace(plan, exact_state_paths=(candidate.ledger_relative, candidate.prefix_relative),
                       attribute_target_selectors=_surface_alias_paths(candidate), phase="append")
        view = policy.evaluate(plan, stage="suffixes")
        try:
            selection = view.require(plan.use, render=_protected_name_error)
        except ReleaseChainError as exc:
            raise AppendError(str(exc)) from exc
        return dict(selection.entries_for(candidate.snapshot, use=plan.use))

    def _attribute_entries(
        candidate: _CandidateTree,
        entries: Mapping[str, GitEntry],
    ) -> tuple[GitEntry, ...]:
        """Return regular blobs on every explicit or configured protected path."""

        materialized = tuple(
            relative.as_posix() for relative in _materialization_prefixes(candidate)
        )
        return tuple(
            entry
            for path, entry in sorted(entries.items())
            if entry.mode in {"100644", "100755"}
            and (
                _is_protected(path, candidate)
                or any(
                    path == prefix or path.startswith(f"{prefix}/")
                    for prefix in materialized
                )
            )
        )

    def _candidate_release_entries_regular(candidate: _CandidateTree) -> None:
        """Preserve the release-leaf shape refusals on the push path."""

        release_root = candidate.spec.chain.release_root_relative.as_posix()
        manifest = candidate.spec.chain.manifest_relative.as_posix()
        for relative, entry in sorted(
            candidate.snapshot.entries(release_root).as_dict().items()
        ):
            # The manifest leaf has its own established directory diagnostic.
            if relative == manifest:
                continue
            if entry.mode == "120000":
                raise AppendError(f"release path is a symlink: {relative}")
            if entry.mode not in {"100644", "100755"}:
                raise AppendError(f"release path is not regular: {relative}")

    def _screen_candidate_materialization(candidate: _CandidateTree) -> None:
        """Rehash every protected candidate blob when no chain is present."""

        with tempfile.TemporaryDirectory(prefix="receipt-append-candidate-") as directory:
            with candidate.snapshot.materialize(
                _materialization_prefixes(candidate),
                pathlib.Path(directory),
                repertoire=candidate.spec.chain.name_repertoire,
            ):
                pass

    def _verify_candidate_release_chain(
        *,
        candidate: _CandidateTree,
        ledger_bytes: bytes,
        prefix_bytes: bytes,
        anchor_dir: pathlib.Path,
        enforce_production_pins: bool,
    ) -> ChainVerification:
        """Verify the selected candidate chain through a private materialization."""

        with tempfile.TemporaryDirectory(prefix="receipt-append-candidate-") as directory:
            with candidate.snapshot.materialize(
                _materialization_prefixes(candidate),
                pathlib.Path(directory),
                repertoire=candidate.spec.chain.name_repertoire,
            ) as materialized:
                return verify_release_chain(
                    materialized.path,
                    spec=candidate.spec.chain,
                    anchor_dir=anchor_dir,
                    require_chain=True,
                    verify_state=True,
                    enforce_production_pins=enforce_production_pins,
                    state_bytes=_state_snapshot_bytes(
                        candidate,
                        ledger_bytes,
                        prefix_bytes,
                    ),
                )

    def check_release_proposal(
        base: _BaseCommit,
        *,
        candidate: _CandidateTree,
        ledger_bytes: bytes,
        prefix_bytes: bytes,
        anchor_dir: pathlib.Path,
        enforce_production_pins: bool,
    ) -> int | None:
        """Verify base custody and the one transition the candidate may add."""

        try:
            _commit, new_files, base_release_entries = verify_release_history_immutable(
                candidate.spec.chain,
                candidate=candidate.snapshot,
                base=base.tree,
            )
        except ReleaseChainError as exc:
            raise AppendError(str(exc)) from exc

        base_has_chain = any(
            relative.startswith(candidate.spec.release_manifest_prefix)
            for relative in base_release_entries
        )
        manifest_relative = candidate.spec.chain.manifest_relative.as_posix()
        manifest_children = candidate.snapshot.entries(manifest_relative).children
        candidate_has_chain = any(
            name.endswith(".json")
            and isinstance(child, GitEntry)
            and child.mode in {"100644", "100755"}
            for name, child in manifest_children.items()
        )
        base_bytes = _base_ledger_bytes(base, candidate)
        appended_bytes = _check_exact_byte_append(base_bytes, ledger_bytes)
        ledger_changed = bool(appended_bytes)

        if not base_has_chain:
            if not candidate_has_chain:
                if new_files:
                    raise AppendError(
                        "legacy pre-genesis proposal must not change releases/; "
                        "add a complete genesis manifest, producer signature, and "
                        "both receipts or no release files at all "
                        f"(changed={sorted(new_files)})"
                    )
                _screen_candidate_materialization(candidate)
                return None
            _release_triple(
                new_files,
                0,
                candidate=candidate,
                allowed_support_files=set(candidate.spec.genesis_support_files),
            )
            try:
                verification = _verify_candidate_release_chain(
                    candidate=candidate,
                    ledger_bytes=ledger_bytes,
                    prefix_bytes=prefix_bytes,
                    anchor_dir=anchor_dir,
                    enforce_production_pins=enforce_production_pins,
                )
            except ReleaseChainError as exc:
                raise AppendError(str(exc)) from exc
            if len(verification.releases) != 1:
                raise AppendError(
                    "genesis proposal must create exactly one release at index 0"
                )
            return 0

        try:
            base_verification = verify_base_release_chain(
                candidate.spec.chain,
                base=base.tree,
                anchor_dir=anchor_dir,
                enforce_production_pins=enforce_production_pins,
            )
        except ReleaseChainError as exc:
            raise AppendError(f"base release chain is invalid: {exc}") from exc
        assert base_verification.head is not None
        expected_index = base_verification.head.release_index + 1

        if ledger_changed:
            _release_triple(new_files, expected_index, candidate=candidate)
        elif new_files:
            raise AppendError(
                "release-only proposal is forbidden after genesis; a next release "
                "must witness an actual ledger byte append"
            )

        try:
            candidate_verification = _verify_candidate_release_chain(
                candidate=candidate,
                ledger_bytes=ledger_bytes,
                prefix_bytes=prefix_bytes,
                anchor_dir=anchor_dir,
                enforce_production_pins=enforce_production_pins,
            )
        except ReleaseChainError as exc:
            raise AppendError(str(exc)) from exc
        expected_length = len(base_verification.releases) + (1 if ledger_changed else 0)
        if len(candidate_verification.releases) != expected_length:
            raise AppendError(
                f"release chain length must be {expected_length} for this proposal; "
                f"found {len(candidate_verification.releases)}"
            )
        assert candidate_verification.head is not None
        return candidate_verification.head.release_index

    def check_release_chain_without_base(
        *,
        candidate: _CandidateTree,
        ledger_bytes: bytes,
        prefix_bytes: bytes,
        anchor_dir: pathlib.Path,
        enforce_production_pins: bool,
    ) -> int | None:
        """Verify an initialized chain from the selected pushed commit."""

        manifest_relative = candidate.spec.chain.manifest_relative.as_posix()
        manifest_listing = candidate.snapshot.entries(manifest_relative)
        initialized = bool(manifest_listing)
        if not initialized:
            _candidate_release_entries_regular(candidate)
            _screen_candidate_materialization(candidate)
            return None
        manifest_entry = candidate.snapshot.entry(manifest_relative)
        if manifest_entry.mode != "040000":
            raise AppendError(
                "release manifest path is not a regular directory: "
                f"{candidate.snapshot.root / candidate.spec.chain.manifest_relative}"
            )
        _candidate_release_entries_regular(candidate)
        try:
            verification = _verify_candidate_release_chain(
                candidate=candidate,
                ledger_bytes=ledger_bytes,
                prefix_bytes=prefix_bytes,
                anchor_dir=anchor_dir,
                enforce_production_pins=enforce_production_pins,
            )
        except ReleaseChainError as exc:
            raise AppendError(str(exc)) from exc
        assert verification.head is not None
        return verification.head.release_index

    def _verify_selected_tree(
        candidate: _CandidateTree,
        *,
        base: _BaseCommit | None,
        trusted_code_root: pathlib.Path,
        release_anchor_dir: pathlib.Path | None,
    ) -> str:
        """Run reader preflights, then retained checks, over entered snapshots."""

        spec = candidate.spec
        ledger_entry = _state_entry(candidate, spec.chain.state_relative)
        prefix_entry = _state_entry(candidate, spec.chain.prefix_relative)
        tree_entries = _screen_candidate_tree_aliases(candidate)
        from receipt.protected_tree import POLICY_VERSION, ProtectionPlan, TreePolicy, attribute_error

        attribute_plan = ProtectionPlan(obligations=("attributes",), listing_scope=(),
            use="append-attributes", phase="attributes", anchor_origin="caller",
            attribute_target_selectors=tuple(
                entry.path for entry in _attribute_entries(candidate, tree_entries)))
        policy = TreePolicy(candidate.snapshot, policy_version=POLICY_VERSION,
                            work=candidate.snapshot.work)
        attributes = policy.evaluate_attributes(attribute_plan)
        attributes.require(attribute_plan.use, render=attribute_error)
        if base is not None:
            _data_changes, gate_changes, unclassified = check_surface_separation(
                base,
                candidate,
            )
            if gate_changes:
                reported = check_gate_only_confinement(unclassified, candidate)
                unclassified_suffix = (
                    f"; unclassified changes={sorted(reported)}" if reported else ""
                )
                base_suffix = (
                    f"; base {base.ref} ({base.commit})" if base.ref != base.commit else ""
                )
                return (
                    "thesis-facts append check OK: gate-only proposal; "
                    "DATA_SURFACE unchanged; GATE_SURFACE changes="
                    f"{sorted(gate_changes)}{unclassified_suffix}{base_suffix}"
                )

        _, ledger_bytes = _read_state_blob(
            candidate,
            spec.chain.state_relative,
            entry=ledger_entry,
        )
        _, prefix_bytes = _read_state_blob(
            candidate,
            spec.chain.prefix_relative,
            entry=prefix_entry,
        )

        text = _as_text(ledger_bytes, candidate.ledger_relative)
        reject_non_append_bytes(text)
        lines = _lines(text)

        prefix = check_prefix(
            lines, _as_text(prefix_bytes, candidate.prefix_relative), candidate
        )
        binding_boundary = int(prefix["prefixLineCount"])
        appended = None
        if base is not None:
            binding_boundary = check_prefix_anchored_to_base(
                base,
                prefix,
                candidate,
            )
            appended = check_append_only(base, lines, candidate)
        check_rows(lines, binding_boundary, spec)

        production_pins = release_anchor_dir is None
        anchor_dir = release_anchor_dir or (trusted_code_root / spec.chain.anchor_relative)
        release_index = (
            check_release_proposal(
                base,
                candidate=candidate,
                ledger_bytes=ledger_bytes,
                prefix_bytes=prefix_bytes,
                anchor_dir=anchor_dir,
                enforce_production_pins=production_pins,
            )
            if base is not None
            else check_release_chain_without_base(
                candidate=candidate,
                ledger_bytes=ledger_bytes,
                prefix_bytes=prefix_bytes,
                anchor_dir=anchor_dir,
                enforce_production_pins=production_pins,
            )
        )

        check_binding_shapes(lines, binding_boundary)
        if base is not None:
            check_state_modes(
                base,
                candidate,
                entries={
                    ledger_entry.path: ledger_entry,
                    prefix_entry.path: prefix_entry,
                },
            )

        resolved = (
            f" {base.ref} ({base.commit})"
            if base is not None and base.ref != base.commit
            else ""
        )
        suffix = f", +{appended} appended vs base{resolved}" if appended is not None else ""
        release_suffix = f", release {release_index}" if release_index is not None else ""
        return (
            f"thesis-facts append check OK: {len(lines)} rows, immutable prefix "
            f"{prefix['prefixLineCount']}{suffix}{release_suffix}"
        )

class PR5Corpus:
    def _path_fold(relative: str) -> str:
        """Fold ASCII letters per component and preserve every other code point.

        This deliberately narrows 0.5.x's ``NFC(casefold)`` key: neither Unicode
        normalization nor Unicode casefolding participates under either name
        repertoire.
        """

        try:
            return "/".join(ascii_fold_text(component) for component in relative.split("/"))
        except NamePolicyError as exc:
            raise CorpusError(str(exc)) from exc

    def _reject_aliasing_paths(
        relatives: list[str], *, work: _PathPrefixWork
    ) -> int:
        """Refuse two declared paths a real filesystem would treat as one.

        Two passes, because a path can alias another in two places and the
        second one was missed.

        The first compares whole paths, which is what "the closed-world set is
        ambiguous" is about: a journal binding both ``rules/x.yaml`` and
        ``rules/X.yaml`` says two different digests about one file on APFS, and
        an auditor cannot say which one they have.

        The second compares every *prefix* of every path — each ancestor
        directory and the path itself — at the depth it sits. Comparing whole
        paths alone missed the case where the collision is a directory:
        ``rules/A/x.yaml`` and ``rules/a/y.yaml`` are two distinct paths whose
        fold keys differ, so the first pass passes them, while an insensitive
        clone merges ``A`` and ``a`` into one directory holding both files —
        and the closed-world sweep, which descends the spellings the journal
        named, walks two directories on the auditor's host and one on the
        consumer's (peer review, Sol round 3). The path itself is included at
        its own depth as well, so a directory in one path colliding with a file
        in another is caught too.

        Under the portable-name policy the fold key over a declared path is
        ASCII case-insensitivity, so what both passes are asking is whether two
        spellings differ only in case.

        **The prefix pass holds no index.** It used to build one — first a
        cumulative string per visit, then a component trie of one node per
        distinct prefix — and a trie is an index whose size is the thing an
        adversary chooses. 4,096 portable 1,023-character paths with distinct
        three-character first components and 510 one-character descendants are
        inside ``MAX_JOURNAL_ROWS``, inside ``MAX_PATH_TEXT`` and inside half of
        :data:`MAX_PATH_COMPONENTS_TOTAL`, and they name 2,093,056 distinct
        prefixes: 594 MB of trie nodes and 4.8 seconds, measured, for a journal
        the budget waved through (peer review, Sol round 7, round 3). Compacting
        the node — ``__slots__``, one shared child dictionary, interned spellings
        — cannot fix that. A Python object plus its dictionary entry is on the
        order of 150 bytes whatever is done to it, so the *representation* was
        never the choice worth making; holding one at all was.

        So the pass sorts instead. Each path is folded a component at a time and
        the folded components are joined by a NUL — a character no portable name
        can hold and one that sorts below every character one can — so
        ordering the keys as strings orders the paths by their folded component
        *sequences*. Two facts make neighbour comparison sufficient:

        - every path sharing a folded prefix occupies a contiguous run of that
          order, which is what sorting by a sequence means;
        - so if two paths in such a run disagree about the spelling of a
          component inside their shared prefix, then some *adjacent* pair in the
          run disagrees about it too — agreement between neighbours is
          transitive along the chain that joins them, and every neighbour in the
          run shares at least that prefix.

        Each adjacent pair is therefore compared for as many components as their
        folded keys agree on, and the first disagreement in spelling is the
        refusal. What is live at any moment is two paths' components and one
        string key per declared path, so the pass allocates a small multiple of
        the declared path text — the text the journal already carries — instead
        of a structure whose size is the adversary's to choose. The same 4,096
        maximum-depth paths now peak at 9.0 MB and 0.6 seconds.

        The number of distinct folded prefixes is the number of components the
        first path contributes plus, for every later path, the components below
        what it shares with its predecessor. Every component visit and every
        counted prefix charges ``work`` before folding or comparison.

        The whole-path pass runs first and completely, so a journal with both
        kinds of collision keeps the message that names the more specific one.
        """

        seen: dict[str, str] = {}
        for relative in relatives:
            key = _path_fold(relative)
            if key in seen and seen[key] != relative:
                raise CorpusError(
                    "two declared paths would alias on a case- or "
                    "normalization-insensitive filesystem, so the closed-world set "
                    f"is ambiguous: {_quoted(seen[key])} and {_quoted(relative)}"
                )
            seen[key] = relative

        keys: list[str] = []
        for relative in relatives:
            components = relative.split("/")
            # Charged before the components are folded, so the fold work and the
            # key it builds are both inside the budget rather than beside it.
            work.charge(len(components))
            keys.append("\x00".join(_path_fold(component) for component in components))

        nodes = 0
        previous_folded: list[str] = []
        previous_spelled: list[str] = []
        for index in sorted(range(len(relatives)), key=keys.__getitem__):
            folded = keys[index].split("\x00")
            spelled = relatives[index].split("/")
            shared = 0
            limit = min(len(folded), len(previous_folded))
            while shared < limit and folded[shared] == previous_folded[shared]:
                shared += 1
            for depth in range(shared):
                if spelled[depth] != previous_spelled[depth]:
                    raise CorpusError(
                        "two declared paths would alias at a directory: "
                        f"{_quoted('/'.join(previous_spelled[: depth + 1]))} and "
                        f"{_quoted('/'.join(spelled[: depth + 1]))}"
                    )
            work.charge(len(folded) - shared)
            nodes += len(folded) - shared
            if nodes > MAX_ALIAS_INDEX_NODES:
                raise CorpusError(
                    f"declared paths name more than {MAX_ALIAS_INDEX_NODES} "
                    "distinct directories; declared paths exceed the alias index "
                    "budget"
                )
            previous_folded, previous_spelled = folded, spelled
        return nodes

    def _screen_tree_listing(
        entries: Mapping[str, GitEntry],
        by_directory: Mapping[str, Mapping[str, GitEntry]],
        *,
        repertoire: str,
    ) -> None:
        """Validate every component and every tree directory's sibling set.

        ``TreeListing.as_dict`` has already materialized each authenticated full
        path exactly once.  Deriving local names from that flat view avoids a
        second charged path traversal through ``TreeListing.children``.
        """

        for relative in sorted(entries):
            name = relative.rpartition("/")[2]
            if repertoire == "portable":
                # The portable operation supplies the retained corpus diagnostic.
                # Ask the strict fold first so undecodable surrogateescaped tree
                # bytes are still refused as undecodable under both repertoires.
                try:
                    ascii_fold_text(name)
                except NamePolicyError as exc:
                    raise CorpusError(str(exc)) from exc
                _assert_portable_name(name, f"tree entry {_quoted(relative)}")
            else:
                try:
                    validate_component_text(
                        name,
                        repertoire=repertoire,
                        label=f"tree entry {_quoted(relative)}",
                    )
                    # Folding is required under both repertoires. In particular,
                    # this refuses surrogateescaped non-UTF-8 bytes before a
                    # verdict could quote or fold them.
                    ascii_fold_text(name)
                except NamePolicyError as exc:
                    raise CorpusError(str(exc)) from exc

        directories = {""}
        directories.update(
            path for path, entry in entries.items() if entry.mode == _TREE_MODE
        )
        for directory in sorted(directories):
            names = tuple(sorted(by_directory.get(directory, {})))

            # Keep the established corpus refusal text. The shared helper still
            # runs for every directory; this pre-check only supplies the retained
            # path-rich diagnostic when the sibling pair itself is the fault.
            seen: dict[str, str] = {}
            for name in names:
                folded = _path_fold(name)
                previous = seen.get(folded)
                if previous is not None:
                    raise CorpusError(
                        "directory holds two entries a case-insensitive filesystem "
                        f"would merge: {_quoted(_under(directory, previous))} and "
                        f"{_quoted(_under(directory, name))}"
                    )
                seen[folded] = name
            try:
                assert_no_merging_tree_names(
                    names,
                    repertoire=repertoire,
                    label=f"tree directory {_quoted(directory or '.')}",
                )
            except NamePolicyError as exc:
                raise CorpusError(str(exc)) from exc

    def _entries_by_directory(
        entries: Mapping[str, GitEntry],
    ) -> dict[str, dict[str, GitEntry]]:
        """Index an authenticated flat listing by each entry's immediate parent."""

        result: dict[str, dict[str, GitEntry]] = {}
        for path, entry in entries.items():
            parent, separator, name = path.rpartition("/")
            if not separator:
                parent, name = "", path
            result.setdefault(parent, {})[name] = entry
        return result

    def _assert_content_root_spellings(
        entries: Mapping[str, GitEntry],
        by_directory: Mapping[str, Mapping[str, GitEntry]],
        spec: CorpusSpec,
    ) -> None:
        """Retain the pinned-root alias refusal over immutable listing names."""

        for root in spec.content_roots:
            relative = root.as_posix()
            parent = ""
            for component in relative.split("/"):
                for name in sorted(by_directory.get(parent, {})):
                    if name != component and _path_fold(name) == _path_fold(component):
                        raise CorpusError(
                            f"tree entry {_quoted(name)} aliases the pinned content "
                            f"root component {_quoted(component)} on a case- or "
                            "normalization-insensitive filesystem"
                        )
                exact = _under(parent, component)
                entry = entries.get(exact)
                if entry is None or entry.mode != _TREE_MODE:
                    break
                parent = exact

    def _content_entries_from_listing(
        entries: Mapping[str, GitEntry], spec: CorpusSpec
    ) -> dict[str, GitEntry]:
        """Return the exact closed-world content set from one tree listing."""

        found: dict[str, GitEntry] = {}
        for content_root in spec.content_roots:
            base_relative = content_root.as_posix()
            root_entry = entries.get(base_relative)
            if root_entry is None:
                raise CorpusError(
                    f"pinned content root is absent from the tree: {base_relative}"
                )
            if root_entry.mode != _TREE_MODE:
                raise CorpusError(
                    f"pinned content root is not a directory: {base_relative}"
                )

            prefix = base_relative + "/"
            for relative in sorted(entries):
                if not relative.startswith(prefix):
                    continue
                entry = entries[relative]
                if entry.mode == "160000":
                    raise CorpusError(
                        f"content root contains a gitlink: {_quoted(relative)}"
                    )

                carries_suffix = _has_pinned_suffix(relative, spec.content_suffixes)
                if not carries_suffix:
                    if (
                        spec.name_repertoire == "portable"
                        and _short_name_carries_pinned_suffix(
                            relative.rpartition("/")[2], spec.content_suffixes
                        )
                    ):
                        raise CorpusError(
                            "content root contains a file whose short-name alias "
                            "would carry a pinned suffix: "
                            f"{_quoted(relative)}"
                        )
                    continue

                if entry.mode == "120000":
                    raise CorpusError(
                        "content root contains a symlink where a regular file was "
                        f"recorded: {_quoted(relative)}"
                    )
                if entry.mode not in _REGULAR_BLOB_MODES or entry.object_type != "blob":
                    raise CorpusError(
                        f"content root contains a non-regular file: {_quoted(relative)}"
                    )
                found[relative] = entry
        return found

    def _assert_tombstones_absent_from_listing(
        entries: Mapping[str, GitEntry], removed: tuple[str, ...]
    ) -> None:
        """Ask exact and ASCII-fold indexes once whether a removed path survives."""

        folded: dict[str, str] = {}
        for path in sorted(entries):
            folded.setdefault(_path_fold(path), path)
        for path in removed:
            if path in entries:
                raise CorpusError(f"removed path is still present in the tree: {path}")
            survivor = folded.get(_path_fold(path))
            if survivor is not None:
                raise CorpusError(
                    "removed path is still present in the tree under a spelling "
                    "that aliases it on a case- or normalization-insensitive "
                    f"filesystem: {path} ({_quoted(survivor)})"
                )

    def _attested_entries_from_snapshot(
        snapshot: TreeSnapshot, attested: Mapping[str, FileBinding]
    ) -> dict[str, GitEntry]:
        """Resolve every attested path exactly and require a regular blob."""

        result: dict[str, GitEntry] = {}
        for path in sorted(attested):
            try:
                entry = snapshot.entry(path)
            except SnapshotError as exc:
                raise CorpusError(
                    f"bound file is missing or not a regular file: {path}"
                ) from exc
            if entry.mode not in _REGULAR_BLOB_MODES or entry.object_type != "blob":
                raise CorpusError(f"bound file is not a regular file: {path}")
            result[path] = entry
        return result

    def verify_corpus_binding(
        snapshot: TreeSnapshot,
        journal_bytes: bytes,
        *,
        spec: CorpusSpec,
    ) -> CorpusVerification:
        """Prove the journal describes the immutable tree selected by ``snapshot``.

        ``journal_bytes`` are the bytes already authenticated by the custody pass.
        The tree is listed once as an immutable object; membership, tombstones,
        exact attested lookups, and streamed digests are all derived from that
        object. Checkout fidelity is outside this binding claim.
        """

        if not isinstance(snapshot, TreeSnapshot):
            raise CorpusError(
                "verify_corpus_binding requires a TreeSnapshot; select one with "
                "TreeSnapshot.select"
            )

        content, attested, gates, removed = parse_journal(journal_bytes, spec=spec)

        prefix_work = _PathPrefixWork()
        _reject_aliasing_paths(list(content) + list(attested), work=prefix_work)

        try:
            listing = snapshot.entries("")
        except SnapshotError as exc:
            raise CorpusError(str(exc)) from exc
        try:
            entries = listing.as_dict(include_trees=True)
        except SnapshotError as exc:
            raise CorpusError(str(exc)) from exc

        by_directory = _entries_by_directory(entries)
        _screen_tree_listing(
            entries,
            by_directory,
            repertoire=spec.name_repertoire,
        )
        _assert_content_root_spellings(entries, by_directory, spec)
        tree = _content_entries_from_listing(entries, spec)

        journal_paths = set(content)
        tree_paths = set(tree)
        unlisted = sorted(tree_paths - journal_paths)
        if unlisted:
            raise CorpusError(
                f"{len(unlisted)} content file(s) in the tree are not bound by the "
                f"witnessed journal, starting with {_quoted(unlisted[0])}"
            )
        absent = sorted(journal_paths - tree_paths)
        if absent:
            raise CorpusError(
                f"{len(absent)} content file(s) bound by the journal are missing "
                f"from the tree, starting with {_quoted(absent[0])}"
            )

        _assert_tombstones_absent_from_listing(entries, removed)

        missing_required = sorted(spec.required_attested_paths - set(attested))
        if missing_required:
            raise CorpusError(
                "the witnessed journal does not attest a path the pinned spec "
                f"requires: {_quoted(missing_required[0])}"
            )
        attested_entries = _attested_entries_from_snapshot(snapshot, attested)

        _verify_binding_digests(
            snapshot,
            content,
            tree,
            attested,
            attested_entries,
        )

        return CorpusVerification(
            content=tuple(content[path] for path in sorted(content)),
            attested=tuple(attested[path] for path in sorted(attested)),
            gates=gates,
            removed_paths=removed,
            name_repertoire=spec.name_repertoire,
        )

PR5_BODY_SHA256 = {'PR5Append': {'_state_entry': '7c7b1d2ecdcc45b1a65d7ef9e766107617b334a3839805a2accf584ac66220ed', '_screen_candidate_tree_aliases': 'd71170dacdebd782a026977b48e471a2c682476063eee01aaf30af4b43765df6', '_attribute_entries': 'd00623c0c560ff2f862a7c9b8d2bace83060d0822f486aceb40d9da782cea698', '_candidate_release_entries_regular': '3ab34473c1ee5f9c8c5c8f5cca10927d99258a48d353cf73546b5e72d1304b7b', '_screen_candidate_materialization': '8328781ce6c7b24d5db731b1259844a082e54b2d1f6696f83803914aa6ddaf95', '_verify_candidate_release_chain': '4779a3d5d10485dff8c072b8c39cbfcb6fe25cd9aab35e2ed9ced6d66a29fa1a', 'check_release_proposal': 'dcf1af93218807c07755b1efe4da6760e84f22f69dfd4a616a094236df0e9d7d', 'check_release_chain_without_base': '5e6d17a1f63eee32cd8621993a916a3039dd10d9077bd8acc2e7be2995dcdde7', '_verify_selected_tree': 'bc8eef49ac8e9462bdde6f09691486352c07c328e6d3ad23a12c4569735504e7'}, 'PR5Corpus': {'_path_fold': 'ab1b0855760740ea63f7a79b845b1705528a9a31bed8a59dbd22b646d3f09401', '_reject_aliasing_paths': 'f9d8ac5f602931db4c176f4eb974913516ea842c5c703d8df003b32c60e1c08a', '_screen_tree_listing': 'bad1d7596bf4f5544696df316b8459ee8bc44c026f041e61464e139a3b147fc7', '_entries_by_directory': '861cf5c7b7a315fab969eebf79fb1bd0de614e2ba61b006c1d0c480c0b820eda', '_assert_content_root_spellings': 'be90893262b73ca44e805a70b8880bcab8d179e6e9d814ef0b70436482f26317', '_content_entries_from_listing': 'e8b80b482aab2ef3c0a56b3810afa2de56ff134985a3215087a4235dbdd383e4', '_assert_tombstones_absent_from_listing': 'a24667effc94c94279e62a2a7c4d42fd4bfc6b5c6335772aed3380d867ce2e20', '_attested_entries_from_snapshot': '7e5e1d8e59b3bc103d55171673da34f32133843af1c945a56e2ca96604e8bad8', 'verify_corpus_binding': '8211d7bacd8e4495e4e6430c305f04eea32604290d2ee91e01aed1bb1ff78101'}}


# PR6 bodies copied verbatim with git show v0.6.1 (3a7ee943817786671535f17ebd4fbb207730eace).

class PR6Names:
    def assert_no_merging_entries(
        names: Iterable[bytes | str],
        *,
        repertoire: str,
        materializing: bool = False,
        label: str = "tree directory",
    ) -> None:
        """Refuse siblings whose raw names agree after ASCII case folding.

        ``names`` is one directory's immediate children, not full paths.  Each
        component is validated before it enters the fold index.  Passing
        ``materializing=True`` applies the portable screen to every component
        before the caller may create any host path.
        """

        selected = validate_repertoire(repertoire)
        seen: dict[bytes, tuple[bytes, str]] = {}
        for value in names:
            if type(value) is bytes:
                raw = validate_component_bytes(value, label="tree entry name")
                text = decode_component(
                    raw,
                    repertoire=selected,
                    materializing=materializing,
                    label="tree entry name",
                )
                try:
                    raw.decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    raise NamePolicyError(
                        "tree entry name is not valid UTF-8 for folding"
                    ) from exc
            elif type(value) is str:
                text = validate_component_text(
                    value,
                    repertoire=selected,
                    materializing=materializing,
                    label="tree entry name",
                )
                raw = _text_as_tree_bytes(text, "tree entry name")
                try:
                    raw.decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    raise NamePolicyError(
                        "tree entry name is not valid UTF-8 for folding"
                    ) from exc
            else:
                raise NamePolicyError(
                    f"tree entry name must be bytes or text: {value!r}"
                )

            folded = raw.translate(_ASCII_LOWER)
            previous = seen.get(folded)
            if previous is not None:
                previous_raw, previous_text = previous
                if previous_raw == raw:
                    raise NamePolicyError(
                        f"{label} contains a duplicate entry name: {text!r}"
                    )
                raise NamePolicyError(
                    f"{label} contains names that merge under ASCII case folding: "
                    f"{previous_text!r} and {text!r}"
                )
            seen[folded] = (raw, text)

class PR6Snapshot:
    def blob(self, entry: GitEntry, *, limit: int) -> bytes:
        """Return one authenticated blob payload under a required caller limit."""

        object_id = self._require_entry(entry)
        if type(limit) is not int or limit < 0:
            raise SnapshotError("blob limit must be a non-negative integer")
        if entry.object_type != "blob":
            raise SnapshotError(
                f"object {entry.object_id} is a {entry.object_type}, not the blob "
                "its reference requires"
            )
        if entry.mode not in _CONTENT_MODES:
            raise SnapshotError(
                f"tree entry has non-regular mode {entry.mode}: {entry.path}"
            )
        payload = self._batch().consume(
            object_id,
            role="blob",
            limit=limit,
            hold=True,
        )
        assert payload is not None
        return payload

class PR6Digest:
    def __next__(self) -> tuple[GitEntry, str]:
        if self._done or self._closed:
            raise StopIteration
        try:
            self._snapshot._batch(digest_token=self._token)
        except BaseException:
            self.close()
            raise
        try:
            entry = next(self._entries)
        except StopIteration:
            self._done = True
            if self._snapshot._state.active_digest_token is self._token:
                self._snapshot._state.active_digest_token = None
            raise
        except BaseException:
            self.close()
            raise
        self._count += 1
        if self._count > MAX_TREE_ENTRIES:
            self.close()
            raise SnapshotError(
                f"content entries exceed the budget of {MAX_TREE_ENTRIES} entries"
            )
        if not isinstance(entry, GitEntry):
            self.close()
            raise SnapshotError("digests entries must all be GitEntry objects")
        try:
            object_id = self._snapshot._require_entry(entry)
        except BaseException:
            self.close()
            raise
        if entry.object_type != "blob":
            self.close()
            raise SnapshotError(
                f"object {entry.object_id} is a {entry.object_type}, not the blob "
                "its reference requires"
            )
        if entry.mode not in _CONTENT_MODES:
            self.close()
            raise SnapshotError(
                f"tree entry has non-regular mode {entry.mode}: {entry.path}"
            )
        batch = self._snapshot._batch(digest_token=self._token)
        try:
            _object_type, size = batch.info(object_id, role="blob")
        except BaseException:
            self.close()
            raise
        per_blob_limit = min(self._per_blob, MAX_CONTENT_BLOB_BYTES)
        if size > per_blob_limit:
            self.close()
            raise SnapshotError(
                f"content blob {entry.path!r} exceeds the budget of "
                f"{per_blob_limit} bytes"
            )
        work = self._snapshot._state.work
        if self._charged + size > self._total:
            self.close()
            raise SnapshotError(
                f"content bytes exceed the budget of {self._total} bytes"
            )
        if self._snapshot._verification_total("content_bytes") + size > MAX_CONTENT_BYTES_TOTAL:
            self.close()
            raise SnapshotError(
                f"content bytes exceed the snapshot budget of "
                f"{MAX_CONTENT_BYTES_TOTAL} bytes"
            )
        digest = hashlib.sha256()

        def consume(chunk: bytes) -> None:
            digest.update(chunk)
            self._snapshot._charge_verification(
                "content_bytes",
                len(chunk),
                ceiling=MAX_CONTENT_BYTES_TOTAL,
                message=(
                    f"content bytes exceed the snapshot budget of "
                    f"{MAX_CONTENT_BYTES_TOTAL} bytes"
                ),
            )

        try:
            batch.consume(
                object_id,
                role="blob",
                limit=per_blob_limit,
                consumer=consume,
            )
        except BaseException:
            self.close()
            raise
        self._charged += size
        work.max_content_blob_bytes = max(work.max_content_blob_bytes, size)
        return entry, digest.hexdigest()

class PR6Corpus:
    def _has_pinned_suffix(relative: str, suffixes: tuple[str, ...]) -> bool:
        """Whether a path ends in a pinned suffix after the policy's ASCII fold."""

        folded = _path_fold(relative)
        return any(folded.endswith(_path_fold(suffix)) for suffix in suffixes)


PR6_BODY_SHA256 = {'PR6Names': {'assert_no_merging_entries': '063e3a8cbfb7e4a2471e2f39d970d1ce5fa54b86c0772c902b18fa93756828e4'}, 'PR6Snapshot': {'blob': '9b7c0c58fd9e7f1ab57469866079a66795ae370c43016a41c223c413750577df'}, 'PR6Digest': {'__next__': '490d613f4a4711a78badce40afc3a69b37ac39142c7246e5bd11519850f2e145'}, 'PR6Corpus': {'_has_pinned_suffix': '81dcc36394024c169a87232611953b33d194cd6af4c76d20382e661062c4bb13'}}

# Keep old name/export comparisons independent of the migrated primitive facade.
from types import FunctionType as _LegacyFunctionType
from receipt import _names as _legacy_names_namespace
assert_no_merging_entries = _LegacyFunctionType(
    PR6Names.assert_no_merging_entries.__code__, _legacy_names_namespace.__dict__,
    argdefs=PR6Names.assert_no_merging_entries.__defaults__)
assert_no_merging_entries.__kwdefaults__ = PR6Names.assert_no_merging_entries.__kwdefaults__
