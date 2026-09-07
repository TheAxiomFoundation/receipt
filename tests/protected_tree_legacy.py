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
