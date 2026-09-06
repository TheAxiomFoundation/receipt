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

