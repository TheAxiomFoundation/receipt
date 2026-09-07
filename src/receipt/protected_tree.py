"""Authenticated name and shape evidence for receipt 0.7 M1.

Names, configured aliases and scoped DOS suffixes are evaluated only at the
caller's existing barriers. The snapshot still owns object authentication and
structural/admission charges. Shape stages consume admitted metadata at the
caller's barrier; export certification precedes writing. Attributes remain PR4 work.

The mapping and sibling compatibility adapters confer no payload authority.
Only TreePolicy, over an entered snapshot, can issue a ProtectedTreeView.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, fields, replace
from pathlib import PurePosixPath
from types import MappingProxyType
from weakref import WeakValueDictionary

from receipt import _names, snapshot

POLICY_VERSION = "v0.6"
NAME_STAGES = ("aliases", "names", "siblings", "suffixes")
SHAPE_STAGES = ("ancestors", "modes")
EXPORT_STAGES = ("ancestors", "modes", "export-names")


class PolicyUseError(RuntimeError):
    """Internal misuse of authenticated evidence, never a repository refusal."""


def _paths(values: Iterable[str | PurePosixPath]) -> tuple[str, ...]:
    # Plans compile admitted configuration, not an alternative spec parser.
    result = tuple(p.as_posix() if isinstance(p, PurePosixPath) else p for p in values)
    if any(type(p) is not str for p in result):
        raise PolicyUseError("plan selectors must be admitted path strings")
    return result


@dataclass(frozen=True)
class ProtectionPlan:
    """Ordered, frozen obligations compiled from already admitted specs.

    Configuration admission and append surface classification remain with their
    callers. listing_scope names exactly the subtrees read at this barrier;
    ancestor_listing_scope selects immediate listings, not their descendants.
    Later-stage fields participate in identity even before they are evaluated.
    """

    repertoire: str = "portable"
    selected_prefixes: tuple[str, ...] = ()
    configured_alias_targets: tuple[str, ...] = ()
    ancestor_listing_scope: tuple[str, ...] = ()
    whole_tree_name_scope: bool = False
    content_roots: tuple[str, ...] = ()
    content_suffixes: tuple[str, ...] = ()
    exact_state_paths: tuple[str, ...] = ()
    exact_attested_paths: tuple[str, ...] = ()
    export_prefixes: tuple[str, ...] = ()
    attribute_target_selectors: tuple[str, ...] = ()
    anchor_origin: str = "tree"
    use: str = "chain-names"
    phase: str = "names"
    obligations: tuple[str, ...] = NAME_STAGES
    listing_scope: tuple[str, ...] = ("",)
    fold_whole_alias_paths: bool = False
    mode_roles: tuple[tuple[str, str], ...] = ()
    ancestor_paths: tuple[str, ...] = ()
    require_ancestors: bool = False
    # Preserve bytes/text argument spelling until the legacy enter-time admission.
    export_requests: tuple[str | bytes, ...] = ()

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if item.name in {
                "selected_prefixes", "configured_alias_targets",
                "ancestor_listing_scope", "content_roots", "content_suffixes",
                "exact_state_paths", "exact_attested_paths", "export_prefixes",
                "attribute_target_selectors", "obligations", "listing_scope", "ancestor_paths",
            }:
                object.__setattr__(self, item.name, _paths(value))
        object.__setattr__(self, "export_requests", tuple(self.export_requests))
        roles = tuple((_paths((path,))[0], role) for path, role in self.mode_roles)
        if any(role not in MODE_ROLES for _, role in roles):
            raise PolicyUseError("unknown protected entry role")
        object.__setattr__(self, "mode_roles", roles)

    @classmethod
    def chain_names(
        cls, prefixes: tuple[PurePosixPath, ...], *, repertoire: str,
        release_directories: tuple[PurePosixPath, ...],
        alias_paths: tuple[str, ...] | None = None,
        use: str = "chain-names", anchor_origin: str = "tree",
    ) -> ProtectionPlan:
        """Compile the retained chain/append facade without re-admitting specs."""
        selected = _paths(prefixes)
        ancestors = tuple(dict.fromkeys(
            "/".join(relative.parts[:depth])
            for relative in prefixes for depth in range(len(relative.parts))
        ))
        return cls(
            repertoire=repertoire, selected_prefixes=selected,
            configured_alias_targets=selected if alias_paths is None else alias_paths,
            ancestor_listing_scope=ancestors, content_roots=_paths(release_directories),
            content_suffixes=(".json", ".sig", ".tsr"), export_prefixes=selected,
            fold_whole_alias_paths=alias_paths is not None,
            anchor_origin=anchor_origin, use=use,
        )

    @classmethod
    def materialization(cls, prefixes: tuple[str | bytes, ...], *, repertoire: str) -> ProtectionPlan:
        """Compile admitted collection arguments; path admission stays lazy."""
        return cls(repertoire=repertoire,
                   export_prefixes=tuple(snapshot._tree_path_decode(p) if type(p) is bytes else p
                                         for p in prefixes),
                   export_requests=prefixes, listing_scope=(), obligations=EXPORT_STAGES,
                   use="materialize", phase="export")

    @property
    def fingerprint(self) -> str:
        values = tuple((f.name, getattr(self, f.name)) for f in fields(self))
        return hashlib.sha256(repr(values).encode("utf-8", "surrogateescape")).hexdigest()


@dataclass(frozen=True)
class Finding:
    """One condition and compact witnesses at a nested execution position.

    Primitive diagnostics retain their exact original text alongside operation,
    input and context. Alias/collision/suffix findings retain spelling witnesses;
    their caller, not this record, chooses public words and exception classes.
    """

    kind: str
    stage: str
    position: tuple[int, ...]
    path: str = ""
    raw_path: bytes | None = None
    parent: str = ""
    name: str = ""
    other_name: str = ""
    target: str = ""
    prefix: str = ""
    suffixes: tuple[str, ...] = ()
    operation: str = ""
    detail: str = ""
    mode: str = ""
    object_type: str = ""
    role: str = ""


MODE_ROLES = frozenset(("release-leaf", "state-leaf", "manifest-child", "ancestor", "export-leaf"))


@dataclass(frozen=True)
class ModeFact:
    """Object/leaf classification, independent of a caller's refusal text."""

    mode: str
    object_type: str
    shape: str

    @property
    def regular(self) -> bool:
        return self.shape in {"regular", "executable"}

    @property
    def directory(self) -> bool:
        return self.shape in {"tree", "empty-tree"}

    def finding(self, path: str, role: str, *, position: tuple[int, ...] = ()) -> Finding | None:
        if role not in MODE_ROLES:
            raise PolicyUseError("unknown protected entry role")
        if self.directory if role == "ancestor" else self.regular:
            return None
        kind = ("missing" if self.shape == "missing" else
                "symlink" if self.shape == "symlink" else
                "non-directory" if role == "ancestor" else "non-regular")
        return Finding(kind, "modes", position, path=path,
                       raw_path=path.encode("utf-8", "surrogateescape"),
                       parent=path.rpartition("/")[0], name=path.rpartition("/")[2],
                       mode=self.mode, object_type=self.object_type, role=role)


def classify_mode(mode: str, object_type: str, *, empty: bool = False) -> ModeFact:
    """Classify already authenticated metadata; never probe a Git object."""
    shapes = {("100644", "blob"): "regular", ("100755", "blob"): "executable",
              ("120000", "blob"): "symlink", ("160000", "commit"): "gitlink",
              ("040000", "tree"): "empty-tree" if empty else "tree",
              ("", ""): "missing"}
    return ModeFact(mode, object_type, shapes.get((mode, object_type), "object-type"))


def ancestor_finding(target: str, prefix: str, mode: str, object_type: str,
                     *, position: tuple[int, ...] = ()) -> Finding | None:
    """One reached component, also used by the reader's three walk facades.

    Missing witnesses keep both the requested path and first absent component.
    The reader decides whether absence is optional at its existing barrier.
    """
    fact = classify_mode(mode, object_type)
    finding = fact.finding(prefix, "ancestor", position=position)
    if finding is None:
        return None
    return replace(finding, stage="ancestors", target=target, prefix=prefix)


@dataclass(frozen=True)
class ShapeWork:
    mode_classifications: int = 0
    ancestor_steps: int = 0
    mode_cache_entries: int = 0
    ancestor_cache_entries: int = 0


class _ShapeFacts:
    def __init__(self):
        self.modes: dict[tuple[str, str, str, bool], ModeFact] = {}
        self.ancestors: dict[str, Finding | None] = {}
        self.steps = 0

    @property
    def work(self) -> ShapeWork:
        return ShapeWork(len(self.modes), self.steps, len(self.modes), len(self.ancestors))

    def mode(self, path: str, entry: snapshot.GitEntry | None, *, empty: bool = False) -> ModeFact:
        mode, kind = (entry.mode, entry.object_type) if entry is not None else ("", "")
        return self.metadata(path, mode, kind, empty=empty)

    def metadata(self, path: str, mode: str, kind: str, *, empty: bool = False) -> ModeFact:
        key = path, mode, kind, empty
        if key not in self.modes:
            self.modes[key] = classify_mode(mode, kind, empty=empty)
        return self.modes[key]

    def ancestor(self, target: str, entries: Mapping[str, snapshot.GitEntry]) -> Finding | None:
        if target not in self.ancestors:
            result = None
            parts = target.split("/")
            for depth in range(1, len(parts)):
                self.steps += 1
                prefix = "/".join(parts[:depth])
                entry = entries.get(prefix)
                fact = self.mode(prefix, entry)
                finding = fact.finding(prefix, "ancestor", position=(depth,))
                if finding is not None:
                    result = replace(finding, stage="ancestors", target=target, prefix=prefix)
                    break
            self.ancestors[target] = result
        return self.ancestors[target]


def export_prefixes(subject: snapshot.TreeSnapshot,
                    prefixes: Iterable[str | bytes]) -> tuple[tuple[bytes, ...], ...]:
    """Legacy supplied-path charges precede prefix deduplication."""
    parts: set[tuple[bytes, ...]] = set()
    for prefix in prefixes:
        parsed = subject._path_parts(prefix, allow_empty=True)
        subject._charge_path_bytes(b"/".join(parsed))
        parts.add(parsed)
    kept: list[tuple[bytes, ...]] = []
    for candidate in sorted(parts):
        if kept and candidate[:len(kept[-1])] == kept[-1]:
            continue
        kept.append(candidate)
    return tuple(kept)


@dataclass(frozen=True)
class ExportWork:
    """Actual export work, independent of the retained reader admission ledger."""

    prefixes: int = 0
    leaves: int = 0
    components: int = 0
    directory_records: int = 0


@dataclass(frozen=True)
class NameWork:
    """Actual computation, distinct from the public SnapshotWork ledger."""

    folds: int = 0
    alias_steps: int = 0
    scope_steps: int = 0
    sibling_steps: int = 0
    suffix_checks: int = 0
    fold_index_entries: int = 0
    alias_index_nodes: int = 0


class _Refusal(Exception):
    def __init__(self, finding: Finding):
        self.finding = finding


class _SiblingCollision(_names.NamePolicyError):
    def __init__(self, message: str, *, name: str, other: str, ordinal: int,
                 duplicate: bool):
        super().__init__(message)
        self.name, self.other, self.ordinal = name, other, ordinal
        self.duplicate = duplicate


@dataclass
class _AliasNode:
    children: dict[str, _AliasNode] = field(default_factory=dict)
    # Earliest target, then earliest target with a different exact prefix.
    first: tuple[int, str, tuple[str, ...]] | None = None
    second: tuple[int, str, tuple[str, ...]] | None = None
    continuing: int | None = None

    def match(self, key: str) -> _AliasNode | None:
        return self.children.get(key)

    def add(self, witness: tuple[int, str, tuple[str, ...]]) -> None:
        if self.first is None:
            self.first = witness
        elif self.second is None and witness[2] != self.first[2]:
            self.second = witness

    def alias(self, exact: tuple[str, ...]):
        return self.second if self.first is not None and self.first[2] == exact else self.first


class _NameFacts:
    """Private bounded component cache and shared name algorithms.

    Each distinct supplied component is folded at most once, including failures.
    Trie nodes grow with unique configured components; each node stores two
    witnesses rather than all colliding pairs. No new admission ceiling is used.
    """

    def __init__(self) -> None:
        self.folds: dict[str, str | _names.NamePolicyError] = {}
        self.counts = dict(folds=0, alias_steps=0, scope_steps=0,
                           sibling_steps=0, suffix_checks=0, alias_index_nodes=0)

    @property
    def work(self) -> NameWork:
        return NameWork(**self.counts, fold_index_entries=len(self.folds))

    def fold(self, name: str) -> str:
        if name not in self.folds:
            self.counts["folds"] += 1
            try:
                self.folds[name] = _names.ascii_fold_text(name)
            except _names.NamePolicyError as exc:
                self.folds[name] = _names.NamePolicyError(str(exc))
        value = self.folds[name]
        if isinstance(value, _names.NamePolicyError):
            raise _names.NamePolicyError(str(value))
        return value

    def folded_parts(self, path: str) -> tuple[str, ...]:
        return tuple(self.fold(part) for part in path.split("/"))

    def path_fold(self, path: str, *, operation: str,
                  position: tuple[int, ...]) -> tuple[str, ...]:
        return tuple(self.primitive(
            operation, lambda: self.fold(part), stage="aliases",
            position=(*position, depth), path=path, name=part,
        ) for depth, part in enumerate(path.split("/"), start=1))

    def primitive(self, operation: str, call: Callable, *, stage: str,
                  position: tuple[int, ...], path: str, name: str = ""):
        try:
            return call()
        except _names.NamePolicyError as exc:
            try:
                raw_path = path.encode("utf-8", "surrogateescape")
            except UnicodeEncodeError:
                # A compatibility mapping can contain text that cannot be Git
                # bytes at all. Preserve its original primitive refusal.
                raw_path = None
            raise _Refusal(Finding(
                "name", stage, position, path=path,
                raw_path=raw_path, name=name,
                parent=path.rpartition("/")[0], operation=operation, detail=str(exc),
            )) from exc

    def aliases(self, entries: Mapping[str, snapshot.GitEntry], plan: ProtectionPlan) -> None:
        root = _AliasNode()
        # Supplied target order is an earlier barrier than any listed entry.
        seen_targets: set[str] = set()
        for ordinal, path in enumerate(plan.configured_alias_targets):
            if path in seen_targets:
                continue
            seen_targets.add(path)
            exact = tuple(path.split("/"))
            folded = self.path_fold(path, operation="target-fold", position=(0, ordinal))
            node = root
            for depth, key in enumerate(folded, start=1):
                if node.continuing is None:
                    node.continuing = ordinal
                if key not in node.children:
                    node.children[key] = _AliasNode()
                    self.counts["alias_index_nodes"] += 1
                node = node.children[key]
                node.add((ordinal, path, exact[:depth]))

        for ordinal, listed in enumerate(sorted(
            entries, key=lambda path: (entries[path].mode == "040000", path),
        )):
            parts = tuple(listed.split("/"))
            folded = self.path_fold(
                listed, operation="whole-path-fold", position=(1, ordinal, 0),
            ) if plan.fold_whole_alias_paths else ()
            node = root
            winner: tuple[int, int, str, tuple[str, ...]] | None = None
            for depth, part in enumerate(parts, start=1):
                if not node.children:
                    break
                # A prior alias would fold its full diagnostic before the
                # legacy traversal could reach a later, unfoldable component.
                try:
                    key = folded[depth - 1] if folded else self.primitive(
                        "reached-component-fold", lambda: self.fold(part), stage="aliases",
                        position=(1, ordinal, 1, node.continuing, depth, 0),
                        path=listed, name=part,
                    )
                except _Refusal:
                    if winner is not None and winner[0] <= node.continuing:
                        self.path_fold(listed, operation="diagnostic-fold",
                            position=(1, ordinal, 1, winner[0], winner[1], 1))
                    raise
                self.counts["alias_steps"] += 1
                child = node.match(key)
                if child is None:
                    break
                node = child
                witness = node.alias(parts[:depth])
                if witness is not None:
                    candidate = (witness[0], depth, witness[1], witness[2])
                    if winner is None or candidate[:2] < winner[:2]:
                        winner = candidate
            if winner is not None:
                target_ordinal, depth, target, exact = winner
                position = (1, ordinal, 1, target_ordinal, depth, 1)
                self.path_fold(listed, operation="diagnostic-fold", position=position)
                raise _Refusal(Finding(
                    "configured-alias", "aliases", position, path=listed,
                    raw_path=listed.encode("utf-8", "surrogateescape"),
                    target=target, prefix="/".join(exact),
                ))

    def in_roots(self, path: str, roots: set[str], *, descendants_only: bool = False) -> bool:
        parts = path.split("/")
        for depth in range(len(parts) if descendants_only else len(parts) + 1):
            self.counts["scope_steps"] += 1
            if "/".join(parts[:depth]) in roots:
                return True
        return False

    def scoped(self, entries: Mapping[str, snapshot.GitEntry], plan: ProtectionPlan) -> tuple[str, ...]:
        ancestors = set(plan.ancestor_listing_scope)
        selected = set(plan.selected_prefixes)
        return tuple(path for path in sorted(entries) if (
            plan.whole_tree_name_scope or path.rpartition("/")[0] in ancestors
            or self.in_roots(path, selected)
        ))

    def names(self, paths: tuple[str, ...], plan: ProtectionPlan) -> None:
        for ordinal, path in enumerate(paths):
            name = path.rpartition("/")[2]
            self.primitive("local-fold", lambda: self.fold(name), stage="names",
                           position=(ordinal, 0), path=path, name=name)
            self.primitive(
                "component", lambda: (
                    _names.assert_portable_name(name, f"tree entry {path!r}")
                    if plan.repertoire == "portable" else
                    _names.validate_component_text(name, repertoire=plan.repertoire,
                                                   label=f"tree entry {path!r}")
                ), stage="names", position=(ordinal, 1), path=path, name=name,
            )

    def siblings(self, names: Iterable[bytes | str], *, repertoire: str,
                 materializing: bool, label: str) -> None:
        # Admission, fold and collision are interleaved per local name. This
        # also serves snapshot's narrower materializing sibling facade.
        selected = _names.validate_repertoire(repertoire)
        seen: dict[str, tuple[bytes, str]] = {}
        for ordinal, value in enumerate(names):
            self.counts["sibling_steps"] += 1
            if type(value) is bytes:
                raw = _names.validate_component_bytes(value, label="tree entry name")
                text = _names.decode_component(raw, repertoire=selected,
                                              materializing=materializing)
            elif type(value) is str:
                text = _names.validate_component_text(value, repertoire=selected,
                                                     materializing=materializing)
                raw = text.encode("utf-8", "surrogateescape")
            else:
                raise _names.NamePolicyError(f"tree entry name must be bytes or text: {value!r}")
            folded = self.fold(text)
            previous = seen.get(folded)
            if previous is not None:
                prior_raw, prior_text = previous
                if prior_raw == raw:
                    raise _SiblingCollision(
                        f"{label} contains a duplicate entry name: {text!r}",
                        name=text, other=prior_text, ordinal=ordinal, duplicate=True,
                    )
                raise _SiblingCollision(
                    f"{label} contains names that merge under ASCII case folding: "
                    f"{prior_text!r} and {text!r}", name=text, other=prior_text,
                    ordinal=ordinal, duplicate=False,
                )
            seen[folded] = (raw, text)

    def sibling_paths(self, paths: tuple[str, ...], plan: ProtectionPlan) -> None:
        by_directory: dict[str, list[str]] = {}
        for path in paths:
            directory, _, name = path.rpartition("/")
            by_directory.setdefault(directory, []).append(name)
        for ordinal, (directory, names) in enumerate(sorted(by_directory.items())):
            try:
                self.siblings(
                    names, repertoire=plan.repertoire, materializing=False,
                    label=f"tree directory {directory or '.'!r}",
                )
            except _SiblingCollision as exc:
                path = f"{directory}/{exc.name}" if directory else exc.name
                raise _Refusal(Finding(
                    "duplicate" if exc.duplicate else "sibling-alias", "siblings",
                    (ordinal, exc.ordinal), path=path,
                    raw_path=path.encode("utf-8", "surrogateescape"),
                    parent=directory, name=exc.name, other_name=exc.other,
                    operation="siblings", detail=str(exc),
                )) from exc
            except _names.NamePolicyError as exc:
                raise _Refusal(Finding(
                    "name", "siblings", (ordinal,), path=directory,
                    operation="siblings", detail=str(exc),
                )) from exc

    def suffixes(self, paths: tuple[str, ...], plan: ProtectionPlan) -> None:
        if plan.repertoire != "portable":
            return
        roots = set(plan.content_roots)
        for ordinal, path in enumerate(paths):
            if not self.in_roots(path, roots, descendants_only=True):
                continue
            name = path.rpartition("/")[2]
            self.counts["suffix_checks"] += 1
            if not self.fold(name).endswith(plan.content_suffixes) and (
                _names.short_name_carries_pinned_suffix(name, plan.content_suffixes)
            ):
                raise _Refusal(Finding(
                    "short-suffix", "suffixes", (ordinal,), path=path,
                    raw_path=path.encode("utf-8", "surrogateescape"),
                    parent=path.rpartition("/")[0], name=name,
                    suffixes=plan.content_suffixes,
                ))


class _NameRun:
    def __init__(self, entries: Mapping[str, snapshot.GitEntry], plan: ProtectionPlan,
                 facts: _NameFacts):
        self.entries = entries
        self.plan = plan
        self.facts = facts
        self.completed: set[str] = set()
        self.findings: list[Finding] = []
        self.paths: tuple[str, ...] | None = None
        self.mode_facts: dict[tuple[str, str], ModeFact] = {}
        self.raw_listings: dict[str, tuple[snapshot._RawTreeEntry, ...]] = {}
        self.tree_ids: dict[str, str | None] = {}
        self.export_siblings: dict[tuple[bytes, ...], set[bytes]] = {}

    def evaluate(self, stage: str) -> None:
        if stage not in NAME_STAGES:
            raise NotImplementedError(f"protected-tree stage {stage!r} belongs to a later migration")
        for current in NAME_STAGES[:NAME_STAGES.index(stage) + 1]:
            if current not in self.plan.obligations or current in self.completed:
                continue
            if self.findings:
                return
            try:
                if current == "aliases":
                    self.facts.aliases(self.entries, self.plan)
                else:
                    if self.paths is None:
                        self.paths = self.facts.scoped(self.entries, self.plan)
                    if current == "names":
                        self.facts.names(self.paths, self.plan)
                    elif current == "siblings":
                        self.facts.sibling_paths(self.paths, self.plan)
                    else:
                        self.facts.suffixes(self.paths, self.plan)
            except _Refusal as exc:
                self.findings.append(exc.finding)
                return
            self.completed.add(current)


def folded_parts(path: str) -> tuple[str, ...]:
    """Compatibility primitive for the retained chain helper import path."""
    return _NameFacts().folded_parts(path)


def evaluate_name_mapping(entries: Mapping[str, snapshot.GitEntry], plan: ProtectionPlan) -> Finding | None:
    """Compatibility evidence only: supplied mappings never certify payloads."""
    run = _NameRun(entries, plan, _NameFacts())
    run.evaluate("suffixes")
    return run.findings[0] if run.findings else None


def screen_siblings(names: Iterable[bytes | str], *, repertoire: str,
                    materializing: bool = False, label: str = "tree directory") -> None:
    """Shared implementation of the snapshot's legacy local-name screen."""
    try:
        _NameFacts().siblings(names, repertoire=repertoire, materializing=materializing, label=label)
    except _SiblingCollision as exc:
        # The old helper exposes exactly NamePolicyError, not an internal type.
        raise _names.NamePolicyError(str(exc)) from exc


@dataclass(frozen=True)
class SubjectIdentity:
    """Session provenance, repository and immutable object identity."""

    session: object = field(repr=False)
    repository: str
    object_format: str
    commit: str
    tree: str


@dataclass(frozen=True)
class TreePolicy:
    """Verification-local evaluator over an entered authenticated TreeSnapshot.

    The fixed version describes v0.6 exact-plus-ASCII-fold attribute semantics.
    Reader limits/hooks are consulted at call time. Private caches share the
    snapshot's existing candidate/base ledger, never acceptance across subjects.
    """

    snapshot: snapshot.TreeSnapshot
    policy_version: str = field(kw_only=True)
    work: snapshot.SnapshotWork = field(kw_only=True)
    _facts: _NameFacts = field(default_factory=_NameFacts, init=False, repr=False, compare=False)
    _shapes: _ShapeFacts = field(default_factory=_ShapeFacts, init=False, repr=False, compare=False)
    _entries: dict[str, snapshot.GitEntry] = field(default_factory=dict, init=False, repr=False, compare=False)
    _scopes: dict[str, str | None] = field(default_factory=dict, init=False, repr=False, compare=False)
    _empty_roots: dict[str, bool] = field(default_factory=dict, init=False, repr=False, compare=False)
    _runs: dict[ProtectionPlan, _NameRun] = field(default_factory=dict, init=False, repr=False, compare=False)
    _export_counts: dict[str, int] = field(default_factory=lambda: dict(prefixes=0, leaves=0, components=0, directory_records=0), init=False, repr=False, compare=False)
    _views: WeakValueDictionary = field(default_factory=WeakValueDictionary, init=False, repr=False, compare=False)
    _selections: WeakValueDictionary = field(default_factory=WeakValueDictionary, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.snapshot) is not snapshot.TreeSnapshot or self.work is not self.snapshot.work:
            raise PolicyUseError("policy subject/work mismatch")
        if self.policy_version != POLICY_VERSION:
            raise PolicyUseError("unsupported protected-tree policy version")
        self.snapshot._batch()

    @property
    def subject(self) -> SubjectIdentity:
        return SubjectIdentity(self.snapshot._state.entry_token, str(self.snapshot.git_dir),
                               self.snapshot.object_format, self.snapshot.commit, self.snapshot.tree)

    @property
    def name_work(self) -> NameWork:
        return self._facts.work

    @property
    def shape_work(self) -> ShapeWork:
        return self._shapes.work

    @property
    def export_work(self) -> ExportWork:
        return ExportWork(**self._export_counts)

    def _read_export(self, plan: ProtectionPlan) -> _NameRun:
        """Acquire exactly the old export reads, retaining uncharged raw topology.

        Immediate ancestor records prove spellings/declared modes only: their
        off-scope object types have not been probed. Selected TreeListing nodes
        additionally authenticate tree objects, including empty trees. Neither
        kind of directory observation creates a payload-capable GitEntry.
        """
        selected: dict[str, snapshot.GitEntry] = {}
        run = _NameRun(MappingProxyType(selected), plan, self._facts)

        def remember(parts, records, oid):
            path = snapshot._tree_path_decode(b"/".join(parts))
            if path not in run.raw_listings:
                run.raw_listings[path] = records
                run.tree_ids[path] = oid
                self._export_counts["directory_records"] += len(records)

        def topology(parts, node):
            remember(parts, tuple(r.raw for r in node.records), node.tree_oid)
            path = snapshot._tree_path_decode(b"/".join(parts))
            run.mode_facts[path, "ancestor"] = self._shapes.metadata(
                path, "040000", "tree", empty=not node.records)
            for record in node.records:
                if record.child is not None:
                    topology((*parts, record.raw.name), record.child)

        def add(entry):
            selected[entry.path] = entry
            self._export_counts["leaves"] += 1
            if len(selected) > snapshot.MAX_TREE_ENTRIES:
                raise snapshot.SnapshotError(
                    f"tree walk exceeds the budget of {snapshot.MAX_TREE_ENTRIES} entries")

        for parts in export_prefixes(self.snapshot, plan.export_requests):
            self._export_counts["prefixes"] += 1
            raw = self.snapshot._raw_entry_at(parts) if parts else None
            if parts:
                # The exact lookup just authenticated these tree records. Reuse
                # them without another reader call, path charge or object probe.
                oid = self.snapshot.tree
                for depth, component in enumerate(parts):
                    records = self.snapshot._state.tree_cache[oid]
                    remember(parts[:depth], records, oid)
                    reached = self.snapshot._find_raw_entry(records, component)
                    if reached is None or reached.mode != b"40000":
                        break
                    oid = reached.oid
                if raw is None:
                    continue
            if not parts or raw.mode == b"40000":
                listing = self.snapshot.entries(b"/".join(parts) if parts else "")
                for entry in listing:
                    add(entry)
                topology(parts, listing._node)
            else:
                add(self.snapshot._public_entry(parts, raw))
        # Successful exact lookups discharge ancestors at the reader's existing
        # barrier, with its missing-prefix and wrong-shape behavior unchanged.
        run.completed.add("ancestors")
        return run

    def _export_names(self, run: _NameRun) -> None:
        for ordinal, (parent, names) in enumerate(run.export_siblings.items()):
            path = snapshot._tree_path_decode(b"/".join(parent))
            try:
                self._facts.siblings(sorted(names), repertoire=run.plan.repertoire,
                                     materializing=True, label=path or "tree root")
            except _names.NamePolicyError as exc:
                run.findings.append(Finding(
                    "sibling-alias" if isinstance(exc, _SiblingCollision) else "name",
                    "export-names", (ordinal, getattr(exc, "ordinal", 0)),
                    parent=path, name=getattr(exc, "name", ""),
                    other_name=getattr(exc, "other", ""), operation="export-siblings",
                    detail=str(exc)))
                return
        run.completed.add("export-names")

    def observe_entries(self, entries: Iterable[snapshot.GitEntry]) -> None:
        """Retain entries already admitted at a legacy read, with no new walk."""
        self.snapshot._batch()
        for entry in entries:
            self.snapshot._require_entry(entry)
            self._entries[entry.path] = entry

    def read_listing(self, prefix: str = "") -> dict[str, snapshot.GitEntry]:
        """Admit a legacy listing use, including repeated path/walk charges.

        Policy stage reuse never calls this again for an already acquired scope.
        An explicit caller read still invokes the reader and honors all existing
        counters and late limits before deduplicating immutable metadata.
        """
        self.snapshot._batch()
        listing = self.snapshot.entries(prefix)
        entries = listing.as_dict(include_trees=True)
        self._entries.update(entries)
        self._scopes[prefix] = listing.tree_oid
        self._empty_roots[prefix] = not listing._node.records
        return entries

    def _validate_view(self, view: ProtectedTreeView) -> None:
        self.snapshot._batch()
        if (type(view) is not ProtectedTreeView or view._evaluator is not self
                or self._views.get(id(view)) is not view or view.subject != self.subject
                or view.policy_version != self.policy_version):
            raise PolicyUseError("protected view does not belong to this evaluator/subject")

    def evaluate(self, plan: ProtectionPlan, *, stage: str,
                 previous: ProtectedTreeView | None = None) -> ProtectedTreeView:
        """Evaluate newly required names at the caller's existing barrier.

        Earlier completed facts are reused. Repeated explicit listing reads
        retain reader admission charges; evaluating a completed fact adds none.
        Previous evidence must be issued by this evaluator for this exact plan,
        including anchor origin and later obligations. No later-stage I/O occurs.
        """
        self.snapshot._batch()
        if previous is not None:
            self._validate_view(previous)
            if previous.plan != plan:
                raise PolicyUseError("protected view has an incompatible plan")
        if stage not in (*NAME_STAGES, *SHAPE_STAGES, "export-names"):
            raise NotImplementedError(f"protected-tree stage {stage!r} belongs to a later migration")
        exporting = "export-names" in plan.obligations
        if exporting and (
            plan.obligations != EXPORT_STAGES or plan.listing_scope
            or tuple(snapshot._tree_path_decode(p) if type(p) is bytes else p
                     for p in plan.export_requests) != plan.export_prefixes
        ):
            raise PolicyUseError("export plan has incompatible obligations/listing scope")
        for scope in plan.listing_scope:
            if scope not in self._scopes:
                self.read_listing(scope)
        run = self._runs.get(plan)
        if run is None and exporting:
            run = self._read_export(plan)
            self._runs[plan] = run
        if run is None:
            # The run owns a stable copy; unrelated later listing extensions do
            # not silently widen its obligations or mutate an already issued view.
            exact = {path for path, _ in plan.mode_roles}
            ancestors = {"/".join(path.split("/")[:depth]) for path in plan.ancestor_paths
                         for depth in range(1, len(path.split("/")))}
            # Exact mode uses (notably each base-history comparison) must not
            # rescan the entire admitted release listing for every leaf.
            selected = {path: entry for path, entry in self._entries.items() if any(
                not scope or path == scope or path.startswith(scope + "/")
                for scope in plan.listing_scope
            )} if plan.listing_scope else {}
            selected.update((path, self._entries[path]) for path in exact | ancestors
                            if path in self._entries)
            run = _NameRun(MappingProxyType(selected), plan, self._facts)
            self._runs[plan] = run
        # The plan is the schedule: callers may stop after names, admit one
        # state lookup/payload, then request a separate shape obligation.
        stages = plan.obligations[:plan.obligations.index(stage) + 1] if stage in plan.obligations else (stage,)
        for current in stages:
            if current in run.completed or run.findings:
                continue
            if current in NAME_STAGES:
                run.evaluate(current)
            elif current == "modes":
                self.evaluate_modes(plan, _run=run)
            elif current == "ancestors":
                self.evaluate_ancestors(plan, _run=run)
            elif current == "export-names":
                self._export_names(run)
            else:
                raise NotImplementedError(f"protected-tree stage {current!r} belongs to a later migration")
        entries = MappingProxyType(dict(run.entries))
        children: dict[str, dict[str, snapshot.GitEntry]] = {p: {} for p in plan.listing_scope}
        for path, entry in entries.items():
            parent, _, name = path.rpartition("/")
            children.setdefault(parent, {})[name] = entry
            if entry.mode == "040000":
                children.setdefault(path, {})
        view = ProtectedTreeView(
            subject=self.subject, plan=plan, policy_version=self.policy_version,
            entries=entries,
            raw_paths=tuple(p.encode("utf-8", "surrogateescape") for p in entries),
            names=tuple(entries),
            listings=MappingProxyType({p: MappingProxyType(dict(v)) for p, v in children.items()}),
            listing_scopes=plan.listing_scope,
            listing_tree_ids=MappingProxyType({p: self._scopes[p] for p in plan.listing_scope}),
            fold_index=MappingProxyType({p: f for p, f in self._facts.folds.items() if isinstance(f, str)}),
            mode_facts=MappingProxyType(dict(run.mode_facts)),
            findings=tuple(run.findings), completed=frozenset(run.completed),
            refused=frozenset(f.stage for f in run.findings),
            unevaluated=frozenset(plan.obligations) - run.completed - {f.stage for f in run.findings},
            admission=tuple((f.name, getattr(self.work, f.name)) for f in fields(self.work)),
            _evaluator=self,
            raw_listings=MappingProxyType(dict(run.raw_listings)),
            raw_listing_tree_ids=MappingProxyType(dict(run.tree_ids)),
        )
        self._views[id(view)] = view
        return view

    def evaluate_modes(self, plan: ProtectionPlan | None = None, *,
                       previous: ProtectedTreeView | None = None,
                       _run: _NameRun | None = None) -> ProtectedTreeView | None:
        """Classify the plan's ordered roles using only admitted metadata."""
        if plan is None:
            # PR2 pinned the unsupported no-plan call in its unchanged suite.
            raise NotImplementedError("receipt 0.7 M1 PR3 mode evaluation requires a plan")
        if _run is None:
            return self.evaluate(plan, stage="modes", previous=previous)
        self.snapshot._batch()
        if self._runs.get(plan) is not _run:
            raise PolicyUseError("mode run does not belong to this evaluator/plan")
        parents = {path.rpartition("/")[0] for path in _run.entries}
        exporting = "export-names" in plan.obligations
        roles = tuple((path, "export-leaf") for path in sorted(_run.entries)) if exporting else plan.mode_roles
        for ordinal, (path, role) in enumerate(roles):
            entry = _run.entries.get(path)
            # Only complete listings establish tree emptiness; exact entries
            # alone establish directory shape, without an extra subtree read.
            complete = any(not p or path == p or path.startswith(p + "/") for p in plan.listing_scope)
            if entry is None and self._scopes.get(path) is not None:
                # A subtree listing carries its root OID separately, including
                # empty roots. Do not manufacture/charge a public GitEntry or
                # confuse that authenticated directory with an absent leaf.
                fact = self._shapes.metadata(path, "040000", "tree", empty=self._empty_roots[path])
            else:
                fact = self._shapes.mode(path, entry, empty=complete and path not in parents
                                         and entry is not None and entry.mode == "040000")
            _run.mode_facts[path, role] = fact
            finding = fact.finding(path, role, position=(ordinal,))
            if finding is not None:
                _run.findings.append(finding)
                return None
            if exporting:
                raw_parts = self.snapshot._path_parts(path, allow_empty=False)
                self._export_counts["components"] += len(raw_parts)
                for index, name in enumerate(raw_parts):
                    _run.export_siblings.setdefault(raw_parts[:index], set()).add(name)
        _run.completed.add("modes")
        return None

    def evaluate_ancestors(self, plan: ProtectionPlan | None = None, *,
                           previous: ProtectedTreeView | None = None,
                           _run: _NameRun | None = None) -> ProtectedTreeView | None:
        """Find the first wrong component without reading beyond this barrier."""
        if plan is None:
            raise NotImplementedError("receipt 0.7 M1 PR3 ancestor evaluation requires a plan")
        if _run is None:
            return self.evaluate(plan, stage="ancestors", previous=previous)
        self.snapshot._batch()
        if self._runs.get(plan) is not _run:
            raise PolicyUseError("ancestor run does not belong to this evaluator/plan")
        for ordinal, path in enumerate(plan.ancestor_paths):
            # A leaf-only view cannot prove absent ancestors or tree emptiness.
            if "" not in self._scopes:
                raise PolicyUseError("ancestor evaluation requires a complete ancestor listing")
            finding = self._shapes.ancestor(path, _run.entries)
            if finding is not None and (finding.kind != "missing" or plan.require_ancestors):
                _run.findings.append(replace(finding, position=(ordinal, *finding.position)))
                return None
        _run.completed.add("ancestors")
        return None

    def select_export(self, view: ProtectedTreeView | None = None, *,
                      render: Callable[[Finding], BaseException] | None = None) -> ProtectedSelection:
        """Certify regular exports from this subject's completed export view."""
        if view is None:
            # PR2 pins the unsupported no-view call, like the no-plan shape APIs.
            raise NotImplementedError("receipt 0.7 M1 PR3 export selection requires a view")
        self._validate_view(view)
        if render is None:
            raise PolicyUseError("export selection requires a compatibility renderer")
        if view.plan.obligations != EXPORT_STAGES:
            raise PolicyUseError("protected view lacks export obligations")
        return view.require(view.plan.use, render=render)

    def evaluate_attributes(self) -> None:
        """PR4: independent exact/folded readings and D12 admission checkpoints.

        Replay successful costs arithmetically; on exhaustion replay only the
        single exhausting rule from its checkpoint, refusing before increment.
        Source loads, path bytes, late hooks and shared ledgers remain unchanged.
        """
        raise NotImplementedError("receipt 0.7 M1 PR4 introduces attribute evaluation")


@dataclass(frozen=True)
class ProtectedTreeView:
    """Frozen authenticated metadata, partial topology and name completion.

    Index backing storage is privately copied. None from finding_for does not
    accept unevaluated obligations. No blob payloads or attribute outcomes are
    fabricated here; later-stage obligations remain explicitly unevaluated.
    """

    subject: SubjectIdentity
    plan: ProtectionPlan
    policy_version: str
    entries: Mapping[str, snapshot.GitEntry]
    raw_paths: tuple[bytes, ...]
    names: tuple[str, ...]
    listings: Mapping[str, Mapping[str, snapshot.GitEntry]]
    listing_scopes: tuple[str, ...]
    listing_tree_ids: Mapping[str, str | None]
    fold_index: Mapping[str, str]
    findings: tuple[Finding, ...]
    completed: frozenset[str]
    refused: frozenset[str]
    unevaluated: frozenset[str]
    admission: tuple[tuple[str, int], ...]
    _evaluator: TreePolicy = field(repr=False, compare=False)
    mode_facts: Mapping[tuple[str, str], ModeFact] = field(
        default_factory=lambda: MappingProxyType({}), kw_only=True)

    # Raw directory records preserve selected empty trees and actual ancestor
    # spellings without manufacturing or charging public tree entries.
    raw_listings: Mapping[str, tuple[snapshot._RawTreeEntry, ...]] = field(
        default_factory=lambda: MappingProxyType({}), kw_only=True)
    raw_listing_tree_ids: Mapping[str, str | None] = field(
        default_factory=lambda: MappingProxyType({}), kw_only=True)

    @property
    def plan_fingerprint(self) -> str:
        return self.plan.fingerprint

    def finding_for(self, use: str) -> Finding | None:
        """Select by stage, traversal ordinal and within-entry sub-step.

        In append, each entry's whole fold precedes that entry's target/depth
        comparisons; an earlier entry's alias still beats a later fold failure.
        """
        self._evaluator._validate_view(self)
        if use != self.plan.use:
            raise PolicyUseError("protected view has a different purpose")
        return min(self.findings, key=lambda f: (self.plan.obligations.index(f.stage), f.position), default=None)

    def require(self, use: str, *, render: Callable[[Finding], BaseException]) -> ProtectedSelection:
        """Render a refusal or issue a selection bound to completed obligations.

        Renderers choose public words/classes only. An incomplete or forged view
        refuses internally, even when finding_for returned None.
        """
        finding = self.finding_for(use)
        if finding is not None:
            refusal = render(finding)
            if not isinstance(refusal, BaseException):
                raise PolicyUseError("finding renderer must refuse")
            raise refusal
        if self.unevaluated or not set(self.plan.obligations) <= self.completed:
            raise PolicyUseError("protected obligations are unevaluated")
        selection = ProtectedSelection(self.subject, use, self.plan_fingerprint,
                                       self.policy_version, self.entries, self.completed, self._evaluator)
        self._evaluator._selections[id(selection)] = selection
        return selection


@dataclass(frozen=True)
class ProtectedSelection:
    """Successful metadata selection bound to session, purpose and completed work.

    Only the recorded obligations are certified. Export selections require all
    export stages; attribute obligations remain a separate later barrier.
    Closing/abandoning a snapshot invalidates subsequent selection consumption.
    """

    subject: SubjectIdentity
    purpose: str
    plan_fingerprint: str
    policy_version: str
    entries: Mapping[str, snapshot.GitEntry]
    completed: frozenset[str]
    _evaluator: TreePolicy = field(repr=False, compare=False)

    def entries_for(self, subject: snapshot.TreeSnapshot, *, use: str,
                    plan: ProtectionPlan | None = None) -> Mapping[str, snapshot.GitEntry]:
        subject._batch()
        if (subject is not self._evaluator.snapshot or use != self.purpose
                or self._evaluator._selections.get(id(self)) is not self):
            raise PolicyUseError("protected selection subject/purpose mismatch")
        if plan is not None and (plan.fingerprint != self.plan_fingerprint or plan.use != use):
            raise PolicyUseError("protected selection has an incompatible plan")
        return self.entries


@dataclass(frozen=True)
class DirectoryEvidence:
    """Distinct bounded direct-reader observations, with no Git/whole-tree claim.

    PR3 adapts regular-file and ancestor facts. Existing lstat, spelling,
    open/fstat, race guards and read-once behavior stay with the directory reader.
    Observations cannot be supplied as a TreePolicy subject or prior view.
    """

    origin: str = "directory"
    observations: tuple[tuple[str, str], ...] = ()
    provenance: object = field(default_factory=object, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "observations", tuple(tuple(item) for item in self.observations))
