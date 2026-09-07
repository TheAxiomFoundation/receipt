"""Authenticated name, shape and attribute evidence for receipt 0.7 M1.

Names, configured aliases and scoped DOS suffixes are evaluated only at the
caller's existing barriers. The snapshot still owns object authentication and
structural/admission charges. Shape stages consume admitted metadata at the
caller's barrier; export certification precedes writing. Attributes are lazy and
use the fixed v0.6 exact-plus-ASCII-fold policy, independent of Git settings.

The mapping and sibling compatibility adapters confer no payload authority.
Only TreePolicy, over an entered snapshot, can issue a ProtectedTreeView.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, fields, replace
from pathlib import PurePosixPath
from types import MappingProxyType
from weakref import WeakValueDictionary

from receipt import _names, snapshot

POLICY_VERSION = "v0.6"
NAME_STAGES = ("aliases", "names", "siblings", "suffixes")
SHAPE_STAGES = ("ancestors", "modes")
BINDING_STAGES = ("content-roots", "content")
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
    source: str = ""
    line: int = 0


MODE_ROLES = frozenset(("release-leaf", "state-leaf", "manifest-child", "ancestor", "export-leaf", "attested-leaf"))


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



def regular_entries(entries: Mapping[str, snapshot.GitEntry], paths: Iterable[str],
                    *, facts: _ShapeFacts | None = None) -> tuple[snapshot.GitEntry, ...]:
    """Select regular metadata without requiring or granting payload authority."""
    facts = facts or _ShapeFacts()
    return tuple(entries[path] for path in paths if facts.mode(path, entries[path]).regular)


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
        self.full_folds: dict[str, str] = {}
        self.suffix_index: dict[tuple[str, tuple[str, ...]], bool] = {}
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

    def full_fold(self, path: str) -> str:
        if path not in self.full_folds:
            self.full_folds[path] = "/".join(self.folded_parts(path))
        return self.full_folds[path]

    def carries_suffix(self, path: str, suffixes: tuple[str, ...]) -> bool:
        return self.full_fold(path).endswith(tuple(self.full_fold(s) for s in suffixes))

    def short_suffix(self, name: str, suffixes: tuple[str, ...]) -> bool:
        key = name, suffixes
        if key not in self.suffix_index:
            self.counts["suffix_checks"] += 1
            self.suffix_index[key] = _names.short_name_carries_pinned_suffix(name, suffixes)
        return self.suffix_index[key]

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
        binding = plan.phase == "binding"
        for ordinal, path in enumerate(paths):
            name = path.rpartition("/")[2]
            validate = _names.validate_component_text
            label = f"tree entry {path!r}"
            if binding:
                # Retain the renderer and late primitive hook at the corpus
                # boundary. The order and all decisions belong to this stage.
                from receipt import corpus
                label = f"tree entry {corpus._quoted(path)}"
                validate = corpus.validate_component_text
            operations = (
                ("local-fold", lambda: self.fold(name)),
                ("binding-portable" if binding and plan.repertoire == "portable" else "component",
                 lambda: (_names.assert_portable_name(name, label)
                    if plan.repertoire == "portable" else
                    validate(name, repertoire=plan.repertoire, label=label))),
            )
            if binding and plan.repertoire != "portable":
                operations = operations[::-1]
            for step, (operation, call) in enumerate(operations):
                self.primitive(operation, call, stage="names", position=(ordinal, step),
                               path=path, name=name)

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
            if not self.fold(name).endswith(plan.content_suffixes) and (
                self.short_suffix(name, plan.content_suffixes)
            ):
                raise _Refusal(Finding(
                    "short-suffix", "suffixes", (ordinal,), path=path,
                    raw_path=path.encode("utf-8", "surrogateescape"),
                    parent=path.rpartition("/")[0], name=name,
                    suffixes=plan.content_suffixes,
                ))


def index_children(entries: Mapping[str, snapshot.GitEntry]) -> dict[str, dict[str, snapshot.GitEntry]]:
    """Index each authenticated entry's immediate parent, retaining empty trees."""
    children: dict[str, dict[str, snapshot.GitEntry]] = {}
    for path, entry in entries.items():
        parent, _, name = path.rpartition("/")
        children.setdefault(parent, {})[name] = entry
        if entry.mode == "040000":
            children.setdefault(path, {})
    return children


class _NameRun:
    def __init__(self, entries: Mapping[str, snapshot.GitEntry], plan: ProtectionPlan,
                 facts: _NameFacts, shapes: _ShapeFacts | None = None):
        self.entries = entries
        self.children = index_children(entries)
        self.shapes = shapes or _ShapeFacts()
        self.selected_paths: tuple[str, ...] | None = None
        self.plan = plan
        self.attribute_outcomes: dict[bytes, AttributeOutcome] = {}
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
                        sibling_paths = self.paths
                        if self.plan.phase == "binding":
                            sibling_paths = tuple(
                                (directory + "/" if directory else "") + name
                                for directory in sorted({"", *(p for p, e in self.entries.items()
                                                              if e.mode == "040000")})
                                for name in sorted(self.children.get(directory, {})))
                        self.facts.sibling_paths(sibling_paths, self.plan)
                    else:
                        self.facts.suffixes(self.paths, self.plan)
            except _Refusal as exc:
                self.findings.append(exc.finding)
                return
            self.completed.add(current)


    def binding(self, stage: str) -> None:
        """Select root spelling or content facts in binding's per-root order."""
        if stage in self.completed or self.findings:
            return
        found: list[str] = []
        try:
            for root_ordinal, root in enumerate(self.plan.content_roots):
                if stage == "content-roots":
                    parent = ""
                    for depth, component in enumerate(root.split("/")):
                        for name in sorted(self.children.get(parent, {})):
                            if name != component and self.facts.full_fold(name) == self.facts.full_fold(component):
                                raise _Refusal(Finding("content-root-alias", stage, (root_ordinal, depth),
                                                      name=name, target=component))
                        exact = (parent + "/" if parent else "") + component
                        if not self.shapes.mode(exact, self.entries.get(exact)).directory:
                            break
                        parent = exact
                    continue
                root_fact = self.shapes.mode(root, self.entries.get(root))
                self.mode_facts[root, "ancestor"] = root_fact
                if not root_fact.directory:
                    raise _Refusal(Finding("content-root-missing" if root_fact.shape == "missing"
                        else "content-root-mode", stage, (root_ordinal, 0), path=root))
                for ordinal, path in enumerate(sorted(self.entries)):
                    if not path.startswith(root + "/"):
                        continue
                    entry = self.entries[path]
                    fact = self.shapes.mode(path, entry)
                    position = (root_ordinal, 1, ordinal)
                    if fact.mode == "160000":
                        raise _Refusal(Finding("content-gitlink", stage, (*position, 0), path=path))
                    if not self.facts.carries_suffix(path, self.plan.content_suffixes):
                        if self.plan.repertoire == "portable" and self.facts.short_suffix(
                            path.rpartition("/")[2], self.plan.content_suffixes):
                            raise _Refusal(Finding("content-short-suffix", stage, (*position, 1), path=path))
                        continue
                    self.mode_facts[path, "attested-leaf"] = fact
                    if not fact.regular:
                        raise _Refusal(Finding("content-symlink" if fact.mode == "120000"
                            else "content-mode", stage, (*position, 2), path=path,
                            mode=fact.mode, object_type=fact.object_type))
                    found.append(path)
        except _Refusal as exc:
            self.findings.append(exc.finding)
            return
        except _names.NamePolicyError as exc:
            self.findings.append(Finding("name", stage, (), detail=str(exc)))
            return
        if stage == "content":
            self.selected_paths = tuple(dict.fromkeys(found))
        self.completed.add(stage)


def evaluate_binding_mapping(entries: Mapping[str, snapshot.GitEntry], plan: ProtectionPlan,
                             *, stage: str, by_directory=None) -> _NameRun:
    """Legacy mapping evidence shares decisions but cannot certify payload reads."""
    run = _NameRun(entries, plan, _NameFacts())
    if by_directory is not None:
        run.children = {p: dict(children) for p, children in by_directory.items()}
    if stage in NAME_STAGES:
        run.evaluate(stage)
    else:
        run.binding(stage)
    return run


def folded_path_index(entries: Mapping[str, snapshot.GitEntry], *,
                      facts: _NameFacts | None = None) -> dict[str, str]:
    """Retain the first sorted exact witness for each lazily requested fold key."""
    facts = facts or _NameFacts()
    folded: dict[str, str] = {}
    for path in sorted(entries):
        folded.setdefault(facts.full_fold(path), path)
    return folded


def read_binding_listing(subject: snapshot.TreeSnapshot, *, evaluator=None):
    """Admit binding's exact reader call before creating a standalone evaluator.

    Declaration prerequisites belong to the caller. This explicit read preserves
    lifecycle refusals at entries(), as well as repeated listing/path charges
    when a custody evaluator already holds the same immutable metadata.
    Subclass listings remain mapping evidence, without policy-view authority.
    """
    if evaluator is not None and evaluator.snapshot is not subject:
        raise PolicyUseError("binding evaluator has a different subject")
    listing = subject.entries("")
    entries = listing.as_dict(include_trees=True)
    if evaluator is None and type(subject) is not snapshot.TreeSnapshot:
        return None, entries
    evaluator = evaluator or TreePolicy(subject, policy_version=POLICY_VERSION, work=subject.work)
    evaluator._entries.update(entries)
    evaluator._scopes[""] = listing.tree_oid
    evaluator._empty_roots[""] = not listing._node.records
    return evaluator, entries


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
class DeclarationObligations:
    """Parsed declaration order and the caller's live alias-index ceiling."""

    paths: tuple[str, ...]
    alias_index_limit: int

    def __post_init__(self):
        object.__setattr__(self, "paths", _paths(self.paths))


def evaluate_declarations(obligations: DeclarationObligations, *, work,
                          render: Callable[[Finding], BaseException],
                          fold: Callable[[str], str] | None = None,
                          facts: _NameFacts | None = None) -> int:
    """Whole paths precede charged prefix keys and adjacent-prefix comparisons.

    Admission is per original visit and counted prefix, even when component
    folds are reused. A substituted legacy fold hook observes each original
    call. Keys hold one string per declaration, never one trie node per prefix.
    """
    facts = facts or _NameFacts()
    fold = fold or facts.full_fold
    relatives = obligations.paths
    try:
        seen: dict[str, str] = {}
        for ordinal, relative in enumerate(relatives):
            key = fold(relative)
            if key in seen and seen[key] != relative:
                raise render(Finding("declared-alias", "declarations", (0, ordinal),
                                     path=relative, target=seen[key]))
            seen[key] = relative
        keys = []
        for relative in relatives:
            components = relative.split("/")
            work.charge(len(components))
            keys.append("\x00".join(fold(component) for component in components))
        nodes = 0
        previous_folded: list[str] = []
        previous_spelled: list[str] = []
        for ordinal, index in enumerate(sorted(range(len(relatives)), key=keys.__getitem__)):
            folded = keys[index].split("\x00")
            spelled = relatives[index].split("/")
            shared = 0
            limit = min(len(folded), len(previous_folded))
            while shared < limit and folded[shared] == previous_folded[shared]:
                shared += 1
            for depth in range(shared):
                if spelled[depth] != previous_spelled[depth]:
                    raise render(Finding("declared-prefix-alias", "declarations", (1, ordinal, depth),
                        path="/".join(spelled[:depth + 1]),
                        target="/".join(previous_spelled[:depth + 1])))
            work.charge(len(folded) - shared)
            nodes += len(folded) - shared
            if nodes > obligations.alias_index_limit:
                raise render(Finding("declared-index-budget", "declarations", (1, ordinal),
                                     target=str(obligations.alias_index_limit)))
            previous_folded, previous_spelled = folded, spelled
        return nodes
    except _names.NamePolicyError as exc:
        raise render(Finding("name", "declarations", (), detail=str(exc))) from exc


@dataclass(frozen=True)
class SubjectIdentity:
    """Session provenance, repository and immutable object identity."""

    session: object = field(repr=False)
    repository: str
    object_format: str
    commit: str
    tree: str


def _unsupported_attribute(path: str, line: int, construct: str) -> snapshot.SnapshotError:
    return snapshot.SnapshotError(
        f"unsupported .gitattributes construct at {path}:{line}: {construct}"
    )


def _attribute_pattern(
    token: bytes, *, path: str, line: int
) -> tuple[bytes, tuple[bytes, ...], bool]:
    try:
        shown = token.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise snapshot._unsupported_attribute(path, line, "non-ASCII pattern") from exc
    if not token:
        raise snapshot._unsupported_attribute(path, line, "empty pattern")
    if token.startswith(b'"'):
        raise snapshot._unsupported_attribute(path, line, "C-quoted pattern")
    if token.startswith(b"!"):
        raise snapshot._unsupported_attribute(path, line, "negative pattern")
    for byte, description in (
        (b"?", "?"),
        (b"[", "bracket expression"),
        (b"]", "bracket expression"),
        (b"\\", "backslash escape"),
    ):
        if byte in token:
            raise snapshot._unsupported_attribute(path, line, description)
    if token.endswith(b"/"):
        raise snapshot._unsupported_attribute(path, line, "trailing slash")
    if re.fullmatch(rb"[A-Za-z0-9._*/-]+", token) is None:
        raise snapshot._unsupported_attribute(path, line, f"pattern {shown!r}")
    anchored = token[1:] if token.startswith(b"/") else token
    if not anchored:
        raise snapshot._unsupported_attribute(path, line, "empty pattern")
    segments = anchored.split(b"/")
    if any(not segment for segment in segments):
        raise snapshot._unsupported_attribute(path, line, "empty pattern segment")
    for segment in segments:
        if b"**" in segment and segment != b"**":
            raise snapshot._unsupported_attribute(path, line, "misplaced **")
    if token == b"**":
        raise snapshot._unsupported_attribute(path, line, "misplaced **")
    return anchored, tuple(segments), token.startswith(b"/") or b"/" in anchored


def _parse_attribute_file(
    path: str, payload: bytes, *, rule_limit: int
) -> tuple[snapshot._AttributeRule, ...]:
    rules: list[snapshot._AttributeRule] = []
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
            raise snapshot._unsupported_attribute(path, line_number, "control byte")
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
                raise snapshot._unsupported_attribute(
                    path, line_number, "line longer than 2048 bytes"
                )
            if any(byte < 0x20 and byte != 0x09 for byte in original):
                raise snapshot._unsupported_attribute(path, line_number, "control byte")
            fields = re.split(rb"[ \t]+", line)
            if len(fields) < 2:
                raise snapshot._unsupported_attribute(
                    path, line_number, "line has no attribute state"
                )
            if fields[0].startswith(b"[attr]"):
                raise snapshot._unsupported_attribute(
                    path, line_number, "attribute macro definition"
                )
            pattern, segments, has_slash = snapshot._attribute_pattern(
                fields[0], path=path, line=line_number
            )
            states: list[tuple[str, str]] = []

            def add_states(additions: tuple[tuple[str, str], ...]) -> None:
                if len(states) + len(additions) > snapshot.MAX_ATTRIBUTE_STATES_PER_LINE:
                    raise snapshot.SnapshotError(
                        f"attribute states at {path}:{line_number} exceed the "
                        f"per-line budget of {snapshot.MAX_ATTRIBUTE_STATES_PER_LINE} states"
                    )
                states.extend(additions)

            for raw_state in fields[1:]:
                try:
                    state = raw_state.decode("ascii", errors="strict")
                except UnicodeDecodeError as exc:
                    raise snapshot._unsupported_attribute(
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
                    raise snapshot._unsupported_attribute(
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
            rule = snapshot._AttributeRule(
                pattern,
                segments,
                match_segments,
                has_slash,
                trailing_descendants,
                tuple(states), source_line=line_number,
            )
            if len(rules) >= rule_limit:
                rule_overflow = True
            else:
                rules.append(rule)
        if line_end < 0:
            break
        position = line_end + 1
    if rule_overflow:
        raise snapshot.SnapshotError(
            f"attribute rules exceed the snapshot budget of "
            f"{snapshot.MAX_ATTRIBUTE_RULES_TOTAL} rules"
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
    rule: snapshot._AttributeRule, relative: tuple[bytes, ...], step: Callable[[], None]
) -> bool:
    if not rule.has_slash:
        return bool(relative) and snapshot._segment_matches(
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
            and snapshot._segment_matches(
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


def load_attribute_rules(
    self, parts: tuple[bytes, ...]
) -> tuple[snapshot._AttributeRule, ...]:
    path_bytes = b"/".join(parts)
    path = snapshot._tree_path_decode(path_bytes)
    cached = self._state.attribute_cache.get(path)
    if cached is not None:
        return cached
    raw = self._raw_entry_at(parts)
    if raw is None:
        self._state.attribute_cache[path] = ()
        return ()
    if raw.mode not in {b"100644", b"100755"}:
        raise snapshot.SnapshotError(
            f"unsupported .gitattributes entry at {path}: mode {raw.display_mode}"
        )
    _kind, size = self._batch().info(raw.oid, role="blob")
    if self._verification_total("attribute_bytes") + size > snapshot.MAX_ATTRIBUTE_BYTES_TOTAL:
        raise snapshot.SnapshotError(
            f"attribute bytes exceed the snapshot budget of "
            f"{snapshot.MAX_ATTRIBUTE_BYTES_TOTAL} bytes"
        )
    entry = self._public_entry(parts, raw)
    payload = self.blob(entry, limit=snapshot.MAX_ATTRIBUTE_BYTES)
    self._charge_verification(
        "attribute_bytes",
        size,
        ceiling=snapshot.MAX_ATTRIBUTE_BYTES_TOTAL,
        message=f"attribute bytes exceed the snapshot budget of {snapshot.MAX_ATTRIBUTE_BYTES_TOTAL} bytes",
    )
    remaining_rules = (
        snapshot.MAX_ATTRIBUTE_RULES_TOTAL
        - self._verification_total("attribute_rules")
    )
    rules = snapshot._parse_attribute_file(
        path, payload, rule_limit=max(0, remaining_rules)
    )
    if self._verification_total("attribute_rules") + len(rules) > snapshot.MAX_ATTRIBUTE_RULES_TOTAL:
        raise snapshot.SnapshotError(
            f"attribute rules exceed the snapshot budget of "
            f"{snapshot.MAX_ATTRIBUTE_RULES_TOTAL} rules"
        )
    self._charge_verification(
        "attribute_rules",
        len(rules),
        ceiling=snapshot.MAX_ATTRIBUTE_RULES_TOTAL,
        message=f"attribute rules exceed the snapshot budget of {snapshot.MAX_ATTRIBUTE_RULES_TOTAL} rules",
    )
    self._state.attribute_cache[path] = rules
    return rules



@dataclass(frozen=True)
class AttributeState:
    """One final disposition and its committed source, independently per reading."""

    disposition: str
    source: str
    line: int


@dataclass(frozen=True)
class AttributeOutcome:
    """Completed exact and ASCII-folded readings for one admitted raw path."""

    exact: Mapping[str, AttributeState]
    folded: Mapping[str, AttributeState]
    sources: tuple[str, ...]

    def finding(self, path: bytes, ordinal: int) -> Finding | None:
        for name in ("filter", "ident", "working-tree-encoding"):
            for reading, states in (("exact", self.exact), ("folded", self.folded)):
                state = states.get(name)
                if state is not None and state.disposition in {"set", "value"}:
                    return Finding("transforming-attribute", "attributes", (ordinal,),
                                   path=snapshot._tree_path_decode(path), raw_path=path,
                                   name=name, operation=reading, source=state.source,
                                   line=state.line)
        return None


@dataclass(frozen=True)
class _RuleCheckpoint:
    # One checkpoint per rule/reading, never one object per matching step.
    cost: int
    matched: bool


@dataclass(frozen=True)
class AttributeWork:
    rule_evaluations: int
    exhaustion_replays: int
    matching_steps: int
    applied_states: int
    checkpoint_entries: int
    path_outcomes: int
    plan_outcomes: int
    folded_rules: int
    folded_paths: int


def _fold_attribute_path(parts: tuple[bytes, ...]) -> tuple[bytes, ...]:
    return tuple(segment.lower() for segment in parts)


class _AttributeStore:
    """Verification-local facts; acceptance keys also bind subject and full plan.

    Linked candidate/base readers still load and admit their own committed
    sources. Only pure rule/relative-path facts can be shared after those reads;
    an OID never authorizes an outcome in another subject or scope.
    """

    def __init__(self):
        self.checkpoints: dict[tuple, _RuleCheckpoint] = {}
        self.folds: dict[tuple, snapshot._AttributeRule] = {}
        self.folded_paths: dict[tuple, tuple[bytes, ...]] = {}
        self.paths: dict[tuple, AttributeOutcome] = {}
        self.plans: dict[tuple, AttributeOutcome] = {}
        self.attempted: set[tuple] = set()
        self.rule_evaluations = self.exhaustion_replays = 0
        self.matching_steps = self.applied_states = 0

    def merge(self, other: _AttributeStore) -> None:
        for name in ("checkpoints", "folds", "folded_paths", "paths", "plans"):
            getattr(self, name).update(getattr(other, name))
        self.attempted.update(other.attempted)
        for name in ("rule_evaluations", "exhaustion_replays", "matching_steps", "applied_states"):
            setattr(self, name, getattr(self, name) + getattr(other, name))

    @property
    def work(self) -> AttributeWork:
        return AttributeWork(self.rule_evaluations, self.exhaustion_replays,
                             self.matching_steps, self.applied_states,
                             len(self.checkpoints), len(self.paths), len(self.plans), len(self.folds),
                             len(self.folded_paths))

    def folded_path(self, version: str, parts: tuple[bytes, ...]) -> tuple[bytes, ...]:
        key = version, parts
        result = self.folded_paths.get(key)
        if result is None:
            result = _fold_attribute_path(parts)
            self.folded_paths[key] = result
        return result

    def rule(self, subject: snapshot.TreeSnapshot, version: str, fold: bool,
             rule: snapshot._AttributeRule, relative: tuple[bytes, ...]) -> _RuleCheckpoint:
        # Resolve legacy hooks after import. Including the matcher hooks in the
        # fact key also observes a replacement made after a completed request.
        key = (version, fold, rule, relative, snapshot._attribute_matches,
               snapshot._segment_matches, type(subject)._attribute_step)
        checkpoint = self.checkpoints.get(key)
        if checkpoint is not None:
            remaining = (snapshot.MAX_ATTRIBUTE_MATCH_WORK
                         - subject._verification_total("attribute_match_work"))
            if checkpoint.cost <= remaining or not checkpoint.cost:
                if checkpoint.cost:
                    _charge_attribute_work(subject, checkpoint.cost)
                return checkpoint
        # A partial first attempt has no completed checkpoint. A resumed call
        # can revisit that one unfinished rule; earlier successes are arithmetic.
        if key in self.attempted:
            self.exhaustion_replays += 1
        else:
            self.rule_evaluations += 1
        start = subject.work.attribute_match_work

        def step():
            subject._attribute_step()
            self.matching_steps += 1

        try:
            matched = snapshot._attribute_matches(rule, relative, step)
            if matched:
                for _ in rule.states:
                    subject._attribute_step()
                    self.applied_states += 1
        finally:
            # Hash the potentially large rule key once per attempt, including
            # partial exhaustion, rather than once per matching/applied step.
            if subject.work.attribute_match_work > start:
                self.attempted.add(key)
        checkpoint = _RuleCheckpoint(subject.work.attribute_match_work - start, matched)
        self.checkpoints[key] = checkpoint
        return checkpoint


def _attribute_store(subject: snapshot.TreeSnapshot) -> _AttributeStore:
    pool = subject._state.work_pool.root()
    if pool.attributes is None:
        pool.attributes = _AttributeStore()
    return pool.attributes


def _charge_attribute_work(subject: snapshot.TreeSnapshot, amount: int = 1) -> None:
    subject._charge_verification(
        "attribute_match_work", amount, ceiling=snapshot.MAX_ATTRIBUTE_MATCH_WORK,
        message=f"attribute matching exceeds the work budget of {snapshot.MAX_ATTRIBUTE_MATCH_WORK} steps",
    )


def _admit_attribute_paths(subject: snapshot.TreeSnapshot, paths: Iterable) -> tuple[tuple[str, ...], dict[bytes, tuple[bytes, ...]]]:
    ordered = []
    unique = {}
    for count, supplied in enumerate(paths, start=1):
        if count > snapshot.MAX_TREE_ENTRIES:
            raise snapshot.SnapshotError(
                f"attribute paths exceed the budget of {snapshot.MAX_TREE_ENTRIES} entries")
        value = supplied.path if isinstance(supplied, snapshot.GitEntry) else supplied
        parts = subject._path_parts(value, allow_empty=False)
        raw = b"/".join(parts)
        subject._charge_path_bytes(raw)
        ordered.append(snapshot._tree_path_decode(raw))
        unique.setdefault(raw, parts)
    return tuple(ordered), unique


def attribute_error(finding: Finding) -> snapshot.SnapshotError:
    """The retained snapshot refusal renderer, also used at verifier barriers."""
    if finding.kind != "transforming-attribute" or finding.raw_path is None:
        raise PolicyUseError("not an attribute finding")
    try:
        path = finding.raw_path.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return snapshot.SnapshotError("tree entry name is not valid UTF-8 for quoting")
    return snapshot.SnapshotError(
        f"transforming attribute {finding.name} applies to protected path {path}")


def refuse_attributes(subject: snapshot.TreeSnapshot, paths: Iterable) -> None:
    """Forward already checked collection arguments without pre-consuming them."""
    ordered, unique = _admit_attribute_paths(subject, paths)
    plan = ProtectionPlan(attribute_target_selectors=ordered, listing_scope=(),
                          obligations=("attributes",), use="snapshot-attributes", phase="attributes")
    evaluator = TreePolicy(subject, policy_version=POLICY_VERSION, work=subject.work)
    view = evaluator.evaluate_attributes(plan, _admitted=unique)
    view.require(plan.use, render=attribute_error)


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
    def attribute_work(self) -> AttributeWork:
        return _attribute_store(self.snapshot).work

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
        run = _NameRun(MappingProxyType(selected), plan, self._facts, self._shapes)

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
        run.children = index_children(selected)
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

    def regular_entries(self, entries: Mapping[str, snapshot.GitEntry],
                        paths: Iterable[str]) -> tuple[snapshot.GitEntry, ...]:
        """Classify a caller's ordered attribute targets without payload authority."""
        return regular_entries(entries, paths, facts=self._shapes)

    def manifest_children(self, prefix: str) -> Mapping[str, ModeFact]:
        """Admit immediate children at append's proposal barrier, including trees."""
        children = self.snapshot.entries(prefix).children
        return MappingProxyType({name: (
            self._shapes.mode(child.path, child) if isinstance(child, snapshot.GitEntry)
            else self._shapes.metadata(prefix + "/" + name, "040000", "tree")
        ) for name, child in children.items()})

    def manifest_initialized(self, prefix: str) -> bool:
        """Retain non-tree iteration and path charges in append's push probe."""
        return bool(self.snapshot.entries(prefix))

    def materialize(self, plan: ProtectionPlan, destination) -> snapshot.Materialization:
        """Admit a conditional export, then certify it at the writer's old barrier.

        Each explicit materialization repeats reader admission; its name and
        shape facts share this evaluator. Physical writes and guards stay in
        the snapshot writer. Attributes are a separate earlier append barrier.
        """
        admitted = self.snapshot.materialize(plan.export_prefixes, destination,
                                              repertoire=plan.repertoire)
        export = replace(plan, obligations=EXPORT_STAGES, listing_scope=(),
                         use="materialize", phase="export", ancestor_paths=(), mode_roles=(),
                         export_requests=admitted._prefixes)
        return _PolicyMaterialization(self, admitted, export)

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
        """Evaluate newly required obligations at the caller's existing barrier.

        Stages: names and aliases, modes and ancestors, export names,
        binding content roots and suffix-selected leaves, and attributes. Earlier completed facts are reused. Repeated explicit
        listing reads retain reader admission charges; evaluating a completed
        name, shape or export fact adds none. Attributes are the exception: a
        repeated attribute plan replays its admission under the record's D12
        compatibility charge schedule (input counts and path bytes charged
        before deduplication, checkpoint blocks replayed arithmetically, a
        single exhausting rule re-executed from its checkpoint), so the public
        counters land where the legacy path left them. Previous evidence must
        be issued by this evaluator for this exact plan, including anchor origin
        and later obligations. No later-stage I/O occurs.
        """
        self.snapshot._batch()
        if previous is not None:
            self._validate_view(previous)
            if previous.plan != plan:
                raise PolicyUseError("protected view has an incompatible plan")
        if stage not in (*NAME_STAGES, *SHAPE_STAGES, *BINDING_STAGES, "export-names", "attributes"):
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
            run = _NameRun(MappingProxyType(selected), plan, self._facts, self._shapes)
            self._runs[plan] = run
        # The plan is the schedule: callers may stop after names, admit one
        # state lookup/payload, then request a separate shape obligation.
        stages = plan.obligations[:plan.obligations.index(stage) + 1] if stage in plan.obligations else (stage,)
        for current in stages:
            if current == "attributes":
                if not any(f.stage != "attributes" for f in run.findings):
                    self.evaluate_attributes(plan, _run=run)
                continue
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
            elif current in BINDING_STAGES:
                run.binding(current)
            else:
                raise NotImplementedError(f"protected-tree stage {current!r} belongs to a later migration")
        return self._view(plan, run)

    def _view(self, plan: ProtectionPlan, run: _NameRun) -> ProtectedTreeView:
        entries = MappingProxyType(dict(run.entries))
        children = {p: {} for p in plan.listing_scope} | run.children
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
            attribute_outcomes=MappingProxyType(dict(run.attribute_outcomes)),
            findings=tuple(run.findings), completed=frozenset(run.completed),
            refused=frozenset(f.stage for f in run.findings),
            unevaluated=frozenset(plan.obligations) - run.completed - {f.stage for f in run.findings},
            admission=tuple((f.name, getattr(self.work, f.name)) for f in fields(self.work)),
            _evaluator=self, selected_paths=run.selected_paths,
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

    def evaluate_attributes(self, plan: ProtectionPlan | None = None, *,
                            previous: ProtectedTreeView | None = None,
                            _run: _NameRun | None = None,
                            _admitted: dict[bytes, tuple[bytes, ...]] | None = None) -> ProtectedTreeView | None:
        """Evaluate committed sources at this barrier, replaying D12 admission.

        Completed path outcomes are subject/version bound; acceptance additionally
        binds the complete plan fingerprint. Repeated and overlapping requests
        replay each source read and rule checkpoint in the old exact/fold order.
        Only an exhausting rule reexecutes matching and applied-state steps.
        """
        if plan is None:
            # PR2 freezes the no-plan call, as it does for modes and ancestors.
            raise NotImplementedError("receipt 0.7 M1 PR4 attribute evaluation requires a plan")
        self.snapshot._batch()
        if _run is None:
            if _admitted is None:
                return self.evaluate(plan, stage="attributes", previous=previous)
            # Only the collection facade has already charged the ordered input.
            if plan.obligations != ("attributes",) or plan.listing_scope:
                raise PolicyUseError("attribute facade has incompatible obligations")
            run = _NameRun(MappingProxyType({}), plan, self._facts)
            self.evaluate_attributes(plan, _run=run, _admitted=_admitted)
            return self._view(plan, run)
        run = _run
        if _admitted is None:
            _, _admitted = _admit_attribute_paths(self.snapshot, plan.attribute_target_selectors)
        run.completed.discard("attributes")
        run.findings[:] = [f for f in run.findings if f.stage != "attributes"]
        run.attribute_outcomes.clear()
        store = _attribute_store(self.snapshot)
        fingerprint = plan.fingerprint
        for ordinal, (raw, parts) in enumerate(_admitted.items()):
            path_key = (self.subject, self.policy_version, raw,
                        snapshot._attribute_matches, snapshot._segment_matches,
                        type(self.snapshot)._attribute_step, type(self.snapshot)._attribute_rules)
            plan_key = (*path_key, fingerprint)
            cached = store.plans.get(plan_key) or store.paths.get(path_key)
            readings = []
            sources = []
            for fold in (False, True):
                final = {}
                for depth in range(len(parts)):
                    attribute_parts = (*parts[:depth], b".gitattributes")
                    # Keep this hook even on outcome reuse: the source loader
                    # owns its snapshot-local cache, authentication and charges.
                    rules = self.snapshot._attribute_rules(attribute_parts)
                    source = snapshot._tree_path_decode(b"/".join(attribute_parts))
                    if not fold:
                        sources.append(source)
                    relative = parts[depth:]
                    if fold:
                        relative = store.folded_path(self.policy_version, parts)[depth:]
                    for rule in rules:
                        source_line = rule.source_line
                        if fold:
                            fold_key = (self.policy_version, rule)
                            folded = store.folds.get(fold_key)
                            if folded is None:
                                folded = replace(rule, pattern=rule.pattern.lower(),
                                                 segments=tuple(s.lower() for s in rule.segments),
                                                 match_segments=tuple(s.lower() for s in rule.match_segments))
                                store.folds[fold_key] = folded
                            rule = folded
                        checkpoint = store.rule(self.snapshot, self.policy_version, fold, rule, relative)
                        if cached is None and checkpoint.matched:
                            for name, disposition in rule.states:
                                final[name] = AttributeState(disposition, source, source_line)
                readings.append(MappingProxyType(final))
            result = cached or AttributeOutcome(readings[0], readings[1], tuple(sources))
            store.paths[path_key] = store.plans[plan_key] = result
            run.attribute_outcomes[raw] = result
            finding = result.finding(raw, ordinal)
            if finding is not None:
                run.findings.append(finding)
                return None
        run.completed.add("attributes")
        return None

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

    attribute_outcomes: Mapping[bytes, AttributeOutcome] = field(
        default_factory=lambda: MappingProxyType({}), kw_only=True)

    # Raw directory records preserve selected empty trees and actual ancestor
    # spellings without manufacturing or charging public tree entries.
    raw_listings: Mapping[str, tuple[snapshot._RawTreeEntry, ...]] = field(
        default_factory=lambda: MappingProxyType({}), kw_only=True)
    raw_listing_tree_ids: Mapping[str, str | None] = field(
        default_factory=lambda: MappingProxyType({}), kw_only=True)

    selected_paths: tuple[str, ...] | None = field(default=None, kw_only=True)

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
        entries = self.entries if self.selected_paths is None else MappingProxyType(
            {path: self.entries[path] for path in self.selected_paths})
        selection = ProtectedSelection(self.subject, use, self.plan_fingerprint,
                                       self.policy_version, entries, self.completed, self._evaluator)
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


class _PolicyMaterialization(snapshot.Materialization):
    """Use an existing evaluator while retaining the snapshot's physical writer."""

    def __init__(self, policy: TreePolicy, admitted: snapshot.Materialization,
                 plan: ProtectionPlan):
        super().__init__(policy.snapshot, admitted._prefixes,
                         admitted._destination, admitted._repertoire)
        self._policy = policy
        self._export_plan = plan

    def _selected_entries(self) -> dict[str, snapshot.GitEntry]:
        # An explicit new writer use admits its reads again, even if an earlier
        # materialization used this same plan. Stage-only reuse still adds none.
        self._policy._runs[self._export_plan] = self._policy._read_export(self._export_plan)
        view = self._policy.evaluate(self._export_plan, stage="export-names")
        selection = self._policy.select_export(view, render=self._export_error)
        return dict(selection.entries_for(self._snapshot, use=self._export_plan.use,
                                           plan=self._export_plan))
