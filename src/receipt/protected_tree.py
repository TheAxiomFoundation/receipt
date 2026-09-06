"""Authenticated name evidence for receipt 0.7 M1.

Names, configured aliases and scoped DOS suffixes are evaluated only at the
caller's existing barriers. The snapshot still owns object authentication and
structural/admission charges. Mode/ancestor policy, certified export and
attributes belong to PR3/PR4; a completed name selection cannot certify them.

The mapping and sibling compatibility adapters confer no payload authority.
Only TreePolicy, over an entered snapshot, can issue a ProtectedTreeView.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, fields
from pathlib import PurePosixPath
from types import MappingProxyType
from weakref import WeakValueDictionary

from receipt import _names, snapshot

POLICY_VERSION = "v0.6"
NAME_STAGES = ("aliases", "names", "siblings", "suffixes")


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

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if item.name in {
                "selected_prefixes", "configured_alias_targets",
                "ancestor_listing_scope", "content_roots", "content_suffixes",
                "exact_state_paths", "exact_attested_paths", "export_prefixes",
                "attribute_target_selectors", "obligations", "listing_scope",
            }:
                object.__setattr__(self, item.name, _paths(value))

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
    raw_path: bytes = b""
    parent: str = ""
    name: str = ""
    other_name: str = ""
    target: str = ""
    prefix: str = ""
    suffixes: tuple[str, ...] = ()
    operation: str = ""
    detail: str = ""


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
            raise _Refusal(Finding(
                "name", stage, position, path=path,
                raw_path=path.encode("utf-8", "surrogateescape"), name=name,
                parent=path.rpartition("/")[0], operation=operation, detail=str(exc),
            )) from exc

    def aliases(self, entries: Mapping[str, snapshot.GitEntry], plan: ProtectionPlan) -> None:
        root = _AliasNode()
        # Supplied target order is an earlier barrier than any listed entry.
        for ordinal, path in enumerate(dict.fromkeys(plan.configured_alias_targets)):
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
                    if winner is not None:
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
    _entries: dict[str, snapshot.GitEntry] = field(default_factory=dict, init=False, repr=False, compare=False)
    _scopes: dict[str, None] = field(default_factory=dict, init=False, repr=False, compare=False)
    _runs: dict[ProtectionPlan, _NameRun] = field(default_factory=dict, init=False, repr=False, compare=False)
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

    def read_listing(self, prefix: str = "") -> dict[str, snapshot.GitEntry]:
        """Admit a legacy listing use, including repeated path/walk charges.

        Policy stage reuse never calls this again for an already acquired scope.
        An explicit caller read still invokes the reader and honors all existing
        counters and late limits before deduplicating immutable metadata.
        """
        self.snapshot._batch()
        entries = self.snapshot.entries(prefix).as_dict(include_trees=True)
        self._entries.update(entries)
        self._scopes[prefix] = None
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
        if stage not in NAME_STAGES:
            raise NotImplementedError(f"protected-tree stage {stage!r} belongs to a later migration")
        for scope in plan.listing_scope:
            if scope not in self._scopes:
                self.read_listing(scope)
        run = self._runs.get(plan)
        if run is None:
            # The run owns a stable copy; unrelated later listing extensions do
            # not silently widen its obligations or mutate an already issued view.
            selected = {path: entry for path, entry in self._entries.items() if any(
                not scope or path == scope or path.startswith(scope + "/")
                for scope in plan.listing_scope
            )}
            run = _NameRun(MappingProxyType(selected), plan, self._facts)
            self._runs[plan] = run
        run.evaluate(stage)
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
            fold_index=MappingProxyType({p: f for p, f in self._facts.folds.items() if isinstance(f, str)}),
            findings=tuple(run.findings), completed=frozenset(run.completed),
            refused=frozenset(f.stage for f in run.findings),
            unevaluated=frozenset(plan.obligations) - run.completed - {f.stage for f in run.findings},
            admission=tuple((f.name, getattr(self.work, f.name)) for f in fields(self.work)),
            _evaluator=self,
        )
        self._views[id(view)] = view
        return view

    def evaluate_modes(self) -> None:
        """PR3: classify regular leaves/object types at each caller's barrier."""
        raise NotImplementedError("receipt 0.7 M1 PR3 introduces mode evaluation")

    def evaluate_ancestors(self) -> None:
        """PR3: share ancestor shapes without changing the reader's physical guards."""
        raise NotImplementedError("receipt 0.7 M1 PR3 introduces ancestor evaluation")

    def select_export(self) -> None:
        """PR3: certify exports after mode-before-name selection, before writing."""
        raise NotImplementedError("receipt 0.7 M1 PR3 introduces export selection")

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
    fold_index: Mapping[str, str]
    findings: tuple[Finding, ...]
    completed: frozenset[str]
    refused: frozenset[str]
    unevaluated: frozenset[str]
    admission: tuple[tuple[str, int], ...]
    _evaluator: TreePolicy = field(repr=False, compare=False)

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
        return min(self.findings, key=lambda f: (NAME_STAGES.index(f.stage), f.position), default=None)

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
    """Successful name selection bound to session, purpose and completed work.

    This PR certifies names only. PR3/PR4 must complete their own obligations
    before handing certified exports or attributed payloads to a verifier.
    Closing/abandoning a snapshot invalidates subsequent selection consumption.
    """

    subject: SubjectIdentity
    purpose: str
    plan_fingerprint: str
    policy_version: str
    entries: Mapping[str, snapshot.GitEntry]
    completed: frozenset[str]
    _evaluator: TreePolicy = field(repr=False, compare=False)

    def entries_for(self, subject: snapshot.TreeSnapshot, *, use: str) -> Mapping[str, snapshot.GitEntry]:
        subject._batch()
        if (subject is not self._evaluator.snapshot or use != self.purpose
                or self._evaluator._selections.get(id(self)) is not self):
            raise PolicyUseError("protected selection subject/purpose mismatch")
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
