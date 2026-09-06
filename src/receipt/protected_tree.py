"""Contract-only shell for receipt 0.7 M1's protected-tree policy.

No production caller imports protected_tree in PR1. PR2 introduces evaluation;
this module makes no policy decision and confers no acceptance certificate.

One policy is not one universal verdict. Existing uses retain their obligations,
refusal strings, exception classes and nested execution schedules. For objects
reached at a legacy barrier, the reader first authenticates objects, canonical
order, legal raw modes, names and structural budgets. Evaluation then computes
component grammar/repertoire/export eligibility and fold keys; classifies object
types, leaf modes and ancestor shapes; derives sibling/configured-prefix aliases
and scoped DOS suffix findings; and evaluates attributes only at their existing
barrier. Independent exact and ASCII-folded attribute readings both remain
necessary. Repository settings and worktree/global/info attributes are not
attribute-policy inputs.

Composed verification runs optional history, aliases, scoped names, siblings,
DOS suffixes, state shapes/payload bounds, all export modes, export names,
physical materialization, attributes, anchors/chain, then binding prerequisites
and binding tree obligations. Base verification uses the custody schedule with
caller-anchor exclusions. Append starts with state shapes and protected
ancestors; in its alias stage each (is_tree, listed_path) ordinal folds the full
path before that entry's configured-target/depth comparisons. An earlier alias
can beat a later fold failure and an earlier fold failure can beat a later
alias. Binding parses the journal and declared aliases first, then all tree
names before siblings, content roots/descendants, closed world, tombstones,
attested paths and digests. Standalone snapshot APIs retain their narrower
contracts and their public argument/provenance guards. Neither a global rule
priority nor a global path order can select every legacy winner.

D12 requires a compatibility charge schedule distinct from cached computation.
Input counts/path bytes are charged before deduplication; source loads retain
existing cache semantics. Replay successful checkpoint blocks arithmetically.
If a block exhausts the ceiling, re-execute only its single exhausting rule
and reading from the rule-start checkpoint, charging individual matching and
applied-state steps. Refuse before incrementing the failed step. Repeating
'protected.txt -filter\\n' yields matching work 28 then 56, path bytes 27 then
40, and attribute bytes/rules 22/1. At ceiling 40, call one passes at 28 and
call two refuses with the counter landing at 40, not 28. Checkpoints must be
compact, not one object per step. Existing SnapshotWork fields, shared
candidate/base ledger, limits and late monkeypatch seams remain authoritative;
M1 adds no lower policy/cache ceiling and never resets existing counters.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

from receipt import snapshot

if TYPE_CHECKING:
    # Finding variants remain typed internal records, extensible without a
    # closed public refusal-code enum; their definitions belong to PR2.
    from typing import Any


@dataclass(frozen=True)
class ProtectionPlan:
    """Frozen normalized obligations derived from already admitted specs.

    The contract includes repertoire; ordered selected prefixes and configured
    alias targets; actual ancestor-listing and whole-tree name scopes; content
    roots/suffixes; exact state/attested paths; export prefixes; attribute target
    selectors; anchor origin; and use/phase identifiers. Preserve original path
    order. Repositories supply no policy callbacks. Configuration admission,
    journal/schema/closed-world semantics and append surface classification
    remain at their existing owners. PR2 supplies the fields and compilation.
    """


@dataclass(frozen=True)
class TreePolicy:
    """Verification-local evaluator over an entered authenticated TreeSnapshot.

    Own private caches and bounded admission accounting, sharing the existing
    candidate/base verification ledger; never resolve a moving ref again.
    The initial policy version describes v0.6 exact-plus-ASCII-fold attribute
    semantics. Subject identity includes session/repository provenance, object
    format and selected commit/tree; equal OIDs alone cannot share acceptance.
    Legacy limits/hooks must be consulted at call time. Future snapshot facades
    import this module inside forwarding methods to avoid an eager import cycle.
    """

    snapshot: snapshot.TreeSnapshot
    policy_version: str = field(kw_only=True)
    work: snapshot.SnapshotWork = field(kw_only=True)

    def evaluate(
        self, plan: ProtectionPlan, *, stage: str,
        previous: ProtectedTreeView | None = None,
    ) -> ProtectedTreeView:
        """Evaluate new obligations at the caller's legacy barrier into a new view.

        Reuse completed facts, retaining explicit completed, refused and
        unevaluated obligations. Repeated stages honor legacy admission charges
        and D12's bounded single-rule exhaustion replay. A previous view must
        belong to this subject/evaluator and a compatible plan. Acquire only
        topology the current barrier reads: no eager complete-tree traversal,
        binding-only folds or attribute I/O before their prerequisites succeed.
        """
        raise NotImplementedError("receipt 0.7 M1 PR2 introduces the evaluator")


@dataclass(frozen=True)
class ProtectedTreeView:
    """Frozen authenticated evidence, including trees and empty tree nodes.

    The contract carries subject identity, plan fingerprint/version, entry
    metadata/OIDs (not all blob payloads), exact immediate-child listings, raw
    byte paths, lossless names, evaluated ASCII-fold indexes, compact findings,
    attribute-source provenance and independent exact/folded outcomes, budget
    evidence and completion state. Read-only indexes require privately owned
    backing storage; a mutable dict inside a frozen dataclass is insufficient.
    Partial topology explicitly records completed listing scopes. Closing or
    abandoning the snapshot invalidates further reads through selections;
    final repository audits can still invalidate accumulated command passes.
    PR2 supplies these fields; a PR1 instance carries no authenticated evidence.
    """

    def finding_for(self, use: str) -> Any | None:
        """Select the earliest finding in this use's nested legacy schedule.

        Compare stage barriers, traversal ordinals and within-entry rule
        sub-steps, including append's interleaved full-fold/alias comparisons.
        Preserve compact first witnesses per priority bucket, never all pairs.
        None is not acceptance when required obligations remain unevaluated.
        Findings carry conditions and witnesses rather than only rendered text.
        """
        raise NotImplementedError("receipt 0.7 M1 PR2 introduces the evaluator")

    def require(self, use: str, *, render: Callable) -> ProtectedSelection:
        """Refuse through the compatibility renderer, or return a frozen selection.

        Refuse internal misuse if obligations are incomplete. On success bind
        the selection to subject, purpose, entries and completed obligations;
        only that selection enters a verifier's protected read/export path.
        Renderers choose existing words/classes from findings, never policy.
        """
        raise NotImplementedError("receipt 0.7 M1 PR2 introduces the evaluator")


@dataclass(frozen=True)
class ProtectedSelection:
    """Frozen successful selection bound to subject, purpose and completed work.

    Contains selected authenticated entries and completed obligations. Acceptance
    keys include the full plan, anchor origin and completion state; equal blobs
    cannot share authority, scope or lifetime across subjects. Closing or
    abandoning the subject invalidates later reads. PR2 supplies the fields.
    """


@dataclass(frozen=True)
class DirectoryEvidence:
    """Bounded observations from the existing direct directory reader.

    This adapter has a distinct subject/provenance type with no Git OID or
    whole-tree claim. Share regular-file/ancestor fact types only where
    applicable; actual lstat, spelling, open/fstat and race guards remain with
    the reader. Keep its read-once contract, historical strings and ordering,
    and do not add Git-only name/attribute obligations or require a repository.
    PR2 supplies the evidence fields; PR1 performs no adaptation.
    """
