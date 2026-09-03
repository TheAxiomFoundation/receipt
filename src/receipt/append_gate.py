"""Gate every change to an append-only observation ledger.

The observation file is append-only with an immutable frozen prefix
(``ledger/immutable_prefix.json``). Resolver appends arrive as pull
requests; this checker is the deterministic review each proposal must pass
before merge:

- the frozen prefix is byte-identical (no rewrite, no truncation);
- against a base ref, the change only appends whole lines;
- every appended row parses, and carries the post-quarantine bindings:
  ``assertionVersion`` (content-addressed, recomputed here), ``retrievedAt``,
  ``sourceVintage``, ``ledgerRepoSha``, and a ``responseArchive`` digest;
- ``targetContentHash`` and ``sourceBindingProjection`` appear together or
  not at all, the projection's response digest matches the archive, and its
  unit matches the row's measure unit;
- a duplicate ``source_record_id`` is legal only as an explicit correction:
  the later row's ``assertionVersion.supersedes`` must name the version ID
  of the row it replaces.
- after witnessed genesis, every byte append carries exactly one next canonical
  release manifest, its producer signature, and two independently anchored
  RFC 3161 receipts; all prior release files remain byte-immutable against the
  PR's base commit.

Usage:
    python3 scripts/check_thesis_facts_append.py [--base-ref REF]

With a base ref (CI: the pull request's base commit) the append-only diff is
enforced; without it only the full-file invariants run.

Extracted nearly verbatim from PolicyEngine/ledger
scripts/check_thesis_facts_append.py at commit
9dafe8174f42a06c00817fe596d5a8e686cb17b7 (branch
codex/thesis-ledger-facts). The only intended behavioral change is
parameterization: every repo-specific constant moved into ``AppendGateSpec``,
supplied by the consumer's committed code. Behavior is gated by the
differential harness in tests/test_append_gate_equivalence.py.

Additions since the extraction close confinement gaps the upstream battery
never presented: a gate-only proposal is confined to the surfaces its verdict
speaks for, classified from what the candidate index records as well as from
what its working tree shows, a state path that traverses a symlinked component
is refused before it is read and so is a release root that does — its own
components are walked from the candidate root before anything reads through
them, because the checks that would have met a link are all downstream of
reading through it — with every component of both required to be spelled by
the directory that holds it, since what a component *is* comes from resolving
its name and a name-folding filesystem resolves one this package never named,
and with a directory that cannot be listed at all refused rather than
descended, because its listing was the only thing that could have bound the
spelling and making it search-only is all a proposal has to arrange,
the base is resolved to a commit once and carried to every consumer, every git
read runs with ``refs/replace`` disabled so a replacement object cannot change
what the printed OID reads as, each state file is read once — through
directory descriptors, so no component of its path is resolved twice, from a
candidate root that is opened before the run begins and held open until it
ends, so that the identity recorded from that descriptor still names a
directory rather than a number a filesystem may hand to the next one created
in its place, and is compared against it again wherever a verdict is decided
without a state read — the surface classification and the gate-only exit,
which perform no descent and so never reached that comparison — and never
through a weaker descent than that, nor a narrower one — the directories above
a state file are opened with search rights where the platform offers them, and
where it does not the read permission the descent needs is stated — every
consumer here, the release verification included, is fed those bytes, and the
file's mode and parent directories as that one read observed them, rather than
the path, with each file re-checked at the end, forwards and then backwards,
the two state files are tracked regular files that keep the base's file mode,
every release file the base carries is still an entry in the candidate index,
the release root's index and working tree agree in both directions — no index
entry the walk cannot see, no entry the walk cannot find, and no entry
answered for through a symlinked component or under another entry's spelling —
the index holds no entry spelled as another spelling of a protected path or
of any prefix of one — the directory a state file is read through is named by
that path as much as its leaf is — which every one of those reconciliations is
blind to because each is a comparison by exact spelling, what the index records as a path's *content* is
the content this verdict read wherever the commit under review changes that
path — every reconciliation above compares stage, mode and type and none of
them bytes, so a file rewritten, staged, and restored on disk went down the
whole data path over the restored bytes while the commit carried the rewrite —
and the post-cutover binding values are validated for shape rather than
presence alone. Every one of those index reads
asks about the exact path, as a literal pathspec, rather than handing git a
name to interpret as a pattern, as does the base tree's enumeration — a
release root beginning with ``:`` was read as pathspec magic and the magic
stripped, so the whole root enumerated as empty, an existing genesis tree was
treated as newly added files, and the byte and mode immutability this pass is
for was never compared — and what that enumeration returns must be the path
asked for or lie under it. Every git read here, like every one in
``release_chain``, runs with git's four pathspec-mode environment variables
dropped, because a pathspec written here has to mean what it says rather than
whatever the caller's environment would make of it. Every one of them reads
the entry's flag word too: an intent-to-add entry records no content while
looking in every other respect like a tracked file, so the tracked-state
check, the still-indexed check, and the release root's scan each refuse one
rather than comparing against a path this commit deletes.

What the closing re-check cannot do is bound the whole run. Verifying a
working tree means verifying something the candidate can write to for as long
as the run lasts, and no immutable snapshot of one is available here: between
the last two reads of a state file there is still an instant in which it can
be replaced unseen, and further passes only move the instant. So this verdict
speaks for the snapshot bytes it read — the bytes every consumer above was
given, and which each state file still held at both of its re-reads — not for
whatever the path holds afterwards. Removing that window means verifying the
committed tree object rather than the working tree, which changes what the
gate verifies rather than adding a check to it; it is tracked as follow-up
work and is not done here.

They run beside the extracted checks without altering any of their refusals,
and every new refusal runs after every pre-existing file-level refusal — with
three stated exceptions at entry, all saying that a comparison cannot be made
here rather than making one, and two further placements stated after them. The
checkout-level ``release_chain.assert_file_modes_authoritative`` runs ahead of
the release-history file checks (and after the base ref is resolved, so a
false setting cannot mask a base that names nothing). Beside it, sharing that
exception rather than adding another,
``release_chain.assert_working_tree_classification_authoritative`` refuses a
checkout in which ``git diff`` and ``git ls-files --others`` are a cache
rather than a comparison: ``core.fsmonitor`` set to anything but false makes
git trust a monitor's "unchanged" for a path, ``core.trustctime`` false and
``core.checkStat`` minimal drop the stat fields a same-size rewrite with a
restored mtime changes, and ``core.untrackedCache`` answers the untracked
listing from a cached directory scan. Every one of them lets a ledger
rewritten beside a gate file classify gate-only, which returns before the
ledger is read — the same fact the assume-unchanged and skip-worktree refusal
covers for one entry, reached through a setting instead. All four are
properties of the checkout rather than of any file, so like the modes guard
they say a comparison cannot be made here rather than making one. The per-state-path
``release_chain.assert_state_path_tracked`` runs ahead of everything that
reads either state file, because an untracked state path, or one under a
gitlink, is not this commit's content and nothing downstream can be a verdict
about it. ``release_chain.assert_index_carries_no_protected_alias`` runs
beside it and shares that exception rather than adding a fourth: it is the
same fact from the other side. That one read of the whole index answers a
second thing nothing else can, and shares the exception for it too — an entry
marked assume-unchanged or skip-worktree tells git to stop comparing that path
against the working tree, so ``git diff`` reports nothing for a file rewritten
on disk, and the surface classification this run is built on is that diff: the
ledger could be rewritten under such an entry, a gate file added beside it,
and the proposal classified gate-only and returned before any of it was read.
An index entry spelled as another spelling of a
protected path — or of any prefix of one, since ``Ledger`` standing where the
state file's own directory is, and ``Ledger/notes.txt`` under it, are second
objects a name-folding checkout puts in that directory or over it — is a
second object every reconciliation below is blind to, because each compares by
exact spelling; which of the two the one file on a name-folding filesystem
answers for is not decidable from the index or the tree, so this too says a
comparison cannot be made rather than making one. Comparing every prefix depth
rather than the protected path's own extends that entry-level check without
moving it: it is the same read of the same index, at entry, answering about
more of the same paths, and an entry spelled exactly right as far down as it
goes is untouched. And
``_assert_root_unchanged`` runs ahead of the surface classification, which is
a pre-existing check and the one that decides which path the whole run takes,
because a root exchanged since ``_set_root`` recorded it means the tree being
classified is not the tree this verdict was asked about; it runs again before
the gate-only return, which is the one exit reached without a state read and
therefore without the descent that would otherwise make the comparison.

Two component walks are placed by the same rule those three follow rather
than being further entry-level exceptions.
``release_chain.assert_no_symlinked_state_component`` runs at the top of each
state read and ``release_chain.assert_no_symlinked_release_root`` at the top
of both release-proposal paths, each ahead of every read through the path it
walks, because a path reached through a linked component — or under a spelling
the candidate tree does not hold — is not the path this verdict is about, and
nothing read through it is evidence about this proposal. The second walks
every configured path under the release tree and not the root alone:
``manifest_relative`` and ``anchor_relative`` are joined onto the candidate
root whole, so a spec whose manifest directory sits more than one component
below the root reaches it through components no walk looked at, and an
untracked link at one of them is invisible to the index reconciliation as
well, since ``rglob`` yields a symlinked directory without descending it and
the release root's scan skips it. Each of those two stops one component short
of its leaf, which already has a refusal of its own — the manifest
directory's is the enumeration's, the anchor directory's is the walk at the
top of ``verify_release_chain`` — so no sentence of theirs is replaced.

The manifest directory's own refusal holds only once something has decided to
enumerate, and on the push path what decides that is the leaf's type:
``initialized`` is ``manifest_directory.is_dir() and any(iterdir())``, which
is false for a tracked blob standing where that directory was, for an empty
untracked link, and for a dangling one. Each of those was this path's word for
"this tree has no chain" — an acceptance with no manifest, signature or
receipt read — while the commit under review may carry the chain still. So
that type is decided before the question is asked, in the enumeration's own
words (``release_chain.assert_manifest_directory_regular``). It stands ahead
of the push path's reads because it decides whether there are any, and it
pre-empts nothing: the enumeration is the only thing that would have spoken
for such a leaf, it does so for exactly one of the three shapes — a link to a
populated directory — and this says the same sentence for it. The anchor
directory's leaf is not the same case and gets no such check: nothing decides
whether the anchors are read, so the first read through that path meets them,
and a non-directory there is already refused as ``missing or non-regular
producer public key`` — and past it, ``missing or non-regular TSA anchor`` —
refusals the extraction gave, which a check here would only replace. A test
pins that, so the difference between the two leaves is bound rather than
asserted.

Standing ahead of the read means standing where a pre-existing refusal about
that content would have stood, and three cases do:

For the release root's own leaf, a link the enumeration would itself have met
is answered in the enumeration's own words, so that refusal is unchanged. A
dangling link is the one it would not have met — ``_working_release_files``
asks ``exists()``, which follows it, and returns nothing at all — so against a
base that tree used to be refused a file later, as ``existing release file was
deleted relative to <commit>``. It is refused as the link it is now, and a
test pins that. For a root of more than one component the walk can also
pre-empt the enumeration's byte and mode refusals about the files it would
have reached through the link — comparisons whose subject is a file outside
the tree.

And the spelling refusal in either walk pre-empts whatever the content behind
the folded name would have been refused for, on a filesystem that folds names,
which is the only kind where a *misspelling* can be found at all. Renaming
``releases`` to ``Releases`` beside a rewritten release file moves the answer
from ``existing release file bytes changed relative to <commit>`` to the
spelling refusal, for a single-component root and with no link anywhere;
renaming ``ledger`` to ``Ledger`` beside a tampered frozen prefix moves it
from ``immutable prefix line 1 ... was rewritten``. Both were checked against
this branch's head rather than reasoned about.

Its fail-closed half — a directory the verifier cannot list — fires on every
filesystem and every platform, because being unable to answer is not a
property of how names are compared. It pre-empts, for such a directory, the
same content refusals: a search-only ``ledger`` beside a rewritten frozen
prefix line answers ``cannot bind the spelling of
ledger/official_observations.jsonl`` where it used to answer ``immutable
prefix line 1 (…) was rewritten``, measured on a checkout whose filesystem
does not fold that name. And it
pre-empts the descent's own ``is not readable by this verifier`` refusal,
which a platform offering neither search-only flag would otherwise give for
the same directory. Both are additions since the extraction, so no upstream
refusal moves; the walk stands ahead of the descent, and the more specific
answer for a directory that cannot say which spelling it holds is that it
cannot say.

That half was once narrowed to directories that could be shown to fold the
name, so that the search-only descent of round one — a directory above a
state file that is traversable and deliberately not listable — stayed
allowed. The narrowing was wrong twice over: the probe could only ask about
the spellings it knew to try, a whole-string swapcase and the other of NFC and
NFD, while a filesystem that folds part of a mixed-case name answers no to all
of them and folds the name regardless; and the test that reproduced the case
reproduced the probe's own assumption with it. So the allowance is withdrawn
and the requirement is now the plain one: every directory above a protected
path must be listable by this verifier. That is stated in ``README.md``, and
it is what the price above buys — asking the question before the read, when
the read is what the folded name would have answered.

And the release root's walk is a pathname preflight, so it is asked again
at the end. Everything that reads through that root resolves its whole name
afresh — ``manifest_directory.is_dir()`` and ``iterdir()`` on the push path,
the working-tree enumeration and the release-history comparisons against a
base — so a root replaced after the walk had passed was followed by all of
them, and the index scan that ends the push path cannot say so because an
untracked root holds no index entries. The walk therefore opens the directory
it approved, from the candidate root's own held descriptor and component by
component with ``O_NOFOLLOW``, and each proposal path holds that descriptor
across every read it makes through the root and then re-runs the walk and
compares the path's ``lstat`` against the descriptor's ``fstat``. A link left
standing anywhere is answered in the walk's own words; a different directory
in the root's place is ``release root changed during verification``. That
runs after the reads it guards, so nothing pre-existing is pre-empted by it.
Like the state files' closing re-reads it is a comparison at two instants
rather than a lock: a root swapped after the walk and swapped back before the
re-check is not seen, and closing that is the same follow-up.

Nothing else is an exception: the per-file
``release_chain.assert_index_agrees_with_tree``, the check beside it that
every base release file is still an entry in the candidate index,
``release_chain.assert_index_content_bound`` after both of those, and the
release root's index scan all run after the comparisons they qualify, so a
comparison that passed while the working tree was not carrying what git
recorded is caught afterwards and nothing pre-existing is pre-empted; the
differential harness pins the upstream's mode-change refusal for an unstaged
chmod, which is both. Each order is pinned by a test. That ordering is per
path, as the loops making it are: a refusal about one release path can still
be reached before a pre-existing refusal about a later one, because the loop
answers each path in turn. Sorting the loop differently would only move which
path is named first, and the harness cannot produce the case — its fixtures
mutate the working tree without touching the index. Classifying the index's
changed set alongside the working tree's takes nothing away either: the union
is held to the rule the working-tree set already met, so a proposal the index
shows to touch both surfaces is refused as mixed, in the words that refusal
has always used, and one it shows to be data goes to the data path, where more
of the pre-existing checks run for it, not fewer.

Two refusals here are not about a tree at all, and are stated because they do
pre-empt everything on every input wherever they apply. Where ``os.open``
cannot take a ``dir_fd``, the state reads refuse before anything is compared,
because the confinement they claim is unavailable on that platform — and so
does ``_set_root``, which opens the candidate root with the descent's flags
before the run begins and therefore meets the same fact first. Where the
platform offers no search-only flag, that open has to ask for read permission
on the root, and a root this verifier may traverse but not read is refused in
the descent's words for that too: it has not changed, it cannot be read. Both
are the gate declining to answer, not a verdict about a proposal. Neither is
the gate's requirement, either, but the package's: the reader and both
sentences are ``release_chain``'s, so ``verify_release_chain`` and ``receipt
verify``'s custody pass refuse in the same words on the same platforms and for
the same directories. receipt requires a POSIX platform — its state reads open
through directory descriptors (``os.open`` with ``dir_fd``, which every POSIX
platform CPython supports and Windows does not), so on Windows ``receipt
verify`` and the append gate refuse rather than reading state through a weaker
path. The refusal says so, and ``README.md`` says the same.

All of it carries its own tests in tests/test_append_gate.py.
"""

from __future__ import annotations

import errno
import hashlib
import json
import locale
import os
import pathlib
import re
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from receipt import release_chain
from receipt.canonical import canonical_sha256
from receipt.release_chain import (
    _git_environment,
    assert_file_modes_authoritative,
    assert_index_agrees_with_tree,
    assert_index_carries_no_protected_alias,
    assert_index_content_bound,
    assert_working_tree_classification_authoritative,
    ChainSpec,
    MANIFEST_RE,
    ReleaseChainError,
    assert_no_symlinked_state_component,
    assert_release_root_unchanged,
    assert_release_root_index_regular,
    ChainVerification,
    hold_release_root,
    assert_secure_descent_supported,
    assert_state_path_tracked,
    confined_state_descriptor,
    git_blob_bytes,
    git_file_entry,
    read_state_descriptor,
    unreadable_directory_error,
    verify_base_release_chain,
    verify_release_chain,
    verify_release_history_immutable,
)


CODE_ROOT = pathlib.Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class AppendGateSpec:
    """Repo-specific gate constants pinned by the consuming repository."""

    chain: ChainSpec
    prefix_schema_version: str
    release_manifest_prefix: str
    genesis_support_files: frozenset[str]
    gate_surface: frozenset[str]
    data_surface: frozenset[str]
    assertion_content_keys: tuple[str, ...]


@dataclass(frozen=True)
class _CandidateTree:
    """Candidate-controlled paths, kept separate from the trusted code root.

    ``root_descriptor`` is the resolved root, held open for the whole verdict,
    and ``root_identity`` is the ``(st_dev, st_ino)`` ``fstat`` of that
    descriptor. Every state read descends from that directory, and the descent
    opened it by name each time, so a root swapped mid-run — the one component
    no walk below it can speak for — was simply followed. The descriptor walk
    compares against the recorded identity; the descriptor is what makes the
    comparison mean something, because an identity is only an identity while
    the inode it names cannot be handed to another directory. See
    ``_set_root``. The gate closes it once, in ``verify_append_gate``.
    """

    root: pathlib.Path
    ledger_path: pathlib.Path
    prefix_path: pathlib.Path
    spec: AppendGateSpec
    root_identity: tuple[int, int]
    root_descriptor: int


@dataclass(frozen=True)
class _BaseCommit:
    """The base of one verdict, resolved once and carried to every consumer.

    ``ref`` is what the caller named; ``commit`` is the OID that name pointed
    at when the run began. Resolving by name at each consumer meant a branch
    that moved mid-run was read at one commit for surface classification, a
    second for the append-only diff and the frozen prefix, and a third for the
    release history — one verdict about no single tree. Refusals keep naming
    ``ref``, exactly the text they always carried; every git read takes
    ``commit``.
    """

    ref: str
    commit: str


class AppendError(ValueError):
    """The proposed ledger change violates an append invariant."""


def _set_root(root: pathlib.Path, spec: AppendGateSpec) -> _CandidateTree:
    """Select the candidate worktree without changing the trusted code root.

    Pull-request CI executes this module from a detached checkout of the base
    commit, while ``--root`` points at the checked-out PR merge tree. Imports
    and production anchors therefore remain rooted at immutable ``CODE_ROOT``;
    only candidate data paths and git comparisons use ``ROOT``.
    """

    candidate_root = root.resolve()
    # Opened once, here, because this is the only moment in the run at which
    # the root has not yet been used for anything: every later read descends
    # from it, and a root exchanged after this is a different tree answering
    # questions asked about this one.
    #
    # The descriptor is held for the whole verdict, and that is what makes
    # the recorded identity evidence. ``(st_dev, st_ino)`` from an ``lstat``
    # is not a name for a directory over time: POSIX filesystems recycle the
    # inode of a deleted directory, so a root removed outright and replaced
    # by another directory — or by a symlink — created in its place can be
    # handed the number this run wrote down, and every comparison against it
    # then passes for a tree this run never selected. (The tests that rename
    # the root aside cannot show this: renaming keeps the original inode
    # live, so the replacement necessarily gets a different one.) An open
    # descriptor holds the inode, so while this one is open no other
    # directory can be given that number, and an ``lstat`` of the path that
    # reports the recorded identity really is the directory recorded here.
    #
    # It is opened the way the state descent opens it — search rights where
    # the platform has them, ``O_DIRECTORY`` and ``O_NOFOLLOW`` — and gives
    # the descent's own two refusals for the two things that can stop it,
    # because they are the same facts about the same open: a platform with no
    # ``dir_fd`` cannot be confined at all, and a root this verifier may
    # traverse but not read has not changed, it cannot be read. Anything else
    # is raised as it stands, as the ``lstat`` this replaced raised it.
    try:
        assert_secure_descent_supported()
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc
    try:
        descriptor = os.open(candidate_root, release_chain.DIRECTORY_OPEN_FLAGS)
    except OSError as exc:
        if release_chain.DESCENT_REQUIRES_DIRECTORY_READ and (
            exc.errno == errno.EACCES
        ):
            raise AppendError(
                str(
                    unreadable_directory_error(
                        candidate_root, spec.chain.state_relative
                    )
                )
            ) from exc
        raise
    recorded = os.fstat(descriptor)
    return _CandidateTree(
        root=candidate_root,
        ledger_path=candidate_root / spec.chain.state_relative,
        prefix_path=candidate_root / spec.chain.prefix_relative,
        spec=spec,
        root_identity=(recorded.st_dev, recorded.st_ino),
        root_descriptor=descriptor,
    )


def _assert_root_unchanged(candidate: _CandidateTree) -> None:
    """Require the root to still be the directory ``_set_root`` selected.

    Every check in this module reaches the candidate tree by name — the
    checkout settings, the tracked-state entries, ``git`` itself with the
    root as its working directory — and the only thing that ever compared
    the recorded identity against what the name resolves to now was the
    descriptor walk each state read performs. A gate-only proposal performs
    no state read: it classifies the changed sets and returns. So a root
    renamed aside, with another repository moved into its place after
    ``_set_root`` recorded it, had the checkout guard, the tracking check and
    both surface probes answered by a replacement, and the verdict returned
    was about a tree this run never selected.

    The comparison is ``os.lstat`` of the resolved root against ``os.fstat``
    of the descriptor ``_set_root`` opened and this run still holds, and a
    root that cannot be ``lstat``-ed at all is the same answer, because it was
    there when the run began. Asking the descriptor rather than a recorded
    pair of numbers is what makes the answer one about a directory: the
    descriptor holds the original inode, so no directory created at that path
    since can have been given its number. The refusal is the wording
    ``release_chain.confined_state_descriptor`` already gives for this fact,
    so one sentence names it wherever it is found.

    Like every other check here this is a comparison at an instant, not a
    lock, and it says the same thing ``_assert_states_unchanged`` says about
    the state files: what it establishes is that the root was the recorded
    directory at these two moments, not that the reads between them saw it.
    A root exchanged after the first comparison, used to answer the surface
    probes, and moved back before the second still yields the gate-only
    acceptance. Closing that needs an immutable snapshot of the tree under
    audit, which this gate does not have; it is the same residual, and the
    same follow-up.
    """

    try:
        current = os.lstat(candidate.root)
        held = os.fstat(candidate.root_descriptor)
    except OSError as exc:
        raise AppendError("candidate root changed during verification") from exc
    if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
        raise AppendError("candidate root changed during verification")


def _git_output(arguments: list[str], candidate: _CandidateTree) -> bytes:
    # Every git read here runs under the shared _git_environment, which turns
    # off refs/replace: a replacement object changes what a commit, tree, or
    # blob reads as while the OID this verdict prints stays the same.
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=candidate.root,
            check=False,
            capture_output=True,
            env=_git_environment(),
        )
    except FileNotFoundError as exc:
        raise AppendError("git is required for --base-ref verification") from exc
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", errors="replace").strip()
        raise AppendError(f"git {' '.join(arguments)} failed: {diagnostic}")
    return completed.stdout


def _resolve_base_commit(base_ref: str, candidate: _CandidateTree) -> str:
    completed = _git_output(
        ["rev-parse", "--verify", "--end-of-options", f"{base_ref}^{{commit}}"],
        candidate,
    )
    commit = completed.decode("ascii").strip()
    _git_output(["merge-base", "--is-ancestor", commit, "HEAD"], candidate)
    return commit


def _nul_paths(payload: bytes) -> set[str]:
    return {os.fsdecode(path) for path in payload.split(b"\0") if path}


def _matches_surface(path: str, surface: frozenset[str]) -> bool:
    for pattern in surface:
        if pattern.endswith("/**"):
            if path.startswith(pattern[:-2]):
                return True
        elif path == pattern:
            return True
    return False


def _classify_surfaces(
    changed: set[str], candidate: _CandidateTree
) -> tuple[set[str], set[str], set[str]]:
    """Split one changed set into DATA, GATE, and everything else.

    Classification is per path, so classifying a union is the same as taking
    the union of the classifications — which is how the gate-only decision
    below folds the index's changed set into the working tree's.
    """

    data_changes = {
        path for path in changed if _matches_surface(path, candidate.spec.data_surface)
    }
    gate_changes = {
        path for path in changed if _matches_surface(path, candidate.spec.gate_surface)
    }
    return data_changes, gate_changes, changed - data_changes - gate_changes


def check_surface_separation(
    base: _BaseCommit, candidate: _CandidateTree
) -> tuple[set[str], set[str], set[str]]:
    """Return data/gate/unclassified changes and reject a combined proposal.

    DATA and GATE do not have to cover the changed set: a path matching
    neither surface is unclassified, and it is returned so no caller can
    treat a surface match as a statement about everything else the proposal
    touched.
    """

    changed = _nul_paths(
        _git_output(
            [
                "diff",
                "--name-only",
                "-z",
                "--no-renames",
                "--no-ext-diff",
                "--no-textconv",
                base.commit,
                "--",
            ],
            candidate,
        )
    )
    # ``git diff`` excludes untracked files. Tests mint release siblings before
    # staging them, and a newly added anchor must still classify as gate code.
    changed.update(
        _nul_paths(
            _git_output(
                ["ls-files", "--others", "--exclude-standard", "-z", "--"],
                candidate,
            )
        )
    )
    data_changes, gate_changes, unclassified = _classify_surfaces(changed, candidate)
    if data_changes and gate_changes:
        raise AppendError(
            "mixed data/gate proposal is forbidden: DATA_SURFACE changes="
            f"{sorted(data_changes)}; GATE_SURFACE changes="
            f"{sorted(gate_changes)}; split them into separate pull requests"
        )
    return data_changes, gate_changes, unclassified


def _staged_surface_changes(
    base: _BaseCommit, candidate: _CandidateTree
) -> tuple[set[str], set[str], set[str]]:
    """Classify what the candidate INDEX changes against the base.

    The classification above is derived from ``git diff`` against the working
    tree plus the untracked files, which is what a proposal's files look like
    — and says nothing about what its commit records. The index is the commit
    under review: a mode a proposal changed lives there, and so does a file it
    staged and then restored on disk, or dropped from the index while leaving
    the bytes where they were. Those changes are invisible to a working-tree
    diff by construction, and the gate-only path returns on that diff alone.
    """

    staged = _nul_paths(
        _git_output(
            [
                "diff-index",
                "--cached",
                "--name-only",
                "-z",
                "--no-renames",
                "--no-ext-diff",
                "--no-textconv",
                base.commit,
                "--",
            ],
            candidate,
        )
    )
    return _classify_surfaces(staged, candidate)


def check_gate_only_confinement(
    unclassified: set[str], candidate: _CandidateTree
) -> set[str]:
    """Confine a gate-only proposal to the surfaces its verdict speaks for.

    A gate-only verdict returns before the ledger is read, so the frozen
    prefix, the append-only diff, the row bindings, and the release history
    are all skipped. Surface classification never checked that DATA and GATE
    covered the changed set, so a proposal that added a gate file AND
    rewrote an unclassified file under the release root — say
    ``releases/README.md`` — was accepted with none of those checks run.
    An unclassified change
    inside the release root is refused here; the rest are returned for the
    caller to name in its success text, so an unclassified change riding a
    gate-only proposal is never silent.
    """

    release_root = candidate.spec.chain.release_root_relative.as_posix()
    inside_release_root = sorted(
        path
        for path in unclassified
        if path == release_root or path.startswith(f"{release_root}/")
    )
    if inside_release_root:
        raise AppendError(
            "gate-only proposal changes unclassified release path(s): "
            f"{inside_release_root}"
        )
    return set(unclassified)


def _confine_state_path(
    relative: pathlib.PurePosixPath, candidate: _CandidateTree
) -> None:
    """Require a candidate state path to live inside the candidate tree.

    ``_set_root`` joins the state and prefix paths lexically, and every reader
    downstream follows whatever the join lands on. A symlinked ``ledger/`` —
    pointed outside the checkout, or at an in-tree directory the surface
    patterns never name — therefore supplied the accepted bytes while the
    prefix hash, the append-only diff, and the row bindings all reported on
    them as though they were the tree's own. Walk every component before the
    read instead.
    """

    try:
        assert_no_symlinked_state_component(candidate.root, relative)
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc


@dataclass(frozen=True)
class _StateSnapshot:
    """One state file as it stood at one instant, and the bytes read then.

    ``identity`` is ``(st_dev, st_ino, st_size, st_mtime_ns, st_ctime_ns)``
    observed on the open descriptor after the read, so a later re-read can
    say whether the same file is still there and still says the same thing.
    ``st_ctime_ns`` is in the tuple because the other four are all
    forgeable by a candidate that puts the file back: a replacement written
    in place and stamped with ``os.utime`` restores the device, the inode,
    the size, and the modification time. The inode change time is set by the
    kernel on every metadata write and cannot be set back.

    ``mode`` is that same descriptor's ``st_mode``. The file's git category
    was worked out twice more after this read, each time by resolving the
    pathname again — once by ``check_state_modes`` for the base comparison
    and once by the index comparison after it — so three answers could be
    about three different files, and a shared parent exchanged A-to-B-to-A
    between them left every one of them looking consistent. Both now take
    the category recorded here.

    ``ancestors`` is the identity of every directory the descriptor walk
    opened on the way to this file, which the leaf's own identity cannot
    supply: ``ledger/`` can be exchanged for a directory holding a hard link
    to the same inode, and device, inode, size, modification time and change
    time all still agree. The closing re-check compares these too, so a file
    reached through different directories is a changed file.
    """

    relative: pathlib.PurePosixPath
    payload: bytes
    identity: tuple[int, int, int, int, int]
    mode: int
    ancestors: tuple[tuple[int, int], ...]

    @property
    def category(self) -> str:
        """The git mode this file would be recorded as, from the read itself.

        ``_read_state_snapshot`` refuses anything that is not a regular file,
        so only the two blob categories are reachable, and git keys them on
        the owner execute bit alone (see ``check_state_modes``).
        """

        return "100755" if self.mode & 0o100 else "100644"


def _read_state_snapshot(
    relative: pathlib.PurePosixPath, candidate: _CandidateTree
) -> _StateSnapshot:
    """Read one candidate state file once, and record what was read.

    Every state read here was check-then-open: the component walk looked at
    the path, and a separate ``read_text`` later followed whatever the name
    resolved to by then. Three things rode on that gap. A FIFO at the ledger
    path blocked the reader indefinitely instead of being refused — the
    walk sees no symlink, and ``open`` on a FIFO waits for a writer. The
    final component could be swapped between the walk and the open, so the
    bytes verified were never the ones inspected. And the ledger was read
    again by the release verification, so one tree could satisfy the row
    checks with one ledger and the release chain with another.

    So: walk the components, ``lstat`` the path, open it with ``O_NOFOLLOW``
    (never traverse a link that appeared since the walk) and ``O_NONBLOCK``
    (never wait on a pipe or device), ``fstat`` the descriptor and require it
    to be the same regular file the ``lstat`` saw, and read the bytes through
    that one descriptor. Every consumer in this module is then fed these
    bytes rather than reading the path again.

    The open goes through ``release_chain.confined_state_descriptor``, which
    resolves the components against directory descriptors rather than
    resolving the pathname a second time: ``O_NOFOLLOW`` on the leaf says
    nothing about ``ledger/``, so a parent this walk found to be a real
    directory could still be replaced by a link before the open followed it.
    It is given the root identity ``_set_root`` recorded, so the one
    component below which nothing can vouch for it — the candidate root
    itself — is checked too, and it refuses outright on a platform whose
    ``os.open`` cannot take a ``dir_fd`` rather than reading the state files
    with confinement it cannot provide there.
    """

    _confine_state_path(relative, candidate)
    path = candidate.root / relative
    display = relative.as_posix()
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise AppendError(f"state file is not a regular file: {display}")
    try:
        confined = confined_state_descriptor(
            candidate.root, relative, root_identity=candidate.root_identity
        )
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc
    descriptor = confined.descriptor
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise AppendError(f"state file is not a regular file: {display}")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise AppendError(
                f"state file was replaced while it was being read: {display}"
            )
        payload = read_state_descriptor(descriptor)
        read = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    return _StateSnapshot(
        relative=relative,
        payload=payload,
        identity=(
            read.st_dev,
            read.st_ino,
            read.st_size,
            read.st_mtime_ns,
            read.st_ctime_ns,
        ),
        mode=read.st_mode,
        ancestors=confined.ancestors,
    )


def _assert_state_unchanged(
    snapshot: _StateSnapshot, candidate: _CandidateTree
) -> None:
    """Require a state file to be what it was when this verdict read it.

    ``check_release_proposal`` and ``check_release_chain_without_base`` now
    hand the release verification the two snapshots this run read, so it no
    longer opens either path by name and no consumer inside one verdict can
    be shown a different file. What is left is the window around the whole
    run: after the last consumer returns, read each state file again and
    require the same file and the same bytes. A tree that changed underneath
    the run gets one refusal naming the file, instead of a verdict assembled
    from two different ledgers. A re-read that cannot be completed at all —
    the path is now a link, a pipe, or gone — is the same answer: it
    changed. The comparison is over the recorded identity as well as the
    bytes, and that identity includes the inode change time, so a
    replacement put back in place with its device, inode, size, and
    modification time restored is still refused.
    """

    display = snapshot.relative.as_posix()
    try:
        current = _read_state_snapshot(snapshot.relative, candidate)
    except (AppendError, OSError) as exc:
        raise AppendError(
            f"state file changed during verification: {display}"
        ) from exc
    if (
        current.identity,
        current.mode,
        current.ancestors,
        current.payload,
    ) != (snapshot.identity, snapshot.mode, snapshot.ancestors, snapshot.payload):
        raise AppendError(f"state file changed during verification: {display}")


def _assert_states_unchanged(
    snapshots: tuple[_StateSnapshot, ...], candidate: _CandidateTree
) -> None:
    """Re-check every state file forwards, then every state file backwards.

    The closing checks were one per file, in order: the ledger, then the
    frozen prefix. That leaves a writer a window it can aim at. Wait for the
    ledger's re-check to return, rewrite the ledger while the prefix is being
    re-checked, and the run answers OK — the ledger was the file this verdict
    was mostly about, and the last thing that looked at it looked before the
    rewrite.

    Closing that window properly needs an immutable snapshot of the tree
    under audit, and this gate has none: it verifies a working directory
    that the candidate can write to for as long as the run lasts. What is
    available is coherence between the closing reads, so the re-check runs
    the files in order and then again in reverse — ledger, prefix, prefix,
    ledger — each pass being the same identity-plus-bytes comparison, and a
    change seen in any of them refusing in the message that already existed.
    A rewrite aimed at the gap after one file's re-check is now seen by that
    file's second re-check.

    This narrows the window; it does not close it. Between the last two
    reads of one file there is still an instant in which that file can be
    replaced and the run will not see it, and adding further passes only
    moves the instant. What the verdict states is what it read: the bytes of
    the snapshots this run took, which every consumer here was fed and which
    each file still held at both of its re-reads. Removing the window
    altogether means verifying a committed tree object instead of a working
    tree — reading the ledger and the prefix out of the commit under review,
    which nothing can rewrite underneath the run — and that is a change to
    what the gate verifies, not a check added to it. It is tracked as
    follow-up work and is not done here.
    """

    for snapshot in (*snapshots, *reversed(snapshots)):
        _assert_state_unchanged(snapshot, candidate)


def _as_text(payload: bytes, encoding: str | None = None) -> str:
    """Decode snapshot bytes exactly as ``Path.read_text`` decoded them.

    The snapshot reader replaced two ``read_text`` calls, and this port's
    refusals are compared with the upstream oracle's byte for byte, so the
    decoding those calls performed is reproduced rather than approximated:
    the caller's encoding or, where the call passed none, the same locale
    default ``open`` would have used, and the universal-newline translation
    text mode applies to a whole file (``\r\n`` and a lone ``\r`` both
    become ``\n``).
    """

    decoded = payload.decode(encoding or locale.getpreferredencoding(False))
    return decoded.replace("\r\n", "\n").replace("\r", "\n")


def _lines(text: str) -> list[str]:
    return [line for line in text.split("\n") if line.strip()]


def reject_non_append_bytes(text: str) -> None:
    """Reject blank/whitespace-only lines and any non-single trailing newline.

    ``_lines`` drops blank lines so row parsing is convenient, but that means a
    blank line inserted into the frozen JSONL would normalize away and pass both
    the prefix hash and the append-only diff. A JSONL row is exactly one
    non-empty line: a blank/whitespace-only line inside the covered region is a
    byte tamper, and the file must end with exactly one trailing newline.
    """
    parts = text.split("\n")
    if parts[-1] != "":
        raise AppendError("ledger must end with exactly one trailing newline")
    for index, part in enumerate(parts[:-1], start=1):
        if not part.strip():
            raise AppendError(
                f"line {index} is blank or whitespace-only; a JSONL row is one "
                "non-empty line and a stray blank line is a tamper"
            )


def expected_assertion_version_id(row: dict[str, Any], spec: AppendGateSpec) -> str:
    """Recompute the content address the resolver must have written.

    Mirrors ``assertion_version`` in the Thesis resolver (av1 v2 spec): the ID
    commits to everything that changes what the assertion MEANS — identity,
    value, timing, population, the complete measure concept mapping, exact
    source lineage/digest, row/cell lineage, and the archived response digest —
    so an in-place edit is detectable and a correction must supersede
    explicitly. This projection must stay byte-identical to the Brier writer's
    ``assertion_version`` (both fed to the shared ``canonical_sha256``), so any
    change here is a coordinated schema migration on both sides.
    """
    measure = row.get("measure") or {}
    source = row.get("source") or {}
    projection = {key: row.get(key) for key in spec.assertion_content_keys}
    projection["measure"] = {
        "concept": measure.get("concept"),
        "unit": measure.get("unit"),
        "source_concept": measure.get("source_concept"),
        "concept_relation": measure.get("concept_relation"),
        "concept_authority": measure.get("concept_authority"),
        "legal_vintage": measure.get("legal_vintage"),
    }
    projection["source"] = {
        "source_name": source.get("source_name"),
        "source_table": source.get("source_table"),
        "source_file": source.get("source_file"),
        "url": source.get("url"),
        "vintage": source.get("vintage"),
        "source_sha256": source.get("source_sha256"),
    }
    projection["lineage"] = {
        "source_row_keys": row.get("source_row_keys"),
        "source_cell_keys": row.get("source_cell_keys"),
    }
    projection["responseArchiveSha256"] = (row.get("responseArchive") or {}).get(
        "sha256"
    )
    return f"av2:{canonical_sha256(projection)}"


def _effective_assertion_id(row: dict[str, Any], spec: AppendGateSpec) -> str:
    """Return the row's effective assertion version ID.

    Post-cutover rows carry an explicit ``assertionVersion.id`` (validated
    against the recomputed content address in :func:`check_rows`); legacy
    pre-versioning rows are addressable by their recomputed content address.
    Either way every row has exactly one effective ID that a correction must
    name and that no later row may reissue.
    """
    version = row.get("assertionVersion")
    if isinstance(version, dict) and version.get("id"):
        return str(version["id"])
    return expected_assertion_version_id(row, spec)


def effective_current_rows(
    rows: list[dict[str, Any]], spec: AppendGateSpec
) -> list[dict[str, Any]]:
    """Return the latest non-superseded row per assertion identity.

    A correction names the version it replaces via
    ``assertionVersion.supersedes``; the replaced row drops out of the current
    view. Aggregate-fact validation runs on this supersede-aware view so a
    legitimate correction (same semantic key, new value) is not mistaken for a
    duplicate key.
    """
    superseded: set[str] = set()
    for row in rows:
        version = row.get("assertionVersion")
        if isinstance(version, dict) and version.get("supersedes"):
            superseded.add(str(version["supersedes"]))
    return [row for row in rows if _effective_assertion_id(row, spec) not in superseded]


def check_prefix(
    lines: list[str], prefix_text: str, candidate: _CandidateTree
) -> dict[str, Any]:
    # The manifest text comes from the caller's one snapshot read of the
    # prefix path, taken where this function used to walk and read it, so the
    # refusals below fire in exactly the order they always did.
    prefix = json.loads(prefix_text)
    if prefix.get("schemaVersion") != candidate.spec.prefix_schema_version:
        raise AppendError(
            f"unsupported prefix manifest schema {prefix.get('schemaVersion')!r}"
        )
    count = int(prefix["prefixLineCount"])
    hashes = prefix["lineSha256s"]
    if len(hashes) != count:
        raise AppendError("prefix manifest line hashes disagree with its count")
    if len(lines) < count:
        raise AppendError(
            f"ledger has {len(lines)} rows but the immutable prefix "
            f"requires at least {count}"
        )
    for index in range(count):
        digest = hashlib.sha256(lines[index].encode("utf-8")).hexdigest()
        if digest != hashes[index]:
            row_id = json.loads(lines[index]).get("source_record_id", "?")
            raise AppendError(
                f"immutable prefix line {index + 1} ({row_id}) was rewritten"
            )
    joined = hashlib.sha256(
        ("\n".join(lines[:count]) + "\n").encode("utf-8")
    ).hexdigest()
    if joined != prefix["prefixSha256"]:
        raise AppendError("immutable prefix cumulative hash mismatch")
    return prefix


def _is_canonical_rfc3339(value: Any) -> bool:
    """Accept exactly the canonical RFC 3339 profile the ledger writer emits.

    Narrower than RFC 3339 on purpose, and stated so: uppercase ``T`` and
    ``Z``, an offset only as ``±HH:MM`` with bounded fields, an optional
    fraction, and no leap second (``:60``). The lowercase ``t``/``z`` forms
    and leap seconds the RFC permits are refused as outside the profile
    (peer review, round three). ``datetime.fromisoformat`` alone accepts a
    wider grammar — a bare date, a space separator, a missing offset — and a
    naive timestamp cannot be ordered against a witnessed genTime at all. So
    the shape is pinned by pattern first and the calendar values are then
    checked by the parser, which is what rejects a February 30th that
    matches the pattern. The offset's hour and minute are bounded in the
    pattern as well, because the parser does not refuse an overflowing
    offset: ``+01:60`` is normalised to ``+02:00`` and accepted (round one).
    """

    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
        r"(?:\.[0-9]+)?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
        value,
    ):
        return False
    try:
        return datetime.fromisoformat(value).tzinfo is not None
    except ValueError:
        return False


def check_rows(lines: list[str], prefix_count: int, spec: AppendGateSpec) -> None:
    """Validate every row, and the post-cutover bindings on appended rows.

    The binding values were checked for presence alone, so a response digest
    of ``"x"``, a ``ledgerRepoSha`` of ``"HEAD"``, and a ``retrievedAt`` of
    ``"yesterday"`` each satisfied a contract the row's custody claim rests
    on. Their shapes are validated by check_binding_shapes, which the gate
    runs after every check that existed before it; this function is the
    ported row validation, unchanged. What any of the values MEANS is
    untouched either way. In particular the ``assertionVersion`` projection
    stays exactly as it is — it must remain byte-identical to the Brier
    writer's, so changing it is a coordinated schema migration on both
    sides, not a gate fix.
    """

    versions: dict[str, int] = {}
    active_by_record_id: dict[str, tuple[int, str | None]] = {}
    for number, line in enumerate(lines, start=1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AppendError(f"line {number} is not valid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise AppendError(f"line {number} is not a JSON object")
        record_id = row.get("source_record_id")
        if not record_id:
            raise AppendError(f"line {number} lacks source_record_id")
        if not isinstance(row.get("value"), (int, float)):
            raise AppendError(f"line {number} ({record_id}) has no numeric value")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(row.get("observed_at", ""))):
            raise AppendError(f"line {number} ({record_id}) has no observed_at date")
        unit = (row.get("measure") or {}).get("unit")
        if not unit:
            raise AppendError(f"line {number} ({record_id}) has no measure unit")

        recomputed = expected_assertion_version_id(row, spec)
        version = row.get("assertionVersion")
        supersedes = None
        if version is not None:
            if not isinstance(version, dict):
                raise AppendError(f"line {number} assertionVersion is not an object")
            version_id = str(version.get("id", ""))
            supersedes = version.get("supersedes")
            if version_id != recomputed:
                raise AppendError(
                    f"line {number} ({record_id}) assertionVersion.id does not "
                    f"match its content ({version_id} != {recomputed})"
                )
            effective_id = version_id
        else:
            # Pre-versioning rows are addressable by their recomputed content
            # address; that ID is reserved just like an explicit one so a legacy
            # synthetic ID cannot be silently reissued.
            effective_id = recomputed

        # Reserve the effective ID of EVERY row. A collision means two rows
        # claim the same assertion version — a duplicate legacy ID or an
        # A->B->A chain trying to restore a superseded value.
        if effective_id in versions:
            raise AppendError(
                f"line {number} restates assertion version {effective_id} "
                f"from line {versions[effective_id]}"
            )
        versions[effective_id] = number

        if number > prefix_count:
            for field in (
                "retrievedAt",
                "sourceVintage",
                "ledgerRepoSha",
                "responseArchive",
                "assertionVersion",
            ):
                if not row.get(field):
                    raise AppendError(
                        f"appended line {number} ({record_id}) lacks {field}"
                    )
            archive = row["responseArchive"]
            if not isinstance(archive, dict) or not archive.get("sha256"):
                raise AppendError(
                    f"appended line {number} responseArchive lacks a digest"
                )
            # Key PRESENCE pairs the binding, and present values must be
            # shape-valid: truthiness accepted targetContentHash "" with a
            # missing (or {}) projection, silently waiving the contract
            # binding (found during the extraction review).
            has_hash = "targetContentHash" in row
            has_projection = "sourceBindingProjection" in row
            if has_hash != has_projection:
                raise AppendError(
                    f"appended line {number} ({record_id}) must carry "
                    "targetContentHash and sourceBindingProjection together"
                )
            if has_hash:
                content_hash = row["targetContentHash"]
                if not isinstance(content_hash, str) or not re.fullmatch(
                    r"[0-9a-f]{64}", content_hash
                ):
                    raise AppendError(
                        f"appended line {number} ({record_id}) "
                        "targetContentHash is not a SHA-256 hex digest"
                    )
                projection = row["sourceBindingProjection"]
                if not isinstance(projection, dict) or not projection:
                    raise AppendError(
                        f"appended line {number} ({record_id}) "
                        "sourceBindingProjection must be a non-empty object"
                    )
                if projection.get("responseSha256") != archive.get("sha256"):
                    raise AppendError(
                        f"appended line {number} projection digest does not "
                        "match its archived response"
                    )
                if projection.get("unit") != unit:
                    raise AppendError(
                        f"appended line {number} projection unit "
                        f"{projection.get('unit')!r} contradicts the row unit "
                        f"{unit!r}"
                    )

        previous = active_by_record_id.get(str(record_id))
        if previous is not None:
            previous_line, previous_version = previous
            if supersedes is None:
                raise AppendError(
                    f"line {number} duplicates {record_id} (line "
                    f"{previous_line}) without superseding an assertion "
                    "version — corrections must be explicit"
                )
            if supersedes != previous_version:
                raise AppendError(
                    f"line {number} supersedes {supersedes} but the active "
                    f"version of {record_id} is {previous_version}"
                )
        elif supersedes is not None:
            raise AppendError(
                f"line {number} supersedes {supersedes} but {record_id} has "
                "no earlier row"
            )
        active_by_record_id[str(record_id)] = (number, effective_id)



def check_append_only(
    base: _BaseCommit, lines: list[str], candidate: _CandidateTree
) -> int:
    relative = candidate.ledger_path.relative_to(candidate.root).as_posix()
    try:
        base_text = subprocess.check_output(
            ["git", "show", f"{base.commit}:{relative}"],
            cwd=candidate.root,
            text=True,
            env=_git_environment(),
        )
    except subprocess.CalledProcessError as exc:
        raise AppendError(f"cannot read {relative} at base {base.ref}") from exc
    base_lines = _lines(base_text)
    if len(lines) < len(base_lines):
        raise AppendError(
            f"change truncates the ledger: {len(base_lines)} -> {len(lines)} rows"
        )
    for index, line in enumerate(base_lines):
        if lines[index] != line:
            row_id = json.loads(line).get("source_record_id", "?")
            raise AppendError(
                f"change rewrites existing line {index + 1} ({row_id}); "
                "the ledger is append-only — supersede instead"
            )
    return len(lines) - len(base_lines)


def _manifest_at_ref(
    base: _BaseCommit, candidate: _CandidateTree
) -> dict[str, Any]:
    relative = candidate.prefix_path.relative_to(candidate.root).as_posix()
    try:
        text = subprocess.check_output(
            ["git", "show", f"{base.commit}:{relative}"],
            cwd=candidate.root,
            text=True,
            env=_git_environment(),
        )
    except subprocess.CalledProcessError as exc:
        raise AppendError(f"cannot read {relative} at base {base.ref}") from exc
    return json.loads(text)


def check_prefix_anchored_to_base(
    base: _BaseCommit,
    candidate_prefix: dict[str, Any],
    candidate: _CandidateTree,
) -> int:
    """Require the frozen prefix manifest to be unchanged from the base.

    The immutable-prefix manifest lives beside the ledger and is candidate-
    controlled, so a PR could grow ``prefixLineCount`` over its own append and
    have every post-cutover binding skipped (the appended row would count as
    "prefix"). Growing the frozen prefix is an explicit, separately reviewed
    migration — never part of the automated append path — so under a base ref
    the count, cumulative hash, and per-line hashes must match the base exactly.
    Returns the BASE prefix line count, which callers use as the post-cutover
    binding boundary so a candidate-controlled count can never move it.
    """
    base_prefix = _manifest_at_ref(base, candidate)
    for field in ("prefixLineCount", "prefixSha256", "lineSha256s"):
        if candidate_prefix.get(field) != base_prefix.get(field):
            raise AppendError(
                f"immutable prefix manifest {field} changed vs base {base.ref}; "
                "the frozen prefix cannot grow through the automated append path "
                "— growing it is an explicit reviewed migration"
            )
    return int(base_prefix["prefixLineCount"])


def check_binding_shapes(lines: list[str], prefix_count: int) -> None:
    """Require the post-cutover binding values to have the shape they claim.

    Presence alone was the whole check on these three. The digest is what
    binds the row to an archived response, the repo sha is what binds it to
    the code that produced it, and retrievedAt is what any chronology claim
    about the row is measured from — a placeholder in any of them satisfied
    the contract while binding nothing.

    Runs after every check that existed before it — row validation, the
    release proposal, the release history — so no pre-existing file-level
    refusal is pre-empted for an input that violates both. Two review rounds
    moved it here: first from ahead of the projection and supersession
    checks, then from ahead of the release checks. The one refusal that does
    run ahead of the pre-existing release checks is the checkout-level one
    in release_chain.assert_file_modes_authoritative, deliberately: a
    checkout that cannot be verified says so before any verdict about its
    files. The rows were parsed and validated by check_rows already, so the
    loads below cannot fail.
    """

    for number, line in enumerate(lines, start=1):
        if number <= prefix_count:
            continue
        row = json.loads(line)
        record_id = row.get("source_record_id")
        digest = row["responseArchive"]["sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise AppendError(
                f"appended line {number} ({record_id}) "
                "responseArchive.sha256 is not a SHA-256 hex digest"
            )
        repo_sha = row["ledgerRepoSha"]
        if not isinstance(repo_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", repo_sha):
            raise AppendError(
                f"appended line {number} ({record_id}) ledgerRepoSha is "
                "not a full 40-character commit id"
            )
        if not _is_canonical_rfc3339(row["retrievedAt"]):
            raise AppendError(
                f"appended line {number} ({record_id}) retrievedAt is not "
                "a canonical RFC 3339 timestamp (uppercase T and Z or "
                "±HH:MM, no leap second)"
            )


def check_state_modes(
    base: _BaseCommit,
    candidate: _CandidateTree,
    *,
    snapshots: Mapping[str, _StateSnapshot] | None = None,
) -> None:
    """Require the ledger and the frozen prefix to keep the base's file mode.

    check_append_only and check_prefix_anchored_to_base compare bytes and
    manifest fields only, and verify_release_history_immutable compares modes
    for ``releases/`` alone, so a proposal could leave both state files
    byte-identical and still flip the ledger to executable. Git tracks that
    bit, a merge carries it, and nothing on the append path looked at it.
    Base release files are already mode-immutable; this is the same invariant
    for the two files the append path itself reads. Git records only the
    executable category, so that is what is compared — a base symlink or
    gitlink entry is a category change too, and refuses here. The comparison
    reads the candidate's mode, so it is only evidence while the working tree
    carries what git recorded: assert_index_agrees_with_tree establishes that
    per file, and the checkout settings are checked as well.

    ``snapshots`` are the state files this run already read, keyed by
    relative POSIX path. The mode came from ``stat``-ing the pathname here
    and the index comparison below then resolved that name a third time, so
    the read, the mode, and the index answer were three separate resolutions
    of one name and a parent exchanged between any two of them made them
    answers about different files. With the snapshots both take the category
    the one read recorded, from the descriptor it held open. Omitted — a
    caller using this function on its own — each is worked out from the path,
    which is now ``lstat``-ed rather than ``stat``-ed, and a symlink there is
    refused instead of being followed to whatever it points at.
    """

    # verify_append_gate already refused a non-authoritative checkout at
    # entry, for the push path as well as this one; the call is kept so this
    # function is safe to call on its own, exactly as the release-history
    # pass keeps its own.
    try:
        assert_file_modes_authoritative(candidate.root)
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc
    for relative in (
        candidate.spec.chain.state_relative,
        candidate.spec.chain.prefix_relative,
    ):
        path = relative.as_posix()
        try:
            entry = git_file_entry(candidate.root, base.commit, path)
        except ReleaseChainError as exc:
            raise AppendError(str(exc)) from exc
        # Git derives the category from the owner bit alone (ce_permissions:
        # ``mode & 0100 ? 0755 : 0644``), so a file executable by group or
        # other but not owner is 100644 to git. Testing any execute bit
        # called that 100755 and missed a 100755 -> 100644 change (peer
        # review). On a checkout with core.fileMode=false the bit is not
        # materialised and this comparison would be fail-open, so such a
        # checkout is refused above rather than compared (peer review, round
        # two); the release-file check does the same.
        snapshot = (snapshots or {}).get(path)
        if snapshot is None:
            # lstat, and a symlink refused outright. stat() follows one, so a
            # state file replaced by a link to a non-executable regular file
            # reported the target's category and compared equal to a 100644
            # base — a category change git records, synthesised away by the
            # read that was meant to observe it. With the index also holding
            # 120000 the comparison after this one agrees with the tree and
            # says nothing either, so on its own this function accepted a
            # state path that is no longer a file at all. Through the gate
            # the snapshot answers, and a link never gets this far.
            observed = (candidate.root / relative).lstat()
            if stat.S_ISLNK(observed.st_mode):
                raise AppendError(f"state file is a symlink: {path}")
            category = "100755" if observed.st_mode & 0o100 else "100644"
        else:
            category = snapshot.category
        if category != entry.mode:
            raise AppendError(f"state file mode changed relative to base: {path}")
        # After the comparison it qualifies, as in the release-history pass:
        # the candidate's own index is what says the working tree carries
        # the mode and type git recorded for this path, and a comparison
        # that passed fail-open is caught here rather than pre-empting the
        # mode-change refusal that existed before it. It is given the
        # category above rather than resolving the name again; without a
        # snapshot there is none to give, and the fallback lstat also
        # distinguishes a link, which the stat above cannot.
        try:
            assert_index_agrees_with_tree(
                candidate.root,
                relative,
                observed=None if snapshot is None else category,
            )
        except ReleaseChainError as exc:
            raise AppendError(str(exc)) from exc
        # And, last for this path, what the index records as its content. The
        # mode comparison above and the type comparison beside it say nothing
        # about bytes, and neither does anything else on this path: the ledger
        # and the frozen prefix were read from the working tree. A rewrite
        # staged and then restored on disk passed every one of them while the
        # commit under review carries a ledger no check here has read. The
        # bytes handed over are the snapshot's — the one read this verdict
        # made of this file — so the index is bound to what was verified
        # rather than to a second read. Without a snapshot there is no such
        # read to bind to, and a caller using this function on its own gets
        # exactly the comparisons it always did.
        if snapshot is not None:
            try:
                assert_index_content_bound(
                    candidate.root, base.commit, relative, snapshot.payload
                )
            except ReleaseChainError as exc:
                raise AppendError(str(exc)) from exc


def _release_triple(
    new_files: set[str],
    expected_index: int,
    *,
    candidate: _CandidateTree,
    allowed_support_files: set[str] | None = None,
) -> pathlib.Path:
    """Require exactly one manifest, producer signature, and two receipts."""

    manifest_files = [
        relative
        for relative in new_files
        if relative.startswith(candidate.spec.release_manifest_prefix)
        and MANIFEST_RE.fullmatch(pathlib.PurePosixPath(relative).name)
    ]
    if len(manifest_files) != 1:
        raise AppendError(
            f"release proposal must add exactly one manifest for index "
            f"{expected_index}; found {sorted(manifest_files)}"
        )
    manifest_relative = manifest_files[0]
    manifest_name = pathlib.PurePosixPath(manifest_relative).name
    match = MANIFEST_RE.fullmatch(manifest_name)
    assert match is not None
    if int(match.group("index")) != expected_index:
        raise AppendError(
            f"release proposal index must be {expected_index}, not "
            f"{int(match.group('index'))}"
        )
    stem = pathlib.PurePosixPath(manifest_name).stem
    expected = {
        manifest_relative,
        *(
            f"{candidate.spec.release_manifest_prefix}{stem}.{tsa}.tsr"
            for tsa in candidate.spec.chain.anchors
        ),
        f"{candidate.spec.release_manifest_prefix}{stem}.producer.sig",
    }
    allowed = expected | (allowed_support_files or set())
    if new_files != expected and not (expected <= new_files and new_files <= allowed):
        raise AppendError(
            "release proposal must add its manifest, producer signature, and "
            f"exactly the {' and '.join(candidate.spec.chain.anchors)} receipts "
            "with no other releases/ changes; "
            f"missing={sorted(expected - new_files)}, "
            f"extra={sorted(new_files - allowed)}"
        )
    return candidate.root / pathlib.PurePosixPath(manifest_relative)


def _base_ledger_bytes(commit: str, candidate: _CandidateTree) -> bytes:
    relative = candidate.ledger_path.relative_to(candidate.root).as_posix()
    return git_blob_bytes(
        candidate.root,
        git_file_entry(candidate.root, commit, relative),
    )


def _check_exact_byte_append(base_bytes: bytes, candidate_bytes: bytes) -> bytes:
    if not candidate_bytes.startswith(base_bytes):
        raise AppendError(
            "change is not an exact byte append to the base JSONL; existing "
            "bytes, including line endings, are immutable"
        )
    return candidate_bytes[len(base_bytes) :]


def _state_snapshot_bytes(
    candidate: _CandidateTree, ledger_bytes: bytes, prefix_bytes: bytes
) -> dict[str, bytes]:
    """The two state snapshots, keyed the way ``release_chain`` reads them.

    The release verification used to open the ledger and the frozen prefix
    by name, which is a second read of each file inside one verdict: an
    A-to-B-to-A replacement showed the row checks one ledger, the release
    chain another, and put the first back before the closing re-read. Handing
    it these bytes means there is only ever one read of each file per run.
    """

    return {
        candidate.spec.chain.state_relative.as_posix(): ledger_bytes,
        candidate.spec.chain.prefix_relative.as_posix(): prefix_bytes,
    }


def _bind_new_release_files(
    base: _BaseCommit,
    candidate: _CandidateTree,
    new_files: set[str],
    verification: ChainVerification,
) -> None:
    """Bind the index to the release files this proposal adds and just verified.

    The release verification is the comparison for a new release file: the
    manifest's bytes are canonical, hash to their own filename, and are what
    the producer signature and both RFC 3161 receipts are over. All of it is
    read from the working tree. Staging different bytes under the same name and
    restoring the verified ones on disk left every one of those checks passing
    over content the commit under review does not carry — and a new file has no
    base entry, so the base comparison the release-history pass makes for an
    existing one does not exist here either.

    The manifest is bound to the bytes the verification itself parsed, which
    the result carries. The producer signature and the receipts are read here:
    the signature's bytes are consumed inside the verification and not
    returned, and a receipt is never read into this process at all — OpenSSL
    opens it by pathname, twice. So for those three what this binds is the
    content of one read made here, after the verification, and the window
    between that read and OpenSSL's is the same read-versus-use residual the
    module docstring states for the working tree as a whole.
    """

    verified: dict[str, bytes] = {}
    for record in verification.releases:
        try:
            listed = record.path.relative_to(candidate.root).as_posix()
        except ValueError:  # pragma: no cover - the walk refuses an outside root
            continue
        verified[listed] = record.raw
    for relative in sorted(new_files):
        payload = verified.get(relative)
        if payload is None:
            try:
                payload = (
                    candidate.root / pathlib.PurePosixPath(relative)
                ).read_bytes()
            except OSError as exc:
                raise AppendError(
                    "cannot re-read the release file this verdict verified: "
                    f"{relative}"
                ) from exc
        try:
            assert_index_content_bound(candidate.root, base.commit, relative, payload)
        except ReleaseChainError as exc:
            raise AppendError(str(exc)) from exc


def _hold_release_root(candidate: _CandidateTree) -> int | None:
    """Walk the release root's paths, then hold the directory they name open.

    Before anything reads through the release root, on both proposal paths: a
    root reached through a symlinked component, or under a spelling the
    candidate tree does not hold, is not this proposal's release root, and
    every comparison below would be about whatever it points at. The leaf case
    is the enumeration's own refusal, in its words, so a symlinked ``releases``
    the enumeration would itself have met is answered here exactly as it always
    was; the one it would not have met — a dangling link — is pre-empted, which
    the module docstring names.

    The descriptor is what lets the caller ask again at the end whether the
    directory it read through is the one the walk approved; see
    ``release_chain.hold_release_root``.
    """

    try:
        return hold_release_root(
            candidate.root,
            candidate.spec.chain,
            root_descriptor=candidate.root_descriptor,
        )
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc


def _assert_release_root_unchanged(
    candidate: _CandidateTree, held: int | None
) -> None:
    """Re-walk the release root's paths and re-check the held directory.

    After every read this proposal path makes through that root and before the
    verdict is returned, for the reason ``_assert_root_unchanged`` runs before
    the gate-only exit: the walk was a pathname preflight, and everything after
    it resolved the name again.
    """

    try:
        assert_release_root_unchanged(candidate.root, candidate.spec.chain, held)
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc


def check_release_proposal(
    base: _BaseCommit,
    *,
    candidate: _CandidateTree,
    ledger_bytes: bytes,
    prefix_bytes: bytes,
    anchor_dir: pathlib.Path | None = None,
    enforce_production_pins: bool | None = None,
) -> int | None:
    """Verify the base chain and the one allowed candidate transition.

    A pre-genesis base keeps legacy append proposals valid only while they do
    not touch ``releases/``.  Genesis may add the prescribed anchors and README
    alongside its exact manifest/signature/receipt bundle.  Once genesis exists,
    all base release files are byte- and mode-immutable and a ledger byte
    append must carry exactly one next release bundle.

    The release root is walked and held open around all of it, and re-checked
    once every read through it has returned. The reads themselves are by
    pathname, so what that establishes is that the root was the walked
    directory at those two instants; the residual is stated on
    ``release_chain.hold_release_root``.
    """

    held = _hold_release_root(candidate)
    try:
        result = _check_release_proposal(
            base,
            candidate=candidate,
            ledger_bytes=ledger_bytes,
            prefix_bytes=prefix_bytes,
            anchor_dir=anchor_dir,
            enforce_production_pins=enforce_production_pins,
        )
        _assert_release_root_unchanged(candidate, held)
        return result
    finally:
        if held is not None:
            os.close(held)


def _check_release_proposal(
    base: _BaseCommit,
    *,
    candidate: _CandidateTree,
    ledger_bytes: bytes,
    prefix_bytes: bytes,
    anchor_dir: pathlib.Path | None,
    enforce_production_pins: bool | None,
) -> int | None:
    """One proposal verified through a release root already walked and held."""

    try:
        commit, new_files, base_release_entries = verify_release_history_immutable(
            candidate.root,
            base.commit,
            spec=candidate.spec.chain,
        )
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc

    base_has_chain = any(
        relative.startswith(candidate.spec.release_manifest_prefix)
        for relative in base_release_entries
    )
    candidate_has_chain = (
        any(
            path.is_file()
            for path in (candidate.root / candidate.spec.chain.manifest_relative).glob(
                "*.json"
            )
        )
        if (candidate.root / candidate.spec.chain.manifest_relative).is_dir()
        else False
    )
    state_bytes = _state_snapshot_bytes(candidate, ledger_bytes, prefix_bytes)
    base_bytes = _base_ledger_bytes(commit, candidate)
    # The ledger this verdict speaks for is the one snapshot the run read, not
    # whatever the path holds by the time this check gets to it.
    appended_bytes = _check_exact_byte_append(base_bytes, ledger_bytes)
    ledger_changed = bool(appended_bytes)
    if enforce_production_pins is None:
        enforce_production_pins = anchor_dir is None

    if not base_has_chain:
        if not candidate_has_chain:
            if new_files:
                raise AppendError(
                    "legacy pre-genesis proposal must not change releases/; "
                    "add a complete genesis manifest, producer signature, and "
                    "both receipts or no release files at all "
                    f"(changed={sorted(new_files)})"
                )
            return None
        _release_triple(
            new_files,
            0,
            candidate=candidate,
            allowed_support_files=set(candidate.spec.genesis_support_files),
        )
        try:
            verification = verify_release_chain(
                candidate.root,
                spec=candidate.spec.chain,
                anchor_dir=anchor_dir,
                require_chain=True,
                verify_state=True,
                enforce_production_pins=enforce_production_pins,
                state_bytes=state_bytes,
            )
        except ReleaseChainError as exc:
            raise AppendError(str(exc)) from exc
        if len(verification.releases) != 1:
            raise AppendError(
                "genesis proposal must create exactly one release at index 0"
            )
        _bind_new_release_files(base, candidate, new_files, verification)
        return 0

    try:
        base_verification = verify_base_release_chain(
            candidate.root,
            commit,
            base_release_entries,
            spec=candidate.spec.chain,
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
        candidate_verification = verify_release_chain(
            candidate.root,
            spec=candidate.spec.chain,
            anchor_dir=anchor_dir,
            require_chain=True,
            verify_state=True,
            enforce_production_pins=enforce_production_pins,
            state_bytes=state_bytes,
        )
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc
    expected_length = len(base_verification.releases) + (1 if ledger_changed else 0)
    if len(candidate_verification.releases) != expected_length:
        raise AppendError(
            f"release chain length must be {expected_length} for this proposal; "
            f"found {len(candidate_verification.releases)}"
        )
    _bind_new_release_files(base, candidate, new_files, candidate_verification)
    return candidate_verification.head.release_index


def check_release_chain_without_base(
    *,
    candidate: _CandidateTree,
    ledger_bytes: bytes,
    prefix_bytes: bytes,
    anchor_dir: pathlib.Path | None = None,
    enforce_production_pins: bool | None = None,
) -> int | None:
    """On push, verify any initialized chain against working-tree state.

    The push path re-opened the two state files here exactly as the base-ref
    path did, so it is fed the same snapshots for the same reason: one read
    of each state file per verdict. It also runs the release root's index
    scan, which the base-ref path runs in the release-history pass; a tree
    with no chain returns here without one otherwise.

    This is the path the release root's walk was weakest on, because it is the
    path with no base comparison at all: ``initialized`` is
    ``manifest_directory.is_dir()``, which resolves the whole name again, and
    the index scan that follows returns when no entry names the root. So the
    walked root is held open across the chain verification and that scan, and
    re-checked before the verdict returns.

    It is also the path on which that question decides whether anything is
    read at all, so what the manifest path *is* is decided before it is asked:
    a tracked blob, an empty link or a dangling link there all answer
    ``initialized`` false, which is this path's word for "no chain", and the
    enumeration that refuses such a path never runs. See
    ``release_chain.assert_manifest_directory_regular``.
    """

    held = _hold_release_root(candidate)
    try:
        result = _check_release_chain_without_base(
            candidate=candidate,
            ledger_bytes=ledger_bytes,
            prefix_bytes=prefix_bytes,
            anchor_dir=anchor_dir,
            enforce_production_pins=enforce_production_pins,
        )
        _assert_release_root_unchanged(candidate, held)
        return result
    finally:
        if held is not None:
            os.close(held)


def _check_release_chain_without_base(
    *,
    candidate: _CandidateTree,
    ledger_bytes: bytes,
    prefix_bytes: bytes,
    anchor_dir: pathlib.Path | None,
    enforce_production_pins: bool | None,
) -> int | None:
    """One push-path verdict through a release root already walked and held."""

    manifest_directory = candidate.root / candidate.spec.chain.manifest_relative
    # What that path *is* decides whether this run has a chain to verify, so it
    # is decided before that question is asked. ``is_dir()`` is false for a
    # tracked blob standing where the manifest directory was, for an empty
    # untracked link, and for a dangling one, and each of those made
    # ``initialized`` false — "this tree has no chain" — for a tree whose chain
    # the commit under review may well still carry. The walk above stops one
    # component short of this leaf and the root's index scan reconciles the
    # blob with the regular file the traversal finds, so nothing else here
    # says it. Refused in ``_enumerate_manifest_files``'s own words, which is
    # what a tree whose manifest path is a link to a populated directory has
    # always been refused with; the enumeration is the only thing that would
    # have spoken for the other two, and only if it ran.
    try:
        release_chain.assert_manifest_directory_regular(
            candidate.root, candidate.spec.chain
        )
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc
    initialized = manifest_directory.is_dir() and any(manifest_directory.iterdir())
    verification = None
    if initialized:
        if enforce_production_pins is None:
            enforce_production_pins = anchor_dir is None
        try:
            verification = verify_release_chain(
                candidate.root,
                spec=candidate.spec.chain,
                anchor_dir=anchor_dir,
                require_chain=True,
                verify_state=True,
                enforce_production_pins=enforce_production_pins,
                state_bytes=_state_snapshot_bytes(
                    candidate, ledger_bytes, prefix_bytes
                ),
            )
        except ReleaseChainError as exc:
            raise AppendError(str(exc)) from exc
    # The release root's index entries, which no enumeration on this path can
    # see: an empty or uninitialised gitlink under releases/ is in no
    # filesystem walk, and the push path runs none of the base-tree
    # comparisons that would meet it. It runs after the chain verification,
    # so every refusal that path already gave still comes first, and before
    # the early return, so a tree with no chain at all is covered too.
    try:
        assert_release_root_index_regular(candidate.root, candidate.spec.chain)
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc
    if verification is None:
        return None
    assert verification.head is not None
    return verification.head.release_index


def verify_append_gate(
    root: pathlib.Path,
    *,
    spec: AppendGateSpec,
    base_ref: str | None = None,
    trusted_code_root: pathlib.Path = CODE_ROOT,
    release_anchor_dir: pathlib.Path | None = None,
) -> str:
    """Verify one candidate tree and return the baseline CLI's success text.

    The library owns no stdout or stderr. ``AppendError`` retains the baseline
    exception text; a CLI adapter may add the original
    ``thesis-facts append check failed: `` prefix when rendering a refusal.
    ``trusted_code_root`` preserves the upstream split between code-owned trust
    anchors and candidate-controlled ledger/release data.

    The candidate root is selected and opened here and held open until the
    verdict is finished, which is what every comparison against its recorded
    identity relies on; see ``_set_root``.
    """

    candidate = _set_root(root, spec)
    try:
        return _verify_selected_tree(
            candidate,
            base_ref=base_ref,
            trusted_code_root=trusted_code_root,
            release_anchor_dir=release_anchor_dir,
        )
    finally:
        # The root descriptor ``_set_root`` opened, and every comparison
        # inside answered from. It is held for exactly the run it speaks for
        # and closed once, however that run ends; the dataclass is frozen, so
        # it is closed by field.
        os.close(candidate.root_descriptor)


def _verify_selected_tree(
    candidate: _CandidateTree,
    *,
    base_ref: str | None,
    trusted_code_root: pathlib.Path,
    release_anchor_dir: pathlib.Path | None,
) -> str:
    """One verdict about one already-selected candidate tree.

    Split out of ``verify_append_gate`` for one reason: the candidate root is
    held open for the whole of a verdict, and this is the whole of a verdict,
    so the descriptor has exactly one place to be closed and no exit from here
    can skip it.
    """

    spec = candidate.spec
    # One resolution for the whole verdict: the base was resolved by name at
    # the surface check, again at the append-only diff and the frozen prefix,
    # and again at the release history, so a branch that moved during the run
    # was read at different commits inside a single answer.
    base = (
        _BaseCommit(
            ref=base_ref, commit=_resolve_base_commit(base_ref, candidate)
        )
        if base_ref
        else None
    )
    # Every mode and type this run compares is read from the working tree, so
    # a checkout that does not carry them cannot be verified at all — on the
    # push path as much as against a base. The guard used to be reachable only
    # through the base-ref path (the release history, then check_state_modes),
    # which left a git 120000 state entry materialised as a plain file holding
    # its target text to pass the component walk and both state reads on a
    # push. It runs here, once, for both paths: after the base ref is
    # resolved, so a false setting cannot mask an invalid ref, and before any
    # state file is read.
    try:
        assert_file_modes_authoritative(candidate.root)
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc
    # And beside it, about the same checkout and for the same reason: whether
    # git will look at the working tree at all. The surface classification
    # below is ``git diff`` plus ``git ls-files --others``, and four settings
    # turn either into a cache — a file-system monitor whose "unchanged" git
    # trusts, a stat comparison with the change time or all but size dropped,
    # a cached untracked listing. Under any of them a ledger rewritten beside
    # a gate file classifies gate-only and is never read. Checkout-level, so
    # it stands where the modes guard stands and shares its exception.
    try:
        assert_working_tree_classification_authoritative(candidate.root)
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc
    # And the two state files must be files git is tracking here, with no
    # gitlink standing over them. Nothing checked either. A 160000 entry at
    # ``ledger`` is a submodule boundary whose contents belong to another
    # repository, and it delivers perfectly regular files that hash, parse,
    # and satisfy every byte comparison below while being no part of this
    # commit; an untracked state file is the same fact without the gitlink.
    # Like the checkout guard, this says a comparison cannot be made rather
    # than making one, so it runs before the checks that would make it — the
    # second of the three places a refusal added after the extraction precedes
    # a pre-existing one (the third is _assert_root_unchanged just below),
    # stated in the module docstring and pinned by a test.
    for relative in (spec.chain.state_relative, spec.chain.prefix_relative):
        try:
            assert_state_path_tracked(candidate.root, relative)
        except ReleaseChainError as exc:
            raise AppendError(str(exc)) from exc
    # And beside it, saying the same kind of thing: every reconciliation
    # between the index and the working tree below is by exact spelling, which
    # is what makes it a comparison, and each is blind to an entry spelled as
    # another spelling of the path it is about. On a filesystem that folds
    # names, such an entry is a second committed object resolving to the same
    # file — under no protected path by name, so nothing reads it, while the
    # commit carries it. Which of the two the one file answers for is not
    # decidable from the index or the tree, so this refuses rather than
    # comparing, and runs here for that reason: it shares the tracked-state
    # exception rather than adding a fourth. It reads the whole index, which
    # is the only read here that no pathspec can express.
    try:
        assert_index_carries_no_protected_alias(candidate.root, spec.chain)
    except ReleaseChainError as exc:
        raise AppendError(str(exc)) from exc
    if base is not None:
        # Before the classification that decides which path this run takes,
        # and again before a gate-only verdict is returned: everything above
        # reached the candidate tree by name, and only a state read ever
        # compares the root against what _set_root recorded — which a
        # gate-only proposal never performs.
        _assert_root_unchanged(candidate)
        tree_data, tree_gate, tree_unclassified = check_surface_separation(
            base,
            candidate,
        )
        # The working tree's diff against the base is what a proposal's files
        # look like; the index is the commit under review, and the two can
        # disagree. A ledger staged as executable, a release file staged and
        # then restored on disk, a release file dropped from the index while
        # its bytes stayed put: each is a change this commit records that the
        # working-tree diff cannot see, and each rode a gate-only acceptance
        # with the ledger, the prefix, the release history, and every mode
        # and index check unread. So the index's own changed set is
        # classified too, and the union decides, by the rule the working-tree
        # set was already held to: both surfaces in it is a mixed proposal,
        # refused in the words check_surface_separation uses (that check
        # fired first, in those words, when the working tree alone was
        # mixed); GATE alone is gate-only, confined over the union's
        # unclassified remainder and naming every GATE path the commit or the
        # tree carries; neither is the data path below, where the state,
        # mode, and index checks answer for whatever the index staged.
        staged_data, staged_gate, staged_unclassified = _staged_surface_changes(
            base, candidate
        )
        data_changes = tree_data | staged_data
        gate_changes = tree_gate | staged_gate
        if data_changes and gate_changes:
            raise AppendError(
                "mixed data/gate proposal is forbidden: DATA_SURFACE changes="
                f"{sorted(data_changes)}; GATE_SURFACE changes="
                f"{sorted(gate_changes)}; split them into separate pull requests"
            )
        if gate_changes:
            reported = check_gate_only_confinement(
                tree_unclassified | staged_unclassified, candidate
            )
            unclassified_suffix = (
                f"; unclassified changes={sorted(reported)}" if reported else ""
            )
            # The same rule as the data path below: a base named by something
            # that can move is quoted with the commit it resolved to, and a
            # base named by its OID keeps the text the harness pins. This
            # acceptance path returned before that suffix existed, so a
            # gate-only verdict against a branch named no snapshot (peer
            # review).
            base_suffix = (
                f"; base {base.ref} ({base.commit})"
                if base.ref != base.commit
                else ""
            )
            # The verdict is about the tree this run selected, so say so
            # last: nothing below the classification reads the filesystem
            # again, and without this the gate-only branch is the one exit
            # that never asks whether the root is still the recorded one.
            _assert_root_unchanged(candidate)
            return (
                "thesis-facts append check OK: gate-only proposal; "
                "DATA_SURFACE unchanged; GATE_SURFACE changes="
                f"{sorted(gate_changes)}{unclassified_suffix}{base_suffix}"
            )

    # One read of each state file, with its identity recorded, feeding every
    # consumer below: the path was walked and then opened separately, and the
    # ledger was opened again by the release verification, so a swap between
    # any two of those reads produced a verdict about no single file.
    ledger_state = _read_state_snapshot(spec.chain.state_relative, candidate)
    text = _as_text(ledger_state.payload, "utf-8")
    reject_non_append_bytes(text)
    lines = _lines(text)
    # Read where check_prefix used to walk and read it, so a proposal that
    # violates both this and an earlier rule keeps the earlier refusal.
    prefix_state = _read_state_snapshot(spec.chain.prefix_relative, candidate)
    prefix = check_prefix(lines, _as_text(prefix_state.payload), candidate)
    # The post-cutover binding boundary is the BASE prefix count under a
    # base ref, so a PR cannot grandfather an unbound append by growing the
    # candidate manifest over it. Without a base ref (push) there is nothing
    # to anchor against, so the candidate manifest is trusted for the
    # full-file invariants only — base-anchoring requires the PR path.
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
    # On the PR path, the trusted code root is the detached base checkout.
    # Production verification must use those immutable anchors and the base
    # verifier's pins, never files supplied by the candidate worktree. The
    # hidden test override remains unpinned and continues to use generated
    # test anchors.
    production_pins = release_anchor_dir is None
    anchor_dir = release_anchor_dir or (trusted_code_root / spec.chain.anchor_relative)
    release_index = (
        check_release_proposal(
            base,
            candidate=candidate,
            ledger_bytes=ledger_state.payload,
            prefix_bytes=prefix_state.payload,
            anchor_dir=anchor_dir,
            enforce_production_pins=production_pins,
        )
        if base is not None
        else check_release_chain_without_base(
            candidate=candidate,
            ledger_bytes=ledger_state.payload,
            prefix_bytes=prefix_state.payload,
            anchor_dir=anchor_dir,
            enforce_production_pins=production_pins,
        )
    )
    # Both of these are new since the extraction, so they run after every
    # check that existed before them: the row checks, the release proposal,
    # and the release history. Peer review caught each earlier placement.
    check_binding_shapes(lines, binding_boundary)
    snapshots = {
        snapshot.relative.as_posix(): snapshot
        for snapshot in (ledger_state, prefix_state)
    }
    if base is not None:
        check_state_modes(base, candidate, snapshots=snapshots)
    else:
        # The push path has no base to compare a mode against, so
        # check_state_modes does not run and nothing on this path asked
        # whether the working tree carries what git recorded for the two
        # state files — a 120000 entry materialised as a plain file, or an
        # executable bit the filesystem dropped, went unnoticed. The index
        # answers that without a base. It runs here, in the position
        # check_state_modes occupies on the other path and for the same
        # reason: after every check that existed before it.
        # Given the category this run's own read recorded, for the reason
        # check_state_modes is: the path is not resolved again here.
        for snapshot in (ledger_state, prefix_state):
            try:
                assert_index_agrees_with_tree(
                    candidate.root, snapshot.relative, observed=snapshot.category
                )
            except ReleaseChainError as exc:
                raise AppendError(str(exc)) from exc
    # Last of all, and after the release verification's own re-reads: the two
    # state files must still be the files this verdict read. Forwards and
    # then backwards, so a rewrite aimed at the gap after one file's re-check
    # is seen by that file's second one; the residual window this leaves is
    # stated on _assert_states_unchanged and in the module docstring.
    _assert_states_unchanged((ledger_state, prefix_state), candidate)
    # Name the commit the verdict was measured against whenever the caller
    # named something that could move. A base given as its own OID already
    # names it, and that verdict text stays exactly what it was — the shape
    # the differential harness compares against its oracle byte for byte.
    resolved = (
        f" {base.ref} ({base.commit})"
        if base is not None and base.ref != base.commit
        else ""
    )
    suffix = (
        f", +{appended} appended vs base{resolved}" if appended is not None else ""
    )
    release_suffix = f", release {release_index}" if release_index is not None else ""
    return (
        f"thesis-facts append check OK: {len(lines)} rows, immutable prefix "
        f"{prefix['prefixLineCount']}{suffix}{release_suffix}"
    )
