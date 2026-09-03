"""Confinement the upstream append gate never had, on a local fixture.

tests/test_append_gate_equivalence.py proves the port reproduces its oracle's
verdicts on the pinned production tree. This module covers what that battery
never presents: proposals that stay inside the classified surfaces the gate
speaks for, state paths that stay inside the candidate tree, one base commit
for the whole verdict, one snapshot of each state file, and a checkout whose
modes and types are what git recorded. Every case here is a NEW refusal (or a
previously silent acceptance made explicit), so the differential gate is
untouched. The state-path cases reach the shared reader in
receipt.release_chain, so they are exercised here directly as well.

Docstrings below labelled F1-F5 name the findings of the fourth review round,
in that review's numbering: F1 the checkout guard the push path never reached,
F2 the checkout settings that are a claim rather than evidence, F3 the
check-then-open state reads, F4 the git reads a replacement object could
redirect, F5 the guard that ran before the base ref was resolved.

Docstrings labelled R5-F1 to R5-F4 name the fifth round, whose numbering
starts over: R5-F1 the snapshots the release verification was not given,
R5-F2 the parent confinement that was still check-then-open, R5-F3 the state
paths taken on the working tree's word rather than the index's, R5-F4 the
release-root index entries the filesystem traversal cannot see.

Docstrings labelled R6-F1 onward name the third gate's first round, whose
numbering starts over again: R6-F1 the release-root index entries never
reconciled with the filesystem, R6-F2 the closing state checks a writer could
step between, R6-F3 the state file's mode and parents resolved again after
the read that established them, R6-F4 the descent that fell back to a
pathname open and the root nothing vouched for.

Docstrings labelled R7-F1 onward name that gate's second round, numbering
from one again: R7-F1 the base release file removed from the candidate index
alone, R7-F3 the gate-only classification that could not see what the index
records, R7-F4 the indexed release path answered for through a symlinked
component, R7-F5 the state mode read that followed a link where there was no
snapshot to take, R7-F6 the index reads that passed a path to git as a
pattern. That round's R7-F2 — the writer that can rewrite a state file after
its last re-read — is the stated residual: it wants an immutable snapshot of
the tree under audit, which this gate does not have, and it is tracked as
follow-up rather than bound by a test here.

Docstrings labelled S4-F1 onward name a fourth gate's first round, numbering
from one again: S4-F1 the recorded root identity a gate-only verdict never
consulted, S4-F2 the release-root reconciliation a case- or
normalisation-insensitive filesystem answered for the wrong entry, S4-F3 the
intent-to-add index entry that records no content, S4-F4 the ambient pathspec
mode that rewrote what every index read asked for, S4-F5 the descent that
demanded read permission on directories it only ever traversed, S4-F6 the
platform restriction documented as the gate's when it is the package's. S4-F6
is bound in tests/test_release_chain.py, where the public custody path and
``receipt verify`` itself are driven.

Docstrings labelled S4R2-F1 onward name that fourth gate's second round,
numbering from one again: S4R2-F1 the release root reached through a
symlinked component, S4R2-F2 the protected path an index entry could spell
another way (F2a) or the working tree could spell another way (F2b), S4R2-F3
the root identity that was two numbers a filesystem may hand to another
directory, S4R2-F4 the configured path handed to ``git ls-tree`` as a
pathspec rather than as a name.

Docstrings labelled S4R3-F1 onward name that fourth gate's third round,
numbering from one again: S4R3-F1 the index blob no check bound to the bytes a
verdict read, S4R3-F2 the assume-unchanged and skip-worktree entries that hide
a working-tree rewrite from ``git diff``, S4R3-F3 the release root re-resolved
after its own walk had passed, S4R3-F4 the configured paths below that root
whose intermediate components nothing walked, S4R3-F5 the spelling check that
failed open where a directory could not be listed.

Docstrings labelled S4R4-F3 onward name that fourth gate's fourth round,
whose numbering starts over again: S4R4-F3 the manifest path whose type
decided there was no chain to verify, S4R4-F5 the checkout settings that make
git's changed set a cache rather than a comparison, S4R4-F6 the alias scan
that compared only at a protected path's own depth, S4R4-F7 the spelling
check that still failed open for a directory it could not be shown to fold,
S4R4-F8 the release path spelled as the candidate root itself. That round's
F1, F2 and F4 are one statement about what this gate verifies — the working
tree as read, per protected path, rather than one commit's tree — which is
stated in ``append_gate``'s module docstring under "What this verdict speaks
for" and tracked as #43 rather than bound by a test here.

Docstrings labelled S5-F1 onward name a fifth gate's first round, numbering
from one again: S5-F1 the ignored files the surface classification's untracked
listing excludes, S5-F2 the caching settings this verifier read and believed
rather than overriding on the reads they decide, S5-F3 the configured leaf
under the release root whose spelling no walk bound, S5-F4 the
classification-only refusal a push verification was held to.

Docstrings labelled S5-R2-F1 onward name that fifth gate's second round,
numbering from one again: S5-R2-F1 the untracked and ignored listings that
took git's exit status for a complete enumeration.

The fixture is a local git repository built from scratch, and no network is
used anywhere here. Most of it holds a README and no manifests, so the gate's
chain verification finds nothing to verify and the checks under test are the
ones that run before it. The cases that need a chain — the ones about what a
verdict reads through the release root, and about the release files a proposal
adds — build a real one offline: two locally generated timestamp authorities
and a generated producer key, from ``corpus_fixture``, over exactly this
fixture's own state bytes.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass, replace
from typing import Any

import pytest

from receipt import append_gate, release_chain
from receipt.append_gate import (
    AppendError,
    AppendGateSpec,
    expected_assertion_version_id,
    verify_append_gate,
)
from receipt.canonical import canonical_bytes
from receipt.release_chain import (
    AnchorSpec,
    ChainSpec,
    ReleaseChainError,
    _regular_file_bytes,
)
from receipt.sign import generate_signing_keypair, sign_payload

from corpus_fixture import LocalTsa, build_local_tsa, created_at

# The fixture repository carries no release manifests, so no anchor identity
# below is ever consumed: these tests exercise the gate's path up to and
# including the ledger and release-history checks, never a signature or an
# RFC 3161 receipt. The layout mirrors the pinned consumer's so the surface
# patterns under test are the real ones.
CHAIN_SPEC = ChainSpec(
    manifest_relative=pathlib.PurePosixPath("releases/manifests"),
    state_relative=pathlib.PurePosixPath("ledger/official_observations.jsonl"),
    prefix_relative=pathlib.PurePosixPath("ledger/immutable_prefix.json"),
    anchor_relative=pathlib.PurePosixPath("releases/anchors"),
    release_root_relative=pathlib.PurePosixPath("releases"),
    schema_version="receipt_fixture_release_v1",
    producer_public_key_filename="producer-ed25519.pub",
    producer_spki_sha256="0" * 64,
    anchors={
        "alpha": AnchorSpec(
            filename="alpha-root.pem",
            pem_sha256="1" * 64,
            policy_oid="1.2.3.4.1",
            signer_certificate_sha256="2" * 64,
            signer_spki_sha256="3" * 64,
        ),
        "beta": AnchorSpec(
            filename="beta-root.pem",
            pem_sha256="4" * 64,
            policy_oid="1.2.3.4.2",
            signer_certificate_sha256="5" * 64,
            signer_spki_sha256="6" * 64,
        ),
    },
)

GATE_SPEC = AppendGateSpec(
    chain=CHAIN_SPEC,
    prefix_schema_version="receipt_fixture_immutable_prefix_v1",
    release_manifest_prefix="releases/manifests/",
    genesis_support_files=frozenset({"releases/README.md"}),
    gate_surface=frozenset(
        {
            "scripts/check_append.py",
            "releases/anchors/**",
        }
    ),
    data_surface=frozenset(
        {
            "ledger/**",
            "releases/manifests/**",
        }
    ),
    assertion_content_keys=(
        "source_record_id",
        "value",
        "observed_at",
        "period",
        "geography",
        "entity",
        "aggregation",
        "filters",
        "domain",
    ),
)

PREFIX_LINE_COUNT = 1
BASE_ROW_COUNT = 2
GATE_FILE = "scripts/check_append.py"


def a_folded_spelling(parent: pathlib.Path, spelled: str) -> bool:
    """Whether ``spelled`` resolves under ``parent`` without being listed there.

    The condition ``release_chain._assert_component_spelled`` gives its
    misspelling refusal for, asked of the fixture that was actually built
    rather than of the filesystem in the abstract. (Its other refusal, for a
    directory that cannot be listed at all, needs no such probe: it holds on
    every filesystem.) A probe of the filesystem's *lookup* does not predict it:
    a rename to a folded-equal name need not change the stored spelling, so a
    filesystem that resolves ``Releases`` for ``releases`` can still leave the
    directory spelled exactly as the spec names it, and then there is no case.
    Where names are compared exactly there is never one — a name that resolves
    is a name its directory lists — which is what the branches below say.
    """

    try:
        listed = os.listdir(parent)
    except OSError:
        return False
    if spelled in listed:
        return False
    try:
        os.lstat(parent / spelled)
    except OSError:
        return False
    return True


@dataclass(frozen=True)
class Candidate:
    """One fixture repository and the commit its proposal is measured against."""

    root: pathlib.Path
    base: str


def observation_row(number: int, **overrides: Any) -> dict[str, Any]:
    """One post-cutover ledger row, self-consistent by construction.

    ``assertionVersion.id`` is recomputed from the finished row, so a test
    that malforms a binding value still gets past the content-address check
    and binds the branch it is aimed at.
    """

    row: dict[str, Any] = {
        "source_record_id": f"fixture.series.observation_{number}",
        "value": float(number),
        "observed_at": "2026-07-01",
        "period": "2026-06",
        "geography": "US",
        "entity": "national",
        "aggregation": "level",
        "filters": {},
        "domain": "fixture",
        "measure": {
            "concept": "fixture.concept",
            "unit": "percent",
            "source_concept": "FIXTURE",
            "concept_relation": "exact",
            "concept_authority": "fixture",
            "legal_vintage": "2026",
        },
        "source": {
            "source_name": "fixture",
            "source_table": "t1",
            "source_file": "t1.csv",
            "url": "https://example.invalid/t1.csv",
            "vintage": "2026-07",
            "source_sha256": hashlib.sha256(f"source-{number}".encode()).hexdigest(),
        },
        "source_row_keys": ["row", str(number)],
        "source_cell_keys": ["cell", str(number)],
        "retrievedAt": "2026-07-10T20:38:58Z",
        "sourceVintage": "2026-07",
        "ledgerRepoSha": hashlib.sha256(f"repo-{number}".encode()).hexdigest()[:40],
        "responseArchive": {
            "sha256": hashlib.sha256(f"response-{number}".encode()).hexdigest()
        },
    }
    row.update(overrides)
    row["assertionVersion"] = {"id": expected_assertion_version_id(row, GATE_SPEC)}
    return row


def jsonl_line(row: dict[str, Any]) -> str:
    return json.dumps(row, ensure_ascii=False, separators=(",", ":"))


def write_ledger(root: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path = root / CHAIN_SPEC.state_relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(f"{jsonl_line(row)}\n" for row in rows),
        encoding="utf-8",
    )


def write_prefix_manifest(root: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    lines = [jsonl_line(row) for row in rows[:PREFIX_LINE_COUNT]]
    manifest = {
        "schemaVersion": GATE_SPEC.prefix_schema_version,
        "prefixLineCount": PREFIX_LINE_COUNT,
        "lineSha256s": [
            hashlib.sha256(line.encode("utf-8")).hexdigest() for line in lines
        ],
        "prefixSha256": hashlib.sha256(
            ("\n".join(lines) + "\n").encode("utf-8")
        ).hexdigest(),
    }
    path = root / CHAIN_SPEC.prefix_relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def git(root: pathlib.Path, *arguments: str, stdin: str | None = None) -> str:
    """Run fixture git commands with ambient user configuration isolated."""

    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        input=stdin,
    )
    return completed.stdout.strip()


def _index_paths(root: pathlib.Path, pathspec: str) -> list[str]:
    """The paths ``_index_entries`` returns for one pathspec, in its order."""

    return [record.path for record in release_chain._index_entries(root, pathspec)]


def spec_with_release_root(release_root: str) -> AppendGateSpec:
    """The fixture spec with its release directory named some other way.

    Every configured path under the root moves with it, so the layout is the
    fixture's own and the only thing under test is the name — which is what a
    consumer pins in its committed code and what this package hands to git.
    """

    chain = replace(
        CHAIN_SPEC,
        release_root_relative=pathlib.PurePosixPath(release_root),
        manifest_relative=pathlib.PurePosixPath(f"{release_root}/manifests"),
        anchor_relative=pathlib.PurePosixPath(f"{release_root}/anchors"),
    )
    return replace(
        GATE_SPEC,
        chain=chain,
        release_manifest_prefix=f"{release_root}/manifests/",
        genesis_support_files=frozenset({f"{release_root}/README.md"}),
        gate_surface=frozenset({GATE_FILE, f"{release_root}/anchors/**"}),
        data_surface=frozenset({"ledger/**", f"{release_root}/manifests/**"}),
    )


def base_repository(
    tmp_path: pathlib.Path, release_root: str = "releases"
) -> Candidate:
    """A committed base: two ledger rows, a frozen prefix, a release README.

    ``release_root`` names the release directory this tree is built with, for
    the cases that pair it with ``spec_with_release_root``; the default is the
    one ``CHAIN_SPEC`` carries and every other test below takes it.
    """

    root = tmp_path / "candidate"
    root.mkdir()
    rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 1)]
    write_ledger(root, rows)
    write_prefix_manifest(root, rows)
    releases = root / release_root
    releases.mkdir(parents=True)
    (releases / "README.md").write_text(
        "Release journal for the fixture ledger.\n", encoding="utf-8"
    )
    git(root, "init", "--quiet")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "config", "user.name", "Append Gate Fixture")
    git(root, "add", "-A")
    git(root, "commit", "--quiet", "-m", "base ledger")
    return Candidate(root=root, base=git(root, "rev-parse", "HEAD"))


def append_one_row(candidate: Candidate, **overrides: Any) -> None:
    """The ordinary data proposal: one more row in the working tree."""

    rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 1)]
    rows.append(observation_row(BASE_ROW_COUNT + 1, **overrides))
    write_ledger(candidate.root, rows)


def stage(candidate: Candidate) -> None:
    """Record the working tree in the candidate's index, as a proposal does.

    A pull request is reviewed from a checkout whose index git wrote from the
    commit under review, so a mode the proposal changed is in the index too. A
    test that only chmods the working tree leaves the index disagreeing with
    it, which is now refused in its own words before any base comparison, so
    every mode-change case below stages first and the base comparison is what
    fires.
    """

    git(candidate.root, "add", "-A")


def add_gate_file(candidate: Candidate) -> None:
    script = candidate.root / GATE_FILE
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("# gate fixture\n", encoding="utf-8")


@contextlib.contextmanager
def selected_tree(candidate: Candidate) -> Iterator[Any]:
    """``_set_root``'s candidate tree, with its root descriptor closed after.

    ``verify_append_gate`` holds the candidate root open for the whole verdict
    and closes it once, in one place. A test that drives a single check on its
    own has to do the same or leak the descriptor.
    """

    tree = append_gate._set_root(candidate.root, GATE_SPEC)
    try:
        yield tree
    finally:
        os.close(tree.root_descriptor)


def run_gate(
    candidate: Candidate,
    base_ref: str | None = None,
    spec: AppendGateSpec = GATE_SPEC,
) -> str:
    return verify_append_gate(
        candidate.root,
        spec=spec,
        base_ref=candidate.base if base_ref is None else base_ref,
    )


def run_push_gate(candidate: Candidate, spec: AppendGateSpec = GATE_SPEC) -> str:
    """The push path: no base ref, so only the full-file invariants run.

    ``run_gate`` always names a base, so nothing above exercised the branch
    that skips surface classification, the append-only diff, the base prefix
    anchor, and the release history.
    """

    return verify_append_gate(candidate.root, spec=spec)


def test_an_ordinary_append_is_accepted(tmp_path: pathlib.Path) -> None:
    """The fixture's baseline verdict, so every refusal below is the change."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_a_gate_only_proposal_cannot_rewrite_the_release_tree(
    tmp_path: pathlib.Path,
) -> None:
    """The gap: a gate match returned OK for everything else in the proposal.

    ``releases/README.md`` is in neither surface, so adding the gate script
    and rewriting the README classified as gate-only and returned before the
    ledger, prefix, and release-history checks ever ran.
    """

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.write_text("Rewritten by a gate-only proposal.\n", encoding="utf-8")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "gate-only proposal changes unclassified release path(s): "
        "['releases/README.md']"
    )


def test_an_unclassified_change_outside_the_release_tree_is_named(
    tmp_path: pathlib.Path,
) -> None:
    """Outside the release root a gate-only proposal is still accepted — but
    the verdict names what it did not check, so nothing rides along silently.
    """

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    (candidate.root / "NOTES.md").write_text("unrelated\n", encoding="utf-8")

    assert run_gate(candidate) == (
        "thesis-facts append check OK: gate-only proposal; DATA_SURFACE "
        f"unchanged; GATE_SURFACE changes=['{GATE_FILE}']; "
        "unclassified changes=['NOTES.md']"
    )


def ignore_rule(candidate: Candidate, *patterns: str) -> None:
    """A gate change's own ``.gitignore``, at the root of the candidate tree.

    The rule is part of the proposal, exactly as the file it hides is: both
    are what the pull request adds. ``.gitignore`` itself is untracked and
    unclassified, so it is named in the success text wherever the proposal is
    still accepted.
    """

    (candidate.root / ".gitignore").write_text(
        "".join(f"{pattern}\n" for pattern in patterns), encoding="utf-8"
    )


def test_an_ignored_ledger_sibling_makes_a_gate_proposal_mixed(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F1 on the data surface. The changed set this classification
    runs over came from ``git diff`` plus ``git ls-files --others
    --exclude-standard``, and ``--exclude-standard`` is what drops the ignored
    files. A gate change carries its own ``.gitignore``, so a proposal can add
    the rule and the file it hides in one commit: a second ledger under
    ``ledger/`` — the directory both state reads descend and the whole data
    surface — is then in neither half of that set.

    Measured at ccc20b4 with the ignored enumeration removed: ``thesis-facts
    append check OK: gate-only proposal; DATA_SURFACE unchanged; GATE_SURFACE
    changes=['scripts/check_append.py']; unclassified changes=['.gitignore']``
    — the verdict says the data surface did not change while a file the gate
    would refuse sits inside it, and it returns before the ledger, the frozen
    prefix, the row bindings and the release history are read.

    Ignored or not, it is a change on a protected surface, so the proposal is
    mixed and is refused in the words a mixed proposal has always been refused
    in."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    ignore_rule(candidate, "ledger/shadow.jsonl")
    (candidate.root / "ledger" / "shadow.jsonl").write_text(
        "{}\n", encoding="utf-8"
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "mixed data/gate proposal is forbidden: DATA_SURFACE changes="
        "['ledger/shadow.jsonl']; GATE_SURFACE changes="
        f"['{GATE_FILE}']; split them into separate pull requests"
    )


def test_an_ignored_release_path_reaches_the_gate_only_confinement(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F1 under the release root, which is the other surface a
    gate-only verdict speaks for without reading. ``releases/README.md``
    rewritten by a gate proposal is refused by
    ``check_gate_only_confinement``; the same file *ignored* was not in the
    changed set at all, so the confinement had nothing to confine.

    Measured at ccc20b4 with the ignored enumeration removed: ``thesis-facts
    append check OK: gate-only proposal; DATA_SURFACE unchanged; GATE_SURFACE
    changes=['scripts/check_append.py']; unclassified changes=['.gitignore']``.
    """

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    ignore_rule(candidate, "releases/scratch.txt")
    (candidate.root / "releases" / "scratch.txt").write_text(
        "riding along\n", encoding="utf-8"
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "gate-only proposal changes unclassified release path(s): "
        "['releases/scratch.txt']"
    )


def test_an_ignored_file_off_every_protected_surface_is_not_a_change(
    tmp_path: pathlib.Path,
) -> None:
    """S5-F1's restriction, which is the other half of the decision. An
    ignored file is a change where this verdict reads the filesystem — the two
    surfaces and the release root — and nowhere else. Build output, a cache
    directory, a virtualenv: none of it is in a commit, none of it is proposed,
    and naming it as an unclassified change would report a checkout's litter
    as part of the proposal, in a list nothing bounds.

    So the verdict here is the one an ordinary gate-only proposal has always
    had, with only the proposal's own ``.gitignore`` named beside the gate
    file."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    ignore_rule(candidate, "build/")
    (candidate.root / "build").mkdir()
    (candidate.root / "build" / "out.o").write_bytes(b"\x00")

    assert run_gate(candidate) == (
        "thesis-facts append check OK: gate-only proposal; DATA_SURFACE "
        f"unchanged; GATE_SURFACE changes=['{GATE_FILE}']; "
        "unclassified changes=['.gitignore']"
    )


def test_an_ignored_gate_path_is_a_gate_change(tmp_path: pathlib.Path) -> None:
    """S5-F1 on the third protected surface. ``releases/anchors/**`` is the
    fixture's gate surface, and an ignored file there is code this proposal
    ships as much as a tracked one is: it classifies GATE, and beside a data
    change it makes the proposal mixed rather than letting the data path run
    with an unread anchor sitting in the tree.

    This tree was refused before the fold as well, further down and in other
    words — measured at ccc20b4 with the ignored enumeration removed:
    ``legacy pre-genesis proposal must not change releases/; add a complete
    genesis manifest, producer signature, and both receipts or no release
    files at all (changed=['releases/anchors/alpha-root.pem'])``, the release
    pass meeting the file the classification could not see. Both refusals are
    the extraction's own, so what the fold moves here is which pre-existing
    sentence a tree already refused gets, in exactly the way the index fold
    already moves one: the union is held to the rule the working-tree set was
    already held to, and a proposal that touches both surfaces is refused as
    mixed in the words that refusal has always used. The harness cannot
    produce the case — its fixtures add no ignore rule."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ignore_rule(candidate, "releases/anchors/")
    anchors = candidate.root / "releases" / "anchors"
    anchors.mkdir()
    (anchors / "alpha-root.pem").write_text("not a root\n", encoding="utf-8")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "mixed data/gate proposal is forbidden: DATA_SURFACE changes="
        "['ledger/official_observations.jsonl']; GATE_SURFACE changes="
        "['releases/anchors/alpha-root.pem']; split them into separate pull "
        "requests"
    )


@pytest.mark.skipif(
    os.getuid() == 0, reason="root lists a directory it has no rights on"
)
def test_an_unreadable_data_directory_cannot_be_classified(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-R2-F1 on the data surface, which is where the finding bites
    hardest. The classification's untracked and ignored listings took ``git
    ls-files``'s exit status for a complete enumeration, and it is not one:
    with ``ledger/sub`` at mode 0 git exits 0, prints ``warning: could not open
    directory 'ledger/sub/': Permission denied`` on stderr, and omits that
    subtree from stdout entirely — measured directly against git 2.53.0 on
    this checkout before anything here was written. The gate discarded stderr,
    so the second ledger inside that directory was in neither half of the
    changed set.

    Measured at 54b589e, this exact tree: ``thesis-facts append check OK:
    gate-only proposal; DATA_SURFACE unchanged; GATE_SURFACE
    changes=['scripts/check_append.py']`` — the verdict names the data surface
    as unchanged, and returns before the ledger, the frozen prefix, the row
    bindings and the release history are read, with a file the gate would
    refuse sitting under the surface it just spoke for.

    The fix does not try to read what git could not. It enumerates every
    protected surface itself and refuses the whole classification when one of
    those directories cannot be listed: not being able to say what is on a
    surface is not the same as there being nothing on it."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    hidden = candidate.root / "ledger" / "sub"
    hidden.mkdir()
    (hidden / "shadow.jsonl").write_text("{}\n", encoding="utf-8")
    hidden.chmod(0o000)
    try:
        with pytest.raises(AppendError) as refusal:
            run_gate(candidate)
        assert str(refusal.value) == (
            "cannot enumerate a protected directory, so the proposal cannot "
            "be classified: ledger/sub (Permission denied)"
        )
    finally:
        hidden.chmod(0o755)


@pytest.mark.skipif(
    os.getuid() == 0, reason="root lists a directory it has no rights on"
)
def test_an_unreadable_release_directory_cannot_be_classified(
    tmp_path: pathlib.Path,
) -> None:
    """S5-R2-F1 on the release root, the other surface a gate-only verdict
    speaks for without reading. ``check_gate_only_confinement`` refuses an
    unclassified change anywhere under that root, and it can only refuse what
    the classification found: an untracked file inside a mode-0 directory
    there is in no listing at all.

    Measured at 54b589e, this exact tree: ``thesis-facts append check OK:
    gate-only proposal; DATA_SURFACE unchanged; GATE_SURFACE
    changes=['scripts/check_append.py']`` — the confinement had nothing to
    confine, and said so as an acceptance.

    The release root is walked whole for that reason, and its own leaf as much
    as anything below it."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    vault = candidate.root / CHAIN_SPEC.release_root_relative / "vault"
    vault.mkdir()
    (vault / "riding-along.txt").write_text("hidden\n", encoding="utf-8")
    vault.chmod(0o000)
    try:
        with pytest.raises(AppendError) as refusal:
            run_gate(candidate)
        assert str(refusal.value) == (
            "cannot enumerate a protected directory, so the proposal cannot "
            "be classified: releases/vault (Permission denied)"
        )
    finally:
        vault.chmod(0o755)


@pytest.mark.skipif(
    os.getuid() == 0, reason="root lists a directory it has no rights on"
)
def test_an_unreadable_directory_off_every_surface_is_not_refused(
    tmp_path: pathlib.Path,
) -> None:
    """S5-R2-F1's restriction, which is S5-F1's restriction applied to the
    same question one layer down. An unreadable directory that lies on no
    protected surface holds files that are in no commit and are proposed by
    nothing: a build tree, a cache, a virtualenv whose site-packages a
    developer has locked down. Refusing over one would refuse a checkout for
    its own litter, which is the direction round 12's F2 had to reverse once
    already.

    So the walk is restricted to the surfaces, exactly as the ignored listing
    is, and this is also what makes the stderr check beside it a scoped one:
    git warns about *every* directory in the checkout it could not open, and
    this tree really does produce ``warning: could not open directory
    'build/sub/': Permission denied`` on the same reads the verdict is built
    from. The verdict is the ordinary gate-only one all the same."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    litter = candidate.root / "build" / "sub"
    litter.mkdir(parents=True)
    (litter / "out.o").write_bytes(b"\x00")
    litter.chmod(0o000)
    try:
        assert run_gate(candidate) == (
            "thesis-facts append check OK: gate-only proposal; DATA_SURFACE "
            f"unchanged; GATE_SURFACE changes=['{GATE_FILE}']"
        )
    finally:
        litter.chmod(0o755)


@pytest.mark.skipif(
    os.getuid() == 0, reason="root lists a directory it has no rights on"
)
def test_the_stderr_check_refuses_what_the_walk_would_have_caught(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S5-R2-F1's belt, shown to hold on its own. The walk is the guarantee —
    it asks the question directly, of every protected directory, before any
    listing is believed — and the stderr check is the second answer for the
    case the walk cannot have: git making the same listing at its own instant
    and finding something the walk did not, a permission changed between the
    two reads among them.

    Disabling the walk in place is how that is measured rather than argued.
    With ``assert_protected_surfaces_enumerable`` replaced by a no-op the tree
    below is still refused, and by the stderr check, in its own words. With
    both gone — the head at 54b589e — it is accepted as ``thesis-facts append
    check OK: gate-only proposal; DATA_SURFACE unchanged; GATE_SURFACE
    changes=['scripts/check_append.py']``."""

    monkeypatch.setattr(
        append_gate, "assert_protected_surfaces_enumerable", lambda candidate: None
    )
    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    hidden = candidate.root / "ledger" / "sub"
    hidden.mkdir()
    (hidden / "shadow.jsonl").write_text("{}\n", encoding="utf-8")
    hidden.chmod(0o000)
    try:
        with pytest.raises(AppendError) as refusal:
            run_gate(candidate)
        assert str(refusal.value) == (
            "git reported a warning while enumerating the working tree: "
            "warning: could not open directory 'ledger/sub/': Permission denied"
        )
    finally:
        hidden.chmod(0o755)


def test_a_warning_this_run_cannot_place_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """S5-R2-F1's belt where it fails closed. Attribution reads the path git
    quoted, because the quoting is what a translated message keeps while the
    wording is not. A line this run finds no path in is a line it cannot
    place, and an unplaceable warning about a listing the verdict is built on
    is refused rather than assumed to be about ground the verdict does not
    speak for. The same goes for a quoted path that is absolute or climbs out
    of the tree: neither is a repository-relative path any surface here can be
    compared against.

    Driven directly, because a git that emits an unattributable warning on
    these reads is not something a fixture can arrange; the protected and
    unprotected lines beside it are the same call answering the cases the
    tree-level tests above produce for real."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    with selected_tree(candidate) as tree:
        for line in (
            b"warning: something went wrong\n",
            b"warning: could not open directory '/etc/shadow/': Denied\n",
            b"warning: could not open directory '../outside/': Denied\n",
            b"warning: could not open directory 'ledger/sub/': Denied\n",
            b"warning: could not open directory 'releases/vault/': Denied\n",
            b"warning: could not open directory 'scripts/': Denied\n",
        ):
            with pytest.raises(AppendError) as refusal:
                append_gate._assert_listing_complete(line, tree)
            assert str(refusal.value) == (
                "git reported a warning while enumerating the working tree: "
                f"{line.decode().strip()}"
            )
        # And the ones this run can place outside every protected surface.
        for quiet in (
            b"",
            b"   \n",
            b"warning: could not open directory 'build/sub/': Denied\n",
            b"warning: could not open directory 'node_modules/': Denied\n",
        ):
            append_gate._assert_listing_complete(quiet, tree)


def test_the_surface_walk_is_bounded(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S5-R2-F1's budget, which is a bound on work rather than a confinement.
    The walk descends no symlink, so no cycle is reachable and the only thing
    that can make it long is a genuinely enormous protected surface. A walk
    that stopped early would be exactly the silent omission the finding is
    about, so exceeding the budget is a refusal in the walk's own terms.

    ``MAX_SURFACE_WALK_ENTRIES`` is 200,000 entries, which no consumer's
    ledger directory and release tree come near, so the bound is lowered here
    rather than the fixture grown to meet it."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    monkeypatch.setattr(append_gate, "MAX_SURFACE_WALK_ENTRIES", 1)
    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value).startswith(
        "protected surface enumeration exceeded 1 entries, so the proposal "
        "cannot be classified: "
    )


def test_a_clean_gate_only_proposal_keeps_its_baseline_verdict(
    tmp_path: pathlib.Path,
) -> None:
    """With nothing unclassified the text is exactly what it always was."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)

    assert run_gate(candidate) == (
        "thesis-facts append check OK: gate-only proposal; DATA_SURFACE "
        f"unchanged; GATE_SURFACE changes=['{GATE_FILE}']"
    )


def relink_ledger_directory(candidate: Candidate, target: pathlib.Path) -> None:
    """Move ``ledger/`` to ``target`` and leave a symlink where it stood.

    The candidate keeps a name that still resolves to a regular JSONL file,
    still hashes to the frozen prefix, and still diffs clean against the base
    blob — while the bytes under audit live wherever the link points.
    """

    ledger = candidate.root / "ledger"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(ledger), str(target))
    ledger.symlink_to(target, target_is_directory=True)


def test_a_symlinked_ledger_parent_cannot_serve_state_from_outside_the_tree(
    tmp_path: pathlib.Path,
) -> None:
    """The gap: only the final component was ever checked for a link.

    With ``ledger/`` pointed at an ambient directory the whole append check
    returned OK on bytes that are no part of the candidate checkout.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    relink_ledger_directory(candidate, tmp_path / "outside" / "ledger")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'ledger': "
        "ledger/official_observations.jsonl"
    )


def test_an_in_tree_symlinked_ledger_parent_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """An in-tree target is the same hole: the accepted bytes then live in a
    directory no surface pattern names and no release check covers."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    relink_ledger_directory(candidate, candidate.root / "shadow")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'ledger': "
        "ledger/official_observations.jsonl"
    )


def test_a_symlinked_state_file_itself_is_refused(tmp_path: pathlib.Path) -> None:
    """The final component too: the gate followed a linked JSONL without
    comment, because nothing between _set_root and read_text looked."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    outside = tmp_path / "outside.jsonl"
    shutil.move(str(ledger), str(outside))
    ledger.symlink_to(outside)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'ledger/official_observations.jsonl': "
        "ledger/official_observations.jsonl"
    )


def test_a_symlinked_prefix_parent_is_refused(tmp_path: pathlib.Path) -> None:
    """The immutable prefix is a state path too, and check_prefix reads it by
    the same lexical join. Here the ledger stays put so the prefix walk is the
    one that fires."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    prefix = candidate.root / CHAIN_SPEC.prefix_relative
    outside = tmp_path / "outside" / "immutable_prefix.json"
    outside.parent.mkdir(parents=True)
    shutil.move(str(prefix), str(outside))
    prefix.symlink_to(outside)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'ledger/immutable_prefix.json': "
        "ledger/immutable_prefix.json"
    )


def test_the_state_reader_refuses_a_symlinked_parent(tmp_path: pathlib.Path) -> None:
    """The same walk in the release-chain reader, which _verify_state_history
    uses for both the ledger and the immutable prefix."""

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "official_observations.jsonl").write_text("{}\n", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "ledger").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ReleaseChainError) as refusal:
        _regular_file_bytes(root, CHAIN_SPEC.state_relative)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'ledger': "
        "ledger/official_observations.jsonl"
    )


def test_the_state_reader_keeps_its_message_for_a_symlinked_state_file(
    tmp_path: pathlib.Path,
) -> None:
    """The final-component refusal predates the walk and is differential-gated:
    a linked state file must still refuse with exactly its own message."""

    root = tmp_path / "repo"
    (root / "ledger").mkdir(parents=True)
    outside = tmp_path / "outside.jsonl"
    outside.write_text("{}\n", encoding="utf-8")
    linked = root / CHAIN_SPEC.state_relative
    linked.symlink_to(outside)

    with pytest.raises(ReleaseChainError) as refusal:
        _regular_file_bytes(root, CHAIN_SPEC.state_relative)
    assert str(refusal.value) == (
        f"required state file is missing or non-regular: {linked}"
    )


def test_the_state_reader_accepts_an_ordinary_regular_file(
    tmp_path: pathlib.Path,
) -> None:
    """The walk costs the ordinary tree nothing."""

    root = tmp_path / "repo"
    (root / "ledger").mkdir(parents=True)
    (root / CHAIN_SPEC.state_relative).write_text("{}\n", encoding="utf-8")

    assert _regular_file_bytes(root, CHAIN_SPEC.state_relative) == b"{}\n"


def moving_base_repository(
    tmp_path: pathlib.Path,
) -> tuple[Candidate, str, str]:
    """A branch on an early commit, a later commit, and a four-row worktree.

    The two commits give different verdicts for the same working tree — two
    appended rows against the first, one against the second — so the verdict
    text alone says which commit the whole run measured against. The later
    commit also differs in the frozen prefix manifest and in the release
    tree, so a consumer that read either at the moved ref would refuse
    outright: the prefix anchor compares manifest fields and the release
    history compares README bytes. That binds every base consumer, not only
    the append count (peer review, round three).
    """

    first = base_repository(tmp_path)
    readme = first.root / CHAIN_SPEC.release_root_relative / "README.md"
    manifest = first.root / CHAIN_SPEC.prefix_relative
    kept_readme, kept_manifest = readme.read_bytes(), manifest.read_bytes()
    rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 2)]
    write_ledger(first.root, rows)
    readme.write_text("Release journal, revised after the base.\n", encoding="utf-8")
    write_prefix_manifest(first.root, [dict(rows[0], value=999.0), *rows[1:]])
    git(first.root, "add", "-A")
    git(first.root, "commit", "--quiet", "-m", "third row, revised prefix and release tree")
    later = git(first.root, "rev-parse", "HEAD")
    git(first.root, "branch", "moving", first.base)
    readme.write_bytes(kept_readme)
    manifest.write_bytes(kept_manifest)
    rows.append(observation_row(BASE_ROW_COUNT + 2))
    write_ledger(first.root, rows)
    # The proposal is staged, as a reviewed checkout's is. Without this the
    # index still holds the later commit's README while the working tree
    # holds the base's, which is a staged rewrite of a base release file with
    # the disk restored — exactly what S4R3-F1 refuses, and nothing this
    # fixture is about.
    git(first.root, "add", "-A")
    return Candidate(root=first.root, base="moving"), first.base, later


def test_the_success_text_names_the_commit_a_symbolic_base_resolved_to(
    tmp_path: pathlib.Path,
) -> None:
    """A verdict against a movable name must say which commit that name was."""

    moving, first, _later = moving_base_repository(tmp_path)

    assert run_gate(moving) == (
        "thesis-facts append check OK: 4 rows, immutable prefix 1, "
        f"+2 appended vs base moving ({first})"
    )


def test_a_base_named_by_its_own_commit_keeps_the_baseline_text(
    tmp_path: pathlib.Path,
) -> None:
    """A caller who named the OID already named the commit, so that verdict
    text is exactly what it always was."""

    moving, first, _later = moving_base_repository(tmp_path)

    assert run_gate(moving, base_ref=first) == (
        "thesis-facts append check OK: 4 rows, immutable prefix 1, "
        "+2 appended vs base"
    )


def test_the_moved_branch_alone_would_change_the_verdict(
    tmp_path: pathlib.Path,
) -> None:
    """The control: the two commits really do disagree about this worktree,
    and not only in the append count. Against the later commit the same tree
    is refused by the prefix anchor or the release history, so the mid-run
    test below proves every base consumer read the first commit (peer
    review, round three)."""

    moving, _first, later = moving_base_repository(tmp_path)
    git(moving.root, "branch", "-f", "moving", later)

    with pytest.raises(AppendError) as refusal:
        run_gate(moving)
    assert "appended" not in str(refusal.value)


def test_a_branch_that_moves_mid_verdict_is_still_read_at_one_commit(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gap: the base was resolved by name at the surface check, again at
    the append-only diff and the frozen prefix, and again at the release
    history. Move the branch after the surface check and the run must still
    answer about the commit it started with."""

    moving, first, later = moving_base_repository(tmp_path)
    separate = append_gate.check_surface_separation

    def move_the_branch(
        base: Any, candidate: Any
    ) -> tuple[set[str], set[str], set[str]]:
        classified = separate(base, candidate)
        git(candidate.root, "branch", "-f", "moving", later)
        return classified

    monkeypatch.setattr(append_gate, "check_surface_separation", move_the_branch)

    assert run_gate(moving) == (
        "thesis-facts append check OK: 4 rows, immutable prefix 1, "
        f"+2 appended vs base moving ({first})"
    )
    assert git(moving.root, "rev-parse", "moving") == later


def test_the_ledger_cannot_be_made_executable_by_a_proposal(
    tmp_path: pathlib.Path,
) -> None:
    """The gap: the append path compared bytes, never the mode git tracks."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.chmod(ledger.stat().st_mode | 0o111)
    stage(candidate)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file mode changed relative to base: "
        "ledger/official_observations.jsonl"
    )


def test_the_frozen_prefix_cannot_be_made_executable_by_a_proposal(
    tmp_path: pathlib.Path,
) -> None:
    """The manifest is candidate-controlled too, and its fields were the only
    thing anchored to the base."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    prefix = candidate.root / CHAIN_SPEC.prefix_relative
    prefix.chmod(prefix.stat().st_mode | 0o111)
    stage(candidate)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file mode changed relative to base: ledger/immutable_prefix.json"
    )


def test_a_ledger_executable_at_the_base_may_stay_executable(
    tmp_path: pathlib.Path,
) -> None:
    """The invariant is "keeps the base's category", not "must be 644": a base
    that already recorded 100755 accepts an ordinary append."""

    candidate = base_repository(tmp_path)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.chmod(ledger.stat().st_mode | 0o111)
    git(candidate.root, "add", "-A")
    git(candidate.root, "commit", "--quiet", "-m", "executable ledger")
    executable_base = Candidate(
        root=candidate.root, base=git(candidate.root, "rev-parse", "HEAD")
    )
    append_one_row(executable_base)
    ledger.chmod(ledger.stat().st_mode | 0o111)

    assert run_gate(executable_base) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_a_response_archive_digest_that_is_not_a_digest_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """The gap: presence was the whole check, so any truthy value bound the
    row to an archived response that may not exist."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, responseArchive={"sha256": "not-a-sha256"})

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) "
        "responseArchive.sha256 is not a SHA-256 hex digest"
    )


def test_an_uppercase_response_archive_digest_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """One spelling per digest: an upper-case twin of the same bytes would
    compare unequal to every digest this package recomputes."""

    candidate = base_repository(tmp_path)
    append_one_row(
        candidate,
        responseArchive={
            "sha256": hashlib.sha256(b"response-3").hexdigest().upper()
        },
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) "
        "responseArchive.sha256 is not a SHA-256 hex digest"
    )


def test_an_abbreviated_ledger_repo_sha_is_refused(tmp_path: pathlib.Path) -> None:
    """An abbreviation names a commit only until the repository grows one
    that shares its prefix."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, ledgerRepoSha="47ca684")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) ledgerRepoSha is "
        "not a full 40-character commit id"
    )


def test_a_symbolic_ledger_repo_sha_is_refused(tmp_path: pathlib.Path) -> None:
    """A symbolic name is truthy and binds nothing: it names whatever the
    repository points it at today."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, ledgerRepoSha="HEAD")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) ledgerRepoSha is "
        "not a full 40-character commit id"
    )


def test_a_retrieved_at_without_a_time_zone_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """A naive timestamp cannot be ordered against a witnessed genTime."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, retrievedAt="2026-07-10T20:38:58")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) retrievedAt is not "
        "a canonical RFC 3339 timestamp (uppercase T and Z or ±HH:MM, no "
        "leap second)"
    )


def test_a_retrieved_at_that_is_not_a_timestamp_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Prose satisfied presence exactly as well as a timestamp did."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, retrievedAt="yesterday")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) retrievedAt is not "
        "a canonical RFC 3339 timestamp (uppercase T and Z or ±HH:MM, no "
        "leap second)"
    )


def test_a_retrieved_at_naming_an_impossible_day_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """The pattern accepts the shape; the parser is what rejects the day."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, retrievedAt="2026-02-30T00:00:00Z")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) retrievedAt is not "
        "a canonical RFC 3339 timestamp (uppercase T and Z or ±HH:MM, no "
        "leap second)"
    )


def test_a_retrieved_at_with_a_non_utc_offset_is_accepted(
    tmp_path: pathlib.Path,
) -> None:
    """RFC 3339 with a time zone, not UTC-only: the check adds a shape, not a
    policy about which zone a resolver may report from."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, retrievedAt="2026-07-10T20:38:58.5+05:30")

    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


@pytest.mark.parametrize("offset", ["+01:60", "+24:00", "-00:60"])
def test_a_retrieved_at_with_an_overflowing_offset_is_refused(
    tmp_path: pathlib.Path, offset: str
) -> None:
    """The parser normalises ``+01:60`` to ``+02:00`` rather than refusing it,
    so the offset's hour and minute are bounded in the pattern (peer review)."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, retrievedAt=f"2026-07-10T20:38:58{offset}")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) retrievedAt is not "
        "a canonical RFC 3339 timestamp (uppercase T and Z or ±HH:MM, no "
        "leap second)"
    )


def test_a_group_execute_bit_alone_is_not_a_mode_change(
    tmp_path: pathlib.Path,
) -> None:
    """Git keys the executable category on the owner bit, so 0655 is 100644
    to git and an ordinary append with it is not a mode change."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.chmod(0o655)

    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_dropping_the_owner_execute_bit_is_a_mode_change_whatever_others_keep(
    tmp_path: pathlib.Path,
) -> None:
    """The case the any-bit test missed: 100755 at the base, 0655 in the
    candidate, which git records as 100644 (peer review)."""

    candidate = base_repository(tmp_path)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.chmod(ledger.stat().st_mode | 0o111)
    git(candidate.root, "add", "-A")
    git(candidate.root, "commit", "--quiet", "-m", "executable ledger")
    executable_base = Candidate(
        root=candidate.root, base=git(candidate.root, "rev-parse", "HEAD")
    )
    append_one_row(executable_base)
    ledger.chmod(0o655)
    stage(executable_base)

    with pytest.raises(AppendError) as refusal:
        run_gate(executable_base)
    assert str(refusal.value) == (
        "state file mode changed relative to base: "
        "ledger/official_observations.jsonl"
    )


def test_a_gate_only_verdict_names_the_commit_a_symbolic_base_resolved_to(
    tmp_path: pathlib.Path,
) -> None:
    """The gate-only acceptance returned before the resolved-base suffix was
    built, so against a movable name it named no snapshot (peer review)."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)

    assert run_gate(candidate, base_ref="HEAD") == (
        "thesis-facts append check OK: gate-only proposal; DATA_SURFACE "
        f"unchanged; GATE_SURFACE changes=['{GATE_FILE}']; base HEAD "
        f"({candidate.base})"
    )


def test_an_existing_row_refusal_wins_over_a_binding_shape_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """A row that both duplicates a record without superseding it and carries
    a symbolic ledgerRepoSha gets the refusal that existed before this branch:
    the shape checks run last in the row (peer review)."""

    candidate = base_repository(tmp_path)
    append_one_row(
        candidate,
        source_record_id="fixture.series.observation_2",
        value=999.0,
        ledgerRepoSha="HEAD",
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "line 3 duplicates fixture.series.observation_2 (line 2) without "
        "superseding an assertion version — corrections must be explicit"
    )


def test_an_existing_row_refusal_wins_over_the_mode_check(
    tmp_path: pathlib.Path,
) -> None:
    """Pins the order the mode check runs in: a proposal that both flips the
    ledger's mode and appends a row lacking retrievedAt gets the row refusal,
    which existed before the mode check did (peer review asked for this)."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, retrievedAt=None)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.chmod(ledger.stat().st_mode | 0o100)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) lacks retrievedAt"
    )


def test_a_release_file_with_a_group_execute_bit_alone_keeps_its_category(
    tmp_path: pathlib.Path,
) -> None:
    """The release-file comparison keys on the owner bit like the state check:
    0655 is 100644 to git, so a 100644 base accepts it."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.chmod(0o655)

    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_dropping_a_release_files_owner_execute_bit_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """100755 at the base, 0655 in the candidate: a mode change the any-bit
    test in the release-file comparison missed (peer review, round two)."""

    candidate = base_repository(tmp_path)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.chmod(readme.stat().st_mode | 0o111)
    git(candidate.root, "add", "-A")
    git(candidate.root, "commit", "--quiet", "-m", "executable readme")
    executable_base = Candidate(
        root=candidate.root, base=git(candidate.root, "rev-parse", "HEAD")
    )
    append_one_row(executable_base)
    readme.chmod(0o655)
    stage(executable_base)

    with pytest.raises(AppendError) as refusal:
        run_gate(executable_base)
    assert str(refusal.value) == (
        f"existing release file mode changed relative to {executable_base.base}: "
        "releases/README.md (100755 -> 100644)"
    )


def test_a_checkout_whose_modes_are_not_authoritative_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """With core.fileMode false the working tree says nothing about the mode
    git records, so comparing it would be fail-open; the gate refuses instead
    (peer review, round two)."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(candidate.root, "config", "core.fileMode", "false")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "file modes cannot be verified: core.fileMode is false in this "
        "checkout, so the working tree does not carry the executable bit git "
        "records"
    )


def test_a_pre_existing_release_refusal_wins_over_a_binding_shape_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """A proposal that both rewrites a base release file and carries a
    symbolic ledgerRepoSha gets the release-history refusal, which existed
    before the shape checks did: they run after the release checks (peer
    review, round two)."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, ledgerRepoSha="HEAD")
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.write_text("rewritten\n", encoding="utf-8")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert "ledgerRepoSha" not in str(refusal.value)
    assert "releases/README.md" in str(refusal.value)


@pytest.mark.parametrize(
    "value",
    ["2026-07-10t20:38:58Z", "2026-07-10T20:38:58z", "2016-12-31T23:59:60Z"],
    ids=["lowercase-t", "lowercase-z", "leap-second"],
)
def test_forms_the_rfc_permits_but_the_profile_does_not_are_refused(
    tmp_path: pathlib.Path, value: str
) -> None:
    """The validator is a stated profile, narrower than RFC 3339: uppercase T
    and Z, ±HH:MM, no leap second (peer review, round three)."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, retrievedAt=value)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "appended line 3 (fixture.series.observation_3) retrievedAt is not "
        "a canonical RFC 3339 timestamp (uppercase T and Z or ±HH:MM, no "
        "leap second)"
    )


def test_a_checkout_that_does_not_materialise_symlinks_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """With core.symlinks false a symlink blob is checked out as a plain file
    holding its target, so byte, mode, and component-walk checks all pass
    over a type change (peer review, round three)."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(candidate.root, "config", "core.symlinks", "false")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "file types cannot be verified: core.symlinks is false in this "
        "checkout, so a symlink entry is materialised as a plain file"
    )


@pytest.mark.parametrize(
    ("key", "message"),
    [
        (
            "core.fileMode",
            "file modes cannot be verified: core.fileMode is false in this "
            "checkout, so the working tree does not carry the executable bit git "
            "records",
        ),
        (
            "core.symlinks",
            "file types cannot be verified: core.symlinks is false in this "
            "checkout, so a symlink entry is materialised as a plain file",
        ),
    ],
    ids=["fileMode", "symlinks"],
)
def test_the_release_history_pass_refuses_a_non_authoritative_checkout_itself(
    tmp_path: pathlib.Path, key: str, message: str
) -> None:
    """Binds the guard inside verify_release_history_immutable directly, since
    through the gate check_state_modes would refuse the same way later
    (peer review, round three)."""

    from receipt.release_chain import ReleaseChainError, verify_release_history_immutable

    candidate = base_repository(tmp_path)
    git(candidate.root, "config", key, "false")

    with pytest.raises(ReleaseChainError) as refusal:
        verify_release_history_immutable(candidate.root, candidate.base, spec=CHAIN_SPEC)
    assert str(refusal.value) == message


def test_the_checkout_refusal_precedes_file_level_release_refusals(
    tmp_path: pathlib.Path,
) -> None:
    """Pins the one intended precedence over pre-existing release checks: a
    checkout that cannot be verified says so before any verdict about its
    files, even a rewritten base release file."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.write_text("rewritten\n", encoding="utf-8")
    git(candidate.root, "config", "core.fileMode", "false")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value).startswith("file modes cannot be verified")


def test_a_replacement_object_cannot_change_what_the_base_commit_reads_as(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F4: every git read in the gate disables ``refs/replace``.

    A replacement rewrites what git returns for an object while every command
    still prints the original OID, so a base commit replaced by a later one is
    shown, diffed, and enumerated as that later commit behind the name the
    verdict prints. Without ``GIT_NO_REPLACE_OBJECTS`` this run reads the
    later commit — which differs in the ledger, the frozen prefix manifest,
    and the release tree — and refuses; the control below shows exactly that.
    """

    moving, first, later = moving_base_repository(tmp_path)
    git(moving.root, "replace", first, later)
    # The replacement is live for an ordinary read: the base OID now shows the
    # later commit's three-row ledger.
    replaced = git(
        moving.root,
        "show",
        f"{first}:{CHAIN_SPEC.state_relative.as_posix()}",
    )
    assert len(replaced.splitlines()) == BASE_ROW_COUNT + 1

    assert run_gate(moving) == (
        "thesis-facts append check OK: 4 rows, immutable prefix 1, "
        f"+2 appended vs base moving ({first})"
    )


def test_the_replacement_control_shows_the_environment_is_what_stops_it(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for F4: strip ``GIT_NO_REPLACE_OBJECTS`` from the shared
    environment helper — in both modules, since append_gate binds the name at
    import — and the same tree is read at the replacement and refused. That is
    the verdict this branch would still be giving without the fix."""

    moving, first, later = moving_base_repository(tmp_path)
    git(moving.root, "replace", first, later)
    monkeypatch.setattr(append_gate, "_git_environment", lambda: dict(os.environ))
    monkeypatch.setattr(release_chain, "_git_environment", lambda: dict(os.environ))

    with pytest.raises(AppendError) as refusal:
        run_gate(moving)
    assert "changed vs base moving" in str(refusal.value)


def test_the_push_path_accepts_an_ordinary_tree(tmp_path: pathlib.Path) -> None:
    """The baseline for F1, so the refusals below are the change: with no base
    ref the verdict carries neither an append count nor a release, and this
    branch of verify_append_gate had no test at all before."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)

    assert run_push_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1"
    )


@pytest.mark.parametrize(
    ("key", "message"),
    [
        (
            "core.fileMode",
            "file modes cannot be verified: core.fileMode is false in this "
            "checkout, so the working tree does not carry the executable bit "
            "git records",
        ),
        (
            "core.symlinks",
            "file types cannot be verified: core.symlinks is false in this "
            "checkout, so a symlink entry is materialised as a plain file",
        ),
    ],
    ids=["fileMode", "symlinks"],
)
def test_the_push_path_refuses_a_non_authoritative_checkout(
    tmp_path: pathlib.Path, key: str, message: str
) -> None:
    """Binds F1: the checkout guard was reachable only through the base-ref
    path — the release-history pass and check_state_modes. On a push both are
    skipped, so with core.symlinks false a git 120000 state entry materialised
    as a plain file holding its target text passed the component walk (there
    is no link to see) and both state reads, and the run returned OK. The
    guard now runs at entry for both paths."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(candidate.root, "config", key, "false")

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == message


def a_lying_file_system_monitor(candidate: Candidate) -> None:
    """Point ``core.fsmonitor`` at a hook that reports nothing ever changes.

    The v2 hook protocol is one line of output: a token git hands back on the
    next query, followed by the NUL-separated paths that changed since the
    token it was given. A hook that prints a token and no paths tells git that
    nothing has changed, and git keeps ``CE_FSMONITOR_VALID`` on every entry
    and reports the whole working tree clean without stat-ing any of it. It is
    the oldest of the four caching arrangements and the most complete: no
    restored mtime, no matching size, nothing arranged about the file at all.

    One ``git status`` warms it, because the valid bits reach the index when a
    command writes the index.
    """

    hook = candidate.root / ".git" / "hooks" / "quiet-monitor"
    hook.write_text("#!/bin/sh\nprintf '1788400000000000000'\n", encoding="utf-8")
    hook.chmod(0o755)
    git(candidate.root, "config", "core.fsmonitor", ".git/hooks/quiet-monitor")
    git(candidate.root, "status", "--porcelain")


def test_a_lying_file_system_monitor_cannot_hide_a_ledger_rewrite(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F2 for the setting the earlier guard refused first. The whole
    surface classification is ``git diff`` plus ``git ls-files --others``, and
    a monitor git trusts answers both without looking at the tree: the ledger
    is rewritten on disk, the gate file is added beside it, and the proposal is
    gate-only — returning ``DATA_SURFACE unchanged`` before the ledger, the
    frozen prefix, the row bindings and the release history are read.

    Refusing the setting was the earlier answer and it refused the checkout
    rather than the proposal. The reads themselves now spell
    ``core.fsmonitor=false`` on their own command lines, so the monitor is not
    consulted for them however the checkout is configured, and the tree is
    classified from the working tree it actually has.

    Measured at 5c2743d with ``WORKING_TREE_SCAN_OPTIONS`` emptied and the
    guard already gone: ``thesis-facts append check OK: gate-only proposal;
    DATA_SURFACE unchanged; GATE_SURFACE changes=['scripts/check_append.py']``.
    """

    candidate = base_repository(tmp_path)
    a_lying_file_system_monitor(candidate)
    append_one_row(candidate)
    add_gate_file(candidate)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "mixed data/gate proposal is forbidden: DATA_SURFACE changes="
        "['ledger/official_observations.jsonl']; GATE_SURFACE changes="
        f"['{GATE_FILE}']; split them into separate pull requests"
    )


def rewrite_the_ledger_past_a_minimal_stat_cache(candidate: Candidate) -> None:
    """A same-size ledger rewrite git's reduced stat comparison will not see.

    ``core.checkStat=minimal`` leaves git comparing an entry's whole-second
    mtime and its size and nothing else — not the inode, not the change time,
    which ``core.trustctime=false`` drops as well. So the rewrite is written to
    a sibling carrying the recorded mtime and renamed over the ledger: same
    size, same mtime, a different inode, and no change git will look for.

    The recorded mtime is set into the past before the index records it, so
    that the entry is not racy — a file whose mtime is not older than the index
    is re-read from content whatever the stat comparison says, which is the one
    thing that would make this arrangement visible for a reason other than the
    one under test.
    """

    ledger = candidate.root / CHAIN_SPEC.state_relative
    past = 1_600_000_000_000_000_000
    os.utime(ledger, ns=(past, past))
    git(candidate.root, "update-index", "--refresh")
    rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 1)]
    rewritten = ledger.parent / ".rewritten"
    original = ledger.read_bytes()
    rows[-1]["value"] = rows[-1]["value"] + 1
    rows[-1]["assertionVersion"]["id"] = expected_assertion_version_id(
        rows[-1], GATE_SPEC
    )
    payload = "".join(jsonl_line(row) for row in rows).encode("utf-8")
    payload = payload[: len(original)].ljust(len(original), b" ")
    assert payload != original and len(payload) == len(original)
    rewritten.write_bytes(payload)
    os.utime(rewritten, ns=(past, past))
    rewritten.rename(ledger)


def test_a_minimal_stat_comparison_cannot_hide_a_ledger_rewrite(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F2 for the two settings that shrink git's stat comparison.
    With ``core.trustctime`` false and ``core.checkStat`` minimal, an entry
    matches on whole-second mtime and size alone, so a same-size rewrite that
    carries the recorded mtime is not a change ``git diff`` reports — and the
    ledger rewritten that way beside a gate file is a gate-only proposal that
    returns before the ledger is read.

    Measured at 5c2743d with ``WORKING_TREE_SCAN_OPTIONS`` emptied: ``git
    diff --name-only <base>`` answers with nothing at all for this tree, and
    the gate accepts it as ``thesis-facts append check OK: gate-only proposal;
    DATA_SURFACE unchanged; GATE_SURFACE changes=['scripts/check_append.py']``.
    With the options on the command line the same read names
    ``ledger/official_observations.jsonl`` and the proposal is mixed."""

    candidate = base_repository(tmp_path)
    git(candidate.root, "config", "core.trustctime", "false")
    git(candidate.root, "config", "core.checkStat", "minimal")
    rewrite_the_ledger_past_a_minimal_stat_cache(candidate)
    add_gate_file(candidate)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "mixed data/gate proposal is forbidden: DATA_SURFACE changes="
        "['ledger/official_observations.jsonl']; GATE_SURFACE changes="
        f"['{GATE_FILE}']; split them into separate pull requests"
    )


def test_an_untracked_cache_cannot_hide_a_new_file_on_the_data_surface(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F2 for the setting the earlier guard could not have caught by
    reading configuration at all. ``core.untrackedCache`` is documented as
    ``keep`` when unset, so an untracked-cache extension written into the index
    by any earlier command — ``git update-index --untracked-cache``, or
    ``feature.manyFiles``, which turns the setting on by itself — stays in use
    in a checkout whose configuration says nothing. The tree here is the one
    that cache can answer wrongly: a decoy removed and a new ledger sibling
    created in its place, so the directory keeps its size, with its recorded
    mtime restored over the change.

    What that costs, measured on this machine (macOS 15, APFS, git 2.53.0):
    ``git status --porcelain`` in exactly this tree answers ``?? ledger/
    decoy.jsonl`` beside the gate file's own directory — the stale listing,
    naming the file that is gone and missing ``ledger/shadow.jsonl``, which is
    there — while ``git ls-files --others --exclude-standard``, the read this
    classification actually makes, answers with ``ledger/shadow.jsonl`` and the
    gate file, with or without the options. ``ls-files`` does not consult the untracked
    cache on this git (``GIT_TRACE2_PERF`` shows the same directories visited
    cached and uncached), so this case binds the option's presence on the
    command line rather than a miss it prevents here — and the option is what
    keeps the answer independent of which reads a later git decides to serve
    from that cache.

    Either way the gate's answer is the one asserted below, and it is the same
    at 5c2743d with ``WORKING_TREE_SCAN_OPTIONS`` emptied."""

    candidate = base_repository(tmp_path)
    ledger_directory = candidate.root / CHAIN_SPEC.state_relative.parent
    (ledger_directory / "decoy.jsonl").write_text("{}\n", encoding="utf-8")
    git(candidate.root, "config", "core.untrackedCache", "true")
    past = 1_600_000_000_000_000_000
    for _ in range(3):
        os.utime(ledger_directory, ns=(past, past))
        git(candidate.root, "status", "--porcelain")

    size_before = os.stat(ledger_directory).st_size
    (ledger_directory / "decoy.jsonl").unlink()
    (ledger_directory / "shadow.jsonl").write_text("{}\n", encoding="utf-8")
    os.utime(ledger_directory, ns=(past, past))
    assert os.stat(ledger_directory).st_size == size_before
    add_gate_file(candidate)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "mixed data/gate proposal is forbidden: DATA_SURFACE changes="
        "['ledger/shadow.jsonl']; GATE_SURFACE changes="
        f"['{GATE_FILE}']; split them into separate pull requests"
    )


CLASSIFICATION_READS = ("diff", "ls-files", "diff-index")


def test_every_git_read_spells_out_the_cache_settings(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S5-F2's own subject, stated about the command lines rather than about
    one arrangement each option defends against. Whether a given git read is
    served from a stat cache, an untracked cache or a monitor is git's business
    and can change between versions; what this package can say is that no read
    it makes is allowed to consult one. So every command line is captured over
    an ordinary verdict and each is required to carry all five options — the
    three reads the classification is built from named explicitly, since those
    are the ones the finding is about."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    seen: list[list[str]] = []
    real_run = subprocess.run

    def record(arguments: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(arguments, list) and arguments[:1] == ["git"]:
            seen.append(list(arguments))
        return real_run(arguments, *args, **kwargs)

    monkeypatch.setattr(append_gate.subprocess, "run", record)
    monkeypatch.setattr(release_chain.subprocess, "run", record)
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )

    options = list(release_chain.WORKING_TREE_SCAN_OPTIONS)
    assert options == [
        "-c",
        "core.untrackedCache=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.trustctime=true",
        "-c",
        "core.checkStat=default",
        "-c",
        "feature.manyFiles=false",
    ]
    subcommands = set()
    for arguments in seen:
        # ``git config`` asks what a setting is, so it must NOT be answered
        # with an override of that setting; every other read carries them.
        if arguments[1] == "-C" and arguments[3] == "config":
            assert "-c" not in arguments
            continue
        assert arguments[1 : 1 + len(options)] == options, arguments
        subcommands.add(arguments[1 + len(options)])
    assert set(CLASSIFICATION_READS) <= subcommands, subcommands


def test_the_classification_reads_leave_an_untracked_cache_alone(
    tmp_path: pathlib.Path,
) -> None:
    """The one thing ``core.untrackedCache=false`` could have cost, ruled out.
    Git removes an untracked-cache extension from an index it writes under that
    setting, and the tree under audit is not this verifier's to modify. None of
    the reads here writes the index — ``diff``, ``ls-files`` and ``diff-index``
    do not — so the extension the candidate carried before the verdict is the
    extension it carries after, byte for byte."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(candidate.root, "update-index", "--untracked-cache")
    git(candidate.root, "status", "--porcelain")
    index = candidate.root / ".git" / "index"
    before = index.read_bytes()
    assert b"UNTR" in before

    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )
    assert index.read_bytes() == before


def test_a_checkout_that_configures_every_cache_verifies_normally(
    tmp_path: pathlib.Path,
) -> None:
    """S5-F2's other side, and the reason the settings guard had to go rather
    than be extended. Each of these settings is something a working copy is
    entitled to configure for its own sake, and a checkout that configures all
    of them is not thereby a proposal to refuse: the reads answer for the tree
    regardless, on both paths, and an ordinary append keeps the verdict it has
    always had. At ccc20b4 each of the four was a refusal naming its setting.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    a_lying_file_system_monitor(candidate)
    for key, value in (
        ("core.trustctime", "false"),
        ("core.checkStat", "minimal"),
        ("core.untrackedCache", "keep"),
        ("feature.manyFiles", "true"),
    ):
        git(candidate.root, "config", key, value)

    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )
    assert run_push_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1"
    )


def test_an_invalid_base_ref_is_refused_before_the_checkout_guard(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F5: the guard used to run before the base ref was resolved, so a
    false core.fileMode masked an unresolvable base — the run blamed the
    checkout for a proposal that never named a real commit. The base is
    resolved first now, and this refusal is the one that predates the guard."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(candidate.root, "config", "core.fileMode", "false")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate, base_ref="refs/heads/does-not-exist")
    assert str(refusal.value).startswith(
        "git rev-parse --verify --end-of-options "
        "refs/heads/does-not-exist^{commit} failed:"
    )


def test_the_release_history_pass_resolves_the_base_before_its_checkout_guard(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F5 at the release-chain level: the guard ran before
    resolve_base_commit, so a false core.fileMode answered a base ref that
    names nothing with a complaint about the checkout. Called directly — the
    gate resolves the base itself and passes an OID — the refusal must be the
    unresolvable ref."""

    candidate = base_repository(tmp_path)
    git(candidate.root, "config", "core.fileMode", "false")

    with pytest.raises(ReleaseChainError) as refusal:
        release_chain.verify_release_history_immutable(
            candidate.root, "refs/heads/does-not-exist", spec=CHAIN_SPEC
        )
    assert str(refusal.value).startswith(
        "cannot resolve base ref 'refs/heads/does-not-exist' to a commit:"
    )


def test_a_symlink_staged_over_a_regular_state_file_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F2: the checkout settings do not prove how the tree was
    materialised. With core.symlinks true and the index holding a 120000
    entry for the ledger, a working tree that carries a plain file there is
    not what git recorded — the exact shape core.symlinks false produces, and
    the shape a filesystem without symlinks leaves behind whatever the config
    says. Nothing compared the two, so the byte and mode checks ran on a
    regular file while git held a link.

    R5-F3 moved which refusal the gate gives for this tree: a 120000 entry
    for a state path is not a tracked regular file, and the entry check says
    so before anything reads the file at all. The comparison this case was
    written for is asserted directly below, so both remain bound."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    target = candidate.root / "link-target"
    target.write_text("outside.jsonl", encoding="utf-8")
    blob = git(candidate.root, "hash-object", "-w", "link-target")
    target.unlink()
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"120000,{blob},{CHAIN_SPEC.state_relative.as_posix()}",
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path ledger/official_observations.jsonl has a non-regular "
        "index entry: 120000"
    )
    with pytest.raises(ReleaseChainError) as compared:
        release_chain.assert_index_agrees_with_tree(
            candidate.root, CHAIN_SPEC.state_relative
        )
    assert str(compared.value) == (
        "candidate index records a symlink at ledger/official_observations.jsonl "
        "but the working tree holds a regular file"
    )


def test_a_state_file_whose_mode_the_working_tree_lost_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F2: core.fileMode true is a claim, not evidence. Here the index
    records the ledger executable and the working tree does not carry the bit
    — a checkout on a filesystem that dropped it, or one that was chmodded
    behind git's back. The base comparison would have read the tree's 100644
    as the proposal's own mode; it refuses to compare instead."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(
        candidate.root,
        "update-index",
        "--chmod=+x",
        "--",
        CHAIN_SPEC.state_relative.as_posix(),
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "candidate working tree mode for ledger/official_observations.jsonl "
        "disagrees with its index entry (100755 vs 100644)"
    )


def test_a_release_file_whose_mode_the_working_tree_lost_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F2 at the other call site: the release-history pass compares the
    same kind of stat for every base release file, and it is evidence under
    the same condition. This refusal comes from that pass, before the state
    files are reached."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(candidate.root, "update-index", "--chmod=+x", "--", "releases/README.md")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "candidate working tree mode for releases/README.md disagrees with "
        "its index entry (100755 vs 100644)"
    )


def test_the_index_check_passes_over_a_path_the_index_does_not_hold(
    tmp_path: pathlib.Path,
) -> None:
    """The other half of F2: a new untracked file has no index entry to
    disagree with, so there is nothing to compare and nothing to refuse —
    without which every release proposal, which adds files, would refuse."""

    candidate = base_repository(tmp_path)
    (candidate.root / "NOTES.md").write_text("new\n", encoding="utf-8")

    release_chain.assert_index_agrees_with_tree(candidate.root, "NOTES.md")


@contextlib.contextmanager
def time_limit(seconds: float) -> Iterator[None]:
    """Fail rather than hang: a blocked open cannot be interrupted otherwise.

    The gap the snapshot reader closes includes a reader that waits forever on
    a FIFO, so the test for it must be able to say "did not return" instead of
    stalling the suite.
    """

    def expire(_signum: int, _frame: Any) -> None:
        raise TimeoutError(f"the gate did not return within {seconds}s")

    previous = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="the platform has no FIFOs to refuse"
)
def test_a_fifo_at_the_ledger_path_is_refused_rather_than_waited_on(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F3: the state read was check-then-open. The component walk sees
    no symlink at a FIFO, so the reader that followed opened it — and an open
    of a FIFO with no writer blocks until one arrives, which for a proposal
    that plants one is never. The gate stalls, holding CI, with no verdict.
    The reader now lstats first and opens with O_NONBLOCK, so this returns
    immediately; the time limit is what would fail if it did not."""

    candidate = base_repository(tmp_path)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.unlink()
    os.mkfifo(ledger)

    with time_limit(20), pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file is not a regular file: ledger/official_observations.jsonl"
    )


@pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="the platform has no FIFOs to refuse"
)
def test_a_fifo_at_the_prefix_path_is_refused_rather_than_waited_on(
    tmp_path: pathlib.Path,
) -> None:
    """F3 for the other state file: the frozen prefix is read by the same
    reader, at the point check_prefix used to walk and open it, so a FIFO
    there is refused the same way and just as promptly instead of stalling
    the run."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    prefix = candidate.root / CHAIN_SPEC.prefix_relative
    prefix.unlink()
    os.mkfifo(prefix)

    with time_limit(20), pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file is not a regular file: ledger/immutable_prefix.json"
    )


def test_a_state_file_swapped_between_the_check_and_the_open_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F3's other half of the check-then-open gap: the file the walk
    inspected and the file the reader opened were resolved separately, so the
    final component could be swapped in between and the bytes verified were
    never the ones checked. Standing in a different file for every lstat of
    the ledger path reproduces exactly that; the open's fstat no longer
    matches what the check saw, and the run refuses instead of reading on."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    decoy = tmp_path / "decoy.jsonl"
    decoy.write_text("{}\n", encoding="utf-8")
    real_lstat = os.lstat

    def swapped(path: Any, *arguments: Any, **keywords: Any) -> os.stat_result:
        try:
            named = os.fspath(path)
        except TypeError:
            return real_lstat(path, *arguments, **keywords)
        if named == os.fspath(ledger):
            return real_lstat(decoy)
        return real_lstat(path, *arguments, **keywords)

    monkeypatch.setattr(os, "lstat", swapped)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file was replaced while it was being read: "
        "ledger/official_observations.jsonl"
    )


def rewrite_ledger_inside(
    candidate: Candidate, monkeypatch: pytest.MonkeyPatch, rows: int
) -> None:
    """Let check_rows return, then rewrite the ledger before the next consumer.

    check_rows is the last consumer of the parsed rows before the release
    verification opens the ledger again, so this is the window in which one
    tree could satisfy the row checks with one ledger and the release chain
    with another.
    """

    checked = append_gate.check_rows

    def rewrite(lines: list[str], prefix_count: int, spec: AppendGateSpec) -> None:
        checked(lines, prefix_count, spec)
        write_ledger(
            candidate.root,
            [observation_row(number) for number in range(1, rows + 1)],
        )

    monkeypatch.setattr(append_gate, "check_rows", rewrite)


def test_a_ledger_rewritten_between_consumers_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F3: the ledger was opened once for the row checks and again by
    the release verification, so a proposal that rewrote it in between got a
    verdict assembled from two different files — the row count, the prefix
    hashes, and the append count from the first, the byte-append and release
    state from the second. Every consumer in append_gate is now fed the one
    snapshot, and the re-check at the end refuses a tree that moved."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    rewrite_ledger_inside(candidate, monkeypatch, rows=BASE_ROW_COUNT + 2)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file changed during verification: "
        "ledger/official_observations.jsonl"
    )
    # The rewrite really did land: the refusal is about the tree, not a
    # rewrite that never happened.
    ledger = candidate.root / CHAIN_SPEC.state_relative
    assert len(ledger.read_text(encoding="utf-8").splitlines()) == BASE_ROW_COUNT + 2


def test_a_prefix_manifest_rewritten_between_consumers_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F3 for the other state file: the frozen prefix is what the release
    verification re-reads and what every base comparison was made from, so it
    is re-checked the same way. Without the re-check the run answered about a
    manifest that no longer existed."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    checked = append_gate.check_rows

    def rewrite(lines: list[str], prefix_count: int, spec: AppendGateSpec) -> None:
        checked(lines, prefix_count, spec)
        prefix = candidate.root / CHAIN_SPEC.prefix_relative
        prefix.write_text(prefix.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    monkeypatch.setattr(append_gate, "check_rows", rewrite)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file changed during verification: ledger/immutable_prefix.json"
    )


def test_a_ledger_replaced_by_an_identical_copy_mid_verdict_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The identity half of F3's re-check, which bytes alone cannot see: the
    ledger is replaced mid-run by a different file holding the same bytes.
    Nothing downstream would notice — every byte comparison still holds — but
    the file this verdict read is gone, and whatever replaced it was never
    the one the walk, the lstat, and the open agreed on."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    checked = append_gate.check_rows

    def replace(lines: list[str], prefix_count: int, spec: AppendGateSpec) -> None:
        checked(lines, prefix_count, spec)
        payload = ledger.read_bytes()
        ledger.unlink()
        ledger.write_bytes(payload)

    monkeypatch.setattr(append_gate, "check_rows", replace)
    before = ledger.stat()

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file changed during verification: "
        "ledger/official_observations.jsonl"
    )
    # Same bytes, different file: only the recorded identity says so. A
    # filesystem may hand the replacement the inode it just freed (ext4 does,
    # APFS does not), in which case the inode change time is what still
    # distinguishes the two; either way the identity the run recorded no
    # longer holds.
    after = ledger.stat()
    assert (after.st_ino, after.st_ctime_ns) != (before.st_ino, before.st_ctime_ns)


def test_a_state_file_that_cannot_be_re_read_is_refused_as_changed(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A re-read that cannot be completed at all is the same answer: the file
    changed. Here the ledger becomes a link to bytes outside the tree after
    the last consumer, which the re-read's component walk refuses — and the
    caller reports the change, because the run had already answered about the
    file that was there."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    compared = append_gate.check_state_modes

    def relink(base: Any, tree: Any, **keywords: Any) -> None:
        compared(base, tree, **keywords)
        ledger = candidate.root / CHAIN_SPEC.state_relative
        outside = tmp_path / "outside.jsonl"
        shutil.move(str(ledger), str(outside))
        ledger.symlink_to(outside)

    monkeypatch.setattr(append_gate, "check_state_modes", relink)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file changed during verification: "
        "ledger/official_observations.jsonl"
    )


def test_an_unchanged_tree_passes_the_re_read(tmp_path: pathlib.Path) -> None:
    """The acceptance F3 must not disturb: an ordinary proposal is the same
    file with the same bytes at the end, and gets the verdict text it got
    before the snapshot reader existed."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)

    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_a_conflicted_index_entry_is_refused(tmp_path: pathlib.Path) -> None:
    """The remaining index state F2 has to answer for: a conflicted merge
    records stages 1-3 and no single mode for the path, so there is nothing
    for the working tree to agree with and no basis for comparing modes.
    Refuse rather than pick one of the stages."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    relative = CHAIN_SPEC.state_relative.as_posix()
    blob = git(candidate.root, "rev-parse", f"HEAD:{relative}")
    git(candidate.root, "rm", "--cached", "--quiet", "--", relative)
    git(
        candidate.root,
        "update-index",
        "--index-info",
        stdin=f"100644 {blob} 1\t{relative}\n100644 {blob} 2\t{relative}\n",
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "candidate index holds an unmerged entry at "
        "ledger/official_observations.jsonl"
    )


def test_file_level_release_refusals_precede_the_index_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """The per-file index check runs after the comparisons it qualifies.

    An unstaged chmod on a base release file is both a mode change against
    the base and an index/worktree disagreement. The upstream verifier
    refuses it as a mode change, and the ledger differential harness pins
    that text (`base_mode_change`), so the index refusal must not pre-empt
    it: a comparison that passed fail-open is caught afterwards instead.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.chmod(readme.stat().st_mode | 0o111)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        f"existing release file mode changed relative to {candidate.base}: "
        "releases/README.md (100644 -> 100755)"
    )


def test_a_ledger_swapped_and_restored_inside_the_release_pass_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R5-F1: the closing re-read could be satisfied by a restoration.

    A candidate that swaps the ledger while the release verification runs and
    puts the original back before the run ends is invisible to a comparison
    over device, inode, size, and modification time: writing the bytes back
    in place keeps the first three, and ``os.utime`` restores the fourth.
    That is the second half of the A-to-B-to-A hole — the first half, the
    release verification reading the path again rather than being handed
    what this run read, is bound in tests/test_release_chain.py, where a
    chain exists to verify. The identity now carries ``st_ctime_ns``, which
    the kernel stamps on every metadata write and no caller can set back.
    Without it this run is accepted, with a verdict about a file that was
    not there for the whole of it.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    original = ledger.read_bytes()
    before = ledger.stat()
    verified = append_gate.verify_release_history_immutable

    def swap(root: Any, commit: str, *, spec: Any) -> Any:
        # B, in place: two more rows than the run read, and a valid byte
        # append in its own right, so nothing downstream would object to it.
        write_ledger(
            candidate.root,
            [observation_row(number) for number in range(1, BASE_ROW_COUNT + 3)],
        )
        try:
            return verified(root, commit, spec=spec)
        finally:
            ledger.write_bytes(original)
            os.utime(ledger, ns=(before.st_atime_ns, before.st_mtime_ns))

    monkeypatch.setattr(append_gate, "verify_release_history_immutable", swap)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file changed during verification: "
        "ledger/official_observations.jsonl"
    )
    # The restoration really was complete in every field the identity carried
    # before this round, so the change time is what refused.
    after = ledger.stat()
    assert ledger.read_bytes() == original
    assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    assert after.st_ctime_ns != before.st_ctime_ns


def test_the_push_path_hands_the_release_verification_its_snapshots(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R5-F1 at the gate: the release verification is given the bytes.

    ``check_release_chain_without_base`` used to let ``verify_release_chain``
    open the ledger and the frozen prefix by name, a second read of each file
    inside one verdict. It now passes the snapshots this run took, keyed by
    their relative POSIX paths. The fixture carries no chain, so the call is
    made directly with the manifest directory stubbed non-empty; what is
    asserted is the mapping the gate hands down.
    """

    candidate = base_repository(tmp_path)
    manifests = candidate.root / CHAIN_SPEC.manifest_relative
    manifests.mkdir(parents=True)
    (manifests / "0000-0000000000000000.json").write_text("{}\n", encoding="utf-8")
    captured: dict[str, Any] = {}

    def capture(root: pathlib.Path, **keywords: Any) -> None:
        captured.update(keywords)
        raise ReleaseChainError("stop before verifying anything")

    monkeypatch.setattr(append_gate, "verify_release_chain", capture)

    with selected_tree(candidate) as tree, pytest.raises(AppendError):
        append_gate.check_release_chain_without_base(
            candidate=tree,
            ledger_bytes=b"ledger snapshot",
            prefix_bytes=b"prefix snapshot",
        )
    assert captured["state_bytes"] == {
        "ledger/official_observations.jsonl": b"ledger snapshot",
        "ledger/immutable_prefix.json": b"prefix snapshot",
    }


def test_a_state_parent_swapped_after_the_walk_cannot_be_followed(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R5-F2: the parent confinement was still check-then-open.

    The component walk inspects ``ledger/`` and then the reader opens
    ``ledger/official_observations.jsonl`` by pathname, which resolves
    ``ledger/`` all over again — so a checked parent could be replaced with a
    symlink in between and the open would follow it. ``O_NOFOLLOW`` on the
    leaf says nothing about its parents. Here the swap is performed on the
    first ``lstat`` of the ledger path, which is after the walk has cleared
    ``ledger/``, and the target holds a decoy ledger of four self-consistent
    rows over the same frozen prefix.

    Without the descriptor walk the reader follows the swapped parent and
    the snapshot this verdict is built from is four rows from outside the
    checkout. The run does still refuse — the frozen prefix is walked next
    and sees the link that is there by then — but it refuses about
    ``ledger/immutable_prefix.json``, having already read the ledger the
    walk was taken to confine. What is bound here is that the ledger read
    itself refuses, and names the component that moved.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    decoy_root = tmp_path / "outside"
    decoy_rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 3)]
    write_ledger(decoy_root, decoy_rows)
    write_prefix_manifest(decoy_root, decoy_rows)

    ledger = candidate.root / CHAIN_SPEC.state_relative
    directory = candidate.root / "ledger"
    real_lstat = os.lstat
    swapped = {"done": False}

    def swap_then_lstat(path: Any, *arguments: Any, **keywords: Any) -> os.stat_result:
        try:
            named = os.fspath(path)
        except TypeError:
            named = None
        if named == os.fspath(ledger) and not swapped["done"]:
            swapped["done"] = True
            shutil.move(str(directory), str(tmp_path / "real-ledger"))
            directory.symlink_to(decoy_root / "ledger", target_is_directory=True)
        return real_lstat(path, *arguments, **keywords)

    monkeypatch.setattr(os, "lstat", swap_then_lstat)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'ledger': "
        "ledger/official_observations.jsonl"
    )
    # The swap really did happen, and the decoy really was reachable by name.
    assert swapped["done"]
    monkeypatch.undo()
    assert len(ledger.read_text(encoding="utf-8").splitlines()) == BASE_ROW_COUNT + 2


def test_the_state_reader_cannot_follow_a_parent_swapped_after_its_walk(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R5-F2 in the release-chain reader, which has the same two steps.

    ``_regular_file_bytes`` checks the final component, walks the parents,
    and then reads the pathname. Replacing ``ledger/`` immediately after the
    walk returns is the gap; the read now goes through the descriptor walk,
    which cannot resolve that name a second time, and refuses in the walk's
    own words. Both refusals the reader already gave still come first and
    still say what they said.
    """

    root = tmp_path / "repo"
    (root / "ledger").mkdir(parents=True)
    (root / CHAIN_SPEC.state_relative).write_text('{"real":true}\n', encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "official_observations.jsonl").write_text(
        '{"decoy":true}\n', encoding="utf-8"
    )
    walked = release_chain.assert_no_symlinked_state_component

    def walk_then_swap(
        walk_root: pathlib.Path, relative: pathlib.PurePosixPath
    ) -> None:
        walked(walk_root, relative)
        directory = walk_root / "ledger"
        shutil.rmtree(directory)
        directory.symlink_to(outside, target_is_directory=True)

    monkeypatch.setattr(
        release_chain, "assert_no_symlinked_state_component", walk_then_swap
    )

    with pytest.raises(ReleaseChainError) as refusal:
        _regular_file_bytes(root, CHAIN_SPEC.state_relative)
    assert str(refusal.value) == (
        "state path traverses a symlink at 'ledger': "
        "ledger/official_observations.jsonl"
    )


def test_a_gitlink_over_the_ledger_directory_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R5-F3: nothing looked at a state path's ancestors.

    A directory reaches the index only as a gitlink, and a 160000 entry at
    ``ledger`` is a submodule boundary: what lies beneath it belongs to
    another repository and is no part of this commit's content, while
    arriving in the working tree as ordinary regular files that hash, parse,
    and satisfy every byte comparison the gate makes. The index check that
    existed returned on a path the index does not hold — which is exactly
    what a gitlink over it produces — so the whole append ran on files git
    never recorded here.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    for relative in (CHAIN_SPEC.state_relative, CHAIN_SPEC.prefix_relative):
        git(candidate.root, "rm", "--cached", "--quiet", "--", relative.as_posix())
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{candidate.base},ledger",
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path ledger/official_observations.jsonl has an indexed "
        "ancestor ledger (160000)"
    )


def test_an_untracked_ledger_is_refused_as_absent_from_the_index(
    tmp_path: pathlib.Path,
) -> None:
    """The other half of R5-F3's leaf rule: an untracked state file is not
    part of the commit under review. Its bytes are not what a merge would
    take and no diff against the base can reach them, so there is nothing for
    this verdict to be about. The index check that existed treated a path it
    did not hold as nothing to compare, and returned."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(
        candidate.root,
        "rm",
        "--cached",
        "--quiet",
        "--",
        CHAIN_SPEC.state_relative.as_posix(),
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state path ledger/official_observations.jsonl is absent from the "
        "candidate index"
    )


def test_the_push_path_refuses_a_symlink_index_entry_for_the_ledger(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R5-F3 on the push path, which had no state check of any kind.

    With no base ref there is no release-history pass and no
    ``check_state_modes``, so a 120000 index entry standing over a regular
    file — what ``core.symlinks`` false materialises, and what a filesystem
    without symlinks leaves whatever the config claims — reached every byte
    check on this path unexamined. The entry check refuses it on both paths
    now, before anything is read.
    """

    candidate = base_repository(tmp_path)
    target = candidate.root / "link-target"
    target.write_text("outside.jsonl", encoding="utf-8")
    blob = git(candidate.root, "hash-object", "-w", "link-target")
    target.unlink()
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"120000,{blob},{CHAIN_SPEC.state_relative.as_posix()}",
    )

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "state path ledger/official_observations.jsonl has a non-regular "
        "index entry: 120000"
    )


def test_the_push_path_compares_the_state_files_against_the_index(
    tmp_path: pathlib.Path,
) -> None:
    """R5-F3's second push-path gap: the working tree was never compared with
    the index there at all. ``check_state_modes`` carries that comparison on
    the base-ref path and does not run without a base, so a state file whose
    recorded executable bit the checkout did not materialise was accepted.
    The comparison runs on the push path in the position check_state_modes
    occupies on the other one — after every check that existed before it."""

    candidate = base_repository(tmp_path)
    git(
        candidate.root,
        "update-index",
        "--chmod=+x",
        "--",
        CHAIN_SPEC.prefix_relative.as_posix(),
    )

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "candidate working tree mode for ledger/immutable_prefix.json "
        "disagrees with its index entry (100755 vs 100644)"
    )


def test_the_tracked_state_refusal_precedes_pre_existing_row_refusals(
    tmp_path: pathlib.Path,
) -> None:
    """The precedence R5-F3 introduces, stated in the module docstring and
    pinned here: like the checkout guard, the entry check says a comparison
    cannot be made and so runs ahead of the checks that would make it — the
    only other place a refusal added after the extraction pre-empts one the
    upstream gate gives. The same tree carries a row the upstream verifier
    refuses in its own words, and that refusal is what fires once the ledger
    is tracked again."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate, responseArchive={"sha256": "not-a-digest"})
    relative = CHAIN_SPEC.state_relative.as_posix()
    git(candidate.root, "rm", "--cached", "--quiet", "--", relative)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        f"state path {relative} is absent from the candidate index"
    )

    git(candidate.root, "add", "--", relative)
    with pytest.raises(AppendError) as pre_existing:
        run_gate(candidate)
    assert "responseArchive.sha256 is not a SHA-256 hex digest" in str(
        pre_existing.value
    )


def stage_release_gitlink(candidate: Candidate) -> None:
    """Record a gitlink under ``releases/`` that nothing has checked out.

    An empty or uninitialised submodule directory is the ordinary state of a
    fresh checkout, and it is the case the filesystem walk cannot see at all:
    there is no directory on disk to skip, and no file to enumerate.
    """

    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{candidate.base},releases/vendor",
    )


def test_a_gitlink_under_the_release_root_is_refused_against_a_base(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R5-F4: the release root's content was taken from a walk.

    ``_working_release_files`` enumerates the release tree from the
    filesystem and skips directories, so an uninitialised gitlink under
    ``releases/`` is in neither the current files nor the new files. The
    release-proposal rules assert the release root holds exactly what that
    walk found, while the index records a boundary into another repository
    inside it — and on the data path no refusal spoke for the difference.
    The base-tree scan refuses a non-regular mode only once such an entry is
    in the base; this is the same entry, in the candidate.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    stage_release_gitlink(candidate)
    # The walk really is blind to it: nothing exists at that path on disk.
    assert not (candidate.root / "releases" / "vendor").exists()

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "release root carries an unsupported index entry: "
        "releases/vendor (160000)"
    )


def test_a_gitlink_under_the_release_root_is_refused_on_the_push_path(
    tmp_path: pathlib.Path,
) -> None:
    """R5-F4 on the push path, which runs none of the base-tree comparisons
    and, with no chain to verify, returned before looking at the release root
    at all. The scan runs there ahead of that early return."""

    candidate = base_repository(tmp_path)
    stage_release_gitlink(candidate)

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "release root carries an unsupported index entry: "
        "releases/vendor (160000)"
    )


def test_a_release_directory_the_index_holds_an_entry_for_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """R5-F4's other half: a directory the walk does find, standing where the
    index records a file. The mode scan calls that entry supported, because
    100644 is supported; what is wrong is that the working tree does not hold
    a file there, and the walk skipped it in silence. A populated gitlink is
    the same shape with an unsupported mode, and the scan above catches
    that."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    blob = git(candidate.root, "hash-object", "-w", "releases/README.md")
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},releases/vendor",
    )
    (candidate.root / "releases" / "vendor").mkdir()

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "release path is a directory with an index entry: "
        "releases/vendor (100644)"
    )


def test_file_level_release_refusals_precede_the_release_root_index_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """R5-F4's placement, pinned the way the per-file index check's is.

    The release root's index scan is new, so it runs after every comparison
    the release-history pass already made: a tree that both rewrites a base
    release file and stages a gitlink beside it gets the byte refusal the
    upstream verifier gives, which the ledger differential harness pins, not
    the scan's.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.write_text("Rewritten beside a gitlink.\n", encoding="utf-8")
    stage_release_gitlink(candidate)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        f"existing release file bytes changed relative to {candidate.base}: "
        "releases/README.md"
    )


def replace_release_root_with_a_tracked_file(candidate: Candidate) -> None:
    """Stage a regular file where ``releases/`` stood, as a commit may do.

    Git records this perfectly happily: one blob at ``releases``, and every
    path that was under it gone from the index. The working tree then has no
    release directory at all.
    """

    releases = candidate.root / CHAIN_SPEC.release_root_relative
    shutil.rmtree(releases)
    releases.write_text("releases is a file now.\n", encoding="utf-8")
    git(candidate.root, "add", "-A")


def test_the_push_path_refuses_a_tracked_file_standing_for_the_release_root(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R6-F1: the release-root scan returned when the root was not a
    directory, and every other release check on the push path is reached
    through the manifest directory. A commit that replaces ``releases/`` with
    a tracked regular file therefore makes chain initialisation false — there
    is no ``releases/manifests`` to find — and the gate accepted the tree with
    the whole chain gone, naming no release. The index says otherwise, and is
    now read against the filesystem: an entry under the root with no
    directory to hold it refuses."""

    candidate = base_repository(tmp_path)
    replace_release_root_with_a_tracked_file(candidate)
    # The manifest directory really is unreachable, which is what made this
    # an acceptance rather than a refusal.
    assert not (candidate.root / CHAIN_SPEC.manifest_relative).is_dir()

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "release root is not a directory while the index records 1 entry "
        "under it"
    )


def test_a_tracked_file_standing_for_the_release_root_is_refused_with_a_base(
    tmp_path: pathlib.Path,
) -> None:
    """R6-F1 on the base-ref path, where a pre-existing refusal gets there
    first and must keep doing so: ``_working_release_files`` enumerates the
    release tree before any of this PR's checks and refuses a root that is
    not a real directory in the words the extraction gave it. The reconciled
    scan is asserted directly on the same tree, so both are bound and the
    order between them is pinned."""

    candidate = base_repository(tmp_path)
    replace_release_root_with_a_tracked_file(candidate)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "releases must be a real directory, not a symlink"
    with pytest.raises(ReleaseChainError) as scanned:
        release_chain.assert_release_root_index_regular(candidate.root, CHAIN_SPEC)
    assert str(scanned.value) == (
        "release root is not a directory while the index records 1 entry "
        "under it"
    )


def test_the_push_path_refuses_a_release_entry_the_working_tree_lost(
    tmp_path: pathlib.Path,
) -> None:
    """R6-F1's other direction: a stage-0 regular entry the filesystem walk
    cannot find. ``_working_release_files`` derives the release files from the
    working tree, so a release file deleted from disk — or never materialised,
    as a sparse checkout leaves it — was simply not among them, and the push
    path, which makes no base comparison, had nothing that would notice. The
    index records the commit under review; every entry it holds must be on
    disk as a regular file."""

    candidate = base_repository(tmp_path)
    (candidate.root / CHAIN_SPEC.release_root_relative / "README.md").unlink()

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "release file recorded in the index is absent or not a regular file: "
        "releases/README.md"
    )


def test_a_release_entry_the_working_tree_lost_is_refused_against_a_base(
    tmp_path: pathlib.Path,
) -> None:
    """R6-F1 on the base-ref path, for an entry the base does not carry: a
    release file staged by the proposal and then removed from the working
    tree. A base release file removed the same way already had a refusal —
    the per-file loop says it was deleted relative to the base — but this one
    is in neither the base tree nor the walk, so it was in ``new_files``
    nowhere and no release-proposal rule was ever applied to it."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    extra = candidate.root / CHAIN_SPEC.release_root_relative / "extra.md"
    extra.write_text("staged, then removed from the working tree.\n", encoding="utf-8")
    git(candidate.root, "add", "--", "releases/extra.md")
    extra.unlink()

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "release file recorded in the index is absent or not a regular file: "
        "releases/extra.md"
    )


def test_a_ledger_rewritten_during_the_prefix_re_check_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R6-F2: the closing re-checks were sequential, one per file.

    The ledger was re-checked, then the frozen prefix, and nothing looked at
    the ledger again — so a writer that waits for the ledger's re-check to
    return and rewrites the ledger while the prefix is being re-checked gets
    an acceptance. The verdict then reports a row count, a prefix hash, an
    append count, and a release index measured on a ledger the tree no longer
    holds, with the last look at that file taken before the rewrite.

    The re-check now runs the files forwards and then backwards — ledger,
    prefix, prefix, ledger — so the rewrite is seen by the ledger's second
    re-read. The recorded call order is asserted because it is the whole
    point: the mutation lands strictly after a ledger re-check that passed,
    which is exactly the run the old order accepted.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = CHAIN_SPEC.state_relative.as_posix()
    prefix = CHAIN_SPEC.prefix_relative.as_posix()
    read = append_gate._read_state_snapshot
    asked: list[str] = []

    def read_then_rewrite(
        relative: pathlib.PurePosixPath, tree: Any
    ) -> append_gate._StateSnapshot:
        asked.append(relative.as_posix())
        snapshot = read(relative, tree)
        # The second time the prefix is asked for is the first prefix
        # re-check, which is after the ledger's own re-check has returned.
        if relative.as_posix() == prefix and asked.count(prefix) == 2:
            write_ledger(
                candidate.root,
                [observation_row(number) for number in range(1, BASE_ROW_COUNT + 3)],
            )
        return snapshot

    monkeypatch.setattr(append_gate, "_read_state_snapshot", read_then_rewrite)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file changed during verification: "
        "ledger/official_observations.jsonl"
    )
    assert asked == [ledger, prefix, ledger, prefix, prefix, ledger]
    # The rewrite really landed, and really was a different ledger.
    written = candidate.root / CHAIN_SPEC.state_relative
    assert len(written.read_text(encoding="utf-8").splitlines()) == BASE_ROW_COUNT + 2


def test_a_state_parent_exchanged_after_the_snapshot_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R6-F3: the closing re-check compared the leaf and nothing else.

    Device, inode, size, modification time and change time are all
    properties of the file, not of where it is, so a candidate can exchange
    ``ledger/`` for a different directory holding a hard link to the same
    inode and every one of them still agrees. The bytes agree too. What has
    changed is the directory the state path resolves through — the thing the
    component walk and the descriptor walk exist to pin — and afterwards the
    candidate owns it: the next run, and every reader that is not this one,
    follows the new parent.

    The snapshot now records the identity of every directory descriptor the
    walk opened, and the re-check compares those as well. The assertions
    below show that nothing else could have refused: the leaf's whole stat
    and its bytes are what they were, and only the parent's inode moved.
    """

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    directory = candidate.root / "ledger"
    ledger = candidate.root / CHAIN_SPEC.state_relative
    twin = tmp_path / "twin"
    twin.mkdir()
    for name in ("official_observations.jsonl", "immutable_prefix.json"):
        # Linked before the run, so the change time the link bumps is already
        # the one the snapshot records.
        os.link(directory / name, twin / name)
    payload = ledger.read_bytes()
    before = ledger.stat()
    directory_before = directory.stat().st_ino
    checked = append_gate.check_rows

    def exchange(lines: list[str], prefix_count: int, spec: AppendGateSpec) -> None:
        checked(lines, prefix_count, spec)
        shutil.move(str(directory), str(tmp_path / "real-ledger"))
        shutil.move(str(twin), str(directory))

    monkeypatch.setattr(append_gate, "check_rows", exchange)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state file changed during verification: "
        "ledger/official_observations.jsonl"
    )
    after = ledger.stat()
    assert ledger.read_bytes() == payload
    assert (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) == (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    assert directory.stat().st_ino != directory_before


def test_check_state_modes_takes_the_mode_from_the_snapshot(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R6-F3's other half: the base mode comparison resolved the state
    path all over again to read its mode, so what it compared was about
    whatever the name reached by then rather than about the file this run
    read — and the index comparison after it resolved the name a third time.
    Here every ``Path.stat`` and ``Path.lstat`` of the ledger reports an
    executable bit the file does not carry. Through the gate the snapshot's
    own ``fstat`` is what answers and the ordinary verdict stands; called on
    its own, with no snapshot to take, the same function believes the lie and
    refuses. The tree is identical in both, so the difference is only where
    the mode came from. (Both reads are made to lie because R7-F5 moved that
    fallback from ``stat`` to ``lstat``, which is the read that can also tell
    a link from a file.)"""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root.resolve() / CHAIN_SPEC.state_relative

    def executable(observed: os.stat_result) -> os.stat_result:
        return os.stat_result((observed.st_mode | 0o111, *tuple(observed)[1:]))

    real_stat = pathlib.Path.stat
    real_lstat = pathlib.Path.lstat

    def lying_stat(self: pathlib.Path, **keywords: Any) -> os.stat_result:
        observed = real_stat(self, **keywords)
        if os.fspath(self) != os.fspath(ledger):
            return observed
        return executable(observed)

    def lying_lstat(self: pathlib.Path, *arguments: Any) -> os.stat_result:
        observed = real_lstat(self, *arguments)
        if os.fspath(self) != os.fspath(ledger):
            return observed
        return executable(observed)

    monkeypatch.setattr(pathlib.Path, "stat", lying_stat)
    monkeypatch.setattr(pathlib.Path, "lstat", lying_lstat)

    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )
    with selected_tree(candidate) as tree, pytest.raises(AppendError) as refusal:
        append_gate.check_state_modes(
            append_gate._BaseCommit(ref=candidate.base, commit=candidate.base),
            tree,
        )
    assert str(refusal.value) == (
        "state file mode changed relative to base: "
        "ledger/official_observations.jsonl"
    )


def test_state_reads_refuse_a_platform_without_secure_descent(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R6-F4: the descriptor walk fell back to the pathname open where
    ``os.open`` takes no ``dir_fd``, which is the behaviour every check in
    that walk exists to replace — the whole path resolved a second time, with
    the walk's findings about the parents already stale, and no refusal
    anywhere saying the confinement had lapsed. A verifier that quietly
    weakens itself on some platforms states an invariant it does not hold
    there. It now says it cannot read the state files instead. Both readers
    go through the same helper, so both say it.

    The message also names the requirement as the package's, which is S4-F6:
    ``release_chain``'s reader is the one ``verify_release_chain`` uses, so
    the same refusal stops ``receipt verify``'s custody pass and not only
    this gate."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    without_open = frozenset(os.supports_dir_fd) - {os.open}
    monkeypatch.setattr(os, "supports_dir_fd", without_open)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "state files cannot be read with secure descent on this platform "
        "(os.open lacks dir_fd support); receipt requires a POSIX platform"
    )
    with pytest.raises(ReleaseChainError) as read:
        _regular_file_bytes(candidate.root, CHAIN_SPEC.state_relative)
    assert str(read.value) == (
        "state files cannot be read with secure descent on this platform "
        "(os.open lacks dir_fd support); receipt requires a POSIX platform"
    )


def test_a_root_that_is_not_the_recorded_one_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R6-F4's other half: the candidate root was the one component of every
    state path that nothing vouched for. The walk below it starts at the root
    and checks what it finds *inside* it, and the descriptor open took the
    root by name with neither ``O_NOFOLLOW`` nor an identity check — so a
    root exchanged for another directory, or for a link to one, was simply
    the tree every subsequent read descended from. ``_set_root`` records the
    resolved root's identity once, and every descent compares against it.
    Here the recorded identity is made to differ from the root on disk; the
    same tree with the identity it really has gets the ordinary verdict, so
    the comparison is what refused."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    real_set_root = append_gate._set_root

    def misrecord(root: pathlib.Path, spec: AppendGateSpec) -> Any:
        tree = real_set_root(root, spec)
        device, inode = tree.root_identity
        return replace(tree, root_identity=(device, inode + 1))

    monkeypatch.setattr(append_gate, "_set_root", misrecord)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "candidate root changed during verification"

    monkeypatch.undo()
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_a_root_relinked_between_the_two_state_reads_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R6-F4 driven by an actual swap rather than a recorded one: the root is
    moved aside and a symlink left in its place after the ledger has been
    read and before the frozen prefix is. Every git command still resolves,
    the component walk still finds real directories inside the root — it
    never looks at the root itself — and before this round the prefix was
    read through the link without complaint. The root open now refuses to
    follow it, and for a caller that recorded the root that is the same
    answer as an identity that does not match."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    checked = append_gate.reject_non_append_bytes

    def relink_root(text: str) -> None:
        checked(text)
        moved = tmp_path / "real-candidate"
        shutil.move(str(candidate.root), str(moved))
        candidate.root.symlink_to(moved, target_is_directory=True)

    monkeypatch.setattr(append_gate, "reject_non_append_bytes", relink_root)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "candidate root changed during verification"
    # The link really is there, and really does still resolve to the tree.
    assert candidate.root.is_symlink()
    assert (candidate.root / CHAIN_SPEC.prefix_relative).is_file()


def test_the_index_comparison_uses_a_category_the_caller_supplies(
    tmp_path: pathlib.Path,
) -> None:
    """R6-F3 at the comparison itself. ``assert_index_agrees_with_tree`` read
    the working tree by resolving the path, which for a state file is a
    resolution after the read that established the file and after the mode
    comparison that precedes this call. It takes an already-observed category
    instead when the caller has one. Here the tree carries an executable bit
    the index does not record, so resolving the path refuses; supplied the
    category a descriptor observed, the same call compares that and returns.
    A caller that supplies nothing — every caller that predates the parameter
    — gets the first behaviour, which is the one asserted first."""

    candidate = base_repository(tmp_path)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.chmod(ledger.stat().st_mode | 0o111)

    with pytest.raises(ReleaseChainError) as refusal:
        release_chain.assert_index_agrees_with_tree(
            candidate.root, CHAIN_SPEC.state_relative
        )
    assert str(refusal.value) == (
        "candidate working tree mode for ledger/official_observations.jsonl "
        "disagrees with its index entry (100644 vs 100755)"
    )
    release_chain.assert_index_agrees_with_tree(
        candidate.root, CHAIN_SPEC.state_relative, observed="100644"
    )


def test_the_push_paths_index_comparison_takes_the_snapshots_category(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R6-F3 at the push path's own call site, which is the only index
    comparison that path makes: it resolved the state path once more, after
    the read that had the file open. Every ``Path.lstat`` of the ledger here
    reports an executable bit the file does not carry — what that second
    resolution could be shown — and the gate answers ordinarily, because the
    category comes from the snapshot. Asked to resolve the path itself, the
    same comparison on the same tree refuses."""

    candidate = base_repository(tmp_path)
    ledger = candidate.root.resolve() / CHAIN_SPEC.state_relative
    real_lstat = pathlib.Path.lstat

    def lying_lstat(self: pathlib.Path, *arguments: Any) -> os.stat_result:
        observed = real_lstat(self, *arguments)
        if os.fspath(self) != os.fspath(ledger):
            return observed
        return os.stat_result((observed.st_mode | 0o111, *tuple(observed)[1:]))

    monkeypatch.setattr(pathlib.Path, "lstat", lying_lstat)

    assert run_push_gate(candidate) == (
        "thesis-facts append check OK: 2 rows, immutable prefix 1"
    )
    with pytest.raises(ReleaseChainError) as refusal:
        release_chain.assert_index_agrees_with_tree(
            candidate.root, CHAIN_SPEC.state_relative
        )
    assert str(refusal.value) == (
        "candidate working tree mode for ledger/official_observations.jsonl "
        "disagrees with its index entry (100644 vs 100755)"
    )


def commit_all(candidate: Candidate, message: str) -> Candidate:
    """Commit the working tree and return the candidate rebased on it."""

    git(candidate.root, "add", "-A")
    git(candidate.root, "commit", "--quiet", "-m", message)
    return replace(candidate, base=git(candidate.root, "rev-parse", "HEAD"))


def test_the_index_is_asked_about_a_path_not_a_pattern(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R7-F6: every index read passed the path to git as a bare
    pathspec, which is a *pattern*. ``releases/x[y]z.md`` is a legitimate
    filename and a glob at the same time, so the read about it also returned
    the sibling ``releases/xyz.md`` that the bracket expression matches —
    entries for a path the caller never asked about, kept out of the two
    exact-path checks only by their own ``listed == path`` filter and not
    kept out of the release root's scan at all, which has no single path to
    filter on. Without the literal pathspec the first assertion here gets
    two records instead of one.

    The missing-entry direction is bound by the two tests below; git compares
    an exact pathspec literally before it tries the pattern, so a bracketed
    name is still found today and this file's own checks pass either way.
    They are asserted so the literal pathspec is pinned as not having lost
    the ordinary match — including through the gate, where the release
    history now requires every base release file to still be in the index."""

    candidate = base_repository(tmp_path)
    releases = candidate.root / CHAIN_SPEC.release_root_relative
    (releases / "x[y]z.md").write_text("bracketed\n", encoding="utf-8")
    (releases / "xyz.md").write_text("what the bracket matches\n", encoding="utf-8")
    candidate = commit_all(candidate, "release files with glob magic in a name")
    append_one_row(candidate)

    assert [
        (record.mode, record.stage, record.path, record.intent_to_add)
        for record in release_chain._index_entries(
            candidate.root, "releases/x[y]z.md"
        )
    ] == [
        ("100644", "0", "releases/x[y]z.md", False)
    ]
    release_chain.assert_index_agrees_with_tree(candidate.root, "releases/x[y]z.md")
    release_chain.assert_state_path_tracked(candidate.root, "releases/x[y]z.md")
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


MAGIC_STATE_PATH = ":odd/official_observations.jsonl"


def track_a_path_git_reads_as_magic(candidate: Candidate) -> pathlib.Path:
    """Commit a file whose first character git parses as pathspec magic.

    ``:odd/x`` asked of ``git ls-files`` is not that path: the leading colon
    introduces pathspec magic, the unrecognised ``o`` ends it, and git looks
    for ``odd/x`` instead — matching nothing, exiting zero, and reporting a
    tracked file as absent from the index.
    """

    path = candidate.root / MAGIC_STATE_PATH
    path.parent.mkdir()
    path.write_text("tracked, whatever the pathspec parser makes of it\n")
    git(candidate.root, "add", "-A")
    return path


def test_a_state_path_git_would_read_as_pathspec_magic_is_tracked(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R7-F6 in the direction that refuses: a path the index does hold,
    reported as absent because git read its name as a pathspec instruction
    rather than as a name. Without the literal pathspec this refuses
    ``state path :odd/official_observations.jsonl is absent from the
    candidate index`` — a tracked file the gate declines to verify."""

    candidate = base_repository(tmp_path)
    track_a_path_git_reads_as_magic(candidate)

    release_chain.assert_state_path_tracked(candidate.root, MAGIC_STATE_PATH)


def test_the_index_comparison_finds_a_path_git_would_read_as_magic(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R7-F6 in the direction that accepts, which is the dangerous one:
    the same misread name leaves ``assert_index_agrees_with_tree`` with no
    entry to compare, and no entry is how a new untracked file looks — so it
    returns, and a working tree that does not carry what git recorded passes
    the check written to catch exactly that. Without the literal pathspec
    this raises nothing at all."""

    candidate = base_repository(tmp_path)
    path = track_a_path_git_reads_as_magic(candidate)
    path.chmod(0o755)

    with pytest.raises(ReleaseChainError) as refusal:
        release_chain.assert_index_agrees_with_tree(candidate.root, MAGIC_STATE_PATH)
    assert str(refusal.value) == (
        f"candidate working tree mode for {MAGIC_STATE_PATH} disagrees with "
        "its index entry (100644 vs 100755)"
    )


def test_a_base_release_file_dropped_from_the_index_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R7-F1: the release-history pass compared the base against the
    working tree and asked the index only whether it disagreed with what was
    on disk. ``git rm --cached`` produces no disagreement — it leaves the
    file exactly where it was, byte-identical and at the base's mode, and
    removes only the entry that makes it part of the commit under review, at
    which point the agreement check has no entry to compare and returns. So
    the mode matched, the bytes matched, the proposal was accepted, and
    merging it deletes a release manifest, receipt, or signature this package
    calls immutable. Without the new check this tree gets the ordinary
    acceptance below."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    git(candidate.root, "rm", "--cached", "--quiet", "--", "releases/README.md")
    # Nothing on disk moved: that is the whole point of the case.
    assert (candidate.root / "releases" / "README.md").read_text(
        encoding="utf-8"
    ) == "Release journal for the fixture ledger.\n"

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "existing release file was removed from the candidate index: "
        "releases/README.md"
    )


def test_a_base_release_file_still_indexed_is_left_alone(
    tmp_path: pathlib.Path,
) -> None:
    """R7-F1's other half, and the reason the check is not a presence test on
    the working tree: an ordinary proposal keeps every base release file in
    the index, so the pass says nothing about them."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)

    release_chain.assert_release_file_still_indexed(
        candidate.root, "releases/README.md"
    )
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_a_gate_only_proposal_whose_index_changes_the_ledger_is_not_gate_only(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R7-F3: surface classification was derived from the working
    tree's diff against the base, and a gate-only match returned on it before
    the ledger, the prefix, the release history, or any mode or index check
    ran. The index is the commit under review, and it can differ: here it
    records the ledger executable while the working tree carries 100644 and
    only the gate script has changed on disk. Without the index's own changed
    set the proposal classifies as gate-only and is accepted with
    ``GATE_SURFACE changes=['scripts/check_append.py']``, carrying a ledger
    mode change no check ever saw. With it the ledger is a DATA change beside
    a GATE change, which is a mixed proposal, refused in the words the
    working-tree classification has always used for one."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    git(
        candidate.root,
        "update-index",
        "--chmod=+x",
        "--",
        CHAIN_SPEC.state_relative.as_posix(),
    )
    # The working tree really does look gate-only: git diff against the base
    # names the ledger nowhere.
    assert "official_observations" not in git(
        candidate.root, "diff", "--name-only", candidate.base, "--"
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "mixed data/gate proposal is forbidden: DATA_SURFACE changes="
        "['ledger/official_observations.jsonl']; GATE_SURFACE changes="
        "['scripts/check_append.py']; split them into separate pull requests"
    )


def test_a_data_proposal_whose_index_carries_a_gate_change_is_mixed(
    tmp_path: pathlib.Path,
) -> None:
    """R7-F3 from the other side. The working tree carries an ordinary
    append and no gate change; the index records the gate script, written
    straight into it with no file on disk. The commit under review touches
    both surfaces, which is the mixed proposal the working-tree classification
    refuses whenever it can see both halves — and here it sees only one. The
    union sees both, and refuses in the same words, naming the path each side
    carries. Without the index's changed set this ran the data path and
    accepted a data verdict over a commit that also changes the gate."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    blob = git(candidate.root, "hash-object", "-w", "--stdin", stdin="# staged gate\n")
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},{GATE_FILE}",
    )
    assert not (candidate.root / GATE_FILE).exists()
    assert "official_observations" in git(
        candidate.root, "diff", "--name-only", candidate.base, "--"
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "mixed data/gate proposal is forbidden: DATA_SURFACE changes="
        "['ledger/official_observations.jsonl']; GATE_SURFACE changes="
        "['scripts/check_append.py']; split them into separate pull requests"
    )


def test_a_gate_only_proposal_whose_index_rewrites_a_release_file_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """R7-F3 for an unclassified release path, which is the gap the gate-only
    confinement was added to close, one level down: the rewrite is staged and
    then undone on disk, so the working tree matches the base exactly and the
    proposal looks clean. The commit under review still rewrites
    ``releases/README.md``. Without the index's changed set this is accepted
    as a clean gate-only proposal."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    original = readme.read_text(encoding="utf-8")
    readme.write_text("Rewritten in the index alone.\n", encoding="utf-8")
    git(candidate.root, "add", "--", "releases/README.md")
    readme.write_text(original, encoding="utf-8")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "gate-only proposal changes unclassified release path(s): "
        "['releases/README.md']"
    )


def serve_a_release_path_through_a_symlink(
    candidate: Candidate, outside: pathlib.Path
) -> None:
    """Index ``releases/vendor/file.md`` and point ``vendor`` outside the tree.

    The entry is written straight into the index because git will not add a
    path that lies beyond a symlink — which is the whole shape of the case:
    the commit records a release file, and the working tree answers for it
    with a file the checkout does not contain.
    """

    outside.mkdir(parents=True)
    (outside / "file.md").write_text("served from outside the tree\n", encoding="utf-8")
    (candidate.root / CHAIN_SPEC.release_root_relative / "vendor").symlink_to(
        outside, target_is_directory=True
    )
    blob = git(
        candidate.root, "hash-object", "-w", "--stdin", stdin="served from outside\n"
    )
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},releases/vendor/file.md",
    )


def test_an_indexed_release_path_served_through_a_symlink_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R7-F4: the release root's index and its working tree were
    reconciled by asking ``is_file()`` about each indexed path, which resolves
    every component of the name — while the traversal that would have seen
    those components resolves none of them, because ``rglob`` yields a
    symlinked directory without descending it and the scan skips it. So
    ``releases/vendor -> /outside`` served an indexed release file: present,
    regular, and no part of the candidate tree. Without the parent walk the
    push path accepts this tree outright."""

    candidate = base_repository(tmp_path)
    serve_a_release_path_through_a_symlink(candidate, tmp_path / "outside")
    # The name resolves to a regular file, which is exactly what the
    # reconciliation used to ask about.
    assert (candidate.root / "releases" / "vendor" / "file.md").is_file()

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "release path traverses a symlink at 'releases/vendor': "
        "releases/vendor/file.md"
    )


def test_the_enumerations_symlink_refusal_still_comes_first_with_a_base(
    tmp_path: pathlib.Path,
) -> None:
    """R7-F4's placement: on the base-ref path the same tree meets
    ``_working_release_files`` first, which is on ``main`` and refuses the
    link it walks into by name. That refusal is not pre-empted; the new walk
    speaks only for the path no traversal reaches, which is why the push path
    above is where it fires."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    serve_a_release_path_through_a_symlink(candidate, tmp_path / "outside")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "release path is a symlink: releases/vendor"


def test_check_state_modes_refuses_a_symlinked_state_file_on_its_own(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R7-F5: with no snapshot to take, the mode comparison read the
    path with ``stat``, which follows a link. So a ledger replaced by a
    symlink to a non-executable regular file reported that target's 100644,
    compared equal to the base's 100644, and passed — a category change git
    records, synthesised away by the read meant to observe it. The index
    comparison after it does not save the case either: with the link staged,
    the index says 120000 and the working tree holds 120000, which agree.
    Without the ``lstat`` this function returns cleanly on this tree.

    Through the gate the tree never gets this far — a 120000 state entry is
    not a tracked regular file, and the entry check at the top says so, which
    is asserted here as the scope of the finding."""

    candidate = base_repository(tmp_path)
    outside = tmp_path / "outside" / "official_observations.jsonl"
    outside.parent.mkdir()
    ledger = candidate.root / CHAIN_SPEC.state_relative
    outside.write_text(ledger.read_text(encoding="utf-8"), encoding="utf-8")
    ledger.unlink()
    ledger.symlink_to(outside)
    git(candidate.root, "add", "--", CHAIN_SPEC.state_relative.as_posix())

    with selected_tree(candidate) as tree, pytest.raises(AppendError) as refusal:
        append_gate.check_state_modes(
            append_gate._BaseCommit(ref=candidate.base, commit=candidate.base),
            tree,
        )
    assert str(refusal.value) == (
        "state file is a symlink: ledger/official_observations.jsonl"
    )
    with pytest.raises(AppendError) as through_the_gate:
        run_gate(candidate)
    assert str(through_the_gate.value) == (
        "state path ledger/official_observations.jsonl has a non-regular "
        "index entry: 120000"
    )


def test_an_ambient_literal_pathspec_mode_cannot_hide_the_index(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S4-F4: every index read here writes ``:(literal)<path>`` so git
    is asked about the exact path, and ``GIT_LITERAL_PATHSPECS`` in the
    ambient environment makes git take that pathspec *as typed* — the magic
    prefix included. The read then looks for a file literally named
    ``:(literal)ledger/official_observations.jsonl``, matches nothing, and
    exits zero, so the state file the whole verdict is about is reported
    absent from the index and the tracked-state check at entry refuses a
    perfectly ordinary proposal. The gate ran every git read under the
    caller's ambient environment, so any CI job or shell that exports the
    variable turned the checks it was meant to help into a refusal battery.
    Without dropping the variable this raises ``state path
    ledger/official_observations.jsonl is absent from the candidate index``."""

    monkeypatch.setenv("GIT_LITERAL_PATHSPECS", "1")
    candidate = base_repository(tmp_path)
    append_one_row(candidate)

    state_path = CHAIN_SPEC.state_relative.as_posix()
    assert _index_paths(candidate.root, state_path) == [state_path]
    release_chain.assert_state_path_tracked(candidate.root, CHAIN_SPEC.state_relative)
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_an_ambient_icase_pathspec_mode_cannot_widen_an_index_read(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S4-F4 from the other direction. ``GIT_ICASE_PATHSPECS`` makes every
    pathspec case-insensitive, so a read about one path answers with records
    for differently spelled siblings: here the index carries both
    ``releases/README.md`` and a ``releases/README.MD`` entry, and the read
    about the first returns both. The checks that ask about exactly one path
    filter the records afterwards and survive that; the release root's scan,
    which reads every record under a directory, does not filter and would
    take in whatever a differently cased sibling directory holds. Without
    dropping the variable ``_index_entries`` returns two records here."""

    monkeypatch.setenv("GIT_ICASE_PATHSPECS", "1")
    candidate = base_repository(tmp_path)
    blob = git(candidate.root, "rev-parse", ":releases/README.md")
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},releases/README.MD",
    )

    assert _index_paths(candidate.root, "releases/README.md") == [
        "releases/README.md"
    ]


def test_an_ambient_icase_pathspec_mode_leaves_an_ordinary_proposal_alone(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S4-F4 for a proposal with nothing odd in it at all, which is the case
    that shows how wide the variable's reach is: the base tree enumeration
    hands git a plain ``releases`` pathspec, and ``git ls-tree`` does not
    accept icase magic, so with the variable set an ordinary append is
    refused with ``cannot enumerate releases at base <oid>: fatal: releases:
    pathspec magic not supported by this command: 'icase'`` before any
    comparison is made. With the variable dropped the verdict is exactly the
    one the gate always gave."""

    monkeypatch.setenv("GIT_ICASE_PATHSPECS", "1")
    candidate = base_repository(tmp_path)
    append_one_row(candidate)

    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_the_git_environment_drops_every_pathspec_mode(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """S4-F4 at the source. All four variables decide what a pathspec means
    before any command line is read, so all four are dropped and nothing else
    is: the replacement-object setting is still applied and the rest of the
    ambient environment still reaches git."""

    for name in release_chain.PATHSPEC_ENVIRONMENT:
        monkeypatch.setenv(name, "1")
    monkeypatch.setenv("GIT_DIR_FIXTURE_MARKER", "carried through")

    environment = release_chain._git_environment()

    assert set(release_chain.PATHSPEC_ENVIRONMENT) == {
        "GIT_LITERAL_PATHSPECS",
        "GIT_GLOB_PATHSPECS",
        "GIT_NOGLOB_PATHSPECS",
        "GIT_ICASE_PATHSPECS",
    }
    assert not set(environment) & set(release_chain.PATHSPEC_ENVIRONMENT)
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["GIT_DIR_FIXTURE_MARKER"] == "carried through"


def re_add_as_intent_to_add(candidate: Candidate, relative: str) -> None:
    """Drop one tracked path from the index and re-add it with ``git add -N``.

    What is left is an *intent-to-add* entry: stage 0, mode 100644, the empty
    blob's object id and no content. The working tree is untouched throughout,
    so every comparison that reads it agrees with the entry — and a commit
    made from this index deletes the path.
    """

    git(candidate.root, "rm", "--cached", "--quiet", "--", relative)
    git(candidate.root, "add", "-N", "--", relative)


def test_an_intent_to_add_index_entry_is_readable_as_such(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F3 at the parse. ``git ls-files -s`` gives an intent-to-add
    entry as ``100644 <empty blob> 0``, which is exactly what an ordinary
    tracked file with the same content looks like — and an empty file really
    does carry that object id, so the object id is no test either. The flag
    word ``git ls-files --debug`` prints is: ``CE_INTENT_TO_ADD`` is set for
    one and clear for the other. Without reading it the two records here are
    indistinguishable."""

    candidate = base_repository(tmp_path)
    state_path = CHAIN_SPEC.state_relative.as_posix()
    empty = candidate.root / "releases" / "empty.md"
    empty.write_text("", encoding="utf-8")
    git(candidate.root, "add", "--", "releases/empty.md")
    re_add_as_intent_to_add(candidate, state_path)

    (intent_record,) = release_chain._index_entries(candidate.root, state_path)
    (empty_record,) = release_chain._index_entries(
        candidate.root, "releases/empty.md"
    )
    # Same mode, same stage, same object id — and only one of them records
    # anything.
    assert (intent_record.mode, intent_record.stage) == ("100644", "0")
    assert (empty_record.mode, empty_record.stage) == ("100644", "0")
    assert intent_record.object_id == empty_record.object_id
    assert git(candidate.root, "rev-parse", f":{state_path}") == git(
        candidate.root, "rev-parse", ":releases/empty.md"
    )
    assert intent_record.intent_to_add is True
    assert empty_record.intent_to_add is False


@pytest.mark.parametrize("with_base", [True, False], ids=["base-ref", "push"])
def test_an_intent_to_add_state_entry_is_refused(
    tmp_path: pathlib.Path, with_base: bool
) -> None:
    """Binds S4-F3 for the two files the whole verdict is about. ``git rm
    --cached`` of the ledger followed by ``git add -N`` of it leaves a stage-0
    100644 entry at the path, so the tracked-state check found an entry, the
    mode was supported, and the working tree carried exactly what the entry
    claimed — while the entry records no content and the commit under review
    deletes the ledger. Without the flag read this proposal is accepted on
    both paths."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    state_path = CHAIN_SPEC.state_relative.as_posix()
    re_add_as_intent_to_add(candidate, state_path)
    # git itself calls the entry a modification of a tracked path, which is
    # the disguise: nothing an index read returns says the content is gone.
    assert f"M\t{state_path}" in git(
        candidate.root, "diff-index", "--cached", "--name-status", "HEAD"
    ).splitlines()

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate) if with_base else run_push_gate(candidate)
    assert str(refusal.value) == (
        f"index entry for {state_path} is intent-to-add and records no content"
    )


def test_an_intent_to_add_state_entry_keeps_the_earlier_refusals(
    tmp_path: pathlib.Path,
) -> None:
    """S4-F3's placement inside the tracked-state check: last, after absent,
    unmerged and non-regular, because a 100644 stage-0 entry has already
    answered all three and there is nothing else left to say about it. An
    intent-to-add entry is not always 100644 — ``git add -N`` records the
    working tree's type, so a state path replaced by a symlink and re-added
    that way is an intent-to-add 120000 entry — and that is the refusal that
    fires, in the words it already had."""

    candidate = base_repository(tmp_path)
    state_path = CHAIN_SPEC.state_relative.as_posix()
    ledger = candidate.root / CHAIN_SPEC.state_relative
    ledger.unlink()
    ledger.symlink_to(tmp_path / "elsewhere.jsonl")
    re_add_as_intent_to_add(candidate, state_path)
    assert [
        (record.mode, record.stage, record.path, record.intent_to_add)
        for record in release_chain._index_entries(candidate.root, state_path)
    ] == [
        ("120000", "0", state_path, True)
    ]

    with pytest.raises(ReleaseChainError) as refusal:
        release_chain.assert_state_path_tracked(
            candidate.root, CHAIN_SPEC.state_relative
        )
    assert str(refusal.value) == (
        f"state path {state_path} has a non-regular index entry: 120000"
    )


def test_an_intent_to_add_base_release_entry_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F3 for a base release file. The still-indexed check refuses a
    path ``git rm --cached`` removed outright; ``git add -N`` puts an entry
    back where that check looks, at the mode and stage it requires, so the
    removal was hidden behind an entry recording nothing. The release file is
    still on disk and byte-identical, so neither byte nor mode comparison
    above says anything. Without the flag read this proposal is accepted."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    re_add_as_intent_to_add(candidate, "releases/README.md")
    assert (candidate.root / "releases" / "README.md").read_text(
        encoding="utf-8"
    ) == "Release journal for the fixture ledger.\n"

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "index entry for releases/README.md is intent-to-add and records no "
        "content"
    )


def test_an_intent_to_add_base_release_entry_keeps_the_byte_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """S4-F3's placement in the release-history pass: the new refusal sits
    after every comparison for that path, so a proposal that also rewrites
    the file's bytes gets the byte refusal the upstream verifier gives, not
    this one."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    readme.write_text("Rewritten as well.\n", encoding="utf-8")
    re_add_as_intent_to_add(candidate, "releases/README.md")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        f"existing release file bytes changed relative to {candidate.base}: "
        "releases/README.md"
    )


def test_an_intent_to_add_release_path_is_refused_by_the_root_scan(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F3 for a release path the base does not carry, which no
    per-file comparison reaches: ``git add -N`` under ``releases/`` records a
    stage-0 100644 entry for a file the reconciliation then finds on disk, so
    the index and the working tree were called agreed over an entry holding
    nothing. The root scan reads the flag beside the mode. Without it the
    push path accepts this tree outright."""

    candidate = base_repository(tmp_path)
    (candidate.root / "releases" / "NOTES.md").write_text(
        "release notes\n", encoding="utf-8"
    )
    git(candidate.root, "add", "-N", "--", "releases/NOTES.md")

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "index entry for releases/NOTES.md is intent-to-add and records no "
        "content"
    )


def index_a_second_spelling(candidate: Candidate, spelling: str) -> None:
    """Record a second index entry for one release file, spelled differently.

    Written straight into the index because there is only one file: git
    cannot be asked to add a name the directory does not hold, and on a
    case-insensitive filesystem it could not hold both anyway. That is the
    shape of the case — two committed release objects, one file to answer for
    them.
    """

    blob = git(candidate.root, "rev-parse", ":releases/README.md")
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},{spelling}",
    )
    assert sorted(
        path.name for path in (candidate.root / "releases").iterdir()
    ) == ["README.md"]


def test_a_second_cased_spelling_of_a_release_entry_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F2: the release root's index was reconciled with the working
    tree by asking ``is_file()`` about each indexed path, which is a question
    the *filesystem* answers. Where names are compared case-insensitively —
    APFS and HFS+ by default, and any case-insensitive mount — it answers
    about whatever entry it considers the same name, so ``releases/README.MD``
    and
    ``releases/README.md`` — two entries the commit carries, two release
    objects — were both answered by the one file on disk. One of them was in
    no enumeration, was never byte- or mode-verified, and the reconciliation
    reported the index and the working tree in agreement. The walk's own
    spelling decides instead: it yields ``releases/README.md`` and nothing
    else, so the other entry is absent under its own spelling.

    On a case-insensitive filesystem this fails without the fix, because
    ``is_file()`` says yes; on a case-sensitive one the entry was already
    absent and the same refusal was already given. The refusal is the same
    sentence on both, which is the point — the verdict does not depend on
    which filesystem the auditor cloned onto."""

    candidate = base_repository(tmp_path)
    index_a_second_spelling(candidate, "releases/README.MD")

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "release file recorded in the index is absent or not a regular file: "
        "releases/README.MD"
    )


def test_a_second_normalisation_of_a_release_entry_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """S4-F2 for Unicode normalisation, which is the same hole without any
    change of case: APFS and HFS+ compare names normalisation-insensitively,
    so an index entry spelled NFD (``e`` + U+0301) resolves to the NFC file
    on disk and ``is_file()`` says yes. Two entries, two release objects, one
    file answering for both. The walk spells the file one way, and the entry
    that is not that spelling is absent.

    As above: without the fix this fails where names are compared
    insensitively and passes where they are not, and with it the refusal is
    the same sentence everywhere."""

    candidate = base_repository(tmp_path)
    composed = "réadme.md"
    decomposed = unicodedata.normalize("NFD", composed)
    assert composed != decomposed
    (candidate.root / "releases" / composed).write_text("r\n", encoding="utf-8")
    candidate = commit_all(candidate, "a release file with a composed name")
    # git records the name the directory holds; the decomposed spelling is a
    # different string, and only the index carries it.
    tracked = git(candidate.root, "ls-files", "-z").split("\0")
    assert f"releases/{composed}" in tracked
    blob = git(candidate.root, "rev-parse", f":releases/{composed}")
    # ``core.precomposeunicode`` — on by default where the filesystem
    # decomposes — would rewrite the decomposed pathname on this command line
    # back to the composed one, so the entry is written with it off. That is
    # what a history authored where the two names are distinct files looks
    # like once it is cloned onto a filesystem where they are not: two
    # entries checked out over one file.
    git(
        candidate.root,
        "-c",
        "core.precomposeunicode=false",
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},releases/{decomposed}",
    )
    assert sorted(
        entry for entry in git(candidate.root, "ls-files", "-z").split("\0") if entry
    ) == [
        "ledger/immutable_prefix.json",
        "ledger/official_observations.jsonl",
        "releases/README.md",
        f"releases/{decomposed}",
        f"releases/{composed}",
    ]

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "release file recorded in the index is absent or not a regular file: "
        f"releases/{decomposed}"
    )


def test_a_second_spelling_is_refused_against_a_base_as_well(
    tmp_path: pathlib.Path,
) -> None:
    """S4-F2 on the other path. The release-history pass compares every base
    release file and finds nothing wrong — the one file on disk is
    byte-identical and at the base's mode — and the root's scan, which runs
    after all of it, is where the second entry is named."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    index_a_second_spelling(candidate, "releases/README.MD")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "release file recorded in the index is absent or not a regular file: "
        "releases/README.MD"
    )


def a_replacement_repository(
    candidate: Candidate, tmp_path: pathlib.Path
) -> pathlib.Path:
    """A second checkout of the candidate, ready to be moved into its place.

    Copied from it, so every OID this run has already resolved still exists
    in the replacement and git answers about it exactly as it would about the
    original — which an unrelated repository would not, and which is what
    makes a swapped root produce a *verdict* rather than an error.
    """

    replacement = tmp_path / "replacement"
    shutil.copytree(candidate.root, replacement, symlinks=True)
    return replacement


def move_a_repository_into_the_root(
    candidate: Candidate, replacement: pathlib.Path
) -> None:
    """Rename the candidate root aside and put ``replacement`` at its path."""

    candidate.root.rename(candidate.root.parent / "moved-aside")
    replacement.rename(candidate.root)


def test_a_gate_only_verdict_is_bound_to_the_recorded_root(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S4-F1: ``_set_root`` records the resolved root's identity, and
    the only thing that ever compared it against what the name resolves to
    now is the descriptor walk a state read performs. A gate-only proposal
    performs none — it classifies the changed sets and returns — so the whole
    branch ran without the recorded root being consulted once. Here the root
    is renamed aside and another repository is moved into its place after the
    classification, exactly where nothing looked; without the check the run
    returns the ordinary gate-only acceptance for a tree it never selected,
    and the tree it is standing in is one the same gate would refuse."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    replacement = a_replacement_repository(candidate, tmp_path)
    # Its first row is not the frozen one, so a run that really did read this
    # tree would refuse it — the acceptance is not merely about the wrong
    # tree, it is about a tree this gate rejects.
    rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 1)]
    rows[0] = observation_row(99)
    write_ledger(replacement, rows)
    staged = append_gate._staged_surface_changes

    def swap_after_classifying(
        base: append_gate._BaseCommit, tree: append_gate._CandidateTree
    ) -> tuple[set[str], set[str], set[str]]:
        classified = staged(base, tree)
        move_a_repository_into_the_root(candidate, replacement)
        return classified

    monkeypatch.setattr(append_gate, "_staged_surface_changes", swap_after_classifying)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "candidate root changed during verification"


def test_the_classification_is_bound_to_the_recorded_root_too(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S4-F1's other call. The checkout guard and the tracked-state check run
    before any classification and reach the tree by name, so a root exchanged
    between ``_set_root`` and the surface probes has those two answered by
    the tree that was selected and everything after them answered by a
    replacement — one verdict assembled from two repositories. The
    classification decides which path the whole run takes, so it is bound to
    the recorded root as well. Here the replacement carries the candidate's
    data change *and* a gate script, so without the check the surface probes
    classify it and the run refuses it as a mixed proposal — a refusal about
    a tree that was never under review, naming files the selected one does
    not contain."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    replacement = a_replacement_repository(candidate, tmp_path)
    script = replacement / GATE_FILE
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("# gate fixture\n", encoding="utf-8")
    assert not (candidate.root / GATE_FILE).exists()
    tracked = append_gate.assert_state_path_tracked
    swapped = False

    def swap_after_the_last_state_path(
        root: pathlib.Path, relative: pathlib.PurePosixPath
    ) -> None:
        nonlocal swapped
        tracked(root, relative)
        if relative == CHAIN_SPEC.prefix_relative and not swapped:
            swapped = True
            move_a_repository_into_the_root(candidate, replacement)

    monkeypatch.setattr(
        append_gate, "assert_state_path_tracked", swap_after_the_last_state_path
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert swapped
    assert str(refusal.value) == "candidate root changed during verification"


@pytest.mark.skipif(
    os.getuid() == 0, reason="root traverses a directory it has no rights on"
)
def test_a_search_only_state_directory_is_refused_by_the_walk(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4R4-F7, and states what it takes back. S4-F5 made the descent
    open every directory above a state file with search rights alone where the
    platform offers them, so a POSIX search-only directory — mode 0o111,
    traversable and not listable, which is how a directory above a published
    state file is often locked down — was read through as the pathname open it
    replaced always had been. That acceptance is the hole: the directory's
    listing is the only thing that binds the spelling of what it holds, so
    making a parent search-only is all a proposal has to arrange to turn the
    one check that could say the ledger on disk is not the ledger the index
    names off.

    S4R3-F5 narrowed the refusal to parents that could be *shown* to fold the
    name, by probing a whole-string swapcase and the other of NFC and NFD.
    That is not the set of names a filesystem may fold: one that folds part of
    a mixed-case name, or a component carrying no cased letters at all and no
    normalisation difference, answers no to every probe while the fold is
    still available. So the probe is gone and the walk fails closed.

    The ledger's own directory is refused here on every filesystem and every
    platform. Measured at 4d8039f: on this APFS checkout the tree was refused
    with the probe's own sentence (``cannot bind the spelling of
    ledger/official_observations.jsonl: its directory folds names and cannot
    be listed: ...``), and with the probe answering False — which is what ext4
    gives, and what any uncased component gives anywhere — it was accepted as
    ``thesis-facts append check OK: 3 rows, immutable prefix 1, +1 appended vs
    base``. The same tree with a rewritten frozen prefix line, measured the
    same way, was refused as ``immutable prefix line 1
    (fixture.series.observation_1) was rewritten``: that is the refusal this
    one now pre-empts, and the module docstring says so. The release-root case
    below is one no probe could have answered on any filesystem, and it was
    accepted here.

    S5-R2-F1 moved which of the two walks answers first for this tree, and
    both halves are asserted here. ``ledger`` is a data-surface subtree, so
    against a base the surface enumeration reaches it before the
    classification it guards, and the answer is that enumeration's. Measured
    at this round's head with ``assert_protected_surfaces_enumerable`` removed
    from ``check_surface_separation``: ``cannot bind the spelling of
    ledger/official_observations.jsonl: its directory cannot be listed:
    ledger/official_observations.jsonl`` — the state walk's sentence, which is
    still what the push path gives, since it classifies nothing and so runs no
    surface enumeration. Neither walk lets the bytes through; which one says
    so depends on which read comes first."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger_directory = candidate.root / "ledger"
    ledger_directory.chmod(0o111)
    try:
        # Search-only, and the state file inside it is readable: the walk is
        # the only thing standing between the gate and those bytes.
        assert (candidate.root / CHAIN_SPEC.state_relative).read_bytes()

        with pytest.raises(AppendError) as refusal:
            run_gate(candidate)
        assert str(refusal.value) == (
            "cannot enumerate a protected directory, so the proposal cannot "
            "be classified: ledger (Permission denied)"
        )

        # And the state path's own walk, where nothing classifies ahead of it.
        with pytest.raises(AppendError) as push_refusal:
            run_push_gate(candidate)
        assert str(push_refusal.value) == (
            "cannot bind the spelling of "
            f"{CHAIN_SPEC.state_relative.as_posix()}: its directory cannot be "
            f"listed: {CHAIN_SPEC.state_relative.as_posix()}"
        )
    finally:
        ledger_directory.chmod(0o755)


@pytest.mark.skipif(
    os.getuid() == 0, reason="root traverses a directory it has no rights on"
)
def test_an_uncased_component_no_probe_could_answer_for_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """S4R4-F7 where the probe it replaces could not fire at all, which is the
    finding rather than a stronger statement of it. ``_folds_a_spelling``
    asked whether a second spelling of the component reached the same file,
    and its spellings were the swapcase and the other normal form. ``2026``
    has neither: swapcasing it returns the same string and its NFC and NFD
    forms are equal, so the probe had nothing to try and answered no on every
    filesystem — including the ones that do fold, by rules those two spellings
    do not enumerate.

    So a release root of ``data/2026`` under a search-only ``data`` was
    accepted at 4d8039f on this APFS checkout, measured: ``thesis-facts append
    check OK: 2 rows, immutable prefix 1`` — with no simulation anywhere, on
    the filesystem the probe was meant to protect against. It is the release
    root's walk rather than the state path's, so both call sites of the check
    are bound by a real checkout here."""

    spec = spec_with_release_root("data/2026")
    candidate = base_repository(tmp_path, "data/2026")
    parent = candidate.root / "data"
    parent.chmod(0o111)
    try:
        with pytest.raises(AppendError) as refusal:
            run_push_gate(candidate, spec=spec)
        assert str(refusal.value) == (
            "cannot bind the spelling of data/2026: its directory cannot be "
            "listed: data/2026"
        )
    finally:
        parent.chmod(0o755)


@pytest.mark.skipif(
    os.getuid() == 0, reason="root traverses a directory it has no rights on"
)
def test_a_candidate_root_that_cannot_be_listed_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """S4R4-F7 at the top of the walk. The candidate root is the parent of the
    first component of every protected path, so it has to be listable for the
    same reason each directory below it does — and, unlike them, it is opened
    by ``_set_root`` before any walk runs. Where the platform has a
    search-only flag that open succeeds on a 0o111 root and the walk is what
    answers; where it has neither, ``_set_root`` answers first, in the
    descent's own words, which the test below pins."""

    candidate = base_repository(tmp_path)
    candidate.root.chmod(0o111)
    try:
        with pytest.raises(AppendError) as refusal:
            run_push_gate(candidate)
        assert str(refusal.value) == (
            "cannot bind the spelling of ledger: its directory cannot be "
            "listed: ledger/official_observations.jsonl"
        )
    finally:
        candidate.root.chmod(0o755)


@pytest.mark.skipif(
    os.getuid() == 0, reason="root traverses a directory it has no rights on"
)
def test_the_shared_state_reader_answers_the_same_way(
    tmp_path: pathlib.Path,
) -> None:
    """S4R4-F7 through ``release_chain``'s own reader, which is the one
    ``verify_release_chain`` — and so ``receipt verify``'s custody pass —
    uses. ``_regular_file_bytes`` runs the same component walk before its
    descent, so the requirement is the package's rather than the gate's and
    both readers state it the same way. That is why ``README.md`` says it
    where a consumer looks. Measured at 4d8039f with the fold probe answering
    False: this reader returns the ledger's bytes for a directory that cannot
    be listed."""

    candidate = base_repository(tmp_path)
    ledger_directory = candidate.root / "ledger"
    expected = (candidate.root / CHAIN_SPEC.state_relative).read_bytes()
    assert expected
    ledger_directory.chmod(0o111)
    try:
        with pytest.raises(ReleaseChainError) as refusal:
            _regular_file_bytes(candidate.root, CHAIN_SPEC.state_relative)
        assert str(refusal.value) == (
            "cannot bind the spelling of "
            f"{CHAIN_SPEC.state_relative.as_posix()}: its directory cannot be "
            f"listed: {CHAIN_SPEC.state_relative.as_posix()}"
        )
    finally:
        ledger_directory.chmod(0o755)
    assert _regular_file_bytes(candidate.root, CHAIN_SPEC.state_relative) == expected


def test_the_descent_asks_for_no_more_than_it_uses(tmp_path: pathlib.Path) -> None:
    """S4-F5's flag choice, stated rather than implied. Where the platform
    has a search-only flag the walk uses it and asks for no read permission;
    where it does not the walk falls back to ``O_RDONLY`` and says so through
    ``DESCENT_REQUIRES_DIRECTORY_READ``, which is what the test below
    branches on. ``O_DIRECTORY`` and ``O_NOFOLLOW`` are in the set either way,
    because a component that became a file or a link must fail rather than be
    followed.

    S4R4-F7 changed what the flags buy rather than which they are: the walk
    refuses a directory it cannot list, so no state read reaches this descent
    through a search-only parent any more. They stay because they are still
    the rights this open uses — ``openat`` and ``fstat``, nothing else — and
    asking a checkout for read permission this open never uses is a claim with
    nothing behind it."""

    flags = release_chain.DIRECTORY_OPEN_FLAGS
    assert flags & os.O_DIRECTORY
    assert flags & os.O_NOFOLLOW
    # Whatever this platform offers, the walk takes it: leaving an available
    # search-only flag unused is the finding, and on a platform offering
    # neither both sides of this are zero.
    offered = getattr(os, "O_PATH", 0) or getattr(os, "O_SEARCH", 0)
    assert release_chain.SEARCH_ONLY_DIRECTORY_FLAG == offered
    if offered:
        assert flags & offered
        assert release_chain.DESCENT_REQUIRES_DIRECTORY_READ is False
    else:
        assert release_chain.DESCENT_REQUIRES_DIRECTORY_READ is True
    # Whichever it is, the walk still reaches an ordinary state file.
    candidate = base_repository(tmp_path)
    assert _regular_file_bytes(candidate.root, CHAIN_SPEC.state_relative)


def without_a_search_only_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """Present a platform whose ``os`` exposes neither ``O_PATH`` nor
    ``O_SEARCH``, which no interpreter this is run on actually is.

    Both constants are read at call time, so patching them is the same
    technique the ``os.supports_dir_fd`` cases use, and it reaches the branch
    that only such a platform would otherwise take.
    """

    monkeypatch.setattr(release_chain, "SEARCH_ONLY_DIRECTORY_FLAG", 0)
    monkeypatch.setattr(release_chain, "DESCENT_REQUIRES_DIRECTORY_READ", True)
    monkeypatch.setattr(
        release_chain,
        "DIRECTORY_OPEN_FLAGS",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )


@pytest.mark.skipif(
    os.getuid() == 0, reason="root traverses a directory it has no rights on"
)
@pytest.mark.parametrize(
    "unreadable", ["ledger", ""], ids=["intermediate-component", "candidate-root"]
)
def test_the_descent_states_the_read_it_needs_where_it_has_no_search_flag(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, unreadable: str
) -> None:
    """S4-F5's other branch, which no interpreter this runs on takes: Linux
    exposes ``O_PATH`` and Darwin exposes ``O_SEARCH`` (checked from CPython
    3.9 to 3.14), so ``DESCENT_REQUIRES_DIRECTORY_READ`` is false everywhere
    the suite runs and the refusal that branch gives would otherwise be
    asserted by nothing. Forcing the fallback flags binds it. Both the
    candidate root and an intermediate component are covered.

    S4R4-F7 moved where each of the two readers meets this, and the unlistable
    root itself is the case above (accepted at 4d8039f with the probe
    answering False, as ``thesis-facts append check OK: 2 rows, immutable
    prefix 1``). Both run the
    component walk before descending, and the walk now refuses a directory it
    cannot list — which a directory it cannot read is — so the descent's own
    sentence is no longer what either reader answers with for a component
    below the root. It is still the answer for the two opens no walk precedes:
    ``confined_state_descriptor`` called on its own, which is what this drives
    directly, and ``_set_root``'s open of the candidate root, which happens
    before any walk and is what the gate answers with for a root this verifier
    may traverse and not read. For an intermediate component the gate answers
    in the walk's words instead, and this pins that too, so the order between
    the two refusals is bound rather than assumed."""

    candidate = base_repository(tmp_path)
    without_a_search_only_flag(monkeypatch)
    directory = candidate.root / unreadable if unreadable else candidate.root
    expected = (
        f"state path component {directory if not unreadable else unreadable} "
        "is not readable by this verifier; secure descent requires read "
        "permission on every directory above a state file on this platform: "
        "ledger/official_observations.jsonl"
    )
    directory.chmod(0o111)
    try:
        # The descent itself, which no walk precedes: this is the reader's
        # own open, asked for directly.
        with pytest.raises(ReleaseChainError) as read:
            release_chain.confined_state_descriptor(
                candidate.root, CHAIN_SPEC.state_relative
            )
        assert str(read.value) == expected
        with pytest.raises(AppendError) as refusal:
            run_push_gate(candidate)
        if unreadable:
            assert str(refusal.value) == (
                "cannot bind the spelling of "
                "ledger/official_observations.jsonl: its directory cannot be "
                "listed: ledger/official_observations.jsonl"
            )
        else:
            assert str(refusal.value) == expected
    finally:
        directory.chmod(0o755)


@pytest.mark.skipif(
    os.getuid() == 0, reason="root lists a directory it has no rights on"
)
def test_an_indexed_release_file_the_walk_cannot_enumerate_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """S4-F2 on any POSIX filesystem, which the two spelling cases above are
    not: they need names compared insensitively, so on a case- and
    normalisation-sensitive filesystem — ext4, and so CI — the entry was
    already absent and the old question already gave the same answer. This
    one binds everywhere, because it is the same substitution with the
    filesystem's *lookup* rather than its comparison doing the work:
    ``is_file()`` resolves the whole name and needs only search permission on
    the parents, so it answered "regular file" for an entry inside a
    directory the traversal cannot list — and the traversal is what the index
    is reconciled against. One committed release object, in no enumeration,
    never byte- or mode-verified, and the two sides called agreed.

    The refusal is deliberate and fail-closed, and it is the standard the
    package already applies with a base: ``_working_release_files`` keys the
    base comparison by the same traversal, so this tree is already refused
    there, in ``main``'s words. Without the fix the push path accepts it
    outright."""

    candidate = base_repository(tmp_path)
    vendor = candidate.root / CHAIN_SPEC.release_root_relative / "vendor"
    vendor.mkdir()
    (vendor / "notes.md").write_text("release notes\n", encoding="utf-8")
    git(candidate.root, "add", "--", "releases/vendor/notes.md")
    vendor.chmod(0o111)
    try:
        # Search permission is all the old question ever needed, and the file
        # really is there: this is a refusal about what can be enumerated,
        # not about what exists.
        assert (vendor / "notes.md").read_text(encoding="utf-8") == "release notes\n"
        assert (candidate.root / "releases" / "vendor" / "notes.md").is_file()

        with pytest.raises(AppendError) as refusal:
            run_push_gate(candidate)
        assert str(refusal.value) == (
            "release file recorded in the index is absent or not a regular "
            "file: releases/vendor/notes.md"
        )
    finally:
        vendor.chmod(0o755)


@pytest.mark.skipif(
    os.getuid() == 0, reason="root lists a directory it has no rights on"
)
def test_the_base_pass_already_refused_the_tree_the_walk_cannot_enumerate(
    tmp_path: pathlib.Path,
) -> None:
    """The other half of the test above, and the reason its refusal is not a
    new standard: with a base ref the same tree is refused by
    ``_working_release_files`` and the per-file loop, which are on ``main``
    and have always keyed the base comparison by the traversal's own
    enumeration. This test passes with S4-F2 reverted — that is its point.
    What S4-F2 changed is that the candidate index and the push path are now
    held to what the base-ref path already required.

    S5-R2-F1 puts a more specific answer in front of that one, deliberately,
    and this test records both. ``releases/vendor`` is inside the release
    root, which is a protected surface, so the surface enumeration meets it
    before the classification runs and refuses that the proposal cannot be
    classified at all. Measured at this round's head with
    ``assert_protected_surfaces_enumerable`` removed from
    ``check_surface_separation``: ``existing release file was deleted relative
    to <base>: releases/vendor/notes.md`` — the pre-existing sentence, and a
    diagnosis this tree does not deserve, since the file is there and only its
    listing is withheld. That is the pre-emption the module docstring states:
    a protected directory the verifier cannot list is answered as one, and the
    base comparison keyed to a traversal that could not see it is not reached.
    The pre-existing refusal is untouched wherever the directory is listable,
    which every other base-comparison test here exercises."""

    candidate = base_repository(tmp_path)
    vendor = candidate.root / CHAIN_SPEC.release_root_relative / "vendor"
    vendor.mkdir()
    (vendor / "notes.md").write_text("release notes\n", encoding="utf-8")
    candidate = commit_all(candidate, "a release file under its own directory")
    append_one_row(candidate)
    vendor.chmod(0o111)
    try:
        with pytest.raises(AppendError) as refusal:
            run_gate(candidate)
        assert str(refusal.value) == (
            "cannot enumerate a protected directory, so the proposal cannot "
            "be classified: releases/vendor (Permission denied)"
        )
    finally:
        vendor.chmod(0o755)


def test_a_release_root_beginning_with_a_colon_is_enumerated_at_the_base(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4R2-F4: the base tree was enumerated by handing the configured
    release root to ``git ls-tree`` as a bare pathspec, and a pathspec
    beginning with ``:`` is magic. The magic is stripped and what is left is
    the path git looks for, so a spec whose root is ``:releases`` asks about
    ``releases``, which this tree does not have: the enumeration comes back
    empty and exits zero. Every release file the base carries is then outside
    the comparison — the history pass has nothing to hold immutable, the whole
    root classifies as newly added files, and a rewritten release file rides
    through as a legacy pre-genesis proposal instead of being refused for the
    bytes it changed.

    With the root named literally the base entries are found and the rewrite
    gets the refusal it has always had. Without the fix this fails with
    ``legacy pre-genesis proposal must not change releases/`` — a message
    about a root the spec never named, for a file whose immutability was
    never checked."""

    spec = spec_with_release_root(":releases")
    candidate = base_repository(tmp_path, ":releases")
    append_one_row(candidate)
    readme = candidate.root / ":releases" / "README.md"
    readme.write_text("Rewritten by a data proposal.\n", encoding="utf-8")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate, spec=spec)
    assert str(refusal.value) == (
        f"existing release file bytes changed relative to {candidate.base}: "
        ":releases/README.md"
    )


def test_a_release_root_carrying_glob_magic_enumerates_only_itself(
    tmp_path: pathlib.Path,
) -> None:
    """S4R2-F4's other half of what a pathspec means, and the honest state of
    it: ``git ls-tree`` does not glob a bare pathspec on the git this package
    is verified with, so a root spelled ``rel[e]ases`` was already enumerated
    as the directory of that name and the run below passes with the
    literalization reverted. ``git ls-files`` is the other way, and this tree
    is the shape that shows it: a directory ``rel[e]ases`` beside a top-level
    file named ``releases``, which the bracket expression matches. That
    difference is what the two assertions on this git bind, and it is the
    whole point — whether a configured path is read as a name or as a pattern
    was a property of one command's default in one version of git, and git's
    pathspec-mode variables rewrite it for every command. ``_git_environment``
    drops those and ``:(literal)`` says what is meant, so neither the index
    reads nor the tree enumeration depends on either.

    Neither command matches a sibling *directory's* contents this way: a
    wildcard pathspec is matched against whole index paths, so ``rel[e]ases``
    cannot match ``releases/unrelated.md``. The sibling here is a file for
    that reason."""

    spec = spec_with_release_root("rel[e]ases")
    candidate = base_repository(tmp_path, "rel[e]ases")
    (candidate.root / "releases").write_text(
        "not a release tree\n", encoding="utf-8"
    )
    candidate = commit_all(candidate, "a sibling the glob reaches")
    append_one_row(candidate)

    # Asked of this git directly, because it is the reason for the change and
    # not something the run below can show: handed the root bare, ls-files
    # answers with the sibling too; named literally, it does not.
    bare = release_chain._git_run(
        candidate.root, ["ls-files", "-z", "--", "rel[e]ases"]
    )
    literal = release_chain._git_run(
        candidate.root, ["ls-files", "-z", "--", ":(literal)rel[e]ases"]
    )
    assert b"releases\x00" in bare.stdout
    assert b"releases\x00" not in literal.stdout
    assert b"rel[e]ases/README.md\x00" in literal.stdout

    assert set(
        release_chain.git_tree_entries(candidate.root, candidate.base, "rel[e]ases")
    ) == {"rel[e]ases/README.md"}
    assert run_gate(candidate, spec=spec) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )


def test_the_base_enumeration_refuses_a_path_outside_the_root_it_asked_for(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S4R2-F4's check on the answer rather than on the question. A literal
    pathspec cannot return a path outside the root asked about, so this is
    what the enumeration is held to rather than what git is expected to do:
    every base entry the release history compares must be the requested root
    or lie under it. Here ``git ls-tree``'s own output is given one more
    record, for a path in neither place, and the enumeration refuses it
    instead of carrying it into the per-file loop — where it would be looked
    for in the release walk, not found, and reported as a release file
    deleted from a root it was never in.

    Without the filter the run refuses with ``existing release file was
    deleted relative to <commit>: outside/x``."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    real_git_run = release_chain._git_run

    def with_a_foreign_record(
        root: pathlib.Path, arguments: list[str], *, text: bool = False
    ) -> Any:
        completed = real_git_run(root, arguments, text=text)
        if arguments[0] == "ls-tree" and arguments[-1].endswith("releases"):
            completed.stdout += b"100644 blob " + b"0" * 40 + b"\toutside/x\0"
        return completed

    monkeypatch.setattr(release_chain, "_git_run", with_a_foreign_record)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "git tree enumeration returned a path outside releases: outside/x"
    )


def test_a_root_deleted_and_recreated_in_place_is_refused(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S4R2-F3: the recorded root identity was ``(st_dev, st_ino)`` from
    an ``lstat``, and that pair is not a name for a directory over time. A
    POSIX filesystem is free to give a deleted directory's inode number to the
    next directory — or symlink — created in its place, so a root removed
    outright and replaced could be handed the number this run wrote down, and
    both comparisons against it then pass for a tree the run never selected.
    The tests above cannot show that: they rename the original aside, which
    keeps its inode live and therefore guarantees the replacement a different
    one. Here the original is deleted, which is the only way the number
    becomes available.

    What binds it is not a comparison but a descriptor: ``_set_root`` opens
    the resolved root and the gate holds it for the whole verdict, so the
    inode stays allocated to the directory this verdict is about and no other
    directory can be given its number while the run lasts. The assertions
    inside the swap say exactly that — the recreated root is not the recorded
    identity, and the held descriptor still is — and the gate then refuses.
    Without the descriptor the refusal depends on the filesystem's allocator:
    on APFS, whose inode numbers are not reused, this passes with the change
    reverted; where they are, it does not."""

    candidate = base_repository(tmp_path)
    add_gate_file(candidate)
    replacement = a_replacement_repository(candidate, tmp_path)
    # Its first row is not the frozen one, so a run that really did read this
    # tree would refuse it: the acceptance would not merely be about the
    # wrong tree, it would be about a tree this gate rejects.
    rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 1)]
    rows[0] = observation_row(99)
    write_ledger(replacement, rows)
    staged = append_gate._staged_surface_changes

    def recreate_the_root_after_classifying(
        base: append_gate._BaseCommit, tree: append_gate._CandidateTree
    ) -> tuple[set[str], set[str], set[str]]:
        classified = staged(base, tree)
        shutil.rmtree(candidate.root)
        # Created at the path, not moved there: this is the moment the freed
        # inode number could be handed out again.
        shutil.copytree(replacement, candidate.root, symlinks=True)
        recreated = os.lstat(candidate.root)
        assert (recreated.st_dev, recreated.st_ino) != tree.root_identity
        held = os.fstat(tree.root_descriptor)
        assert (held.st_dev, held.st_ino) == tree.root_identity
        return classified

    monkeypatch.setattr(
        append_gate, "_staged_surface_changes", recreate_the_root_after_classifying
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "candidate root changed during verification"


@pytest.mark.parametrize("verdict", ["accepted", "refused"])
def test_the_root_descriptor_does_not_outlive_the_verdict(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, verdict: str
) -> None:
    """S4R2-F3's other half. The root descriptor is held for exactly the run
    it speaks for: opened as the candidate tree is selected and closed once,
    on the way out, whichever way the verdict goes. A descriptor kept past the
    verdict is a directory this process is still holding open — and one leaked
    per call in a caller that verifies many trees.

    Both exits are covered because they are different code paths out of the
    same run, and the ``finally`` is what makes them the same for the
    descriptor. Without the change there is no descriptor to close."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    if verdict == "refused":
        # An ordinary refusal from the middle of the run, after the root is
        # opened and well before the end.
        (candidate.root / CHAIN_SPEC.prefix_relative).write_text(
            "{}\n", encoding="utf-8"
        )
    trees: list[append_gate._CandidateTree] = []
    real_set_root = append_gate._set_root
    closed: list[int] = []
    real_close = os.close

    def capture(root: pathlib.Path, spec: AppendGateSpec) -> Any:
        tree = real_set_root(root, spec)
        trees.append(tree)
        return tree

    def record(descriptor: int) -> None:
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(append_gate, "_set_root", capture)
    monkeypatch.setattr(os, "close", record)

    if verdict == "refused":
        with pytest.raises(AppendError):
            run_gate(candidate)
    else:
        assert run_gate(candidate) == (
            "thesis-facts append check OK: 3 rows, immutable prefix 1, "
            "+1 appended vs base"
        )

    (tree,) = trees
    # Exactly once: no descriptor this run opened afterwards can have been
    # given the root's number while the root was still holding it.
    assert closed.count(tree.root_descriptor) == 1
    with pytest.raises(OSError) as after:
        os.fstat(tree.root_descriptor)
    assert after.value.errno == errno.EBADF


def index_an_alias(candidate: Candidate, tracked: str, alias: str) -> None:
    """Add ``alias`` to the index with the blob ``tracked`` already carries.

    What a commit authored where the two names are distinct files looks like:
    two entries, and — on a filesystem that folds names — one file on disk
    once it is checked out. ``update-index --cacheinfo`` is the only way to
    write the second entry from here, because ``git add`` would go through the
    working tree and find the one file.
    """

    blob = git(candidate.root, "rev-parse", f":{tracked}")
    git(
        candidate.root,
        "update-index",
        "--add",
        "--cacheinfo",
        f"100644,{blob},{alias}",
    )


def test_an_index_alias_of_the_release_root_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4R2-F2a: the exact-spelling reconciliation the release root's
    scan makes covers the entries *under* that root, and the root's own
    component was never anybody's question. ``:(literal)releases`` does not
    match ``Releases/README.md``, so that entry is in no ``modes`` mapping, no
    walk compares it, and nothing in the gate reads it at all — while the
    commit under review carries it as a second release object and, on a
    case-insensitive filesystem, a checkout materializes it over the same
    file the protected entry names.

    The whole index is read once at entry to say so. Nothing about this
    depends on how the filesystem compares names: the entry is an alias by its
    spelling, and it is refused on every filesystem. Without the check the
    push path accepts this tree outright."""

    candidate = base_repository(tmp_path)
    index_an_alias(candidate, "releases/README.md", "Releases/README.md")

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "index carries an alias of a protected path: Releases/README.md "
        "(for releases at releases)"
    )


def test_an_index_alias_of_a_state_path_is_refused(tmp_path: pathlib.Path) -> None:
    """S4R2-F2a for the two paths the whole verdict is about, where the leaf's
    own spelling can differ too. ``assert_state_path_tracked`` and
    ``assert_index_agrees_with_tree`` both look the state path up in the index
    by the name the spec pins and are answered correctly, because that entry
    is there and is exactly what they asked for. Neither can see a second
    entry beside it that a name-folding filesystem resolves to the same file —
    a ledger this commit also carries, under a name no check here reads, whose
    bytes are whatever that entry's blob holds rather than the bytes this
    verdict read.

    Without the check this tree is accepted with the alias in the commit."""

    candidate = base_repository(tmp_path)
    index_an_alias(
        candidate,
        "ledger/official_observations.jsonl",
        "Ledger/official_observations.jsonl",
    )

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "index carries an alias of a protected path: "
        "Ledger/official_observations.jsonl "
        "(for ledger/official_observations.jsonl at ledger)"
    )


def test_an_index_alias_is_refused_against_a_base_as_well(
    tmp_path: pathlib.Path,
) -> None:
    """S4R2-F2a on the other path. The check runs once, at entry, before the
    surface classification decides which path the run takes, so a proposal
    that carries an alias is refused whether or not it names a base — and
    before the classification could report the alias as an unclassified change
    and accept it as gate-only."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    index_an_alias(candidate, "releases/README.md", "Releases/README.md")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "index carries an alias of a protected path: Releases/README.md "
        "(for releases at releases)"
    )


@pytest.mark.parametrize(
    ("tracked", "alias", "protected", "prefix"),
    [
        (
            "ledger/official_observations.jsonl",
            "Ledger",
            "ledger/official_observations.jsonl",
            "ledger",
        ),
        (
            "ledger/official_observations.jsonl",
            "Ledger/notes.txt",
            "ledger/official_observations.jsonl",
            "ledger",
        ),
        ("releases/README.md", "Releases/notes.txt", "releases", "releases"),
    ],
    ids=["ancestor-as-a-file", "under-the-ancestor", "under-the-release-root"],
)
def test_an_index_alias_of_a_protected_ancestor_is_refused(
    tmp_path: pathlib.Path, tracked: str, alias: str, protected: str, prefix: str
) -> None:
    """Binds S4R4-F6. The alias scan compared an entry against a protected
    path at that path's own depth alone, and a protected path names each of
    its ancestors as much as its leaf: ``ledger`` is the directory the state
    file is read through. An entry spelled ``Ledger`` — a file standing where
    that directory is — is shorter than the state path, and
    ``Ledger/notes.txt`` differs from it at the leaf, so at that one depth
    neither folded onto anything and neither was refused, while both are
    second committed objects a name-folding checkout materialises in the
    protected directory or over it. No other check names them either: every
    index read here asks about a path by its exact spelling, so
    ``:(literal)ledger/official_observations.jsonl`` never matches them.

    Measured at c45fcd7: the first two trees are accepted outright, as
    ``thesis-facts append check OK: 2 rows, immutable prefix 1``. The third
    was already refused, because the release root *is* one component and so
    its own depth was the prefix depth; it is here because the refusal now
    names which prefix the entry misspells, and that answer must not change
    for the case that already had one."""

    candidate = base_repository(tmp_path)
    index_an_alias(candidate, tracked, alias)

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        f"index carries an alias of a protected path: {alias} "
        f"(for {protected} at {prefix})"
    )


def test_an_ordinary_path_under_a_protected_directory_is_not_an_alias(
    tmp_path: pathlib.Path,
) -> None:
    """S4R4-F6's other side: comparing every prefix must not turn an ordinary
    file into an alias. ``ledger/notes.txt`` is spelled exactly right at every
    component it shares with the state path and differs from it at the leaf,
    which is a different file rather than a second spelling of one, and
    ``releases/README.md`` is the fixture's own. Both stay accepted."""

    candidate = base_repository(tmp_path)
    (candidate.root / "ledger" / "notes.txt").write_text("notes\n", encoding="utf-8")
    git(candidate.root, "add", "-A")

    assert run_push_gate(candidate) == (
        "thesis-facts append check OK: 2 rows, immutable prefix 1"
    )


def an_outside_release_tree(
    tmp_path: pathlib.Path,
    holding: str,
    *,
    witnesses: Witnesses,
    candidate: Candidate,
    anchors: pathlib.Path,
    chain: ChainSpec = CHAIN_SPEC,
) -> pathlib.Path:
    """A release tree outside the candidate, holding a chain that verifies.

    A chain is what makes the difference visible: the push path decides
    whether one exists by asking ``is_dir()`` about the manifest directory,
    which follows every component of the path it is given, so a root pointing
    here made this chain the one the verdict spoke for. It is a *valid* chain,
    over exactly the candidate's own state bytes, because that is what makes
    the escape an acceptance — a malformed manifest here would be refused a
    step later and the tests below would pin a rejection that says nothing
    about which tree was read.
    """

    outside = tmp_path / "outside"
    ledger_bytes, prefix_bytes = state_bytes_of(candidate, chain)
    write_release_chain(
        outside / holding,
        anchors,
        witnesses=witnesses,
        chain=chain,
        ledger_bytes=ledger_bytes,
        prefix_bytes=prefix_bytes,
    )
    return outside


def test_a_symlinked_release_root_is_refused_on_the_push_path(
    tmp_path: pathlib.Path, witnesses: Witnesses
) -> None:
    """Binds S4R2-F1: on the push path everything the gate knows about a
    release tree it learns by joining the configured root onto the candidate
    root and reading what the join lands on — ``initialized`` is
    ``manifest_directory.is_dir()``, which follows links — and nothing asked
    what the join went through. So an untracked ``releases`` pointing at a
    directory outside the checkout made the chain inside *that* directory the
    one ``verify_release_chain`` was run against, and the verdict spoke for a
    release history that is no part of the tree under review, no part of the
    commit under review, and diffable against no base.

    The root's index scan cannot say so: it refuses a symlinked root only
    when the index records entries under that root, and an untracked one
    records none, so it returns. Walking the root's own components before
    anything reads through them is what answers it, in the words this package
    has always refused a symlinked ``releases`` with.

    Without the walk this run reaches ``verify_release_chain`` and *accepts*
    on the strength of the outside chain: with the walk's body removed this
    tree returns ``thesis-facts append check OK: 2 rows, immutable prefix 1,
    release 0``, a verdict naming a release the candidate tree does not
    carry."""

    candidate = base_repository(tmp_path)
    shutil.rmtree(candidate.root / "releases")
    candidate = commit_all(candidate, "a base with no release tree")
    anchors = tmp_path / "anchors"
    outside = an_outside_release_tree(
        tmp_path,
        "manifests",
        witnesses=witnesses,
        candidate=candidate,
        anchors=anchors,
    )
    (candidate.root / "releases").symlink_to(outside)

    with pytest.raises(AppendError) as refusal:
        run_push_gate_with_anchors(candidate, anchors)
    assert str(refusal.value) == "releases must be a real directory, not a symlink"


def test_a_symlinked_parent_of_a_nested_release_root_is_refused(
    tmp_path: pathlib.Path, witnesses: Witnesses
) -> None:
    """S4R2-F1 for a component above the root, which is the same substitution
    without the root itself being a link: a spec whose release root is
    ``data/releases`` reaches it through ``data``, and a link there redirects
    the whole subtree exactly as a link at the leaf does. The leaf's own
    refusal cannot see it — ``releases`` under the link is a real directory —
    and the index scan again records nothing for an untracked root.

    The component that redirects is named, in the shape the state-path walk
    uses for the same fact. Here too the chain behind the link verifies, so
    the escape is an acceptance: with this walk's body and S4R3-F3's closing
    re-check both removed, this tree returns ``thesis-facts append check OK: 2
    rows, immutable prefix 1, release 0``. With only the walk removed the
    re-check catches it instead — ``data/releases`` ``lstat``s as a directory
    through the link while nothing was held for it — which is the two
    answering for the same fact from opposite ends of the run, not one of them
    being redundant: the leaf case above is accepted outright with the walk
    removed, because an ``lstat`` of a symlinked leaf is not a directory and
    the re-check with nothing held has nothing to object to."""

    spec = spec_with_release_root("data/releases")
    candidate = base_repository(tmp_path, "data/releases")
    shutil.rmtree(candidate.root / "data")
    candidate = commit_all(candidate, "a base with no release tree")
    anchors = tmp_path / "anchors"
    outside = an_outside_release_tree(
        tmp_path,
        "releases/manifests",
        witnesses=witnesses,
        candidate=candidate,
        anchors=anchors,
        chain=spec.chain,
    )
    (candidate.root / "data").symlink_to(outside)

    with pytest.raises(AppendError) as refusal:
        run_push_gate_with_anchors(candidate, anchors, spec=spec)
    assert str(refusal.value) == (
        "release root path traverses a symlink at 'data': data/releases"
    )


@pytest.mark.parametrize(
    "swap, refusal_text",
    [
        ("symlink", "releases must be a real directory, not a symlink"),
        ("directory", "release root changed during verification"),
    ],
    ids=["symlink", "directory"],
)
def test_a_release_root_swapped_after_its_walk_is_refused(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    witnesses: Witnesses,
    swap: str,
    refusal_text: str,
) -> None:
    """Binds S4R3-F3. The release root's walk was a pathname preflight: it
    looked at every component with ``lstat`` and returned, and everything that
    reads through that root afterwards resolves the whole name again —
    ``manifest_directory.is_dir()``, ``iterdir()``, and the chain verification
    on this path. So a root replaced *after* the walk passed was followed by
    all of them, and the index scan that ends this path cannot say so: it
    refuses a symlinked root only when the index records entries under it, and
    an untracked root records none, so it returns.

    The tree here makes the substitution visible rather than assumed. The
    chain inside the candidate enumerates but does not verify — its manifest
    is over state bytes this ledger does not hold — so an acceptance can only
    have come from the chain outside, which is valid over exactly these state
    bytes. Verified against this branch with ``_assert_release_root_unchanged``
    made a no-op, where both parameters return ``thesis-facts append check OK:
    2 rows, immutable prefix 1, release 0``.

    Both halves of the closing check are bound. Swapped for a link, the
    re-walk answers in the walk's own words, which is the more specific of the
    two true things to say; swapped for another real directory, the walk has
    nothing to object to and what refuses is the comparison of the held
    descriptor's ``fstat`` against the path's ``lstat``. What neither can do is
    see a root swapped after the walk and swapped back before the re-check;
    that residual is stated on ``release_chain.hold_release_root`` and in both
    module docstrings."""

    candidate = base_repository(tmp_path)
    shutil.rmtree(candidate.root / "releases")
    candidate = commit_all(candidate, "a base with no release tree")
    anchors = tmp_path / "anchors"
    ledger_bytes, prefix_bytes = state_bytes_of(candidate)
    write_release_chain(
        candidate.root / CHAIN_SPEC.manifest_relative,
        anchors,
        witnesses=witnesses,
        ledger_bytes=ledger_bytes + b"a row this ledger does not carry\n",
        prefix_bytes=prefix_bytes,
    )
    outside = an_outside_release_tree(
        tmp_path,
        "manifests",
        witnesses=witnesses,
        candidate=candidate,
        anchors=anchors,
    )
    release_root = candidate.root / CHAIN_SPEC.release_root_relative
    verified_for_real = append_gate.verify_release_chain

    def swap_the_root_first(*arguments: Any, **keywords: Any) -> Any:
        """Exchange the walked root, at the first read that goes through it."""

        release_root.rename(tmp_path / "the-walked-root")
        if swap == "symlink":
            release_root.symlink_to(outside)
        else:
            shutil.move(str(outside), str(release_root))
        return verified_for_real(*arguments, **keywords)

    monkeypatch.setattr(append_gate, "verify_release_chain", swap_the_root_first)

    with pytest.raises(AppendError) as refusal:
        run_push_gate_with_anchors(candidate, anchors)
    assert str(refusal.value) == refusal_text


@pytest.mark.parametrize("spelling", [".", ""], ids=["dot", "empty"])
@pytest.mark.parametrize(
    "field",
    ["release_root_relative", "manifest_relative", "anchor_relative"],
    ids=["release-root", "manifest", "anchor"],
)
def test_a_release_path_spelled_as_the_candidate_root_is_refused(
    tmp_path: pathlib.Path, field: str, spelling: str
) -> None:
    """Binds S4R4-F8. A configured release path with no components at all —
    ``.`` and the empty path both give that — names the candidate root itself,
    and the gate's own reads disagree about what is inside such a root.
    ``git ls-tree`` lists the entries under ``.`` with no prefix (``a/f.txt``,
    not ``./a/f.txt``, checked on the git this repository is verified with),
    so ``git_tree_entries`` refuses the first of them as a path outside the
    root it asked about and the base enumeration never returns; the gate-only
    confinement asks whether a changed path is ``.`` or begins with ``./`` and
    finds nothing inside the release root, so that confinement is silently a
    no-op; and the release root's hold has no component to walk.

    Only the descriptor holder ever supported such a spec, by seeding its walk
    with the candidate root — which answered the ``AssertionError`` an earlier
    draft raised, and left every read above still disagreeing. The seeding is
    gone and the spec is refused at the gate's entry instead, before the tree
    is touched.

    Measured at de1dbe4 with the refusal removed, for both spellings. A
    release root of ``.``: the push path accepts it outright, as
    ``thesis-facts append check OK: 2 rows, immutable prefix 1``, having
    walked, held and scanned nothing; against a base it is refused as ``git
    tree enumeration returned a path outside .:
    ledger/immutable_prefix.json`` — the enumeration meeting the tree's own
    first file. A manifest path of ``.``: the push path refuses as ``release
    manifest directory contains a non-regular entry: <root>/releases``, the
    enumeration having taken the whole checkout for a manifest directory,
    while against a base the tree is accepted, since no ``*.json`` sits at the
    root and the run decides there is no chain. An anchor path of ``.`` is
    accepted on both paths, because the gate reads the anchors it is handed
    rather than the candidate's. Three configurations, five different
    answers, none of them about this proposal.

    No consumer pins such a spec and no fixture here builds one; the point is
    that a verifier answers rather than asserting or half-reading."""

    candidate = base_repository(tmp_path)
    chain = replace(
        CHAIN_SPEC, **{field: pathlib.PurePosixPath(spelling)}
    )
    spec = replace(GATE_SPEC, chain=chain)
    label = {
        "release_root_relative": "release root",
        "manifest_relative": "release manifest path",
        "anchor_relative": "release anchor path",
    }[field]

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate, spec=spec)
    assert str(refusal.value) == (
        f"{label} must be a subdirectory of the candidate root"
    )

    with pytest.raises(AppendError) as with_base:
        run_gate(candidate, spec=spec)
    assert str(with_base.value) == str(refusal.value)


def test_an_ordinary_spec_names_a_subdirectory_for_every_release_path(
    tmp_path: pathlib.Path,
) -> None:
    """S4R4-F8's other side: the check is about a path with no components, and
    every spec in this repository — and every consumer's — names a
    subdirectory for all three. The fixture's own is accepted exactly as
    before."""

    for relative in (
        CHAIN_SPEC.release_root_relative,
        CHAIN_SPEC.manifest_relative,
        CHAIN_SPEC.anchor_relative,
    ):
        assert relative.parts

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )



def test_the_chain_inside_a_walked_root_is_what_the_verdict_reads(
    tmp_path: pathlib.Path, witnesses: Witnesses
) -> None:
    """S4R3-F3's control, and the half of the case the swap test asserts by
    contradiction: the in-tree chain those parameters plant really is one this
    verifier refuses, so an acceptance there could only have been the outside
    one. Left unswapped, this tree is refused for the state its own manifest
    claims."""

    candidate = base_repository(tmp_path)
    shutil.rmtree(candidate.root / "releases")
    candidate = commit_all(candidate, "a base with no release tree")
    anchors = tmp_path / "anchors"
    ledger_bytes, prefix_bytes = state_bytes_of(candidate)
    write_release_chain(
        candidate.root / CHAIN_SPEC.manifest_relative,
        anchors,
        witnesses=witnesses,
        ledger_bytes=ledger_bytes + b"a row this ledger does not carry\n",
        prefix_bytes=prefix_bytes,
    )

    with pytest.raises(AppendError) as refusal:
        run_push_gate_with_anchors(candidate, anchors)
    assert str(refusal.value) == (
        "release 0 lineCount 3 exceeds working-tree line count 2"
    )


def spec_with_nested_manifests(release_root: str = "releases") -> AppendGateSpec:
    """The fixture spec with its manifest directory one component deeper.

    ``releases/journal/manifests`` is a layout a ``ChainSpec`` permits and the
    pinned consumer does not use: the manifest directory is no longer the
    release root's own child, so ``journal`` is a component of a configured
    path that walking the release root alone never looks at.
    """

    chain = replace(
        CHAIN_SPEC,
        release_root_relative=pathlib.PurePosixPath(release_root),
        manifest_relative=pathlib.PurePosixPath(f"{release_root}/journal/manifests"),
        anchor_relative=pathlib.PurePosixPath(f"{release_root}/anchors"),
    )
    return replace(
        GATE_SPEC,
        chain=chain,
        release_manifest_prefix=f"{release_root}/journal/manifests/",
        genesis_support_files=frozenset({f"{release_root}/README.md"}),
        gate_surface=frozenset({GATE_FILE, f"{release_root}/anchors/**"}),
        data_surface=frozenset({"ledger/**", f"{release_root}/journal/**"}),
    )


def test_a_symlinked_component_below_the_release_root_is_refused(
    tmp_path: pathlib.Path, witnesses: Witnesses
) -> None:
    """Binds S4R3-F4. Only ``release_root_relative`` was walked, and the paths
    configured below it are joined onto the candidate root whole. A spec whose
    manifest directory sits more than one component under the root —
    ``releases/journal/manifests`` — reaches it through ``journal``, which no
    walk looked at: ``is_dir()``, ``iterdir()`` and the chain verification all
    follow it, and the release root's index scan cannot see it either, because
    ``rglob`` yields a symlinked directory without descending it and that scan
    skips it. An untracked link there is in no walk at all, which makes this a
    stable escape rather than a race — the same substitution S4R2-F1 closed at
    the root, one component lower down.

    The release root itself is a real, tracked directory here, so the walk
    that existed has nothing to say about this tree. Verified against 762ca71,
    where it is accepted as ``thesis-facts append check OK: 2 rows, immutable
    prefix 1, release 0`` — a verdict naming a release held entirely outside
    the checkout.

    Refused now by walking every component of ``manifest_relative`` and
    ``anchor_relative`` too, one component short of each leaf, in the words
    the root's own walk uses."""

    spec = spec_with_nested_manifests()
    candidate = base_repository(tmp_path)
    anchors = tmp_path / "anchors"
    outside = an_outside_release_tree(
        tmp_path,
        "manifests",
        witnesses=witnesses,
        candidate=candidate,
        anchors=anchors,
        chain=spec.chain,
    )
    (candidate.root / "releases" / "journal").symlink_to(outside)

    with pytest.raises(AppendError) as refusal:
        run_push_gate_with_anchors(candidate, anchors, spec=spec)
    assert str(refusal.value) == (
        "release root path traverses a symlink at 'releases/journal': "
        "releases/journal/manifests"
    )


def test_a_manifest_directory_that_is_itself_a_link_keeps_its_own_refusal(
    tmp_path: pathlib.Path, witnesses: Witnesses
) -> None:
    """S4R3-F4's boundary, which is why the two walks below the root stop one
    component short of their leaves. A symlinked manifest directory already
    has a refusal of its own, in ``_enumerate_manifest_files``'s words, and it
    is reached wherever anything is read through that directory at all.
    Walking the leaf here would replace that sentence with the walk's, for no
    fact the walk is needed to establish.

    The same tree as the case above, with the link moved down to the leaf: the
    message is the enumeration's, and this test is what holds the extension to
    the components that had no answer."""

    spec = spec_with_nested_manifests()
    candidate = base_repository(tmp_path)
    anchors = tmp_path / "anchors"
    outside = an_outside_release_tree(
        tmp_path,
        "manifests",
        witnesses=witnesses,
        candidate=candidate,
        anchors=anchors,
        chain=spec.chain,
    )
    (candidate.root / "releases" / "journal").mkdir()
    (candidate.root / "releases" / "journal" / "manifests").symlink_to(
        outside / "manifests"
    )

    with pytest.raises(AppendError) as refusal:
        run_push_gate_with_anchors(candidate, anchors, spec=spec)
    assert str(refusal.value) == (
        "release manifest path is not a regular directory: "
        f"{candidate.root}/releases/journal/manifests"
    )


def test_a_nested_manifest_directory_in_the_tree_is_accepted(
    tmp_path: pathlib.Path, witnesses: Witnesses
) -> None:
    """S4R3-F4's other side: the extension refuses links, not depth. The same
    spec with its chain really inside ``releases/journal/manifests`` is
    verified and accepted, so the walk added here costs a legitimate nested
    layout nothing."""

    spec = spec_with_nested_manifests()
    candidate = base_repository(tmp_path)
    anchors = tmp_path / "anchors"
    ledger_bytes, prefix_bytes = state_bytes_of(candidate)
    write_release_chain(
        candidate.root / spec.chain.manifest_relative,
        anchors,
        witnesses=witnesses,
        chain=spec.chain,
        ledger_bytes=ledger_bytes,
        prefix_bytes=prefix_bytes,
    )

    assert run_push_gate_with_anchors(candidate, anchors, spec=spec) == (
        "thesis-facts append check OK: 2 rows, immutable prefix 1, release 0"
    )


def a_manifest_path_that_is_not_a_directory(
    candidate: Candidate, tmp_path: pathlib.Path, shape: str
) -> None:
    """Put one of the three non-directories at the manifest path.

    Each is a thing ``manifest_directory.is_dir() and any(iterdir())`` reads as
    "this tree has no chain": a tracked regular file, a link to an empty
    directory, and a link to nothing at all.
    """

    manifests = candidate.root / CHAIN_SPEC.manifest_relative
    if shape == "tracked-blob":
        manifests.write_text("not a manifest directory\n", encoding="utf-8")
        git(candidate.root, "add", "-A")
        git(candidate.root, "commit", "--quiet", "-m", "a blob at the manifest path")
        return
    if shape == "empty-directory-link":
        empty = tmp_path / "an-empty-directory"
        empty.mkdir()
        manifests.symlink_to(empty)
        return
    manifests.symlink_to(tmp_path / "nothing-is-here")


@pytest.mark.parametrize(
    "shape",
    ["tracked-blob", "empty-directory-link", "dangling-link"],
)
def test_the_push_path_decides_the_manifest_paths_type_before_its_chain(
    tmp_path: pathlib.Path, shape: str
) -> None:
    """Binds S4R4-F3. On the push path there is no base to compare against, so
    whether this tree has a chain at all is decided by asking the filesystem:
    ``initialized`` is ``manifest_directory.is_dir() and any(iterdir())``. All
    three shapes here answer that question ``False`` — a tracked 100644 blob
    standing where the manifest directory was is not a directory, a link to an
    empty directory has nothing in it, a dangling link resolves to nothing —
    and ``False`` means "no chain", which is an acceptance with no manifest,
    no signature and no receipt verified.

    Nothing else on this path says otherwise. The release root's walk stops one
    component short of this leaf, deliberately, because the leaf has the
    enumeration's own refusal — but the enumeration only runs once something
    has decided to enumerate, and this is the decision. The root's index scan
    that follows reconciles the tracked blob with the regular file the
    traversal finds, which is exactly what it is, and holds no entry at all for
    either untracked link.

    Measured at 22da6c4 with the type decision removed: all three return
    ``thesis-facts append check OK: 2 rows, immutable prefix 1``. Refused now
    in ``_enumerate_manifest_files``'s own words, which is what a link to a
    *populated* directory here has always been refused with."""

    candidate = base_repository(tmp_path)
    a_manifest_path_that_is_not_a_directory(candidate, tmp_path, shape)

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "release manifest path is not a regular directory: "
        f"{candidate.root}/{CHAIN_SPEC.manifest_relative.as_posix()}"
    )


def test_a_manifest_path_that_is_absent_is_still_no_chain(
    tmp_path: pathlib.Path,
) -> None:
    """S4R4-F3's other side: an absent chain is legal and stays legal. The
    fixture carries no manifest directory at all, which is the ordinary
    pre-genesis tree, and the type decision returns for it exactly as
    ``_enumerate_manifest_files``'s own ``exists()`` does — the push path's
    acceptance for such a tree is unchanged."""

    candidate = base_repository(tmp_path)
    assert not (candidate.root / CHAIN_SPEC.manifest_relative).exists()

    assert run_push_gate(candidate) == (
        "thesis-facts append check OK: 2 rows, immutable prefix 1"
    )


def test_an_anchor_path_that_is_not_a_directory_keeps_its_own_refusal(
    tmp_path: pathlib.Path, witnesses: Witnesses
) -> None:
    """S4R4-F3's boundary, which is why only the manifest leaf gets a type
    decision. The release root's walk stops one component short of the anchor
    path too, on the same reasoning — the leaf has a refusal of its own — and
    unlike the manifest path nothing here decides whether the anchors are
    read. The first read through that path meets them, and a path that is not
    a directory is refused in words the extraction gave: the producer key's,
    and past it the TSA anchor's. Adding a check ahead of them would replace
    those sentences for every tree they answer.

    The anchor directory the gate reads is the one it is handed — the trusted
    code root's, or this override — so this drives it through the same
    ``release_anchor_dir`` the fixtures use. Passes either way by design."""

    candidate, _anchors, _stem = genesis_proposal(tmp_path, witnesses)
    not_a_directory = tmp_path / "anchors-as-a-file"
    not_a_directory.write_text("not a directory\n", encoding="utf-8")

    with pytest.raises(AppendError) as refusal:
        run_push_gate_with_anchors(candidate, not_a_directory)
    assert str(refusal.value) == (
        "missing or non-regular producer public key: "
        f"{not_a_directory}/{CHAIN_SPEC.producer_public_key_filename}"
    )


def test_the_base_ref_path_keeps_its_symlinked_release_root_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """S4R2-F1's placement against a base, which is the order this pins. With
    a base ref a symlinked ``releases`` was already refused, by
    ``_working_release_files`` at the top of the release-history pass, and the
    walk now runs ahead of that pass. It says the same sentence, so the
    refusal for this tree is unchanged — that is the point of borrowing the
    enumeration's words rather than minting new ones. This passes either way,
    deliberately."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    outside = tmp_path / "outside"
    shutil.move(str(candidate.root / "releases"), str(outside))
    (candidate.root / "releases").symlink_to(outside)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "releases must be a real directory, not a symlink"


@pytest.mark.parametrize("path", ["push", "base-ref"])
def test_a_release_root_spelled_differently_on_disk_is_refused(
    tmp_path: pathlib.Path, path: str
) -> None:
    """Binds S4R2-F2b: every component of a configured path was checked by
    resolving its name, and resolution is exactly where a case- or
    normalisation-insensitive filesystem answers with a directory this package
    never named. A checkout whose release directory is spelled ``Releases``
    answers to ``releases``: the enumeration walks it, the index scan
    reconciles against it, the manifests are read out of it, and the whole
    verdict is about a release tree whose name is neither the one the spec
    pins nor the one the index records. The directory's own listing is the
    question that does not go through resolution, and it says ``Releases``.

    On a filesystem that compares names exactly the rename is a deletion, so
    the spelling case cannot exist there at all — a name that resolves is a
    name its directory lists — and this tree is refused for being gone
    instead. Both answers are fail-closed and both are asserted, because the
    finding is about the filesystems where the first one is reachable. Without
    the check, a case-folding filesystem accepts this tree on both paths."""

    candidate = base_repository(tmp_path)
    (candidate.root / "releases").rename(candidate.root / "Releases")
    folded = a_folded_spelling(candidate.root, "releases")

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate) if path == "push" else run_gate(candidate)
    if folded:
        expected = (
            "path component releases is not spelled by its directory: releases"
        )
    elif path == "push":
        expected = (
            "release root is not a directory while the index records 1 entry "
            "under it"
        )
    else:
        expected = (
            f"existing release file was deleted relative to {candidate.base}: "
            "releases/README.md"
        )
    assert str(refusal.value) == expected


def test_a_nested_release_root_component_in_another_normalisation_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """S4R2-F2b for Unicode normalisation and for a component above the leaf,
    which is the same hole without any change of case: APFS and HFS+ compare
    names normalisation-insensitively, so a spec naming ``donnée/releases`` in
    NFC is answered by a directory stored in NFD, and every read below is of a
    subtree the spec does not name. The listing spells it one way, and the
    component that is not that spelling is refused.

    Where names are compared exactly the NFD rename is again a deletion, and
    the tree is refused for that instead. And on a filesystem that normalises
    a name as it stores it — a case-sensitive APFS volume does, where the
    case-insensitive one this repository sits on preserves the spelling it is
    given — the rename is neither: the directory comes back spelled exactly as
    the spec names it, which is the fixture failing to build the case rather
    than the case being answered, so it is skipped. That is the same fact
    ``a_folded_spelling`` documents for the case-folding renames, asked here of
    the spelling the spec pins rather than of a second one."""

    composed = "donnée"
    decomposed = unicodedata.normalize("NFD", composed)
    assert composed != decomposed
    spec = spec_with_release_root(f"{composed}/releases")
    candidate = base_repository(tmp_path, f"{composed}/releases")
    (candidate.root / composed).rename(candidate.root / decomposed)
    if composed in os.listdir(candidate.root):
        pytest.skip("the filesystem normalised the rename back to the pinned name")
    folded = a_folded_spelling(candidate.root, composed)

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate, spec=spec)
    if folded:
        expected = (
            f"path component {composed} is not spelled by its directory: "
            f"{composed}/releases"
        )
    else:
        expected = (
            "release root is not a directory while the index records 1 entry "
            "under it"
        )
    assert str(refusal.value) == expected


@pytest.mark.parametrize(
    ("field", "leaf"),
    [("manifest_relative", "manifests"), ("anchor_relative", "anchors")],
    ids=["manifests", "anchors"],
)
def test_a_configured_leaf_spelled_differently_on_disk_is_refused(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    leaf: str,
) -> None:
    """Binds S5-F3, simulated the way the round-9 spelling cases are. The two
    configured paths under the release root were walked one component short,
    so the one component nothing bound was the leaf — the manifest directory's
    own name, and the anchor directory's. A spec naming ``releases/manifests``
    over a ``releases/Manifests`` on disk has the chain in that directory
    verified wherever names fold and no chain at all, which is an acceptance,
    wherever they do not: one commit, two verdicts, neither about the path the
    spec pins.

    What a name-folding filesystem produces is one pair of facts — the
    directory's listing does not hold the requested spelling, and an ``lstat``
    of that spelling succeeds anyway. Here the second is real and the first is
    simulated, by answering one ``os.listdir`` of the release root with the
    folded spelling and delegating every other listing, which is the whole of
    what ``_assert_component_spelled`` reads. The real-checkout case is below.

    Measured at 62a6d03 with the leaf left out of the walk: ``thesis-facts
    append check OK: 2 rows, immutable prefix 1`` for both leaves — the
    manifest directory read as a chain the spec does not name, the anchor
    directory never questioned."""

    candidate = base_repository(tmp_path)
    for relative in (CHAIN_SPEC.manifest_relative, CHAIN_SPEC.anchor_relative):
        (candidate.root / relative).mkdir()
    release_root = candidate.root / CHAIN_SPEC.release_root_relative
    real_listdir = os.listdir

    def a_listing_that_folds(where: Any) -> list[str]:
        listed = real_listdir(where)
        if pathlib.Path(os.fspath(where)) == release_root:
            return [leaf.capitalize() if name == leaf else name for name in listed]
        return listed

    monkeypatch.setattr(os, "listdir", a_listing_that_folds)
    # The other half of the pair is real: the spelling still resolves.
    assert (release_root / leaf).is_dir()

    configured = getattr(CHAIN_SPEC, field).as_posix()
    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        f"path component {configured} is not spelled by its directory: "
        f"{configured}"
    )


@pytest.mark.skipif(
    os.getuid() == 0, reason="root lists a directory it has no rights on"
)
def test_a_manifest_directory_spelled_differently_on_disk_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """S5-F3 on a real checkout, which only a name-folding filesystem can
    carry: where names compare exactly, a directory renamed to ``Manifests``
    leaves no ``manifests`` to resolve, and the tree is the ordinary
    no-manifest-directory one this gate accepts. So this skips on ext4 and on
    CI, where the simulated case above binds the refusal, and it binds the
    whole arrangement here — the manifests really are read out of the folded
    directory, and the refusal really does stand ahead of that read.

    Measured at 62a6d03 with the leaf left out of the walk, on APFS: the
    directory spelled ``Manifests`` is opened as ``releases/manifests``, its
    contents are enumerated as the chain, and the tree is refused for what that
    file is rather than for where it is — ``unknown file in closed release
    manifest directory: notes.json``. On a filesystem that compares names
    exactly, ``releases/manifests`` resolves to nothing, which is the
    no-manifest-directory tree
    ``test_a_manifest_path_that_is_absent_is_still_no_chain`` binds as
    ``thesis-facts append check OK: 2 rows, immutable prefix 1``. Neither
    verdict is about ``releases/manifests``, and they are not the same
    verdict."""

    candidate = base_repository(tmp_path)
    manifests = candidate.root / CHAIN_SPEC.manifest_relative
    manifests.mkdir()
    (manifests / "notes.json").write_text("{}\n", encoding="utf-8")
    release_root = candidate.root / CHAIN_SPEC.release_root_relative
    manifests.rename(release_root / "Manifests")
    if not a_folded_spelling(release_root, CHAIN_SPEC.manifest_relative.name):
        pytest.skip("the rename left no folded spelling to answer for")

    configured = CHAIN_SPEC.manifest_relative.as_posix()
    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        f"path component {configured} is not spelled by its directory: "
        f"{configured}"
    )


def test_the_manifest_leaf_keeps_its_own_type_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """S5-F3's other side: what the walk binds at a leaf is its spelling, not
    its type. A manifest directory spelled exactly as the spec names it and
    standing over a symlink is still refused by
    ``assert_manifest_directory_regular`` in the enumeration's own words, and a
    regular file there likewise, because the walk asks the directory's listing
    about the name and leaves what the name resolves to alone. The two
    questions are separable because they are asked of different things.

    ``test_a_manifest_directory_that_is_itself_a_link_keeps_its_own_refusal``
    and ``test_the_push_path_decides_the_manifest_paths_type_before_its_chain``
    bind the same boundary from the other direction; this one states it for
    the leaf the walk now visits."""

    candidate = base_repository(tmp_path)
    release_root = candidate.root / CHAIN_SPEC.release_root_relative
    manifest_path = candidate.root / CHAIN_SPEC.manifest_relative
    manifest_path.write_text("not a directory\n", encoding="utf-8")
    assert CHAIN_SPEC.manifest_relative.name in os.listdir(release_root)

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        f"release manifest path is not a regular directory: {manifest_path}"
    )


def test_the_anchor_leaf_is_spelled_but_not_typed_by_the_walk(
    tmp_path: pathlib.Path,
) -> None:
    """S5-F3 for the other leaf the walk now visits, which is where the
    separation of the two questions earns its keep. A regular file standing at
    the candidate's own ``releases/anchors`` is spelled exactly as the spec
    names it, so the walk passes it — and nothing here reads that path at all:
    the anchors this gate reads come from the trusted code root or from a
    caller's override, never from the candidate. Judging the leaf's type in the
    walk would refuse this tree over a directory the verdict never opens.

    ``test_an_anchor_path_that_is_not_a_directory_keeps_its_own_refusal`` binds
    the sentence for the anchor path that *is* read; this binds that the walk
    does not take it over, and that visiting the leaf for its spelling costs
    the tree nothing."""

    candidate = base_repository(tmp_path)
    release_root = candidate.root / CHAIN_SPEC.release_root_relative
    (candidate.root / CHAIN_SPEC.anchor_relative).write_text(
        "not a directory\n", encoding="utf-8"
    )
    assert CHAIN_SPEC.anchor_relative.name in os.listdir(release_root)

    assert run_push_gate(candidate) == (
        "thesis-facts append check OK: 2 rows, immutable prefix 1"
    )


def test_a_state_path_component_spelled_differently_on_disk_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """S4R2-F2b for the two state paths, which reach their file through the
    same kind of walk and had the same gap. ``ledger/`` resolves to a
    ``Ledger/`` on disk, the descent opens it component by component and never
    asks whether the component it opened is the one the directory holds, and
    the bytes this verdict speaks for come out of a directory the index does
    not record and no surface pattern names.

    ``assert_state_path_tracked`` cannot answer it: the index entry it asks
    about is there and is exactly right, which is the point — the index is
    correct and the working tree is answering for it with something else.
    Where names are compared exactly this refusal is unreachable — the rename
    is a deletion, and a state path that is not there is a different question
    — so the test skips rather than assert a different tree's answer; what
    covers the index side there, on every filesystem, is
    ``assert_index_carries_no_protected_alias``, and what covers this check
    there is the simulated fold below. Without the check this tree is
    accepted, with the ledger read out of ``Ledger/``."""

    candidate = base_repository(tmp_path)
    (candidate.root / "ledger").rename(candidate.root / "Ledger")
    if not a_folded_spelling(candidate.root, "ledger"):
        pytest.skip("the rename left no folded spelling to answer for")

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "path component ledger is not spelled by its directory: "
        "ledger/official_observations.jsonl"
    )


def test_a_dangling_release_root_link_is_named_as_a_link(
    tmp_path: pathlib.Path,
) -> None:
    """S4R2-F1's one pre-emption, pinned rather than left incidental. A link
    at the release root that points nowhere is the one link
    ``_working_release_files`` never met: ``exists()`` follows it, finds
    nothing, and the enumeration returns an empty mapping, so against a base
    this tree was refused a file later — ``existing release file was deleted
    relative to <commit>: releases/README.md`` — for the consequence rather
    than for the link. Verified by running this tree with the walk removed.

    The walk refuses it as the link it is, which changes that refusal. Of the
    links the walk meets it is the only one whose refusal moves — a link the
    enumeration does reach still gets the enumeration's own sentence, which
    the test above pins — and this test is what holds it to that one case. It
    is not the only pre-existing refusal this round pre-empts: the spelling
    check inside both walks pre-empts whatever the content behind a folded
    name would have been refused for, which ``append_gate``'s module docstring
    states with both cases measured."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    shutil.move(str(candidate.root / "releases"), str(tmp_path / "moved-away"))
    (candidate.root / "releases").symlink_to(tmp_path / "nothing-is-here")
    assert not (candidate.root / "releases").exists()
    assert (candidate.root / "releases").is_symlink()

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == "releases must be a real directory, not a symlink"


def test_a_path_the_index_stores_as_non_utf8_bytes_is_not_the_gate_s_business(
    tmp_path: pathlib.Path,
) -> None:
    """S4R2-F2a's blast radius, bound. The alias check reads the whole index,
    and the parse it reuses decoded every path as strict UTF-8 — which was
    right while a literal pathspec meant the only records it ever saw were the
    ones about a configured path. Over the whole index it is a refusal about
    somebody else's file: git stores paths as bytes, a filename that is not
    valid UTF-8 is legal and ordinary in a history authored under a non-UTF-8
    locale, and one of them anywhere in the repository refused every proposal
    at entry with ``cannot parse the candidate index`` — verified against
    d48b8ed, where the same tree is accepted.

    The whole-index read carries such a path through with ``surrogateescape``
    instead. It cannot hide an alias: protected paths come from the spec as
    ``str``, and a filesystem that folds names is one that requires valid
    UTF-8 filenames, so a record this cannot decode is not a spelling of a
    protected path on any tree that could exist.

    The entry is written straight into the index because APFS refuses the
    filename on disk, which is also how a clone of such a history reaches a
    macOS auditor: the index carries the path, the checkout cannot."""

    candidate = base_repository(tmp_path)
    latin1 = os.fsdecode(b"notes-caf\xe9.txt")
    index_an_alias(candidate, "releases/README.md", latin1)
    recorded = release_chain._git_run(candidate.root, ["ls-files", "-z"]).stdout
    assert b"notes-caf\xe9.txt" in recorded

    assert run_push_gate(candidate) == (
        "thesis-facts append check OK: 2 rows, immutable prefix 1"
    )


@pytest.mark.parametrize(
    "component, path",
    [
        ("releases", "releases"),
        ("ledger", "ledger/official_observations.jsonl"),
    ],
    ids=["release-root", "state-path"],
)
def test_a_folded_component_is_refused_on_any_filesystem(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    component: str,
    path: str,
) -> None:
    """S4R2-F2b where the filesystem will not produce the case. A checkout
    that holds one spelling and answers to another cannot be built where names
    are compared exactly — a name that resolves is a name its directory lists
    — so on ext4, and therefore on CI, the three tests above assert the
    pre-existing refusal that fires there instead and one of them skips. Then
    nothing on the runners this project uses binds the refusal itself.

    What a name-folding filesystem produces is one pair of facts: the
    directory's listing does not hold the requested spelling, and an ``lstat``
    of that spelling succeeds anyway. Here the second is real and the first is
    simulated, by answering one ``os.listdir`` of the candidate root with the
    folded spelling and delegating every other listing. That is the whole of
    what ``_assert_component_spelled`` reads, so the refusal, its message and
    its placement are bound on every filesystem, and the tests above stay as
    the end-to-end binding wherever a real checkout can carry the case.

    Both call sites are covered, because they are two walks: the release
    root's own, and the one every state read performs."""

    candidate = base_repository(tmp_path)
    real_listdir = os.listdir

    def a_listing_that_folds(where: Any) -> list[str]:
        listed = real_listdir(where)
        if pathlib.Path(os.fspath(where)) == candidate.root:
            folded = component.capitalize()
            return [folded if name == component else name for name in listed]
        return listed

    monkeypatch.setattr(os, "listdir", a_listing_that_folds)
    # The other half of the pair is real: the spelling still resolves.
    assert (candidate.root / component).is_dir()

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        f"path component {component} is not spelled by its directory: {path}"
    )


@pytest.mark.skipif(
    os.getuid() == 0, reason="root lists a directory it has no rights on"
)
def test_a_folded_state_file_is_refused_listable_and_unlistable_alike(
    tmp_path: pathlib.Path,
) -> None:
    """The substitution S4R2-F2b is about, on a real checkout, answered both
    ways. Only a name-folding filesystem can carry it — a checkout that holds
    one spelling and answers to another cannot be built where names are
    compared exactly — so on ext4, and so on CI, this skips and the simulated
    case above binds the misspelling refusal there. It also skips as root, who
    lists a directory it has no rights on.

    Listable, the directory says which spelling it holds and the substitution
    is refused for that. Made search-only — mode 0o111, which the descent can
    still traverse — the same tree used to be accepted, with the ledger read
    out of a file the index does not name: ``thesis-facts append check OK: 2
    rows, immutable prefix 1``, measured before the check existed. S4R4-F7 is
    why the second half no longer depends on the filesystem: the directory is
    refused for not being listable at all, rather than for being shown to
    fold, so this half of the case is bound on every filesystem by the tests
    below and this one keeps it end to end where a real checkout can carry
    the first half."""

    candidate = base_repository(tmp_path)
    ledger_directory = candidate.root / "ledger"
    (candidate.root / CHAIN_SPEC.state_relative).rename(
        ledger_directory / "Official_Observations.jsonl"
    )
    if not a_folded_spelling(ledger_directory, CHAIN_SPEC.state_relative.name):
        pytest.skip("the rename left no folded spelling to answer for")

    with pytest.raises(AppendError) as listed:
        run_push_gate(candidate)
    assert str(listed.value) == (
        "path component ledger/official_observations.jsonl is not spelled by "
        "its directory: ledger/official_observations.jsonl"
    )

    ledger_directory.chmod(0o111)
    try:
        with pytest.raises(AppendError) as refusal:
            run_push_gate(candidate)
        assert str(refusal.value) == (
            "cannot bind the spelling of ledger/official_observations.jsonl: "
            "its directory cannot be listed: "
            "ledger/official_observations.jsonl"
        )
    finally:
        ledger_directory.chmod(0o755)


def stage_a_rewrite_and_restore(path: pathlib.Path, rewritten: bytes) -> bytes:
    """Record ``rewritten`` for ``path`` in the index, leaving the disk as it was.

    The shape S4R3-F1 is about, in three lines: write the bytes the commit is
    to carry, stage them, put the verified bytes back. ``git diff`` still
    reports the path (the index differs from the base), so the surface
    classification is unchanged and the data path runs; every check on that
    path then reads the disk. Returns the bytes left on disk.
    """

    kept = path.read_bytes()
    path.write_bytes(rewritten)
    git(path.parent, "add", "-A")
    path.write_bytes(kept)
    return kept


def test_a_ledger_staged_as_a_rewrite_and_restored_on_disk_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4R3-F1 for the file the whole verdict is about. Every check that
    is a verdict about the ledger's content reads the working tree: the frozen
    prefix comparison, the append-only diff, the row bindings, and the release
    verification are all fed one snapshot of the bytes on disk. The index — the
    commit under review — was compared for stage, mode and type and never for
    content, because the parse discarded the object id.

    So a proposal could stage a rewrite of the frozen prefix's own first line
    beside an ordinary append, restore the appended bytes on disk, and be
    accepted: the ledger this verdict read is a lawful append, and the ledger
    this commit carries rewrites line 1. Verified against 7f7597a, where this
    tree is accepted as ``thesis-facts append check OK: 3 rows, immutable
    prefix 1, +1 appended vs base``.

    Without ``assert_index_content_bound`` in ``check_state_modes`` this run
    returns that acceptance."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    rewritten = b" " + ledger.read_bytes()
    stage_a_rewrite_and_restore(ledger, rewritten)

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "candidate index records different content for "
        "ledger/official_observations.jsonl than the working tree this "
        "verdict read"
    )


def test_a_base_release_file_staged_as_a_rewrite_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """S4R3-F1 for a release file the base already carries. The release-history
    pass compares that file's mode and its bytes, and both comparisons read the
    working tree; ``assert_release_file_still_indexed`` beside them asks only
    whether an entry is there. ``git rm --cached`` was the hole that check
    closed — this is the other half of the same fact, an entry that is there
    and records something else.

    A file the base carries has a base blob, so the rule is at its tightest
    here: the index has to record that blob, because the pass just established
    that the bytes on disk are it. Verified against 7f7597a, where this tree is
    accepted.

    Without the call after ``assert_release_file_still_indexed`` this run
    returns that acceptance."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    readme = candidate.root / CHAIN_SPEC.release_root_relative / "README.md"
    stage_a_rewrite_and_restore(readme, b"Release history, quietly revised.\n")

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "candidate index records different content for releases/README.md "
        "than the working tree this verdict read"
    )


def test_a_pre_existing_state_refusal_precedes_the_content_binding(
    tmp_path: pathlib.Path,
) -> None:
    """S4R3-F1's placement. The binding runs after every pre-existing
    comparison for the path it is about — in ``check_state_modes``, which is
    after the frozen prefix, the append-only diff, the row checks and the
    release proposal — so a tree that is wrong in a way the extracted verifier
    already names keeps that refusal.

    Here the working tree rewrites the frozen prefix's first line and the index
    records a third thing again. The prefix comparison speaks first, in the
    words it always used.

    Without the placement — the binding moved ahead of ``check_prefix`` — this
    would answer with the index refusal instead."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    ledger = candidate.root / CHAIN_SPEC.state_relative
    rows = ledger.read_bytes().splitlines(keepends=True)
    ledger.write_bytes(b"".join([b"  " + rows[0], *rows[1:]]))
    git(candidate.root, "add", "-A")
    ledger.write_bytes(b"".join([b" " + rows[0], *rows[1:]]))

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value).startswith("immutable prefix line 1 ")


@dataclass(frozen=True)
class Witnesses:
    """One generated producer key and two locally generated timestamp authorities.

    Everything a real release carries, built offline: the anchors, policy OIDs,
    signer certificates and SPKIs are real values, so a chain written with them
    is one ``verify_release_chain`` verifies for real rather than one it skips.
    Expensive (two RSA keygens and two certificate signings), so it is built
    once per module and the trees below are written from it.
    """

    alpha: LocalTsa
    beta: LocalTsa
    private_pem: bytes
    public_pem: bytes


@pytest.fixture(scope="module")
def witnesses(tmp_path_factory: pytest.TempPathFactory) -> Witnesses:
    workspace = tmp_path_factory.mktemp("witnesses")
    alpha = build_local_tsa(workspace / "alpha", "alpha", "1.3.6.1.4.1.99999.1.1")
    beta = build_local_tsa(workspace / "beta", "beta", "1.3.6.1.4.1.99999.2.1")
    private_pem, public_pem = generate_signing_keypair()
    return Witnesses(
        alpha=alpha, beta=beta, private_pem=private_pem, public_pem=public_pem
    )


def write_release_chain(
    manifests: pathlib.Path,
    anchors: pathlib.Path,
    *,
    witnesses: Witnesses,
    chain: ChainSpec = CHAIN_SPEC,
    ledger_bytes: bytes,
    prefix_bytes: bytes,
) -> str:
    """A valid genesis release over exactly these state bytes; return its stem.

    ``manifests`` and ``anchors`` are written wherever the caller points them,
    which is the whole point for the cases below: a chain that verifies is what
    makes an escape an *acceptance* rather than a refusal about a malformed
    manifest, and where such a chain sits decides which tree a verdict spoke
    for.
    """

    manifests.mkdir(parents=True, exist_ok=True)
    anchors.mkdir(parents=True, exist_ok=True)
    (anchors / chain.producer_public_key_filename).write_bytes(witnesses.public_pem)
    for tsa in (witnesses.alpha, witnesses.beta):
        (anchors / tsa.root_pem.name).write_bytes(tsa.root_pem.read_bytes())
    lines = ledger_bytes.decode("utf-8").split("\n")[:-1]
    manifest = {
        "schemaVersion": chain.schema_version,
        "releaseIndex": 0,
        "previousManifestSha256": None,
        "state": {
            "path": chain.state_path,
            "jsonlSha256": hashlib.sha256(ledger_bytes).hexdigest(),
            "lineCount": len(lines),
            "immutablePrefixSha256": hashlib.sha256(prefix_bytes).hexdigest(),
        },
        "append": None,
        "createdAtUtc": created_at(120),
        "producer": {"repo": "TheAxiomFoundation/receipt", "branch": "fixture"},
    }
    raw = canonical_bytes(manifest) + b"\n"
    digest = hashlib.sha256(raw).hexdigest()
    stem = f"0000-{digest[:16]}"
    (manifests / f"{stem}.json").write_bytes(raw)
    (manifests / f"{stem}.producer.sig").write_bytes(
        sign_payload(witnesses.private_pem, raw, domain=b"")
    )
    for tsa in (witnesses.alpha, witnesses.beta):
        tsa.stamp(digest, manifests / f"{stem}.{tsa.name}.tsr")
    return stem


def state_bytes_of(
    candidate: Candidate, chain: ChainSpec = CHAIN_SPEC
) -> tuple[bytes, bytes]:
    return (
        (candidate.root / chain.state_relative).read_bytes(),
        (candidate.root / chain.prefix_relative).read_bytes(),
    )


def genesis_proposal(
    tmp_path: pathlib.Path, witnesses: Witnesses
) -> tuple[Candidate, pathlib.Path, str]:
    """A base with no chain, and a working tree carrying a valid genesis one.

    The anchors live outside the candidate deliberately: ``releases/anchors``
    is GATE_SURFACE here, so a proposal that wrote them into the tree would be
    a mixed data/gate proposal and never reach the release verification at all.
    The gate takes them through ``release_anchor_dir``, which is also what
    turns production pin enforcement off for these fixture identities.
    """

    candidate = base_repository(tmp_path)
    anchors = tmp_path / "anchors"
    ledger_bytes, prefix_bytes = state_bytes_of(candidate)
    stem = write_release_chain(
        candidate.root / CHAIN_SPEC.manifest_relative,
        anchors,
        witnesses=witnesses,
        ledger_bytes=ledger_bytes,
        prefix_bytes=prefix_bytes,
    )
    return candidate, anchors, stem


def run_gate_with_anchors(
    candidate: Candidate,
    anchors: pathlib.Path,
    *,
    base_ref: str | None = None,
    spec: AppendGateSpec = GATE_SPEC,
) -> str:
    return verify_append_gate(
        candidate.root,
        spec=spec,
        base_ref=candidate.base if base_ref is None else base_ref,
        release_anchor_dir=anchors,
    )


def run_push_gate_with_anchors(
    candidate: Candidate,
    anchors: pathlib.Path,
    *,
    spec: AppendGateSpec = GATE_SPEC,
) -> str:
    """The push path over a chain built by this module's own witnesses.

    ``release_anchor_dir`` is what turns production pin enforcement off for
    those generated identities, exactly as it does on the base-ref path; the
    cases that need a chain the gate actually verifies take this rather than
    ``run_push_gate``, which points the verifier at the production anchors the
    fixture has none of.
    """

    return verify_append_gate(
        candidate.root, spec=spec, release_anchor_dir=anchors
    )


def test_a_valid_genesis_proposal_is_accepted(
    tmp_path: pathlib.Path, witnesses: Witnesses
) -> None:
    """The control the three cases below need: a genesis release this fixture
    builds offline really does verify, so an acceptance means the chain was
    verified rather than that nothing was found to verify."""

    candidate, anchors, _stem = genesis_proposal(tmp_path, witnesses)
    stage(candidate)

    assert run_gate_with_anchors(candidate, anchors) == (
        "thesis-facts append check OK: 2 rows, immutable prefix 1, "
        "+0 appended vs base, release 0"
    )


@pytest.mark.parametrize("suffix", [".json", ".alpha.tsr"], ids=["manifest", "receipt"])
def test_a_new_release_file_staged_with_other_content_is_refused(
    tmp_path: pathlib.Path, witnesses: Witnesses, suffix: str
) -> None:
    """S4R3-F1 for the files a release proposal adds. A new release file has no
    base entry, so the byte comparison the release-history pass makes for an
    existing one does not apply to it; what stands in its place is the chain
    verification, and that reads the working tree — the manifest's canonical
    bytes, the signature over them, both receipts over their digest.

    Staging different bytes under the same name and restoring the verified ones
    on disk left all of it passing over content the commit does not carry.
    Verified against 7f7597a, where this tree is accepted as ``thesis-facts
    append check OK: 2 rows, immutable prefix 1, +0 appended vs base,
    release 0``.

    Both branches of the binding are covered: the manifest is bound to the
    bytes the verification itself parsed and returned, and a receipt is bound
    to a read made after it, because a receipt is never read into this process
    at all — OpenSSL opens it by pathname.

    Without ``_bind_new_release_files`` this run returns that acceptance."""

    candidate, anchors, stem = genesis_proposal(tmp_path, witnesses)
    target = candidate.root / CHAIN_SPEC.manifest_relative / f"{stem}{suffix}"
    stage_a_rewrite_and_restore(target, b"not what this verdict verified\n")

    with pytest.raises(AppendError) as refusal:
        run_gate_with_anchors(candidate, anchors)
    assert str(refusal.value) == (
        "candidate index records different content for "
        f"{CHAIN_SPEC.manifest_relative.as_posix()}/{stem}{suffix} than the "
        "working tree this verdict read"
    )


@pytest.mark.parametrize(
    "flag", ["--assume-unchanged", "--skip-worktree"], ids=["assume", "skip"]
)
def test_an_index_entry_that_hides_the_working_tree_is_refused(
    tmp_path: pathlib.Path, flag: str
) -> None:
    """Binds S4R3-F2. ``git update-index --assume-unchanged`` and
    ``--skip-worktree`` both tell git to stop comparing an entry against the
    working tree, and the whole surface classification is built on ``git
    diff``: with the bit set the ledger can be rewritten on disk and the diff
    reports nothing. Add a gate file beside it and the proposal classifies as
    gate-only, which returns before the frozen prefix, the append-only diff,
    the row bindings and the release history are read at all — so a data
    rewrite ships under a verdict that says DATA_SURFACE unchanged.

    Verified against 7f7597a, where this tree is accepted as ``thesis-facts
    append check OK: gate-only proposal; DATA_SURFACE unchanged; GATE_SURFACE
    changes=['scripts/check_append.py']``.

    Refusing the flag itself is the answer, at entry, for any entry rather
    than only the protected ones: the classification the bit corrupts covers
    every path in the tree. Without
    ``assert_index_hides_no_working_tree_change`` this run returns that
    acceptance. S5-F4 moved that refusal to this path alone, which is the path
    the classification is on; the case it binds is unchanged."""

    candidate = base_repository(tmp_path)
    state_path = CHAIN_SPEC.state_relative.as_posix()
    git(candidate.root, "update-index", flag, "--", state_path)
    append_one_row(candidate)
    add_gate_file(candidate)
    # The bit does what the finding says it does: the rewrite is invisible.
    assert git(candidate.root, "diff", "--name-only") == ""

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        f"index entry for {state_path} is marked assume-unchanged or "
        "skip-worktree, which hides working-tree changes from git"
    )


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_the_push_path_verifies_a_tree_whose_index_hides_an_entry(
    tmp_path: pathlib.Path, flag: str
) -> None:
    """Binds S5-F4. The hidden-entry refusal is about ``git diff``: the bit
    stops git comparing that path against the working tree, and the only thing
    here that reads ``git diff`` is the surface classification, which only the
    base-ref path performs. The push path names no base, classifies nothing,
    and answers for the two state files and the release tree by reading them —
    the ledger's bytes come from a descriptor this run opened, its category
    from that run's own ``lstat``, and ``assert_index_agrees_with_tree``
    compares them against the index directly rather than through a diff. So
    the bit hides nothing from this path, and refusing here refused a valid
    verification for a mechanism it does not use.

    Measured at d6f1035, where the refusal ran unconditionally: ``index entry
    for ledger/official_observations.jsonl is marked assume-unchanged or
    skip-worktree, which hides working-tree changes from git`` — for a tree
    with no proposal in it at all."""

    candidate = base_repository(tmp_path)
    state_path = CHAIN_SPEC.state_relative.as_posix()
    git(candidate.root, "update-index", flag, "--", state_path)

    assert run_push_gate(candidate) == (
        "thesis-facts append check OK: 2 rows, immutable prefix 1"
    )


def test_the_push_path_still_reads_a_ledger_its_index_hides(
    tmp_path: pathlib.Path,
) -> None:
    """S5-F4's premise, stated as a measurement rather than as reasoning. The
    reason the push path may verify a tree whose index hides an entry is that
    it never asks git what changed: it reads the ledger and refuses on what it
    finds. So the rewrite the bit conceals from ``git diff`` — which the
    assertion below shows really is concealed — is still the rewrite this path
    refuses, in the frozen prefix's own words."""

    candidate = base_repository(tmp_path)
    state_path = CHAIN_SPEC.state_relative.as_posix()
    git(candidate.root, "update-index", "--assume-unchanged", "--", state_path)
    rows = [observation_row(number) for number in range(1, BASE_ROW_COUNT + 1)]
    rows[0]["value"] = rows[0]["value"] + 1
    rows[0]["assertionVersion"]["id"] = expected_assertion_version_id(
        rows[0], GATE_SPEC
    )
    write_ledger(candidate.root, rows)
    assert git(candidate.root, "diff", "--name-only") == ""

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "immutable prefix line 1 (fixture.series.observation_1) was rewritten"
    )


def test_a_push_verification_is_not_refused_for_a_monitor_or_a_hidden_entry(
    tmp_path: pathlib.Path,
) -> None:
    """S5-F4 with S5-F2, which are the same finding from two sides: the
    checkout-level refusals this branch had accumulated were about the
    classification, and the push path performs none. A tree carrying both — a
    file-system monitor git would trust and an index entry marked
    assume-unchanged — verifies on the push path exactly as an ordinary tree
    does. At ccc20b4 the monitor alone was ``working-tree changes cannot be
    classified: core.fsmonitor is enabled…`` and the entry alone was ``index
    entry for ledger/official_observations.jsonl is marked
    assume-unchanged…``, both on this path."""

    candidate = base_repository(tmp_path)
    a_lying_file_system_monitor(candidate)
    git(
        candidate.root,
        "update-index",
        "--assume-unchanged",
        "--",
        CHAIN_SPEC.prefix_relative.as_posix(),
    )

    assert run_push_gate(candidate) == (
        "thesis-facts append check OK: 2 rows, immutable prefix 1"
    )


def test_an_index_alias_is_refused_on_the_push_path_too(
    tmp_path: pathlib.Path,
) -> None:
    """S5-F4's other half: only the hidden-entry refusal moved. An alias is a
    second committed object standing over a protected path — the one file on a
    name-folding checkout answering for either of two entries, with nothing in
    the index or the tree to say which — and that is as true of a push as of a
    proposal against a base. It is asked on both paths, and this pins that the
    split left it there.

    ``test_an_index_alias_of_the_release_root_is_refused`` and its siblings
    bind the refusal itself; this binds the path it is asked on."""

    candidate = base_repository(tmp_path)
    index_an_alias(candidate, "releases/README.md", "Releases/README.md")

    with pytest.raises(AppendError) as refusal:
        run_push_gate(candidate)
    assert str(refusal.value) == (
        "index carries an alias of a protected path: Releases/README.md "
        "(for releases at releases)"
    )


def test_an_alias_refusal_precedes_the_hidden_entry_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """S5-F4 kept the order the single function had. The alias refusal was the
    first of that read's two passes so that a tree an alias already refuses
    keeps that refusal; splitting the passes into two functions keeps the
    calls in that order, and a tree carrying both still answers with the
    alias."""

    candidate = base_repository(tmp_path)
    index_an_alias(candidate, "releases/README.md", "Releases/README.md")
    git(
        candidate.root,
        "update-index",
        "--assume-unchanged",
        "--",
        CHAIN_SPEC.state_relative.as_posix(),
    )

    with pytest.raises(AppendError) as refusal:
        run_gate(candidate)
    assert str(refusal.value) == (
        "index carries an alias of a protected path: Releases/README.md "
        "(for releases at releases)"
    )


def test_an_ordinary_proposal_carries_no_hidden_index_entry(
    tmp_path: pathlib.Path,
) -> None:
    """S4R3-F2's other side: the refusal is about a bit a proposal has to set
    on purpose, so an ordinary one is untouched. Every record in an ordinary
    candidate index reads as visible, and the proposal is accepted exactly as
    it was before the check existed."""

    candidate = base_repository(tmp_path)
    append_one_row(candidate)
    stage(candidate)

    assert [
        record.hidden
        for record in release_chain._all_index_entries(candidate.root)
    ] == [False, False, False]
    assert run_gate(candidate) == (
        "thesis-facts append check OK: 3 rows, immutable prefix 1, "
        "+1 appended vs base"
    )
