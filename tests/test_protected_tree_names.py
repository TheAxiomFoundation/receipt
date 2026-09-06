"""PR2 name evidence and provenance, using raw Git objects (no checkout)."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from pathlib import PurePosixPath

import pytest

from receipt import _names, protected_tree as policy, snapshot
from receipt.release_chain import _protected_name_error
from m1_fixture import RawRepo, raw_repo


def plan(**changes):
    value = policy.ProtectionPlan.chain_names(
        (PurePosixPath("protected"),), repertoire="portable",
        release_directories=(PurePosixPath("protected"),),
    )
    return replace(value, **changes)


def evaluator(snap):
    return policy.TreePolicy(snap, policy_version=policy.POLICY_VERSION, work=snap.work)


def test_plan_normalizes_without_deduplicating_or_reordering():
    prefixes = [PurePosixPath("b"), PurePosixPath("a"), PurePosixPath("b")]
    value = policy.ProtectionPlan(selected_prefixes=prefixes,
        configured_alias_targets=prefixes, exact_state_paths=["state"],
        exact_attested_paths=["attested"], attribute_target_selectors=["rules/**"],
        export_prefixes=prefixes, anchor_origin="caller", phase="append")
    prefixes.clear()
    assert value.selected_prefixes == ("b", "a", "b")
    assert value.configured_alias_targets == value.export_prefixes == ("b", "a", "b")
    assert value.exact_state_paths == ("state",)
    assert value.exact_attested_paths == ("attested",)
    assert value.attribute_target_selectors == ("rules/**",)
    assert value.fingerprint == replace(value).fingerprint
    assert value.fingerprint != replace(value, anchor_origin="tree").fingerprint
    with pytest.raises(FrozenInstanceError):
        value.repertoire = "posix-bytes"


@pytest.mark.parametrize("name,portable", (
    ("A_9-z.txt", True), (".axiom", True), ("COM0", True),
    ("bad?", False), ("has space", False), ("name.", False),
    ("AUX", False), ("cOm9.log", False), ("é", False), ("é", False),
))
@pytest.mark.parametrize("repertoire", ("portable", "posix-bytes"))
def test_repertoire_matrix(raw_repo, name, portable, repertoire):
    commit = raw_repo.commit((("protected/" + name, "100644"),))
    with raw_repo.snapshot(commit) as snap:
        value = plan(repertoire=repertoire)
        view = evaluator(snap).evaluate(value, stage="suffixes")
        finding = view.finding_for(value.use)
        if portable or repertoire == "posix-bytes":
            assert finding is None
            assert view.require(value.use, render=_protected_name_error).completed == frozenset(policy.NAME_STAGES)
        else:
            assert finding.stage == "names"
            assert finding.operation == "component"
            assert finding.name == name
            with pytest.raises(ValueError, match="not a portable name"):
                view.require(value.use, render=_protected_name_error)


def test_raw_bytes_roundtrip_without_out_of_scope_folds(raw_repo):
    raw = b"unused/raw-\xff-\xfe"
    commit = raw_repo.commit(((raw, "100644"),), empty=(b"unused/empty-\x80",))
    with raw_repo.snapshot(commit) as snap:
        value = plan(repertoire="posix-bytes")
        view = evaluator(snap).evaluate(value, stage="suffixes")
        assert view.finding_for(value.use) is None
        assert raw in view.raw_paths
        assert tuple(p.encode("utf-8", "surrogateescape") for p in view.names) == view.raw_paths
        assert view.listings["unused"]["empty-\udc80"].mode == "040000"
        assert "raw-\udcff-\udcfe" not in view.fold_index
        entry = view.entries[raw.decode("utf-8", "surrogateescape")]
        assert snap.blob(entry, limit=100) == b"probe\n"


@pytest.mark.parametrize("repertoire", ("portable", "posix-bytes"))
@pytest.mark.parametrize("location,whole", (("protected", False), ("unused", True)))
def test_utf8_folding_failure_is_at_legacy_substep(raw_repo, repertoire, location, whole):
    commit = raw_repo.commit(((location.encode() + b"/bad\xff", "100644"),))
    with raw_repo.snapshot(commit) as snap:
        value = plan(repertoire=repertoire, fold_whole_alias_paths=whole)
        view = evaluator(snap).evaluate(value, stage="suffixes")
        finding = view.finding_for(value.use)
        assert finding.detail == "tree entry name is not valid UTF-8 for folding"
        assert finding.stage == ("aliases" if whole else "names")


def test_ascii_only_unicode_siblings(raw_repo):
    names = ("é", "é", "Ä", "ä", "Σ", "σ")
    commit = raw_repo.commit(tuple(("protected/" + n, "100644") for n in names))
    with raw_repo.snapshot(commit) as snap:
        view = evaluator(snap).evaluate(plan(repertoire="posix-bytes"), stage="suffixes")
        assert not view.findings
        assert {n: view.fold_index[n] for n in names} == {n: n for n in names}


@pytest.mark.parametrize("left", ("blob", "tree", "empty"))
@pytest.mark.parametrize("right", ("blob", "tree", "empty"))
def test_tree_blob_and_empty_tree_sibling_witnesses(raw_repo, left, right):
    entries, empty = [], []
    for name, shape in (("A", left), ("a", right)):
        path = "protected/" + name
        if shape == "empty":
            empty.append(path)
        else:
            entries.append((path + ("/leaf" if shape == "tree" else ""), "100644"))
    commit = raw_repo.commit(entries, empty=empty)
    with raw_repo.snapshot(commit) as snap:
        view = evaluator(snap).evaluate(plan(), stage="suffixes")
        finding = view.findings[0]
        assert (finding.kind, finding.parent, finding.other_name, finding.name) == (
            "sibling-alias", "protected", "A", "a")
        assert finding.raw_path == b"protected/a"
        assert len(view.findings) == 1


@pytest.mark.parametrize("depth", (1, 2, 3, 4))
@pytest.mark.parametrize("shape", ("blob", "tree", "empty", "symlink", "gitlink"))
def test_lone_configured_alias_at_every_depth(raw_repo, depth, shape):
    components = ["a", "b", "c", "d"][:depth]
    components[-1] = components[-1].upper()
    path = "/".join(components)
    listed = path + "/leaf" if shape == "tree" else path
    mode = {"blob": "100644", "tree": "100644", "symlink": "120000", "gitlink": "160000"}.get(shape)
    commit = raw_repo.commit(((listed, mode),) if mode else (), empty=(path,) if shape == "empty" else ())
    value = policy.ProtectionPlan.chain_names((PurePosixPath("a/b/c/d"),),
        repertoire="portable", release_directories=())
    with raw_repo.snapshot(commit) as snap:
        finding = evaluator(snap).evaluate(value, stage="aliases").findings[0]
        assert finding.kind == "configured-alias"
        assert finding.path == listed
        assert finding.target == "a/b/c/d"
        assert finding.prefix == "/".join(("a", "b", "c", "d")[:depth])


@pytest.mark.parametrize("targets,expected", (
    (("a/b", "a/B/c"), "a/b"), (("a/B/c", "a/b"), "a/B/c"),
    (("a/b/c", "a/B/d"), "a/b/c"), (("a/B/d", "a/b/c"), "a/b/c"),
    (("a/b/C", "a/B/c"), "a/b/C"), (("a/B/c", "a/b/C"), "a/B/c"),
))
def test_ordered_nested_target_witnesses(raw_repo, targets, expected):
    commit = raw_repo.commit((("a/B/C/leaf", "100644"),))
    value = plan(configured_alias_targets=targets)
    with raw_repo.snapshot(commit) as snap:
        finding = evaluator(snap).evaluate(value, stage="aliases").findings[0]
        assert finding.target == expected


@pytest.mark.parametrize("bad,winner", (("unused/bad\udcff", "configured-alias"),
                                         ("AAA-bad\udcff", "name")))
def test_append_entry_interleave(raw_repo, bad, winner):
    commit = raw_repo.commit((("Protected/leaf", "100644"), (bad, "100644")))
    with raw_repo.snapshot(commit) as snap:
        view = evaluator(snap).evaluate(plan(repertoire="posix-bytes", fold_whole_alias_paths=True), stage="suffixes")
        assert view.findings[0].kind == winner
        assert view.findings[0].stage == "aliases"
        assert view.unevaluated == frozenset(("names", "siblings", "suffixes"))


def test_non_tree_witness_precedes_earlier_empty_tree(raw_repo):
    commit = raw_repo.commit((("Protected/z", "100644"),), empty=("PROTECTED",))
    with raw_repo.snapshot(commit) as snap:
        view = evaluator(snap).evaluate(plan(), stage="aliases")
        assert view.findings[0].path == "Protected/z"


@pytest.mark.parametrize("include", (False, True))
def test_disjoint_caller_anchor_scope(raw_repo, include):
    commit = raw_repo.commit(((b"anchors/bad\xff", "100644"),))
    prefixes = (PurePosixPath("protected"),) + ((PurePosixPath("anchors"),) if include else ())
    value = policy.ProtectionPlan.chain_names(prefixes, repertoire="posix-bytes",
        release_directories=(), anchor_origin="tree" if include else "caller")
    with raw_repo.snapshot(commit) as snap:
        view = evaluator(snap).evaluate(value, stage="suffixes")
        assert bool(view.findings) == include


@pytest.mark.parametrize("suffix,refuses", ((".s", False), (".si", False), (".sig", True),
                                            (".sigx", False), (".tar.sig", False)))
def test_short_name_suffix_lengths(raw_repo, suffix, refuses):
    commit = raw_repo.commit((("protected/hidden.sigxyz", "100644"),))
    with raw_repo.snapshot(commit) as snap:
        view = evaluator(snap).evaluate(plan(content_suffixes=(suffix,)), stage="suffixes")
        assert bool(view.findings) == refuses
        if refuses:
            assert view.findings[0].kind == "short-suffix"
            assert view.findings[0].suffixes == (suffix,)


def test_none_is_not_acceptance_and_later_obligations_remain_incomplete(raw_repo):
    with raw_repo.snapshot() as snap:
        subject = evaluator(snap)
        value = plan(obligations=(*policy.NAME_STAGES, "attributes"))
        early = subject.evaluate(value, stage="aliases")
        assert early.finding_for(value.use) is None
        with pytest.raises(policy.PolicyUseError, match="unevaluated"):
            early.require(value.use, render=_protected_name_error)
        names = subject.evaluate(value, stage="suffixes", previous=early)
        assert names.unevaluated == frozenset(("attributes",))
        with pytest.raises(policy.PolicyUseError, match="unevaluated"):
            names.require(value.use, render=_protected_name_error)


def test_compatible_stages_reuse_completed_facts_and_frozen_storage(raw_repo):
    commit = raw_repo.commit((("protected/a", "100644"),), empty=("protected/empty",))
    with raw_repo.snapshot(commit) as snap:
        subject, value = evaluator(snap), plan()
        early = subject.evaluate(value, stage="aliases")
        counters = vars(snap.work).copy()
        final = subject.evaluate(value, stage="suffixes", previous=early)
        work = subject.name_work
        repeated = subject.evaluate(value, stage="suffixes", previous=final)
        assert subject.name_work == work
        assert vars(snap.work) == counters
        assert early.completed == frozenset(("aliases",))
        assert final.completed == repeated.completed == frozenset(policy.NAME_STAGES)
        assert final.subject == subject.subject
        assert final.plan_fingerprint == value.fingerprint
        assert final.entries["protected/empty"].mode == "040000"
        for mapping in (final.entries, final.listings, final.listings["protected"], final.fold_index):
            with pytest.raises(TypeError):
                mapping["forged"] = None
        selected = final.require(value.use, render=_protected_name_error)
        assert selected.entries_for(snap, use=value.use) == final.entries


@pytest.mark.parametrize("change", (
    {"repertoire": "posix-bytes"}, {"content_suffixes": (".yml",)},
    {"selected_prefixes": ("other",)}, {"anchor_origin": "caller"},
    {"exact_state_paths": ("other",)}, {"attribute_target_selectors": ("other/**",)},
))
def test_incompatible_plan_rejected_before_listing(raw_repo, monkeypatch, change):
    with raw_repo.snapshot() as snap:
        subject, value = evaluator(snap), plan()
        view = subject.evaluate(value, stage="aliases")
        monkeypatch.setattr(snapshot.TreeSnapshot, "entries", lambda *a: pytest.fail("read before provenance check"))
        with pytest.raises(policy.PolicyUseError, match="incompatible plan"):
            subject.evaluate(replace(value, **change), stage="suffixes", previous=view)


@pytest.mark.parametrize("kind", ("same-subject-evaluator", "second-session", "same-oid-repository"))
def test_foreign_provenance_rejected(raw_repo, tmp_path, monkeypatch, kind):
    other_repo = RawRepo(tmp_path / "other")
    # Empty trees are equal even though repositories and sessions differ.
    with raw_repo.snapshot() as snap, (other_repo if kind == "same-oid-repository" else raw_repo).snapshot() as other:
        first = evaluator(snap)
        view = first.evaluate(plan(), stage="aliases")
        second = evaluator(snap if kind == "same-subject-evaluator" else other)
        assert snap.tree == other.tree
        monkeypatch.setattr(snapshot.TreeSnapshot, "entries", lambda *a: pytest.fail("foreign view performed I/O"))
        with pytest.raises(policy.PolicyUseError, match="evaluator/subject"):
            second.evaluate(plan(), stage="suffixes", previous=view)


def test_forged_views_and_selections_refuse(raw_repo):
    with raw_repo.snapshot() as snap:
        subject, value = evaluator(snap), plan()
        view = subject.evaluate(value, stage="suffixes")
        with pytest.raises(policy.PolicyUseError, match="evaluator/subject"):
            replace(view).require(value.use, render=_protected_name_error)
        selected = view.require(value.use, render=_protected_name_error)
        with pytest.raises(policy.PolicyUseError, match="subject/purpose"):
            replace(selected).entries_for(snap, use=value.use)
        with pytest.raises(policy.PolicyUseError, match="different purpose"):
            view.require("export", render=_protected_name_error)


@pytest.mark.parametrize("abandon", (False, True))
def test_closed_or_abandoned_selection_refuses(raw_repo, abandon):
    with raw_repo.snapshot() as snap:
        subject, value = evaluator(snap), plan()
        view = subject.evaluate(value, stage="suffixes")
        selected = view.require(value.use, render=_protected_name_error)
        if abandon:
            snap._abandon()
            with pytest.raises(snapshot.SnapshotError, match="abandoned"):
                selected.entries_for(snap, use=value.use)
            return
    with pytest.raises(snapshot.SnapshotError):
        selected.entries_for(snap, use=value.use)


def test_partial_listing_does_not_visit_unrelated_bad_tree(raw_repo):
    tree = raw_repo.git("write-tree").decode()
    malformed = raw_repo.hash(b"malformed", "tree")
    tree = raw_repo.tree_replace(tree, b"unused", "040000", malformed)
    commit = raw_repo.git("commit-tree", tree, data=b"partial\n").decode()
    value = plan(listing_scope=("protected",), ancestor_listing_scope=())
    with raw_repo.snapshot(commit) as snap:
        subject = evaluator(snap)
        view = subject.evaluate(value, stage="suffixes")
        assert not view.findings
        assert view.listing_scopes == ("protected",)
        with pytest.raises(snapshot.SnapshotError):
            subject.read_listing("")


@pytest.mark.parametrize("method", ("evaluate_modes", "evaluate_ancestors", "select_export", "evaluate_attributes"))
def test_later_stage_contracts_stay_unimplemented(raw_repo, method):
    with raw_repo.snapshot() as snap:
        with pytest.raises(NotImplementedError):
            getattr(evaluator(snap), method)()


def test_scoped_immediate_ancestors_do_not_screen_their_descendants(raw_repo):
    commit = raw_repo.commit((("a/b/selected/leaf", "100644"),
        ("a/unused/bad?", "100644"), ("a/unused/A", "100644"), ("a/unused/a", "100644")))
    value = policy.ProtectionPlan.chain_names((PurePosixPath("a/b/selected"),),
        repertoire="portable", release_directories=())
    assert value.ancestor_listing_scope == ("", "a", "a/b")
    with raw_repo.snapshot(commit) as snap:
        subject = evaluator(snap)
        assert not subject.evaluate(value, stage="suffixes").findings
        whole = subject.evaluate(replace(value, whole_tree_name_scope=True), stage="suffixes")
        assert whole.findings[0].path == "a/unused/bad?"
        assert whole.findings[0].stage == "names"


def test_all_names_precede_siblings_even_at_earlier_paths(raw_repo):
    commit = raw_repo.commit(tuple(("protected/" + n, "100644") for n in ("A", "a", "z?")))
    with raw_repo.snapshot(commit) as snap:
        finding = evaluator(snap).evaluate(plan(), stage="suffixes").findings[0]
        assert (finding.stage, finding.path) == ("names", "protected/z?")


def test_target_folds_precede_listed_entry_traversal(raw_repo):
    commit = raw_repo.commit((("Protected/leaf", "100644"),))
    with raw_repo.snapshot(commit) as snap:
        value = plan(configured_alias_targets=("protected", "bad\udcff"))
        finding = evaluator(snap).evaluate(value, stage="aliases").findings[0]
        assert finding.operation == "target-fold"
        assert finding.position == (0, 1, 1)


def test_name_evaluation_reads_no_payload_or_attributes(raw_repo, monkeypatch):
    commit = raw_repo.commit((("protected/file", "100644"),
                              (".gitattributes", "100644", b"* filter\n")))
    with raw_repo.snapshot(commit) as snap:
        def forbidden(*args, **kwargs):
            pytest.fail("name evaluation read protected payload or attributes")
        monkeypatch.setattr(snapshot.TreeSnapshot, "blob", forbidden)
        monkeypatch.setattr(snapshot.TreeSnapshot, "_attribute_rules", forbidden)
        view = evaluator(snap).evaluate(plan(), stage="suffixes")
        assert not view.findings
        assert snap.work.attribute_bytes == snap.work.content_bytes == 0


@pytest.mark.parametrize("name", (b"", b".", b"..", b"two/components"))
def test_reader_grammar_precedes_policy(raw_repo, name):
    blob = raw_repo.hash(b"payload\n")
    tree = raw_repo.hash(b"100644 " + name + b"\0" + bytes.fromhex(blob), "tree")
    commit = raw_repo.hash((f"tree {tree}\nauthor Test <a@b> 0 +0000\n"
                           "committer Test <a@b> 0 +0000\n\nraw grammar\n").encode(), "commit")
    with pytest.raises(snapshot.SnapshotError, match="invalid entry name"):
        with raw_repo.snapshot(commit) as snap:
            evaluator(snap).evaluate(plan(), stage="aliases")


@pytest.mark.parametrize("siblings", ((b"a", b"a"), ("a", "a"), (b"a", "a")))
def test_duplicate_inputs_are_admitted_before_deduplication(siblings):
    with pytest.raises(_names.NamePolicyError) as caught:
        policy.screen_siblings(siblings, repertoire="posix-bytes")
    assert type(caught.value) is _names.NamePolicyError
    assert str(caught.value) == "tree directory contains a duplicate entry name: 'a'"


def test_renderer_cannot_turn_a_finding_into_acceptance(raw_repo):
    commit = raw_repo.commit((("Protected/leaf", "100644"),))
    with raw_repo.snapshot(commit) as snap:
        value = plan()
        view = evaluator(snap).evaluate(value, stage="suffixes")
        with pytest.raises(policy.PolicyUseError, match="renderer must refuse"):
            view.require(value.use, render=lambda finding: None)


def test_directory_evidence_and_plan_selectors_are_frozen_non_callbacks(raw_repo):
    observations = [["path", "regular"]]
    evidence = policy.DirectoryEvidence(observations=observations)
    observations[0][1] = "changed"
    assert evidence.observations == (("path", "regular"),)
    with pytest.raises(policy.PolicyUseError, match="path strings"):
        plan(attribute_target_selectors=(lambda path: True,))
    with raw_repo.snapshot() as snap:
        with pytest.raises(policy.PolicyUseError, match="subject/work mismatch"):
            policy.TreePolicy(evidence, policy_version=policy.POLICY_VERSION, work=snap.work)


def test_duplicate_target_witness_keeps_original_input_ordinal(raw_repo):
    with raw_repo.snapshot() as snap:
        value = plan(configured_alias_targets=("safe", "safe", "bad\udcff"))
        finding = evaluator(snap).evaluate(value, stage="aliases").findings[0]
        assert finding.position == (0, 2, 1)


def test_unrepresentable_mapping_name_keeps_primitive_refusal():
    entries = {"protected/\ud800": snapshot.GitEntry("100644", "blob", "0" * 40, "protected/\ud800")}
    finding = policy.evaluate_name_mapping(entries, plan())
    assert finding.kind == "name"
    assert finding.raw_path is None
    assert finding.detail == "tree entry name cannot be represented as Git tree-name bytes: '\\ud800'"
