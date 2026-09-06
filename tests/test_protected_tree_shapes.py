"""PR3a shape roles, raw topology, renderers and authenticated reuse controls."""
from dataclasses import asdict, replace
from pathlib import PurePosixPath

import pytest

from receipt import protected_tree as policy, snapshot, verify
from receipt.release_chain import _base_shape_error, _protected_name_error
from m1_fixture import RawRepo, raw_repo, signed_repo, outcome


def evaluator(snap):
    return policy.TreePolicy(snap, policy_version=policy.POLICY_VERSION, work=snap.work)


def shape_plan(**changes):
    return replace(policy.ProtectionPlan(use="shape-test", obligations=("ancestors", "modes"),
        selected_prefixes=("a",), ancestor_paths=("a/b/leaf",),
        mode_roles=(("a/b/leaf", "state-leaf"),)), **changes)


@pytest.mark.parametrize("shape,mode,kind", (
    ("regular", "100644", "blob"), ("executable", "100755", "blob"),
    ("symlink", "120000", "blob"), ("gitlink", "160000", "commit"),
    ("tree", "040000", "tree"), ("empty-tree", "040000", "tree"),
))
@pytest.mark.parametrize("role", ("release-leaf", "state-leaf", "manifest-child", "ancestor", "export-leaf"))
def test_mode_object_type_role_matrix(raw_repo, shape, mode, kind, role):
    entries = (("selected/child", "100644"),) if shape == "tree" else (
        () if shape == "empty-tree" else (("selected", mode),))
    commit = raw_repo.commit(entries, empty=("selected",) if shape == "empty-tree" else ())
    with raw_repo.snapshot(commit) as snap:
        value = shape_plan(obligations=("modes",), ancestor_paths=(), mode_roles=(("selected", role),))
        view = evaluator(snap).evaluate_modes(value)
        fact = view.mode_facts["selected", role]
        assert (fact.shape, fact.mode, fact.object_type) == (shape, mode, kind)
        expected = shape in ({"tree", "empty-tree"} if role == "ancestor" else {"regular", "executable"})
        finding = view.finding_for(value.use)
        assert (finding is None) == expected
        if expected:
            assert view.require(value.use, render=_base_shape_error).entries_for(snap, use=value.use, plan=value)
        else:
            assert (finding.path, finding.raw_path, finding.role, finding.mode, finding.object_type) == (
                "selected", b"selected", role, mode, kind)
        assert snap.work.content_bytes == snap.work.attribute_bytes == snap.work.materialized_bytes == 0
    assert raw_repo.git("config", "core.precomposeUnicode") == b"false"


@pytest.mark.parametrize("mode", ("100644", "100755", "120000", "160000", "040000"))
@pytest.mark.parametrize("kind", ("blob", "tree", "commit"))
@pytest.mark.parametrize("role", ("release-leaf", "state-leaf", "manifest-child", "ancestor"))
def test_mode_object_type_cross_product_cannot_certify_wrong_object(mode, kind, role):
    # Mismatched object references are refused by snapshot authentication before
    # a view exists. Pure classification still must not call them regular.
    fact = policy.classify_mode(mode, kind)
    accepted = (mode == "040000" and kind == "tree") if role == "ancestor" else (
        mode in {"100644", "100755"} and kind == "blob")
    assert (fact.finding("leaf", role) is None) == accepted


@pytest.mark.parametrize("depth", (1, 2, 3, 4, 5))
@pytest.mark.parametrize("mode", ("120000", "100644", "100755", "160000"))
@pytest.mark.parametrize("caller", ("entry", "entries", "materialize"))
def test_d6_real_ancestor_renderers_at_every_depth(raw_repo, tmp_path, depth, mode, caller):
    parts = ("a", "b", "c", "d", "e", "leaf")
    prefix, target = "/".join(parts[:depth]), "/".join(parts)
    commit = raw_repo.commit(((prefix, mode),))
    with raw_repo.snapshot(commit) as snap:
        value = shape_plan(obligations=("ancestors",), ancestor_paths=(target,))
        view = evaluator(snap).evaluate_ancestors(value)
        finding = view.finding_for(value.use)
        assert (finding.prefix, finding.target, finding.raw_path, finding.mode, finding.role) == (
            prefix, target, prefix.encode(), mode, "ancestor")
        assert finding.kind == ("symlink" if mode == "120000" else "non-directory")
        def call():
            if caller == "materialize":
                with snap.materialize((PurePosixPath(target),), tmp_path, repertoire="portable"):
                    pytest.fail("wrong ancestor was exported")
            return getattr(snap, caller)(target)
        actual = outcome(call)
        if caller == "materialize":
            message = f"protected path ancestor is not a directory: {prefix}"
        elif mode == "120000":
            message = f"state path has a symlinked component: {prefix}"
        else:
            message = f"tree path ancestor is not a directory: {prefix}"
        assert actual == {"exception": "receipt.snapshot.SnapshotError", "message": message}


@pytest.mark.parametrize("depth", (1, 2, 3, 4))
def test_missing_ancestor_preserves_requested_path_and_first_absent_component(raw_repo, tmp_path, depth):
    parts = ("a", "b", "c", "d", "leaf-\udcff")
    target = "/".join(parts)
    parent = "/".join(parts[:depth - 1])
    commit = raw_repo.commit(empty=(parent,) if parent else ())
    with raw_repo.snapshot(commit) as snap:
        subject = evaluator(snap)
        value = shape_plan(obligations=("ancestors",), ancestor_paths=(target,), require_ancestors=True)
        view = subject.evaluate_ancestors(value)
        finding = view.finding_for(value.use)
        assert finding.kind == "missing"
        assert finding.prefix == "/".join(parts[:depth])
        assert finding.target == target
        assert finding.raw_path == finding.prefix.encode()
        assert outcome(lambda: snap.entry(target)) == {
            "exception": "receipt.snapshot.SnapshotError", "message": f"tree entry does not exist: {target}"}
        assert snap.entries(target).as_dict(include_trees=True) == {}
        with snap.materialize((PurePosixPath(target),), tmp_path, repertoire="posix-bytes") as materialized:
            assert materialized.entries == {}
        # Optional absence uses the same cached witness without inventing a
        # required state leaf for base-chain/materialization consumers.
        optional = subject.evaluate_ancestors(replace(value, require_ancestors=False))
        assert not optional.findings


def test_missing_state_leaf_retains_exact_raw_path(raw_repo):
    target = "a/b/leaf-\udcff"
    commit = raw_repo.commit(empty=("a/b",))
    with raw_repo.snapshot(commit) as snap:
        value = shape_plan(mode_roles=((target, "state-leaf"),))
        view = evaluator(snap).evaluate_modes(value)
        finding = view.findings[0]
        assert (finding.kind, finding.path, finding.raw_path) == ("missing", target, b"a/b/leaf-\xff")
        assert str(verify._custody_state_error(finding)) == f"state file is missing or not a regular file: {target}"


@pytest.mark.parametrize("change", ({"anchor_origin": "caller"}, {"selected_prefixes": ("elsewhere",)},
    {"mode_roles": (("a/b/leaf", "ancestor"),)}, {"require_ancestors": True}, {"use": "other"}))
def test_shape_selection_refuses_incompatible_plan_before_reads(raw_repo, monkeypatch, change):
    commit = raw_repo.commit((("a/b/leaf", "100644"),))
    with raw_repo.snapshot(commit) as snap:
        subject, value = evaluator(snap), shape_plan()
        final = subject.evaluate_modes(value)
        selected = final.require(value.use, render=_base_shape_error)
        monkeypatch.setattr(snapshot.TreeSnapshot, "entries", lambda *a: pytest.fail("incompatible selection read"))
        changed = replace(value, **change)
        with pytest.raises(policy.PolicyUseError, match="incompatible plan"):
            selected.entries_for(snap, use=value.use, plan=changed)
        with pytest.raises(policy.PolicyUseError, match="incompatible plan"):
            subject.evaluate_modes(changed, previous=final)


@pytest.mark.parametrize("context", ("other-subject", "other-repository", "closed", "abandoned"))
def test_shape_selections_refuse_foreign_or_finished_contexts(raw_repo, tmp_path, context):
    other = RawRepo(tmp_path / "other") if context == "other-repository" else raw_repo
    with raw_repo.snapshot() as snap:
        value = shape_plan(mode_roles=(), ancestor_paths=())
        final = evaluator(snap).evaluate_modes(value)
        selected = final.require(value.use, render=_base_shape_error)
        if context in {"other-subject", "other-repository"}:
            with other.snapshot() as foreign:
                assert foreign.tree == snap.tree
                with pytest.raises(policy.PolicyUseError, match="subject/purpose"):
                    selected.entries_for(foreign, use=value.use, plan=value)
            return
        if context == "abandoned":
            snap._abandon()
            with pytest.raises(snapshot.SnapshotError, match="abandoned"):
                selected.entries_for(snap, use=value.use, plan=value)
            return
    with pytest.raises(snapshot.SnapshotError, match="entered"):
        selected.entries_for(snap, use=value.use, plan=value)


def test_compatible_shape_reuse_is_frozen_and_performs_no_io(raw_repo, monkeypatch):
    commit = raw_repo.commit((("a/b/leaf", "100755"),), empty=("a/empty",))
    with raw_repo.snapshot(commit) as snap:
        subject, value = evaluator(snap), shape_plan()
        early = subject.evaluate_ancestors(value)
        with pytest.raises(policy.PolicyUseError, match="unevaluated"):
            early.require(value.use, render=_base_shape_error)
        before = asdict(snap.work)
        final = subject.evaluate_modes(value, previous=early)
        cost = subject.shape_work
        def forbidden(*args, **kwargs):
            pytest.fail("completed shape evaluation recomputed or read")
        monkeypatch.setattr(snapshot.TreeSnapshot, "entries", forbidden)
        monkeypatch.setattr(snapshot.TreeSnapshot, "blob", forbidden)
        monkeypatch.setattr(snapshot.TreeSnapshot, "_attribute_rules", forbidden)
        monkeypatch.setattr(policy, "classify_mode", forbidden)
        repeated = subject.evaluate_modes(value, previous=final)
        selection = repeated.require(value.use, render=_base_shape_error)
        entry = selection.entries_for(snap, use=value.use, plan=value)["a/b/leaf"]
        assert entry.mode == "100755"
        assert early.completed == frozenset(("ancestors",))
        assert repeated.completed == frozenset(("ancestors", "modes"))
        assert asdict(snap.work) == before
        assert subject.shape_work == cost
        assert repeated.entries["a/empty"].mode == "040000"
        with pytest.raises(TypeError):
            repeated.mode_facts["a/b/leaf", "state-leaf"] = None


def test_partial_history_modes_do_not_acquire_unrelated_tree(raw_repo, monkeypatch):
    commit = raw_repo.commit((("a/b/leaf", "100644"),))
    with raw_repo.snapshot(commit) as snap:
        subject = evaluator(snap)
        subject.observe_entries(snap.entries("a").as_dict().values())
        value = shape_plan(obligations=("modes",), listing_scope=(), ancestor_paths=())
        monkeypatch.setattr(snapshot.TreeSnapshot, "entries", lambda *a: pytest.fail("full listing before history"))
        assert not subject.evaluate_modes(value).findings
        # Without actual ancestor listings this view cannot claim topology.
        with pytest.raises(policy.PolicyUseError, match="ancestor listing"):
            subject.evaluate_ancestors(replace(value, obligations=("ancestors",), ancestor_paths=("a/b/leaf",)))


@pytest.mark.parametrize("method", ("evaluate_modes", "evaluate_ancestors"))
def test_internal_shape_runs_cannot_poison_an_authenticated_view(raw_repo, method):
    with raw_repo.snapshot() as snap:
        subject, value = evaluator(snap), shape_plan()
        run = policy._NameRun({}, value, policy._NameFacts())
        with pytest.raises(policy.PolicyUseError, match="does not belong"):
            getattr(subject, method)(value, _run=run)


@pytest.mark.parametrize("mode", ("100644", "100755", "120000"))
def test_object_authentication_precedes_mode_finding(raw_repo, mode):
    tree = raw_repo.git("mktree", data=b"").decode()
    root = raw_repo.hash(mode.encode() + b" leaf\0" + bytes.fromhex(tree), "tree")
    commit = raw_repo.git("commit-tree", root, data=b"wrong object reference\n").decode()
    with pytest.raises(snapshot.SnapshotError, match="not the blob"):
        with raw_repo.snapshot(commit) as snap:
            value = shape_plan(obligations=("modes",), mode_roles=(("leaf", "state-leaf"),))
            evaluator(snap).evaluate_modes(value)
