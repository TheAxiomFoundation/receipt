"""PR4 fixed committed-attribute policy; raw trees under either ignoreCase setting."""
from __future__ import annotations

from dataclasses import replace

import pytest

from receipt import protected_tree as policy, snapshot
from m1_fixture import raw_repo, signed_repo, outcome
from m1_append_fixture import append_repo


def evaluator(subject):
    return policy.TreePolicy(subject, policy_version=policy.POLICY_VERSION, work=subject.work)


def plan(*paths, **kwargs):
    return policy.ProtectionPlan(obligations=("attributes",), listing_scope=(),
        attribute_target_selectors=paths, use="attribute-unit", phase="attributes", **kwargs)


def evaluate(subject, value):
    view = evaluator(subject).evaluate_attributes(value)
    result = outcome(lambda: view.require(value.use, render=policy.attribute_error) and None)
    return view, result


@pytest.mark.parametrize("name", ("filter", "ident", "working-tree-encoding"))
@pytest.mark.parametrize("state,disposition,refuses", (
    ("{name}", "set", True), ("{name}=evil", "value", True), ("{name}=", "value", True),
    ("-{name}", "unset", False), ("!{name}", "unspecified", False), ("text", None, False),
))
def test_every_transforming_attribute_state(raw_repo, name, state, disposition, refuses):
    commit = raw_repo.commit(((".gitattributes", "100644", f"Protected.txt {state.format(name=name)}\n".encode()),))
    with raw_repo.snapshot(commit) as snap:
        view, result = evaluate(snap, plan("protected.txt"))
        assert ("exception" in result) == refuses
        fact = view.attribute_outcomes[b"protected.txt"]
        assert name not in fact.exact
        assert (fact.folded[name].disposition if name in fact.folded else None) == disposition
        if refuses:
            assert result["message"] == f"transforming attribute {name} applies to protected path protected.txt"
            assert view.findings[0].operation == "folded"
            assert (view.findings[0].source, view.findings[0].line) == (".gitattributes", 1)
            assert view.refused == {"attributes"} and not view.completed
        else:
            assert view.completed == {"attributes"} and not view.unevaluated


@pytest.mark.parametrize("name", ("text", "eol", "diff", "merge", "custom", "Filter", "IDENT"))
@pytest.mark.parametrize("state", ("{name}", "{name}=value", "-{name}", "!{name}"))
def test_harmless_states_and_attribute_names_are_case_sensitive(raw_repo, name, state):
    commit = raw_repo.commit(((".gitattributes", "100755", f"* {state.format(name=name)}\n".encode()),))
    with raw_repo.snapshot(commit) as snap:
        assert evaluate(snap, plan("missing"))[1] == {"value": None}


@pytest.mark.parametrize("rules,path,exact,folded", (
    (b"Protected.txt filter\nprotected.txt -filter\n", "Protected.txt", "set", "unset"),
    (b"protected.txt filter\nProtected.txt -filter\n", "Protected.txt", "unset", "unset"),
    (b"protected.txt filter\nProtected.txt -filter\n", "protected.txt", "set", "unset"),
    (b"Protected.txt -filter\nprotected.txt filter\n", "Protected.txt", "unset", "set"),
    (b"Protected.txt filter\nprotected.txt !filter\n", "Protected.txt", "set", "unspecified"),
    (b"protected.txt filter\nProtected.txt !filter\n", "Protected.txt", "unspecified", "unspecified"),
))
def test_exact_and_folded_resets_are_independent(raw_repo, rules, path, exact, folded):
    commit = raw_repo.commit(((".gitattributes", "100644", rules),))
    with raw_repo.snapshot(commit) as snap:
        view, result = evaluate(snap, plan(path))
        fact = view.attribute_outcomes[path.encode()]
        assert (fact.exact["filter"].disposition, fact.folded["filter"].disposition) == (exact, folded)
        assert ("exception" in result) == ("set" in {exact, folded})


def test_nearer_sources_override_each_reading_and_preserve_physical_lines(raw_repo):
    commit = raw_repo.commit(((".gitattributes", "100644", b"p/** filter\n"),
        ("p/.gitattributes", "100755", b"# comment\n\nLeaf !filter\nleaf ident\n")))
    with raw_repo.snapshot(commit) as snap:
        view, result = evaluate(snap, plan("p/Leaf"))
        fact = view.attribute_outcomes[b"p/Leaf"]
        assert fact.exact["filter"] == policy.AttributeState("unspecified", "p/.gitattributes", 3)
        assert fact.folded["ident"] == policy.AttributeState("set", "p/.gitattributes", 4)
        assert (view.findings[0].name, view.findings[0].source, view.findings[0].line) == (
            "ident", "p/.gitattributes", 4)
        assert result["message"] == "transforming attribute ident applies to protected path p/Leaf"
        with pytest.raises(TypeError):
            fact.exact["filter"] = "set"
        with pytest.raises(TypeError):
            view.attribute_outcomes[b"other"] = fact


def test_repeated_identical_rules_retain_last_source_line(raw_repo):
    commit = raw_repo.commit(((".gitattributes", "100644", b"* filter\n\n* filter\n"),))
    with raw_repo.snapshot(commit) as snap:
        view, _ = evaluate(snap, plan("path"))
        fact = view.attribute_outcomes[b"path"]
        assert fact.exact["filter"].line == fact.folded["filter"].line == 3


@pytest.mark.parametrize("mode", ("100644", "100755", "120000", "160000", "040000"))
def test_attribute_source_modes(raw_repo, mode):
    entries = () if mode == "040000" else ((".gitattributes", mode, b"* binary\n"),)
    commit = raw_repo.commit(entries, empty=(".gitattributes",) if mode == "040000" else ())
    with raw_repo.snapshot(commit) as snap:
        result = outcome(lambda: snap.refuse_transforming_attributes(("missing",)))
        if mode in {"100644", "100755"}:
            assert result == {"value": None}
        else:
            assert result == {"exception": "receipt.snapshot.SnapshotError",
                "message": f"unsupported .gitattributes entry at .gitattributes: mode {mode}"}


def test_only_exact_committed_sources_are_inputs(raw_repo, tmp_path):
    commit = raw_repo.commit(((".gitattributes", "100644", b"* -filter\n"),
                              ("P/.gitattributes", "120000"),
                              ("p/.GITATTRIBUTES", "160000")))
    (raw_repo.root / ".gitattributes").write_bytes(b"* filter\n")
    (raw_repo.root / ".git/info/attributes").write_bytes(b"* filter\n")
    global_attributes = tmp_path / "global-attributes"
    global_attributes.write_bytes(b"* filter\n")
    raw_repo.git("config", "core.attributesFile", str(global_attributes))
    with raw_repo.snapshot(commit) as snap:
        view, result = evaluate(snap, plan("p/missing"))
        assert result == {"value": None}
        assert view.attribute_outcomes[b"p/missing"].sources == (".gitattributes", "p/.gitattributes")


@pytest.mark.parametrize("payload,construct", (
    (b'"path" filter\n', "C-quoted pattern"), (b"!path filter\n", "negative pattern"),
    (b"p? filter\n", "?"), (b"[p] filter\n", "bracket expression"),
    (b"p\\q filter\n", "backslash escape"), (b"p/ filter\n", "trailing slash"),
    (b"p@ filter\n", "pattern 'p@'"), (b"p//q filter\n", "empty pattern segment"),
    (b"p**q filter\n", "misplaced **"), (b"** filter\n", "misplaced **"),
    (b"\xff filter\n", "non-ASCII pattern"), (b"p \xff\n", "non-ASCII attribute state"),
    (b"p\n", "line has no attribute state"), (b"[attr]custom filter\n", "attribute macro definition"),
    (b"p -\n", "attribute name ''"), (b"p builtin_x\n", "attribute name 'builtin_x'"),
    (b"p --name\n", "attribute name '-name'"), (b"p foo/bar\n", "attribute name 'foo/bar'"),
    (b"# comment\0\n", "control byte"), (b"p\r filter\n", "control byte"),
))
def test_unsupported_constructs_fail_closed(raw_repo, payload, construct):
    commit = raw_repo.commit(((".gitattributes", "100644", b"\n" + payload),))
    with raw_repo.snapshot(commit) as snap:
        result = outcome(lambda: snap.refuse_transforming_attributes(("path",)))
        assert result["message"] == f"unsupported .gitattributes construct at .gitattributes:2: {construct}"


def test_unsupported_construct_precedes_rule_overflow(raw_repo, monkeypatch):
    commit = raw_repo.commit(((".gitattributes", "100644", b"* -filter\n[attr]macro filter\n"),))
    monkeypatch.setattr(snapshot, "MAX_ATTRIBUTE_RULES_TOTAL", 0)
    with raw_repo.snapshot(commit) as snap:
        result = outcome(lambda: snap.refuse_transforming_attributes(("path",)))
        assert result["message"].endswith(":2: attribute macro definition")


@pytest.mark.parametrize("paths,winner", ((("z", "a"), "z"), (("a", "z"), "a"),
                                         ((b"z", "z", "a"), "z")))
def test_supplied_order_and_sorted_first_transform_are_retained(raw_repo, paths, winner):
    commit = raw_repo.commit(((".gitattributes", "100644", b"* working-tree-encoding=utf8 ident filter=x\n"),))
    with raw_repo.snapshot(commit) as snap:
        result = outcome(lambda: snap.refuse_transforming_attributes(paths))
        assert result["message"] == f"transforming attribute filter applies to protected path {winner}"
        assert policy._attribute_store(snap).work.path_outcomes == 1


@pytest.mark.parametrize("value", ("x", b"x", 1, None, snapshot.GitEntry("100644", "blob", "0" * 40, "x")))
def test_public_collection_argument_checks(raw_repo, value):
    with raw_repo.snapshot() as snap:
        assert outcome(lambda: snap.refuse_transforming_attributes(value)) == {
            "exception": "receipt.snapshot.SnapshotError", "message": "attribute paths must be an iterable of paths"}
        assert snap.work.path_bytes == 0


def test_invalid_later_input_precedes_first_transform_and_sources(raw_repo, monkeypatch):
    commit = raw_repo.commit(((".gitattributes", "100644", b"* filter\n"),))
    calls = []
    original = snapshot.TreeSnapshot._attribute_rules
    def rules(*args):
        calls.append(1)
        return original(*args)
    monkeypatch.setattr(snapshot.TreeSnapshot, "_attribute_rules", rules)
    with raw_repo.snapshot(commit) as snap:
        result = outcome(lambda: snap.refuse_transforming_attributes(("first", 3)))
        assert "transforming attribute" not in result["message"]
        assert not calls


def test_equal_oids_never_reuse_subject_acceptance(raw_repo):
    commit = raw_repo.commit(((".gitattributes", "100644", b"* -filter\n"),))
    with raw_repo.snapshot(commit) as first, raw_repo.snapshot(commit) as second:
        a, b = evaluator(first), evaluator(second)
        value = plan("path")
        view = a.evaluate_attributes(value)
        assert first.tree == second.tree and a.subject != b.subject
        with pytest.raises(policy.PolicyUseError, match="evaluator/subject"):
            b.evaluate_attributes(value, previous=view)
        other = b.evaluate_attributes(value)
        assert view.attribute_outcomes[b"path"] is not other.attribute_outcomes[b"path"]
        selection = view.require(value.use, render=policy.attribute_error)
        with pytest.raises(policy.PolicyUseError):
            selection.entries_for(second, use=value.use, plan=value)


def test_versions_plans_and_overlapping_requests_have_separate_acceptance(raw_repo, monkeypatch):
    commit = raw_repo.commit(((".gitattributes", "100644", b"* -filter\n"),))
    with raw_repo.snapshot(commit) as snap:
        a = evaluator(snap)
        value = plan("a", "b")
        first = a.evaluate_attributes(value)
        other_plan = replace(value, anchor_origin="caller", attribute_target_selectors=("b", "a"))
        second = a.evaluate_attributes(other_plan)
        assert first.plan_fingerprint != second.plan_fingerprint
        assert first.attribute_outcomes[b"a"] is second.attribute_outcomes[b"a"]
        assert a.attribute_work.rule_evaluations == 4
        assert a.attribute_work.plan_outcomes == 4
        with pytest.raises(policy.PolicyUseError, match="incompatible plan"):
            a.evaluate_attributes(other_plan, previous=first)
        # Production admits one fixed version. Simulate a second compiled
        # version to test isolation without exposing a repository policy input.
        monkeypatch.setattr(policy, "POLICY_VERSION", "test-second-version")
        b = evaluator(snap)
        third = b.evaluate_attributes(value)
        assert third.policy_version != first.policy_version
        assert third.attribute_outcomes[b"a"] is not first.attribute_outcomes[b"a"]
        assert b.attribute_work.rule_evaluations == 8
        with pytest.raises(policy.PolicyUseError, match="unsupported"):
            policy.TreePolicy(snap, policy_version="repository-supplied", work=snap.work)


def test_attribute_obligation_is_incomplete_until_its_barrier_and_invalid_after_close(raw_repo):
    commit = raw_repo.commit(((".gitattributes", "100644", b"* -filter\n"),))
    with raw_repo.snapshot(commit) as snap:
        a = evaluator(snap)
        value = replace(plan("path"), obligations=("modes", "attributes"))
        early = a.evaluate(value, stage="modes")
        assert early.unevaluated == {"attributes"}
        assert snap.work.attribute_bytes == 0
        with pytest.raises(policy.PolicyUseError, match="unevaluated"):
            early.require(value.use, render=policy.attribute_error)
        final = a.evaluate_attributes(value, previous=early)
        assert final.completed == {"modes", "attributes"}
        assert final.require(value.use, render=policy.attribute_error)
    with pytest.raises(snapshot.SnapshotError):
        final.require(value.use, render=policy.attribute_error)


def test_late_legacy_hooks_and_limits_govern_forwarding(raw_repo, monkeypatch):
    commit = raw_repo.commit(((".gitattributes", "100644", b"path -filter\n"),))
    with raw_repo.snapshot(commit) as snap:
        snap.refuse_transforming_attributes(("path",))
        before = snap.work.attribute_match_work
        original = snapshot._attribute_matches
        calls = []
        def matching(*args):
            calls.append(1)
            return original(*args)
        monkeypatch.setattr(snapshot, "_attribute_matches", matching)
        monkeypatch.setattr(snapshot, "MAX_ATTRIBUTE_MATCH_WORK", before + 2)
        result = outcome(lambda: snap.refuse_transforming_attributes(("path",)))
        assert result["message"] == f"attribute matching exceeds the work budget of {before + 2} steps"
        assert len(calls) == 1 and snap.work.attribute_match_work == before + 2


def test_late_parser_pattern_and_segment_hooks_are_forwarded(raw_repo, monkeypatch):
    calls = []
    for name in ("_parse_attribute_file", "_attribute_pattern", "_segment_matches"):
        original = getattr(policy, name)
        def hook(*args, _name=name, _original=original, **kwargs):
            calls.append(_name)
            return _original(*args, **kwargs)
        monkeypatch.setattr(policy, name, hook)
    commit = raw_repo.commit(((".gitattributes", "100644", b"path -filter\n"),))
    with raw_repo.snapshot(commit) as snap:
        snap.refuse_transforming_attributes(("path",))
    assert calls == ["_parse_attribute_file", "_attribute_pattern", "_segment_matches", "_segment_matches"]


def test_empty_pattern_and_non_utf8_transform_quote_keep_legacy_text(raw_repo):
    assert outcome(lambda: snapshot._attribute_pattern(b"", path=".gitattributes", line=2))["message"] == (
        "unsupported .gitattributes construct at .gitattributes:2: empty pattern")
    commit = raw_repo.commit(((".gitattributes", "100644", b"* filter\n"),))
    with raw_repo.snapshot(commit) as snap:
        assert outcome(lambda: snap.refuse_transforming_attributes((b"bad\xff",)))["message"] == (
            "tree entry name is not valid UTF-8 for quoting")


def test_equal_tree_oids_in_distinct_repositories_do_not_share_acceptance(raw_repo, tmp_path):
    from m1_fixture import RawRepo
    other = RawRepo(tmp_path / "another-repository")
    entries = ((".gitattributes", "100644", b"* -filter\n"),)
    with raw_repo.snapshot(raw_repo.commit(entries)) as first, other.snapshot(other.commit(entries)) as second:
        assert first.tree == second.tree
        a, b = evaluator(first), evaluator(second)
        value = plan("path")
        first_view, second_view = a.evaluate_attributes(value), b.evaluate_attributes(value)
        assert first_view.subject != second_view.subject
        assert first_view.attribute_outcomes[b"path"] is not second_view.attribute_outcomes[b"path"]
        assert a.attribute_work.rule_evaluations == b.attribute_work.rule_evaluations == 2
        with pytest.raises(policy.PolicyUseError):
            b.evaluate_attributes(value, previous=first_view)


@pytest.mark.parametrize("first,second", (("receipt.snapshot", "receipt.protected_tree"),
                                         ("receipt.protected_tree", "receipt.snapshot")))
def test_import_orders_with_late_forwarded_limits_and_hooks(first, second):
    import os
    import pathlib
    import subprocess
    import sys
    root = pathlib.Path(__file__).resolve().parents[1]
    code = f'''import {first}
import {second}
from receipt import snapshot, protected_tree
snapshot.MAX_ATTRIBUTE_STATES_PER_LINE = 0
try:
    snapshot._parse_attribute_file('.gitattributes', b'* filter\\n', rule_limit=1)
except snapshot.SnapshotError as exc:
    assert str(exc) == 'attribute states at .gitattributes:1 exceed the per-line budget of 0 states'
else:
    raise AssertionError('late legacy limit was ignored')
calls = []
def segment(pattern, value, step):
    calls.append((pattern, value))
    return False
protected_tree._segment_matches = segment
assert not snapshot._segment_matches(b'*', b'path', lambda: None)
assert calls == [(b'*', b'path')]
'''
    result = subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True,
                            timeout=30, env=os.environ | {"PYTHONPATH": str(root / "src")})
    assert (result.returncode, result.stdout, result.stderr) == (0, b"", b"")


def test_late_legacy_step_hook_invalidates_completed_matching(raw_repo, monkeypatch):
    commit = raw_repo.commit(((".gitattributes", "100644", b"* -filter\n"),))
    with raw_repo.snapshot(commit) as snap:
        snap.refuse_transforming_attributes(("path",))
        before = snap.work.attribute_match_work
        calls = []
        def step(subject):
            calls.append(subject)
            raise snapshot.SnapshotError("late step hook")
        monkeypatch.setattr(snapshot.TreeSnapshot, "_attribute_step", step)
        assert outcome(lambda: snap.refuse_transforming_attributes(("path",)))["message"] == "late step hook"
        assert calls == [snap] and snap.work.attribute_match_work == before


@pytest.mark.parametrize("consumer", ("custody", "base", "append"))
def test_consumers_reach_attribute_policy_after_their_existing_barriers(
    signed_repo, append_repo, monkeypatch, consumer,
):
    from receipt import append_gate, release_chain, verify
    from m1_append_fixture import GATE_SPEC
    calls = []
    original = policy.TreePolicy.evaluate_attributes
    def stage(subject, value=None, **kwargs):
        if kwargs.get("_run") is not None:
            calls.append((value.use, value.attribute_target_selectors, subject.snapshot.work.materialized_bytes))
        return original(subject, value, **kwargs)
    monkeypatch.setattr(policy.TreePolicy, "evaluate_attributes", stage)
    def forbidden(*args, **kwargs):
        pytest.fail("concrete verifier routed attributes through the old public method")
    monkeypatch.setattr(snapshot.TreeSnapshot, "refuse_transforming_attributes", forbidden)
    if consumer == "custody":
        result = verify.run_verification(signed_repo.root, signed_repo.loaded, commit=signed_repo.base)
        assert all(p.ok for p in result.passes)
        assert calls[0][0] == "custody"
    elif consumer == "base":
        with signed_repo.snapshot() as snap:
            result = release_chain.verify_base_release_chain(signed_repo.chain, base=snap)
            assert result.head is not None
        assert calls[0][0] == "base-chain"
    else:
        with append_repo.snapshot() as snap:
            candidate = append_gate._CandidateTree(snap, GATE_SPEC,
                GATE_SPEC.chain.state_relative.as_posix(), GATE_SPEC.chain.prefix_relative.as_posix())
            # Preserve the real state/name/attribute preflights; stop immediately
            # after that barrier, before the unrelated row/chain orchestration.
            def stop(*args, **kwargs):
                raise RuntimeError("after append attributes")
            monkeypatch.setattr(append_gate, "_read_state_blob", stop)
            with pytest.raises(RuntimeError, match="after append attributes"):
                append_gate._verify_selected_tree(candidate, base=None,
                    trusted_code_root=append_repo.root, release_anchor_dir=None)
        assert calls[0][0] == "append-attributes"
    assert len(calls) == 1 and calls[0][1]
    assert (calls[0][2] > 0) == (consumer != "append")
