"""PR3b export authority, topology and retained physical facade boundaries."""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from receipt import protected_tree as policy, release_chain, snapshot
from m1_fixture import RawRepo, raw_repo, signed_repo, outcome, assert_golden


def export_view(snap, prefixes=("protected",), *, stage="export-names"):
    evaluator = policy.TreePolicy(snap, policy_version=policy.POLICY_VERSION, work=snap.work)
    plan = policy.ProtectionPlan.materialization(prefixes, repertoire="portable")
    return evaluator, evaluator.evaluate(plan, stage=stage)


def certify(evaluator, view):
    return evaluator.select_export(view, render=snapshot.Materialization._export_error)


@pytest.mark.parametrize("prefix", ("protected", "protected/empty", "missing", ""))
def test_empty_trees_and_ancestor_aliases_are_facts_without_writes(raw_repo, tmp_path, prefix):
    commit = raw_repo.commit((("protected/file", "100755", b"executable"),),
                             empty=("protected/empty", "Protected", "protected/FILE"))
    scratch = tmp_path / "exports"
    scratch.mkdir()
    with raw_repo.snapshot(commit) as snap:
        evaluator, view = export_view(snap, (prefix,))
        assert {r.name for r in view.raw_listings[""]} == {b"Protected", b"protected"}
        if prefix in {"", "protected", "protected/empty"}:
            assert view.mode_facts["protected/empty", "ancestor"].shape == "empty-tree"
            assert view.raw_listings["protected/empty"] == ()
        selected = certify(evaluator, view)
        expected = {"protected/file"} if prefix in {"", "protected"} else set()
        assert set(selected.entries_for(snap, use=view.plan.use, plan=view.plan)) == expected
        assert list(scratch.iterdir()) == []
        with snap.materialize((prefix,), scratch, repertoire="portable") as materialized:
            assert set(materialized.entries) == expected
            assert "Protected" not in os.listdir(materialized.path)
            assert not (materialized.path / "protected/empty").exists()
            if expected:
                assert stat.S_IMODE((materialized.path / "protected/file").stat().st_mode) == 0o755
                assert (materialized.path / "protected/file").read_bytes() == b"executable"
        assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("mode", ("100644", "100755", "120000", "160000"))
def test_selected_modes_are_screened_before_scratch_creation(raw_repo, tmp_path, monkeypatch, mode):
    commit = raw_repo.commit((("file", mode, b"payload"),))
    scratch = tmp_path / "exports"
    scratch.mkdir()
    created = []
    original = snapshot.tempfile.mkdtemp
    def mkdir(*args, **kwargs):
        created.append(kwargs)
        return original(*args, **kwargs)
    with raw_repo.snapshot(commit) as snap, monkeypatch.context() as patch:
        patch.setattr(snapshot.tempfile, "mkdtemp", mkdir)
        def call():
            with snap.materialize(("file",), scratch, repertoire="portable") as materialized:
                assert (materialized.path / "file").read_bytes() == b"payload"
                return sorted(materialized.entries)
        assert_golden(f"payload/{mode}/materialize", outcome(call))
    assert len(created) == (1 if mode in {"100644", "100755"} else 0)
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("bad,link", (("a?", "z-link"), ("z?", "a-link")))
def test_standalone_all_modes_precede_names_but_custody_names_win(raw_repo, tmp_path, bad, link):
    commit = raw_repo.commit(((f"protected/{bad}", "100644"), (f"protected/{link}", "120000")))
    scratch = tmp_path / "exports"
    scratch.mkdir()
    with raw_repo.snapshot(commit) as snap:
        evaluator, view = export_view(snap)
        finding = view.finding_for(view.plan.use)
        assert finding.stage == "modes" and finding.path == f"protected/{link}"
        assert evaluator.name_work.sibling_steps == 0
        with pytest.raises(snapshot.SnapshotError, match="base tree entry has non-regular mode 120000"):
            with snap.materialize(("protected",), scratch, repertoire="portable"):
                pytest.fail("mode refusal reached writer")
        names = policy.ProtectionPlan.chain_names((PurePosixPath("protected"),),
            repertoire="portable", release_directories=(), use="custody")
        custody = evaluator.evaluate(names, stage="suffixes")
        assert custody.finding_for("custody").stage == "names"
        assert custody.finding_for("custody").path == f"protected/{bad}"
    assert list(scratch.iterdir()) == []


def test_export_refuses_incomplete_forged_and_incompatible_views(raw_repo):
    commit = raw_repo.commit((("protected/file", "100644"),))
    with raw_repo.snapshot(commit) as snap:
        evaluator, early = export_view(snap, stage="modes")
        assert early.finding_for(early.plan.use) is None
        with pytest.raises(policy.PolicyUseError, match="unevaluated"):
            certify(evaluator, early)
        with pytest.raises(policy.PolicyUseError, match="does not belong"):
            certify(evaluator, replace(early, completed=frozenset(policy.EXPORT_STAGES), unevaluated=frozenset()))
        full = evaluator.evaluate(early.plan, stage="export-names", previous=early)
        selected = certify(evaluator, full)
        assert list(selected.entries_for(snap, use=full.plan.use, plan=full.plan)) == ["protected/file"]
        with pytest.raises(TypeError):
            full.raw_listings[""] = ()
        with pytest.raises(TypeError):
            selected.entries["forged"] = snap.entry("protected/file")
        for changed in (replace(full.plan, anchor_origin="caller"),
                        replace(full.plan, repertoire="posix-bytes"),
                        replace(full.plan, use="custody"),
                        replace(full.plan, export_prefixes=("elsewhere",))):
            with pytest.raises(policy.PolicyUseError):
                selected.entries_for(snap, use=full.plan.use, plan=changed)
            with pytest.raises(policy.PolicyUseError):
                evaluator.evaluate(changed, stage="export-names", previous=full)
        with pytest.raises(policy.PolicyUseError, match="purpose"):
            selected.entries_for(snap, use="custody")
        wrong = replace(full.plan, export_prefixes=("elsewhere",))
        with pytest.raises(policy.PolicyUseError, match="incompatible"):
            evaluator.evaluate(wrong, stage="export-names")
        attributes = replace(full.plan, obligations=(*policy.EXPORT_STAGES, "attributes"))
        with pytest.raises(policy.PolicyUseError):
            evaluator.evaluate(attributes, stage="export-names")


@pytest.mark.parametrize("foreign", ("session", "repository", "candidate"))
def test_foreign_export_selection_never_reaches_writer(raw_repo, tmp_path, monkeypatch, foreign):
    commit = raw_repo.commit((("protected/file", "100644"),))
    other_repo = RawRepo(tmp_path / "other") if foreign == "repository" else raw_repo
    other_commit = (other_repo.commit((("protected/file", "100644"),)) if foreign == "repository"
                    else raw_repo.commit((("protected/file", "100755"),)) if foreign == "candidate" else commit)
    scratch = tmp_path / "exports"
    scratch.mkdir()
    with raw_repo.snapshot(commit) as first, other_repo.snapshot(other_commit) as second:
        evaluator, view = export_view(first)
        selection = certify(evaluator, view)
        if foreign != "candidate":
            assert first.tree == second.tree
        other = policy.TreePolicy(second, policy_version=policy.POLICY_VERSION, work=second.work)
        with pytest.raises(policy.PolicyUseError):
            certify(other, view)
        monkeypatch.setattr(policy.TreePolicy, "select_export", lambda *a, **kw: selection)
        with pytest.raises(policy.PolicyUseError, match="subject/purpose"):
            with second.materialize(("protected",), scratch, repertoire="portable"):
                pytest.fail("foreign selection reached writer")
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("state", ("closed", "abandoned"))
def test_export_lifetime_refuses_before_writer(raw_repo, tmp_path, monkeypatch, state):
    commit = raw_repo.commit((("protected/file", "100644"),))
    scratch = tmp_path / "exports"
    scratch.mkdir()
    snap = raw_repo.snapshot(commit)
    with snap:
        evaluator, view = export_view(snap)
        selected = certify(evaluator, view)
        if state == "abandoned":
            snap._batch()._abandoned = True
            with pytest.raises(snapshot.SnapshotError):
                selected.entries_for(snap, use=view.plan.use)
            with pytest.raises(snapshot.SnapshotError):
                certify(evaluator, view)
    with pytest.raises(snapshot.SnapshotError):
        selected.entries_for(snap, use=view.plan.use)
    with pytest.raises(snapshot.SnapshotError):
        with snap.materialize(("protected",), scratch, repertoire="portable"):
            pytest.fail("closed context reached writer")
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("case", ("regular", "leaf_link", "ancestor_link", "platform", "replaced", "short", "long"))
def test_directory_secure_read_once_after_certified_export(raw_repo, tmp_path, monkeypatch, case):
    commit = raw_repo.commit((("state/journal", "100644", b"hello"),))
    scratch = tmp_path / "exports"
    scratch.mkdir()
    with raw_repo.snapshot(commit) as snap:
        with snap.materialize(("state",), scratch, repertoire="portable") as materialized:
            root = materialized.path
            target = root / "state/journal"
            if case == "leaf_link":
                target.unlink()
                target.symlink_to("missing")
            elif case == "ancestor_link":
                target.unlink()
                target.parent.rmdir()
                target.parent.symlink_to(tmp_path / "outside")
            opened, reads = [], []
            original_open, original_read = os.open, os.read
            def open_file(path, *args, **kwargs):
                if Path(path) == target:
                    opened.append(path)
                    if case == "replaced":
                        replacement = root / "replacement"
                        replacement.write_bytes(b"other")
                        replacement.replace(target)
                return original_open(path, *args, **kwargs)
            def read(fd, count):
                reads.append(count)
                if case == "short":
                    return b""
                value = original_read(fd, count)
                return (value or b"x") if case == "long" else value
            with monkeypatch.context() as patch:
                patch.setattr(os, "open", open_file)
                patch.setattr(os, "read", read)
                if case == "platform":
                    patch.setattr(os, "O_NOFOLLOW", 0)
                assert_golden("directory/reader/" + case, outcome(lambda:
                    release_chain._regular_file_bytes(root, PurePosixPath("state/journal"))), ((root, "<ROOT>"),))
            assert len(opened) == (0 if case in {"leaf_link", "ancestor_link", "platform"} else 1)
            if case == "regular":
                assert reads == [5, 1]
    assert list(scratch.iterdir()) == []


def test_anchor_digest_bytes_match_pr1_after_certified_export(raw_repo, tmp_path):
    commit = raw_repo.commit((("anchors/producer.pem", "100644", b"producer\n"),
                             ("anchors/root.pem", "100755", b"root\n")))
    spec = SimpleNamespace(anchor_relative=PurePosixPath("anchors"), producer_public_key_filename="producer.pem",
                           anchors={"tsa": SimpleNamespace(filename="root.pem")})
    scratch = tmp_path / "exports"
    scratch.mkdir()
    with raw_repo.snapshot(commit) as snap:
        with snap.materialize(("anchors", "anchors/root.pem"), scratch, repertoire="portable") as materialized:
            expected = json.loads((Path(__file__).parent / "m1_expected/census_snapshot.json").read_bytes())
            assert materialized.anchor_set_sha256(spec).encode() == expected["anchor/accept"]["value"].encode()
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("mode", ("100644", "100755", "120000", "160000"))
def test_risk9_cli_command_golden_bytes(signed_repo, tmp_path, mode):
    # Raw index input, including executable/link/gitlink; no hostile host staging.
    state = signed_repo.chain.state_relative.as_posix()
    commit = signed_repo.commit(((state, mode, signed_repo.journal),))
    assert signed_repo.git("config", "core.ignoreCase") == os.environ.get("RECEIPT_M1_IGNORECASE", "false").encode()
    assert signed_repo.git("config", "core.precomposeUnicode") == b"false"
    actual = signed_repo.cli(commit, tmp_path)
    golden = json.loads((Path(__file__).parent / "m1_expected/census_commands.json").read_bytes())
    expected = golden[f"state/{state}/{mode}"]["cli"]
    # PR1 command goldens store the complete stable command observation, not
    # volatile stdout identities. Compare its serialized bytes without rewriting it.
    assert json.dumps(actual, ensure_ascii=True).encode() == json.dumps(expected, ensure_ascii=True).encode()
    assert actual["stderr"].encode() == b""


@pytest.mark.parametrize("fault", ("clean", "export-link"))
def test_cli_complete_stdout_and_stderr_bytes_match_old_selector(signed_repo, tmp_path, fault):
    commit = signed_repo.commit((("releases/link", "120000"),) if fault == "export-link" else ())
    source = Path(__file__).resolve().parents[1]
    command = ["verify", "--spec", str(signed_repo.root / "verification/spec.py"),
               "--root", str(signed_repo.root), "--commit", commit, "--json"]
    results = []
    for old in (True, False):
        code = """
import sys
from receipt import cli, snapshot
import protected_tree_legacy as legacy
if sys.argv.pop(1) == 'old':
    legacy.MAX_TREE_ENTRIES = snapshot.MAX_TREE_ENTRIES
    legacy._CONTENT_MODES = snapshot._CONTENT_MODES
    snapshot.Materialization._selected_entries = legacy._selected_entries
    snapshot.Materialization._deduplicated_prefixes = legacy._deduplicated_prefixes
raise SystemExit(cli.main())
"""
        result = subprocess.run([sys.executable, "-c", code, "old" if old else "new", *command],
            capture_output=True, timeout=60, cwd=source,
            env=os.environ | {"PYTHONPATH": os.pathsep.join((str(source / "src"), str(source / "tests")))})
        results.append((result.returncode, result.stdout, result.stderr))
    assert results[0] == results[1]
    assert results[1][0] == (0 if fault == "clean" else 1)
    assert results[1][2] == b""
    assert json.loads(results[1][1])["verdict"] == ("PASS" if fault == "clean" else "FAIL")
