"""Authenticate whole M3 bodies before comparing distinct executable legs."""
import hashlib

import pytest

from m3_fixture import authenticated_m3_oracle, compare, repo
from m3_legacy import BODY_SHA256, FROZEN_SOURCE, SOURCE_SHA256, authenticate, modules, source_tree


def test_m3_frozen_sources_authenticate_against_measured_tree(authenticated_m3_oracle):
    for path, source in FROZEN_SOURCE.items():
        assert hashlib.sha256(source.encode()).hexdigest() == SOURCE_SHA256[path]
    required = {"TreeSnapshot.select", "TreeSnapshot.__enter__", "TreeSnapshot.__exit__",
                "TreeSnapshot._link_verification_work", "TreeSnapshot._verification_total",
                "TreeSnapshot._charge_verification", "TreeSnapshot._tree_object",
                "TreeSnapshot._commit_object", "TreeSnapshot.blob", "TreeSnapshot.entry",
                "TreeSnapshot.entries", "TreeSnapshot.digests", "TreeSnapshot.assert_ancestor",
                "TreeSnapshot.changed_paths", "TreeSnapshot.verify_object_store"}
    assert required <= BODY_SHA256["src/receipt/snapshot.py"].keys()
    assert "run_verification" in BODY_SHA256["src/receipt/verify.py"]
    assert "_AttributeStore.merge" in BODY_SHA256["src/receipt/protected_tree.py"]


def _exercise(m, repo, patch, early):
    s = m.snapshot
    if early:
        from m3_fixture import outcome
        return outcome(lambda: s.TreeSnapshot.select(repo.root, ""))
    with s.TreeSnapshot.select(repo.root, repo.base) as a:
        with s.TreeSnapshot.select(repo.root, repo.base) as b:
            a._link_verification_work(b)
            assert not a.entries("").as_dict()
            return [a.commit, a.tree, a.work.tree_bytes, b.work.tree_bytes]


@pytest.mark.parametrize("early", (False, True))
def test_distinct_intended_bodies_are_reached(repo, monkeypatch, early):
    observed = compare(_exercise, repo, monkeypatch, early)
    assert observed["bodies"]["TreeSnapshot.select"] == (1 if early else 2)
    assert observed["bodies"].get("TreeSnapshot.__enter__", 0) == (0 if early else 2)
    assert observed["bodies"].get("TreeSnapshot.__exit__", 0) == (0 if early else 2)
    assert observed["bodies"].get("TreeSnapshot._link_verification_work", 0) == (0 if early else 1)


def test_frozen_dependencies_cannot_follow_live_globals(repo, monkeypatch):
    from receipt import snapshot
    def forbidden(*args, **kwargs):
        pytest.fail("legacy body reached a live transport dependency")
    monkeypatch.setattr(snapshot, "_git_run", forbidden)
    with source_tree(old=True):
        old = modules().snapshot
        assert old._git_run is not snapshot._git_run
        with old.TreeSnapshot.select(repo.root, repo.base) as selected:
            assert selected.entries("").as_dict() == {}


def test_comparison_rejects_two_accidentally_identical_legs(repo, monkeypatch):
    from contextlib import nullcontext
    import m3_fixture
    # Reproduce an uncalled legacy seam: both nominal legs execute live code
    # and produce equal results/counts. Only the code-identity guard can refuse.
    monkeypatch.setattr(m3_fixture, "source_tree", lambda **kwargs: nullcontext())
    with pytest.raises(AssertionError, match="legacy/live selector bodies must be distinct"):
        compare(_exercise, repo, monkeypatch, True)
