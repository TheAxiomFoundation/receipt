"""M3-PR1: current context boundaries, characterized from executed raw objects.

D1 capture-once and D7/A7 context-scoped availability are proposed deliberate
corrections awaiting separate maintainer approval. These tests pin TODAY'S moving
environment and independent-owner behavior. The independent-owner pair adapter
is the compatibility boundary: pairing admits six totals, without adopting a
process, config baseline, entry capability, policy outcome or failure domain.

Decision record for the next migration steps:
- D1 is a pending capture-once correction. D1-False records the actual sequence
  ["select", "select", "enter", "close"]; D1-True additionally records the store
  capture and every Git child. Neither trace is a capture-once guarantee.
- A7 is a separate pending availability correction. The 288 D7 cases retain the
  independent warm/cold refusal split, including both read orders and selection
  warmth. No successful payload is substituted for a cold-owner refusal.
- Independent owners retain the admitted pair adapter: six shared totals and
  attribute facts, distinct accounts/capabilities/PIDs/audit baselines, and
  independent closure/abandonment. D3/D4/D5/D6/D9/D11/D13 pin both sides.
These tests grant neither approval and introduce no ownership/linkage removal.
"""
from dataclasses import asdict, replace
from pathlib import Path, PurePosixPath
import os
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from m3_fixture import (Trace, authenticated_m3_oracle, compare, outcome, plain,
                        policy, repo, work)


def select(m, repo, commit=None, **kwargs):
    return m.snapshot.TreeSnapshot.select(repo.root, commit or repo.base, **kwargs)


def d1(m, repo, patch, store):
    s = m.snapshot
    repo.hash(b"", "tree")
    captures, children = [], []
    environment, popen = s._git_environment, s.subprocess.Popen
    original_path = os.environ["PATH"]
    def epoch(label):
        patch.setenv("RECEIPT_M3_PROBE", label)
        patch.setenv("HOME", str(repo.root / ("home-" + label)))
        patch.setenv("PATH", original_path + os.pathsep + str(repo.root / label))
        patch.setenv("LC_ALL", "C" if label in {"select", "close"} else "C.UTF-8")
        patch.setenv("GIT_FUTURE_M3", label)
    def capture(path):
        env = environment(path)
        captures.append(env["RECEIPT_M3_PROBE"])
        return env
    def spawn(argv, **kwargs):
        env = kwargs["env"]
        children.append([env["RECEIPT_M3_PROBE"], Path(env["HOME"]).name,
                         env["PATH"].rsplit(os.pathsep, 1)[-1].split("/")[-1],
                         env["LC_ALL"], sorted(k for k in env if k.startswith("GIT_")),
                         "count-objects" if "count-objects" in argv else
                         "fsck" if "fsck" in argv else "cat-file" if "cat-file" in argv else
                         "config" if "config" in argv else "version" if "version" in argv else "resolve"])
        return popen(argv, **kwargs)
    patch.setattr(s, "_git_environment", capture)
    patch.setattr(s.subprocess, "Popen", spawn)
    epoch("select")
    a = select(m, repo, verify_objects=store)
    initial = work(a)
    epoch("enter")
    with a:
        if store:
            epoch("store")
            report = a.verify_object_store((a.commit,))
            assert report.seconds >= 0
        epoch("close")
    return {"captures": captures, "children": children, "initial": initial,
            "final": work(a), "closed": a._state.closed}


def d2(m, repo, patch, restore):
    a = select(m, repo)
    repo.git("config", "m3.probe", "changed")
    try:
        b = select(m, repo)
        a.__enter__()
        b.__enter__()
        different = a._state.config_records != b._state.config_records
        if restore:
            repo.git("config", "--unset", "m3.probe")
        trace = Trace(a, b)
        trace.call("B close", lambda: b.__exit__(None, None, None))
        trace.call("A close", lambda: a.__exit__(None, None, None))
        return {"different_records": different, "events": trace.events,
                "closed": [a._state.closed, b._state.closed],
                "resources": [a.batch_pid, b.batch_pid, a.temporary_directory, b.temporary_directory]}
    finally:
        if not restore:
            repo.git("config", "--unset", "m3.probe")


def d3_d4(m, repo, patch, relation):
    commit = repo.commit((("protected.txt", "100644"),
                          (".gitattributes", "100644", b"protected.txt -filter\n")))
    other_root, other_commit = repo.root, commit
    worktree = None
    if relation == "different-commit":
        other_commit = repo.commit(base=commit)
    elif relation == "different-repository":
        from m1_fixture import RawRepo
        other = RawRepo(repo.root.parent / "other")
        shutil.rmtree(other.root / ".git/objects")
        shutil.copytree(repo.root / ".git/objects", other.root / ".git/objects")
        other_root = other.root
    elif relation == "linked-worktree":
        worktree = repo.root.parent / "linked"
        repo.git("worktree", "add", "--detach", "--no-checkout", str(worktree), commit)
        other_root = worktree
    try:
        with select(m, repo, commit) as a, m.snapshot.TreeSnapshot.select(other_root, other_commit) as b:
            pa, pb = policy(m, a), policy(m, b)
            ea, eb = a.entry("protected.txt"), b.entry("protected.txt")
            value = m.protected_tree.ProtectionPlan(use="m3", obligations=("attributes",),
                        listing_scope=(), attribute_target_selectors=("protected.txt",))
            va = pa.evaluate_attributes(value)
            vb = pb.evaluate_attributes(value)
            trace = Trace(a, b)
            trace.call("own capability", lambda: a.blob(ea, limit=100))
            trace.call("foreign capability", lambda: a.blob(eb, limit=100))
            trace.call("own view", lambda: pa.evaluate_attributes(value, previous=va).completed)
            trace.call("foreign view", lambda: pb.evaluate_attributes(value, previous=va).completed)
            return {"equal": [a == b, ea == eb, a.commit == b.commit, a.tree == b.tree,
                              a.common_dir == b.common_dir, a.git_dir == b.git_dir],
                    "separate": [pa.subject != pb.subject, a.batch_pid != b.batch_pid,
                                 a._state.tree_cache is not b._state.tree_cache,
                                 va.subject != vb.subject], "events": trace.events}
    finally:
        if worktree:
            repo.git("worktree", "remove", "--force", str(worktree))


LIMITS = (("path_bytes", "MAX_PATH_BYTES_TOTAL"),
          ("attribute_bytes", "MAX_ATTRIBUTE_BYTES_TOTAL"),
          ("attribute_rules", "MAX_ATTRIBUTE_RULES_TOTAL"),
          ("attribute_match_work", "MAX_ATTRIBUTE_MATCH_WORK"),
          ("content_bytes", "MAX_CONTENT_BYTES_TOTAL"),
          ("materialized_bytes", "MAX_MATERIALIZED_BYTES"))


def d5(m, repo, patch, index, closed):
    a, b, c = select(m, repo), select(m, repo), select(m, repo)
    if closed:
        with b:
            pass
    for field, ceiling in LIMITS[index:]:
        setattr(a.work, field, 6)
        setattr(b.work, field, 5)
        patch.setattr(m.snapshot, ceiling, 10)
    trace = Trace(a, b, c)
    roots = lambda: a._state.work_pool.root() is b._state.work_pool.root()
    trace.call("competing admission", lambda: a._link_verification_work(b))
    separate = not roots()
    for field, ceiling in LIMITS[index:]:
        patch.setattr(m.snapshot, ceiling, 11)
    trace.call("admitted pair", lambda: a._link_verification_work(b))
    for field, ceiling in LIMITS[index:]:
        patch.setattr(m.snapshot, ceiling, 0)
    trace.call("reverse already admitted", lambda: b._link_verification_work(a))
    trace.call("repeat already admitted", lambda: a._link_verification_work(b))
    trace.call("failed transitive", lambda: b._link_verification_work(c))
    field, ceiling = LIMITS[index]
    trace.call("future public charge", lambda: b._charge_verification(field, 1, ceiling=11,
                    message="m3 future charge refused"))
    for field, ceiling in LIMITS[index:]:
        patch.setattr(m.snapshot, ceiling, 100)
    trace.call("admitted transitive", lambda: c._link_verification_work(b))
    return {"separate_after_refusal": separate, "paired": roots(),
            "three_accounts": len(a._state.work_pool.root().works),
            "closed_B": b._state.closed, "events": trace.events}


def d6(m, repo, patch, barrier):
    commit = repo.commit((("releases/a", "100644"),))
    unrelated = repo.git("commit-tree", repo.git("rev-parse", f"{commit}^{{tree}}").decode(),
                         data=b"unrelated\n").decode()
    with select(m, repo, commit) as a, select(m, repo, unrelated if barrier == "failed-ancestry" else commit) as b:
        trace = Trace(a, b)
        if barrier == "linked":
            a._link_verification_work(b)
        elif barrier in {"ancestry", "failed-ancestry"}:
            patch.setattr(m.snapshot, "MAX_ANCESTRY_COMMITS", 1)
            trace.call("ancestry", lambda: a.assert_ancestor(b))
            trace.call("repeat ancestry", lambda: a.assert_ancestor(b))
        patch.setattr(m.snapshot, "MAX_PATH_BYTES_TOTAL", 19)
        if barrier == "changed-paths":
            trace.call("changed paths", lambda: a.changed_paths(b))
        else:
            trace.call("borrowed history", lambda: m.release_chain.verify_release_history_immutable(
                SimpleNamespace(release_root_relative=PurePosixPath("releases")), candidate=a, base=b)[0])
        return {"events": trace.events,
                "linked": a._state.work_pool.root() is b._state.work_pool.root(),
                "ancestry_bases": sorted(a._state.ancestry_bases)}


def d8(m, repo, patch, variant, reverse):
    common = (("protected.txt", "100644"), ("a/protected.txt", "100644"))
    base = repo.commit(common)
    if variant == "missing":
        entries = ((".gitattributes", "100644", b"protected.txt filter\n"),)
    elif variant == "depth":
        entries = ((".gitattributes", "100644", b"protected.txt -filter\n"),
                   ("a/.gitattributes", "100644", b"protected.txt -filter\n"))
    else:
        entries = ((".gitattributes", variant, b"protected.txt filter\n"),)
    candidate = repo.commit(entries, base=base)
    with select(m, repo, candidate if reverse else base) as a, select(m, repo, base if reverse else candidate) as b:
        a._link_verification_work(b)
        trace = Trace(a, b)
        for name, subject in (("A", a), ("B", b)):
            for path in ("protected.txt", "a/protected.txt"):
                trace.call(name + ":" + path, lambda s=subject, p=path: s.refuse_transforming_attributes((p,)))
        return {"events": trace.events, "distinct_source_cache": a._state.attribute_cache is not b._state.attribute_cache}


def d9_d12(m, repo, patch, ceiling, linkage):
    commit = repo.commit((("protected.txt", "100644"),
                          (".gitattributes", "100644", b"protected.txt -filter\n")))
    with select(m, repo, commit) as a, select(m, repo, commit) as b:
        pa, pb = policy(m, a), policy(m, b)
        if linkage == "before":
            a._link_verification_work(b)
        patch.setattr(m.snapshot, "MAX_ATTRIBUTE_MATCH_WORK", ceiling)
        trace = Trace(a, b)
        trace.call("A first", lambda: a.refuse_transforming_attributes(("protected.txt",)))
        trace.call("B first", lambda: b.refuse_transforming_attributes(("protected.txt",)))
        if linkage == "after":
            trace.call("link after loading", lambda: a._link_verification_work(b))
        trace.call("A replay", lambda: a.refuse_transforming_attributes(("protected.txt",)))
        return {"events": trace.events, "actual": [asdict(pa.attribute_work), asdict(pb.attribute_work)],
                "distinct_sources": a._state.attribute_cache is not b._state.attribute_cache}


def d10(m, repo, patch, fault):
    commit = repo.commit((("protected.txt", "100644"),))
    with select(m, repo, commit) as a:
        p = policy(m, a)
        p.read_listing()
        old = a.work
        if fault == "work":
            a._state.work = m.snapshot.SnapshotWork()
        elif fault == "token":
            a._state.entry_token = object()
        elif fault == "shell":
            p = policy(m, replace(a, commit="0" * 40))
        trace = Trace(a)
        trace.call("listing after drift", lambda: sorted(p.read_listing()))
        return {"events": trace.events, "same_work": p.work is a.work,
                "registered_work": any(x is a.work for x in a._state.work_pool.root().works),
                "old_work": asdict(old)}


def d11_d13(m, repo, patch, lifecycle):
    commit = repo.commit((("protected.txt", "100644"), ("second.txt", "100644")))
    a, b = select(m, repo, commit), select(m, repo, commit)
    a.__enter__()
    b.__enter__()
    try:
        a._link_verification_work(b)
        p = policy(m, a)
        listing = a.entries("")
        p.read_listing()
        entry = a.entry("protected.txt")
        trace = Trace(a, b)
        iterator = None
        if lifecycle in {"held", "exhausted"}:
            iterator = a.digests((entry,), per_blob=100, total=100)
            trace.call("first digest", lambda: [next(iterator)[1]])
            if lifecycle == "exhausted":
                trace.call("exhaustion", lambda: list(iterator))
            trace.call("sibling during stream", lambda: b.entry("protected.txt").path)
        elif lifecycle == "abandoned":
            a._abandon()
        else:
            a.__exit__(None, None, None)
        trace.call("cached reader", lambda: a.entry("protected.txt").path)
        trace.call("cached listing", lambda: len(listing))
        trace.call("cached policy", lambda: sorted(p.read_listing()))
        trace.call("sibling after refusal", lambda: b.entry("protected.txt").path)
        if iterator:
            iterator.close()
        a.__exit__(None, None, None)
        trace.call("reenter", lambda: a.__enter__())
        trace.call("policy after exit", lambda: sorted(p.read_listing()))
        return {"events": trace.events, "abandoned": [a._state.abandoned, b._state.abandoned]}
    finally:
        if not a._state.closed:
            a.__exit__(None, None, None)
        b.__exit__(None, None, None)


def d14(m, repo, patch, heads):
    repo.hash(b"", "tree")
    commit = repo.commit((("file", "100644"),))
    with select(m, repo, commit, verify_objects=True) as a, select(m, repo, repo.base) as b:
        trace = Trace(a, b)
        trace.call("base unready", lambda: b.verify_object_store((b.commit,)))
        if heads != "unproven":
            a.assert_ancestor(b)
        values = {"exact": (a.commit, b.commit), "reverse": (b.commit, a.commit),
                  "duplicate": (a.commit, a.commit), "missing": (a.commit,),
                  "three": (a.commit, b.commit, b.commit), "scalar": a.commit,
                  "unproven": (a.commit, b.commit), "failed-count": (a.commit, b.commit)}[heads]
        def store():
            report = a.verify_object_store(values)
            assert report.seconds >= 0
            return {"class": type(report).__module__ + "." + type(report).__name__,
                    "objects": report.objects, "store_kib": report.store_kib}
        if heads == "failed-count":
            original = m.snapshot._git_run
            def fail_count(argv, **kwargs):
                if "count-objects" in argv:
                    return subprocess.CompletedProcess(argv, 1, b"", b"m3 count failure\n")
                return original(argv, **kwargs)
            patch.setattr(m.snapshot, "_git_run", fail_count)
        trace.call("store", store)
        attempted = a._state.object_store_attempted
        trace.call("repeat store", store)
        return {"events": trace.events, "attempted": attempted,
                "base_attempted": b._state.object_store_attempted}


def d18(m, repo, patch, shape):
    entries = (("a/b/leaf", "100755"),) if shape == "tree" else (
               (("a", "120000"),) if shape == "symlink" else ())
    commit = repo.commit(entries, empty=("a/empty",) if shape in {"tree", "empty"} else ())
    with select(m, repo, commit) as a:
        p = policy(m, a)
        value = m.protected_tree.ProtectionPlan(use="m3", obligations=("ancestors", "modes"),
                    selected_prefixes=("a",), ancestor_paths=("a/b/leaf",),
                    mode_roles=(("a/b/leaf", "state-leaf"),))
        trace = Trace(a)
        early = p.evaluate_ancestors(value)
        trace.call("incomplete", lambda: early.require(value.use, render=m.release_chain._base_shape_error))
        final = p.evaluate_modes(value, previous=early)
        def certified(view):
            selected = view.require(value.use, render=m.release_chain._base_shape_error)
            return sorted(selected.entries_for(a, use=value.use, plan=value))
        trace.call("complete", lambda: certified(final))
        before = work(a)
        trace.call("resumed", lambda: certified(p.evaluate_modes(value, previous=final)))
        no_charge = work(a) == before
        trace.call("fresh policy foreign view", lambda: policy(m, a).evaluate_modes(value, previous=final))
        trace.call("explicit repeated listing", lambda: sorted(p.read_listing("a")))
        return {"events": trace.events, "completed": sorted(final.completed),
                "resumed_without_charge": no_charge, "shape_work": asdict(p.shape_work)}


CASES = {
    **{f"D1-{store}": (d1, store) for store in (False, True)},
    **{f"D2-restore-{restore}": (d2, restore) for restore in (False, True)},
    **{f"D3-D4-{relation}": (d3_d4, relation) for relation in
       ("same-commit", "different-commit", "different-repository", "linked-worktree")},
    **{f"D5-{field}-closed-{closed}": (d5, i, closed)
       for i, (field, _) in enumerate(LIMITS) for closed in (False, True)},
    **{f"D6-{barrier}": (d6, barrier) for barrier in
       ("unlinked", "linked", "ancestry", "failed-ancestry", "changed-paths")},
    **{f"D8-{variant}-reverse-{reverse}": (d8, variant, reverse)
       for variant in ("missing", "depth", "120000", "160000") for reverse in (False, True)},
    **{f"D9-{link}": (d9_d12, 1000, link) for link in ("none", "before", "after")},
    **{f"D10-{fault}": (d10, fault) for fault in ("work", "token", "shell")},
    **{f"D11-D13-{state}": (d11_d13, state) for state in ("closed", "abandoned", "held", "exhausted")},
    **{f"D12-ceiling-{ceiling}": (d9_d12, ceiling, "none") for ceiling in range(57)},
    **{f"D14-{heads}": (d14, heads) for heads in
       ("exact", "reverse", "duplicate", "missing", "three", "scalar", "unproven", "failed-count")},
    **{f"D18-{shape}": (d18, shape) for shape in ("tree", "empty", "missing", "symlink")},
}


@pytest.mark.parametrize("case", CASES)
def test_context_boundary(repo, monkeypatch, case):
    from m3_context_expected import OBSERVED
    probe, *args = CASES[case]
    compare(probe, repo, monkeypatch, *args, expected=OBSERVED[case])
