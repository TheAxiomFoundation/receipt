"""Additional D7/D8/D13/D14 raw-object admission and late-hook controls."""
from dataclasses import asdict
import zlib

import pytest

from m3_fixture import Trace, authenticated_m3_oracle, compare, policy, repo, work


def raw_admission(m, repo, patch, constant, delta, paired):
    commit = repo.commit((("a/leaf", "100644", b"payload\n"),))
    s = m.snapshot
    with s.TreeSnapshot.select(repo.root, commit) as a, s.TreeSnapshot.select(repo.root, commit) as b:
        if paired:
            a._link_verification_work(b)
        subtree = repo.git("rev-parse", f"{commit}:a").decode()
        size = len(repo.git("cat-file", "tree", subtree))
        trace = Trace(a, b)
        trace.call("warm A subtree", lambda: [e.path for e in a.entries("a")])
        threshold = {"MAX_TREE_OBJECT_BYTES": size, "MAX_TREE_BYTES_TOTAL": b.work.tree_bytes + size,
                     "MAX_TREE_ENTRIES": 2, "MAX_TREE_DEPTH": 1}[constant]
        patch.setattr(s, constant, threshold + delta)
        trace.call("A cached subtree", lambda: [e.path for e in a.entries("a")])
        trace.call("B first subtree", lambda: [e.path for e in b.entries("a")])
        return {"events": trace.events, "cache_membership": [subtree in x._state.tree_cache for x in (a, b)]}


def malformed(m, repo, patch, fault):
    s = m.snapshot
    leaf = repo.hash(b"payload\n")
    if fault == "role":
        raw = b"40000 leaf\0" + bytes.fromhex(leaf)
    else:
        raw = b"100644 leaf\0" + bytes.fromhex(leaf) + b"broken"
    tree = repo.hash(raw, "tree")
    # commit-tree rejects a malformed tree; a literal canonical commit preserves it.
    payload = (f"tree {tree}\n" +
        "author M3 <m3@example.invalid> 978307200 +0000\n" +
        "committer M3 <m3@example.invalid> 978307200 +0000\n\nM3\n").encode()
    commit = repo.hash(payload, "commit")
    from m3_fixture import outcome
    return outcome(lambda: s.TreeSnapshot.select(repo.root, commit))


def late_attribute_hook(m, repo, patch, hook):
    commit = repo.commit(((".gitattributes", "100644", b"protected.txt -filter\n"),))
    s = m.snapshot
    with s.TreeSnapshot.select(repo.root, commit) as a:
        trace = Trace(a)
        trace.call("complete attribute cache", lambda: a.refuse_transforming_attributes(("protected.txt",)))
        def refused(*args, **kwargs):
            raise s.SnapshotError("m3 late " + hook + " hook")
        patch.setattr(s.TreeSnapshot if hook in {"_attribute_rules", "_attribute_step"} else s, hook, refused)
        trace.call("after hook replacement", lambda: a.refuse_transforming_attributes(("protected.txt",)))
        return trace.events


def callback_failure(m, repo, patch):
    commit = repo.commit((("file", "100644", b"payload\n"),))
    s = m.snapshot
    with s.TreeSnapshot.select(repo.root, commit) as a, s.TreeSnapshot.select(repo.root, commit) as b:
        a._link_verification_work(b)
        entry = a.entry("file")
        trace = Trace(a, b)
        def callback(chunk):
            assert chunk == b"payload\n"
            raise ValueError("m3 callback interrupted frame")
        trace.call("interrupted frame", lambda: a._batch().consume(entry.object_id, role="blob", limit=100, consumer=callback))
        trace.call("owner after frame failure", lambda: a.entry("file").path)
        trace.call("independent sibling", lambda: b.blob(b.entry("file"), limit=100))
        return trace.events


def same_commit_store(m, repo, patch):
    repo.hash(b"", "tree")
    commit = repo.commit((("file", "100644"),))
    s = m.snapshot
    with s.TreeSnapshot.select(repo.root, commit, verify_objects=True) as a, s.TreeSnapshot.select(repo.root, commit, verify_objects=True) as b:
        trace = Trace(a, b)
        for label, subject in (("A", a), ("A repeated", a), ("B independent", b)):
            def call(subject=subject):
                report = subject.verify_object_store((subject.commit,))
                assert report.seconds >= 0
                return [report.objects, report.store_kib]
            trace.call(label, call)
        return {"events": trace.events, "attempted": [a._state.object_store_attempted, b._state.object_store_attempted]}


CASES = {
    **{f"D7-{constant}-{delta}-paired-{paired}": (raw_admission, constant, delta, paired)
       for constant in ("MAX_TREE_OBJECT_BYTES", "MAX_TREE_BYTES_TOTAL", "MAX_TREE_ENTRIES", "MAX_TREE_DEPTH")
       for delta in (-1, 0, 1) for paired in (False, True)},
    **{f"D7-{fault}": (malformed, fault) for fault in ("role", "malformed")},
    **{f"D8-late-{hook}": (late_attribute_hook, hook) for hook in
       ("_attribute_rules", "_attribute_matches", "_parse_attribute_file", "_attribute_step")},
    "D13-callback": (callback_failure,),
    "D14-same-commit": (same_commit_store,),
}


@pytest.mark.parametrize("case", CASES)
def test_late_account_admission(repo, monkeypatch, case):
    from m3_admission_expected import OBSERVED
    probe, *args = CASES[case]
    compare(probe, repo, monkeypatch, *args, expected=OBSERVED[case])
