"""D15/D16: real subclasses, ledger-free fakes, and operative public factories.

Factory replacements are characterized, including pre-import and simultaneous
class/reference substitution. Acceptance at one public boundary does not grant
concrete policy authority at a borrowed consumer boundary.

Observed limits of the record's proposed substitution gate are explicit:
accepted binding subclasses still fail direct history/base-chain policy admission
with "policy subject/work mismatch". Replacing both snapshot.TreeSnapshot and
verify.TreeSnapshot with the no-ledger fake reaches the current mutable-class
comparison and renders "AttributeError: 'Fake' object has no attribute 'work'".
The verify-only class patch and classmethod-to-fake control succeed without
policy authority. Broad proposed substitution support is not a current universal
acceptance claim; this freeze deliberately retains these different outcomes.
"""
from collections import Counter
from dataclasses import asdict
import importlib
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from m3_fixture import (Trace, authenticated_m3_oracle, compare, outcome, plain,
                        reached, repo, work)
from test_m3_context_cleanup import pipeline
from test_verify import JOURNAL_BYTES, PREFIX_BYTES, ANCHOR_DIGEST


def fake_reader(commit, tree, calls):
    class FakeMaterialization:
        def __init__(self, path):
            self.path = path
            self.entries = {"releases/manifest": SimpleNamespace(path="releases/manifest", mode="100644")}
        def __enter__(self):
            calls.append("export enter")
            return self
        def __exit__(self, *args):
            calls.append("export exit")
        def anchor_set_sha256(self, spec):
            return ANCHOR_DIGEST
    class Fake:
        def __init__(self):
            self.commit, self.tree, self.object_format = commit, tree, "sha1"
        @classmethod
        def select(cls, root, revision="HEAD", **kwargs):
            calls.append(["select", revision, kwargs])
            return cls()
        def __enter__(self):
            calls.append("enter")
            return self
        def __exit__(self, *args):
            calls.append("exit")
        def assert_ancestor(self, other):
            calls.append("ancestry")
            return other.commit
        def entry(self, path):
            calls.append(["entry", path])
            return SimpleNamespace(path=path, mode="100644")
        def entries(self, prefix):
            calls.append(["entries", prefix])
            return SimpleNamespace(as_dict=lambda *, include_trees=False: {})
        def blob(self, entry, *, limit):
            calls.append(["blob", entry.path, limit])
            return JOURNAL_BYTES if entry.path.endswith("jsonl") else PREFIX_BYTES
        def materialize(self, prefixes, destination, *, repertoire):
            calls.append(["materialize", [str(p) for p in prefixes], repertoire])
            return FakeMaterialization(destination)
        def refuse_transforming_attributes(self, entries):
            calls.append(["attributes", [e.path for e in entries]])
        def verify_object_store(self, heads):
            calls.append(["objects", list(heads)])
            return SimpleNamespace(objects=1, store_kib=1, seconds=0)
    return Fake


def constructors(m, patch):
    counts = Counter()
    for cls in (m.protected_tree.TreePolicy, m.protected_tree.ProtectedTreeView,
                m.protected_tree.ProtectedSelection):
        original = cls.__init__
        def init(self, *args, _body=original, _name=cls.__name__, **kwargs):
            counts[_name] += 1
            return _body(self, *args, **kwargs)
        patch.setattr(cls, "__init__", init)
    return counts


def public_matrix(m, repo, patch, kind, boundary, state):
    loaded, commit = pipeline(m, repo, patch, binding=True)
    s, calls = m.snapshot, []
    original = s.TreeSnapshot
    class Subclass(original):
        pass
    class Override(original):
        def entry(self, path):
            calls.append(["override entry", path])
            return super().entry(path)
        def entries(self, prefix=""):
            calls.append(["override entries", prefix])
            return super().entries(prefix)
        def digests(self, entries, **kwargs):
            calls.append("override digests")
            return super().digests(entries, **kwargs)
    Fake = fake_reader(commit, repo.git("rev-parse", f"{commit}^{{tree}}").decode(), calls)
    reader = {"concrete": original, "subclass": Subclass, "override": Override, "fake": Fake}[kind]
    selected = reader.select(repo.root, commit)
    authorities = constructors(m, patch)
    if state == "closed":
        with selected:
            pass
    elif state == "entered":
        selected.__enter__()
    try:
        journal = repo.git("cat-file", "blob", f"{commit}:receipt/journal.jsonl") + b"\n"
        def call():
            if boundary == "binding":
                return m.corpus.verify_corpus_binding(selected, journal, spec=loaded.verification.corpus)
            if boundary == "declaration-first":
                return m.corpus.verify_corpus_binding(selected, b"malformed\n", spec=loaded.verification.corpus)
            if boundary in {"attested", "empty-attested"}:
                entries = m.corpus._attested_entries_from_snapshot(selected,
                    {} if boundary == "empty-attested" else {".axiom/toolchain.toml": None})
                return {k: [e.path, e.mode] for k, e in entries.items()}
            if boundary == "history":
                return m.release_chain.verify_release_history_immutable(loaded.verification.chain,
                    candidate=selected, base=selected)[0]
            if boundary == "base-chain":
                patch.setattr(m.release_chain, "verify_release_chain", m.verify.verify_release_chain)
                return m.release_chain.verify_base_release_chain(loaded.verification.chain, base=selected,
                    anchor_dir=repo.root / "caller-anchors").anchor_set_sha256
            if boundary == "select":
                return [type(selected).__name__, selected.commit, selected.tree]
            raise AssertionError(boundary)
        result = outcome(call)
        if kind in {"subclass", "override"} and boundary == "binding" and state == "entered":
            assert "value" in result and not authorities
        if boundary == "empty-attested":
            assert result == {"value": {}} and not authorities
        ledger = None if kind == "fake" else work(selected)
        if kind == "fake":
            assert all(not hasattr(selected, name) for name in ("work", "_state", "_batch", "context"))
        return {"result": result, "class": type(selected).__name__, "work": ledger,
                "calls": calls, "authority": dict(authorities)}
    finally:
        if state == "entered":
            selected.__exit__(None, None, None)


def factory_matrix(m, repo, patch, replacement, boundary, timing, history):
    loaded, commit = pipeline(m, repo, patch)
    s, calls, owners = m.snapshot, [], []
    original_class = s.TreeSnapshot
    original_select = original_class.select.__func__
    Fake = fake_reader(commit, repo.git("rev-parse", f"{commit}^{{tree}}").decode(), calls)
    class Subclass(original_class):
        pass
    returned = Subclass if replacement == "subclass" else Fake
    def substituted(cls, root, revision="HEAD", **kwargs):
        calls.append(["classmethod", revision, kwargs])
        selected = (original_select(returned, root, revision, **kwargs)
                    if replacement == "subclass" else returned.select(root, revision, **kwargs))
        owners.append(selected)
        return selected
    if timing == "after-success":
        with original_class.select(repo.root, commit):
            pass
    if replacement == "class":
        patch.setattr(m.verify, "TreeSnapshot", Fake)
        patch.setattr(m.append_gate, "TreeSnapshot", Fake)
    elif replacement == "both-classes":
        patch.setattr(s, "TreeSnapshot", Fake)
        patch.setattr(m.verify, "TreeSnapshot", Fake)
        patch.setattr(m.append_gate, "TreeSnapshot", Fake)
    else:
        patch.setattr(original_class, "select", classmethod(substituted))
    if timing == "before-import":
        # Real module execution after the patch, with original sentinel imports.
        # monkeypatch restores both sys.modules and the package's attribute.
        package = sys.modules["receipt"]
        patch.delitem(sys.modules, "receipt.verify")
        patch.delattr(package, "verify")
        m.verify = importlib.import_module("receipt.verify")
        # Reinstall unrelated borrowed evidence seams in the newly imported root.
        loaded, _ = pipeline(m, repo, patch)
    authorities = constructors(m, patch)
    with reached(m) as counts:
        def call():
            if boundary == "verify":
                answer = m.verify.run_verification(repo.root, loaded, commit=commit,
                    base_ref=commit if history else None, expect_commit=commit if history else None)
                return {"class": type(answer).__name__, "ok": answer.ok,
                        "passes": [plain(p) for p in answer.passes]}
            if boundary == "select":
                selected = (m.verify.TreeSnapshot if replacement == "class" else s.TreeSnapshot).select(repo.root, commit)
                with selected:
                    return [type(selected).__name__, selected.commit, selected.tree]
            gate = m.append_gate.AppendGateSpec(loaded.verification.chain, "m3-prefix",
                "releases/manifests/", frozenset(), frozenset(), frozenset(), ())
            patch.setattr(m.append_gate, "_verify_selected_tree", lambda *args, **kwargs: "m3 append body accepted")
            function = (m.append_gate.verify_append_gate if boundary == "append-text" else
                        m.append_gate.verify_append_gate_verdict)
            return function(repo.root, spec=gate, commit=commit, base_ref=commit if history else None)
        result = outcome(call)
    return {"result": result, "calls": calls, "authority": dict(authorities),
            "work": [work(owner)[0] for owner in owners if hasattr(owner, "work")],
            "bodies_after_import": dict(sorted(counts.items()))}


def binding_seam(m, repo, patch, seam):
    loaded, commit = pipeline(m, repo, patch, binding=True)
    calls = []
    original = m.corpus._verify_corpus_binding
    def shared(*args, **kwargs):
        calls.append(["private", kwargs.get("policy") is not None])
        return original(*args, **kwargs)
    patch.setattr(m.corpus, "_verify_corpus_binding", shared)
    def refused(*args, **kwargs):
        calls.append(["substitute"])
        raise m.corpus.CorpusError("m3 public binding substitution")
    if seam == "public-path":
        patch.setattr(m.corpus, "_VERIFY_CORPUS_BINDING_ORIGINAL", object())
    elif seam in {"verify-side", "both", "before-import"}:
        patch.setattr(m.verify, "verify_corpus_binding", refused)
        if seam in {"both", "before-import"}:
            patch.setattr(m.corpus, "verify_corpus_binding", refused)
        if seam == "before-import":
            patch.delitem(sys.modules, "receipt.verify")
            patch.delattr(sys.modules["receipt"], "verify")
            m.verify = importlib.import_module("receipt.verify")
            loaded, _ = pipeline(m, repo, patch, binding=True)
    authorities = constructors(m, patch)
    owners = []
    enter = m.snapshot.TreeSnapshot.__enter__
    def entered(subject):
        owners.append(subject)
        return enter(subject)
    patch.setattr(m.snapshot.TreeSnapshot, "__enter__", entered)
    with reached(m) as counts:
        answer = m.verify.run_verification(repo.root, loaded, commit=commit)
    assert counts["verify.run_verification"] == 1
    assert calls == ([["private", True]] if seam == "shared" else
                     [["private", False]] if seam == "public-path" else [["substitute"]])
    assert answer.ok == (seam in {"shared", "public-path"})
    return {"passes": [plain(p) for p in answer.passes], "calls": calls,
            "work": work(*owners), "authority": dict(authorities),
            "bodies_after_import": dict(sorted(counts.items()))}


CASES = {
    **{f"D15-{kind}-{boundary}-{state}": (public_matrix, kind, boundary, state)
       for kind in ("concrete", "subclass", "override", "fake")
       for boundary in ("binding", "declaration-first", "attested", "empty-attested", "history", "base-chain", "select")
       for state in ("entered", "closed", "unentered")},
    **{f"D16-factory-{replacement}-{boundary}-{timing}-{history}":
       (factory_matrix, replacement, boundary, timing, history)
       for replacement in ("class", "both-classes", "classmethod", "subclass")
       for boundary in ("verify", "append-verdict", "append-text", "select")
       for timing in ("after-import", "before-import", "after-success")
       for history in (False, True)},
    **{f"D16-binding-{seam}": (binding_seam, seam)
       for seam in ("shared", "public-path", "verify-side", "both", "before-import")},
}


@pytest.mark.parametrize("case", CASES)
def test_public_substitution_boundaries(repo, monkeypatch, case):
    from m3_substitution_expected import OBSERVED
    probe, *args = CASES[case]
    compare(probe, repo, monkeypatch, *args, expected=OBSERVED[case])
