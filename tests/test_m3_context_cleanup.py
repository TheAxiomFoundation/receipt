"""D17: ordered primary/notes and physical cleanup with completed evidence."""
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from m3_fixture import Trace, authenticated_m3_oracle, compare, outcome, plain, repo, work
from test_verify import SPEC_SOURCE, JOURNAL_BYTES, PREFIX_BYTES, ANCHOR_DIGEST


class CloseFaults:
    """Fault real exit barriers; still perform real child/directory cleanup."""
    def __init__(self, m, repo, patch, mask):
        self.events, self.owners, self.resources, self.exports = [], [], [], []
        self.active = False
        self.mask = mask
        s = m.snapshot
        export_enter = s.Materialization.__enter__
        def materialize(export):
            result = export_enter(export)
            self.exports.append(export.path)
            return result
        patch.setattr(s.Materialization, "__enter__", materialize)
        entry, exit = s.TreeSnapshot.__enter__, s.TreeSnapshot.__exit__
        audit, run = s.TreeSnapshot._reaudit_repository_files, s._git_run
        close = s._BatchReader.close
        def enter(subject):
            result = entry(subject)
            self.owners.append(subject)
            self.resources.append((subject.temporary_directory, subject._state.batch.process))
            temporary = subject._state.tempdir
            clean = temporary.cleanup
            def cleanup():
                self.events.append([next(i for i, x in enumerate(self.owners) if x is subject), "directory"])
                clean()
                if self.active and "directory" in mask:
                    raise OSError("m3 directory cleanup failure")
            patch.setattr(temporary, "cleanup", cleanup)
            return result
        def batch_close(batch):
            owners = [i for i, subject in enumerate(self.owners) if subject._state.batch is batch]
            if owners:
                self.events.append([owners[0], "child"])
            close(batch)
            if owners and self.active and "child" in mask:
                raise s.SnapshotError("m3 child close failure")
        def reaudit(subject):
            if any(x is subject for x in self.owners) and self.active:
                self.events.append([next(i for i, x in enumerate(self.owners) if x is subject), "sentinel"])
                if "sentinel" in mask:
                    raise s.SnapshotError("m3 sentinel audit failure")
            return audit(subject)
        def git_run(argv, **kwargs):
            if self.active and "--show-scope" in argv:
                self.events.append(["configuration", "read"])
                if "configuration" in mask:
                    raise s.SnapshotError("m3 configuration audit failure")
            return run(argv, **kwargs)
        patch.setattr(s.TreeSnapshot, "__enter__", enter)
        patch.setattr(s._BatchReader, "close", batch_close)
        patch.setattr(s.TreeSnapshot, "_reaudit_repository_files", reaudit)
        patch.setattr(s, "_git_run", git_run)
        # Count exact notes without substituting the real exit error.
        def traced_exit(subject, kind, exc, tb):
            index = next(i for i, x in enumerate(self.owners) if x is subject)
            try:
                answer = exit(subject, kind, exc, tb)
            except BaseException as error:
                self.events.append([index, "exit raised", type(error).__module__ + "." + type(error).__name__,
                                    str(error), list(getattr(error, "__notes__", ()))])
                raise
            self.events.append([index, "exit returned", list(getattr(exc, "__notes__", ()))])
            return answer
        patch.setattr(s.TreeSnapshot, "__exit__", traced_exit)

    def observation(self):
        return {"events": self.events, "work": work(*self.owners),
                "exports_removed": [not path.exists() for path in self.exports],
                "physical": [[not path.exists(), process.poll() is not None]
                             for path, process in self.resources],
                "state": [[s._state.closed, s.batch_pid, s.temporary_directory] for s in self.owners]}


def direct_close(m, repo, patch, mask, body):
    faults = CloseFaults(m, repo, patch, mask)
    def call():
        with m.snapshot.TreeSnapshot.select(repo.root, repo.base):
            faults.active = True
            if body == "error":
                raise ValueError("m3 body failure")
            if body == "interrupt":
                raise KeyboardInterrupt("m3 operator interruption")
    result = outcome(call)
    return {"result": result, "cleanup": faults.observation()}


def pipeline(m, repo, patch, *, binding=False):
    """Real raw snapshots/listings/exports; deterministic borrowed evidence seams."""
    specfile = repo.root.parent / "spec.py"
    from corpus_fixture import CONTENT, ATTESTED, JOURNAL_SCHEMA, journal_rows, render_journal
    journal = render_journal(journal_rows(gates=[])) if binding else JOURNAL_BYTES
    source = SPEC_SOURCE.replace(b'schema_version="test-v1"', ('schema_version="' + JOURNAL_SCHEMA + '"').encode()) if binding else SPEC_SOURCE
    specfile.write_bytes(source)
    loaded = m.verify.load_spec(specfile)
    commit = repo.commit((("receipt/journal.jsonl", "100644", journal),
                          ("receipt/prefix.json", "100644", PREFIX_BYTES),
                          ("releases/manifests/manifest.json", "100644", b"{}")) +
                         (tuple((path, "100644", text.encode()) for path, text in {**CONTENT, **ATTESTED}.items()) if binding else ()))
    record = m.release_chain.ReleaseRecord(
        path=Path("0000-0123456789abcdef.json"), raw=b"{}", sha256="1" * 64,
        manifest={"releaseIndex": 0, "state": {"jsonlSha256": hashlib.sha256(journal).hexdigest()}},
        receipt_paths={}, receipt_times={"alpha": datetime(2026, 1, 1, tzinfo=timezone.utc)},
        producer_signature_path=Path("producer.sig"))
    chain = m.release_chain.ChainVerification((record,), anchor_set_sha256=ANCHOR_DIGEST,
                                             anchor_file_sha256s=(("alpha-root.pem", "2" * 64),))
    corpus = m.corpus.CorpusVerification((), (), (), (), "portable")
    patch.setattr(m.snapshot.Materialization, "anchor_set_sha256", lambda *args: ANCHOR_DIGEST)
    patch.setattr(m.verify, "verify_release_chain", lambda *args, **kwargs: chain)
    if not binding:
        patch.setattr(m.verify, "verify_corpus_binding", lambda *args, **kwargs: corpus)
    patch.setattr(m.verify, "verify_declarations", lambda *args, **kwargs: ())
    return loaded, commit


def composed_close(m, repo, patch, mask, history, phase, body):
    loaded, commit = pipeline(m, repo, patch)
    faults = CloseFaults(m, repo, patch, mask)
    target = {"history": "verify_release_history_immutable", "custody": "verify_release_chain",
              "binding": "verify_corpus_binding", "declaration": "verify_declarations"}[phase]
    original = getattr(m.verify, target)
    def pass_boundary(*args, **kwargs):
        answer = original(*args, **kwargs)
        faults.active = True
        if body == "error":
            error = m.corpus.CorpusError if phase in {"binding", "declaration"} else m.release_chain.ReleaseChainError
            raise error("m3 " + phase + " body failure")
        if body == "interrupt":
            raise KeyboardInterrupt("m3 operator interruption")
        return answer
    patch.setattr(m.verify, target, pass_boundary)
    results = []
    def call():
        result = m.verify.run_verification(repo.root, loaded, commit=commit,
            base_ref=commit if history else None, expect_commit=commit if history else None)
        results.append(result)
        return {"class": type(result).__module__ + "." + type(result).__name__, "ok": result.ok,
                "passes": [plain(p) for p in result.passes],
                "chain": result.chain is not None, "corpus": result.corpus is not None}
    result = outcome(call)
    assert faults.owners
    if not mask and body == "none":
        assert result["value"]["ok"]
    if body == "interrupt":
        assert result["exception"] == "builtins.KeyboardInterrupt"
    assert all(process.poll() is not None for _, process in faults.resources)
    return {"result": result, "cleanup": faults.observation()}


MASKS = ((), ("child",), ("sentinel",), ("configuration",), ("directory",),
         ("child", "sentinel", "configuration", "directory"))
CASES = {
    **{f"D17-direct-{mask}-{body}": (direct_close, mask, body)
       for mask in MASKS for body in ("none", "error", "interrupt")},
    **{f"D17-composed-{mask}-{history}-{phase}-{body}": (composed_close, mask, history, phase, body)
       for mask in MASKS for history in (False, True)
       for phase in (("history", "custody", "binding", "declaration") if history else
                     ("custody", "binding", "declaration"))
       for body in ("none", "error", "interrupt")},
}


@pytest.mark.parametrize("case", CASES)
def test_cleanup_and_pass_publication(repo, monkeypatch, case):
    from m3_cleanup_expected import OBSERVED
    probe, *args = CASES[case]
    observed = compare(probe, repo, monkeypatch, *args, expected=OBSERVED[case])
    assert all(all(item) for item in observed["trace"]["cleanup"]["physical"])
