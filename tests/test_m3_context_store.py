"""D7/A7: freeze independent Git-process availability before any correction.

A7 context-scoped availability awaits separate maintainer approval. Payload
warming and completed selection warming are intentionally distinct: selection's
child is closed before an entered reader starts. Both observation orders retain
logical entry/blob admission and complete SnapshotWork, even on refusal.

Tamper overwrites equal-length compressed payload bytes in place (no truncation,
SIGBUS or timing race). Replacement unlinks old pack files and installs a new
pack. Duplicate layout mutations affect the pack, retaining the loose target;
additional duplicate controls mutate the loose side and both stores explicitly.
"""
from pathlib import Path
import shutil
import zlib

import pytest

from m1_fixture import RawRepo
from m3_fixture import Trace, authenticated_m3_oracle, compare, repo, work

PAYLOAD = b"payload\n"
FORGED = b"PAYLOAD\n"
TARGET = "c2981a9931b383b5eb128dc5e3505654ab5269b6"


def _loose(root, oid):
    return root / ".git" / "objects" / oid[:2] / oid[2:]


def _tamper_pack(repo, target):
    packdir = repo.root / ".git/objects/pack"
    index, = packdir.glob("*.idx")
    records = repo.git("verify-pack", "-v", str(index)).splitlines()
    record, = [line.split() for line in records if line.startswith(target.encode() + b" ")]
    position = int(record[4])
    pack = index.with_suffix(".pack")
    data = bytearray(pack.read_bytes())
    while data[position] & 0x80:
        position += 1
    position += 1
    decompressor = zlib.decompressobj()
    assert decompressor.decompress(data[position:]) == PAYLOAD
    length = len(data[position:]) - len(decompressor.unused_data)
    # Git's selected compression level need not equal zlib's default.
    candidates = [zlib.compress(FORGED, level) for level in range(1, 10)]
    replacement = next(value for value in candidates if len(value) == length)
    data[position:position + length] = replacement
    pack.chmod(0o600)
    with pack.open("r+b") as handle:
        handle.write(data)


def d7(m, fixture, patch, layout, mutation, warmth, source, order):
    root = fixture.root.parent / "store"
    if root.exists():
        shutil.rmtree(root)
    repo = RawRepo(root)
    commit = repo.commit((("file", "100644", PAYLOAD),))
    repo.git("update-ref", "HEAD", commit)
    assert repo.hash(PAYLOAD) == TARGET
    loose = _loose(root, TARGET)
    saved = loose.read_bytes()
    packdir = root / ".git/objects/pack"
    if layout != "loose":
        repo.git("repack", "-ad")
        repo.git("prune-packed")
        assert not loose.exists()
        if layout == "duplicate":
            loose.parent.mkdir(exist_ok=True)
            loose.write_bytes(saved)
    replacement_files = []
    if mutation.startswith("replace") and layout != "loose":
        unrelated = repo.hash(b"unrelated\n")
        destination = root / "replacement"
        destination.mkdir()
        wanted = [unrelated] + ([TARGET] if mutation == "replace-keep" else [])
        repo.git("pack-objects", str(destination / "pack"),
                 data=("\n".join(wanted) + "\n").encode())
        replacement_files = list(destination.iterdir())
    s = m.snapshot
    selection_children = []
    original_close = s._BatchReader.close
    def remember_close(batch):
        original_close(batch)
        selection_children.append(batch.process.poll() is not None)
    with patch.context() as selection_patch:
        selection_patch.setattr(s._BatchReader, "close", remember_close)
        a, b = s.TreeSnapshot.select(root, commit), s.TreeSnapshot.select(root, commit)
    assert selection_children == [True, True]
    assert a.batch_pid is b.batch_pid is None
    trace = Trace(a, b)
    with a, b:
        distinct = a.batch_pid != b.batch_pid
        for index, subject in enumerate((a, b)):
            if warmth & (1 << index):
                if source == "payload":
                    trace.call(f"warm {index}", lambda s=subject: s.blob(s.entry("file"), limit=100))
                else:
                    # A repeated selection warms a real temporary Git child,
                    # which is closed; none of its Python or Git caches is adopted.
                    with patch.context() as selection_patch:
                        selection_patch.setattr(s._BatchReader, "close", remember_close)
                        extra = s.TreeSnapshot.select(root, commit)
                    assert extra.batch_pid is None
        removed = 0
        target_store = "loose" if layout == "loose" or mutation.endswith("loose") else "pack"
        if mutation in {"remove", "remove-loose", "remove-all", "replace-keep", "replace-omit"}:
            if target_store == "loose" or mutation == "remove-all":
                if loose.exists():
                    loose.unlink()
            if target_store == "pack" or mutation == "remove-all":
                for path in packdir.iterdir():
                    if path.suffix in {".pack", ".idx", ".rev"}:
                        path.unlink()
                        removed += 1
        if mutation == "replace-keep" and layout == "loose":
            loose.write_bytes(saved)
        elif mutation.startswith("replace"):
            for path in replacement_files:
                shutil.copyfile(path, packdir / path.name)
        if mutation in {"tamper", "tamper-loose"}:
            if target_store == "loose":
                loose.chmod(0o600)
                loose.write_bytes(zlib.compress(b"blob 8\0" + FORGED))
            else:
                _tamper_pack(repo, TARGET)
        for subject in (a, b):
            subject._state.batch._headers.clear()
            assert subject._state.batch._headers == {}
        for index in order:
            subject = (a, b)[index]
            trace.call(f"read {index}", lambda s=subject: s.blob(s.entry("file"), limit=100))
        # Snapshot close notes belong to the same observable trace.
        resources = [(x.temporary_directory, x._state.batch.process) for x in (a, b)]
    return {"events": trace.events, "separate_pids": distinct,
            "removed_pack_files": removed, "selection_children_reaped": selection_children,
            "closed": [a._state.closed, b._state.closed],
            "physical_cleanup": [[not path.exists(), process.poll() is not None] for path, process in resources],
            "final": work(a, b)}


CASES = {
    f"D7-{layout}-{mutation}-{warmth}-{source}-{''.join(map(str, order))}":
        (d7, layout, mutation, warmth, source, order)
    for layout in ("loose", "packed", "duplicate")
    for mutation in (("unchanged", "remove", "tamper", "replace-keep", "replace-omit") +
                     (("remove-loose", "tamper-loose", "remove-all") if layout == "duplicate" else ()))
    for warmth in range(4)
    for source in ("payload", "selection")
    for order in ((0, 1), (1, 0))
}


@pytest.mark.parametrize("case", CASES)
def test_independent_store_availability(repo, monkeypatch, case):
    from m3_store_expected import CASE_TRACE, TRACES
    probe, *args = CASES[case]
    compare(probe, repo, monkeypatch, *args, expected=TRACES[CASE_TRACE[case]])
