"""Refusal battery for the corpus binding pass.

Each test names one way a producer could publish a journal that does not
describe the tree an auditor cloned, and asserts the binding pass refuses. The
happy-path test is one line; the value is entirely in the refusals.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import unicodedata

import pytest

from receipt._render import bounded_encoded, bounded_key
from receipt.corpus import (
    EVIDENCE_RENDER_STRUCTURE,
    GATE_RENDER_STRUCTURE,
    MAX_EVIDENCE_ENTRIES,
    MAX_EVIDENCE_TEXT,
    MAX_GATE_DECLARATIONS,
    MAX_GATE_TEXT,
    MAX_JOURNAL_BYTES,
    MAX_JOURNAL_ROW_BYTES,
    MAX_JOURNAL_ROWS,
    MAX_JOURNAL_ROWS_CEILING,
    MAX_PATH_COMPONENTS_TOTAL,
    MAX_PATH_TEXT,
    MAX_REMOVED_TEXT,
    REMOVED_PATH_RENDER_STRUCTURE,
    CorpusError,
    verify_corpus_binding as _verify_corpus_binding,
    verify_declarations,
)
from receipt.snapshot import TreeSnapshot

from corpus_fixture import (
    ATTESTED,
    CONTENT,
    JOURNAL_SCHEMA,
    corpus_spec,
    journal_rows,
    render_journal,
    sha256_text,
)


#: The one refusal the portable-name policy produces. Quoted here so a test
#: asserting it reads as one fact rather than as three lines of message, and
#: so a change to the wording is one edit rather than a dozen.
NOT_PORTABLE = (
    "is not a portable name (ASCII letters, digits, '.', '_' and '-', not "
    "ending in '.', not a Win32 device name)"
)


def _git(
    root: pathlib.Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and completed.returncode:
        raise AssertionError(
            f"git {' '.join(arguments)} failed: "
            f"{completed.stderr.decode('utf-8', 'replace')}"
        )
    return completed.stdout


def _commit_worktree(root: pathlib.Path) -> str:
    """Commit the fixture tree and return the immutable subject OID."""

    if not (root / ".git").exists():
        _git(root, "init", "-q")
        _git(root, "config", "user.name", "Receipt Tests")
        _git(root, "config", "user.email", "receipt-tests@example.invalid")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "--allow-empty", "-m", "corpus fixture")
    return _git(root, "rev-parse", "HEAD").decode("ascii").strip()


def _hash_blob(root: pathlib.Path, payload: bytes) -> str:
    return (
        _git(root, "hash-object", "-w", "--stdin", input_bytes=payload)
        .decode("ascii")
        .strip()
    )


def _commit_index_updates(
    root: pathlib.Path,
    updates: list[tuple[str, str | None, bytes]],
) -> str:
    """Commit raw index entries, including names a checkout cannot express."""

    records = bytearray()
    for mode, object_id, path in updates:
        if object_id is None:
            records.extend(b"0 " + (b"0" * 40) + b"\t" + path + b"\0")
        else:
            records.extend(
                mode.encode("ascii")
                + b" "
                + object_id.encode("ascii")
                + b"\t"
                + path
                + b"\0"
            )
    _git(
        root,
        "-c",
        "core.protectNTFS=false",
        "-c",
        "core.protectHFS=false",
        "-c",
        "core.ignoreCase=false",
        "update-index",
        "-z",
        "--index-info",
        input_bytes=bytes(records),
    )
    _git(root, "commit", "-q", "--no-gpg-sign", "-m", "raw tree fixture")
    return _git(root, "rev-parse", "HEAD").decode("ascii").strip()


def _commit_extra_blob(root: pathlib.Path, path: bytes, payload: bytes = b"scratch\n") -> str:
    _commit_worktree(root)
    return _commit_index_updates(root, [("100644", _hash_blob(root, payload), path)])


def _verify_commit(
    root: pathlib.Path,
    oid: str,
    journal_bytes: bytes,
    *,
    spec,
):
    with TreeSnapshot.select(root, oid) as snapshot:
        return _verify_corpus_binding(snapshot, journal_bytes, spec=spec)


def verify_corpus_binding(
    subject: pathlib.Path | TreeSnapshot,
    journal_bytes: bytes,
    *,
    spec,
):
    """Adapt ordinary fixtures to the commit-addressed production API."""

    if isinstance(subject, TreeSnapshot):
        return _verify_corpus_binding(subject, journal_bytes, spec=spec)
    oid = _commit_worktree(subject)
    with TreeSnapshot.select(subject, oid) as snapshot:
        return _verify_corpus_binding(snapshot, journal_bytes, spec=spec)


def write_tree(
    root: pathlib.Path,
    content: dict[str, str] | None = None,
    attested: dict[str, str] | None = None,
) -> None:
    for relative, text in {**(content or CONTENT), **(attested or ATTESTED)}.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def reindex(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    for index, row in enumerate(rows):
        row["entryIndex"] = index
    return rows


def charged_gate(gate: dict[str, object]) -> int:
    """What the module charges one gate declaration against ``MAX_GATE_TEXT``.

    Spelled out from the shipped constants and ``json.dumps`` rather than
    imported from ``receipt.corpus``, so the arithmetic under every budget
    test is the renderer's and not a copy of the code being tested. The
    bound comes from ``receipt._render``, which is the renderer: it is the
    module ``receipt.cli`` puts every string through on its way into the
    verdict, and charging the string before it rather than after was
    S5R3-F10.
    """

    evidence: dict[str, str] = gate["evidence"]  # type: ignore[assignment]
    return (
        GATE_RENDER_STRUCTURE
        + len(json.dumps(bounded_encoded(gate["gateId"])))
        + len(json.dumps(bounded_encoded(gate["outcome"])))
        + sum(
            EVIDENCE_RENDER_STRUCTURE
            + len(json.dumps(bounded_key(key)))
            + len(json.dumps(bounded_encoded(value)))
            for key, value in evidence.items()
        )
    )


def charged_removed(path: str) -> int:
    """What the module charges one removed path against ``MAX_REMOVED_TEXT``."""

    return REMOVED_PATH_RENDER_STRUCTURE + len(json.dumps(bounded_encoded(path)))


def first_over(cost: int, budget: int) -> tuple[int, int]:
    """Which identically-priced item first carries the total over ``budget``.

    Returns its one-based position and the running total at that point,
    which is what the refusal names.
    """

    number = budget // cost + 1
    return number, number * cost


@pytest.mark.parametrize("name_repertoire", ["portable", "posix-bytes"])
def test_binding_accepts_a_journal_that_describes_the_tree(
    tmp_path: pathlib.Path, name_repertoire: str
) -> None:
    write_tree(tmp_path)
    verification = verify_corpus_binding(
        tmp_path,
        render_journal(journal_rows()),
        spec=corpus_spec(name_repertoire=name_repertoire),
    )
    assert [entry.path for entry in verification.content] == sorted(CONTENT)
    assert [entry.path for entry in verification.attested] == sorted(ATTESTED)
    assert len(verification.gates) == 3
    assert verification.name_repertoire == name_repertoire


def test_binding_requires_a_selected_tree_snapshot(tmp_path: pathlib.Path) -> None:
    with pytest.raises(CorpusError) as caught:
        _verify_corpus_binding(
            tmp_path,
            render_journal(journal_rows()),
            spec=corpus_spec(),
        )  # type: ignore[arg-type]
    assert str(caught.value) == (
        "verify_corpus_binding requires a TreeSnapshot; select one with "
        "TreeSnapshot.select"
    )


@pytest.mark.parametrize("name_repertoire", ["portable", "posix-bytes"])
@pytest.mark.parametrize(
    ("shape", "message"),
    [
        (
            "gitlink",
            "content root contains a gitlink: 'rules/vendor'",
        ),
        (
            "symlink",
            "content root contains a symlink where a regular file was recorded: "
            "'rules/tax/linked.yaml'",
        ),
        (
            "non-utf8",
            "tree entry name is not valid UTF-8 for folding",
        ),
        (
            "fold-siblings",
            "directory holds two entries a case-insensitive filesystem would "
            "merge: 'misc/README' and 'misc/ReadMe'",
        ),
    ],
)
def test_refuses_unsupported_committed_tree_shapes_under_each_repertoire(
    tmp_path: pathlib.Path,
    name_repertoire: str,
    shape: str,
    message: str,
) -> None:
    """Tree modes and names are screened from objects, not a checkout."""

    write_tree(tmp_path)
    base_oid = _commit_worktree(tmp_path)
    blob_oid = _hash_blob(tmp_path, b"shape fixture\n")
    if shape == "gitlink":
        updates = [("160000", base_oid, b"rules/vendor")]
    elif shape == "symlink":
        updates = [("120000", blob_oid, b"rules/tax/linked.yaml")]
    elif shape == "non-utf8":
        updates = [("100644", blob_oid, b"misc/non-utf8-\xff")]
    else:
        updates = [
            ("100644", blob_oid, b"misc/README"),
            ("100644", blob_oid, b"misc/ReadMe"),
        ]
    oid = _commit_index_updates(tmp_path, updates)

    with pytest.raises(CorpusError) as caught:
        _verify_commit(
            tmp_path,
            oid,
            render_journal(journal_rows()),
            spec=corpus_spec(name_repertoire=name_repertoire),
        )
    assert str(caught.value) == message


def test_binding_is_invariant_to_every_worktree_mutation_class(
    tmp_path: pathlib.Path,
) -> None:
    """Rewrite, insert, and rename below every protected root after selection."""

    content_roots = (
        pathlib.PurePosixPath("rules"),
        pathlib.PurePosixPath("policies"),
    )
    content = {
        f"{root.as_posix()}/rewrite.yaml": f"name: {root.name}-rewrite\n"
        for root in content_roots
    }
    content.update(
        {
            f"{root.as_posix()}/rename.yaml": f"name: {root.name}-rename\n"
            for root in content_roots
        }
    )
    attested = {
        ".axiom/toolchain.toml": 'python = "3.14"\n',
        ".axiom/rename-me.txt": "rename me\n",
    }
    write_tree(tmp_path, content=content, attested=attested)
    journal_bytes = render_journal(journal_rows(content=content, attested=attested))
    oid = _commit_worktree(tmp_path)
    spec = corpus_spec(content_roots=content_roots)

    def selected_verdict() -> tuple[object, tuple[str, str]]:
        with TreeSnapshot.select(tmp_path, oid) as snapshot:
            identity = (snapshot.commit, snapshot.tree)
            verdict = _verify_corpus_binding(snapshot, journal_bytes, spec=spec)
        return verdict, identity

    before_verdict, before_oids = selected_verdict()

    for root in content_roots:
        directory = tmp_path / root.as_posix()
        (directory / "rewrite.yaml").write_text("rewritten outside the tree\n")
        (directory / "inserted.yaml").write_text("inserted outside the tree\n")
        (directory / "rename.yaml").rename(directory / "renamed.yaml")
    (tmp_path / ".axiom/toolchain.toml").write_text("rewritten outside the tree\n")
    (tmp_path / ".axiom/inserted.txt").write_text("inserted outside the tree\n")
    (tmp_path / ".axiom/rename-me.txt").rename(
        tmp_path / ".axiom/renamed.txt"
    )
    assert _git(tmp_path, "status", "--porcelain")

    after_verdict, after_oids = selected_verdict()
    assert after_verdict == before_verdict
    assert before_oids[0] == oid
    assert after_oids == before_oids


def test_binding_materializes_each_listing_path_once(tmp_path: pathlib.Path) -> None:
    """The one flat listing and exact attested lookup pay one path charge each."""

    write_tree(tmp_path)
    oid = _commit_worktree(tmp_path)
    with TreeSnapshot.select(tmp_path, oid) as snapshot:
        _verify_corpus_binding(
            snapshot,
            render_journal(journal_rows()),
            spec=corpus_spec(),
        )
        charged = snapshot.work.path_bytes

    leaves = set(CONTENT) | set(ATTESTED)
    tree_paths = set(leaves)
    for path in leaves:
        parts = path.split("/")
        tree_paths.update("/".join(parts[:depth]) for depth in range(1, len(parts)))
    expected_listing = sum(len(path.encode()) for path in tree_paths)
    expected_attested_lookups = sum(len(path.encode()) for path in ATTESTED)
    assert charged == expected_listing + expected_attested_lookups


def test_refuses_a_content_file_edited_after_witnessing(tmp_path: pathlib.Path) -> None:
    write_tree(tmp_path)
    (tmp_path / "rules/tax/rate.yaml").write_text("name: rate\nvalue: 0.99\n")
    with pytest.raises(CorpusError, match="does not match its witnessed digest"):
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )


def test_refuses_an_unlisted_content_file(tmp_path: pathlib.Path) -> None:
    """The closed-world sweep is the point: a smuggled rule must not pass."""

    write_tree(tmp_path)
    (tmp_path / "rules/tax/smuggled.yaml").write_text("name: smuggled\n")
    with pytest.raises(CorpusError, match="not bound by the witnessed journal"):
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )


def test_refuses_a_bound_file_deleted_from_the_tree(tmp_path: pathlib.Path) -> None:
    write_tree(tmp_path)
    (tmp_path / "rules/benefit/amount.yaml").unlink()
    with pytest.raises(CorpusError, match="missing from the tree"):
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )


def test_refuses_a_content_symlink(tmp_path: pathlib.Path) -> None:
    write_tree(tmp_path)
    outside = tmp_path.parent / "outside.yaml"
    outside.write_text("name: outside\n")
    (tmp_path / "rules/tax/linked.yaml").symlink_to(outside)
    with pytest.raises(CorpusError, match="symlink"):
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )


def test_refuses_control_characters_in_gate_evidence(tmp_path: pathlib.Path) -> None:
    """Regression: evidence strings are rendered to a terminal, so a producer
    could embed CR/ESC and redraw the verdict line into a false PASS."""

    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "not-run",
                "evidence": {
                    "reason": "skipped\x1b[2K\r  VERDICT: PASS — all gates verified"
                },
            }
        ]
    )
    with pytest.raises(CorpusError, match="control character"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_tombstone_naming_a_superseded_digest(
    tmp_path: pathlib.Path,
) -> None:
    """Regression: present(H1) → present(H2) → removed(H1) deleted the
    effective H2 while the journal recorded retiring an already-superseded
    digest. A tombstone must name what it actually removes."""

    remaining = {k: v for k, v in CONTENT.items() if k != "rules/tax/rate.yaml"}
    write_tree(tmp_path, content=remaining)
    rows = journal_rows()
    original = sha256_text(CONTENT["rules/tax/rate.yaml"])
    rows.append(
        {
            "schemaVersion": JOURNAL_SCHEMA,
            "entryIndex": len(rows),
            "kind": "content",
            "path": "rules/tax/rate.yaml",
            "sha256": sha256_text("name: rate\nvalue: 0.175\n"),
            "state": "present",
        }
    )
    rows.append(
        {
            "schemaVersion": JOURNAL_SCHEMA,
            "entryIndex": len(rows),
            "kind": "content",
            "path": "rules/tax/rate.yaml",
            "sha256": original,  # stale: names H1, not the effective H2
            "state": "removed",
        }
    )
    with pytest.raises(CorpusError, match="but the effective revision is"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_path_with_a_colon(tmp_path: pathlib.Path) -> None:
    """Binds the policy: "C:/x" joins drive-absolute under Windows pathlib.

    A colon is outside the portable repertoire, so one screen refuses it and
    the module no longer carries a colon rule of its own — it carried two,
    one for declared paths and one for enumerated names, saying the same
    thing in different words. Without the screen this path validates and
    joins drive-absolute under ``pathlib`` on Windows, referencing a file
    outside the root.
    """

    write_tree(tmp_path)
    rows = journal_rows()
    rows[3]["path"] = "C:/outside.toml"  # the attested row
    with pytest.raises(CorpusError, match="is not a portable name"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_an_attested_path_the_spec_requires_but_the_journal_omits(
    tmp_path: pathlib.Path,
) -> None:
    """The consumer decides what must be covered, not the producer."""

    write_tree(tmp_path)
    rows = reindex([row for row in journal_rows() if row.get("kind") != "attested"])
    with pytest.raises(CorpusError, match="does not attest a path the pinned spec"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_required_gate_the_journal_omits(tmp_path: pathlib.Path) -> None:
    """Completeness is a DECLARATION failure, not a binding failure — the pass
    boundary the verdict describes."""

    write_tree(tmp_path)
    rows = reindex(
        [
            row
            for row in journal_rows()
            if row.get("gateId") != "rulespec/compile"
        ]
    )
    spec = corpus_spec()
    # Binding still succeeds: the tree does match the journal.
    verification = verify_corpus_binding(tmp_path, render_journal(rows), spec=spec)
    with pytest.raises(CorpusError, match="does not declare a gate the pinned spec"):
        verify_declarations(verification, spec=spec)


def test_refuses_a_tier_the_spec_does_not_accept(tmp_path: pathlib.Path) -> None:
    """A lane that only accepts publicly reproducible gates must refuse a
    ci-attested one rather than quietly widening its own claim."""

    write_tree(tmp_path)
    strict = corpus_spec(
        accepted_gate_tiers=frozenset({"public"}),
        required_gates=frozenset({"rulespec/compile"}),
    )
    with pytest.raises(CorpusError, match="which the pinned spec does not accept"):
        verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=strict)


def test_refuses_an_invented_tier(tmp_path: pathlib.Path) -> None:
    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "totally-reproducible",
                "outcome": "pass",
                "evidence": {"command": "make validate"},
            }
        ]
    )
    with pytest.raises(CorpusError, match="unknown reproducibility tier"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_waiver_that_does_not_name_its_waiver_set(
    tmp_path: pathlib.Path,
) -> None:
    """"Waived" without a waiver-set digest is an unfalsifiable excuse."""

    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "waived",
                "evidence": {"note": "known gap"},
            }
        ]
    )
    with pytest.raises(CorpusError, match="waived without naming"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_accepts_a_waiver_that_names_its_waiver_set(tmp_path: pathlib.Path) -> None:
    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "waived",
                "evidence": {"waiverSetSha256": "a" * 64},
            }
        ]
    )
    verification = verify_corpus_binding(
        tmp_path, render_journal(rows), spec=corpus_spec()
    )
    assert verification.gates[0].outcome == "waived"


def test_refuses_a_not_run_gate_that_does_not_say_why(tmp_path: pathlib.Path) -> None:
    """A disabled gate must state its reason; silence reads as "it passed"."""

    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "not-run",
                "evidence": {"note": "n/a"},
            }
        ]
    )
    with pytest.raises(CorpusError, match="not-run without a non-empty"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_waiver_whose_digest_is_a_placeholder(tmp_path: pathlib.Path) -> None:
    """A short/invalid waiverSetSha256 is no more falsifiable than a missing one."""

    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "waived",
                "evidence": {"waiverSetSha256": "x"},
            }
        ]
    )
    with pytest.raises(CorpusError, match="waiverSetSha256"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_not_run_reason_that_is_only_whitespace(
    tmp_path: pathlib.Path,
) -> None:
    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "not-run",
                "evidence": {"reason": "   "},
            }
        ]
    )
    with pytest.raises(CorpusError, match="not-run without a non-empty"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_row_whose_kind_is_not_a_string(tmp_path: pathlib.Path) -> None:
    """An unhashable JSON kind must refuse with CorpusError, not raise TypeError."""

    write_tree(tmp_path)
    rows = journal_rows()
    rows.append({"kind": [], "entryIndex": len(rows)})
    with pytest.raises(CorpusError, match="unknown kind"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_accepts_a_not_run_gate_that_states_its_reason(tmp_path: pathlib.Path) -> None:
    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "not-run",
                "evidence": {"reason": "run-generated-guard: false in the caller"},
            }
        ]
    )
    verification = verify_corpus_binding(
        tmp_path, render_journal(rows), spec=corpus_spec()
    )
    assert verification.gates[0].outcome == "not-run"


def test_refuses_a_restated_gate(tmp_path: pathlib.Path) -> None:
    """A second declaration could silently downgrade the first one's tier."""

    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "pass",
                "evidence": {"command": "make validate"},
            },
            {
                "gateId": "rulespec/compile",
                "tier": "ci-attested",
                "outcome": "pass",
                "evidence": {"workflow": "x.yml"},
            },
        ]
    )
    with pytest.raises(CorpusError, match="restates gate"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_path_escaping_the_root(tmp_path: pathlib.Path) -> None:
    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["path"] = "rules/../../etc/passwd"
    with pytest.raises(CorpusError, match="relative segment"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_content_reclassified_as_attested(tmp_path: pathlib.Path) -> None:
    """Relabelling a rule file as "attested" would exempt it from the sweep."""

    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["kind"] = "attested"
    with pytest.raises(CorpusError, match="must be swept closed-world"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_non_contiguous_entry_index(tmp_path: pathlib.Path) -> None:
    """Gapped indices would let a row be dropped without leaving a hole."""

    write_tree(tmp_path)
    rows = journal_rows()
    rows[2]["entryIndex"] = 99
    with pytest.raises(CorpusError, match="entryIndex must be"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_foreign_schema_version(tmp_path: pathlib.Path) -> None:
    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["schemaVersion"] = "some/other-journal/v1"
    with pytest.raises(CorpusError, match="but the pinned spec is"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_unknown_row_keys(tmp_path: pathlib.Path) -> None:
    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["extra"] = "surprise"
    with pytest.raises(CorpusError, match="not closed-world"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_journal_without_a_trailing_newline(tmp_path: pathlib.Path) -> None:
    write_tree(tmp_path)
    payload = render_journal(journal_rows()).rstrip(b"\n")
    with pytest.raises(CorpusError, match="must end with exactly one LF"):
        verify_corpus_binding(tmp_path, payload, spec=corpus_spec())


def test_supersession_tracks_the_latest_row(tmp_path: pathlib.Path) -> None:
    """A corrected encoding appends; it never rewrites an earlier row."""

    corrected = dict(CONTENT)
    corrected["rules/tax/rate.yaml"] = "name: rate\nvalue: 0.175\n"
    write_tree(tmp_path, content=corrected)
    rows = journal_rows()
    rows.append(
        {
            "schemaVersion": JOURNAL_SCHEMA,
            "entryIndex": len(rows),
            "kind": "content",
            "path": "rules/tax/rate.yaml",
            "sha256": sha256_text(corrected["rules/tax/rate.yaml"]),
            "state": "present",
        }
    )
    verification = verify_corpus_binding(
        tmp_path, render_journal(rows), spec=corpus_spec()
    )
    binding = next(e for e in verification.content if e.path == "rules/tax/rate.yaml")
    assert binding.sha256 == sha256_text(corrected["rules/tax/rate.yaml"])


def test_removal_drops_the_path_from_the_present_view(tmp_path: pathlib.Path) -> None:
    remaining = {k: v for k, v in CONTENT.items() if k != "rules/benefit/amount.yaml"}
    write_tree(tmp_path, content=remaining)
    rows = journal_rows()
    rows.append(
        {
            "schemaVersion": JOURNAL_SCHEMA,
            "entryIndex": len(rows),
            "kind": "content",
            "path": "rules/benefit/amount.yaml",
            "sha256": sha256_text(CONTENT["rules/benefit/amount.yaml"]),
            "state": "removed",
        }
    )
    verification = verify_corpus_binding(
        tmp_path, render_journal(rows), spec=corpus_spec()
    )
    assert "rules/benefit/amount.yaml" not in {e.path for e in verification.content}
    assert verification.removed_paths == ("rules/benefit/amount.yaml",)


def test_refuses_removing_a_path_that_was_never_present(tmp_path: pathlib.Path) -> None:
    write_tree(tmp_path)
    rows = journal_rows()
    rows.append(
        {
            "schemaVersion": JOURNAL_SCHEMA,
            "entryIndex": len(rows),
            "kind": "content",
            "path": "rules/tax/never.yaml",
            "sha256": "b" * 64,
            "state": "removed",
        }
    )
    with pytest.raises(CorpusError, match="which was never present"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_spec_refuses_an_unknown_tier_at_construction() -> None:
    with pytest.raises(CorpusError, match="unknown reproducibility tier"):
        corpus_spec(accepted_gate_tiers=frozenset({"vibes"}))


def test_spec_declares_a_defaulted_closed_name_repertoire() -> None:
    assert corpus_spec().name_repertoire == "portable"
    assert corpus_spec(name_repertoire="posix-bytes").name_repertoire == "posix-bytes"
    with pytest.raises(
        CorpusError,
        match="name repertoire must be 'portable' or 'posix-bytes'",
    ):
        corpus_spec(name_repertoire="unicode")


def test_posix_bytes_spec_accepts_nonportable_utf8_paths() -> None:
    spec = corpus_spec(
        content_roots=(pathlib.PurePosixPath("règles"),),
        required_attested_paths=frozenset({".axiom/outil:chaîne.toml"}),
        name_repertoire="posix-bytes",
    )
    assert spec.content_roots == (pathlib.PurePosixPath("règles"),)


def test_spec_refuses_an_empty_content_root() -> None:
    with pytest.raises(CorpusError, match="at least one content root"):
        corpus_spec(content_roots=())


def test_spec_refuses_a_journal_capacity_above_the_byte_derived_ceiling() -> None:
    """Binds S7-F2: a consumer capacity needs a hard byte-derived ceiling.

    The shortest valid compact row is a 115-byte gate plus its required LF,
    so 64 MiB can hold at most 578,524 rows. A larger consumer pin is refused
    at construction. Without S7-F2 ``CorpusSpec`` has no such field or, with
    the upper validation disabled, this construction does not raise the
    required ``CorpusError``.
    """

    smallest = {
        "schemaVersion": "s",
        "entryIndex": 0,
        "kind": "gate",
        "gateId": "g",
        "tier": "public",
        "outcome": "pass",
        "evidence": {"": ""},
    }
    compact = json.dumps(smallest, separators=(",", ":")).encode() + b"\n"
    assert len(compact) == 116
    assert MAX_JOURNAL_ROWS_CEILING == MAX_JOURNAL_BYTES // 116 == 578524

    with pytest.raises(CorpusError) as caught:
        corpus_spec(journal_row_capacity=MAX_JOURNAL_ROWS_CEILING + 1)
    assert str(caught.value) == (
        "CorpusSpec journal_row_capacity must be an integer from 1 to 578524"
    )


def test_the_spec_pins_a_suffix_by_one_rule_or_refuses_it() -> None:
    """Binds the suffix policy, S5R4-F5 and S7-F7: two regexes, two questions.

    A pin used to be screened four times over — a leading dot, a foldability
    screen against a pinned Unicode table, an ASCII rule, and a fold-key
    length test to decide which pins the ASCII rule applied to — and every
    one of those was added by a review round that found the previous
    arrangement wrong. The policy replaced them with one rule, and stated it
    one notch too tightly: a period and one to sixteen ASCII letters or
    digits. That was a compatibility break the finding named — the released
    ``CorpusSpec`` accepted any dot-prefixed portable suffix. That includes
    ``.tar.gz``, ``.ssxx``, ``.a-b`` and ``._``. S7-F7 corrects the old prose's
    conflation with alias capability: ``.a-b`` and ``._`` *are* structurally
    8.3 extensions and are screened by the narrower regex; ``.ssxx`` has four
    characters after its period and is not.

    So the rule is a period followed by portable characters, with interior
    periods allowed and no length cap, and it still refuses everything the
    four screens were there for: an unassigned code point, a non-ASCII
    letter inside an alias-capable pin, a non-ASCII letter outside one, a
    separator, a bare period, and a pin with no period.

    Without the widening ``.tar.gz``, ``.ssxx``, ``.a-b``, ``._`` and a
    twenty-character pin are refused at construction and a consumer whose
    corpus is spelled that way cannot state its own spec. Without the rule
    itself ``.yaml\u0378`` constructs — the fold screen it used to face is
    gone with the pinned table — and the suffix is then folded against every
    path in the tree and every entry name the sweep sees.
    """

    for suffix in (
        ".yaml\u0378", ".\u00e9ml", ".\u00e9yaml", ".y/ml", ".", "yaml", ""
    ):
        with pytest.raises(CorpusError) as caught:
            corpus_spec(content_suffixes=(suffix,))
        assert str(caught.value).startswith(
            "CorpusSpec content suffix must be '.' followed by one or more "
            "portable characters"
        ), suffix
    assert corpus_spec(content_suffixes=(".yaml", ".yml")).content_suffixes
    # The five shapes the sixteen-character grammar took away, given back.
    for suffix in (".tar.gz", ".ssxx", ".a-b", "._", "." + "y" * 20):
        assert corpus_spec(content_suffixes=(suffix,)).content_suffixes == (suffix,)


def test_the_spec_refuses_a_content_root_outside_the_portable_repertoire() -> None:
    """Binds the policy, root half: the same screen, named for the spec.

    A root is folded by ``content_root_of`` for every path the journal binds,
    and the sweep descends its exact spelling, so a root whose equivalence
    class this module would have to guess at decides closed-world membership
    on the auditor's host rather than on the corpus. The screen runs before
    the path rules so the refusal names the consumer's committed spec, which
    is the file that has to be edited, rather than naming a path. Without it
    the refusal is the path-shaped one.
    """

    with pytest.raises(CorpusError, match="is not a portable name") as caught:
        corpus_spec(content_roots=(pathlib.PurePosixPath("ru\u0378les"),))
    assert str(caught.value).startswith("CorpusSpec content root is not a portable")


def test_reproducible_and_unreproducible_gates_are_separated(
    tmp_path: pathlib.Path,
) -> None:
    """The honesty property: the split survives into the returned value."""

    write_tree(tmp_path)
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows()), spec=corpus_spec()
    )
    assert [g.gate_id for g in verification.reproducible_gates] == ["rulespec/compile"]
    assert {g.gate_id for g in verification.unreproducible_gates} == {
        "oracle/licensed-parity",
        "ci/repository-checks",
    }


def test_refuses_paths_that_alias_under_case_or_normalization(
    tmp_path: pathlib.Path,
) -> None:
    """Two declared paths a case-insensitive filesystem would merge make the
    closed-world set ambiguous, host-independently. (Cross-family review.)"""

    write_tree(tmp_path)
    rows = journal_rows()
    # Duplicate an existing content row under a case-variant of a middle
    # segment — same content root, same suffix, so it clears every earlier
    # check and only the alias guard can catch it.
    content_rows = [r for r in rows if r.get("kind") == "content"]
    victim = dict(content_rows[0])
    original = victim["path"]  # e.g. rules/benefit/amount.yaml
    segments = original.split("/")
    segments[1] = segments[1].capitalize()  # rules/Benefit/amount.yaml
    victim["path"] = "/".join(segments)
    assert victim["path"] != original
    rows.append(victim)
    reindex(rows)
    with pytest.raises(CorpusError, match="would alias"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


# --- second cross-family round: races the first round's guards left open -----


def test_refuses_two_declared_paths_that_would_alias_at_a_directory(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R3-F9: the aliasing guard compared whole paths only.

    ``rules/A/x.yaml`` and ``rules/a/y.yaml`` are two distinct paths and
    their fold keys differ, so the whole-path comparison passed them. An
    insensitive clone merges ``A`` and ``a`` into one directory holding both
    files, and the closed-world sweep descends the spellings the journal
    named — two directories on the auditor's host, one on the consumer's. A
    closed world whose shape depends on which filesystem resolved it is not
    closed, which is exactly what the whole-path comparison exists to say.

    Every component prefix is compared now, at the depth it sits, so the
    collision is caught where it is: at the directory.

    The guard runs on the parsed journal, before the sweep, so no files are
    written for the aliasing pair and what is asserted is the guard itself.
    With the prefix comparison disabled in place the pair passes it, and
    what the verifier says next is decided by whichever tree the auditor's
    filesystem produced — which is the finding, and which is why the
    assertion here is on the refusal that does not depend on the host.
    """

    write_tree(tmp_path)
    rows = journal_rows()
    for path, digest_source in (
        ("rules/A/x.yaml", "name: a\n"),
        ("rules/a/y.yaml", "name: b\n"),
    ):
        rows.append(
            {
                "schemaVersion": JOURNAL_SCHEMA,
                "kind": "content",
                "path": path,
                "sha256": sha256_text(digest_source),
                "state": "present",
            }
        )
    reindex(rows)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert str(caught.value) == (
        "two declared paths would alias at a directory: 'rules/A' and "
        "'rules/a'"
    )


def test_two_declared_paths_under_distinct_ancestors_still_verify(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R3-F9, the control: the prefix pass must not refuse a corpus.

    Every content path in an ordinary corpus shares its leading components
    with every other one — the fixture's three files sit under ``rules``,
    ``rules/tax`` and ``rules/benefit`` — so a prefix comparison that
    mistook a repeated spelling for a collision would refuse every corpus
    there is. What refuses is two *distinct* spellings folding equal at the
    same depth, and identical prefixes are not that.

    A second content directory beside the first is added here so the
    control has a sibling pair to be right about, and the whole corpus is
    verified rather than merely parsed.

    This test passes with the S5R3-F9 change disabled, which is the point.
    """

    content = dict(CONTENT)
    content["rules/A/x.yaml"] = "name: a\n"
    content["rules/b/y.yaml"] = "name: b\n"
    write_tree(tmp_path, content=content)
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows(content=content)), spec=corpus_spec()
    )
    assert [entry.path for entry in verification.content] == sorted(content)


def _root_divergent_maximum_depth_paths(count: int) -> list[str]:
    """The review's worst case: distinct first components, no shared prefix.

    Each path is 1,023 characters and 511 components — a three-character
    first component, then 510 one-character descendants — so ``count`` of
    them name ``count`` × 511 distinct prefixes and share none of them.
    """

    paths = ["/".join((f"{index:03x}", *(["x"] * 510))) for index in range(count)]
    assert len(paths[0]) == 1023
    assert len(paths[0].split("/")) == 511
    return paths


def test_a_root_divergent_maximum_depth_layout_is_counted_and_not_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Binds S7-R3-F1: the visit budget bounded walking, not holding.

    These 4,096 paths are portable, 1,023 characters each, and inside every
    bound the module states: ``MAX_JOURNAL_ROWS`` rows, ``MAX_PATH_TEXT``
    characters, and 2,093,056 prefix visits against a budget of 4,194,304.
    They share no prefix at all, so the component trie S7-F1 introduced held
    one node per visit: measured on this interpreter, 594.2 MB and 4.8
    seconds for a journal every guard waved through, and 74.3 MB for the
    review's own 512-path reproduction.

    The prefix pass now sorts the folded component sequences and compares
    neighbours, so what it holds is one key per declared path — a small
    multiple of the path text the journal already carries — and the peak
    asserted here is a fifty-fifth of what the trie allocated. The node
    count is still computed, because it is what
    ``MAX_ALIAS_INDEX_NODES`` bounds and what the generations recorder will
    be asked to stamp; it is simply not materialised.

    Without S7-R3-F1 this test fails on memory rather than on logic: the
    trie's peak is two orders of magnitude above the bound asserted here.
    """

    import tracemalloc

    from receipt.corpus import (
        MAX_ALIAS_INDEX_NODES,
        _PathPrefixWork,
        _reject_aliasing_paths,
    )

    paths = _root_divergent_maximum_depth_paths(MAX_JOURNAL_ROWS)
    work = _PathPrefixWork()
    tracemalloc.start()
    try:
        nodes = _reject_aliasing_paths(paths, work=work)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert nodes == MAX_JOURNAL_ROWS * 511 == 2093056
    # Visits and counted prefixes both charge, and this layout is the one
    # that makes them equal: 2,093,056 of each, inside the shared budget.
    assert work.work == 2 * nodes == 4186112
    assert work.work <= MAX_PATH_COMPONENTS_TOTAL
    # Under the ceiling, which this layout does not reach: diverging at the
    # root costs three characters to spell 4,096 first components, which caps
    # such a path at 511 rather than 512. The layout that does come closest
    # is the neighbouring test's arithmetic.
    assert nodes < MAX_ALIAS_INDEX_NODES == 2097152
    # Measured at 9.0 MB on CPython 3.14 and 3.11; the bound is stated with
    # room for an interpreter that lays strings out differently, and is a
    # quarter of the 64 MiB the review asked the worst case to stay under.
    assert peak < 16 * 1024 * 1024


def _fold_distinct_short_names() -> tuple[list[str], list[str]]:
    """Every fold-distinct portable name of one character, and of two.

    Built from ``PORTABLE_NAME_RE`` and ``_path_fold`` rather than counted by
    hand, because the count is the whole of S8-F4: the ceiling's margin was
    derived from the 64 one-character portable names and the index counts
    prefixes by fold key, where the 52 letters are 26.
    """

    from receipt.corpus import _assert_portable_name, _path_fold

    def portable(name: str) -> bool:
        try:
            _assert_portable_name(name, "declared path component")
        except CorpusError:
            return False
        return True

    characters = [chr(point) for point in range(128)]
    ones = [name for name in characters if portable(name)]
    twos = [
        first + second
        for first in characters
        for second in ones
        if portable(first + second)
    ]

    def distinct(names: list[str]) -> list[str]:
        seen: dict[str, str] = {}
        for name in names:
            seen.setdefault(_path_fold(name), name)
        return sorted(seen.values())

    return distinct(ones), distinct(twos)


def _widest_default_journal_paths() -> tuple[str, ...]:
    """The default-capacity path set naming the most distinct folded prefixes.

    Constructed rather than asserted (S8-F4). Each of the 1,520 fold-distinct
    one- and two-character names heads one root-divergent maximum-depth path,
    which is every root divergence the repertoire and ``MAX_PATH_TEXT``
    admit; the remaining rows share a one-character first component and
    diverge at their second, which costs each of them one prefix. A
    maximum-depth path carries at most one two-character component, so the
    shared paths take a one-character head and any other name below it.
    """

    from receipt.corpus import MAX_PATH_COMPONENTS, _path_fold

    ones, twos = _fold_distinct_short_names()
    heads = ones + twos
    filler = "a"
    deep_tail = "/".join(filler for _ in range(MAX_PATH_COMPONENTS - 1))
    paths = [f"{head}/{deep_tail}" for head in heads]
    shared_tail = "/".join(filler for _ in range(MAX_PATH_COMPONENTS - 2))
    for first in ones:
        for second in heads:
            if len(paths) == MAX_JOURNAL_ROWS:
                return tuple(paths)
            if _path_fold(second) == _path_fold(filler):
                # That is the root-divergent path under this head already.
                continue
            paths.append(f"{first}/{second}/{shared_tail}")
    return tuple(paths)


def test_the_alias_index_ceiling_is_above_the_widest_default_journal() -> None:
    """Binds S7-R3-F1 and S8-F4: the margin was derived twice over from 64.

    The ceiling exists to refuse a declared set whose distinct prefixes the
    generations recorder could not hold, so it has to sit above the most a
    default-capacity journal can name — and the review's 2,093,056 does not.
    That number is the worst case for what the old trie *allocated*: paths
    that diverge at the root need three characters to spell 4,096 first
    components, so they carry 511 components rather than 512.

    Cardinality peaks elsewhere, and this test used to say where by
    arithmetic alone: 64 one-character names, 4,096 second components,
    2,093,120 prefixes. Both halves were wrong. The index counts prefixes by
    *fold key*, and only 38 of the 64 one-character names are fold-distinct,
    so that layout aliases and is refused on the first pass — S8-F4. And the
    true maximum is higher, not lower: 1,520 fold-distinct one- and
    two-character names head one maximum-depth path each, the other 2,576
    rows share a first component, and 1,520 x 512 + 2,576 x 511 = 2,094,576,
    which is 1,456 above the number this test used to assert. A ceiling
    tightened to that number would have refused a legitimate journal by 1,456
    prefixes.

    So the layout is built and counted rather than stated. Without S8-F4 this
    file asserts 2,093,120 from a path set it never constructs, which is why
    it could not notice that the set is inadmissible.
    """

    from receipt.corpus import (
        MAX_ALIAS_INDEX_NODES,
        MAX_PATH_COMPONENTS,
        MAX_PATH_TEXT,
        _PathPrefixWork,
        _reject_aliasing_paths,
        _validate_relative_path,
    )

    ones, twos = _fold_distinct_short_names()
    assert (len(ones), len(twos)) == (38, 1482)

    paths = _widest_default_journal_paths()
    assert len(paths) == len(set(paths)) == MAX_JOURNAL_ROWS
    for path in paths:
        # Admissible, which is what the old arithmetic never checked.
        _validate_relative_path(path, "content path")
    assert max(len(path) for path in paths) <= MAX_PATH_TEXT
    assert max(path.count("/") + 1 for path in paths) == MAX_PATH_COMPONENTS

    assert len(ones) + len(twos) == 1520
    nodes = _reject_aliasing_paths(paths, work=_PathPrefixWork())
    assert nodes == 1520 * 512 + 2576 * 511 == 2094576
    assert MAX_ALIAS_INDEX_NODES - nodes == 2576


def test_the_layout_the_old_margin_named_is_refused_as_aliasing() -> None:
    """Binds S8-F4: the witness the margin was derived from cannot be built.

    "4,096 paths of 512 one-character components diverging at their second
    component" needs 64 fold-distinct one-character names. There are 38: the
    52 letters fold onto 26. So the second and the third path of that layout
    are ``-/A/a/...`` and ``-/a/a/...``, which fold to one key, and
    ``_reject_aliasing_paths`` refuses the whole set before it counts
    anything.

    Without S8-F4 nothing in this file builds that layout, so nothing notices.
    """

    from receipt.corpus import (
        MAX_PATH_COMPONENTS,
        PORTABLE_NAME_RE,
        _PathPrefixWork,
        _reject_aliasing_paths,
    )

    ones = [
        chr(point)
        for point in range(128)
        if PORTABLE_NAME_RE.fullmatch(chr(point)) is not None
        and not chr(point).endswith(".")
    ]
    assert len(ones) == 64
    tail = "/".join("a" for _ in range(MAX_PATH_COMPONENTS - 2))
    claimed = [
        f"{first}/{second}/{tail}" for first in ones for second in ones
    ][:MAX_JOURNAL_ROWS]
    assert len(claimed) == MAX_JOURNAL_ROWS

    with pytest.raises(CorpusError) as caught:
        _reject_aliasing_paths(tuple(claimed), work=_PathPrefixWork())
    assert "would alias on a case- or normalization-insensitive filesystem" in str(
        caught.value
    )


def test_the_alias_index_ceiling_cannot_be_reached() -> None:
    """Binds S8-F4: the ceiling's refusal is unreachable by construction.

    ``_reject_aliasing_paths`` charges one shared counter once per prefix it
    visits and once per distinct prefix it counts, and a counted prefix is
    always a visited one, so counting N prefixes has charged at least 2N.
    ``MAX_PATH_COMPONENTS_TOTAL`` is exactly twice ``MAX_ALIAS_INDEX_NODES``,
    which puts the visit refusal strictly before the node refusal for every
    input: the set that would name 2,097,153 prefixes has already charged
    4,194,306 against a budget of 4,194,304.

    The comment said instead that "a spec that pins a larger
    ``journal_row_capacity`` can exceed it and is refused here", and the PR
    body listed the refusal among the verdicts that change. Neither is true —
    a larger capacity adds paths, and every path adds at least as many visits
    as counted prefixes, so the inequality is unaffected by the pin.

    This is the ratio the constant's comment says a test pins, so that moving
    one of the four fails here rather than quietly reviving or burying the
    cap. The refusal itself is bound by the neighbouring test, which patches
    the ceiling down to reach it.
    """

    from receipt.corpus import (
        MAX_ALIAS_INDEX_NODES,
        MAX_PATH_COMPONENTS,
        MAX_PATH_COMPONENTS_TOTAL,
        MAX_PATH_TEXT,
        _PathPrefixWork,
        _reject_aliasing_paths,
    )

    assert MAX_PATH_COMPONENTS_TOTAL == 2 * MAX_ALIAS_INDEX_NODES
    assert MAX_PATH_COMPONENTS == (MAX_PATH_TEXT + 1) // 2

    # And the inequality the proof rests on, measured on the layout that
    # maximises cardinality: every counted prefix was visited first.
    work = _PathPrefixWork()
    nodes = _reject_aliasing_paths(_widest_default_journal_paths(), work=work)
    assert work.work >= 2 * nodes
    assert work.work <= MAX_PATH_COMPONENTS_TOTAL


def test_the_maximum_depth_journal_spends_what_the_comment_says() -> None:
    """The maximum-depth journal remains inside the alias-prefix budget.

    The pass charges one unit per component visit and one per distinct folded
    directory prefix. Filesystem ancestor recording is no longer part of the
    immutable-tree verifier.
    """

    from receipt.corpus import (
        MAX_PATH_COMPONENTS,
        MAX_PATH_COMPONENTS_TOTAL,
        _PathPrefixWork,
        _reject_aliasing_paths,
    )

    paths = _widest_default_journal_paths()
    assert all(path.count("/") + 1 == MAX_PATH_COMPONENTS for path in paths)

    visits = MAX_JOURNAL_ROWS * MAX_PATH_COMPONENTS
    assert visits == 2097152

    work = _PathPrefixWork()
    nodes = _reject_aliasing_paths(paths, work=work)
    assert work.work == visits + nodes == 4191728
    assert work.work <= MAX_PATH_COMPONENTS_TOTAL == 4194304

def test_the_alias_index_refuses_more_prefixes_than_its_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Binds S7-R3-F1: nothing bounded the size of the declared-prefix set.

    The count is what the rest of the run allocates for — every distinct
    declared prefix that exists on disk becomes one stamp
    ``_DirectoryGenerations`` holds until the verdict — so it is refused
    before it is stat-ed rather than after. The ceiling itself is derived
    from the default capacity and cannot be reached by a default-capacity
    journal, so what is bound here is the refusal: the same maximum-depth
    layout passes with the ceiling at its own node count and refuses one
    node below it.

    Without S7-R3-F1 there is no ceiling to move and no refusal at all: the
    layout is accepted at any cardinality the visit budget allows.
    """

    from receipt.corpus import _PathPrefixWork, _reject_aliasing_paths

    paths = _root_divergent_maximum_depth_paths(MAX_JOURNAL_ROWS)

    monkeypatch.setattr("receipt.corpus.MAX_ALIAS_INDEX_NODES", 2093056)
    assert _reject_aliasing_paths(paths, work=_PathPrefixWork()) == 2093056

    monkeypatch.setattr("receipt.corpus.MAX_ALIAS_INDEX_NODES", 2093055)
    with pytest.raises(CorpusError) as caught:
        _reject_aliasing_paths(paths, work=_PathPrefixWork())
    assert str(caught.value) == (
        "declared paths name more than 2093055 distinct directories; "
        "declared paths exceed the alias index budget"
    )


def test_maximum_rows_at_maximum_portable_depth_share_their_counted_prefixes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Binds S7-F1 and S7-R3-F1: prefix text was materialised per visit.

    These 4,096 paths are each 1,023 characters and 511 components, the
    review's maximum-depth fixture. They make 2,093,056 prefix visits, but
    share their first 510 components, so exactly 4,606 distinct folded
    prefixes are counted. That shared layout is the *best* case for
    cardinality, which is what makes it the one that isolates the per-visit
    text cost; the root-divergent worst case is the neighbouring memory
    regression's. The old slice/join/fold loop instead materialised
    and re-folded one cumulative string per visit, and had no allocation
    count or budget for the test to assert; paths with distinct prefixes
    retained that same 2.1-million cardinality in its dictionary.

    What the folded-character recorder measures is the finding's own number.
    Every prefix reaches ``_path_fold`` exactly once per visit either way, so
    the total characters folded is the total prefix text the check
    materialises. The prefix pass folds one component per visit —
    2,101,248 characters over these paths, plus the 4,190,208 the whole-path
    pass folds and always did; it did so into a trie under S7-F1 and does so
    building each path's sorted key under S7-R3-F1, which is the same fold
    count either way. The cumulative loop folded a joined prefix per visit
    instead: 1,069,559,808 characters for the prefix pass alone, so
    1,073,750,016 in total — a gibibyte of prefix strings for one within-cap
    journal, which is what the finding measured as about two gibibytes held
    live once each is also kept in the index.

    Without S7-F1 the call does not accept a budget, the returned allocation
    count is absent rather than 4,606, and the folded-character total is
    1,073,750,016 rather than 6,291,456 — 170 times the bound asserted here.
    """

    import receipt.corpus as corpus_module

    from receipt.corpus import _PathPrefixWork, _reject_aliasing_paths

    shared = ["a"] * 510
    paths = [
        "/".join((*shared, f"{index:03x}"))
        for index in range(MAX_JOURNAL_ROWS)
    ]
    assert len(paths) == 4096
    assert len(paths[0]) == 1023
    assert len(paths[0].split("/")) == 511

    real_fold = corpus_module._path_fold
    folded = [0]

    def recording_fold(value: str) -> str:
        folded[0] += len(value)
        return real_fold(value)

    monkeypatch.setattr(corpus_module, "_path_fold", recording_fold)
    work = _PathPrefixWork()
    entries = _reject_aliasing_paths(paths, work=work)

    assert (
        MAX_PATH_COMPONENTS_TOTAL
        == MAX_JOURNAL_ROWS * MAX_PATH_TEXT
        == 4194304
    )
    # 2,093,056 visits and, since S7-R3-F1 charges what is counted as well
    # as what is walked, 4,606 more for the prefixes they name.
    assert work.work == MAX_JOURNAL_ROWS * 511 + 4606 == 2097662
    assert entries == 510 + MAX_JOURNAL_ROWS == 4606
    # The whole-path pass folds each path once and is unchanged; the prefix
    # pass folds one component per visit rather than one joined prefix.
    whole_paths = MAX_JOURNAL_ROWS * 1023
    components = MAX_JOURNAL_ROWS * (510 * 1 + 3)
    assert folded[0] == whole_paths + components == 6291456
    # A joined prefix per visit costs 1 + 3 + … + 1019 for the shared
    # components and 1,023 for the leaf, per path.
    joined = MAX_JOURNAL_ROWS * (510**2 + 1023)
    assert whole_paths + joined == 1073750016
    assert folded[0] < 8 * 1024 * 1024 < joined


def test_the_fixture_spends_nineteen_units_from_the_alias_prefix_budget(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fixture charges eleven visits and eight distinct folded prefixes."""

    write_tree(tmp_path)
    monkeypatch.setattr("receipt.corpus.MAX_PATH_COMPONENTS_TOTAL", 19)
    verify_corpus_binding(
        tmp_path, render_journal(journal_rows()), spec=corpus_spec()
    )

    monkeypatch.setattr("receipt.corpus.MAX_PATH_COMPONENTS_TOTAL", 18)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "declared paths visit more than 18 prefixes; the corpus cannot be "
        "bound safely"
    )

def test_refuses_paths_that_alias_under_unicode_normalization_alone(
    tmp_path: pathlib.Path,
) -> None:
    """Binds the policy: the normalization class is removed, not paired.

    NFC and NFD spellings of the same name are one file on a normalizing
    filesystem and two on others, and the fold key used to pair them so a
    journal listing both was refused as ambiguous. The policy answers it one
    step earlier and without a model: neither spelling is a portable name, so
    a corpus cannot carry either and there is no pair to decide about.

    Without the screen these two rows are ordinary content paths whose
    ambiguity depends on which filesystem the auditor cloned onto. The
    aliasing check the fold key still performs is asserted, over the case
    variation that remains inside the repertoire, by
    ``test_refuses_paths_that_alias_under_case_or_normalization``.
    """

    import unicodedata

    write_tree(tmp_path)
    rows = journal_rows()
    composed = "rules/tax/café.yaml"
    decomposed = unicodedata.normalize("NFD", composed)
    assert composed != decomposed
    for path in (composed, decomposed):
        rows.append(
            {
                "schemaVersion": JOURNAL_SCHEMA,
                "kind": "content",
                "path": path,
                "sha256": sha256_text("name: café\n"),
                "state": "present",
            }
        )
    reindex(rows)
    with pytest.raises(CorpusError, match="is not a portable name"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


# --- later review round: what the sweep and the sanitiser still let past ----


def test_refuses_an_unlisted_content_file_whose_suffix_differs_only_by_case(
    tmp_path: pathlib.Path,
) -> None:
    """Regression for a demonstrated false PASS.

    The sweep matched pinned suffixes byte-for-byte, so ``smuggled.YAML`` was
    not content and never entered the closed-world set. On the
    case-insensitive filesystems this module already defends against it is
    the same file as ``smuggled.yaml`` — an unwitnessed rule that every
    consumer reads, under a verdict claiming the world was closed over three
    files while four were present.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/tax/smuggled.YAML").write_text("name: smuggled\n")
    with pytest.raises(CorpusError, match="not bound by the witnessed journal"):
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )


def test_the_suffix_predicate_does_not_normalize_unicode() -> None:
    """Only ASCII case is folded; composed and decomposed text stays exact."""

    import unicodedata

    from receipt.corpus import _has_pinned_suffix

    decomposed = unicodedata.normalize("NFD", "rules/tax/smuggled.café")
    assert decomposed != "rules/tax/smuggled.café"
    assert not _has_pinned_suffix(decomposed, (".yaml", ".café"))
    assert _has_pinned_suffix("rules/tax/smuggled.café", (".yaml", ".café"))
    assert not _has_pinned_suffix(decomposed, (".yaml",))


def test_refuses_a_bidi_override_in_gate_evidence(tmp_path: pathlib.Path) -> None:
    """Control characters are not the only way to redraw a verdict line.

    U+202E RIGHT-TO-LEFT OVERRIDE is invisible and reverses everything after
    it, so a producer can spell a not-run reason that renders as the opposite
    of what the journal says. The sanitiser has to cover the whole format
    class, not the C0 block it started with.
    """

    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "not-run",
                "evidence": {"reason": "gate disabled \u202edeifirev setag lla"},
            }
        ]
    )
    with pytest.raises(CorpusError, match="Unicode format control"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_line_separator_in_gate_evidence(tmp_path: pathlib.Path) -> None:
    """U+2028 breaks a line in any renderer that honours it, and it is outside
    the C0 block the control-character screen covers. One evidence string
    becomes as many verdict lines as the producer wants."""

    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "not-run",
                "evidence": {"reason": "skipped\u2028  VERDICT: PASS"},
            }
        ]
    )
    with pytest.raises(CorpusError, match="Unicode line separator"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_gate_evidence_longer_than_the_bound(tmp_path: pathlib.Path) -> None:
    """Sanitising bounds what a character does, not how many there are. Two
    hundred thousand blameless characters scroll every line the auditor
    needed to read out of the terminal."""

    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "not-run",
                "evidence": {"reason": "x" * 200_000},
            }
        ]
    )
    with pytest.raises(CorpusError, match="longer than 1024 characters"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_accepts_gate_evidence_exactly_at_the_bound(tmp_path: pathlib.Path) -> None:
    """The bound is a limit, not an off-by-one: MAX_EVIDENCE_TEXT characters
    is still a reason a producer may state."""

    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "not-run",
                "evidence": {"reason": "x" * MAX_EVIDENCE_TEXT},
            }
        ]
    )
    verification = verify_corpus_binding(
        tmp_path, render_journal(rows), spec=corpus_spec()
    )
    assert len(verification.gates[0].evidence["reason"]) == MAX_EVIDENCE_TEXT


def test_refuses_a_removed_attested_path_that_is_still_in_the_tree(
    tmp_path: pathlib.Path,
) -> None:
    """A tombstone the tree does not honour.

    Attested paths sit outside the content roots, so the closed-world sweep
    never looks at them: a retired apply manifest could stay on disk, bound by
    no row, while the verdict listed it under removedPaths and an auditor's
    tools read it as current. Removal has to be true of the tree, not only of
    the journal.
    """

    attested = dict(ATTESTED)
    attested[".axiom/apply-manifest.json"] = '{"applied": true}\n'
    write_tree(tmp_path, attested=attested)
    rows = journal_rows(attested=attested)
    rows.append(
        {
            "schemaVersion": JOURNAL_SCHEMA,
            "kind": "attested",
            "path": ".axiom/apply-manifest.json",
            "sha256": sha256_text(attested[".axiom/apply-manifest.json"]),
            "state": "removed",
        }
    )
    reindex(rows)
    with pytest.raises(CorpusError, match="removed path is still present in the tree"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_a_removed_attested_path_absent_from_the_tree_verifies(
    tmp_path: pathlib.Path,
) -> None:
    """The same journal against the tree it actually describes: the file is
    gone, the binding passes, and the verdict names the path as removed."""

    attested = dict(ATTESTED)
    attested[".axiom/apply-manifest.json"] = '{"applied": true}\n'
    write_tree(tmp_path, attested=attested)
    rows = journal_rows(attested=attested)
    rows.append(
        {
            "schemaVersion": JOURNAL_SCHEMA,
            "kind": "attested",
            "path": ".axiom/apply-manifest.json",
            "sha256": sha256_text(attested[".axiom/apply-manifest.json"]),
            "state": "removed",
        }
    )
    reindex(rows)
    (tmp_path / ".axiom/apply-manifest.json").unlink()
    verification = verify_corpus_binding(
        tmp_path, render_journal(rows), spec=corpus_spec()
    )
    assert verification.removed_paths == (".axiom/apply-manifest.json",)
    assert ".axiom/apply-manifest.json" not in {e.path for e in verification.attested}


def test_refuses_a_case_varied_content_path_bound_as_attested(
    tmp_path: pathlib.Path,
) -> None:
    """The same escape approached from the other side of the fold.

    While the suffix match was byte-exact, ``rules/tax/smuggled.YAML`` was not
    a content path, so a producer could bind it as attested — exempt from the
    closed-world sweep by construction — and every consumer on a
    case-insensitive filesystem would read it as ``rules/tax/smuggled.yaml``.
    Kind is a function of the path, and after folding this path is content.
    """

    body = "name: smuggled\n"
    write_tree(tmp_path)
    (tmp_path / "rules/tax/smuggled.YAML").write_text(body)
    rows = journal_rows()
    rows.append(
        {
            "schemaVersion": JOURNAL_SCHEMA,
            "kind": "attested",
            "path": "rules/tax/smuggled.YAML",
            "sha256": sha256_text(body),
            "state": "present",
        }
    )
    reindex(rows)
    with pytest.raises(CorpusError, match="must be swept closed-world"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_zero_width_joiner_in_a_journal_path(tmp_path: pathlib.Path) -> None:
    """Binds the policy: a path used to be screened as producer text.

    A zero-width joiner makes two rows binding two different files print as
    one name in the verdict an auditor reads, and HFS+ ignores it entirely
    when it compares names, so the two rows are one file there. Both were
    answered by screens on paths — the format-control class and the
    default-ignorable table — and both are answered now by the repertoire,
    which holds neither. ``_reject_control_characters`` still runs over gate
    evidence, where the text is not a name and cannot be constrained this
    way.

    Without the screen this row is an ordinary content path.
    """

    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["path"] = "rules/benefit/amo\u200dunt.yaml"
    with pytest.raises(CorpusError, match="is not a portable name"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_a_removed_content_path_still_in_the_tree_is_refused_as_unlisted(
    tmp_path: pathlib.Path,
) -> None:
    """The content half of the tombstone rule, and which check catches it.

    A content file that outlived its removal row is caught by the closed-world
    sweep before the tombstone check runs at all: the journal no longer binds
    it, so it is an unlisted file in a content root. The refusal an auditor
    sees is the sweep's, unchanged.
    """

    write_tree(tmp_path)
    rows = journal_rows()
    rows.append(
        {
            "schemaVersion": JOURNAL_SCHEMA,
            "kind": "content",
            "path": "rules/tax/rate.yaml",
            "sha256": sha256_text(CONTENT["rules/tax/rate.yaml"]),
            "state": "removed",
        }
    )
    reindex(rows)
    with pytest.raises(CorpusError, match="not bound by the witnessed journal"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_lone_surrogate_in_gate_evidence(tmp_path: pathlib.Path) -> None:
    """JSON can spell a lone surrogate inside otherwise valid UTF-8.

    ``\\ud800`` decodes to a code point in category Cs that neither the C0 nor
    the Cf screen covers, and nothing downstream can render or stat it. It is
    refused at the schema boundary like the other invisible classes.
    """

    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "not-run",
                "evidence": {"reason": "gate disabled \ud800"},
            }
        ]
    )
    with pytest.raises(CorpusError, match="lone surrogate"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_lone_surrogate_in_a_journal_path(tmp_path: pathlib.Path) -> None:
    """A path carrying a lone surrogate cannot be looked for at all.

    ``os.lstat`` raises ``UnicodeEncodeError`` on it, a ``ValueError`` that no
    ``OSError`` handler in this module sees, so without the screen the row
    escaped as an unclassified exception instead of a refusal that names it.

    Binds the policy for the message: a lone surrogate is outside the
    portable repertoire, so the refusal is the portable-name one and the
    surrogate class no longer needs a rule of its own on a path. It keeps
    one on gate evidence, which is not a name.
    """

    write_tree(tmp_path)
    rows = journal_rows()
    # A further attested row, deliberately: a content path spelled this way
    # is caught earlier, by the sweep, as unlisted, and mutating the one
    # required attested row is caught earlier still, as missing. A new
    # attested row is what reached os.lstat (peer review, round two).
    rows.append(
        {
            "schemaVersion": JOURNAL_SCHEMA,
            "kind": "attested",
            "path": ".axiom/tool\ud800chain.toml",
            "sha256": sha256_text("never on disk"),
            "state": "present",
        }
    )
    reindex(rows)
    with pytest.raises(CorpusError, match="is not a portable name"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_removed_path_that_survives_under_an_aliasing_spelling(
    tmp_path: pathlib.Path,
) -> None:
    """A tombstone is honoured under the module's own portability model.

    Two paths whose fold keys agree are one file on some real filesystem. A
    tombstone checked by exact-spelling lstat ignored that: on a
    case-sensitive host ``retired/apply-manifest.json`` could be reported
    removed while ``retired/APPLY-MANIFEST.JSON`` remained, and that survivor
    answers to the tombstoned name on a case-insensitive consumer. Found by
    peer review. On a case-insensitive host the rename below is the same file
    under a new spelling, and it refuses there too.

    Which of the two refusals speaks depends on the host, and the assertion
    below follows the host rather than assuming one: where the tombstoned
    spelling still resolves natively, the exact-path probe added for F1
    answers first and names that spelling; where it does not, the fold search
    names the survivor it found.
    """

    body = '{"applied": true}\n'
    attested = dict(ATTESTED)
    attested["retired/apply-manifest.json"] = body
    write_tree(tmp_path, attested=attested)
    rows = journal_rows(attested=attested)
    rows.append(
        {
            "schemaVersion": JOURNAL_SCHEMA,
            "kind": "attested",
            "path": "retired/apply-manifest.json",
            "sha256": sha256_text(body),
            "state": "removed",
        }
    )
    reindex(rows)
    pathlib.Path.rename(
        tmp_path / "retired/apply-manifest.json",
        tmp_path / "retired/APPLY-MANIFEST.JSON",
    )
    with pytest.raises(CorpusError, match="still present in the tree") as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert str(caught.value) == (
        "removed path is still present in the tree under a spelling that aliases "
        "it on a case- or normalization-insensitive filesystem: "
        "retired/apply-manifest.json ('retired/APPLY-MANIFEST.JSON')"
    )


def test_unicode_case_and_normalization_are_not_folded(
    tmp_path: pathlib.Path,
) -> None:
    """The fold preserves non-ASCII bytes and portable paths refuse them."""

    from receipt.corpus import _has_pinned_suffix, _path_fold

    assert _path_fold("x\u00df\u0301") != _path_fold("xs\u015b")
    assert not _has_pinned_suffix(
        "rules/tax/smuggled.\u00df\u0301", (".s\u015b",)
    )

    write_tree(tmp_path)
    rows = journal_rows()
    for path in ("rules/tax/x\u00df\u0301.yaml", "rules/tax/xs\u015b.yaml"):
        rows.append(
            {
                "schemaVersion": JOURNAL_SCHEMA,
                "kind": "content",
                "path": path,
                "sha256": sha256_text("name: smuggled\n"),
                "state": "present",
            }
        )
    reindex(rows)
    with pytest.raises(CorpusError, match="is not a portable name"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_format_control_whatever_unicode_table_the_interpreter_carries(
    tmp_path: pathlib.Path,
) -> None:
    """The Cf set is pinned, so the verdict does not depend on the runtime.

    U+1343A is Cf under Unicode 15 and later and unassigned under Unicode 14,
    which Python 3.11 ships, so the same journal was refused on 3.12 and
    accepted on 3.11 (peer review). The module pins Unicode 16.0's Cf set and
    refuses anything in it or anything the running table calls Cf.

    The table moved to ``receipt._unicode_repertoire`` in S5-F2, so that
    ``receipt.cli`` can escape the same set on its way to a terminal; its
    contents are unchanged and this test is unchanged but for the import.
    """

    import unicodedata

    from receipt._unicode_repertoire import FORMAT_CONTROL_RANGES

    pinned = {
        code for low, high in FORMAT_CONTROL_RANGES for code in range(low, high + 1)
    }
    assert 0x1343A in pinned
    running = {
        code for code in range(0x110000) if unicodedata.category(chr(code)) == "Cf"
    }
    assert running <= pinned, sorted(running - pinned)[:5]

    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "not-run",
                "evidence": {"reason": "gate disabled \U0001343a"},
            }
        ]
    )
    with pytest.raises(CorpusError, match="Unicode format control"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_gate_declarations_over_the_verdict_budget(
    tmp_path: pathlib.Path,
) -> None:
    """The per-string bound caps one flood; cardinality was uncapped.

    Three hundred not-run gates each carrying a bound-length reason are each
    within the per-string bound and together put three hundred thousand
    characters into the verdict. The effective view's gate text is bounded
    as a whole (peer review).
    """

    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": f"flood/gate-{index}",
                "tier": "public",
                "outcome": "not-run",
                "evidence": {"reason": "x" * 1024},
            }
            for index in range(300)
        ]
    )
    # Matched loosely on purpose: what this test is about is that three
    # hundred bounded strings together exceed the text budget, not which
    # declaration the running total first crosses at (S4-F6 made the refusal
    # name that, and it is pinned by the tests that are about it).
    with pytest.raises(CorpusError, match="the verdict budget of"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_more_gate_declarations_than_the_verdict_budget(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F3 (round five): characters were bounded, gates never were.

    ``MAX_GATE_TEXT`` charged gate-id and evidence payload characters and
    nothing else, so a producer that kept every string short could declare as
    many gates as it liked. Thirty thousand short ids with two characters of
    evidence each charge about two hundred and thirty thousand and passed,
    while the verdict they render is four hundred thousand characters of text
    and four million of JSON — the flood the budget exists to stop, built out
    of strings none of which is long.

    Two things about this test moved with S5R2-F4, and the second is worth
    stating because it is a fact about the shipped constants rather than
    about this journal. The count is the declaration cap plus two rather
    than thirty thousand, because a thirty-thousand-row journal is now
    refused a level earlier by ``MAX_JOURNAL_ROWS``, before anything is
    parsed. And the refusal that speaks is the *text* budget rather than the
    declaration cap, because both are now enforced in row order and the text
    budget is reached first: since round seven made ``GATE_RENDER_STRUCTURE``
    exact, the cheapest gate a journal can declare costs 130 characters of
    rendered verdict, so 2,048 of them cost more than ``MAX_GATE_TEXT`` and
    the declaration cap cannot be reached by any journal. It is kept as a
    backstop against a change to either constant, and its comment says so.

    What this test binds is unchanged: a journal of short gates whose count
    is the flood is refused, and the refusal names where it stopped.
    """

    write_tree(tmp_path)
    gates = [
        {
            "gateId": f"g{index}",
            "tier": "public",
            "outcome": "pass",
            "evidence": {"c": "1"},
        }
        for index in range(MAX_GATE_DECLARATIONS + 2)
    ]
    # What the old charge came to, which is why this journal used to pass.
    assert sum(len(gate["gateId"]) + 2 for gate in gates) < MAX_GATE_TEXT
    # The cheapest gate expressible in this schema, and why the declaration
    # cap is unreachable: a gate id of one character, the shortest outcome,
    # and one evidence entry with an empty key and an empty value.
    cheapest = GATE_RENDER_STRUCTURE + 3 + 6 + EVIDENCE_RENDER_STRUCTURE + 2 + 2
    assert cheapest == 130
    assert MAX_GATE_DECLARATIONS * cheapest > MAX_GATE_TEXT
    # These gate ids differ in length, so the running total is accumulated
    # here rather than multiplied out: the refusal names the first
    # declaration that carries it over.
    charged = 0
    for number, gate in enumerate(gates, start=1):
        charged += charged_gate(gate)
        if charged > MAX_GATE_TEXT:
            break
    assert number < MAX_GATE_DECLARATIONS
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(gates=gates)), spec=corpus_spec()
        )
    assert str(caught.value) == (
        f"journal gate declarations cost more than the verdict budget of "
        f"{MAX_GATE_TEXT} characters: {charged} charged at declaration "
        f"{number} (journal row {len(CONTENT) + len(ATTESTED) + number})"
    )


def test_refuses_gates_whose_rendering_cost_alone_floods_the_verdict(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F3 (round five): a gate was free apart from what it declared.

    The other half of the same hole, and the half a declaration count cannot
    close: two thousand gates is inside the declaration budget, and two
    thousand forty-eight-character ids with two characters of evidence
    charged a hundred thousand — comfortably inside the text budget — while
    the JSON they render is over a third of a million characters, some
    seventy per cent of it the fixed cost the old charge counted as nothing.

    Each gate is now charged the fixed cost of the lines it produces, and
    each evidence entry the cost of the member JSON puts around it, so this
    journal is refused on the text budget. Without the fix it verifies.
    """

    write_tree(tmp_path)
    gates = [
        {
            "gateId": f"overhead/{index:04d}".ljust(48, "x"),
            "tier": "public",
            "outcome": "pass",
            "evidence": {"c": "1"},
        }
        for index in range(2000)
    ]
    assert len(gates) <= MAX_GATE_DECLARATIONS
    # What the old charge came to, which is why this journal used to pass.
    assert sum(len(gate["gateId"]) + 2 for gate in gates) < MAX_GATE_TEXT
    # Every producer string is charged as the verdict renders it (R6-F3) and
    # every character of JSON structure around it exactly (S4-F6), so the
    # arithmetic here goes through json.dumps and the shipped constants.
    # The charge stops at the first declaration that carries the total over,
    # which is what the refusal names.
    number, charged = first_over(charged_gate(gates[0]), MAX_GATE_TEXT)
    assert number < len(gates)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(gates=gates)), spec=corpus_spec()
        )
    assert str(caught.value) == (
        f"journal gate declarations cost more than the verdict budget of "
        f"{MAX_GATE_TEXT} characters: {charged} charged at declaration "
        f"{number} (journal row {len(CONTENT) + len(ATTESTED) + number})"
    )


def test_refuses_a_gate_evidence_key_longer_than_the_bound(
    tmp_path: pathlib.Path,
) -> None:
    """The key is bounded like the value, and the reviewer asked for the test."""

    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "pass",
                "evidence": {"k" * 1025: "make validate"},
            }
        ]
    )
    with pytest.raises(CorpusError, match="is longer than 1024 characters"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_verifies_a_content_row_spelled_with_a_case_varied_suffix(
    tmp_path: pathlib.Path,
) -> None:
    """The acceptance half of the suffix fold, which the body discloses.

    ``main`` refused a content row spelled ``.YAML`` at parse as not under a
    pinned suffix; after the fold it classifies as content, is swept, and
    verifies when the file is present and matching (peer review asked for
    the positive case).
    """

    content = dict(CONTENT)
    content["rules/tax/extra.YAML"] = "name: extra\nvalue: 1\n"
    write_tree(tmp_path, content=content)
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows(content=content)), spec=corpus_spec()
    )
    assert "rules/tax/extra.YAML" in {binding.path for binding in verification.content}


def test_refuses_a_path_carrying_an_unassigned_code_point(
    tmp_path: pathlib.Path,
) -> None:
    """Binds the policy: the unassigned class is refused by repertoire now.

    The fold key is stable across Unicode tables only for characters the
    standard has already encoded, so a path carrying an unassigned code
    point could alias under one interpreter's table and not another's (peer
    review, round two). Two rounds went into deciding *whose* table said
    which, ending with 698 ranges of Unicode 14.0 pinned in the package. The
    policy answers it with no table at all: U+0378 is not an ASCII letter,
    digit, ``.``, ``_`` or ``-``, and neither is anything the standard has
    yet to encode.

    Without the screen this row is an ordinary content path whose fold key
    depends on the auditor's interpreter.
    """

    import unicodedata

    assert unicodedata.category("\u0378") == "Cn"
    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["path"] = "rules/benefit/amo\u0378unt.yaml"
    with pytest.raises(CorpusError, match="is not a portable name"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_journal_path_longer_than_the_bound(
    tmp_path: pathlib.Path,
) -> None:
    """Paths are quoted in refusals and rendered as removedPaths; bounded first."""

    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["path"] = "rules/" + "a" * 1100 + ".yaml"
    with pytest.raises(CorpusError, match="is longer than 1024 characters"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_a_gate_bounded_by_the_renderer_is_charged_what_the_renderer_prints(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R3-F10: the charge and the rendering were two different sums.

    ``receipt.cli`` puts every string in the verdict through
    ``receipt._render`` before printing it, and ``receipt.corpus`` charged
    the string the producer wrote. The two therefore disagreed in both
    directions. Twenty-two evidence values of 1,024 U+1F600 each are the
    accepting side of it: they render as 12,288 characters apiece
    unbounded, so the old charge came to 270,000 and refused the gate —
    over a budget that bounds the verdict, for text the verdict would never
    have carried, because the renderer truncates each of them to 4,121.

    The charge is made on the bounded string now, so this gate is accepted,
    and the rendering is measured against it rather than assumed: the
    verdict is built exactly as ``main`` builds it — ``result_to_dict``,
    ``_bounded_payload``, ``json.dumps(..., indent=2, sort_keys=True)`` —
    and the gate section's length is asserted equal to what was charged.

    Without the fix this verification refuses.
    """

    write_tree(tmp_path)
    evidence = {f"{index:04d}": "\U0001F600" * 1024 for index in range(22)}
    gates = [
        {"gateId": "g", "tier": "public", "outcome": "pass", "evidence": evidence}
    ]
    # What the unbounded charge came to, which is why this gate was refused.
    unbounded = (
        GATE_RENDER_STRUCTURE
        + len(json.dumps("g"))
        + len(json.dumps("pass"))
        + sum(
            EVIDENCE_RENDER_STRUCTURE + len(json.dumps(key)) + len(json.dumps(value))
            for key, value in evidence.items()
        )
    )
    assert unbounded > MAX_GATE_TEXT
    charged = charged_gate(gates[0])
    assert charged <= MAX_GATE_TEXT

    rows = journal_rows(gates=gates)
    verification = verify_corpus_binding(
        tmp_path, render_journal(rows), spec=corpus_spec()
    )
    assert [gate.gate_id for gate in verification.gates] == ["g"]
    rendered, _text = _verdict_of(tmp_path, rows)
    assert len(_json_list_body(rendered, "public", 6)) == charged


def test_refuses_removed_paths_over_the_verdict_budget(
    tmp_path: pathlib.Path,
) -> None:
    """removedPaths is the other producer list the verdict renders verbatim."""

    content = dict(CONTENT)
    names = [f"rules/tax/{'r' * 900}{index:04d}.yaml" for index in range(300)]
    for name in names:
        content[name] = "name: r\n"
    rows = journal_rows(content=content)
    for name in names:
        rows.append(
            {
                "schemaVersion": JOURNAL_SCHEMA,
                "kind": "content",
                "path": name,
                "sha256": sha256_text("name: r\n"),
                "state": "removed",
            }
        )
    reindex(rows)
    write_tree(tmp_path)
    with pytest.raises(CorpusError, match="removed paths total"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_a_malformed_gate_id_is_quoted_within_bounds(tmp_path: pathlib.Path) -> None:
    """A refusal never echoes a flood, even for a field it must name."""

    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "X" * 100000,
                "tier": "public",
                "outcome": "pass",
                "evidence": {"command": "make validate"},
            }
        ]
    )
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert "gateId is malformed" in str(caught.value)
    assert len(str(caught.value)) < 600
    assert "more characters]" in str(caught.value)


def _tombstone_rows(path: str, body: str) -> list[dict[str, object]]:
    """A journal that binds ``path`` as attested and then retires it."""

    attested = dict(ATTESTED)
    attested[path] = body
    rows = journal_rows(attested=attested)
    rows.append(
        {
            "schemaVersion": JOURNAL_SCHEMA,
            "kind": "attested",
            "path": path,
            "sha256": sha256_text(body),
            "state": "removed",
        }
    )
    return reindex(rows)


def test_refuses_a_declared_path_with_a_trailing_dot_component(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F1 and the policy: Win32 strips trailing dots before a lookup.

    ``rules/tax/rate.yaml.`` and ``rules/tax/rate.yaml`` are one file there,
    and no listing emits the dotted spelling, so nothing in the fold model
    can pair them. This is the one Win32 alias rule the portable repertoire
    does *not* subsume — a trailing period is spelled out of characters the
    repertoire admits — so the screen asks it as its own question, and the
    refusal is the portable-name one.

    Without it the path is ordinary and binds a second row against the same
    file.
    """

    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["path"] = "rules/benefit/amount.yaml."
    with pytest.raises(CorpusError, match="is not a portable name"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_declared_path_with_a_trailing_space_component(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F1 and the policy: the same lookup strips trailing spaces.

    A directory component is enough — the alias need not be the file itself.
    Unlike the trailing period, a space needs no rule of its own: it is
    outside the portable repertoire wherever it sits, so a name carrying one
    anywhere is refused and the trailing case is a special case of nothing.

    Without the screen the path validates and the trailing space is
    invisible in every rendered verdict.
    """

    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["path"] = "rules/benefit /amount.yaml"
    with pytest.raises(CorpusError, match="is not a portable name"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_declared_path_shaped_like_an_8_3_short_name(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F1, F12 and the policy: the tilde grammar is gone with the tilde.

    ``RULESF~1.YAM`` is not emitted by any listing, so the fold model cannot
    pair it with the long name it opens, and a declared path spelled that way
    aliased a file this module could not enumerate. Deciding *which* names
    were spelled that way took a grammar — a repertoire, a stem length, a
    numeric tail, a rule about which tilde the tail is taken from — and two
    review rounds, one to widen it and one to narrow it, each of which had
    been wrong about ordinary names a corpus may hold.

    ``~`` is outside the portable repertoire, so there is no grammar left to
    get wrong: every one of these is refused with the same message, whether
    or not 8.3 generation could have produced it. That is also what closes
    S5R3-F12, whose two spellings are among them.

    Without the screen every one of these is an ordinary declared path.
    """

    write_tree(tmp_path)
    for spelling in (
        "rules/RULESF~1.YAM",
        "rules/benefit/long~1name.yaml",
        "rules/A~0.TXT",
        "rules/A~1.TXT",
        "rules/benefit/notes.yaml~",
    ):
        rows = journal_rows()
        rows[0]["path"] = spelling
        with pytest.raises(CorpusError, match="is not a portable name"):
            verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_a_directory_that_became_a_file_verifies_and_keeps_verifying(
    tmp_path: pathlib.Path,
) -> None:
    """A tombstoned descendant stays absent when its old parent is a blob."""

    write_tree(tmp_path)
    legacy = "rules/README.md/legacy.yaml"
    body = "name: legacy\n"
    rows = journal_rows()
    for state in ("present", "removed"):
        rows.append(
            {
                "schemaVersion": JOURNAL_SCHEMA,
                "kind": "content",
                "path": legacy,
                "sha256": sha256_text(body),
                "state": state,
            }
        )
    reindex(rows)
    readme = tmp_path / "rules" / "README.md"
    readme.write_text("# rules\n")
    assert readme.is_file()

    oid = _commit_worktree(tmp_path)
    for _ in range(2):
        verification = _verify_commit(
            tmp_path,
            oid,
            render_journal(rows),
            spec=corpus_spec(),
        )
        assert verification.removed_paths == (legacy,)
        assert legacy not in {entry.path for entry in verification.content}


def test_refuses_a_tree_entry_carrying_an_unassigned_code_point(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F2 and the policy: entry names were folded without a screen.

    Declared paths were screened for an unassigned code point because the
    fold key is stable across Unicode tables only for assigned characters.
    Filesystem entry names went straight into the same fold — U+A7CB folds
    to U+0264 on Unicode 16 and to itself before it — so whether the sweep
    called a file content, and so whether the closed world contained it,
    depended on the verifier's interpreter rather than on the tree.

    The class is refused by repertoire now rather than by a pinned table,
    but the site is unchanged and so is what it pins: the screen has to run
    before anything else looks at the entry, and without it the name is
    folded, found to carry no pinned suffix or to be no regular file, and
    the refusal is a different one or none at all.
    """

    import unicodedata

    assert unicodedata.category("͸") == "Cn"
    write_tree(tmp_path)
    oid = _commit_extra_blob(tmp_path, "rules/tax/notes͸".encode())
    with pytest.raises(CorpusError, match="is not a portable name") as caught:
        _verify_commit(
            tmp_path,
            oid,
            render_journal(journal_rows()),
            spec=corpus_spec(),
        )
    assert "tree entry 'rules/tax/notes" in str(caught.value)


def test_refuses_an_unassigned_code_point_in_a_tombstone_listing(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F2 and the policy: the tombstone search folds entry names too.

    The fold search buckets every name in a directory by fold key to decide
    whether a removed path survives under an aliasing spelling. A name whose
    equivalence class this module would have to guess at lands in one bucket
    here and another on the filesystem that resolves it, so the same tree
    honours the tombstone on one host and refuses on another. The index
    reads nothing but the name, so an injected entry is exactly what a real
    one would be here: without the screen the name folds unexamined, no
    survivor is found, and this verification passes.
    """

    body = '{"applied": true}\n'
    write_tree(tmp_path)
    rows = _tombstone_rows("retired/apply-manifest.json", body)
    oid = _commit_extra_blob(tmp_path, "retired/sibling͸".encode())
    with pytest.raises(CorpusError, match="is not a portable name") as caught:
        _verify_commit(tmp_path, oid, render_journal(rows), spec=corpus_spec())
    assert f"tree entry {'retired/sibling͸'!r}" in str(caught.value)


def test_the_refusal_no_longer_depends_on_the_interpreter_at_all(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F5 and the policy: the version-dependence is gone, not pinned.

    S4-F5 was that "is this code point assigned" was answered by the
    *running* table, so U+A7CB — unassigned in Unicode 14.0 and 15.1, which
    Python 3.11 through 3.13 ship, and assigned in 16.0, which 3.14 ships —
    was refused on three supported interpreters and accepted on the fourth.
    The answer was to pin 698 ranges of Unicode 14.0 in the package.

    The policy answers it without a table: U+A7CB is outside the portable
    repertoire on every interpreter, as is U+1FAF6, which Unicode 14.0 did
    encode and which the pinned table therefore accepted. Both are asserted,
    because what the policy trades away is exactly the second one — a corpus
    could name a file ``🫶.yaml`` and cannot now — and the trade should be
    visible in the suite rather than only in a docstring.

    Without the screen the first path verifies and folds to a key three of
    the four supported interpreters would not produce.
    """

    write_tree(tmp_path)
    for spelling in ("rules/benefit/amo\ua7cbunt.yaml", "rules/tax/\U0001faf6.yaml"):
        rows = journal_rows()
        rows[0]["path"] = spelling
        with pytest.raises(CorpusError) as caught:
            verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
        # The quoted spelling is not pinned: ``_quoted`` is ``repr``, and
        # repr prints a character the *running* table calls assigned and
        # escapes one it does not, so the same path reads back differently
        # on 3.13 and 3.14. What is pinned is the refusal, which does not.
        assert str(caught.value).startswith(
            f"journal row 1 path {NOT_PORTABLE}: "
        ), spelling


def test_an_oversized_tier_is_quoted_within_bounds(tmp_path: pathlib.Path) -> None:
    """Binds F5: only two fields were bounded when quoted, and tier was not.

    _quoted was reached by duplicate keys and malformed gate ids alone. Every
    other producer-controlled value a refusal names — kind, schemaVersion,
    entryIndex, the unknown-key list, tier, outcome, sha256, state — was
    reproduced verbatim, so a million-character tier put a million characters
    into the verdict and scrolled away every line the auditor needed. Without
    the fix this refusal is a megabyte long.
    """

    write_tree(tmp_path)
    rows = journal_rows(
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "T" * 1000000,
                "outcome": "pass",
                "evidence": {"command": "make validate"},
            }
        ]
    )
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert "unknown reproducibility tier" in str(caught.value)
    assert len(str(caught.value)) < 600
    assert "more characters]" in str(caught.value)


def test_an_oversized_unknown_row_key_is_quoted_within_bounds(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F5: the closed-world key refusal interpolated whole lists.

    ``missing=`` and ``unknown=`` rendered their lists with str(), which is
    repr of every element, so one long key name flooded the verdict the same
    way. The list goes through _quoted now, which is byte-identical for the
    short lists a real journal produces.
    """

    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["K" * 1000000] = "x"
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert "keys are not closed-world" in str(caught.value)
    assert len(str(caught.value)) < 600


def test_a_short_producer_value_is_quoted_exactly_as_before(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F5: routing through _quoted must not restate any real refusal.

    _quoted is plain repr under the bound, so every refusal a corpus of
    ordinary size can produce is byte-identical to what it was. Pinned here
    because the alternative — a bound that also reshaped short messages —
    would silently invalidate the rest of this battery.
    """

    write_tree(tmp_path)
    rows = journal_rows()
    rows[-1]["tier"] = "insider"
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert str(caught.value) == (
        "journal row 7 gate 'ci/repository-checks' declares unknown "
        "reproducibility tier 'insider'"
    )


def test_a_forged_verdict_line_in_a_tree_name_is_escaped(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F4: filesystem names went into refusals unescaped.

    Journal strings are control-screened at the schema boundary; filesystem
    names are screened by nothing, and the CLI prints refusal text into the
    verdict it hands an auditor. A file named ``\\x1b[2K\\rVERDICT: PASS``
    under a content root put those bytes straight into the refusal, where the
    terminal erased the line and redrew it. Without the fix the raw escape is
    in the message.

    Which refusal carries the name moved twice, and the property under test
    did not: S5R2-F3 moved it to the colon screen, and the policy moved it
    to the one screen that replaced all of those. The forged line carries an
    ESC, a carriage return, a space and a colon, none of them
    in the portable repertoire, and the screen runs before anything decides
    whether the entry is a symlink. A tree-derived name still reaches an
    auditor escaped, and it is still bound at the earliest boundary every
    enumerated name passes through.
    """

    forged = "\x1b[2K\rVERDICT: PASS"
    write_tree(tmp_path)
    (tmp_path / "rules/tax" / forged).symlink_to(tmp_path / "rules/tax/rate.yaml")
    with pytest.raises(CorpusError, match="is not a portable name") as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    message = str(caught.value)
    assert "\x1b" not in message and "\r" not in message
    assert "\\x1b[2K\\rVERDICT: PASS" in message


def test_refuses_a_content_root_spelled_with_a_varied_case(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F6: content-root membership was the one comparison not folded.

    The suffix predicate folds, the alias guard folds, the tombstone search
    folds — and a path's root was matched byte for byte. So on a
    case-sensitive host ``RULES/evil.yaml`` sat outside the pinned ``rules/``
    root, was not content, and was never swept; on a case-insensitive host
    the same bytes are inside it. The same published corpus was closed on one
    auditor's machine and open on another's.

    Which refusal speaks depends on the host, and both are asserted here:
    where the write lands inside ``rules/`` the file is an unlisted content
    file, and where it lands beside it the tree entry aliases the root
    component. Without the fix a case-sensitive host verifies this tree.
    """

    write_tree(tmp_path)
    (tmp_path / "RULES").mkdir(exist_ok=True)
    (tmp_path / "RULES/evil.yaml").write_text("name: evil\n")
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    message = str(caught.value)
    assert "evil.yaml" in message or "RULES" in message


def test_a_case_varied_content_root_makes_a_path_content(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F6, the classification half: kind is decided from the fold key.

    A producer could bind ``RULES/smuggled.yaml`` as attested — exempt from
    the closed-world sweep by construction — because content_root_of compared
    the root byte for byte and found none. Every consumer on a
    case-insensitive filesystem reads that path as ``rules/smuggled.yaml``.
    After folding it is a content path and the attested row is refused, at
    parse time, before the tree is touched. Without the fix the row is
    accepted and the run fails later for an unrelated reason, if at all.
    """

    body = "name: smuggled\n"
    write_tree(tmp_path)
    rows = journal_rows()
    rows.append(
        {
            "schemaVersion": JOURNAL_SCHEMA,
            "kind": "attested",
            "path": "RULES/smuggled.yaml",
            "sha256": sha256_text(body),
            "state": "present",
        }
    )
    reindex(rows)
    with pytest.raises(CorpusError, match="must be swept closed-world"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_the_aliasing_root_component_refusal_names_the_entry(
    tmp_path: pathlib.Path,
) -> None:
    """A raw tree with only an alias spelling names the pinned component."""

    write_tree(tmp_path)
    _commit_worktree(tmp_path)
    updates: list[tuple[str, str | None, bytes]] = []
    for path in sorted(CONTENT):
        object_id = (
            _git(tmp_path, "rev-parse", f"HEAD:{path}").decode("ascii").strip()
        )
        updates.append(("0", None, path.encode("ascii")))
        updates.append(
            ("100644", object_id, path.replace("rules/", "RULES/", 1).encode("ascii"))
        )
    oid = _commit_index_updates(tmp_path, updates)
    with pytest.raises(CorpusError) as caught:
        _verify_commit(
            tmp_path,
            oid,
            render_journal(journal_rows()),
            spec=corpus_spec(),
        )
    assert str(caught.value) == (
        "tree entry 'RULES' aliases the pinned content root component 'rules' "
        "on a case- or normalization-insensitive filesystem"
    )


def test_refuses_a_tree_file_whose_short_name_alias_would_be_content(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R6-F1: the alias screen covered declared paths, not tree names.

    ``_aliases_natively`` refuses a *declared* path Win32 would resolve under
    a spelling nothing emits. Closed-world membership is not decided by
    declared paths, though — it is decided by what the sweep finds on disk,
    and there the same asymmetry was wide open. With ``.yml`` pinned, an
    emitted entry ``rules/smuggled.ymlx`` is not content under
    ``_has_pinned_suffix``, so the sweep skipped it; the ``SMUGGL~1.YML``
    that 8.3 generation hands out for it opens the same bytes and *is*
    content, sitting outside the closed world the verdict just called closed.

    The file is real here — POSIX allows the name, and it is the emitted long
    name that the sweep has to judge. Without the fix this verification
    returns a CorpusVerification with the file in the tree.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/smuggled.ymlx").write_text("name: smuggled\n")
    spec = corpus_spec(content_suffixes=(".yaml", ".yml"))
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=spec)
    assert str(caught.value) == (
        "content root contains a file whose short-name alias would carry a "
        "pinned suffix: 'rules/smuggled.ymlx'"
    )


@pytest.mark.parametrize("shape", ["symlink", "directory"])
@pytest.mark.parametrize("name_repertoire", ["portable", "posix-bytes"])
def test_short_name_suffix_screen_covers_every_tree_entry_kind_in_portable(
    tmp_path: pathlib.Path,
    shape: str,
    name_repertoire: str,
) -> None:
    """A non-blob cannot evade portable 8.3 screening by its entry mode."""

    write_tree(tmp_path)
    _commit_worktree(tmp_path)
    blob_oid = _hash_blob(tmp_path, b"shape fixture\n")
    path = "rules/hidden.ymlx"
    if shape == "symlink":
        updates = [("120000", blob_oid, path.encode())]
    else:
        updates = [("100644", blob_oid, f"{path}/child.txt".encode())]
    oid = _commit_index_updates(tmp_path, updates)
    spec = corpus_spec(
        content_suffixes=(".yaml", ".yml"),
        name_repertoire=name_repertoire,
    )

    if name_repertoire == "posix-bytes":
        verification = _verify_commit(
            tmp_path,
            oid,
            render_journal(journal_rows()),
            spec=spec,
        )
        assert verification.name_repertoire == "posix-bytes"
    else:
        with pytest.raises(CorpusError) as caught:
            _verify_commit(
                tmp_path,
                oid,
                render_journal(journal_rows()),
                spec=spec,
            )
        assert str(caught.value) == (
            "content root contains a file whose short-name alias would carry a "
            f"pinned suffix: {path!r}"
        )


def _refuses_short_name_alias(tmp_path: pathlib.Path, name: str) -> None:
    """Write ``rules/<name>`` and assert the short-name screen refuses it."""

    write_tree(tmp_path)
    (tmp_path / "rules" / name).write_text("name: smuggled\n")
    spec = corpus_spec(content_suffixes=(".yaml", ".yml"))
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=spec)
    assert str(caught.value) == (
        "content root contains a file whose short-name alias would carry a "
        f"pinned suffix: {'rules/' + name!r}"
    )


def _refuses_as_unportable(tmp_path: pathlib.Path, name: str) -> None:
    """Write ``rules/<name>`` and assert the portable-name screen refuses it."""

    write_tree(tmp_path)
    (tmp_path / "rules" / name).write_text("name: smuggled\n")
    spec = corpus_spec(content_suffixes=(".yaml", ".yml"))
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=spec)
    assert str(caught.value) == (
        f"tree entry {'rules/' + name!r} {NOT_PORTABLE}: {name!r}"
    )


@pytest.mark.parametrize(
    "name", ["smuggled.y mlx", "smuggled.y m l x", "smuggled . yml"]
)
def test_refuses_a_short_name_alias_hidden_behind_a_space(
    tmp_path: pathlib.Path, name: str
) -> None:
    """Binds S4-F1 and the policy: the space class is refused, not modelled.

    Win32 removes every space from a name *before* it truncates the
    extension to three characters, so with ``.yml`` pinned each of these is
    handed the alias ``SMUGGL~1.YML``, which opens the same bytes. The screen
    read the written extension instead — ``y mlx`` truncating to ``Y M`` —
    decided the alias could not carry a pinned suffix, and let the long name
    be skipped as non-content, so the closed world the verdict called closed
    held a file reachable under a content name. Three separate tests pinned
    the three ways a space could hide there, because a fix that dropped only
    the first space, or only a leading one, would satisfy one and leave the
    others open.

    A space is outside the portable repertoire, so all three refuse on the
    name and none of them reaches the derivation at all. The space rule
    stays in ``_short_name_extension`` because it is Win32's rule and the
    function is asked directly by tests, but no name the sweep hands it can
    carry one. Without the screen these are ordinary non-content files and
    the verification returns a CorpusVerification over a tree that holds
    them.
    """

    _refuses_as_unportable(tmp_path, name)


def test_a_short_name_extension_carrying_a_non_ascii_character_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F3 and the policy: the code-page question is not asked now.

    Round seven pinned this name as an *acceptance*, on the model that 8.3
    generation substitutes an underscore for every character its namespace
    cannot hold, so ``smuggled.ÿml`` would be handed ``._ML`` or ``.Y_M``
    and neither is ``.YML``. The model was wrong: the 8.3 namespace is an
    OEM code page and not ASCII, so a character the volume's code page can
    represent survives into the short name and is uppercased there — with
    ``.éml`` pinned, ``smuggled.émlx`` gets an alias ending ``.ÉML`` on a
    code page 850 volume (peer review, round eight). Round eight refused the
    name as underivable; Sol round 2 then had to bound that refusal twice
    over, because it was refusing ordinary names.

    The refusal stands and its reason is now the repertoire: a non-ASCII
    extension is a non-portable name, so no code page is consulted, no
    derivation is attempted, and there is no bound to get wrong. Without the
    screen this name is silently skipped as non-content under a model of a
    mapping the volume had not agreed to.
    """

    _refuses_as_unportable(tmp_path, "smuggled.ÿml")


def test_refuses_a_tree_entry_whose_name_windows_would_strip(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R6-F1: a trailing dot on a tree entry aliases the name beside it.

    Win32 strips trailing dots and spaces before the lookup, so
    ``rules/tax/notes.yaml.`` opens ``rules/tax/notes.yaml`` there. The two
    spellings are not fold-equal, so no fold key pairs them, and a declared
    path spelled either way has been refused since round three — but the
    entry the *tree* carries was never asked. A file emitted under the dotted
    spelling is not content by suffix, is skipped by the sweep, and answers
    to a content name on the filesystem this module's whole portability model
    is about.

    The name is injected through the sweep's listing rather than written:
    what the verifier has to hold against is a filesystem that emits the
    name, and injecting it makes the test say the same thing on every host.
    Without the screen the entry falls through to the ``lstat``, which fails,
    and the refusal is the non-regular-file one instead.

    Binds the policy for the message: the trailing period is the one Win32
    alias rule the portable repertoire does not subsume, so it is one of the
    three questions the single screen asks and its refusal is that screen's.
    """

    write_tree(tmp_path)
    oid = _commit_extra_blob(tmp_path, b"rules/tax/notes.yaml.")
    with pytest.raises(CorpusError) as caught:
        _verify_commit(
            tmp_path,
            oid,
            render_journal(journal_rows()),
            spec=corpus_spec(),
        )
    assert str(caught.value) == (
        f"tree entry 'rules/tax/notes.yaml.' {NOT_PORTABLE}: 'notes.yaml.'"
    )


def test_refuses_an_entry_beside_a_root_component_windows_would_strip(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R6-F1: the same strip decides which directory *is* the root.

    ``rules `` beside the pinned ``rules`` is the content root on Windows —
    the lookup strips the space — so a producer can fill it with rule files
    that a POSIX verifier never sweeps, because the walk descends the
    spelling the spec pinned and the fold check beside it cannot pair two
    names that are not fold-equal. The aliasing-root-component guard now asks
    the strip question as well as the fold question.

    Injected into the tree root's listing so the branch is covered on every
    host. Without the screen nothing here refuses: the entry is not
    fold-equal to ``rules``, the sweep never descends it, and the
    verification passes.

    Binds the policy for the message, and for the width of the screen: this
    is the site where the portable-name rule reaches furthest, because every
    entry beside a component of a pinned root is screened and the first such
    component's parent is the repository root. A space is outside the
    repertoire wherever it sits, so this refuses whether the space is
    trailing or not.
    """

    write_tree(tmp_path)
    oid = _commit_extra_blob(tmp_path, b"rules /scratch.txt")
    with pytest.raises(CorpusError) as caught:
        _verify_commit(
            tmp_path,
            oid,
            render_journal(journal_rows()),
            spec=corpus_spec(),
        )
    assert str(caught.value) == (
        f"tree entry 'rules ' {NOT_PORTABLE}: 'rules '"
    )


def test_an_ordinary_non_content_file_under_a_content_root_still_verifies(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R6-F1, the other side: the screen must not close the closed world.

    The sweep binds files with a pinned suffix and ignores everything else
    under a content root, which is what lets a corpus keep a README beside
    its rules. The short-name screen refuses only a name whose 8.3 extension
    would fold onto a pinned one, so an ordinary neighbour is untouched.
    Pinned because a conservative screen that also refused these would break
    every real corpus while every refusal test above still passed.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/README.md").write_text("# rules\n")
    (tmp_path / "rules/tax/notes.txt").write_text("scratch\n")
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows()), spec=corpus_spec()
    )
    assert len(verification.content) == len(CONTENT)


def test_the_same_corpus_verifies_on_posix(tmp_path: pathlib.Path) -> None:
    """Binds S4-F3, the control: the refusal above is about the platform.

    The identical tree, journal and spec, with ``os.name`` left alone. If
    this ever fails alongside the test above passing, the platform screen has
    become the only reason anything refuses.
    """

    write_tree(tmp_path)
    assert os.name == "posix"
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows()), spec=corpus_spec()
    )
    assert len(verification.content) == len(CONTENT)


def test_refuses_a_gate_whose_escaped_evidence_floods_the_verdict(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R6-F3: the budget counted Python characters, the verdict renders JSON.

    ``receipt.cli`` renders the verdict with ``json.dumps(..., indent=2,
    sort_keys=True)`` and leaves ``ensure_ascii`` at its default, so every
    non-ASCII character a producer writes leaves as an escape — twelve ASCII
    characters for one outside the BMP, which JSON spells as a surrogate
    pair. Charging what Python holds rather than what the renderer emits left
    a factor of twelve unbudgeted, and it takes exactly one legal gate to
    spend it: four-character evidence keys with 1024 U+1F600 characters per
    value, each value inside ``MAX_EVIDENCE_TEXT`` and each key
    unremarkable.

    That gate charged well under the budget of 262,144 and passed, while the
    JSON it renders is a multiple of it — the flood the budget exists to
    stop, assembled out of strings none of which is over the per-string
    bound. Every producer string is charged its rendered length now. Without
    the fix this journal verifies.

    The entry count is ``MAX_EVIDENCE_ENTRIES`` rather than round six's 249:
    S5R2-F4 bounds how many entries one gate may declare, so the version of
    this journal with 249 of them is refused for its cardinality before any
    entry is validated. The demonstration is unchanged — the twelvefold gap
    between what Python holds and what JSON emits is what carries a legal
    gate past a budget it was charged against — and the refusal names the
    row, because the charge is made as the row is validated.

    Also binds S5R3-F10, from the side that still refuses. Each of these
    values renders as 12,288 characters unbounded and as 4,121 once
    ``receipt._render`` has bounded it — the 341 emoji that fit, plus the
    truncation marker, which is itself charged because it is itself
    printed. Sixty-four of them come to 265,262, over the budget, so this
    gate is refused for what the verdict *renders* rather than for what the
    producer wrote. Its sibling below is the same gate at twenty-two
    values, which fits and is accepted.
    """

    write_tree(tmp_path)
    evidence = {
        f"{index:04d}": "\U0001F600" * 1024 for index in range(MAX_EVIDENCE_ENTRIES)
    }
    gates = [
        {"gateId": "g", "tier": "public", "outcome": "pass", "evidence": evidence}
    ]
    # What round five's charge came to, which is why this journal used to
    # pass: 64 per gate, 24 per evidence entry, and Python characters for
    # every string.
    old_charge = (
        64
        + len("g")
        + sum(24 + len(key) + len(value) for key, value in evidence.items())
    )
    assert old_charge <= MAX_GATE_TEXT
    charged = charged_gate(gates[0])
    # The gap itself, stated on one value rather than on the whole charge:
    # 1024 code points outside the BMP leave json.dumps as 12,288 characters.
    assert len(json.dumps("\U0001F600" * 1024)) == 12 * 1024 + 2
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(gates=gates)), spec=corpus_spec()
        )
    row = len(CONTENT) + len(ATTESTED) + 1
    assert str(caught.value) == (
        f"journal gate declarations cost more than the verdict budget of "
        f"{MAX_GATE_TEXT} characters: {charged} charged at declaration 1 "
        f"(journal row {row})"
    )


def test_a_removed_path_can_no_longer_render_wider_than_it_is_written(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R6-F3 and the policy: the escaping gap is closed for paths.

    R6-F3 was that ``MAX_REMOVED_TEXT`` charged Python characters while
    ``json.dumps`` renders with ``ensure_ascii`` on, so a path spelled in
    characters outside the BMP rendered twelve times its length: four
    hundred of them charged 30,800 against a budget of 262,144 while putting
    295,600 characters of escaped JSON into the verdict. The fix was to
    charge what the renderer emits, and it stands.

    Under the portable-name policy the input that demonstrated it cannot
    exist. A removed path is a declared path, so it is ASCII, so
    ``json.dumps`` escapes nothing in it and its rendered length is its
    written length plus the two quotes. Both halves are asserted here: the
    old demonstration journal refuses as a non-portable name, and the
    rendering of a portable path is exactly its length plus two.

    The gap itself is not gone from the module — gate evidence is producer
    text and not a name, so it can still carry a non-BMP character, and
    ``test_refuses_a_gate_whose_escaped_evidence_floods_the_verdict``
    exercises the same arithmetic where it is still reachable.
    """

    from receipt.corpus import _rendered_length

    body = '{"applied": true}\n'
    retired = [
        ".axiom/" + "\U0001F600" * 60 + f"-{index:04d}.json" for index in range(400)
    ]
    attested = dict(ATTESTED)
    for path in retired:
        attested[path] = body
    rows = journal_rows(attested=attested)
    for path in retired:
        rows.append(
            {
                "schemaVersion": JOURNAL_SCHEMA,
                "kind": "attested",
                "path": path,
                "sha256": sha256_text(body),
                "state": "removed",
            }
        )
    reindex(rows)
    write_tree(tmp_path)
    # What the old charge came to, which is why this journal used to pass.
    assert sum(len(path) for path in retired) <= MAX_REMOVED_TEXT
    # And what the renderer would have made of it, which is the gap.
    assert sum(_rendered_length(path) for path in retired) > MAX_REMOVED_TEXT
    with pytest.raises(CorpusError, match="is not a portable name"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    # No portable path can reopen it: escaping a portable name is a no-op.
    for portable in (".axiom/apply-manifest.json", "rules/tax/rate.yaml", "a-_.b"):
        assert _rendered_length(portable) == len(portable) + 2


def _gate_id(index: int, width: int) -> str:
    """A distinct gate id of exactly ``width`` characters.

    Base 36 over ``[0-9a-z]``, padded with ``x`` when the width is wider
    than the counter needs — so three characters really is three characters
    and still gives 46,656 distinct ids, which is more than the declaration
    cap. Round six measured its worst ratio over a two-character alphabet
    that ran out at 1,296 and had to correct the figure; a base wide enough
    to spell every id at the declared width is what stops that recurring.
    """

    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    text = ""
    value = index
    for _ in range(min(width, 6)):
        text = digits[value % 36] + text
        value //= 36
    assert value == 0, "index does not fit the requested id width"
    return text.ljust(width, "x")


def _json_list_body(rendered: str, key: str, depth: int) -> str:
    """The characters of one rendered JSON list between its brackets.

    Everything after the ``[`` up to, and including, the newline that
    precedes the closing ``]`` — which is exactly the region the per-item
    charges add up to, because each item contributes the newline before it,
    its indentation, its escaped text, and one separator: a comma, or for
    the last item the newline the closing bracket sits after.

    The search is safe on any content: ``json.dumps`` with ``ensure_ascii``
    emits no raw newline inside a string, so a line beginning with exactly
    ``depth`` spaces and a bracket can only be the list's own closing one.
    """

    opening = f'{" " * depth}"{key}": [\n'
    start = rendered.index(opening) + len(opening) - 1
    closing = "\n" + " " * depth + "]"
    return rendered[start : rendered.index(closing, start) + 1]


def _verdict_of(
    tmp_path: pathlib.Path, rows: list[dict[str, object]]
) -> tuple[str, str]:
    """Verify a journal and render its verdict both ways, as the CLI does.

    Returns the JSON and the text, from the same ``VerifyResult`` and through
    the same two renderers ``receipt.cli`` calls — ``result_to_dict`` with
    ``json.dumps(..., indent=2, sort_keys=True)``, and ``_format_text``.

    The chain half is left out — ``chain=None`` — because it is a fixed
    handful of digests and timestamps with no producer-controlled string in
    it, so it cannot scale with either budget. What is measured is exactly
    what the budgets bound.

    ``_bounded_payload`` is applied before ``json.dumps``, because ``main``
    applies it: the string the verdict carries is the bounded one, and a
    measurement that skipped the bound would be measuring something the
    command never prints (S5R3-F10).
    """

    from receipt.cli import _bounded_payload, _format_text
    from receipt.verify import VerifyResult, result_to_dict

    verification = verify_corpus_binding(
        tmp_path, render_journal(rows), spec=corpus_spec()
    )
    result = VerifyResult(
        spec_name="receipt test corpus",
        spec_path=tmp_path / "verification" / "spec.py",
        spec_sha256="0" * 64,
        root=tmp_path,
        receipt_version="test",
        producer_spki_sha256="0" * 64,
        passes=(),
        chain=None,
        corpus=verification,
    )
    return json.dumps(
        _bounded_payload(result_to_dict(result)), indent=2, sort_keys=True
    ), _format_text(result)


def _near_cap_rows(
    tmp_path: pathlib.Path, gate_id_width: int
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[str]]:
    """A journal filling both budgets to just under their caps.

    ``gate_id_width`` chooses the shape: a wide id makes the charge mostly
    producer text, and the narrowest distinct id makes it mostly the JSON
    structure the budget used to under-count.
    """

    body = '{"applied": true}\n'
    write_tree(tmp_path)

    def gate(index: int) -> dict[str, object]:
        return {
            "gateId": _gate_id(index, gate_id_width),
            "tier": "public",
            "outcome": "pass",
            "evidence": {"c": "1"},
        }

    count = min(MAX_GATE_TEXT // charged_gate(gate(0)), MAX_GATE_DECLARATIONS)
    gates = [gate(index) for index in range(count)]
    # Each component stays inside the 255-byte name limit every filesystem
    # this runs on enforces, since these paths are looked for on disk.
    path_template = ".axiom/" + "r" * 240 + f"-{0:04d}.json"
    retired = [
        ".axiom/" + "r" * 240 + f"-{index:04d}.json"
        for index in range(MAX_REMOVED_TEXT // charged_removed(path_template))
    ]
    attested = dict(ATTESTED)
    for path in retired:
        attested[path] = body
    rows = journal_rows(attested=attested, gates=gates)
    for path in retired:
        rows.append(
            {
                "schemaVersion": JOURNAL_SCHEMA,
                "kind": "attested",
                "path": path,
                "sha256": sha256_text(body),
                "state": "removed",
            }
        )
    reindex(rows)
    return rows, gates, retired


def _assert_budgets_equal_what_is_rendered(
    tmp_path: pathlib.Path, gate_id_width: int
) -> None:
    """Charge a near-cap journal and hold the charge against the rendering."""

    rows, gates, retired = _near_cap_rows(tmp_path, gate_id_width)
    charged_gates = sum(charged_gate(gate) for gate in gates)
    charged_paths = sum(charged_removed(path) for path in retired)
    assert charged_gates <= MAX_GATE_TEXT
    assert charged_paths <= MAX_REMOVED_TEXT

    rendered, text = _verdict_of(tmp_path, rows)
    # Every gate here is public, so the section is one list; the removed
    # paths are one list at their own depth.
    assert len(_json_list_body(rendered, "public", 6)) == charged_gates
    assert len(_json_list_body(rendered, "removedPaths", 4)) == charged_paths
    # The other renderer, measured on the same journal: the text verdict
    # prints one short line per gate and no removed paths at all, so the JSON
    # section is the larger of the two and charging it charges both. If that
    # ever inverts, the text is what has to be charged.
    assert len(text) <= charged_gates + charged_paths


def test_the_gate_and_removed_budgets_equal_what_the_verdict_renders(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F6: the budgets under-counted the structure they bound.

    A removed path was charged its escaped string with the six spaces of
    indentation, the comma and the newline around it free, and a gate was
    charged a flat 64 for a JSON object that really costs 101 plus its
    outcome — ``GATE_RENDER_OVERHEAD`` was documented as a floor, and a
    journal filled to just under the cap therefore rendered well past it.
    The test that was supposed to hold the budgets to the renderer permitted
    a ratio of four, so it could not see the gap.

    The constants are derived from the renderer's own shape now, and this is
    the assertion that keeps them honest: the total charged equals ``len()``
    of the section rendered, exactly, for both budgets. Any change to
    ``result_to_dict``'s shape or to the CLI's ``json.dumps`` call fails here
    and forces the constants to be re-derived rather than quietly loosening
    what the budget admits.

    This shape is the wide-id one: a 31-character gate id, so most of what is
    charged is producer text — 1,618 gates and 981 removed paths, charging
    262,116 and 261,927 and rendering exactly that much. Without the fix the
    charge is short of the rendering by about a fifth and the equality fails.
    """

    _assert_budgets_equal_what_is_rendered(tmp_path, gate_id_width=31)


def test_the_budgets_still_equal_the_rendering_at_the_worst_ratio(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F6: the shape that maximised the old ratio, held exactly.

    Round six measured 1.36 as the most a journal could render per unit
    charged *at* the budget, and the shape that did it was the largest number
    of gates with the shortest distinct id and the smallest evidence — the
    shape where the structural overhead the budget under-charged dominates
    the strings it charged exactly.

    That shape is charged exactly now, so its ratio is 1.00 for the sections
    the budgets bound: 1,956 three-character ids charging 262,104 and
    rendering 262,104. Pinned separately from the wide-id case because a
    constant that happened to be right for long ids and wrong for short ones
    would satisfy that test and not this one. Without the fix the charge is
    short by roughly a quarter here.

    What the two together say about the whole verdict: the JSON the CLI
    prints for either journal is 1.002 times the two charges, the remainder
    being fixed text no producer controls, and the text renderer is a tenth
    of it or less — it prints one short line per gate and no removed paths
    at all. So charging the JSON sections charges both renderers.
    """

    _assert_budgets_equal_what_is_rendered(tmp_path, gate_id_width=3)

def test_the_rendered_charge_equals_what_json_dumps_would_cost() -> None:
    """Binds R6-F3: the charge must be the renderer's escaping, not a model of it.

    The budgets charge what ``json.dumps`` makes of a producer string, and
    the module takes that from the escaper ``json.dumps`` applies to a
    top-level string rather than by calling ``json.dumps`` itself —
    ``JSONEncoder.encode`` short-circuits to exactly that function when
    ``ensure_ascii`` is on, and naming it keeps a caller who has replaced
    ``json.dumps`` from silently changing what a budget charges. Equal by
    construction, and pinned here rather than assumed, across the shapes the
    two differ over if they ever were to: plain ASCII, a character that
    escapes to six, one outside the BMP that escapes to twelve as a
    surrogate pair, and the characters JSON escapes for its own syntax.

    Without the fix — with the charge counting Python characters — every case
    below but the first is short by the factor this finding is about.
    """

    from receipt.corpus import _rendered_length

    for text in (
        "",
        "make validate",
        "rules/tax/rate.yaml",
        "café",
        "中文",
        "\U0001F600",
        "\U0001F600" * 64,
        'quote " backslash \\ tab-free',
    ):
        assert _rendered_length(text) == len(json.dumps(text, ensure_ascii=True))
    assert _rendered_length("\U0001F600") == 14
    assert _rendered_length("abc") == 5


# --- second fresh gate, round one: what the closing checks still let past ----


ZERO_WIDTH_JOINER = "‍"
COMBINING_GRAPHEME_JOINER = "͏"
DOTLESS_SMALL_I = "ı"
DOTTED_CAPITAL_I = "İ"


def test_refuses_a_tree_entry_a_target_filesystem_would_ignore_a_code_point_in(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F2: the fold key is not a proof about the target filesystem.

    HFS+ ignores default-ignorable code points when it compares names, so
    ``rules/evil.y\\u200dml`` and ``rules/evil.yml`` are one file there. Here
    they are two: the fold key is NFC plus case folding, which preserves the
    joiner, so the first name carries the suffix ``.y\\u200dml``, is not
    content under a ``.yml`` pin, and was skipped by the sweep — while on the
    filesystem the module's whole portability model is about, it opens a
    content file that no journal row binds and no sweep ever saw.

    The screen refuses the name instead of trying to decide which
    filesystem's equivalence the auditor will use, because it cannot know:
    the clone is verified on one host and resolved on another.

    Without the screen this verification returns a CorpusVerification with
    the file sitting in the tree, unbound.

    Binds the policy for the message and for the table behind it. The class
    used to be decided by 17 pinned ranges of Unicode 14.0's
    ``Default_Ignorable_Code_Point`` property, parsed from the published
    file because ``unicodedata`` exposes no query for it. The repertoire
    decides it now, with nothing to pin and nothing to re-derive: a joiner
    is not an ASCII letter, digit, ``.``, ``_`` or ``-``.
    """

    _refuses_as_unportable(tmp_path, f"evil.y{ZERO_WIDTH_JOINER}ml")


def test_refuses_a_tombstone_listing_entry_a_filesystem_may_ignore(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F2: the tombstone search buckets by the same fold key.

    A tombstone is honoured when no fold-equal spelling survives in a
    listing. ``apply-manifest.jso\\u200dn`` is not fold-equal to
    ``apply-manifest.json`` here — the joiner survives NFC and case folding
    — so the bucket lookup misses it and the verdict names the path as
    removed. On HFS+ that entry *is* the removed path: the file the journal
    says is gone still answers to the name it was retired under.

    The entry is injected into the listing rather than written, for the
    reason ``_late_survivor_scandir`` gives: what has to be held against is
    a filesystem that emits the name, and injecting it says the same thing
    on every host. Without the screen this verification passes and reports
    ``retired/apply-manifest.json`` under removedPaths.

    Binds the policy for the message: the tombstone listing is screened by
    the same one screen every other listing is.
    """

    body = '{"applied": true}\n'
    write_tree(tmp_path)
    (tmp_path / "retired").mkdir()
    rows = _tombstone_rows("retired/apply-manifest.json", body)
    survivor = f"apply-manifest.jso{ZERO_WIDTH_JOINER}n"
    (tmp_path / "retired" / survivor).write_text(body)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert str(caught.value) == (
        f"tree entry {('retired/' + survivor)!r} {NOT_PORTABLE}: {survivor!r}"
    )


def test_refuses_two_declared_paths_hfs_plus_would_call_one_file(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F2: the default-ignorable class is wider than the Cf class.

    U+034F COMBINING GRAPHEME JOINER is default-ignorable and *not* a format
    control, so the Cf screen never saw it while HFS+ ignores it exactly as
    it ignores U+200D. A journal binding both ``rules/tax/rate.yaml`` and
    ``rules/tax/ra\\u034fte.yaml`` therefore declares two content files that
    are one file on that filesystem, and ``_reject_aliasing_paths`` could not
    pair them because their fold keys differ.

    This is the same hazard ``_reject_aliasing_paths`` refuses for case and
    normalization aliases, one class further out: a closed world whose
    membership depends on which filesystem the auditor resolved the tree on
    is not closed. Both files are real here and both hash, so without the
    screen this verification passes and reports a closed world of four
    content files that no HFS+ consumer can hold.

    Binds the policy for the message. U+034F is the case that shows why the
    repertoire is the better answer than a table: it is default-ignorable
    and *not* a format control, so the Cf screen never saw it and a second
    pinned table had to be added to catch it. The repertoire needs no third.
    """

    smuggled = f"rules/tax/ra{COMBINING_GRAPHEME_JOINER}te.yaml"
    content = dict(CONTENT)
    content[smuggled] = "name: rate\nvalue: 0.99\n"
    write_tree(tmp_path, content=content)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(content=content)), spec=corpus_spec()
        )
    assert str(caught.value) == (
        f"journal row 4 path {NOT_PORTABLE}: '{smuggled}'"
    )


def test_refuses_a_dotless_i_beside_the_name_an_upcase_table_folds_it_onto(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F2, restated by S5R2-F11: an upcase table and ``casefold``.

    Unicode gives U+0131 DOTLESS SMALL I the simple uppercase mapping
    U+0049, so an upcase table built from those mappings folds
    ``rules/tax/evıl.yaml`` and ``rules/tax/evil.yaml`` into one name.
    ``str.casefold`` keeps them apart, and so does every fold key in this
    module, so a journal can bind both and a POSIX verifier will find both
    — while the consumer whose host merges them can hold only one, and
    cannot tell which of the two digests the file it has is supposed to
    match.

    Refusing it is the only answer that does not require choosing whose
    case-folding this module implements. Adopting the mapping would fold
    two names together that a POSIX host genuinely keeps apart, which
    breaks the closed world in the other direction.

    S5R2-F11 then had to restate the claim, because the two upcase tables
    that can actually be read disagree about the dotless half and agree that
    nothing maps the *dotted* U+0130 onto ``I`` — so the pair was refused
    together on a premise that held for one of them, and a Turkish-locale
    producer lost the spelling they are far more likely to write. That is
    the shape the policy exists to stop: three review rounds spent deciding
    whose case mapping this module implements, over two characters.

    Both are outside the portable repertoire now, and both refuse with the
    same message and for a reason that needs no table at all. Both are
    asserted, because the second is the cost side of the trade.

    Both files are real and both are bound, so without the screen the
    dotless verification returns a CorpusVerification over five content
    files.
    """

    content = dict(CONTENT)
    content["rules/tax/evil.yaml"] = "name: evil\nvalue: 1\n"
    content[f"rules/tax/ev{DOTLESS_SMALL_I}l.yaml"] = "name: evil\nvalue: 2\n"
    write_tree(tmp_path, content=content)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(content=content)), spec=corpus_spec()
        )
    assert str(caught.value) == (
        f"journal row 3 path {NOT_PORTABLE}: "
        f"'rules/tax/ev{DOTLESS_SMALL_I}l.yaml'"
    )

    dotted = dict(CONTENT)
    dotted[f"rules/tax/{DOTTED_CAPITAL_I}.yaml"] = "name: dotted\nvalue: 1\n"
    write_tree(tmp_path, content=dotted)
    with pytest.raises(CorpusError, match="is not a portable name"):
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(content=dotted)), spec=corpus_spec()
        )


def test_an_ordinary_neighbour_is_not_refused_against_a_four_character_pin(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F3: a pin longer than three characters cannot be aliased at all.

    An 8.3 extension is at most three characters, so no alias of anything
    ends ``.yaml``. Comparing the first three characters of the pin instead
    made the screen refuse a name whose alias carries a suffix that is not
    pinned and cannot be: with ``.yaml`` pinned, ``rules/notes.yam`` is an
    ordinary non-content file whose alias reads ``.YAM``, which is nothing
    the spec asked about, and the sweep refused the corpus over it.

    The comparison is exact now, and only against pins short enough for an
    alias to carry. Without the fix this verification refuses a corpus that
    is exactly what it claims to be.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/notes.yam").write_text("scratch\n")
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows()), spec=corpus_spec()
    )
    assert len(verification.content) == len(CONTENT)


def test_a_longer_name_over_a_four_character_pin_is_not_refused_either(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F3: the same over-refusal from the direction round seven named.

    Round seven wrote the truncating comparison down as a deliberate trade —
    "with ``.yaml`` pinned, a file named ``x.yamlx`` refuses too, though its
    alias would read ``.YAM``" — on the reasoning that refusing a name no
    real corpus carries is cheap. It is not a trade at all: the alias reads
    ``.YAM``, the pin is ``.yaml``, and on the volume the screen models
    those are two different extensions. The name is simply not content, and
    the closed world it sat outside was closed correctly.

    Pinned separately from its sibling because a fix that only ignored pins
    longer than three characters when the *name* was shorter would satisfy
    that test and not this one. Without the fix this verification refuses.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/x.yamlx").write_text("scratch\n")
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows()), spec=corpus_spec()
    )
    assert len(verification.content) == len(CONTENT)


def test_refuses_a_name_whose_alias_extension_the_code_page_would_decide(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F3: the é of the finding's own example, against a short pin.

    With ``.eml`` pinned — three characters, so an alias can carry it — a
    file named ``smuggled.émlx`` has an extension whose 8.3 spelling the
    volume's OEM code page decides. On code page 850 the é survives and
    uppercases, so the alias ends ``.ÉML``; under the round-seven underscore
    model it read ``._ML``, matched no pin, and the file was skipped as
    non-content while its alias opened a content name.

    Refused rather than modelled, because the clone does not report the code
    page — and refused now by the repertoire, one step earlier and without
    the two bounds Sol round 2 had to put on the underivability refusal to
    stop it refusing ordinary names. Without the screen this verification
    passes with the file in the tree and no row binding it.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/smuggled.émlx").write_text("name: smuggled\n")
    spec = corpus_spec(content_suffixes=(".yaml", ".eml"))
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=spec)
    assert str(caught.value) == (
        f"tree entry 'rules/smuggled.émlx' {NOT_PORTABLE}: 'smuggled.émlx'"
    )


def test_the_spec_refuses_a_non_ascii_content_suffix_at_construction() -> None:
    """Binds S5-F3 and the policy: a pin the screen cannot judge is refused.

    A pin carrying a non-ASCII character could never be compared with
    confidence against an alias extension the volume's OEM code page
    decides, so the pin cannot answer the question it exists to ask. S5-F3
    refused it; Sol round 2 then narrowed the refusal to alias-capable pins,
    because refusing ``.éyaml`` refused a configuration nothing ever asks
    about.

    The policy refuses both, and refuses them for the plainer reason that a
    pin is ASCII. That is a real narrowing of what a spec may declare, and
    it is asserted here at both lengths so the cost is on the record.
    Without the rule the spec is accepted and every name is judged against a
    pin no alias can be compared to.
    """

    for suffix in (".éml", ".éyaml"):
        with pytest.raises(CorpusError) as caught:
            corpus_spec(content_suffixes=(".yaml", suffix))
        assert str(caught.value) == (
            "CorpusSpec content suffix must be '.' followed by one or more "
            f"portable characters (ASCII letters, digits, '.', '_' and '-'): "
            f"{suffix!r}"
        )


def test_refuses_a_declared_path_naming_a_win32_reserved_device(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F4: a bound path Win32 resolves to a device, not to a file.

    ``CON``, ``PRN``, ``AUX``, ``NUL`` and the ``COM``/``LPT`` series name
    character devices in every directory on Win32, whatever extension
    follows them. So a journal binding ``rules/NUL.yaml`` and a POSIX file
    of that name verified here — the file is a regular file, its digest
    matches, the sweep finds exactly it — while an ordinary Win32 lookup of
    the same path opens the null device and reads nothing the verdict
    covered.

    That is the module's standing hazard in a new shape: the spelling means
    one thing to the verifier and another to the host that will use the
    tree. Without the screen this row is accepted and the verdict claims a
    binding no Win32 consumer can rely on.

    The device table survives the portable-name policy, because a device
    name is spelled out of portable characters: ``NUL.yaml`` is ASCII
    letters and a period. It is one of the three questions the single screen
    asks, so the refusal is that screen's.
    """

    content = dict(CONTENT)
    content["rules/NUL.yaml"] = "name: null\nvalue: 0\n"
    write_tree(tmp_path, content=content)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(content=content)), spec=corpus_spec()
        )
    assert str(caught.value) == (
        f"journal row 1 path {NOT_PORTABLE}: 'rules/NUL.yaml'"
    )


def test_refuses_a_tree_entry_named_for_a_win32_reserved_device(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F4: the sweep meets the name the journal never mentions.

    ``rules/con.yml`` is not content under a ``.yaml`` pin, so the sweep
    skipped it and the closed world was reported closed around it. On Win32
    that entry is the console device, and anything opening it under a
    content root reads a stream rather than a file — the same reason a FIFO
    under a content root is refused here, arriving under a name instead of
    under a mode.

    Matched case-insensitively on the text before the first period, so the
    lowercase spelling and the extension change nothing. Without the screen
    this verification passes with the entry in the tree.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/con.yml").write_text("scratch\n")
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        f"tree entry 'rules/con.yml' {NOT_PORTABLE}: 'con.yml'"
    )


def test_refuses_a_tree_entry_named_for_a_superscript_com_port(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F4: the superscript spellings are on Microsoft's own list.

    ``COM¹``, ``COM²``, ``COM³`` and the ``LPT`` equivalents resolve exactly
    as their ASCII-digit counterparts do, and they are the half of the list
    a from-memory implementation leaves out. Pinned separately because a
    screen built from ``CON PRN AUX NUL COM1-9 LPT1-9`` alone satisfies
    every other test here and leaves six device names reachable.

    They are also the one place the two sources genuinely disagree, and the
    disagreement is resolved by naming which source each entry rests on:
    Microsoft's page lists the superscripts and says Windows "treats them
    as valid parts of COM# and LPT# device names", while ``ntdll``'s
    matcher compares ASCII digits only. The page is what these six rest on.

    The name is ASCII-uppercased rather than ``str.upper``-ed, so U+00B9 is
    compared as written; that is why the superscripts are table entries and
    not a mapping. Without the screen this verification passes.

    Under the portable-name policy these six are refused twice over — a
    superscript digit is not an ASCII digit either — and the message no
    longer says which question refused them. The table entries stay because
    they are the shape of a Win32 fact and not of this repertoire, and
    because ``_win32_device_basename`` is asked directly by
    ``test_the_device_basename_is_derived_the_way_win32_derives_it``.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/COM¹.yml").write_text("scratch\n")
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        f"tree entry 'rules/COM¹.yml' {NOT_PORTABLE}: 'COM¹.yml'"
    )


def test_names_that_merely_begin_with_a_device_name_still_verify(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F4, the other side: the match is the basename, not a prefix.

    ``nul2.yml`` and ``aux-notes.yml`` are ordinary files. Win32 resolves
    neither to a device — the match is on the whole component up to its
    first period — and a screen that took a prefix instead would refuse a
    corpus that is exactly what it claims to be while every refusal test
    above still passed.

    This test passes on the head as well, which is the point: the screen
    must not close the closed world it is protecting.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/nul2.yml").write_text("scratch\n")
    (tmp_path / "rules/aux-notes.yml").write_text("scratch\n")
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows()), spec=corpus_spec()
    )
    assert len(verification.content) == len(CONTENT)


def test_refuses_a_device_name_padded_with_spaces_before_its_extension(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F4: the device match is two Win32 rules, not one.

    Win32 truncates a component at its first period *or colon* and only then
    removes trailing spaces from what is left, so ``NUL .yaml`` — device
    name, one space, extension — presents ``NUL`` to the device table and
    opens the null device. Taking the text before the first period and
    nothing else missed that: the component does not end in a space, so the
    trailing-strip screen this module already had never fired either, and
    one keystroke walked a bound path straight past the device refusal
    (found by adversarial review of the round-eight fix).

    The composition is ``ntdll``'s own ``RtlIsDosDeviceName_U``. Wine's
    conformance table for it — ``dlls/ntdll/tests/path.c``, run against
    real Windows, not the implementation file beside it — carries
    ``{ "c:nul . . :", 4, 6 }`` and ``{ "c:NUL  ....  ", 4, 6 }``, both of
    which need the truncation and the space-strip in that order.

    Without the composition this journal verifies: the file is a regular
    file, its digest matches, and the sweep calls the world closed, while a
    Win32 consumer reading the same path gets nothing at all.

    The portable-name policy refuses it on the space before the device
    question is reached, so this input now has two independent reasons to
    refuse and one message for both. The composition is still asserted
    directly, over unscreened names, by
    ``test_the_device_basename_is_derived_the_way_win32_derives_it``.
    """

    content = dict(CONTENT)
    content["rules/NUL .yaml"] = "name: null\nvalue: 0\n"
    write_tree(tmp_path, content=content)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(content=content)), spec=corpus_spec()
        )
    assert str(caught.value) == (
        f"journal row 1 path {NOT_PORTABLE}: 'rules/NUL .yaml'"
    )


def test_refuses_a_tree_entry_whose_device_name_is_cut_short_by_a_colon(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F4: the truncation is at a period *or* a colon.

    ``RtlIsDosDeviceName_U`` stops at whichever comes first, so
    ``CON:stream.yml`` is the console device on Win32. A declared path is
    saved from this by the separate colon refusal in
    ``_validate_relative_path``; a *tree entry* is not screened for colons
    anywhere, and POSIX allows the name, so the sweep is where this one has
    to be caught.

    Trailing spaces are removed after that truncation and not before.
    Without the composition this entry is skipped as an ordinary non-content
    file and the verification passes.

    The portable-name policy refuses it on the colon as well, so the one
    message covers both reasons; the composition itself is asserted directly
    by ``test_the_device_basename_is_derived_the_way_win32_derives_it``.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/CON:stream.yml").write_text("scratch\n")
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        f"tree entry 'rules/CON:stream.yml' {NOT_PORTABLE}: "
        "'CON:stream.yml'"
    )


def test_the_device_basename_is_derived_the_way_win32_derives_it() -> None:
    """Binds S5-F4: the two rules and their order, and what is not a rule.

    Truncate at the first period or colon, then strip trailing spaces. Every
    accepted case below is a name Win32 does *not* resolve to a device, and
    a screen that applied the rules in the other order, or stripped leading
    spaces as well, or stripped anything but spaces, would fail one of them.

    ``CONIN$`` and ``CONOUT$`` are in the table because ``ntdll``'s matcher
    resolves them, although Microsoft's naming page does not list them. The
    table's comment attributes every entry to the source it rests on rather
    than describing itself as a union: S5R2-F10 removed ``COM0`` and
    ``LPT0``, which no source supports at all.
    """

    from receipt._names import (
        WIN32_RESERVED_DEVICE_NAMES,
        _win32_device_basename,
    )

    for name in (
        "NUL.yaml",
        "NUL .yaml",
        "nul  ....",
        "NUL:stream",
        "nul",
        "nul ",
        "COM1 .txt",
        "conin$.log",
    ):
        assert _win32_device_basename(name) in WIN32_RESERVED_DEVICE_NAMES, name
    for name in (
        " NUL.yaml",  # a leading space is not stripped, and Win32 does not
        "nul2.yml",
        "aux-notes.yml",
        "NULL.yaml",
        "nul\t.yml",  # only spaces are stripped, and Win32 strips only spaces
        "notes.yaml",
    ):
        assert _win32_device_basename(name) not in WIN32_RESERVED_DEVICE_NAMES, name


def test_refuses_an_attested_path_the_directory_does_not_spell(
    tmp_path: pathlib.Path,
) -> None:
    """An exact attested lookup does not resolve a case-varied tree name."""

    attested = {**ATTESTED, "readme.md": "# corpus\n"}
    write_tree(tmp_path, attested=attested)
    _commit_worktree(tmp_path)
    object_id = (
        _git(tmp_path, "rev-parse", "HEAD:readme.md").decode("ascii").strip()
    )
    oid = _commit_index_updates(
        tmp_path,
        [
            ("0", None, b"readme.md"),
            ("100644", object_id, b"README.md"),
        ],
    )
    with pytest.raises(CorpusError) as caught:
        _verify_commit(
            tmp_path,
            oid,
            render_journal(journal_rows(attested=attested)),
            spec=corpus_spec(),
        )
    assert str(caught.value) == (
        "bound file is missing or not a regular file: readme.md"
    )


def test_refuses_an_attested_name_stored_under_a_different_normalization(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F1 and the policy: normalization aliases as case does.

    The journal attests the NFC spelling of ``café.md`` and the tree stores
    the NFD one. APFS and HFS+ resolve either spelling to the file they
    hold, so the declared name opened the stored bytes and the digest
    matched; ext4 holds two distinct names and the declared one is simply
    absent — the same corpus, the same journal, two verdicts. S5R2-F1
    settled it by binding the spelling a listing emits.

    The policy settles the *declared* half one step earlier and on every
    host identically: neither spelling is a portable name, so a corpus
    cannot attest either. The spelling walk is what still answers the case
    variation that remains inside the repertoire, which
    ``test_refuses_an_attested_path_the_directory_does_not_spell`` asserts.

    Without the screen the refusal is host-dependent — the spelling walk on
    a resolving host, the missing-file refusal elsewhere — and without
    S5R2-F1 as well the resolving host passes.
    """

    nfc = unicodedata.normalize("NFC", "caf\u00e9.md")
    nfd = unicodedata.normalize("NFD", nfc)
    assert nfc != nfd
    attested = {**ATTESTED, nfc: "# corpus\n"}
    write_tree(tmp_path, attested=attested)
    (tmp_path / nfc).unlink()
    (tmp_path / nfd).write_text("# corpus\n")
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path,
            render_journal(journal_rows(attested=attested)),
            spec=corpus_spec(),
        )
    assert str(caught.value) == (
        f"journal row 5 path {NOT_PORTABLE}: {nfc!r}"
    )


@pytest.mark.parametrize(
    "sibling, why",
    [
        ("toolchain.toml.", "Win32 strips a trailing period before the lookup"),
        ("toolchain.toml ", "and it strips a trailing space the same way"),
    ],
)
def test_refuses_an_unscreened_sibling_of_a_bound_component(
    tmp_path: pathlib.Path,
    sibling: str,
    why: str,
) -> None:
    """Binds S5R4-F1: the sibling scan compared names it never screened.

    S5R3-F3 made this check consume the whole listing and refuse a sibling
    that folds onto the bound component. What it did not do is screen the
    entries it was handed, and the fold key answers exactly one class of
    equivalence — two spellings that differ in case. A spelling a *lookup*
    collapses onto the bound name without collapsing under the fold walked
    straight through: a POSIX tree holding both ``.axiom/toolchain.toml``
    and ``.axiom/toolchain.toml.`` passes, because the exact spelling is
    present and the sibling's fold key differs, while Win32 strips the
    trailing period before it resolves the name and hands back whichever of
    the two it stores — so the witnessed digest covers a file the auditor
    cannot identify. A trailing space is the same story with the other
    character Win32 strips.

    The portable-name screen is what answers both, and it is the screen
    every other listing in this module already runs. Without it this
    verification returns a CorpusVerification over the corpus, on the host
    where the two names coexist and on the host where they do not.

    The sibling is injected into the listing rather than written, so the
    test says the same thing wherever it runs — including on a host whose
    filesystem refuses to store the name at all.
    """

    write_tree(tmp_path)
    oid = _commit_extra_blob(tmp_path, f".axiom/{sibling}".encode("ascii"))
    with pytest.raises(CorpusError) as caught:
        _verify_commit(
            tmp_path,
            oid,
            render_journal(journal_rows()),
            spec=corpus_spec(),
        )
    assert str(caught.value) == (
        f"tree entry '.axiom/{sibling}' {NOT_PORTABLE}: {sibling!r}"
    ), why


def test_refuses_a_required_attested_path_the_directory_does_not_spell(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F1: the requirement is what makes the gap consequential.

    The spec *requires* ``readme.md``, so the consumer has said the corpus is
    not complete without it. On a case-insensitive clone the requirement was
    satisfied by a file named ``README.md``; on a case-sensitive clone of the
    same bytes the requirement can never be satisfied at all. A required
    path whose satisfaction depends on the auditor's filesystem is not a
    requirement, which is why the spelling is bound rather than the
    resolution.

    The assertion is deliberately on the path the refusal names rather than
    on which refusal it is, because the two hosts refuse for different
    reasons and both are correct. That also means this test binds the fix
    only where the declared spelling resolves: on a case-sensitive host the
    pre-existing missing-file refusal satisfies it, and its two siblings
    above assert the mechanism by host. Without the fix the resolving host
    reports the requirement met.
    """

    attested = {**ATTESTED, "readme.md": "# corpus\n"}
    write_tree(tmp_path, attested=attested)
    (tmp_path / "readme.md").unlink()
    (tmp_path / "README.md").write_text("# corpus\n")
    spec = corpus_spec(
        required_attested_paths=frozenset({".axiom/toolchain.toml", "readme.md"})
    )
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(attested=attested)), spec=spec
        )
    assert "readme.md" in str(caught.value)


def test_a_content_file_found_by_its_spelled_name_still_verifies(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F1, the other side: the sweep already spells its own names.

    Every content path in the journal is compared against a set the walk
    built out of ``os.scandir`` names, so a content file that verifies is one
    the listing emitted under exactly that spelling. That is why the spelling
    check is asked of attested paths only: asking it of content too would
    answer a question already answered, at one listing per component per
    file, which for a wide content directory is quadratic and unbudgeted.

    Both halves are asserted — an ordinary corpus verifies, and a content
    file whose on-disk spelling differs from the bound one is refused by the
    sweep itself, on any host, with the spelling walk never consulted.

    This test passes with the fix disabled, which is the point.
    """

    write_tree(tmp_path)
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows()), spec=corpus_spec()
    )
    assert [entry.path for entry in verification.content] == sorted(CONTENT)
    assert [entry.path for entry in verification.attested] == sorted(ATTESTED)

    _commit_worktree(tmp_path)
    object_id = (
        _git(tmp_path, "rev-parse", "HEAD:rules/tax/rate.yaml")
        .decode("ascii")
        .strip()
    )
    oid = _commit_index_updates(
        tmp_path,
        [
            ("0", None, b"rules/tax/rate.yaml"),
            ("100644", object_id, b"rules/tax/RATE.yaml"),
        ],
    )
    with pytest.raises(CorpusError) as caught:
        _verify_commit(
            tmp_path,
            oid,
            render_journal(journal_rows()),
            spec=corpus_spec(),
        )
    assert "not bound by the witnessed journal" in str(caught.value)


@pytest.mark.parametrize("survivor", ["gone.", "gone "])
def test_refuses_a_tombstone_survivor_windows_strips_to_the_tombstoned_name(
    tmp_path: pathlib.Path, survivor: str
) -> None:
    """Binds S5R2-F2: the strip rule reaches tombstone listings too.

    ``retired/gone.`` and ``retired/gone `` open ``retired/gone`` on Win32,
    which removes a trailing dot or space from a component before the
    lookup. Neither of the two questions a tombstone asks can see that: the
    exact ``os.lstat`` of ``retired/gone`` misses on POSIX, and the fold key
    of ``gone.`` is not the fold key of ``gone``, so the survivor sits in a
    different bucket from the one the search reads. Both answered "absent",
    the verdict named the path under removedPaths, and the file still opened
    under the retired name on the host that matters — and no host catches it
    in passing, because the verifier refuses to run on Windows.

    The sweep already refuses such an entry under a content root; this is
    the same rule where a tombstone reads a listing. Without it this
    verification returns a CorpusVerification naming ``retired/gone`` as
    removed.

    Binds the policy for the message, and the two spellings now refuse for
    two different reasons under one wording: ``gone.`` ends in a period,
    which is the third question the screen asks, and ``gone `` carries a
    character the repertoire does not hold.
    """

    body = '{"applied": true}\n'
    rows = _tombstone_rows("retired/gone", body)
    write_tree(tmp_path, attested={**ATTESTED, "retired/gone": body})
    (tmp_path / "retired/gone").unlink()
    (tmp_path / "retired" / survivor).write_text(body)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert str(caught.value) == (
        f"tree entry 'retired/{survivor}' {NOT_PORTABLE}: {survivor!r}"
    )


def test_refuses_a_tree_entry_named_as_an_alternate_data_stream(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F3: a colon in an enumerated name passed every screen.

    ``rules/tax/rate.yaml:payload.txt`` is an ordinary file on POSIX and was
    a perfectly good filename here: it is not under a pinned suffix, its 8.3
    alias extension is ``TXT``, it aliases no other entry by stripping, it
    carries no device basename, and its fold key collides with nothing. So
    the sweep skipped it as non-content. On Win32 the same name opens an
    alternate data stream of ``rules/tax/rate.yaml`` — a file the journal
    binds by digest — and a producer's bytes ride into the tree beside
    witnessed ones without appearing anywhere in the closed world the
    verdict just called closed.

    Declared paths refused a colon from round three and enumerated names
    from Sol round 2, in two rules with two wordings. The colon is outside
    the portable repertoire, so there is one rule and one wording. Without
    it this verification returns a CorpusVerification over the three content
    files and never mentions the stream.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/tax/rate.yaml:payload.txt").write_text("smuggled\n")
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        f"tree entry 'rules/tax/rate.yaml:payload.txt' {NOT_PORTABLE}: "
        "'rate.yaml:payload.txt'"
    )


def test_refuses_a_tombstone_listing_entry_carrying_a_colon(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F3: the tombstone listing screens colons as well.

    A tombstone asks whether any fold-equal spelling of the retired path
    survives. ``retired/gone:stream`` is not fold-equal to ``retired/gone``,
    so the search reported absence — while on Win32 that name is a stream
    of the retired file, which the tombstone says has left the tree. One
    screen serves every listing, so the entry is refused where it is read.

    Without the fix the verification returns with ``retired/gone`` named
    under removedPaths.
    """

    body = '{"applied": true}\n'
    rows = _tombstone_rows("retired/gone", body)
    write_tree(tmp_path, attested={**ATTESTED, "retired/gone": body})
    (tmp_path / "retired/gone").unlink()
    (tmp_path / "retired/gone:stream").write_text(body)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert str(caught.value) == (
        f"tree entry 'retired/gone:stream' {NOT_PORTABLE}: 'gone:stream'"
    )


def test_the_parser_validates_at_most_the_gate_cap_plus_one_declaration(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S5R2-F4: the gate budgets fired only after every row was done.

    Both gate limits were compared once, after the parse loop had finished,
    so a journal of 2,050 gates was decoded and validated in full — every id
    matched against its pattern, every tier and outcome checked, every
    evidence string screened for size and for control characters, twice each
    — and only then refused for a count that was knowable at row 2,049. The
    budgets bounded the verdict and nothing about the work of reaching it.

    Both are enforced as the rows arrive now, so the parser validates at most
    the declaration cap plus one gate. This counts what the per-gate
    validator actually processed. Without the fix the count is 2,050.
    """

    import receipt.corpus as corpus_module

    write_tree(tmp_path)
    gates = [
        {
            "gateId": f"g{index}",
            "tier": "public",
            "outcome": "pass",
            "evidence": {"c": "1"},
        }
        for index in range(MAX_GATE_DECLARATIONS + 2)
    ]
    real = corpus_module._validate_gate
    processed: list[str] = []

    def recording(row, number, spec):  # type: ignore[no-untyped-def]
        processed.append(str(row.get("gateId")))
        return real(row, number, spec)

    monkeypatch.setattr(corpus_module, "_validate_gate", recording)
    with pytest.raises(CorpusError):
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(gates=gates)), spec=corpus_spec()
        )
    assert len(processed) <= MAX_GATE_DECLARATIONS + 1
    assert len(processed) < len(gates)


def test_refuses_a_gate_declaring_more_evidence_entries_than_the_limit(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F4: nothing bounded how many evidence entries one gate held.

    ``MAX_EVIDENCE_TEXT`` caps each key and each value. The cardinality of
    the mapping was capped by nothing at all, so one legal gate row could
    carry an unbounded number of short pairs and every one of them was
    validated — screened for size and for control characters, key and value,
    four passes per entry — before any budget was consulted.

    The limit is checked against ``len(mapping)`` before the first entry is
    looked at, and this journal proves it: one of its entries carries a
    value over ``MAX_EVIDENCE_TEXT``, which is the refusal that would speak
    if any entry were validated first. The cardinality refusal is what comes
    back, so no entry was. Without the fix the oversize refusal speaks
    instead, on the very first entry it screens.
    """

    write_tree(tmp_path)
    evidence = {f"{index:04d}": "x" for index in range(MAX_EVIDENCE_ENTRIES + 1)}
    evidence["0000"] = "y" * (MAX_EVIDENCE_TEXT + 1)
    gates = [
        {"gateId": "g", "tier": "public", "outcome": "pass", "evidence": evidence}
    ]
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(gates=gates)), spec=corpus_spec()
        )
    row = len(CONTENT) + len(ATTESTED) + 1
    assert str(caught.value) == (
        f"journal row {row} gate 'g' declares {len(evidence)} evidence "
        f"entries, over the limit of {MAX_EVIDENCE_ENTRIES}"
    )


def test_refuses_a_row_larger_than_the_parser_budget_before_parsing_it(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S5R3-F8: the row cap bounded how many, never how large.

    ``MAX_JOURNAL_ROWS`` counts line feeds before the split, which bounds the
    number of rows and says nothing about the size of one of them. So a
    single row of arbitrary size was decoded, split out, and handed to
    ``json.loads`` — which materialises the whole object graph the row
    describes — with no budget consulted anywhere on the way.

    ``MAX_JOURNAL_ROW_BYTES`` is checked on the row's own bytes first,
    before the decode, before ``strip`` and before the parse. The oversized
    row is placed first, so the recorder on ``_parse_row`` can assert what
    matters: not that this row was refused before it was parsed, but that
    *nothing* was parsed at all.

    Without it ``_parse_row`` is called and ``json.loads`` runs on a row of
    whatever size the producer chose. The test below this one is the same
    bound one level lower, where S5R4-F4 moved it.
    """

    import receipt.corpus as corpus_module

    parsed: list[int] = []
    real = corpus_module._parse_row

    def recorder(line: str, number: int, spec: object):
        parsed.append(number)
        return real(line, number, spec)  # type: ignore[arg-type]

    monkeypatch.setattr(corpus_module, "_parse_row", recorder)

    filler = "x" * (MAX_JOURNAL_ROW_BYTES + 1)
    huge = json.dumps({"kind": "content", "path": filler}).encode("utf-8")
    assert len(huge) > MAX_JOURNAL_ROW_BYTES
    write_tree(tmp_path)
    journal = huge + b"\n" + render_journal(journal_rows())
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, journal, spec=corpus_spec())
    assert parsed == []
    assert str(caught.value) == (
        f"journal row 1 is {len(huge)} bytes, over the parser budget of "
        f"{MAX_JOURNAL_ROW_BYTES}"
    )


def test_refuses_a_journal_larger_than_the_parser_budget_before_decoding_it(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S5R3-F8, one level up: the decode was the first allocation.

    Every other budget here is measured after ``journal_bytes.decode``, and
    that decode is itself unbounded: a journal of arbitrary size became a
    ``str`` of arbitrary size before the line feeds could be counted.
    ``MAX_JOURNAL_BYTES`` is checked on the raw bytes first.

    The ordering is what this asserts, and it is asserted by handing the
    parser bytes that are *not* valid UTF-8: if the size check runs first the
    refusal names the size, and if it does not the refusal names the
    encoding. The real budget is sixty-four mebibytes — a stated ceiling on
    what a corpus journal may be at all, where it used to be the eight
    gibibytes the two constants below it multiply to (S5R4-F4) — so it is
    lowered here rather than met.

    Without the check this raises "corpus journal is not UTF-8", after
    decoding whatever it was given.
    """

    monkeypatch.setattr("receipt.corpus.MAX_JOURNAL_BYTES", 64)
    write_tree(tmp_path)
    journal = b"\xff" * 200
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, journal, spec=corpus_spec())
    assert str(caught.value) == (
        "corpus journal is 200 bytes, over the parser budget of 64"
    )


def test_refuses_an_oversized_row_before_the_journal_is_decoded(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S5R4-F4: the row bound bound the parse, not the allocation.

    S5R3-F8 added a per-row byte cap and checked it on the decoded text: the
    whole payload was decoded, the whole decoded text was split into rows,
    and only then was the first row measured. So the allocation the cap
    exists to stop had already been made twice over by the time the cap
    spoke, and what it bounded was ``json.loads`` alone.

    The rows are found by splitting the *raw bytes* now, and each row is
    measured as bytes before it is turned into text. What proves the order
    is that the oversized row here is not valid UTF-8: if any decode ran
    first the refusal would name the encoding, and the recorders show that
    neither ``_parse_row`` nor ``json.loads`` was reached at all.

    Without the fix this raises "corpus journal is not UTF-8", after
    allocating a string for every byte the producer sent.
    """

    import receipt.corpus as corpus_module

    parsed: list[int] = []
    loaded: list[str] = []
    monkeypatch.setattr(
        corpus_module,
        "_parse_row",
        lambda line, number, spec: parsed.append(number),
    )
    real_loads = json.loads

    def recording_loads(*arguments, **options):  # type: ignore[no-untyped-def]
        loaded.append("called")
        return real_loads(*arguments, **options)

    monkeypatch.setattr(corpus_module.json, "loads", recording_loads)

    huge = b"\xff" * (MAX_JOURNAL_ROW_BYTES + 1)
    write_tree(tmp_path)
    journal = huge + b"\n" + render_journal(journal_rows())
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, journal, spec=corpus_spec())
    assert parsed == [] and loaded == []
    assert str(caught.value) == (
        f"journal row 1 is {len(huge)} bytes, over the parser budget of "
        f"{MAX_JOURNAL_ROW_BYTES}"
    )


def test_the_total_byte_budget_speaks_before_the_row_budget(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S5R4-F4, the order: the total is the outermost of the three.

    A payload can be over the total *and* carry an oversized row, and which
    refusal speaks says which check ran first. The total is checked on the
    raw bytes before the payload is split, let alone decoded, so it is the
    one that speaks — and it is the only bound that can say anything at all
    about an input that is not a journal.

    The ceiling is lowered here rather than met: sixty-four mebibytes is a
    statement about what a corpus journal may be, not a number a test should
    allocate.

    This ordering held before S5R4-F4 as well, and the test is here because
    of what changed beneath it: the row bound now runs on bytes too, so the
    two checks are asked in the same units and which of them speaks is worth
    pinning.
    """

    monkeypatch.setattr("receipt.corpus.MAX_JOURNAL_BYTES", 256)
    write_tree(tmp_path)
    journal = b"\xff" * 300 + b"\n"
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, journal, spec=corpus_spec())
    assert str(caught.value) == (
        "corpus journal is 301 bytes, over the parser budget of 256"
    )


def test_journal_byte_bounds_and_capacity_ceiling_are_derived_or_stated() -> None:
    """Binds S5R3-F8, S5R4-F4 and S7-F2: which bounds are arithmetic.

    ``MAX_JOURNAL_ROW_BYTES`` is derived from the largest row the schema
    admits — a gate declaration carrying ``MAX_EVIDENCE_ENTRIES`` entries
    whose key and value are each ``MAX_EVIDENCE_TEXT`` characters, with JSON
    free to spell one character in twelve bytes — and the derivation is
    written out beside the constant, so raising ``MAX_EVIDENCE_TEXT`` or
    ``MAX_EVIDENCE_ENTRIES`` without re-deriving the row cap fails here.

    ``MAX_JOURNAL_BYTES`` is not derived from anything. It used to be the
    product of the two constants above, which is eight gibibytes — two worst
    cases no journal reaches at once, and no ceiling at all on an input that
    is not a journal (S5R4-F4). It is a stated ceiling now, asserted far below
    that product. S7-F2 derives the separate consumer-capacity ceiling *from*
    those 64 MiB and the 116-byte minimum valid row; without that derivation
    its new assertion fails or the constant is absent.
    """

    string = 12 * MAX_EVIDENCE_TEXT + 2
    entry = 2 * string + 4
    assert entry == 24584
    assert MAX_EVIDENCE_ENTRIES * entry == 1573376
    assert MAX_JOURNAL_ROW_BYTES == 2097152
    assert MAX_EVIDENCE_ENTRIES * entry <= MAX_JOURNAL_ROW_BYTES
    assert MAX_JOURNAL_BYTES == 64 * 1024 * 1024
    assert MAX_JOURNAL_BYTES < MAX_JOURNAL_ROWS * MAX_JOURNAL_ROW_BYTES
    assert MAX_JOURNAL_ROWS_CEILING == MAX_JOURNAL_BYTES // 116 == 578524
    # And what a journal actually costs: the package's own fixture, which
    # binds four paths and declares three gates.
    assert len(render_journal(journal_rows())) < 2048


def test_a_consumer_can_pin_capacity_for_five_thousand_lifecycle_rows(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S7-F2: the process-global 4,096 cap stranded growing journals.

    One path goes through 1,250 four-row lifecycles: present, revised,
    removed at the revised digest, then present again. The resulting 5,000
    append-only rows leave one current binding whose index is 4,999, and a
    consumer pin of 8,192 admits it. Without S7-F2 ``parse_journal`` still
    consults the global default and refuses before parsing row 4,097.
    """

    relative = "rules/current.yaml"
    original = "value: original\n"
    revised = "value: revised\n"
    current = "value: current\n"
    lifecycle = (
        ("present", sha256_text(original)),
        ("present", sha256_text(revised)),
        ("removed", sha256_text(revised)),
        ("present", sha256_text(current)),
    )
    rows: list[dict[str, object]] = []
    for _ in range(1250):
        for state, digest in lifecycle:
            rows.append(
                {
                    "schemaVersion": JOURNAL_SCHEMA,
                    "entryIndex": len(rows),
                    "kind": "content",
                    "path": relative,
                    "sha256": digest,
                    "state": state,
                }
            )
    assert len(rows) == 5000

    target = tmp_path / relative
    target.parent.mkdir(parents=True)
    target.write_text(current)
    spec = corpus_spec(
        required_attested_paths=frozenset(),
        required_gates=frozenset(),
        journal_row_capacity=8192,
    )
    verification = verify_corpus_binding(
        tmp_path, render_journal(rows), spec=spec
    )

    assert len(verification.content) == 1
    assert verification.content[0].path == relative
    assert verification.content[0].entry_index == 4999
    assert verification.removed_paths == ()


def test_refuses_a_journal_with_more_rows_than_the_parser_budget(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S5R2-F4 and S7-F2: the default still refuses its 4,097th row.

    The gate and removed-path budgets bound what a *valid* journal costs the
    verdict. What an invalid one could make the parser allocate before any
    of them was consulted was bounded by nothing: the whole text was split
    into a list of rows and every row decoded, whatever the count.

    The row count is taken by counting line feeds — which walks the text
    without building the list — and refused before the split, so the
    allocation a journal can ask for is a stated function of its stated
    size. The recorder proves no row was parsed. Without the fix every one
    of these rows is decoded and validated before anything refuses.
    """

    import receipt.corpus as corpus_module

    write_tree(tmp_path)
    spec = corpus_spec()
    assert spec.journal_row_capacity == MAX_JOURNAL_ROWS == 4096
    rows = journal_rows()
    filler = dict(rows[0])
    lines = [json.dumps(row, sort_keys=True) for row in rows]
    lines += [json.dumps(filler, sort_keys=True)] * (
        MAX_JOURNAL_ROWS + 1 - len(lines)
    )
    journal = ("\n".join(lines) + "\n").encode("utf-8")

    parsed: list[int] = []

    def recording(line, number, spec):  # type: ignore[no-untyped-def]
        parsed.append(number)
        raise AssertionError("no row should be parsed")

    monkeypatch.setattr(corpus_module, "_parse_row", recording)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, journal, spec=spec)
    assert parsed == []
    assert str(caught.value) == (
        f"corpus journal carries {MAX_JOURNAL_ROWS + 1} rows, over the "
        f"parser budget of {MAX_JOURNAL_ROWS}"
    )


def test_a_non_ascii_extension_is_not_refused_where_no_pin_can_carry_it(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F5 and the policy: the pins are still filtered first.

    With only ``.yaml`` pinned, no 8.3 alias can carry a pinned suffix at
    all: an alias extension is three characters and ``.yaml`` needs four, so
    the answer for every name in the tree is the same. S5R2-F5 was that the
    extension was derived *before* the unusable pins were filtered out, so
    ``notes.é`` was refused as underivable over a question no pin had put.

    The filter-first order stands and is asserted directly. What the policy
    changes is the example: ``notes.é`` is refused now, by name and on every
    configuration, so the name that shows the order is an ASCII one. An
    ordinary ``notes.yam`` under a four-character pin verifies, which is the
    same property the round-eight exactness fix left, and the predicate is
    asserted beside it so the order is stated rather than inferred.

    Without the filter this file still verifies — the derivation succeeds
    and matches nothing — so the direct assertion is what binds it.
    """

    from receipt.corpus import _short_name_carries_pinned_suffix

    assert not _short_name_carries_pinned_suffix("notes.yam", (".yaml",))
    assert _short_name_carries_pinned_suffix("notes.yamx", (".yam",))
    write_tree(tmp_path)
    (tmp_path / "rules/notes.yam").write_text("scratch\n")
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows()), spec=corpus_spec()
    )
    assert len(verification.content) == len(CONTENT)


def test_a_non_ascii_character_past_the_third_cannot_reach_the_alias(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F5 and the policy: the truncation still comes first.

    An 8.3 extension is three characters, so the fourth character of the
    extension source is dropped before anything else looks at it. S5R2-F5
    was that the whole extension source was screened for non-ASCII before
    the truncation, so ``x.abcé`` — alias extension ``ABC`` on every volume
    there is — was refused as underivable.

    The truncation still runs first, and the derivation is asserted directly
    over the finding's own name, which is the assertion that survives the
    policy: the name itself is refused now, by name, before the sweep asks
    the 8.3 question at all. Both are asserted, so neither the order nor the
    screen can be removed silently.
    """

    from receipt.corpus import _short_name_extension

    assert _short_name_extension("x.abcé") == "ABC"
    write_tree(tmp_path)
    (tmp_path / "rules/x.abcé").write_text("scratch\n")
    spec = corpus_spec(content_suffixes=(".yaml", ".yml"))
    with pytest.raises(CorpusError, match="is not a portable name"):
        verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=spec)


def test_the_derivation_still_lands_on_the_first_three_characters(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F5 and the policy: the 8.3 model still refuses over ASCII.

    ``x.ymlé`` has the alias extension ``YML``, which is a pinned suffix, so
    the file was content under a name no listing emits and the sweep had to
    refuse it — for that reason and not as an underivable one. That is what
    S5R2-F5's truncation-first order bought, and the derivation is still
    asserted directly.

    What the policy keeps is the part that matters to a corpus: an *ASCII*
    name whose alias carries a pinned suffix is still refused by the 8.3
    screen, with the 8.3 screen's own message. ``smuggled.ymlx`` is that
    name, and it is the one the model exists for. The é name is refused by
    the portable-name screen a step earlier, which is asserted too, so which
    screen speaks for which name is pinned rather than assumed.
    """

    from receipt.corpus import _short_name_extension

    assert _short_name_extension("x.ymlé") == "YML"
    write_tree(tmp_path)
    spec = corpus_spec(content_suffixes=(".yaml", ".yml"))

    (tmp_path / "rules/x.ymlé").write_text("scratch\n")
    with pytest.raises(CorpusError, match="is not a portable name"):
        verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=spec)
    (tmp_path / "rules/x.ymlé").unlink()

    (tmp_path / "rules/smuggled.ymlx").write_text("scratch\n")
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=spec)
    assert str(caught.value) == (
        "content root contains a file whose short-name alias would carry a "
        "pinned suffix: 'rules/smuggled.ymlx'"
    )


@pytest.mark.parametrize("name", ["COM0.yaml", "LPT0.yaml", "com0.yml", "lpt0"])
def test_a_zero_numbered_port_is_not_a_reserved_device_name(
    tmp_path: pathlib.Path, name: str
) -> None:
    """Binds S5R2-F10: two entries in the device table rest on no source.

    The table said it took the union of Microsoft's documented list and
    ``ntdll``'s matcher because they disagree. They do disagree — about
    ``CONIN$``, ``CONOUT$`` and the superscripts — but not about zero.
    Microsoft's "Naming Files, Paths, and Namespaces" (fetched 2026-09-03,
    dated 2024-08-28) lists ``COM1`` through ``COM9`` and ``LPT1`` through
    ``LPT9`` and no zero; ``RtlIsDosDeviceName_U`` tests the digit with
    ``if (*end <= '0' || *end > '9') break;`` and so excludes zero as well.
    ``COM0`` and ``LPT0`` were the fail-closed side of a disagreement that
    does not exist, and the cost was real: a corpus holding an ordinary
    ``COM0.yaml`` was refused outright, with a message naming a device
    Windows does not resolve.

    Every spelling here is checked as a tree entry under a content root, so
    the screen really runs on it, and the two ``.yaml`` spellings are bound
    as content so the whole closed world closes over them. Without the fix
    each raises.
    """

    content = dict(CONTENT)
    if name.endswith(".yaml"):
        content[f"rules/{name}"] = "name: port\nvalue: 0\n"
    write_tree(tmp_path, content=content)
    if f"rules/{name}" not in content:
        (tmp_path / "rules" / name).write_text("scratch\n")
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows(content=content)), spec=corpus_spec()
    )
    assert len(verification.content) == len(content)


def test_the_device_table_is_exactly_what_its_two_sources_say() -> None:
    """Binds S5R2-F10: the table is stated, and each entry has an owner.

    Microsoft's page supplies CON, PRN, AUX, NUL, COM1-9, LPT1-9 and the
    six superscript spellings; ``ntdll``'s ``RtlIsDosDeviceName_U`` supplies
    CONIN$ and CONOUT$, which that page does not list. Nothing else is in
    the table, and in particular nothing rests on "the union" of sources
    that were not compared.

    Spelled out here rather than imported from the module, so the shipped
    table is checked against the sentence quoted beside it rather than
    against itself. Without S5R2-F10 the module's table has two more
    entries than this one.
    """

    from receipt.corpus import WIN32_RESERVED_DEVICE_NAMES

    documented = {"CON", "PRN", "AUX", "NUL"}
    documented |= {f"COM{digit}" for digit in "123456789"}
    documented |= {f"LPT{digit}" for digit in "123456789"}
    documented |= {f"COM{superscript}" for superscript in "¹²³"}
    documented |= {f"LPT{superscript}" for superscript in "¹²³"}
    matcher_only = {"CONIN$", "CONOUT$"}
    assert WIN32_RESERVED_DEVICE_NAMES == documented | matcher_only
    assert "COM0" not in WIN32_RESERVED_DEVICE_NAMES
    assert "LPT0" not in WIN32_RESERVED_DEVICE_NAMES


def test_a_real_aliasing_root_spelling_keeps_the_root_component_refusal(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F1, adversarially: the generic refusal must not preempt.

    S5R2-F1 binds every bound path component to the spelling its directory
    emits, and the pinned content root's own components pass through the
    same walk. On a case-insensitive host that made the generic "not spelled
    by its directory" refusal fire for a tree holding ``RULES/`` under a
    ``rules`` pin — preempting ``_assert_no_aliasing_root_component``, which
    asks the same question a line later and names the entry that aliases the
    pinned spelling. The existing test for that wording injects a phantom
    entry into the listing and so never exercised the real case.

    The content-root walk asks the symlink question and not the spelling
    one, because the check a line later says more. This asserts the refusal
    an auditor actually gets, following the host: where the pinned spelling
    resolves to the differently-spelled directory, the aliasing refusal
    names it; where it does not, the root is simply absent.
    """

    write_tree(tmp_path)
    (tmp_path / "rules").rename(tmp_path / "RULES")
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    message = str(caught.value)
    assert message in (
        "tree entry 'RULES' aliases the pinned content root component "
        "'rules' on a case- or normalization-insensitive filesystem",
        "pinned content root is absent from the tree: rules",
    ), message


def test_alias_capability_is_bounded_at_both_ends() -> None:
    """Binds S5R2-F5 and S7-F7: what a pin an alias could carry is.

    An 8.3 extension is one to three characters, so a carryable pin is a
    period and one to three more. Both ends were found the hard way. The
    upper end came from round eight, where comparing the first three
    characters of a longer pin refused an ordinary ``notes.yam`` under a
    ``.yaml`` configuration. The lower end came from the adversarial review
    of S5R2-F5: the schema then accepted a bare ``"."`` as a pin, a derived
    alias extension is never empty, and counting that pin capable made every
    non-ASCII extension under a content root raise the underivability
    refusal for a configuration whose answer is False on every code page.

    The lower end is now a statement rather than a guard, because
    :data:`CONTENT_SUFFIX_RE` admits no pin shorter than two characters —
    which is asserted here too, so removing the guard cannot quietly outlive
    the rule that makes it safe. And the measurement is the written spelling
    again rather than the fold key, which is sound only because a pin is
    ASCII: that is asserted as well.

    S5R4-F5 moved the measurement from a length to a shape, because the
    schema admits interior periods again. ``.tar.gz`` is six characters, so
    a length test would have called it incapable for the wrong reason and a
    six-character pin without a period would have been called incapable
    correctly by accident; what makes ``.tar.gz`` incapable is that an 8.3
    extension is the text after the *last* period and carries none of its
    own. Without the shape rule a pin like ``.a.b`` is compared against a
    derived extension it can never equal.

    S7-F7 records the boundary examples explicitly: ``.a-b`` and ``._``
    match the one-to-three-character alias grammar and are screened, while
    the four-character ``.ssxx`` does not. The old prose claimed the reverse
    for the short pins even though this test and the implementation did not.

    Without the bounds a four-character pin is compared truncated, and a
    bare period is treated as carryable.
    """

    from receipt.corpus import _alias_capable_suffix, _path_fold

    assert not _alias_capable_suffix(".")
    assert _alias_capable_suffix(".y")
    assert _alias_capable_suffix(".yml")
    assert _alias_capable_suffix(".a-b")
    assert _alias_capable_suffix("._")
    assert not _alias_capable_suffix(".yaml")
    assert not _alias_capable_suffix(".ssxx")
    # Four characters after the period, and a second period: neither can be
    # the extension an 8.3 alias carries.
    assert not _alias_capable_suffix(".tar.gz")
    assert not _alias_capable_suffix(".a.b")
    # The schema is what keeps the low end unreachable.
    for degenerate in (".", ""):
        with pytest.raises(CorpusError):
            corpus_spec(content_suffixes=(degenerate,))
    # And ASCII is what makes the written length the folded length.
    for pin in (".y", ".yml", ".YAML", ".t3st"):
        assert len(_path_fold(pin)) == len(pin)
