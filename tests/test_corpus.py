"""Refusal battery for the corpus binding pass.

Each test names one way a producer could publish a journal that does not
describe the tree an auditor cloned, and asserts the binding pass refuses. The
happy-path test is one line; the value is entirely in the refusals.
"""

from __future__ import annotations

import json
import os
import pathlib

import pytest

from receipt.corpus import (
    EVIDENCE_RENDER_OVERHEAD,
    GATE_RENDER_OVERHEAD,
    MAX_EVIDENCE_TEXT,
    MAX_GATE_DECLARATIONS,
    MAX_GATE_TEXT,
    MAX_REMOVED_TEXT,
    CorpusError,
    verify_corpus_binding,
    verify_declarations,
)

from corpus_fixture import (
    ATTESTED,
    CONTENT,
    JOURNAL_SCHEMA,
    corpus_spec,
    journal_rows,
    render_journal,
    sha256_text,
)


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


def test_binding_accepts_a_journal_that_describes_the_tree(tmp_path: pathlib.Path) -> None:
    write_tree(tmp_path)
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows()), spec=corpus_spec()
    )
    assert [entry.path for entry in verification.content] == sorted(CONTENT)
    assert [entry.path for entry in verification.attested] == sorted(ATTESTED)
    assert len(verification.gates) == 3


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


def test_refuses_a_symlinked_directory_of_unwitnessed_rules(
    tmp_path: pathlib.Path,
) -> None:
    """Regression for a demonstrated false PASS (cross-family review).

    rglob does not descend symlinked directories, so a suffix-only symlink
    refusal left a linked tree of rule files invisible to the sweep while any
    consumer that resolves links would read them as verified corpus content.
    Every symlink under a content root must refuse, whatever its name.
    """

    write_tree(tmp_path)
    outside = tmp_path.parent / "smuggled-rules"
    outside.mkdir()
    (outside / "evil.yaml").write_text("name: evil\nvalue: 999\n")
    (tmp_path / "rules/injected").symlink_to(outside)
    with pytest.raises(CorpusError, match="symlink"):
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )


def test_refuses_a_symlink_with_a_non_content_name(tmp_path: pathlib.Path) -> None:
    """Even a symlink named nothing like content refuses — the invariant is
    "no symlinks under a content root", not "no suspicious-looking ones"."""

    write_tree(tmp_path)
    outside = tmp_path.parent / "elsewhere.txt"
    outside.write_text("x\n")
    (tmp_path / "rules/readme.txt").symlink_to(outside)
    with pytest.raises(CorpusError, match="symlink"):
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )


def test_refuses_a_directory_it_cannot_enumerate(tmp_path: pathlib.Path) -> None:
    """Regression: rglob swallows PermissionError while descending, so a
    searchable-but-unlistable directory (mode 0111) contributed nothing to the
    sweep while its files stayed readable by exact path — an unwitnessed rule
    file hid inside it and the corpus still verified. Enumeration failure must
    refuse, not return an empty result."""

    import os

    write_tree(tmp_path)
    hidden = tmp_path / "rules" / "hidden"
    hidden.mkdir()
    (hidden / "evil.yaml").write_text("name: evil\n")
    os.chmod(hidden, 0o111)
    try:
        with pytest.raises(CorpusError, match="cannot enumerate a directory"):
            verify_corpus_binding(
                tmp_path, render_journal(journal_rows()), spec=corpus_spec()
            )
    finally:
        os.chmod(hidden, 0o755)


def test_refuses_a_bound_path_behind_a_symlinked_parent(
    tmp_path: pathlib.Path,
) -> None:
    """Regression: checking only the final component let an intermediate
    directory symlink put an attested file outside the clone while it still
    looked regular and matched its digest."""

    write_tree(tmp_path)
    outside = tmp_path.parent / "ambient"
    outside.mkdir(exist_ok=True)
    (outside / "toolchain.toml").write_text(ATTESTED[".axiom/toolchain.toml"])
    import shutil

    shutil.rmtree(tmp_path / ".axiom")
    (tmp_path / ".axiom").symlink_to(outside)
    with pytest.raises(CorpusError, match="traverses a symlink"):
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


def test_refuses_a_fifo_named_like_content(tmp_path: pathlib.Path) -> None:
    """A FIFO where a rule file is expected is unreadable as content but
    openable by a consumer; the sweep must refuse, not skip it."""

    import os

    write_tree(tmp_path)
    os.mkfifo(tmp_path / "rules/tax/pipe.yaml")
    with pytest.raises(CorpusError, match="non-regular"):
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )


def test_refuses_a_path_with_a_colon(tmp_path: pathlib.Path) -> None:
    """"C:/x" joins drive-absolute under Windows pathlib; refuse everywhere."""

    write_tree(tmp_path)
    rows = journal_rows()
    rows[3]["path"] = "C:/outside.toml"  # the attested row
    with pytest.raises(CorpusError, match="':'"):
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


def test_spec_refuses_an_empty_content_root() -> None:
    with pytest.raises(CorpusError, match="at least one content root"):
        corpus_spec(content_roots=())


def test_spec_refuses_a_content_suffix_carrying_an_unassigned_code_point() -> None:
    """Binds F3: the suffix was checked for its leading dot and nothing else.

    ``_has_pinned_suffix`` folds the pinned suffix against every journal path
    and every tree entry name, and a fold key is stable across Unicode tables
    only for assigned characters. U+0378 has never been assigned, so a spec
    pinning ``.yaml\u0378`` decides what the closed world contains one way on
    the interpreter that encodes it next and another on every interpreter
    today — the consumer's own trust anchor, silently interpreter-dependent.
    Every other name this module folds is screened; this one was not.

    Without the fix the spec constructs and the suffix is folded unexamined.
    """

    import unicodedata

    assert unicodedata.category("\u0378") == "Cn"
    with pytest.raises(CorpusError, match="outside the pinned Unicode") as caught:
        corpus_spec(content_suffixes=(".yaml\u0378",))
    assert str(caught.value).startswith("CorpusSpec content suffix contains")


def test_spec_refuses_a_content_root_carrying_an_unassigned_code_point() -> None:
    """Binds F3, the root half: the same screen, named for the spec.

    A root is folded by ``content_root_of`` for every path the journal binds,
    so an unassigned code point in one has the same effect as in a suffix.
    ``_validate_relative_path`` already refused it, under a label that named
    a path; the screen now runs first and names the spec, because the fault
    is in the consumer's committed code and that is what has to be edited.
    Without the fix the refusal is the path-shaped one.
    """

    with pytest.raises(CorpusError, match="outside the pinned Unicode") as caught:
        corpus_spec(content_roots=(pathlib.PurePosixPath("ru\u0378les"),))
    assert str(caught.value).startswith("CorpusSpec content root contains")


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


def test_refuses_an_empty_content_root_behind_a_symlinked_parent(
    tmp_path: pathlib.Path,
) -> None:
    """A suffix-empty root behind a symlinked parent must not enumerate to an
    empty set and silently pass. (Cross-family review finding.)"""

    write_tree(tmp_path)
    # Nested content root corpus/rules, with corpus a symlink to an ambient dir.
    ambient = tmp_path / "ambient"
    (ambient / "rules").mkdir(parents=True)
    (tmp_path / "corpus").symlink_to("ambient", target_is_directory=True)
    spec = corpus_spec(content_roots=(pathlib.PurePosixPath("corpus/rules"),))
    # Journal binds nothing under corpus/rules; without the parent guard the
    # empty enumeration would match an empty journal content set and pass.
    rows = [r for r in journal_rows() if r.get("kind") != "content"]
    reindex(rows)
    with pytest.raises(CorpusError, match="symlink or reparse point"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=spec)


def test_refuses_a_content_file_inserted_after_first_enumeration(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Closed-world means stable: a file that appears between the first
    enumeration and the post-hash re-enumeration must refuse, not pass."""

    write_tree(tmp_path)
    rows = journal_rows()

    import receipt.corpus as corpus_mod

    real = corpus_mod._tree_content_paths
    calls = {"n": 0}

    def enumerate_then_inject(root: pathlib.Path, spec: object, **passed) -> dict:
        # The closing sweep is handed a directory-generation recorder (R6-F2);
        # it is passed straight through so the stand-in stamps what the real
        # sweep would have stamped.
        result = real(root, spec, **passed)
        calls["n"] += 1
        if calls["n"] == 1:
            # Simulate an unlisted file landing after the closed-world set was
            # taken but before verification finished.
            (root / "rules" / "sneaked.yaml").write_text("name: x\nvalue: 1\n")
        return result

    monkeypatch.setattr(corpus_mod, "_tree_content_paths", enumerate_then_inject)
    with pytest.raises(CorpusError, match="changed during verification"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


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


def test_refuses_a_fifo_at_an_attested_path_without_blocking(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Attested paths sit outside the content roots, so the tree walk never
    screens them — the hashing guard is their only non-regular check. A FIFO
    there must refuse by name, before any open a reader could block on: the
    sentinel turns a reintroduced open into a loud failure, never a hang."""

    import os

    if not hasattr(os, "mkfifo"):
        pytest.skip("platform has no FIFOs")
    write_tree(tmp_path)
    victim = tmp_path / ".axiom/toolchain.toml"
    victim.unlink()
    os.mkfifo(victim)

    real_open = os.open

    def refuse_to_open_the_fifo(
        path: object, flags: int, *args: object, **kwargs: object
    ) -> int:
        assert str(path) != str(victim), (
            "open() reached a FIFO the by-name screen should have refused"
        )
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("os.open", refuse_to_open_the_fifo)
    with pytest.raises(CorpusError, match="not a regular file"):
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )


def test_hashing_opens_non_blocking_and_no_follow(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The open flags are load-bearing: O_NONBLOCK is what keeps a raced FIFO
    from parking the verifier, O_NOFOLLOW (where the platform has it) what
    keeps a raced symlink from being followed. Capture the flags actually
    used for a bound file so removing either one fails here, not in an
    unbounded hang somewhere else."""

    import os

    write_tree(tmp_path)
    captured: list[tuple[str, int]] = []
    real_open = os.open

    def recording_open(
        path: object, flags: int, *args: object, **kwargs: object
    ) -> int:
        captured.append((str(path), flags))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("os.open", recording_open)
    verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=corpus_spec())
    flagged = [flags for path, flags in captured if path.endswith("rate.yaml")]
    assert flagged
    assert all(flags & os.O_NONBLOCK for flags in flagged)
    if hasattr(os, "O_NOFOLLOW"):
        assert all(flags & os.O_NOFOLLOW for flags in flagged)


def test_a_fifo_raced_in_after_the_name_check_refuses_without_blocking(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The window the flags exist for: the name check saw a regular file, the
    open lands on a FIFO. The non-blocking open must return a descriptor
    immediately and fstat must refuse it. The alarm converts a reintroduced
    blocking open into a loud failure instead of a hung suite."""

    import os
    import signal

    if not hasattr(os, "mkfifo"):
        pytest.skip("platform has no FIFOs")
    write_tree(tmp_path)
    victim = tmp_path / ".axiom/toolchain.toml"
    decoy = tmp_path / "decoy-regular-file"
    decoy.write_text("looks fine\n")
    victim.unlink()
    os.mkfifo(victim)

    real_lstat = os.lstat

    def masking_lstat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if str(path) == str(victim):
            return real_lstat(decoy)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr("os.lstat", masking_lstat)

    def blocked(_signum: int, _frame: object) -> None:
        raise RuntimeError("the open blocked: the non-blocking guard is gone")

    previous = signal.signal(signal.SIGALRM, blocked)
    signal.alarm(10)
    try:
        with pytest.raises(CorpusError, match="not a regular file"):
            verify_corpus_binding(
                tmp_path, render_journal(journal_rows()), spec=corpus_spec()
            )
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def test_refuses_a_file_swapped_between_lstat_and_open(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The descriptor must be the file the name check saw. The decoy carries
    the correct bytes, so only the device/inode cross-check can refuse — this
    is the removal detector for that comparison."""

    import os

    write_tree(tmp_path)
    victim = tmp_path / "rules/tax/rate.yaml"
    decoy = tmp_path / "decoy-with-identical-bytes"
    decoy.write_bytes(victim.read_bytes())

    real_open = os.open
    state = {"armed": True}

    def swap_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if state["armed"] and str(path) == str(victim):
            state["armed"] = False
            return real_open(decoy, flags, *args, **kwargs)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("os.open", swap_open)
    with pytest.raises(CorpusError, match="changed identity while being opened"):
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )


def test_refuses_paths_that_alias_under_unicode_normalization_alone(
    tmp_path: pathlib.Path,
) -> None:
    """NFC and NFD spellings of the same name are one file on a normalizing
    filesystem and two on others; a journal listing both is ambiguous
    everywhere, case differences aside entirely."""

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
    with pytest.raises(CorpusError, match="would alias"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def _mutate_after_hashing(
    monkeypatch: pytest.MonkeyPatch, victim_relative: str, mutate: object
) -> None:
    """Run the real digest, then fire ``mutate`` once, right after the victim
    was hashed — the exact window the post-hash sweeps exist to close."""

    import receipt.corpus as corpus_mod

    real = corpus_mod._regular_file_digest
    state = {"armed": True}

    def hash_then_mutate(root: pathlib.Path, relative: str):
        result = real(root, relative)
        if state["armed"] and relative == victim_relative:
            state["armed"] = False
            mutate()
        return result

    monkeypatch.setattr("receipt.corpus._regular_file_digest", hash_then_mutate)


def test_refuses_a_bound_file_rewritten_in_place_after_hashing(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same path, same inode, same size, different bytes, written after the
    digest was taken: membership re-enumeration cannot see it, so the per-file
    identity sweep must."""

    write_tree(tmp_path)
    victim = tmp_path / "rules/tax/rate.yaml"

    def rewrite() -> None:
        tampered = b"name: rate\nvalue: 9.99\n"
        assert len(tampered) == len(victim.read_bytes())
        victim.write_bytes(tampered)

    _mutate_after_hashing(monkeypatch, "rules/tax/rate.yaml", rewrite)
    with pytest.raises(CorpusError, match="changed during verification"):
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )


def test_refuses_a_bound_file_replaced_after_hashing_even_with_identical_bytes(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Replacement with byte-identical content still changes the inode; the
    sweep refuses on identity, not content, so it catches the swap that a
    re-hash would wave through."""

    import os

    write_tree(tmp_path)
    victim = tmp_path / "rules/tax/rate.yaml"

    def replace() -> None:
        before = os.lstat(victim)
        stand_in = tmp_path / "stand-in"
        stand_in.write_bytes(victim.read_bytes())
        os.replace(stand_in, victim)
        # Restore every identity field the sweep compares except the inode,
        # so only the inode comparison can catch this — removing just that
        # comparison from the sweep fails this test.
        os.utime(victim, ns=(before.st_atime_ns, before.st_mtime_ns))
        after = os.lstat(victim)
        assert after.st_ino != before.st_ino
        assert (after.st_dev, after.st_size, after.st_mtime_ns) == (
            before.st_dev,
            before.st_size,
            before.st_mtime_ns,
        )

    _mutate_after_hashing(monkeypatch, "rules/tax/rate.yaml", replace)
    with pytest.raises(CorpusError, match="changed during verification"):
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )


def test_refuses_an_attested_file_removed_after_hashing(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Attested paths sit outside the content roots, so membership
    re-enumeration never sees them; the identity sweep is their only
    post-hash guard and must cover them too."""

    write_tree(tmp_path)
    victim = tmp_path / ".axiom/toolchain.toml"

    _mutate_after_hashing(monkeypatch, ".axiom/toolchain.toml", victim.unlink)
    with pytest.raises(CorpusError, match="disappeared during verification"):
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )


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


def test_refuses_an_unlisted_content_file_whose_suffix_differs_only_by_normalization(
    tmp_path: pathlib.Path,
) -> None:
    """The same escape spelled in Unicode rather than in case.

    A pinned suffix carrying a composed character has a decomposed spelling
    that is byte-different and, on a normalizing filesystem, the same name.
    The sweep folds both before comparing, so neither spelling sits outside
    the closed world.
    """

    import unicodedata

    write_tree(tmp_path)
    spec = corpus_spec(content_suffixes=(".yaml", ".café"))
    decomposed = unicodedata.normalize("NFD", "rules/tax/smuggled.café")
    assert decomposed != "rules/tax/smuggled.café"
    (tmp_path / decomposed).write_text("name: smuggled\n")
    with pytest.raises(CorpusError, match="not bound by the witnessed journal"):
        verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=spec)


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
    """Paths are sanitised by the same helper the evidence strings are.

    Widening that helper to Unicode category Cf widens what a path may spell,
    which is where the format class does its other damage: a zero-width joiner
    makes two rows binding two different files print as one name in the verdict
    an auditor reads.
    """

    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["path"] = "rules/benefit/amo\u200dunt.yaml"
    with pytest.raises(CorpusError, match="Unicode format control"):
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


def test_refuses_a_removed_path_the_verifier_cannot_look_for(
    tmp_path: pathlib.Path,
) -> None:
    """A tombstone nothing could check is not a tombstone honoured.

    Listing a parent that is neither readable nor searchable fails with
    EACCES, not ENOENT, so a removed path swallowed by "any error means gone"
    is reported to the auditor as removed on the strength of a permission
    error while the file sits on disk. Failure to look is not an absence —
    the same rule the sweep applies to a directory it cannot enumerate.
    """

    import os

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
    journal = render_journal(rows)
    os.chmod(tmp_path / "retired", 0o000)
    try:
        with pytest.raises(CorpusError, match="tombstone is unverifiable"):
            verify_corpus_binding(tmp_path, journal, spec=corpus_spec())
    finally:
        os.chmod(tmp_path / "retired", 0o755)


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
    with pytest.raises(CorpusError, match="lone surrogate"):
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

    import os

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
    os.rename(
        tmp_path / "retired/apply-manifest.json",
        tmp_path / "retired/APPLY-MANIFEST.JSON",
    )
    natively_aliased = (tmp_path / "retired/apply-manifest.json").exists()
    with pytest.raises(CorpusError, match="still present in the tree") as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    if natively_aliased:
        assert str(caught.value) == (
            "removed path is still present in the tree: retired/apply-manifest.json"
        )
    else:
        assert "retired/APPLY-MANIFEST.JSON" in str(caught.value)


def test_refuses_an_unlisted_content_file_varied_in_case_and_normalization_at_once(
    tmp_path: pathlib.Path,
) -> None:
    """Casefold can itself produce decomposed text.

    U+00DF followed by U+0301 folds to s, s, U+0301, whose composed form is
    s, U+015B; a pinned suffix spelled with U+015B folded to the composed
    form. One NFC pass before folding left those keys unequal, so a file
    varied in case and normalization at once was not content and escaped
    the sweep. Found by peer review; the fold now normalizes again after
    folding.
    """

    write_tree(tmp_path)
    spec = corpus_spec(content_suffixes=(".yaml", ".s\u015b"))
    (tmp_path / "rules/tax/smuggled.\u00df\u0301").write_text("name: smuggled\n")
    with pytest.raises(CorpusError, match="not bound by the witnessed journal"):
        verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=spec)


def test_refuses_a_format_control_whatever_unicode_table_the_interpreter_carries(
    tmp_path: pathlib.Path,
) -> None:
    """The Cf set is pinned, so the verdict does not depend on the runtime.

    U+1343A is Cf under Unicode 15 and later and unassigned under Unicode 14,
    which Python 3.11 ships, so the same journal was refused on 3.12 and
    accepted on 3.11 (peer review). The module pins Unicode 16.0's Cf set and
    refuses anything in it or anything the running table calls Cf.
    """

    import unicodedata

    from receipt.corpus import _FORMAT_CONTROL_RANGES

    pinned = {
        code for low, high in _FORMAT_CONTROL_RANGES for code in range(low, high + 1)
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
    with pytest.raises(CorpusError, match="over the verdict budget"):
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

    Cardinality is bounded for its own sake now, and checked before the text
    budget because the count is what is wrong with this journal. Without the
    fix it verifies.
    """

    write_tree(tmp_path)
    gates = [
        {
            "gateId": f"g{index}",
            "tier": "public",
            "outcome": "pass",
            "evidence": {"c": "1"},
        }
        for index in range(30000)
    ]
    # What the old charge came to, which is why this journal used to pass.
    assert sum(len(gate["gateId"]) + 2 for gate in gates) < MAX_GATE_TEXT
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(gates=gates)), spec=corpus_spec()
        )
    assert str(caught.value) == (
        f"journal declares {len(gates)} gates, over the verdict budget of "
        f"{MAX_GATE_DECLARATIONS} declarations"
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
    # Every producer string is charged as the verdict renders it (R6-F3), so
    # the arithmetic here goes through json.dumps rather than len — and
    # through the stdlib call the CLI makes, not through the module's own
    # helper, so this stays a measurement of the renderer.
    charged = sum(
        GATE_RENDER_OVERHEAD
        + len(json.dumps(gate["gateId"]))
        + EVIDENCE_RENDER_OVERHEAD
        + len(json.dumps("c"))
        + len(json.dumps("1"))
        for gate in gates
    )
    assert charged > MAX_GATE_TEXT
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(gates=gates)), spec=corpus_spec()
        )
    assert str(caught.value) == (
        f"journal gate declarations cost {charged} characters of verdict "
        f"text, over the verdict budget of {MAX_GATE_TEXT}"
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


def test_refuses_a_removed_path_under_a_symlinked_parent(
    tmp_path: pathlib.Path,
) -> None:
    """An intermediate symlink refuses, for tombstones as for bound paths.

    Following it also made the fold walk unbounded: case-varied links back
    into the same directory branch without end (peer review, round two).
    """

    import os

    import shutil

    body = '{"applied": true}\n'
    attested = dict(ATTESTED)
    attested["links/apply-manifest.json"] = body
    write_tree(tmp_path, attested=attested)
    rows = journal_rows(attested=attested)
    rows.append(
        {
            "schemaVersion": JOURNAL_SCHEMA,
            "kind": "attested",
            "path": "links/apply-manifest.json",
            "sha256": sha256_text(body),
            "state": "removed",
        }
    )
    reindex(rows)
    # The file is gone; its parent is now a link to an empty directory. On a
    # case-insensitive host a case-varied link would be the same entry, so
    # the link is spelled exactly: what is refused is the traversal.
    shutil.rmtree(tmp_path / "links")
    (tmp_path / "retired").mkdir()
    os.symlink("retired", tmp_path / "links")
    with pytest.raises(CorpusError, match="traverses a symlink") as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert "'links'" in str(caught.value)


def test_refuses_a_path_carrying_an_unassigned_code_point(
    tmp_path: pathlib.Path,
) -> None:
    """The fold key is stable only for assigned characters.

    Unicode fixes case folding and normalization once a character is
    encoded and says nothing before, so a path with an unassigned code point
    could alias under one interpreter's table and not another's (peer
    review, round two). U+0378 has never been assigned.
    """

    import unicodedata

    assert unicodedata.category("\u0378") == "Cn"
    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["path"] = "rules/benefit/amo\u0378unt.yaml"
    with pytest.raises(CorpusError, match="outside the pinned Unicode"):
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


def _two_tombstone_rows() -> list[dict[str, object]]:
    """A journal retiring two attested paths inside the same directory."""

    body = '{"applied": true}\n'
    attested = dict(ATTESTED)
    attested[".axiom/a.json"] = body
    attested[".axiom/b.json"] = body
    rows = journal_rows(attested=attested)
    for name in (".axiom/a.json", ".axiom/b.json"):
        rows.append(
            {
                "schemaVersion": JOURNAL_SCHEMA,
                "kind": "attested",
                "path": name,
                "sha256": sha256_text(body),
                "state": "removed",
            }
        )
    return reindex(rows)


def _tombstone_pass_entries(tmp_path: pathlib.Path) -> int:
    """Directory entries the two-tombstone pass must index, counting each once."""

    return len(list(tmp_path.iterdir())) + len(list((tmp_path / ".axiom").iterdir()))


def _tombstone_pass_work(tmp_path: pathlib.Path) -> int:
    """Budget units the *first* two-tombstone pass charges, counting each once.

    Two directories are listed — the tree root and ``.axiom`` — and every
    entry consumed from a listing is one unit. Each of the two searches then
    visits the ``.axiom`` candidate on its way down, and a visited candidate
    is charged as well (F2), which is the two units added here.

    Only the first pass costs this. The second caches nothing (R6-F2), so it
    pays the helper below instead, and both are charged against one budget.
    """

    return _tombstone_pass_entries(tmp_path) + 2


def _uncached_tombstone_pass_work(tmp_path: pathlib.Path) -> int:
    """Budget units the *second* two-tombstone pass charges, sharing nothing.

    The second pass lists every directory afresh for every tombstone, which
    is the point of it: a listing left behind by an earlier search in the
    same pass is exactly the staleness that pass exists to close. So each of
    the two searches pays for both listings itself, plus the one candidate it
    visits on the way down.
    """

    return 2 * (_tombstone_pass_entries(tmp_path) + 1)


def test_the_tombstone_budget_counts_entries_not_listings(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F3: the old budget counted listings and reset per removed path.

    ``MAX_TOMBSTONE_LISTINGS`` was a local counter inside one search, so it
    bounded a single tombstone and said nothing about the pass: R tombstones
    over a root of E entries cost R×E listings with no ceiling on the product.
    The budget now counts entries indexed across the whole pass. Without the
    fix nothing here refuses — the tree is three entries wide.
    """

    write_tree(tmp_path)
    monkeypatch.setattr(
        "receipt.corpus.MAX_TOMBSTONE_WORK", _tombstone_pass_entries(tmp_path) - 1
    )
    with pytest.raises(CorpusError, match="tombstone work budget of") as caught:
        verify_corpus_binding(
            tmp_path, render_journal(_two_tombstone_rows()), spec=corpus_spec()
        )
    assert "tombstone is unverifiable: .axiom/a.json" in str(caught.value)


def test_the_tombstone_index_is_shared_across_removed_paths(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F3: two tombstones must not pay twice for the same directory.

    The budget is set to exactly what the two passes charge between them —
    the first sharing its listings, the second sharing nothing. Both removed
    paths start at the tree root and share their parent, so this passes only
    because the *first* index reads each directory once and hands the listing
    to the second search. Re-listing per removed path there too — what the
    module did before — would push that pass from five to eight and refuse.
    """

    write_tree(tmp_path)
    monkeypatch.setattr(
        "receipt.corpus.MAX_TOMBSTONE_WORK",
        _tombstone_pass_work(tmp_path) + _uncached_tombstone_pass_work(tmp_path),
    )
    verification = verify_corpus_binding(
        tmp_path, render_journal(_two_tombstone_rows()), spec=corpus_spec()
    )
    assert verification.removed_paths == (".axiom/a.json", ".axiom/b.json")


class _NamedEntry:
    """The one attribute the tombstone index reads off a scanned entry.

    ``_TombstoneIndex.folded`` takes ``entry.name`` and builds the child path
    itself, so a declared entry needs nothing more than a name to stand in
    for a real ``os.DirEntry``.
    """

    def __init__(self, name: str) -> None:
        self.name = name


class _Scan:
    """A stand-in for the iterator ``os.scandir`` hands back.

    The tombstone index scans inside a ``with`` block and abandons the
    iterator the moment the budget refuses, so a stand-in has to be a context
    manager and an iterator both. It pulls from the real iterator only as the
    module asks for the next entry, which is the property these tests are
    about: an entry the module never asks for is an entry the host is never
    asked to read.
    """

    def __init__(self, inner=None, *, pulled=None, hidden=(), extra=()) -> None:
        self._inner = inner
        self._pulled = pulled
        self._hidden = frozenset(hidden)
        self._extra = iter([_NamedEntry(name) for name in extra])

    def __enter__(self) -> "_Scan":
        return self

    def __exit__(self, *exc_info: object) -> bool:
        if self._inner is not None:
            self._inner.__exit__(*exc_info)
        return False

    def __iter__(self) -> "_Scan":
        return self

    def __next__(self):
        if self._inner is not None:
            for entry in self._inner:
                if self._pulled is not None:
                    self._pulled.append(entry.name)
                if entry.name not in self._hidden:
                    return entry
        return next(self._extra)


def _scandir(directory_name: str, **reshape):
    """An ``os.scandir`` that reshapes exactly one directory's listing.

    Only the tombstone index scans; the content sweep lists through
    ``pathlib.Path.iterdir``. On 3.13 and 3.14 ``iterdir`` is itself built on
    ``os.scandir``, so the wrapper is scoped by directory name and hands back
    the host's own iterator, untouched, for every other listing.
    """

    real = os.scandir

    def scandir(target):
        if pathlib.PurePath(os.fspath(target)).name != directory_name:
            return real(target)
        return _Scan(real(target), **reshape)

    return scandir


def test_the_tombstone_scan_stops_reading_a_directory_wider_than_its_budget(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F2 (round five): the listing was read whole before the check.

    ``pathlib.Path.iterdir`` materialises the entire directory before it
    yields anything, so a per-entry charge against it bounded only what this
    module did with the names. The read itself — which is the exhaustion an
    adversary plants a wide directory to cause — went ahead in full, and
    round four's test hid that by replacing ``iterdir`` with a lazy
    generator, which is a listing production never has.

    The index now scans with ``os.scandir`` inside a ``with`` and refuses
    from inside the loop, so the iterator is closed early and the entries
    after the one that broke the budget are never pulled. This wrapper hands
    the module the host's real scandir iterator over a directory really on
    disk and counts what the module takes from it: at most one entry past the
    budget, out of two thousand. Without the fix every one of the two
    thousand is read before the refusal.
    """

    width = 2000
    budget = 64
    pulled: list[str] = []
    body = '{"applied": true}\n'
    write_tree(tmp_path)
    wide = tmp_path / "wide"
    wide.mkdir()
    for index in range(width):
        (wide / f"entry-{index:05d}").write_text("")
    rows = _tombstone_rows("wide/apply-manifest.json", body)
    monkeypatch.setattr("receipt.corpus.MAX_TOMBSTONE_WORK", budget)
    monkeypatch.setattr(os, "scandir", _scandir("wide", pulled=pulled))
    with pytest.raises(CorpusError, match="tombstone work budget"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert len(pulled) <= budget + 1
    assert len(pulled) < width


def test_many_tombstones_over_one_cached_bucket_exceed_the_budget(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F2: re-traversing a cached bucket advanced no counter.

    The index reads each directory once, so after the first tombstone every
    later search walks buckets that are already in memory — and those visits
    were free. R tombstones over a bucket of K entries examined R×K candidates
    while the counter stayed at the entries indexed, which for this tree is
    four, so the budget bounded the listings and nothing about the search.

    Forty tombstones share one path here, and each of them re-walks the same
    two cached components. Every visited candidate is now charged against the
    same running total, so the pass refuses part-way through. Without the fix
    it costs four units, the budget of twenty never fires, and the
    verification returns all forty paths as removed.
    """

    body = '{"applied": true}\n'
    write_tree(tmp_path)
    (tmp_path / ".axiom/retired").mkdir(parents=True)
    retired = [f".axiom/retired/gone-{index:03d}.json" for index in range(40)]
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
    monkeypatch.setattr("receipt.corpus.MAX_TOMBSTONE_WORK", 20)
    with pytest.raises(CorpusError, match="tombstone work budget") as caught:
        verify_corpus_binding(
            tmp_path, render_journal(reindex(rows)), spec=corpus_spec()
        )
    assert "tombstone is unverifiable: .axiom/retired/gone-" in str(caught.value)


def _planting_fold_survivor(plant):
    """A ``_fold_survivor`` that changes the tree once, then searches for real.

    The tombstone pass is the longest walk of the tree the verifier does, so
    it is the widest window an adversary with write access to the clone has.
    Firing the change from inside the search is only how that window is made
    to open on every run.
    """

    import receipt.corpus

    real = receipt.corpus._fold_survivor
    fired = []

    def fold_survivor(index, relative):
        if not fired:
            fired.append(relative)
            plant()
        return real(index, relative)

    return fold_survivor


def test_a_content_file_inserted_during_the_tombstone_pass_refuses(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F4: the tombstone pass ran after the last look at the tree.

    Membership was swept once before hashing and re-swept once after, and the
    tombstone walk ran after both. A content file inserted while that walk was
    reading directories was therefore never enumerated: the closed-world claim
    was made over a set that had already changed, and the verdict passed.

    The pass now runs before the hashing, so the re-sweep covers it. Without
    the fix this verification returns a CorpusVerification and the smuggled
    rule file is in the tree it just called closed.
    """

    body = '{"applied": true}\n'
    write_tree(tmp_path)
    rows = _tombstone_rows(".axiom/apply-manifest.json", body)
    monkeypatch.setattr(
        "receipt.corpus._fold_survivor",
        _planting_fold_survivor(
            lambda: (tmp_path / "rules/tax/smuggled.yaml").write_text("name: evil\n")
        ),
    )
    with pytest.raises(CorpusError, match="content tree changed during verification"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_a_bound_file_rewritten_during_the_tombstone_pass_refuses(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F4: the identity re-check ran before the tombstone walk too.

    The per-file identity re-check is what catches a bound file rewritten
    after it was hashed, and it ran before the tombstone pass, so a rewrite
    during that pass kept the verdict of the bytes that were there earlier.
    The verdict then described a tree that no longer existed, which is the one
    thing this module is for.

    With the pass moved ahead of the hashing, the rewrite lands before the
    file is read and the digest itself refuses. Without the fix this
    verification passes.
    """

    body = '{"applied": true}\n'
    write_tree(tmp_path)
    rows = _tombstone_rows(".axiom/apply-manifest.json", body)
    monkeypatch.setattr(
        "receipt.corpus._fold_survivor",
        _planting_fold_survivor(
            lambda: (tmp_path / "rules/tax/rate.yaml").write_text("value: 0.99\n")
        ),
    )
    with pytest.raises(CorpusError, match="does not match its witnessed digest"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def _after_nth_search(after: str, occurrence: int, act):
    """A ``_fold_survivor`` firing ``act`` after the nth search for ``after``.

    The sibling helper above fires *before* the first search of the pass, so
    the change is inside the walk. These tests need the change to land after
    a named removed path has been looked for, which is how the window between
    the two tombstone passes — or between one search and the next inside a
    pass — is opened deterministically. Which path to fire behind is the
    whole design of each test below, so it is named rather than counted.

    Which *pass* is named the same way. A verification searches for every
    removed path twice, so the first search for a path is the first pass's
    and the second is the second pass's; ``occurrence`` picks between them,
    and firing on the second is how a test puts its change inside the pass
    that closes the run (R6-F2).
    """

    import receipt.corpus

    real = receipt.corpus._fold_survivor
    seen: list[str] = []

    def fold_survivor(index, relative):
        found = real(index, relative)
        if relative == after:
            seen.append(relative)
            if len(seen) == occurrence:
                act()
        return found

    return fold_survivor


def _after_searching(after: str, act):
    """Fire ``act`` after the *first* search for ``after`` — the first pass's."""

    return _after_nth_search(after, 1, act)


def _late_survivor_scandir(directory_name: str, survivor: str, planted: list[str]):
    """A scan that reports one more entry once ``planted`` is non-empty.

    The survivor is declared rather than written, and deliberately so: a name
    the host itself resolves is caught by the exact-spelling ``os.lstat``
    whichever pass reaches it first, and on a case-insensitive filesystem
    that is every fold-varied spelling of a real file. Leaving it in the
    listing alone makes the fold search the only thing that can find it, and
    so makes the freshness of the listing the fold search reads the only
    thing the test is about.
    """

    real = os.scandir

    def scandir(target):
        if pathlib.PurePath(os.fspath(target)).name != directory_name:
            return real(target)
        return _Scan(real(target), extra=[survivor] if planted else [])

    return scandir


def test_a_survivor_planted_after_a_shared_parent_was_cached_refuses(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F1 (round five): tombstone absence was never re-established.

    The pass reads each directory once and hands the cached listing to every
    later search, and nothing revalidated it. Nothing after the pass looked
    at a removed path either: the membership re-sweep covers content paths
    and the identity re-check covers bound files. Two tombstones sharing a
    parent is enough to turn that into a false PASS — the first search caches
    the parent, a fold-varied survivor of the second tombstone appears in
    that directory afterwards, and the second search reads the stale listing,
    finds nothing, and the verdict names the path under removedPaths while it
    is there to be opened.

    The change fires after the search for ``.axiom/a.json``, which is exactly
    the moment the shared parent has been cached and ``.axiom/b.json`` has
    not yet been looked for, so the first pass genuinely misses it. The pass
    now runs a second time over an index that has cached nothing, and that is
    what refuses. Without the fix this verification returns a
    CorpusVerification with both paths among its removed paths.
    """

    planted: list[str] = []
    write_tree(tmp_path)
    monkeypatch.setattr(
        os, "scandir", _late_survivor_scandir(".axiom", "B.JSON", planted)
    )
    monkeypatch.setattr(
        "receipt.corpus._fold_survivor",
        _after_searching(".axiom/a.json", lambda: planted.append("B.JSON")),
    )
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(_two_tombstone_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "removed path appeared during verification under a spelling that "
        "aliases it on a case- or normalization-insensitive filesystem: "
        ".axiom/b.json ('.axiom/B.JSON')"
    )


def test_a_removed_file_written_back_after_the_first_pass_refuses(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F1 (round five): the same hole with a real file on disk.

    A tombstoned file that reappears while the verifier works — a checkout, a
    stray build step, anyone with write access to the clone — was reported
    removed, because the tombstone pass ran once and everything after it
    looked at content membership and at the bound bytes instead. The file is
    written back here after the first pass has looked for both tombstones, so
    that pass is honest about the tree it saw and only a second pass can see
    this.

    Which refusal the second pass raises depends on the host: its
    exact-spelling ``os.lstat`` resolves ``.axiom/B.JSON`` on a
    case-insensitive filesystem, and on a case-sensitive one the fold search
    is what finds it. This pins the clause both of them carry, and the path
    they name. Without the fix the verification passes and calls the file
    removed.
    """

    write_tree(tmp_path)
    monkeypatch.setattr(
        "receipt.corpus._fold_survivor",
        _after_searching(
            ".axiom/b.json",
            lambda: (tmp_path / ".axiom/B.JSON").write_text('{"applied": true}\n'),
        ),
    )
    with pytest.raises(CorpusError, match="appeared during verification") as caught:
        verify_corpus_binding(
            tmp_path, render_journal(_two_tombstone_rows()), spec=corpus_spec()
        )
    assert ".axiom/b.json" in str(caught.value)


def test_the_two_tombstone_passes_charge_one_budget(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F1 (round five): the second pass is not a second budget.

    The work budget bounds a verification, not an index. A second index
    starting from zero would let a tree of any width be walked twice for the
    price of the cap once — the pass added to re-establish absence would
    double the very cost the budget exists to bound. The budget here is
    exactly what one pass charges, so the first pass finishes and the second
    refuses on its first charged entry, which happens only if the second
    index starts where the first one stopped.
    """

    write_tree(tmp_path)
    monkeypatch.setattr(
        "receipt.corpus.MAX_TOMBSTONE_WORK", _tombstone_pass_work(tmp_path)
    )
    with pytest.raises(CorpusError, match="tombstone work budget") as caught:
        verify_corpus_binding(
            tmp_path, render_journal(_two_tombstone_rows()), spec=corpus_spec()
        )
    assert "tombstone is unverifiable: .axiom/a.json" in str(caught.value)


class _PlainDirectory:
    """What ``lstat`` says about an ordinary directory.

    Enough of a ``stat_result`` for the tombstone search, which reads the mode
    to decide the entry is neither a symlink nor a reparse point.
    """

    st_mode = 0o040755
    st_reparse_tag = 0


class _CaseFoldingPath:
    """A path object that compares and hashes case-insensitively, as Windows does.

    ``pathlib.WindowsPath`` folds case in ``__eq__`` and ``__hash__`` — that is
    the platform's own rule, not an approximation — so two spellings of one
    name are a single dict key there. NTFS carries an opt-in per-directory
    case-sensitivity flag, so those two spellings can be two real directories
    at the same time. No POSIX host can hold both, which is why the listings
    here are declared rather than written to disk.

    Only what the tombstone pass touches is modelled: the ``__fspath__`` the
    scan is given and the ``__truediv__`` the index builds children with,
    ``name``, and an ``lstat`` that reports a plain directory.
    """

    def __init__(self, spelling: str, listings: dict[str, list[str]]) -> None:
        self.spelling = spelling
        self.listings = listings

    @property
    def name(self) -> str:
        return self.spelling.rsplit("/", 1)[-1]

    def __fspath__(self) -> str:
        return self.spelling

    def __truediv__(self, name: str) -> "_CaseFoldingPath":
        return _CaseFoldingPath(
            f"{self.spelling}/{name}" if self.spelling else name, self.listings
        )

    def lstat(self) -> _PlainDirectory:
        return _PlainDirectory()

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, _CaseFoldingPath)
            and self.spelling.lower() == other.spelling.lower()
        )

    def __hash__(self) -> int:
        return hash(self.spelling.lower())


def _declared_scandir(listings: dict[str, list[str]]):
    """An ``os.scandir`` serving listings no POSIX host could hold at once.

    Keyed by the exact spelling the scanned object reports through
    ``__fspath__``, so the stand-in distinguishes the two directories the
    test is about and the index has to distinguish them for itself.
    """

    def scandir(target):
        spelling = os.fspath(target)
        if spelling not in listings:
            raise FileNotFoundError(spelling)
        return _Scan(extra=listings[spelling])

    return scandir


def test_the_tombstone_index_keys_two_case_varied_directories_apart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Binds F1: the listing cache was keyed by a path object.

    ``pathlib.Path`` equality and hashing ignore case on Windows, so an empty
    ``A/`` and a populated ``a/`` shared one cache entry there. Whichever was
    listed first answered for both: the empty one cached as ``A``'s listing was
    returned for ``a``, the fold search found no survivor, and a tombstone for
    ``A/target`` passed while ``a/TARGET`` sat on disk under a spelling that
    opens the tombstoned name on the very filesystems this search models.

    The cache is keyed by the exact spelling the walk used. Without the fix the
    second ``folded`` call returns the first call's listing and the survivor is
    never found.
    """

    from receipt.corpus import _fold_survivor, _TombstoneIndex

    listings = {"": ["A", "a"], "A": [], "a": ["TARGET"]}
    monkeypatch.setattr(os, "scandir", _declared_scandir(listings))
    root = _CaseFoldingPath("", listings)
    index = _TombstoneIndex(root)

    upper = index.folded(_CaseFoldingPath("A", listings), "A", "A/target")
    lower = index.folded(_CaseFoldingPath("a", listings), "a", "A/target")
    assert upper == {}
    assert list(lower) == ["target"]

    assert _fold_survivor(index, "A/target") == "a/TARGET"


def test_refuses_a_declared_path_with_a_trailing_dot_component(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F1: Win32 strips trailing dots before the lookup.

    ``rules/tax/rate.yaml.`` and ``rules/tax/rate.yaml`` are one file there,
    and no listing emits the dotted spelling, so nothing in the fold model
    can pair them. A declared path spelled that way is refused instead.
    Without the fix it is an ordinary path and binds a second row against the
    same file.
    """

    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["path"] = "rules/benefit/amount.yaml."
    with pytest.raises(CorpusError, match="component Windows would alias"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_declared_path_with_a_trailing_space_component(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F1: the same lookup strips trailing spaces.

    A directory component is enough — the alias need not be the file itself.
    Without the fix the path validates and the trailing space is invisible in
    every rendered verdict.
    """

    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["path"] = "rules/benefit /amount.yaml"
    with pytest.raises(CorpusError, match="component Windows would alias"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_refuses_a_declared_path_shaped_like_an_8_3_short_name(
    tmp_path: pathlib.Path,
) -> None:
    """Binds F1: NTFS hands out 8.3 short names that open the long name.

    ``RULESF~1.YAM`` is not emitted by any listing, so the fold model cannot
    pair it with the long name it opens. Refused at the schema boundary; a
    path of that shape but too long to be a short name is left alone, which
    is what the second half asserts.
    """

    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["path"] = "rules/RULESF~1.YAM"
    with pytest.raises(CorpusError, match="component Windows would alias"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())

    rows = journal_rows()
    rows[0]["path"] = "rules/benefit/long~1name.yaml"
    with pytest.raises(CorpusError, match="not bound by the witnessed journal") as other:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert "Windows would alias" not in str(other.value)


def _hiding_scandir(directory_name: str, hidden: str):
    """A scan that omits one entry, the way Win32 lookup aliases behave.

    Win32 resolves names no enumeration emits: it strips trailing dots and
    spaces before a lookup, and NTFS answers to 8.3 short names. No POSIX host
    does either, so the only way to put a verifier on this machine in front of
    that filesystem is to hide from the listing a name the OS still resolves.
    That is the whole premise of F1, and it is what this wrapper models.
    """

    return _scandir(directory_name, hidden=[hidden])


def test_a_tombstoned_path_the_listing_hides_but_the_host_resolves_refuses(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F1: absence read off a listing is not absence.

    _fold_survivor decided whether a removed path survived from the names
    ``iterdir`` emits, and Win32 lookup resolves names enumeration never emits.
    So a retired apply manifest that still opens under the tombstoned spelling
    was reported gone, the tombstone was honoured, and the verdict listed the
    path under removedPaths while the file sat on disk.

    The exact-path ``os.lstat`` now runs before the fold search, letting the
    host that is actually running answer for its own lookup rules. Without it
    this verification passes and returns the path as removed.
    """

    body = '{"applied": true}\n'
    write_tree(tmp_path)
    (tmp_path / "retired").mkdir()
    (tmp_path / "retired/apply-manifest.json").write_text(body)
    rows = _tombstone_rows("retired/apply-manifest.json", body)
    monkeypatch.setattr(
        os, "scandir", _hiding_scandir("retired", "apply-manifest.json")
    )
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert str(caught.value) == (
        "removed path is still present in the tree: retired/apply-manifest.json"
    )


def _mutating_scandir(directory_name: str, mutate):
    """A scan that changes the tree after reading it, deterministically.

    The window between reading a directory's names and stat-ing an entry one
    of them named is a real one; taking the whole listing here and firing the
    mutation before the module is handed its first entry is only how that
    window is made to open on every run.

    Once, though. The tombstone pass reads this directory again on its second
    run (F1), and a mutation that fired a second time would either fail or
    describe a tree the test never meant to build.
    """

    real = os.scandir
    fired: list[str] = []

    def scandir(target):
        directory = pathlib.Path(os.fspath(target))
        if directory.name != directory_name or fired:
            return real(target)
        with real(target) as entries:
            names = [entry.name for entry in entries]
        fired.append(directory_name)
        mutate(directory)
        return _Scan(extra=names)

    return scandir


def test_a_tombstone_entry_that_vanishes_after_the_listing_is_not_a_survivor(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F7: a listed entry may be gone by the time it is stat-ed.

    ``entry.lstat()`` sat outside the ``except OSError`` arm, so a directory
    deleted between the listing and the probe raised FileNotFoundError out of
    the verifier. Without the fix this test errors with FileNotFoundError;
    with it the entry is simply not a survivor, and the tombstone — whose path
    really is gone — is honoured.
    """

    body = '{"applied": true}\n'
    write_tree(tmp_path)
    (tmp_path / "retired/vanishing").mkdir(parents=True)
    rows = _tombstone_rows("retired/vanishing/apply-manifest.json", body)
    monkeypatch.setattr(
        os,
        "scandir",
        _mutating_scandir("retired", lambda d: (d / "vanishing").rmdir()),
    )
    verification = verify_corpus_binding(
        tmp_path, render_journal(rows), spec=corpus_spec()
    )
    assert verification.removed_paths == ("retired/vanishing/apply-manifest.json",)


def test_a_tombstone_entry_that_cannot_be_stat_after_the_listing_refuses(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F7: the same probe leaked PermissionError.

    A directory that is readable but not searchable lists fine and refuses
    every stat of a child. The permission drops after the listing here, so the
    exact-path probe has already returned ENOENT and the fold search is the
    one that meets the error. Without the fix it is a bare PermissionError out
    of the verifier; with it, the module's own rule applies — a failure to
    look is not an absence.
    """

    import os

    body = '{"applied": true}\n'
    write_tree(tmp_path)
    (tmp_path / "retired/sub").mkdir(parents=True)
    rows = _tombstone_rows("retired/sub/apply-manifest.json", body)
    monkeypatch.setattr(
        os,
        "scandir",
        _mutating_scandir("retired", lambda d: os.chmod(d, 0o444)),
    )
    try:
        with pytest.raises(CorpusError, match="tombstone is unverifiable"):
            verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    finally:
        os.chmod(tmp_path / "retired", 0o755)


def _listing_with(directory_name: str, extra: str):
    """An ``iterdir`` that reports one more entry than the content sweep holds.

    APFS refuses to create a filename carrying an unassigned code point at
    all — the ``open`` fails with EILSEQ — while ext4 and NTFS store the bytes
    without comment. The verifier has to hold on the filesystems that allow
    the name, so on this host the name reaches the sweep through the listing
    rather than through the disk.
    """

    real = pathlib.Path.iterdir

    def iterdir(self: pathlib.Path):
        entries = list(real(self))
        if self.name == directory_name:
            entries.append(self / extra)
        return iter(entries)

    return iterdir


def test_refuses_a_tree_entry_carrying_an_unassigned_code_point(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F2: entry names were folded without being screened.

    Declared paths refuse an unassigned code point because the fold key is
    only stable across Unicode tables for assigned characters. Filesystem
    entry names went straight into the same fold — U+A7CB folds to U+0264 on
    Unicode 16 and to itself before it — so whether the sweep called a file
    content, and so whether the closed world contained it, depended on the
    verifier's interpreter rather than on the tree.

    The screen has to run before anything else looks at the entry, and that
    is what this pins: without it the name is folded, found to carry no
    pinned suffix or to be no regular file, and the refusal is a different
    one or none at all.
    """

    import unicodedata

    assert unicodedata.category("͸") == "Cn"
    write_tree(tmp_path)
    monkeypatch.setattr(pathlib.Path, "iterdir", _listing_with("tax", "notes͸"))
    with pytest.raises(CorpusError, match="outside the pinned Unicode") as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert "tree entry 'rules/tax/notes" in str(caught.value)


def test_refuses_an_unassigned_code_point_in_a_tombstone_listing(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F2: the tombstone search folds entry names too.

    The fold search buckets every name in a directory by fold key to decide
    whether a removed path survives under an aliasing spelling. An unassigned
    code point lands in one bucket on one interpreter and another on the next,
    so the same tree honours the tombstone under one Python and refuses under
    another. The index reads nothing but the name, so an injected entry is
    exactly what a real one would be here: without the screen the name folds
    unexamined, no survivor is found, and this verification passes.
    """

    body = '{"applied": true}\n'
    write_tree(tmp_path)
    (tmp_path / "retired").mkdir()
    rows = _tombstone_rows("retired/apply-manifest.json", body)
    monkeypatch.setattr(os, "scandir", _scandir("retired", extra=["sibling͸"]))
    with pytest.raises(CorpusError, match="outside the pinned Unicode") as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert "tree entry examined for a tombstone" in str(caught.value)


def test_refuses_a_path_carrying_a_code_point_the_pinned_table_lacks(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F5: the screen consulted the running table, so it moved.

    ``_assert_assigned`` exists to make the fold key mean one thing on every
    supported interpreter. Deciding "assigned" from the *running* table gave
    it the same defect facing the other way: U+A7CB is unassigned in Unicode
    14.0 and 15.1 — Python 3.11 through 3.13 — and assigned in 16.0, which
    3.14 ships, where it folds to U+0264. So a journal carrying it was
    refused on three supported interpreters and accepted on the fourth, and
    the acceptance the screen promises to make stable was itself a function
    of which Python the auditor happened to run.

    The repertoire is pinned to Unicode 14.0 now, so this refuses everywhere.
    Without the fix this test fails on 3.14 — the path verifies and folds to
    a key three of the four supported interpreters would not produce — and
    passes on 3.11 through 3.13 for the wrong reason, which is the finding.
    """

    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["path"] = "rules/benefit/amo\ua7cbunt.yaml"
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    # The quoted spelling is not pinned: ``_quoted`` is ``repr``, and repr
    # prints a character the *running* table calls assigned and escapes one
    # it does not — so the same path reads back differently on 3.13 and
    # 3.14. What is pinned is the refusal, which no longer does.
    assert str(caught.value).startswith(
        "journal row 1 path contains a code point outside the pinned "
        "Unicode 14.0 repertoire (0xa7cb): "
    )
    assert "amo" in str(caught.value) and "unt.yaml" in str(caught.value)


def test_a_character_assigned_in_the_pinned_table_still_verifies(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F5, the other side: the pin must not shrink the repertoire.

    U+1FAF6 HEART HANDS was encoded in Unicode 14.0, which is the pinned
    table, so it is inside the repertoire on every supported interpreter and
    a corpus may name a file with it. A pin taken from a table *older* than
    the oldest supported interpreter, or a generator that mistook an
    assigned block for an unassigned one, would refuse this and every
    refusal test above would still pass.

    The file is real, so the name goes through the sweep's screen as well as
    the journal's. This test passes on the head too — it is a control, not a
    regression.
    """

    content = dict(CONTENT)
    content["rules/tax/\U0001faf6.yaml"] = "name: hands\nvalue: 1\n"
    write_tree(tmp_path, content=content)
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows(content=content)), spec=corpus_spec()
    )
    assert "rules/tax/\U0001faf6.yaml" in [entry.path for entry in verification.content]


def test_the_pinned_repertoire_decides_each_class_of_code_point() -> None:
    """Binds S4-F5: the three answers the pin has to give, stated together.

    A code point no table has ever assigned (U+0378) refuses. One assigned
    after the pinned table (U+A7CB, Unicode 16.0) refuses, because the
    question is what Unicode 14.0 knew and not what this interpreter knows.
    One assigned by the pinned table (U+1FAF6, Unicode 14.0) is accepted.

    Without the fix the middle answer is whatever the running interpreter
    says, which is the whole finding: on 3.14 it is "accepted".
    """

    import unicodedata

    from receipt.corpus import _assert_assigned

    for code in (0x0378, 0xA7CB):
        with pytest.raises(CorpusError) as caught:
            _assert_assigned(f"x{chr(code)}y", "label")
        assert str(caught.value).startswith(
            f"label contains a code point outside the pinned Unicode 14.0 "
            f"repertoire ({code:#06x})"
        )
    assert _assert_assigned("x\U0001faf6y", "label") == "x\U0001faf6y"
    # The running table's own answer, recorded so the reason the middle case
    # exists stays legible when the table moves again: U+A7CB is Cn until
    # Unicode 16.0, which is what the old screen consulted.
    running = tuple(int(part) for part in unicodedata.unidata_version.split("."))
    assert (unicodedata.category(chr(0xA7CB)) == "Cn") == (running < (16,))


def test_the_shipped_repertoire_is_what_its_generator_produces() -> None:
    """Binds S4-F5: the pinned data must be checkable, not merely asserted.

    ``generate_unassigned_ranges`` is the script that produced the shipped
    tuple, kept in the module so this test can re-run it. On an interpreter
    carrying Unicode 14.0 — CI's 3.11 job — the two must be equal. On any
    later table the generator returns a strict subset, which is the superset
    property the pin relies on rather than a disagreement, so the comparison
    is skipped there with that reason.
    """

    import unicodedata

    from receipt._unicode_repertoire import (
        UNASSIGNED_RANGES,
        UNIDATA_VERSION,
        generate_unassigned_ranges,
    )

    running = unicodedata.unidata_version
    if running != UNIDATA_VERSION:
        regenerated = generate_unassigned_ranges()
        pinned = {
            code
            for first, last in UNASSIGNED_RANGES
            for code in range(first, last + 1)
        }
        running_set = {
            code for first, last in regenerated for code in range(first, last + 1)
        }
        # The property that makes pinning safe, checked on the interpreter
        # that is actually running: nothing this table calls unassigned is
        # outside the pinned set.
        assert running_set <= pinned
        pytest.skip(
            f"the running Unicode table is {running}, not {UNIDATA_VERSION}; "
            "the generator reproduces the shipped tuple only on the pinned "
            "table, and the superset property was checked instead"
        )
    assert generate_unassigned_ranges() == UNASSIGNED_RANGES


def test_the_shipped_repertoire_is_sorted_disjoint_and_in_range() -> None:
    """Binds S4-F5: the bisect in ``is_unassigned`` assumes all three.

    ``is_unassigned`` finds the last range starting at or below a code point
    and looks no further, which is only correct for ranges that are sorted
    and do not overlap. Adjacency is checked too: two touching ranges would
    mean the generator emitted what should have been one, and a hand edit
    that split a range is exactly the kind of change this catches.
    """

    from receipt._unicode_repertoire import UNASSIGNED_RANGES, is_unassigned

    assert UNASSIGNED_RANGES
    previous = -1
    for first, last in UNASSIGNED_RANGES:
        assert 0 <= first <= last <= 0x10FFFF
        assert first > previous + 1
        previous = last
    # The lookup agrees with a scan at every boundary, including the ends.
    for first, last in UNASSIGNED_RANGES:
        assert is_unassigned(first) and is_unassigned(last)
        if first > 0:
            assert not is_unassigned(first - 1)
        if last < 0x10FFFF:
            assert not is_unassigned(last + 1)
    # U+10FFFF is itself a noncharacter and so ``Cn``; the assigned side is
    # checked with characters the pinned table encodes.
    assert not is_unassigned(ord("a"))
    assert not is_unassigned(0x1FAF6)


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
    """

    forged = "\x1b[2K\rVERDICT: PASS"
    write_tree(tmp_path)
    (tmp_path / "rules/tax" / forged).symlink_to(tmp_path / "rules/tax/rate.yaml")
    with pytest.raises(CorpusError, match="contains a symlink") as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    message = str(caught.value)
    assert "\x1b" not in message and "\r" not in message
    assert "\\x1b[2K\\rVERDICT: PASS" in message


def test_refuses_a_directory_reparse_point_under_a_content_root(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F5: a Windows junction is not a symlink and was descended.

    The sweep asked ``is_symlink()``, which answers for POSIX symlinks only.
    On Windows a junction, and every other directory reparse point, reports
    ``False`` there while redirecting the walk somewhere else entirely — so a
    directory under a content root could be a link into an ambient tree, and
    the sweep would descend it, hash whatever it found, and call the closed
    world closed. ``st_reparse_tag`` is how Windows reports one, and it is the test
    ``_assert_no_symlinked_component`` already applies to a bound path.

    No POSIX host can create a reparse point, so the ``lstat`` for one entry
    is answered here the way Windows would answer it. Without the fix the
    walk descends and the refusal names the file inside instead — that is,
    the junction itself is accepted as an ordinary directory.
    """

    import stat
    import types

    write_tree(tmp_path)
    junction = tmp_path / "rules/junction"
    junction.mkdir()
    (junction / "evil.yaml").write_text("name: evil\n")
    real = pathlib.Path.lstat

    def lstat(self: pathlib.Path, *args: object, **kwargs: object):
        if self == junction:
            # IO_REPARSE_TAG_MOUNT_POINT, the tag a junction carries.
            return types.SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o755, st_reparse_tag=0xA0000003
            )
        return real(self, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, "lstat", lstat)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "content root contains a symlink or reparse point: 'rules/junction'"
    )


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
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds F6: the refusal a case-sensitive host raises, pinned on any host.

    A case-insensitive filesystem cannot hold ``rules`` and ``RULES`` at once,
    so the test above reaches the unlisted-file refusal here and the
    aliasing-root-component refusal only on a case-sensitive host. The entry
    is injected into the tree root's listing so the branch — and its exact
    wording, which an auditor has to act on — is covered everywhere.
    """

    real = pathlib.Path.iterdir

    def iterdir(self: pathlib.Path):
        entries = list(real(self))
        if self == tmp_path:
            entries.append(self / "RULES")
        return iter(entries)

    write_tree(tmp_path)
    monkeypatch.setattr(pathlib.Path, "iterdir", iterdir)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
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


def test_refuses_a_short_name_alias_hidden_behind_an_embedded_space(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F1: the extension was truncated before the 8.3 rules ran.

    Win32 removes every space from a name *before* it truncates the
    extension to three characters, so with ``.yml`` pinned the file emitted
    as ``smuggled.y mlx`` is handed the alias ``SMUGGL~1.YML`` and that
    alias opens the same bytes. The screen read the written extension
    instead — ``y mlx``, first three characters ``Y M`` — decided the alias
    could not carry a pinned suffix, and let the long name be skipped as
    non-content. The closed world the verdict then called closed held a file
    reachable under a content name.

    Without the fix this verification returns a CorpusVerification with the
    file sitting in the tree, unbound.
    """

    _refuses_short_name_alias(tmp_path, "smuggled.y mlx")


def test_refuses_a_short_name_alias_hidden_behind_several_spaces(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F1: one space was not the bound; every space is removed.

    ``smuggled.y m l x`` carries three of them, and the alias Win32 derives
    is the same ``SMUGGL~1.YML``. Pinned separately from its sibling because
    a fix that dropped only the first space, or only a leading one, would
    satisfy that test and leave this hole open. Without the fix the written
    extension truncates to ``Y M`` again and the file is skipped.
    """

    _refuses_short_name_alias(tmp_path, "smuggled.y m l x")


def test_refuses_a_short_name_alias_whose_space_precedes_the_dot(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F1: the removal happens before the period is located, too.

    ``smuggled . yml`` is not content by suffix — its last four characters
    are ``" yml"``, not ``".yml"`` — and it does not end in a dot or a
    space, so the stripping screen does not reach it either. Win32 removes
    both spaces first and then finds the period, so the alias is
    ``SMUGGL~1.YML``. Without the fix the written extension is ``" yml"``,
    truncating to ``" YM"``, and the file is skipped as non-content.
    """

    _refuses_short_name_alias(tmp_path, "smuggled . yml")


def test_a_short_name_extension_mapping_a_non_ascii_character_still_verifies(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S4-F1, the other side: the character mapping is pinned, not guessed.

    8.3 generation cannot hold a character outside its own small set, and
    substitutes an underscore for one. So ``smuggled.ÿml`` is handed the
    extension ``_ML`` — or ``Y_M`` where the host stores the name
    decomposed, since the combining mark maps to the underscore instead —
    and neither is ``.YML``. The file is not content under either name and
    the verification stands.

    Pinned as an acceptance rather than left to chance: a screen that mapped
    every unrepresentable character to *nothing* rather than to an
    underscore would read this name as ``.YML`` and refuse a corpus that is
    exactly what it claims to be, and every refusal test above would still
    pass. This test passes on the head as well, which is the point — the
    mapping must not over-refuse either.
    """

    write_tree(tmp_path)
    (tmp_path / "rules" / "smuggled.ÿml").write_text("name: smuggled\n")
    spec = corpus_spec(content_suffixes=(".yaml", ".yml"))
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows()), spec=spec
    )
    assert len(verification.content) == len(CONTENT)


def test_refuses_a_tree_entry_whose_name_windows_would_strip(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
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
    Without the fix the entry falls through to the ``lstat``, which fails,
    and the refusal is the non-regular-file one instead.
    """

    write_tree(tmp_path)
    monkeypatch.setattr(pathlib.Path, "iterdir", _listing_with("tax", "notes.yaml."))
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "content root contains an entry Windows would alias: "
        "'rules/tax/notes.yaml.'"
    )


def test_refuses_an_entry_beside_a_root_component_windows_would_strip(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R6-F1: the same strip decides which directory *is* the root.

    ``rules `` beside the pinned ``rules`` is the content root on Windows —
    the lookup strips the space — so a producer can fill it with rule files
    that a POSIX verifier never sweeps, because the walk descends the
    spelling the spec pinned and the fold check beside it cannot pair two
    names that are not fold-equal. The aliasing-root-component guard now asks
    the strip question as well as the fold question.

    Injected into the tree root's listing so the branch is covered on every
    host. Without the fix nothing here refuses: the entry is not fold-equal
    to ``rules``, the sweep never descends it, and the verification passes.
    """

    real = pathlib.Path.iterdir

    def iterdir(self: pathlib.Path):
        entries = list(real(self))
        if self == tmp_path:
            entries.append(self / "rules ")
        return iter(entries)

    write_tree(tmp_path)
    monkeypatch.setattr(pathlib.Path, "iterdir", iterdir)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "content root contains an entry Windows would alias: 'rules '"
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


def test_a_survivor_planted_inside_the_second_tombstone_pass_refuses(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R6-F2: the second pass repeated the first pass's own staleness.

    Round five gave the second pass a fresh index, which closed the window
    the first pass left open. It did not close the same window *inside*
    itself: a fresh index that still cached listed the shared parent once for
    the first tombstone and handed that listing to every tombstone after it.
    So the defect the second pass exists to refuse — a survivor appearing
    after its parent has been listed, with another tombstone still to be
    checked under it — survived one pass later, and the verdict still named
    the path under removedPaths while the file answered to it.

    The change fires after the *second* pass's search for ``.axiom/a.json``,
    which is exactly when that pass has cached the shared parent and has not
    yet looked for ``.axiom/b.json``. The index now caches nothing, so the
    second search lists ``.axiom`` again and finds the survivor. Without the
    fix it reads the listing the first search left behind, finds nothing, and
    the verification returns both paths as removed.

    The survivor is declared rather than written, for the reason
    ``_late_survivor_scandir`` gives, and it is also what isolates this
    finding from its sibling: a name that is not on disk moves no directory's
    mtime, so the generation check below cannot be what refuses here.
    """

    planted: list[str] = []
    write_tree(tmp_path)
    monkeypatch.setattr(
        os, "scandir", _late_survivor_scandir(".axiom", "B.JSON", planted)
    )
    monkeypatch.setattr(
        "receipt.corpus._fold_survivor",
        _after_nth_search(".axiom/a.json", 2, lambda: planted.append("B.JSON")),
    )
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(_two_tombstone_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "removed path appeared during verification under a spelling that "
        "aliases it on a case- or normalization-insensitive filesystem: "
        ".axiom/b.json ('.axiom/B.JSON')"
    )


def test_a_content_file_inserted_during_the_second_tombstone_pass_refuses(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R6-F2: nothing watched the tree while the last pass walked it.

    Round four moved the tombstone walk ahead of the hashing so the two
    re-checks would close a window over it; round five then put a second walk
    *after* those re-checks, and stated the cost — no membership re-sweep
    follows it. That cost was a false PASS: a content file inserted while the
    second walk read directories was never enumerated again, and the verdict
    called a set closed that had gained a file since it was last looked at.

    A third re-sweep would only move the boundary, so the walk is watched by
    generation instead. Every directory the closing sweep read is stamped an
    instant before it is read and re-stated once the walk has finished, and
    an insertion moves its parent's mtime and ctime. Without the fix this
    verification returns a CorpusVerification with the smuggled rule file in
    the tree it just called closed.

    The check sees a write the host's directory timestamps distinguish from
    the stamp taken before it; measured on this host, a create moves both
    stamps. A filesystem with coarser directory timestamps would leave a
    window this cannot see, which is a property of the stamp, not of the pass.
    """

    write_tree(tmp_path)
    monkeypatch.setattr(
        "receipt.corpus._fold_survivor",
        _after_nth_search(
            ".axiom/a.json",
            2,
            lambda: (tmp_path / "rules/tax/smuggled.yaml").write_text("name: evil\n"),
        ),
    )
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(_two_tombstone_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "the tree changed during verification; the closed-world verdict is refused"
    )


def test_a_bound_file_rewritten_during_the_second_tombstone_pass_refuses(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds R6-F2: the identity re-check could not speak for the last walk.

    The per-file identity re-check is what catches a hashed file replaced
    afterwards, and it runs before the second tombstone pass — so a rewrite
    landing during that pass kept the verdict of bytes that were no longer
    there. This one replaces a bound content file by renaming another file
    over its name, which is how a rewrite is done atomically and how it is
    done by every tool that does it safely.

    A rename over an existing name replaces a directory entry, so the
    parent's mtime and ctime both move and the generation check refuses. The
    replacement is staged outside the verified tree so the only change inside
    it is the one under test. Without the fix this verification passes and
    reports a digest the tree no longer holds.

    What stays inside the residual, deliberately: a rewrite in place, through
    the same inode, after the identity re-check has run. It moves the file's
    own mtime and ctime, not its parent's, and nothing after the identity
    re-check reads the file again. Closing that would mean re-hashing every
    bound file after the last pass, which only moves the last look rather
    than removing it.
    """

    staged = tmp_path.parent / f"{tmp_path.name}-staged.yaml"
    staged.write_text("name: rate\nvalue: 0.99\n")
    write_tree(tmp_path)
    monkeypatch.setattr(
        "receipt.corpus._fold_survivor",
        _after_nth_search(
            ".axiom/a.json",
            2,
            lambda: os.replace(staged, tmp_path / "rules/tax/rate.yaml"),
        ),
    )
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(_two_tombstone_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "the tree changed during verification; the closed-world verdict is refused"
    )


def _replace_keeping_size_and_mtime(
    target: pathlib.Path, body: str, staging: pathlib.Path
) -> None:
    """Rename ``body`` over ``target`` and put the old mtime back.

    How a careful writer replaces a file, and how an adversary hides having
    done it: same length, same modification time, a new inode. Everything
    the identity re-check compared before this round survives it except the
    inode — and the rename lands after that re-check has run, so the only
    thing left that can notice is the parent directory's own generation.

    The replacement is staged *outside* the verified tree, which is not
    tidiness: creating and removing a staging file inside the tree root would
    move the root's own generation, and the root is stamped by every walk, so
    the test would refuse for a reason that has nothing to do with the file
    under test.
    """

    before = target.stat()
    assert len(body.encode()) == before.st_size
    staged = staging / f"{target.name}.staged"
    staged.write_text(body)
    os.replace(staged, target)
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))


def test_an_attested_file_replaced_during_the_second_tombstone_pass_refuses(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S4-F2: generation tracking watched the walks, not the verdict's own files.

    Round six stamped every directory the closing membership sweep and the
    second tombstone walk *read*. Neither of them reads the directory that
    holds an attested file: attested paths sit outside the content roots, and
    a tombstone walk descends only toward a removed path — here a path under
    ``retired/``, so the walk touches the tree root and ``retired`` and
    nothing else. ``.axiom`` was stamped by nothing.

    So a producer with write access to the clone could wait until the bound
    files' identities had been re-stated, then replace
    ``.axiom/toolchain.toml`` while the last pass walked elsewhere. The
    rename moves only ``.axiom``'s mtime and ctime, no stamp existed to
    compare them against, and the verdict returned the digest of bytes the
    tree no longer held.

    Every ancestor of every bound path is stamped now, before the identity
    re-check, and ``assert_unchanged`` re-states them last. Without the fix
    this verification returns a CorpusVerification naming a toolchain pin
    that is no longer in the tree.
    """

    body = '{"applied": true}\n'
    write_tree(tmp_path)
    (tmp_path / "retired").mkdir()
    rows = _tombstone_rows("retired/apply-manifest.json", body)
    replacement = '[toolchain]\ncorpus_release = "test-2026-99-99"\n'
    monkeypatch.setattr(
        "receipt.corpus._fold_survivor",
        _after_nth_search(
            "retired/apply-manifest.json",
            2,
            lambda: _replace_keeping_size_and_mtime(
                tmp_path / ".axiom/toolchain.toml", replacement, tmp_path.parent
            ),
        ),
    )
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert str(caught.value) == (
        "the tree changed during verification; the closed-world verdict is refused"
    )
    assert (tmp_path / ".axiom/toolchain.toml").read_text() == replacement


def test_a_bound_file_rewritten_in_place_with_its_mtime_restored_refuses(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S4-F2: the identity tuple compared only what a writer can restore.

    The per-file identity re-check held a bound file to the device, inode,
    size and mtime the hashing descriptor saw. A rewrite through the same
    open inode changes none of the first three, and the fourth is a value
    ``os.utime`` puts back — so a rewrite landing between the hashing and the
    re-check passed the re-check, and no directory generation saw it either,
    because writing through an existing inode does not touch the parent
    directory at all.

    The identity now carries ``st_ctime_ns``, which on POSIX is the inode
    change time and is not settable from userspace. The rewrite is fired
    from inside the closing membership sweep, which is the window between the
    hashing and the re-check; the sweep's own answer is unaffected, since
    membership does not change. Without the ctime term this verification
    returns a CorpusVerification reporting a digest the tree no longer holds.
    """

    import receipt.corpus as corpus_mod

    write_tree(tmp_path)
    target = tmp_path / "rules/tax/rate.yaml"
    replacement = "name: rate\nvalue: 0.99\n"
    assert len(replacement) == len(CONTENT["rules/tax/rate.yaml"])
    real = corpus_mod._tree_content_paths
    calls = {"n": 0}

    def sweep_then_rewrite(root: pathlib.Path, spec: object, **passed) -> dict:
        result = real(root, spec, **passed)
        calls["n"] += 1
        if calls["n"] == 2:
            before = target.stat()
            with open(target, "r+b") as handle:
                handle.write(replacement.encode())
            os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
            after = target.stat()
            # The premise: everything the old tuple compared is back.
            assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
        return result

    monkeypatch.setattr(corpus_mod, "_tree_content_paths", sweep_then_rewrite)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "bound file 'rules/tax/rate.yaml' changed during verification; the "
        "verdict is refused"
    )


def test_refuses_to_verify_at_all_off_posix(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S4-F3: every concurrency claim here rests on POSIX ctime.

    ``_directory_generation`` treats ``st_ctime_ns`` as the change stamp a
    writer cannot forge, and the bound-file identity added by S4-F2 does the
    same for a file. On Windows every supported CPython puts the *creation*
    time in that field — 3.12 deprecated it and 3.14 still does it — so an
    entry can be added, removed or renamed and the directory's mtime put
    back with ``os.utime``, leaving the recorded tuple identical. Every
    stamp the module compares would then say "unchanged" about a tree that
    changed, which is worse than not looking.

    So the module refuses there, first thing, on a corpus that otherwise
    verifies — which is what this pins: the tree, the journal and the spec
    below are the fixture's own, and the verification is refused for the
    platform alone. Without the fix it returns a PASS whose central claim
    the platform cannot support.
    """

    write_tree(tmp_path)
    monkeypatch.setattr(os, "name", "nt")
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "corpus verification requires POSIX change-time semantics (st_ctime "
        "as the inode change time) to detect a tree changing under it; on "
        "this platform the verifier refuses rather than trusting a stamp a "
        "writer can restore"
    )


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
    spend it: 249 four-character evidence keys with 1024 U+1F600 characters
    per value, each value inside ``MAX_EVIDENCE_TEXT`` and each key
    unremarkable.

    That gate charged 262,013 against a budget of 262,144 and passed, while
    the JSON it renders is over three million characters — the flood the
    budget exists to stop, assembled out of strings none of which is over the
    per-string bound. Every producer string is charged its rendered length
    now. Without the fix this journal verifies.
    """

    write_tree(tmp_path)
    evidence = {f"{index:04d}": "\U0001F600" * 1024 for index in range(249)}
    gates = [
        {"gateId": "g", "tier": "public", "outcome": "pass", "evidence": evidence}
    ]
    # What the old charge came to, which is why this journal used to pass.
    old_charge = (
        GATE_RENDER_OVERHEAD
        + len("g")
        + sum(
            EVIDENCE_RENDER_OVERHEAD + len(key) + len(value)
            for key, value in evidence.items()
        )
    )
    assert old_charge == 262013
    assert old_charge <= MAX_GATE_TEXT
    charged = (
        GATE_RENDER_OVERHEAD
        + len(json.dumps("g"))
        + sum(
            EVIDENCE_RENDER_OVERHEAD + len(json.dumps(key)) + len(json.dumps(value))
            for key, value in evidence.items()
        )
    )
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(gates=gates)), spec=corpus_spec()
        )
    assert str(caught.value) == (
        f"journal gate declarations cost {charged} characters of verdict "
        f"text, over the verdict budget of {MAX_GATE_TEXT}"
    )


def test_refuses_removed_paths_whose_escaped_spelling_floods_the_verdict(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R6-F3: ``MAX_REMOVED_TEXT`` had the same gap as the gate budget.

    removedPaths is the other producer-controlled list the verdict renders
    verbatim, and it was charged the same way — by Python characters. A path
    spelled in characters outside the BMP renders twelve times its length, so
    four hundred of them charged 30,800 against a budget of 262,144 while
    putting 295,600 characters of escaped JSON into the verdict.

    Nothing else in the schema stops it: each path is inside
    ``MAX_PATH_TEXT``, each code point is assigned and is neither a control
    nor a format character, and a producer may retire as many paths as it
    likes. Charged as rendered, the set refuses. Without the fix it verifies
    — really verifies, not merely refuses differently, which is why each
    name here stays inside the 255-byte limit a filesystem puts on one
    component: a path too long to look for would refuse on the old module as
    an unverifiable tombstone and the test would bind nothing.
    """

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
    charged = sum(len(json.dumps(path)) for path in retired)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert str(caught.value) == (
        f"journal removed paths total {charged} characters, over the verdict "
        f"budget of {MAX_REMOVED_TEXT}"
    )


def test_a_journal_just_under_both_budgets_renders_within_them(
    tmp_path: pathlib.Path,
) -> None:
    """Binds R6-F3: the budgets are measured against the renderer, not modelled.

    The two budgets above are refusals; this is the other half of the claim
    they make — that a journal they *admit* renders a verdict of about the
    size they charged. Both are filled to just under their caps here, the
    verdict is rendered exactly as ``receipt.cli`` renders it (the same
    ``result_to_dict`` and the same ``json.dumps(..., indent=2,
    sort_keys=True)``), and its size is held against what the budgets
    charged.

    Measured rather than asserted: this journal charges 519,096 and renders
    599,972 characters, a ratio of 1.16. The shape that renders most per unit
    charged *at* the budget — the largest number of gates the declaration cap
    allows, each with the shortest distinct id and the smallest evidence, so
    that the structural overhead the budget under-charges dominates the
    strings it charges exactly — measures 1.36. Below the budget the ratio
    says nothing: about 1.2 kB of the verdict is fixed text no producer
    controls, which is thirteen times the charge of a journal declaring one
    gate and negligible for one at the cap. A factor of four is the bound
    pinned here, far enough above the ratio at the budget that rewording a
    verdict line does not fail the test and close enough that a renderer
    growing multiples per gate would.

    Without the R6-F3 fix this test still passes: it is not a refusal test.
    It exists so that the two refusal tests above cannot be satisfied by a
    budget that has drifted away from what the verdict actually costs.

    The chain half of the verdict is left out — the result is built with
    ``chain=None`` — because it is a fixed handful of digests and timestamps
    with no producer-controlled string in it, so it cannot scale with either
    budget. What is measured is exactly what the budgets bound.
    """

    from receipt.verify import VerifyResult, result_to_dict

    body = '{"applied": true}\n'
    write_tree(tmp_path)
    gates = [
        {
            "gateId": f"g/{index:04d}".ljust(31, "x"),
            "tier": "public",
            "outcome": "pass",
            "evidence": {"c": "1"},
        }
        for index in range(MAX_GATE_DECLARATIONS)
    ]
    # Each component stays inside the 255-byte name limit every filesystem
    # this runs on enforces, since these paths are looked for on disk.
    retired = [".axiom/" + "r" * 240 + f"-{index:04d}.json" for index in range(1000)]
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

    charged_gates = sum(
        GATE_RENDER_OVERHEAD
        + len(json.dumps(gate["gateId"]))
        + EVIDENCE_RENDER_OVERHEAD
        + len(json.dumps("c"))
        + len(json.dumps("1"))
        for gate in gates
    )
    charged_removed = sum(len(json.dumps(path)) for path in retired)
    assert charged_gates <= MAX_GATE_TEXT
    assert charged_removed <= MAX_REMOVED_TEXT

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
    rendered = json.dumps(result_to_dict(result), indent=2, sort_keys=True)
    assert len(rendered) < 4 * (charged_gates + charged_removed)


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
