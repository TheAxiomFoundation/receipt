"""Refusal battery for the corpus binding pass.

Each test names one way a producer could publish a journal that does not
describe the tree an auditor cloned, and asserts the binding pass refuses. The
happy-path test is one line; the value is entirely in the refusals.
"""

from __future__ import annotations

import json
import os
import pathlib
import unicodedata

import pytest

from receipt.corpus import (
    EVIDENCE_RENDER_STRUCTURE,
    GATE_RENDER_STRUCTURE,
    MAX_EVIDENCE_ENTRIES,
    MAX_EVIDENCE_TEXT,
    MAX_GATE_DECLARATIONS,
    MAX_GATE_TEXT,
    MAX_JOURNAL_ROWS,
    MAX_REMOVED_TEXT,
    REMOVED_PATH_RENDER_STRUCTURE,
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


def charged_gate(gate: dict[str, object]) -> int:
    """What the module charges one gate declaration against ``MAX_GATE_TEXT``.

    Spelled out from the shipped constants and ``json.dumps`` rather than
    imported from the module, so the arithmetic under every budget test is
    the renderer's and not a copy of the code being tested.
    """

    evidence: dict[str, str] = gate["evidence"]  # type: ignore[assignment]
    return (
        GATE_RENDER_STRUCTURE
        + len(json.dumps(gate["gateId"]))
        + len(json.dumps(gate["outcome"]))
        + sum(
            EVIDENCE_RENDER_STRUCTURE + len(json.dumps(key)) + len(json.dumps(value))
            for key, value in evidence.items()
        )
    )


def charged_removed(path: str) -> int:
    """What the module charges one removed path against ``MAX_REMOVED_TEXT``."""

    return REMOVED_PATH_RENDER_STRUCTURE + len(json.dumps(path))


def first_over(cost: int, budget: int) -> tuple[int, int]:
    """Which identically-priced item first carries the total over ``budget``.

    Returns its one-based position and the running total at that point,
    which is what the refusal names.
    """

    number = budget // cost + 1
    return number, number * cost


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


def test_the_suffix_predicate_folds_a_decomposed_spelling_onto_its_pin() -> None:
    """The same escape spelled in Unicode rather than in case.

    A suffix carrying a composed character has a decomposed spelling that is
    byte-different and, on a normalizing filesystem, the same name. The
    predicate folds both before comparing, so neither spelling sits outside
    the closed world.

    Written against ``_has_pinned_suffix`` rather than through a
    verification, because S5-F3 made a non-ASCII *pinned* suffix illegal at
    construction — an 8.3 alias extension cannot be derived against one, and
    a pin the screen cannot judge is a pin that cannot answer the question
    it exists to ask. The fold itself is unchanged and is still reached with
    non-ASCII text everywhere else this module compares names: content-root
    membership, declared-path aliasing (held end to end by
    ``test_refuses_paths_that_alias_under_unicode_normalization_alone``),
    the entry names the sweep judges, and the tombstone search's buckets.
    """

    import unicodedata

    from receipt.corpus import _has_pinned_suffix

    decomposed = unicodedata.normalize("NFD", "rules/tax/smuggled.café")
    assert decomposed != "rules/tax/smuggled.café"
    assert _has_pinned_suffix(decomposed, (".yaml", ".café"))
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


def test_two_paths_varied_in_case_and_normalization_at_once_still_alias(
    tmp_path: pathlib.Path,
) -> None:
    """Casefold can itself produce decomposed text.

    U+00DF followed by U+0301 folds to s, s, U+0301, whose composed form is
    s, U+015B. One NFC pass before folding left those keys unequal, so text
    varied in case and normalization at once escaped every comparison built
    on the fold. Found by peer review; the fold normalizes again after
    folding.

    Exercised through a pinned non-ASCII suffix before S5-F3 made one
    illegal at construction. The same fold decides which declared paths
    would alias on a case- or normalization-insensitive filesystem, so the
    property is held there instead — end to end, and on a site where a
    non-ASCII name is still legal — with the predicate checked directly
    beside it.
    """

    from receipt.corpus import _has_pinned_suffix, _path_fold

    assert _path_fold("x\u00df\u0301") == _path_fold("xs\u015b")
    assert _has_pinned_suffix("rules/tax/smuggled.\u00df\u0301", (".s\u015b",))

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
    with pytest.raises(CorpusError, match="would alias"):
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

    Which refusal carries the name moved with S5R2-F3: the forged line
    carries a colon, and the name screen refuses that before anything
    decides whether the entry is a symlink. The property under test is
    unchanged — a tree-derived name reaches an auditor escaped — and it is
    now bound at the earlier of the two boundaries, which is the one every
    enumerated name passes through.
    """

    forged = "\x1b[2K\rVERDICT: PASS"
    write_tree(tmp_path)
    (tmp_path / "rules/tax" / forged).symlink_to(tmp_path / "rules/tax/rate.yaml")
    with pytest.raises(CorpusError, match="contains a colon") as caught:
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


def test_a_short_name_extension_carrying_a_non_ascii_character_is_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5-F3: the underscore model was unsound, so the name is refused.

    Round seven pinned this name as an *acceptance*, on the model that 8.3
    generation substitutes an underscore for every character its namespace
    cannot hold, so ``smuggled.ÿml`` would be handed ``._ML`` or ``.Y_M``
    and neither is ``.YML``. The model was wrong: the 8.3 namespace is an
    OEM code page and not ASCII, so a character the volume's code page can
    represent survives into the short name and is uppercased there. With
    ``.éml`` pinned, ``smuggled.émlx`` gets an alias ending ``.ÉML`` on a
    code page 850 volume while the underscore model answered ``._ML`` and
    let the file be skipped as non-content (peer review, round eight).

    Which code page a volume uses is not something an auditor's clone
    reports, and guessing it wrong in either direction is a wrong answer
    about closed-world membership. So the expectation moves from acceptance
    to refusal: the verifier says it cannot derive the alias rather than
    deriving one it cannot stand behind. Without the fix this name is
    silently skipped as non-content under a model of a mapping the volume
    had not agreed to.
    """

    write_tree(tmp_path)
    (tmp_path / "rules" / "smuggled.ÿml").write_text("name: smuggled\n")
    spec = corpus_spec(content_suffixes=(".yaml", ".yml"))
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=spec)
    assert str(caught.value) == (
        "8.3 alias extension cannot be derived for a name whose extension "
        "carries non-ASCII characters (the volume's OEM code page decides "
        "it): 'smuggled.ÿml'"
    )


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
    # Every path costs the same here, so which one first carries the running
    # total over is arithmetic; the module charges them in sorted order,
    # which is the order the verdict renders them in.
    number, charged = first_over(charged_removed(retired[0]), MAX_REMOVED_TEXT)
    assert number <= len(retired)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert str(caught.value) == (
        f"journal removed paths total more than the verdict budget of "
        f"{MAX_REMOVED_TEXT} characters: {charged} charged at path {number} "
        f"of {len(retired)}"
    )


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
    """

    from receipt.cli import _format_text
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
    return json.dumps(result_to_dict(result), indent=2, sort_keys=True), _format_text(
        result
    )


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


def test_a_directory_changed_after_its_own_re_read_is_caught_going_back(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S5-F1: one ordered re-read leaves every earlier directory open.

    ``assert_unchanged`` re-stated each stamped directory once, in sorted
    order. A writer with the clone open could therefore wait for the pass to
    move past a directory and change it while a later one was still being
    re-read: that directory is never revisited, and the verdict returned
    claiming a residual of "one instant" that was really the whole span
    after each directory's own last re-read.

    Here the change lands during the forward pass's re-read of the *last*
    stamped directory (``rules/tax``) and creates a file in one the pass has
    already accepted (``rules``). The sequence of re-reads is asserted, not
    assumed, so the test says which pass refuses: five directories forwards,
    then backwards until ``rules``, where the stamp no longer matches.

    Without the backward pass nothing refuses — the forward pass has already
    passed ``rules``, the identity re-check ran earlier and is unaffected by
    a new file, and the closed-world sweep that would have named the file
    ``unlisted`` is over — so the verification returns a PASS over a tree
    that gained a content file while it was being verified.

    The residual this test cannot reach, and no ordering can: a change that
    lands after the *backward* pass's own re-read of that directory. Some
    directory is always read last, and only verifying an immutable snapshot
    removes the span after it (receipt#44).
    """

    import receipt.corpus as corpus_mod

    write_tree(tmp_path)
    real = corpus_mod._directory_generation
    observed: list[str] = []
    last = tmp_path / "rules/tax"
    reads: dict[str, int] = {}

    def watched(directory: pathlib.Path):
        generation = real(directory)
        relative = (
            "" if directory == tmp_path else directory.relative_to(tmp_path).as_posix()
        )
        observed.append(relative)
        reads[relative] = reads.get(relative, 0) + 1
        # The first read of the last directory is its stamp; the second is
        # the forward pass reaching it, which is the moment the finding is
        # about — every other stamped directory has been re-read by then.
        if directory == last and reads[relative] == 2:
            (tmp_path / "rules/smuggled.yaml").write_text("name: evil\n")
        return generation

    monkeypatch.setattr(corpus_mod, "_directory_generation", watched)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "the tree changed during verification; the closed-world verdict is refused"
    )
    assert observed[-8:] == [
        # forwards, in sorted order, accepting every one of them
        "",
        ".axiom",
        "rules",
        "rules/benefit",
        "rules/tax",
        # and back, refusing at the directory the forward pass had passed
        "rules/tax",
        "rules/benefit",
        "rules",
    ]


ZERO_WIDTH_JOINER = "‍"
COMBINING_GRAPHEME_JOINER = "͏"
DOTLESS_SMALL_I = "ı"
DOTTED_CAPITAL_I = "İ"


#: The ``Default_Ignorable_Code_Point`` section of Unicode 14.0.0's
#: DerivedCoreProperties.txt, verbatim, so the generator's self-check runs
#: offline and the source of the shipped table is on the record beside it:
#: https://www.unicode.org/Public/14.0.0/ucd/DerivedCoreProperties.txt
#: Quoted exactly as published, which is why these lines run past the width
#: the rest of this module keeps to — a re-wrapped quotation proves nothing.
UCD_14_DEFAULT_IGNORABLE = """\
00AD          ; Default_Ignorable_Code_Point # Cf       SOFT HYPHEN
034F          ; Default_Ignorable_Code_Point # Mn       COMBINING GRAPHEME JOINER
061C          ; Default_Ignorable_Code_Point # Cf       ARABIC LETTER MARK
115F..1160    ; Default_Ignorable_Code_Point # Lo   [2] HANGUL CHOSEONG FILLER..HANGUL JUNGSEONG FILLER
17B4..17B5    ; Default_Ignorable_Code_Point # Mn   [2] KHMER VOWEL INHERENT AQ..KHMER VOWEL INHERENT AA
180B..180D    ; Default_Ignorable_Code_Point # Mn   [3] MONGOLIAN FREE VARIATION SELECTOR ONE..MONGOLIAN FREE VARIATION SELECTOR THREE
180E          ; Default_Ignorable_Code_Point # Cf       MONGOLIAN VOWEL SEPARATOR
180F          ; Default_Ignorable_Code_Point # Mn       MONGOLIAN FREE VARIATION SELECTOR FOUR
200B..200F    ; Default_Ignorable_Code_Point # Cf   [5] ZERO WIDTH SPACE..RIGHT-TO-LEFT MARK
202A..202E    ; Default_Ignorable_Code_Point # Cf   [5] LEFT-TO-RIGHT EMBEDDING..RIGHT-TO-LEFT OVERRIDE
2060..2064    ; Default_Ignorable_Code_Point # Cf   [5] WORD JOINER..INVISIBLE PLUS
2065          ; Default_Ignorable_Code_Point # Cn       <reserved-2065>
2066..206F    ; Default_Ignorable_Code_Point # Cf  [10] LEFT-TO-RIGHT ISOLATE..NOMINAL DIGIT SHAPES
3164          ; Default_Ignorable_Code_Point # Lo       HANGUL FILLER
FE00..FE0F    ; Default_Ignorable_Code_Point # Mn  [16] VARIATION SELECTOR-1..VARIATION SELECTOR-16
FEFF          ; Default_Ignorable_Code_Point # Cf       ZERO WIDTH NO-BREAK SPACE
FFA0          ; Default_Ignorable_Code_Point # Lo       HALFWIDTH HANGUL FILLER
FFF0..FFF8    ; Default_Ignorable_Code_Point # Cn   [9] <reserved-FFF0>..<reserved-FFF8>
1BCA0..1BCA3  ; Default_Ignorable_Code_Point # Cf   [4] SHORTHAND FORMAT LETTER OVERLAP..SHORTHAND FORMAT UP STEP
1D173..1D17A  ; Default_Ignorable_Code_Point # Cf   [8] MUSICAL SYMBOL BEGIN BEAM..MUSICAL SYMBOL END PHRASE
E0000         ; Default_Ignorable_Code_Point # Cn       <reserved-E0000>
E0001         ; Default_Ignorable_Code_Point # Cf       LANGUAGE TAG
E0002..E001F  ; Default_Ignorable_Code_Point # Cn  [30] <reserved-E0002>..<reserved-E001F>
E0020..E007F  ; Default_Ignorable_Code_Point # Cf  [96] TAG SPACE..CANCEL TAG
E0080..E00FF  ; Default_Ignorable_Code_Point # Cn [128] <reserved-E0080>..<reserved-E00FF>
E0100..E01EF  ; Default_Ignorable_Code_Point # Mn [240] VARIATION SELECTOR-17..VARIATION SELECTOR-256
E01F0..E0FFF  ; Default_Ignorable_Code_Point # Cn [3600] <reserved-E01F0>..<reserved-E0FFF>
"""


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
    the file sitting in the tree, unbound. The 8.3 rule from S5-F3 refuses
    the same name a few lines later, for the unrelated reason that its
    extension carries a non-ASCII character — so disabling this screen alone
    on the finished head moves the refusal rather than removing it, and it
    is the *skip* that was the defect.
    """

    write_tree(tmp_path)
    (tmp_path / "rules" / f"evil.y{ZERO_WIDTH_JOINER}ml").write_text("name: evil\n")
    spec = corpus_spec(content_suffixes=(".yaml", ".yml"))
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=spec)
    assert str(caught.value) == (
        "tree entry 'rules/evil.y\\u200dml' contains a Unicode format control "
        "(0x200d): 'evil.y\\u200dml'"
    )


def test_refuses_a_tombstone_listing_entry_a_filesystem_may_ignore(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
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
    """

    body = '{"applied": true}\n'
    write_tree(tmp_path)
    (tmp_path / "retired").mkdir()
    rows = _tombstone_rows("retired/apply-manifest.json", body)
    monkeypatch.setattr(
        os,
        "scandir",
        _scandir("retired", extra=[f"apply-manifest.jso{ZERO_WIDTH_JOINER}n"]),
    )
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert str(caught.value) == (
        "tree entry examined for a tombstone contains a Unicode format control "
        "(0x200d): 'apply-manifest.jso\\u200dn'"
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

    This is the same hazard that function refuses for case and normalization
    aliases, one class further out: a closed world whose membership depends
    on which filesystem the auditor resolved the tree on is not closed. Both
    files are real here and both hash, so without the screen this
    verification passes and reports a closed world of four content files
    that no HFS+ consumer can hold.
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
        "journal row 4 path contains a code point a target filesystem may "
        f"ignore when comparing names (0x034f): '{smuggled}'"
    )


def test_refuses_a_dotless_i_beside_the_name_ntfs_folds_it_onto(
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

    The wording moved with S5R2-F11: the claim rests on Unicode's own
    mapping table rather than on "NTFS", because the two upcase tables that
    can actually be read disagree — see
    ``test_the_dotless_i_claim_is_checked_against_a_real_upcase_table``.

    Both files are real and both are bound, so without the screen this
    verification returns a CorpusVerification over five content files.
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
        "journal row 3 path contains the Turkic dotless i (0x0131), which an "
        "upcase table built from Unicode's simple uppercase mappings folds "
        "onto I while this fold key keeps it distinct: "
        f"'rules/tax/ev{DOTLESS_SMALL_I}l.yaml'"
    )


def test_accepts_a_declared_path_carrying_the_turkic_dotted_capital_i(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F11: U+0130 was refused on a premise the sources deny.

    The pair was refused together, on the claim that NTFS's upcase table
    maps both onto ASCII ``I``. Half of that is wrong, and it is the half
    that costs a corpus a legal name. U+0130 LATIN CAPITAL LETTER I WITH
    DOT ABOVE is already uppercase: Unicode 14.0 gives it *no* simple
    uppercase mapping, and the one real upcase table that can be read maps
    it to itself. Nothing merges it with ``i``, so the fold key and the
    filesystem agree about it, and refusing it refused a spelling a
    Turkish-locale producer is far more likely to write than its dotless
    sibling.

    What ``casefold`` does to it — the two-character key ``i\u0307`` —
    merges it with the *sequence* ``i`` plus U+0307, which a real table
    keeps apart. That is over-refusal, the safe direction, and
    ``_reject_aliasing_paths`` already refuses such a pair when both
    spellings are actually bound. This journal binds one.

    Without the fix this verification raises. The dotless half is still
    refused, which its own test asserts.
    """

    content = dict(CONTENT)
    content[f"rules/tax/{DOTTED_CAPITAL_I}.yaml"] = "name: dotted\nvalue: 1\n"
    write_tree(tmp_path, content=content)
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows(content=content)), spec=corpus_spec()
    )
    assert f"rules/tax/{DOTTED_CAPITAL_I}.yaml" in [
        entry.path for entry in verification.content
    ]


def test_the_dotless_i_claim_is_checked_against_a_real_upcase_table() -> None:
    """Binds S5R2-F11: the refusal has to rest on something that was read.

    Two sources were fetched on 2026-09-03 and both are quoted here, because
    the claim the screen rests on is a claim about tables this module does
    not ship.

    Unicode 14.0's ``UnicodeData.txt``
    (https://www.unicode.org/Public/14.0.0/ucd/UnicodeData.txt), the pinned
    repertoire's own release, lines 305 and 306:

        0130;LATIN CAPITAL LETTER I WITH DOT ABOVE;Lu;0;L;0049 0307;;;;N;
        LATIN CAPITAL LETTER I DOT;;;0069;
        0131;LATIN SMALL LETTER DOTLESS I;Ll;0;L;;;;;N;;;0049;;0049

    Field 12 is the simple *uppercase* mapping. U+0131 has one, U+0049. U+0130
    has none — it is already uppercase, and its field 13 lowercase mapping is
    U+0069. So an upcase table built from these mappings folds ``ı`` onto
    ``I`` and leaves ``İ`` alone, which is exactly what ``str.upper`` does on
    the running interpreter and what the first two assertions below pin.

    ntfs-3g's ``ntfs_upcase_table_build``
    (https://raw.githubusercontent.com/tuxera/ntfs-3g/edge/libntfs-3g/unistr.c),
    the default ``$UpCase`` it builds when a volume's own table cannot be
    read, described in its comment as "the table as defined by Windows XP"
    with deltas up to Windows 7. It encodes the table as ranges and offsets,
    and the relevant structure is ``uc_dup_table``, which maps each odd code
    point onto the even one below it:

        static int uc_dup_table[][2] = { /* Start, End */
        {0x0100, 0x012F}, {0x01A0, 0x01A6}, ...
        {0x0132, 0x0137}, {0x01B3, 0x01B7}, ...

    The first range stops at 0x012F and the next begins at 0x0132, so
    **neither** 0x0130 nor 0x0131 is mapped by it — and no ``uc_run_table``
    range, no ``uc_byte_table`` offset and no ``newuppercase`` entry covers
    either. Rebuilding the whole 65,536-entry table from that source gives
    ``uc[0x130] == 0x130`` and ``uc[0x131] == 0x131``, with U+0049 and
    U+0069 the only code points mapping onto ``I``.

    That is a real disagreement between the two sources about U+0131, and it
    is itself the reason to refuse it: the fold key must decide the same
    question the target filesystem decides, and here two readable candidate
    tables decide it differently, so no single answer is safe. About U+0130
    they agree, and they agree with ``casefold``, which is why S5R2-F11 stops
    refusing it.

    This test is a restatement of the fetched sources plus the checks the
    running interpreter can make; it cannot re-fetch them offline. It passes
    with the S5R2-F11 change disabled, which is the point — it is the record
    of what the decision rests on.
    """

    # Unicode's simple case mappings, as the interpreter implements them.
    assert DOTLESS_SMALL_I.upper() == "I"
    assert DOTTED_CAPITAL_I.upper() == DOTTED_CAPITAL_I
    # And what this module's fold key does with the same two.
    assert DOTLESS_SMALL_I.casefold() == DOTLESS_SMALL_I
    assert DOTTED_CAPITAL_I.casefold() == "i\u0307"
    # So the dotless i is the one an upcase table merges and the fold key
    # does not: two names this module calls distinct, one file there.
    assert DOTLESS_SMALL_I.upper() == "i".upper()
    assert DOTLESS_SMALL_I.casefold() != "i".casefold()
    # And the dotted capital is not: distinct under both, either way round.
    assert DOTTED_CAPITAL_I.upper() != "i".upper()
    assert DOTTED_CAPITAL_I.casefold() != "i".casefold()


def test_the_shipped_ignorable_table_is_what_its_generator_produces() -> None:
    """Binds S5-F2: the pinned property table must be checkable, not asserted.

    ``unicodedata`` exposes no ``Default_Ignorable_Code_Point`` query at all,
    so the table cannot be re-derived from the running interpreter the way
    the unassigned ranges can. It is parsed from the published property file
    instead, and the 27 lines of that file are carried here verbatim — the
    ``Default_Ignorable_Code_Point`` section of

        https://www.unicode.org/Public/14.0.0/ucd/DerivedCoreProperties.txt

    — so the check runs offline and the source text sits beside the claim it
    supports. Parsing them must reproduce the shipped tuple exactly: 17
    ranges and 4,174 code points, the 27 lines merging in exactly three
    places — three Mongolian lines into U+180B..U+180F, three word-joiner
    and invisible-operator lines into U+2060..U+206F, and seven tag and
    variation-selector lines into U+E0000..U+E0FFF.

    Without the fix there is no table to check. A hand-edited one is what
    this catches: an entry dropped, a range widened, or the merge done wrong.
    """

    from receipt._unicode_repertoire import (
        DEFAULT_IGNORABLE_RANGES,
        generate_default_ignorable_ranges,
    )

    assert generate_default_ignorable_ranges(UCD_14_DEFAULT_IGNORABLE) == (
        DEFAULT_IGNORABLE_RANGES
    )
    assert len(DEFAULT_IGNORABLE_RANGES) == 17
    assert sum(last - first + 1 for first, last in DEFAULT_IGNORABLE_RANGES) == 4174
    assert (
        len(
            [
                line
                for line in UCD_14_DEFAULT_IGNORABLE.splitlines()
                if "; Default_Ignorable_Code_Point" in line
            ]
        )
        == 27
    )


def test_the_shipped_ignorable_table_is_sorted_disjoint_and_in_range() -> None:
    """Binds S5-F2: ``is_default_ignorable`` bisects, so it assumes all three.

    The lookup finds the last range starting at or below a code point and
    looks no further, which is only correct for ranges that are sorted and
    do not overlap. Adjacency is checked too: two touching ranges would mean
    the generator's merge failed to join what the file split, and a hand edit
    that split a range is exactly what this catches.
    """

    from receipt._unicode_repertoire import (
        DEFAULT_IGNORABLE_RANGES,
        is_default_ignorable,
    )

    assert DEFAULT_IGNORABLE_RANGES
    previous = -1
    for first, last in DEFAULT_IGNORABLE_RANGES:
        assert 0 <= first <= last <= 0x10FFFF
        assert first > previous + 1
        previous = last
    for first, last in DEFAULT_IGNORABLE_RANGES:
        assert is_default_ignorable(first) and is_default_ignorable(last)
        assert not is_default_ignorable(first - 1)
        assert not is_default_ignorable(last + 1)
    # The two classes the screen keeps apart, and one ordinary character.
    assert is_default_ignorable(0x200D) and is_default_ignorable(0x034F)
    assert not is_default_ignorable(ord("a"))
    assert not is_default_ignorable(0x0131)


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
    page. Without the fix this verification passes with the file in the tree
    and no row binding it.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/smuggled.émlx").write_text("name: smuggled\n")
    spec = corpus_spec(content_suffixes=(".yaml", ".eml"))
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=spec)
    assert str(caught.value) == (
        "8.3 alias extension cannot be derived for a name whose extension "
        "carries non-ASCII characters (the volume's OEM code page decides "
        "it): 'smuggled.émlx'"
    )


def test_the_spec_refuses_a_non_ascii_content_suffix_at_construction() -> None:
    """Binds S5-F3: a pin the 8.3 screen cannot judge against is refused.

    The screen refuses to derive an alias extension for a name whose
    extension carries a non-ASCII character, because the volume's OEM code
    page decides it. A *pin* carrying one has the same problem from the
    other side: nothing the screen can derive could ever be compared
    against ``.éml`` with confidence, so the pin cannot answer the question
    it exists to ask.

    Refused at construction, where the committed spec that carries the fault
    is what a refusal names. Without the rule the spec is accepted and every
    ASCII-extension name is silently judged against a pin no alias can be
    compared to.
    """

    with pytest.raises(CorpusError) as caught:
        corpus_spec(content_suffixes=(".yaml", ".éml"))
    assert str(caught.value) == (
        "CorpusSpec content suffix must be ASCII, because an 8.3 alias "
        "extension cannot be derived against a non-ASCII one: '.éml'"
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
    tree. Without the fix this row is accepted and the verdict claims a
    binding no Win32 consumer can rely on.
    """

    content = dict(CONTENT)
    content["rules/NUL.yaml"] = "name: null\nvalue: 0\n"
    write_tree(tmp_path, content=content)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(content=content)), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "journal row 1 path carries a Win32 reserved device name in a "
        "component: 'rules/NUL.yaml'"
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
    lowercase spelling and the extension change nothing. Without the fix
    this verification passes with the entry in the tree.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/con.yml").write_text("scratch\n")
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "tree entry 'rules/con.yml' carries a Win32 reserved device name in "
        "a component: 'con.yml'"
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
    not a mapping. Without the fix this verification passes.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/COM¹.yml").write_text("scratch\n")
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "tree entry 'rules/COM¹.yml' carries a Win32 reserved device "
        "name in a component: 'COM¹.yml'"
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
    """

    content = dict(CONTENT)
    content["rules/NUL .yaml"] = "name: null\nvalue: 0\n"
    write_tree(tmp_path, content=content)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows(content=content)), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "journal row 1 path carries a Win32 reserved device name in a "
        "component: 'rules/NUL .yaml'"
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

    Trailing spaces are removed after that truncation and not before, which
    ``nul  .txt`` pins in the same breath. Without the composition both
    entries are skipped as ordinary non-content files and the verification
    passes.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/CON:stream.yml").write_text("scratch\n")
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "tree entry 'rules/CON:stream.yml' carries a Win32 reserved device "
        "name in a component: 'CON:stream.yml'"
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

    from receipt.corpus import (
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


def _case_insensitive(directory: pathlib.Path) -> bool:
    """Whether this volume resolves a name under a spelling it does not store."""

    probe = directory / "ReceiptCaseProbe"
    probe.write_text("probe\n")
    try:
        return (directory / "receiptcaseprobe").exists()
    finally:
        probe.unlink()


def test_refuses_an_attested_path_the_directory_does_not_spell(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F1: a bound path was opened by its declared spelling.

    The journal attests ``readme.md`` and the tree holds ``README.md``. On a
    case-insensitive volume the declared spelling resolves to the stored one,
    so the file was lstat-ed, opened, hashed and matched, and the verdict
    passed — while a case-sensitive clone of the *same* corpus has no
    ``readme.md`` at all and refuses it as missing. Which filesystem the
    auditor cloned onto decided whether the corpus verified, which is exactly
    the host-dependence the fold-key rules exist to remove.

    Refused on every filesystem now, by one of two mechanisms, and the test
    asserts the one that belongs to the host it is running on: where the
    volume resolves the declared spelling, the component walk refuses because
    the parent's listing does not emit it; where it does not, nothing
    resolves and the existing missing-file refusal speaks. Without the fix
    the first host returns a CorpusVerification over the corpus.
    """

    attested = {**ATTESTED, "readme.md": "# corpus\n"}
    write_tree(tmp_path, attested=attested)
    (tmp_path / "readme.md").unlink()
    (tmp_path / "README.md").write_text("# corpus\n")
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path,
            render_journal(journal_rows(attested=attested)),
            spec=corpus_spec(),
        )
    if _case_insensitive(tmp_path):
        assert str(caught.value) == (
            "path component 'readme.md' is not spelled by its directory: "
            "readme.md"
        )
    else:
        assert str(caught.value) == (
            "bound file is missing or not a regular file: readme.md"
        )


def test_refuses_an_attested_name_stored_under_a_different_normalization(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F1: normalization aliases a spelling exactly as case does.

    The journal attests the NFC spelling of ``café.md``; the tree stores the
    NFD one. APFS and HFS+ resolve either spelling to the file they hold, so
    the declared name opened the stored bytes and the digest matched; ext4
    holds two distinct names and the declared one is simply absent. The same
    corpus, the same journal, two verdicts — and the listing is what settles
    it, because a listing emits the spelling the volume stores.

    Without the fix the resolving host passes.
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
    message = str(caught.value)
    assert message in (
        f"path component {nfc!r} is not spelled by its directory: {nfc}",
        f"bound file is missing or not a regular file: {nfc}",
    ), message


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

    Without the fix the resolving host reports the requirement met.
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
    the listing emitted under exactly that spelling — the new component check
    can only agree with the sweep about them. It is asked of them anyway, so
    that one rule covers both bound kinds rather than two rules covering one
    each, and this asserts the rule costs the ordinary corpus nothing.

    This test passes with the fix disabled, which is the point.
    """

    write_tree(tmp_path)
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows()), spec=corpus_spec()
    )
    assert [entry.path for entry in verification.content] == sorted(CONTENT)
    assert [entry.path for entry in verification.attested] == sorted(ATTESTED)


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
    """

    body = '{"applied": true}\n'
    rows = _tombstone_rows("retired/gone", body)
    write_tree(tmp_path, attested={**ATTESTED, "retired/gone": body})
    (tmp_path / "retired/gone").unlink()
    (tmp_path / "retired" / survivor).write_text(body)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert str(caught.value) == (
        "tree entry Windows would alias by stripping a trailing dot or "
        f"space: {survivor!r}"
    )


def test_the_second_tombstone_pass_screens_the_strip_alias_as_well(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S5R2-F2: the screen belongs to both askings, not to the first.

    The tombstone pair is asked twice per verification, and the second
    asking exists precisely because the first one concluded absence from
    listings it cached. A screen present only in the first pass would leave
    the pass that re-establishes absence able to read a stripping alias out
    of a fresh listing and call the path absent — which is the round-five
    and round-six defect one pass later. The check sits where every listing
    is read, so both askings screen the same way.

    The first pass is patched to pass so that only the second can refuse,
    and the call count asserts that is what happened. Without the fix the
    second pass reports absence and the verification returns.
    """

    import receipt.corpus as corpus_module

    body = '{"applied": true}\n'
    rows = _tombstone_rows("retired/gone", body)
    write_tree(tmp_path, attested={**ATTESTED, "retired/gone": body})
    (tmp_path / "retired/gone").unlink()
    (tmp_path / "retired/gone.").write_text(body)

    real = corpus_module._assert_tombstones_absent
    calls: list[int] = []

    def patched(*args: object, **kwargs: object) -> None:
        calls.append(1)
        if len(calls) == 1:
            return None
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(corpus_module, "_assert_tombstones_absent", patched)
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
    assert calls == [1, 1]
    assert str(caught.value) == (
        "tree entry Windows would alias by stripping a trailing dot or "
        "space: 'gone.'"
    )


def test_refuses_a_tree_entry_named_as_an_alternate_data_stream(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F3: a colon in an enumerated name passed every screen.

    ``rules/tax/rate.yaml:payload.txt`` is an ordinary file on POSIX and a
    perfectly good filename here: it is not under a pinned suffix, its 8.3
    alias extension is ``TXT``, it aliases no other entry by stripping, it
    carries no device basename, and its fold key collides with nothing. So
    the sweep skipped it as non-content. On Win32 the same name opens an
    alternate data stream of ``rules/tax/rate.yaml`` — a file the journal
    binds by digest — and a producer's bytes ride into the tree beside
    witnessed ones without appearing anywhere in the closed world the
    verdict just called closed.

    Declared paths have refused a colon since round three. This is the same
    rule where the tree's own names are screened. Without it this
    verification returns a CorpusVerification over the three content files
    and never mentions the stream.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/tax/rate.yaml:payload.txt").write_text("smuggled\n")
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(
            tmp_path, render_journal(journal_rows()), spec=corpus_spec()
        )
    assert str(caught.value) == (
        "tree entry 'rules/tax/rate.yaml:payload.txt' contains a colon, "
        "which Win32 reads as a stream or drive separator: "
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
        "tree entry examined for a tombstone contains a colon, which Win32 "
        "reads as a stream or drive separator: 'gone:stream'"
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
    instead, after 64 entries have already been screened.
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


def test_refuses_a_journal_with_more_rows_than_the_parser_budget(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S5R2-F4: every other budget bounds a journal already decoded.

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
        verify_corpus_binding(tmp_path, journal, spec=corpus_spec())
    assert parsed == []
    assert str(caught.value) == (
        f"corpus journal carries {MAX_JOURNAL_ROWS + 1} rows, over the "
        f"parser budget of {MAX_JOURNAL_ROWS}"
    )


def test_a_non_ascii_extension_is_not_refused_where_no_pin_can_carry_it(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F5: the screen derived before it filtered the pins.

    With only ``.yaml`` pinned, no 8.3 alias can carry a pinned suffix at
    all: an alias extension is three characters and ``.yaml`` needs four. So
    the answer for every name in the tree is the same, and it does not
    depend on any code page. ``notes.é`` was refused as underivable anyway,
    because the extension was derived before the pins that could not use it
    were filtered out — a refusal over a question no pin had put, against an
    ordinary non-content file that a real corpus may well carry.

    The pins are selected first now, and where none is alias-capable the
    name is never touched. Without the fix this verification raises the OEM
    refusal instead of returning.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/notes.é").write_text("scratch\n")
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows()), spec=corpus_spec()
    )
    assert len(verification.content) == len(CONTENT)


def test_a_non_ascii_character_past_the_third_cannot_reach_the_alias(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F5: the code page decides nothing past the third character.

    An 8.3 extension is three characters, so the fourth character of the
    extension source is dropped before any code page could have an opinion
    about it. ``x.abcé`` is handed the alias extension ``ABC`` on every
    volume there is; with ``.yml`` pinned that is not a pinned suffix, and
    the file is an ordinary non-content one. Screening the whole extension
    source for non-ASCII refused it as underivable.

    The truncation runs first now, so what the code page is asked about is
    exactly what reaches the alias. Without the fix this verification raises
    the OEM refusal.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/x.abcé").write_text("scratch\n")
    spec = corpus_spec(content_suffixes=(".yaml", ".yml"))
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows()), spec=spec
    )
    assert len(verification.content) == len(CONTENT)


def test_the_derivation_still_lands_on_the_first_three_characters(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F5, the other side: truncating first must not skip a file.

    ``x.ymlé`` has the alias extension ``YML``, which is a pinned suffix, so
    the file is content under a name no listing emits and the sweep must
    refuse it — for that reason and not as an underivable one. This pins
    which refusal speaks, because the change that stops refusing the é could
    as easily have stopped deriving anything.

    ``_short_name_extension`` is asserted directly as well, so the
    derivation is stated rather than inferred from the refusal. This test
    fails on the head with the OEM refusal in place of the alias refusal.
    """

    from receipt.corpus import _short_name_extension

    assert _short_name_extension("x.ymlé") == "YML"
    write_tree(tmp_path)
    (tmp_path / "rules/x.ymlé").write_text("scratch\n")
    spec = corpus_spec(content_suffixes=(".yaml", ".yml"))
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=spec)
    assert str(caught.value) == (
        "content root contains a file whose short-name alias would carry a "
        "pinned suffix: 'rules/x.ymlé'"
    )


def test_a_non_ascii_character_inside_the_alias_is_still_underivable(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F5, the control: the refusal that must survive the change.

    ``smuggled.émlx`` truncates to ``éml``, so the é *does* reach the alias
    and the volume's code page decides whether it ends ``.ÉML`` — a pinned
    suffix — or something else. That is the round-eight finding, and
    narrowing the screen to the first three characters must not narrow it
    past this name.

    This test passes with the S5R2-F5 change disabled, which is the point:
    it is here to catch the change going one character too far.
    """

    write_tree(tmp_path)
    (tmp_path / "rules/smuggled.émlx").write_text("name: smuggled\n")
    spec = corpus_spec(content_suffixes=(".yaml", ".eml"))
    with pytest.raises(CorpusError) as caught:
        verify_corpus_binding(tmp_path, render_journal(journal_rows()), spec=spec)
    assert str(caught.value) == (
        "8.3 alias extension cannot be derived for a name whose extension "
        "carries non-ASCII characters (the volume's OEM code page decides "
        "it): 'smuggled.émlx'"
    )


def test_the_spec_accepts_a_non_ascii_suffix_no_alias_could_carry() -> None:
    """Binds S5R2-F5: the ASCII rule belongs to alias-capable pins only.

    ``.éyaml`` has a five-character extension, so no 8.3 alias can carry it
    and the screen never derives anything to compare against it. Refusing
    the pin at construction refused a legal configuration over a question
    the screen would never put — and it is a configuration a real corpus
    might hold, since a suffix outside ASCII is legal everywhere else in
    this module.

    ``.éml`` is still refused, because an alias could carry a three-
    character extension and the derivation against it cannot be made. Both
    halves are asserted here; without the fix the first raises.
    """

    spec = corpus_spec(content_suffixes=(".yaml", ".éyaml"))
    assert ".éyaml" in spec.content_suffixes
    with pytest.raises(CorpusError) as caught:
        corpus_spec(content_suffixes=(".yaml", ".éml"))
    assert str(caught.value) == (
        "CorpusSpec content suffix must be ASCII, because an 8.3 alias "
        "extension cannot be derived against a non-ASCII one: '.éml'"
    )


@pytest.mark.parametrize("name", ["A~1B.TXT", "~1foo.txt", "a ~1.txt"])
def test_an_ordinary_name_carrying_a_tilde_digit_is_not_a_short_name(
    tmp_path: pathlib.Path, name: str
) -> None:
    """Binds S5R2-F9: the recognizer was much wider than 8.3 generation.

    A tilde-digit anywhere inside any run of non-period characters was
    enough, so three ordinary names were refused at the schema boundary for
    resembling an alias none of them could be. ``A~1B.TXT`` has no numeric
    tail, so no collision counter produced it; ``~1foo.txt`` has nothing
    before the tilde to have been shortened from; ``a ~1.txt`` carries a
    space, which generation replaces with an underscore rather than
    emitting. Each is a path a real corpus may hold, and the module refused
    the whole journal over it.

    The grammar is what generation produces now. Without the fix this
    verification raises "has a component Windows would alias".
    """

    body = "# note\n"
    attested = {**ATTESTED, name: body}
    write_tree(tmp_path, attested=attested)
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows(attested=attested)), spec=corpus_spec()
    )
    assert name in [entry.path for entry in verification.attested]


@pytest.mark.parametrize("name", ["RULESF~1.YAM", "SMUGG~12.YML"])
def test_a_real_short_name_shape_is_still_refused(
    tmp_path: pathlib.Path, name: str
) -> None:
    """Binds S5R2-F9, the control: the shapes generation does produce.

    ``RULESF~1.YAM`` is the six-character basis with a one-digit counter;
    ``SMUGG~12.YML`` is the five-character basis with a two-digit one, which
    is how generation makes room as the counter grows. Both are eight-
    character stems, both are spellings NTFS hands out, and neither is
    emitted by any listing — so a declared path spelled either way aliases a
    file this module cannot enumerate and is refused.

    Both of these pass with the S5R2-F9 change disabled, which is the point:
    they are here to stop the tightened grammar from being tightened past
    the spellings that matter.
    """

    write_tree(tmp_path)
    rows = journal_rows()
    rows[0]["path"] = f"rules/{name}"
    with pytest.raises(CorpusError, match="component Windows would alias"):
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())


def test_a_stem_longer_than_eight_characters_is_not_a_short_name(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F9: the 8 of 8.3 is a definition, so it bounds the grammar.

    ``SMUGGL~12.YML`` has a nine-character stem. The 8.3 namespace holds
    eight, which is what Microsoft's "Naming Files, Paths, and Namespaces"
    means by "the short MS-DOS (also called *8.3*) style naming
    convention", and it is why generation shortens the basis as the
    collision counter grows — ``SMUGG~12`` rather than ``SMUGGL~12``. No
    volume hands out the nine-character spelling, so a declared path
    carrying it aliases nothing and is an ordinary name.

    Pinned beside its eight-character sibling so the boundary is stated
    rather than implied. This test passes with the S5R2-F9 change disabled
    as well — the old recognizer's ``[^.]{1,8}`` stem already bounded this
    — and it is here because the round-2 brief named ``SMUGGL~12.YML`` as a
    spelling that should stay refused. It does not, under either grammar,
    and the nine characters are why.
    """

    body = "# note\n"
    attested = {**ATTESTED, "SMUGGL~12.YML": body}
    write_tree(tmp_path, attested=attested)
    verification = verify_corpus_binding(
        tmp_path, render_journal(journal_rows(attested=attested)), spec=corpus_spec()
    )
    assert "SMUGGL~12.YML" in [entry.path for entry in verification.attested]


def test_the_short_name_grammar_is_the_one_generation_produces() -> None:
    """Binds S5R2-F9: the grammar itself, at its every boundary.

    Each accepted spelling below is one 8.3 generation can hand out and each
    refused one is not, and every clause of the grammar has a pair that
    turns on it: the repertoire, the one-to-six basis, the one-to-six
    digits, the eight-character stem, the three-character extension, and
    the tail being taken from the *last* tilde rather than the first —
    ``A~1FOO~1.TXT`` is what generation gives a long name beginning
    ``A~1foo``, and a first-tilde split would not recognise it.
    """

    from receipt.corpus import _is_short_name

    for name in (
        "RULESF~1.YAM",
        "RULESF~1",
        "SMUGG~12.YML",
        "A~1",
        "A~123456",
        "A~1FOO~1.TXT",
        "$~1.Y_L",
    ):
        assert _is_short_name(name), name
    for name in (
        "A~1B.TXT",  # no numeric tail
        "~1foo.txt",  # nothing before the tilde
        "a ~1.txt",  # a space is not in the repertoire
        "SMUGGL~12.YML",  # a nine-character stem
        "A~1234567",  # seven digits
        "ABCDEFG~1",  # a seven-character basis, and a nine-character stem
        "RULESF~1.YAML",  # a four-character extension
        "RULESF~1.Y.M",  # a period inside the extension
        "rules.yaml",  # no tilde at all
        ".yml",  # an empty stem
        "long~1name.yaml",
    ):
        assert not _is_short_name(name), name


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


def test_alias_capability_is_measured_on_the_fold_key_not_the_written_pin(
    tmp_path: pathlib.Path,
) -> None:
    """Binds S5R2-F5, adversarially: the two halves must measure the same thing.

    S5R2-F5 filters the pins an alias could carry before deriving anything,
    and asks the ASCII rule only of that set. Measuring the set by the
    *written* length of the pin while every comparison in this module uses
    the fold key put the two halves out of step: the NFD spelling of
    ``.éml`` is five characters written and four folded, so it was called
    incapable, escaped the ASCII rule that refuses it at construction, and
    was then skipped by the alias comparison as well — while
    ``_has_pinned_suffix`` folds and happily calls a file ending ``.éml``
    content. That reopens exactly the hole round eight closed: on a code
    page 850 volume the alias of ``smuggled.émlx`` ends ``.ÉML``, which
    folds onto that pin, and the sweep skipped the file as non-content.

    Capability is measured on the fold key now, in one predicate both halves
    call. Without it the spec below constructs and the file below verifies.
    """

    from receipt.corpus import _alias_capable_suffix

    nfd = unicodedata.normalize("NFD", ".éml")
    assert len(nfd) == 5 and len(unicodedata.normalize("NFC", nfd)) == 4
    assert _alias_capable_suffix(nfd)
    assert not _alias_capable_suffix(".éyaml")
    with pytest.raises(CorpusError) as caught:
        corpus_spec(content_suffixes=(".yaml", nfd))
    # Quoted as written, so the refusal names the spelling the spec carries
    # rather than the composed form the fold key derived from it.
    assert str(caught.value) == (
        "CorpusSpec content suffix must be ASCII, because an 8.3 alias "
        f"extension cannot be derived against a non-ASCII one: {nfd!r}"
    )
