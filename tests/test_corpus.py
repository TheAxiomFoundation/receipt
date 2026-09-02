"""Refusal battery for the corpus binding pass.

Each test names one way a producer could publish a journal that does not
describe the tree an auditor cloned, and asserts the binding pass refuses. The
happy-path test is one line; the value is entirely in the refusals.
"""

from __future__ import annotations

import pathlib

import pytest

from receipt.corpus import (
    MAX_EVIDENCE_TEXT,
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

    def enumerate_then_inject(root: pathlib.Path, spec: object) -> dict:
        result = real(root, spec)
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
    # An attested path, deliberately: a content path spelled this way is
    # caught earlier, by the sweep, as unlisted; the attested read is what
    # reached os.lstat.
    row = next(row for row in rows if row["kind"] == "attested")
    row["path"] = ".axiom/tool\ud800chain.toml"
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
    with pytest.raises(CorpusError, match="still present in the tree") as caught:
        verify_corpus_binding(tmp_path, render_journal(rows), spec=corpus_spec())
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
