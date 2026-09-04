# Receipt 0.6 Lane C progress

## State

In progress on `feat/0.6-lane-c`, based at `145f3db93d745ddc43aeb47f6b7bd8b30aa331a3`.

## Done

- Read PLAN-0.6 sections 3.1, 3.3, 3.5, 3.7, 3.8 step two, 3.9, 4, and section 5's final paragraph in the required order.
- Read the `receipt.snapshot` module contract and the complete `TreeSnapshot` and `Materialization` implementations without changing them.
- Confirmed the branch is clean and starts at the requested Lane E merge.

## Decisions

- `PROGRESS.md` is committed because the standing order at the start of the brief explicitly requires a committed salvage record.
- Preserve `src/receipt/snapshot.py` exactly; any reader defect will be recorded here and worked around.
- Keep Lane B and Lane D files out of this lane. Until Lane D merges `CorpusSpec.name_repertoire`, `run_verification` will use `getattr(spec.corpus, "name_repertoire", "portable")`; Lane B must remove that compatibility read after merging Lane D.
- Use `Co-Authored-By: OpenAI Codex <noreply@openai.com>` on every lane commit.

## Findings

- None yet.

## Next

- Index/query the current dependency graph and inventory implementation/tests.
- Rewrite the retained directory verifier surface and delete guards whose subjects no longer exist.
- Add tree-based release history/base verification, then `LoadedSpec`, commit-addressed `run_verification`, CLI pins/output, and harness re-pin extras in coherent commits.
