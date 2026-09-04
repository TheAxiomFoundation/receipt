# Receipt 0.6 Lane C progress

## State

In progress on `feat/0.6-lane-c`, based at `145f3db93d745ddc43aeb47f6b7bd8b30aa331a3`.

## Done

- Read PLAN-0.6 sections 3.1, 3.3, 3.5, 3.7, 3.8 step two, 3.9, 4, and section 5's final paragraph in the required order.
- Read the `receipt.snapshot` module contract and the complete `TreeSnapshot` and `Materialization` implementations without changing them.
- Confirmed the branch is clean and starts at the requested Lane E merge.
- Added and validated the defaulted `ChainSpec.name_repertoire` and `VerificationSpec.anchor_set_sha256` fields; focused tests pass (2 passed).
- Wired the cached OpenSSL 3.0 preflight into `verify_release_chain` and made every RFC 3161 `-CAfile` a 0600 private byte-for-byte copy, including unpinned/unobserved calls; focused tests pass (2 passed).
- Reworked `verify_release_chain` as a directory-as-read verifier: argument validation and OpenSSL preflight precede the anchor/path/manifest-shape/enumeration ladder, every input routes through the bounded lstat-plus-`O_NOFOLLOW` reader, and the docstring states the breaking concurrent-writer precondition. `tests/test_release_chain.py` is green (61 passed).
- Replaced release-history inspection with a comparison of two entered `TreeSnapshot`s, re-exported `snapshot.GitEntry`, and made base-chain verification materialize its entered base. The three existing immutability messages remain exact and candidate links retain the live-directory refusal. `tests/test_release_chain.py` is green (67 passed).
- Deleted the descriptor-holding and cross-run root/state race helpers. Their working-tree race subject no longer exists for commit-addressed callers; their private support functions' callers are deleted. The directory verifier retains its one bounded `O_NOFOLLOW` read.
- Added frozen, loader-constructed `LoadedSpec`; `load_spec` now hashes its single source read and enforces an optional expected digest before `compile` or `exec`. Existing callers consume the record explicitly, and focused tests pass (4 passed).
- Deleted the complete obsolete Git/index/history helper closure (`WORKING_TREE_SCAN_OPTIONS`, index guards, base-ref resolution, `git_tree_entries`, file/blob reads, and their private support). Its checkout/index subject no longer exists or its caller is deleted; `TreeSnapshot` now owns the object reads. The retained live-directory release tests are green (63 passed).
- Re-pinned the 8 ledger base-ref cases to entered candidate/base snapshots and a private candidate materialization; added 7 port-only tree-object cases for the intended dirty-checkout divergence, working-tree/index/environment/replace invariance, and loose-object corruption. The authenticated ledger harness collects and passes 43 cases with zero skips.
- Added `receipts/repin-0.6-tree-object.md` with the Lane E fixture change, genuine ledger divergence, 26 re-pinned / 68 unchanged / 94 prior / 101 integrated census, and the two narrow snapshot diagnostic adapters.\n- Merged Lane D through `4e6070c`: the corpus binder now consumes an entered immutable snapshot, shared name-policy screens and both repertoire fields are present, generated corpus fixtures commit by default, and subjectless filesystem tests are removed. Lane D's remaining retained-test conversions will be merged when committed.

## Decisions

- `PROGRESS.md` is committed because the standing order at the start of the brief explicitly requires a committed salvage record.
- Preserve `src/receipt/snapshot.py` exactly; any reader defect will be recorded here and worked around.
- Keep Lane B files out of this lane. Although Lane D's `CorpusSpec.name_repertoire` is now merged, retain the brief's one-line `getattr(spec.corpus, "name_repertoire", "portable")` compatibility read; Lane B removes it after integration.
- Use `Co-Authored-By: OpenAI Codex <noreply@openai.com>` on every lane commit.

## Findings

- `tsa._require_supported_openssl()` was already present and cached on the starting head; Lane C only needs to wire it into `verify_release_chain` and map its refusal into `ReleaseChainError`.
- Integration dependency: the 0.5.2 `append_gate.py` imports most release-chain guards section 3.5 requires Lane C to delete. The standalone Lane C tree cannot both remove them and collect the append-gate suite until Lane B replaces those callers; keep this visible rather than silently retaining dead compatibility code.
- Snapshot diagnostic surface: `TreeSnapshot.select` reports an unresolvable base as `cannot resolve commit ...` without the old Git stderr, and `assert_ancestor` names an explicit candidate OID rather than `HEAD`. The ledger differential wrapper uses narrow message adapters so the pre-existing moved-case outputs stay pinned; `snapshot.py` remains unchanged.
- The brief assigns the exact append-only deliberate-divergence refusal (`change rewrites existing line ...`) to `tests/test_ledger_equivalence.py`, while that module's baseline is the release-chain script and the phrase belongs to the append-gate oracle. Re-check the harness composition before implementing; if the requested case truly cannot be expressed there, preserve the scope conflict in the final record rather than changing either oracle.

## Next

- Implement commit-addressed `run_verification` and the CLI pins/output over the merged snapshot corpus API.
- Re-run the ledger harness after the final verifier/CLI integration, then run the complete 101-case equivalence census.
