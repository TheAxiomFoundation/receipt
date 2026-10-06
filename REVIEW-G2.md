# Receipt 0.6 Lane G round 2: defensive correctness and completeness audit

**Verdict: approve. No findings.** Both round-1 findings are closed. The fresh offline suite passes **1,466 tests**, and all four unchanged pinned equivalence harnesses pass **108 tests**, with zero skips in either run.

Reviewed draft PR: [TheAxiomFoundation/receipt#59](https://github.com/TheAxiomFoundation/receipt/pull/59). Exact detached head: `a2228e40fc0bb2d8e525cae61b91ea495eec4112`. Base: `d6ca1a83d580c1c902f992412a6933da75c8387d`, the untagged 0.6.0 release head. The audited fold consists of:

- `b842f4148ade1bad0648891f70f8eabde7355d15` — Refuse lone aliases of configured protected prefixes.
- `a2228e40fc0bb2d8e525cae61b91ea495eec4112` — Reject Unicode host aliases and padded GitHub origins.

This review began fresh verification at 15:48 UTC on 2026-09-05. A partial report was saved within three minutes and updated as results arrived. This final report supersedes the pre-existing partial; earlier logs were not substituted for fresh runs.

The round-1 verdict/full review, fold brief, PLAN-0.6 §§3.1 and 3.3, current PR body, [maintainer read](https://github.com/TheAxiomFoundation/receipt/pull/59#issuecomment-5552771331) and [posted round-1 verdict](https://github.com/TheAxiomFoundation/receipt/pull/59#issuecomment-5552771419) were read. `gh pr view 59 --comments` could not connect; the read-only GitHub connector supplied the discussion and confirmed the requested head/base. Builder claims were checked against source, independent probes and fresh tests. GitNexus PR-review guidance was read; no GitNexus tools were available, so affected calls were traced directly without indexing. Three independent subreviews covered R1, R2 and preservation; the primary reviewer inspected their evidence and ran the required suites.

The task-specific read-only instruction overrides the standing commit order. No tracked files, index entries or commits were changed; nothing was pushed or posted. This report remains untracked. Existing ignored/untracked PROGRESS.md was left untouched. Probe fixtures and old-source exports were confined to temporary directories.

**R1 — configured-prefix alias: closed.**

`src/receipt/release_chain.py:2234–2333` now contains the shared implementation. Lines 2267–2295 compare exact and ASCII-folded component tuples at every protected-prefix depth, even when the exact spelling is absent. The comparison visits authenticated files and trees, including empty trees, and retains non-tree-first ordering so the legacy diagnostic can name the complete descendant path. There is one diagnostic template, at lines 2293–2294:

```text
index carries an alias of a protected path: {listed} (for {path} at {prefix})
```

The base helper calls it at `release_chain.py:2361–2368`, composed custody at `verify.py:665–673`, and append at `append_gate.py:839–850`. Every call supplies `entries("").as_dict(include_trees=True)`. The screen precedes materialization and consequently OpenSSL. Append retains its existing state/ancestor-shape precedence and translates the shared `ReleaseChainError` to `AppendError` without changing the message. Its explicit `alias_paths=protected` retains the wider configured anchor/surface comparison and global UTF-8 folding.

The supplied `/Users/maxghenis/chief-of-staff/state/receipt-052/peer/lane-g-r1/probes/receipt-g2-absent-protected.py`, run with `PYTHONPATH=src:tests` and the supplied venv Python, exits **1 at the shared helper**, as required: its old acceptance assertion cannot be reached. The exception text is exactly:

```text
index carries an alias of a protected path: CUSTODY (for custody at custody)
```

A temporary catch-and-continue adaptation preserves the signed fixture and surrounds base, composed and public append calls with materialization and OpenSSL tripwires. Under both `portable` and `posix-bytes`, all three refuse with that identical text. Composed custody fails and binding is `not reached`; the fixture uses explicit commit, tree, loader-verified spec and anchor-set pins. One fresh run bound commit `d68fe1fdc60707e6bd0ab9dd2407557f7afc3890` and tree `0e26657e4cd81d6fa4ee3ace03c502a4408b1dd4`. Script/log: `/tmp/receipt-g2-r1-refusal-probe.py` and `/tmp/receipt-g2-r1-refusal-probe.log`.

The caller-anchor boundary remains correct. `verify_base_release_chain` excludes the configured tree-anchor prefix when `anchor_dir` is supplied (`release_chain.py:2353–2360`). Lazy folding stops after a component differs from every selected prefix, preserving exclusion of unused descendants. Immediate ancestor listings remain screened. The new signed controls put an `ANCHORS` alias, merging `EXTRA`/`extra` entries and invalid UTF-8 inside an unused `separate/ANCHORS` subtree: caller trust accepts under both repertoires; selecting tree trust refuses.

The regression evidence is load-bearing:

| Check | Result at reviewed head | Result against exported fbd2654 source |
|---|---:|---:|
| New lone aliases: leaf/ancestor × empty/nonempty/blob × both repertoires × base/composed (`tests/test_release_chain.py:537–592`) | 24 pass | All 24 fail by reaching the materialization tripwire, directly or through the composed diagnostic |
| New caller-anchor controls (`tests/test_release_chain.py:595–632`) | 2 pass | Both positive caller-trust checks still pass; the later tree-trust assertions fail because old code reaches a missing-anchor `SnapshotError` instead of the early `ReleaseChainError` |
| Original protected sibling regressions | 16 pass | Not reopened; their round-1 negative-control evidence remains applicable |

The focused head run totals **42 passed, 85 deselected** in 9.87 seconds. The old-source run totals **26 failed, 101 deselected** in 9.05 seconds; both PYTHONPATH and pytest's configured `pythonpath` were overridden so the installed editable pointer could not select head source. Log: `/tmp/receipt-g2-r1-fail-first.log`. The two exclusion controls do not imply that old caller-trust acceptance was broken.

Existing external-trust and append alias/sibling/suffix-scope controls pass **32 tests** (`/tmp/receipt-g2-r1-existing-controls.log`). Another **192 independent helper assertions** pass across depths 1–4, tree/blob/executable/symlink/gitlink modes, descendants, both repertoires, exact spelling and component boundaries, shared-ancestor exclusions, and UTF-8 guards before quoting a complete alias. Script/log: `/tmp/receipt-g2-r1-scope-probe.py` and `/tmp/receipt-g2-r1-scope-probe.log`.

**R2 — origin parser: closed.**

`src/receipt/attest.py:233–269` captures this one query as bytes, removes exactly one trailing `b"\n"`, decodes with UTF-8/surrogateescape and sends the preserved value to the existing whitespace/control-character guard. Generic `git_output` at lines 166–171 and its other callers are unchanged. Both authority patterns use `re.IGNORECASE | re.ASCII`, retaining uppercase ASCII host acceptance while rejecting Unicode case aliases.

Independent real-Git repositories produced these results, with every refusal exactly `cannot derive repository slug from {origin!r}`:

| Origin family | Result |
|---|---|
| `gıthub.com` (U+0131), HTTPS / SSH with port / SCP | All 3 refuse |
| `gİthub.com` (U+0130), HTTPS / SSH with port / SCP | All 3 refuse |
| `' https://github.com/O/R.git'` | Refuse; leading space retained |
| `'https://github.com/O/R.git '` | Refuse; trailing space retained |
| `'\nhttps://github.com/O/R.git\n'` | Refuse; both configured newlines retained |
| `https://GITHUB.COM/O/R.git` | Accept `O/R` |
| Uppercase-ASCII SSH and SCP controls | Both accept `O/R` |

All 12 raw Git captures were checked to equal the configured UTF-8 value plus one framing newline. Script/log: `/tmp/receipt-g2-r2-origin-probe.py` and `/tmp/receipt-g2-r2-origin-probe.log`.

All **60 attestation tests pass**. The six added Unicode-host regressions at `tests/test_attest.py:388–405` and three boundary-whitespace regressions at lines 408–427 **all fail on fbd2654**, each with `DID NOT RAISE ProvenanceError`, using exported source and an explicit pytest `pythonpath` override. Log: `/tmp/receipt-g2-r2-origin-old-tests.log`. Existing tests retain uppercase ASCII acceptance and prior path/host refusal coverage.

`CHANGELOG.md:98–106` is now true: the host match ignores ASCII case, foreign Unicode host aliases and whitespace refuse, and the origin query removes only Git's framing newline. The statement that `receipt verify` does not call this helper remains accurate.

**Preservation of round-1 clean closures and refusal text.**

The fold changes six files and only three existing top-level source definitions: the shared listing screen, append's delegating screen and `repository_slug`; `_folded_parts` moves from append into release-chain code. G1 attribute matching/audit, G3 UTF-8 state decoding and consumers, G5 portability policy, G6 guarded anchor consumption/digest observation, and G7's remaining explanations are unchanged. The relocated alias comment still identifies the legacy diagnostic's authenticated-tree subject. These closures were checked for preservation, without rerunning the whole-package review's untouched investigations.

The original 16 sibling cases remain green. The release-suffix screen is unchanged and stays restricted to release/manifest descendants. All four harness files, pins, the repin record and README are unchanged.

An AST inventory of literal/f-string first arguments to raises in the changed source files is identical: **180 before and 180 after; zero templates added or removed**. A deterministic differential using the actual old functions extracted from fbd2654 and the current append screen compared **20,000 generated listings** under both repertoires. Every acceptance or exception class/full diagnostic matched, including aliases, invalid UTF-8 descendants, protected anchors/surfaces and mode combinations. These generated helper checks supplement the real-snapshot tests; they are not a claim of exhaustive equivalence. Script/log: `/tmp/receipt-g2-append-preservation.py` and `/tmp/receipt-g2-append-preservation.log`.

**Required fresh suites and final state.**

Both commands ran from this worktree at the requested head, using short process-session polling; no foreground wait exceeded two minutes and no broad process-kill command was used.

```sh
RECEIPT_LEDGER_TREE=/Users/maxghenis/TheAxiomFoundation/receipt/.extraction/ledger-9dafe81 \
RECEIPT_BRIER_TREE=/Users/maxghenis/TheAxiomFoundation/receipt/.extraction/brier-4b9e7be \
PYTHONPATH=$PWD/src \
/Users/maxghenis/TheAxiomFoundation/receipt/.venv/bin/python -m pytest -q -p no:warnings -k "not equivalence"
```

**1,466 passed, 108 deselected, zero skips, 310.82 seconds, exit 0.** This is the round-1 total of 1,431 plus 35 additions: 26 R1 cases and nine R2 cases. Log: `/tmp/receipt-g2-r2-review-offline.log`.

```sh
RECEIPT_LEDGER_TREE=/Users/maxghenis/TheAxiomFoundation/receipt/.extraction/ledger-9dafe81 \
RECEIPT_BRIER_TREE=/Users/maxghenis/TheAxiomFoundation/receipt/.extraction/brier-4b9e7be \
PYTHONPATH=$PWD/src \
/Users/maxghenis/TheAxiomFoundation/receipt/.venv/bin/python -m pytest -q -p no:warnings -rs tests/test_*_equivalence.py
```

**108 passed, zero skips, 259.09 seconds, exit 0.** The four harnesses are ledger, append gate, attestation and Brier witness. Log: `/tmp/receipt-g2-r2-review-harnesses.log`.

`git diff --check` passes over both the fold and full PR ranges. Tracked status is clean and HEAD remains the requested SHA; only `REVIEW-G2.md` appears in ordinary short status. No new residual-class finding was identified. Existing concurrent-writer assumptions for direct directory callers and caller-owned trust remain residuals and do not hold this review. This approval covers the fold at this exact head; installed-artifact smoke runs and tagging were not part of the requested verification.

State: audit complete. Done: both finding closures, negative controls, preservation checks and required suites. Next: the maintainer can use this report and verdict for the PR; no review work remains pending.

Finalized 2026-09-05 15:57:27 UTC.

---SUBFLEET-VERDICT-BEGIN---
{"schema_version": 1, "artifact_revision": {"kind": "pr", "repository": "TheAxiomFoundation/receipt", "number": 59, "head_sha": "a2228e40fc0bb2d8e525cae61b91ea495eec4112", "base_sha": "d6ca1a83d580c1c902f992412a6933da75c8387d"}, "findings": [], "notes": ["R1 closed: signed probes refuse identically in base, composed custody and append before materialization/OpenSSL; all 24 alias regressions fail on fbd2654; caller-anchor exclusion and original sibling controls pass.", "R2 closed: six Unicode-host and three padded-origin probes refuse with exact text; uppercase ASCII accepts; all nine new tests fail on fbd2654.", "Fresh exact-head offline suite: 1466 passed, 108 deselected, zero skips. All four unchanged pinned harnesses: 108 passed, zero skips.", "Round-1 clean closures preserved; 180 existing message templates unchanged; 20000 append-screen differential cases identical; tracked files and Git history unchanged."], "summary": "Approve: both round-1 findings are closed, the fold preserves prior clean closures, and all required suites pass.", "verdict": "approve"}
---SUBFLEET-VERDICT-END---
