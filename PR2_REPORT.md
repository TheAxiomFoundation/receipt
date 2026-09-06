**receipt 0.7 M1 PR2 — authenticated view and shared name evaluation**

Implementation is committed, but this lane is **not ready to merge** under the
requested gates. The unchanged PR1 shell tests forbid the implementation this
assignment requires, and the supplied Chronicle checkout is absent. No golden,
D fixture, precedence assertion, or existing test was edited to hide either
problem. The report uses `PR2_REPORT.md`: the request referred to an `-o` file
without supplying a filename, and no alternative was received.

**Converted sites** (line ranges compare `origin/main` at `f220c77` with the
final implementation, `09ceb6b`):

| Site | Old lines | New lines | Result |
|---|---:|---:|---|
| `src/receipt/protected_tree.py` | 1–163 | 1–709 | Filled the shell with ordered plans, name evaluator, frozen views/selections, provenance checks and private indexes. |
| `release_chain._folded_parts` | 2234–2235 | 2234–2237 | Retained import/signature; forwards the shared fold primitive. |
| `release_chain._screen_protected_tree_names` | 2238–2333 | 2240–2267 | Compiles the exact ordered plan and delegates every name/alias decision. Its renderer is at 2270–2282; no second decision loop remains. |
| `snapshot.assert_no_merging_entries` | Import at 119; call at 3241–3246 | Facade at 161–168; call at 3250–3255 | Forwards local sibling screening with the original arguments, labels and NamePolicyError class. |
| `append_gate._screen_candidate_tree_aliases` | 819–851 | 819–858 | Acquires the same listing, retains the ancestor-shape barrier, then consumes authenticated name evidence and preserves ReleaseChainError → AppendError rendering. |

The plan records repertoire, original ordered prefixes/alias targets, immediate
ancestor and whole-tree name scopes, content roots/suffixes, exact state and
attested paths, export prefixes, attribute selectors, anchor origin, use and
phase. It compiles admitted configuration; it does not relocate spec admission
or append surface classification.

Name stages preserve target-fold admission, non-tree-before-tree traversal,
append's per-entry whole fold, target/depth comparisons, all scoped names before
siblings, and scoped DOS suffix checks. A configured-prefix trie retains at most
two ordered spelling witnesses per node. Findings retain raw paths and condition
witnesses, including the exact target/traversal/sub-step position. Unicode folding
is ASCII-only, with no NFC/NFD normalization.

Views retain authenticated metadata, lossless raw paths, immutable privately
backed indexes, completed listing scopes and their tree OIDs (including empty
selected roots), findings, admission evidence and explicit completed/refused/
unevaluated obligations. A previous view from another subject, session,
evaluator or incompatible plan refuses before further listing I/O. Replaced or
forged views/selections, incorrect purposes, closed/abandoned sessions and
incomplete obligations refuse internally. Compatible stage reuse does not
repeat completed name facts. Mapping/sibling compatibility adapters confer no
payload authority; authenticated selections certify only their declared name
obligations in this PR.

**Retained sites and scope.** No compatibility mismatch required reverting a
converted site. The following sites remain on their old paths because the
record assigns them to later PRs or explicitly retains their separate contracts:

| Site | Old → new lines | Reason |
|---|---|---|
| Release-chain literal focus range | 446–633 → 446–633 | Contains manifest decoding, closed release filename schema and filesystem shape/I/O checks; no additional generic name loop exists here. |
| `assert_manifest_directory_regular` / `_enumerate_manifest_files` | 487–568 / 571–650, unchanged | Direct-reader lstat and closed manifest schema stay with their owners. |
| Snapshot `entry` / `entries` | 2619–2646 → 2628–2655; 2648–2688 → 2657–2697 | Authentication, raw grammar, public argument/path admission and ancestor-shape guards stay in the reader. Bodies unchanged. |
| Snapshot materialization selection | 3194–3249 → 3203–3258 | Body unchanged; only its existing sibling callable now forwards. Mode/export selection and physical writing are PR3 work. |
| Snapshot attributes | 3014–3101 → 3023–3110 | Body unchanged; independent readings and D12 matching remain PR4 work. |
| Append state / ancestor shapes | 746–765 unchanged; ancestor loop within 819–858 | Mode and ancestor decisions are PR3 work. |
| Append attribute selector / release-leaf modes | 854–874 → 861–881; 877–891 → 884–898 | Bodies unchanged; attribute and mode consumption stay at their existing barriers. |
| Append proposal/history/schema | 937–1043 → 944–1050 | Body unchanged, including manifest `.json` child classification. |
| Base chain | 2336–2391 → 2285–2340 | Body unchanged; naturally uses the migrated name facade. No base mode/export/attribute migration. |

Corpus, verify's composed orchestration, directory race guards, anchor evidence
serialization and physical materialization were not edited. Later mode,
ancestor, export-selection and attribute contracts remain explicit
`NotImplementedError` methods in the new module.

**Verification results.** Commands used only `.venv/bin/python` and
`.venv/bin/pytest`; no installation, network, fetch, push, PR, subagent or
background job was requested.

| Gate | Result |
|---|---|
| Before: required non-harness suite | 1,968 passed, zero skips, 369.38 seconds. |
| After: same suite, final implementation | 2,130 passed, 4 PR1 shell-only failures, zero skips, 374.52 seconds (2,134 total; +166 tests). |
| Additions alone | 166 passed, zero skips, 32.62 seconds: 110 module tests and 56 work/comparison tests. |
| All `tests/test_m1_*.py`, `RECEIPT_M1_IGNORECASE=true` | 485 passed, zero skips, 72.19 seconds. |
| All `tests/test_m1_*.py`, `RECEIPT_M1_IGNORECASE=false` | 485 passed, zero skips, 74.24 seconds. |
| Chronicle transparency/isolation | Not run: supplied checkout and both named files are absent. |

The before/after command was:

```text
.venv/bin/pytest -q --ignore=tests/test_ledger_equivalence.py --ignore=tests/test_append_gate_equivalence.py --ignore=tests/test_brier_witness_equivalence.py --ignore=tests/test_attest_equivalence.py
```

The four incompatible cases are
`tests/test_protected_tree_shell.py::test_policy_methods_are_unimplemented`
(three parameters) and `test_production_callers_do_not_import_shell`. They require
empty unauthenticated shell construction, methods that raise the exact PR1
NotImplementedError, and no production imports. PR2 requires authenticated fields,
implemented methods and production forwarding imports. Permission to replace
only those PR1-only assertions with PR2 contract checks was requested and was
not received; the file remains unchanged. This is an unmet full-suite gate,
not a successful run or a reason to weaken the frozen behavioral net.

**Work accounting.** Frozen old helper bodies were copied from `f220c77` into
`tests/protected_tree_legacy.py` (body SHA-256:
`b25067c301871c8414a166b852bacdc54e83a4ea6d24bad8ac0aa9b0cfe19612`).
Comparisons cover 30 repeated-listing/fault/budget cases (three calls per leg),
12 overlapping-export/budget cases, four D12 matching ceilings, four append
cases and three shared candidate/base ledger ceilings. Every public SnapshotWork
field, exception category/text and attempted path-charge trace agrees where
applicable. Two further tests compare 1,250 ordered target/path combinations
against the old nested alias loops.

The bounded duplicate-input probe supplies 2,048 targets (64 paths repeated 32
times) over 129 authenticated entries. Independent instrumentation observes 66
actual fold calls and 321 actual alias lookups. Retained indexes contain 66 fold
keys and 129 alias nodes; sibling visits number 129. Repeated completed stages
add zero folds/lookups. Public counters are tree_entries=129, tree_bytes=2,230,
path_bytes=1,328, max_path_bytes=13; no new public counter or lower ceiling was
introduced. Explicit repeated listing calls still charge the original reader
schedule before metadata deduplication.

The existing standalone D12 remains work 28 then 40 at ceiling 40, with path
bytes 27 then 40 and attribute bytes/rules 22/1. The integrated old/new name-plus-
attribute comparisons also agree: after identical initial name-listing admission,
attribute path-byte deltas are 27 then 40. They make three actual matcher calls
at the exhausting ceiling and four on clean repeated inputs, whose public
matching work reaches 56. No PR4 attribute caching or exhaustion replay is
claimed in this PR.

**Record/code discrepancies and limits.** The step-2 release-chain focus range
446–633 does not locate the generic name helper in this checkout; the actual
helper is at 2238–2333. Its literal range was audited and its retained schema and
shape boundaries left intact. The PR1 shell-only tests conflict with PR2's
required migration, as described above. The record's historical 1,466-test
baseline predates the PR1 additions; the measured current starting count is
1,968. The shell supplied no separate later-stage methods, so explicit documented
PR3/PR4 stubs were added while implementing only names. No disagreement requiring
a behavioral golden, D fixture or precedence change was found.

Chronicle is unavailable at `/Users/maxghenis/TheAxiomFoundation/chronicle`.
Consequently its then-current receipt pin and authenticated oracle could not be
inspected, and zero consumer byte differences have not been established. There
is no evidence that these gates need network access; the observed blocker is the
missing checkout. They remain required before merge. The four equivalence
harnesses were excluded exactly as requested; their separate 108-case gate was
not run. Maintainer and independent review remain outstanding; no merge was
attempted.

Host: macOS 26.6.2 arm64, Python 3.14.4, Git 2.53.0, a case-insensitive worktree
filesystem. Raw index/tree fixtures set `core.precomposeUnicode=false`. Both Git
ignoreCase settings were tested; no second host, case-sensitive filesystem or
minimum Python-version coverage is claimed.

`git diff origin/main --stat` limits production changes to `protected_tree.py`,
`release_chain.py`, `snapshot.py` and `append_gate.py`. `_names.py`, other production
modules, package version and CHANGELOG are unchanged. The requested frozen-path
diff is empty; the only test changes are the three new files. No consumer-visible
symbol was removed or moved. `PROGRESS.md` remains ignored and uncommitted,
following the later explicit instruction. The pre-existing untracked user file
`issue-62.md` was preserved. Every implementation/report commit has the requested
Claude Fable coauthor trailer.
