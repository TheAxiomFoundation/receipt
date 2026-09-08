# Defensive correctness and completeness audit: receipt 0.7 M3 PR1

**Verdict: approve. No findings.** The freeze reproduces current behavior, including existing refusals and defects, without changing production code, design documents, or existing tests. This verdict covers PR #74 at `0f47e917854fb66a7aac19891d6ed659e1b52788`. It does not approve the proposed D1/A7 corrections or a future change to the independent-owner compatibility boundary.

Reviewed locally on 2026-09-07 in one pass, without subagents, background jobs, network access, installations, or remote writes. Only `.venv/bin/python` and `.venv/bin/pytest` were used for Python execution. Long test commands ran serially in the foreground; tool sessions were drained to completion.

The supplied state directory is outside this session's writable roots, and no separate `-o` path was supplied. This committed `review-full.md` is the requested fallback output. `PROGRESS.md` was created at the start. Its first ordinary `git add` was rejected by `.gitignore:26`; a narrow `!/PROGRESS.md` exception was then committed with it, honoring the explicit standing order without force-adding. Those review artifacts are separate from the PR revision audited below.

**Scope and unchanged M1 evidence**

The worktree started clean and `git rev-parse HEAD` returned the requested PR SHA. Before creating review commits, I ran the exact requested scope command:

```sh
git diff 44baaedf7f27219a5c65a9f65728f1c8863c2014 --stat
```

Output:

```text
 tests/m3_admission_expected.py        |   36 +
 tests/m3_cleanup_expected.py          |  148 +
 tests/m3_context_expected.py          |  116 +
 tests/m3_fixture.py                   |  134 +
 tests/m3_legacy.py                    | 6501 +++++++++++++++++++++++++++++++++
 tests/m3_store_expected.py            |  361 ++
 tests/m3_substitution_expected.py     |  189 +
 tests/test_m3_context_admission.py    |  105 +
 tests/test_m3_context_boundary.py     |  381 ++
 tests/test_m3_context_cleanup.py      |  179 +
 tests/test_m3_context_store.py        |  159 +
 tests/test_m3_context_substitution.py |  271 ++
 tests/test_m3_legacy.py               |   64 +
 13 files changed, 8644 insertions(+)
```

Subsequent checks explicitly pinned both revisions so review commits could not contaminate the scope result:

```sh
git diff --name-status 44baaedf7f27219a5c65a9f65728f1c8863c2014 0f47e917854fb66a7aac19891d6ed659e1b52788
git diff --exit-code 44baaedf7f27219a5c65a9f65728f1c8863c2014 0f47e917854fb66a7aac19891d6ed659e1b52788 -- src docs
git diff --exit-code f797f7282a224d6171db91d4f2a8325087e8b833 0f47e917854fb66a7aac19891d6ed659e1b52788 -- tests/m1_fixture.py 'tests/test_m1*' tests/m1_expected
git diff --check 44baaedf7f27219a5c65a9f65728f1c8863c2014 0f47e917854fb66a7aac19891d6ed659e1b52788
git diff --exit-code 0f47e917854fb66a7aac19891d6ed659e1b52788 -- src docs tests
```

Results: exactly the 13 additions above, each status `A`; all other commands exited 0 with no output. Thus no existing fixture, precedence assertion, golden, production module, or design document changed.

I additionally enumerated goldens with `git ls-files 'tests/m1_expected/*.json'` and compared actual bytes, using this executed Python check:

```python
paths = subprocess.check_output(
    ['git', 'ls-files', 'tests/m1_expected/*.json'], text=True
).splitlines()
assert len(paths) == 19
for path in paths:
    current = Path(path).read_bytes()
    for ref in ('f797f7282a224d6171db91d4f2a8325087e8b833',
                '0f47e917854fb66a7aac19891d6ed659e1b52788'):
        assert current == subprocess.check_output(['git', 'show', f'{ref}:{path}'])
```

Output: `19/19 M1 golden files byte-identical to supplied main base, PR head, and worktree`.

An initial additional comparison to the symbolic local `main` failed: `git rev-parse main` returned `d542d592eabcda2924eae573c1c0d0399934ee99`, and `git show main:tests/m1_expected/census_budgets.json` reported that the path does not exist in that ref (exit 128). This is a stale local ref, not a PR finding. The successful authoritative checks use the full main-base SHA supplied in the task. The oracle's `DESIGN_HEAD` names `7c420a2...`; `git diff --stat 7c420a2d27ec73a347f2c2bc72d0564c730d7830 44baaedf7f27219a5c65a9f65728f1c8863c2014 -- docs/design/0.7-m3-repository-context.md` is empty. The specified design record bytes agree.

**Oracle authentication and independence**

I read `tests/m3_legacy.py`, `tests/m3_fixture.py`, and `tests/test_m3_legacy.py`, then independently extracted function spans from `git show 9dc1f85:src/receipt/...`. The following is the authentication portion of the executed `.venv/bin/python` here-document; it deliberately does not call the oracle's `function_hashes` implementation:

```python
import ast, hashlib, subprocess, sys
sys.path.insert(0, 'tests')
import m3_legacy as legacy
sha = '9dc1f85fc0e06cb58b73bad6d09da4c89ee9a4d6'
count = 0
samples = []
for path, expected in legacy.SOURCE_SHA256.items():
    raw = subprocess.check_output(['git', 'show', f'{sha}:{path}'])
    assert hashlib.sha256(raw).hexdigest() == expected, path
    if path in legacy.FROZEN_SOURCE:
        assert raw == legacy.FROZEN_SOURCE[path].encode(), path
    if path not in legacy.BODY_SHA256:
        continue
    lines = raw.splitlines(keepends=True)
    actual = {}
    def walk(nodes, prefix=''):
        for node in nodes:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                key = prefix + node.name
                if not isinstance(node, ast.ClassDef):
                    first = min([node.lineno] + [d.lineno for d in node.decorator_list]) - 1
                    actual[key] = hashlib.sha256(b''.join(lines[first:node.end_lineno])).hexdigest()
                walk(node.body, key + '.')
    walk(ast.parse(raw).body)
    assert actual == legacy.BODY_SHA256[path], path
    count += len(actual)
    names = sorted(actual)
    chosen = names[::max(1, len(names)//8)][:8]
    samples.extend((path, name, actual[name]) for name in chosen)
    print(f'{path}: {len(actual)} independent function-span hashes match')
print(f'{len(legacy.SOURCE_SHA256)} source modules authenticated; '
      f'{len(legacy.FROZEN_SOURCE)} verbatim modules; {count} function records match')
for path, name, digest in samples:
    print(f'SAMPLE {path}:{name} {digest}')
assert len(samples) >= 20
```

Output: 102 protected-tree functions, 118 snapshot functions, 19 verify functions; **239/239 records match, 15/15 source modules authenticate, and all three embedded modules are byte-for-byte verbatim**. Here are the 24 printed sample records; module paths are under `src/receipt/`:

| Module / function | SHA-256 matched against Git source |
| --- | --- |
| protected_tree.py / AttributeOutcome.finding | ebe0d1bc18b2f9addce8168bd847d2418ef17c50b903f4d9f67e5f6b2d640fe9 |
| protected_tree.py / ProtectionPlan.fingerprint | 0f70aa7898dceb081b00413289468d0ea9597a1f3e4b573b69354cafd40c1717 |
| protected_tree.py / TreePolicy.evaluate_ancestors | ff6d1be8e3031a6abb6582d01e84fba4bfff11eca7537b1b39cb5b89266add22 |
| protected_tree.py / TreePolicy.shape_work | 43e8dd9f2c45d21695077f3290389b6ab78ea343b75599f0344a56e315315620 |
| protected_tree.py / _NameFacts.aliases | daba81b5a31cf8b7f6ec10c31fe6fdc7e4d735b75fa711b3b53a7c94970b9e16 |
| protected_tree.py / _NameFacts.siblings | 1854262a4e720323c29e615f0b9bd7936e5768511b901f2ed43777a087942ea5 |
| protected_tree.py / _ShapeFacts.metadata | 5ade94a7965b79fe5f74c9c6fb5d3b76c2bb0a97a084d5808eff5e9b695676b8 |
| protected_tree.py / _segment_matches | 00c5b18ab3b52d136e3b175af9618d5edb7f97a104ba28edfbf672f3d043eeb9 |
| snapshot.py / Materialization.__enter__ | 9ad1092069e4023a6624c306ba9c4fc553a822a04ce6622d364b655f65586457 |
| snapshot.py / TreeListing._walk_from | 5bcaf48f5e14ed55fdef2b82a35babf9285b8641d88424d6fe49baf85ece7f27 |
| snapshot.py / TreeSnapshot._charge_verification | 0cd9b99e9416c41ae9b1714e4b65f6aa1c080e21eadfaee3f0d70310edca98a9 |
| snapshot.py / TreeSnapshot._tree_object | d8a16737161d8cfa8a038fddc54d465caaef0369cf290f9fb71b13117c77f422 |
| snapshot.py / TreeSnapshot.refuse_transforming_attributes | ec84c03d9ec83629f46c764cb46a1cde2476aec38befd727214e1202eec49b2b |
| snapshot.py / _BatchReader._request | a7e241066433e35dd1e906b7c21eb75845823a63742bcc8af7bbdabb3dd66b07 |
| snapshot.py / _DigestIterator.__next__.consume | 17705a2c43591e358181db0198b0cca84dc42a0c0622ba7374054828bf27c6e5 |
| snapshot.py / _check_tree_ancestor | 293379d3f2354ecf097d350619061228db89875ca250c315a2be6900e6d39f4b |
| verify.py / LoadedSpec.__new__ | 92912f3a0cc28e38bc24ae2adb123fbcf42537150db9bf27cfac14775ce36319 |
| verify.py / VerifyResult.anchor_file_sha256s | 48ba2645688556e4a79ffc4bd88b1b996e34a18dcccc84ec087d21a167f5afd6 |
| verify.py / VerifyResult.head_name | 3fe4e963a84303175e1e0f27703bee0bf14e052e10ca6464c018c49a93efb666 |
| verify.py / VerifyResult.witness_times | aedf445fea44b633afaeb963c4c2c7b8f3bff9d1a54ecb5db1160c6a8bd0e25d |
| verify.py / _custody_detail | a86509a6827f5c98066b0ca56febf51faebfe9da49c6b032957b76d703037eea |
| verify.py / _declaration_detail | 04acd40cc09fa1081e696ee19e9b8775d331551ec97588f9ce8c429a92788bca |
| verify.py / _witness_time | abdef50d003f93340c7864e585b3870df709b100e3fa17f6135309fbecbcfe25 |
| verify.py / result_to_dict | b3a51f5fd5241e1ac54b4553e997c366dfdfc300706c272cd908e04258548652 |

The fifteen authenticated modules are `__init__`, `_names`, `_render`, `_unicode_repertoire`, `append_gate`, `attest`, `canonical`, `cli`, `corpus`, `protected_tree`, `release_chain`, `sign`, `snapshot`, `tsa`, and `verify`. The three embedded modules retain their imports, globals, decorators and defaults; the other twelve come from the authenticated Git tree. `_SourceTree` refuses unregistered receipt dependencies rather than falling through to live package globals.

I instrumented `legacy.subprocess.run`, cleared `authenticate.cache_clear()`, entered `legacy.source_tree(old=True)`, asserted that 15 Git calls had already completed, and only then called `legacy.modules()`. Output: `15 git-show authentications completed before frozen module execution`. This supplements the session-autouse fixture in `m3_fixture.py:15` and the unconditional authentication call in `source_tree`.

Independent in-memory tampering with the frozen snapshot source and with the corpus source digest produced, respectively, `Tamper rejected: src/receipt/snapshot.py` and `Tamper rejected: src/receipt/corpus.py`. I also exercised the actual authentication test with a tampered oracle:

```sh
.venv/bin/python - <<'PY'
import sys
sys.path.insert(0, 'tests')
import pytest, m3_legacy
m3_legacy.FROZEN_SOURCE['src/receipt/snapshot.py'] += '\n# independent audit tamper\n'
m3_legacy.authenticate.cache_clear()
code = pytest.main(['-q', '--tb=short',
    'tests/test_m3_legacy.py::test_m3_frozen_sources_authenticate_against_measured_tree'])
assert code == pytest.ExitCode.TESTS_FAILED, code
print('EXPECTED NEGATIVE CONTROL: tampered oracle rejected at fixture setup; pytest exit=1')
PY
```

Output: `ERROR at setup`, `tests/m3_fixture.py:17`, `tests/m3_legacy.py:6429: assert source.encode() == original, path`, `AssertionError: src/receipt/snapshot.py`, `1 error in 0.14s`. The outer audit command exited 0 because it required that rejection. No tracked oracle bytes were modified.

`.venv/bin/pytest -q tests/test_m3_legacy.py` separately returned **5 passed in 1.02s**. Its identical-leg negative control replaces `source_tree` with `nullcontext`, so both legs really use the same live selector and return equal results/counts. `compare` still rejects them with `legacy/live selector bodies must be distinct`. The guard precedes result equality; matching output cannot bypass it. Success and early refusal controls count reached selectors and the reached entry/exit/link bodies. Patching the live `_git_run` to fail does not affect the frozen leg.

**D1–D18: record probe to executable characterization**

I read the design census and all disagreement rows in `docs/design/0.7-m3-repository-context.md`, including the D7 reproduction appendix, and read all six new test modules. Both suite executions below reran every row. `compare` checks old/live complete observations and then the frozen expected value; all 761 characterization cases reproduced their stored values. This establishes their executable support independently of the build lane's claim about capture provenance. Fixture-dependent commit bytes are measured from the deterministic fixtures, not copied from the prose's illustrative byte total.

In this table, B = `tests/test_m3_context_boundary.py`, S = `tests/test_m3_context_store.py`, A = `tests/test_m3_context_admission.py`, C = `tests/test_m3_context_cleanup.py`, and U = `tests/test_m3_context_substitution.py`.

| Row | Probe and inputs checked | Current observation pinned and rerun |
| --- | --- | --- |
| D1 | B `d1`, with/without store check; mutate probe label, HOME, PATH, locale and future GIT variable across select/enter/store/close | Captures `[select, select, enter, close]`, or `[select, select, enter, store, close]`; every child records its epoch and filtered Git keys. This asserts multiple environment reads, not capture-once. |
| D2 | B `d2`; select A, change harmless `m3.probe`, select B; restore/not restore before close | Distinct config records; without restoration B closes and A refuses `repository configuration changed during verification`; restoration preserves the corresponding opposite baseline comparison and resource cleanup. |
| D3 | B `d3_d4`, same commit and `protected.txt` entries | Equal shells/entries but distinct subjects, PIDs and caches; own entry succeeds, foreign entry refuses `GitEntry does not belong to this snapshot`; foreign policy evidence refuses. The fixture's tree-byte total is its actual measured value. |
| D4 | B `d3_d4`; different commits with one tree, copied objects in another repo, linked worktree with common directory | Commit/tree/root/private/common-directory relationships are observed independently; prior entry/view reuse does not gain authority from equal object IDs. |
| D5 | B `d5`; 6/5 public counters, ceiling 10, every suffix of the six-field admission order, including closed B | First competing charge refuses atomically; pools stay separate. Ceiling 11 admits, reversed/repeated links stay idempotent after lowering limits, failed/transitive links and future charges preserve totals. Closed-owner controls retain all fields. |
| D6 | B `d6`; raw `releases/a`, ceiling 19, unlinked/linked/ancestry/failed ancestry/changed paths | Unlinked borrowed history passes at path counts 10/10. Explicitly linked history refuses the 19-byte budget at 0/10. Failed/repeated ancestry and changed-path linkage retain their different barriers. |
| D7 | S `d7`, 288 raw-store cases; A raw-admission and malformed/role controls | Packed removal retains the warm-reader payload and cold-reader unavailability split with cleared Python headers, distinct PIDs and real cleanup. Loose/duplicate controls, replacement, tamper, both read orders, all warmth combinations, selection warmth, and per-account structural/byte ceilings are exercised. A7 is a future correction. |
| D8 | B `d8`; missing versus added attributes, reverse subjects, identical bytes at different depths, symlink/gitlink sources; A late hooks | Source caches stay distinct, presence/scope/mode refusals follow each selected tree, and late loader/parser/matcher/step substitutions affect subsequent reads. |
| D9 | B `d9_d12`, unlinked and link-before/link-after accounts, `protected.txt -filter\n` | Each account admits 22 bytes, one rule and 28 matching steps; linked pure facts are shared while source dictionaries and subject outcomes remain separate. Local charges are retained on merging. |
| D10 | B `d10`; work, entry token and frozen-shell subject drift after policy use | Private work replacement can still leave `policy.work is a.work` false and the new work unregistered while listing succeeds. The test preserves the present invariant hazard rather than asserting its proposed repair. |
| D11 | B `d11_d13`; warmed caches, clean close or abandonment, independent linked sibling | Closed reads refuse `snapshot must be entered before object reads`; reentry refuses `snapshot is closed`; abandoned reads retain `snapshot stream was abandoned`; sibling remains usable. |
| D12 | B `d9_d12`, all 57 ceilings 0–56 plus ordinary replay/link controls | Matching advances 28 then 56, paths 27 then 40, bytes/rules remain 22/1. At ceiling 40 the replay refuses exactly at 40 with the full work tuple retained. Existing checkpoint/stopping-step tests also remain unchanged and passed. |
| D13 | B held/exhausted digest controls and A callback failure | B reads during A's held iterator; competing read abandons A alone. Exhaustion releases the reservation. A callback error abandons the owner, while the independent sibling still reads authentic payload. |
| D14 | B head/readiness/count/retry matrix; A equal-commit successful store checks | Unready base, exact/reversed/duplicate/missing/extra/scalar/unproven heads and failed-count retry preserve validation/attempt ordering. Equal selections retain independent attempted state. Runtime seconds are checked nonnegative, not frozen. |
| D15 | U `public_matrix`; concrete/plain subclass/overriding subclass/no-ledger fake × seven boundaries × entered/closed/unentered | Binding accepts real subclasses with zero concrete policy authority. Empty attested maps remain no-read; malformed declarations precede lifecycle admission. History/base-chain subclass refusal and fake rejection remain current outcomes, not universal acceptance claims. |
| D16 | U `factory_matrix` and `binding_seam`; class, both-class and classmethod changes, subclass returns, before import/after import/after success, with/without history | Select, composed verify, append verdict/text and public/private binding dispatch follow operative substitutions. Simultaneously replacing both classes with the fake retains the current missing-`work` failure; verify-only/classmethod controls preserve their different results. |
| D17 | C direct and composed close matrix: six masks × ordinary/body-error/KeyboardInterrupt, all reached phases, with/without history | Exact primary exception and ordered notes, pass arrays, retained completed history, cleared chain/corpus, directory/export removal and reaped children are frozen. Fault wrappers invoke real cleanup and count real owners. |
| D18 | B `d18`; raw empty/missing/tree/symlink shapes, ancestor then mode stages, resumed versus fresh policy, repeated listing | Incomplete evidence refuses, completed obligations and their findings remain distinct, foreign-policy reuse refuses, and explicit reads retain charges. Empty/missing mode rendering currently raises the production NameError documented below; the fixture does not invent a repaired exception. |

The D7 sample output I extracted after its successful executions was:

```text
D7-packed-remove-1-payload-01: distinct PIDs=True, removed pack files=3
read 0: payload\n
read 1: receipt.snapshot.SnapshotError: object c2981a9931b383b5eb128dc5e3505654ab5269b6 is unavailable
D7-packed-remove-2-payload-10: distinct PIDs=True, removed pack files=3
read 1: payload\n
read 0: the same exact unavailability refusal
D7-packed-remove-1-selection-01: both entered readers give that unavailability refusal
```

The actual captured bytes are `7061796c6f61640a`. The source verifies the target hash, closes/reaps selection children, clears both entered readers' Python header maps, then issues actual entry/blob reads. There is no Python payload-cache explanation or claim that selection's closed child warms an entered child. Packed tampering overwrites equal-length compressed bytes in place; replacement unlinks old pack files and installs another pack. Duplicate controls explicitly distinguish pack-side, loose-side and both-store mutations.

One additional baseline qualification emerged from my own final exception scan: D18 empty/missing `complete` and `resumed` observations contain `builtins.NameError: name 'SnapshotError' is not defined`. I traced it directly through each implementation using an empty RawRepo, the test's `ProtectionPlan`, `evaluate_ancestors`, `evaluate_modes`, and `final.require(..., render=m.release_chain._base_shape_error)`, printing `traceback.extract_tb`. Both executions ended at `protected_tree.py:1844` (`refusal = render(finding)`) then **release_chain.py:2398** (`return SnapshotError(`). Commands `sed -n '2390,2415p' src/receipt/release_chain.py`, `grep -n '^from receipt.snapshot\|SnapshotError\|def _base_shape_error' src/receipt/release_chain.py`, and `git show 9dc1f85:src/receipt/release_chain.py | sed -n '2390,2415p'` confirm the same renderer and the missing import in production and historical source. This is an existing production defect faithfully characterized by the freeze, not a new PR defect or a broken test helper. No repair belongs in this tests-only PR.

**Accepting entry-point and accounting completeness**

I checked U's dispatch against the record's “Verification owners and borrowed readers” census (`docs/design/0.7-m3-repository-context.md:69`). Coverage includes every snapshot-accepting/creating public boundary in that census:

| Public entry point | Coverage |
| --- | --- |
| `TreeSnapshot.select` | U public select and factory-select cases; plain/overriding subclasses and replacement factories |
| `verify.run_verification` | U factory-verify cases and five binding seams; before/after import, simultaneous references, classmethod replacement, history/no history |
| `append_gate.verify_append_gate_verdict` | U factory `append-verdict` cases |
| `append_gate.verify_append_gate` | U factory `append-text` cases |
| `corpus.verify_corpus_binding` | U `binding` and `declaration-first`, all four reader kinds and three lifecycle states |
| `release_chain.verify_release_history_immutable` | U `history`, plus B paired/unpaired and ancestry barriers |
| `release_chain.verify_base_release_chain` | U `base-chain`, all reader kinds/states |

The attested-reader helper `corpus._attested_entries_from_snapshot` is also covered, including empty maps, despite being private. The census's directory-only `verify_release_chain`, evidence-only `verify_declarations`, standalone environment preflight and CLI are not additional public snapshot-accepting APIs; their existing tests remain in the required suite.

U contains 84 public-reader cases, 96 factory cases and five binding cases: **185** total. The ledger-free fake is checked to have none of `work`, `_state`, `_batch`, or `context`. Constructor counters cover `TreePolicy`, `ProtectedTreeView`, and `ProtectedSelection`, so zero authority on accepting subclass/fake branches is an asserted observation. Rejected branches preserve their actual exception/dispatch behavior.

`Trace.call` captures outcome followed by `asdict` for every supplied account. I independently enumerated `dataclasses.fields(SnapshotWork)` and recursively checked every recorded account dictionary for exact key-set equality. The full old/live/expected comparisons then reproduced these values under both Git settings:

| Matrix | Cases | Complete 15-field account observations |
| --- | ---: | ---: |
| Context | 112 | 872 |
| Store | 288 | 2,016 |
| Admission | 32 | 164 |
| Cleanup | 144 | 216 |
| Substitution | 185 | 101 |
| Total | 761 | 3,369 |

All fifteen fields are included: `tree_entries`, `max_tree_entries_in_walk`, `tree_bytes`, `max_tree_object_bytes`, `path_bytes`, `max_path_bytes`, `ancestry_commits`, `ancestry_edges`, `attribute_bytes`, `attribute_rules`, `attribute_match_work`, `content_bytes`, `max_content_blob_bytes`, `materialized_bytes`, and `max_materialized_blob_bytes`. This includes paired, unpaired, failed-link and closed-owner observations. Case keys were also checked for exact equality with expected keys; S's interned traces retain an explicit mapping for all 288 cases. An independent recursive exception scan found no frozen `AssertionError` outcomes.

**Raw fixtures and host measurement**

I read `tests/m1_fixture.py:1` through its RawRepo implementation and the M3 fixture. Construction uses `hash-object --literally`, `update-index --add --cacheinfo`, `read-tree`, `write-tree`, `mktree -z`, and `commit-tree`; adversarial names, modes and empty trees do not require a checkout. `core.precomposeUnicode=false` is set by RawRepo and asserted by the M3 fixture; `RECEIPT_M1_IGNORECASE` controls the actual repository config.

My `.venv/bin/python` host/fixture probe used `platform.platform()`, `platform.python_version()`, `git --version`, `openssl version`, and `/sbin/mount`; a temporary directory inside this worktree tested physical spelling and normalization aliases. For each flag `false` and `true`, it set `RECEIPT_M1_IGNORECASE`, created a fresh RawRepo, committed raw `A`, `a`, decomposed `e\u0301`, and an empty subtree, read both config values and inspected `git ls-tree -rz --name-only`.

Output:

```text
HOST macOS-26.6.2-arm64-arm-64bit-Mach-O arm64 Python 3.14.4
git version 2.53.0
OpenSSL 3.6.3 9 Jun 2026
Filesystem: APFS; worktree on /System/Volumes/Data
case_insensitive=True unicode_normalization_insensitive=True
RAW false ignoreCase=b'false' precomposeUnicode=b'false' paths=[b'A', b'a', b'e\xcc\x81', b'']
RAW true  ignoreCase=b'true'  precomposeUnicode=b'false' paths=[b'A', b'a', b'e\xcc\x81', b'']
```

The full suite inherited `RECEIPT_M1_IGNORECASE=None`, so RawRepo used its explicit default `false`. The second M3 run explicitly used `true`. These are both Git settings on one case-insensitive, normalization-insensitive APFS host, not a claim of another physical filesystem or minimum-version host. I also asserted that `Path(receipt.snapshot.__file__).resolve()` equals this worktree's `src/receipt/snapshot.py`; it does.

**Suite commands and results**

```sh
.venv/bin/pytest -q tests/test_m3_legacy.py
```

Result: **5 passed in 1.02s**, exit 0, zero skips.

```sh
set -o pipefail
.venv/bin/pytest -q --ignore=tests/test_ledger_equivalence.py --ignore=tests/test_append_gate_equivalence.py --ignore=tests/test_brier_witness_equivalence.py --ignore=tests/test_attest_equivalence.py 2>&1 | tee /private/tmp/receipt-m3-pr1-review-suite.log
```

Result: **3955 passed in 1053.42s (0:17:33)**, exit 0, zero skips. This reproduces the lane's stated 3,955 count with my own run and includes all 766 additions and all 3,189 existing non-harness cases.

```sh
set -o pipefail
RECEIPT_M1_IGNORECASE=true .venv/bin/pytest -q tests/test_m3_legacy.py tests/test_m3_context_boundary.py tests/test_m3_context_store.py tests/test_m3_context_admission.py tests/test_m3_context_cleanup.py tests/test_m3_context_substitution.py 2>&1 | tee /private/tmp/receipt-m3-pr1-review-ignorecase-true.log
```

Result: **766 passed in 455.71s (0:07:35)**, exit 0, zero skips. Additions comprise 5 oracle controls plus the 761 characterization cases tabulated above. The four excluded differential harnesses remain for the maintainer's networked host, as requested; no result is claimed for them or external consumer suites.

**Voice and build-report comparison**

I inspected test module docstrings and comments with `cat`/`sed`, extracted docstrings with `ast.get_docstring`, and ran:

```sh
grep -n 'DESIGN_HEAD\|awaiting\|proposed\|approved\|ignoreCase\|precomposeUnicode' tests/test_m3_*.py tests/m3_fixture.py
```

The test modules cite D rows and A7. The decision notes say “proposed deliberate corrections awaiting separate maintainer approval,” “pending capture-once correction,” “separate pending availability correction,” and “These tests grant neither approval.” The store module says A7 “awaits separate maintainer approval.” The pair-adapter note describes today's admitted relationship and explicitly preserves separate accounts, capabilities, PIDs, audit baselines and failure domains; it does not claim approval or implementation of the future ownership proposal. The substitution docstring expressly distinguishes its proposed gate from current acceptance limits. I found no new comment claiming a nonexistent mechanism. Verbatim historical source comments remain verbatim, including the already documented finalization-comment/history-filter mismatch.

Only after forming and committing my independent view and completing both runs did I read `/Users/maxghenis/chief-of-staff/state/receipt-07/lanes/m3-pr1-build.report.md` with `cat`. Its 3,955/766 counts, 239 hashes, fifteen modules, scope and host claims agree with my independent evidence. It describes the build lane's earlier `c335748...` code head and progress handling; this audit is pinned to the requested `0f47e917...` PR head and uses its own committed progress and output. Its disclosed subclass/factory and fixture-dependent D3 qualifications agree with my review. The pre-existing D18 renderer NameError above is an additional qualification I independently verified; it does not change the verdict on this behavior freeze.

No false, unsupported, or behavior-changing PR assertion remains. There are no findings at any severity, so approval does not depend on waiving a low-severity issue. D1 and A7 remain proposed and awaiting their separate approvals, and the existing independent-owner adapter remains intact.

{"schema_version":1,"artifact_revision":{"kind":"pr","repo":"TheAxiomFoundation/receipt","number":74,"commit":"0f47e917854fb66a7aac19891d6ed659e1b52788"},"verdict":"approve","findings":[]}
