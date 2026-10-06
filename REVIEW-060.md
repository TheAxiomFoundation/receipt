# Receipt 0.6.0: defensive correctness and completeness audit

Review completed: 2026-09-05 14:06 UTC (started 13:26 UTC; approximately 40 minutes). Reviewed checkout: `d6ca1a83d580c1c902f992412a6933da75c8387d`. Release PR #58 head: `bd64008e693af89e7bf1d023077a105773ee02ee`; base: `a768d99498ff8caa192d78f6187540fe749116f8`.

## 1 Release-candidate review

**Hold this candidate for targeted correctness and contract corrections. Do not restructure the package as a prerequisite to tagging.** The important failure is that an unpinned repository setting can turn a transforming-attribute refusal into a complete, fully pinned PASS. A second public verification entry point omits a required name refusal. The other required corrections are small: deterministic append decoding, a correct GitHub-origin parser, and two false contract docstrings.

This is a whole-package review, not a review of the release diff. The audit used independent reader, append/corpus, and release/composition lanes, plus a root review of the CLI, cryptographic boundaries, claims, release evidence, and the combined findings. The requested prior peer records and relevant responses were read across those lanes before conclusions were drawn. In particular, this review accepts the folded external-base-anchor fix, disjoint-manifest name coverage, restored direct-directory tests, pre-execution spec pin, OpenSSL ordering, all-shallow refusal, and the POSIX erratum. It does not reopen the accepted blob-base diagnostic exception or the documented SHA-1/SHA1DC limitation.

Classes used throughout: **(a)** corrections required before this candidate is tagged; **(b)** post-tag improvements; **(c)** greenfield observations or explicit scope limits, not defects charged against this head. None of the blocking reproductions requires a concurrent writer to the working tree/index or depends on their divergence from the selected commit. Scratch repositories and process-local instrumentation were used; no tracked source, test, or documentation file was changed, committed, or pushed.

The requested external output path was denied by the sandbox. This file is the authorized untracked `REVIEW-060.md` fallback. An initial partial was written near the start and updated during the audit. `PROGRESS.md` is an untracked/ignored progress artifact; the review-specific no-commit instruction overrides the standing commit order.

### Findings by severity

#### F1 — High, class (a): local configuration can remove a required refusal with all four pins fixed

**Location:** `src/receipt/snapshot.py:719-735,3031-3115`, particularly `3076-3102`; the conflicting contract is `paper/index.qmd:39-44` and PLAN §3.1.

`refuse_transforming_attributes` takes `core.ignorecase` from local/worktree configuration. That setting chooses which rules participate in last-rule-wins precedence. It can disable an otherwise active transforming attribute; it is not merely an additional conservative refusal.

I independently ran a real signed, dual-TSA corpus whose committed root `.gitattributes` contains:

```gitattributes
releases/** filter=evil
RELEASES/** -filter
```

The candidate commit, tree, loader-pinned spec digest, and explicitly pinned anchor-set digest were identical across runs. With static `core.ignorecase=false`, `run_verification` refused `transforming attribute filter applies to protected path releases/anchors/alpha-root.pem`. With static `core.ignorecase=true`, it returned **PASS**, completing custody, binding, and declaration. Git status was empty after both runs. No configuration changed during either invocation, so the closing re-audit correctly observed no change and cannot address this defect.

**Verification:** `/tmp/receipt060-ignorecase.py`; root independently repeated the reader lane's real-crypto reproduction. The reader lane also compared 1,200 accepted patterns against 300 paths under both case settings: **720,000 comparisons with hermetic `git check-attr --cached`, zero disagreements**. Thus the problem is policy selection by an unpinned input, not incorrect emulation of Git. This does not relitigate the previous review's correctly folded boolean parser or its matcher correctness result.

**Fix:** make attribute semantics a deterministic part of the tree policy. A conservative policy can compute the complete final attribute state independently under exact matching and ASCII-folded matching, then refuse if either interpretation leaves a transform active. Simply pooling matching rules is insufficient: the fold-only reset in this reproduction would still cancel the exact-match rule. Alternatively, an explicit caller-pinned spec field can select the interpretation. Repository configuration must not select a different verification result.

**Coverage gap:** `tests/test_snapshot_features.py:1455,1485,1523` currently pin per-setting Git emulation. They do not assert a fixed public verdict while varying configuration, nor exercise a later case-differing reset that turns FAIL into PASS. Add the fully pinned end-to-end invariant, both reset forms (`-filter`, `!filter`), and equivalent cases for `ident` and `working-tree-encoding`. Preserve the parser differential as a separate test of each interpretation.

#### F2 — High, class (a): the standalone base-chain verifier omits the protected-name refusal

**Location:** `src/receipt/release_chain.py:2237-2270`; `src/receipt/snapshot.py:3208-3262`.

`verify_base_release_chain` normalizes the spec, materializes selected leaves, checks attributes and anchors, and returns a `ChainVerification`. It never performs the required sibling/alias screen over the protected tree and its ancestors. The materializer screens names it will write; an empty tree with no selected leaf is invisible to that screen.

A real signed corpus with a regular `releases/extra` file and an empty sibling tree named `releases/EXTRA` is accepted by the standalone helper with one verified release. Both entries are inside the protected release prefix. The identical commit supplied to `run_verification` completes custody but refuses later in corpus binding: `directory holds two entries a case-insensitive filesystem would merge: 'releases/EXTRA' and 'releases/extra'`. This is a mandatory-refusal bypass through a second public entry point, under PLAN §3.3's requirement that protected-path alias refusals precede extracted checks. It is not a claim that the full composed command passes, or that the helper verified unauthenticated cryptographic bytes.

**Verification:** `/tmp/receipt060-protected-empty-alias.py` and `.log`, independently repeated by root (`/tmp/receipt060-protected-empty-alias-root.log`); a raw canonical tree was necessary to represent an empty Git tree. The condition is the committed tree shape, not checkout/index contents. The audit also examined the materializer's leaf-selection code and the helper's complete call sequence.

**Fix:** give the base helper the same shared protected-tree policy check used by the other commit entry points, including empty entries and siblings at protected ancestor depths, before materialization/crypto. Do not make the low-level materializer silently impose a whole-repository policy. Add direct-helper tests under both repertoires and nonempty/empty aliases, preserving the exclusion of a disjoint unused tree-anchor subtree when the caller supplies external anchors.

**Coverage gap:** current base-helper tests cover attributes, anchor containment, normalized paths, disjoint trust and checkout independence (`tests/test_release_chain.py:405-618`), but not this empty-tree alias. `tests/test_corpus.py:493` covers the later composed refusal; it cannot protect standalone base verification.

#### F3 — Medium, class (a): append decoding depends on the ambient locale and can misdiagnose unchanged history

**Location:** `src/receipt/append_gate.py:238-251,559-575,593-595,1218-1222`.

The base ledger is decoded with `_as_text`'s `locale.getpreferredencoding(False)` default. The candidate ledger is explicitly UTF-8. A correct committed Unicode base (`domain="café"`) followed by an ordinary exact-byte one-row append accepts under `LC_ALL=en_US.UTF-8`, falsely refuses `change rewrites existing line 1 ...` under `en_US.ISO8859-1`, and leaks `UnicodeDecodeError` under C/ASCII when Python UTF-8/coercion modes are disabled. The prefix JSON reads also use the locale default.

**Verification:** root independently ran `/tmp/receipt060-locale-repro.py`, using separate child processes with real locale settings and clean status before/after. The same candidate/base OIDs and spec were used in all three calls. No existing append or append-harness test varies locale. This is an incorrect refusal and a false mechanism message. I rate it medium rather than implying a proven changed-byte acceptance: `_check_exact_byte_append` at `726-732`, called at `1057-1058`, independently blocks the obvious mojibake rewrite attack.

**Fix:** decode all snapshot JSON/JSONL through one deterministic UTF-8 path, retaining only intentional newline handling, and translate malformed input into a stable `AppendError`. Add Unicode base/append invariance tests and invalid-UTF-8 refusal tests. The existing ASCII differential fixtures should keep their exact outcomes; any necessary new Unicode behavior difference must be recorded, not hidden by normalization.

#### F4 — Medium, class (a): the public GitHub-origin parser returns another repository's identity

**Location:** `src/receipt/attest.py:224-231`; tests at `tests/test_attest.py:290-315`.

`repository_slug` searches for a `github.com` substring and stops the repository component at its first period. On actual local repositories, both HTTPS and SCP-style origins for `TheAxiomFoundation/receipt.audit.git` return `TheAxiomFoundation/receipt`. Worse, `https://notgithub.com/TheAxiomFoundation/receipt.git` and `https://evil.example/github.com/TheAxiomFoundation/receipt.git` also return that GitHub slug. A normal SSH URL with a port, `ssh://git@github.com:22/O/R.git`, returns `22/O`.

**Verification:** root independently configured local `remote.origin.url` values and called the helper; the append/corpus reviewer expanded this to 16 origin cases. No network or attestation service was involved. Dotted slugs are expressly accepted by `AttestSpec`'s validator at `47-52`. The current test covers one `brier.git` success and one unrelated hostname without the substring; it misses the accepted wrong identities.

**Fix:** parse the URL/SCP form, validate its actual authority as GitHub, require exactly the owner/repository path, and remove only an optional terminal `.git` suffix. Preserve periods inside the repository name. Define handling of ports, trailing slashes, queries/fragments and host case; reject unsupported forms rather than returning a plausible prefix. Add dotted-name and hostile-host/path fixtures beside the existing parser tests.

This is a whole-package public helper defect. `receipt verify` does not call this helper and the package's provenance verification receives an explicit `AttestSpec`; this reproduction does not demonstrate a forged attestation or a wrong top-level corpus PASS. Retention of the pinned parser explains the history, not the incorrect general API result.

#### F5 — Medium, class (a): the portable-name docstring retains a premise the package already disproved

**Location:** `src/receipt/corpus.py:738-785`, particularly `763-766`.

The helper says every corpus the package verifies was already within the portable repertoire, so refusing other names costs nothing a real corpus carries. PLAN §2 specifically rejects that premise. The package's own `CHANGELOG.md:399-405` records rulespec-us having 33 nonportable names among 15,216; 0.6's `posix-bytes` option and positive tests exist to accommodate this distinction.

**Verification:** source comparison against that durable census, the current module/README policy, and `test_posix_bytes_accepts_tree_names_outside_the_portable_repertoire` / `test_posix_bytes_preserves_normalization_and_still_folds_ascii_case` (`tests/test_corpus.py:265,293`). No behavioral defect is inferred from this stale prose.

**Fix:** replace the universal/costless claim with the declared portability policy and its known cost. The helper now delegates to `_names`; it does not need the old filesystem-model essay. This is medium under the requested rule for false contract documentation and is a small pre-tag edit.

#### F6 — Medium, class (a): the public directory-verifier docstring promises one open per input, but anchors are reread

**Location:** `src/receipt/release_chain.py:1949-1953`; actual reads at `863,1101`, inside the release loop at `2026-2090`.

“Every input file is opened once” is false for a complete invocation. A real two-release chain reads the producer public key and each configured TSA anchor twice. `ChainVerification`'s own documentation at `250-253` correctly explains repeated consumption across releases/roles.

**Verification:** `/tmp/receipt060-clock-read-probe.py` creates real signed releases and instruments `_regular_file_bytes` without substituting its bytes or crypto. Root independently repeated it: two releases, two reads each of `producer-ed25519.pub`, `alpha-root.pem`, and `beta-root.pem`.

**Fix:** say each consumption uses the guarded reader and that anchors may be consumed again across releases/roles; when digest observation is enabled, repeated observed bytes must agree. Do not rewrite working code to satisfy an accidental sentence. The false sentence needs no concurrent writer to disprove. Exploiting a direct directory caller through concurrent replacement remains the expressly stated residual and is not this finding.

#### F7 — Low, class (b): retained diagnostics and helper explanations name deleted mechanisms

**Location:** `src/receipt/append_gate.py:865-867`; `src/receipt/release_chain.py:484-509,1307-1312,1440-1442,1663-1669,1702,1714,1750-1754`; `src/receipt/snapshot.py:3242-3244`.

The append alias refusal says `index carries an alias` although it examines authenticated tree entries. State refusals say `working-tree` even when supplied object bytes; one hardcodes `ledger/immutable_prefix.json` despite configured paths. The general materializer can call a candidate a `base tree`. Several helper docstrings still cite descriptor descent, removed corpus helpers, or closing rereads.

**Verification:** direct call-site searches and source tracing: no index access or descriptor descent survives in `release_chain`; the retained direct-directory reader uses component `lstat`, a bounded `O_NOFOLLOW` open, and `fstat`. These are misleading labels, not newly missing safety checks. Some strings are intentionally preserved compatibility contracts.

**Fix:** correct internal explanations and document the diagnostic subject explicitly. Keep consumer-pinned legacy text unless a separately recorded migration changes it; add structured subject/code fields in the later refactor. This wording debt does not independently block the tag.

### End-to-end contract trace and trust boundaries

The object-reader foundation is strong. `TreeSnapshot.select` (`snapshot.py:1857-2124`) resolves the candidate once, rehashes its commit and root tree, checks commit before tree expectations, and returns named identity. `_BatchReader.consume` (`1425-1485`) verifies role/type/size, requires contents framing to match the preliminary header, consumes the complete payload and terminating LF, hashes Git's `<type> <size>\0` plus payload, and compares the requested OID. Blob, streamed digest and materialization paths all converge there. Streamed SHA-256 and OID verification consume the same chunks.

`GitEntry` provenance (`194-219,2388-2420`) prevents an arbitrary constructed or edited entry from authorizing a read. Canonical tree parsing (`814-861`) checks raw modes, components, duplicates and Git's directory-sort suffix; canonical commit parsing (`864-964`) handles signed/continued headers and ignores parent-shaped message text. Ancestry (`2780-2832`) walks rehashed commits, including both merge parents, rather than consulting `merge-base` or replaceable commit-graph answers.

| Entry point | What supplies the bytes and authority | Audit result |
|---|---|---|
| `receipt verify` / `run_verification` | `verify.py:601-745`: entered candidate/base, rehashed journal/prefix, five selected materialization prefixes, pre-crypto anchor digest, normalized spec reused in crypto, post-crypto digest equality, same journal object passed to binding | No checkout/index payload route found. F1 changes a refusal with unpinned config. F2's alias is eventually refused by binding but after custody. |
| `verify_append_gate_verdict` and string wrapper | `append_gate.py:1301-1356`: nested selected snapshots, full candidate OID with base, object ancestry; state blobs; raw append/prefix comparison; candidate/base private release materializations; caller-owned anchors | Object provenance holds. F3's locale affects interpretation. Protected gate-only/disjoint-manifest screens are present; the two prior review rounds' omissions are folded. |
| `verify_corpus_binding` | `corpus.py:1777-1835`: caller-authenticated journal bytes, one whole-tree listing, exact regular entries, membership/tombstone rules; streamed content/attested digests at `1719-1745` | No hidden filesystem read. A directory argument refuses. The journal-bytes parameter is an explicit composition precondition, not an assertion that this helper independently verified custody. |
| `verify_base_release_chain` | `release_chain.py:2237-2270`: entered base materialization, attributes, normalized anchor filenames and tree digest before crypto; explicit `anchor_dir` is caller trust | Prior path escape is closed. F2 omits required name policy for the standalone result. Disjoint unused tree anchors remain excluded when external trust is supplied. |
| `verify_release_chain` | `release_chain.py:1927-2155`: directory-as-read API; package callers pass private materializations; guarded regular reads; private receipt and `-CAfile` copies | The object-only claim belongs to its commit-addressed callers. Direct `root`, `anchor_dir`, `state_bytes`, and writer residuals are explicit. F6 corrects the per-consumption wording. |
| `verify_release_history_immutable` | `release_chain.py:2174-2220`: authenticated entry metadata, modes and OID identity; tuple result of base/additions/entries | Deliberately metadata-only under PLAN §§3.2, 3.4–3.5. Payload authentication follows in composed verification. See the scope-limit discussion below; not an independent high finding. |
| `load_spec` and pins | `verify.py:317-378`: validates a built-in lowercase SHA-256 expectation, reads once, compares before compile/exec, produces loader-owned `LoadedSpec` | Source pin binds the source actually executed. Caller Python remains trusted executable policy; its dependencies are not magically pinned transitively. An explicit anchor pin requires pinned source; an unpinned spec field is a producer proposal. |

The anchor ladder is correctly implemented apart from the independent F1 policy input: explicit/declared pinned expectations must agree; names normalize once; exact configured materialized bytes enter the canonical per-filename digest; a mismatch precedes crypto; the digest actually observed by custody must match afterward (`verify.py:490-508,699-723`). TSA PEM, signer certificate/SPKI and policy pins, and producer SPKI pins bind at their appropriate read sites. Stateful path objects cannot make the pre-check and use select different names. Canonical per-file digest mapping is injective and JSON-round-trippable, with specific tests for the previously discovered filename hazards.

All inherited `GIT_*` variables are removed by the reader and exactly three set (`snapshot.py:445-464`). Absolute repository selection, both git/common-directory control-file checks, the configuration deny-list and final re-audit are present. The public append/composed entries intentionally retain their five redirecting-environment refusals; this previously accepted compatibility behavior is accurately documented. F1 is the remaining unpinned repository **semantic** input identified here, not a suggestion that those existing refusals should disappear.

### Refusal vocabulary, accepted shapes, and load-bearing tests

A source census found 665 direct literal/f-string raise sites and 586 normalized templates after deduplication within each module, across the package's named exception types: snapshot 141, names 18, release 98, append 57, corpus 81, verify 17, TSA 134, sign 36, attest 4. These are **direct-raise template counts**, not the total transitive vocabulary: helper-built exceptions, dynamically forwarded messages, standard exceptions and parameter values expand it. The count is evidence that text is a substantial API, not a proposed deletion target.

| Shape or boundary | Shipped behavior and tests bearing its load |
|---|---|
| Commit/tree pins, same tree with different parentage | `test_select_expectations_are_checked_commit_then_tree`, `test_expectations_require_exact_full_object_names`, `test_commit_identity_distinguishes_commits_with_the_same_tree` (`test_snapshot.py:204,245,298`). `test_candidate_expectations_refuse_commit_before_tree` (`test_verify.py:512`) tests composition. |
| Rehash, framing and role substitution | `test_batch_contents_header_must_equal_the_info_header` (`test_snapshot.py:1335`); frame/LF/hash/role cases `1454-1552`; tampered tree/blob (`test_snapshot_security.py:714,779`). These would fail if the reader trusted the object name alone after fetching payloads. |
| Gitlink/submodule and `120000` | Five-mode raw tree test (`test_snapshot.py:750`) proves foreign gitlink OIDs are not fetched. Direct digest symlink refusal (`test_snapshot_features.py:1289`); content/attested modes (`test_corpus.py:367-452`); ledger/release gitlinks (`test_append_gate.py:1576,1613,1626`); history replacement modes (`test_release_chain.py:351`). Regular payload modes are only `100644`/`100755`. |
| Non-UTF-8, fold-equal siblings, both repertoires | `test_snapshot_names.py:107-393`; positive `posix-bytes` and NFC/NFD cases (`test_corpus.py:265,293`); root/mixed-mode sibling test (`493`); portable short-name screen (`3213`). Non-UTF-8 can be retained as raw reader names but refuses when quoted/folded. No Unicode normalization policy is silently reintroduced. F2 is the direct-helper omission. |
| Empty trees | Canonical empty trees are reader inputs; listings distinguish directory entries from materialized leaves. Corpus's whole listing sees them; the append protected screen covers its selected scopes. F2 shows that direct base verification does not yet enforce the same rule. Empty manifest-subtree behavior is tested at `test_append_gate.py:2098`; that is not a substitute for an empty sibling alias test. |
| Attributes | Exact Chronicle fixture (`test_snapshot_features.py:213`), state/precedence (`285,323`), refused grammar (`361,389,526,554,600`), irrelevant `info/attributes` (`373`), Git differential (`457,488`). F1 needs the missing public configuration-invariance test. Unsupported syntax remains fail-closed. |
| Object format/repository boundary | `test_snapshot_security.py:441-625` covers SHA-256, grafts, shallow/common-directory precedence, bare/nonrepository/top-level selection. SHA-256 refusal is intentional until a complete parsing/corruption fixture exists; there is no claim of SHA-256 support. |
| Budgets and cleanup | `test_snapshot_acceptance.py:98` accepts 20,000 entries/128 MiB; its `190-394` cases exercise resource ceilings. Shared and attribute-work budgets (`test_snapshot_features.py:1136-1313`); acquisition/abandonment/interrupt cleanup (`test_snapshot.py:322-687,1348-1400`); failed/short materialization writes (`test_snapshot_features.py:814,869,891,912`). |
| Store-wide verification | SHA1DC/floor (`test_snapshot_security.py:264`), corrupt unreachable loose/packed objects (`797,830`), exact heads/commands (`919`; `test_snapshot_features.py:1377,1430`). No known-collision fixture tests SHA1DC itself; that accepted limit is stated honestly. |
| Spec and anchor pins | `test_load_spec_cannot_be_pinned_by_a_forged_equality_object`, `test_load_spec_reads_source_bytes_once`, `test_expected_digest_refuses_before_compile_or_exec` (`test_verify.py:118,136,157`); mismatch/pre-post observation/proposal/spec-field/conflict (`467,493,567,585,608`). |
| Base trust and path containment | `test_base_release_chain_materializes_the_entered_snapshot`, disjoint anchor materialization, before-OpenSSL binding, normalized-spec identity, external trust, disjoint unused subtree and attribute checks (`test_release_chain.py:405-618`). Missing direct alias coverage is F2. |
| Direct directory crypto guards | `test_openssl_is_fed_the_digested_bytes` (`test_release_chain.py:659`); preflight/order/probe (`727,755,814`); guarded reads (`832`); repeated anchor observation (`1587,1621`); platform/parent/leaf spelling (`2197-2423`). Repeated-read tests protect the actual behavior that F6's sentence misstates. |
| Append subject, modes, early return and raw state | Full OID/identity/push (`test_append_gate.py:376,390,417`); gate-only and disjoint manifest matrices (`445-810`); moving branch (`1011`); state modes (`1038-1075`); state-byte handoff (`1529`); selected chain (`2009`); real/caller/disjoint anchors (`2487-2528`). No locale regression: F3. |
| Corpus completeness and digest binding | Edited content/attested (`test_corpus.py:791,800`), unlisted/missing (`820,831`), tombstone revision/survival (`872,2118,2313`), worktree rewrite/insert/rename property (`526`). Index independence is carried by reader/harness tests rather than that particular property. |
| CLI failure/claim delivery | End-to-end fixture/pin tests; missing spec/root/aborted/serialization paths (`test_cli.py:2154-2285`); protected verdict sentinel/escaping (`2384-2685,3324,3369`); bounds/key collisions (`2751-3235`); short writes/codec safety/failed streams (`3455-4739`); legacy environment refusal (`4777`). The three core passes must have run; vacuous `all([])` cannot produce PASS (`verify.py:218-232`). |
| Ancillary APIs | `test_attest.py:290-315` omits F4. Forced sign-backend tests cover Ed25519 but not the unsupported-dependency fallback algorithm divergence discussed in §2. The reviewer additionally compared 101,752 finite random/boundary floats with installed Node's `JSON.stringify`, with no number-formatting disagreement. |

The 0.6 screens are generally well tested and adversarial, not decorative. The reader reviewer ran 134 focused tests; append/corpus ran 19; chain/composition ran 31. These were targeted investigations of specific boundaries, additional to the requested once-only full offline run. Earlier review mutation results were read as prior evidence; they were not falsely counted as new mutation runs here.

### Required suite and release-evidence results

Both reviewed commits have root tree **`61ef6469caaeb06bd419348f1d6931d9e24d1481`**, independently checked with `git rev-parse` and a quiet tree diff. The checkout remains at the requested detached merge commit.

1. Exact requested offline command: **1368 passed, 108 deselected, zero skips, 281.23 seconds**, exit 0. Log: `/tmp/receipt060-offline.log`.
2. Exact requested four-harness command with only the supplied ledger override: **71 passed, 37 setup errors**, exit 1, because the Brier fallback attempted a network clone the sandbox could not perform. Log: `/tmp/receipt060-harnesses.log`.
3. Justified rerun of all four with the existing local authenticated Brier extraction added:

```sh
RECEIPT_LEDGER_TREE=/Users/maxghenis/TheAxiomFoundation/receipt/.extraction/ledger-9dafe81 \
RECEIPT_BRIER_TREE=/Users/maxghenis/TheAxiomFoundation/receipt/.extraction/brier-4b9e7be \
PYTHONPATH=$PWD/src \
/Users/maxghenis/TheAxiomFoundation/receipt/.venv/bin/python -m pytest -q -p no:warnings -rs \
  tests/test_ledger_equivalence.py tests/test_attest_equivalence.py \
  tests/test_brier_witness_equivalence.py tests/test_append_gate_equivalence.py
```

**108 passed, zero skips, 232.69 seconds**, exit 0. Log: `/tmp/receipt060-harnesses-local.log`. The harnesses themselves authenticate the pinned source files; this override does not waive their hashes or change their oracles. Long commands ran under process sessions with short polling; no broad process-kill command was used.

The saved exact-head release record (`state/receipt-052/logs/release-060-suites2.txt`) identifies `bd64008...` and records 1368/108. Separate installed wheel/sdist runs in `release-060-presmoke2.txt` record 1366 passes and two layout-only deselections each. I inspected the smoke script: it creates separate virtual environments, removes `PYTHONPATH`, verifies import location, and runs copied offline tests outside the repository. I did not rebuild those artifacts or claim to have rerun their installed suites. I independently hashed the saved files and compared **every packaged `receipt/*.py` module** to this checkout; both have zero differences:

| Artifact | SHA-256 |
|---|---|
| `receipt-0.6.0-py3-none-any.whl` | `ffebed6b3ee794822679dc9ee2771807238b443d99b5fa6c49a303755dc8896f` |
| `receipt-0.6.0.tar.gz` | `7df322c9f3159da40e132f5ad26d5dd7b40b6d15284cdc82b04af4ee468d0797` |

**Exact tag target matters.** PLAN §5 criterion (g) and residual row 20 specify the reviewed PR-head OID; the current task explicitly names the tree-identical merge `d6ca1a...` as the candidate, superseding that older target choice for this audit. This review and the required source suites ran at `d6ca1a...`; the mandated verdict schema and saved installed-artifact evidence name `bd64008...`. The report preserves both identities. Tree equality proves packaged-source equality, not commit/ancestry identity. After the required corrections, bind the new review, source suites, installed artifacts and tag to the one exact chosen commit; do not reuse stale results merely because a later merge is expected to have the same tree.

An external release-automation observation is **not a finding against package HEAD**: the inspected `state/receipt-052/chains/release_tag_060.sh` still gates on `release-060-suites.txt` rather than the second-head record and extracts the **0.5.2** changelog section for a 0.6 release. Its `presmoke` path did not execute that publication branch. Correct/review the actual publishing procedure before using it; this audit did not run it or publish anything.

### Claims review and deliberate limits

The README example is wired: `--spec`, `--commit HEAD`, optional root discovery, dependent pin arguments, JSON failure boundary, named commit/tree and narrowed trust claims match the implementation. Requirements match the reader/tool preflights: Python 3.11+, Git 2.36 for ordinary reading, Git 2.50 plus a SHA1_DC build for `--verify-objects`, OpenSSL 3.0+, POSIX and `O_NOFOLLOW`. Shallow, bare, SHA-256 and LFS limitations are stated; the POSIX erratum is delivered, not silently waived for temporary directories.

CHANGELOG 0.6's API census, four status lines, loader-owned spec, anchor ladder, materialized subjects, deleted-name inventory, differential census and deliberate text migrations agree with the inspected code, subject to F1–F2's incompleteness. The README's statement that changing checkout/index bytes does not change the selected subject is borne by object tracing and the invariance harnesses. The paper's 0.6 note is the current contract and is violated by F1; its explicitly identified 0.5.1 account below is historical and was not treated as an unannounced restoration of the old Unicode/filesystem policy. False current docstring contracts are F5–F6; stale explanatory mechanisms and inherited diagnostic labels are F7.

The audit did not attempt to prove arbitrary caller Python safe, defeat a malicious installed Git/OpenSSL/Python, prove collision resistance, or remove the same-uid/private-materialization and live-directory writer assumptions. These are actual declared trust boundaries. `tsa.py` and `attest.py` remain directory/subprocess APIs; they are not secretly tree-verifying entry points. The provenance helper defect F4 is evaluated on its own advertised API, not by pretending it belongs to the offline corpus pipeline.

**History scope, class (c):** I tested a corrupt same-length loose blob stored under its old OID. `verify_release_history_immutable` returned matching entry metadata; a following `snapshot.blob` refused the hash. The initial partial report provisionally called this high. Independent challenge established that PLAN §§3.2, 3.4–3.5 explicitly selects this metadata-only comparison, its public docstring promises entry comparison, and its return is a tuple rather than custody evidence. That proposed finding is withdrawn. No stronger standalone payload-authentication contract was found. The composed commands rehash candidate payloads before overall PASS. A fresh API should make this intermediate evidence impossible to mistake for a full payload audit.

**Runtime time, class (c):** the real-crypto clock probe demonstrated FAIL with the verifier clock ten minutes early and PASS with the actual clock for the same pinned tree. `release_chain.py:2025,1163-1167` checks future timestamps; `run_verification` neither accepts nor reports evaluation time. This is reasonable time-validity policy within the trusted runtime, not a demonstrated cryptographic false acceptance. A fresh reproducible API should expose and report the evaluation time and distinguish immutable evidence from that assessment. The abstract tree-contract sentence should be read with its stated trusted tool/runtime assumptions, not as a claim that elapsed-time/output fields or resource failures are mathematical constants.

## 2 From-scratch build

### Design from the contract, without migration obligations — class (c)

I would retain the central design: one authenticated object source, explicit immutable policy and trust, three separate checks for custody/binding/declarations, and precise limited claims. I would separate those concepts by types and module ownership instead of carrying the old directory-verifier call shape through the orchestrators.

A greenfield dependency direction would be:

```text
model, errors, canonical
        ↓
reader (git_process, object_codec, tree_walk, budgets)
        ↓
policy (names, attributes, protected views)   spec + trust
        ↓                                      ↓
journal     crypto/signatures     crypto/timestamps + witness transitions
        ↓                    ↓
     binding          custody          append
        └────────────────┬───────────────┘
                       verify
                         ↓
                    CLI / rendering

provenance: a separate explicit GitHub-attestation adapter over the same model
```

`TreePath` contains raw POSIX component bytes, with separate strict UTF-8/display operations. `Entry` is reader-created and binds mode, role, OID and snapshot identity. A `Repository` owns one frozen process environment, bounded batch child, object cache and work budget shared by candidate/base snapshots. Selection authenticates commit/tree before exposing identity. Internal `info` is metadata, never an authenticated-payload result; a digest/result is yielded only after complete OID rehash. Listing must expose empty trees, not only files. Every protected view applies names, modes, ancestor aliases and attributes before an extracted verifier can consume it.

Names belong in one policy module. Repertoires are closed enum choices, not filesystem guesses: portable ASCII/device/trailing-period/8.3 policy; otherwise exact valid-UTF-8 bytes, with ASCII-fold sibling refusal in both. Materialization still requires portable names regardless of the wider content repertoire. The Unicode display/control table belongs to output/journal policy, separately from name identity. Attribute syntax and precedence are a fixed, versioned policy; local `core.ignorecase` is not an input. Preserve the fail-closed grammar and independent budgets for parse size, states and matching work.

The chain verifier takes authenticated byte records and immutable trust material. Only the OpenSSL adapter writes private byte copies. It owns the exact original PEM, including trusted-certificate auxiliary settings, because re-encoding can change trust. The current single-certificate count, signer identity/policy checks and chronology rules stay. Directory input remains a separate explicitly named adapter; its source identity and concurrent-writer assumptions must not be confused with a selected tree. A capability such as `WitnessedJournal` can only come from successful custody, eliminating the public composition's raw-bytes assertion as a type-level shortcut.

`LoadedSpec` holds the raw source digest, validated `VerificationSpec` and trust basis. From scratch I would use a bounded declarative UTF-8 JSON spec, with duplicate-key refusal, strict field types, immutable mappings and an explicit schema version. The digest comparison occurs before parsing; no candidate Python executes. An optional trusted-code adapter, if genuinely needed by a consumer, would be explicitly named and take caller-constructed policy at the verifier-code trust level. It would not masquerade as a sandboxed or transitively pinned config file.

The pin ladder remains: commit pin selects identity/ancestry; tree pin selects content identity; spec pin binds policy; anchor-set pin binds the exact configured trust bytes. A pinned declarative spec can carry the anchor digest, and a direct anchor pin must agree with it. Unpinned policy/anchors can produce explicitly provisional evidence, never an auditor-trusted claim. Unlike executable specs, merely parsing an unpinned declarative file would not allow it to patch later independent comparisons; that is a deliberate greenfield contract improvement, not a claim that 0.6's documented trust model is hidden.

### Complete proposed public surface

The following is the public schema/signature inventory I would publish. All records are frozen, validate exact built-in types and bounds, and contain immutable collections. Mutable JSON is accepted only at the parsing/serialization boundary; constructors copy/deep-freeze evidence into tuples and immutable mappings, never retain a caller mapping. Records shown with constructor-style signatures are dataclasses; evidence records are library-created, not caller assertions. Generic `Outcome[T]` carries either typed evidence or a `Refusal`. Supporting implementation helpers, Git commands, callbacks, caches and compatibility renderers are private. This deliberately does not preserve every currently importable non-underscored helper.

```python
# model / policy / errors
JSON = None | bool | int | float | str | list[JSON] | dict[str, JSON]  # wire values
FrozenJSON = None | bool | int | float | str | tuple[FrozenJSON, ...] | Mapping[str, FrozenJSON]
NameRepertoire = Literal['portable', 'posix-bytes']
EntryMode = Literal['100644', '100755', '120000', '160000', '040000']
TrustBasis = Literal['caller-owned', 'auditor-pinned', 'producer-proposed']
GateTier = Literal['public', 'restricted', 'ci-attested']
GateOutcome = Literal['pass', 'waived', 'not-run']
Sha256(hex: str)
ObjectId(format: Literal['sha1'], hex: str)
TreePath(components: tuple[bytes, ...])
SnapshotIdentity(commit: ObjectId, tree: ObjectId)
TimePolicy(as_of: datetime, future_seconds: int, skew_seconds: int)
Limits(objects: int, entries: int, ancestry: int, depth: int,
       blob_bytes: int, content_bytes: int, tree_bytes: int,
       path_bytes: int, total_path_bytes: int, attribute_bytes: int,
       attribute_rules: int, attribute_states: int, attribute_work: int,
       materialized_bytes: int, git_output_bytes: int, git_seconds: float,
       fsck_objects: int, fsck_store_bytes: int,
       fsck_output_bytes: int, fsck_seconds: float)
ReadWork(counters: Mapping[str, int])
Refusal(code: ErrorCode, phase: str, subject: SnapshotIdentity | None,
        path: TreePath | None, details: Mapping[str, FrozenJSON])
Outcome[T](evidence: T | None, refusal: Refusal | None)
class ReceiptError(Exception):
    def __init__(self, refusal: Refusal) -> None: ...

def tree_path(value: str | bytes) -> TreePath: ...
def canonical_bytes(value: JSON) -> bytes: ...
def canonical_sha256(value: JSON) -> Sha256: ...
def format_refusal(error: Refusal, *, version: Literal[1] = 1) -> str: ...

# reader: Repository owns lifetime; Snapshot cannot outlive it.
Entry(path: TreePath, mode: EntryMode, oid: ObjectId)  # opaque provenance
BlobDigest(entry: Entry, sha256: Sha256, size: int)
EntryDelta(path: TreePath, before: Entry | None, after: Entry | None)
StoreReport(objects: int, store_bytes: int, seconds: float)
class Repository:
    def select(self, revision: str = 'HEAD', *,
               expect_commit: ObjectId | None = None,
               expect_tree: ObjectId | None = None) -> Snapshot: ...
    def require_ancestor(self, candidate: Snapshot, base: Snapshot) -> None: ...
    def verify_store(self, candidate: Snapshot,
                     base: Snapshot | None = None) -> StoreReport: ...
    @property
    def work(self) -> ReadWork: ...
class Snapshot:
    @property
    def identity(self) -> SnapshotIdentity: ...
    def lookup(self, path: TreePath) -> Entry | None: ...
    def entries(self, prefix: TreePath | None = None, *,
                include_trees: bool = True) -> Iterator[Entry]: ...
    def read(self, entry: Entry, *, limit: int) -> bytes: ...
    def digests(self, entries: Iterable[Entry], *, per_blob: int,
                total: int) -> Iterator[BlobDigest]: ...
    def changes(self, base: Snapshot) -> Iterator[EntryDelta]: ...
class Materialization:
    @property
    def path(self) -> Path: ...
    @property
    def entries(self) -> Mapping[TreePath, Entry]: ...
def open_repository(root: Path, *, limits: Limits) -> ContextManager[Repository]: ...
def materialize(snapshot: Snapshot, paths: Iterable[TreePath], *,
                repertoire: NameRepertoire,
                parent: Path | None = None) -> ContextManager[Materialization]: ...
ProtectedPaths(files: frozenset[TreePath], trees: frozenset[TreePath])
class ProtectedTree:  # created only by applying complete policy
    @property
    def snapshot(self) -> Snapshot: ...
    @property
    def paths(self) -> ProtectedPaths: ...
def protect(snapshot: Snapshot, paths: ProtectedPaths, *,
            repertoire: NameRepertoire) -> ProtectedTree: ...

# policy/spec/trust: path and byte identity are separate.
KeySpec(id: str, fingerprint: Sha256, scheme: Literal['spki', 'raw'])
KeyringSpec(current: tuple[KeySpec, ...], legacy: tuple[KeySpec, ...],
            threshold: int)
AuthoritySpec(id: str, filename: TreePath, pem_sha256: Sha256,
              root_spki: Sha256, signer_spkis: frozenset[Sha256],
              signer_certificates: frozenset[Sha256],
              policies: frozenset[str], imprint_oids: frozenset[str])
BundleSpec(id: str, path: TreePath, size: int, sha256: Sha256,
           canonical_sha256: Sha256, authorities: tuple[AuthoritySpec, ...])
WitnessSpec(bundles: tuple[BundleSpec, ...], legacy_bundle: str,
            max_token_lead_seconds: int)
GateSpec(id: str, tier: GateTier, required: bool)
CorpusSpec(content_roots: tuple[TreePath, ...], suffixes: frozenset[str],
           attested_paths: frozenset[TreePath], gates: tuple[GateSpec, ...],
           names: NameRepertoire)
ChainSpec(release_root: TreePath, manifests: TreePath, journal: TreePath,
          prefix: TreePath, anchors: TreePath, schema: str,
          producer_file: TreePath, producer: KeyringSpec,
          authorities: tuple[AuthoritySpec, ...], names: NameRepertoire)
AppendSpec(chain: ChainSpec, data_surface: frozenset[str],
           gate_surface: frozenset[str], manifest_prefix: str,
           observation_schema: str)
AttestSpec(repository: str, workflows: frozenset[str], ref: str,
           protected_prefix: TreePath, checker: TreePath)
VerificationSpec(version: int, name: str, chain: ChainSpec, corpus: CorpusSpec,
                 anchor_set: Sha256 | None)
LoadedSpec(verification: VerificationSpec, source_sha256: Sha256,
           source_path: Path | None, pinned: bool)
TrustMaterial(files: Mapping[TreePath, bytes], per_file: Mapping[TreePath, Sha256],
              anchor_set: Sha256, basis: TrustBasis)
PinSet(commit: ObjectId | None, tree: ObjectId | None,
       spec: Sha256 | None, anchors: Sha256 | None)

def load_spec(source: bytes, *, expect_sha256: Sha256 | None = None) -> LoadedSpec: ...
def load_spec_file(path: Path, *, expect_sha256: Sha256 | None = None) -> LoadedSpec: ...
def tree_trust(tree: ProtectedTree, spec: LoadedSpec, *,
               expect_anchor_set: Sha256 | None = None) -> TrustMaterial: ...
def external_trust(files: Mapping[TreePath, bytes], *, spec: ChainSpec,
                   expect_anchor_set: Sha256) -> TrustMaterial: ...

# signing, timestamp and witness transition API: exact bytes throughout.
SignatureEvidence(key_ids: tuple[str, ...], legacy_ids: tuple[str, ...])
TokenEvidence(digest: Sha256, time: datetime, policy: str,
              signer_spki: Sha256, signer_certificate: Sha256,
              signed_info_digest: Sha256)
WitnessState(active_bundles: tuple[str, ...], pending_bundles: tuple[str, ...])
WitnessEvidence(status: Literal['available', 'unavailable'],
                tokens: tuple[TokenEvidence, ...], reason: str | None)
WitnessStep(evidence: WitnessEvidence, next_state: WitnessState)

def generate_signing_keypair() -> tuple[bytes, bytes]: ...
def sign_payload(payload: bytes, private_key: bytes, *, domain: bytes = b'') -> bytes: ...
def key_fingerprint(public_key: bytes, *, scheme: Literal['spki', 'raw']) -> Sha256: ...
def verify_signature(payload: bytes, signature: bytes, public_key: bytes, *,
                     expect_spki: Sha256) -> Outcome[SignatureEvidence]: ...
def verify_threshold(payload: bytes, signatures: Mapping[str, bytes],
                     public_keys: Mapping[str, bytes], spec: KeyringSpec, *,
                     domain: bytes, allow_legacy: bool) -> Outcome[SignatureEvidence]: ...
def verify_any_generation(payload: bytes, signature: bytes,
                          public_keys: Mapping[str, bytes], spec: KeyringSpec, *,
                          domain: bytes) -> Outcome[SignatureEvidence]: ...
def verify_timestamp(payload_digest: Sha256, response: bytes, *,
                     authority: AuthoritySpec, root_pem: bytes,
                     at: TimePolicy) -> Outcome[TokenEvidence]: ...
def initial_witness_state(genesis: bytes, *, spec: WitnessSpec,
                          files: Mapping[TreePath, bytes]) -> Outcome[WitnessState]: ...
def verify_witness_step(record: bytes, witness: bytes, *, spec: WitnessSpec,
                        files: Mapping[TreePath, bytes], prior: WitnessState,
                        at: TimePolicy) -> Outcome[WitnessStep]: ...

# semantic verification and orchestration
FileBinding(path: TreePath, sha256: Sha256, journal_index: int)
GateDeclaration(id: str, tier: GateTier, outcome: GateOutcome,
                evidence: Mapping[str, FrozenJSON], journal_index: int)
JournalView(content: tuple[FileBinding, ...], attested: tuple[FileBinding, ...],
            removed: tuple[FileBinding, ...], gates: tuple[GateDeclaration, ...])
WitnessedJournal(data: bytes, sha256: Sha256, tree: SnapshotIdentity)
ReleaseEvidence(name: TreePath, digest: Sha256,
                signature: SignatureEvidence, witnesses: tuple[TokenEvidence, ...])
ChainEvidence(subject: SnapshotIdentity, releases: tuple[ReleaseEvidence, ...],
              journal: WitnessedJournal, trust: TrustMaterial)
EntryComparison(base: SnapshotIdentity, candidate: SnapshotIdentity,
                additions: tuple[TreePath, ...])  # metadata evidence only
BindingEvidence(content_files: int, attested_files: int,
                removed: tuple[TreePath, ...], journal: JournalView)
DeclarationEvidence(gates: tuple[GateDeclaration, ...])
AppendEvidence(candidate: SnapshotIdentity, base: SnapshotIdentity | None,
               rows: int, prefix_rows: int, appended_rows: int,
               chain: ChainEvidence | None, names: NameRepertoire)
DirectoryEvidence(root: Path, releases: tuple[ReleaseEvidence, ...],
                  journal_sha256: Sha256, trust: TrustMaterial)
VerificationResult(candidate: SnapshotIdentity | None,
                   base: SnapshotIdentity | None, spec: LoadedSpec,
                   at: TimePolicy, completed: tuple[str, ...],
                   chain: ChainEvidence | None, binding: BindingEvidence | None,
                   declarations: DeclarationEvidence | None,
                   history: EntryComparison | None, store: StoreReport | None,
                   refusal: Refusal | None)

def parse_journal(data: bytes, *, spec: CorpusSpec) -> Outcome[JournalView]: ...
def verify_custody(tree: ProtectedTree, *, spec: ChainSpec,
                   trust: TrustMaterial, at: TimePolicy) -> Outcome[ChainEvidence]: ...
def compare_release_entries(candidate: ProtectedTree, base: ProtectedTree, *,
                            spec: ChainSpec) -> Outcome[EntryComparison]: ...
def verify_binding(tree: Snapshot, journal: WitnessedJournal, *,
                   spec: CorpusSpec) -> Outcome[BindingEvidence]: ...
def verify_declarations(journal: JournalView, *,
                        spec: CorpusSpec) -> Outcome[DeclarationEvidence]: ...
def verify_append(candidate: ProtectedTree, *, base: ProtectedTree | None,
                  spec: AppendSpec, trust: TrustMaterial,
                  at: TimePolicy) -> Outcome[AppendEvidence]: ...
def verify_directory(root: Path, *, spec: ChainSpec, trust: TrustMaterial,
                     at: TimePolicy) -> Outcome[DirectoryEvidence]: ...
def run_verification(root: Path, spec: LoadedSpec, *, commit: str = 'HEAD',
                     base_ref: str | None = None, pins: PinSet, at: TimePolicy,
                     limits: Limits, verify_objects: bool = False) -> VerificationResult: ...

# provenance is explicitly online, separate from the offline corpus verdict.
ProvenanceEvidence(commit: ObjectId, repository: str, signer_uris: frozenset[str])
def attestation_subject(repository: str, commit: ObjectId) -> bytes: ...
def repository_slug(root: Path) -> str: ...
def enforcement_epoch(root: Path, *, spec: AttestSpec) -> ObjectId: ...
def protected_commits(root: Path, revision_range: str, *,
                      spec: AttestSpec) -> tuple[ObjectId, ...]: ...
def verify_commit_attestation(root: Path, commit: ObjectId, *, spec: AttestSpec,
                              at: TimePolicy) -> Outcome[ProvenanceEvidence]: ...

# CLI and rendering
def result_to_dict(result: VerificationResult) -> dict[str, JSON]: ...
def render_text(result: VerificationResult) -> str: ...
def render_json(result: VerificationResult) -> bytes: ...
def main(argv: Sequence[str] | None = None) -> int: ...
```

`ErrorCode` is the closed 64-member enum described below; other capitalized standard collection/context/time/path names in the signatures are standard-library types. `Limits` and `TimePolicy` are explicit so a reproducibility claim does not hide default clock or resource policy. `VerificationResult` requires all configured stages for PASS, with separate immutable evidence and failure fields. No separate `verify_base_release_chain` is necessary: open/select/protect the base and call `verify_custody`. No public raw-byte custody substitute is necessary: use `verify_directory` for the directory contract and `WitnessedJournal` for proven composition.

### CLI, refusal structure, test architecture, dependencies and size

I would keep the current CLI command and recognizable pin flag names. Parsing selects one declarative spec and one repository context, captures one explicit evaluation time, enforces base/commit binding, runs all configured stages, then emits a versioned result. Text has an immutable final PASS/FAIL sentinel; JSON is UTF-8 with stable error codes, bounded fields, explicit subject/trust/time/object-store status and exit status authoritative. The codec/short-write/flush protections already earned by `cli.py` stay, preferably in a small output module. Arbitrary custom streams should not force the verifier to accept arbitrary stateful encodings.

For the greenfield refusal vocabulary I would budget **64 stable typed codes**, each with a canonical human template and structured detail: 8 runtime/repository, 12 object/authentication/framing, 10 path/name/attribute, 8 spec/pin/trust, 10 custody/signature/witness, 6 journal/binding, 4 append, 3 declaration, 3 output. This is a proposed closed code vocabulary, not a claim that every current refusal can be folded into 64 indistinguishable strings. A code identifies the invariant; fields carry object role, scope, raw/display path, actual/expected digest, attribute state, budget and reason. A closed reason enum distinguishes subcases consumers need. Legacy text rendering is a separate versioned adapter while migrating from 0.6; no consumer should have to parse “index” to learn that the subject is a tree.

The complete proposed `ErrorCode` enum is:

| Family | Enum members |
|---|---|
| Runtime/repository (8) | `TOOL_MISSING`, `TOOL_VERSION`, `PLATFORM_UNSUPPORTED`, `REPOSITORY_INVALID`, `REPOSITORY_LAYOUT`, `REPOSITORY_CONFIG`, `ENVIRONMENT_REDIRECT`, `CONFIG_CHANGED` |
| Objects (12) | `OBJECT_FORMAT`, `REVISION_UNRESOLVED`, `OBJECT_MISSING`, `OBJECT_ROLE`, `OBJECT_HASH`, `OBJECT_FRAMING`, `COMMIT_SYNTAX`, `TREE_SYNTAX`, `ANCESTRY`, `READ_BUDGET`, `STREAM_STATE`, `STORE_INTEGRITY` |
| Paths/policy (10) | `PATH_SYNTAX`, `PATH_MISSING`, `PATH_MODE`, `PATH_SYMLINK`, `PATH_GITLINK`, `NAME_ENCODING`, `NAME_REPERTOIRE`, `NAME_COLLISION`, `ATTRIBUTE_SYNTAX`, `ATTRIBUTE_TRANSFORM` |
| Spec/trust (8) | `SPEC_SYNTAX`, `SPEC_SCHEMA`, `SPEC_DIGEST`, `SPEC_TRUST`, `COMMIT_PIN`, `TREE_PIN`, `ANCHOR_PIN`, `PIN_CONFLICT` |
| Custody/crypto (10) | `KEY_FORMAT`, `KEY_PIN`, `SIGNATURE_INVALID`, `THRESHOLD_UNMET`, `MANIFEST_SCHEMA`, `CHAIN_LINK`, `STATE_BINDING`, `TOKEN_INVALID`, `WITNESS_POLICY`, `TRUST_TRANSITION` |
| Journal/binding (6) | `JOURNAL_SYNTAX`, `JOURNAL_SCHEMA`, `CONTENT_UNLISTED`, `BOUND_FILE_MISSING`, `CONTENT_DIGEST`, `TOMBSTONE_PRESENT` |
| Append (4) | `SURFACE_MIXED`, `SURFACE_UNCLASSIFIED`, `PREFIX_CHANGED`, `APPEND_VIOLATION` |
| Declarations (3) | `GATE_MISSING`, `GATE_SCHEMA`, `GATE_TIER` |
| Output (3) | `OUTPUT_SCHEMA`, `OUTPUT_ENCODING`, `OUTPUT_WRITE` |

A refusal carries the exact subreason (for example signer reuse, authority split/merge, timestamp regression, repeated anchor bytes, or a particular resource ceiling) as a typed detail, so this organization does not collapse those invariants. `TOOL_*` and `OUTPUT_*` also distinguish an unavailable execution from a negative judgment of candidate data.

Tests would be organized by invariant and trust boundary:

- Pure parser/policy units: raw commit/tree canonicality, role binding, UTF-8/portable policy, attribute syntax/precedence, schema bounds and canonical JSON.
- Adversarial object repositories: corrupt loose/packed objects, forged headers/entry provenance, replace/graft/shallow/promisor/alternate/config controls, mixed modes, empty trees, hostile names, disjoint protected prefixes and all entry points.
- Properties/metamorphic tests: same pinned inputs give the same decision under checkout/index changes, locale and allowed repository settings; full and standalone compositions enforce the same protected policy; cost counters grow within stated bounds; abandoned streams cannot be reused. Distinguish trusted-runtime time from immutable evidence.
- Real cryptography: generated and authenticated fixture chains, exact PEM/signature/token byte capture, algorithm confusion, authority split/merge/rotation, duplicate token identity, auxiliary PEM trust, chronology, and before-use pins. Test supported backends rather than maintaining an unpromised fallback solely for tests.
- Delivery tests: real CLI plus hostile/partial streams, complete JSON failure boundary, no terminal control injection, exact nonclaims and stage completeness.
- Differential harnesses: keep all 108 current cases as a compatibility adapter suite even though greenfield design would not need checkout-era semantics. Preserve oracle hashes, two legs and zero-skip requirement. Add behavioral properties independently; a clean historical fixture is not a test of the complete input domain.

A re-pin record must name old/new subject, unchanged oracle hashes, exact cases affected, raw old/new outputs, the reason and scope of each deliberate disagreement, and exact reviewed commits/results. The existing 26/68/14 census is a good model. Neither a generic whitespace normalization nor a broad exception wrapper should erase new refusals. Archive prior review mutations as regression cases with concise rationales, not necessarily as thousands of lines of narrative beside runtime code.

For the first greenfield implementation I would keep the **measured current floors**: Python 3.11+, `cryptography>=42` for Ed25519, Git 2.36 for the batch protocol, Git 2.50 with SHA1_DC for the optional store-wide command, OpenSSL 3.0 for RFC 3161/CMS and certificate counting, and POSIX with `O_NOFOLLOW` for path adapters. Pure byte parsers/signatures could be portable; that does not justify claiming the whole package runs wherever Git does. SHA-256 support waits for a complete object/corruption fixture. `gh` and network access belong solely to the optional provenance adapter, not the offline verdict. Do not remove OpenSSL by inventing a lightly reviewed ASN.1/CMS trust verifier; the current parser/counting lessons show the risk.

**Size estimate:** approximately **11,000–14,000 production physical lines**, including concise contract documentation, and **25,000–35,000 test/fixture lines**, for equivalent shipped functionality. Reader/policy/materialization would be about 2,000–2,800 lines; journal/binding/append around 2,200–2,800; custody/crypto/witness transitions remain the largest semantic area; CLI/orchestration/provenance make up the balance. This is an engineering estimate, not a promised target. The current 17,998 lines include about 4,103 docstring lines and extensive forensic commentary: TSA alone has 1,599 docstring lines, CLI 815. Much apparent size is retained review history, while snapshot still contains roughly 3,009 nonblank/non-comment/non-docstring lines. A tiny rewrite would almost certainly have discarded hard-won constraints, not discovered a tenfold simpler proof.

### Concrete comparison with this head

| Current structure | Greenfield treatment and reason | Class |
|---|---|---|
| `snapshot.py:445-808,814-964,1224-1587,1592-3020,3031-3470` combines process, parser, traversal, attributes and materialization | Split private implementation modules under one reader façade; keep raw object rehash and type/role validation unchanged in substance. | (c) |
| Two snapshots own resources and then share work through mutable budget linkage (`snapshot.py:232-265,2284-2346`) | One repository/budget context, immutable selected views. This reduces lifecycle/counter states without weakening bounds. | (c), suitable later (b) refactor |
| `GitEntry` public construction/re-export (`snapshot.py:194-219`; `release_chain.py` import) | Opaque authenticated `Entry`; avoid compatibility fields that look like authority but are unusable until reader-bound. Current provenance validation is correct and better than a naïve dataclass. | (c) |
| Tree reader knows `ChainSpec`-shaped anchor filenames (`snapshot.py:3403-3470`) | Move anchor-set construction into trust policy over authenticated bytes/digests; keep injective normalized mapping and exact-byte pre/post comparison. | (c) |
| `_as_text` deliberately emulates checkout `read_text` (`append_gate.py:238-251`) | Drop locale emulation. This is genuine migration machinery, and F3 demonstrates its cost. | Fix now (a); design explanation (c) |
| `_CandidateTree` / `_BaseCommit` (`append_gate.py:66-81`) carry repeated paths/ref/identity | One verification context with derived normalized paths; fewer transport objects for old helper signatures. | (c) |
| Corpus local fold pass followed by shared fold pass (`corpus.py:1552-1573`) and portability/short-name adapters (`738-905`) | One typed policy failure plus a legacy text renderer. The second fold exists to preserve exact text. | (b)/(c) |
| Observation schema validation lives in append orchestration (`append_gate.py:273-555`) | Separate immutable observation/journal policy from generic byte-prefix/history orchestration. Preserve exact byte append, supersession and binding-shape checks. | (c) |
| `verify.py`, `release_chain.py`, `append_gate.py` each assemble selected paths, trust and reader-to-directory transitions (`verify.py:601-723`; `append_gate.py:784-928,1041-1140`; `release_chain.py:2223-2270`) | Share a `ProtectedTree` and immutable trust adapter, with separate custody/binding/append semantics. Do not merge all verifiers into one giant module. F2 illustrates the risk of caller-owned screen assembly. | (a) missing screen; later (b) consolidation |
| Direct path guards (`release_chain.py:479-644,1336-1629`) remain beside object reads | Keep them in the explicitly separate directory adapter. They are not dead guards merely because the principal CLI materializes; real direct callers and trusted anchor directories still need them. | Keep (c) |
| Uncalled compatibility guard `assert_no_symlinked_state_component` (`release_chain.py:1428-1459`) and stale closing-read explanation (`1663-1669`) | Remove/deprecate only after public-import census; delete explanations whose mechanisms are gone. | (b)/(c) |
| Directory leaf flags (`release_chain.py:1927-1940`), especially `state_bytes`, `compute_anchor_set_digest`, optional production pinning | Byte/evidence core with explicit trust authority, directory wrapper for legacy behavior. These flags are not all dead: tests/direct callers use them; the main command fixes a stricter combination. | (c) |
| OpenSSL producer fallback (`sign.py:44,117-184,218-228`; `release_chain.py:875-895`) | Remove when `cryptography` is mandatory. Forced fallback accepts a 64-byte RSA-512 signature with matching RSA SPKI whereas the normal backend refuses non-Ed25519. This occurs only when the mandatory dependency is absent/forced off; it is not demonstrated in a supported installed configuration. It is strong evidence against preserving an unused backend. | (c), post-tag scope decision |
| TSA witness API wrappers retain public legacy call shape and private additional evidence (`tsa.py:2527-2570,4140-4263`) | Keep one explicit transition-step API with immutable prior/current state and evidence. Do not discard authority-class/split/merge/duplicate-token checks merely to shorten it. | (c) |
| CLI commentary and emission machinery (`cli.py:1-250,395-623,1026-1578`) | Move forensic history to design records; keep fused escaping/bounds, safe codecs, partial writes and final sentinel. The current code is substantially better than naïve `print(json.dumps(...))`. | (b)/(c) |
| `verify_release_history_immutable` returns a positional tuple (`release_chain.py:2174-2220`) | Rename/retype as entry comparison; if exposing an independent byte-authentication function, explicitly add bounded blob rehash instead of extending the tuple's meaning by implication. | (c), not a tag finding |

The current package is better than a naïve fresh implementation in several crucial ways: canonical raw Git parsing instead of trusting `ls-tree`; object-role checks as well as OID checks; exact authenticated fsck heads; bounded cumulative work rather than only per-file caps; unavailable-witness semantics and authority-history equivalence; one-certificate OpenSSL counting without PEM re-encoding; shared captured state/anchor bytes; repertoire distinctions without speculative Unicode filesystem equivalence; and hostile-stream-safe verdict delivery. Those are part of the product. Moving them is review work, not a safe consequence of fewer lines.

### Cost, release decision and named later scope

A broad pre-tag restructure would discard much of the value of the review already invested in this exact shape. The current 108-case harness is powerful evidence for compatibility but does not prove arbitrary refactoring: 26 cases deliberately changed subject, 68 stayed unchanged and 14 are new invariants. Chronicle's shim is a known consumer of exact text. Public helper imports, both directory and tree contracts, saved paper claims and the release evidence all need a migration ledger. The test suite must move with the proof obligations; its deletion is not a success metric. As a planning estimate, the narrow corrections are roughly 2–5 engineering days plus an independent review cycle; the 0.7 internal scope is roughly 2–4 engineering weeks plus 1–2 weeks of overlapping review/consumer validation for one implementation lane and one peer. A declarative-spec/public-error migration needs its own consumer inventory before a reliable schedule can be given. These are estimates, not elapsed time required to reproduce the findings.

My recommendation is **hold this head for F1–F6 only, then tag the corrected exact reviewed commit and plan a 0.7 restructure named “shared tree policy and typed evidence.”** Of the proposed options, this is a hold on the tag, with pre-tag restructuring limited to the shared-policy boundaries needed by those corrections. The tag cannot wait for later fixes because F1 permits a fully pinned forbidden proposal to pass, F2 bypasses a required refusal through a public verifier, and F3–F6 leave demonstrably false behavior/contracts in the release being certified. None requires replacing the reader, cryptography or verifier architecture.

Pre-tag completion is concrete: define/test deterministic attribute policy; apply protected-name policy to direct base verification; use deterministic append UTF-8/refusals; fix origin parsing; correct the two docstrings; run focused regressions, the offline suite and all four authenticated harnesses at zero skips; obtain review of the new exact head; rebuild and smoke the wheel and sdist separately; bind the chosen tag target and published artifacts to those results. Re-pin only genuinely changed outcomes and document them explicitly.

For **0.7**, retain exact public text and return adapters while extracting a single protected-tree policy, repository/budget context, deterministic journal parser and immutable trust/evidence core. Move historical commentary to design records. Require consumer import/call-site checks and all compatibility suites at each step. For **1.0**, if desired, publish declarative specs, closed typed refusal codes, a smaller explicit public API, distinct entry-comparison/directory/tree evidence, and reported evaluation time; migrate Chronicle's text matching first. Replacing executable specs and changing error text are separate public contracts, not incidental cleanup.

## 3 The verdict block

---SUBFLEET-VERDICT-BEGIN---
{"schema_version": 1, "artifact_revision": {"kind": "pr", "repository": "TheAxiomFoundation/receipt", "number": 58, "head_sha": "bd64008e693af89e7bf1d023077a105773ee02ee", "base_sha": "a768d99498ff8caa192d78f6187540fe749116f8"}, "findings": [{"severity": "high", "location": "src/receipt/snapshot.py:3076-3102", "description": "Local core.ignorecase changes a fully pinned real signed corpus from transforming-attribute FAIL to complete PASS: releases/** filter=evil followed by RELEASES/** -filter. Commit, tree, spec and anchor pins remain identical. Define deterministic attribute policy independent of repository configuration and add the end-to-end invariant regression.", "residual_class": false, "blocks_tag": true}, {"severity": "high", "location": "src/receipt/release_chain.py:2237-2270; src/receipt/snapshot.py:3208-3262", "description": "Standalone verify_base_release_chain accepts a signed tree containing regular releases/extra beside empty tree releases/EXTRA, bypassing the required sibling-name refusal. The composed command refuses later during binding. Independently reproduced with real crypto. Screen protected entries including empty trees and ancestor siblings before base verification.", "residual_class": false, "blocks_tag": true}, {"severity": "medium", "location": "src/receipt/append_gate.py:238-251,559-595,1218-1222", "description": "Base ledger decoding uses the locale while candidate decoding uses UTF-8. The same valid Unicode append accepts under UTF-8, falsely reports rewritten history under ISO-8859-1, and leaks UnicodeDecodeError under ASCII. Independently reproduced in child processes; the raw-byte guard prevents demonstrated rewrite acceptance. Use deterministic UTF-8, stable decode refusals and locale regressions.", "residual_class": false, "blocks_tag": true}, {"severity": "medium", "location": "src/receipt/attest.py:224-231", "description": "repository_slug truncates receipt.audit.git to receipt and accepts notgithub.com or a foreign URL path containing github.com as GitHub identity. Real local-origin probes reproduce this; no forged attestation is claimed. Parse and validate the actual URL/SCP authority and complete repository component, stripping only terminal .git; add dotted-name and hostile-origin tests.", "residual_class": false, "blocks_tag": true}, {"severity": "medium", "location": "src/receipt/corpus.py:763-766", "description": "The portable-name docstring falsely says every real corpus was already portable and refusing other names costs nothing. PLAN section 2 and CHANGELOG lines 399-405 record 33 nonportable rulespec-us names; positive posix-bytes tests confirm the distinction. Replace the obsolete universal claim with the declared policy and its known cost.", "residual_class": false, "blocks_tag": true}, {"severity": "medium", "location": "src/receipt/release_chain.py:1949-1953", "description": "The public contract says every input file is opened once, but a genuine two-release verification reads each producer/TSA anchor twice. Independently counted guarded reads without changing their bytes. Correct the sentence to once per consumption with repeated anchor observation, consistent with ChainVerification documentation; concurrent-writer exploitation remains residual.", "residual_class": false, "blocks_tag": true}, {"severity": "low", "location": "src/receipt/append_gate.py:865-867; src/receipt/release_chain.py:1307-1312,1663-1669,1702-1754; src/receipt/snapshot.py:3242-3244", "description": "Retained text names index, working-tree, descriptor-descent and base-tree mechanisms when current paths inspect tree entries, supplied bytes or candidate materializations. Source/call-site tracing confirms the mismatch. Correct explanations and expose structured subjects later while preserving consumer-pinned legacy messages unless explicitly migrated.", "residual_class": false, "blocks_tag": false}], "notes": ["Defensive whole-package audit at d6ca1a83d580c1c902f992412a6933da75c8387d; independently confirmed its tree equals PR head: 61ef6469caaeb06bd419348f1d6931d9e24d1481. No tracked edits, commits or pushes. Full report is the sandbox fallback REVIEW-060.md.", "Required offline suite: 1368 passed, 108 deselected. Four harnesses: 108 passed, zero skips with authenticated local ledger and Brier extractions; the initial requested invocation had 71 passes and 37 blocked-network fixture setup errors.", "Verified fetched-payload rehash/type binding, spec pin before execution, normalized pre-crypto anchor binding, consumed-digest equality, shared journal bytes and private OpenSSL inputs. Saved wheel/sdist hashes match recorded smoke evidence and every packaged Python module matches this checkout.", "The history helper is intentionally metadata-only under the governing plan; its same-OID corruption probe is a scope/design observation, not an independent payload-authentication finding. Direct-directory writer, trusted-runtime time and mandatory-dependency fallback observations are separately qualified in the report.", "Hold for six targeted corrections, then tag the corrected exact reviewed commit and plan a 0.7 shared-tree-policy/typed-evidence refactor; preserve all 108 harness cases and legacy refusal rendering, reserving declarative-spec and public-error changes for a coordinated later release."], "summary": "Changes are requested for two required-refusal bypasses, locale-dependent append refusal, incorrect repository identity parsing and two false contract docstrings; all required suites pass.", "verdict": "changes_requested"}
---SUBFLEET-VERDICT-END---
