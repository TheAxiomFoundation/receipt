# Independent review — receipt 0.7 M1 design record, round 1

Defensive correctness and completeness audit of
`docs/design/0.7-m1-protected-tree-policy.md` at
`2144f075c6a9dd1dd1359e3f530081d9068d1c20`, read in the detached worktree
`/Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-07-m1-review`
(`git status` clean, `git diff v0.6.0 -- src tests CONTRIBUTING.md` empty,
`e404d59298c972993b268494c726472a2613f3b3` confirmed an ancestor of HEAD).
The record was written by a different lane; I re-derived every claim I report
on with my own commands. I did not edit the record and did not run subagents.

Reviewer stance: the person who has to implement this and then defend the
result to Chronicle, whose harness compares complete normalized stderr bytes
(`tests/test_receipt_shim_transparency.py:152–161,187–216` at
`origin/codex/thesis-ledger-facts`).

**Verdict: changes requested.** Every factual claim I checked held — the
census, the twelve disagreements, the consumer surface, the test-pin gaps, the
suite counts. The changes I am asking for are additive, and one of them is
load-bearing: the record does not state an observable precedence obligation
that its own `finding_for` selection mechanism is the most likely thing to
break, no existing test covers it, and none of the nine risk probes would
catch it. I demonstrate it below.

## What I ran

| Command | Result |
|---|---|
| `git diff v0.6.0 -- src tests CONTRIBUTING.md` | empty |
| `sed -n '635,801p' <record> > complete-probes.py; PYTHONPATH=src .venv/bin/python complete-probes.py` | exit 0, 40.4s, 52 JSONL rows (43 cases + fixture dir + 4 historical + 4 repeat-charge) |
| `sed -n '822,880p' <record> > contract-probes.py; PYTHONPATH=src .venv/bin/python contract-probes.py` | exit 0, 4.9s, 9 rows |
| isolated reader probes on the driver's `symlink_releases` / `gitlink_releases` commits | reproduces the record's supplemental table |
| my own append alias-screen interleave probe (`/tmp/receipt-m1-review/interleave.py`) | new evidence, §4b |
| `.venv/bin/python -m pytest --ignore-glob='tests/test_*_equivalence.py' -q` | **1466 passed**, zero skips, exit 0, 410.68s |
| `RECEIPT_LEDGER_TREE=… RECEIPT_BRIER_TREE=… pytest -q tests/test_*_equivalence.py` | **108 passed**, zero skips, exit 0, 291.48s |
| `pytest --collect-only -q` per harness file | 43 / 28 / 17 / 20 = 108 |
| `git -C /Users/maxghenis/PolicyEngine/chronicle show|grep origin/codex/thesis-ledger-facts:…` | no checkout performed |
| `git -C …/axiom-encode grep`, `git -C …/thesis grep` on `origin/main` and the 0.6 adoption refs | §3 |

Probe artifacts: `/tmp/receipt-m1-review/{complete-probes.jsonl,contract-probes.jsonl,interleave.py,non-harness.log,harness.log}`.

---

## 1. The census — **CONFIRMED**

I verified 30+ sites (the brief asked for fifteen) on line range, condition
checked, tree region covered, and exact refusal expression. Every one matched.

**verify.py**
- `638–645` — history call before custody; `verify_release_history_immutable(normalized_chain, candidate=…, base=…)`. CONFIRMED.
- `658–673` — five prefixes in the stated order; `candidate.entries("").as_dict(include_trees=True)`; `release_directories=(release_root, manifest)`. CONFIRMED. `as_dict`'s `include_trees` default is `False` (`snapshot.py:1670`), so the record's separate claim that history enumerates only non-tree release descendants is right.
- `675–691` (`state_blob`) — exact-string adapter `if str(exc) == f"tree entry does not exist: {display}"` at 680; the three expressions at 682, 686, 689; `display = relative.as_posix()` at 676; `MAX_JOURNAL_BYTES` at 691. CONFIRMED.
- `702–709` — materialize five prefixes, then `refuse_transforming_attributes(materialized.entries.values())` at 707–709, before `anchor_set_sha256` at 710. CONFIRMED.
- `776–777` / `781–795` — history wrapper text exact; custody stores the unmodified message via `failed("custody", exc, (ReleaseChainError, SnapshotError))` at 792, and 784 discards every non-history pass. CONFIRMED (the record's "Finalization auditing … may invalidate prior passes" is 784).
- `336–345` — spec-path screen, correctly excluded from M1. CONFIRMED.

**release_chain.py**
- `2185–2231` — candidate modes (2201/2203) before base modes (2207), missing (2212), mode change (2217), OID change (2222); all six history expressions verbatim at 2202, 2204, 2209, 2214–2215, 2219–2220, 2224–2225. CONFIRMED.
- `2238–2333` (`_screen_protected_tree_names`) — alias (2272–2295) → repertoire (2296–2312) → sibling merge (2313–2317) → portable DOS suffix (2318–2331) → `except NamePolicyError → ReleaseChainError(str(exc))` (2332–2333). Sort key `(entries[path].mode == "040000", path)` at 2273; `prefix = "/".join(exact[path][:depth])` at 2290. The lazy-vs-eager fold asymmetry is exactly as described: `listed_folded = _folded_parts(listed) if alias_paths is not None else ()` at 2276, extended one component at a time at 2281–2284 when `alias_paths is None`. CONFIRMED.
- `2352–2376` (`verify_base_release_chain`) — four prefixes, anchors appended only when `anchor_dir is None` (2359–2360); names before materialization; attributes at 2376; no `SnapshotError → ReleaseChainError` wrapper here. CONFIRMED.
- `487–568` — expressions at 551–552/566–567, 556–557, 563. CONFIRMED.
- `571–607` — 579, 589, 606. CONFIRMED.
- `1311–1325` + `1435–1466` — expression at 1322–1325. `grep -rn assert_no_symlinked_state_component src/ tests/` returns exactly one hit, the definition: the record's "exported legacy guard, no production call, no dedicated test" is exactly right. CONFIRMED.
- `1343–1432` — 1419–1422 and 1429–1432; ENOENT/ENOTDIR return at 1411–1418. CONFIRMED.
- `1469–1542` — 1534–1536 and 1537–1540. CONFIRMED.
- `1553–1635` — 1572–1576, 1585, 1587, and the ancestor-vs-leaf split at 1598–1601. CONFIRMED.
- `1984–2015` — 1999–2001, caller-anchor exemption at 1986, walk at 2013 and manifest guard at 2015 after the probe. CONFIRMED.
- `1082–1112`, `441–445`, `870–875`, `926–931`, `964–971`, `1108–1111` — every caller-specific shape string verbatim. CONFIRMED.

**append_gate.py**
- `746–765` (`_state_entry`) — 756–759, 762, 764 with `AppendError`. CONFIRMED.
- `792–851` — ancestor loop 826–835 (absence allowed at 831; 834 symlink; 835 non-directory; both `SnapshotError`), shared helper 839–848 with `alias_paths=protected`, wrapper 849–850. CONFIRMED.
- `149–170` (`_is_protected`) — surfaces + release root subtree + release-root proper ancestors. CONFIRMED.
- `854–874` (`_attribute_entries`) — regular modes ∪ `_is_protected` ∪ four materialization prefixes, `sorted(entries.items())`. CONFIRMED.
- `877–891` / `894–903` / `916–921` — 889, 891; manifest-path skip at 886. CONFIRMED.
- `1056–1068` — expression at 1066–1067. CONFIRMED.
- `644–661` + `1170–1178` — 661. CONFIRMED.
- `948–955`, `997–999`, `1007–1014`, `1034–1035`, `1078–1079`, `1273–1274` — the `base release chain is invalid: ` prefix is applied only to `ReleaseChainError` at 1014; `SnapshotError` escapes to 1273–1274. CONFIRMED, and this really is observable text.
- `1094–1099` and the gate-only return at `1105–1117`. CONFIRMED.

**corpus.py**
- `539–561` (`_quoted`), `738–760`, `883–934`, `1430–1439`, `1441–1475`, `1495–1518`, `1520–1548`, `1565–1587`, `1595–1606`, `1608–1616`, `1618–1631`, `1633–1642`, `1646–1663`, `1666–1682`, `1764–1817`, `1758–1762`, `1317–1326`, `1468–1473` — all expressions verbatim, all orderings as described. CONFIRMED. `assert_no_merging_tree_names` at 1542 is an import alias of `_names.assert_no_merging_entries` (`corpus.py:56`), so the record's phrasing is accurate.
- Budget arithmetic checks out: `MAX_JOURNAL_ROWS` 4096 × `MAX_PATH_TEXT` 1024 = 4,194,304; 4096 × `MAX_PATH_COMPONENTS` 512 = 2,097,152.

**snapshot.py**
- `797–844`, `2514–2542`, `2620–2645`, `2648–2687`, `2690–2703`, `2931–2950`, `2964–2967`, `3033–3045`, `3090–3101`, `3112–3141`, `3164–3174`, `3194–3249`, `3266–3280`, `3295–3309`, `3367–3387`, `3414–3437`, `3442–3446`, `3451–3456` — every expression verbatim. `_RAW_MODES` is exactly `{100644,100755,120000,160000,40000}` (155). `TreeListing.__iter__ → iter_entries(include_trees=False)` (1643–1644, 1631–1634), so the record's "TreeListing iteration excludes trees" is right. Every budget constant matches (128–147). CONFIRMED.

**_names.py**
- `75–83`, `113–172`, `175–181`, `184–206`, `209–217`, `220–233`, `236–268`, `271–295`, `298–320`, `323–386` — all expressions verbatim. `ALIAS_CAPABLE_SUFFIX_RE = r"\.[A-Za-z0-9_-]{1,3}\Z"` (49), so `.yaml` and `.tar.gz` are not alias-capable and `.jsonx→.JSO` / `.sigx→.SIG` / `.tsrx→.TSR` behave exactly as claimed. CONFIRMED.

**Cited test pins, sampled:** `test_release_chain.py:293–329` (substring) and `332–402` (exact `==` at 402); `446–467` and `470–499` (exact, both repertoires × empty/nonempty × protected/ancestor); `537–592` (exact, ×2 repertoires ×3 shapes ×2 locations ×2 entry points); `595–633` (verdict-only, correctly typed `V` — the second half asserts `pytest.raises` with no message); `790–817` (exact); `833–852` (exact equality at 849 plus substring at 850). `test_append_gate.py:583–618` (exact `transforming attribute filter applies to protected path ledger/immutable_prefix.json`); `test_verify.py:740–783` (exact, ignorecase-independent). `test_snapshot_features.py:778–782` (exact, `tree root` label), `1231–1248` (`work.attribute_match_work == 1_011_000`), `1289–1303` (fully anchored, text at 1300). `test_snapshot.py:1239–1253` (fully anchored). All CONFIRMED.

**The census gaps are real.** I grepped `tests/` for thirteen of the strings
the record says have no exact pin — `protected path ancestor is not a
directory`, `attribute paths must be an iterable`, `bytes changed during
verification`, `does not round-trip through Git tree-name bytes`, `cannot be
represented as Git tree-name bytes`, `pinned content root is not a directory`,
`two configured anchor filenames are distinct`, `release manifest path ancestor
is not a directory`, `releases must be a real directory`, `short-name source
must be text`, `pinned suffixes must be iterable text`, `materialization
prefixes must be iterable`, `materialization destination must be path-like` —
and every one returns zero hits. PR1's scope is correctly sized on this axis.

**Absence claims spot-checked and true:** `refuse_transforming_attributes`
appears zero times in `corpus.py` and zero times inside `Materialization`
(`snapshot.py:3145–3460`); `normalization-insensitive` survives at
`corpus.py:1436, 1581, 1661`.

Line-range starts are consistently a line or two off where a decorator or
`def` sits (e.g. `_screen_candidate_tree_aliases` is 819–851, not 792–851;
`entry` is 2619; `short_name_extension` is 113; `test_release_chain.py:790`
points at a parameter line of a function that starts at 787;
`committed_fixture_filesystem` is 1134). Individually trivial; see §7.

---

## 2. The twelve disagreements — **CONFIRMED**

The record's own driver runs clean from the record's text: 43 cases in 40
seconds, exit 0, plus the 8 contract cases. I reproduced all six the brief
named, and the other six came along with them.

**D1 — CONFIRMED.** `fold_releases`: custody
`tree directory 'releases' contains names that merge under ASCII case folding: 'Pair.txt' and 'pair.txt'`;
direct binding
`directory holds two entries a case-insensitive filesystem would merge: 'releases/Pair.txt' and 'releases/pair.txt'`;
direct materialize
`releases contains names that merge under ASCII case folding: 'Pair.txt' and 'pair.txt'`.
`fold_rules` / `fold_unused` reach binding only; chain/base/append pass.
`ancestor_siblings` (`AA.txt`/`aa.txt` at root): custody and base and append
refuse with `tree directory '.' …`; **materialize returns PASS** — the
record's "materialization alone misses them" is exact. Three renderers, one
fact. The M1 decision preserves all three (the `Finding` carries path, parent
and local names, which is what the three templates need — note the
materializer's root label is `"tree root"` while custody's is `'.'`, so the
parent identity, not a pre-rendered label, has to be the stored fact).

**D2 — CONFIRMED.** `pinned_alias` and `empty_pinned_alias`: custody/base/append
`index carries an alias of a protected path: Releases/other.txt (for releases at releases)`
and `… : Releases (for releases at releases)`; **materialize PASSes both**;
binding uses `directory holds two entries … 'Releases' and 'releases'`.
`content_root_alias`: binding
`tree entry 'Rules' aliases the pinned content root component 'rules' on a case- or normalization-insensitive filesystem`
while append preflight says
`index carries an alias of a protected path: Rules/unbound.txt (for rules at rules)`.
`state_alias` behaves as described. Both preserved by the M1 decision.

**D5 — CONFIRMED.** `symlink_releases` / `gitlink_releases`: custody, base and
materialize all give `base tree entry has non-regular mode 120000: releases/link.txt`
(`160000: releases/module`) while **binding passes the release extra** and
append preflight passes. `symlink_rules` and `symlink_unused` and
`gitlink_unused` are full PASSes. `gitlink_rules` refuses
`content root contains a gitlink: 'rules/module'` regardless of suffix.
`symlink_content` → `content root contains a symlink where a regular file was recorded: 'rules/tax/rate.yaml'`.
`symlink_attested` → `bound file is not a regular file: .axiom/toolchain.toml`.
Reader table reproduced in isolated snapshots: `entry` returns metadata for
both; `blob` and `digests` give `tree entry has non-regular mode 120000: releases/link.txt`
and `object <oid> is a commit, not the blob its reference requires`;
`materialize` gives the `base tree entry …` texts. All preserved.

**D8 — CONFIRMED.** `attrs_releases`: custody/base/append refuse
`transforming attribute filter applies to protected path releases/anchors/producer-ed25519.pub`;
binding and materialize PASS. `attrs_rules` and `attrs_axiom`: composed CLI
**PASSes**, append refuses. `attrs_bad_content`: append only,
`unsupported .gitattributes construct at rules/.gitattributes:1: attribute macro definition`.
`attrs_mode_content`: append only. `attrs_mode_root`: custody/base/append,
`unsupported .gitattributes entry at .gitattributes: mode 120000`.
`attrs_unused`: all pass. The M1 decision ("no attribute obligation for raw
binding or standalone materialize … do not enlarge attribute scope") preserves
every one of these, including the PASSes, which are the ones a careless
refactor breaks.

**D10 — CONFIRMED, all four legs.**
- `name_and_mode`: custody gives the portable-name error; direct materialize gives `base tree entry has non-regular mode 120000: releases/a-link`. Names before modes composed; modes first standalone.
- `names_vs_state`: composed custody `index carries an alias of a protected path: Releases/other.txt …`; full `verify_append_gate` `state file is a symlink: receipt/corpus-journal.jsonl`. Opposite order.
- `mode_vs_attributes`: composed custody `base tree entry has non-regular mode 120000: releases/link.txt`; full append `transforming attribute filter applies to protected path releases/anchors/alpha-root.pem`. Opposite order.
- `history_symlink`: with `--base-ref`, the history pass fails `release history is not immutable: release path is a symlink: releases/link.txt`; without a base the same tree fails custody with the materializer's text.
All four preserved by the schedule table (record 445–451).

**D12 — CONFIRMED numerically.** Two calls to
`refuse_transforming_attributes(('protected.txt',))` on one snapshot:
`attribute_match_work` 28 → 56, `path_bytes` 27 → 40, `attribute_bytes` 22 and
`attribute_rules` 1 unchanged. With `MAX_ATTRIBUTE_MATCH_WORK` monkeypatched to
40 the first call passes and the second refuses
`attribute matching exceeds the work budget of 40 steps` **with the counter at
40**. See §4c — that "40" is the part the record's charge-schedule prose does
not account for.

**Also reproduced:** D3 (`gate_posix_export` — the full append gate *accepts*
`releases/policy/bad?.txt` as a gate-only proposal while composed custody
refuses `… under name repertoire 'posix-bytes': 'bad?.txt'`), D4
(`raw_unused`, `names_posix_unicode`), D6 (all six state/ancestor/root cases,
including the `state path has a symlinked component: receipt` vs
`protected path ancestor is not a directory: receipt` vs
`tree path ancestor is not a directory: receipt` three-way split), D7, D9
(`caller_anchors` default refuses / caller passes), D11 (direct
`verify_release_chain` on a `.git`-less copy PASSes both the fold and attribute
cases the Git-composed command refuses, and gives
`required state file is missing or non-regular: /private/var/…` with an
absolute path).

**Historical control — CONFIRMED.** Old `src` at
`301e73d964e23b261cfc80affcc46238b15e4fc9`: base helper PASSes with 1 release;
old CLI passes custody then refuses binding with
`directory holds two entries a case-insensitive filesystem would merge: 'releases/EXTRA' and 'releases/extra'`.
Current package refuses at custody with
`tree directory 'releases' contains names that merge under ASCII case folding: 'EXTRA' and 'extra'`.
My fixture commit is `211f6a54…`, not the record's `4b55ceb2…` — the record
says OIDs vary on rebuild, which is correct.

The record is right, and this matters for the whole milestone: **issue #62's
stated motivation for M1 — "the 0.6.0 pre-tag finding where the base-chain
helper accepted an empty-tree alias the composed command refused later" — is
already fixed at v0.6.0 by `c14bcf0`.** The record says so plainly (lines
348–350) and refuses to re-bank it. See finding F7.

---

## 3. The consumer census — **CONFIRMED**

Read `/Users/maxghenis/PolicyEngine/chronicle` only via `git show` / `git grep`
at `origin/codex/thesis-ledger-facts`, which resolves to
`e9b803b609e0282f8ea33cd2c07e47e869b0739c` — the record's commit exactly. No
checkout.

- `scripts/canonical_json.py:7–13` imports and `15–21` re-exports the five `receipt.canonical` names. Exact.
- `scripts/receipt_pins.py:7–8` imports `AppendGateSpec`, `AnchorSpec`, `ChainSpec`; `LEDGER_SPEC` 11–50; `APPEND_GATE_SPEC` 53–94. Exact.
- `scripts/verify_release_chain.py:21–22` module import + `SnapshotError`/`TreeSnapshot`. Every re-export line number the record lists is right: 44, 45, 46, 47, 48, 49, 50, 52, 53, 54, 56, 57, 58, 59, 60, 61, 63, 64, 65, 66, 67 — I checked all twenty-one. Private `_receipt_re` at 51 and `_format_time` at 278 are real obligations. Wrapper call lines 71, 75, 79, 90, 107, 147, 171, 187, 201 exact; `candidate.assert_ancestor(base)` at 250 inside 245–260.
- `scripts/check_thesis_facts_append.py:50–51` imports; `70–73` re-exports; wrappers at 409, 415, 419, 430; verdict reads at 508, 511, 512–514. Exact.
- Stderr wrappers: `f"release chain verification failed: {exc}"` at `verify_release_chain.py:270–272`; `VERDICT_REFUSAL_PREFIX = "thesis-facts append check failed: "` at 184 and `REFUSAL_PREFIX = "thesis-facts append check refused: "` at 185 in the append shim, used at 505–507 and 502–504. Exact.
- `tests/test_receipt_shim_transparency.py`: hashes 21–31 + `OPENSSL_QUEUE_ID` 32; authentication 93–112; `_normalized_stderr` 146–149 with **only** the OpenSSL substitution and **no** `.strip()`; `_assert_byte_identical` 152–161; `_assert_gate_bytes_identical` 187–216 with the refusal branch asserting `tail is None` at 212. Marker batteries 313–353 and 558–603 carry exactly the six strings the record quotes, and in both the marker assertion follows full equality (351→353, 595→603). Exact.
- `tests/test_thesis_append_shim_isolation.py`: 364–386 (`FAILED`, the exact `path`, and `("symlink" if mode == "120000" else "not regular")`), 390–412, 823–824, 873–918, 1009–1012. Exact.

**Addition the record does not make (worth knowing):** the runtime coupling is
by exception *type*, and it is narrow. `verify_release_chain.py:270` catches
`(OSError, ReleaseChainError, SnapshotError)`; `check_thesis_facts_append.py:505`
catches only `AppendError`. Anything M1 lets escape outside those types
produces a Python traceback in Chronicle's CI, not a refusal line. The record
does say "Exception classes and wrapper prefixes are part of compatibility"
(line 28) and risk 6 names the wrapper distinction, so the obligation is
covered — but the *consequence* is worth one sentence in the consumer section,
because it is what makes a type change worse than a text change. I also
confirmed the record's characterisation that no shim does runtime string
matching: grepping the three scripts for `startswith` / `in str(` / `.match(` /
`== "` finds only `if __name__ == "__main__"` and unrelated git-config
comparisons.

**axiom-encode — CONFIRMED, with one provenance correction.** The record cites
`origin/chore/receipt-0.6.0` = `249101423e988b681293c8b2171db3101326f88d` and
says the local HEAD `427edd81…` predates the imports. Both true. But the brief
asked about *main*, and `origin/main` is now `2ea0f06ae62ad14bd03b41d728c3d284cc0bb40f`,
which carries the adoption: `src/axiom_encode/cli.py:46 import receipt.sign`
and `tests/test_receipt_sign_adoption.py:7`, with byte-identical usage at
`cli.py:25846–25866` (`KeyringSpec`, `KeySpec`, `raw_public_key_sha256`,
`verify_threshold`, `except receipt.sign.SignError` → `"has an invalid encoder
apply manifest signature"`). `git grep` for any `import receipt` / `from
receipt` on `origin/main` returns those two lines and nothing else — **no
protected-tree import on main**. `pyproject.toml:32` pins `receipt==0.6.0`.
The record's conclusion holds on main; its ref list does not include main.

**thesis — CONFIRMED, same correction.** `origin/main` is
`188e34696e5040840cae1dc2702dd1584ef9447c`; the record cites local HEAD
`6b6a382e…` (correct) and adoption ref `54eeca2b…` (correct). On both
`origin/main` and the adoption ref the only executable receipt imports are
`scripts/sign_record_snapshot.py:265–270` (`SignError`, `sign_payload`,
`spki_sha256`, `verify_signature_bytes`), `scripts/verify_record_chain.py:286`
(`SignError`, `spki_sha256`, `verify_signature_bytes`) and
`tests/test_producer_signing.py:23–27` (`generate_signing_keypair`,
`sign_payload`, `spki_sha256`). `pyproject.toml:38` pins
`receipt==0.6.0; python_version >= '3.11'` on both. **No protected-tree
import.**

**Harness obligations — CONFIRMED.** Oracle pins `9dafe817…`
(`test_ledger_equivalence.py:129`, `test_append_gate_equivalence.py:132`) and
`4b9e7be2…` (`test_brier_witness_equivalence.py:439`,
`test_attest_equivalence.py:96`). Ledger imports `_format_time` at 122 inside
118–127; append imports at 123–129; witness at 421–437; attest at 84–94.
Normalizers at ledger 454–459, append 312–319, witness ~817–822, attest
~332–337. Full equality precedes markers at ledger 938–944 and 1314–1320,
append 515–522. The harness-local legacy adapter at ledger 370–414 asserts
`str(error) == expected` **exactly** for `cannot resolve commit {base_ref!r}`
and `base commit {…} is not an ancestor of candidate commit {…}` — those two
`SnapshotError` diagnostics are byte-pinned by the harness itself, which the
record correctly flags. Ledger markers 731–735, 738–757 (with the APFS/ext4
either-branch note verbatim), 760–768, 1160–1168, 1194–1201, 1221–1234, and
`committed_fixture_filesystem` at 1134–1157 all match.

One precision nit: the record says "Baseline subprocess wrappers strip outer
whitespace before comparison." In the append harness the `.strip()` is inside
the shared `_normalize_openssl_ids` (312–319), applied to **both** sides;
ledger's (454–459) does not strip at all. The two harnesses therefore have
different normalizations, and the append one is strictly broader. The record's
instruction ("new migrations must not broaden the existing normalization") is
right; the description of where the strip lives is not.

---

## 4. The design

### 4a. Is the module surface sufficient? — **CONFIRMED with corrections**

The surface (`ProtectionPlan` / `TreePolicy.evaluate` / `ProtectedTreeView` /
`finding_for` / `require` / `DirectoryEvidence`) is the right shape, and the
central judgement is correct and well argued: *one owner of facts, per-use
obligations, per-caller renderers*. The record's closing sentence — "'One
policy' cannot honestly mean one universal verdict and one universal first
error while also meeting #62's compatibility requirements" (510–511) — is the
single most valuable thing in the document, and my reproduction of D1–D12 is
what proves it. The `Finding` contract (388–396) carries exactly the witnesses
the three collision renderers, the three ancestor renderers and the two
DOS-suffix renderers need. `require(use, *, render)` with "unevaluated is not
acceptance" is the right defence against the second-most-likely bug.

But the conversion table (490–501) does **not** cover every surviving decision.
Sites it leaves with their own loop:

1. **`append_gate.check_release_chain_without_base` — `append_gate.py:1057–1058, 1063–1068`.** `initialized = bool(manifest_listing)` (which routes through `TreeListing.__len__` at `snapshot.py:1646–1648` and therefore *is* a tree-shape decision) and `manifest_entry.mode != "040000"`. The census records the site (record line 45) and the Append schedule row keeps "retained … manifest checks", but the conversion table has no row for it, so an implementer working from the table alone would leave a mode decision behind and not know it was deliberate.
2. **`release_chain._enumerate_manifest_files` — `571–607`.** A closed *filename grammar* (`MANIFEST_RE` / `_receipt_re` / `PRODUCER_SIGNATURE_RE`, 591–606) applied to entries of a directory that, on the base/append paths, is a receipt-owned materialization of a Git tree. The record's census (line 70) knowingly separates it "independently of generic filename repertoire" — but the design's absolute sentence, "No verifier may independently reimplement a name, mode, ancestor, suffix-alias or attribute decision" (370–371), needs this carve-out written into it, not left in a census cell forty lines earlier.
3. **`snapshot.Materialization._exact_filename` / `anchor_set_sha256` — `3367–3456`.** Anchor-filename admission, the explicit-surrogate rule, the `utf16_sort_key` JSON-key aliasing check, and the post-write `lstat`/`S_ISREG` guards. The record argues correctly (190, 193, 207) that these are evidence-serialization and physical-guard boundaries, and row 7 keeps "materialized-anchor guards" — but again the carve-out is not in the table.
4. **`CorpusSpec.__post_init__` (`corpus.py:385–414`) and `ChainSpec.__post_init__` (`release_chain.py:~190–205` via `_spec_relative_path` at 94–116).** These validate the *configured* paths that become `ProtectionPlan` input — including a genuine portable-name decision at `corpus.py:405–409`, `_assert_portable_name(component, "CorpusSpec content root")`, and a repertoire validation at `corpus.py:387` and `release_chain.py:202`. **The record does not mention these anywhere** — not in the census, not in the conversion table. `ProtectionPlan` is described as "derived from existing specs", which leaves it unstated whether plan compilation takes these over or the dataclasses keep them. This is the one genuinely missing site.
5. **Partial: `append_gate._is_protected` (`149–170`).** Used at `868` as the attribute-target selector (inside M1) and at `219` by `check_gate_only_confinement` (explicitly outside M1: "Surface classification … remain outside M1", record 495). The record never says which side owns the predicate after the split.

None of these is fatal; four are defensible carve-outs. But the conversion
table is what an implementer works from, and as written it under-describes the
residue.

### 4b. Is lazy-at-the-legacy-barrier compatible with every pinned precedence in D10? — **CONFIRMED for D10, but D10 is not the whole precedence surface**

For the four D10 legs, yes, and cleanly: each caller asks for stages in its own
order at its own barrier, so composed-names-before-modes, append-state-before-
aliases, composed-modes-before-attributes and append-attributes-before-push-
materialization all fall out without a global order. The record's argument
against eager evaluation (433–441) — budget consumption, poisoned-snapshot
abandonment, object I/O before an earlier materialization failure — is correct
and is the right reason.

**What the record does not state, and what I demonstrated:** within a single
stage, the choice between two *different rule kinds* can be decided by sorted
traversal position, not by rule priority. In append mode
(`alias_paths is not None`), `release_chain.py:2276` folds the **entire**
listed path for every listed entry, inside the same loop that raises the alias
refusal at 2292–2295. So:

```
$ PYTHONPATH=src .venv/bin/python /tmp/receipt-m1-review/interleave.py
{"case":"alias_before_unfoldable","entries":["Releases/other.txt","unused/bad\udcff"],
 "append_alias_screen":"AppendError: index carries an alias of a protected path: Releases/other.txt (for releases at releases)"}
{"case":"unfoldable_before_alias","entries":["Releases/other.txt","AAA-bad\udcff"],
 "append_alias_screen":"AppendError: tree entry name is not valid UTF-8 for folding"}
{"case":"unfoldable_only","entries":["AAA-bad\udcff"],
 "append_alias_screen":"AppendError: tree entry name is not valid UTF-8 for folding"}
{"case":"alias_only","entries":["Releases/other.txt"],
 "append_alias_screen":"AppendError: index carries an alias of a protected path: Releases/other.txt (for releases at releases)"}
```

Same two faults, same repertoire, same spec. `AAA-bad\xff` sorts before
`Releases/other.txt` and wins; `unused/bad\xff` sorts after and loses. This is
not rule priority and it is not a pure traversal ordering either — in the
**non**-append call the alias stage runs to completion over every listed path
before the name stage starts (2272–2295 then 2296–2312), so there rule stage
dominates position; and in `corpus._screen_tree_listing` the same
`ascii_fold_text` primitive sits inside the *name* stage (1502, 1516), so a
fold failure there is a name-stage finding at that path's ordinal. The same
primitive occupies three different positions in three callers' schedules.

`view.finding_for(use)` is specified as "Select the earliest applicable finding
under an explicit legacy priority schedule" (384), which reads as rule
priority; `Finding` "retains stable traversal/rule ordinals" (391), which is
the mechanism. The record never says how the two combine, and neither
(stage, position) nor (position, stage) lexicographic is correct on its own.
An implementer who picks either one ships a refusal-byte change.

**And nothing catches it.** `tests/test_append_gate.py:974–1001`
(`test_an_unfoldable_tree_name_is_an_append_refusal`) constructs an unfoldable
name with no co-occurring alias; the whole 1,466 + 108 battery has no
same-stage two-fault case of this kind. Risk 1's probe list (record 599) is
five *cross-stage* two-fault matrices — malformed journal + collision, state
symlink + alias, portable error + mode, bad attribute source + mode/write,
history mutation + name — and not one of them is same-stage-position-decides.
This is finding **F1**.

### 4c. Is the D12 compatibility charge schedule implementable without a behavior change? — **CORRECTED**

Implementable, yes. Implementable *as specified*, no.

`_charge_verification` (`snapshot.py:2271–2282`) raises **before**
incrementing, so the public counter stops at the last successful value. In the
reduced-ceiling leg of D12 the second call refuses with
`snap.work.attribute_match_work == 40` — i.e. 12 of that call's 28 steps were
charged one at a time and the 13th was refused *inside* a rule's matching.

The record's stated granularity is "cached match outcomes carry work-cost
checkpoints sufficient to replay budget exhaustion **at the same path, rule and
reading**" (471–473) with "Keep checkpoints compact" (475–476). At
(path, rule, reading) granularity there is exactly one rule and two readings
here, so a replay would charge in ~14-step blocks and refuse with the counter
at 28, not 40. `TreeSnapshot.work` is public and already pinned by an exact
test (`test_snapshot_features.py:1248`, `== 1_011_000`), and risk 3's probe
explicitly says "Compare old/new public counters and refusal location" — so
the probe would catch this, but the design text hands the implementer a
granularity that fails it.

Either the schedule needs step resolution in the exhaustion region, or it needs
an explicit stated fallback (when a checkpoint block would cross the ceiling,
re-execute that one rule's matching to find the exact stopping step — still
bounded, still not a full re-evaluation). One sentence fixes it. Finding **F2**.

Two smaller notes on the same section: the `path_bytes` 27 → 40 leg is a
pre-dedup `_charge_path_bytes` call per supplied path (`snapshot.py:3051–3054`)
and is straightforwardly replayable — the record is right that this must be
kept. And "Preserve existing `SnapshotWork` fields, constants and monkeypatch
seams used by tests; forwarding must consult the legacy limit at call time, not
copy it once at import" (477–478) is exactly right and is the kind of detail
that shows the author actually ran the probe: my D12 reproduction only works
because `MAX_ATTRIBUTE_MATCH_WORK` is read at call time.

### 4d. Unaddressed structural constraint

`receipt.protected_tree` must be importable **by** `snapshot.py` (row 6:
`TreeSnapshot.refuse_transforming_attributes` forwards to it, and the attribute
parser/matcher move out of `snapshot.py`) while `TreePolicy(snapshot, …)`
takes a `TreeSnapshot`. That is a cycle. It is solvable — `snapshot.py:3449`
already does a function-local `from receipt.canonical import …` for exactly
this reason — but the record never names the constraint, and the resolution
(which direction is deferred, whether `TreePolicy` types its subject
structurally) is a real design decision with consequences for the forwarding
aliases PR4 promises. Finding **F5**.

---

## 5. The migration plan — **CORRECTED**

Ordering is right: freeze → names/aliases → modes/ancestors/export →
attributes → append/binding → cleanup. Dependencies work because PR2 and PR3
keep facades, so append's push path keeps calling the same helpers while their
insides move.

**PR3 needs splitting, and the record only flags PR5.** PR3 is "Unify modes,
ancestor and export obligations. Migrate composed custody and base-chain
selection plus materializer selection." That is three coherent changes across
three modules: (a) mode classification consumed by `verify.py:675–691, 702–709`
and `release_chain.py:2352–2376`; (b) the ancestor-shape finding, which has to
reconcile the three-way text disagreement D6 pins between `entry`
(`snapshot.py:2643–2644`), `entries` (`2681–2686`) and `_raw_entry_at`
(`2946–2948`) on the same input; (c) a certified export selection threaded into
`Materialization._selected_entries` (`3194–3249`) while keeping the writer,
byte budgets, cleanup and `anchor_set_sha256` guards. It also has to preserve
the materializer's modes-before-names order against composed custody's
names-before-modes order — the D10 leg most likely to be got wrong. PR5 is
flagged "Split this PR if review size requires"; PR3 is not, and by
`CONTRIBUTING.md:34` ("One coherent change per PR") it is the one that most
clearly is not one change. Finding **F3**.

**The consumer gate is in the wrong place.** The per-PR gate list (527–532) is
1,466 non-harness + full expanded suite + 108 harness both legs zero skips +
refreshed import/call-site/text-match census + maintainer read + independent
model review. Chronicle's byte-transparency and isolation suites appear **only**
in PR6 (579–581). But PR2, PR3, PR4 and PR5 each change a refusal path, and
Chronicle's suites are the only gate that compares *complete normalized stderr
bytes* against an authenticated pre-receipt oracle
(`_assert_byte_identical` 152–161, `_assert_gate_bytes_identical` 187–216).
The F1 class of regression — a same-stage precedence flip — is exactly what
they catch and the in-repo battery does not. Running them at the end means
finding a PR2 regression after PR6. They are cheap relative to a five-PR
bisect. Finding **F4**.

**Gates that are present and correct:** the 1,466 count, the 108-with-zero-skips
rule, the both-legs requirement (589–593), the no-symbol-removal-without-shim
rule (588–591) including in-repo monkeypatch seams, the PR1 consumer import
smokes covering `_receipt_re` and `_format_time`, PR4's "old counters/refusal
points remain identical", PR6's leftover-decision-loop sweep. I verified the
two counts myself and both are exact.

**Two smaller gate gaps.** (i) PR3 has no counter/work comparison, though PR2
("bounded duplicate input/index accounting") and PR4 ("counters … identical")
do; the export-selection change in PR3 touches `_charge_path_bytes` and the
tree-walk counters. (ii) Risk 9 requires running on a case-sensitive **and** a
case-insensitive host with modes and symlinks, but no PR gate says so; the
record's own validation ran on macOS only and says so honestly (897–898). One
of the six PRs should own that requirement explicitly.

---

## 6. The risks — **CORRECTED**

The ranking is sound. Ranks 1 (eager evaluation changes order / does hazardous
I/O early) and 2 (a cached selection from another subject authorizes an unsafe
read, or unevaluated reads as accepted) are the two ways this refactor silently
changes a verdict, and they belong at the top. Ranks 3–7 are correctly ordered
behind them. Rank 8 and 9 are correctly demoted to medium.

Probes mostly do decide their risks:
- Risk 1's "instrument attribute reads and assert zero before the old barrier" is decisive and cheap.
- Risk 3's "compare old/new public counters and refusal location" is decisive, and as noted it is what catches F2.
- Risk 5's "compare target sets **before** comparing outcomes" is the right ordering and would catch a silently widened attribute scope even where the outcome happens to agree.
- Risk 6's golden-strings-plus-Chronicle-plus-108 is decisive.
- Risk 7's fault injections, including "run direct directory verification without `.git`", are decisive — and I confirmed that path works today: the record's own contract driver copies the fixture with `.git` excluded and `verify_release_chain` still returns a verdict.
- Risk 4's "force index names and construct empty trees with `mktree`" is decisive; the driver already does it.

Gaps:

1. **Risk 1's probe list has no same-stage two-fault case** (F1). All five listed matrices cross stage boundaries. Add: two faults of different rule kinds inside one stage, with the offending paths swapped so that sorted position, not rule kind, decides which fires — the `unfoldable_before_alias` / `alias_before_unfoldable` pair above is the minimal instance.
2. **Risk 2's probe has no negative control.** "Every incompatible use must reject internally" is satisfiable by rejecting everything. It needs the paired assertion that a *compatible* reuse across stages does **not** re-evaluate and does **not** reject — which is also the only thing that demonstrates the caching this whole design exists to enable.
3. **No risk covers the module-dependency direction** (F5). An import cycle between `receipt.protected_tree` and `receipt.snapshot` is a plausible way PR4 stalls or acquires a lazy import that changes when a monkeypatch seam is resolved. Low probability, cheap to state.

I did not find a missing *critical*. Ranks 1 and 2 do cover the two ways a
green verdict could become wrong.

---

## 7. Voice and precision — **CORRECTED**

The record is dense, declarative and locator-heavy; it does not narrate. That
is the right register and it mostly holds. Specific defects:

- **A wrong locator on a load-bearing citation.** Line 262: "CONTRIBUTING.md:16–20 expressly forbids weakening normalization or skipping a case to manufacture a pass." Lines 16–20 are the closing code fence, a blank line, and the first three lines of the harness paragraph. The prohibition — "Do not weaken a normalization or skip a case to make one pass — if the behavior genuinely diverged, that is the finding." — is at **CONTRIBUTING.md:21–22**. The claim is true; the citation does not support it.
- **Range starts are systematically off by a line or three.** `append_gate.py:792-851` is labelled `_screen_candidate_tree_aliases`, which is 819–851 (792–816 are `_surface_alias_paths` and `_protected_paths`); `877-903` is labelled the release-leaf screen, which is 877–891 (894–903 is `_screen_candidate_materialization`); `snapshot.py:2620–2645` for `entry` (`def` at 2619); `_names.py:114–172` for the 8.3 operation (`def` at 113); `test_release_chain.py:790-817` (function starts 787); ledger `1135–1158` (fixture starts 1134); witness `421–436` (import block closes 437). Each is individually harmless; together they mean the ranges cannot be used as function boundaries, which is exactly what a migration census is for.
- **Unreproducible identifiers presented as locators.** The supplemental reader-probe table (356–359) cites commits `20a1124d16c86ae75defea0ce782e8aeb7acb178` and `3de5192cea917baa448336f1a9e259fe77bd7493`. Those come from a throwaway `mkdtemp` fixture; mine were `427f3fce…` and `244ddf2a…`. The record notes OID variance for the historical control (347) but not here. Drop them or add the same caveat.
- **`/tmp` evidence paths.** Lines 252, 344–345, 354, 902–905 point the reader at files under `/tmp` that no future reader can open. The record partly anticipates this (890: "the source-expression census above preserves both full diagnostics independent of those temporary files") and, more importantly, ships a driver that actually reproduces — which I confirmed. But the Validation table's Evidence column is otherwise unusable as evidence.
- **Claims without locators.** All of these are true — I checked each — but none carries one: line 65 "Public `verify_release_chain` must not suddenly require a Git repository"; line 87 "legacy corpus refusal words still say 'normalization-insensitive'" (it is `corpus.py:1436, 1581, 1661`); line 108 "**No transforming-attribute screen exists anywhere in `verify_corpus_binding`**" (zero occurrences in `corpus.py`); line 150 "`Materialization` itself does NOT call this operation" (zero occurrences in `snapshot.py:3145–3460`); line 246 "documentation/log quotations elsewhere are not active imports".
- **One row of the Validation table is narration.** "Independent review | Source-census and design-feasibility reads completed; omissions and precedence/budget corrections incorporated" (907) names no artifact, no reviewer, no locator, and no correction. Either cite the round and what changed, or drop the row.
- **Lane process inside the design record.** Lines 913–914 ("Because no `-o` path was supplied, the output copy is `/tmp/receipt-07-m1-output.md`, containing this same record") is dispatch bookkeeping. It belongs in `PROGRESS.md`.

Two things the record gets *right* that are worth naming, because they are the
hardest kind of precision: the census conventions block (21–29) defines `E`/`S`/`V`
and then applies them correctly — I checked six and all six were typed right,
including `test_release_chain.py:595–633` as `V` because it asserts only the
exception class; and "Where no exact pin was found, that is a migration test
gap, not permission to change the message" (25–26) is the correct disposition
and is what makes PR1 non-optional.

---

## Findings

**F1 (medium, correctness) — Same-stage precedence is decided by traversal
position, and the record neither states it nor probes it.**
`release_chain.py:2276` folds whole listed paths eagerly in append mode inside
the alias loop, so a whole-path foldability failure and a configured-prefix
alias resolve by sorted position, not rule kind (demonstrated above: swapping
`unused/bad\xff` for `AAA-bad\xff` flips the refusal text). The same primitive
sits in a different schedule position in each of three callers. `finding_for`
is specified as a "priority schedule" while `Finding` carries "traversal/rule
ordinals" and the record never says how they combine. No test in the 1,466 +
108 covers it (`tests/test_append_gate.py:974–1001` has the fault alone).
Risk 1's five probes are all cross-stage.
*Fix:* state the obligation in the §"Evaluation order and compatibility" table
(whole-path foldability is a sub-step of the alias stage in append mode, not a
stage of its own; in corpus it is a sub-step of the name stage); add the
two-way swap as a PR1 permanent fixture; add a same-stage two-fault matrix to
risk 1's probe.

**F2 (medium, correctness) — The D12 charge-schedule granularity as written
produces a different public counter.** `_charge_verification`
(`snapshot.py:2279–2282`) refuses before incrementing, so the reduced-ceiling
repeat lands at `attribute_match_work == 40` — mid-rule. Checkpoints "at the
same path, rule and reading" (471–473) replay in whole-rule blocks and would
land at 28. `TreeSnapshot.work` is public and exact-pinned
(`test_snapshot_features.py:1248`). Risk 3's probe catches it; the design text
should not require the implementer to discover it there.
*Fix:* specify step resolution in the exhaustion region, or an explicit
"re-execute the single exhausting rule to find the exact stopping step"
fallback.

**F3 (medium, process) — PR3 is at least as large as PR5 and is not flagged for
splitting.** It spans mode classification, the D6 three-way ancestor-text
reconciliation, and threading a certified export selection through
`Materialization._selected_entries` — three modules, and the D10 leg where
composed names-before-modes must coexist with materializer modes-before-names.
`CONTRIBUTING.md:34` requires one coherent change per PR.
*Fix:* split into 3a (mode + ancestor findings consumed by composed custody and
base chain) and 3b (certified export selection into the materializer); add a
work/counter comparison gate to both.

**F4 (medium, process) — Chronicle's transparency and isolation suites are
gated only at PR6.** They are the only gate comparing complete normalized
stderr bytes against an authenticated oracle, and they are the gate that would
catch F1-class regressions introduced in PR2.
*Fix:* add them to the per-PR gate list for every PR that touches a refusal
path (2, 3, 4, 5), against the consumer's then-current pin, as the record
already requires once at 244.

**F5 (low, completeness) — Four sites keep their own decision loop and the
conversion table names none of them; one is unmentioned anywhere.**
`append_gate.py:1057–1058, 1063–1068` (manifest listing/mode);
`release_chain.py:571–607` (closed filename grammar);
`snapshot.py:3367–3456` (anchor filename admission and post-write guards);
and — not mentioned in the record at all — `corpus.py:385–414` and
`release_chain.py:~190–205` / `94–116`, where `CorpusSpec.__post_init__` and
`ChainSpec.__post_init__` make their own configured-path name decisions
(`_assert_portable_name(component, "CorpusSpec content root")` at 409) that
feed `ProtectionPlan`. Also unstated: which side of the M1 boundary owns
`append_gate._is_protected` (`149–170`), used at `868` inside scope and `219`
outside it.
*Fix:* add table rows (or explicit carve-out sentences under the "No verifier
may independently reimplement…" claim at 370–371) for each.

**F6 (low, completeness) — The `receipt.protected_tree` ↔ `receipt.snapshot`
import direction is a cycle the record does not address.** Row 6 has
`snapshot.py` forwarding into the module while `TreePolicy` takes a
`TreeSnapshot`. Solvable, but the resolution affects PR4's forwarding aliases
and when monkeypatch seams resolve.

**F7 (low, framing) — The record disproves #62's stated motivation for M1 and
never replaces it.** The historical control shows the empty-tree divergence was
fixed by `c14bcf0` before v0.6.0, and the record correctly refuses to bank it
(348–350). Every remaining divergence is then shown to be intentional and
required to be preserved byte-for-byte. That leaves M1 as a zero-verdict-change
refactor carrying two critical and five high risks, and the record never states
what it buys. The census already contains the answer — one duplicated
fold-collision implementation (`corpus.py:1530–1540` beside
`_names.assert_no_merging_entries`, which row 5 removes), two fold-key helpers
(`release_chain.py:2234–2235`, `corpus.py:1343–1346`), two configured-prefix
alias algorithms (`release_chain.py:2272–2295`, `corpus.py:1441–1475` +
`1565–1587`), two DOS-suffix applications (`release_chain.py:2318–2331`,
`corpus.py:1618–1631`), three ancestor-shape texts for one condition
(`snapshot.py:2643–2644 / 2681–2686 / 2946–2948`) — but never assembles it.
*Fix:* one paragraph, with those locators, stating what M1 removes and what
class of future divergence it forecloses, so the maintainer can weigh 2–4
engineering weeks against two criticals.

**F8 (low, precision) — `CONTRIBUTING.md:16–20` should be `18–22`;** range
starts are systematically off by a line or three; the reader-probe table cites
fixture OIDs that cannot be reproduced; five true claims carry no locator; one
Validation row is narration. Details in §7.

---

## What I would need to see to approve

1. F1's obligation stated in the evaluation-order table, its fixture in PR1, and its probe in risk 1.
2. F2's granularity resolved in one sentence.
3. F3's PR3 split, and F4's Chronicle gate moved to per-PR.
4. F5's four rows added to the conversion table (the `CorpusSpec` / `ChainSpec` one is the only genuinely new site).
5. F8's `CONTRIBUTING.md` citation corrected.

F6 and F7 are worth doing and would not by themselves block.

Everything else in this record checked out against the code, the tests, three
consumer repositories and two full suite runs. It is the most carefully
evidenced design record I have reviewed in this repo, and its central
argument — that "one policy" must mean one owner of facts with per-use
obligations and per-caller renderers, because #62 demands both unification and
byte-identical refusals — is correct and is proved by the twelve
disagreements, which I reproduced exactly.

---

---SUBFLEET-VERDICT-BEGIN---
{"schema_version": 1, "artifact_revision": {"kind": "file", "path": "docs/design/0.7-m1-protected-tree-policy.md", "commit": "2144f075c6a9dd1dd1359e3f530081d9068d1c20"}, "verdict": "changes_requested", "findings": [{"severity": "high", "location": "Evaluation order and compatibility / \"Select the earliest applicable finding under an explicit legacy priority schedule\"", "description": "Whole-path foldability is a sub-step of the append alias stage (release_chain.py:2276), so it and a configured-prefix alias resolve by sorted traversal position, not rule priority - demonstrated by swapping unused/bad\\xff for AAA-bad\\xff; the record never states this obligation, no test in the 1,466+108 covers it, and none of risk 1's five cross-stage probes would catch it."}, {"severity": "medium", "location": "\"cached match outcomes carry work-cost checkpoints sufficient to replay budget exhaustion at the same path, rule and reading\"", "description": "_charge_verification (snapshot.py:2279-2282) refuses before incrementing, so D12's reduced-ceiling repeat lands at the public counter attribute_match_work == 40 mid-rule; whole-rule checkpoints would land at 28, so the stated granularity fails risk 3's own counter comparison."}, {"severity": "medium", "location": "PR-sized migration plan, step 3 (\"Unify modes, ancestor and export obligations\")", "description": "PR3 spans mode classification, the D6 three-way ancestor-text reconciliation and threading a certified export selection through Materialization._selected_entries across three modules; PR5 is flagged for splitting and PR3, which is at least as large, is not."}, {"severity": "medium", "location": "PR-sized migration plan, per-PR gate list (lines 527-532) vs step 6", "description": "Chronicle's byte-transparency and isolation suites - the only gate comparing complete normalized stderr bytes against an authenticated oracle - run only at PR6, so an F1-class regression introduced in PR2 surfaces five PRs late."}, {"severity": "low", "location": "Converting every existing site (conversion table, lines 490-501)", "description": "Four sites keep their own name/mode decision loop with no table row: append_gate.py:1057-1068, release_chain.py:571-607, snapshot.py:3367-3456, and - unmentioned anywhere in the record - CorpusSpec.__post_init__ (corpus.py:385-414, portable-name screen at 409) and ChainSpec.__post_init__; ownership of append_gate._is_protected (149-170) across the M1 boundary is also unstated."}, {"severity": "low", "location": "Proposed module and protected view / row for snapshot.refuse_transforming_attributes", "description": "receipt.protected_tree must be imported by snapshot.py while TreePolicy takes a TreeSnapshot; the resulting import cycle and its resolution are never addressed, though they affect PR4's forwarding aliases and monkeypatch-seam resolution."}, {"severity": "low", "location": "\"This was fixed by c14bcf0 before v0.6.0\" / M1 CHANGELOG paragraph", "description": "The record disproves #62's stated motivation for M1 (the empty-tree divergence is already fixed) and shows every remaining divergence must be preserved byte-for-byte, but never states what M1 buys against two critical and five high risks, though the census already holds the answer (duplicate fold-collision loop at corpus.py:1530-1540, two fold-key helpers, two alias algorithms, two DOS-suffix applications, three ancestor texts)."}, {"severity": "low", "location": "\"CONTRIBUTING.md:16-20 expressly forbids weakening normalization\"", "description": "The prohibition is at CONTRIBUTING.md:21-22; 16-20 is a code fence and the first three lines of the harness paragraph. Range starts are also systematically off by a line or three across the census, the reader-probe table cites unreproducible fixture OIDs, five true claims carry no locator, and one Validation row is pure narration."}], "notes": ["Ran the record's own reproducibility driver extracted verbatim from lines 635-801: exit 0, 40.4s, 43 cases + historical control + repeat-charge; and the contract driver from lines 822-880: exit 0, 8 cases.", "Reproduced D1, D2, D5, D8, D10, D12 byte-for-byte, plus D3/D4/D6/D7/D9/D11, the historical empty-tree control (old src at 301e73d9 passes base and refuses binding; current refuses at custody) and the payload-reader table in isolated snapshots.", "Verified 30+ census sites by line range, condition, region and exact refusal expression across verify.py, release_chain.py, append_gate.py, corpus.py, snapshot.py and _names.py; spot-checked cited test pins in test_release_chain.py, test_append_gate.py, test_verify.py, test_snapshot.py, test_snapshot_names.py, test_snapshot_features.py.", "Grepped tests/ for thirteen strings the record says have no exact pin: all thirteen return zero hits, so PR1's scope is correctly sized.", "Consumer census by git show/grep only at chronicle origin/codex/thesis-ledger-facts = e9b803b609e0282f8ea33cd2c07e47e869b0739c: all 21 re-export line numbers, both stderr wrapper prefixes, the transparency hashes/normalizer/comparators and both marker batteries verified exact; no runtime string matching in the shims.", "axiom-encode origin/main (2ea0f06a) and thesis origin/main (188e3469) each import receipt.sign only - the record cites the 0.6 adoption refs and local HEADs but not main; conclusion unchanged.", "Ran both suites myself: pytest --ignore-glob='tests/test_*_equivalence.py' -q gave 1466 passed, zero skips, exit 0 (410.68s); the four harnesses with RECEIPT_LEDGER_TREE/RECEIPT_BRIER_TREE gave 108 passed, zero skips, exit 0 (291.48s); per-file collection is 43/28/17/20.", "New evidence for F1: /tmp/receipt-m1-review/interleave.py shows append's alias screen returns the alias refusal when the aliasing path sorts first and the UTF-8 fold refusal when the unfoldable path sorts first, on otherwise identical inputs."]}
---SUBFLEET-VERDICT-END---
