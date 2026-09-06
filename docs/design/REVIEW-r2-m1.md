**Approve, with one low-priority completeness note.** The folded design is
implementable under the refusal-byte compatibility contract. All eight round-1
folds are supported by the source and independently reproduced controls. The
remaining conversion-table omission described below does not block approval.

Defensive correctness and completeness audit of
`docs/design/0.7-m1-protected-tree-policy.md` at
`ca5c664545e12216cfed05813e36e7c86b108312`, dated 2026-09-06. This review treats
the design as instructions for an implementer accountable to Chronicle's
complete normalized stderr comparison, including exception wrappers and
newlines. It does not approve an implementation that does not yet exist.

I read the entire 1,082-line record, the supplied issue-62.md, CONTRIBUTING.md,
REVIEW-r1-m1.md and the partial Opus notes. I worked alone, offline, without
background tasks, fetching, installation or consumer checkouts. Prior results
were not used as independent evidence without rerunning them. The design
record, package source, tests and CONTRIBUTING.md were left unchanged.

In the source locators below, package filenames are relative to `src/receipt/`
and test filenames to `tests/`. Design line numbers refer to the artifact
revision above. E means exact full-string assertion, S means substring or
unanchored regex, and V means verdict or precedence coverage. A cited test for
one branch does not imply that every branch of that function has an exact pin.

**1. Census — CONFIRMED for the sampled sites; one additional conversion
coverage correction is recorded in item 4.**

I read the following source ranges and their cited tests directly. Conditions,
regions, line ranges and refusal expressions agree with the record. Adjacent
string literals in this table concatenate as they do in Python.

| Site | Condition and tree region | Refusal expression and test evidence |
|---|---|---|
| `verify.py:638–645`; `release_chain.py:2185–2231` | Optional history before custody; non-tree descendants of the release root in candidate and base. Candidate mode pass precedes per-base-entry comparisons. | `f"release path is a symlink: {relative}"`; `f"release path is not regular: {relative}"`; `f"base release entry has non-regular git mode {prior.mode}: {relative}"`. Deletion, changed mode and changed OID retain the `{base.commit}` templates at 2214–2225. CLI prefix is `"release history is not immutable: "` at `verify.py:776–777`. S: `test_release_chain.py:293–329`; E: 332–402. |
| `verify.py:658–673` | Complete tree listing, including trees and empty trees; five ordered custody prefixes and actual ancestor listings. | Delegates the exact configured-alias/name/sibling expressions below. E and no-materialization ordering: `test_release_chain.py:470–499,537–592`. |
| `verify.py:675–691` | Journal and prefix exact leaf lookup; missing, symlink, then other nonregular mode; ancestor errors propagate. | `f"state file is missing or not a regular file: {display}"`; `f"state file is a symlink: {display}"`; `f"state file is not a regular file: {display}"`, with `display = relative.as_posix()`. Missing detection compares exactly to `f"tree entry does not exist: {display}"`. The append symlink equivalent is E at `test_append_gate.py:1028–1029`; composed missing/nonregular exact-pin gaps remain gaps. |
| `verify.py:702–709` | Materialize five custody prefixes, then attributes over selected entries, before anchor digest and chain verification. | Inherited export refusals; attribute expression `f"transforming attribute {name} applies to protected " f"path {path}"`. E: `test_verify.py:740–783`; tests compare the same verdict under both ignorecase settings. |
| `release_chain.py:2238–2333` | Configured-prefix aliases over the supplied listing; scoped repertoire and sibling checks; portable release DOS suffixes. | `f"index carries an alias of a protected path: {listed} " f"(for {path} at {prefix})"`, where `prefix = "/".join(exact[path][:depth])`. Non-tree paths precede trees; target order and depth matter. E: `test_release_chain.py:537–592`. |
| `release_chain.py:2296–2333` | Scoped names before sibling merges before portable short-suffix checks. | Name labels are `f"tree entry {relative!r}"`; sibling label is `f"tree directory {directory or '.'!r}"`; suffix expression is `"release root contains an entry whose short-name alias " f"would carry a pinned suffix: {relative}"`. Shared `NamePolicyError` becomes `ReleaseChainError(str(exc))`. E sibling coverage: `test_release_chain.py:446–499`; independently reproduced suffix case D7. |
| `release_chain.py:2352–2376` | Base helper selects four prefixes, adding anchors only without caller override; names, materialization, attributes in that order. | Delegated strings retain their original exception classes. V: `test_release_chain.py:595–633`; E for included/excluded anchor symlink: 787–817; E equality to direct attribute refusal and S text: 833–852. |
| `release_chain.py:487–568` | Physical manifest path components; absence allowed, ancestor and leaf type failures distinct. | `"release manifest path ancestor is not a directory: " f"{'/'.join(walked)}"`; `"cannot stat release manifest path: " f"{'/'.join(walked)} ({exc.strerror})"`; `f"release manifest path is not a regular directory: {current}"`. Permission E: `test_release_chain.py:2660–2688`; standalone ancestor exact-pin gap is correctly identified. |
| `release_chain.py:571–607` | Direct directory leaf shape and immediate manifest-directory children; closed release filename grammar. | `f"release manifest path is not a regular directory: {directory}"`; `f"release manifest directory contains a non-regular entry: {entry}"`; `f"unknown file in closed release manifest directory: {entry.name}"`. Harness markers and full normalized comparison: `test_ledger_equivalence.py:731–768,938–947`. Iteration remains unsorted. |
| `release_chain.py:1553–1635` | Physical state and cryptographic-input reads; component links/spelling, regular leaf, O_NOFOLLOW, open/fstat identity and length checks. | Default `nonregular or f"required state file is missing or non-regular: {path}"`; default replacement `replaced or f"required state file was replaced while being read: {path}"`; state-ancestor link uses `"state path traverses a symlink at " f"{'/'.join(walked)!r}: {relative.as_posix()}"`. E: `test_release_chain.py:2416–2466,2569–2607`; directory-state probe reproduced the absolute path. |
| `append_gate.py:746–765,1094–1095` | Two state leaves before global aliases and gate-only return. | The three state expressions above, using `AppendError`; inherited ancestor `SnapshotError` is preserved through outer translation. E: `test_append_gate.py:1016–1030,1675–1694`. |
| `append_gate.py:819–851` | Complete listing; proper ancestors of ordered protected paths, then the shared alias screen with wider alias targets. Missing ancestor is allowed. | `f"state path has a symlinked component: {prefix}"`; `f"tree path ancestor is not a directory: {prefix}"`, both `SnapshotError`; helper `ReleaseChainError` becomes `AppendError(str(exc))`. E examples: `test_append_gate.py:1675–1694,1749–1775`. |
| `append_gate.py:854–874,1097–1099` | Regular entries selected by surface/release/ancestor predicate or four materialization prefixes, in sorted path order. | Delegates snapshot attribute text; no implicit inclusion of a disjoint anchor subtree. E: `test_append_gate.py:583–618`. |
| `append_gate.py:877–891` | Non-tree release leaves on the push path; exact manifest path skipped for its own directory diagnostic. | `f"release path is a symlink: {relative}"`; `f"release path is not regular: {relative}"`. E: `test_append_gate.py:1712–1737`; gate-only/export distinction at 730–755. |
| `append_gate.py:1056–1068` | No-base initialization uses non-tree listing emptiness, then requires the manifest entry to be a tree. | `"release manifest path is not a regular directory: " f"{candidate.snapshot.root / candidate.spec.chain.manifest_relative}"`. E: `test_append_gate.py:2268–2285,2367–2382`; competing base-path text at 2288–2302. |
| `corpus.py:1430–1475` | Declared content plus attested paths; whole-path aliases before prefix aliases and their budgets. | `"two declared paths would alias on a case- or " "normalization-insensitive filesystem, so the closed-world set " f"is ambiguous: {_quoted(seen[key])} and {_quoted(relative)}"`; prefix expression `"two declared paths would alias at a directory: " f"{_quoted('/'.join(previous_spelled[: depth + 1]))} and " f"{_quoted('/'.join(spelled[: depth + 1]))}"`. Whole-path S: `test_corpus.py:1416–1437`; prefix E: 1483–1488. |
| `corpus.py:1495–1518,738–760` | Every actual tree entry, including irrelevant descendants and empty tree nodes; local component admission in sorted full-path order. | Fold failure `"tree entry name is not valid UTF-8 for folding"`; portable wrapper `f"{label} is not a portable name (ASCII letters, digits, " "'.', '_' and '-', not ending in '.', not a Win32 device " f"name): {_quoted(value)}"`. E: `test_corpus.py:362–417,3270–3280`. |
| `corpus.py:1520–1548` | Every actual sibling set, both repertoires, after all name checks. | `"directory holds two entries a case-insensitive filesystem " f"would merge: {_quoted(_under(directory, previous))} and " f"{_quoted(_under(directory, name))}"`. E: `test_corpus.py:341–346,362–417,477–524`. |
| `corpus.py:1565–1606` | Pinned content-root components and actual ancestor siblings, then exact root existence/tree mode. | `f"tree entry {_quoted(name)} aliases the pinned content " f"root component {_quoted(component)} on a case- or " "normalization-insensitive filesystem"`; `f"pinned content root is absent from the tree: {base_relative}"`; `f"pinned content root is not a directory: {base_relative}"`. Alias E: `test_corpus.py:3151–3178`; root-mode literal gap confirmed. |
| `corpus.py:1608–1642` | Every content-root descendant: gitlink first, suffix/DOS decision, then selected-leaf mode. Suffixless symlinks remain allowed where specified. | `f"content root contains a gitlink: {_quoted(relative)}"`; `"content root contains a file whose short-name alias " "would carry a pinned suffix: " f"{_quoted(relative)}"`; `"content root contains a symlink where a regular file was " f"recorded: {_quoted(relative)}"`; `f"content root contains a non-regular file: {_quoted(relative)}"`. E: `test_corpus.py:362–417,452–474,3250–3267`. |
| `corpus.py:1666–1682` | Exact attested paths; masks lookup errors, then checks regular blob mode/type. | `f"bound file is missing or not a regular file: {path}"`; `f"bound file is not a regular file: {path}"`. E: `test_corpus.py:420–449,654–663`. |
| `snapshot.py:2619–2687` | Exact-byte lookup/listing ancestors. Metadata leaf lookup accepts symlink/gitlink; missing listing is empty. | `"tree entry does not exist: " f"{_tree_path_decode(b'/'.join(parts))}"`; symlink `f"state path has a symlinked component: {prefix}"`; other ancestor `f"tree path ancestor is not a directory: {prefix}"`. Listing uses `prefix_text` instead. Missing E: `test_snapshot.py:385–394`; ancestor E via append tests above. |
| `snapshot.py:2931–2950` | Exact ancestor walk used by attributes/materialization. | `f"protected path ancestor is not a directory: {ancestor}"`, with `ancestor = _tree_path_decode(b"/".join(parts[: index + 1]))`. No exact literal pin found; D6 independently reproduced the distinct wording. |
| `snapshot.py:2690–2703,1735–1759` | Caller-supplied entry payload admission, any region: provenance, object type, then mode. | `f"object {entry.object_id} is a {entry.object_type}, not the blob " "its reference requires"`; `f"tree entry has non-regular mode {entry.mode}: {entry.path}"`. Digests E: `test_snapshot_features.py:1289–1303`; isolated reader probes confirmed both orders. |
| `snapshot.py:2964–2967,3033–3101` | Committed attribute source modes, bounded ordered inputs, exact/folded evaluation and transforming states. | `f"unsupported .gitattributes entry at {path}: mode {raw.display_mode}"`; `"attribute paths must be an iterable of paths"`; transform expression in the verify row above. Source-mode anchored regex: `test_snapshot_features.py:385–416`; exact transformed path: `test_verify.py:780–783`; scalar-input literal gap confirmed. |
| `snapshot.py:3194–3249` | Selected non-tree export entries; all selected modes before parent-group sibling/name checks. | `f"base tree entry has non-regular mode {entry.mode}: {path}"`; collision label is parent path or `"tree root"`. E collision: `test_snapshot_features.py:778–782`; S mode and no-mkdtemp-before-refusal: 787–811. |
| `_names.py:75–83,175–206` | Repertoire API admission and portable components. | `"name repertoire must be 'portable' or 'posix-bytes': " f"{repertoire!r}"`; portable expression at 178–180 retains optional `f" under name repertoire {repertoire!r}"`. S: `test_snapshot_names.py:107–113,155–191`; caller exact renderers are covered separately. |
| `_names.py:220–233,298–320,323–386` | Raw component grammar, strict UTF-8 fold boundary, then sibling admission/fold/collision interleaving. | `f"{label} must be bytes: {value!r}"`, `f"{label} is empty"`, `f"{label} is a dot component: {value!r}"`, `f"{label} contains NUL: {value!r}"`, `f"{label} contains '/': {value!r}"`; fold failure above; duplicate `f"{label} contains a duplicate entry name: {text!r}"`; collision `f"{label} contains names that merge under ASCII case folding: " f"{previous_text!r} and {text!r}"`. S: `test_snapshot_names.py:276–284,352–358,375–396`; materializer E above. |

The `_quoted` truncation expression at `corpus.py:539–561`, short-name
derivation at `_names.py:113–172`, spec constructors, anchor serialization
guards, and shared-budget implementation were also read. The record correctly
distinguishes these boundaries from a second actual-tree policy walk. Literal
searches over `git ls-files tests` returned no matches for twenty claimed gaps,
including the protected-ancestor, scalar-attribute-input, root-mode,
round-trip, anchor-mutation and materialization-argument messages. This
confirms the stated literal-pin gaps; it does not prove absence of all indirect
coverage. Both complete suites passed without changing any tests.

**2. D1–D12 and the folds' execution evidence — CONFIRMED.**

I extracted and ran the record's Python blocks at 733–899, 930–988 and
1007–1045 verbatim. They produced respectively 52, 9 and 4 JSONL rows, exit 0,
with empty driver stderr: 43 matrix cases, eight contract cases, four historical
controls, four repeated-charge rows, four interleave cases and fixture-location
rows. All matrix JSON CLI refusals had exit 1 and empty stderr. The JSON phase
fields inspected were `name`, `ok` and `failure`.

| Disagreement | Independently observed result | M1 preservation assessment |
|---|---|---|
| D1 | `fold_releases` gives custody `tree directory 'releases' contains names that merge under ASCII case folding: 'Pair.txt' and 'pair.txt'`; binding uses `directory holds two entries a case-insensitive filesystem would merge: 'releases/Pair.txt' and 'releases/pair.txt'`; materialization uses `releases contains names that merge under ASCII case folding: 'Pair.txt' and 'pair.txt'`. Rules/unused collisions reach binding. Root sibling collisions escape standalone materialization. | Shared witnesses have enough parent/local/full-path information for all three renderers; role and phase remain distinct. |
| D2 | Regular `Releases/other.txt` and empty `Releases` refuse custody/base/append with the configured-alias text; standalone materialization passes. Lone `Rules` after removing exact `rules` gets binding's pinned-content-root wording and append's configured-target wording. | Actual ancestor listings and ordered configured targets preserve both refusal locations and texts, including absence of an exact counterpart. |
| D3 | Portable `bad?.txt` refuses the relevant name stage. Posix release names pass name screening but fail physical export with the repertoire-qualified materializer text. Full gate-only append of `releases/policy/bad?.txt` passes. | Separate repertoire and export obligations preserve the pinned PASS. |
| D4 | `unused/bad\xff` passes chain/base/export, refuses binding and append with `tree entry name is not valid UTF-8 for folding`; NFC/NFD UTF-8 names pass under posix-bytes. | Raw bytes, strict fold obligations and ASCII-only folding preserve scope and text. |
| D5 | Release symlink/gitlink refuses custody/base/materialization with `base tree entry has non-regular mode 120000: releases/link.txt` or `160000: releases/module`; binding passes those release extras. Content gitlinks refuse regardless of suffix; ordinary suffixless content symlinks and unrelated links pass. Selected content/attested symlinks use their distinct corpus texts. | Purpose-specific mode/type facts preserve all refusals and acceptance exceptions. |
| D6 | State leaf link gives composed `state file is a symlink: receipt/corpus-journal.jsonl`; direct export uses the base-tree mode text. Ancestor links distinguish `state path has a symlinked component: receipt` from materializer `protected path ancestor is not a directory: receipt`; ancestor blobs use `tree path ancestor is not a directory: receipt`. | Leaf/ancestor role and caller masking preserve all renderers. Supplied journal bytes do not imply a state re-read. |
| D7 | Portable `releases/hidden.sigx` gets the release short-suffix refusal; binding/export pass. With `.yml` pinned, both regular and symlink `rules/hidden.ymlx` get corpus's quoted short-suffix text; posix variants pass. | One extension operation can serve both suffix obligations without changing activation or quotation. |
| D8 | `attrs_releases` refuses custody/base/append with `transforming attribute filter applies to protected path releases/anchors/producer-ed25519.pub`; binding/export pass. Rules/toolchain transforms and rules-local bad source syntax/mode refuse append only; root source symlink refuses custody/base/append; irrelevant transforms pass everywhere. | The proposed selectors preserve these target sets and both exact/folded readings. No new binding/export attribute obligation is introduced. |
| D9 | Disjoint tree anchors with an unused symlink refuse base verification; identical candidate with explicit caller anchors passes. Existing alias/non-UTF-8 exclusion tests also passed. | Anchor origin in the plan and acceptance key is necessary and sufficient for this distinction. |
| D10 | `name_and_mode`: custody names win, standalone export mode wins. `names_vs_state`: custody alias wins, full append state symlink wins. `mode_vs_attributes`: custody export mode wins, append attribute wins at `releases/anchors/alpha-root.pem`. `history_symlink`: CLI history fails with `release history is not immutable: release path is a symlink: releases/link.txt`. | Legacy barriers preserve all four. The separate append call on the corpus-schema history fixture returns `line 1 lacks source_record_id`, exactly as the record cautions; it is not evidence of append push-chain validation. |
| D11 | Direct directory verification without `.git` passes the fold and attribute controls; state-link failure contains the absolute physical path and `required state file is missing or non-regular: `. | Distinct DirectoryEvidence and retained OS guards preserve this public contract. |
| D12 | Normal repeated calls: matching work 28 then 56. Ceiling 40: first passes at 28, second refuses `attribute matching exceeds the work budget of 40 steps` at exactly 40. Path bytes 27 then 40; attribute bytes/rules remain 22/1. | The folded exact-step exhaustion replay is implementable; whole-rule admission alone would be insufficient. |

The full historical package at `301e73d964e23b261cfc80affcc46238b15e4fc9`
passed the base helper on the empty `releases/EXTRA` collision and failed the
CLI at binding. Current source refused both at the custody/name screen. The
child's package path pointed into the extracted historical `src`. A separate
Git diff confirmed current `_names.py`, `snapshot.py` and `corpus.py` match that
historical revision. This confirms the record's statement that M1 must not
claim the pre-v0.6 fix as a new security result.

Eight isolated reader operations also matched: `entry` returns metadata for
both link types, blob/digests refuse a symlink by mode and a gitlink by object
type, while materialization uses its base-tree mode wording. The gitlink
diagnostic contained this run's actual fixture-base OID, not a copied OID.

F1's four embedded controls reproduced exactly. Nine additional raw-index/tree
probes confirmed the expanded schedule at design 472–490:

- A non-tree raw-byte failure beats a lexically earlier empty-tree alias;
  a non-tree alias beats a lexically earlier empty-tree raw-byte failure.
- Non-append configured aliases beat an earlier scoped portable-name fault;
  an alias witness with a bad-byte descendant must itself pass the full-path
  folding sub-step before an alias can be rendered.
- In binding, swapping early portable and raw-byte failures swaps the winner;
  all name checks precede even an earlier sibling collision.
- In standalone materialization, an earlier local sibling collision beats a
  later invalid local name. Parent groups use insertion order: collision in
  `a-foo` beats invalid `a/bad?.txt`, although sorting parent strings would
  inspect `a` first.

For F2, I additionally ran an isolated cached-matcher feasibility experiment.
Successful match costs were admitted arithmetically; a match that would exceed
the remaining ceiling reran the original matcher with individual charge steps.
Original state-application charging remained in place. At all 62 ceilings
`0..60` and `67108864`, two-call outcomes, exception classes and every public
`SnapshotWork` field equaled the unmodified API. The experiment exercised 63
cache hits and 54 exhaustion replays. It establishes the folded mechanism's
feasibility for D12, not completion of M1 or proof of all overlapping-plan cases.

**3. Consumer census — CONFIRMED, with main-ref evidence refreshed.**

The specifically requested Chronicle location exists at
`/Users/maxghenis/PolicyEngine/chronicle`; the alternate
`/Users/maxghenis/TheAxiomFoundation/chronicle` path in the offline preamble
does not exist. All Chronicle inspection used Git show/grep at
`origin/codex/thesis-ledger-facts`, independently resolved to
`e9b803b609e0282f8ea33cd2c07e47e869b0739c`; no checkout was performed.

- `scripts/canonical_json.py:7–21`: `canonical_bytes`, `canonical_sha256`,
  `canonical_stringify`, `main`, `utf16_sort_key`.
- `scripts/receipt_pins.py:7–8`: `AppendGateSpec`, `AnchorSpec`, `ChainSpec`.
- `scripts/verify_release_chain.py:21–22,44–67`: release-chain module,
  `SnapshotError`, `TreeSnapshot`; the constants, regexes, records and utility
  re-exports enumerated in design 236 all match. This includes
  `CRYPTOGRAPHY_AVAILABLE`, `DEFAULT_CLOCK_SKEW_SECONDS`, `MAX_FUTURE_SECONDS`,
  `MAX_RELEASE_INDEX`, `MANIFEST_RE`, `PRODUCER_SIGNATURE_BYTES`,
  `PRODUCER_SIGNATURE_RE`, `SHA256_RE`, `STRICT_UTC_RE`, `TIME_STAMP_RE`,
  `AnchorSpec`, `ChainSpec`, `ChainVerification`, `GitEntry`,
  `ReleaseChainError`, `ReleaseRecord`, `jsonl_line_offsets`,
  `manifest_filename`, `parse_created_at`,
  `producer_signature_path_for_manifest`, and `sha256_bytes`.
  Private `_receipt_re` at 51 and `_format_time` at 278 are real dependencies.
- The wrappers at 70–207 call `validate_manifest_schema`, `load_manifest`,
  `receipt_paths_for_manifest`, `verify_producer_signature_bytes`,
  `verify_producer_signature`, `verify_receipt`, `verify_release_receipts`,
  `verify_release_chain`, `verify_release_history_immutable`, and
  `verify_base_release_chain`. Main uses snapshot selection and
  `candidate.assert_ancestor(base)` at 245–260.
- `scripts/check_thesis_facts_append.py:50–73,408–437,508–514`: append module,
  `MANIFEST_RE`, `ReleaseChainError`, `AppendError`, `AppendGateSpec`,
  `AppendGateVerdict`, `reject_non_append_bytes`,
  `expected_assertion_version_id`, `effective_current_rows`, `check_rows`,
  `verify_append_gate_verdict`, and the verdict's summary and candidate/base
  commit/tree fields.

Runtime wrappers preserve messages through exception types; they do not select
protected-tree outcomes by a text switch. Their exact stderr templates are
`f"release chain verification failed: {exc}"` at release shim 270–272,
`f"{VERDICT_REFUSAL_PREFIX}{exc}"` at append shim 505–507, and
`f"{REFUSAL_PREFIX}{exc}"` at 502–504. The prefixes at 184–185 are
`"thesis-facts append check failed: "` and
`"thesis-facts append check refused: "`; print adds a newline.

Chronicle's `test_receipt_shim_transparency.py:146–161,187–216` compares
exit code, stdout and complete normalized stderr bytes. The only stderr
normalization replaces the OpenSSL queue ID matched by
`rb"(?m)^[0-9A-Fa-f]{8,16}(?=:error:)"`; it does not strip whitespace.
The successful candidate/base stdout line is separately asserted and absent on
refusal. Full equality precedes the markers at 313–353 and 558–603:
line-count mismatch, producer signature failure, RFC 3161 inspection,
rewritten historical line, appended-line failure and missing release manifest.
Isolation tests at 364–412,823–824,873–918,1009–1012 independently match
symlink/not-regular paths, truncation/rewrite text and the refused prefix.

Axiom-encode's local `origin/main` resolved to
`629b8f9fd5fc511ff82d58d23790cc29d460096b`. Its executable receipt imports are
`receipt.sign` at `src/axiom_encode/cli.py:46` and
`tests/test_receipt_sign_adoption.py:7`; the five used sign symbols and error
mapping at CLI 25846–25865 agree with design 246. Thesis `origin/main` resolved
to `188e34696e5040840cae1dc2702dd1584ef9447c`: its only receipt imports are
`receipt.sign` at `scripts/sign_record_snapshot.py:265–270`,
`scripts/verify_record_chain.py:286`, and `tests/test_producer_signing.py:23–27`.
I also independently resolved and searched both 0.6 adoption refs named by the
record; hashes and sign-only conclusions match. These are local Git-object
censuses under the offline instruction, not claims about newer remote state.

**4. Design — CONFIRMED for sufficiency, ordering and D12 feasibility;
CORRECTED for one low-priority conversion-table omission.**

The proposed surface is sufficient. ProtectionPlan represents ordered scope
and purpose; TreePolicy owns decisions and private caches; immutable views
record topology, findings and completion; finding_for selects by the caller's
nested trace; require rejects incomplete or incompatible selections;
DirectoryEvidence preserves a separate physical subject. The witness fields
at design 411–419 support the actual competing renderers. Provenance and plan
keys at 421–432 prevent equal OIDs from authorizing reuse across unrelated
subjects. Partial topology at 434–439 is essential for state/history barriers.

Lazy evaluation is compatible with every reproduced D10 precedence. The fold
also addresses the harder same-stage ordering: the explicit schedules and
sub-steps at 472–490 match the four embedded and nine independent order probes.
Canonical fact reuse cannot supply one universal failure rank; the design now
states that constraint precisely. Attribute I/O remains deferred until its old
barrier. The D12 replay paragraph at 507–525 is implementable without the
public-counter change found in round 1, as the 62-ceiling experiment confirms.

The four formerly missing boundary categories are now assigned at 549–552:
no-base manifest initialization, closed manifest filename schema, anchor
serialization/physical guards, and construction-time CorpusSpec/ChainSpec
admission. `_is_protected` ownership at 553 is explicit. These retained
configuration, schema and actual-I/O checks are defensible boundaries, not
duplicate generic decisions over already authenticated tree evidence.

**Low finding R2-L1 — include the base-aware manifest-child classifier.**
`append_gate.check_release_proposal`, at `append_gate.py:962–967`, gets
`manifest_listing.children` and computes `candidate_has_chain` using:

```python
name.endswith(".json")
and isinstance(child, GitEntry)
and child.mode in {"100644", "100755"}
```

The conversion table at design 539–553 explicitly assigns the analogous
no-base classifier at 1057–1068, but not this immediate-child shape/mode loop.
Add this site to that row: shared view evidence supplies immediate regular
children; append retains `.json` schema classification and pre-genesis
orchestration. Preserve its barrier after release-history checks and before
the later genesis branch.

An independent raw-index probe using `test_append_gate.base_repository`
confirmed the distinction: both regular modes at
`releases/manifests/0000-0000000000000000.json` reach the missing
manifest/signature/receipt-triple refusal, while a tree at that same `.json`
path reaches the legacy pre-genesis changed-releases refusal. Earlier history
already rejects nonregular release leaves (`release_chain.py:2200–2204`),
so this is a small completeness/duplicate-classification issue, not an
uncovered acceptance defect. The architecture can represent it; the table
should tell the implementer to consume those facts here too. This low alone
does not block approval. I found no other unassigned generic rejection loop
in the audited runtime sites.

The snapshot-to-policy import direction at design 381–394 is workable:
function-local forwarding avoids the import cycle, while call-time lookup
preserves legacy hooks and limit monkeypatches. No unsupported eager aliasing
assumption remains. The consolidation benefit is concrete at 565–575, with
source locators for duplicate collision, fold-key, prefix-alias, DOS and
ancestor machinery.

**5. Migration plan — CONFIRMED.**

The six numbered milestones now describe seven implementation PR units because
PR3 is explicitly split into 3a and 3b. Ordering is correct: freeze contracts;
introduce names/aliases behind facades; migrate modes/ancestors; thread export
selections into the writer; move attribute evaluation/accounting; migrate
append/binding; remove duplicate algorithms and validate consumers.

PR3a/3b have explicit public-counter, path-charge, traversal and refusal-point
gates at 630–646. PR3b owns the case-sensitive/case-insensitive host validation.
No further mandatory split is established by this design audit; PR5 remains
the widest step and already explicitly permits splitting append and binding
if the implementation diff warrants it. Preserve that review-size checkpoint.

Design 591–602 requires every numbered PR to retain the 1,466 baseline tests,
run the expanded suite and all 108 authenticated harness cases with zero skips,
refresh the consumer/import/text census, and obtain both reviews. Chronicle
transparency and isolation now gate every refusal-path PR, including 3a and 3b,
instead of appearing only at the end. PR1 freezes exact census gaps and F1
fixtures; PR4 covers late imports/hooks and D12 boundaries; PR6 checks for
leftover decision loops, import shims, CLI bytes and consumer signing tests.
No required compatibility gate is missing.

Independent execution confirmed **1,466 passed, zero skips, exit 0, 295.02s**
and **108 passed, zero skips, exit 0, 294.44s**. Harness collection was
43 ledger / 28 append / 17 witness / 20 attest. All eleven per-suite
SHA-256 checks matched. The existing independent-checkout legs remain in the
unchanged harnesses. Ledger's normalization helper does not strip; append,
witness and attest helpers do. Baseline subprocess wrappers also perform
their existing stripping. None of this permits broadening normalization, and
Chronicle's complete-byte comparison remains the stronger whitespace gate.

**6. Risks — CONFIRMED.**

| Risk | Assessment of ranking and whether the specified probe decides it |
|---|---|
| 1: evaluation order and early I/O, critical | Correct top priority. D10, same-stage swaps, tree/non-tree and binding sub-step controls decide the identified ordering errors. Instrumented zero attribute reads before old barriers tests the I/O hazard directly. Current-behavior controls reproduced. |
| 2: provenance, scope and incomplete acceptance, critical | Correct. Incompatible reuse must refuse before payload access; the added compatible reuse control rules out an implementation that merely refuses everything. Subject/plan/anchor/closed-context dimensions are represented. Future implementation gate, not a completed test of a nonexistent view. |
| 3: budget and memory, high | Correct. Exact public counters and refusal points, alongside actual operation counts/cache growth, distinguish preserved admission from merely faster computation. D12 replay feasibility was independently exercised; overlapping/resumed/base-candidate sweeps remain required. |
| 4: empty-tree and ancestor omission, high | Raw-index/mktree variants decide the omission independently of host staging behavior. Current and historical controls reproduced. |
| 5: attribute scope/readings, high | Comparing selected targets before outcomes detects changes hidden by coincidentally equal verdicts; independent exact/folded reset and source-mode controls address the algorithm. D8 controls reproduced. |
| 6: exception/rendering/byte drift, high | Exact golden strings, wrapper classes, long `_quoted` paths, witness order and consumer complete-byte comparisons test the observable contract. |
| 7: physical guards, high | Direct-directory tests without `.git`, replacement/partial-write and post-materialization mutation probes distinguish a static tree certificate from safe actual reads. Existing guards remain explicit. |
| 8: deliberate scope exceptions, medium | The repertoire × region × entry-type × use matrix plus D3–D9 tests the named scope errors; sign-only imports guard unrelated consumers. |
| 9: misleading validation environment, medium | Forced Git entries, both filesystem case behaviors, authenticated oracle sources, both legs and zero skips address the stated evidence hazards. Platform recording prevents one modern host from being misreported as minimum-floor coverage. |
| Import cycle/forwarding, additional low | Both fresh-process import orders and patches made after import test partial initialization, recursion and stale bindings directly. The deferred import direction is specified. |

The ranking is defensible and no additional critical risk was identified.
These probes decide the named risks when run against old and new code; passing
finite controls is not a proof of every future input. The record correctly
labels them implementation acceptance gates at 707–709.

**7. Voice and precision — CONFIRMED.**

F8's concrete corrections hold: CONTRIBUTING.md:21–22 contains the prohibition;
the corrected helper/function ranges locate their intended code; the ledger
fixture's decorator is 1134 and its `def` is 1135; reader fixture OIDs are now
case labels with an explicit variability caveat. The formerly unlocated
directory/no-attribute/normalization-word claims now cite code or scoped
absence checks at design 65,87,108,150,246. The round-1 validation row at 1073
links the committed review and identifies its changes; dispatch bookkeeping
has moved out of the design. The distinction between durable source/drivers
and temporary result files is explicit at 1080–1082.

I found no remaining substantive baseline-behavior claim without a usable
source/test locator or executable control. Proposal contracts and ranked risks
are identified as proposed constraints, rather than misrepresented as source
facts. Run metadata is labeled as run metadata. The prose states conditions,
evidence and decisions without an implementation narrative. The low
conversion omission in item 4 is a completeness issue, not a voice issue.

All eight round-1 folds are confirmed: F1 nested schedules/fixtures/risk probe;
F2 exact-step replay; F3 PR3a/3b and counter/host gates; F4 per-PR Chronicle
gates; F5 boundary/constructor/selector rows; F6 import-cycle resolution;
F7 concrete consolidation benefits; F8 locator/fixture/normalization and
validation-row corrections. No previously correct D1–D12 or consumer
compatibility result regressed in this audit.

**Commands, artifacts and limits.**

The reusable local evidence directory is `/tmp/receipt-m1-r2-astra/`:
`complete-probes.py/.jsonl`, `contract-probes.py/.jsonl`,
`interleave.py/.jsonl`, `independent-probes.py/.jsonl`,
`manifest-classifier.py/.jsonl`, `gap-needles.txt`, `harness-collection.log`,
`non-harness.log`, and `harness.log`. The first three scripts are exact
extractions of the design's cited blocks; the independent scripts use their
freshly generated fixture or the existing append test fixture. No package or
test implementation was patched on disk. The replay experiment restored its
process-local monkeypatches.

The review-specific probe sources are also retained durably in
`docs/design/review-r2/independent-probes.py` and
`docs/design/review-r2/manifest-classifier.py`. Run the embedded complete
driver first to generate the fresh `/tmp/receipt-m1-r2-astra/complete-probes.jsonl`
consumed by the independent probe.

```sh
git rev-parse HEAD
git ls-files
git diff v0.6.0 -- src tests CONTRIBUTING.md
git diff ca5c664545e12216cfed05813e36e7c86b108312 -- \
  docs/design/0.7-m1-protected-tree-policy.md src tests CONTRIBUTING.md
PYTHONPATH=src .venv/bin/python /tmp/receipt-m1-r2-astra/complete-probes.py
PYTHONPATH=src .venv/bin/python /tmp/receipt-m1-r2-astra/contract-probes.py
PYTHONPATH=src .venv/bin/python /tmp/receipt-m1-r2-astra/interleave.py
PYTHONPATH=src .venv/bin/python /tmp/receipt-m1-r2-astra/independent-probes.py
PYTHONPATH=src .venv/bin/python /tmp/receipt-m1-r2-astra/manifest-classifier.py
.venv/bin/pytest --ignore-glob='tests/test_*_equivalence.py' -q
RECEIPT_LEDGER_TREE=/Users/maxghenis/TheAxiomFoundation/receipt/.extraction/ledger-9dafe81 \
RECEIPT_BRIER_TREE=/Users/maxghenis/TheAxiomFoundation/receipt/.extraction/brier-4b9e7be \
.venv/bin/pytest -q tests/test_ledger_equivalence.py \
  tests/test_append_gate_equivalence.py tests/test_brier_witness_equivalence.py \
  tests/test_attest_equivalence.py
```

Additional read-only commands were scoped source/test reads and grep;
consumer `git ls-files`, `git show`, `git grep`; per-harness collection; and
each harness's existing `_authenticated_baseline_tree` plus direct SHA-256
comparison of its source-file dictionary. The recorded starting HEAD was the
requested artifact commit. The two source/design diffs above are empty.

Validation host: Python 3.14.4, Git 2.53.0, OpenSSL 3.6.3, macOS 26.6.2 arm64.
Minimum-version floors and a second filesystem platform were not rerun.
Consumer suites were inspected, not executed; the current design requires
those future upgraded-checkout gates and does not claim they have passed.
No proposed protected_tree implementation, cache integration or consumer pin
bump is certified by this design approval.

Delivery limitation: the filesystem sandbox rejected direct writes to both
requested external files, `review-full.md` and `verdict.md`, under
`/Users/maxghenis/chief-of-staff/state/receipt-07/peer/m1-design-r2-astra/`
with `Operation not permitted`. This complete report is preserved at
`docs/design/REVIEW-r2-m1.md` and `/tmp/receipt-m1-r2-astra/review-full.md`.
The final response carries the report for the runner's `-o` capture; this
session cannot verify that external capture or place the second external copy.

---SUBFLEET-VERDICT-BEGIN---
{"schema_version":1,"artifact_revision":{"kind":"file","path":"docs/design/0.7-m1-protected-tree-policy.md","commit":"ca5c664545e12216cfed05813e36e7c86b108312"},"verdict":"approve","findings":[{"severity":"low","location":"Converting every existing site, lines 539-553; append_gate.check_release_proposal at append_gate.py:962-967","description":"The base-aware candidate_has_chain loop still classifies immediate manifest children by GitEntry shape and regular mode but lacks an explicit conversion row; assign shared regular-child evidence to the view while retaining append's .json/pre-genesis orchestration, as already done for the no-base classifier."}],"notes":["Defensive correctness and completeness audit completed alone and offline; all seven requested items assessed, with no design/source/test edits and no subagents or background tasks.","Verified 28 sampled source sites across all six modules by ranges, conditions, tree scope, exact refusal expressions and cited E/S/V tests; twenty claimed literal-pin gaps reproduced by scoped grep.","Reran all three embedded drivers: 52/9/4 JSONL rows, exit 0 and empty driver stderr; all D1-D12 cases, historical controls, public append/directory/anchor controls and F1 swaps reproduced.","Ran nine additional ordering probes, eight isolated payload-reader operations and a three-case base-aware manifest classification probe using real Git objects.","D12 reproduced counters 28/56 normally and 28/40 at ceiling 40; a cached-matcher arithmetic-admission experiment with single-match exhaustion replay matched outcomes, exception classes and all public SnapshotWork fields at 62 ceilings.","Chronicle Git-object census confirmed e9b803b609e0282f8ea33cd2c07e47e869b0739c and complete normalized stderr comparison; axiom-encode origin/main 629b8f9fd5fc511ff82d58d23790cc29d460096b and thesis origin/main 188e34696e5040840cae1dc2702dd1584ef9447c import receipt.sign only; both adoption refs also confirmed.","1466 non-harness tests passed in 295.02s; 108 authenticated harness cases passed in 294.44s; both zero skips and exit 0. Collection 43/28/17/20; all eleven per-suite source SHA-256 checks matched.","All F1-F8 folds confirmed. The one remaining low-priority completeness note does not block approval. Consumer upgrade suites, alternate-host floors and the proposed module remain future implementation gates."]}
---SUBFLEET-VERDICT-END---