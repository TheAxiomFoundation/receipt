# Changelog

Every entry says what changed and what an auditor can conclude from it that
they could not before. Refusals are named as refusals: a check added here is an
input the package used to accept, or accept for the wrong reason.

## 0.6.0

### Commit and tree subjects (#52, #55, #56, #57; breaking)

`verify_append_gate(root, *, spec, base_ref=None, commit="HEAD", ...)` verifies
the tree object named by `commit`. State bytes, release entries, changed paths
and base ancestry come from entered `TreeSnapshot`s; the working tree and index
are never read. With a base, the candidate must be a full commit OID or the gate
refuses `base_ref requires a full commit OID`. The string return keeps the
existing success text. `verify_append_gate_verdict` returns that text as
`AppendGateVerdict.summary` beside `candidate_commit`, `candidate_tree`,
`base_commit`, `base_tree`, `object_format` and `name_repertoire`, so a consumer
can record which commit the gate judged even when `HEAD` later moves.

Append state blobs, including both base and candidate ledgers and prefixes,
decode as UTF-8 with universal-newline translation. Invalid bytes refuse
`state file is not valid UTF-8: {relative}` through `AppendError`. An ordinary
append over a committed `café` row now accepts under UTF-8, ISO8859-1 and C
process locales; previously it falsely reported an existing-line rewrite
under ISO8859-1 and leaked `UnicodeDecodeError` under C.

`verify_corpus_binding(snapshot, journal_bytes, *, spec)` takes an entered
`TreeSnapshot`. A directory argument refuses with
`verify_corpus_binding requires a TreeSnapshot; select one with TreeSnapshot.select`.
One authenticated tree listing supplies content membership, exact spellings,
fold-equal siblings and tombstone absence; bound digests stream from the named
blobs. A content-root gitlink refuses `content root contains a gitlink: {path}`;
a content symlink refuses
`content root contains a symlink where a regular file was recorded: {path}`.
The #44 property tests rewrite, insert and rename files under both content
roots and `.axiom`, then obtain the same verdict, commit and tree OIDs.

`run_verification(root, spec: LoadedSpec, *, base_ref=None, commit="HEAD",
expect_commit=None, expect_tree=None, expect_anchor_set=None,
verify_objects=False)` replaces the split `VerificationSpec`, `spec_path` and
`spec_sha256` inputs. A direct `VerificationSpec` refuses
`spec must be a LoadedSpec returned by load_spec`; a base without the candidate
pin refuses `base_ref requires expect_commit`. `LoadedSpec` is a frozen,
loader-owned record of `verification`, `path`, `sha256` and `pinned`.
`load_spec(spec_path, *, expect_sha256=None)` hashes the source bytes once and checks
the expectation before compiling or executing them; a mismatch refuses
`spec {digest} is not the expected spec {expected}` without running the spec.

An explicit `expect_anchor_set` without a pinned spec refuses
`an anchor pin requires a pinned spec`. The new defaulted
`VerificationSpec.anchor_set_sha256` can supply the anchor expectation under a
matching spec pin; in an unpinned spec it remains the producer's proposal and
does not establish trust. Two conflicting pins refuse
`anchor pins disagree: command expects {direct}, spec expects {declared}`.
The configured anchor filenames are normalized once, their materialized bytes
are hashed into the canonical anchor-set digest, and the digest is compared
before any OpenSSL call. A mismatch refuses
`anchor set {actual} is not the pinned anchor set {expected}`; the digest the
custody pass actually consumed must also equal the materialized digest.

`verify_release_history_immutable(spec, *, candidate, base)` compares two
entered snapshots instead of a directory and a base ref, retaining the
`existing release file was deleted`, `existing release file mode changed` and
`existing release file bytes changed` refusals relative to the resolved base
OID. `verify_base_release_chain(spec, *, base, anchor_dir=None,
enforce_production_pins=True, clock_skew_seconds=DEFAULT_CLOCK_SKEW_SECONDS)`
materializes an entered base instead of taking a root, commit and release-entry
mapping. An explicit `anchor_dir` supplies caller-owned trust material; a
disjoint unused anchor subtree is then excluded from materialization. Anchors
nested under a required release prefix are still written and screened, but the
append gate's cryptographic calls use the caller-owned directory.

The base helper and composed custody stage share the append gate's protected
listing screen before materialization or OpenSSL. Files, trees, empty trees
and every protected ancestor directory's siblings are screened under the
declared repertoire. A regular `releases/extra` beside an empty `releases/EXTRA`
now refuses `tree directory 'releases' contains names that merge under ASCII
case folding: 'EXTRA' and 'extra'`; the base helper previously accepted one
verified release, and the composed command refused only after custody.
Disjoint unused tree-anchor descendants remain excluded with caller trust.

`verify_release_chain(root)` remains a directory verifier with its existing
signature. Its breaking precondition is explicit: it speaks for the directory
as it was read, once, by this process; a caller on a directory it does not own
carries the concurrent-writer residual. Commit-addressed callers use
`verify_append_gate` or `run_verification`, which hand the directory verifier
private materializations. The directory verifier retains component spelling,
symlink and regular-file guards; it probes anchors before the configured-path
and manifest-directory checks, after argument validation and the OpenSSL 3.0
preflight. OpenSSL's `-CAfile` names a private byte-for-byte copy of the captured
anchor bytes even when production pinning and observation are disabled. The
26-case authenticated `--full` battery retains its directory subject.
The docstring describes guarded reads per consumption: a two-release probe
reads the producer key and each TSA anchor twice, and digest observation
requires repeated anchor bytes to agree across releases and roles.

`repository_slug` parses HTTPS/SSH authorities and SCP origins, requiring
exactly `github.com` ignoring ASCII case and two path components. An optional
user, port and trailing slash are accepted; only a terminal `.git` is stripped,
preserving `TheAxiomFoundation/receipt.audit`. Foreign hosts (including Unicode
case aliases), extra components, whitespace, queries and fragments refuse
`cannot derive repository slug from {url!r}`. The origin query
removes only Git's single framing newline before validation.
The SSH-port origin `ssh://git@github.com:22/O/R.git` yields `O/R`, previously
`22/O`. `receipt verify` does not call this helper.

### Verdict fields and command output (#56; breaking)

The seven-field `VerifyResult` identity and object-store group is `commit`,
`tree`, `object_format`, `base_commit`, `base_tree`, `name_repertoire` and
`object_store`. Six are new relative to 0.5.2: `base_commit` already existed.
Candidate identity is reported once selection succeeds; refusals before that
point leave it absent. JSON reports `commit`, `tree`, `objectFormat`, `base`
with commit/tree members, `nameRepertoire` and `objectStore`; the spec record
gains `pinned`.

`receipt verify` adds `--commit`, `--expect-spec-sha256`, `--expect-commit`,
`--expect-tree`, `--expect-anchor-set` and `--verify-objects`. The CLI refuses
`--base-ref requires --expect-commit` and
`--expect-anchor-set requires --expect-spec-sha256`, including through the JSON
error boundary. The four identity/status lines are
`commit <oid> (tree <oid>)`, `base <oid> (tree <oid>)` when supplied,
`names <repertoire>` and `objects ...`. Object-store status distinguishes
`objects not requested`, `objects requested; verification did not complete`
and `objects verified: <count>`; JSON distinguishes `null`,
`{"requested": true, "report": null}` and a report with `objects`, `storeKiB`
and `seconds`.

The binding claim changes from
`binding of the witnessed journal to this working tree` to
`binding of the witnessed journal to tree {tree[:12]}`. Custody without an
auditor-owned anchor pin reads
`custody under the anchor set {digest} the verified tree carries`; with the pin
it reads `custody of the release chain`. `notEstablished` adds
`that the files in any checkout equal the verified tree`, and, when applicable,
`that the anchor set is one the auditor trusts` and
`that the spec's code was trusted`. Spec, commit, tree and anchor-set pins are
the auditor's out-of-band inputs, not assertions supplied by the producer.

### Object reader and declared names (#52, #55)

`receipt.snapshot` adds `TreeSnapshot`, `TreeListing`, `Materialization` and
`ObjectStoreReport`. The context-managed reader type-binds and rehashes fetched
commit, tree and blob bytes against their object names before using them,
walks ancestry over authenticated commit objects, and owns one long-lived
`git cat-file --batch-command` child while entered. Framing failures abandon
the stream; object, byte, path, depth, time and materialization budgets refuse
as work arrives. The acceptance fixture has 20,000 entries and exactly
134,217,728 content bytes and verifies within every default budget. A blob the
verdict never fetches is bound by name and type only; gitlink OIDs are never
fetched.

Git runs under a frozen environment and command allow-list, with an explicit
repository and closing configuration re-audit. The ordinary reader requires
Git 2.36.0; `verify_objects=True` additionally requires Git 2.50.0 and a build
reporting `SHA1_DC`, then runs bounded store-wide `fsck` without refs or index.
The default rehash is plain `hashlib.sha1`. The corruption test flips a packed
object byte and proves the integrity refusal; collision detection itself is
Git's, attested by the build-options preflight. Bare and SHA-256 repositories,
grafts, partial clones and alternates refuse. The shipped reader also refuses
every shallow repository with `shallow repositories are unsupported`, a
stronger rule than the plan's base-outside-boundary residual; use
`fetch-depth: 0`.

The reader interprets committed `.gitattributes` through a bounded,
fail-closed matcher. Exact and ASCII-folded readings each compute their own
final attribute state with last-rule-wins precedence; if either reading
leaves protected `filter`, `ident` or `working-tree-encoding` set or valued,
verification refuses in the existing transforming-attribute words. Repository
configuration never chooses the reading. The same fully pinned commit with
`releases/** filter=evil` followed by `RELEASES/** -filter` now refuses under
both `core.ignoreCase` settings; it previously passed under `true`.
`text` and `eol` remain accepted.
LFS-tracked content roots are unsupported: the raw pointer blob's digest will
not match the journal's content digest. The working tree's transformed bytes
cannot substitute for the committed blob.

`receipt/_names.py` shares the component, device-name, ASCII-fold and 8.3
suffix screens. `CorpusSpec.name_repertoire` and `ChainSpec.name_repertoire`
default to `"portable"` and also accept `"posix-bytes"`; existing spec fields
remain. `CorpusVerification.name_repertoire`, `VerifyResult.name_repertoire`
and `AppendGateVerdict.name_repertoire` report the choice. Mismatched chain and
corpus declarations refuse `spec declares two name repertoires`. Both
repertoires refuse undecodable UTF-8 names wherever quoted or folded and
ASCII-fold-equal siblings; only `portable` applies the component repertoire,
Win32 device table and 8.3 extension screen. `posix-bytes` otherwise compares
exact bytes, with no Unicode normalization or Unicode case-fold model.
`TreeSnapshot.materialize(..., repertoire=...)` requires the keyword and always
screens names it writes as portable, including under `posix-bytes`. The review
proved positive nonportable-name cases and NFC/NFD pairs under `posix-bytes`,
with portable and ASCII-case-collision controls.
The portable-name helper's docstring states the policy's known cost:
rulespec-us at d58cc0c carries 33 non-portable names among 15,216 tracked paths.

### Refusal migrations and removed machinery (#55, #56, #57; breaking)

The whole-listing corpus screen changes the portable-name contexts
`tree entry beside '<sibling>'` and `tree entry examined for a tombstone` to
`tree entry '<entry>'`; the portable-name explanation is unchanged. Both
`removed path ...` tombstone messages retain their complete wording. Required
attested-path completeness now precedes every digest comparison, so a journal
with both an omitted required attested path and a bad content digest refuses
on completeness first. `CorpusSpec` additionally refuses
`CorpusSpec content suffix cannot be the Git dot-dot component: {suffix}`.
Four retained corpus templates interpolate raw paths; `receipt.cli._rendered`
remains the escaping boundary for command output, while a library caller
printing `CorpusError` directly receives those raw paths.

The requirement that every directory above a protected path be listable is
removed for commit-addressed entry points: they read objects and write ordinary
files. The POSIX requirement remains, including for their private
materializations and the append gate's caller-owned anchors. The shared
regular-file reader requires `os.O_NOFOLLOW` and now refuses
`state files cannot be read with secure descent on this platform (os.O_NOFOLLOW is unavailable); receipt requires a POSIX platform`.
The parenthetical was `(os.open lacks dir_fd support)` in 0.5.2; descriptor
descent was removed, not the platform requirement (plan erratum r3l).

The append gate retains a narrow adapter for a nonexistent base's old
`git rev-parse` diagnostic. An existing blob OID supplied as `base_ref` is an
accepted exception to exact text: Git's first line,
`error: <oid>^{commit}: expected commit type, but the object dereferences to blob type`,
is omitted because snapshot selection normalizes resolution failures. Both
versions refuse. The harness and re-pin record name this exception; they do
not broaden message normalization to hide it.

The removed `release_chain` names are `assert_secure_descent_supported`,
`hold_release_root`, `assert_release_root_unchanged`, `confined_state_descriptor`,
`read_state_descriptor`, `_working_release_files`,
`assert_file_modes_authoritative`, `WORKING_TREE_SCAN_OPTIONS`,
`assert_index_carries_no_protected_alias`,
`assert_index_hides_no_working_tree_change`, `assert_state_path_tracked`,
`assert_index_agrees_with_tree`, `assert_release_file_still_indexed`,
`assert_index_content_bound`, `assert_release_root_index_regular`, `_blob_id`,
`git_tree_entries` in full, `git_file_entry`, `git_blob_bytes`,
`materialize_base_tree`, `resolve_base_commit`, `SEARCH_ONLY_DIRECTORY_FLAG`,
`DIRECTORY_OPEN_FLAGS`, `DESCENT_REQUIRES_DIRECTORY_READ`,
`unreadable_directory_error`, `_is_symlink_at`, `ConfinedState`,
`PATHSPEC_ENVIRONMENT`, `_git_environment`, `_git_run`, `_git_bool`,
`_observed_git_category`, `CE_INTENT_TO_ADD`, `CE_VALID`, `CE_SKIP_WORKTREE`,
`INDEX_DEBUG_LINES`, `_INDEX_DEBUG_FLAGS_RE`, `_IndexRecord`,
`_split_index_debug`, `_parse_index_records`, `_index_entries`,
`_all_index_entries`, `_fold_component`, `_folded_parts`, `_surface_alias_paths`,
`_exact_relative` and `_assert_no_symlinked_release_component`. Their subjects
were checkout/index agreement, descriptor lifetimes or readers whose callers
were deleted. `GitEntry` moved to `snapshot.py` and remains re-exported from
`release_chain`.

The removed `append_gate` names are `_git_output`, `_resolve_base_commit`,
`_manifest_at_ref`, `_set_root` including its descriptor-holding return,
`_staged_surface_changes`, `_StateSnapshot`, `_read_state_snapshot`,
`_assert_state_unchanged`, `_assert_states_unchanged`, `_assert_root_unchanged`,
`_bind_new_release_files`, `_hold_release_root`, `_assert_release_root_unchanged`,
`_assert_release_tree_confined`, `_confine_state_path`, `_nul_paths`,
`_surface_directories`, `_enumerate_surface_directory`, `_unenumerable_surface`,
`_assert_listing_complete`, `_warning_is_outside_the_surfaces`,
`assert_protected_surfaces_enumerable`, `GIT_WARNING_PATH_RE` and
`MAX_SURFACE_WALK_ENTRIES`. `_check_release_proposal` and
`_check_release_chain_without_base` are replaced by the selected-tree flow.
`tests/test_append_gate_diagnostics.py` is deleted: every test targeted
`_set_root`, `_resolve_base_commit` or `_manifest_at_ref`. Five direct-directory
reader tests were relocated to `tests/test_release_chain.py`, where their
subjects still exist.

The removed `corpus` names are `_list_directory`, `_directory_generation`,
`_DirectoryGenerations`, `_TombstoneIndex`, `_fold_survivor` and its filesystem
lookup, `_assert_spelled_by_its_directory`, `_SpellingWork`,
`_assert_no_symlinked_component`, `_assert_no_aliasing_root_component` and its
stat checks, `_regular_file_digest`, `_FileIdentity`, `_AncestorPrefix`,
`_SweepWork`, `_assert_tombstones_absent`, `_tree_content_paths`,
`_assert_no_merging_entries`, `_ascii_upper` and `_win32_device_basename`.
Shared screens replace the local name helpers. `MAX_TOMBSTONE_WORK`,
`MAX_SPELLING_WORK` and `MAX_SWEEP_WORK` are removed; the latter was 262144,
with refusal
`the closed-world sweep would read more than {MAX_SWEEP_WORK} directory entries; the tree cannot be closed`.
`MAX_TREE_ENTRIES` bounds immutable tree width instead. The closing membership
re-sweep, identity re-check, second tombstone pass, POSIX change-time
precondition and `tree changed during verification` refusals disappear with
the live filesystem subject. The imported `PORTABLE_NAME_RE`,
`WIN32_RESERVED_DEVICE_NAMES`, `SHORT_NAME_PUNCTUATION` and
`ALIAS_CAPABLE_SUFFIX_RE` remain available from `corpus`.

### Harness subject and measured differential (#54, #56, #57)

Lane E committed the mutated fixture before verifier changes and ran each
moved case with both readers on the clean main checkout, then with the oracle
on a detached checkout and the port on the main worktree. It checked clean
status, no ignored files and index-tree equality with `HEAD^{tree}`; the
fixtures copy only `ledger/` and `releases/`, with no `.gitattributes`. All 94
baseline cases passed before and after this fixture change. The 0.6 census is
26 re-pinned cases (18 append and 8 ledger), 68 unchanged, 7 Lane C additions
and 7 Lane B additions: 108, comprising append 28, ledger 43, attest 20 and
Brier 17. Lane B recorded 108/108 with zero skips and a separate port-only
production-tree differential of 17/17: both acceptance texts and all 15
retained mutation markers matched against the authenticated `9dafe81` tree.
After a candidate commit, an unstaged rewrite of ledger line 129 deliberately
makes the append-only directory oracle refuse while the port accepts the
unchanged commit. The complete fixture, exception and measurement record is
[`receipts/repin-0.6-tree-object.md`](receipts/repin-0.6-tree-object.md).

### Stated residuals

The plan's STATE rows remain: a same-owner writer to the repository's
configuration files, which every git process re-reads — detected by the
closing re-audit, not excluded — and a direct `verify_release_chain` caller on
a live directory (row 3); shallow: a base outside the boundary refuses,
`fetch-depth: 0` (row 7; the shipped reader's stronger all-shallow refusal is
recorded above); attributes and filters for checkouts and for a direct
`verify_release_chain` caller (`text`, `eol`, `core.autocrlf`, LFS pointers,
whatever the checkout applied; row 9); the checkout's half of name folding and
Win32 aliases, repertoire named in the verdict (row 12); binding — the journal
cannot bind the tree that holds the manifest, #35 is the later closure — and
collision substitution, STATE by default and CLOSE to the reach of git's own
detector under `--verify-objects`, because the rehash is `hashlib.sha1`, plain
SHA-1, and would accept a colliding pair substituted under one OID (row 13);
stale GitHub test merge: ancestor check kept, both OIDs printed, branch
protection is the consumer's remedy (row 14); private materialization:
`mkdtemp` 0700, written once by this process, a same-uid writer is inside the
process's trust boundary (row 15); append-gate trusted anchors:
`trusted_code_root` unchanged, at the trust level of the gate's own imported
code, a commit-addressed `trusted_anchor_commit` is a later non-breaking
addition; `receipt verify` trust otherwise unestablished, a spec field alone
is the producer's proposal, custody narrowed to the anchor set the verified
tree carries (row 16); OpenSSL pathname reads for a direct
`verify_release_chain` caller on a live directory, where OpenSSL still reads
receipt paths in that directory (row 18); producer-controlled spec code unless
the spec is pinned, since without `--expect-spec-sha256` arbitrary code from
the verified repository runs inside the verifier and can defeat every other
row, while under a pin a mismatching spec never runs (row 19); release
identity: the exact-target checks are recorded evidence in the release notes,
reviewed by the release peer rather than re-run by it, with closure requiring
the tag on the reviewed head OID itself under a merge-commit merge (row 20).
`tsa.py` and `attest.py` remain directory verifiers: their upstreams verify
record directories with no commit under review.

## 0.5.2

A refusal release. Nothing new is verified; four classes of input that used to
reach a PASS, or reach it without the check that was supposed to decide it, are
refused instead. It closes #32, the tracking issue for the gaps found in the
2026-09-01 review, in four pull requests — #40, #39, #38 and #41 — plus the
smaller items below.

### The TSA witness lane (#40)

A legacy v1 witness could satisfy a multi-anchor trust bundle with one
producer-selected token, because the spec required at least one signer identity
per bundle rather than one per anchor while v1 verifies exactly one token. Both
halves are closed: `verify_witness` refuses a v1 witness whose legacy bundle
configures more than one anchor, and `_load_trust_bundle` refuses a bundle
anchor the spec carries no identity for. This is a breaking change for a
consumer whose legacy bundle configures two or more anchors, and it is the
intent of the fix.

Existence was taken for agreement. An anchor's declared root and allowed
signers were compared with its pinned identity only for the anchor a witness
selected, so a rotation bundle reusing an active anchor id could activate a
bundle whose anchor contradicted the identity pinned for it with nothing
comparing the two. Every anchor's declared root and signers are compared with
its identity at load now, and the root material itself — path, PEM hash,
certificate hash, actual SPKI — is validated there through the same
`_root_material` helper selection uses. The single-certificate rule for a
pinned root is OpenSSL's own count (`openssl storeutl -noout -certs`) rather
than a pattern of ours, with a new refusal for a root whose certificates
OpenSSL returns no total for.

The record and the response are read once each, through a single descriptor
opened with `O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_BINARY` where
the platform defines each flag, and `fstat`ed for the regular-file rule.
OpenSSL is handed private byte-for-byte copies of exactly those bytes rather
than repository paths: `-data` is the read the witness digest was taken over,
`-in` is the read `tokenSha256` describes, `-CAfile` the read the root's pins
describe. The same discipline reaches the trust bundle, the witness sidecar and
the chain genesis file — `_load_json_once` for the sidecar and genesis, and
`_read_json_once`, which returns the captured bytes beside the payload so the
canonical-JSON comparison, the commitment hash and the size are all answered
from one read, for the trust bundle.

The record, the response and the pinned root are read through descriptors
anchored at the records root rather than checked by name and re-opened by whole
pathname: each interior component is opened relative to the descriptor above it
and the leaf relative to the last, every descriptor staying open until the
bytes are read. The records root's own descriptor opens without `O_NOFOLLOW`,
so a records tree that is itself a link still verifies while a link below the
boundary keeps its refusal. The trust bundle, the sidecar and the genesis keep
the one-read discipline but still open by whole pathname, so `records/trust` is
the one component below the root that no walk looks at. Every component of a
witness token path is `lstat`ed from the records root down and a symlink at any
of them is refused by name. Where `os.open` takes no `dir_fd`, an anchored read
is refused rather than quietly falling back to the check-then-open race.

Trust transitions run over one persistent authority component graph, built per
verification from every active and pending anchor, joining equal `(ID, root
SPKI)` authorities and shared signing keys whether or not an occurrence is
skipped, and never deleting an edge — so a skipped rotation or rename still
counts as history and the order of an anchor array cannot change a verdict. A
pending bundle whose two anchors resolve to one historical class is refused,
naming both anchor slots and every authority identity in the class they share.
A rotation importing another class's signing key meets that same refusal where
that class holds its own slot in the bundle, and a verdict of its own
otherwise, naming the rotating anchor's authority and every identity of every
class whose key it took. A rename is measured against the class's current
signers, the union over its active occurrences in its newest active era, as an
interval rather than an equality, so an authority whose signer rotation has
already activated can still be renamed. A pending-only authority contributes
exactly one candidate, its newest occurrence whatever names it has been filed
under, so a multi-version catch-up is witnessable rather than counted as two
authorities.

A chain walk has a public step. `verify_witness_step` takes the earlier
records' pending updates as `prior_pending_updates`, derives this record's own
from the bytes it authenticates, evaluates the two together, and returns the
derived list beside the evidence in a public `WitnessStep`, so a walker carries
a record's updates forward from the verification rather than from a read of its
own. The supplied-versus-derived comparison runs both ways now, so an update
entry the one read did not derive is refused and named. `verify_witness` keeps
0.5.1's signature, and `TokenEvidence` keeps 0.5.1's fields in 0.5.1's order.

A cached preflight runs `openssl version` before any trust bundle is read and
refuses anything but OpenSSL 3.0 or newer, naming the banner it found. And
`_decode_oid` decodes a policy OID's first subidentifier in full base-128
instead of reading its combined first two arcs from a single octet — recorded
as a corrected baseline defect rather than a stricter rule.

The offline suite gained real RFC 3161 coverage where it had none:
`tests/test_tsa.py` goes from 8 test functions to 121 — 159 collected cases —
driving `verify_witness` and `verify_timestamp_token` end to end over genuine
`openssl ts -reply` responses from the two local authorities the corpus fixture
already generates.

### The corpus closed world (#39)

Every name in a corpus is a portable name. Five filesystem models are replaced
by one repertoire rule — ASCII letters, digits, `.`, `_` and `-`, not ending in
a period and not a Win32 reserved device basename — asked by a single screen
that refuses with one message. The policy is priced rather than asserted: a
census over thirty-seven distinct `rulespec-*` repositories at their
`origin/main` heads on 2026-09-03 found thirty-six carrying no tracked path
outside that repertoire, and `rulespec-us` at d58cc0c carrying 33 of 15,216
that do. Those corpora refuse verification until the names are respelled, and a
consumer needing more widens `PORTABLE_NAME_RE` in this module and takes the
modelling back — the repertoire is the module's, not a field on `CorpusSpec`.

Suffix matching was case-sensitive while path names were case-folded, so a file
could be invisible to the sweep and present in the tree at once. The journal
classifier and the tree sweep share one case-folding suffix predicate now, and
content-root membership is decided by component-wise fold keys, so what kind a
path is does not depend on the host. Every swept entry is judged from a single
`lstat`, so a Windows junction is not descended as an ordinary directory, and
every listing compares entry names pairwise on the fold key so two entries a
case-insensitive volume would merge refuse before either is classified. Every
component of every bound attested path must appear in a listing of its parent
under exactly the declared spelling.

Every walk and every parse in this module has a ceiling, charged as work
arrives rather than after it is done. One residual is stated rather than fixed:
`release_chain.jsonl_line_offsets` splits the same journal in the custody pass
that runs first, with none of these bounds — that module is pinned byte for
byte by a differential harness, so bounding it is its own change against its
own harness. The spelling walk and the closed-world sweep each take a per-entry
budget charged one entry at a time. Journal parsing gains size and cardinality
budgets enforced before the work they bound: a row count taken by counting line
feeds before any row is parsed, a per-row byte cap, a per-gate evidence-entry
cap, and a stated 64 MiB total checked on the raw payload before anything else
looks at it (0.5.1 bounded none of this). The
gate and removed-path budgets charge the exact JSON structure each item renders
to, and the rendering bound moved into a new `src/receipt/_render.py`,
importing the standard library alone, so the corpus module charges the same
string the CLI prints. The journal row cap is a consumer pin, defaulted, validated at construction
against a derived ceiling.

A tombstoned attested path could remain on disk while `removedPaths` asserted
its removal. The absence pass is one function called twice — once before the
hashing and once after the final identity re-check over a fresh index — so a
removed path that reappears during verification refuses instead of being
reported as removed. Each pass indexes with `os.scandir` inside a `with` block,
charging each name as it arrives and reading each directory it touches once —
once per pass, not once per verification, because the second pass exists
precisely so that nothing the first concluded from a cached listing goes
unrechecked — under one running entry budget carried across both.

Verdict emission is restricted to a named codec allow-list: the module writes
UTF-8 alone, and where it falls back to ASCII the stream's codec must be one of
61 named single-byte code pages, everything else refusing through the render
boundary. Every value a refusal quotes goes through the quoting helper (72 call
sites in the shipped module, counted by AST), the trusted verdict line prints
last so attacker-derived detail cannot scroll it away, and a partial write is
repeated at both layers until the payload is gone rather than discarded.

Bound-file hashing reads exactly the size captured at `fstat`, refusing a file
that shrank or grew while being read rather than hashing to a live EOF a writer
controls. A generation recorder is built before anything reads the tree and
carried into every directory read the run makes, its stamps re-stated forwards
and then backwards, so a change is caught if it lands before that directory's
final re-read. And `verify_corpus_binding` refuses at entry on any non-POSIX
platform, because the generation stamps rest on `st_ctime` meaning the inode
change time, which Windows CPython does not report.

### Append-gate confinement (#38)

A gate-only proposal that also rewrote an unclassified file returned OK with no
immutability check. The surface classification returns the unclassified remainder now: on the
gate-only exit an unclassified change on the release surface is refused and any
other unclassified path is named in the success text, so nothing rides along
silently; a proposal that touches the data surface runs every immutability
check instead. The release root's proper ancestors are on the release surface
— with a root of `data/releases`, replacing `data` decides whether there is a
release root at all — and the index's own changed set is classified beside the
working tree's, the union deciding, so a rewrite staged into the commit under
review cannot ride a verdict the working-tree diff could not see.

Ignored files were dropped from the untracked half of the changed set by
`--exclude-standard`, so a gate change carrying its own ignore rule could add a
second ledger and still be told the data surface was unchanged. They are
enumerated beside the untracked listing now and folded into the same changed
set, restricted to the surfaces the verdict speaks for — the two the spec names
and the release root — because everywhere else an ignored file is in no commit
and proposed by nothing.

A listing that exits 0 is not thereby a complete one: `git ls-files --others`
exits 0 while warning that it could not open a directory and omitting that
subtree. `assert_protected_surfaces_enumerable` walks every protected surface
itself with `os.scandir` before any listing is believed, descending no symlink,
bounded by `MAX_SURFACE_WALK_ENTRIES`, charged inside the scandir iteration
before each name is kept, and refusing on the first `OSError` a listing raises
other than `ENOENT` or `ENOTDIR` — absence is not a withheld listing, and a
checkout with no release root yet passes for that reason. Beside it, the stderr
of the four classification reads is attributed rather than discarded, so a git
warning naming a protected path refuses while one outside every protected
surface is left alone.

Every surface match is by exact spelling, which is what makes it a comparison
and what makes it blind to a second spelling of the same path on a filesystem
that folds names. `release_chain.assert_index_carries_no_protected_alias` reads
the whole index once, with no pathspec, and refuses any entry fold-equal to a
protected path or lying under a fold-equal prefix of one that is not spelled
identically — and it takes the caller's configured surfaces now, deriving its
protected set the way the surface enumeration derives its directories, so an
entry spelled `Scripts/check_append.py` under a `scripts/**` gate pattern no
longer classifies as merely unclassified.

A guard that read four caching settings and believed them — added and removed
inside #38's own branch, so no release ever shipped it — is gone, and
`release_chain.WORKING_TREE_SCAN_OPTIONS` spells five settings out (those four
and `feature.manyFiles`) on the command line of every git read the verifier and the gate make, with one deliberate
exception in the helper that asks git what a setting *is*. (`receipt.attest`
runs its own git commands without them; it reads commit history rather than a
working tree.) The options change no verdict about any tree. A read that refreshes the index
— `git diff` against a base does, when its cached stat data has gone stale —
rewrites it under `core.untrackedCache=false` and drops an untracked-cache
extension it finds there; the refresh changes no entry's stage, mode, object
id or flag word, which is all the reads compare.

Each state file is read once, through a component walk, an `lstat`, an
`O_NOFOLLOW|O_NONBLOCK` open, an `fstat` required to be the same regular file,
and one read through that descriptor — and those bytes feed every consumer
rather than each re-opening the path. `assert_state_path_tracked` requires each
state path to be exactly one stage-0 entry at 100644 or 100755 recording
content, refusing an indexed ancestor at any mode along with absent, 120000,
160000, unmerged and intent-to-add entries. `assert_index_content_bound` binds
the blob the index records for a protected path to either the base tree's blob
or the blob id of the bytes just verified. The release root is walked component
by component and then held, and that confinement walk runs at the top of
`verify_release_chain` itself, so `receipt verify`'s custody pass carries it
too rather than it being the gate's alone. Every directory above a protected
path must be listable by the verifier — a listing is the only thing that binds
the spelling of what a directory holds — and because these reads open through
directory descriptors, receipt states a POSIX-platform requirement in
`README.md`, in both module docstrings and in the refusal text, and refuses on
Windows rather than reading state through a weaker path. Post-cutover binding
values are shape-checked rather than merely present.

### Spec validation and the verdict boundary (#41)

`producer_spki_sha256 = None` passed straight to the signing module, which
reads `None` as "no pin requested" and skips the comparison, so a chain
re-signed under a substituted key passed custody and the command failed only
downstream, slicing a prefix off `None` — the wrong reason, not a live false
PASS at the command level. An empty `anchors` mapping
was the same hole from the other side: the receipt-set equality passed
vacuously, no witness was verified, and the verdict read "the 0 pinned RFC 3161
authorities ()". `ChainSpec` and `AnchorSpec` validate at construction now —
every pin 64 lowercase hex, `policy_oid` dotted decimal, `anchors` a non-empty
mapping of non-empty names to `AnchorSpec`, every relative path a
`PurePosixPath` with at least one component, not absolute, with no `..`. A spec
that pins nothing is a configuration error, not a policy.

A spec that raised `SystemExit` exited the interpreter with its own status and
printed no verdict, because every boundary in `verify` and `cli` caught
`Exception` and `SystemExit` is not one. The boundaries catch `BaseException`
and re-raise only `KeyboardInterrupt`; a non-`Exception` raise is quoted with
its type. Two boundaries #41 did not reach — the two in `cli._refuse` that
print a refusal — still caught `Exception`, so a spec that left `sys.stderr` or
`sys.stdout` holding an object whose `encoding` raises `SystemExit(0)` made a
refusal exit 0 with nothing printed; this release closes those two the same
way (found in the release PR's peer review). `asyncio.CancelledError` is converted too — this library is
synchronous, so the only way it arrives is a spec raising it explicitly, which
is the same trick under another name.

The three OpenSSL invocations reopened the receipt path by name, so nothing
held the file still between the `-text` inspection, the `-verify` and the token
extraction, and the tree under audit could present one token for its genTime
and policy and another for verification. `_receipt_bytes` reads each receipt
once through one descriptor — `O_NOFOLLOW` where the platform has it, then
`fstat` compared against the preceding `lstat` by device and inode — and every
call is fed a private snapshot. A receipt that exists but cannot be opened
refuses as `cannot read RFC 3161 receipt … PermissionError` before OpenSSL is
invoked, where it used to surface OpenSSL's own `Permission denied`.

Smaller, in the same PR: a non-zero digit past the sixth fractional place of a
genTime refuses rather than being rounded down and reasoned from, while zeros
past the sixth name the same instant and are accepted; witness times render
microseconds whenever the token carries them. `--base-ref` reports the resolved
commit rather than the caller's spelling — `VerifyResult.base_commit`, the
history detail's `at <ref> (<oid>)`, and `history.baseCommit` in JSON.
`VerifyResult.ok` requires all of `REQUIRED_PASSES = ("custody", "binding",
"declaration")` to have completed rather than passing vacuously over an empty
list; no path through `run_verification` produced such a result, so this
hardens the public dataclass for library callers rather than closing a live
false PASS. A spec path's final component is checked for a symlink as supplied,
before `resolve()` has already followed every link. The custody detail quotes
the full head manifest digest beside the filename, because the digest is what
an auditor compares out of band. And the two `subprocess.check_output` calls in
the append gate capture stderr and fold the bounded diagnostic into the
refusal, so the library no longer writes over its caller's output while
refusing without a reason.

### Also in this release

`pyproject.toml` sets `pythonpath = ["src"]` under `[tool.pytest.ini_options]`
(#42). A shared venv holds one editable pointer, which `uv run` rewrites to
whichever project directory ran last, so `import receipt` under pytest resolved
through that pointer and a suite started from one worktree could be importing
another worktree's source — a green run proving less than it appeared to.
Pytest prepends the rootdir's own `src` before collection now. CI is
unaffected; a fresh venv per job has nothing else to resolve to.

`append_gate.verify_append_gate` refuses a candidate root that is not there
(#46). `_set_root` recorded the root's identity with an unguarded open, so a
`--root` naming nothing, or naming a regular file, or reached through one, or
spelled through a symlink loop, escaped as the OS's own `FileNotFoundError` or `NotADirectoryError` for the
first three shapes, and for a loop as a bare `OSError` (`ELOOP`) or, on CPython
3.11 and 3.12, as `pathlib`'s own `RuntimeError` from `resolve` — carrying the
OS's message rather than the root, where every other refusal in the module is
an `AppendError` naming what it refused. `receipt verify` never reaches this
code (its own `--root` check refuses a non-directory earlier, in its own words),
and the consumer command that does reach it, Chronicle's append-check script,
catches `AppendError` alone, so the bare exception escaped that boundary and
ended the run non-zero with a traceback: nothing was ever accepted that should
not have been, and a library caller got an exception from outside the module's
vocabulary. All four refuse as `candidate root is missing or not a directory:
<root>` now — the words state what was tested, and no more — from the open
itself for the first three, rather than from a check placed ahead of it, and at
the resolve for a loop where `pathlib` reports it there, before any git command
is run. The vocabulary holds for the gate alone: `verify_release_chain`,
`verify_release_history_immutable` and `run_verification` still resolve their
root outside a boundary, so a root spelled through a loop raises there as it
did in 0.5.1; `receipt verify` refuses it first, in its own words.

Both verifier entries refuse a git environment that would redirect their reads
(#45, the part that is a check rather than a redesign). `GIT_DIR`,
`GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY` and
`GIT_ALTERNATE_OBJECT_DIRECTORIES` can each decide which repository, working
tree, index or object store some git read this package makes — the base resolution, an index
read, the release-root scan, the intent-to-add detection — resolves in, rather
than the checkout named as `root`, while the verdict still speaks of the
checkout named. `verify_release_chain` refuses before it resolves the root it
was given; `run_verification` asks before its optional history pass, so
`receipt verify --base-ref` refuses before any base is resolved, and
`verify_release_history_immutable` asks at its own entry; `verify_append_gate`
refuses ahead of its platform, spec and root checks; all saying `{NAME} is set in the
environment and would redirect git reads; unset it`; `receipt verify`'s custody
pass answers the same way. They are refused rather than dropped for the child
processes: a drop would leave the verifier's own environment redirected while
its children's was not, and both modules read the candidate tree directly as
well as through git, so the two halves of one verdict would then be about two
trees. Pinning `GIT_DIR` to `<root>/.git` for every read — stating a command's
target rather than merely not overriding it — is 0.6 work, and so is asking it
of every helper rather than of the public entries: a caller reaching another
`release_chain` helper directly is still unguarded, and so is `receipt.attest`,
which runs its own git commands under the ambient environment and is neither
guarded nor claimed to be. One
consequence is stated rather than hidden: git sets some of these variables in
its own hook environments (measured on git 2.53.0: `pre-commit`,
`prepare-commit-msg`, `commit-msg` and `post-commit` run with
`GIT_INDEX_FILE`; a server-side `pre-receive` with `GIT_DIR`,
`GIT_OBJECT_DIRECTORY` and `GIT_ALTERNATE_OBJECT_DIRECTORIES`; `pre-push` and
`post-checkout` with none of the five), so a consumer that had wired either
entry into one of the former is refused there; the invocation both are written
for is a CI job over a checkout. `README.md` names the five variables beside the rest of the
requirements.

### What a 0.5.x verdict speaks for

The subject of every check in this release is the working tree as the run read
it, and the working tree is not the commit. A 0.5.x PASS speaks for a clean
checkout of one commit, read once, with no concurrent writer. Bytes are read
once — the two state files through directory descriptors, everything else
(manifests, signatures, RFC 3161 receipts, anchors, the corpus's content files)
by whole pathname, each once and each `fstat`ed against what was opened — and
the gate re-reads the state files and the release root at its end, which
establishes that a path held those bytes at the reads the run made; a commit's content is
bound per protected path where the index differs from the base, with no
coherent-tree guarantee across correlated files; and every descriptor held is a
comparison at two instants rather than a confinement of the reads between them,
so a directory swapped after a walk and swapped back before the closing check
is not seen. The append gate's push path binds no commit at all, because with
no base ref there is none to bind: what that path verifies is the tree in front
of it. The corpus sweep says the same thing in its own terms: its closing
passes narrow the window in which a change goes unseen but cannot close it, and
the span after each directory's last re-read remains.

Closing that means verifying the committed tree object rather than the working
tree — the append gate's state files read out of the commit under review, the
corpus's content roots and attested files read out of its tree object — which
changes what these verdicts are about rather than adding a check to them. That
is 0.6, tracked as #43 for the gate and #44 for the corpus.

### Closes #32

Closed by #40 (TSA witness lane), #39 (corpus closed world), #38 (append-gate
confinement) and #41 (spec validation and the verdict boundary), with #42, #46
and the checkable half of #45 landing in this release PR.

The mutable-working-tree class is closed to 0.5.x work. A new finding in it — a
window between a read and the verdict, a writer active during a run, a state
file or content root that can change after the check that read it — goes to #43
or #44 rather than becoming another check on a tree that can still be written
to while the answer is being formed.

## 0.5.1

Released 2026-08-17. See the [v0.5.1
tag](https://github.com/TheAxiomFoundation/receipt/releases/tag/v0.5.1): the
verdict names the anchor set custody consumed, closing #24.

Earlier releases are recorded on their tags; this file begins at 0.5.1.
