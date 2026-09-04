# Changelog

Every entry says what changed and what an auditor can conclude from it that
they could not before. Refusals are named as refusals: a check added here is an
input the package used to accept, or accept for the wrong reason.

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
looks at it — replacing the eight-gibibyte product of two other constants. The
gate and removed-path budgets charge the exact JSON structure each item renders
to, and the rendering bound moved into a new `src/receipt/_render.py`,
importing the standard library alone, so the corpus module charges the same
string the CLI prints. The journal row cap became a consumer pin defaulting to
the old value and validated at construction against a derived ceiling.

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
immutability check. The surface classification returns the unclassified
remainder now: an unclassified change on the release surface is refused, and
any other unclassified path is named in the success text, so nothing rides
along silently. The release root's proper ancestors are on the release surface
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

The guard that read five caching settings and believed them is deleted, and
`release_chain.WORKING_TREE_SCAN_OPTIONS` spells all five out on the command
line of every git read the verifier and the gate make, with one deliberate
exception in the helper that asks git what a setting *is*. (`receipt.attest`
runs its own git commands without them; it reads commit history rather than a
working tree.) The options change no verdict about any tree, and an
untracked-cache extension already in the index is left byte-identical.

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
re-signed under a substituted key passed custody. An empty `anchors` mapping
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
its type. `asyncio.CancelledError` is converted too — this library is
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
`--root` naming nothing, or naming a regular file, or reached through one,
escaped as the OS's own `FileNotFoundError` or `NotADirectoryError` — carrying
the OS's message rather than the root, where every other refusal in the module
is an `AppendError` naming what it refused. The CLI's fail-closed boundary
caught it and reported a FAIL, so nothing was ever accepted that should not
have been; a library caller got an exception from outside the module's
vocabulary. Both refuse as `candidate root is missing or not a directory: <root>` now —
the words state what the open tested, and no more — from the open itself rather than from a check placed
ahead of it, before any git command is run.

Both verifier entries refuse a git environment that would redirect their reads
(#45, the part that is a check rather than a redesign). `GIT_DIR`,
`GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY` and
`GIT_ALTERNATE_OBJECT_DIRECTORIES` each send every git read this package makes
— the base resolution, the index reads, the release-root scan, the
intent-to-add detection — to another repository, index or object store than the
checkout named as `root`, from that checkout's own working directory, while the
verdict still speaks of the checkout named. `verify_release_chain` refuses
before it resolves the root it was given, and `verify_append_gate` refuses
ahead of its platform, spec and root checks, both saying `{NAME} is set in the
environment and would redirect git reads; unset it`; `receipt verify`'s custody
pass answers the same way. They are refused rather than dropped for the child
processes: a drop would leave the verifier's own environment redirected while
its children's was not, and both modules read the candidate tree directly as
well as through git, so the two halves of one verdict would then be about two
trees. Pinning `GIT_DIR` to `<root>/.git` for every read — stating a command's
target rather than merely not overriding it — is 0.6 work, and so is asking it
of every helper rather than of the two public entries: a caller reaching a
`release_chain` helper directly is still unguarded. `README.md` names the five
variables beside the rest of the requirements.

### What a 0.5.x verdict speaks for

The subject of every check in this release is the working tree as the run read
it, and the working tree is not the commit. A 0.5.x PASS speaks for a clean
checkout of one commit, read once, with no concurrent writer. Bytes are read
once through directory descriptors and re-read at the end, which establishes
that a path held those bytes at the reads the run made; a commit's content is
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
