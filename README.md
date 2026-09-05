# receipt

Verifiable custody of agent-produced records.

## Status

Shipped so far: the release-chain verifier, the append gate, ECMAScript-compatible canonical JSON, standalone Ed25519 signing with consumer-pinned threshold keyrings, RFC 3161 dual-witness verification, workflow-provenance verification, closed-world corpus binding, and the spanning `receipt verify` command. The machinery arrives by extraction from three production systems that each built it independently (a signed statute corpus, pre-registered forecast records, an observation-ledger release chain). Where the source system has a verifier, extraction runs behind a differential gate: the extracted verifier must reproduce the source verifier's verdict, pass and fail alike, on the live production chain at a pinned commit before any system consumes the package. Where it has an incident to teach instead, the semantics arrive as a reviewed adaptation — the signing module's legacy-key generations come from the statute corpus's key-rotation incident. The gates have held end to end — the observation ledger consumes the package in production, with the differential harnesses re-proving equivalence on every package change; the `receipts/` directory carries the port diffs, pinned source hashes, and review records.

## What it provides, and what is still arriving

Shipped:

- `receipt.release_chain` — append-only hash-chained manifests over record sets: enumerated genesis, content-addressed links, immutable-prefix verification
- `receipt.tsa` — RFC 3161 dual-witness verification against consumer-committed trust bundles and signer identities, with explicit unavailable-witness outcomes
- `receipt.sign` — Ed25519 producer signatures verified against fingerprints pinned in the consumer's own committed code (shipped: ported ledger primitives, sign-side helpers, N-of-M keyrings with legacy verification generations — retired keys verify immutable history only; rotation by reviewed spec change)
- `receipt.attest` — workflow-provenance verification with self-anchoring enforcement epochs and a full-history sweep over every protected-tree commit
- `receipt.canonical` — one byte stream per value: canonical JSON with UTF-16 code-unit key order and ECMAScript number formatting
- `receipt.append_gate` — a candidate change to an append-only ledger must extend the trusted base exactly: prefix retained, rows valid, releases untouched
- `receipt.corpus` — closed-world binding of a witnessed journal to a committed tree object: every content file bound, every bound file present, every digest exact, and per-gate reproducibility tiers so a declaration is never mistaken for a verification
- `receipt verify` — the outside auditor's command: a clone, commodity tools, one offline fail-closed verdict

Arriving:

- `receipt.ratchet` — shrink-only exception registries recomputed from live state; an excused failure that starts passing is an error until removed
- `receipt.chronology` — record-vs-event ordering tiers: does witnessed time prove the record existed *ante quem* — before the event it predicts or observes?

`receipt.corpus` and `receipt verify` are composition over the extracted modules rather than a fourth extraction: they add no cryptography and no trust anchors, and every cryptographic verdict they report comes from a module that passed its own differential gate. Their gate is a refusal battery — each way a published corpus can fail to be what it claims, exercised against a real chain with real signatures and configured RFC 3161 authorities.

## Using it

```bash
receipt verify --spec path/to/spec.py --commit HEAD
```

The command selects a commit and prints its full commit and tree OIDs. The
binding pass compares the witnessed journal with that tree's raw blob bytes;
changes to the working tree or index do not change the selected subject.
`--root` names the repository's top level. A history comparison also needs the
base commit in that repository: `--base-ref REF` requires `--expect-commit OID`.

The auditor's out-of-band pins are `--expect-spec-sha256`, `--expect-commit`,
`--expect-tree`, and `--expect-anchor-set`. The spec digest is checked before
its Python code executes. An explicit anchor-set pin requires the spec pin;
under a pinned spec, `VerificationSpec.anchor_set_sha256` can supply the
anchor-set pin instead. The anchor bytes are compared before custody
verification invokes OpenSSL. Without an effective anchor pin, the claim is
"custody under the anchor set {digest} the verified tree carries"; without a
spec pin, the verdict also does not establish that the spec's code was trusted.
The command performs verification offline; its trust configuration is
executable Python supplied by the caller.

## What this verdict speaks for

A PASS establishes custody under the reported anchor set and binding of the
witnessed journal to the named tree. An optional history pass establishes that
every release object at the supplied base remains byte- and mode-identical.
The verdict does not establish:

- that any declared gate actually passed;
- that the encoded rules are a correct reading of the law;
- that this clone holds the producer's newest release (`--base-ref` only bounds
  staleness against a head the auditor recorded; newest needs an out-of-band
  comparison);
- that this is the only history the producer maintains (equivocation is
  undetectable from a single clone; compare head digests out of band);
- that the files in any checkout equal the verified tree.

Without an effective anchor pin, it also does not establish that the anchor
set is one the auditor trusts. The direct `verify_release_chain` API speaks
for a directory as this process read it once; its caller carries the
concurrent-writer residual. Commit-addressed callers use `run_verification`
or `verify_append_gate`.

## Install

Requires Python 3.11+, git 2.36.0 or later, and OpenSSL 3.0 or later as
`openssl` on the path. The reader uses `git cat-file --batch-command`;
`--verify-objects` additionally requires git 2.50.0 or later and a build
reporting `SHA1_DC`. That option runs bounded whole-store `fsck` and reports
its measurements; ordinary verification rehashes the objects it reads with
plain SHA-1. SHA-256 repositories and bare repositories are refused.

receipt requires a POSIX platform. Its guarded regular-file reader requires
`os.O_NOFOLLOW`, including when reading a private materialization or the append
gate's caller-owned trust directory. OpenSSL's RFC 3161 verification uses
`-no-CAstore`, and pinned-root certificate counting uses `storeutl`; the
preflight refuses LibreSSL and OpenSSL below 3.0. Install OpenSSL (for example
`brew install openssl`) and put its `openssl` first on the path.

Use a repository containing the candidate and, when supplied, the base commit.
Shallow clones cannot verify a base outside their boundary; this release
refuses every shallow repository with `shallow repositories are unsupported`,
including one whose requested commits are present. Use `fetch-depth: 0` in
GitHub Actions. LFS-tracked content roots are unsupported: verification reads
the pointer blob, whose digest will not match a journal digest of the expanded
content. Protected paths with transforming `filter`, `ident`, or
`working-tree-encoding` attributes refuse; `text` and `eol` are accepted, and
checkout fidelity is outside the verdict.

`ChainSpec.name_repertoire` and `CorpusSpec.name_repertoire` default to
`portable`: ASCII letters, digits, `.`, `_`, and `-`, no trailing period or
Win32 device basename. A spec may declare `posix-bytes` for exact-byte names
outside the materialized paths; names quoted or folded must still be valid
UTF-8, and ASCII-fold-equal siblings refuse under both repertoires. Both spec
fields must agree. Private materialization always requires portable names,
even under `posix-bytes`, so that declaration can widen content names but cannot
widen materialized release, state, manifest, or anchor names.

The public `receipt verify` and append-gate entries retain their refusal when
`GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY`, or
`GIT_ALTERNATE_OBJECT_DIRECTORIES` is set. The object reader separately freezes
its Git environment and explicitly selects the repository for its reads.

```bash
uv pip install receipt
```

Or with pip:

```bash
pip install receipt
```

From a clone, for development:

```bash
uv venv && uv pip install -e ".[dev]"
uv run pytest
```

## Design principle

Trust anchors live in the consumer's committed code, never in runtime configuration a producer could swap. The package ships machinery; consumers pin roots.

## The name

Software already uses the word in exactly this sense: an app-store receipt is a signed proof validated offline, without trusting the store that issued it. This package writes receipts for agent-produced records; `receipt verify` is what happens when someone asks to see them.

Releases through 0.1.2 shipped as `vidimus`; those remain on PyPI under the old name.

## License

Apache-2.0.
