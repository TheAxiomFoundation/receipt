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
- `receipt.corpus` — closed-world binding of a witnessed journal to a working tree: every content file bound, every bound file present, every digest exact, and per-gate reproducibility tiers so a declaration is never mistaken for a verification
- `receipt verify` — the outside auditor's command: a clone, commodity tools, one offline fail-closed verdict

Arriving:

- `receipt.ratchet` — shrink-only exception registries recomputed from live state; an excused failure that starts passing is an error until removed
- `receipt.chronology` — record-vs-event ordering tiers: does witnessed time prove the record existed *ante quem* — before the event it predicts or observes?

`receipt.corpus` and `receipt verify` are composition over the extracted modules rather than a fourth extraction: they add no cryptography and no trust anchors, and every cryptographic verdict they report comes from a module that passed its own differential gate. Their gate is a refusal battery — each way a published corpus can fail to be what it claims, exercised against a real chain with real signatures and configured RFC 3161 authorities.

## Using it

```bash
receipt verify --spec path/to/your/spec.py
```

`TheAxiomFoundation/rulespec-nz` is the reference consumer: its `verification/spec.py` is the whole trust configuration, and its `VERIFY.md` is the third-party procedure. The command needs no network, no credentials, and no cooperation from the producer — `openssl`, `git`, and Python are the only dependencies.

## Install

Requires Python 3.11+, `git`, and OpenSSL 3.0 or newer as `openssl` on the path: verifying an RFC 3161 token passes `-no-CAstore`, which older releases do not have, and counting a pinned root's certificates uses `storeutl`, which LibreSSL — the stock `/usr/bin/openssl` on macOS — has at no version. `receipt.tsa` checks the version once per process and refuses a build below the floor by name, before it reads a trust bundle; elsewhere in the package an unusable `openssl` surfaces wherever OpenSSL itself fails. Install OpenSSL (for example `brew install openssl`) and put its `openssl` first on the path. The corpus sweep's change detection requires POSIX change-time semantics; on Windows it refuses to verify rather than trusting a stamp a writer can restore. Corpus paths are portable names: ASCII letters, digits, '.', '_' and '-', not ending in a dot and not a Win32 device name; anything else refuses verification. receipt requires a POSIX platform: its state reads open through directory descriptors (`os.open` with `dir_fd`, which every POSIX platform CPython supports and Windows does not), so on Windows `receipt verify` and the append gate refuse rather than reading state through a weaker path. Every directory above a protected path — the state files, the release root, and the paths configured under it — must also be listable by the verifier: a directory's listing is the only thing that binds the spelling of what it holds, so one that cannot be listed is refused rather than descended, even where it can be traversed. The append gate asks the same of every directory *under* a protected surface whenever it classifies a proposal against a base ref, for the neighbouring reason: `git ls-files` exits 0 while warning that it could not open a directory and omitting that subtree, so a surface the verifier cannot enumerate for itself is a proposal it refuses to classify rather than one it reports as unchanged; that enumeration is bounded, and the bound is charged as each listing is read rather than after a directory has been listed whole, so a directory wider than the bound costs one entry past it and not all of them. The surface a gate-only proposal is confined to includes every directory *above* the release root as well as the root and everything under it: with a release root of `data/releases`, replacing `data` decides whether there is a release root at all, so a change there is a change on the release surface rather than an unclassified one, and the root's components are walked before that verdict is returned. Both halves of that confinement — no symlinked component, every component spelled by the directory that holds it — are checked by `receipt verify` itself, at the top of its custody pass, and not only by the append gate: a release tree reached through a link, or read out of a leaf spelled some other way, is refused before any manifest is enumerated. And the gate reads the whole index once at entry for an entry spelled as another spelling of any path it protects — the release root, the two state files, the manifest and anchor directories, and every path the consumer's own gate and data surface patterns name — because a checkout that folds names materialises both spellings onto one file while every check here compares by exact spelling. Five environment variables make the verifier decline to answer at all: `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY` and `GIT_ALTERNATE_OBJECT_DIRECTORIES` can each decide which repository, index or object store some git read resolves in, so `receipt verify` (every pass, the `--base-ref` history pass included) and the append gate refuse when one is set in their own environment rather than answering about a tree they were not asked about. git sets these variables in its own hook environments, so neither entry can run inside a git hook; the invocation they are written for is a CI job over a checkout.

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
