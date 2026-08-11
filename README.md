# receipt

Verifiable custody of agent-produced records.

## Status

Shipped so far: the release-chain verifier, the append gate, ECMAScript-compatible canonical JSON, standalone Ed25519 signing with consumer-pinned threshold keyrings, RFC 3161 dual-witness verification, and workflow-provenance verification. The machinery arrives by extraction from three production systems that each built it independently (pre-registered forecast records, an observation-ledger release chain, a signed statute corpus). Where the source system has a verifier, extraction runs behind a differential gate: the extracted verifier must reproduce the source verifier's verdict, pass and fail alike, on the live production chain at a pinned commit before any system consumes the package. Where it has an incident to teach instead, the semantics arrive as a reviewed adaptation — the signing module's legacy-key generations come from the statute corpus's key-rotation incident. The gates have held end to end — the observation ledger consumes the package in production, with the differential harnesses re-proving equivalence on every package change; the `receipts/` directory carries the port diffs, pinned source hashes, and review records.

## What it provides, and what is still arriving

Shipped:

- `receipt.release_chain` — append-only hash-chained manifests over record sets: enumerated genesis, content-addressed links, immutable-prefix verification
- `receipt.tsa` — RFC 3161 dual-witness verification against consumer-committed trust bundles and signer identities, with explicit unavailable-witness outcomes
- `receipt.sign` — Ed25519 producer signatures verified against fingerprints pinned in the consumer's own committed code (shipped: ported ledger primitives, sign-side helpers, N-of-M keyrings with legacy verification generations — retired keys verify immutable history only; rotation by reviewed spec change)
- `receipt.attest` — workflow-provenance verification with self-anchoring enforcement epochs and a full-history sweep over every protected-tree commit
- `receipt.canonical` — one byte stream per value: canonical JSON with UTF-16 code-unit key order and ECMAScript number formatting
- `receipt.append_gate` — a candidate change to an append-only ledger must extend the trusted base exactly: prefix retained, rows valid, releases untouched

Arriving:

- `receipt.ratchet` — shrink-only exception registries recomputed from live state; an excused failure that starts passing is an error until removed
- `receipt.chronology` — record-vs-event ordering tiers: does witnessed time prove the record existed *ante quem* — before the event it predicts or observes?
- `receipt verify` — the outside auditor's command: a clone, commodity tools, one offline fail-closed verdict (under review for the 0.5.0 release)

## Design principle

Trust anchors live in the consumer's committed code, never in runtime configuration a producer could swap. The package ships machinery; consumers pin roots.

## The name

Software already uses the word in exactly this sense: an app-store receipt is a signed proof validated offline, without trusting the store that issued it. This package writes receipts for agent-produced records; `receipt verify` is what happens when someone asks to see them.

Releases through 0.1.2 shipped as `vidimus`; those remain on PyPI under the old name.

## License

Apache-2.0.
