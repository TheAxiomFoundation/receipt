"""Verifiable custody of agent-produced records.

Shipped: the append-only release-chain verifier (receipt.release_chain),
ECMAScript-compatible canonical JSON (receipt.canonical), the append-only gate
(receipt.append_gate), standalone Ed25519 signing plus consumer-pinned threshold
keyrings (receipt.sign), RFC 3161 dual-witness verification (receipt.tsa), and
workflow-provenance verification (receipt.attest). The ledger machinery was
extracted from PolicyEngine/ledger at commit 0798427850, and the TSA and
attestation machinery from MaxGhenis/brier at commit 4b9e7be22de, behind
differential harnesses that run the unmodified upstream as an oracle and prove
byte-identical verdicts. Trust anchors are supplied by the consumer's committed
code via ChainSpec, AppendGateSpec, ProducerKeySpec, KeyringSpec, TsaSpec,
AttestSpec, or CorpusSpec; the package ships no defaults.

Also shipped: closed-world corpus binding (receipt.corpus) and the spanning
verification command (receipt.verify, `receipt verify`). These are new
composition over the extracted modules rather than a fourth extraction — they
add no cryptography and no trust anchors of their own, and the cryptographic
verdicts they report are produced entirely by the differentially gated modules
above. Their own gate is the refusal battery in tests/test_corpus.py and
tests/test_cli.py.

Pending extraction: waiver ratchet and chronology tiers.
"""

__version__ = "0.5.1"
