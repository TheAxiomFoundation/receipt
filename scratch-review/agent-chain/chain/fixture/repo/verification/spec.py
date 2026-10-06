"""Committed trust anchors for the receipt test corpus."""

import pathlib
import re

from receipt.corpus import CorpusSpec
from receipt.release_chain import AnchorSpec, ChainSpec
from receipt.verify import VerificationSpec

CHAIN = ChainSpec(
    manifest_relative=pathlib.PurePosixPath('releases/manifests'),
    state_relative=pathlib.PurePosixPath('receipt/corpus-journal.jsonl'),
    prefix_relative=pathlib.PurePosixPath('receipt/immutable-prefix.json'),
    anchor_relative=pathlib.PurePosixPath('releases/anchors'),
    release_root_relative=pathlib.PurePosixPath("releases"),
    schema_version='receipt_test_corpus_release_v1',
    producer_public_key_filename="producer-ed25519.pub",
    producer_spki_sha256='0e3b3d74d15750f1e437524135238a3ffe1f1b7c03a2c6dc9f4b5c523d861fb4',
    anchors={
        'alpha': AnchorSpec(
            filename='alpha-root.pem',
            pem_sha256='b51e31bc6dc778e0e043eacb3e475c0aa91b311423a3432a986fb89af087338c',
            policy_oid='1.3.6.1.4.1.99999.1.1',
            signer_certificate_sha256='bfaaad0eb9ac4ae57434237ea8ae24e6880a18b55eca9b527b60778a7f848d81',
            signer_spki_sha256='030d8bc5431c89846b9d8b11c79a462a909b1b7164324daecfda046a032e5dd7',
        ),
        'beta': AnchorSpec(
            filename='beta-root.pem',
            pem_sha256='e9a42518db0f140b61bceacb9c00fcc5d3ed1ee8e49a259058d7b96902b63f1a',
            policy_oid='1.3.6.1.4.1.99999.2.1',
            signer_certificate_sha256='6361278099f8be332b57b36db4721b84116a3f28741dfb4648175c02abef5ba6',
            signer_spki_sha256='c317c7ebf4a9cc196a30171dafed4053b977ef9db833574123c2e713fa5bbfa4',
        )
    },
)

CORPUS = CorpusSpec(
    schema_version='receipt/test-corpus-journal/v1',
    content_roots=(pathlib.PurePosixPath("rules"),),
    content_suffixes=(".yaml",),
    required_attested_paths=frozenset({".axiom/toolchain.toml"}),
    accepted_gate_tiers=frozenset({"public", "restricted", "ci-attested"}),
    required_gates=frozenset({"rulespec/compile"}),
)

SPEC = VerificationSpec(
    name="receipt test corpus",
    chain=CHAIN,
    corpus=CORPUS,
)
