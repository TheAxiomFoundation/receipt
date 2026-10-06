
import pathlib
from receipt.corpus import CorpusSpec
from receipt.release_chain import AnchorSpec, ChainSpec
from receipt.verify import VerificationSpec

SPEC = VerificationSpec(
    name="weaken",
    chain=ChainSpec(
        manifest_relative=pathlib.PurePosixPath("releases/manifests"),
        state_relative=pathlib.PurePosixPath("receipt/journal.jsonl"),
        prefix_relative=pathlib.PurePosixPath("receipt/prefix.json"),
        anchor_relative=pathlib.PurePosixPath("releases/anchors"),
        release_root_relative=pathlib.PurePosixPath("releases"),
        schema_version="t",
        producer_public_key_filename="p.pub",
        producer_spki_sha256="0000000000000000000000000000000000000000000000000000000000000000",
        anchors={
            "alpha": AnchorSpec(
                filename="alpha-root.pem",
                pem_sha256="c" * 64,
                policy_oid="1.3.6.1.4.1.99999.1.1",
                signer_certificate_sha256="d" * 64,
                signer_spki_sha256="e" * 64,
            ),
        },
    ),
    corpus=CorpusSpec(
        schema_version="t",
        content_roots=(pathlib.PurePosixPath("rules"),),
        content_suffixes=(".yaml",),
        required_attested_paths=frozenset(),
        accepted_gate_tiers=frozenset({"public"}),
        required_gates=frozenset(),
    ),
)
