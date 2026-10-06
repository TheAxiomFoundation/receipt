"""The approved consumer census is an import-path compatibility contract."""
from __future__ import annotations

import dataclasses
import re

import pytest


# record: consumer census Chronicle scripts/canonical_json.py 7-21
# record: consumer census Chronicle scripts/receipt_pins.py 7-8 and verify_release_chain.py 21-207
# record: consumer census Chronicle scripts/check_thesis_facts_append.py 50-73, 408-437
# record: consumer census axiom-encode src/axiom_encode/cli.py 46, 25846-25865
# record: consumer census thesis signing/verification scripts and test_producer_signing.py 23-27
# record: harness census ledger 118-127, append 123-129, witness 421-437, attest 84-94
CALLABLES = {
    "receipt.canonical": ("canonical_bytes", "canonical_sha256", "canonical_stringify", "main", "utf16_sort_key"),
    "receipt.release_chain": (
        "AnchorSpec", "ChainSpec", "ChainVerification", "GitEntry", "ReleaseChainError", "ReleaseRecord",
        "jsonl_line_offsets", "manifest_filename", "parse_created_at", "producer_signature_path_for_manifest",
        "sha256_bytes", "_receipt_re", "_format_time", "validate_manifest_schema", "load_manifest",
        "receipt_paths_for_manifest", "verify_producer_signature_bytes", "verify_producer_signature", "verify_receipt",
        "verify_release_receipts", "verify_release_chain", "verify_release_history_immutable", "verify_base_release_chain",
        # record: directory census release_chain.py 1311-1325, 1435-1466 retained legacy export
        "assert_no_symlinked_state_component",
    ),
    "receipt.snapshot": ("SnapshotError", "TreeSnapshot"),
    "receipt.append_gate": ("AppendError", "AppendGateSpec", "AppendGateVerdict", "reject_non_append_bytes",
        "expected_assertion_version_id", "effective_current_rows", "check_rows", "verify_append_gate_verdict", "verify_append_gate"),
    "receipt.sign": ("KeyringSpec", "KeySpec", "raw_public_key_sha256", "verify_threshold", "SignError", "sign_payload",
        "spki_sha256", "verify_signature_bytes", "generate_signing_keypair"),
    "receipt.tsa": ("TrustBundleSpec", "TsaError", "TsaIdentitySpec", "TsaSpec", "WitnessEvidence", "activate_trust_bundles",
        "bootstrap_trust_bundles", "load_json", "logical_path", "physical_path", "sha256_file", "trust_bundle_updates", "verify_witness"),
    "receipt.attest": ("AttestSpec", "ProvenanceError", "attestation_subject", "cert_identity_pattern", "commit_in_scope",
        "enforcement_epoch", "records_commits", "repository_slug", "verify_commit"),
}


@pytest.mark.parametrize("module,symbol", [(module, symbol) for module, names in CALLABLES.items() for symbol in names],
                         ids=[f"{module}.{symbol}" for module, names in CALLABLES.items() for symbol in names])
def test_consumer_callable_at_original_import_path(module, symbol):
    namespace = {}
    exec(f"from {module} import {symbol}", namespace)
    # record: consumer and harness census rows enumerated in CALLABLES above
    assert callable(namespace[symbol]), f"{module}.{symbol}"


# These census entries are values/compiled patterns, not callable functions.
# Assert their real public categories instead of pretending they are callable.
CONSTANTS = {
    "CRYPTOGRAPHY_AVAILABLE": bool,
    "DEFAULT_CLOCK_SKEW_SECONDS": int,
    "MAX_FUTURE_SECONDS": int,
    "MAX_RELEASE_INDEX": int,
    "PRODUCER_SIGNATURE_BYTES": int,
    "MANIFEST_RE": re.Pattern,
    "PRODUCER_SIGNATURE_RE": re.Pattern,
    "SHA256_RE": re.Pattern,
    "STRICT_UTC_RE": re.Pattern,
    "TIME_STAMP_RE": re.Pattern,
}


@pytest.mark.parametrize("symbol,category", CONSTANTS.items())
def test_chronicle_reexported_values(symbol, category):
    namespace = {}
    exec(f"from receipt.release_chain import {symbol}", namespace)
    # record: consumer census Chronicle scripts/verify_release_chain.py 44-54
    assert type(namespace[symbol]) is category


@pytest.mark.parametrize("symbol", ("select", "assert_ancestor", "materialize"))
def test_consumer_snapshot_methods(symbol):
    from receipt.snapshot import TreeSnapshot
    # record: consumer census Chronicle 245-260, ledger harness 381-433
    assert callable(getattr(TreeSnapshot, symbol))


def test_chronicle_append_verdict_fields_and_git_entry_shim():
    from receipt.append_gate import AppendGateVerdict
    from receipt.release_chain import GitEntry
    from receipt.snapshot import GitEntry as SnapshotGitEntry
    # record: consumer census Chronicle check_thesis_facts_append.py 508-514
    assert {field.name for field in dataclasses.fields(AppendGateVerdict)} == {
        "summary", "candidate_commit", "candidate_tree", "base_commit", "base_tree", "object_format", "name_repertoire"}
    # record: consumer census Chronicle verify_release_chain.py 59, retained re-export
    assert GitEntry is SnapshotGitEntry
