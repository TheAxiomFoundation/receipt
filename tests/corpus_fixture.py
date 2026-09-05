"""Build a complete witnessed corpus in a temporary directory, offline.

The fixture stands up everything a real published corpus has — content files, an
append-only journal, a hash-linked manifest chain, an Ed25519 producer
signature, and two independent RFC 3161 witnesses — with no network and no
production key material. The two witnesses are locally generated certificate
authorities, so the anchors, policy OIDs, signer certificates, and signer SPKIs
are all real values that the production pinning code path checks for real.

That matters: a fixture that skipped ``enforce_production_pins`` would leave the
strictest branch of the verifier untested, which is the branch an auditor
actually runs.
"""

from __future__ import annotations

import hashlib
import pathlib
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from receipt.canonical import canonical_bytes
from receipt.corpus import CorpusSpec
from receipt.release_chain import AnchorSpec, ChainSpec
from receipt.sign import generate_signing_keypair, sign_payload, spki_sha256

SCHEMA_VERSION = "receipt_test_corpus_release_v1"
JOURNAL_SCHEMA = "receipt/test-corpus-journal/v1"
JOURNAL_RELATIVE = "receipt/corpus-journal.jsonl"
PREFIX_RELATIVE = "receipt/immutable-prefix.json"
MANIFEST_RELATIVE = "releases/manifests"
ANCHOR_RELATIVE = "releases/anchors"
ANCHOR_NAMES = ("alpha", "beta")

_GIT_SECONDS = 30
_GIT_OUTPUT_BYTES = 64 * 1024


def _git(root: pathlib.Path, *arguments: str) -> str:
    """Run one bounded fixture-setup Git command and return stripped stdout."""

    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_GIT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"git {' '.join(arguments)} exceeded the {_GIT_SECONDS}-second "
            "fixture budget"
        ) from exc
    output_size = len(completed.stdout) + len(completed.stderr)
    if output_size > _GIT_OUTPUT_BYTES:
        raise RuntimeError(
            f"git {' '.join(arguments)} produced {output_size} bytes, over the "
            f"{_GIT_OUTPUT_BYTES}-byte fixture budget"
        )
    if completed.returncode:
        diagnostic = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"git {' '.join(arguments)} failed with exit {completed.returncode}: "
            f"{diagnostic or 'no diagnostic'}"
        )
    return completed.stdout.decode("utf-8", errors="strict").strip()


def _commit_fixture(root: pathlib.Path, message: str, *, initialize: bool) -> str:
    """Stage the whole fixture and return the commit that records it."""

    if initialize:
        _git(root, "init", "--quiet")
        _git(root, "config", "user.name", "Receipt Corpus Fixture")
        _git(root, "config", "user.email", "receipt-corpus@example.invalid")
        _git(root, "config", "commit.gpgSign", "false")
        _git(root, "config", "core.autocrlf", "false")
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", message)
    oid = _git(root, "rev-parse", "--verify", "HEAD")
    if len(oid) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in oid
    ):
        raise RuntimeError(f"git returned a malformed fixture commit OID: {oid!r}")
    return oid


def created_at(seconds_ago: int) -> str:
    """A creation time just before the tokens this cut is about to fetch.

    The verifier refuses a manifest whose witnessed genTime precedes its own
    createdAtUtc, so a fixture with a hardcoded timestamp passes only until
    the wall clock moves past it. Deriving it from now keeps the ordering
    true on every future run.
    """

    stamp = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")



CONTENT = {
    "rules/tax/rate.yaml": "name: rate\nvalue: 0.15\n",
    "rules/tax/rate.test.yaml": "cases: []\n",
    "rules/benefit/amount.yaml": "name: amount\nvalue: 120\n",
}
ATTESTED = {
    ".axiom/toolchain.toml": '[toolchain]\ncorpus_release = "test-2026-07-25"\n',
}


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class LocalTsa:
    """A locally generated timestamp authority: root, signer, and its pins."""

    name: str
    directory: pathlib.Path
    root_pem: pathlib.Path
    policy_oid: str
    signer_certificate_sha256: str
    signer_spki_sha256: str

    @property
    def signer_pem(self) -> pathlib.Path:
        return self.directory / "signer.pem"

    def stamp(self, digest: str, out: pathlib.Path) -> None:
        query = self.directory / f"{out.stem}.tsq"
        _openssl(
            ["ts", "-query", "-digest", digest, "-sha256", "-cert", "-out", str(query)]
        )
        _openssl(
            [
                "ts",
                "-reply",
                "-config",
                str(self.directory / "tsa.cnf"),
                "-section",
                "tsa_config",
                "-queryfile",
                str(query),
                "-out",
                str(out),
            ],
            cwd=self.directory,
        )


def _openssl(arguments: list[str], cwd: pathlib.Path | None = None) -> bytes:
    completed = subprocess.run(
        ["openssl", *arguments],
        check=False,
        capture_output=True,
        cwd=None if cwd is None else str(cwd),
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"openssl {' '.join(arguments)} failed: "
            f"{completed.stderr.decode('utf-8', 'replace')}"
        )
    return completed.stdout


def certificate_pins(pem: pathlib.Path) -> dict[str, str]:
    """The exact identity dict the verifiers derive from a certificate.

    A trust bundle's ``allowedSigners`` entry is compared for equality against
    this dict, so a fixture that assembled it any other way would pin nothing:
    a stray key or a differently formatted subject fails the comparison even
    when the certificate is the right one, and the test would then prove only
    that the verifier refuses its own fixture.
    """

    certificate_der = _openssl(["x509", "-in", str(pem), "-outform", "DER"])
    with tempfile.TemporaryDirectory(prefix="receipt-fixture-") as temporary:
        public_key_pem = pathlib.Path(temporary) / "public.pem"
        public_key_pem.write_bytes(
            _openssl(["x509", "-in", str(pem), "-pubkey", "-noout"])
        )
        spki_der = _openssl(
            ["pkey", "-pubin", "-in", str(public_key_pem), "-outform", "DER"]
        )
    description = _openssl(
        ["x509", "-in", str(pem), "-noout", "-serial", "-subject", "-nameopt", "RFC2253"]
    ).decode("utf-8")
    fields: dict[str, str] = {}
    for line in description.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key] = value
    return {
        "certificateSha256": sha256_bytes(certificate_der),
        "spkiSha256": sha256_bytes(spki_der),
        "serial": fields.get("serial", "").upper(),
        "subject": fields.get("subject", ""),
    }


SIGNER_EXTENSIONS = (
    "[ tsa_ext ]\n"
    "basicConstraints = critical,CA:FALSE\n"
    "keyUsage = critical,digitalSignature\n"
    "extendedKeyUsage = critical,timeStamping\n"
    "subjectKeyIdentifier = hash\n"
)


def _tsa_config(root_name: str, policy_oid: str, *, tsa_name: bool = True) -> str:
    return (
        "[ tsa_config ]\n"
        "serial = ./tsa_serial\n"
        "crypto_device = builtin\n"
        "signer_cert = ./signer.pem\n"
        "signer_key = ./signer.key\n"
        "signer_digest = sha256\n"
        f"certs = ./{root_name}\n"
        f"default_policy = {policy_oid}\n"
        "digests = sha256, sha512\n"
        "accuracy = secs:1\n"
        "ordering = yes\n"
        f"tsa_name = {'yes' if tsa_name else 'no'}\n"
        "ess_cert_id_chain = no\n"
        "ess_cert_id_alg = sha256\n"
    )


def stamp_anonymously(
    tsa: LocalTsa,
    digest: str,
    out: pathlib.Path,
    *,
    policy_oid: str,
    serial: str,
) -> None:
    """Stamp ``digest`` with everything optional about the authority left out.

    A ``TSTInfo`` names the authority that signed it in two ways RFC 3161
    leaves optional: the ``tsa`` general name, and a serial number the
    standard requires to be unique only within one TSA. Turn the name off,
    fix the policy and the serial, and ask for no nonce, and two independent
    authorities stamping one digest in one second sign byte-identical
    ``TSTInfo``s -- two legitimate responses that a rule counting the signed
    timestamp alone reads as one.

    Nothing here is forged. Each response is ``openssl ts -reply``'s own work
    under its own signing key, from the authority's own configuration with
    two settings changed; what a caller has to arrange is the second, which
    is why callers retry.

    ``serial`` is written into the authority's counter, which the reply then
    advances, so pass one above anything the fixture's ordinary stamping
    reaches and no two tokens in a session share a serial by accident.
    """

    query = tsa.directory / f"{out.stem}.tsq"
    _openssl(
        [
            "ts", "-query", "-digest", digest, "-sha256", "-cert", "-no_nonce",
            "-out", str(query),
        ]
    )
    config = tsa.directory / "anonymous.cnf"
    config.write_text(_tsa_config(tsa.root_pem.name, policy_oid, tsa_name=False))
    (tsa.directory / "tsa_serial").write_text(f"{serial}\n")
    _openssl(
        [
            "ts", "-reply", "-config", str(config), "-section", "tsa_config",
            "-queryfile", str(query), "-out", str(out),
        ],
        cwd=tsa.directory,
    )


def _issue_signer(
    directory: pathlib.Path,
    *,
    subject: str,
    root_pem: pathlib.Path,
    ca_key: pathlib.Path,
) -> None:
    """Issue a timestamping certificate under ``root_pem`` into ``directory``."""

    extensions = directory / "signer-ext.cnf"
    extensions.write_text(SIGNER_EXTENSIONS)
    _openssl(
        [
            "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(directory / "signer.key"),
            "-out", str(directory / "signer.csr"),
            "-subj", subject,
        ]
    )
    _openssl(
        [
            "x509", "-req", "-in", str(directory / "signer.csr"),
            "-CA", str(root_pem), "-CAkey", str(ca_key),
            "-CAcreateserial", "-out", str(directory / "signer.pem"),
            "-days", "3650",
            "-extfile", str(extensions), "-extensions", "tsa_ext",
        ]
    )


def _signer_pins(directory: pathlib.Path) -> tuple[str, str]:
    certificate_der = _openssl(
        ["x509", "-in", str(directory / "signer.pem"), "-outform", "DER"]
    )
    public_key_pem = directory / "signer-public.pem"
    public_key_pem.write_bytes(
        _openssl(["x509", "-in", str(directory / "signer.pem"), "-pubkey", "-noout"])
    )
    spki_der = _openssl(["pkey", "-pubin", "-in", str(public_key_pem), "-outform", "DER"])
    return sha256_bytes(certificate_der), sha256_bytes(spki_der)


def build_local_tsa(directory: pathlib.Path, name: str, policy_oid: str) -> LocalTsa:
    directory.mkdir(parents=True, exist_ok=True)
    root_pem = directory / f"{name}-root.pem"
    _openssl(
        [
            "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(directory / "ca.key"),
            "-out", str(root_pem),
            "-days", "3650",
            "-subj", f"/CN=receipt test {name} root",
        ]
    )
    _issue_signer(
        directory,
        subject=f"/CN=receipt test {name} signer",
        root_pem=root_pem,
        ca_key=directory / "ca.key",
    )
    (directory / "tsa_serial").write_text("01\n")
    (directory / "tsa.cnf").write_text(_tsa_config(root_pem.name, policy_oid))
    certificate_sha256, spki_sha256 = _signer_pins(directory)
    return LocalTsa(
        name=name,
        directory=directory,
        root_pem=root_pem,
        policy_oid=policy_oid,
        signer_certificate_sha256=certificate_sha256,
        signer_spki_sha256=spki_sha256,
    )


def rotate_tsa_signer(source: LocalTsa, directory: pathlib.Path) -> LocalTsa:
    """Issue a second signing certificate under an existing authority's root.

    A timestamp authority rotates its signing key without disturbing the root
    a consumer pinned, so the rotated tokens must still chain to that root:
    reissuing from ``source``'s own CA key is what makes them do so. Generating
    a fresh root instead would model a different authority, not a rotation, and
    would prove nothing about how a spec spans one.
    """

    directory.mkdir(parents=True, exist_ok=True)
    root_pem = directory / source.root_pem.name
    root_pem.write_bytes(source.root_pem.read_bytes())
    _issue_signer(
        directory,
        subject=f"/CN=receipt test {source.name} signer rotated",
        root_pem=source.root_pem,
        ca_key=source.directory / "ca.key",
    )
    (directory / "tsa_serial").write_text("01\n")
    (directory / "tsa.cnf").write_text(_tsa_config(root_pem.name, source.policy_oid))
    certificate_sha256, spki_sha256 = _signer_pins(directory)
    return LocalTsa(
        name=f"{source.name}-rotated",
        directory=directory,
        root_pem=root_pem,
        policy_oid=source.policy_oid,
        signer_certificate_sha256=certificate_sha256,
        signer_spki_sha256=spki_sha256,
    )


def journal_rows(
    content: dict[str, str] | None = None,
    attested: dict[str, str] | None = None,
    gates: list[dict[str, object]] | None = None,
) -> list[dict[str, object]]:
    content = CONTENT if content is None else content
    attested = ATTESTED if attested is None else attested
    if gates is None:
        gates = [
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "pass",
                "evidence": {"command": "make validate"},
            },
            {
                "gateId": "oracle/licensed-parity",
                "tier": "restricted",
                "outcome": "pass",
                "evidence": {"restrictedInput": "licensed bundle"},
            },
            {
                "gateId": "ci/repository-checks",
                "tier": "ci-attested",
                "outcome": "pass",
                "evidence": {"workflow": "repository-checks.yml"},
            },
        ]

    rows: list[dict[str, object]] = []
    index = 0
    for path in sorted(content):
        rows.append(
            {
                "schemaVersion": JOURNAL_SCHEMA,
                "entryIndex": index,
                "kind": "content",
                "path": path,
                "sha256": sha256_text(content[path]),
                "state": "present",
            }
        )
        index += 1
    for path in sorted(attested):
        rows.append(
            {
                "schemaVersion": JOURNAL_SCHEMA,
                "entryIndex": index,
                "kind": "attested",
                "path": path,
                "sha256": sha256_text(attested[path]),
                "state": "present",
            }
        )
        index += 1
    for gate in gates:
        rows.append(
            {
                "schemaVersion": JOURNAL_SCHEMA,
                "entryIndex": index,
                "kind": "gate",
                **gate,
            }
        )
        index += 1
    return rows


def render_journal(rows: list[dict[str, object]]) -> bytes:
    return b"".join(canonical_bytes(row) + b"\n" for row in rows)


def chain_spec(alpha: LocalTsa, beta: LocalTsa, producer_spki: str) -> ChainSpec:
    return ChainSpec(
        manifest_relative=pathlib.PurePosixPath(MANIFEST_RELATIVE),
        state_relative=pathlib.PurePosixPath(JOURNAL_RELATIVE),
        prefix_relative=pathlib.PurePosixPath(PREFIX_RELATIVE),
        anchor_relative=pathlib.PurePosixPath(ANCHOR_RELATIVE),
        release_root_relative=pathlib.PurePosixPath("releases"),
        schema_version=SCHEMA_VERSION,
        producer_public_key_filename="producer-ed25519.pub",
        producer_spki_sha256=producer_spki,
        anchors={
            tsa.name: AnchorSpec(
                filename=tsa.root_pem.name,
                pem_sha256=sha256_bytes(tsa.root_pem.read_bytes()),
                policy_oid=tsa.policy_oid,
                signer_certificate_sha256=tsa.signer_certificate_sha256,
                signer_spki_sha256=tsa.signer_spki_sha256,
            )
            for tsa in (alpha, beta)
        },
    )


def corpus_spec(**overrides: object) -> CorpusSpec:
    defaults: dict[str, object] = {
        "schema_version": JOURNAL_SCHEMA,
        "content_roots": (pathlib.PurePosixPath("rules"),),
        "content_suffixes": (".yaml",),
        "required_attested_paths": frozenset({".axiom/toolchain.toml"}),
        "accepted_gate_tiers": frozenset({"public", "restricted", "ci-attested"}),
        "required_gates": frozenset({"rulespec/compile"}),
    }
    defaults.update(overrides)
    return CorpusSpec(**defaults)  # type: ignore[arg-type]


def build_corpus(
    root: pathlib.Path,
    workspace: pathlib.Path,
    *,
    content: dict[str, str] | None = None,
    attested: dict[str, str] | None = None,
    gates: list[dict[str, object]] | None = None,
    commit: bool = True,
) -> str | None:
    """Write a witnessed corpus and return its commit OID unless opted out."""

    content = CONTENT if content is None else content
    attested = ATTESTED if attested is None else attested

    for relative, text in {**content, **attested}.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    rows = journal_rows(content, attested, gates)
    journal_bytes = render_journal(rows)
    journal_path = root / JOURNAL_RELATIVE
    journal_path.parent.mkdir(parents=True, exist_ok=True)
    journal_path.write_bytes(journal_bytes)

    lines = journal_bytes.decode("utf-8").split("\n")[:-1]
    prefix = {
        "schemaVersion": "receipt/test-corpus-prefix/v1",
        "prefixLineCount": len(lines),
        "lineSha256s": [sha256_text(line) for line in lines],
        "prefixSha256": sha256_text("\n".join(lines) + "\n"),
    }
    prefix_path = root / PREFIX_RELATIVE
    prefix_bytes = canonical_bytes(prefix) + b"\n"
    prefix_path.write_bytes(prefix_bytes)

    alpha = build_local_tsa(workspace / "alpha", "alpha", "1.3.6.1.4.1.99999.1.1")
    beta = build_local_tsa(workspace / "beta", "beta", "1.3.6.1.4.1.99999.2.1")

    private_pem, public_pem = generate_signing_keypair()
    anchors = root / ANCHOR_RELATIVE
    anchors.mkdir(parents=True, exist_ok=True)
    (anchors / "producer-ed25519.pub").write_bytes(public_pem)
    for tsa in (alpha, beta):
        (anchors / tsa.root_pem.name).write_bytes(tsa.root_pem.read_bytes())

    spec_chain = chain_spec(alpha, beta, spki_sha256(public_pem))

    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "releaseIndex": 0,
        "previousManifestSha256": None,
        "state": {
            "path": JOURNAL_RELATIVE,
            "jsonlSha256": sha256_bytes(journal_bytes),
            "lineCount": len(lines),
            "immutablePrefixSha256": sha256_bytes(prefix_bytes),
        },
        "append": None,
        "createdAtUtc": created_at(120),
        "producer": {"repo": "TheAxiomFoundation/receipt", "branch": "test"},
    }
    manifest_bytes = canonical_bytes(manifest) + b"\n"
    digest = sha256_bytes(manifest_bytes)
    manifests = root / MANIFEST_RELATIVE
    manifests.mkdir(parents=True, exist_ok=True)
    stem = f"0000-{digest[:16]}"
    (manifests / f"{stem}.json").write_bytes(manifest_bytes)
    (manifests / f"{stem}.producer.sig").write_bytes(
        sign_payload(private_pem, manifest_bytes, domain=b"")
    )
    for tsa in (alpha, beta):
        tsa.stamp(digest, manifests / f"{stem}.{tsa.name}.tsr")

    write_spec_module(root, spec_chain, alpha, beta)
    (workspace / "producer.key").write_bytes(private_pem)
    if not commit:
        return None
    return _commit_fixture(root, "build corpus fixture", initialize=True)


def append_release(
    root: pathlib.Path,
    workspace: pathlib.Path,
    *,
    content: dict[str, str],
    attested: dict[str, str] | None = None,
    gates: list[dict[str, object]] | None = None,
    commit: bool = True,
) -> str | None:
    """Cut a second release over an updated tree, appending to the journal.

    Deliberately re-derives everything the way a producer must: the previous
    manifest is linked by digest, the journal is extended rather than rewritten,
    and the immutable prefix file is left exactly as genesis sealed it — the
    invariant that a growing prefix would silently break. Returns the new commit
    OID, or ``None`` when ``commit`` is false.
    """

    if commit and not (root / ".git").exists():
        raise ValueError(
            "append_release(commit=True) cannot follow build_corpus(commit=False)"
        )

    attested = ATTESTED if attested is None else attested
    for relative, text in {**content, **attested}.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    journal_path = root / JOURNAL_RELATIVE
    existing_bytes = journal_path.read_bytes()
    existing_lines = existing_bytes.decode("utf-8").split("\n")[:-1]

    appended = []
    index = len(existing_lines)
    for path in sorted(content):
        appended.append(
            {
                "schemaVersion": JOURNAL_SCHEMA,
                "entryIndex": index,
                "kind": "content",
                "path": path,
                "sha256": sha256_text(content[path]),
                "state": "present",
            }
        )
        index += 1
    appended_bytes = render_journal(appended)
    journal_bytes = existing_bytes + appended_bytes
    journal_path.write_bytes(journal_bytes)
    lines = journal_bytes.decode("utf-8").split("\n")[:-1]

    # Untouched on purpose: the prefix is sealed once, at genesis.
    prefix_bytes = (root / PREFIX_RELATIVE).read_bytes()

    manifests = root / MANIFEST_RELATIVE
    previous = sorted(manifests.glob("*.json"))[-1]
    previous_digest = sha256_bytes(previous.read_bytes())
    release_index = len(list(manifests.glob("*.json")))

    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "releaseIndex": release_index,
        "previousManifestSha256": previous_digest,
        "state": {
            "path": JOURNAL_RELATIVE,
            "jsonlSha256": sha256_bytes(journal_bytes),
            "lineCount": len(lines),
            "immutablePrefixSha256": sha256_bytes(prefix_bytes),
        },
        "append": {
            "previousLineCount": len(existing_lines),
            "appendedRowCount": len(appended),
            "appendedBytesSha256": sha256_bytes(appended_bytes),
        },
        "createdAtUtc": created_at(60),
        "producer": {"repo": "TheAxiomFoundation/receipt", "branch": "test"},
    }
    manifest_bytes = canonical_bytes(manifest) + b"\n"
    digest = sha256_bytes(manifest_bytes)
    stem = f"{release_index:04d}-{digest[:16]}"
    (manifests / f"{stem}.json").write_bytes(manifest_bytes)
    (manifests / f"{stem}.producer.sig").write_bytes(
        sign_payload((workspace / "producer.key").read_bytes(), manifest_bytes, domain=b"")
    )
    for name in ANCHOR_NAMES:
        # Re-open the authorities genesis created; stamping needs only their
        # working directory and openssl config, both of which persist there.
        directory = workspace / name
        tsa = LocalTsa(
            name=name,
            directory=directory,
            root_pem=directory / f"{name}-root.pem",
            policy_oid="",
            signer_certificate_sha256="",
            signer_spki_sha256="",
        )
        tsa.stamp(digest, manifests / f"{stem}.{name}.tsr")
    if not commit:
        return None
    return _commit_fixture(root, "append corpus release", initialize=False)


def write_spec_module(
    root: pathlib.Path,
    spec_chain: ChainSpec,
    alpha: LocalTsa,
    beta: LocalTsa,
) -> pathlib.Path:
    """Emit the consumer-side committed spec module the CLI loads."""

    anchors = ",\n".join(
        f"""        {name!r}: AnchorSpec(
            filename={anchor.filename!r},
            pem_sha256={anchor.pem_sha256!r},
            policy_oid={anchor.policy_oid!r},
            signer_certificate_sha256={anchor.signer_certificate_sha256!r},
            signer_spki_sha256={anchor.signer_spki_sha256!r},
        )"""
        for name, anchor in sorted(spec_chain.anchors.items())
    )
    module = f'''"""Committed trust anchors for the receipt test corpus."""

import pathlib

from receipt.corpus import CorpusSpec
from receipt.release_chain import AnchorSpec, ChainSpec
from receipt.verify import VerificationSpec

CHAIN = ChainSpec(
    manifest_relative=pathlib.PurePosixPath({MANIFEST_RELATIVE!r}),
    state_relative=pathlib.PurePosixPath({JOURNAL_RELATIVE!r}),
    prefix_relative=pathlib.PurePosixPath({PREFIX_RELATIVE!r}),
    anchor_relative=pathlib.PurePosixPath({ANCHOR_RELATIVE!r}),
    release_root_relative=pathlib.PurePosixPath("releases"),
    schema_version={SCHEMA_VERSION!r},
    producer_public_key_filename="producer-ed25519.pub",
    producer_spki_sha256={spec_chain.producer_spki_sha256!r},
    anchors={{
{anchors}
    }},
)

CORPUS = CorpusSpec(
    schema_version={JOURNAL_SCHEMA!r},
    content_roots=(pathlib.PurePosixPath("rules"),),
    content_suffixes=(".yaml",),
    required_attested_paths=frozenset({{".axiom/toolchain.toml"}}),
    accepted_gate_tiers=frozenset({{"public", "restricted", "ci-attested"}}),
    required_gates=frozenset({{"rulespec/compile"}}),
)

SPEC = VerificationSpec(
    name="receipt test corpus",
    chain=CHAIN,
    corpus=CORPUS,
)
'''
    spec_path = root / "verification" / "spec.py"
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text(module)
    return spec_path
