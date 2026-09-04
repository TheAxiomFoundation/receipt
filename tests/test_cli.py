"""End-to-end battery for ``receipt verify`` over a real witnessed corpus.

The fixture builds an actual hash-linked manifest chain, an actual Ed25519
producer signature, and two actual RFC 3161 tokens from two locally generated
authorities — so ``enforce_production_pins`` is live in every test here, and the
anchor bytes, policy OIDs, signer certificates, and signer SPKIs are all pinned
and checked for real.

The battery has two halves. The refusals prove the command fails closed on each
way a published corpus can be wrong. The verdict-text assertions prove the
command does not overclaim when everything is right — which, for an artifact
whose whole purpose is to be handed to a skeptic, is the more important half.
"""

from __future__ import annotations

import codecs
import contextlib
import hashlib
import io
import json
import pathlib
import shutil
import sys

import pytest

from receipt.cli import EXIT_FAIL, EXIT_OK, EXIT_USAGE, main
from receipt.sign import generate_signing_keypair, sign_payload
from receipt.verify import load_spec

from corpus_fixture import CONTENT, append_release, build_corpus


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """One expensive build (RSA keygen ×2, two TSAs); copied per test."""

    base = tmp_path_factory.mktemp("corpus-origin")
    root = base / "repo"
    root.mkdir()
    build_corpus(root, base / "tsa-workspace")
    return root


@pytest.fixture()
def repo(built: pathlib.Path, tmp_path: pathlib.Path) -> pathlib.Path:
    destination = tmp_path / "repo"
    shutil.copytree(built, destination, symlinks=True)
    return destination


def run(repo: pathlib.Path, *extra: str) -> int:
    return main(["verify", "--spec", str(repo / "verification/spec.py"),
                 "--root", str(repo), *extra])


def manifest_stem(repo: pathlib.Path) -> pathlib.Path:
    manifests = sorted((repo / "releases/manifests").glob("*.json"))
    assert len(manifests) == 1
    return manifests[0]


# --- the command accepts a corpus that is exactly what it claims to be -------


def test_verifies_a_published_corpus_from_a_clone(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo) == EXIT_OK
    out = capsys.readouterr().out
    assert "VERDICT: PASS" in out
    assert "custody" in out and "binding" in out


def test_json_pass_writes_to_a_redirected_stringio(
    repo: pathlib.Path,
) -> None:
    """Binds S7-F5: a codec-less StringIO is a safe Unicode stdout sink.

    ``redirect_stdout`` installs exactly the bufferless, codec-less stream
    applications use to capture a command in memory. S7-F5 writes the JSON
    text directly and preserves the passing exit code. Without it the
    bufferless guard rejects the verdict, the refusal hits the same guard,
    stdout stays empty, and ``main`` returns ``EXIT_FAIL``.
    """

    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        code = run(repo, "--json")

    assert code == EXIT_OK
    text = captured.getvalue()
    assert text.endswith("\n")
    assert json.loads(text)["verdict"] == "PASS"


def test_text_pass_writes_to_a_redirected_stringio(
    repo: pathlib.Path,
) -> None:
    """Binds S7-F5: a Unicode stdout sink must also carry the text verdict.

    The rendered text, including its fixed em dash, is written as Unicode
    rather than encoded and decoded through a codec that does not exist.
    Without S7-F5 ``_byte_safe_encoding`` rejects this stream, ``main`` turns
    the valid PASS into ``EXIT_FAIL``, and the redirected stdout is empty.
    """

    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        code = run(repo)

    assert code == EXIT_OK
    text = captured.getvalue()
    assert text.startswith("receipt ")
    assert "VERDICT: PASS — custody and corpus binding" in text
    assert text.endswith("  digests out of band.\n")


def test_refusal_writes_to_a_redirected_stringio_stderr(
    repo: pathlib.Path,
) -> None:
    """Binds S7-F5: the refusal path rejected the same Unicode sink too.

    A missing root refuses before verification and writes the two fixed
    refusal lines through ``redirect_stderr``. Without S7-F5 the bufferless
    codec-less stderr is rejected inside ``_refuse`` and swallowed, leaving
    the caller the exit code but no captured explanation.
    """

    missing = repo / "missing-root"
    captured = io.StringIO()
    with contextlib.redirect_stderr(captured):
        code = main(
            [
                "verify",
                "--spec",
                str(repo / "verification/spec.py"),
                "--root",
                str(missing),
            ]
        )

    assert code == EXIT_USAGE
    assert captured.getvalue() == (
        f"receipt verify: root is not a directory: {missing}\n"
        "receipt verify: FAIL\n"
    )


def _a_non_ascii_character_this_page_spells(name: str) -> str | None:
    """A character above 0x7F this code page encodes, from its own table.

    The allow-list's shift-state check needs a probe the member under test
    actually encodes; a fixed tuple of five characters does not have one for
    nine of the sixty-one, and an encoder that refused every probe was then
    asked whether ``A`` still encodes to ``b"A"`` in a state nothing had
    entered (S8-F8). Reading the page's own decode table gives a probe for
    every member that has one, and ``None`` only for ``ascii``, which spells
    no such character at all.
    """

    for value in range(0x80, 0x100):
        try:
            character = bytes([value]).decode(name)
        except UnicodeDecodeError:
            continue
        if ord(character) < 0x80:
            continue
        try:
            character.encode(name)
        except (UnicodeEncodeError, UnicodeError):
            continue
        return character
    return None


#: What a codec outside ``_ASCII_TRANSPARENT_CODECS`` is refused with. Spelled
#: once here, with the size written out rather than read off the module, so a
#: change to the allow-list fails the table test rather than silently rewording
#: every refusal below (S8-F5).
NOT_ON_THE_ALLOW_LIST = (
    "verdict stream codec {name} is not one of the 61 single-byte code pages "
    "this command will write ASCII for; the verdict cannot be written safely"
)


def test_the_json_contract_is_at_most_one_object_not_exactly_one(
    repo: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Binds S8-F9: "exactly one JSON object" is wrong in both directions.

    Zero is already asserted a few tests below, where the emission guard
    refuses stdout and ``_refuse`` re-emits to the same stream and swallows
    the second failure. Two is what this pins: the write completes, the flush
    after it fails, and the render boundary emits its own refusal object
    behind the complete one the run had already written. A consumer reading
    the stream as a single JSON document gets a parse error from the second
    object rather than from a truncated first.

    The behaviour is deliberate and unchanged — the exit code is EXIT_FAIL in
    both cases, so a consumer keying on it is told the truth — and what the
    command never does is print a *partial* object and exit passing. The
    contract sentence now says "at most one" and names the exit code as the
    carrier; this is the case that made "exactly" false.
    """

    class _FlushFailingStdout(io.StringIO):
        """A stream that takes every byte and then cannot flush them."""

        def flush(self) -> None:
            raise OSError("cannot flush the verdict stream")

    stream = _FlushFailingStdout()
    monkeypatch.setattr(sys, "stdout", stream)
    assert run(repo, "--json") == EXIT_FAIL

    written = stream.getvalue()
    decoder = json.JSONDecoder()
    first, index = decoder.raw_decode(written)
    second, _ = decoder.raw_decode(written[index:].lstrip())
    assert first["verdict"] == "PASS"
    assert second["verdict"] == "FAIL"
    assert second["stage"] == "render"
    # Two objects, so the stream is not one JSON document.
    with pytest.raises(json.JSONDecodeError):
        json.loads(written)
    assert "verdict could not be rendered" in capsys.readouterr().err


def test_a_codecs_stream_writer_is_not_mistaken_for_a_unicode_sink(
    repo: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Binds S7-R3-F4: "no codec and no buffer" is a shape, not a guarantee.

    ``codecs.StreamWriter`` forwards attribute lookups to the binary stream it
    wraps, so ``encoding`` and ``buffer`` are both absent on a writer over a
    ``BytesIO`` — the exact shape S7-F5 classified as a byte-free Unicode
    sink. It is not one: it encodes everything written to it with the codec
    it was built from, so the rendered verdict's U+203A leaves as the single
    byte 0x9B, which is CSI, and whatever follows it is a control sequence
    the escaper had no reason to touch.

    Recognising sinks rather than inferring them refuses this stream before
    the render. Without S7-R3-F4 the run reports PASS and the writer holds
    cp1252 bytes.
    """

    import codecs as codecs_module

    from receipt.cli import _stream_encoding

    buffer = io.BytesIO()
    stream = codecs_module.getwriter("cp1252")(buffer)

    # The shape, and what the shape hides.
    assert getattr(stream, "encoding", None) is None
    assert _stream_encoding(stream) == ""
    stream.write("\u203a[2J")
    assert buffer.getvalue() == b"\x9b[2J"
    buffer.seek(0)
    buffer.truncate()

    monkeypatch.setattr(sys, "stdout", stream)
    assert run(repo, "--json") == EXIT_FAIL
    assert buffer.getvalue() == b""
    error = capsys.readouterr().err
    assert "verdict could not be rendered; treat the run as unverified" in error
    assert (
        "OSError: verdict stream has no binary buffer and its encoding is "
        "not UTF-8; the verdict cannot be written safely" in error
    )


def test_a_text_io_base_subclass_without_an_encoding_is_refused(
    repo: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Binds S7-R3-F4: a counting text stream has a sink's shape too.

    ``io.TextIOBase`` leaves ``encoding`` as ``None`` and defines no buffer,
    so a subclass that accepts text and returns a count — a progress wrapper,
    a tee, a stream a host substituted — was classified as a Unicode sink and
    written to. Whether that is safe depends entirely on what the subclass
    does with the text, which this module cannot see. Only a recognised sink
    is treated as one now; this one refuses.

    Without S7-R3-F4 the verdict is written to it and the run reports PASS.
    """

    from receipt.cli import _stream_encoding

    class _CountingTextStream(io.TextIOBase):
        def __init__(self) -> None:
            self.text: list[str] = []

        def write(self, text: str) -> int:  # type: ignore[override]
            self.text.append(text)
            return len(text)

    stream = _CountingTextStream()
    assert stream.encoding is None
    assert _stream_encoding(stream) == ""

    monkeypatch.setattr(sys, "stdout", stream)
    assert run(repo, "--json") == EXIT_FAIL
    assert stream.text == []
    error = capsys.readouterr().err
    assert "verdict could not be rendered; treat the run as unverified" in error
    assert (
        "OSError: verdict stream has no binary buffer and its encoding is "
        "not UTF-8; the verdict cannot be written safely" in error
    )


def test_a_tee_that_offers_getvalue_is_not_a_unicode_sink(
    repo: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Binds S8-F2: ``getvalue`` is a method name, not a byte-freeness proof.

    S7-R3-F4 refused the counting ``TextIOBase`` subclass above and then
    admitted anything offering a ``getvalue`` that returns ``str``, calling
    that "the in-memory-text protocol ``StringIO`` defines". Adding one
    method to the refused class walked it straight back in. This is that
    class with the method: a tee that keeps the text in memory *and*
    forwards it to a cp1252 byte stream — which is exactly the "progress
    wrapper, a tee, a stream a host substituted" the test above says must
    refuse.

    Restore the probe and the classification assertion below fails first —
    ``_stream_encoding`` answers ``None``, the positive sink verdict — and
    the two after it fail with it: ``_byte_safe_encoding`` answers utf-8,
    the verdict is written through the stream, the run reports PASS, and the
    byte stream holds cp1252 where the escaper had approved U+203A. Measured
    with the probe restored and this line removed: ``run`` returns EXIT_OK.

    A sink is ``io.StringIO`` and nothing else now, so this refuses at the
    render boundary before anything is written.
    """

    from receipt.cli import _stream_encoding

    class _TeeingTextStream(io.TextIOBase):
        """In-memory text, and the same text encoded to a byte stream."""

        def __init__(self, binary: io.BytesIO) -> None:
            self._text: list[str] = []
            self._binary = binary

        def write(self, text: str) -> int:  # type: ignore[override]
            self._text.append(text)
            self._binary.write(text.encode("cp1252", "replace"))
            return len(text)

        def getvalue(self) -> str:
            return "".join(self._text)

    binary = io.BytesIO()

    # The shape the probe read as a guarantee, and what it hides. Shown on
    # its own instance so the stream the run is given starts empty.
    probe = _TeeingTextStream(binary)
    assert probe.encoding is None
    assert isinstance(probe.getvalue(), str)
    probe.write("\u203a[2J")
    assert binary.getvalue() == b"\x9b[2J"
    binary.seek(0)
    binary.truncate()

    stream = _TeeingTextStream(binary)
    assert _stream_encoding(stream) == ""

    monkeypatch.setattr(sys, "stdout", stream)
    assert run(repo, "--json") == EXIT_FAIL
    assert binary.getvalue() == b""
    assert stream.getvalue() == ""
    error = capsys.readouterr().err
    assert "verdict could not be rendered; treat the run as unverified" in error
    assert (
        "OSError: verdict stream has no binary buffer and its encoding is "
        "not UTF-8; the verdict cannot be written safely" in error
    )


def test_a_string_io_subclass_is_still_a_unicode_sink(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S7-R3-F4, the control: the narrowing must not lose the sink.

    S7-F5 exists because ``redirect_stdout(StringIO())`` is how an
    application captures this command in memory, and a subclass of it is the
    same object with a name. Both are recognised by type rather than by
    probing ``getvalue``, which is all that is left of the recognition after
    S8-F2 deleted the probe.

    This test passes with S7-R3-F4 disabled, which is the point: it is what
    keeps the narrowing from turning every bufferless stream back into a
    refusal.
    """

    class _NamedCapture(io.StringIO):
        pass

    captured = _NamedCapture()
    monkeypatch.setattr(sys, "stdout", captured)
    assert run(repo, "--json") == EXIT_OK
    assert json.loads(captured.getvalue())["verdict"] == "PASS"


def test_the_verdict_states_what_it_did_not_establish(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A passing verdict a reader can over-read is a failure of the artifact."""

    assert run(repo) == EXIT_OK
    out = capsys.readouterr().out
    assert "NOT RE-RUN BY THIS COMMAND" in out
    assert "does NOT prove" in out
    assert "correct reading of the law" in out


def test_gate_tiers_are_reported_separately(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo) == EXIT_OK
    out = capsys.readouterr().out
    assert "public: you can re-run these yourself" in out
    assert "restricted: reproducible only with restricted pinned inputs" in out
    assert "ci-attested: not reproducible" in out
    assert "oracle/licensed-parity" in out


def test_json_output_marks_gates_as_not_re_run(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo, "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "PASS"
    assert payload["gateDeclarations"]["reRunByThisCommand"] is False
    assert set(payload["gateDeclarations"]["byTier"]) == {
        "public",
        "restricted",
        "ci-attested",
    }
    assert payload["scope"]["notEstablished"] == [
        "that any declared gate actually passed",
        "that the encoded rules are a correct reading of the law",
        "that this clone holds the producer's newest release "
        "(--base-ref only bounds staleness against a head the auditor "
        "recorded; newest needs an out-of-band comparison)",
        "that this is the only history the producer maintains "
        "(equivocation is undetectable from a single clone; compare "
        "head digests out of band)",
    ]
    assert payload["scope"]["established"] == [
        "custody of the release chain",
        "binding of the witnessed journal to this working tree",
    ]
    assert payload["chain"]["releases"] == 1
    assert len(payload["chain"]["witnesses"]) == 2
    assert payload["binding"]["contentFiles"] == 3


def anchor_set_recomputed(repo: pathlib.Path) -> tuple[str, dict[str, str]]:
    """The recomputation an auditor would script, sharing no package code:
    hash the spec-configured anchor files, then SHA-256 the compact
    sorted-key JSON of the mapping (receipt-canonical JSON for these
    ASCII filenames)."""

    spec, _ = load_spec(repo / "verification/spec.py")
    names = {
        spec.chain.producer_public_key_filename,
        *(anchor.filename for anchor in spec.chain.anchors.values()),
    }
    per_file = {
        name: hashlib.sha256(
            (repo / "releases/anchors" / name).read_bytes()
        ).hexdigest()
        for name in names
    }
    combined = hashlib.sha256(
        json.dumps(per_file, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return combined, per_file


def test_the_json_verdict_names_the_anchor_set_in_force(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """receipt#24: an auditor confirms from the verdict alone which anchor
    bytes custody consumed. TSA anchors are byte-pinned; producer identity
    is SPKI-pinned, so its entry records the serialization that verified."""

    assert run(repo, "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    combined, per_file = anchor_set_recomputed(repo)
    assert payload["chain"]["anchorSetSha256"] == combined
    assert payload["chain"]["anchorFiles"] == per_file


def test_the_text_verdict_carries_the_full_anchor_set_digest(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The digest exists to be quoted from the verdict alone, and it is
    pinned nowhere else — a prefix would not be quotable evidence."""

    combined, _ = anchor_set_recomputed(repo)
    assert run(repo) == EXIT_OK
    out = capsys.readouterr().out
    assert f"anchor set {combined}" in out


def test_a_gate_that_did_not_run_is_shouted_not_hidden(
    built: pathlib.Path, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The failure mode this schema exists to stop: a disabled gate that reads
    like a passing one."""

    root = tmp_path / "repo"
    build_corpus(
        root,
        tmp_path / "tsa",
        gates=[
            {
                "gateId": "rulespec/compile",
                "tier": "public",
                "outcome": "pass",
                "evidence": {"command": "make validate"},
            },
            {
                "gateId": "guard/manual-rulespec-changes",
                "tier": "ci-attested",
                "outcome": "not-run",
                "evidence": {"reason": "run-generated-guard: false in the caller"},
            },
        ],
    )
    assert main(["verify", "--spec", str(root / "verification/spec.py"),
                 "--root", str(root)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "1 of 2 declared gate(s) did not pass cleanly" in out
    assert "DID NOT RUN — run-generated-guard: false in the caller" in out


def test_json_output_carries_the_spec_digest(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An auditor must be able to quote the exact configuration they ran under."""

    assert run(repo, "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    import hashlib

    expected = hashlib.sha256((repo / "verification/spec.py").read_bytes()).hexdigest()
    assert payload["spec"]["sha256"] == expected


# --- a chain that has actually been appended to ------------------------------


@pytest.fixture(scope="module")
def two_releases(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """Genesis plus one real append: manifest linking, strictly increasing line
    counts, byte-exact append digests, and a sealed prefix that did NOT move."""

    base = tmp_path_factory.mktemp("corpus-appended")
    root = base / "repo"
    root.mkdir()
    workspace = base / "tsa-workspace"
    build_corpus(root, workspace)
    corrected = dict(CONTENT)
    corrected["rules/tax/rate.yaml"] = "name: rate\nvalue: 0.175\n"
    corrected["rules/benefit/supplement.yaml"] = "name: supplement\nvalue: 40\n"
    append_release(root, workspace, content=corrected)
    return root


def test_verifies_a_chain_with_a_second_release(
    two_releases: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(two_releases) == EXIT_OK
    out = capsys.readouterr().out
    assert "2 release(s)" in out
    assert "VERDICT: PASS" in out


def test_a_corrected_encoding_binds_to_its_new_bytes(
    two_releases: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Supersession is real: the tree holds the corrected value and verifies,
    while the superseded row stays in the witnessed history."""

    assert run(two_releases, "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["binding"]["contentFiles"] == 4

    rows = [
        json.loads(line)
        for line in (two_releases / "receipt/corpus-journal.jsonl").read_text().splitlines()
    ]
    rate_rows = [r for r in rows if r.get("path") == "rules/tax/rate.yaml"]
    assert len(rate_rows) == 2, "the superseded row must survive in the history"
    assert rate_rows[0]["sha256"] != rate_rows[1]["sha256"]

    import hashlib

    on_disk = hashlib.sha256(
        (two_releases / "rules/tax/rate.yaml").read_bytes()
    ).hexdigest()
    assert on_disk == rate_rows[1]["sha256"], "the tree must hold the corrected bytes"


def test_refuses_a_rewritten_prefix_seal(two_releases: pathlib.Path, tmp_path: pathlib.Path) -> None:
    """The genesis seal is immutable; moving it invalidates every manifest."""

    repo = tmp_path / "repo"
    shutil.copytree(two_releases, repo, symlinks=True)
    prefix = repo / "receipt/immutable-prefix.json"
    prefix.write_bytes(prefix.read_bytes().replace(b'"prefixLineCount":7', b'"prefixLineCount":9'))
    assert main(["verify", "--spec", str(repo / "verification/spec.py"),
                 "--root", str(repo)]) == EXIT_FAIL


def test_refuses_a_removed_head_release(
    two_releases: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """Rolling the chain back to hide the latest state must not verify."""

    repo = tmp_path / "repo"
    shutil.copytree(two_releases, repo, symlinks=True)
    for path in (repo / "releases/manifests").glob("0001-*"):
        path.unlink()
    assert main(["verify", "--spec", str(repo / "verification/spec.py"),
                 "--root", str(repo)]) == EXIT_FAIL


# --- refusals: the corpus is not what it claims to be -----------------------


def test_refuses_an_edited_rule_file(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "rules/tax/rate.yaml").write_text("name: rate\nvalue: 0.99\n")
    assert run(repo) == EXIT_FAIL
    err = capsys.readouterr().err
    assert "VERDICT: FAIL" in err
    assert "witnessed digest" in err


def test_refuses_a_rule_file_added_without_witnessing(repo: pathlib.Path) -> None:
    (repo / "rules/tax/extra.yaml").write_text("name: extra\n")
    assert run(repo) == EXIT_FAIL


def test_refuses_a_symlinked_directory_under_a_content_root(
    repo: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """End-to-end regression for the demonstrated symlinked-directory false
    PASS: the full command must fail closed, not just the library."""

    outside = tmp_path / "smuggled"
    outside.mkdir()
    (outside / "evil.yaml").write_text("name: evil\n")
    (repo / "rules/injected").symlink_to(outside)
    assert run(repo) == EXIT_FAIL


def test_scope_established_on_failure_json(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A FAIL verdict must not carry an "established" list claiming the
    binding it never proved (cross-family review finding)."""

    (repo / "rules/tax/rate.yaml").write_text("tampered\n")
    assert run(repo, "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["scope"]["established"] == ["custody of the release chain"]
    assert any("newest release" in item for item in payload["scope"]["notEstablished"])


def test_pass_verdict_derives_the_witness_clause(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The witness sentence names the anchors that actually verified, rather
    than asserting a hardcoded count."""

    assert run(repo) == EXIT_OK
    out = capsys.readouterr().out
    assert "the 2 pinned RFC 3161 authorities (alpha, beta)" in out
    assert "newest release" in out  # staleness is named, not implied away


def test_refuses_an_edited_attested_file(repo: pathlib.Path) -> None:
    """The toolchain pin is bound too: swapping the corpus release must refuse."""

    (repo / ".axiom/toolchain.toml").write_text(
        '[toolchain]\ncorpus_release = "something-else"\n'
    )
    assert run(repo) == EXIT_FAIL


def test_refuses_an_edited_journal(repo: pathlib.Path) -> None:
    """Editing the journal to match a tampered tree breaks custody instead."""

    journal = repo / "receipt/corpus-journal.jsonl"
    journal.write_bytes(journal.read_bytes().replace(b"rules/tax", b"rules/tex"))
    assert run(repo) == EXIT_FAIL


def test_refuses_a_forged_manifest(repo: pathlib.Path) -> None:
    path = manifest_stem(repo)
    path.write_bytes(path.read_bytes().replace(b'"lineCount":7', b'"lineCount":8'))
    assert run(repo) == EXIT_FAIL


def test_refuses_a_corrupt_producer_signature(repo: pathlib.Path) -> None:
    signature = manifest_stem(repo).with_suffix(".producer.sig")
    if not signature.exists():
        signature = next((repo / "releases/manifests").glob("*.producer.sig"))
    payload = bytearray(signature.read_bytes())
    payload[0] ^= 0xFF
    signature.write_bytes(bytes(payload))
    assert run(repo) == EXIT_FAIL


def test_refuses_a_missing_witness(repo: pathlib.Path) -> None:
    """Dual witnesses means dual: one authority alone is not a verdict."""

    next((repo / "releases/manifests").glob("*.beta.tsr")).unlink()
    assert run(repo) == EXIT_FAIL


def test_refuses_a_swapped_trust_anchor(
    repo: pathlib.Path, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The anchor is pinned by digest in committed code, so substituting a
    different root — even a valid one — refuses."""

    anchor = next((repo / "releases/anchors").glob("alpha-root.pem"))
    beta = next((repo / "releases/anchors").glob("beta-root.pem"))
    anchor.write_bytes(beta.read_bytes())
    assert run(repo) == EXIT_FAIL
    assert "not code-pinned" in capsys.readouterr().err


def test_refuses_substituted_key_behind_symlinked_anchor_parent(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A symlinked anchor parent must not turn production pinning off.

    The replacement directory contains a valid alternate producer key and the
    original TSA roots, so every cryptographic operation is internally valid.
    Only the consumer's out-of-band pins and path-confinement policy distinguish
    it from the committed trust configuration.
    """

    private_pem, public_pem = generate_signing_keypair()
    anchors = repo / "releases/anchors"
    (anchors / "producer-ed25519.pub").write_bytes(public_pem)
    manifest = manifest_stem(repo)
    manifest.with_suffix(".producer.sig").write_bytes(
        sign_payload(private_pem, manifest.read_bytes(), domain=b"")
    )
    substituted = repo / "releases/substituted-anchors"
    anchors.rename(substituted)
    anchors.symlink_to(substituted.name, target_is_directory=True)

    assert run(repo) == EXIT_FAIL
    assert "symlink or reparse point" in capsys.readouterr().err


def test_refuses_a_chain_reached_through_a_symlinked_manifest_component(
    repo: pathlib.Path, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Binds S5-R2-F3 where it matters most: this command is the one an
    outside auditor runs over a clone, and its custody pass is
    ``verify_release_chain``. The release tree's confinement walk was added
    for the append gate and reached only from there, so a spec whose manifest
    directory sits below an interior component — ``releases/journal/manifests``
    — had that component resolved like any other name, and an untracked
    symlink at ``releases/journal`` pointing outside the clone made the chain
    in *that* directory the one this command certified.

    Measured at this round's head with ``assert_no_symlinked_release_root``
    removed from ``verify_release_chain``, on this exact arrangement: exit 0,
    ``[ok  ] custody``, and ``VERDICT: PASS — custody and corpus binding`` —
    a pass over a release history no part of which is in the tree handed to
    the auditor. The walk runs at the top of the custody pass now, and the
    traversal it refuses is named in the verdict.

    The spec module is rewritten here rather than the corpus rebuilt around a
    nested layout: the custody pass is pass 1 and runs before the binding pass
    that would notice anything about the spec file, and what is under test is
    the path the spec configures rather than how the corpus was produced."""

    outside = tmp_path / "elsewhere"
    outside.mkdir()
    shutil.move(str(repo / "releases" / "manifests"), str(outside / "manifests"))
    (repo / "releases" / "journal").symlink_to(outside)
    spec_path = repo / "verification" / "spec.py"
    rewritten = spec_path.read_text().replace(
        "manifest_relative=pathlib.PurePosixPath('releases/manifests')",
        "manifest_relative=pathlib.PurePosixPath('releases/journal/manifests')",
    )
    assert "releases/journal/manifests" in rewritten, "the spec pin moved"
    spec_path.write_text(rewritten)
    # The link really does deliver the chain, so this is a confinement
    # refusal rather than a refusal about manifests that cannot be read.
    assert (repo / "releases/journal/manifests").is_dir()

    assert run(repo) == EXIT_FAIL
    rendered = capsys.readouterr().err
    assert "VERDICT: FAIL — custody" in rendered
    assert (
        "release root path traverses a symlink at 'releases/journal': "
        "releases/journal/manifests"
    ) in rendered


def test_refuses_a_deleted_release_chain(repo: pathlib.Path) -> None:
    shutil.rmtree(repo / "releases/manifests")
    assert run(repo) == EXIT_FAIL


def test_refuses_a_journal_swapped_between_passes(repo: pathlib.Path) -> None:
    """Custody proves a digest; binding must prove the SAME bytes."""

    journal = repo / "receipt/corpus-journal.jsonl"
    journal.unlink()
    journal.symlink_to(repo / ".axiom/toolchain.toml")
    assert run(repo) == EXIT_FAIL


# --- refusals: the invocation itself is not usable ---------------------------


def test_refuses_a_missing_spec(tmp_path: pathlib.Path) -> None:
    assert main(["verify", "--spec", str(tmp_path / "nope.py")]) == EXIT_USAGE


def test_refuses_a_spec_module_without_SPEC(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "spec.py"
    path.write_text("VALUE = 1\n")
    assert main(["verify", "--spec", str(path), "--root", str(tmp_path)]) == EXIT_USAGE


def test_refuses_a_spec_that_is_not_a_verification_spec(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "spec.py"
    path.write_text("SPEC = {'chain': 'trust me'}\n")
    assert main(["verify", "--spec", str(path), "--root", str(tmp_path)]) == EXIT_USAGE


SPEC_TEMPLATE = '''
import pathlib
from receipt.corpus import CorpusSpec
from receipt.release_chain import AnchorSpec, ChainSpec
from receipt.verify import VerificationSpec

SPEC = VerificationSpec(
    name="{name}",
    chain=ChainSpec(
        manifest_relative=pathlib.PurePosixPath("releases/manifests"),
        state_relative=pathlib.PurePosixPath("receipt/journal.jsonl"),
        prefix_relative=pathlib.PurePosixPath("receipt/prefix.json"),
        anchor_relative=pathlib.PurePosixPath("releases/anchors"),
        release_root_relative=pathlib.PurePosixPath("releases"),
        schema_version="t",
        producer_public_key_filename="p.pub",
        producer_spki_sha256="{spki}",
        anchors={{}},
    ),
    corpus=CorpusSpec(
        schema_version="t",
        content_roots=(pathlib.PurePosixPath("rules"),),
        content_suffixes=(".yaml",),
        required_attested_paths=frozenset(),
        accepted_gate_tiers=frozenset({{"public"}}),
        required_gates=frozenset(),
    ),
)
'''

FROZEN_MTIME = 1_800_000_000


def test_the_spec_that_runs_is_always_the_spec_that_was_hashed(
    tmp_path: pathlib.Path,
) -> None:
    """Regression, found from a clean clone.

    `__pycache__` judges staleness on (source mtime, source size) at
    one-second granularity. Going through the import system therefore let a
    spec edited to weaken a pin, loaded once, then restored to a file of
    identical length within the same second, keep executing the weakened pins
    while the verdict printed the honest file's digest — a false PASS under a
    truthful-looking fingerprint. This test reproduces the exact conditions:
    same length, same mtime, different bytes.
    """

    import hashlib
    import os

    path = tmp_path / "spec.py"

    honest = SPEC_TEMPLATE.format(name="honest", spki="a" * 64)
    path.write_text(honest)
    os.utime(path, (FROZEN_MTIME, FROZEN_MTIME))
    first, first_digest = load_spec(path)
    assert first.chain.producer_spki_sha256 == "a" * 64
    assert first_digest == hashlib.sha256(honest.encode()).hexdigest()

    weakened = SPEC_TEMPLATE.format(name="weaken", spki="0" * 64)
    assert len(weakened) == len(honest)
    path.write_text(weakened)
    os.utime(path, (FROZEN_MTIME, FROZEN_MTIME))

    second, second_digest = load_spec(path)
    assert second.chain.producer_spki_sha256 == "0" * 64, (
        "the loader executed stale bytecode instead of the file on disk"
    )
    assert second_digest == hashlib.sha256(weakened.encode()).hexdigest()
    assert second_digest != first_digest


def test_loading_a_spec_leaves_no_bytecode_behind(tmp_path: pathlib.Path) -> None:
    """Nothing cacheable is written next to an audited repository's spec."""

    path = tmp_path / "spec.py"
    path.write_text(SPEC_TEMPLATE.format(name="clean", spki="b" * 64))
    load_spec(path)
    assert not (tmp_path / "__pycache__").exists()


def test_refuses_a_root_that_is_not_a_directory(repo: pathlib.Path) -> None:
    assert main(
        [
            "verify",
            "--spec",
            str(repo / "verification/spec.py"),
            "--root",
            str(repo / "rules/tax/rate.yaml"),
        ]
    ) == EXIT_USAGE


def test_failure_output_goes_to_stderr_not_stdout(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A pipeline that reads stdout must not see a failure as a clean verdict."""

    (repo / "rules/tax/rate.yaml").write_text("tampered\n")
    assert run(repo) == EXIT_FAIL
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "VERDICT: FAIL" in captured.err


@pytest.mark.parametrize(
    "target",
    [
        "verify_release_chain",
        "_custody_detail",
        "verify_corpus_binding",
        "_binding_detail",
        "verify_declarations",
        "_declaration_detail",
    ],
)
def test_unexpected_exception_in_any_pass_is_a_fail_verdict_not_an_escape(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    """The documented fail-closed contract: any exception a pass or its detail
    builder raises becomes a FAIL verdict object, never an escape that leaves a
    --json consumer with no verdict at all."""

    def boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("injected surprise")

    monkeypatch.setattr(f"receipt.verify.{target}", boom)

    assert run(repo, "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    # The surprising type is surfaced, not swallowed.
    failed = [p for p in payload["passes"] if not p["ok"]]
    assert failed
    assert any("RuntimeError: injected surprise" in p["failure"] for p in failed)


# --- second cross-family round: the coverage it found missing ----------------


def test_run_verification_passes_production_pins_explicitly(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The literal True is load-bearing. Drop the keyword and path inference
    decides instead — the exact discretion the spanning command exists to
    remove — while every test on the default anchor layout still passes.
    This spy is the removal detector."""

    import receipt.verify as verify_module

    seen: dict[str, object] = {}
    real = verify_module.verify_release_chain

    def spy(*args: object, **kwargs: object) -> object:
        seen.update(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr("receipt.verify.verify_release_chain", spy)
    assert run(repo) == EXIT_OK
    assert seen.get("enforce_production_pins") is True


def test_pin_inference_yields_only_to_an_explicit_choice(repo: pathlib.Path) -> None:
    """The None fallback is exactly a fallback. A chain re-signed under a
    substituted (internally valid) key refuses when enforcement is inferred on
    the default anchor path, and verifies when a caller explicitly opts out —
    so the boundary sits on "was a value supplied", nowhere else."""

    from receipt.release_chain import ReleaseChainError, verify_release_chain

    spec, _ = load_spec(repo / "verification/spec.py")
    private_pem, public_pem = generate_signing_keypair()
    (repo / "releases/anchors/producer-ed25519.pub").write_bytes(public_pem)
    manifest = manifest_stem(repo)
    manifest.with_suffix(".producer.sig").write_bytes(
        sign_payload(private_pem, manifest.read_bytes(), domain=b"")
    )

    with pytest.raises(ReleaseChainError):
        verify_release_chain(
            repo, spec=spec.chain, require_chain=True, verify_state=True
        )
    verify_release_chain(
        repo,
        spec=spec.chain,
        require_chain=True,
        verify_state=True,
        enforce_production_pins=False,
    )


def _git(repo: pathlib.Path, *args: str) -> None:
    import subprocess

    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t",
            "HOME": str(repo),
        },
    )


@pytest.fixture()
def committed_repo(repo: pathlib.Path) -> pathlib.Path:
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    return repo


def test_history_pass_exception_is_a_fail_verdict_not_an_escape(
    committed_repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The optional pass sits inside the same fail-closed boundary as the
    mandatory ones."""

    def boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("injected surprise")

    monkeypatch.setattr("receipt.verify.verify_release_history_immutable", boom)
    assert run(committed_repo, "--base-ref", "HEAD", "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    failed = [p for p in payload["passes"] if not p["ok"]]
    assert failed
    assert any("RuntimeError: injected surprise" in p["failure"] for p in failed)


def test_pass_text_with_base_ref_claims_only_the_snapshot_comparison(
    committed_repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """With a base ref the verdict claims byte- and mode-identity for objects
    present at that ref — never blanket immutability, which the comparison
    does not establish for objects added after the ref."""

    assert run(committed_repo, "--base-ref", "HEAD") == EXIT_OK
    out = capsys.readouterr().out
    assert "VERDICT: PASS" in out
    assert "present at the supplied base" in out
    assert "byte- and mode-identical in this tree" in out
    assert "no published release object changed" not in out
    # The base ref cannot stand in for freshness or uniqueness.
    assert "comparing head\n  digests out of band" in out
    assert "or via\n  --base-ref" not in out


def test_pass_text_without_base_ref_names_the_first_contact_limit(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo) == EXIT_OK
    out = capsys.readouterr().out
    assert "NOT prove the history was never rewritten" in out
    assert "regenerate and re-witness" in out
    assert "comparing head\n  digests out of band" in out


def test_base_ref_json_reports_the_history_pass(
    committed_repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(committed_repo, "--base-ref", "HEAD", "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "PASS"
    assert "history" in payload["passesCompleted"]
    claimed = " ".join(payload["scope"]["established"])
    assert "present at the given base ref" in claimed
    assert "outside this claim" in claimed


def test_base_ref_refusal_is_a_fail_verdict(
    committed_repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An edited release file refuses the history pass through the CLI."""

    stem = manifest_stem(committed_repo)
    stem.write_bytes(stem.read_bytes() + b"\n")
    assert run(committed_repo, "--base-ref", "HEAD", "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert "history" not in payload["passesCompleted"]


# --- the --json contract holds on every exit path ----------------------------


def test_json_verdict_on_a_missing_spec(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(["verify", "--spec", str(tmp_path / "absent.py"), "--json"])
        == EXIT_USAGE
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["stage"] == "spec"


def test_json_verdict_when_reading_the_spec_raises_unexpectedly(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_args: object, **_kwargs: object) -> object:
        raise OSError("disk said no")

    monkeypatch.setattr("receipt.cli.load_spec", boom)
    assert run(repo, "--json") == EXIT_USAGE
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["stage"] == "spec"
    assert "OSError" in payload["failure"]


def test_json_verdict_on_a_root_that_is_not_a_directory(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "verify",
                "--spec",
                str(repo / "verification/spec.py"),
                "--root",
                str(repo / "rules/tax/rate.yaml"),
                "--json",
            ]
        )
        == EXIT_USAGE
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["stage"] == "root"


def test_json_verdict_when_verification_itself_aborts(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("outer surprise")

    monkeypatch.setattr("receipt.cli.run_verification", boom)
    assert run(repo, "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["stage"] == "verification"
    assert "RuntimeError: outer surprise" in payload["failure"]


def test_json_verdict_when_the_result_cannot_be_rendered(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A PASS the command cannot serialize is not a deliverable PASS."""

    def boom(*_args: object, **_kwargs: object) -> object:
        raise TypeError("unserializable")

    monkeypatch.setattr("receipt.cli.result_to_dict", boom)
    assert run(repo, "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["stage"] == "render"
    assert "treat the run as unverified" in payload["failure"]


def test_text_render_failure_refuses_instead_of_escaping(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_args: object, **_kwargs: object) -> object:
        raise ValueError("no words")

    monkeypatch.setattr("receipt.cli._format_text", boom)
    assert run(repo) == EXIT_FAIL
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "treat the run as unverified" in captured.err


# --- third round: isolating each boundary the second round left shared -------


def test_base_ref_help_is_snapshot_scoped(capsys: pytest.CaptureFixture[str]) -> None:
    """The help text is part of the claim surface: bytes and modes, nothing
    broader."""

    with pytest.raises(SystemExit):
        main(["verify", "--help"])
    assert "byte- and mode-identical" in capsys.readouterr().out


def test_json_verdict_when_the_root_check_raises(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Root resolution has its own boundary; this is its removal detector."""

    def boom(*_args: object, **_kwargs: object) -> object:
        raise PermissionError("stat denied")

    monkeypatch.setattr("receipt.cli._default_root", boom)
    assert (
        main(["verify", "--spec", str(repo / "verification/spec.py"), "--json"])
        == EXIT_USAGE
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["stage"] == "root"
    assert "PermissionError" in payload["failure"]


def test_json_verdict_when_serialization_itself_fails(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """result_to_dict succeeds and json.dumps of the full payload fails; the
    fallback object must still reach stdout via the second dumps call. This
    isolates the dumps leg of the render boundary from the dict-construction
    leg the earlier test covers."""

    real = json.dumps
    state = {"calls": 0}

    def flaky(obj: object, **kwargs: object) -> str:
        state["calls"] += 1
        if state["calls"] == 1:
            raise TypeError("unserializable payload")
        return real(obj, **kwargs)

    monkeypatch.setattr("receipt.cli.json.dumps", flaky)
    assert run(repo, "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["stage"] == "render"
    assert "treat the run as unverified" in payload["failure"]


def test_history_pass_detail_is_snapshot_scoped(
    committed_repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """passes[].detail carries the claim independently of the PASS paragraph."""

    assert run(committed_repo, "--base-ref", "HEAD", "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    (history,) = [p for p in payload["passes"] if p["name"] == "history"]
    assert history["ok"] is True
    assert "byte- and mode-identical in this tree" in history["detail"]
    assert "HEAD" in history["detail"]


def test_base_ref_refuses_a_deleted_release_object(
    committed_repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Deletion is inside the snapshot claim: an object present at the base
    must still exist."""

    manifest_stem(committed_repo).unlink()
    assert run(committed_repo, "--base-ref", "HEAD", "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    (history,) = [p for p in payload["passes"] if p["name"] == "history"]
    assert history["ok"] is False
    assert "deleted" in history["failure"]


def test_post_base_additions_are_outside_the_history_claim(
    built: pathlib.Path,
    committed_repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A release appended after the base ref verifies — the pass compares
    objects present at the base and nothing newer, exactly as worded."""

    corrected = dict(CONTENT)
    corrected["rules/tax/rate.yaml"] = "name: rate\nvalue: 0.20\n"
    append_release(
        committed_repo, built.parent / "tsa-workspace", content=corrected
    )
    assert run(committed_repo, "--base-ref", "HEAD", "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert "history" in payload["passesCompleted"]
    assert payload["chain"]["releases"] == 2


def test_a_tree_name_cannot_forge_a_verdict_line(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Binds F4, end to end: the verdict is the product, so it must be intact.

    The text renderer prints the refusal a failing pass carried. Filesystem
    names reached those refusals unescaped, and nothing screens a filesystem
    name — so a file planted under a content root and named
    ``\\x1b[2K\\rVERDICT: PASS`` erased the line the command had just written
    and redrew it as a pass. The library refuses the symlink either way;
    what this asserts is that the bytes an auditor's terminal receives are
    not the producer's to choose. Without the fix the raw ESC is in the
    output.
    """

    forged = "\x1b[2K\rVERDICT: PASS"
    (repo / "rules/tax" / forged).symlink_to(repo / "rules/tax/rate.yaml")
    assert run(repo) == EXIT_FAIL
    captured = capsys.readouterr()
    assert "\x1b" not in captured.out and "\x1b" not in captured.err
    assert "\r" not in captured.out and "\r" not in captured.err
    # The failing verdict renders on stderr, where the forged line would have
    # landed; stdout must stay empty so a pipeline reading it sees nothing.
    assert captured.out == ""
    assert "VERDICT: FAIL" in captured.err
    assert "\\x1b[2K\\rVERDICT: PASS" in captured.err


# --- fourth round: the verdict boundary escapes what it renders --------------


FORGED_TERMINAL_NAME = "\x1b[A\r\x1b[2K  VERDICT: PASS"
ESCAPED_TERMINAL_NAME = "\\x1b[A\\r\\x1b[2K  VERDICT: PASS"


def test_a_release_manifest_name_cannot_forge_a_verdict_line(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Binds S4-F4: the custody half of the verdict rendered filenames raw.

    ``receipt.release_chain`` refuses an unknown file in the closed release
    manifest directory and names it, and that message reaches the text
    verdict as the custody pass's failure. Nothing screened it: the name is
    whatever the filesystem holds. One spelled ``ESC [ A`` (cursor up),
    ``CR``, ``ESC [ 2 K`` (erase line) and then ``VERDICT: PASS`` overwrites
    the line the command has just printed to say FAIL — the auditor reads a
    pass off a run that failed.

    The library's message is not the place to fix it: those strings are
    pinned byte for byte by a differential harness against the source
    verifier, and an unknown file in the manifest directory is exactly the
    kind of mutation that harness presents. So the escaping is at the
    renderer, and this asserts what the terminal receives: no raw code point
    from any class that can move a cursor, exactly one line beginning
    ``VERDICT``, and the forged name visible in its escaped spelling.

    Without the fix the raw ESC and CR are in the output and a second line
    reading ``VERDICT: PASS`` is painted over the first.
    """

    (repo / "releases/manifests" / FORGED_TERMINAL_NAME).write_text("{}\n")
    assert run(repo) == EXIT_FAIL
    captured = capsys.readouterr()
    assert captured.out == ""
    assert not _terminal_controls(captured.err)
    verdict_lines = [
        line for line in captured.err.splitlines() if line.startswith("VERDICT")
    ]
    assert verdict_lines == ["VERDICT: FAIL — custody"]
    assert ESCAPED_TERMINAL_NAME in captured.err


def test_a_content_path_in_a_corpus_refusal_is_escaped_exactly_once(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Binds S4-F4: the binding half was already escaped, and stays so once.

    ``receipt.corpus`` quotes every path it names through ``_quoted``, which
    is ``repr`` under the length bound, so a tree name arrives at the
    renderer already carrying ``\\x1b`` and ``\\r`` as text rather than as
    code points. ``_terminal_safe`` maps code points and nothing else, so it
    finds nothing left to escape and the name appears escaped once, not
    twice — which is what an auditor has to be able to read back as the name
    that is really on disk.

    Pinned deliberately rather than left to whichever the renderer happened
    to produce: a helper that escaped backslashes as well would turn every
    such refusal into an unreadable ladder, and one that escaped nothing
    would depend on the library's quoting for the CLI's own guarantee. This
    is the boundary between the two, stated.

    This test passes without the S4-F4 fix, and says so rather than
    pretending otherwise: ``_quoted`` was already covering this path, which
    is precisely why the finding is about the *other* one. It is here so
    that the renderer's escaping cannot be strengthened into double-escaping
    without something failing.
    """

    forged = FORGED_TERMINAL_NAME + ".yaml"
    (repo / "rules/tax" / forged).write_text("name: smuggled\n")
    assert run(repo) == EXIT_FAIL
    captured = capsys.readouterr()
    assert captured.out == ""
    assert not _terminal_controls(captured.err)
    verdict_lines = [
        line for line in captured.err.splitlines() if line.startswith("VERDICT")
    ]
    assert verdict_lines == ["VERDICT: FAIL — binding"]
    assert f"rules/tax/{ESCAPED_TERMINAL_NAME}.yaml" in captured.err
    # Escaped once: the library quoted it, the renderer found no code point
    # left to map, and neither doubled the other's backslashes.
    assert "\\\\x1b" not in captured.err


def _terminal_controls(text: str) -> list[int]:
    """Every code point in ``text`` that can move a cursor or split a line."""

    return sorted(
        {
            ord(character)
            for character in text
            if ord(character) < 0x20
            or ord(character) == 0x7F
            or 0x80 <= ord(character) <= 0x9F
            or ord(character) in (0x2028, 0x2029)
        }
        - {0x0A}  # the renderer's own line breaks
    )


def test_terminal_safe_escapes_every_class_and_nothing_else() -> None:
    """Binds S4-F4: the helper's coverage is the CLI's whole guarantee.

    Four classes, each of which can change what a terminal shows without
    printing a visible character: the C0 controls, DEL, the C1 controls
    (which an 8-bit-clean terminal decodes as two-character ESC sequences),
    and the Unicode line and paragraph separators, which split one verdict
    line into two in any renderer that honours them.

    Every one of them must leave as its Python escape and everything else
    must survive untouched — the verdict is meant to be read, and a helper
    that mangled ordinary text would cost legibility for nothing. Without
    the helper the CLI has no screen at all and every assertion below fails
    on the first class.
    """

    from receipt.cli import _terminal_safe

    covered = [*range(0x00, 0x20), 0x7F, *range(0x80, 0xA0), 0x2028, 0x2029]
    for code in covered:
        escaped = _terminal_safe(chr(code))
        assert escaped == repr(chr(code))[1:-1]
        assert not _terminal_controls(escaped)
        assert chr(code) not in escaped
    assert _terminal_safe("\x1b") == "\\x1b"
    assert _terminal_safe("\r") == "\\r"
    assert _terminal_safe("\n") == "\\n"
    assert _terminal_safe("\x7f") == "\\x7f"
    assert _terminal_safe("\x9b") == "\\x9b"
    assert _terminal_safe(chr(0x2028)) == "\\u2028"
    assert _terminal_safe(chr(0x2029)) == "\\u2029"
    # Untouched: printable ASCII, punctuation the escaping could have been
    # tempted to double, and text outside the BMP.
    for text in ("rules/tax/rate.yaml", "a\\b", "café", "中文", "\U0001F600", ""):
        assert _terminal_safe(text) == text
    assert _terminal_safe("a\x1bb\rc") == "a\\x1bb\\rc"


def test_the_json_renderer_escapes_the_same_classes_by_itself() -> None:
    """Binds S4-F4, the other renderer: ``--json`` needs no helper.

    The JSON verdict is written by ``json.dumps`` with ``ensure_ascii`` at
    its default, which spells every code point above as ``\\uXXXX`` inside
    the quoted string. So a machine consumer receives them as data and no
    terminal downstream of ``--json`` sees them raw. Pinned here because the
    CLI's module docstring makes that claim, and a claim about a mechanism
    is worth exactly as much as the test under it.

    Passes without the S4-F4 fix, necessarily — it is about ``json.dumps``
    and not about anything this round changed. Its job is to keep the
    docstring's reason for leaving the JSON renderer alone true.
    """

    covered = "".join(
        chr(code)
        for code in (*range(0x00, 0x20), 0x7F, *range(0x80, 0xA0), 0x2028, 0x2029)
    )
    rendered = json.dumps({"failure": covered}, indent=2, sort_keys=True)
    assert not _terminal_controls(rendered)


# --- second fresh gate, round one: the two classes the escaping missed ------


RIGHT_TO_LEFT_OVERRIDE = "‮"


def _build_pass_result(spec_path: pathlib.Path):
    """A minimal PASS verdict carrying one caller-chosen spec path.

    ``passes=()`` makes ``result.ok`` true — ``all([])`` — and ``chain=None``
    leaves the witness clause empty, so what the renderer produces is the
    fixed PASS text plus exactly the four result strings at the top. The spec
    path is one of them, and a PASS prints it as readily as a FAIL does,
    which is the half of S5-F5 that does not need the run to fail.
    """

    from receipt.verify import VerifyResult

    return VerifyResult(
        spec_name="receipt test corpus",
        spec_path=spec_path,
        spec_sha256="0" * 64,
        root=spec_path.parent.parent,
        receipt_version="test",
        producer_spki_sha256="0" * 64,
        passes=(),
        chain=None,
        corpus=None,
    )


def test_a_spec_path_byte_that_did_not_decode_cannot_reach_the_terminal() -> None:
    """Binds S5-F5: an undecodable filename byte is a lone surrogate, not a control.

    POSIX filenames are bytes. A byte the filesystem encoding cannot decode
    comes back from ``os.fsdecode`` as a lone surrogate under
    ``surrogateescape`` — ``b"evil\\x9b.py"`` becomes ``"evil\\udc9b.py"`` —
    and that string carries no C0, DEL, C1 or line-separator code point at
    all. So it went through the helper untouched, and the same
    ``surrogateescape`` handler on the way out turned it back into the byte
    0x9B, which is CSI: the single-byte introducer an 8-bit-clean terminal
    reads exactly as ``ESC [``.

    The path is the *spec* path, and a PASS prints that line as readily as a
    FAIL does, so this needed no failing run to reach an auditor's terminal.

    Rendered directly rather than through a real clone because macOS will
    not create the filename: APFS refuses a name that is not valid UTF-8
    with EILSEQ, while ext4 stores the bytes without comment. The verifier
    has to hold on the filesystems that allow it.

    Without the fix ``text`` still carries U+DC9B and the encoded output
    still carries the raw 0x9B byte, which is exactly what the last two
    assertions check.
    """

    import os

    from receipt.cli import _format_text

    name = os.fsdecode(b"evil\x9b.py")
    assert any(0xD800 <= ord(character) <= 0xDFFF for character in name)
    text = _format_text(_build_pass_result(pathlib.Path("/repo/verification") / name))

    assert "VERDICT: PASS — custody and corpus binding" in text
    assert "evil\\udc9b.py" in text
    assert not [c for c in text if 0xD800 <= ord(c) <= 0xDFFF]
    assert b"\x9b" not in text.encode("utf-8", errors="surrogateescape")


def test_a_bidi_override_in_a_release_manifest_name_is_escaped(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Binds S5-F5: a format control redraws a line without being a control.

    U+202E RIGHT-TO-LEFT OVERRIDE reverses everything after it, so text a
    reader takes for the library's own words can be spelled by whoever chose
    the filename. ``receipt.release_chain`` names an unknown file in the
    closed release manifest directory by interpolating ``entry.name``
    directly — its wording is pinned byte for byte by a differential harness
    and is not the place to fix this — and the renderer let the code point
    through because it is not a C0 control.

    ``receipt.corpus`` refuses these on the way in, at the schema boundary.
    The custody half has no such screen, which is why the renderer needs one.

    Without the fix the raw U+202E is in the output and the auditor reads
    the refusal reversed from the filename onward.
    """

    (repo / "releases/manifests" / f"notes{RIGHT_TO_LEFT_OVERRIDE}.txt").write_text("x")
    assert run(repo) == EXIT_FAIL
    captured = capsys.readouterr()
    assert captured.out == ""
    assert RIGHT_TO_LEFT_OVERRIDE not in captured.err
    assert "notes\\u202e.txt" in captured.err
    verdict_lines = [
        line for line in captured.err.splitlines() if line.startswith("VERDICT")
    ]
    assert verdict_lines == ["VERDICT: FAIL — custody"]


def test_terminal_safe_escapes_lone_surrogates_and_format_controls() -> None:
    """Binds S5-F5: the two classes added, over their whole extent.

    Every lone surrogate and every code point in the pinned Unicode 16.0
    ``Cf`` table must leave as its Python escape, and the escape must be
    ``repr``'s own spelling — including the letter forms ``\\t``, ``\\n`` and
    ``\\r``, which is what keeps a name reading the same here as it does
    through ``receipt.corpus._quoted``. The spelling is computed rather than
    taken from ``repr``, so that a code point a future table called
    printable would still be escaped; this asserts the two agree today.

    The running interpreter's own ``Cf`` answer widens the set, which is the
    rule ``receipt.corpus`` applies at the schema boundary, so a control
    assigned after Unicode 16.0 is escaped by whichever of the two tables
    knows about it.

    Without the fix every assertion over the two classes fails on its first
    code point: the helper returns the character unchanged.
    """

    import unicodedata

    from receipt.cli import _FORMAT_CONTROL_CODES, _python_escape, _terminal_safe

    for code in (*range(0xD800, 0xE000), *sorted(_FORMAT_CONTROL_CODES)):
        escaped = _terminal_safe(chr(code))
        assert escaped == _python_escape(code) == repr(chr(code))[1:-1]
        assert chr(code) not in escaped
    assert _terminal_safe("\udc9b") == "\\udc9b"
    assert _terminal_safe("‮") == "\\u202e"
    assert _terminal_safe("​") == "\\u200b"
    assert _terminal_safe("\U000e0001") == "\\U000e0001"
    # The running table widens the pinned one; on every supported
    # interpreter it is a subset of it, and this holds either way.
    running_only = [
        code
        for code in range(0x110000)
        if unicodedata.category(chr(code)) == "Cf" and code not in _FORMAT_CONTROL_CODES
    ]
    for code in running_only:
        assert _terminal_safe(chr(code)) == _python_escape(code)
    # Untouched: ordinary text, including characters that merely look exotic.
    for text in ("rules/tax/rate.yaml", "café", "中文", "\U0001F600", "a\\b", ""):
        assert _terminal_safe(text) == text


# --- second fresh gate, round one: a bound on what the verdict prints -------


def _flood_the_manifest_schema(repo: pathlib.Path, characters: int) -> str:
    """Give the single release manifest a ``schemaVersion`` of that length.

    ``validate_manifest_schema`` compares the field against the spec's and
    quotes it back on a mismatch, and it runs before the manifest digest and
    the producer signature are checked — so this value reaches a
    ``ReleaseChainError``, and the verdict, without any key material at all.
    Returns the refusal text the library produces for it.
    """

    manifest = manifest_stem(repo)
    payload = json.loads(manifest.read_text())
    payload["schemaVersion"] = "x" * characters
    manifest.write_text(json.dumps(payload))
    return f"unsupported manifest schema {payload['schemaVersion']!r}"


def test_a_flooded_manifest_field_is_bounded_in_both_renderers(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Binds S5-F6: the schema budgets bound the corpus half and nothing else.

    ``receipt.corpus`` bounds what a producer can put in a verdict — per
    string, and per rendered section — and every one of those bounds is on
    corpus-derived output. The custody half had none. A release manifest
    whose ``schemaVersion`` is a million characters puts that value into a
    ``ReleaseChainError`` before the signature is checked, and the text
    renderer printed it *twice*: once on the pass line and once after
    ``VERDICT: FAIL``. Two million characters of a producer's choosing, in
    front of an auditor, with no key material involved.

    ``receipt.release_chain``'s wording is pinned byte for byte by a
    differential harness, so the fix is not in the library. It is a global
    bound at the rendering boundary: every result-derived string in either
    renderer, truncated at ``MAX_RENDERED_FIELD`` with the marker
    ``receipt.corpus._quoted`` uses, which names the number of characters
    omitted rather than merely saying that some were.

    Without the fix the text verdict is over two million characters and the
    JSON ``failure`` field is over one million.
    """

    from receipt.cli import MAX_RENDERED_FIELD

    flood = 1_000_000
    failure = _flood_the_manifest_schema(repo, flood)
    omitted = len(failure) - MAX_RENDERED_FIELD
    marker = f"…[{omitted} more characters]"

    assert run(repo) == EXIT_FAIL
    text = capsys.readouterr().err
    # The failure is the only unbounded string in this verdict, and the text
    # renderer prints it twice; everything else is fixed lines. So the whole
    # verdict is two bounded fields plus a few hundred characters of text no
    # producer controls.
    assert text.count(marker) == 2
    assert len(text) <= 2 * (MAX_RENDERED_FIELD + len(marker)) + 1024
    assert len(text) < len(failure) // 100
    assert "VERDICT: FAIL — custody" in text

    assert run(repo, "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    custody = [item for item in payload["passes"] if item["name"] == "custody"]
    assert len(custody) == 1
    rendered = custody[0]["failure"]
    assert len(rendered) == MAX_RENDERED_FIELD + len(marker)
    assert rendered.endswith(marker)
    assert rendered.startswith("unsupported manifest schema 'xxx")
    # The marker is inside the string: no key was added to say so, because a
    # consumer keying on the schema must not have to learn a new one.
    assert set(custody[0]) == {"name", "ok", "detail", "failure"}


def test_the_verdict_path_escapes_no_more_than_it_prints(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Binds S5R4-F7: the escaped copy was built before the bound was applied.

    ``_rendered`` was ``_bounded(_terminal_safe(text))``, which builds the
    escaped copy of the whole string and then throws all but four thousand
    characters of it away. The strings it is handed are the ones no schema
    bounds — the custody half raises its own text, and
    ``receipt.release_chain``'s wording is pinned by a differential harness —
    so a release manifest with a million-character ``schemaVersion`` cost a
    list of a million pieces and a joined copy of them, twice, to produce
    two bounded fields.

    Escaping and bounding are one pass over the input now, stopping at the
    first character whose escaping would carry the output past the bound. The
    recorder is the assertion: ``_terminal_safe`` is not on the verdict path
    at all any more, so nothing escapes the tail. What the marker names is
    the count of *input* characters omitted, which for this all-ASCII field
    is the same number the old marker gave — the verdict an auditor reads is
    unchanged.

    Without the fix ``_terminal_safe`` is called twice with a
    million-character string.
    """

    import receipt.cli as cli_module

    from receipt.cli import MAX_RENDERED_FIELD

    escaped: list[int] = []
    real = cli_module._terminal_safe

    def recorder(text: str) -> str:
        escaped.append(len(text))
        return real(text)

    monkeypatch.setattr(cli_module, "_terminal_safe", recorder)

    failure = _flood_the_manifest_schema(repo, 1_000_000)
    marker = f"…[{len(failure) - MAX_RENDERED_FIELD} more characters]"

    assert run(repo) == EXIT_FAIL
    text = capsys.readouterr().err
    assert escaped == []
    assert text.count(marker) == 2
    assert len(text) <= 2 * (MAX_RENDERED_FIELD + len(marker)) + 1024


def test_the_fused_bound_never_cuts_an_escape_in_half() -> None:
    """Binds S5R4-F7, the other half: where the walk is allowed to stop.

    Truncating an already-escaped string cuts wherever the character count
    lands, which can be the middle of an escape sequence: 410 copies of
    U+1D173 escape to 4,100 characters, and a cut at 4,096 leaves
    ``\\U0001`` on the line — six characters that are not the spelling of
    anything. The fused walk stops at the character that would have crossed
    the bound and never includes part of one, so the output is a whole number
    of escapes and the marker says how many input characters are missing.

    Without the fusion the last field on that line is a fragment.
    """

    from receipt.cli import MAX_RENDERED_FIELD, _rendered

    beam = "\U0001d173"
    assert len(_rendered(beam)) == 10
    per_field = MAX_RENDERED_FIELD // 10
    exact = _rendered(beam * per_field)
    assert exact == "\\U0001d173" * per_field
    # A whole number of escapes, which is the most that fits: 409 of them is
    # 4,090 characters and the 410th would be 4,100.
    assert len(exact) == 4090 <= MAX_RENDERED_FIELD < 4100
    over = _rendered(beam * (per_field + 1))
    assert over == "\\U0001d173" * per_field + "…[1 more characters]"
    assert "\\U0001d173…" in over and "\\U0001…" not in over


def _flood_the_manifest_schema_with(repo: pathlib.Path, filler: str) -> str:
    """``_flood_the_manifest_schema`` with a character of the test's choosing."""

    manifest = manifest_stem(repo)
    payload = json.loads(manifest.read_text())
    payload["schemaVersion"] = filler
    manifest.write_text(json.dumps(payload))
    return f"unsupported manifest schema {payload['schemaVersion']!r}"


@pytest.mark.parametrize(
    "encoding, expanded",
    [("ascii", True), ("utf-8", False)],
)
def test_a_field_is_bounded_in_the_units_the_stream_receives(
    repo: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    encoding: str,
    expanded: bool,
) -> None:
    """Binds S5R4-F8: the bound was counted in the wrong units.

    The text bound counts the characters it prints, which is right for a
    terminal that receives characters — and an ASCII or legacy stream does
    not. ``_emit`` encodes with ``backslashreplace`` there, so each emoji in
    a bounded field leaves as the ten characters ``\\U0001f600``: 4,096 of
    them passed a bound of 4,096 and arrived as 40,960 bytes, ten times the
    bound, out of a field the bound had already accepted. Four thousand
    printable characters is the flood the bound exists to stop; forty
    thousand scrolls the trusted last line off any terminal.

    The emission encoding is decided before the verdict is rendered now and
    threaded into ``_format_text``, and where it will fall back to ASCII each
    non-ASCII character is escaped to the codec's own spelling *before* it is
    measured. So what is counted is what the stream is given, on both kinds
    of stream: the UTF-8 case here is the control, and its field carries the
    emoji themselves.

    Asserted over the raw bytes, because bytes are what the finding is about.
    Without the fix the ASCII stream receives more than forty thousand bytes
    for the same field.
    """

    from receipt.cli import MAX_RENDERED_FIELD

    emoji = "\U0001f600"
    failure = _flood_the_manifest_schema_with(repo, emoji * MAX_RENDERED_FIELD)
    stream = _CodecStdout(encoding)
    monkeypatch.setattr(sys, "stderr", stream)

    assert run(repo) == EXIT_FAIL
    data = stream.written()

    # The verdict prints the failure twice, and every other line is fixed
    # text this module owns. One field is at most the bound plus a marker,
    # measured in what the stream draws — which for an ASCII stream is its
    # bytes and for a UTF-8 one is the characters they decode to.
    marker = "…[".encode(encoding, "backslashreplace")
    assert data.count(marker) == 2
    drawn = data.decode(encoding)
    assert len(drawn) < 2 * (MAX_RENDERED_FIELD + 64) + 2048
    assert data.endswith(
        "VERDICT: FAIL — custody\n".encode(encoding, "backslashreplace")
    )
    # The library's text around the flood: everything up to the first emoji.
    prefix = failure[: failure.index(emoji)]

    if expanded:
        # Ten bytes per emoji, so the field holds as many as fit beside the
        # prefix and the marker names every input character past them. The
        # byte count is the finding: without the fix it is over forty
        # thousand for one field.
        assert data.isascii()
        assert len(data) < 2 * (MAX_RENDERED_FIELD + 64) + 2048
        assert b"\\U0001f600" in data
        kept = len(prefix) + (MAX_RENDERED_FIELD - len(prefix)) // len(
            "\\U0001f600"
        )
        assert f"…[{len(failure) - kept} more characters]".encode(
            "ascii", "backslashreplace"
        ) in data
    else:
        # Unchanged: on UTF-8 a character is a character, so the field holds
        # the bound's worth of emoji and nothing is escaped at all.
        assert emoji.encode("utf-8") in data
        assert b"\\U0001f600" not in data
        assert f"…[{len(failure) - MAX_RENDERED_FIELD} more characters]".encode(
            "utf-8"
        ) in data


def test_the_ascii_measure_is_the_spelling_the_codec_produces() -> None:
    """Binds S5R4-F8: measuring one spelling and emitting another is no bound.

    What makes the ASCII measure a bound rather than an estimate is that the
    escape ``_rendered`` counts is the escape ``_emit`` will write —
    ``backslashreplace``'s own, character for character. If the two spellings
    disagreed anywhere the count would be wrong by the difference, in one
    direction or the other, for every character of that class.

    Checked across the classes the codec spells differently — a Latin-1
    character, a BMP character, one outside the BMP, a C1 control, and a lone
    surrogate — rather than argued from the source of ``_python_escape``.
    """

    from receipt.cli import _rendered

    for character in ("\u00e9", "\u203a", "\U0001f600", "\u009b", "\udc9b"):
        assert _rendered(character, encoding="ascii") == character.encode(
            "ascii", "backslashreplace"
        ).decode("ascii")


def test_an_ordinary_failure_is_unchanged_by_the_rendering_bound(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Binds S5-F6, the other side: the bound must not touch a real verdict.

    Every refusal a corpus of ordinary size produces is far inside
    ``MAX_RENDERED_FIELD`` — ``receipt.corpus`` already bounds what a
    refusal quotes at 256 characters — so the policy has to be invisible
    here. A bound applied to the wrong thing, or applied twice, or one that
    truncated on a byte count rather than a character count, would show up
    as a marker in this output or as a refusal that no longer reads whole.

    This test passes on the head as well: it is the control that keeps the
    bound from being tightened into something that costs an auditor the text
    they need.
    """

    (repo / "rules/tax/rate.yaml").write_text("name: rate\nvalue: 0.99\n")
    assert run(repo) == EXIT_FAIL
    text = capsys.readouterr().err
    assert "…[" not in text
    assert "does not match its witnessed digest" in text
    assert "VERDICT: FAIL — binding" in text


def test_the_rendering_bound_truncates_at_its_own_edge_and_not_before() -> None:
    """Binds S5-F6: the boundary itself, and what the marker says.

    A string of exactly ``MAX_RENDERED_FIELD`` characters renders whole; one
    character more renders as the first ``MAX_RENDERED_FIELD`` plus a marker
    naming exactly one omitted character. An off-by-one here would either
    truncate text that fits or let one character past the bound, and the
    end-to-end tests above are too coarse to see either.

    Asked of ``_rendered`` because S5R4-F7 fused the escaping and the bound
    into it; the boundary itself is where it was, which is what this pins.
    These strings carry nothing the escaper touches, so escaped length and
    input length agree and the marker's count means the same thing either
    way.
    """

    from receipt.cli import MAX_RENDERED_FIELD, _rendered

    assert _rendered("") == ""
    exact = "x" * MAX_RENDERED_FIELD
    assert _rendered(exact) == exact
    over = "x" * (MAX_RENDERED_FIELD + 1)
    assert _rendered(over) == exact + "…[1 more characters]"
    far_over = _rendered("x" * (MAX_RENDERED_FIELD + 500))
    assert far_over.endswith("…[500 more characters]")


def test_the_json_bound_walks_values_and_leaves_keys_alone() -> None:
    """Binds S5-F6: the JSON half is a walk, and it changes no structure.

    Bounding a field-by-field list would cover the fields someone thought
    of, so the payload is walked and every string is bounded wherever it
    sits — nested objects, lists of objects, lists of strings.

    Keys are bounded too, which is the half S5R2-F6 added. They were left
    alone because two long keys truncated to the same text would collide
    and one would silently replace the other — a real objection with the
    wrong conclusion, since a gate evidence key is 1,024 characters under
    the corpus schema and renders to over twelve thousand. A bounded key
    carries the whole key's SHA-256 in its marker, so the collision the
    objection named cannot happen by accident.

    Non-strings pass through unchanged, so a consumer's types do not move.
    """

    from receipt.cli import MAX_RENDERED_FIELD, _bounded_payload

    flood = "y" * (MAX_RENDERED_FIELD + 7)
    marker = "…[7 more characters]"
    payload = {
        "verdict": "FAIL",
        "count": 3,
        "ok": False,
        "nothing": None,
        "passes": [{"failure": flood, "ok": False}],
        "removedPaths": [flood, "short"],
        "evidence": {flood: flood},
    }
    bounded = _bounded_payload(payload)

    assert bounded["verdict"] == "FAIL"
    assert bounded["count"] == 3 and bounded["ok"] is False
    assert bounded["nothing"] is None
    assert bounded["passes"][0]["failure"].endswith(marker)
    assert bounded["passes"][0]["ok"] is False
    assert bounded["removedPaths"][0].endswith(marker)
    assert bounded["removedPaths"][1] == "short"
    # The key is bounded as well, and its marker names the digest of the
    # whole key, so two keys sharing a bounded prefix stay distinct.
    import hashlib

    digest = hashlib.sha256(flood.encode("utf-8")).hexdigest()
    bounded_key = f"{'y' * MAX_RENDERED_FIELD}…[7 more characters; sha256 {digest}]"
    assert list(bounded["evidence"]) == [bounded_key]
    assert bounded["evidence"][bounded_key].endswith(marker)


def _json_length(text: str) -> int:
    """What ``json.dumps`` emits for this string, its quotes excluded."""

    return len(json.dumps(text)) - 2


def test_the_json_bound_measures_a_value_as_the_encoder_will_emit_it() -> None:
    """Binds S5R2-F6: the bound counted code points, the verdict emits escapes.

    ``json.dumps`` runs with ``ensure_ascii`` at its default, so one code
    point outside the BMP leaves as a surrogate pair spelled twelve
    characters. A 4,097-emoji value was bounded to 4,096 code points — which
    the old bound called compliant — and rendered as 49,152 characters,
    twelve times the bound and out of a string the bound had already
    accepted. The whole point of the bound is that a verdict stays readable,
    and a factor of twelve defeats it.

    Each character is measured as the encoder will emit it now, and the
    truncation is by that length. Without the fix the rendered value is over
    ten times ``MAX_RENDERED_FIELD``.
    """

    from receipt.cli import MAX_RENDERED_FIELD, _bounded_payload

    value = "\U0001F600" * (MAX_RENDERED_FIELD + 1)
    # What the old, code-point bound would have produced and what it renders.
    assert _json_length(value[:MAX_RENDERED_FIELD]) == 12 * MAX_RENDERED_FIELD
    assert _json_length(value[:MAX_RENDERED_FIELD]) > 10 * MAX_RENDERED_FIELD

    bounded = _bounded_payload({"failure": value})["failure"]
    head, _, marker = bounded.partition("…")
    assert _json_length(head) <= MAX_RENDERED_FIELD
    assert _json_length(bounded) <= MAX_RENDERED_FIELD + _json_length("…" + marker)
    assert _json_length("…" + marker) < 128
    assert marker == f"[{len(value) - len(head)} more characters]"


def test_the_json_bound_covers_keys_and_keeps_them_distinct() -> None:
    """Binds S5R2-F6: evidence keys bypassed the bound entirely.

    ``_bounded_payload`` walked values and left keys alone, on the reasoning
    that two long keys truncated to the same text would collide. The
    objection was right and the conclusion was not: ``MAX_EVIDENCE_TEXT``
    lets a gate evidence key be 1,024 characters, and 1,024 characters
    outside the BMP render as 12,288 — a key alone scrolls the verdict away,
    which is the flood ``MAX_RENDERED_FIELD`` exists to stop.

    Keys are bounded the same way values are, and the collision is closed
    rather than avoided: the marker carries the whole key's SHA-256, so two
    keys sharing a bounded prefix differ in the marker and neither can
    replace the other. Both halves are asserted. Without the fix the
    rendered key is over twelve thousand characters.

    Binds S5R3-F11 for the digest length: sixteen hex characters is
    sixty-four bits, which is about 2^32 trials by the birthday bound for
    an adversary who wants two evidence keys to render identically, and
    what that buys is one value silently replacing another in a verdict an
    auditor reads. The whole digest is in the marker now, and the assertion
    below is on all sixty-four characters of it.
    """

    from receipt.cli import MAX_RENDERED_FIELD, _bounded_payload

    key = "\U0001F600" * 1024
    assert _json_length(key) == 12 * 1024 > 2 * MAX_RENDERED_FIELD

    bounded = _bounded_payload({key: "value"})
    (rendered_key,) = list(bounded)
    head, _, marker = rendered_key.partition("…")
    assert _json_length(head) <= MAX_RENDERED_FIELD
    assert _json_length(rendered_key) <= MAX_RENDERED_FIELD + _json_length(
        "…" + marker
    )
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    assert len(digest) == 64
    assert marker.endswith(f"; sha256 {digest}]")

    # Two keys sharing every character the bound keeps still render apart.
    shared = "\U0001F600" * 400
    first, second = shared + "a", shared + "b"
    walked = _bounded_payload({first: "1", second: "2"})
    assert len(walked) == 2
    assert walked[_bounded_payload({first: ""}).popitem()[0]] == "1"
    # And they share every character the bound kept, so nothing but the
    # digest is keeping them apart.
    heads = [rendered.partition("…")[0] for rendered in walked]
    assert heads[0] == heads[1]


def test_a_key_collision_refuses_instead_of_replacing_a_value() -> None:
    """Binds S5R3-F11: a digest is a distinguisher, not a proof.

    The marker carries the whole key's SHA-256 now rather than sixteen hex
    characters of it, which takes a deliberate merge from about 2^32 trials
    to out of reach. It does not take it to impossible, and what a merge
    buys is one evidence value silently replacing another in a verdict an
    auditor reads — a length policy turning into a data-loss policy, which
    is the objection that kept keys unbounded in the first place.

    So the mapping is checked rather than argued about: two keys that come
    out of the bound equal refuse. The collision is forced here by
    replacing the digest with a constant, which is the only way to reach
    the branch and which is exactly the capability an attacker with a
    collision would have.

    Without the check the second value replaces the first and the verdict
    reports one key where the producer wrote two.
    """

    import receipt._render as render_module
    from receipt.cli import _bounded_payload

    shared = "\U0001F600" * 400
    first, second = shared + "a", shared + "b"
    # The control: with the real digest the two render apart.
    assert len(_bounded_payload({first: "1", second: "2"})) == 2

    original = render_module.key_digest
    render_module.key_digest = lambda key: "0" * 64
    try:
        with pytest.raises(ValueError) as caught:
            _bounded_payload({first: "1", second: "2"})
    finally:
        render_module.key_digest = original
    assert str(caught.value).startswith(
        "two keys in one verdict object render identically once bounded: "
    )


def test_a_key_collision_becomes_the_render_refusal(
    repo: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Binds S5R3-F11: the refusal has to be the one the contract promises.

    ``_bounded_payload`` raising is only the right answer if it lands where
    every other unrenderable verdict lands: the render boundary in ``main``,
    which prints one JSON object bearing a ``verdict`` key and returns the
    failing exit code. This drives the real command over a real corpus and
    asserts that.

    Two things are faked and both are named. The digest is replaced by a
    constant, which is the collision itself and cannot be produced any other
    way. And a pair of long evidence keys is added to the payload, because
    the fixture corpus declares only short ones — they are the shape a gate
    may legitimately carry, 1,024 characters each under
    ``MAX_EVIDENCE_TEXT``, and the rest of the payload is the real verdict.

    Without the check the run reports PASS with one of the two keys gone.
    """

    import receipt._render as render_module
    from receipt.verify import result_to_dict as real_result_to_dict

    shared = "\U0001F600" * 400
    first, second = shared + "a", shared + "b"

    def with_long_keys(result: object) -> dict[str, object]:
        payload = real_result_to_dict(result)  # type: ignore[arg-type]
        payload["forcedEvidence"] = {first: "1", second: "2"}
        return payload

    monkeypatch.setattr("receipt.cli.result_to_dict", with_long_keys)
    monkeypatch.setattr(render_module, "key_digest", lambda key: "0" * 64)
    assert run(repo, "--json") == EXIT_FAIL
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "FAIL"
    assert payload["stage"] == "render"
    assert "treat the run as unverified" in payload["failure"]
    assert "ValueError" in payload["failure"]


def test_the_text_bound_still_counts_the_characters_it_prints() -> None:
    """Binds S5R2-F6, the other side: the text renderer's units did not move.

    A terminal receives characters, not JSON escapes, so what bounds the
    text half is the count of what it prints — an escape sequence charged
    the six characters it draws. The encoded measure belongs to the JSON
    half alone, and applying it to both would have bounded ordinary
    non-ASCII prose at a sixth of its stated length.

    Asked of ``_rendered`` since S5R4-F7 fused the two policies into it, and
    of a UTF-8 emission, which is what leaves ordinary non-ASCII prose as
    itself.

    This test passes with the S5R2-F6 change disabled, which is the point:
    it is here to catch the new measure being applied to the wrong half.
    """

    from receipt.cli import MAX_RENDERED_FIELD, _rendered

    bmp = "é" * (MAX_RENDERED_FIELD + 5)
    bounded = _rendered(bmp)
    assert bounded == "é" * MAX_RENDERED_FIELD + "…[5 more characters]"
    assert _rendered("é" * MAX_RENDERED_FIELD) == "é" * MAX_RENDERED_FIELD


def _physical_rows(text: str, columns: int = 80) -> list[str]:
    """The rows a terminal of this width draws for this text.

    Soft wrapping, spelled out: every logical line is cut into runs of
    ``columns`` characters, and each run occupies one row of the screen.
    """

    rows: list[str] = []
    # A trailing newline ends the last line; it does not draw a further row.
    for line in text[:-1].split("\n") if text.endswith("\n") else text.split("\n"):
        if not line:
            rows.append(line)
            continue
        rows.extend(
            line[index : index + columns]
            for index in range(0, len(line), columns)
        )
    return rows


def test_the_failure_verdict_ends_with_the_trusted_sentinel(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Binds S5R2-F7: the trusted line was printed before the untrusted text.

    ``VERDICT: FAIL`` came first and the failure detail after it. The detail
    is escaped and bounded, so it carries no escape sequence and at most
    four thousand and ninety-six characters — and that is enough. Four
    thousand printable characters soft-wrap through fifty rows of an
    eighty-column terminal, which scrolls the real verdict off the screen,
    and the last row a reader is left looking at is whatever the producer
    put at the end of them. ``VERDICT: PASS`` at column one costs the
    producer nothing to arrange.

    The sentinel is the last thing printed now, and nothing untrusted
    follows it. The assertion is over *physical* rows, because that is the
    unit the attack works in. Without the fix the last row is the forged
    line and rows after the real sentinel begin with ``VERDICT``.
    """

    forged = "VERDICT: PASS — custody and corpus binding".ljust(80)
    _flood_the_manifest_schema(repo, 0)
    manifest = manifest_stem(repo)
    payload = json.loads(manifest.read_text())
    payload["schemaVersion"] = forged * 50
    manifest.write_text(json.dumps(payload))

    assert run(repo) == EXIT_FAIL
    text = capsys.readouterr().err
    rows = _physical_rows(text)
    # The detail really does wrap through dozens of rows, which is what
    # makes the position of the sentinel matter at all.
    assert len(rows) > 60
    forged_rows = [index for index, row in enumerate(rows) if "VERDICT: PASS" in row]
    assert len(forged_rows) > 40
    sentinel = [
        index for index, row in enumerate(rows) if row.startswith("VERDICT: FAIL")
    ]
    assert sentinel == [len(rows) - 1]
    assert rows[-1] == "VERDICT: FAIL — custody"
    assert max(forged_rows) < sentinel[0]
    assert not [row for row in rows[sentinel[0] + 1 :] if row.startswith("VERDICT")]


def test_a_refusal_ends_with_the_trusted_sentinel(
    repo: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Binds S5R2-F7: ``_refuse`` is the other exit at the same boundary.

    An abort prints one line of attacker-influenced text — a spec path, an
    exception's message, a filename off the disk — and printed nothing
    after it. Bounded at four thousand and ninety-six characters, that line
    alone wraps through fifty rows, so the same forged last row is available
    on the refusal path as on the verdict path.

    ``receipt verify: FAIL`` is the last line either way now. Without the
    fix the last physical row is the producer's own text.
    """

    forged = "VERDICT: PASS — custody and corpus binding".ljust(80)
    spec = repo / "verification/spec.py"
    spec.write_text(
        spec.read_text()
        + "\nraise RuntimeError('"
        + "x" * 3000
        + forged.strip()
        + "')\n"
    )

    assert run(repo) == EXIT_USAGE
    captured = capsys.readouterr()
    rows = _physical_rows(captured.err)
    assert rows[-1] == "receipt verify: FAIL"
    assert not [row for row in rows[:-1] if row == "receipt verify: FAIL"]
    assert forged.strip() in captured.err


class _StrictAsciiStdout(io.TextIOWrapper):
    """A stdout whose codec refuses everything outside ASCII, as a pipe can.

    ``PYTHONIOENCODING=ascii``, and a POSIX locale with output redirected,
    both give the command exactly this: a text stream whose ``encoding`` is
    ASCII and whose error handler is ``strict``.
    """

    def __init__(self) -> None:
        super().__init__(io.BytesIO(), encoding="ascii", errors="strict", newline="")

    def written(self) -> str:
        self.flush()
        return self.buffer.getvalue().decode("ascii")


class _PartialBuffer:
    """A binary layer that takes at most ``limit`` bytes per call.

    What ``RawIOBase.write`` is allowed to do, and what ``BufferedWriter``
    never does — which is why a discarded return value went unnoticed. A
    ``python -u`` run, or a host that substitutes its own stream, gets this
    behaviour rather than the buffered one.
    """

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()
        self.calls = 0

    def write(self, payload) -> int:
        self.calls += 1
        chunk = bytes(payload[: self.limit])
        self.data += chunk
        return len(chunk)

    def flush(self) -> None:
        return None


class _PartialStdout(io.TextIOWrapper):
    """A stdout whose binary layer accepts only part of what it is offered."""

    def __init__(self, limit: int) -> None:
        super().__init__(io.BytesIO(), encoding="utf-8", newline="")
        self._partial = _PartialBuffer(limit)

    @property
    def buffer(self) -> _PartialBuffer:  # type: ignore[override]
        return self._partial


def test_a_short_write_does_not_truncate_the_verdict() -> None:
    """Binds S5R3-F7: the count ``write`` returns was discarded.

    ``write`` is not obliged to take everything it is offered. A
    ``BufferedWriter`` writes it all or raises, which is why this went
    unnoticed, but a raw or unbuffered stream returns the number of bytes it
    actually took, and returning a short count is not an error. The verdict
    was therefore truncated wherever the operating system stopped, and
    ``main`` returned the passing exit code over it — in ``--json`` mode,
    half an object to a machine consumer.

    ``_write_all`` repeats the write until the payload is gone. Seven bytes
    a call is enough to prove the loop: the payload here needs more than
    forty of them.

    Without the loop the stream holds the first seven bytes and nothing
    else.
    """

    from receipt.cli import _byte_safe_encoding, _emit

    payload = "VERDICT: FAIL \u2014 binding\nreceipt verify: FAIL"
    stream = _PartialStdout(7)
    _emit(payload, stream, encoding=_byte_safe_encoding(stream))
    assert bytes(stream.buffer.data) == (payload + "\n").encode("utf-8")
    assert stream.buffer.calls > 6


class _OneUnitTarget:
    """A writer that takes exactly one unit per call and records the offers.

    The degenerate short writer, and the one the copying cost is worst on. It
    records the length of everything it is offered and, separately, how many
    units had to be *materialised* to make those offers: a ``memoryview``
    slice is a window on the caller's own buffer and costs nothing, while a
    ``bytes`` or ``str`` slice is a fresh object of that length.
    """

    def __init__(self) -> None:
        self.data: list[object] = []
        self.offered: list[int] = []
        self.materialised = 0

    def write(self, payload) -> int:
        self.offered.append(len(payload))
        if not isinstance(payload, memoryview):
            self.materialised += len(payload)
        self.data.append(payload[:1] if isinstance(payload, str) else bytes(payload[:1]))
        return 1

    def flush(self) -> None:
        return None


def test_a_one_unit_writer_costs_the_payload_and_not_its_square() -> None:
    """Binds S6-F5: the remainder was copied after every short write.

    ``_write_all`` repeated the write until the payload was gone by rebinding
    ``payload = payload[written:]``, which copies everything left over on
    every call. A writer that takes one unit at a time therefore made the
    loop copy N + (N−1) + … + 1 units to write N — quadratic in the length of
    a verdict, on exactly the streams this loop exists for, since a
    ``BufferedWriter`` never short-writes and a raw or unbuffered one is
    where the counts come from at all. Nothing here is adversary-controlled,
    so this is cost rather than a hole; it is still the wrong shape.

    The loop tracks an offset into one ``memoryview`` now. What each call is
    offered is a window on the caller's own buffer, so the offers are still
    N, N−1, … by length and nothing whatever is copied to make them, which is
    what the recorder separates. Without the fix ``materialised`` is the sum
    of the offers — over eight million units for this four-kilobyte payload.
    """

    from receipt.cli import _write_all

    payload = b"x" * 4096
    target = _OneUnitTarget()
    _write_all(target, payload)

    assert b"".join(target.data) == payload
    assert len(target.offered) == len(payload)
    assert target.materialised == 0
    # The offers themselves are unchanged — each call is offered everything
    # that is left — so what the fix removes is the copying and not the
    # accounting.
    assert sum(target.offered) == len(payload) * (len(payload) + 1) // 2


def test_a_one_unit_text_writer_materialises_only_bounded_chunks() -> None:
    """Binds S6-F5 and S7-F6: text offset slices still copied quadratically.

    ``_emit``'s bufferless fallback hands this loop a ``str``, which has no
    zero-copy view. The old offset branch offered its entire remainder on
    every one-character short write, materialising N + (N−1) + … + 1
    characters: 137,439,215,616 for this 524,288-character near-cap payload.
    S7-F6 bounds the first slice at 8,192 and adapts later offers to the one
    character the writer accepted, while preserving the S6-F5 whole-payload
    result. Without S7-F6 the materialised-character bound fails by five
    orders of magnitude.
    """

    from receipt.cli import TEXT_WRITE_CHUNK, _write_all
    from receipt.corpus import MAX_GATE_TEXT, MAX_REMOVED_TEXT

    payload = "x" * (MAX_GATE_TEXT + MAX_REMOVED_TEXT)
    assert len(payload) == 524288
    target = _OneUnitTarget()
    _write_all(target, payload)

    assert "".join(target.data) == payload
    assert len(target.offered) == len(payload)
    assert target.materialised < 2 * len(payload) + TEXT_WRITE_CHUNK
    assert target.offered[0] == TEXT_WRITE_CHUNK == 8192
    assert max(target.offered) == TEXT_WRITE_CHUNK
    assert target.materialised == sum(target.offered)


class _ByteCountingTarget:
    """A text writer over a byte sink that returns the *byte* count.

    The reachable carrier S8-F3 names: one character of a multi-byte
    encoding goes in and a larger number comes back, because the wrapper is
    reporting what its sink took rather than what it was handed. Nothing
    about that is an error the writer would raise; it is a count in the wrong
    units, and every non-ASCII character in the offer widens the gap.

    ``take`` is how many characters it actually accepts, so the count it
    returns can exceed both the characters delivered and the offer itself.
    """

    def __init__(self, take: int) -> None:
        self.take = take
        self.taken: list[str] = []

    def write(self, payload: str) -> int:
        accepted = payload[: self.take]
        self.taken.append(accepted)
        return len(accepted.encode("utf-8"))

    def flush(self) -> None:
        return None


def test_a_writer_reporting_more_than_it_was_offered_refuses() -> None:
    """Binds S8-F3: an over-count truncated the verdict and returned EXIT_OK.

    ``_write_all`` bounded the count with ``if not written`` and
    ``if written < len(piece)`` — no upper bound and no type check — so a
    count larger than the offer advanced the offset past what the writer had
    delivered. The loop finished early, ``_write_all`` returned normally, and
    ``main`` returned the passing exit code over a truncated verdict.

    The writer here takes one character of a two-character payload and
    reports the three bytes its sink took for it, which is what a text
    wrapper over a byte sink does with an em dash. Without the check
    ``_write_all`` returns None having delivered one character of two; with
    it the offer is what the count is measured against, as CPython's own
    ``BufferedWriter`` loop measures it.
    """

    from receipt.cli import _write_all

    target = _ByteCountingTarget(1)
    with pytest.raises(OSError) as caught:
        _write_all(target, "\u2014a")
    assert str(caught.value) == (
        "the verdict stream reported an invalid write length (3) for 2 units "
        "offered; the verdict cannot be written"
    )
    assert target.taken == ["\u2014"]


def test_an_over_count_after_a_short_write_refuses() -> None:
    """Binds S8-F3: the shrunken offer is where four for one unit is caught.

    The first offer is ``TEXT_WRITE_CHUNK`` characters, so a payload shorter
    than that is offered whole and only a count above its length is out of
    range. After an honest short write the loop caps the next offer at what
    the writer demonstrated it can take, and it is there that a writer taking
    one unit and reporting four is refused rather than believed: offered one
    character, four cannot be a length.

    Without the check the offset jumps to five over a four-character payload,
    the loop ends, and two of the four characters were ever delivered.
    """

    from receipt.cli import _write_all

    class _ShortThenOverReporting:
        def __init__(self) -> None:
            self.taken: list[str] = []

        def write(self, payload: str) -> int:
            self.taken.append(payload[:1])
            return 1 if len(self.taken) == 1 else 4

        def flush(self) -> None:
            return None

    target = _ShortThenOverReporting()
    with pytest.raises(OSError) as caught:
        _write_all(target, "1234")
    assert str(caught.value) == (
        "the verdict stream reported an invalid write length (4) for 1 units "
        "offered; the verdict cannot be written"
    )
    assert target.taken == ["1", "2"]


def test_a_writer_reporting_a_negative_count_refuses_rather_than_spinning() -> None:
    """Binds S8-F3: ``-1`` passed the truthiness guard and never terminated.

    ``if not written`` is false for ``-1``, so the old loop set ``chunk`` to
    ``-1``, walked ``offset`` backwards, and looped for ever — both branches
    of the function, measured with a three-second alarm in the round-eight
    review. A negative count is not a short write; it is a stream that has
    answered a different question, and this command's answer to that is a
    refusal the exit code carries.

    Without the check this test does not fail, it hangs, which is why the
    writer raises once it has been asked more times than the payload is long.
    Both branches are driven, because both had the hole.
    """

    from receipt.cli import _write_all

    class _NegativeTarget:
        def __init__(self) -> None:
            self.calls = 0

        def write(self, payload) -> int:
            self.calls += 1
            if self.calls > 16:
                raise AssertionError("the write loop did not terminate")
            return -1

        def flush(self) -> None:
            return None

    for payload in ("12345678", b"12345678"):
        target = _NegativeTarget()
        with pytest.raises(OSError) as caught:
            _write_all(target, payload)
        assert str(caught.value) == (
            "the verdict stream reported an invalid write length (-1) for 8 "
            "units offered; the verdict cannot be written"
        )
        assert target.calls == 1


def test_a_writer_reporting_true_refuses() -> None:
    """Binds S8-F3: ``bool`` is an ``int`` and ``True`` is not a length.

    A stream that answers "yes, written" rather than "how much" passes every
    arithmetic check — ``True`` is ``1`` — and would deliver whatever it
    liked per call while the loop believed one unit had been accounted for.
    It is a writer answering a different question, and the type is what says
    so; the refusal names the type rather than repeating the object back,
    because an arbitrary object's ``repr`` does not belong in a refusal.
    """

    from receipt.cli import _write_all

    class _TruthfulTarget:
        def write(self, payload) -> bool:
            return True

        def flush(self) -> None:
            return None

    with pytest.raises(OSError) as caught:
        _write_all(_TruthfulTarget(), "12345678")
    assert str(caught.value) == (
        "the verdict stream reported an invalid write length (a bool) for 8 "
        "units offered; the verdict cannot be written"
    )


def test_an_over_reporting_stdout_becomes_the_render_refusal(
    repo: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Binds S8-F3 end to end: the exit code, not a truncated verdict.

    The unit tests above pin the loop; this pins what a consumer sees. The
    over-reporting writer is put where a host substitutes a stream — an
    ``io.StringIO`` subclass, so the sink recognition of S8-F2 admits it and
    the run reaches the write at all — and the run refuses at the render
    boundary with the exit code the refusal carries. Without the check the
    run reports PASS with one character of the verdict on that stream.
    """

    class _OverReportingStdout(io.StringIO):
        def __init__(self) -> None:
            super().__init__()
            self.taken: list[str] = []

        def write(self, text: str) -> int:  # type: ignore[override]
            self.taken.append(text[:1])
            return len(text) + 1

    stream = _OverReportingStdout()
    monkeypatch.setattr(sys, "stdout", stream)
    assert run(repo, "--json") == EXIT_FAIL
    # ``write`` never reaches the buffer underneath, so what a consumer of
    # this stream would have is what the overriding writer kept: one
    # character per call, and the loop stopped on the first one.
    assert stream.getvalue() == ""
    assert stream.taken and all(len(text) == 1 for text in stream.taken)
    error = capsys.readouterr().err
    assert "verdict could not be rendered; treat the run as unverified" in error
    assert "OSError: the verdict stream reported an invalid write length" in error


def test_a_stream_that_takes_no_bytes_becomes_the_render_refusal(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Binds S5R3-F7: a writer that accepts nothing is not a success either.

    A zero-length write is the degenerate short write, and the one a spin
    loop would hang on. It is a failure here: this is a one-shot verdict on
    a stream the command does not own, so a writer that will take nothing is
    a writer the exit code has to carry. ``_write_all`` raises ``OSError``,
    which is exactly what the render boundary in ``main`` already turns into
    the refusal — the same stage, the same exit code, and ``_refuse``
    writing to a stderr that still works.

    Without the check the write loop is a spin, or — with the count
    discarded, which is the head this finding is against — the run reports
    PASS with nothing at all on stdout.
    """

    stream = _PartialStdout(0)
    monkeypatch.setattr(sys, "stdout", stream)
    assert run(repo) == EXIT_FAIL
    assert bytes(stream.buffer.data) == b""
    error = capsys.readouterr().err
    assert "verdict could not be rendered; treat the run as unverified" in error
    assert "OSError" in error
    assert error.rstrip("\n").endswith("receipt verify: FAIL")


class _CodecStdout(io.TextIOWrapper):
    """A stdout whose ``encoding`` is whatever a host's locale happens to be.

    ``sys.stdout.encoding`` follows the locale, so a verdict printed on a
    Windows console under a Western European code page, or into a Japanese
    terminal, is encoded by a codec this command does not model.
    """

    def __init__(self, encoding: str) -> None:
        super().__init__(io.BytesIO(), encoding=encoding, errors="strict", newline="")

    def written(self) -> bytes:
        self.flush()
        return self.buffer.getvalue()


@pytest.mark.parametrize(
    "encoding, canonical",
    [("utf-7", "utf-7"), ("unicode_escape", "unicode-escape")],
)
def test_a_codec_that_decodes_ascii_into_controls_is_refused(
    repo: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    encoding: str,
    canonical: str,
) -> None:
    """Binds S7-F4: raw ASCII is not literal under every non-UTF-8 codec.

    UTF-7 turns the printable bytes ``+ABs-`` into ESC, while
    ``unicode_escape`` turns the sanitiser's own ``\\x1b`` spelling back into
    ESC. The runtime probe refuses both before stdout receives a byte and
    ``main`` returns the existing render refusal. Without S7-F4 the old
    fallback reports PASS and writes raw ASCII that the advertised decoder
    interprets as a control-bearing or invalid verdict.
    """

    if encoding == "utf-7":
        assert b"+ABs-[2J".decode(encoding) == "\x1b[2J"
    else:
        assert b"\\x1b[2J".decode(encoding) == "\x1b[2J"

    stream = _CodecStdout(encoding)
    monkeypatch.setattr(sys, "stdout", stream)
    assert run(repo, "--json") == EXIT_FAIL
    assert stream.written() == b""
    error = capsys.readouterr().err
    assert "verdict could not be rendered; treat the run as unverified" in error
    assert "OSError: " + NOT_ON_THE_ALLOW_LIST.format(name=canonical) in error
    assert error.rstrip("\n").endswith("receipt verify: FAIL")


def test_a_latin1_stream_round_trips_the_proved_ascii_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Binds S7-F4: literal-ASCII codecs must retain the safe fallback.

    Latin-1 carries every probed byte literally, so non-ASCII producer text
    is backslash-escaped into ASCII and the stream's own decoder recovers the
    exact emitted text. The recorder also proves the fallback was selected by
    the probe. Without S7-F4 the old unconditional ASCII branch never calls
    it, so that assertion fails even though Latin-1 happened to be safe.
    """

    import receipt.cli as cli_module

    real_probe = cli_module._ascii_is_literal
    probed: list[str] = []

    def recording_probe(encoding: str) -> bool:
        probed.append(encoding)
        return real_probe(encoding)

    monkeypatch.setattr(cli_module, "_ascii_is_literal", recording_probe)

    payload = "FAILED: binding \u203a rules/x.yaml\tcontrol"
    stream = _CodecStdout("latin-1")
    encoding = cli_module._byte_safe_encoding(stream)
    assert encoding == "ascii"
    assert probed == ["iso8859-1"]
    cli_module._emit(payload, stream, encoding=encoding)
    data = stream.written()

    expected = payload.encode("ascii", "backslashreplace").decode("ascii") + "\n"
    assert data == expected.encode("ascii")
    assert data.decode(stream.encoding) == expected


@pytest.mark.parametrize(
    "encoding, payload",
    [
        # U+203A is cp1252's 0x9B, which is CSI.
        ("cp1252", "FAILED: binding \u203a rules/x.yaml"),
    ],
)
def test_a_legacy_codec_cannot_turn_the_verdict_into_a_control_sequence(
    encoding: str, payload: str
) -> None:
    """Binds S5R3-F6: escaping ran before an unmodelled codec encoded it.

    ``_terminal_safe`` escapes every code point that can move a cursor or
    begin an escape sequence, and then ``_emit`` encoded the result with the
    stream's own codec. That order leaves the escaping to be undone by the
    encoder: cp1252 spells the perfectly printable U+203A as the single byte
    0x9B, which is CSI, so a filename carrying it began a control sequence
    through a character the escaper had no reason to touch.

    The stream's codec is used now only when it is UTF-8; a single-byte code
    page such as this one receives ASCII with ``backslashreplace``, so no
    character outside ASCII can produce a byte and every byte written is one
    the escaper approved. Without the fix the payload puts 0x9b on the
    stream.

    ISO-2022-JP was parametrised here too, as the worse-in-kind case that
    emits ESC to switch character sets. S7-R3-F3 refuses it outright rather
    than sending it ASCII, because the ASCII it would receive is read in
    whatever mode an earlier write left the stream in, so its case now lives
    in ``test_a_stateful_codec_is_refused_rather_than_written_to_shifted``.
    """

    from receipt.cli import _byte_safe_encoding, _emit

    # What the stream's own codec would have made of it, which is the
    # finding: a byte the terminal reads as a control, out of text that
    # carries no control character at all.
    assert any(byte in (0x1B, 0x9B) for byte in payload.encode(encoding))
    assert all(ord(character) not in (0x1B, 0x9B) for character in payload)

    stream = _CodecStdout(encoding)
    _emit(payload, stream, encoding=_byte_safe_encoding(stream))
    data = stream.written()
    assert data.isascii()
    assert b"\x1b" not in data and b"\x9b" not in data
    assert data.startswith(b"FAILED: binding ")
    assert data.endswith(b"\n")


def test_every_ascii_transparent_codec_is_a_stateless_single_byte_page() -> None:
    """Binds S7-R3-F3: the allow-list is a claim, and this is its proof.

    Membership grants raw ASCII bytes to a reader of that codec, so every
    member has to be a single-byte code page: a canonical name, ASCII
    literal under the probe, no byte that combines with an adjacent ASCII
    byte to become part of another character, no character it spells in more
    than one byte, and no shift state that a previous write could leave it
    in. All five are checked here for every name — which used to be true of
    four of them: the shift-state probe came from a fixed five-character
    tuple that nine members spell none of, so for ``ascii``, ``cp1006``,
    ``cp737``, ``cp869``, ``cp874``, ``iso8859-6``, ``iso8859-7``,
    ``iso8859-11`` and ``tis-620`` the encoder was asked whether ``A``
    survives a state nothing had entered (S8-F8). The probe is read off each
    page's own decode table now, ``ascii`` is skipped by name because it
    spells nothing above 0x7F, and the count of members really probed is
    asserted. So the list cannot acquire a member on assertion alone.

    The last two are what exclude by property rather than by omission, and
    they exclude different families. The shift check excludes ``iso2022_*``:
    an incremental encoder that has just written a non-ASCII character
    spells ``A`` as ``\x1b(BA`` there, and as ``A`` here. The one-byte
    check excludes ``raw-unicode-escape``, which is stateless, has no
    combining byte and passes the probe — and spells U+3042 as the six
    bytes ``\u3042``, which is the same thing read backwards as the decode
    hole the next test is about.

    Without S7-R3-F3 there is no list to check and this test cannot be
    written; ``_byte_safe_encoding`` grants the fallback to whatever the
    one-string probe happens to pass.
    """

    import codecs

    from receipt.cli import _ASCII_TRANSPARENT_CODECS, _ascii_is_literal

    assert len(_ASCII_TRANSPARENT_CODECS) == 61
    probed: list[str] = []
    for name in sorted(_ASCII_TRANSPARENT_CODECS):
        assert codecs.lookup(name).name == name, name
        assert _ascii_is_literal(name), name
        for value in range(256):
            decoded = bytes([value, 0x41]).decode(name, errors="replace")
            assert len(decoded) == 2 and decoded[1] == "A", (name, value)
        # Characters from outside every one of these pages: a code page
        # either cannot spell them at all or spells them in one byte, and a
        # codec that answers with more than one byte is not a code page.
        for outside in ("\u3042", "\u4e2d", "\uff71", "\u20ac", "\u2122"):
            try:
                spelled = outside.encode(name)
            except (UnicodeEncodeError, UnicodeError):
                continue
            assert len(spelled) == 1, (name, outside)
        # The shift-state check, over a probe taken from this page's own
        # table rather than from a fixed tuple. The tuple fell through for
        # nine members — ascii, cp1006, cp737, cp869, cp874, iso8859-6,
        # iso8859-7, iso8859-11 and tis-620 — none of which spells é, а, あ,
        # µ or Ж, so ``encoder.encode("A")`` was asserted on a fresh encoder
        # and the property went unchecked while the docstring said all five
        # were (S8-F8).
        probe = _a_non_ascii_character_this_page_spells(name)
        if probe is None:
            # ``ascii`` alone spells nothing above 0x7F, so it has no state
            # to leave behind and nothing to probe with. Skipped by name, not
            # by falling through.
            assert name == "ascii", name
        else:
            encoder = codecs.lookup(name).incrementalencoder()
            assert encoder.encode(probe) != b"", (name, probe)
            assert encoder.encode("A") == b"A", name
            probed.append(name)

    # Every member but ``ascii`` was really probed, which is what the fixed
    # tuple could not say (S8-F8).
    assert len(probed) == 60
    assert "ascii" not in probed

    # The excluded families, named in the constant, are excluded in fact.
    for name in (
        "utf-7",
        "unicode-escape",
        "raw-unicode-escape",
        "iso2022_jp",
        "cp037",
        "cp864",
        "cp932",
        "utf-16",
        "utf-32",
        "idna",
    ):
        assert codecs.lookup(name).name not in _ASCII_TRANSPARENT_CODECS


def test_a_codec_that_decodes_printable_escapes_into_controls_is_refused(
    repo: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Binds S7-R3-F3: the probe passes ``raw-unicode-escape``, which is a hole.

    Every runtime property the fallback was granted on is true of this codec.
    It is stateless, its ASCII range is the identity, no byte of it combines
    with a neighbour, and it passes ``_ascii_is_literal`` — and it decodes
    the six printable ASCII characters ``\\u001b`` into ESC and ``\\u000d``
    into CR. A producer's filename spelled that way carries no control
    character for ``_terminal_safe`` to escape and arrives as one, so the
    verdict line can be redrawn by text the escaper had no reason to touch.

    No probe over one fixed string can see this, because the hazard is a
    multi-character decode. The allow-list is what refuses it, before a byte
    is written, and since S8-F5 the refusal says so rather than telling the
    auditor that a codec ``_ascii_is_literal`` returns True for does not
    carry ASCII literally.

    Without S7-R3-F3 the probe grants the ASCII fallback, the run reports
    PASS, and the stream holds bytes whose own decoder makes a control
    sequence of them.
    """

    from receipt.cli import _ascii_is_literal

    # The hole, and the reason a probe cannot find it.
    assert _ascii_is_literal("raw-unicode-escape")
    assert b"\\u001b[2J".decode("raw-unicode-escape") == "\x1b[2J"
    assert b"\\u000d".decode("raw-unicode-escape") == "\r"
    assert all(
        ord(character) not in (0x1B, 0x0D) for character in "\\u001b[2J"
    )

    stream = _CodecStdout("raw-unicode-escape")
    monkeypatch.setattr(sys, "stdout", stream)
    assert run(repo, "--json") == EXIT_FAIL
    assert stream.written() == b""
    error = capsys.readouterr().err
    assert "verdict could not be rendered; treat the run as unverified" in error
    assert (
        "OSError: " + NOT_ON_THE_ALLOW_LIST.format(name="raw-unicode-escape")
        in error
    )
    assert error.rstrip("\n").endswith("receipt verify: FAIL")


def test_a_stateful_codec_is_refused_rather_than_written_to_shifted(
    repo: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Binds S7-R3-F3: the probe reads a fresh codec, not the one ``_emit`` has.

    ``iso2022_jp`` passes ``_ascii_is_literal`` because the probe encodes and
    decodes from a fresh state. The stream ``_emit`` reaches need not be in
    one: this stream has already written a single Japanese character, and
    flushing does not emit the ``\x1b(B`` that would return it to ASCII, so
    the buffer ends inside JIS X 0208. Raw ASCII bytes appended there are
    read two at a time — the four bytes of ``PASS`` decode as ``日仭嗷`` —
    and a longer verdict raises ``UnicodeDecodeError`` in the consumer
    instead. Either way the reader does not receive the verdict this module
    escaped.

    Without S7-R3-F3 the probe grants the fallback, the run reports PASS, and
    those bytes go on the stream behind the shift.
    """

    from receipt.cli import _ascii_is_literal

    stream = _CodecStdout("iso2022_jp")
    stream.write("\u65e5")
    stream.flush()
    shifted = stream.written()

    # The probe passes, and the state the probe never sees is what decides.
    assert _ascii_is_literal("iso2022_jp")
    assert shifted == b"\x1b$BF|"
    assert (shifted + b"PASS").decode("iso2022_jp") == "\u65e5\u4eed\u55f7"
    with pytest.raises(UnicodeDecodeError):
        (shifted + b"VERDICT: FAIL").decode("iso2022_jp")

    monkeypatch.setattr(sys, "stdout", stream)
    assert run(repo, "--json") == EXIT_FAIL
    # Nothing was appended behind the shift.
    assert stream.written() == shifted
    error = capsys.readouterr().err
    assert "verdict could not be rendered; treat the run as unverified" in error
    assert "OSError: " + NOT_ON_THE_ALLOW_LIST.format(name="iso2022_jp") in error


@pytest.mark.parametrize("encoding", ["utf-8", "UTF_8", "utf-8-sig"])
def test_a_utf8_stream_still_carries_the_characters_themselves(
    encoding: str,
) -> None:
    """Binds S5R3-F6, the control: UTF-8 is what the escaping was built on.

    UTF-8 maps the characters ``_terminal_safe`` kept onto bytes a reader
    decodes back to those characters, which is the property the escaping
    needs and the property a code page does not have. Its multi-byte
    sequences are a lead byte of 0xC2 or above followed by continuation
    bytes of 0x80 through 0xBF, disjoint from C0 and from ASCII, so a
    byte-oriented reader never sees a control the text did not carry.

    So a UTF-8 stream is written in UTF-8 and a verdict printed to a modern
    terminal is unchanged. The spellings are canonicalised through
    ``codecs.lookup``, which is why ``UTF_8`` is here beside ``utf-8``.

    Asserted over the raw bytes, and against one expected value for all
    three, because the three spellings are one codec and S6-F4 is the
    difference between saying that and assuming it: ``utf-8-sig`` prepends a
    byte-order mark, and decoding the result with ``utf-8-sig`` would have
    stripped the mark again and hidden it. What is checked is that the bytes
    a ``utf-8-sig`` stream receives are the bytes a ``utf-8`` stream
    receives.

    This test passes with the S5R3-F6 and S5R4-F3 changes disabled, which is
    the point: it is the control that keeps either fix from flattening every
    verdict to ASCII. It fails with S6-F4 disabled, on the ``utf-8-sig``
    case alone.
    """

    from receipt.cli import _byte_safe_encoding, _emit

    payload = "FAILED: binding \u203a \u30c6\u30b9\u30c8.yaml"
    stream = _CodecStdout(encoding)
    _emit(payload, stream, encoding=_byte_safe_encoding(stream))
    data = stream.written()
    assert data == (payload + "\n").encode("utf-8")
    assert not data.startswith(codecs.BOM_UTF8)


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-32-le"])
def test_a_wider_code_unit_cannot_carry_an_escape_sequence_either(
    encoding: str,
) -> None:
    """Binds S5R4-F3 and S7-F4: wider codecs cannot carry raw ASCII bytes.

    S5R3-F6 admitted UTF-16 and UTF-32 alongside UTF-8 on the argument that
    they are "the same with wider units". They are not, and the difference
    is the whole of the argument: what makes UTF-8 safe is that its code
    units *are* bytes, so the escaper judged every byte the stream will
    carry. A wider unit is a unit no reader of bytes sees. Under UTF-16LE
    the two perfectly printable code points U+5B1B and U+6D38 encode to
    ``1b 5b 38 6d`` — ``ESC [ 8 m``, the SGR sequence that renders the rest
    of the line invisible — out of text carrying no control character at
    all, which is exactly the shape of the cp1252 finding one round earlier.

    Hiding a line is enough: the verdict's trusted last line is where an
    auditor reads PASS or FAIL.

    S5R4-F3 removed them from the trusted codec path and sent raw ASCII to
    their binary buffer instead. S7-F4 closes the remaining mismatch: their
    advertised decoder does not carry those ASCII bytes literally, so the
    stream is refused before anything is written. Without S7-F4
    ``_byte_safe_encoding`` returns ``"ascii"`` and the no-byte assertion
    and exact ``OSError`` both fail.
    """

    from receipt.cli import _byte_safe_encoding

    payload = "FAILED: binding \u5b1b\u6d38.yaml"
    assert all(ord(character) not in (0x1B, 0x9B) for character in payload)
    assert 0x1B in payload.encode(encoding)

    stream = _CodecStdout(encoding)
    with pytest.raises(OSError) as caught:
        _byte_safe_encoding(stream)
    assert str(caught.value) == NOT_ON_THE_ALLOW_LIST.format(
        name=codecs.lookup(encoding).name
    )
    assert stream.written() == b""


class _ShiftingCodecStdout(io.TextIOWrapper):
    """A stdout whose ``encoding`` answers differently to successive reads.

    ``encoding`` is a plain attribute on a ``TextIOWrapper`` and a property
    on plenty of the wrappers a host substitutes for one — a stream that
    reports the console's current code page, a lazily reopened stream, a
    proxy that follows the locale. Nothing in the contract says two reads
    agree, and the command must not need them to.

    The bytes go to the real underlying buffer, so what the verdict actually
    received is what is asserted.
    """

    def __init__(self, first: str, then: str) -> None:
        super().__init__(io.BytesIO(), encoding=first, errors="strict", newline="")
        self._answers = [first, then]
        self.reads = 0

    @property
    def encoding(self) -> str:  # type: ignore[override]
        answer = self._answers[min(self.reads, len(self._answers) - 1)]
        self.reads += 1
        return answer

    def written(self) -> bytes:
        self.flush()
        return self.buffer.getvalue()


def test_the_emission_encoding_is_decided_once(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S6-F3: the stream was sampled twice and could answer twice.

    S5R4-F8 made the text bound count in the units the stream receives by
    deciding the emission encoding in ``main`` and threading it into
    ``_format_text``. ``_emit`` then sampled the stream again to encode, so
    the two halves rested on a stream answering the same question the same
    way twice. A stream that reports ``utf-8`` to the first read and
    ``ascii`` to the second is measured in characters and written with
    ``backslashreplace``: 4,096 emoji pass a bound of 4,096 and arrive as
    40,960 bytes of ``\\U0001f600``, which is the very defect S5R4-F8
    closed, reopened by the second sampling.

    ``main`` decides once and hands the decision to both, and ``_emit`` no
    longer asks — so the stream is read exactly once and the verdict is
    written in the encoding it was measured in. Without the fix the stream
    is read twice and the field arrives tenfold, spelled in backslashes.
    """

    from receipt.cli import MAX_RENDERED_FIELD

    emoji = "\U0001f600"
    _flood_the_manifest_schema_with(repo, emoji * MAX_RENDERED_FIELD)
    stream = _ShiftingCodecStdout("utf-8", "ascii")
    monkeypatch.setattr(sys, "stderr", stream)

    assert run(repo) == EXIT_FAIL
    data = stream.written()

    assert emoji.encode("utf-8") in data
    assert b"\\U0001f600" not in data
    assert stream.reads == 1
    # Counted in the units the stream receives, which for a UTF-8 emission
    # are the characters it decodes to: two bounded fields plus this
    # module's own fixed lines. Without the fix the field arrives spelled in
    # backslashes, which is ten ASCII characters for each of 4,096 emoji.
    drawn = data.decode("utf-8")
    assert len(drawn) < 2 * (MAX_RENDERED_FIELD + 64) + 2048
    assert data.endswith("VERDICT: FAIL — custody\n".encode("utf-8"))


class _BufferlessStdout(io.TextIOWrapper):
    """A stdout with no usable binary layer, of a codec the test chooses.

    The shape ``_emit``'s text fallback exists for: a detached wrapper, or
    one a host substituted that never had a buffer. What it writes is kept
    as text, because the point of the fallback is that the stream's own
    codec is what turns it into bytes.
    """

    def __init__(self, encoding: str) -> None:
        super().__init__(io.BytesIO(), encoding=encoding, errors="strict", newline="")
        self.text: list[str] = []

    @property
    def buffer(self):  # type: ignore[override]
        raise ValueError("underlying buffer has been detached")

    def write(self, text: str) -> int:  # type: ignore[override]
        self.text.append(text)
        return len(text)


def test_the_allow_list_property_is_the_ascii_decode_identity() -> None:
    """Binds S8-F7: "a fixed 256-entry table" is not what the members have.

    The list's comment named three properties: a fixed 256-entry table, no
    shift state, and an ASCII-identical lower half. The first is false of 22
    of the 61 — every page with undefined byte positions — and of ``ascii``
    itself, which defines 128. Stating a property the members do not have
    invites the next reader to admit a codec on it, or to strike a member
    that fails it.

    What the safety argument actually needs is that the bytes this module
    writes come back as the characters it wrote, which is the 0x00-0x7F
    decode identity, and all 61 have it. Both facts are measured here.
    """

    from receipt.cli import _ASCII_TRANSPARENT_CODECS

    ascii_bytes = bytes(range(0x80))
    ascii_text = "".join(chr(point) for point in range(0x80))
    narrow = []
    for name in sorted(_ASCII_TRANSPARENT_CODECS):
        assert ascii_bytes.decode(name) == ascii_text, name
        defined = 0
        for byte in range(256):
            try:
                bytes([byte]).decode(name)
            except UnicodeDecodeError:
                continue
            defined += 1
        if defined < 256:
            narrow.append(name)

    assert len(_ASCII_TRANSPARENT_CODECS) == 61
    assert len(narrow) == 22
    assert "ascii" in narrow


def test_no_printable_ascii_byte_survives_the_ebcdic_pages() -> None:
    """Binds S8-F7: "not ASCII at any byte" is false as written.

    cp037, cp273, cp424 and cp500 each agree with ASCII at 19 C0 control
    positions — NUL, and the shared controls around it. What is true, and
    stronger, is that none of 0x20 through 0x7E survives: every printable
    character of a verdict written as ASCII arrives as something else, which
    is the reason these pages are off the list.
    """

    for page in ("cp037", "cp273", "cp424", "cp500"):
        agreeing = []
        for byte in range(0x80):
            try:
                character = bytes([byte]).decode(page)
            except UnicodeDecodeError:
                continue
            if character == chr(byte):
                agreeing.append(byte)
        assert len(agreeing) == 19, page
        assert all(byte < 0x20 for byte in agreeing), page


def test_an_allow_list_miss_is_refused_by_name_not_by_the_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Binds S8-F5: one raise served both refusals and told the wrong story.

    S7-R3-F3 made eligibility a matter of being named in
    ``_ASCII_TRANSPARENT_CODECS``, with ``_ascii_is_literal`` kept as a belt,
    precisely because no probe can prove the property. The single raise then
    still said "does not carry ASCII literally" — which the module's own
    probe says is false of 23 codecs the interpreter ships, big5, gbk,
    cp932, euc_jp, shift_jis, raw-unicode-escape and iso2022_jp among them.
    An auditor reading that of big5 is told something untrue and given
    nothing to act on.

    So the miss is named as a miss. Each codec checked here passes the probe
    and is off the list, which is exactly the pair the old sentence
    misdescribed.

    Without S8-F5 every one of these carries the belt's sentence instead.
    """

    from receipt.cli import (
        _ASCII_TRANSPARENT_CODECS,
        _ascii_is_literal,
        _byte_safe_encoding,
    )

    for encoding in ("big5", "gbk", "cp932", "euc_jp", "shift_jis"):
        name = codecs.lookup(encoding).name
        # Off the list, and the probe cannot tell you why.
        assert name not in _ASCII_TRANSPARENT_CODECS
        assert _ascii_is_literal(name)

        stream = _CodecStdout(encoding)
        with pytest.raises(OSError) as caught:
            _byte_safe_encoding(stream)
        assert str(caught.value) == NOT_ON_THE_ALLOW_LIST.format(name=name)
        assert stream.written() == b""


def test_a_listed_codec_the_belt_rejects_keeps_the_belt_sentence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Binds S8-F5: the belt still has its own sentence, and its own meaning.

    The allow-list grants eligibility and ``_ascii_is_literal`` is the belt
    over it: a listed codec whose runtime table does not carry ASCII after
    all is the interpreter disagreeing with what this module recorded, which
    is a different fact from "this codec is not one we write ASCII for" and
    now says so.

    Reaching it takes a listed name whose probe fails, which no shipped codec
    is — that is the point of the list — so the probe is patched for one
    member.

    This is the control, and it passes with S8-F5 disabled: before the split
    both branches raised this sentence, so nothing here can fail against the
    old source. What it binds is the other direction — that splitting the
    refusal did not take the belt's own sentence away from the belt — which
    is what the sibling test above cannot see.
    """

    from receipt.cli import _ASCII_TRANSPARENT_CODECS, _byte_safe_encoding

    listed = codecs.lookup("latin-1").name
    assert listed in _ASCII_TRANSPARENT_CODECS
    monkeypatch.setattr(
        "receipt.cli._ascii_is_literal", lambda name: name != listed
    )

    stream = _CodecStdout("latin-1")
    with pytest.raises(OSError) as caught:
        _byte_safe_encoding(stream)
    assert str(caught.value) == (
        f"verdict stream codec {listed} does not carry ASCII literally; "
        "the verdict cannot be written safely"
    )
    assert str(caught.value) != NOT_ON_THE_ALLOW_LIST.format(name=listed)
    assert stream.written() == b""


def test_a_bufferless_stream_of_an_untrusted_codec_is_refused(
    repo: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Binds S6-F3: the fallback handed the bytes back to the rejected codec.

    ``_byte_safe_encoding`` refuses to trust a codec that can spell a
    printable character as a terminal-controlling byte, and encodes as ASCII
    instead. The bufferless fallback then decoded those safe bytes and wrote
    the *text* through the stream, whose own codec encodes it again — the
    one this module had just rejected. cp037 is an EBCDIC page: it spells an
    ordinary ``a`` as 0x81 and a space as 0x40, so a verdict carrying no
    control character at all leaves as bytes in the C1 range, and UTF-16
    would put a NUL beside every ASCII character. Everything the escaping
    and the codec choice bought was given back at the last step.

    There is nothing safe to do with such a stream, so the write refuses and
    the render boundary turns that into the refusal it already has. Without
    the fix the run reports PASS and the stream holds EBCDIC bytes.
    """

    stream = _BufferlessStdout("cp037")
    monkeypatch.setattr(sys, "stdout", stream)
    assert run(repo) == EXIT_FAIL
    assert stream.text == []
    error = capsys.readouterr().err
    assert "verdict could not be rendered; treat the run as unverified" in error
    assert "OSError: " + NOT_ON_THE_ALLOW_LIST.format(name="cp037") in error
    assert error.rstrip("\n").endswith("receipt verify: FAIL")


def test_a_bufferless_utf8_stream_still_gets_the_verdict(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S6-F3, the control: the fallback still serves the stream it is for.

    The refusal above must not cost the fallback its reason for existing. A
    detached or substituted wrapper whose own codec is UTF-8 re-encodes the
    text to exactly the bytes the buffer would have received, because UTF-8
    is the one codec this module trusts to do that, so the verdict is
    written through the text API and the run reports what it found.

    This test passes with the S6-F3 change disabled, which is the point: it
    is what keeps the guard from turning every bufferless stream into a
    refusal.
    """

    stream = _BufferlessStdout("utf-8")
    monkeypatch.setattr(sys, "stdout", stream)
    assert run(repo) == EXIT_OK
    assert "VERDICT: PASS" in "".join(stream.text)


def test_a_bufferless_literal_ascii_codec_still_meets_the_buffer_guard(
    repo: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Binds S6-F3's own sentence, which S7-F4 left this as the only path to.

    The bufferless guard refuses a stream with no binary layer whose codec is
    not the trusted UTF-8, because writing through the text API re-encodes
    with that codec. Until this round the cp037 case above was what reached
    it; S7-F4 now refuses cp037 one step earlier, at the literal-ASCII probe,
    so the guard's own refusal is reachable only for a codec that *passes*
    the probe and still is not UTF-8. Latin-1 is exactly that: every probed
    byte is literal, so ``_byte_safe_encoding`` answers ``ascii`` — and the
    text API would then hand those characters back to Latin-1, which is not
    the codec the bytes were encoded in.

    Without the guard this stream receives Latin-1 text for a verdict this
    module encoded as ASCII, and the run reports PASS over it. With S7-F4
    alone and no guard, nothing refuses at all.
    """

    from receipt.cli import _ascii_is_literal

    stream = _BufferlessStdout("latin-1")
    assert _ascii_is_literal("iso8859-1")
    monkeypatch.setattr(sys, "stdout", stream)
    assert run(repo) == EXIT_FAIL
    assert stream.text == []
    error = capsys.readouterr().err
    assert "verdict could not be rendered; treat the run as unverified" in error
    assert (
        "OSError: verdict stream has no binary buffer and its encoding is not "
        "UTF-8; the verdict cannot be written safely" in error
    )
    assert error.rstrip("\n").endswith("receipt verify: FAIL")


@pytest.mark.parametrize("as_json", [True, False])
def test_a_utf8_sig_stream_receives_no_byte_order_mark(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch, as_json: bool
) -> None:
    """Binds S6-F4: a trusted codec was handed back to the encoder by name.

    ``_byte_safe_encoding`` returned the stream's own spelling wherever it
    trusted it, and ``utf-8-sig`` was in the trusted set on the argument
    that it is UTF-8. It is UTF-8 with a byte-order mark: Python's codec
    writes U+FEFF ahead of the first character. So a ``--json`` verdict
    written to a stream reporting that codec — a Windows console under a
    UTF-8 code page, a stream a host opened with the signature codec — began
    ``ef bb bf``, and a JSON document does not begin with a byte-order mark.
    RFC 8259 permits an implementation to ignore one and plenty do not: a
    consumer that decodes the stream and parses the resulting string gets
    ``json.loads``'s own ``Unexpected UTF-8 BOM``. The command's
    JSON contract is that every exit path prints exactly one object bearing
    a ``verdict`` key, and this path printed something no parser would read.

    The trusted set holds ``utf-8`` alone now, and a stream reporting
    ``utf-8-sig`` is recognised as a UTF-8 stream and written as ``utf-8``:
    the same bytes, minus a mark this command was never asked to send. The
    text verdict is here too, because the mark is not content there either.

    Asserted over the raw bytes, because a decode with ``utf-8-sig`` would
    strip the very thing under test. Without the fix the JSON verdict starts
    ``ef bb bf`` and ``json.loads`` raises on it.
    """

    stream = _CodecStdout("utf-8-sig")
    monkeypatch.setattr(sys, "stdout", stream)
    assert run(repo, *(["--json"] if as_json else [])) == EXIT_OK
    data = stream.written()

    assert not data.startswith(codecs.BOM_UTF8)
    assert codecs.BOM_UTF8 not in data
    if as_json:
        assert data.startswith(b"{")
        assert json.loads(data.decode("utf-8"))["verdict"] == "PASS"
    else:
        assert data.startswith(b"receipt ")
        assert b"VERDICT: PASS" in data


def test_a_strict_ascii_stdout_still_gets_the_text_verdict(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S5R2-F8: the emission sat outside the fail-closed boundary.

    The rendering of the verdict is wrapped in a boundary that turns any
    failure into a render refusal. The ``print`` that wrote the rendered
    text out was not inside it, and it is the call that fails: ``print``
    hands the text to the stream's codec with the stream's error handler,
    and a strict ASCII one raises on the em dash in this module's own fixed
    lines. Not producer text — the header line's own dash. So the command
    that promises a fail-closed verdict on every exit path printed a
    traceback instead, on any host that runs it into a pipe under a POSIX
    locale.

    ``_emit`` encodes with ``backslashreplace`` and writes bytes to the
    stream's buffer, so the dash arrives as ``\\u2014`` and the verdict
    arrives whole. Without the fix this call raises ``UnicodeEncodeError``.
    """

    stdout = _StrictAsciiStdout()
    monkeypatch.setattr(sys, "stdout", stdout)
    assert run(repo) == EXIT_OK
    written = stdout.written()
    assert written.startswith("receipt ")
    assert "VERDICT: PASS" in written
    # The em dash of "receipt <version> — <spec name>", spelled the way an
    # ASCII stream can carry it.
    assert "\\u2014" in written
    assert "—" not in written


def test_a_strict_ascii_stdout_still_gets_the_json_verdict(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S5R2-F8: the JSON emission was outside the boundary as well.

    ``json.dumps`` with ``ensure_ascii`` produces ASCII, so this path
    survives an ASCII stream on its own merits — but it survived by
    accident, not by contract, and the boundary is what makes it a
    contract. The verdict is emitted through the same guarded writer, and
    the JSON a machine consumer keys on arrives intact.

    This test passes with the S5R2-F8 change disabled, which is the point:
    it is the control that keeps the guarded writer from changing what a
    machine consumer parses.
    """

    stdout = _StrictAsciiStdout()
    monkeypatch.setattr(sys, "stdout", stdout)
    assert run(repo, "--json") == EXIT_OK
    payload = json.loads(stdout.written())
    assert payload["verdict"] == "PASS"


def test_an_emission_that_raises_becomes_the_render_refusal(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Binds S5R2-F8: everything about the write is inside the boundary now.

    Encoding is the failure this finding was about, and it is not the only
    way a write fails: a closed stream, a full disk, a pipe whose reader has
    gone. With the emission outside the boundary every one of those left
    :func:`main` by exception. Inside it, they are the refusal the module
    already has for a verdict it cannot render — the same stage, the same
    exit code, and the JSON contract kept.

    Without the fix this call raises ``OSError``.
    """

    class _Failing(io.TextIOWrapper):
        """A stdout that fails at both layers, so no writer escapes it."""

        def __init__(self) -> None:
            super().__init__(io.BytesIO(), encoding="utf-8", newline="")

        def write(self, text: str) -> int:  # type: ignore[override]
            raise OSError(28, "No space left on device")

        @property
        def buffer(self):  # type: ignore[override]
            raise OSError(28, "No space left on device")

    monkeypatch.setattr(sys, "stdout", _Failing())
    assert run(repo) == EXIT_FAIL
    error = capsys.readouterr().err
    assert "verdict could not be rendered; treat the run as unverified" in error
    assert "OSError" in error
    assert error.rstrip("\n").endswith("receipt verify: FAIL")


def test_a_refusal_survives_a_stream_that_will_not_take_bytes(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S5R2-F8, adversarially: `_refuse` is what the boundary calls.

    The render boundary calls ``_refuse`` *after* an emission has already
    failed, and in ``--json`` mode it handed the refusal the very stream
    that had just failed. So the one exit path the JSON contract exists for
    — a verdict that cannot be rendered still prints an object bearing a
    ``verdict`` key — raised out of ``main`` instead, which is the failure
    the guarded writer was added to remove.

    Both writes are guarded now, and separately, so a failing stderr cannot
    suppress the JSON either. A refusal that cannot be written is still a
    refusal: the exit code carries it. Without the guard this call raises
    ``OSError``.
    """

    class _Failing(io.TextIOWrapper):
        def __init__(self) -> None:
            super().__init__(io.BytesIO(), encoding="utf-8", newline="")

        def write(self, text: str) -> int:  # type: ignore[override]
            raise OSError(28, "No space left on device")

        @property
        def buffer(self):  # type: ignore[override]
            raise OSError(28, "No space left on device")

    monkeypatch.setattr(sys, "stdout", _Failing())
    monkeypatch.setattr(sys, "stderr", _Failing())
    assert run(repo, "--json") == EXIT_FAIL


def test_the_guarded_writer_survives_a_detached_buffer(
    repo: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binds S5R2-F8, adversarially: absent and unusable are not the same.

    ``_emit`` documents a fallback to the stream's text API for a stream
    with no ``buffer``. A detached ``TextIOWrapper`` *raises* ``ValueError``
    from that property rather than lacking it, and a ``getattr`` default
    absorbs only ``AttributeError``, so the documented fallback was
    unreachable for the one real stream that needs it.

    The lookup catches both now. This drives a verdict through a stream
    whose buffer raises the way a detached one does and asserts the text
    arrives through the text API. Without the fix the emission raises and
    the run becomes a render refusal.
    """

    written: list[str] = []

    class _Detached(io.TextIOWrapper):
        def __init__(self) -> None:
            super().__init__(io.BytesIO(), encoding="utf-8", newline="")

        @property
        def buffer(self):  # type: ignore[override]
            raise ValueError("underlying buffer has been detached")

        def write(self, text: str) -> int:  # type: ignore[override]
            written.append(text)
            return len(text)

    monkeypatch.setattr(sys, "stdout", _Detached())
    assert run(repo) == EXIT_OK
    assert "VERDICT: PASS" in "".join(written)
