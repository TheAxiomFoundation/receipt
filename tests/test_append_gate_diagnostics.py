"""The append gate reads two files at the base ref, and owns no stderr.

``check_append_only`` and ``_manifest_at_ref`` each run ``git show`` for a
file at the trusted base. Both used ``check_output`` without capturing stderr,
so a git failure did two things at once: git's own diagnostic went to whatever
stderr the calling process held — a library writing over its caller's output,
which the module's own contract says it never does, and which the differential
harness asserts — while the ``AppendError`` it raised named the file and never
said why it could not be read. A reviewer of a refused proposal saw "cannot
read ledger/facts.jsonl at base <sha>" with the reason printed somewhere else,
or nowhere.

These are unit tests over a plain git repository: no release chain, no
witnesses, nothing the append gate's own battery exercises. The base commit
simply does not contain the file, which is the ordinary way that ``git show``
fails.
"""

from __future__ import annotations

import pathlib
import subprocess

import pytest

from receipt.append_gate import (
    AppendError,
    AppendGateSpec,
    _manifest_at_ref,
    _set_root,
    check_append_only,
)
from receipt.release_chain import AnchorSpec, ChainSpec

LEDGER_RELATIVE = "ledger/facts.jsonl"
PREFIX_RELATIVE = "ledger/immutable_prefix.json"

SPEC = AppendGateSpec(
    chain=ChainSpec(
        manifest_relative=pathlib.PurePosixPath("releases/manifests"),
        state_relative=pathlib.PurePosixPath(LEDGER_RELATIVE),
        prefix_relative=pathlib.PurePosixPath(PREFIX_RELATIVE),
        anchor_relative=pathlib.PurePosixPath("releases/anchors"),
        release_root_relative=pathlib.PurePosixPath("releases"),
        schema_version="t",
        producer_public_key_filename="producer-ed25519.pub",
        producer_spki_sha256="a" * 64,
        anchors={
            "alpha": AnchorSpec(
                filename="alpha-root.pem",
                pem_sha256="b" * 64,
                policy_oid="1.3.6.1.4.1.99999.1.1",
                signer_certificate_sha256="c" * 64,
                signer_spki_sha256="d" * 64,
            ),
        },
    ),
    prefix_schema_version="t",
    release_manifest_prefix="releases/manifests/",
    genesis_support_files=frozenset(),
    gate_surface=frozenset(),
    data_surface=frozenset(),
    assertion_content_keys=(),
)


def _git(root: pathlib.Path, *arguments: str) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t",
            "HOME": str(root),
        },
    )


@pytest.fixture()
def base_without_the_ledger(tmp_path: pathlib.Path) -> pathlib.Path:
    """A repository whose base commit holds neither file the gate reads."""

    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    (root / "README").write_text("not a ledger\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    return root


@pytest.mark.parametrize(
    ("call", "relative"),
    [
        (lambda candidate: check_append_only("HEAD", [], candidate), LEDGER_RELATIVE),
        (lambda candidate: _manifest_at_ref("HEAD", candidate), PREFIX_RELATIVE),
    ],
    ids=["check_append_only", "manifest_at_ref"],
)
def test_an_unreadable_base_file_says_why_and_prints_nothing(
    base_without_the_ledger: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
    call: object,
    relative: str,
) -> None:
    """The reason belongs in the refusal, not on the caller's stderr."""

    candidate = _set_root(base_without_the_ledger, SPEC)
    capfd.readouterr()
    with pytest.raises(AppendError) as raised:
        call(candidate)  # type: ignore[operator]

    captured = capfd.readouterr()
    assert captured.out == ""
    assert captured.err == "", "the library wrote git's diagnostic to stderr"

    message = str(raised.value)
    assert message.startswith(f"cannot read {relative} at base HEAD: ")
    # git's own words, carried into the refusal rather than lost beside it.
    assert "fatal" in message
    assert relative in message.split(": ", 1)[1]
