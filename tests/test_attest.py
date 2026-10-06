"""Focused unit coverage for the spec-parameterized attestation helpers.

The oracle-level command and git-history comparisons live in the dedicated
attestation differential.  These tests pin pure behavior, spec validation,
captured subprocess boundaries, and every refusal emitted directly by the
library.
"""

from __future__ import annotations

import inspect
import itertools
import json
import os
import pathlib
import re
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import FrozenInstanceError

import pytest
from hypothesis import given, settings, strategies as st

import receipt.attest as attest_module
from receipt.attest import (
    AttestSpec,
    ProvenanceError,
    attestation_subject,
    cert_identity_pattern,
    commit_age_seconds,
    commit_in_scope,
    enforcement_epoch,
    extract_certificate_identities,
    records_commits,
    repository_slug,
    subject_bytes,
    subject_name,
    verify_commit,
)


COMMIT = "a" * 40
WORKFLOW = ".github/workflows/record-forecasts.yml"
SECOND_WORKFLOW = ".github/workflows/roll-docket.yml"

#: The two queries every history walk asks before it walks.
HISTORY_PROBES = (
    ("rev-parse", "--is-shallow-repository"),
    ("rev-parse", "--git-path", "info/grafts"),
)


def _fake_git_output(
    outputs: Iterator[str], seen: list[tuple[object, ...]]
) -> Callable[..., str]:
    """A ``git_output`` stand-in whose history probes find a complete
    repository, answering every other query with the next of ``outputs``."""

    def fake_git_output(path: pathlib.Path, *args: str) -> str:
        seen.append((path, *args))
        if args == HISTORY_PROBES[0]:
            return "false"
        if args == HISTORY_PROBES[1]:
            return ".git/info/grafts"
        return next(outputs)

    return fake_git_output


def _spec(**changes: object) -> AttestSpec:
    values: dict[str, object] = {
        "repository": "MaxGhenis/brier",
        "allowed_workflows": frozenset({WORKFLOW, SECOND_WORKFLOW}),
        "allowed_ref": "refs/heads/main",
        "protected_prefix": "records/",
        "checker_path": pathlib.PurePosixPath(
            "scripts/verify_records_attestations.py"
        ),
    }
    values.update(changes)
    return AttestSpec(**values)  # type: ignore[arg-type]


def test_attestation_subject_is_exact_canonical_payload() -> None:
    expected = (
        b'{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        b'"repository":"MaxGhenis/brier",'
        b'"schemaVersion":"thesis_records_push_subject_v1"}\n'
    )
    assert attestation_subject("MaxGhenis/brier", COMMIT) == expected
    assert subject_bytes("MaxGhenis/brier", COMMIT) == expected
    assert subject_name(COMMIT) == f"records-push-{COMMIT}.json"


@pytest.mark.parametrize(
    ("repository", "commit", "message"),
    [
        (
            "MaxGhenis/brier",
            "abc123",
            "subject requires a full 40-hex commit sha: 'abc123'",
        ),
        (
            "not a slug",
            COMMIT,
            "invalid repository slug: 'not a slug'",
        ),
    ],
)
def test_attestation_subject_refusals_are_verbatim(
    repository: str,
    commit: str,
    message: str,
) -> None:
    with pytest.raises(ValueError) as caught:
        attestation_subject(repository, commit)
    assert str(caught.value) == message


def test_attest_spec_is_required_frozen_and_deeply_immutable() -> None:
    for field in (
        "repository",
        "allowed_workflows",
        "allowed_ref",
        "protected_prefix",
        "checker_path",
    ):
        assert (
            inspect.signature(AttestSpec).parameters[field].default
            is inspect.Parameter.empty
        )

    workflows = {WORKFLOW}
    spec = _spec(allowed_workflows=workflows, checker_path="scripts/check.py")
    workflows.add(".github/workflows/foreign.yml")
    assert spec.allowed_workflows == frozenset({WORKFLOW})
    assert spec.checker_path == pathlib.PurePosixPath("scripts/check.py")
    with pytest.raises(FrozenInstanceError):
        spec.repository = "Other/repo"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        (
            {"repository": "no-slash"},
            "invalid repository slug: 'no-slash'",
        ),
        (
            {"allowed_workflows": frozenset()},
            "allowed_workflows must be a non-empty collection of workflow paths",
        ),
        (
            {"allowed_workflows": WORKFLOW},
            "allowed_workflows must be a non-empty collection of workflow paths",
        ),
        (
            {"allowed_workflows": frozenset({"workflows/publish.yml"})},
            "invalid allowed workflow path: 'workflows/publish.yml'",
        ),
        (
            {"allowed_workflows": frozenset({".github/workflows/../evil.yml"})},
            "invalid allowed workflow path: '.github/workflows/../evil.yml'",
        ),
        (
            {"allowed_ref": "main"},
            "invalid allowed ref: 'main'",
        ),
        (
            {"allowed_ref": "refs/heads/main@evil"},
            "invalid allowed ref: 'refs/heads/main@evil'",
        ),
        (
            {"protected_prefix": "../records/"},
            "invalid protected prefix: '../records/'",
        ),
        (
            {"checker_path": pathlib.PurePosixPath("/scripts/check.py")},
            "invalid checker path: PurePosixPath('/scripts/check.py')",
        ),
        (
            {"checker_path": "scripts/"},
            "invalid checker path: 'scripts/'",
        ),
    ],
)
def test_attest_spec_validation_refusals(
    changes: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError) as caught:
        _spec(**changes)
    assert str(caught.value) == message


def test_cert_identity_pattern_is_exact_and_anchored() -> None:
    spec = _spec()
    pattern_text = cert_identity_pattern(spec)
    assert pattern_text == (
        r"^https://github\.com/MaxGhenis/brier/"
        r"(\.github/workflows/record\-forecasts\.yml|"
        r"\.github/workflows/roll\-docket\.yml)@refs/heads/main$"
    )
    pattern = re.compile(pattern_text)
    assert pattern.fullmatch(
        "https://github.com/MaxGhenis/brier/"
        ".github/workflows/record-forecasts.yml@refs/heads/main"
    )
    for identity in (
        "https://github.com/Other/repo/"
        ".github/workflows/record-forecasts.yml@refs/heads/main",
        "https://github.com/MaxGhenis/brier/"
        ".github/workflows/foreign.yml@refs/heads/main",
        "https://github.com/MaxGhenis/brier/"
        ".github/workflows/record-forecasts.yml@refs/heads/feature",
        "https://github.com/MaxGhenis/brier/"
        ".github/workflows/record-forecasts.yml@refs/heads/main.evil",
    ):
        assert pattern.fullmatch(identity) is None


def test_certificate_identity_extraction_uses_certificate_fields_only() -> None:
    first = (
        "https://github.com/MaxGhenis/brier/.github/workflows/"
        "record-forecasts.yml@refs/heads/main"
    )
    second = (
        "https://github.com/MaxGhenis/brier/.github/workflows/"
        "roll-docket.yml@refs/heads/main"
    )
    payload = [
        {
            "verificationResult": {
                "signature": {
                    "certificate": {
                        "buildSignerURI": first,
                        "other": f"prefix {second} suffix",
                        "ignored": 7,
                    }
                },
                "statement": {
                    "certificate": (
                        "github.com/Evil/fork/.github/workflows/"
                        "evil.yml@refs/heads/main"
                    )
                },
            }
        },
        None,
        {"verificationResult": "wrong type"},
    ]
    assert extract_certificate_identities(payload) == {
        first.removeprefix("https://"),
        second.removeprefix("https://"),
    }


def test_enforcement_epoch_command_and_refusals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = pathlib.Path("/repo")
    spec = _spec()
    seen: list[tuple[object, ...]] = []
    outputs = iter(["", f"{'b' * 40}\n{'c' * 40}", "d" * 40])
    monkeypatch.setattr(
        attest_module, "git_output", _fake_git_output(outputs, seen)
    )
    with pytest.raises(ProvenanceError) as caught:
        enforcement_epoch(root, spec=spec)
    assert str(caught.value) == (
        "enforcement epoch must be exactly one introducing commit for "
        "scripts/verify_records_attestations.py; found 0"
    )
    with pytest.raises(ProvenanceError) as caught:
        enforcement_epoch(root, spec=spec)
    assert str(caught.value).endswith("; found 2")
    assert enforcement_epoch(root, spec=spec) == "d" * 40
    assert seen[:3] == [
        (root, *HISTORY_PROBES[0]),
        (root, *HISTORY_PROBES[1]),
        (
            root,
            "log",
            "--full-history",
            "--diff-filter=A",
            "--format=%H",
            "--",
            "scripts/verify_records_attestations.py",
        ),
    ]


def test_records_commits_uses_full_history_and_consumer_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = pathlib.Path("/repo")
    seen: list[tuple[object, ...]] = []
    outputs = iter([f"{'b' * 40}\n{'c' * 40}", ""])
    monkeypatch.setattr(
        attest_module, "git_output", _fake_git_output(outputs, seen)
    )
    assert records_commits(root, "A..B", spec=_spec()) == ["b" * 40, "c" * 40]
    assert records_commits(root, "B..C", spec=_spec()) == []
    assert seen[:3] == [
        (root, *HISTORY_PROBES[0]),
        (root, *HISTORY_PROBES[1]),
        (
            root,
            "log",
            "--full-history",
            "--format=%H",
            "--end-of-options",
            "A..B",
            "--",
            "records/",
        ),
    ]


def test_commit_age_and_repository_slug_parsers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = pathlib.Path("/repo")
    outputs = iter(
        [
            b"100\n",
            b"200\n",
            b"git@github.com:MaxGhenis/brier.git\n",
            b"https://example.com/MaxGhenis/brier.git\n",
        ]
    )

    def fake_check_output(*args: object, **kwargs: object) -> bytes | str:
        output = next(outputs)
        return output.decode() if kwargs.get("text") else output

    monkeypatch.setattr(
        attest_module.subprocess, "check_output", fake_check_output
    )
    assert commit_age_seconds(root, COMMIT, now=150.9) == 50
    assert commit_age_seconds(root, COMMIT, now=150) == 0
    assert repository_slug(root) == "MaxGhenis/brier"
    with pytest.raises(ProvenanceError) as caught:
        repository_slug(root)
    assert str(caught.value) == (
        "cannot derive repository slug from "
        "'https://example.com/MaxGhenis/brier.git'"
    )


@pytest.mark.parametrize(
    ("origin", "expected"),
    [
        (
            "https://github.com/TheAxiomFoundation/receipt.audit.git",
            "TheAxiomFoundation/receipt.audit",
        ),
        (
            "git@github.com:TheAxiomFoundation/receipt.audit.git",
            "TheAxiomFoundation/receipt.audit",
        ),
        ("ssh://git@github.com:22/O/R.git", "O/R"),
        ("https://GITHUB.COM/O/R.git", "O/R"),
        ("git@GITHUB.COM:O/R.git", "O/R"),
        ("https://github.com/O/R.git/", "O/R"),
        ("git@github.com:O/R.git/", "O/R"),
        ("https://git@github.com:443/O/R.git", "O/R"),
        ("ssh://github.com/O/R.git.audit", "O/R.git.audit"),
        ("https://github.com/O/R", "O/R"),
    ],
)
def test_repository_slug_preserves_github_origin_identity(
    tmp_path: pathlib.Path, origin: str, expected: str
) -> None:
    """The slug names the whole repository at the parsed GitHub authority."""

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "config", "remote.origin.url", origin], cwd=tmp_path, check=True
    )
    assert repository_slug(tmp_path) == expected


@pytest.mark.parametrize(
    "origin",
    [
        "https://notgithub.com/TheAxiomFoundation/receipt.git",
        "https://evil.example/github.com/TheAxiomFoundation/receipt.git",
        "https://github.com.evil.example/O/R.git",
        "https://github.com/O/R.git/extra",
        "https://github.com/O/R.git?query=value",
        "https://github.com/O/R.git#fragment",
        "https://github.com/O/R.git?",
        "git@github.com:O/R.git#fragment",
        "git://github.com/O/R.git",
        "http://github.com/O/R.git",
        "ssh://git@github.com:invalid/O/R.git",
        "ssh://git@github.com:65536/O/R.git",
        "https://github.com/O//R.git",
        "https://github.com/O/.git",
        "https://github.com/O/../",
    ],
)
def test_repository_slug_refuses_non_github_or_ambiguous_origin(
    tmp_path: pathlib.Path, origin: str
) -> None:
    """A GitHub-looking substring must never supply a different identity."""

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "config", "remote.origin.url", origin], cwd=tmp_path, check=True
    )
    with pytest.raises(ProvenanceError) as caught:
        repository_slug(tmp_path)
    assert str(caught.value) == f"cannot derive repository slug from {origin!r}"


@pytest.mark.parametrize("host", ["g\u0131thub.com", "g\u0130thub.com"])
@pytest.mark.parametrize(
    "origin_template",
    ["https://{host}/O/R.git", "git@{host}:O/R.git", "ssh://git@{host}:22/O/R.git"],
)
def test_repository_slug_refuses_unicode_case_aliases(
    tmp_path: pathlib.Path, host: str, origin_template: str
) -> None:
    """Unicode case matches of ASCII i still name a foreign authority."""

    origin = origin_template.format(host=host)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "config", "remote.origin.url", origin], cwd=tmp_path, check=True
    )
    with pytest.raises(ProvenanceError) as caught:
        repository_slug(tmp_path)
    assert str(caught.value) == f"cannot derive repository slug from {origin!r}"


@pytest.mark.parametrize(
    "origin",
    [
        " https://github.com/O/R.git",
        "https://github.com/O/R.git ",
        "\nhttps://github.com/O/R.git\n",
    ],
)
def test_repository_slug_refuses_boundary_whitespace(
    tmp_path: pathlib.Path, origin: str
) -> None:
    """Only Git's final framing newline may be removed before validation."""

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "config", "remote.origin.url", origin], cwd=tmp_path, check=True
    )
    with pytest.raises(ProvenanceError) as caught:
        repository_slug(tmp_path)
    assert str(caught.value) == f"cannot derive repository slug from {origin!r}"


@pytest.mark.parametrize(
    ("returncode", "expected"),
    [(0, False), (1, True)],
)
def test_commit_scope_branch_outcomes(
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    expected: bool,
) -> None:
    root = pathlib.Path("/repo")
    seen: list[tuple[list[str], dict[str, object]]] = []
    probed: list[tuple[object, ...]] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        seen.append((args, kwargs))
        return subprocess.CompletedProcess(args, returncode, b"", b"")

    monkeypatch.setattr(
        attest_module, "git_output", _fake_git_output(iter(()), probed)
    )
    monkeypatch.setattr(attest_module.subprocess, "run", fake_run)
    monkeypatch.setenv("GIT_DIR", "/elsewhere/.git")
    assert commit_in_scope(root, "b" * 40, "c" * 40) is expected
    assert probed == [(root, *HISTORY_PROBES[0]), (root, *HISTORY_PROBES[1])]
    assert seen == [
        (
            [
                "git",
                "--no-replace-objects",
                "-c",
                "core.commitGraph=false",
                "merge-base",
                "--is-ancestor",
                "--end-of-options",
                "b" * 40,
                "c" * 40,
            ],
            {
                "cwd": root,
                "env": attest_module._git_environment(),
                "capture_output": True,
                "check": False,
            },
        )
    ]
    environment = seen[0][1]["env"]
    assert isinstance(environment, dict)
    assert {name for name in environment if name.startswith("GIT_")} == {
        "GIT_NO_REPLACE_OBJECTS"
    }
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"


def test_commit_scope_merge_base_error_is_verbatim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed = subprocess.CompletedProcess(
        ["git"], 128, stdout=b"", stderr=b"fatal: bad object\n"
    )
    monkeypatch.setattr(
        attest_module, "git_output", _fake_git_output(iter(()), [])
    )
    monkeypatch.setattr(
        attest_module.subprocess,
        "run",
        lambda *args, **kwargs: completed,
    )
    with pytest.raises(ProvenanceError) as caught:
        commit_in_scope(pathlib.Path("/repo"), "b" * 40, "c" * 40)
    assert str(caught.value) == (
        f"merge-base --is-ancestor failed for {'b' * 40}: fatal: bad object"
    )


def _verification_payload(workflow: str = WORKFLOW) -> dict[str, object]:
    return {
        "verificationResult": {
            "signature": {
                "certificate": {
                    "subjectAlternativeName": (
                        "https://github.com/MaxGhenis/brier/"
                        f"{workflow}@refs/heads/main"
                    ),
                    "buildSignerURI": (
                        "https://github.com/MaxGhenis/brier/"
                        f"{workflow}@refs/heads/main"
                    )
                }
            }
        }
    }


def test_verify_commit_constructs_exact_gh_command_and_is_silent(
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    root = pathlib.Path("/repo")
    spec = _spec()
    seen: list[tuple[list[str], dict[str, object], bytes]] = []

    monkeypatch.setattr(
        attest_module,
        "commit_age_seconds",
        lambda _root, _commit: 10**9,
    )

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        seen.append((args, kwargs, pathlib.Path(args[3]).read_bytes()))
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=json.dumps(_verification_payload()),
            stderr="",
        )

    monkeypatch.setattr(attest_module.subprocess, "run", fake_run)
    identity = verify_commit(root, COMMIT, spec=spec)
    assert identity == (
        "github.com/MaxGhenis/brier/.github/workflows/"
        "record-forecasts.yml@refs/heads/main"
    )
    assert len(seen) == 1
    args, kwargs, payload = seen[0]
    assert pathlib.Path(args[3]).name == subject_name(COMMIT)
    assert args[:3] == ["gh", "attestation", "verify"]
    assert args[4:] == [
        "--repo",
        "MaxGhenis/brier",
        "--cert-identity-regex",
        cert_identity_pattern(spec),
        "--format",
        "json",
    ]
    assert kwargs == {"capture_output": True, "text": True, "check": False}
    assert payload == attestation_subject("MaxGhenis/brier", COMMIT)
    assert capfd.readouterr() == ("", "")


def test_verify_commit_retries_fresh_commit_then_accepts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        attest_module,
        "commit_age_seconds",
        lambda _root, _commit: 1,
    )
    outcomes = iter(
        [
            subprocess.CompletedProcess(
                ["gh"], 1, stdout="", stderr="not indexed yet"
            ),
            subprocess.CompletedProcess(
                ["gh"],
                0,
                stdout=json.dumps(_verification_payload(SECOND_WORKFLOW)),
                stderr="",
            ),
        ]
    )
    calls: list[list[str]] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        calls.append(args)
        return next(outcomes)

    monkeypatch.setattr(attest_module.subprocess, "run", fake_run)
    delays: list[float] = []
    identity = verify_commit(
        pathlib.Path("/repo"),
        COMMIT,
        spec=_spec(),
        sleep=delays.append,
    )
    assert len(calls) == 2
    assert delays == [20]
    assert "roll-docket.yml@refs/heads/main" in identity


def test_verify_commit_exhausts_retries_and_uses_last_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        attest_module,
        "commit_age_seconds",
        lambda _root, _commit: 1,
    )
    calls = 0

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(
            args,
            1,
            stdout="stdout fallback",
            stderr=f"attempt {calls}\nlast detail {calls}\n",
        )

    monkeypatch.setattr(attest_module.subprocess, "run", fake_run)
    delays: list[float] = []
    with pytest.raises(ProvenanceError) as caught:
        verify_commit(
            pathlib.Path("/repo"),
            COMMIT,
            spec=_spec(),
            sleep=delays.append,
        )
    assert calls == 6
    assert delays == [20] * 5
    assert str(caught.value) == (
        f"{COMMIT}: no valid attestation for its records push subject "
        "(last detail 6)"
    )


def test_verify_commit_old_failure_and_unparseable_success_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        attest_module,
        "commit_age_seconds",
        lambda _root, _commit: 10**9,
    )
    outcomes = iter(
        [
            subprocess.CompletedProcess(["gh"], 1, stdout="", stderr=""),
            subprocess.CompletedProcess(["gh"], 0, stdout="not json", stderr=""),
        ]
    )
    monkeypatch.setattr(
        attest_module.subprocess,
        "run",
        lambda *args, **kwargs: next(outcomes),
    )
    with pytest.raises(ProvenanceError) as caught:
        verify_commit(pathlib.Path("/repo"), COMMIT, spec=_spec())
    assert str(caught.value) == (
        f"{COMMIT}: no valid attestation for its records push subject (no detail)"
    )
    assert verify_commit(pathlib.Path("/repo"), COMMIT, spec=_spec()) == "<verified>"


# --- 0.6.2 review, L6 finding 14: the logged identity is the enforced one


def _accepting_gh(monkeypatch: pytest.MonkeyPatch, stdout: str) -> None:
    monkeypatch.setattr(
        attest_module, "commit_age_seconds", lambda _root, _commit: 10**9
    )
    monkeypatch.setattr(
        attest_module.subprocess,
        "run",
        lambda args, **_kwargs: subprocess.CompletedProcess(
            args, 0, stdout=stdout, stderr=""
        ),
    )


def test_verify_commit_returns_the_identity_gh_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """In a reusable-workflow run the certificate names the called workflow
    (the SAN gh matched) and the caller (``buildConfigURI``). The smallest
    identity-shaped string won, so the log could name the caller, a workflow
    the allowlist excludes."""

    enforced = (
        "https://github.com/MaxGhenis/brier/.github/workflows/"
        "roll-docket.yml@refs/heads/main"
    )
    caller = (
        "https://github.com/MaxGhenis/brier/.github/workflows/"
        "a-unlisted-caller.yml@refs/heads/feature"
    )
    payload = [
        {
            "verificationResult": {
                "signature": {
                    "certificate": {
                        "subjectAlternativeName": enforced,
                        "buildConfigURI": caller,
                    }
                }
            }
        }
    ]
    _accepting_gh(monkeypatch, json.dumps(payload))
    assert verify_commit(pathlib.Path("/repo"), COMMIT, spec=_spec()) == (
        enforced.removeprefix("https://")
    )


@pytest.mark.parametrize(
    "stdout",
    [
        json.dumps([{"verificationResult": {"signature": None}}]),
        json.dumps([{"verificationResult": {"signature": "text"}}]),
        json.dumps([{"verificationResult": {"signature": ["list"]}}]),
        "[" * 100_000 + "]" * 100_000,
        "not json",
        "",
    ],
    ids=["signature-null", "signature-string", "signature-list", "deep", "text", "empty"],
)
def test_verify_commit_reads_malformed_gh_output_as_no_identity(
    monkeypatch: pytest.MonkeyPatch, stdout: str
) -> None:
    """Acceptance is gh's exit status alone; its stdout is only for the log.
    A ``null`` or string ``signature`` raised AttributeError, and nesting past
    the decoder's stack raised RecursionError, after gh had accepted."""

    _accepting_gh(monkeypatch, stdout)
    assert verify_commit(pathlib.Path("/repo"), COMMIT, spec=_spec()) == "<verified>"


# --- 0.6.2 review, L6 finding 15: a frozen spec keeps exact strings


class _Widening(str):
    """A str whose escaping widens once ``widen`` is set."""

    widen = False

    def __iter__(self):  # type: ignore[override]
        return iter(".*" if self.widen else str.__str__(self))


@pytest.mark.parametrize(
    "field", ["repository", "allowed_ref", "protected_prefix", "allowed_workflows"]
)
def test_attest_spec_refuses_str_subclasses(field: str) -> None:
    values = {
        "repository": _Widening("MaxGhenis/brier"),
        "allowed_ref": _Widening("refs/heads/main"),
        "protected_prefix": _Widening("records/"),
        "allowed_workflows": frozenset({_Widening(WORKFLOW)}),
    }
    with pytest.raises(ValueError):
        _spec(**{field: values[field]})


def test_a_constructed_spec_pattern_cannot_change_afterwards() -> None:
    spec = _spec()
    before = cert_identity_pattern(spec)
    assert all(
        type(value) is str
        for value in (spec.repository, spec.allowed_ref, spec.protected_prefix)
    )
    assert all(type(workflow) is str for workflow in spec.allowed_workflows)
    assert cert_identity_pattern(spec) == before
# --- the sweep reads the whole history of the repository it names ----------
#
# Review of 0.6.2 (L6 F1, F2, F13 and the inherited-GIT_DIR case). Each
# fixture history is base -> epoch (adds the checker) -> attested (records)
# -> unattested (records). The consumer verifies every commit the sweep
# returns in scope; a sweep that returns no unattested commit accepts it.


def _fixture_git(root: pathlib.Path, *args: str, timestamp: int = 1_900_000_000) -> str:
    """Fixture git, isolated from ambient configuration and redirects."""

    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Attest Fixture",
            "GIT_AUTHOR_EMAIL": "attest-fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Attest Fixture",
            "GIT_COMMITTER_EMAIL": "attest-fixture@example.invalid",
            "GIT_AUTHOR_DATE": f"{timestamp} +0000",
            "GIT_COMMITTER_DATE": f"{timestamp} +0000",
        }
    )
    return subprocess.run(
        ["git", *args],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _fixture_commit(root: pathlib.Path, relative: str, message: str, timestamp: int) -> str:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{message}\n")
    _fixture_git(root, "add", "-A")
    _fixture_git(root, "commit", "--quiet", "-m", message, timestamp=timestamp)
    return _fixture_git(root, "rev-parse", "HEAD")


def _fixture_history(root: pathlib.Path, *, origin: str = "MaxGhenis/brier") -> dict[str, str]:
    root.mkdir(parents=True)
    _fixture_git(root, "init", "--quiet", "--initial-branch=main", "--object-format=sha1")
    _fixture_git(root, "remote", "add", "origin", f"https://github.com/{origin}.git")
    return {
        "base": _fixture_commit(root, "README.md", "base", 1_900_000_000),
        "epoch": _fixture_commit(
            root, "scripts/verify_records_attestations.py", "checker", 1_900_000_100
        ),
        "attested": _fixture_commit(root, "records/a.json", "attested", 1_900_000_200),
        "unattested": _fixture_commit(root, "records/b.json", "unattested", 1_900_000_300),
    }


def _in_scope(root: pathlib.Path, rev_range: str | None = None) -> list[str]:
    """The records commits the consumer composition would verify."""

    spec = _spec()
    epoch = enforcement_epoch(root, spec=spec)
    selected = rev_range if rev_range else f"{epoch}..HEAD"
    return [
        commit
        for commit in records_commits(root, selected, spec=spec)
        if commit_in_scope(root, commit, epoch)
    ]


def test_a_full_history_sweep_reaches_the_unattested_commit(
    tmp_path: pathlib.Path,
) -> None:
    ids = _fixture_history(tmp_path / "full")
    assert enforcement_epoch(tmp_path / "full", spec=_spec()) == ids["epoch"]
    assert _in_scope(tmp_path / "full") == [ids["unattested"], ids["attested"]]


@pytest.mark.parametrize("depth", [1, 2])
def test_a_shallow_clone_refuses_before_it_is_swept(
    tmp_path: pathlib.Path, depth: int
) -> None:
    """A depth-1 clone made its tip the enforcement epoch, exempted it, and
    swept an empty range: the unattested commit was accepted unseen."""

    ids = _fixture_history(tmp_path / "full")
    shallow = tmp_path / "shallow"
    _fixture_git(
        tmp_path,
        "clone",
        "--quiet",
        "--depth",
        str(depth),
        f"file://{tmp_path / 'full'}",
        str(shallow),
    )
    assert (shallow / ".git" / "shallow").exists()
    for call in (
        lambda: enforcement_epoch(shallow, spec=_spec()),
        lambda: records_commits(shallow, f"{ids['attested']}..HEAD", spec=_spec()),
        lambda: commit_in_scope(shallow, ids["unattested"], ids["attested"]),
    ):
        with pytest.raises(ProvenanceError) as caught:
            call()
        assert str(caught.value) == "shallow repositories are unsupported"


def test_a_graft_file_refuses_before_it_is_swept(tmp_path: pathlib.Path) -> None:
    """A graft rewrites parents even with replace objects off."""

    root = tmp_path / "full"
    ids = _fixture_history(root)
    (root / ".git" / "info").mkdir(exist_ok=True)
    (root / ".git" / "info" / "grafts").write_text(f"{ids['unattested']}\n")
    for call in (
        lambda: enforcement_epoch(root, spec=_spec()),
        lambda: records_commits(root, f"{ids['epoch']}..HEAD", spec=_spec()),
        lambda: commit_in_scope(root, ids["unattested"], ids["epoch"]),
    ):
        with pytest.raises(ProvenanceError) as caught:
            call()
        assert str(caught.value) == "repository grafts are unsupported"


def _replace_unattested(root: pathlib.Path, ids: dict[str, str], ref: str) -> None:
    """Point ``ref`` at a commit with the unattested commit's parent and
    message but its parent's tree, so the records change disappears."""

    parent_tree = _fixture_git(root, "rev-parse", f"{ids['attested']}^{{tree}}")
    substitute = _fixture_git(
        root, "commit-tree", parent_tree, "-p", ids["attested"], "-m", "unattested"
    )
    _fixture_git(root, "update-ref", ref, substitute)


def test_a_replace_ref_does_not_hide_a_commit(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "full"
    ids = _fixture_history(root)
    _replace_unattested(root, ids, f"refs/replace/{ids['unattested']}")
    assert _in_scope(root) == [ids["unattested"], ids["attested"]]


def test_a_commit_graph_entry_does_not_hide_a_commit(tmp_path: pathlib.Path) -> None:
    """The commit-graph file is a cache git trusts: an entry giving a records
    commit below the tip its parent's tree made the walk pass over it."""

    root = tmp_path / "repo"
    root.mkdir()
    _fixture_git(root, "init", "--quiet", "--initial-branch=main", "--object-format=sha1")
    _fixture_git(root, "remote", "add", "origin", "https://github.com/MaxGhenis/brier.git")
    _fixture_commit(root, "README.md", "base", 1_900_000_000)
    epoch = _fixture_commit(
        root, "scripts/verify_records_attestations.py", "checker", 1_900_000_100
    )
    unattested = _fixture_commit(root, "records/u.json", "unattested", 1_900_000_200)
    attested = _fixture_commit(root, "records/a.json", "attested", 1_900_000_300)
    _fixture_git(root, "commit-graph", "write", "--reachable")
    graph = root / ".git" / "objects" / "info" / "commit-graph"
    data = bytearray(graph.read_bytes())
    assert data[:4] == b"CGPH"
    chunks = {
        bytes(data[8 + 12 * i : 12 + 12 * i]): int.from_bytes(
            data[12 + 12 * i : 20 + 12 * i], "big"
        )
        for i in range(data[6] + 1)
    }
    lookup, records = chunks[b"OIDL"], chunks[b"CDAT"]
    oids = [
        data[lookup + 20 * i : lookup + 20 * (i + 1)].hex()
        for i in range((records - lookup) // 20)
    ]
    entry = records + oids.index(unattested) * 36
    data[entry : entry + 20] = bytes.fromhex(
        _fixture_git(root, "rev-parse", f"{epoch}^{{tree}}")
    )
    graph.chmod(0o644)
    graph.write_bytes(bytes(data))
    # The graph now hides the commit from git's own walk.
    assert _fixture_git(
        root, "log", "--full-history", "--format=%H", f"{epoch}..HEAD", "--", "records/"
    ).split() == [attested]

    assert _in_scope(root) == [attested, unattested]


@pytest.mark.parametrize("variable", ["GIT_DIR", "GIT_GRAFT_FILE", "GIT_REPLACE_REF_BASE"])
def test_an_inherited_git_variable_does_not_move_the_sweep(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, variable: str
) -> None:
    """Every inherited GIT_* variable is dropped: the sweep and the slug are
    about the repository ``root`` names."""

    root = tmp_path / "full"
    ids = _fixture_history(root)
    if variable == "GIT_DIR":
        other = tmp_path / "other"
        _fixture_history(other, origin="Someone/else")
        _fixture_git(other, "reset", "--quiet", "--hard", "HEAD~2")
        value = str(other / ".git")
    elif variable == "GIT_GRAFT_FILE":
        grafts = tmp_path / "grafts"
        grafts.write_text(f"{ids['unattested']}\n")
        value = str(grafts)
    else:
        _replace_unattested(root, ids, f"refs/elsewhere/{ids['unattested']}")
        value = "refs/elsewhere/"
    monkeypatch.setenv(variable, value)

    assert repository_slug(root) == "MaxGhenis/brier"
    assert enforcement_epoch(root, spec=_spec()) == ids["epoch"]
    assert _in_scope(root) == [ids["unattested"], ids["attested"]]


def test_option_shaped_arguments_are_read_as_revisions(tmp_path: pathlib.Path) -> None:
    """``--author=nobody..`` used to reach git as an option and empty the
    sweep; after ``--end-of-options`` git refuses it as a revision."""

    root = tmp_path / "full"
    ids = _fixture_history(root)
    with pytest.raises(subprocess.CalledProcessError) as caught:
        records_commits(root, "--author=nobody..", spec=_spec())
    assert "bad revision '--author=nobody..'" in caught.value.stderr
    with pytest.raises(subprocess.CalledProcessError):
        commit_age_seconds(root, "--format=0", now=0)
    with pytest.raises(ProvenanceError) as scope:
        commit_in_scope(root, "--octopus", ids["epoch"])
    # Git names the argument as a revision it cannot find, not as an option.
    assert re.fullmatch(
        r"merge-base --is-ancestor failed for --octopus: "
        r"fatal: Not a valid (commit|object) name --octopus",
        str(scope.value),
    )


def _reference_records(root: pathlib.Path, rev_range: str) -> list[str]:
    """The records commits git lists with replace objects off and no
    inherited environment: the reference the sweep must equal."""

    return _fixture_git(
        root,
        "--no-replace-objects",
        "-c",
        "core.commitGraph=false",
        "log",
        "--full-history",
        "--format=%H",
        "--end-of-options",
        rev_range,
        "--",
        "records/",
    ).splitlines()


def test_the_sweep_is_invariant_under_ambient_git_state_exhaustively(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """For two histories (linear, and an unattested commit on a merged side
    branch), every subset of four inherited variables that can each move a
    git read (``GIT_DIR``, ``GIT_OBJECT_DIRECTORY``, ``GIT_GRAFT_FILE``,
    ``GIT_REPLACE_REF_BASE``), and a ``refs/replace/`` ref present or absent:
    2 × 16 × 2 = 64 sweeps. In every one the epoch is the commit that added
    the checker, and the commits in scope are exactly the reference's
    records commits after it, the unattested one included."""

    histories: dict[str, tuple[pathlib.Path, dict[str, str]]] = {}
    linear = tmp_path / "linear"
    histories["linear"] = (linear, _fixture_history(linear))
    merged = tmp_path / "merged"
    ids = _fixture_history(merged)
    _fixture_git(merged, "checkout", "--quiet", "-b", "side", ids["epoch"])
    ids["side"] = _fixture_commit(merged, "records/side.json", "side", 1_900_000_400)
    _fixture_git(merged, "checkout", "--quiet", "main")
    _fixture_git(merged, "merge", "--quiet", "--no-ff", "-m", "merge side", "side", timestamp=1_900_000_500)
    histories["merged"] = (merged, ids)

    other = tmp_path / "other"
    _fixture_history(other, origin="Someone/else")
    _fixture_git(other, "reset", "--quiet", "--hard", "HEAD~2")
    grafts = tmp_path / "grafts"
    values = {
        "GIT_DIR": str(other / ".git"),
        "GIT_OBJECT_DIRECTORY": str(other / ".git" / "objects"),
        "GIT_GRAFT_FILE": str(grafts),
        "GIT_REPLACE_REF_BASE": "refs/elsewhere/",
    }
    sweeps = 0
    for name, (root, history) in histories.items():
        hidden = history["side"] if name == "merged" else history["unattested"]
        grafts.write_text(f"{history['unattested']}\n")
        expected = _reference_records(root, f"{history['epoch']}..HEAD")
        assert hidden in expected
        for replaced in (False, True):
            if replaced:
                for ref in (f"refs/replace/{hidden}", f"refs/elsewhere/{hidden}"):
                    parent = _fixture_git(root, "rev-parse", f"{hidden}^")
                    substitute = _fixture_git(
                        root,
                        "commit-tree",
                        _fixture_git(root, "rev-parse", f"{parent}^{{tree}}"),
                        "-p",
                        parent,
                        "-m",
                        "substitute",
                    )
                    _fixture_git(root, "update-ref", ref, substitute)
            for chosen in itertools.product((False, True), repeat=len(values)):
                with monkeypatch.context() as patch:
                    for (variable, value), on in zip(values.items(), chosen):
                        if on:
                            patch.setenv(variable, value)
                    assert repository_slug(root) == "MaxGhenis/brier"
                    assert enforcement_epoch(root, spec=_spec()) == history["epoch"]
                    assert _in_scope(root) == expected, (name, replaced, chosen)
                sweeps += 1
    assert sweeps == 64


@pytest.mark.parametrize("signer", [WORKFLOW, SECOND_WORKFLOW])
def test_verify_commit_reports_signer_when_caller_is_also_allowed(
    monkeypatch: pytest.MonkeyPatch, signer: str
) -> None:
    """A matching caller URI never substitutes for the certificate's SAN."""

    identity = f"https://github.com/MaxGhenis/brier/{signer}@refs/heads/main"
    caller_workflow = SECOND_WORKFLOW if signer == WORKFLOW else WORKFLOW
    caller = f"https://github.com/MaxGhenis/brier/{caller_workflow}@refs/heads/main"
    payload = [{
        "verificationResult": {
            "signature": {
                "certificate": {
                    "subjectAlternativeName": identity,
                    "buildConfigURI": caller,
                }
            }
        }
    }]
    _accepting_gh(monkeypatch, json.dumps(payload))
    assert verify_commit(pathlib.Path("/repo"), COMMIT, spec=_spec()) == (
        identity.removeprefix("https://")
    )



@pytest.mark.parametrize("signer", [None, 7, "https://example.org/unlisted"])
def test_verify_commit_does_not_report_caller_without_matching_signer(
    monkeypatch: pytest.MonkeyPatch, signer: object
) -> None:
    caller = f"https://github.com/MaxGhenis/brier/{WORKFLOW}@refs/heads/main"
    payload = [{
        "verificationResult": {
            "signature": {
                "certificate": {
                    "subjectAlternativeName": signer,
                    "buildConfigURI": caller,
                }
            }
        }
    }]
    _accepting_gh(monkeypatch, json.dumps(payload))
    assert verify_commit(pathlib.Path("/repo"), COMMIT, spec=_spec()) == "<verified>"


@settings(max_examples=40, deadline=None, derandomize=True)
@given(
    signer=st.one_of(
        st.sampled_from([
            f"https://github.com/MaxGhenis/brier/{workflow}@refs/heads/main"
            for workflow in (WORKFLOW, SECOND_WORKFLOW)
        ]),
        st.none(),
        st.integers(),
        st.text(max_size=80),
    ),
    caller=st.sampled_from([WORKFLOW, SECOND_WORKFLOW]),
)
def test_verified_identity_always_comes_from_the_certificate_san(
    signer: object, caller: str
) -> None:
    """An allowlisted caller never replaces an absent or different signer."""

    payload = [{
        "verificationResult": {
            "signature": {
                "certificate": {
                    "subjectAlternativeName": signer,
                    "buildConfigURI": (
                        f"https://github.com/MaxGhenis/brier/{caller}@refs/heads/main"
                    ),
                }
            }
        }
    }]
    with pytest.MonkeyPatch.context() as monkeypatch:
        _accepting_gh(monkeypatch, json.dumps(payload))
        identity = verify_commit(pathlib.Path("/repo"), COMMIT, spec=_spec())
    expected = (
        signer.removeprefix("https://")
        if isinstance(signer, str) and re.fullmatch(cert_identity_pattern(_spec()), signer)
        else "<verified>"
    )
    assert identity == expected
