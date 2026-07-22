"""Differential harness for brier's workflow-provenance verifier.

Baseline = ``MaxGhenis/brier``'s unmodified
``scripts/verify_records_attestations.py`` at commit
``4b9e7be22debc8349e76b8bdfe5a0fe18ed31a3f``.  Candidate = a thin
harness-local entry-point composition of :mod:`receipt.attest`.  The brier
values below are the consumer-committed spec; the package contains none of
them.

Comparison contract, stated exactly:

- exit status must match (0 accept, 1 refuse);
- on refusal, the baseline entry point's stderr (or the original baseline
  exception caught by the outcome adapter for a top-level refusal) must equal
  the candidate exception message byte for byte after two stated
  normalizations, and baseline stdout must be empty: surrounding whitespace
  is stripped from both captured messages, and OpenSSL 3's volatile 8--16
  hexadecimal error-queue identifier before ``:error:`` is masked at the
  start of embedded error lines;
- on acceptance, the baseline stdout summary must equal the summary composed
  from the candidate return values byte for byte, and baseline stderr is
  empty;
- the package port is a silent library: stdout and stderr remain empty around
  candidate calls (asserted with ``capfd``); subprocesses capture their own
  streams.

No live-network equivalence is claimed.  This harness pins only ``gh`` command
construction and outcome handling against an identical local stub.  The clock
and retry sleep are fixed at the same boundaries for baseline and candidate.
Only the independently random temporary-directory prefix is replaced in
command logs; the subject basename, subject bytes, and every other argument
are exact.  That command-log comparison is not a third refusal-message
normalization.
Each divergence probe returns an empirically observed refusal marker, asserted
only after full normalized message equality.

Deliberately outside the CLI mutation contract:

- invalid subject commit IDs cannot come from ``git log --format=%H``; invalid
  repository subjects and valid non-brier origins conflict with the committed
  brier repository spec.  The original subject helpers are compared directly
  for their refusal messages;
- a ``merge-base --is-ancestor`` status above one cannot be produced by the
  normal entry point from the extant hashes emitted by Git.  Its original and
  ported helpers are compared directly with a deliberately invalid object ID;
- ``AttestSpec`` validation has no baseline analogue because the upstream
  policy is module-level constants; focused package tests own that boundary;
- successful ``gh`` output without a parseable certificate identity is an
  acceptance (rendered ``<verified>``), never a refusal branch;
- upstream argparse and entry-point rendering are consumer orchestration, not
  package API.  This harness composes the default range and the one-commit
  loop/summary behavior used by its boundary probes solely to compare the
  extracted helpers.  Because upstream leaves repository, epoch, and range
  errors uncaught, the adapter catches the original ``ProvenanceError``
  instead of inventing a forbidden traceback normalization.

The authenticated tree resolves from ``RECEIPT_BRIER_TREE``, then the local
``.extraction/`` materialization, then a fresh public clone at the pin.  The
entry script and both transitive imports it executes are SHA-authenticated in
every path.  Constructed repositories receive byte-identical copies and never
write under the read-only oracle tree.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import types
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from receipt.attest import (
    AttestSpec,
    ProvenanceError,
    attestation_subject,
    cert_identity_pattern,
    commit_in_scope,
    enforcement_epoch,
    records_commits,
    repository_slug,
    verify_commit,
)

BRIER_PIN = "4b9e7be22debc8349e76b8bdfe5a0fe18ed31a3f"
BRIER_REPO_URL = "https://github.com/MaxGhenis/brier.git"

BASELINE_AUTHENTICATED_FILES = {
    "scripts/verify_records_attestations.py": (
        "469ecd7890b22dcf5fb2bf12422cfd6b433eb1dbd121f14a7c4f2415fee5d887"
    ),
    "scripts/attest_subject.py": (
        "d3dce3a15c11823567c0faf495d8a5365a66ddb782a604cb4b58fcf4263ddac2"
    ),
    "scripts/canonical_json.py": (
        "562bf267b7686bce8cb71f3c13f34825c21cd4ef0aba1c0c46aff16962a6cadd"
    ),
}

# Consumer-committed transcription of the authenticated brier verifier.  The
# package has no repository, workflow, ref, or protected-path defaults.
BRIER_ATTEST_SPEC = AttestSpec(
    repository="MaxGhenis/brier",
    allowed_workflows=frozenset(
        {
            ".github/workflows/roll-docket.yml",
            ".github/workflows/strategy-docket.yml",
            ".github/workflows/prospect-docket.yml",
            ".github/workflows/record-forecasts.yml",
            ".github/workflows/resolve-and-rebuild.yml",
        }
    ),
    allowed_ref="refs/heads/main",
    protected_prefix="records/",
    checker_path=pathlib.PurePosixPath(
        "scripts/verify_records_attestations.py"
    ),
)

FIXED_NOW = 2_000_000_000
BASE_COMMIT_TIME = FIXED_NOW - 4_000
EPOCH_COMMIT_TIME = FIXED_NOW - 2_000
OLD_RECORD_TIME = FIXED_NOW - 900
FRESH_RECORD_TIME = FIXED_NOW - 899
ALLOWED_IDENTITY = (
    "https://github.com/MaxGhenis/brier/"
    ".github/workflows/roll-docket.yml@refs/heads/main"
)


@dataclass(frozen=True)
class RunOutcome:
    code: int
    stdout: str
    stderr: str
    sleeps: tuple[float, ...] = ()


@dataclass(frozen=True)
class GhStub:
    executable: pathlib.Path
    state: pathlib.Path


def _authenticated_baseline_tree(tree: pathlib.Path) -> pathlib.Path:
    """Authenticate the entry point and every repository source it executes."""

    for relative, expected in BASELINE_AUTHENTICATED_FILES.items():
        path = tree / relative
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected:
            raise RuntimeError(
                "baseline oracle is not the pinned verifier: "
                f"{path} has SHA-256 {digest}, expected {expected} "
                "(receipts/brier-pin-source-hashes.txt). A stale or altered "
                "baseline must not silently vouch for the port."
            )
    return tree


@pytest.fixture(scope="session")
def brier_tree(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    override = os.environ.get("RECEIPT_BRIER_TREE")
    if override:
        tree = pathlib.Path(override)
        if not tree.is_dir():
            raise RuntimeError(f"RECEIPT_BRIER_TREE is not a directory: {tree}")
        return _authenticated_baseline_tree(tree)
    local = (
        pathlib.Path(__file__).resolve().parents[1]
        / ".extraction"
        / f"brier-{BRIER_PIN[:7]}"
    )
    if local.is_dir():
        return _authenticated_baseline_tree(local)
    clone = tmp_path_factory.mktemp("brier-attest-pin") / "brier"
    subprocess.run(
        ["git", "clone", "--quiet", BRIER_REPO_URL, str(clone)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(clone), "checkout", "--quiet", BRIER_PIN],
        check=True,
    )
    return _authenticated_baseline_tree(clone)


def _load_reference(root: pathlib.Path) -> Any:
    """Load a byte-authenticated, otherwise unmodified reference module."""

    _authenticated_baseline_tree(root)
    script = root / "scripts" / "verify_records_attestations.py"
    module_spec = importlib.util.spec_from_file_location(
        f"_receipt_attest_reference_{abs(hash(root))}", script
    )
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError(f"cannot load reference verifier: {script}")

    # The unmodified source prepends its own scripts directory and imports these
    # names absolutely.  Isolate that import state so constructed repositories
    # cannot bleed into one another.
    imported_names = ("attest_subject", "canonical_json")
    saved_path = sys.path[:]
    saved_modules = {
        name: sys.modules.pop(name)
        for name in imported_names
        if name in sys.modules
    }
    module = importlib.util.module_from_spec(module_spec)
    try:
        module_spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved_path
        for name in imported_names:
            sys.modules.pop(name, None)
        sys.modules.update(saved_modules)
    return module


def run_baseline(
    root: pathlib.Path, rev_range: str | None = None
) -> RunOutcome:
    """Run the original entry function with only clock/sleep outcome seams."""

    reference = _load_reference(root)
    sleeps: list[float] = []
    reference.time = types.SimpleNamespace(
        time=lambda: float(FIXED_NOW),
        sleep=sleeps.append,
    )
    stdout = io.StringIO()
    stderr = io.StringIO()
    previous_argv = sys.argv[:]
    sys.argv = [
        str(root / "scripts" / "verify_records_attestations.py"),
        *([] if rev_range is None else ["--range", rev_range]),
    ]
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = int(reference.main())
            except reference.ProvenanceError as exc:
                print(str(exc), file=sys.stderr)
                code = 1
    finally:
        sys.argv = previous_argv
    return RunOutcome(
        code,
        stdout.getvalue().strip(),
        stderr.getvalue().strip(),
        tuple(sleeps),
    )


def run_candidate(
    root: pathlib.Path, rev_range: str | None = None
) -> RunOutcome:
    """Compose the consumer-owned entry loop around silent package helpers."""

    sleeps: list[float] = []
    try:
        repository = repository_slug(root)
        if repository != BRIER_ATTEST_SPEC.repository:
            raise AssertionError(
                "constructed repository origin does not match the brier spec: "
                f"{repository!r}"
            )
        epoch = enforcement_epoch(root, spec=BRIER_ATTEST_SPEC)
        selected_range = rev_range
        if not selected_range or selected_range.startswith("0" * 40):
            selected_range = f"{epoch}..HEAD"
        elif ".." not in selected_range:
            raise ProvenanceError(
                f"--range must be A..B, got {selected_range!r}"
            )
        commits = [
            commit
            for commit in records_commits(
                root, selected_range, spec=BRIER_ATTEST_SPEC
            )
            if commit_in_scope(root, commit, epoch)
        ]
    except ProvenanceError as exc:
        return RunOutcome(1, "", str(exc), tuple(sleeps))

    if not commits:
        return RunOutcome(
            0,
            f"records provenance OK: no records commits in {selected_range}",
            "",
            tuple(sleeps),
        )

    output: list[str] = []
    failures: list[str] = []
    for commit in commits:
        try:
            identity = verify_commit(
                root,
                commit,
                spec=BRIER_ATTEST_SPEC,
                now=FIXED_NOW,
                sleep=sleeps.append,
            )
            output.append(f"records provenance OK: {commit} <- {identity}")
        except ProvenanceError as exc:
            failures.append(str(exc))

    if failures:
        error_lines = [
            *(f"records provenance FAIL: {failure}" for failure in failures),
            "",
            f"{len(failures)} records commit(s) lack allowlisted workflow provenance",
        ]
        return RunOutcome(1, "\n".join(output), "\n".join(error_lines), tuple(sleeps))

    output.append(f"records provenance OK: {len(commits)} commit(s) verified")
    return RunOutcome(0, "\n".join(output), "", tuple(sleeps))


def _normalize_openssl_ids(message: str) -> str:
    return re.sub(
        r"(?m)^[0-9A-Fa-f]{8,16}(?=:error:)",
        "<openssl-err-id>",
        message.strip(),
    )


def _assert_candidate_silent(capfd: pytest.CaptureFixture[str]) -> None:
    captured = capfd.readouterr()
    assert (captured.out, captured.err) == ("", ""), (
        "the port must not write to stdout/stderr; captured "
        f"out={captured.out!r} err={captured.err!r}"
    )


def _assert_refused_identically(
    name: str,
    baseline: RunOutcome,
    candidate: RunOutcome,
    marker: str,
) -> None:
    assert baseline.code == 1, f"baseline ACCEPTED divergence probe {name}"
    assert baseline.stdout == "", (
        f"baseline printed to stdout while refusing {name}: {baseline.stdout!r}"
    )
    assert candidate.code == 1, f"candidate ACCEPTED divergence probe {name}"
    assert candidate.stdout == baseline.stdout, (
        f"candidate printed to stdout while refusing {name}: {candidate.stdout!r}"
    )
    normalized_baseline = _normalize_openssl_ids(baseline.stderr)
    normalized_candidate = _normalize_openssl_ids(candidate.stderr)
    assert normalized_candidate == normalized_baseline, (
        f"divergent refusal for {name}:\n"
        f"  baseline: {baseline.stderr}\n"
        f"  candidate: {candidate.stderr}"
    )
    assert marker in normalized_candidate, (
        f"probe {name} no longer binds its observed branch:\n"
        f"  expected: {marker}\n"
        f"  refusal: {candidate.stderr}"
    )


def _git_env(timestamp: int) -> dict[str, str]:
    environment = os.environ.copy()
    git_date = f"{timestamp} +0000"
    environment.update(
        {
            "GIT_AUTHOR_DATE": git_date,
            "GIT_COMMITTER_DATE": git_date,
        }
    )
    return environment


def _git(
    root: pathlib.Path,
    *args: str,
    timestamp: int | None = None,
) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        env=None if timestamp is None else _git_env(timestamp),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed: "
            f"{(completed.stderr or completed.stdout).strip()}"
        )
    return completed.stdout.strip()


def _write_text(root: pathlib.Path, relative: str, value: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)


def _initialize_repository(root: pathlib.Path) -> None:
    root.mkdir(parents=True)
    _git(
        root,
        "init",
        "--quiet",
        "--initial-branch=main",
        "--object-format=sha1",
    )
    _git(root, "config", "user.name", "Attest Equivalence")
    _git(root, "config", "user.email", "attest-equivalence@example.invalid")
    _git(root, "config", "commit.gpgSign", "false")
    _git(root, "config", "tag.gpgSign", "false")
    _git(root, "config", "core.hooksPath", os.devnull)
    _git(root, "remote", "add", "origin", BRIER_REPO_URL)


def _commit(root: pathlib.Path, message: str, timestamp: int) -> str:
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", message, timestamp=timestamp)
    return _git(root, "rev-parse", "HEAD")


def _materialize_reference(tree: pathlib.Path, root: pathlib.Path) -> None:
    for relative in BASELINE_AUTHENTICATED_FILES:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(tree / relative, destination)


def _base_repository(root: pathlib.Path) -> str:
    _initialize_repository(root)
    _write_text(root, "README.md", "constructed attestation audit repository\n")
    return _commit(root, "base", BASE_COMMIT_TIME)


def _repository_with_epoch(
    root: pathlib.Path, tree: pathlib.Path
) -> str:
    _base_repository(root)
    _materialize_reference(tree, root)
    return _commit(root, "introduce provenance verifier", EPOCH_COMMIT_TIME)


def zero_epoch_probe(
    root: pathlib.Path, tree: pathlib.Path
) -> str:
    _base_repository(root)
    _materialize_reference(tree, root)
    return (
        "enforcement epoch must be exactly one introducing commit for "
        "scripts/verify_records_attestations.py; found 0"
    )


def two_epoch_probe(
    root: pathlib.Path, tree: pathlib.Path
) -> str:
    _repository_with_epoch(root, tree)
    (root / BRIER_ATTEST_SPEC.checker_path).unlink()
    _commit(root, "remove provenance verifier", EPOCH_COMMIT_TIME + 1)
    shutil.copyfile(
        tree / BRIER_ATTEST_SPEC.checker_path,
        root / BRIER_ATTEST_SPEC.checker_path,
    )
    _commit(root, "reintroduce provenance verifier", EPOCH_COMMIT_TIME + 2)
    return (
        "enforcement epoch must be exactly one introducing commit for "
        "scripts/verify_records_attestations.py; found 2"
    )


EPOCH_REFUSAL_PROBES: tuple[
    tuple[str, Callable[[pathlib.Path, pathlib.Path], str]], ...
] = (
    ("zero_introductions", zero_epoch_probe),
    ("two_introductions", two_epoch_probe),
)


GH_STUB_SOURCE = r'''#!/usr/bin/env python3
import json
import os
import pathlib
import sys

config_path = pathlib.Path(os.environ["RECEIPT_ATTEST_STUB_CONFIG"])
state_path = pathlib.Path(os.environ["RECEIPT_ATTEST_STUB_STATE"])
run_name = os.environ["RECEIPT_ATTEST_STUB_RUN"]
subject_path = pathlib.Path(sys.argv[3])
subject_payload = subject_path.read_bytes()
commit = json.loads(subject_payload)["commit"]
config = json.loads(config_path.read_text())
state = json.loads(state_path.read_text())
run_calls = state.setdefault("calls", {}).setdefault(run_name, [])
call_index = sum(1 for call in run_calls if call["commit"] == commit)
run_calls.append(
    {
        "argv": sys.argv[1:],
        "commit": commit,
        "subject_name": subject_path.name,
        "subject_hex": subject_payload.hex(),
    }
)
state_path.write_text(json.dumps(state, sort_keys=True))
outcomes = config[commit]
outcome = outcomes[min(call_index, len(outcomes) - 1)]
sys.stdout.write(outcome.get("stdout", ""))
sys.stderr.write(outcome.get("stderr", ""))
raise SystemExit(outcome["returncode"])
'''


def _install_gh_stub(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    outcomes: dict[str, list[dict[str, object]]],
) -> GhStub:
    bin_dir = tmp_path / "stub-bin"
    bin_dir.mkdir()
    executable = bin_dir / "gh"
    executable.write_text(GH_STUB_SOURCE)
    executable.chmod(0o755)
    config = tmp_path / "gh-config.json"
    state = tmp_path / "gh-state.json"
    config.write_text(json.dumps(outcomes, sort_keys=True))
    state.write_text('{"calls": {}}')
    monkeypatch.setenv(
        "PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"
    )
    monkeypatch.setenv("RECEIPT_ATTEST_STUB_CONFIG", str(config))
    monkeypatch.setenv("RECEIPT_ATTEST_STUB_STATE", str(state))
    return GhStub(executable, state)


def _normalized_stub_calls(stub: GhStub, run_name: str) -> list[dict[str, Any]]:
    state = json.loads(stub.state.read_text())
    normalized: list[dict[str, Any]] = []
    for logged in state["calls"].get(run_name, []):
        argv = list(logged["argv"])
        argv[2] = f"<temporary>/{logged['subject_name']}"
        normalized.append({**logged, "argv": argv})
    return normalized


def _assert_stub_calls_match(
    stub: GhStub,
    commit: str,
    expected_calls: int,
) -> None:
    baseline = _normalized_stub_calls(stub, "baseline")
    candidate = _normalized_stub_calls(stub, "candidate")
    assert candidate == baseline
    assert len(candidate) == expected_calls
    expected_name = f"records-push-{commit}.json"
    expected_subject = attestation_subject(BRIER_ATTEST_SPEC.repository, commit)
    expected_argv = [
        "attestation",
        "verify",
        f"<temporary>/{expected_name}",
        "--repo",
        BRIER_ATTEST_SPEC.repository,
        "--cert-identity-regex",
        cert_identity_pattern(BRIER_ATTEST_SPEC),
        "--format",
        "json",
    ]
    for call in candidate:
        assert call["argv"] == expected_argv
        assert call["commit"] == commit
        assert call["subject_name"] == expected_name
        assert bytes.fromhex(call["subject_hex"]) == expected_subject


def _repository_with_record(
    root: pathlib.Path,
    tree: pathlib.Path,
    *,
    timestamp: int,
) -> tuple[str, str]:
    epoch = _repository_with_epoch(root, tree)
    _write_text(root, "records/example.json", '{"record":true}\n')
    commit = _commit(root, "add protected record", timestamp)
    return epoch, commit


def invalid_commit_subject_probe() -> tuple[str, str, str]:
    return (
        BRIER_ATTEST_SPEC.repository,
        "not-a-commit",
        "subject requires a full 40-hex commit sha: 'not-a-commit'",
    )


def invalid_repository_subject_probe() -> tuple[str, str, str]:
    return (
        "not a repository",
        "a" * 40,
        "invalid repository slug: 'not a repository'",
    )


SUBJECT_REFUSAL_PROBES: tuple[
    tuple[str, Callable[[], tuple[str, str, str]]], ...
] = (
    ("invalid_commit", invalid_commit_subject_probe),
    ("invalid_repository", invalid_repository_subject_probe),
)


def old_attestation_refusal_probe(
    commit: str,
) -> tuple[list[dict[str, object]], str]:
    detail = f"stub old-commit refusal for {commit}"
    return (
        [{"returncode": 1, "stderr": f"stub preface\n{detail}"}],
        f"{commit}: no valid attestation for its records push subject ({detail})",
    )


def fresh_attestation_exhaustion_probe(
    commit: str,
) -> tuple[list[dict[str, object]], str]:
    outcomes = [
        {
            "returncode": 1,
            "stderr": f"stub retry {attempt} for {commit}",
        }
        for attempt in range(1, 6)
    ]
    detail = f"stub final refusal for {commit}"
    outcomes.append(
        {"returncode": 1, "stderr": f"stub final preface\n{detail}"}
    )
    return (
        outcomes,
        f"{commit}: no valid attestation for its records push subject ({detail})",
    )


def old_stdout_attestation_refusal_probe(
    commit: str,
) -> tuple[list[dict[str, object]], str]:
    detail = f"stub stdout refusal for {commit}"
    return (
        [{"returncode": 1, "stdout": f"stub stdout preface\n{detail}"}],
        f"{commit}: no valid attestation for its records push subject ({detail})",
    )


def old_no_detail_attestation_refusal_probe(
    commit: str,
) -> tuple[list[dict[str, object]], str]:
    return (
        [{"returncode": 1}],
        f"{commit}: no valid attestation for its records push subject (no detail)",
    )


GH_REFUSAL_PROBES: tuple[
    tuple[
        str,
        int,
        int,
        tuple[float, ...],
        Callable[[str], tuple[list[dict[str, object]], str]],
    ],
    ...,
] = (
    ("old_refusal", OLD_RECORD_TIME, 1, (), old_attestation_refusal_probe),
    (
        "old_stdout_refusal",
        OLD_RECORD_TIME,
        1,
        (),
        old_stdout_attestation_refusal_probe,
    ),
    (
        "old_no_detail_refusal",
        OLD_RECORD_TIME,
        1,
        (),
        old_no_detail_attestation_refusal_probe,
    ),
    (
        "fresh_retry_exhaustion",
        FRESH_RECORD_TIME,
        6,
        (20, 20, 20, 20, 20),
        fresh_attestation_exhaustion_probe,
    ),
)


@pytest.mark.parametrize(
    ("repository", "commit"),
    (
        ("MaxGhenis/brier", "0" * 40),
        ("owner.example/repository-name", "a" * 40),
        ("Axiom_Foundation/receipt.py", "0123456789abcdef" * 2 + "01234567"),
    ),
)
def test_canonical_subject_bytes_match(
    brier_tree: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
    repository: str,
    commit: str,
) -> None:
    reference = _load_reference(brier_tree)
    expected = reference.subject_bytes(repository, commit)
    capfd.readouterr()
    candidate = attestation_subject(repository, commit)
    _assert_candidate_silent(capfd)
    assert candidate == expected
    assert candidate.endswith(b"\n")


@pytest.mark.parametrize(
    ("name", "probe"),
    SUBJECT_REFUSAL_PROBES,
    ids=[name for name, _probe in SUBJECT_REFUSAL_PROBES],
)
def test_subject_refusals_match_directly(
    brier_tree: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
    name: str,
    probe: Callable[[], tuple[str, str, str]],
) -> None:
    repository, commit, marker = probe()
    reference = _load_reference(brier_tree)
    with pytest.raises(ValueError) as baseline_error:
        reference.subject_bytes(repository, commit)
    capfd.readouterr()
    with pytest.raises(ValueError) as candidate_error:
        attestation_subject(repository, commit)
    _assert_candidate_silent(capfd)
    normalized_baseline = _normalize_openssl_ids(str(baseline_error.value))
    normalized_candidate = _normalize_openssl_ids(str(candidate_error.value))
    assert normalized_candidate == normalized_baseline, (
        f"divergent direct subject refusal for {name}"
    )
    assert marker in normalized_candidate


def test_single_enforcement_epoch_resolves_identically(
    brier_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "single-epoch"
    expected_epoch = _repository_with_epoch(root, brier_tree)
    reference = _load_reference(root)
    assert reference.enforcement_epoch() == expected_epoch
    capfd.readouterr()
    assert enforcement_epoch(root, spec=BRIER_ATTEST_SPEC) == expected_epoch
    _assert_candidate_silent(capfd)

    baseline = run_baseline(root)
    capfd.readouterr()
    candidate = run_candidate(root)
    _assert_candidate_silent(capfd)
    assert baseline.code == candidate.code == 0
    assert baseline.stderr == candidate.stderr == ""
    assert candidate.stdout == baseline.stdout
    assert f"{expected_epoch}..HEAD" in candidate.stdout


@pytest.mark.parametrize(
    ("name", "probe"),
    EPOCH_REFUSAL_PROBES,
    ids=[name for name, _probe in EPOCH_REFUSAL_PROBES],
)
def test_enforcement_epoch_refusals_match(
    brier_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
    name: str,
    probe: Callable[[pathlib.Path, pathlib.Path], str],
) -> None:
    root = tmp_path / name
    marker = probe(root, brier_tree)
    baseline = run_baseline(root)
    capfd.readouterr()
    candidate = run_candidate(root)
    _assert_candidate_silent(capfd)
    _assert_refused_identically(name, baseline, candidate, marker)


def test_full_history_selects_side_branch_commit_identically(
    brier_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "full-history"
    base = _base_repository(root)
    _write_text(root, "records/shared.json", '{"value":"base"}\n')
    base = _commit(root, "establish protected file", BASE_COMMIT_TIME + 1)

    _git(root, "switch", "--quiet", "--create", "side", base)
    _write_text(root, "records/shared.json", '{"value":"converged"}\n')
    side = _commit(root, "side protected change", BASE_COMMIT_TIME + 2)

    _git(root, "switch", "--quiet", "main")
    _materialize_reference(brier_tree, root)
    epoch = _commit(root, "introduce provenance verifier", EPOCH_COMMIT_TIME)
    _write_text(root, "records/shared.json", '{"value":"converged"}\n')
    main_record = _commit(root, "main protected change", EPOCH_COMMIT_TIME + 1)
    _git(
        root,
        "merge",
        "--quiet",
        "--no-ff",
        "side",
        "-m",
        "merge side history",
        timestamp=EPOCH_COMMIT_TIME + 2,
    )

    rev_range = f"{epoch}..HEAD"
    simplified = _git(
        root,
        "log",
        "--format=%H",
        rev_range,
        "--",
        BRIER_ATTEST_SPEC.protected_prefix,
    ).splitlines()
    assert side not in simplified, (
        "constructed graph no longer distinguishes --full-history from Git's "
        "default path simplification"
    )

    reference = _load_reference(root)
    baseline_commits = reference.records_commits(rev_range)
    baseline_selected = [
        commit
        for commit in baseline_commits
        if reference.commit_in_scope(commit, epoch)
    ]
    capfd.readouterr()
    candidate_commits = records_commits(
        root, rev_range, spec=BRIER_ATTEST_SPEC
    )
    candidate_selected = [
        commit
        for commit in candidate_commits
        if commit_in_scope(root, commit, epoch)
    ]
    _assert_candidate_silent(capfd)
    assert candidate_commits == baseline_commits
    assert set(candidate_commits) == {main_record, side}
    assert side in candidate_commits
    assert candidate_selected == baseline_selected
    assert set(candidate_selected) == {main_record, side}


def test_cert_identity_pattern_matches_exactly(
    brier_tree: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    reference = _load_reference(brier_tree)
    expected = reference.cert_identity_pattern(BRIER_ATTEST_SPEC.repository)
    capfd.readouterr()
    candidate = cert_identity_pattern(BRIER_ATTEST_SPEC)
    _assert_candidate_silent(capfd)
    assert candidate == expected
    assert candidate == (
        r"^https://github\.com/MaxGhenis/brier/"
        r"(\.github/workflows/prospect\-docket\.yml|"
        r"\.github/workflows/record\-forecasts\.yml|"
        r"\.github/workflows/resolve\-and\-rebuild\.yml|"
        r"\.github/workflows/roll\-docket\.yml|"
        r"\.github/workflows/strategy\-docket\.yml)@refs/heads/main$"
    )


@pytest.mark.parametrize(
    ("name", "timestamp", "retry", "expected_calls", "expected_sleeps"),
    (
        ("old_accept", OLD_RECORD_TIME, False, 1, ()),
        ("fresh_retry_accept", FRESH_RECORD_TIME, True, 2, (20,)),
    ),
    ids=("old_accept", "fresh_retry_accept"),
)
def test_gh_accept_and_retry_grace_match(
    brier_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    name: str,
    timestamp: int,
    retry: bool,
    expected_calls: int,
    expected_sleeps: tuple[float, ...],
) -> None:
    root = tmp_path / name
    _epoch, commit = _repository_with_record(
        root, brier_tree, timestamp=timestamp
    )
    success = {
        "returncode": 0,
        "stdout": json.dumps(
            [
                {
                    "verificationResult": {
                        "signature": {
                            "certificate": {
                                "subjectAlternativeName": ALLOWED_IDENTITY
                            }
                        }
                    }
                }
            ]
        ),
    }
    scripted = (
        [{"returncode": 1, "stderr": "stub indexing delay"}, success]
        if retry
        else [success]
    )
    stub = _install_gh_stub(tmp_path, monkeypatch, {commit: scripted})

    monkeypatch.setenv("RECEIPT_ATTEST_STUB_RUN", "baseline")
    baseline = run_baseline(root)
    capfd.readouterr()
    monkeypatch.setenv("RECEIPT_ATTEST_STUB_RUN", "candidate")
    candidate = run_candidate(root)
    _assert_candidate_silent(capfd)

    assert baseline.code == candidate.code == 0
    assert baseline.stderr == candidate.stderr == ""
    assert candidate.stdout == baseline.stdout
    assert f"records provenance OK: {commit} <- github.com/" in candidate.stdout
    assert candidate.sleeps == baseline.sleeps == expected_sleeps
    _assert_stub_calls_match(stub, commit, expected_calls)


@pytest.mark.parametrize(
    ("name", "timestamp", "expected_calls", "expected_sleeps", "probe"),
    GH_REFUSAL_PROBES,
    ids=[name for name, *_rest in GH_REFUSAL_PROBES],
)
def test_gh_refusals_match(
    brier_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    name: str,
    timestamp: int,
    expected_calls: int,
    expected_sleeps: tuple[float, ...],
    probe: Callable[[str], tuple[list[dict[str, object]], str]],
) -> None:
    root = tmp_path / name
    _epoch, commit = _repository_with_record(
        root, brier_tree, timestamp=timestamp
    )
    scripted, marker = probe(commit)
    stub = _install_gh_stub(tmp_path, monkeypatch, {commit: scripted})

    monkeypatch.setenv("RECEIPT_ATTEST_STUB_RUN", "baseline")
    baseline = run_baseline(root)
    capfd.readouterr()
    monkeypatch.setenv("RECEIPT_ATTEST_STUB_RUN", "candidate")
    candidate = run_candidate(root)
    _assert_candidate_silent(capfd)

    _assert_refused_identically(name, baseline, candidate, marker)
    assert candidate.sleeps == baseline.sleeps == expected_sleeps
    _assert_stub_calls_match(stub, commit, expected_calls)


def invalid_remote_probe(root: pathlib.Path) -> str:
    malformed = "ssh://example.invalid/not-github"
    _git(root, "remote", "set-url", "origin", malformed)
    return f"cannot derive repository slug from {malformed!r}"


def test_repository_slug_refusal_matches(
    brier_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "invalid-remote"
    _repository_with_epoch(root, brier_tree)
    marker = invalid_remote_probe(root)
    baseline = run_baseline(root)
    capfd.readouterr()
    candidate = run_candidate(root)
    _assert_candidate_silent(capfd)
    _assert_refused_identically("invalid_remote", baseline, candidate, marker)


def invalid_merge_base_probe() -> tuple[str, str]:
    commit = "0" * 40
    return commit, f"merge-base --is-ancestor failed for {commit}:"


def test_merge_base_fatal_refusal_matches_directly(
    brier_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "merge-base-fatal"
    epoch = _repository_with_epoch(root, brier_tree)
    commit, marker = invalid_merge_base_probe()
    reference = _load_reference(root)
    with pytest.raises(reference.ProvenanceError) as baseline_error:
        reference.commit_in_scope(commit, epoch)
    capfd.readouterr()
    with pytest.raises(ProvenanceError) as candidate_error:
        commit_in_scope(root, commit, epoch)
    _assert_candidate_silent(capfd)
    normalized_baseline = _normalize_openssl_ids(str(baseline_error.value))
    normalized_candidate = _normalize_openssl_ids(str(candidate_error.value))
    assert normalized_candidate == normalized_baseline
    assert marker in normalized_candidate


@pytest.mark.parametrize(
    "dependency",
    ("scripts/attest_subject.py", "scripts/canonical_json.py"),
)
def test_swapped_runtime_import_fails_authentication(
    brier_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    dependency: str,
) -> None:
    fake = tmp_path / "tree"
    (fake / "scripts").mkdir(parents=True)
    for relative in BASELINE_AUTHENTICATED_FILES:
        shutil.copyfile(brier_tree / relative, fake / relative)
    path = fake / dependency
    path.write_bytes(path.read_bytes() + b"\n# tampered\n")
    with pytest.raises(RuntimeError, match=re.escape(path.name)):
        _load_reference(fake)
