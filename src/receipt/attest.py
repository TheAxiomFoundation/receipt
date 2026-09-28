"""Verify workflow provenance for commits touching a protected tree.

This module is a spec-parameterized port of brier's pinned
``verify_records_attestations.py`` and ``attest_subject.py``.  It contains no
repository policy: the repository, workflow identities, ref, protected path,
and self-anchoring checker path all arrive in a frozen :class:`AttestSpec`
committed by the consumer.

Git and ``gh attestation verify`` remain subprocess boundaries.  Every
subprocess stream is captured, so these helpers are silent library calls; the
caller decides how to render accepted and refused outcomes.

Every git child answers about the repository ``root`` names, as its objects
record it: it runs with ``--no-replace-objects`` and
``core.commitGraph=false`` and with every inherited ``GIT_*`` variable
dropped (:func:`_git_environment`), the history walks refuse shallow and
grafted repositories, and revisions are passed after ``--end-of-options``.  Configuration files are read where git finds them by
default.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from receipt.canonical import canonical_bytes


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SUBJECT_SCHEMA = "thesis_records_push_subject_v1"
SIGNER_RE = re.compile(
    r"github\.com/(?P<repo>[^/]+/[^/]+)/(?P<workflow>\.github/workflows/[^@]+)"
    r"@(?P<ref>refs/\S+)"
)

# Protocol mechanics retained from the pinned verifier.  These values do not
# identify a trusted repository, signer, or ref; all such policy is in
# AttestSpec.
FRESH_COMMIT_GRACE_SECONDS = 15 * 60
VERIFY_RETRIES = 6
VERIFY_RETRY_DELAY_SECONDS = 20


class ProvenanceError(RuntimeError):
    """A protected-tree commit failed provenance verification."""


def _repository_slug(repository: object) -> str:
    if not isinstance(repository, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
    ):
        raise ValueError(f"invalid repository slug: {repository!r}")
    return repository


def _relative_posix_path(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if "\\" in value or "\x00" in value or "\n" in value or "\r" in value:
        return None
    path = pathlib.PurePosixPath(value)
    parts = value[:-1].split("/") if value.endswith("/") else value.split("/")
    if path.is_absolute() or any(part in {"", ".", ".."} for part in parts):
        return None
    return value


@dataclass(frozen=True)
class AttestSpec:
    """Consumer-committed workflow-provenance policy.

    Every field is required.  ``allowed_workflows`` is normalized to a
    ``frozenset`` so the frozen spec does not retain a mutable policy object.
    """

    repository: str
    allowed_workflows: frozenset[str]
    allowed_ref: str
    protected_prefix: str
    checker_path: pathlib.PurePosixPath

    def __post_init__(self) -> None:
        _repository_slug(self.repository)

        workflows_value: object = self.allowed_workflows
        if isinstance(workflows_value, (str, bytes)) or not isinstance(
            workflows_value, Iterable
        ):
            raise ValueError(
                "allowed_workflows must be a non-empty collection of workflow paths"
            )
        try:
            workflows = frozenset(workflows_value)
        except TypeError as exc:
            raise ValueError(
                "allowed_workflows must be a non-empty collection of workflow paths"
            ) from exc
        if not workflows:
            raise ValueError(
                "allowed_workflows must be a non-empty collection of workflow paths"
            )
        for workflow in sorted(workflows, key=repr):
            if (
                _relative_posix_path(workflow) is None
                or not isinstance(workflow, str)
                or not workflow.startswith(".github/workflows/")
                or workflow == ".github/workflows/"
                or "@" in workflow
            ):
                raise ValueError(f"invalid allowed workflow path: {workflow!r}")
        object.__setattr__(self, "allowed_workflows", workflows)

        if (
            not isinstance(self.allowed_ref, str)
            or not self.allowed_ref.startswith("refs/")
            or self.allowed_ref == "refs/"
            or "@" in self.allowed_ref
            or re.search(r"\s", self.allowed_ref)
        ):
            raise ValueError(f"invalid allowed ref: {self.allowed_ref!r}")

        if _relative_posix_path(self.protected_prefix) is None:
            raise ValueError(f"invalid protected prefix: {self.protected_prefix!r}")

        checker_value: object = self.checker_path
        if isinstance(checker_value, pathlib.PurePosixPath):
            checker_text = checker_value.as_posix()
        elif isinstance(checker_value, str):
            checker_text = checker_value
        else:
            checker_text = ""
        if _relative_posix_path(checker_text) is None:
            raise ValueError(f"invalid checker path: {checker_value!r}")
        if checker_text.endswith("/"):
            raise ValueError(f"invalid checker path: {checker_value!r}")
        object.__setattr__(self, "checker_path", pathlib.PurePosixPath(checker_text))


def attestation_subject(repository: str, commit: str) -> bytes:
    """Return the canonical records-push subject, including its final newline."""

    if not COMMIT_RE.fullmatch(commit):
        raise ValueError(f"subject requires a full 40-hex commit sha: {commit!r}")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError(f"invalid repository slug: {repository!r}")
    return (
        canonical_bytes(
            {
                "schemaVersion": SUBJECT_SCHEMA,
                "repository": repository,
                "commit": commit,
            }
        )
        + b"\n"
    )


# Keep the pinned producer's helper name available at the same public joint.
subject_bytes = attestation_subject


def subject_name(commit: str) -> str:
    return f"records-push-{commit}.json"


def _git_environment() -> dict[str, str]:
    """Return the environment for every git child of this module.

    Every inherited name beginning ``GIT_`` is removed.  ``GIT_DIR``,
    ``GIT_WORK_TREE``, ``GIT_OBJECT_DIRECTORY`` and
    ``GIT_ALTERNATE_OBJECT_DIRECTORIES`` each answered a query from somewhere
    other than ``root``, so a sweep could accept by reading another
    repository's history; ``GIT_GRAFT_FILE``, ``GIT_REPLACE_REF_BASE`` and the
    ``GIT_CONFIG_*`` channels could reshape the history walked.  Removing the
    whole prefix also covers names a later git adds.  The release-chain
    entries refuse the redirecting variables instead, because they also read
    the tree directly and a drop would leave two subjects; this module reads
    the repository only through git, so dropping them leaves one.
    ``GIT_NO_REPLACE_OBJECTS=1`` is then installed, matching the
    ``--no-replace-objects`` every command carries: a ``refs/replace/`` ref
    fetched with the repository substituted another commit's tree for the one
    a branch names, and the sweep walked the substitute.
    """

    environment = {
        name: value for name, value in os.environ.items() if not name.startswith("GIT_")
    }
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    return environment


def _git_command(*args: str) -> list[str]:
    """Return the argv for one git child of this module.

    ``core.commitGraph=false`` makes git read parents and root trees from the
    commit objects rather than from the commit-graph file, a cache git trusts
    without checking it against them: a stale or altered graph entry gave a
    records commit below the tip its parent's tree, and the path-limited walk
    then passed over it.
    """

    return ["git", "--no-replace-objects", "-c", "core.commitGraph=false", *args]


def git_output(root: pathlib.Path, *args: str) -> str:
    """Run a captured git query in ``root`` and return stripped text.

    The query carries :func:`_git_command`'s options and runs under
    :func:`_git_environment`.
    """

    return subprocess.check_output(
        _git_command(*args),
        cwd=root,
        env=_git_environment(),
        text=True,
        stderr=subprocess.PIPE,
    ).strip()


def _refuse_rewritten_history(root: pathlib.Path) -> None:
    """Refuse a repository whose history git would walk only in part.

    In a shallow clone git treats each boundary commit as a root, so the
    boundary appeared to introduce the checker: :func:`enforcement_epoch`
    named it, :func:`commit_in_scope` exempted it as its own ancestor, and the
    default range after it was empty.  A depth-1 clone, the GitHub Actions
    checkout default, therefore accepted an unattested protected-tree commit
    at its tip without a refusal.  A graft file rewrites parents the same way,
    and git honors it with replace objects off.  Both refuse, in the words
    the tree-snapshot reader uses; the fix for a shallow checkout is the whole
    history (``fetch-depth: 0``).
    """

    if git_output(root, "rev-parse", "--is-shallow-repository") != "false":
        raise ProvenanceError("shallow repositories are unsupported")
    grafts = git_output(root, "rev-parse", "--git-path", "info/grafts")
    if os.path.lexists(pathlib.Path(root) / grafts):
        raise ProvenanceError("repository grafts are unsupported")


def enforcement_epoch(root: pathlib.Path, *, spec: AttestSpec) -> str:
    _refuse_rewritten_history(root)
    commits = git_output(
        root,
        "log",
        "--full-history",
        "--diff-filter=A",
        "--format=%H",
        "--",
        spec.checker_path.as_posix(),
    ).splitlines()
    if len(commits) != 1:
        raise ProvenanceError(
            "enforcement epoch must be exactly one introducing commit for "
            f"{spec.checker_path.as_posix()}; found {len(commits)}"
        )
    return commits[0]


def records_commits(
    root: pathlib.Path,
    rev_range: str,
    *,
    spec: AttestSpec,
) -> list[str]:
    """Enumerate protected-tree commits without simplifying merge history.

    ``rev_range`` is read as revisions only: a value git would otherwise take
    as an option, which could empty the sweep, is refused by git instead.
    """

    _refuse_rewritten_history(root)
    # --full-history: path simplification may otherwise drop a protected-tree
    # commit that arrived on a side branch.
    output = git_output(
        root,
        "log",
        "--full-history",
        "--format=%H",
        "--end-of-options",
        rev_range,
        "--",
        spec.protected_prefix,
    )
    return output.splitlines() if output else []


def commit_age_seconds(
    root: pathlib.Path,
    commit: str,
    *,
    now: float | None = None,
) -> int:
    committed = int(
        git_output(root, "show", "-s", "--format=%ct", "--end-of-options", commit)
    )
    current = time.time() if now is None else now
    return max(0, int(current) - committed)


def repository_slug(root: pathlib.Path) -> str:
    """Derive an exact GitHub ``owner/name`` from an HTTPS, SSH or SCP origin.

    URL authorities may carry a user and port; host comparison ignores ASCII case.
    One trailing slash and a terminal ``.git`` are removed, preserving periods
    inside the repository name. Queries, fragments and other path shapes refuse.
    """

    # Preserve the configured value's whitespace and control bytes for the
    # guard below; only the command's one framing newline may be removed.
    raw_url = subprocess.check_output(
        _git_command("remote", "get-url", "origin"),
        cwd=root,
        env=_git_environment(),
        stderr=subprocess.PIPE,
    )
    url = raw_url.removesuffix(b"\n").decode("utf-8", errors="surrogateescape")
    try:
        if "?" in url or "#" in url or any(
            character.isspace() or ord(character) < 32 for character in url
        ):
            raise ValueError
        if "://" in url:
            parsed = urlsplit(url)
            if parsed.scheme not in {"https", "ssh"} or not re.fullmatch(
                r"(?:[^@:/\s]+@)?github\.com(?::[0-9]+)?",
                parsed.netloc,
                re.IGNORECASE | re.ASCII,
            ):
                raise ValueError
            # Accessing port validates its numeric range as well as its syntax.
            _ = parsed.port
            path = parsed.path.removeprefix("/")
        else:
            match = re.fullmatch(
                r"[^@:/\s]+@github\.com:(.+)", url, re.IGNORECASE | re.ASCII
            )
            if match is None:
                raise ValueError
            path = match.group(1)
        owner, name = path.removesuffix("/").split("/")
        name = name.removesuffix(".git")
        if owner in {".", ".."} or name in {".", ".."}:
            raise ValueError
        return _repository_slug(f"{owner}/{name}")
    except ValueError:
        raise ProvenanceError(
            f"cannot derive repository slug from {url!r}"
        ) from None


def extract_certificate_identities(payload: object) -> set[str]:
    """Return signer URIs from verificationResult.signature.certificate only."""

    identities: set[str] = set()
    results = payload if isinstance(payload, list) else [payload]
    for result in results:
        if not isinstance(result, dict):
            continue
        certificate = (
            (result.get("verificationResult") or {})
            .get("signature", {})
            .get("certificate", {})
            if isinstance(result.get("verificationResult"), dict)
            else {}
        )
        if not isinstance(certificate, dict):
            continue
        for value in certificate.values():
            if isinstance(value, str):
                for match in SIGNER_RE.finditer(value):
                    identities.add(match.group(0))
    return identities


def cert_identity_pattern(spec: AttestSpec) -> str:
    """Return the exact signer-identity regex that ``gh`` must enforce."""

    workflows = "|".join(
        re.escape(workflow) for workflow in sorted(spec.allowed_workflows)
    )
    return (
        f"^https://github\\.com/{re.escape(spec.repository)}/"
        f"({workflows})@{re.escape(spec.allowed_ref)}$"
    )


def verify_commit(
    root: pathlib.Path,
    commit: str,
    *,
    spec: AttestSpec,
    now: float | None = None,
    sleep: Callable[[float], None] | None = None,
) -> str:
    """Verify one commit's attestation; return the accepted signer identity."""

    payload = attestation_subject(spec.repository, commit)
    with tempfile.TemporaryDirectory() as tmp:
        subject_path = pathlib.Path(tmp) / subject_name(commit)
        subject_path.write_bytes(payload)
        age = (
            commit_age_seconds(root, commit)
            if now is None
            else commit_age_seconds(root, commit, now=now)
        )
        attempts = VERIFY_RETRIES if age < FRESH_COMMIT_GRACE_SECONDS else 1
        last_error = ""
        for attempt in range(1, attempts + 1):
            completed = subprocess.run(
                [
                    "gh",
                    "attestation",
                    "verify",
                    str(subject_path),
                    "--repo",
                    spec.repository,
                    "--cert-identity-regex",
                    cert_identity_pattern(spec),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if completed.returncode == 0:
                # gh already enforced the certificate identity; parse it back
                # out of the certificate fields for the log line only.
                try:
                    parsed = json.loads(completed.stdout)
                except json.JSONDecodeError:
                    parsed = None
                identities = extract_certificate_identities(parsed)
                return sorted(identities)[0] if identities else "<verified>"
            last_error = (completed.stderr or completed.stdout).strip()
            if attempt < attempts:
                (time.sleep if sleep is None else sleep)(
                    VERIFY_RETRY_DELAY_SECONDS
                )
        raise ProvenanceError(
            f"{commit}: no valid attestation for its records push subject "
            f"({last_error.splitlines()[-1] if last_error else 'no detail'})"
        )


def commit_in_scope(root: pathlib.Path, commit: str, epoch: str) -> bool:
    """Exempt only commits proven ancestors of the enforcement epoch."""

    _refuse_rewritten_history(root)
    probe = subprocess.run(
        _git_command("merge-base", "--is-ancestor", "--end-of-options", commit, epoch),
        cwd=root,
        env=_git_environment(),
        capture_output=True,
        check=False,
    )
    if probe.returncode == 0:
        return False
    if probe.returncode == 1:
        return True
    raise ProvenanceError(
        f"merge-base --is-ancestor failed for {commit}: "
        f"{probe.stderr.decode(errors='replace').strip()}"
    )
