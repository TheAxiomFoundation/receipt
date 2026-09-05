"""Read and authenticate one immutable Git tree without consulting a checkout.

``TreeSnapshot`` selects a commit, parses canonical commit and raw tree
objects, and authenticates every fetched payload as
``<type> <size>\0<payload>``. A named object is type-bound before its payload
is used. Gitlinks are the sole exception: mode ``160000`` records a foreign
commit name, is never fetched, and need not exist locally. An unrelated blob
which a caller never reads is name- and type-bound by a tree walk, but this
module makes no claim about that blob's bytes.

The working tree and index are never subjects of this reader. The private
configuration setup and Git version children are not repository-addressed and
run from their own private temporary directories, never the caller's cwd.
Discovery uses the worktree only to establish that ``root`` is the repository
top level; every object operation thereafter carries an absolute ``--git-dir``
and ``--no-replace-objects``. All inherited ``GIT_*`` variables are discarded,
the three variables in :func:`_git_environment` are installed, and ``HOME`` is
deliberately preserved. Repository configuration is audited without includes
at selection and again at close. A same-owner configuration writer is not
excluded, but changed configuration or repository-control sentinel files are
rechecked at child boundaries and refused. A writer racing between one check
and the following system call remains a same-owner residual.

The configuration audit is scoped to the frozen :data:`GIT_COMMANDS`: private
``safe.directory`` setup; version, repository discovery, and configuration
listing; explicit revision resolution and the batch child; and the optional
object count and ``fsck``. Includes, program-valued keys, partial-clone and
promisor keys, and every family that can weaken ``fsck`` are denied in local
or worktree scope. Other repository keys are inert for this exact command set;
adding a command therefore requires revisiting both the allow-list and that
claim.

The default SHA-1 rehash closes substitution only to ordinary SHA-1 collision
resistance. :meth:`TreeSnapshot.verify_object_store` widens the subject from
the selected trees to the whole primary object database and asks Git's SHA1DC
``fsck`` to examine it. Git's own memory use during that command remains
Git's. Alternates are refused, so the primary database is the entire store.
SHA-256 repositories fail closed until a commit/tree/blob/corruption fixture
exists. Bare repositories, worktree snapshots, and index snapshots are not
supported.

Resource budgets are constants rather than input-derived guesses:

Candidate and base snapshots join one verification budget when they are
compared or ancestry is proved with the base snapshot object. Tree-object
bytes remain per snapshot as specified; path, attribute, content, and
materialization totals are then enforced across both snapshots together.

* ``MAX_TREE_ENTRIES`` is 1,048,576 entries per walk, versus 15,216 measured
  rulespec-us blobs, and bounds traversal and whole-tree alias work.
* ``MAX_TREE_OBJECT_BYTES`` is 64 MiB per commit or tree, checked from ``info``
  before payload bytes move. ``MAX_TREE_BYTES_TOTAL`` is 512 MiB of commit and
  tree payloads per snapshot; rulespec-us has 2,597 commits.
* ``MAX_ENTRY_NAME_BYTES`` and ``MAX_PATH_BYTES`` are each 4,096 bytes.
  ``MAX_PATH_BYTES_TOTAL`` is 256 MiB across paths built on demand. Listings
  are hierarchical so a long prefix is stored once rather than per leaf.
* ``MAX_GIT_OUTPUT_BYTES`` is 1 MiB for every non-batch, non-fsck Git call.
  ``MAX_GIT_SECONDS`` is 60 seconds for those calls and each batch response
  and graceful close. ``BATCH_KILL_REAP_SECONDS`` gives a killed batch child a
  fresh 5 seconds to be reaped after that graceful-close budget is spent.
* ``MAX_TREE_DEPTH`` is 256 and ``MAX_ANCESTRY_COMMITS`` is 1,048,576,
  bounding hostile nesting and parent walks while remaining above real trees.
* ``MAX_ATTRIBUTE_BYTES`` is 1 MiB per attributes file;
  ``MAX_ATTRIBUTE_BYTES_TOTAL`` is 16 MiB and
  ``MAX_ATTRIBUTE_RULES_TOTAL`` is 65,536 per verification.
  ``MAX_ATTRIBUTE_STATES_PER_LINE`` is 256; Git has no corresponding limit,
  but this bounds one matching rule's application fan-out and is far above
  Chronicle's maximum of three expanded states on one line.
  ``MAX_ATTRIBUTE_MATCH_WORK`` is 67,108,864 matcher transitions and applied
  states. Checks cover protected paths only, making this generous for
  Chronicle's small surface.
  Git 2.53.0 skips blank and comment lines before any other test, discards
  rule lines at least 2,048 bytes long and rules naming an invalid or
  reserved attribute, and stops reading a blob at an embedded NUL; this
  reader skips the same lines and refuses each discarding case and the NUL,
  so discarded input cannot silently change rule precedence.
* ``MAX_CONTENT_BLOB_BYTES`` is 256 MiB per streamed content object and
  ``MAX_CONTENT_BYTES_TOTAL`` is 16 GiB. The largest measured rulespec-us blob
  is 6,550,684 bytes and all 15,216 blobs total 107,132,889 bytes.
* ``MAX_MATERIALIZED_BLOB_BYTES`` is 64 MiB because downstream manifest and
  signature readers hold a file whole. ``MAX_MATERIALIZED_BYTES`` is 4 GiB,
  charged for every byte written into the private directory.
* ``MAX_FSCK_OBJECTS`` is 4,194,304 and ``MAX_STORE_KIB`` is 16 GiB expressed
  as 16,777,216 KiB, versus 79,890 measured rulespec-us objects.
  ``MAX_FSCK_OUTPUT_BYTES`` is 1 MiB and ``MAX_FSCK_SECONDS`` is 600 seconds.

Git 2.36.0 is the reader floor because it introduced ``cat-file
--batch-command``. The frozen ``fsck --no-references`` invocation was added
to Git in 2.50.0; optional store verification therefore fails closed on 2.36
through 2.49 instead of pretending that option exists. This resolves an
inconsistency in the frozen plan without weakening either command.

Where the plan fixes no refusal text or representation detail, this module
fails closed: malformed protocol/header bytes, malformed raw trees,
unsupported repository state, invalid public arguments, and exhausted
budgets raise :class:`SnapshotError` rather than being coerced.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from bisect import bisect_left
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import BinaryIO, Callable

from receipt._names import (
    NamePolicyError,
    assert_no_merging_entries,
    validate_component_bytes,
    validate_repertoire,
)


GIT_MIN_VERSION = (2, 36, 0)
GIT_FSCK_NO_REFERENCES_MIN_VERSION = (2, 50, 0)

MAX_TREE_ENTRIES = 1_048_576
MAX_TREE_OBJECT_BYTES = 64 * 1024 * 1024
MAX_TREE_BYTES_TOTAL = 512 * 1024 * 1024
MAX_ENTRY_NAME_BYTES = 4_096
MAX_PATH_BYTES = 4_096
MAX_PATH_BYTES_TOTAL = 256 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 1 * 1024 * 1024
MAX_GIT_SECONDS = 60
BATCH_KILL_REAP_SECONDS = 5
MAX_TREE_DEPTH = 256
MAX_ANCESTRY_COMMITS = 1_048_576
MAX_ATTRIBUTE_BYTES = 1 * 1024 * 1024
MAX_ATTRIBUTE_BYTES_TOTAL = 16 * 1024 * 1024
MAX_ATTRIBUTE_RULES_TOTAL = 65_536
MAX_ATTRIBUTE_STATES_PER_LINE = 256
MAX_ATTRIBUTE_MATCH_WORK = 67_108_864
MAX_CONTENT_BLOB_BYTES = 256 * 1024 * 1024
MAX_CONTENT_BYTES_TOTAL = 16 * 1024 * 1024 * 1024
MAX_MATERIALIZED_BYTES = 4 * 1024 * 1024 * 1024
MAX_MATERIALIZED_BLOB_BYTES = 64 * 1024 * 1024
MAX_FSCK_OBJECTS = 4_194_304
MAX_STORE_KIB = 16 * 1024 * 1024
MAX_FSCK_OUTPUT_BYTES = 1 * 1024 * 1024
MAX_FSCK_SECONDS = 600

_BATCH_CHUNK_BYTES = 1024 * 1024
_BATCH_HEADER_BYTES = 4096
_RAW_MODES = frozenset({b"100644", b"100755", b"120000", b"160000", b"40000"})
_CONTENT_MODES = frozenset({"100644", "100755"})
_OID_RE = re.compile(rb"[0-9a-f]+\Z")
_VERSION_RE = re.compile(r"\bgit version (\d+)\.(\d+)\.(\d+)")
_SURROGATE_PAIR_RE = re.compile("[\ud800-\udbff][\udc00-\udfff]")


def _tree_path_decode(value: bytes) -> str:
    """Decode logical Git path bytes independently of the host filesystem."""

    return value.decode("utf-8", errors="surrogateescape")


def _tree_path_encode(value: str) -> bytes:
    """Encode logical Git path text independently of the host filesystem."""

    return value.encode("utf-8", errors="surrogateescape")


def _validate_expected_oid(value: object, *, label: str, object_format: str) -> str:
    """Return an exact auditor expectation without invoking hostile equality."""

    width = hashlib.new(object_format).digest_size * 2
    if (
        type(value) is not str
        or len(value) != width
        or re.fullmatch(r"[0-9a-f]+", value) is None
    ):
        raise SnapshotError(
            f"expected {label} must be a full lowercase hexadecimal object name"
        )
    return value


class SnapshotError(ValueError):
    """The repository cannot produce the authenticated immutable snapshot."""


@dataclass(frozen=True)
class GitEntry:
    """One tree entry, with Git's six-digit display mode and full path.

    The private binding is deliberately excluded from equality and repr. It
    lets payload APIs refuse entries forged, altered with ``replace()``, or
    obtained from a different snapshot without turning every streamed blob
    into a second path walk. Four-argument construction remains
    source-compatible, but an unbound entry cannot authorize an object read.
    """

    mode: str
    object_type: str
    object_id: str
    path: str
    _snapshot_token: object | None = field(
        default=None, repr=False, compare=False
    )


@dataclass(frozen=True)
class _EntryBinding:
    snapshot_token: object
    mode: str
    object_type: str
    object_id: str
    path: str


@dataclass(frozen=True)
class ObjectStoreReport:
    """The bounded result of an explicitly requested primary-store fsck."""

    objects: int
    store_kib: int
    seconds: float


@dataclass
class SnapshotWork:
    """Observable work counters used to prove fixtures remain below ceilings."""

    tree_entries: int = 0
    max_tree_entries_in_walk: int = 0
    tree_bytes: int = 0
    max_tree_object_bytes: int = 0
    path_bytes: int = 0
    max_path_bytes: int = 0
    ancestry_commits: int = 0
    ancestry_edges: int = 0
    attribute_bytes: int = 0
    attribute_rules: int = 0
    attribute_match_work: int = 0
    content_bytes: int = 0
    max_content_blob_bytes: int = 0
    materialized_bytes: int = 0
    max_materialized_blob_bytes: int = 0


@dataclass
class _WorkPool:
    """Union-find node grouping verification-wide counters across snapshots."""

    works: list[SnapshotWork]
    parent: "_WorkPool | None" = None

    def root(self) -> "_WorkPool":
        if self.parent is None:
            return self
        self.parent = self.parent.root()
        return self.parent


@dataclass(frozen=True)
class _RawTreeEntry:
    mode: bytes
    name: bytes
    oid: str

    @property
    def display_mode(self) -> str:
        return "040000" if self.mode == b"40000" else self.mode.decode("ascii")

    @property
    def object_type(self) -> str:
        if self.mode == b"40000":
            return "tree"
        if self.mode == b"160000":
            return "commit"
        return "blob"


@dataclass(frozen=True)
class _CommitObject:
    oid: str
    tree: str
    parents: tuple[str, ...]


@dataclass
class _SnapshotState:
    root: pathlib.Path
    common_dir: pathlib.Path
    revision: str
    version: tuple[int, int, int]
    config_records: tuple[tuple[str, str, str], ...]
    global_config_bytes: bytes
    verify_objects_ready: bool
    selected_commit: _CommitObject
    root_tree: tuple[_RawTreeEntry, ...]
    work: SnapshotWork
    work_pool: _WorkPool
    tree_cache: dict[str, tuple[_RawTreeEntry, ...]]
    commit_cache: dict[str, _CommitObject]
    entry_token: object = field(default_factory=object)
    ancestry_bases: set[str] = field(default_factory=set)
    object_store_attempted: bool = False
    attribute_cache: dict[str, tuple["_AttributeRule", ...]] = field(
        default_factory=dict
    )
    entered: bool = False
    closed: bool = False
    abandoned: bool = False
    active_digest_token: object | None = None
    batch: "_BatchReader | None" = None
    tempdir: "tempfile.TemporaryDirectory[str] | None" = None
    global_config: pathlib.Path | None = None


# These are the 73 variables documented by git(1) 2.53.0. Enforcement is the
# prefix rule in _git_environment; this tuple makes the boundary reviewable.
GIT_ENVIRONMENT_DROPPED_DOCUMENTED = (
    "GIT_ADVICE",
    "GIT_ALLOW_PROTOCOL",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_ASKPASS",
    "GIT_ATTR_SOURCE",
    "GIT_AUTHOR_DATE",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_NAME",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMITTER_DATE",
    "GIT_COMMITTER_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMIT_GRAPH_PARANOIA",
    "GIT_COMMON_DIR",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_SYSTEM",
    "GIT_DEFAULT_HASH",
    "GIT_DEFAULT_REF_FORMAT",
    "GIT_DIFF_OPTS",
    "GIT_DIFF_PATH_COUNTER",
    "GIT_DIFF_PATH_TOTAL",
    "GIT_DIR",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_EDITOR",
    "GIT_EXEC_PATH",
    "GIT_EXTERNAL_DIFF",
    "GIT_EXTERNAL_DIFF_TRUST_EXIT_CODE",
    "GIT_FLUSH",
    "GIT_GLOB_PATHSPECS",
    "GIT_ICASE_PATHSPECS",
    "GIT_INDEX_FILE",
    "GIT_INDEX_VERSION",
    "GIT_LITERAL_PATHSPECS",
    "GIT_MERGE_VERBOSITY",
    "GIT_NAMESPACE",
    "GIT_NOGLOB_PATHSPECS",
    "GIT_NO_LAZY_FETCH",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_OBJECT_DIRECTORY",
    "GIT_OPTIONAL_LOCKS",
    "GIT_PAGER",
    "GIT_PRINT_SHA1_ELLIPSIS",
    "GIT_PROGRESS_DELAY",
    "GIT_PROTOCOL",
    "GIT_PROTOCOL_FROM_USER",
    "GIT_REDIRECT_STDERR",
    "GIT_REDIRECT_STDIN",
    "GIT_REDIRECT_STDOUT",
    "GIT_REFLOG_ACTION",
    "GIT_REF_PARANOIA",
    "GIT_SEQUENCE_EDITOR",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_SSH_VARIANT",
    "GIT_SSL_NO_VERIFY",
    "GIT_TERMINAL_PROMPT",
    "GIT_TRACE",
    "GIT_TRACE2",
    "GIT_TRACE2_EVENT",
    "GIT_TRACE2_PERF",
    "GIT_TRACE_CURL",
    "GIT_TRACE_CURL_NO_DATA",
    "GIT_TRACE_FSMONITOR",
    "GIT_TRACE_PACKET",
    "GIT_TRACE_PACKFILE",
    "GIT_TRACE_PACK_ACCESS",
    "GIT_TRACE_PERFORMANCE",
    "GIT_TRACE_REDACT",
    "GIT_TRACE_REFS",
    "GIT_TRACE_SETUP",
    "GIT_TRACE_SHALLOW",
    "GIT_WORK_TREE",
)

GIT_ENVIRONMENT_DROPPED_UNDOCUMENTED = (
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_<n>",
    "GIT_CONFIG_VALUE_<n>",
)

GIT_ENVIRONMENT_DROPPED = (
    *GIT_ENVIRONMENT_DROPPED_DOCUMENTED,
    *GIT_ENVIRONMENT_DROPPED_UNDOCUMENTED,
)

# Templates, not shell strings: every production Git child must match one.
GIT_COMMANDS = (
    ("setup", "config", "-f", "<global>", "safe.directory", "<root>"),
    ("discovery", "version"),
    ("discovery", "version", "--build-options"),
    (
        "discovery",
        "rev-parse",
        "--show-toplevel",
        "--absolute-git-dir",
        "--git-common-dir",
        "--show-object-format",
    ),
    ("discovery", "config", "--list", "--show-scope", "--no-includes", "-z"),
    ("object", "rev-parse", "--verify", "--end-of-options", "<rev>^{commit}"),
    ("object", "cat-file", "--batch-command"),
    ("object", "count-objects", "-v"),
    (
        "object",
        "-c",
        "core.commitGraph=false",
        "fsck",
        "--full",
        "--no-dangling",
        "--no-reflogs",
        "--no-references",
        "--no-progress",
        "<candidate>",
        "[<base>]",
    ),
)


def _git_environment(global_config: pathlib.Path | str) -> dict[str, str]:
    """Return the exact environment for every Git child.

    Every inherited name beginning ``GIT_`` is removed, including numbered
    config channels and names introduced by a later Git. Exactly three Git
    variables are installed. ``HOME`` and all non-Git ambient variables
    survive; global and system configuration are redirected instead.
    """

    environment = {
        name: value for name, value in os.environ.items() if not name.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.fspath(global_config),
        }
    )
    return environment


def _kill_reap_and_close(process: subprocess.Popen[bytes]) -> None:
    """Best-effort cleanup for a child which could not finish setup."""

    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=MAX_GIT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        pass
    for pipe in (process.stdin, process.stdout, process.stderr):
        if pipe is not None:
            try:
                pipe.close()
            except OSError:
                pass


def _bounded_process(
    argv: Sequence[str],
    *,
    cwd: pathlib.Path | None,
    environment: Mapping[str, str],
    input_bytes: bytes | None,
    output_limit: int,
    seconds: float,
) -> subprocess.CompletedProcess[bytes]:
    """Run one child while retaining at most ``output_limit`` output bytes."""

    try:
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise SnapshotError("git is required to read an immutable tree snapshot") from exc

    assert process.stdout is not None
    assert process.stderr is not None
    output = [bytearray(), bytearray()]
    drain_failures: list[BaseException] = []
    total = 0
    exceeded = False
    lock = threading.Lock()
    started_threads: list[threading.Thread] = []
    primary_error: BaseException | None = None

    def drain(pipe: BinaryIO, target: bytearray) -> None:
        nonlocal total, exceeded
        try:
            while True:
                chunk = pipe.read(65_536)
                if not chunk:
                    return
                with lock:
                    remaining = output_limit + 1 - total
                    if remaining > 0:
                        target.extend(chunk[:remaining])
                        total += min(len(chunk), remaining)
                    if len(chunk) > remaining or total > output_limit:
                        exceeded = True
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
        except BaseException as caught:
            with lock:
                drain_failures.append(caught)
            try:
                process.kill()
            except OSError:
                pass

    try:
        threads = (
            threading.Thread(
                target=drain, args=(process.stdout, output[0]), daemon=True
            ),
            threading.Thread(
                target=drain, args=(process.stderr, output[1]), daemon=True
            ),
        )
        for thread in threads:
            thread.start()
            started_threads.append(thread)
        if input_bytes is not None:
            assert process.stdin is not None
            try:
                process.stdin.write(input_bytes)
            except (BrokenPipeError, OSError):
                pass
            finally:
                try:
                    process.stdin.close()
                except OSError:
                    pass
        try:
            returncode = process.wait(timeout=seconds)
        except subprocess.TimeoutExpired as exc:
            raise SnapshotError(
                f"git command exceeded its {seconds:g} second budget"
            ) from exc
        for thread in threads:
            thread.join(MAX_GIT_SECONDS)
            if thread.is_alive():
                raise SnapshotError("git output drain did not finish")
        if drain_failures:
            raise SnapshotError("git output could not be read") from drain_failures[0]
        if exceeded:
            raise SnapshotError(
                f"git output exceeds the budget of {output_limit} bytes"
            )
        return subprocess.CompletedProcess(
            list(argv), returncode, bytes(output[0]), bytes(output[1])
        )
    except BaseException as caught:
        primary_error = caught
        raise
    finally:
        cleanup_failures: list[BaseException] = []
        reaped = getattr(process, "returncode", None) is not None
        if not reaped:
            try:
                process.kill()
            except OSError:
                pass
            except BaseException as caught:
                cleanup_failures.append(caught)
            try:
                process.wait(timeout=MAX_GIT_SECONDS)
            except BaseException as caught:
                cleanup_failures.append(caught)
            else:
                reaped = True
        deadline = time.monotonic() + MAX_GIT_SECONDS
        for thread in started_threads:
            try:
                thread.join(max(0.0, deadline - time.monotonic()))
            except BaseException as caught:
                cleanup_failures.append(caught)
        for pipe in (process.stdin, process.stdout, process.stderr):
            if pipe is None:
                continue
            try:
                pipe.close()
            except OSError:
                pass
            except BaseException as caught:
                cleanup_failures.append(caught)
        if any(thread.is_alive() for thread in started_threads):
            cleanup_failures.append(SnapshotError("git output drain did not finish"))
        if not reaped:
            cleanup_failures.append(SnapshotError("git child could not be reaped"))
        if cleanup_failures:
            cleanup_error = SnapshotError("git child cleanup failed")
            for failure in cleanup_failures[1:]:
                cleanup_error.add_note(f"Additional cleanup failure: {failure}")
            if primary_error is not None:
                primary_error.add_note(f"Git child cleanup also failed: {cleanup_error}")
            else:
                raise cleanup_error from cleanup_failures[0]


def _git_run(
    arguments: Sequence[str],
    *,
    cwd: pathlib.Path | None,
    environment: Mapping[str, str],
    output_limit: int = MAX_GIT_OUTPUT_BYTES,
    seconds: float = MAX_GIT_SECONDS,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run one allow-listed Git command without a shell and with hard bounds."""

    return _bounded_process(
        ("git", *arguments),
        cwd=cwd,
        environment=environment,
        input_bytes=input_bytes,
        output_limit=output_limit,
        seconds=seconds,
    )


def _first_error(completed: subprocess.CompletedProcess[bytes]) -> str:
    output = completed.stderr or completed.stdout
    text = output.decode("utf-8", errors="replace").strip()
    return text.splitlines()[0] if text else f"git exited {completed.returncode}"


def _object_arguments(git_dir: pathlib.Path, arguments: Sequence[str]) -> list[str]:
    return [f"--git-dir={git_dir}", "--no-replace-objects", *arguments]


def _parse_version(output: bytes) -> tuple[int, int, int]:
    match = _VERSION_RE.search(output.decode("ascii", errors="replace"))
    if match is None:
        raise SnapshotError("git version output is not recognized")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def _parse_config(output: bytes) -> tuple[tuple[str, str, str], ...]:
    """Parse scoped ``--list -z`` records, including implicit booleans."""

    fields = output.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 2:
        raise SnapshotError("repository configuration listing is malformed")
    records: list[tuple[str, str, str]] = []
    for index in range(0, len(fields), 2):
        try:
            scope = fields[index].decode("utf-8", errors="strict")
            key_value = fields[index + 1].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise SnapshotError("repository configuration is not UTF-8") from exc
        key, separator, value = key_value.partition("\n")
        if not scope or not key:
            raise SnapshotError("repository configuration listing is malformed")
        if not separator:
            value = "true"
        records.append((scope, key, value))
    return tuple(records)


def _config_bool(key: str, value: str) -> bool:
    """Classify a boolean configuration value as git 2.53.0 does.

    ``true``, ``yes``, ``on`` and ``1`` are true, and so is the valueless
    form, which ``_parse_config`` already spells ``true``; ``false``, ``no``,
    ``off``, ``0`` and an explicitly empty value (``ignorecase =``) are false,
    as ``git config --type=bool`` reports them (peer review, round 4). Git
    reads any other integer as true when it is non-zero and dies on other
    text; this reader refuses both, deliberately narrower than git, because a
    value outside that closed set is one it will not apply on git's behalf.
    """

    lowered = value.strip().lower()
    if lowered in {"true", "yes", "on", "1"}:
        return True
    if lowered in {"", "false", "no", "off", "0"}:
        return False
    raise SnapshotError(f"repository configuration key {key!r} has a non-boolean value {value!r}")


def _config_ignorecase(records: tuple[tuple[str, str, str], ...]) -> bool:
    """Whether git folds ASCII case when matching attribute patterns here.

    ``core.ignoreCase`` is written into the local configuration by every
    ``git init`` and ``git clone`` on a case-insensitive filesystem (macOS APFS
    among them), and under it git matches ``.gitattributes`` patterns with
    ``WM_CASEFOLD``. A byte-exact matcher would then miss a transforming
    attribute git applies (peer review of the Lane A PR, round 2). The last
    record wins, as in git; only the repository's own scopes can set it here,
    since the global file is the reader's and the system file is disabled.
    """

    result = False
    for scope, key, value in records:
        if scope in {"local", "worktree"} and key.lower() == "core.ignorecase":
            result = _config_bool(key, value)
    return result


def _config_key_denied(key: str) -> bool:
    lowered = key.lower()
    return (
        lowered.startswith("include.")
        or lowered.startswith("includeif.")
        or lowered
        in {
            "core.fsmonitor",
            "core.hookspath",
            "core.alternaterefscommand",
            "core.gitproxy",
            "core.sshcommand",
            "core.askpass",
            "extensions.partialclone",
        }
        or (lowered.startswith("remote.") and lowered.endswith(".promisor"))
        or (
            lowered.startswith("remote.")
            and lowered.endswith(".partialclonefilter")
        )
        or lowered.startswith("fsck.")
        or lowered.startswith("receive.fsck.")
        or lowered.startswith("transfer.fsck")
    )


def _audit_config(
    records: tuple[tuple[str, str, str], ...], root: pathlib.Path
) -> None:
    global_records = [
        (key.lower(), value)
        for scope, key, value in records
        if scope == "global"
    ]
    if global_records != [("safe.directory", os.fspath(root))]:
        raise SnapshotError(
            "the private global Git configuration does not contain exactly "
            "the selected safe.directory"
        )
    if any(scope == "system" for scope, _, _ in records):
        raise SnapshotError("system Git configuration was not disabled")
    for scope, key, _ in records:
        if scope in {"local", "worktree"} and _config_key_denied(key):
            raise SnapshotError(
                f"repository configuration key {key!r} is not allowed for "
                "immutable tree reads"
            )
    _config_ignorecase(records)  # refuses a value git could not classify either


def _create_global_config(root: pathlib.Path) -> bytes:
    """Serialize safe.directory from a private cwd with no ambient repository."""

    with tempfile.TemporaryDirectory(prefix="receipt-snapshot-select-") as directory:
        private_directory = pathlib.Path(directory)
        path = private_directory / "global.gitconfig"
        environment = _git_environment(path)
        completed = _git_run(
            ["config", "-f", os.fspath(path), "safe.directory", os.fspath(root)],
            cwd=private_directory,
            environment=environment,
        )
        if completed.returncode != 0:
            raise SnapshotError(
                f"cannot create private Git configuration: {_first_error(completed)}"
            )
        try:
            return path.read_bytes()
        except OSError as exc:
            raise SnapshotError("cannot read the private Git configuration") from exc


def _raw_tree_sort_key(entry: _RawTreeEntry) -> bytes:
    return entry.name + (b"/" if entry.mode == b"40000" else b"")


def _parse_raw_tree(
    oid: str, payload: bytes, *, object_format: str
) -> tuple[_RawTreeEntry, ...]:
    oid_bytes = hashlib.new(object_format).digest_size
    position = 0
    entries: list[_RawTreeEntry] = []
    names: set[bytes] = set()
    previous_key: bytes | None = None
    while position < len(payload):
        if len(entries) >= MAX_TREE_ENTRIES:
            raise SnapshotError(
                f"tree walk exceeds the budget of {MAX_TREE_ENTRIES} entries"
            )
        space = payload.find(b" ", position)
        if space < 0:
            raise SnapshotError(f"tree {oid} has a malformed entry")
        mode = payload[position:space]
        if mode not in _RAW_MODES:
            shown = mode.decode("ascii", errors="backslashreplace")
            raise SnapshotError(f"tree {oid} has unsupported raw mode {shown!r}")
        nul = payload.find(b"\0", space + 1)
        if nul < 0:
            raise SnapshotError(f"tree {oid} has a malformed entry")
        name = payload[space + 1 : nul]
        if len(name) > MAX_ENTRY_NAME_BYTES:
            raise SnapshotError(
                f"tree entry name exceeds the budget of {MAX_ENTRY_NAME_BYTES} bytes"
            )
        try:
            validate_component_bytes(name)
        except NamePolicyError as exc:
            raise SnapshotError(f"tree {oid} has an invalid entry name: {exc}") from exc
        binary_start = nul + 1
        binary_end = binary_start + oid_bytes
        if binary_end > len(payload):
            raise SnapshotError(f"tree {oid} has a truncated object name")
        object_id = payload[binary_start:binary_end].hex()
        entry = _RawTreeEntry(mode=mode, name=name, oid=object_id)
        if name in names:
            raise SnapshotError(f"tree {oid} contains duplicate entry name {name!r}")
        key = _raw_tree_sort_key(entry)
        if previous_key is not None and key <= previous_key:
            raise SnapshotError(f"tree {oid} entries are not in canonical Git order")
        entries.append(entry)
        names.add(name)
        previous_key = key
        position = binary_end
    return tuple(entries)


def _canonical_commit(
    oid: str,
    payload: bytes,
    *,
    object_format: str,
    parent_limit: int | None = None,
) -> _CommitObject:
    """Parse exactly the canonical commit-header shape fixed by the plan."""

    separator = payload.find(b"\n\n")
    if separator < 0:
        raise SnapshotError(f"commit {oid} is not a canonical commit object")

    if parent_limit is None:
        parent_limit = MAX_ANCESTRY_COMMITS
    hex_length = hashlib.new(object_format).digest_size * 2

    def object_name(value: bytes) -> str:
        if len(value) != hex_length or _OID_RE.fullmatch(value) is None:
            raise SnapshotError(f"commit {oid} is not a canonical commit object")
        return value.decode("ascii")

    tree: str | None = None
    parents: list[str] = []
    parent_overflow = False
    phase = "tree"

    def accept_header(name: bytes, value: bytes) -> None:
        nonlocal parent_overflow, phase, tree
        if phase == "tree":
            if name != b"tree":
                raise SnapshotError(
                    f"commit {oid} is not a canonical commit object"
                )
            tree = object_name(value)
            phase = "parents"
            return
        if phase == "parents":
            if name == b"parent":
                parent = object_name(value)
                if len(parents) >= parent_limit:
                    parent_overflow = True
                else:
                    parents.append(parent)
                return
            if name != b"author":
                raise SnapshotError(
                    f"commit {oid} is not a canonical commit object"
                )
            phase = "committer"
            return
        if phase == "committer":
            if name != b"committer":
                raise SnapshotError(
                    f"commit {oid} is not a canonical commit object"
                )
            phase = "later"
            return
        if name in {b"tree", b"parent", b"author", b"committer"}:
            raise SnapshotError(f"commit {oid} is not a canonical commit object")

    # Commit framing names LF exactly. Scan it directly so a hostile commit
    # cannot allocate a second list containing every physical header line.
    position = 0
    current_name: bytes | None = None
    current_value = b""
    while position <= separator:
        line_end = payload.find(b"\n", position, separator)
        if line_end < 0:
            line_end = separator
        line = payload[position:line_end]
        position = line_end + 1
        if line.startswith(b" "):
            if current_name is None:
                raise SnapshotError(
                    f"commit {oid} is not a canonical commit object"
                )
            if current_name in {b"tree", b"parent"}:
                current_value += b"\n" + line[1:]
            continue
        if current_name is not None:
            accept_header(current_name, current_value)
        name, space, value = line.partition(b" ")
        if (
            not space
            or not name
            or any(byte <= 0x20 or byte >= 0x7F for byte in name)
        ):
            raise SnapshotError(f"commit {oid} is not a canonical commit object")
        current_name = name
        current_value = value if name in {b"tree", b"parent"} else b""
    if current_name is not None:
        accept_header(current_name, current_value)
    if tree is None or phase != "later":
        raise SnapshotError(f"commit {oid} is not a canonical commit object")
    if parent_overflow:
        raise SnapshotError(
            f"ancestry walk exceeds the budget of "
            f"{MAX_ANCESTRY_COMMITS} commits"
        )
    return _CommitObject(oid=oid, tree=tree, parents=tuple(parents))


def _unsupported_attribute(path: str, line: int, construct: str) -> SnapshotError:
    return SnapshotError(
        f"unsupported .gitattributes construct at {path}:{line}: {construct}"
    )


def _attribute_pattern(
    token: bytes, *, path: str, line: int
) -> tuple[bytes, tuple[bytes, ...], bool]:
    try:
        shown = token.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise _unsupported_attribute(path, line, "non-ASCII pattern") from exc
    if not token:
        raise _unsupported_attribute(path, line, "empty pattern")
    if token.startswith(b'"'):
        raise _unsupported_attribute(path, line, "C-quoted pattern")
    if token.startswith(b"!"):
        raise _unsupported_attribute(path, line, "negative pattern")
    for byte, description in (
        (b"?", "?"),
        (b"[", "bracket expression"),
        (b"]", "bracket expression"),
        (b"\\", "backslash escape"),
    ):
        if byte in token:
            raise _unsupported_attribute(path, line, description)
    if token.endswith(b"/"):
        raise _unsupported_attribute(path, line, "trailing slash")
    if re.fullmatch(rb"[A-Za-z0-9._*/-]+", token) is None:
        raise _unsupported_attribute(path, line, f"pattern {shown!r}")
    anchored = token[1:] if token.startswith(b"/") else token
    if not anchored:
        raise _unsupported_attribute(path, line, "empty pattern")
    segments = anchored.split(b"/")
    if any(not segment for segment in segments):
        raise _unsupported_attribute(path, line, "empty pattern segment")
    for segment in segments:
        if b"**" in segment and segment != b"**":
            raise _unsupported_attribute(path, line, "misplaced **")
    if token == b"**":
        raise _unsupported_attribute(path, line, "misplaced **")
    return anchored, tuple(segments), token.startswith(b"/") or b"/" in anchored


def _parse_attribute_file(
    path: str, payload: bytes, *, rule_limit: int
) -> tuple[_AttributeRule, ...]:
    rules: list[_AttributeRule] = []
    rule_overflow = False
    line_number = 0
    position = 0
    while True:
        line_number += 1
        line_end = payload.find(b"\n", position)
        if line_end < 0:
            original = payload[position:]
        else:
            original = payload[position:line_end]
        # Git 2.53.0's read_attr_from_buf() stops reading the blob at an
        # embedded NUL, so every rule after one is unseen by git: refuse the
        # blob on any line rather than honour rules git never reads.
        if b"\0" in original:
            raise _unsupported_attribute(path, line_number, "control byte")
        # attr.c's parse_attr_line() skips leading blanks (space, tab and CR,
        # measured on git 2.53.0) and returns before any other test on an
        # empty line or a '#' comment, whatever the line's length or contents;
        # the reader skips those lines the same way (peer review, round 4).
        line = original.strip(b" \t\r")
        if line and not line.startswith(b"#"):
            # attr.h fixes ATTR_MAX_LINE_LENGTH at 2048 and parse_attr_line()
            # drops a rule line whose strlen(), leading blanks included, is at
            # least that; parse_attr() drops the whole rule when
            # attr_name_valid() or attr_name_reserved() rejects one state
            # name; and git splits fields at CR as well as at space and tab
            # (measured). Refuse these cases rather than disagreeing about
            # precedence.
            if len(original) >= 2048:
                raise _unsupported_attribute(
                    path, line_number, "line longer than 2048 bytes"
                )
            if any(byte < 0x20 and byte != 0x09 for byte in original):
                raise _unsupported_attribute(path, line_number, "control byte")
            fields = re.split(rb"[ \t]+", line)
            if len(fields) < 2:
                raise _unsupported_attribute(
                    path, line_number, "line has no attribute state"
                )
            if fields[0].startswith(b"[attr]"):
                raise _unsupported_attribute(
                    path, line_number, "attribute macro definition"
                )
            pattern, segments, has_slash = _attribute_pattern(
                fields[0], path=path, line=line_number
            )
            states: list[tuple[str, str]] = []

            def add_states(additions: tuple[tuple[str, str], ...]) -> None:
                if len(states) + len(additions) > MAX_ATTRIBUTE_STATES_PER_LINE:
                    raise SnapshotError(
                        f"attribute states at {path}:{line_number} exceed the "
                        f"per-line budget of {MAX_ATTRIBUTE_STATES_PER_LINE} states"
                    )
                states.extend(additions)

            for raw_state in fields[1:]:
                try:
                    state = raw_state.decode("ascii", errors="strict")
                except UnicodeDecodeError as exc:
                    raise _unsupported_attribute(
                        path, line_number, "non-ASCII attribute state"
                    ) from exc
                if state == "binary":
                    add_states(
                        (
                            ("diff", "unset"),
                            ("merge", "unset"),
                            ("text", "unset"),
                        )
                    )
                    continue
                disposition = "set"
                name = state
                if state.startswith("-"):
                    disposition, name = "unset", state[1:]
                elif state.startswith("!"):
                    disposition, name = "unspecified", state[1:]
                elif "=" in state:
                    name, value = state.split("=", 1)
                    disposition = "value"
                if name.startswith(("-", "builtin_")) or re.fullmatch(
                    r"[A-Za-z0-9_.-]+", name
                ) is None:
                    raise _unsupported_attribute(
                        path, line_number, f"attribute name {name!r}"
                    )
                add_states(((name, disposition),))
            trailing_globstars = 0
            for segment in reversed(segments):
                if segment != b"**":
                    break
                trailing_globstars += 1
            trailing_descendants = bool(
                trailing_globstars and trailing_globstars < len(segments)
            )
            match_segments = (
                segments[:-trailing_globstars]
                if trailing_descendants
                else segments
            )
            rule = _AttributeRule(
                pattern,
                segments,
                match_segments,
                has_slash,
                trailing_descendants,
                tuple(states),
            )
            if len(rules) >= rule_limit:
                rule_overflow = True
            else:
                rules.append(rule)
        if line_end < 0:
            break
        position = line_end + 1
    if rule_overflow:
        raise SnapshotError(
            f"attribute rules exceed the snapshot budget of "
            f"{MAX_ATTRIBUTE_RULES_TOTAL} rules"
        )
    return tuple(rules)


def _segment_matches(
    pattern: bytes, value: bytes, step: Callable[[], None]
) -> bool:
    pattern_index = value_index = 0
    star = -1
    retry = 0
    while value_index < len(value):
        step()
        if (
            pattern_index < len(pattern)
            and pattern[pattern_index] != ord("*")
            and pattern[pattern_index] == value[value_index]
        ):
            pattern_index += 1
            value_index += 1
        elif pattern_index < len(pattern) and pattern[pattern_index] == ord("*"):
            star = pattern_index
            pattern_index += 1
            retry = value_index
        elif star >= 0:
            retry += 1
            value_index = retry
            pattern_index = star + 1
        else:
            return False
    while pattern_index < len(pattern) and pattern[pattern_index] == ord("*"):
        step()
        pattern_index += 1
    return pattern_index == len(pattern)


def _attribute_matches(
    rule: _AttributeRule, relative: tuple[bytes, ...], step: Callable[[], None]
) -> bool:
    if not rule.has_slash:
        return bool(relative) and _segment_matches(
            rule.segments[0], relative[-1], step
        )
    pattern_index = value_index = 0
    globstar = -1
    retry = 0
    while value_index < len(relative):
        if (
            rule.trailing_descendants
            and pattern_index == len(rule.match_segments)
        ):
            # The non-globstar prefix matched and at least one descendant
            # remains. Git's trailing ``/**`` excludes the directory itself.
            return True
        step()
        if (
            pattern_index < len(rule.match_segments)
            and rule.match_segments[pattern_index] == b"**"
        ):
            globstar = pattern_index
            pattern_index += 1
            retry = value_index
        elif (
            pattern_index < len(rule.match_segments)
            and _segment_matches(
                rule.match_segments[pattern_index],
                relative[value_index],
                step,
            )
        ):
            pattern_index += 1
            value_index += 1
        elif globstar >= 0:
            retry += 1
            value_index = retry
            pattern_index = globstar + 1
        else:
            return False
    while (
        pattern_index < len(rule.match_segments)
        and rule.match_segments[pattern_index] == b"**"
    ):
        step()
        pattern_index += 1
    if rule.trailing_descendants:
        return False
    return pattern_index == len(rule.match_segments)


class _BatchReader:
    """One framed ``cat-file --batch-command`` conversation."""

    def __init__(
        self,
        git_dir: pathlib.Path,
        *,
        environment: Mapping[str, str],
        object_format: str,
    ) -> None:
        self._object_format = object_format
        self._abandoned = False
        self._closed = False
        self._headers: dict[str, tuple[str, int]] = {}
        self._stderr_bytes = bytearray()
        self._stderr_truncated = False
        try:
            self._process = subprocess.Popen(
                [
                    "git",
                    *_object_arguments(git_dir, ["cat-file", "--batch-command"]),
                ],
                cwd=None,
                env=dict(environment),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
        except FileNotFoundError as exc:
            raise SnapshotError("git is required to read an immutable tree snapshot") from exc
        try:
            if (
                self._process.stdin is None
                or self._process.stdout is None
                or self._process.stderr is None
            ):
                raise SnapshotError("cannot open the Git batch object's pipes")
            self._stdin = self._process.stdin
            self._stdout = self._process.stdout
            self._stderr_thread = threading.Thread(
                target=self._drain_stderr,
                name="receipt-git-batch-stderr",
                daemon=True,
            )
            self._stderr_thread.start()
        except BaseException:
            _kill_reap_and_close(self._process)
            raise

    def _drain_stderr(self) -> None:
        """Drain stderr continuously while retaining only the bounded prefix."""

        pipe = self._process.stderr
        if pipe is None:
            return
        try:
            while chunk := pipe.read(_BATCH_CHUNK_BYTES):
                remaining = MAX_GIT_OUTPUT_BYTES - len(self._stderr_bytes)
                if remaining > 0:
                    self._stderr_bytes.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self._stderr_truncated = True
        except OSError:
            return

    @property
    def abandoned(self) -> bool:
        return self._abandoned

    @property
    def process(self) -> subprocess.Popen[bytes]:
        return self._process

    def _usable(self) -> None:
        if self._abandoned:
            raise SnapshotError("snapshot stream was abandoned")
        if self._closed:
            raise SnapshotError("snapshot is closed")

    def abandon(self) -> None:
        self._abandoned = True

    def _request(self, command: str, oid: str) -> None:
        self._usable()
        try:
            self._stdin.write(f"{command} {oid}\n".encode("ascii"))
            self._stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            self._abandoned = True
            raise SnapshotError("Git batch child stopped accepting requests") from exc
        except BaseException:
            # The write may have stopped after an arbitrary prefix. No later
            # request may guess whether Git received a complete command.
            self._abandoned = True
            try:
                self._process.kill()
            except OSError:
                pass
            raise

    def _read_with_deadline(
        self, operation: Callable[[], bytes], *, deadline: float
    ) -> bytes:
        """Run one pipe read without allowing the batch child to hang us."""

        result: list[bytes] = []
        failure: list[BaseException] = []

        def read() -> None:
            try:
                result.append(operation())
            except BaseException as exc:
                failure.append(exc)

        try:
            reader = threading.Thread(
                target=read,
                name="receipt-git-batch-stdout",
                daemon=True,
            )
            reader.start()
        except BaseException:
            self._abandoned = True
            try:
                self._process.kill()
            except OSError:
                pass
            raise
        try:
            reader.join(max(0.0, deadline - time.monotonic()))
            if reader.is_alive():
                raise SnapshotError(
                    f"Git batch child exceeded the budget of "
                    f"{MAX_GIT_SECONDS} seconds"
                )
            if failure:
                raise SnapshotError("Git batch child could not be read") from failure[0]
            if not result:
                raise SnapshotError("Git batch child could not be read")
            return result[0]
        except BaseException:
            # An interruption while the helper thread owns stdout leaves the
            # frame position unknowable even if that thread later completes.
            self._abandoned = True
            try:
                self._process.kill()
            except OSError:
                pass
            try:
                reader.join(max(0.0, deadline - time.monotonic()))
            except BaseException:
                pass
            raise

    def _line(self, *, deadline: float) -> bytes:
        line = self._read_with_deadline(
            lambda: self._stdout.readline(_BATCH_HEADER_BYTES + 1),
            deadline=deadline,
        )
        if len(line) > _BATCH_HEADER_BYTES or not line.endswith(b"\n"):
            self._abandoned = True
            raise SnapshotError("batch stream out of frame")
        return line[:-1]

    def _parse_header(self, requested: str, line: bytes) -> tuple[str, int]:
        if line == f"{requested} missing".encode("ascii"):
            raise SnapshotError(f"object {requested} is unavailable")
        parts = line.split(b" ")
        if len(parts) != 3:
            self._abandoned = True
            raise SnapshotError("batch stream out of frame")
        try:
            returned = parts[0].decode("ascii")
            object_type = parts[1].decode("ascii")
            size_text = parts[2].decode("ascii")
        except UnicodeDecodeError as exc:
            self._abandoned = True
            raise SnapshotError("batch stream out of frame") from exc
        if returned != requested or not size_text.isdecimal():
            self._abandoned = True
            raise SnapshotError("batch stream out of frame")
        size = int(size_text)
        return object_type, size

    def info(self, oid: str, *, role: str | None = None) -> tuple[str, int]:
        self._usable()
        header = self._headers.get(oid)
        if header is None:
            self._request("info", oid)
            header = self._parse_header(
                oid,
                self._line(deadline=time.monotonic() + MAX_GIT_SECONDS),
            )
            self._headers[oid] = header
        if role is not None and header[0] != role:
            raise SnapshotError(
                f"object {oid} is a {header[0]}, not the {role} its reference requires"
            )
        return header

    def consume(
        self,
        oid: str,
        *,
        role: str,
        limit: int,
        consumer: Callable[[bytes], None] | None = None,
        hold: bool = False,
    ) -> bytes | None:
        """Consume one complete contents frame and authenticate the payload."""

        object_type, size = self.info(oid, role=role)
        if size > limit:
            raise SnapshotError(
                f"object {oid} exceeds the payload budget of {limit} bytes"
            )
        self._request("contents", oid)
        deadline = time.monotonic() + MAX_GIT_SECONDS
        response_type, response_size = self._parse_header(
            oid, self._line(deadline=deadline)
        )
        if (response_type, response_size) != (object_type, size):
            self._abandoned = True
            raise SnapshotError("batch stream out of frame")

        object_hash = hashlib.new(self._object_format)
        object_hash.update(f"{object_type} {size}\0".encode("ascii"))
        retained = bytearray() if hold else None
        remaining = size
        try:
            while remaining:
                chunk = self._read_with_deadline(
                    lambda: self._stdout.read(
                        min(_BATCH_CHUNK_BYTES, remaining)
                    ),
                    deadline=deadline,
                )
                if not chunk:
                    self._abandoned = True
                    raise SnapshotError("batch stream out of frame")
                remaining -= len(chunk)
                object_hash.update(chunk)
                if retained is not None:
                    retained.extend(chunk)
                if consumer is not None:
                    consumer(chunk)
        except BaseException:
            # Even when the callback failed on the final payload chunk, the
            # framing LF remains unread, so every callback failure abandons
            # the stream rather than guessing at its position.
            self._abandoned = True
            raise
        if self._read_with_deadline(
            lambda: self._stdout.read(1), deadline=deadline
        ) != b"\n":
            self._abandoned = True
            raise SnapshotError("batch stream out of frame")
        if object_hash.hexdigest() != oid:
            self._abandoned = True
            raise SnapshotError(f"object {oid} does not hash to its name")
        return bytes(retained) if retained is not None else None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        was_abandoned = self._abandoned
        deadline = time.monotonic() + MAX_GIT_SECONDS

        failures: list[BaseException] = []

        def kill() -> None:
            try:
                self._process.kill()
            except OSError:
                pass
            except BaseException as caught:
                failures.append(caught)

        def wait(wait_deadline: float) -> bool:
            try:
                self._process.wait(
                    timeout=max(0.0, wait_deadline - time.monotonic())
                )
            except subprocess.TimeoutExpired:
                return False
            except BaseException as caught:
                failures.append(caught)
                return False
            return True

        reaped = False
        wait_deadline = deadline
        try:
            if was_abandoned and self._process.poll() is None:
                kill()
                wait_deadline = time.monotonic() + BATCH_KILL_REAP_SECONDS
            try:
                self._stdin.close()
            except OSError:
                pass
            reaped = wait(wait_deadline)
            if not reaped:
                kill()
                wait_deadline = time.monotonic() + BATCH_KILL_REAP_SECONDS
                reaped = wait(wait_deadline)
        finally:
            # Cleanup is deliberately independent: an injected failure in one
            # operation must not skip the remaining pipe closes or reap attempt.
            if not reaped:
                kill()
                wait_deadline = time.monotonic() + BATCH_KILL_REAP_SECONDS
                reaped = wait(wait_deadline)
            try:
                self._stderr_thread.join(
                    max(0.0, wait_deadline - time.monotonic())
                )
            except BaseException as caught:
                failures.append(caught)
            for pipe in (self._stdin, self._stdout, self._process.stderr):
                if pipe is None:
                    continue
                try:
                    pipe.close()
                except OSError:
                    pass
                except BaseException as caught:
                    failures.append(caught)
            if self._stderr_thread.is_alive():
                failures.append(
                    SnapshotError("Git batch stderr drain did not finish")
                )
        if not reaped:
            failures.append(SnapshotError("Git batch child could not be reaped"))
        if failures:
            error = SnapshotError("Git batch child cleanup failed")
            for failure in failures[1:]:
                error.add_note(f"Additional cleanup failure: {failure}")
            raise error from failures[0]
        if not was_abandoned and self._process.returncode != 0:
            detail = bytes(self._stderr_bytes).decode(
                "utf-8", errors="replace"
            ).splitlines()
            first = detail[0] if detail else "no diagnostic"
            if self._stderr_truncated:
                first += " (diagnostic output truncated)"
            raise SnapshotError(f"Git batch child failed: {first}")

    def __enter__(self) -> "_BatchReader":
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        exc: BaseException | None,
        _traceback: object,
    ) -> None:
        try:
            self.close()
        except BaseException as closing_error:
            if exc is not None:
                exc.add_note(f"Git batch close also failed: {closing_error}")
            else:
                raise


@dataclass(frozen=True)
class _ListingRecord:
    raw: _RawTreeEntry
    child: "_TreeNode | None" = None


@dataclass(frozen=True)
class _TreeNode:
    records: tuple[_ListingRecord, ...]
    tree_oid: str | None


@dataclass(frozen=True)
class _AttributeRule:
    pattern: bytes
    segments: tuple[bytes, ...]
    match_segments: tuple[bytes, ...]
    has_slash: bool
    trailing_descendants: bool
    states: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class TreeListing:
    """A hierarchical tree listing whose nodes store each local name once."""

    _snapshot: "TreeSnapshot" = field(repr=False, compare=False)
    _prefix: tuple[bytes, ...] = field(repr=False)
    _node: _TreeNode = field(repr=False)

    @property
    def tree_oid(self) -> str | None:
        return self._node.tree_oid

    def _walk_from(
        self,
        node: _TreeNode,
        prefix: tuple[bytes, ...],
        *,
        include_trees: bool,
    ) -> Iterator[tuple[tuple[bytes, ...], _RawTreeEntry]]:
        for record in node.records:
            parts = (*prefix, record.raw.name)
            if include_trees or record.raw.mode != b"40000":
                yield parts, record.raw
            if record.child is not None:
                yield from self._walk_from(
                    record.child, parts, include_trees=include_trees
                )

    def _walk(
        self, *, include_trees: bool = False
    ) -> Iterator[tuple[tuple[bytes, ...], _RawTreeEntry]]:
        yield from self._walk_from(
            self._node, self._prefix, include_trees=include_trees
        )

    def iter_entries(
        self,
        *,
        include_trees: bool = False,
        _digest_token: object | None = None,
    ) -> Iterator[GitEntry]:
        """Build and charge full paths only as the caller asks for them."""

        self._snapshot._batch(digest_token=_digest_token)
        for parts, raw in self._walk(include_trees=include_trees):
            yield self._snapshot._public_entry(parts, raw)

    def __iter__(self) -> Iterator[GitEntry]:
        return self.iter_entries()

    def __len__(self) -> int:
        self._snapshot._batch()
        return sum(1 for _parts, raw in self._walk() if raw.mode != b"40000")

    @property
    def children(self) -> Mapping[str, GitEntry | "TreeListing"]:
        """Immediate children keyed by a lossless surrogateescaped spelling."""

        self._snapshot._batch()
        children: dict[str, GitEntry | TreeListing] = {}
        for record in self._node.records:
            name = _tree_path_decode(record.raw.name)
            if record.child is not None:
                children[name] = TreeListing(
                    self._snapshot,
                    (*self._prefix, record.raw.name),
                    record.child,
                )
            else:
                children[name] = self._snapshot._public_entry(
                    (*self._prefix, record.raw.name), record.raw
                )
        return MappingProxyType(children)

    def as_dict(self, *, include_trees: bool = False) -> dict[str, GitEntry]:
        """Return an explicitly requested flat view, charging every full path."""

        return {
            entry.path: entry
            for entry in self.iter_entries(include_trees=include_trees)
        }


class _DigestIterator(Iterator[tuple[GitEntry, str]]):
    """A conservative iterator which abandons its snapshot unless exhausted."""

    def __init__(
        self,
        snapshot: "TreeSnapshot",
        entries: Iterable[GitEntry],
        *,
        per_blob: int,
        total: int,
    ) -> None:
        self._snapshot = snapshot
        self._token = object()
        if snapshot._state.active_digest_token is not None:
            snapshot._abandon()
            raise SnapshotError("snapshot stream was abandoned")
        try:
            if type(entries) is TreeListing:
                self._entries = entries.iter_entries(
                    _digest_token=self._token
                )
            else:
                self._entries = iter(entries)
        except TypeError as exc:
            raise SnapshotError(
                "digests entries must be an iterable of GitEntry objects"
            ) from exc
        snapshot._state.active_digest_token = self._token
        self._per_blob = per_blob
        self._total = total
        self._charged = 0
        self._count = 0
        self._done = False
        self._closed = False

    def __iter__(self) -> "_DigestIterator":
        return self

    def __next__(self) -> tuple[GitEntry, str]:
        if self._done or self._closed:
            raise StopIteration
        try:
            self._snapshot._batch(digest_token=self._token)
        except BaseException:
            self.close()
            raise
        try:
            entry = next(self._entries)
        except StopIteration:
            self._done = True
            if self._snapshot._state.active_digest_token is self._token:
                self._snapshot._state.active_digest_token = None
            raise
        except BaseException:
            self.close()
            raise
        self._count += 1
        if self._count > MAX_TREE_ENTRIES:
            self.close()
            raise SnapshotError(
                f"content entries exceed the budget of {MAX_TREE_ENTRIES} entries"
            )
        if not isinstance(entry, GitEntry):
            self.close()
            raise SnapshotError("digests entries must all be GitEntry objects")
        try:
            object_id = self._snapshot._require_entry(entry)
        except BaseException:
            self.close()
            raise
        if entry.object_type != "blob":
            self.close()
            raise SnapshotError(
                f"object {entry.object_id} is a {entry.object_type}, not the blob "
                "its reference requires"
            )
        if entry.mode not in _CONTENT_MODES:
            self.close()
            raise SnapshotError(
                f"tree entry has non-regular mode {entry.mode}: {entry.path}"
            )
        batch = self._snapshot._batch(digest_token=self._token)
        try:
            _object_type, size = batch.info(object_id, role="blob")
        except BaseException:
            self.close()
            raise
        per_blob_limit = min(self._per_blob, MAX_CONTENT_BLOB_BYTES)
        if size > per_blob_limit:
            self.close()
            raise SnapshotError(
                f"content blob {entry.path!r} exceeds the budget of "
                f"{per_blob_limit} bytes"
            )
        work = self._snapshot._state.work
        if self._charged + size > self._total:
            self.close()
            raise SnapshotError(
                f"content bytes exceed the budget of {self._total} bytes"
            )
        if self._snapshot._verification_total("content_bytes") + size > MAX_CONTENT_BYTES_TOTAL:
            self.close()
            raise SnapshotError(
                f"content bytes exceed the snapshot budget of "
                f"{MAX_CONTENT_BYTES_TOTAL} bytes"
            )
        digest = hashlib.sha256()

        def consume(chunk: bytes) -> None:
            digest.update(chunk)
            self._snapshot._charge_verification(
                "content_bytes",
                len(chunk),
                ceiling=MAX_CONTENT_BYTES_TOTAL,
                message=(
                    f"content bytes exceed the snapshot budget of "
                    f"{MAX_CONTENT_BYTES_TOTAL} bytes"
                ),
            )

        try:
            batch.consume(
                object_id,
                role="blob",
                limit=per_blob_limit,
                consumer=consume,
            )
        except BaseException:
            self.close()
            raise
        self._charged += size
        work.max_content_blob_bytes = max(work.max_content_blob_bytes, size)
        return entry, digest.hexdigest()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if not self._done:
            self._snapshot._abandon()
        if self._snapshot._state.active_digest_token is self._token:
            self._snapshot._state.active_digest_token = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


@dataclass(frozen=True)
class TreeSnapshot:
    """A frozen commit/tree identity with resources acquired only on entry."""

    git_dir: pathlib.Path
    commit: str
    tree: str
    object_format: str
    _state: _SnapshotState = field(repr=False, compare=False)

    @classmethod
    def select(
        cls,
        root: os.PathLike[str] | str,
        revision: str = "HEAD",
        *,
        verify_objects: bool = False,
        expect_commit: str | None = None,
        expect_tree: str | None = None,
    ) -> "TreeSnapshot":
        """Resolve and authenticate a commit and its root tree, then release Git.

        The plan's API sketch has no way to signal the conditional SHA1DC
        build preflight. The optional ``verify_objects`` keyword is the
        fail-closed plumbing choice. Expectations are checked commit first and
        tree second, before an entered snapshot can run another pass.

        Selection uses one temporary private config and one short-lived batch
        child under ``try/finally``. Non-repository setup and version children
        run from the applicable private directory. The long-lived child and
        its private directory are acquired only by :meth:`__enter__`.
        """

        if type(revision) is not str or not revision or "\0" in revision:
            raise SnapshotError("snapshot revision must be a non-empty string without NUL")
        if type(verify_objects) is not bool:
            raise SnapshotError("verify_objects must be a bool")
        try:
            selected_root = pathlib.Path(os.fspath(root)).resolve()
        except (TypeError, ValueError, OSError) as exc:
            raise SnapshotError(f"candidate repository path is invalid: {root!r}") from exc
        if "\n" in os.fspath(selected_root) or "\r" in os.fspath(selected_root):
            raise SnapshotError("repository top-level path contains a line break")

        global_bytes = _create_global_config(selected_root)
        with tempfile.TemporaryDirectory(prefix="receipt-snapshot-discovery-") as directory:
            private_directory = pathlib.Path(directory)
            global_path = private_directory / "global.gitconfig"
            global_path.write_bytes(global_bytes)
            environment = _git_environment(global_path)

            version_arguments = ["version"]
            if verify_objects:
                version_arguments.append("--build-options")
            version_result = _git_run(
                version_arguments,
                cwd=private_directory,
                environment=environment,
            )
            if version_result.returncode != 0:
                try:
                    root_is_directory = selected_root.is_dir()
                except OSError:
                    root_is_directory = False
                if not root_is_directory:
                    raise SnapshotError(
                        "candidate repository is missing or not a git repository: "
                        f"{selected_root}"
                    )
                raise SnapshotError(f"cannot run git version: {_first_error(version_result)}")
            version = _parse_version(version_result.stdout)
            if version < GIT_MIN_VERSION:
                floor = ".".join(str(part) for part in GIT_MIN_VERSION)
                raise SnapshotError(
                    f"Git {floor} or later is required for cat-file --batch-command"
                )
            if verify_objects:
                if b"SHA-1: SHA1_DC" not in version_result.stdout.splitlines():
                    raise SnapshotError(
                        "--verify-objects requires a Git build using SHA-1: SHA1_DC"
                    )
                if version < GIT_FSCK_NO_REFERENCES_MIN_VERSION:
                    raise SnapshotError(
                        "--verify-objects requires Git 2.50.0 or later for "
                        "fsck --no-references"
                    )

            discovery = _git_run(
                [
                    "-C",
                    os.fspath(selected_root),
                    "rev-parse",
                    "--show-toplevel",
                    "--absolute-git-dir",
                    "--git-common-dir",
                    "--show-object-format",
                ],
                cwd=None,
                environment=environment,
            )
            if discovery.returncode != 0:
                raise SnapshotError(
                    "candidate repository is missing or not a git repository: "
                    f"{selected_root}"
                )
            try:
                discovery_lines = discovery.stdout.decode(
                    "utf-8", errors="strict"
                ).splitlines()
            except UnicodeDecodeError as exc:
                raise SnapshotError("repository discovery output is not UTF-8") from exc
            if len(discovery_lines) != 4:
                raise SnapshotError("repository discovery output is malformed")
            top_text, git_dir_text, common_text, object_format = discovery_lines
            top_level = pathlib.Path(top_text).resolve()
            if top_level != selected_root:
                raise SnapshotError("root is not the top level of its repository")
            git_dir = pathlib.Path(git_dir_text)
            if not git_dir.is_absolute():
                git_dir = selected_root / git_dir
            git_dir = git_dir.resolve()
            common_dir = pathlib.Path(common_text)
            if not common_dir.is_absolute():
                common_dir = selected_root / common_dir
            common_dir = common_dir.resolve()
            cls._refuse_grafts_and_shallow(git_dir, common_dir)
            if object_format != "sha1":
                if object_format == "sha256":
                    raise SnapshotError(
                        "SHA-256 repositories are unsupported until a complete "
                        "reader fixture exists"
                    )
                raise SnapshotError(f"unsupported Git object format {object_format!r}")
            cls._refuse_alternates(git_dir, common_dir)

            config_result = _git_run(
                [
                    "-C",
                    os.fspath(selected_root),
                    "config",
                    "--list",
                    "--show-scope",
                    "--no-includes",
                    "-z",
                ],
                cwd=None,
                environment=environment,
            )
            if config_result.returncode != 0:
                raise SnapshotError(
                    f"cannot audit repository configuration: {_first_error(config_result)}"
                )
            config_records = _parse_config(config_result.stdout)
            _audit_config(config_records, selected_root)
            cls._refuse_grafts_and_shallow(git_dir, common_dir)
            cls._refuse_alternates(git_dir, common_dir)

            resolved = _git_run(
                _object_arguments(
                    git_dir,
                    [
                        "rev-parse",
                        "--verify",
                        "--end-of-options",
                        f"{revision}^{{commit}}",
                    ],
                ),
                cwd=None,
                environment=environment,
            )
            if resolved.returncode != 0:
                raise SnapshotError(f"cannot resolve commit '{revision}'")
            candidate = resolved.stdout.rstrip(b"\n")
            if (
                b"\n" in candidate
                or len(candidate) != hashlib.sha1().digest_size * 2
                or _OID_RE.fullmatch(candidate) is None
            ):
                raise SnapshotError(f"cannot resolve commit '{revision}'")
            candidate_oid = candidate.decode("ascii")

            cls._refuse_grafts_and_shallow(git_dir, common_dir)
            cls._refuse_alternates(git_dir, common_dir)
            with _BatchReader(
                git_dir,
                environment=environment,
                object_format=object_format,
            ) as batch:
                _kind, commit_size = batch.info(candidate_oid, role="commit")
                commit_payload = batch.consume(
                    candidate_oid,
                    role="commit",
                    limit=MAX_TREE_OBJECT_BYTES,
                    hold=True,
                )
                assert commit_payload is not None
                parsed_commit = _canonical_commit(
                    candidate_oid, commit_payload, object_format=object_format
                )
                if len(parsed_commit.parents) > MAX_ANCESTRY_COMMITS:
                    raise SnapshotError(
                        f"ancestry walk exceeds the budget of "
                        f"{MAX_ANCESTRY_COMMITS} commits"
                    )
                _kind, tree_size = batch.info(parsed_commit.tree, role="tree")
                if commit_size + tree_size > MAX_TREE_BYTES_TOTAL:
                    raise SnapshotError(
                        f"commit and tree bytes exceed the snapshot budget of "
                        f"{MAX_TREE_BYTES_TOTAL} bytes"
                    )
                tree_payload = batch.consume(
                    parsed_commit.tree,
                    role="tree",
                    limit=MAX_TREE_OBJECT_BYTES,
                    hold=True,
                )
                assert tree_payload is not None
                root_tree = _parse_raw_tree(
                    parsed_commit.tree, tree_payload, object_format=object_format
                )
                if len(root_tree) > MAX_TREE_ENTRIES:
                    raise SnapshotError(
                        f"tree walk exceeds the budget of {MAX_TREE_ENTRIES} entries"
                    )
                for parent in parsed_commit.parents:
                    batch.info(parent, role="commit")
                for raw in root_tree:
                    if raw.mode != b"160000":
                        batch.info(raw.oid, role=raw.object_type)

        if expect_commit is not None:
            expected_commit = _validate_expected_oid(
                expect_commit,
                label="commit",
                object_format=object_format,
            )
            if candidate_oid != expected_commit:
                raise SnapshotError(
                    f"commit {candidate_oid} is not the expected commit "
                    f"{expected_commit}"
                )
        if expect_tree is not None:
            expected_tree = _validate_expected_oid(
                expect_tree,
                label="tree",
                object_format=object_format,
            )
            if parsed_commit.tree != expected_tree:
                raise SnapshotError(
                    f"tree {parsed_commit.tree} is not the expected tree "
                    f"{expected_tree}"
                )

        work = SnapshotWork(
            tree_bytes=commit_size + tree_size,
            max_tree_object_bytes=max(commit_size, tree_size),
        )
        state = _SnapshotState(
            root=selected_root,
            common_dir=common_dir,
            revision=revision,
            version=version,
            config_records=config_records,
            global_config_bytes=global_bytes,
            verify_objects_ready=verify_objects,
            selected_commit=parsed_commit,
            root_tree=root_tree,
            work=work,
            work_pool=_WorkPool([work]),
            tree_cache={parsed_commit.tree: root_tree},
            commit_cache={candidate_oid: parsed_commit},
        )
        return cls(
            git_dir=git_dir,
            commit=candidate_oid,
            tree=parsed_commit.tree,
            object_format=object_format,
            _state=state,
        )

    @staticmethod
    def _repository_directories(
        git_dir: pathlib.Path, common_dir: pathlib.Path
    ) -> tuple[pathlib.Path, ...]:
        return tuple(dict.fromkeys((git_dir, common_dir)))

    @staticmethod
    def _repository_control_exists(path: pathlib.Path) -> bool:
        try:
            path.lstat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise SnapshotError(
                f"cannot inspect repository control path: {path}"
            ) from exc
        return True

    @classmethod
    def _refuse_grafts_and_shallow(
        cls, git_dir: pathlib.Path, common_dir: pathlib.Path
    ) -> None:
        for directory in cls._repository_directories(git_dir, common_dir):
            if cls._repository_control_exists(directory / "info" / "grafts"):
                raise SnapshotError("repository grafts are unsupported")
            if cls._repository_control_exists(directory / "shallow"):
                raise SnapshotError("shallow repositories are unsupported")

    @classmethod
    def _refuse_alternates(
        cls, git_dir: pathlib.Path, common_dir: pathlib.Path
    ) -> None:
        for directory in cls._repository_directories(git_dir, common_dir):
            if cls._repository_control_exists(
                directory / "objects" / "info" / "alternates"
            ):
                raise SnapshotError("alternate object databases are unsupported")

    def _reaudit_repository_files(self) -> None:
        """Recheck repository-control sentinels before another Git child."""

        self._refuse_grafts_and_shallow(self.git_dir, self._state.common_dir)
        self._refuse_alternates(self.git_dir, self._state.common_dir)

    def __enter__(self) -> "TreeSnapshot":
        if self._state.closed:
            raise SnapshotError("snapshot is closed")
        if self._state.entered:
            raise SnapshotError("snapshot is already entered")
        temporary: tempfile.TemporaryDirectory[str] | None = None
        try:
            temporary = tempfile.TemporaryDirectory(prefix="receipt-snapshot-")
            global_path = pathlib.Path(temporary.name, "global.gitconfig")
            global_path.write_bytes(self._state.global_config_bytes)
            global_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            self._reaudit_repository_files()
            batch = _BatchReader(
                self.git_dir,
                environment=_git_environment(global_path),
                object_format=self.object_format,
            )
        except BaseException as caught:
            if temporary is not None:
                try:
                    temporary.cleanup()
                except BaseException as cleanup_error:
                    caught.add_note(
                        f"Snapshot startup cleanup also failed: {cleanup_error}"
                    )
            self._state.closed = True
            raise
        self._state.tempdir = temporary
        self._state.global_config = global_path
        self._state.batch = batch
        self._state.entered = True
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        _traceback: object,
    ) -> None:
        closing_errors: list[BaseException] = []
        try:
            if self._state.active_digest_token is not None:
                self._abandon()
            if self._state.batch is not None:
                try:
                    self._state.batch.close()
                except BaseException as caught:
                    closing_errors.append(caught)
            try:
                self._reaudit_repository_files()
            except BaseException as caught:
                closing_errors.append(caught)
            if self._state.global_config is not None:
                try:
                    completed = _git_run(
                        [
                            "-C",
                            os.fspath(self._state.root),
                            "config",
                            "--list",
                            "--show-scope",
                            "--no-includes",
                            "-z",
                        ],
                        cwd=None,
                        environment=_git_environment(self._state.global_config),
                    )
                    if completed.returncode != 0:
                        raise SnapshotError(
                            f"cannot re-audit repository configuration: "
                            f"{_first_error(completed)}"
                        )
                    records = _parse_config(completed.stdout)
                    if records != self._state.config_records:
                        raise SnapshotError(
                            "repository configuration changed during verification"
                        )
                    _audit_config(records, self._state.root)
                except BaseException as caught:
                    closing_errors.append(caught)
        finally:
            try:
                if self._state.tempdir is not None:
                    self._state.tempdir.cleanup()
            except BaseException as caught:
                closing_errors.append(caught)
            finally:
                self._state.batch = None
                self._state.tempdir = None
                self._state.global_config = None
                self._state.entered = False
                self._state.closed = True
        if closing_errors:
            if exc is not None:
                for closing_error in closing_errors:
                    exc.add_note(f"Snapshot close also failed: {closing_error}")
            else:
                primary, *additional = closing_errors
                for closing_error in additional:
                    primary.add_note(f"Snapshot close also failed: {closing_error}")
                raise primary

    @property
    def root(self) -> pathlib.Path:
        return self._state.root

    @property
    def common_dir(self) -> pathlib.Path:
        return self._state.common_dir

    @property
    def work(self) -> SnapshotWork:
        return self._state.work

    def _verification_total(self, field_name: str) -> int:
        pool = self._state.work_pool.root()
        return sum(getattr(work, field_name) for work in pool.works)

    def _charge_verification(
        self,
        field_name: str,
        amount: int,
        *,
        ceiling: int,
        message: str,
    ) -> None:
        if self._verification_total(field_name) + amount > ceiling:
            raise SnapshotError(message)
        work = self._state.work
        setattr(work, field_name, getattr(work, field_name) + amount)

    def _link_verification_work(self, other: "TreeSnapshot") -> None:
        """Make verification-wide budgets cumulative across a snapshot pair."""

        left = self._state.work_pool.root()
        right = other._state.work_pool.root()
        if left is right:
            return
        combined = (*left.works, *right.works)
        limits = (
            (
                "path_bytes",
                MAX_PATH_BYTES_TOTAL,
                f"tree paths exceed the snapshot budget of {MAX_PATH_BYTES_TOTAL} bytes",
            ),
            (
                "attribute_bytes",
                MAX_ATTRIBUTE_BYTES_TOTAL,
                f"attribute bytes exceed the snapshot budget of {MAX_ATTRIBUTE_BYTES_TOTAL} bytes",
            ),
            (
                "attribute_rules",
                MAX_ATTRIBUTE_RULES_TOTAL,
                f"attribute rules exceed the snapshot budget of {MAX_ATTRIBUTE_RULES_TOTAL} rules",
            ),
            (
                "attribute_match_work",
                MAX_ATTRIBUTE_MATCH_WORK,
                f"attribute matching exceeds the work budget of {MAX_ATTRIBUTE_MATCH_WORK} steps",
            ),
            (
                "content_bytes",
                MAX_CONTENT_BYTES_TOTAL,
                f"content bytes exceed the snapshot budget of {MAX_CONTENT_BYTES_TOTAL} bytes",
            ),
            (
                "materialized_bytes",
                MAX_MATERIALIZED_BYTES,
                f"materialized bytes exceed the budget of {MAX_MATERIALIZED_BYTES} bytes",
            ),
        )
        for field_name, ceiling, message in limits:
            if sum(getattr(work, field_name) for work in combined) > ceiling:
                raise SnapshotError(message)
        left.works.extend(right.works)
        right.parent = left

    @property
    def batch_pid(self) -> int | None:
        batch = self._state.batch
        return batch.process.pid if batch is not None else None

    @property
    def temporary_directory(self) -> pathlib.Path | None:
        temporary = self._state.tempdir
        return pathlib.Path(temporary.name) if temporary is not None else None

    def _batch(self, *, digest_token: object | None = None) -> _BatchReader:
        if self._state.abandoned:
            raise SnapshotError("snapshot stream was abandoned")
        if (
            self._state.active_digest_token is not None
            and digest_token is not self._state.active_digest_token
        ):
            self._abandon()
            raise SnapshotError("snapshot stream was abandoned")
        if not self._state.entered or self._state.batch is None:
            raise SnapshotError("snapshot must be entered before object reads")
        if self._state.batch.abandoned:
            self._state.abandoned = True
            raise SnapshotError("snapshot stream was abandoned")
        return self._state.batch

    def _abandon(self) -> None:
        self._state.abandoned = True
        if self._state.batch is not None:
            self._state.batch.abandon()

    def _validate_oid(self, oid: str) -> str:
        width = hashlib.new(self.object_format).digest_size * 2
        if (
            type(oid) is not str
            or len(oid) != width
            or re.fullmatch(r"[0-9a-f]+", oid) is None
        ):
            raise SnapshotError(f"object name is not full lowercase hexadecimal: {oid!r}")
        return oid

    def _require_entry(self, entry: GitEntry) -> str:
        """Bind an entry argument to this snapshot before using its OID."""

        if type(entry) is not GitEntry:
            raise SnapshotError("blob entry must be a GitEntry")
        binding = entry._snapshot_token
        if (
            type(binding) is not _EntryBinding
            or binding.snapshot_token is not self._state.entry_token
            or any(
                type(value) is not str
                for value in (
                    entry.mode,
                    entry.object_type,
                    entry.object_id,
                    entry.path,
                )
            )
            or (
                entry.mode,
                entry.object_type,
                entry.object_id,
                entry.path,
            )
            != (
                binding.mode,
                binding.object_type,
                binding.object_id,
                binding.path,
            )
        ):
            raise SnapshotError("GitEntry does not belong to this snapshot")
        return self._validate_oid(entry.object_id)

    def header(self, oid: str) -> tuple[str, int]:
        """Return an object's type and size without requesting its payload."""

        return self._batch().info(self._validate_oid(oid))

    def _charge_tree_object(self, size: int) -> None:
        work = self._state.work
        if work.tree_bytes + size > MAX_TREE_BYTES_TOTAL:
            raise SnapshotError(
                f"tree and commit bytes exceed the snapshot budget of "
                f"{MAX_TREE_BYTES_TOTAL} bytes"
            )
        work.tree_bytes += size
        work.max_tree_object_bytes = max(work.max_tree_object_bytes, size)

    def _tree_object(self, oid: str) -> tuple[_RawTreeEntry, ...]:
        batch = self._batch()
        cached = self._state.tree_cache.get(oid)
        if cached is not None:
            return cached
        _kind, size = batch.info(oid, role="tree")
        if self._state.work.tree_bytes + size > MAX_TREE_BYTES_TOTAL:
            raise SnapshotError(
                f"tree and commit bytes exceed the snapshot budget of "
                f"{MAX_TREE_BYTES_TOTAL} bytes"
            )
        payload = batch.consume(
            oid, role="tree", limit=MAX_TREE_OBJECT_BYTES, hold=True
        )
        assert payload is not None
        self._charge_tree_object(size)
        parsed = _parse_raw_tree(oid, payload, object_format=self.object_format)
        if len(parsed) > MAX_TREE_ENTRIES:
            raise SnapshotError(
                f"tree walk exceeds the budget of {MAX_TREE_ENTRIES} entries"
            )
        for raw in parsed:
            if raw.mode != b"160000":
                batch.info(raw.oid, role=raw.object_type)
        self._state.tree_cache[oid] = parsed
        return parsed

    def _commit_object(
        self, oid: str, *, parent_budget: int | None = None
    ) -> _CommitObject:
        batch = self._batch()
        cached = self._state.commit_cache.get(oid)
        if cached is not None:
            return cached
        _kind, size = batch.info(oid, role="commit")
        if self._state.work.tree_bytes + size > MAX_TREE_BYTES_TOTAL:
            raise SnapshotError(
                f"tree and commit bytes exceed the snapshot budget of "
                f"{MAX_TREE_BYTES_TOTAL} bytes"
            )
        payload = batch.consume(
            oid, role="commit", limit=MAX_TREE_OBJECT_BYTES, hold=True
        )
        assert payload is not None
        self._charge_tree_object(size)
        if parent_budget is None:
            parent_budget = MAX_ANCESTRY_COMMITS
        parsed = _canonical_commit(
            oid,
            payload,
            object_format=self.object_format,
            parent_limit=parent_budget,
        )
        batch.info(parsed.tree, role="tree")
        if len(parsed.parents) > parent_budget:
            raise SnapshotError(
                f"ancestry walk exceeds the budget of "
                f"{MAX_ANCESTRY_COMMITS} commits"
            )
        # Every tree line reached by the ancestry walk is authenticated even
        # though parentage itself needs only the commit payload.
        self._tree_object(parsed.tree)
        for parent in parsed.parents:
            batch.info(parent, role="commit")
        self._state.commit_cache[oid] = parsed
        return parsed

    def _charge_walk_records(
        self, records: Sequence[_RawTreeEntry], count: list[int]
    ) -> None:
        count[0] += len(records)
        work = self._state.work
        work.tree_entries += len(records)
        work.max_tree_entries_in_walk = max(
            work.max_tree_entries_in_walk, count[0]
        )
        if count[0] > MAX_TREE_ENTRIES:
            raise SnapshotError(
                f"tree walk exceeds the budget of {MAX_TREE_ENTRIES} entries"
            )

    @staticmethod
    def _find_raw_entry(
        records: Sequence[_RawTreeEntry], component: bytes
    ) -> _RawTreeEntry | None:
        """Find an exact raw name in canonical Git order in logarithmic work."""

        for key in (component, component + b"/"):
            index = bisect_left(records, key, key=_raw_tree_sort_key)
            if index < len(records) and records[index].name == component:
                return records[index]
        return None

    @staticmethod
    def _path_parts(path: str | bytes, *, allow_empty: bool) -> tuple[bytes, ...]:
        if type(path) is str:
            try:
                raw_path = _tree_path_encode(path)
            except UnicodeEncodeError as exc:
                raise SnapshotError(f"tree path cannot be encoded: {path!r}") from exc
        elif type(path) is bytes:
            raw_path = path
        else:
            raise SnapshotError(f"tree path must be str or bytes: {path!r}")
        if not raw_path and allow_empty:
            return ()
        if not raw_path or raw_path.startswith(b"/") or raw_path.endswith(b"/"):
            raise SnapshotError(f"tree path must be a relative non-empty path: {path!r}")
        if len(raw_path) > MAX_PATH_BYTES:
            raise SnapshotError(
                f"tree path exceeds the budget of {MAX_PATH_BYTES} bytes"
            )
        parts = tuple(raw_path.split(b"/"))
        if len(parts) > MAX_TREE_DEPTH + 1:
            raise SnapshotError(
                f"tree path exceeds the depth budget of {MAX_TREE_DEPTH}"
            )
        try:
            for part in parts:
                validate_component_bytes(part, label="tree path component")
        except NamePolicyError as exc:
            raise SnapshotError(str(exc)) from exc
        return parts

    def _public_entry(
        self, parts: tuple[bytes, ...], raw: _RawTreeEntry
    ) -> GitEntry:
        path_bytes = b"/".join(parts)
        self._charge_path_bytes(path_bytes)
        path_text = _tree_path_decode(path_bytes)
        mode = raw.display_mode
        object_type = raw.object_type
        binding = _EntryBinding(
            self._state.entry_token,
            mode,
            object_type,
            raw.oid,
            path_text,
        )
        return GitEntry(
            mode=mode,
            object_type=object_type,
            object_id=raw.oid,
            path=path_text,
            _snapshot_token=binding,
        )

    def _charge_path_bytes(self, path_bytes: bytes) -> None:
        """Charge one full logical path at the moment it is materialized."""

        size = len(path_bytes)
        if size > MAX_PATH_BYTES:
            raise SnapshotError(
                f"tree path exceeds the budget of {MAX_PATH_BYTES} bytes"
            )
        work = self._state.work
        self._charge_verification(
            "path_bytes",
            size,
            ceiling=MAX_PATH_BYTES_TOTAL,
            message=f"tree paths exceed the snapshot budget of {MAX_PATH_BYTES_TOTAL} bytes",
        )
        work.max_path_bytes = max(work.max_path_bytes, size)

    def _build_listing(
        self,
        tree_oid: str,
        *,
        depth: int,
        count: list[int],
    ) -> _TreeNode:
        if depth > MAX_TREE_DEPTH:
            raise SnapshotError(
                f"tree depth exceeds the budget of {MAX_TREE_DEPTH}"
            )
        records: list[_ListingRecord] = []
        raw_entries = self._tree_object(tree_oid)
        for raw in raw_entries:
            count[0] += 1
            self._state.work.tree_entries += 1
            self._state.work.max_tree_entries_in_walk = max(
                self._state.work.max_tree_entries_in_walk, count[0]
            )
            if count[0] > MAX_TREE_ENTRIES:
                raise SnapshotError(
                    f"tree walk exceeds the budget of {MAX_TREE_ENTRIES} entries"
                )
            child: _TreeNode | None = None
            if raw.mode != b"160000":
                self._batch().info(raw.oid, role=raw.object_type)
            if raw.mode == b"40000":
                child = self._build_listing(
                    raw.oid,
                    depth=depth + 1,
                    count=count,
                )
            records.append(_ListingRecord(raw=raw, child=child))
        return _TreeNode(tuple(records), tree_oid)

    def entry(self, path: str | bytes) -> GitEntry:
        """Look up one path by its exact component bytes."""

        self._batch()
        parts = self._path_parts(path, allow_empty=False)
        tree_oid = self.tree
        count = [0]
        for index, component in enumerate(parts):
            records = self._tree_object(tree_oid)
            self._charge_walk_records(records, count)
            raw = self._find_raw_entry(records, component)
            if raw is None:
                raise SnapshotError(
                    "tree entry does not exist: "
                    f"{_tree_path_decode(b'/'.join(parts))}"
                )
            last = index == len(parts) - 1
            if raw.mode != b"160000":
                self._batch().info(raw.oid, role=raw.object_type)
            if last:
                return self._public_entry(parts, raw)
            if raw.mode != b"40000":
                prefix = _tree_path_decode(b"/".join(parts[: index + 1]))
                if raw.mode == b"120000":
                    raise SnapshotError(f"state path has a symlinked component: {prefix}")
                raise SnapshotError(f"tree path ancestor is not a directory: {prefix}")
            tree_oid = raw.oid
        raise AssertionError("a non-empty path has at least one component")

    def entries(self, prefix: str | bytes = "") -> TreeListing:
        """Walk a subtree into a hierarchical listing under the walk budgets."""

        self._batch()
        parts = self._path_parts(prefix, allow_empty=True)
        if not parts:
            node = self._build_listing(self.tree, depth=0, count=[0])
            return TreeListing(self, (), node)
        tree_oid = self.tree
        count = [0]
        for index, component in enumerate(parts):
            records = self._tree_object(tree_oid)
            self._charge_walk_records(records, count)
            raw = self._find_raw_entry(records, component)
            if raw is None:
                return TreeListing(self, parts, _TreeNode((), None))
            last = index == len(parts) - 1
            if raw.mode != b"160000":
                self._batch().info(raw.oid, role=raw.object_type)
            if last:
                if raw.mode == b"40000":
                    node = self._build_listing(
                        raw.oid, depth=len(parts), count=count
                    )
                    return TreeListing(self, parts, node)
                return TreeListing(
                    self,
                    parts[:-1],
                    _TreeNode((_ListingRecord(raw=raw),), None),
                )
            if raw.mode != b"40000":
                prefix_text = _tree_path_decode(b"/".join(parts[: index + 1]))
                if raw.mode == b"120000":
                    raise SnapshotError(
                        f"state path has a symlinked component: {prefix_text}"
                    )
                raise SnapshotError(
                    f"tree path ancestor is not a directory: {prefix_text}"
                )
            tree_oid = raw.oid
        raise AssertionError("a non-empty path has at least one component")

    def blob(self, entry: GitEntry, *, limit: int) -> bytes:
        """Return one authenticated blob payload under a required caller limit."""

        object_id = self._require_entry(entry)
        if type(limit) is not int or limit < 0:
            raise SnapshotError("blob limit must be a non-negative integer")
        if entry.object_type != "blob":
            raise SnapshotError(
                f"object {entry.object_id} is a {entry.object_type}, not the blob "
                "its reference requires"
            )
        if entry.mode not in _CONTENT_MODES:
            raise SnapshotError(
                f"tree entry has non-regular mode {entry.mode}: {entry.path}"
            )
        payload = self._batch().consume(
            object_id,
            role="blob",
            limit=limit,
            hold=True,
        )
        assert payload is not None
        return payload

    def digests(
        self,
        entries: Iterable[GitEntry],
        *,
        per_blob: int = MAX_CONTENT_BLOB_BYTES,
        total: int = MAX_CONTENT_BYTES_TOTAL,
    ) -> Iterator[tuple[GitEntry, str]]:
        """Stream authenticated blobs and yield their SHA-256 digests."""

        if type(per_blob) is not int or per_blob < 0:
            raise SnapshotError("per_blob must be a non-negative integer")
        if type(total) is not int or total < 0:
            raise SnapshotError("total must be a non-negative integer")
        if isinstance(entries, (str, bytes, GitEntry)):
            raise SnapshotError("digests entries must be an iterable of GitEntry objects")
        self._batch()
        return _DigestIterator(self, entries, per_blob=per_blob, total=total)

    def changed_paths(self, base: "TreeSnapshot") -> set[str]:
        """Compare authenticated leaf OIDs and modes without reading blob bytes."""

        if not isinstance(base, TreeSnapshot):
            raise SnapshotError("changed_paths base must be a TreeSnapshot")
        if base.git_dir != self.git_dir or base.object_format != self.object_format:
            raise SnapshotError("candidate and base snapshots must share an object store")
        self._batch()
        base._batch()
        self._link_verification_work(base)
        candidate_entries = self.entries("").as_dict()
        base_entries = base.entries("").as_dict()
        changed: set[str] = set()
        for path in candidate_entries.keys() | base_entries.keys():
            candidate = candidate_entries.get(path)
            prior = base_entries.get(path)
            if (
                candidate is None
                or prior is None
                or candidate.mode != prior.mode
                or candidate.object_id != prior.object_id
            ):
                changed.add(path)
        return changed

    def parents(self, commit: str) -> tuple[str, ...]:
        """Return parents from an authenticated canonical commit object."""

        self._batch()
        return self._commit_object(self._validate_oid(commit)).parents

    def assert_ancestor(self, base: "TreeSnapshot") -> str:
        """Prove a selected base commit is in this candidate's parent graph.

        A symbolic base is selected exactly once by its own
        :meth:`TreeSnapshot.select` call. Requiring that entered snapshot
        prevents a moving ref from being resolved a second time and joins the
        verification-wide work budgets before either tree is consumed.
        """

        self._batch()
        if not isinstance(base, TreeSnapshot):
            raise SnapshotError("assert_ancestor base must be a TreeSnapshot")
        if base.git_dir != self.git_dir or base.object_format != self.object_format:
            raise SnapshotError("candidate and base snapshots must share an object store")
        base._batch()
        base_oid = base.commit
        stack = [self.commit]
        seen: set[str] = set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            work = self._state.work
            if work.ancestry_commits >= MAX_ANCESTRY_COMMITS:
                raise SnapshotError(
                    f"ancestry walk exceeds the budget of "
                    f"{MAX_ANCESTRY_COMMITS} commits"
                )
            work.ancestry_commits += 1
            commit = self._commit_object(
                current,
                parent_budget=MAX_ANCESTRY_COMMITS - work.ancestry_edges,
            )
            if current == base_oid:
                self._link_verification_work(base)
                self._state.ancestry_bases.add(base_oid)
                return base_oid
            if work.ancestry_edges + len(commit.parents) > MAX_ANCESTRY_COMMITS:
                raise SnapshotError(
                    f"ancestry walk exceeds the budget of "
                    f"{MAX_ANCESTRY_COMMITS} commits"
                )
            work.ancestry_edges += len(commit.parents)
            stack.extend(reversed(commit.parents))
        if self._state.revision == "HEAD":
            raise SnapshotError(
                f"base commit {base_oid} is not an ancestor of HEAD"
            )
        raise SnapshotError(
            f"base commit {base_oid} is not an ancestor of candidate commit "
            f"{self.commit}"
        )

    def verify_object_store(self, heads: Iterable[str]) -> ObjectStoreReport:
        """Run the bounded SHA1DC verification of the whole primary store."""

        self._batch()
        if not self._state.verify_objects_ready:
            raise SnapshotError(
                "verify_object_store requires select(..., verify_objects=True)"
            )
        if self._state.global_config is None:
            raise AssertionError("an entered snapshot has a private config")
        if self._state.object_store_attempted:
            raise SnapshotError("verify_object_store may be run only once per snapshot")
        if isinstance(heads, (str, bytes)):
            raise SnapshotError("verify_object_store heads must be an iterable of OIDs")
        try:
            iterator = iter(heads)
        except TypeError as exc:
            raise SnapshotError(
                "verify_object_store heads must be an iterable of OIDs"
            ) from exc
        supplied: list[str] = []
        for head in iterator:
            if len(supplied) == 2:
                raise SnapshotError(
                    "verify_object_store requires candidate and optional base heads"
                )
            supplied.append(self._validate_oid(head))
        resolved_heads = tuple(supplied)
        if not resolved_heads or resolved_heads[0] != self.commit:
            raise SnapshotError(
                "verify_object_store first head must be the selected candidate commit"
            )
        if self._state.ancestry_bases:
            heads_are_exact = (
                len(resolved_heads) == 2
                and resolved_heads[1] in self._state.ancestry_bases
            )
        else:
            heads_are_exact = resolved_heads == (self.commit,)
        if not heads_are_exact:
            raise SnapshotError(
                "verify_object_store heads must be exactly the resolved candidate and base"
            )
        self._state.object_store_attempted = True
        environment = _git_environment(self._state.global_config)
        self._reaudit_repository_files()
        counted = _git_run(
            _object_arguments(self.git_dir, ["count-objects", "-v"]),
            cwd=None,
            environment=environment,
        )
        if counted.returncode != 0:
            raise SnapshotError(
                f"cannot count the primary object database: {_first_error(counted)}"
            )
        values: dict[str, int] = {}
        try:
            count_lines = counted.stdout.decode(
                "ascii", errors="strict"
            ).splitlines()
        except UnicodeDecodeError as exc:
            raise SnapshotError("git count-objects output is malformed") from exc
        for line in count_lines:
            key, separator, value = line.partition(": ")
            if not separator or key in values:
                raise SnapshotError("git count-objects output is malformed")
            if key == "alternate":
                raise SnapshotError("alternate object databases are unsupported")
            if value.isdecimal():
                values[key] = int(value)
        required = {"count", "size", "in-pack", "size-pack"}
        if not required <= values.keys():
            raise SnapshotError("git count-objects output is malformed")
        objects = values["count"] + values["in-pack"]
        store_kib = values["size"] + values["size-pack"]
        if objects > MAX_FSCK_OBJECTS:
            raise SnapshotError(
                f"object database exceeds the budget of {MAX_FSCK_OBJECTS} objects"
            )
        if store_kib > MAX_STORE_KIB:
            raise SnapshotError(
                f"object database exceeds the budget of {MAX_STORE_KIB} KiB"
            )

        self._reaudit_repository_files()
        started = time.monotonic()
        checked = _git_run(
            _object_arguments(
                self.git_dir,
                [
                    "-c",
                    "core.commitGraph=false",
                    "fsck",
                    "--full",
                    "--no-dangling",
                    "--no-reflogs",
                    "--no-references",
                    "--no-progress",
                    *resolved_heads,
                ],
            ),
            cwd=None,
            environment=environment,
            output_limit=MAX_FSCK_OUTPUT_BYTES,
            seconds=MAX_FSCK_SECONDS,
        )
        elapsed = time.monotonic() - started
        if checked.returncode != 0:
            raise SnapshotError(
                "object database failed git's own verification: "
                f"{_first_error(checked)}"
            )
        return ObjectStoreReport(objects=objects, store_kib=store_kib, seconds=elapsed)

    def _raw_entry_at(self, parts: tuple[bytes, ...]) -> _RawTreeEntry | None:
        tree_oid = self.tree
        count = [0]
        for index, component in enumerate(parts):
            records = self._tree_object(tree_oid)
            self._charge_walk_records(records, count)
            raw = self._find_raw_entry(records, component)
            if raw is None:
                return None
            if raw.mode != b"160000":
                self._batch().info(raw.oid, role=raw.object_type)
            if index == len(parts) - 1:
                return raw
            if raw.mode != b"40000":
                ancestor = _tree_path_decode(b"/".join(parts[: index + 1]))
                raise SnapshotError(
                    f"protected path ancestor is not a directory: {ancestor}"
                )
            tree_oid = raw.oid
        return None

    def _attribute_rules(
        self, parts: tuple[bytes, ...]
    ) -> tuple[_AttributeRule, ...]:
        path_bytes = b"/".join(parts)
        path = _tree_path_decode(path_bytes)
        cached = self._state.attribute_cache.get(path)
        if cached is not None:
            return cached
        raw = self._raw_entry_at(parts)
        if raw is None:
            self._state.attribute_cache[path] = ()
            return ()
        if raw.mode not in {b"100644", b"100755"}:
            raise SnapshotError(
                f"unsupported .gitattributes entry at {path}: mode {raw.display_mode}"
            )
        _kind, size = self._batch().info(raw.oid, role="blob")
        if self._verification_total("attribute_bytes") + size > MAX_ATTRIBUTE_BYTES_TOTAL:
            raise SnapshotError(
                f"attribute bytes exceed the snapshot budget of "
                f"{MAX_ATTRIBUTE_BYTES_TOTAL} bytes"
            )
        entry = self._public_entry(parts, raw)
        payload = self.blob(entry, limit=MAX_ATTRIBUTE_BYTES)
        self._charge_verification(
            "attribute_bytes",
            size,
            ceiling=MAX_ATTRIBUTE_BYTES_TOTAL,
            message=f"attribute bytes exceed the snapshot budget of {MAX_ATTRIBUTE_BYTES_TOTAL} bytes",
        )
        remaining_rules = (
            MAX_ATTRIBUTE_RULES_TOTAL
            - self._verification_total("attribute_rules")
        )
        rules = _parse_attribute_file(
            path, payload, rule_limit=max(0, remaining_rules)
        )
        if self._verification_total("attribute_rules") + len(rules) > MAX_ATTRIBUTE_RULES_TOTAL:
            raise SnapshotError(
                f"attribute rules exceed the snapshot budget of "
                f"{MAX_ATTRIBUTE_RULES_TOTAL} rules"
            )
        self._charge_verification(
            "attribute_rules",
            len(rules),
            ceiling=MAX_ATTRIBUTE_RULES_TOTAL,
            message=f"attribute rules exceed the snapshot budget of {MAX_ATTRIBUTE_RULES_TOTAL} rules",
        )
        self._state.attribute_cache[path] = rules
        return rules

    def _attribute_step(self) -> None:
        self._charge_verification(
            "attribute_match_work",
            1,
            ceiling=MAX_ATTRIBUTE_MATCH_WORK,
            message=(
                f"attribute matching exceeds the work budget of "
                f"{MAX_ATTRIBUTE_MATCH_WORK} steps"
            ),
        )

    def refuse_transforming_attributes(
        self, paths: Iterable[str | bytes | GitEntry]
    ) -> None:
        """Evaluate the fail-closed committed-attribute subset over paths.

        Only ``filter``, ``ident`` and ``working-tree-encoding`` transform raw
        blob bytes: their set and valued states refuse, while unset, absent
        and an explicit unspecified state are harmless. ``text`` and ``eol``
        are accepted in every state, and the built-in ``binary`` macro expands
        to ``-diff -merge -text``. Under ``core.ignoreCase`` in the
        repository's own scopes the patterns and the paths are compared after
        an ASCII case fold, as git's ``WM_CASEFOLD`` does; a value of that key
        git could not classify as a boolean is refused at selection. No
        non-tree attribute source is consulted.
        """

        self._batch()
        if isinstance(paths, (str, bytes, GitEntry)):
            raise SnapshotError("attribute paths must be an iterable of paths")
        try:
            iterator = iter(paths)
        except TypeError as exc:
            raise SnapshotError("attribute paths must be an iterable of paths") from exc
        unique: dict[bytes, tuple[bytes, ...]] = {}
        for count, supplied in enumerate(iterator, start=1):
            if count > MAX_TREE_ENTRIES:
                raise SnapshotError(
                    f"attribute paths exceed the budget of {MAX_TREE_ENTRIES} entries"
                )
            value: str | bytes
            if isinstance(supplied, GitEntry):
                value = supplied.path
            else:
                value = supplied
            parts = self._path_parts(value, allow_empty=False)
            path_bytes = b"/".join(parts)
            self._charge_path_bytes(path_bytes)
            unique.setdefault(path_bytes, parts)

        transforms = {"filter", "ident", "working-tree-encoding"}
        # Under core.ignoreCase git matches attribute patterns with
        # WM_CASEFOLD, an ASCII fold of both sides; the same fold is applied
        # here so a pattern spelled in another case still reaches the
        # transforming-attribute refusal (peer review, round 2). bytes.lower
        # folds ASCII letters alone, which is what git's tolower does.
        fold = _config_ignorecase(self._state.config_records)
        folded_rules: dict[int, _AttributeRule] = {}
        for path_bytes, parts in unique.items():
            final: dict[str, str] = {}
            for depth in range(len(parts)):
                attribute_parts = (*parts[:depth], b".gitattributes")
                rules = self._attribute_rules(attribute_parts)
                relative = parts[depth:]
                if fold:
                    relative = tuple(segment.lower() for segment in relative)
                for rule in rules:
                    if fold:
                        candidate_rule = folded_rules.get(id(rule))
                        if candidate_rule is None:
                            candidate_rule = _AttributeRule(
                                rule.pattern.lower(),
                                tuple(s.lower() for s in rule.segments),
                                tuple(s.lower() for s in rule.match_segments),
                                rule.has_slash,
                                rule.trailing_descendants,
                                rule.states,
                            )
                            folded_rules[id(rule)] = candidate_rule
                        rule = candidate_rule
                    if _attribute_matches(rule, relative, self._attribute_step):
                        for name, disposition in rule.states:
                            self._attribute_step()
                            final[name] = disposition
            for name in sorted(transforms):
                if final.get(name) in {"set", "value"}:
                    try:
                        path = path_bytes.decode("utf-8", errors="strict")
                    except UnicodeDecodeError as exc:
                        raise SnapshotError(
                            "tree entry name is not valid UTF-8 for quoting"
                        ) from exc
                    raise SnapshotError(
                        f"transforming attribute {name} applies to protected "
                        f"path {path}"
                    )

    def materialize(
        self,
        prefixes: Iterable[str | bytes | pathlib.PurePosixPath],
        destination: os.PathLike[str] | str,
        *,
        repertoire: str,
    ) -> "Materialization":
        """Return an unentered private materialization; no path exists yet."""

        try:
            selected_repertoire = validate_repertoire(repertoire)
        except NamePolicyError as exc:
            raise SnapshotError(str(exc)) from exc
        if isinstance(prefixes, (str, bytes, pathlib.PurePath)):
            raise SnapshotError("materialization prefixes must be an iterable of paths")
        try:
            requested_list: list[str | bytes] = []
            for prefix in prefixes:
                if len(requested_list) >= MAX_TREE_ENTRIES:
                    raise SnapshotError(
                        f"materialization prefixes exceed the budget of "
                        f"{MAX_TREE_ENTRIES} entries"
                    )
                if type(prefix) is pathlib.PurePosixPath:
                    requested_list.append(prefix.as_posix())
                elif type(prefix) in {str, bytes}:
                    requested_list.append(prefix)
                else:
                    raise SnapshotError(
                        "materialization prefix must be str, bytes, or "
                        f"PurePosixPath: {prefix!r}"
                    )
            requested = tuple(requested_list)
        except TypeError as exc:
            raise SnapshotError("materialization prefixes must be iterable") from exc
        try:
            parent = pathlib.Path(os.fspath(destination))
        except (TypeError, ValueError) as exc:
            raise SnapshotError("materialization destination must be path-like") from exc
        return Materialization(self, requested, parent, selected_repertoire)


class Materialization:
    """A context-managed, screen-first private directory of selected blobs."""

    def __init__(
        self,
        snapshot: TreeSnapshot,
        prefixes: tuple[str | bytes, ...],
        destination: pathlib.Path,
        repertoire: str,
    ) -> None:
        self._snapshot = snapshot
        self._prefixes = prefixes
        self._destination = destination
        self._repertoire = repertoire
        self._path: pathlib.Path | None = None
        self._entries: dict[str, GitEntry] = {}
        self._entered = False
        self._closed = False

    @property
    def path(self) -> pathlib.Path:
        if self._path is None:
            raise SnapshotError("materialization must be entered before its path is used")
        return self._path

    @property
    def entries(self) -> dict[str, GitEntry]:
        if not self._entered:
            raise SnapshotError("materialization must be entered before entries are used")
        return dict(self._entries)

    def _deduplicated_prefixes(self) -> tuple[tuple[bytes, ...], ...]:
        parts: set[tuple[bytes, ...]] = set()
        for prefix in self._prefixes:
            parsed = self._snapshot._path_parts(prefix, allow_empty=True)
            path_bytes = b"/".join(parsed)
            self._snapshot._charge_path_bytes(path_bytes)
            parts.add(parsed)
        # Lexicographic tuple order places an ancestor immediately before all
        # of its descendants. Keeping only the last retained prefix therefore
        # avoids the quadratic all-parents scan for many disjoint prefixes.
        ordered = sorted(parts)
        kept: list[tuple[bytes, ...]] = []
        for candidate in ordered:
            if kept and candidate[: len(kept[-1])] == kept[-1]:
                continue
            kept.append(candidate)
        return tuple(kept)

    def _selected_entries(self) -> dict[str, GitEntry]:
        selected: dict[str, GitEntry] = {}
        for parts in self._deduplicated_prefixes():
            if not parts:
                for entry in self._snapshot.entries(""):
                    selected[entry.path] = entry
                    if len(selected) > MAX_TREE_ENTRIES:
                        raise SnapshotError(
                            f"tree walk exceeds the budget of "
                            f"{MAX_TREE_ENTRIES} entries"
                        )
                continue
            raw = self._snapshot._raw_entry_at(parts)
            if raw is None:
                continue
            if raw.mode == b"40000":
                for entry in self._snapshot.entries(b"/".join(parts)):
                    selected[entry.path] = entry
                    if len(selected) > MAX_TREE_ENTRIES:
                        raise SnapshotError(
                            f"tree walk exceeds the budget of "
                            f"{MAX_TREE_ENTRIES} entries"
                        )
            else:
                entry = self._snapshot._public_entry(parts, raw)
                selected[entry.path] = entry
                if len(selected) > MAX_TREE_ENTRIES:
                    raise SnapshotError(
                        f"tree walk exceeds the budget of "
                        f"{MAX_TREE_ENTRIES} entries"
                    )

        sibling_names: dict[tuple[bytes, ...], set[bytes]] = {}
        for path, entry in sorted(selected.items()):
            if entry.mode not in _CONTENT_MODES:
                raise SnapshotError(
                    f"base tree entry has non-regular mode {entry.mode}: {path}"
                )
            raw_parts = self._snapshot._path_parts(path, allow_empty=False)
            for index, name in enumerate(raw_parts):
                sibling_names.setdefault(raw_parts[:index], set()).add(name)
        for parent, names in sibling_names.items():
            label = (
                _tree_path_decode(b"/".join(parent)) if parent else "tree root"
            )
            try:
                assert_no_merging_entries(
                    sorted(names),
                    repertoire=self._repertoire,
                    materializing=True,
                    label=label,
                )
            except NamePolicyError as exc:
                raise SnapshotError(str(exc)) from exc
        return selected

    def _write_chunk(self, handle: BinaryIO, chunk: bytes) -> None:
        written = 0
        view = memoryview(chunk)
        while written < len(chunk):
            count = handle.write(view[written:])
            if count is None or count <= 0:
                raise OSError("materialized file write made no progress")
            written += count
            self._snapshot._charge_verification(
                "materialized_bytes",
                count,
                ceiling=MAX_MATERIALIZED_BYTES,
                message=f"materialized bytes exceed the budget of {MAX_MATERIALIZED_BYTES} bytes",
            )

    def __enter__(self) -> "Materialization":
        if self._closed:
            raise SnapshotError("materialization is closed")
        if self._entered:
            raise SnapshotError("materialization is already entered")
        self._snapshot._batch()
        selected = self._selected_entries()
        try:
            destination_stat = self._destination.lstat()
        except OSError as exc:
            raise SnapshotError("materialization destination does not exist") from exc
        if not stat.S_ISDIR(destination_stat.st_mode) or stat.S_ISLNK(
            destination_stat.st_mode
        ):
            raise SnapshotError("materialization destination is not a real directory")

        created: pathlib.Path | None = None
        written_entries: dict[str, GitEntry] = {}
        local_total = 0
        try:
            created = pathlib.Path(
                tempfile.mkdtemp(
                    prefix=f"{self._snapshot.tree[:12]}-",
                    dir=self._destination,
                )
            )
            created.chmod(stat.S_IRWXU)
            for relative, entry in sorted(selected.items()):
                batch = self._snapshot._batch()
                _kind, size = batch.info(entry.object_id, role="blob")
                if size > MAX_MATERIALIZED_BLOB_BYTES:
                    raise SnapshotError(
                        f"materialized blob {relative!r} exceeds the budget of "
                        f"{MAX_MATERIALIZED_BLOB_BYTES} bytes"
                    )
                work = self._snapshot.work
                if (
                    local_total + size > MAX_MATERIALIZED_BYTES
                    or self._snapshot._verification_total("materialized_bytes") + size > MAX_MATERIALIZED_BYTES
                ):
                    raise SnapshotError(
                        f"materialized bytes exceed the budget of "
                        f"{MAX_MATERIALIZED_BYTES} bytes"
                    )
                output = created.joinpath(*relative.split("/"))
                output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with output.open("xb") as handle:

                    def consume(chunk: bytes, *, _handle: BinaryIO = handle) -> None:
                        self._write_chunk(_handle, chunk)

                    batch.consume(
                        entry.object_id,
                        role="blob",
                        limit=MAX_MATERIALIZED_BLOB_BYTES,
                        consumer=consume,
                    )
                output.chmod(0o755 if entry.mode == "100755" else 0o644)
                local_total += size
                work.max_materialized_blob_bytes = max(
                    work.max_materialized_blob_bytes, size
                )
                written_entries[relative] = entry
        except BaseException as caught:
            if created is not None:
                try:
                    shutil.rmtree(created, ignore_errors=False)
                except BaseException as cleanup_error:
                    caught.add_note(
                        f"Materialization cleanup also failed: {cleanup_error}"
                    )
            self._closed = True
            raise
        self._path = created
        self._entries = written_entries
        self._entered = True
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        exc: BaseException | None,
        _traceback: object,
    ) -> None:
        cleanup_error: BaseException | None = None
        try:
            if self._path is not None:
                shutil.rmtree(self._path, ignore_errors=False)
        except BaseException as caught:
            cleanup_error = caught
        finally:
            self._entries = {}
            self._path = None
            self._entered = False
            self._closed = True
        if cleanup_error is not None:
            if exc is not None:
                exc.add_note(f"Materialization cleanup also failed: {cleanup_error}")
            else:
                raise cleanup_error

    @staticmethod
    def _exact_filename(value: object) -> str:
        if not isinstance(value, (str, os.PathLike)):
            raise SnapshotError(
                "anchor filenames must be str or os.PathLike when the "
                f"anchor-set digest is computed; got {type(value).__name__}"
            )
        try:
            decoded = os.fsdecode(value)
            result = decoded if type(decoded) is str else str.__str__(decoded)
        except Exception as exc:
            raise SnapshotError(
                "anchor filename could not be decoded to a pathname: "
                f"{type(value).__name__}"
            ) from exc
        if _SURROGATE_PAIR_RE.search(result):
            raise SnapshotError(
                "anchor filename spells an astral character as an explicit "
                "surrogate pair, which JSON parsing would rewrite; configure "
                f"the character directly: {result!r}"
            )
        return result

    def anchor_set_sha256(self, chain_spec: object) -> str:
        """Digest configured materialized anchor bytes in receipt-canonical JSON."""

        if not self._entered or self._path is None:
            raise SnapshotError(
                "materialization must be entered before anchor bytes are digested"
            )
        try:
            anchor_relative = getattr(chain_spec, "anchor_relative")
            producer = getattr(chain_spec, "producer_public_key_filename")
            anchors = getattr(chain_spec, "anchors")
        except Exception as exc:
            raise SnapshotError("chain_spec does not carry the configured anchor set") from exc
        if not isinstance(anchor_relative, pathlib.PurePosixPath):
            raise SnapshotError("chain_spec anchor_relative must be a PurePosixPath")
        if not isinstance(anchors, Mapping):
            raise SnapshotError("chain_spec anchors must be a mapping")
        configured = [producer]
        for anchor in anchors.values():
            try:
                configured.append(getattr(anchor, "filename"))
            except Exception as exc:
                raise SnapshotError("configured anchor does not carry a filename") from exc

        per_file: dict[str, str] = {}
        for supplied in configured:
            filename = self._exact_filename(supplied)
            relative = anchor_relative / filename
            if relative.is_absolute() or ".." in relative.parts:
                raise SnapshotError(
                    f"configured anchor filename leaves the anchor directory: {filename!r}"
                )
            relative_text = relative.as_posix()
            if relative_text not in self._entries:
                raise SnapshotError(
                    f"configured anchor was not materialized: {relative_text}"
                )
            path = self._path.joinpath(*relative.parts)
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise SnapshotError(
                    f"configured materialized anchor is unavailable: {relative_text}"
                ) from exc
            if not stat.S_ISREG(metadata.st_mode):
                raise SnapshotError(
                    f"configured materialized anchor is not regular: {relative_text}"
                )
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                while chunk := handle.read(_BATCH_CHUNK_BYTES):
                    digest.update(chunk)
            prior = per_file.get(filename)
            if prior is not None and prior != digest.hexdigest():
                raise SnapshotError(
                    f"anchor file {filename!r} bytes changed during verification"
                )
            per_file[filename] = digest.hexdigest()

        from receipt.canonical import canonical_sha256, utf16_sort_key

        sort_keys = [utf16_sort_key(name) for name in per_file]
        if len(set(sort_keys)) != len(sort_keys):
            raise SnapshotError(
                "two configured anchor filenames are distinct in Python but "
                "identical as JSON strings; the verdict cannot report them faithfully"
            )
        return canonical_sha256(dict(per_file))


__all__ = [
    "BATCH_KILL_REAP_SECONDS",
    "GIT_COMMANDS",
    "GIT_ENVIRONMENT_DROPPED",
    "GIT_ENVIRONMENT_DROPPED_UNDOCUMENTED",
    "GIT_FSCK_NO_REFERENCES_MIN_VERSION",
    "GIT_MIN_VERSION",
    "GitEntry",
    "MAX_ANCESTRY_COMMITS",
    "MAX_ATTRIBUTE_BYTES",
    "MAX_ATTRIBUTE_BYTES_TOTAL",
    "MAX_ATTRIBUTE_MATCH_WORK",
    "MAX_ATTRIBUTE_RULES_TOTAL",
    "MAX_ATTRIBUTE_STATES_PER_LINE",
    "MAX_CONTENT_BLOB_BYTES",
    "MAX_CONTENT_BYTES_TOTAL",
    "MAX_ENTRY_NAME_BYTES",
    "MAX_FSCK_OBJECTS",
    "MAX_FSCK_OUTPUT_BYTES",
    "MAX_FSCK_SECONDS",
    "MAX_GIT_OUTPUT_BYTES",
    "MAX_GIT_SECONDS",
    "MAX_MATERIALIZED_BLOB_BYTES",
    "MAX_MATERIALIZED_BYTES",
    "MAX_PATH_BYTES",
    "MAX_PATH_BYTES_TOTAL",
    "MAX_STORE_KIB",
    "MAX_TREE_BYTES_TOTAL",
    "MAX_TREE_DEPTH",
    "MAX_TREE_ENTRIES",
    "MAX_TREE_OBJECT_BYTES",
    "Materialization",
    "ObjectStoreReport",
    "SnapshotError",
    "SnapshotWork",
    "TreeListing",
    "TreeSnapshot",
]
