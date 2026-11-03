"""What a refusal costs, and that every refusal is the module's own (#89, #90).

#89: a producer-written ``tokenPath`` with many components cost time quadratic
in its length before the verifier refused it, and a deep enough real tree cost
far more in the symlink walk. The guards here count the work the verifier asks
of the kernel, not the time it takes, and compare it across two sizes, so a
slow runner cannot fail them and a quadratic path cannot pass them.

#90: caller arguments of the wrong shape raised ``KeyError``, ``TypeError``,
``AttributeError`` or ``ValueError`` out of the public entry points. Each case
the issue lists is pinned below, and a Hypothesis property states the rule
over the whole domain of JSON-shaped arguments: the call returns, or it raises
``TsaError``.

The invariant both changes keep is that the verifier accepts nothing it
refused before. A path past the bound, or an argument of the wrong shape, was
never accepted: each one either refused or raised. So every test here that
feeds one in asserts a refusal.
"""

from __future__ import annotations

import contextlib
import os
import pathlib
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from hypothesis import HealthCheck, example, given, settings, strategies as st

from receipt import release_chain
from receipt import tsa as tsa_module
from receipt.tsa import (
    TokenEvidence,
    TsaError,
    WitnessEvidence,
    preferred_active_trust_bundle,
    verify_timestamp_token,
)

from test_tsa import (  # noqa: F401 - local_anchors is a fixture
    BUNDLE_LOGICAL,
    LocalAnchor,
    WitnessTree,
    build_witness_tree,
    local_anchors,
    rewrite_witness,
    token_claim,
    verify_step,
    verify_tree,
)

UTC = timezone.utc
HUGE = 10**5000  # past the interpreter's 4,300-digit str() limit
PROPERTY = settings(
    max_examples=120,
    deadline=None,
    derandomize=True,
    suppress_health_check=list(HealthCheck),
)


@contextlib.contextmanager
def kernel_work(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, int]]:
    """Count the path lookups the code under test asks of the kernel.

    ``calls`` is the number of ``stat`` and ``lstat`` calls, and ``bytes`` the
    total length of the pathnames handed to them. ``Path.resolve``,
    ``Path.is_file`` and ``Path.is_symlink`` all reach the kernel through these
    two, on every supported Python.
    """

    work = {"calls": 0, "bytes": 0}
    real_stat, real_lstat = os.stat, os.lstat

    def counted(real: Any) -> Any:
        def call(path: Any, *args: Any, **kwargs: Any) -> Any:
            work["calls"] += 1
            if not isinstance(path, int):
                work["bytes"] += len(os.fsencode(path))
            return real(path, *args, **kwargs)

        return call

    with monkeypatch.context() as patch:
        patch.setattr(os, "stat", counted(real_stat))
        patch.setattr(os, "lstat", counted(real_lstat))
        yield work


# ---------------------------------------------------------------------------
# #89: a long tokenPath is refused at a cost that does not grow with it.


def long_token_path(components: int) -> str:
    return "records/" + "a/" * components + "x.tsr"


def test_a_token_path_past_the_bound_costs_the_same_at_any_length(
    tmp_path: pathlib.Path,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#89: 12,500 and 50,000 components cost the same before the refusal.

    Before the bound, ``physical_path`` resolved the whole pathname, once for
    the duplicate-path rule and once in the token verifier. ``realpath`` looks
    up every prefix, so the pathname bytes handed to the kernel grew with the
    square of the component count: sixteen times the work for four times the
    components. Python 3.11 to 3.13 then raised ``OSError`` (ENAMETOOLONG)
    out of ``Path.is_file`` rather than refuse.

    The refusal text is the one a missing token always had.
    """

    work: dict[int, int] = {}
    for components in (12_500, 50_000):
        root = tmp_path / str(components)
        root.mkdir()
        tree = build_witness_tree(root, local_anchors[:1])
        declared = long_token_path(components)
        rewrite_witness(
            tree,
            lambda payload: payload["anchorOutcomes"][0].update(
                {"tokenPath": declared}
            ),
        )
        records = tree.records.resolve()
        expected = (
            f"witness token is missing for {tree.record}: "
            f"{records / declared.removeprefix('records/')}"
        )
        with kernel_work(monkeypatch) as counted:
            with pytest.raises(TsaError) as refused:
                verify_tree(tree)
        assert str(refused.value) == expected
        work[components] = counted["bytes"]
    # Linear growth would be at most four times; quadratic is sixteen.
    assert work[50_000] <= 2 * work[12_500], work


def test_a_long_spelling_of_a_short_path_is_still_read(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """The bound is on the path the spelling names, not on the spelling.

    ``Path`` drops ``.`` components and repeated separators, so a tokenPath
    of 10,000 ``./`` segments names the token's own short path. It verified
    before #89 and must still verify: a bound on the raw string would refuse
    a file the verifier used to read.
    """

    alpha = local_anchors[0]
    tree = build_witness_tree(tmp_path, local_anchors[:1])
    declared = token_claim(tree, alpha)["tokenPath"]
    spelled = "records/" + "./" * 10_000 + declared.removeprefix("records/")
    rewrite_witness(
        tree,
        lambda payload: payload["anchorOutcomes"][0].update({"tokenPath": spelled}),
    )
    assert verify_tree(tree).status == "available"


def test_a_token_just_under_the_bound_is_still_read(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """Review of #92, P2: pins the bound's value, not just its existence.

    A token moved into real directories so that its path joined under the
    records root is 4,095 bytes, the longest pathname Linux opens, verified
    on main and must verify here. A bound below 4,096 bytes -- macOS's 1,024,
    say -- would refuse it as missing.
    """

    tree = build_witness_tree(tmp_path, local_anchors[:1])
    records = tree.records.resolve()
    path_max = os.pathconf(records, "PC_PATH_MAX")
    if path_max < 4096:
        pytest.skip(f"PATH_MAX here is {path_max}; a 4,095-byte path cannot be opened")
    target = 4095
    remaining = target - len(os.fsencode(str(records))) - 1
    directory = "d" * 200
    depth = (remaining - 5) // (len(directory) + 1)
    name_length = remaining - depth * (len(directory) + 1)
    name = "t" * (name_length - 4) + ".tsr"
    alpha = local_anchors[0]
    token = tree.tokens[alpha.anchor_id]
    data = token.read_bytes()
    descriptor = os.open(records, os.O_RDONLY)
    try:
        for _ in range(depth):
            os.mkdir(directory, dir_fd=descriptor)
            child = os.open(directory, os.O_RDONLY, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        written = os.open(name, os.O_CREAT | os.O_WRONLY, 0o644, dir_fd=descriptor)
        try:
            os.write(written, data)
        finally:
            os.close(written)
    finally:
        os.close(descriptor)
    token.unlink()
    declared = "records/" + f"{directory}/" * depth + name
    assert len(os.fsencode(str(records / declared.removeprefix("records/")))) == target
    rewrite_witness(
        tree,
        lambda payload: payload["anchorOutcomes"][0].update({"tokenPath": declared}),
    )
    assert verify_tree(tree).status == "available"


def test_a_token_name_longer_than_name_max_is_refused_as_missing(
    tmp_path: pathlib.Path, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """A component over NAME_MAX raised OSError out of ``Path.is_file``.

    Python before 3.14 lets ENAMETOOLONG through ``is_file``; the path is
    under the whole-pathname bound, so it reaches that check. It now gets the
    refusal any other token the verifier cannot find gets.
    """

    tree = build_witness_tree(tmp_path, local_anchors[:1])
    declared = "records/" + "a" * 300 + ".tsr"
    rewrite_witness(
        tree,
        lambda payload: payload["anchorOutcomes"][0].update({"tokenPath": declared}),
    )
    records = tree.records.resolve()
    with pytest.raises(TsaError) as refused:
        verify_tree(tree)
    assert str(refused.value) == (
        f"witness token is missing for {tree.record}: "
        f"{records / declared.removeprefix('records/')}"
    )


def build_deep_tree(root: pathlib.Path, depth: int, *, link: bool) -> pathlib.Path:
    """``records/[alias/]a/a/.../x.tsr``, ``depth`` directories deep.

    With ``link`` the first component is ``alias``, a symlink to ``.`` -- the
    records root again -- which sends the walk down its symlink branch.
    """

    root.mkdir()
    records = (root / "records").resolve()
    records.mkdir()
    top = records
    if link:
        (records / "alias").symlink_to(".")
        top = records / "alias"
    descriptor = os.open(top, os.O_RDONLY)
    try:
        for _ in range(depth):
            os.mkdir("a", dir_fd=descriptor)
            child = os.open("a", os.O_RDONLY, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        os.close(os.open("x.tsr", os.O_CREAT | os.O_WRONLY, 0o644, dir_fd=descriptor))
    finally:
        os.close(descriptor)
    return records


@pytest.mark.parametrize("link", [False, True], ids=["plain", "through-a-link"])
def test_the_symlink_walk_costs_one_lookup_per_component(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, link: bool
) -> None:
    """#89: ``_refuse_a_linked_component`` grows linearly in the depth.

    It resolved every parent from scratch, and for a link every ancestor of
    it too, so the lookups grew with the square of the depth and the kernel
    work with its cube: a real 2,032-level tree under the pathname bound took
    81 s of CPU before its refusal. Each prefix is now resolved once.
    """

    lookups: dict[int, int] = {}
    for depth in (100, 400):
        records = build_deep_tree(tmp_path / f"{depth}-{link}", depth, link=link)
        spelled = ("alias/" if link else "") + "a/" * depth + "x.tsr"
        path = tsa_module.physical_path(records, spelled)
        with kernel_work(monkeypatch) as counted:
            if link:
                with pytest.raises(TsaError, match="traverses a symlink at"):
                    tsa_module._refuse_a_linked_component(
                        records, path, subject="witness token path"
                    )
            else:
                components = tsa_module._refuse_a_linked_component(
                    records, path, subject="witness token path"
                )
                assert len(components) == depth + 1
        lookups[depth] = counted["calls"]
    # Linear growth is four times; quadratic is sixteen.
    assert lookups[400] <= 5 * lookups[100], lookups


# ---------------------------------------------------------------------------
# #90: each malformed caller argument the issue lists is a named refusal.


@pytest.fixture(scope="module")
def tree(
    tmp_path_factory: pytest.TempPathFactory, local_anchors: tuple[LocalAnchor, ...]
) -> WitnessTree:
    built = build_witness_tree(tmp_path_factory.mktemp("caller-arguments"), local_anchors[:1])
    assert verify_tree(built).status == "available"
    return built


def verify_token(tree: WitnessTree, claim: Any, reference: Any) -> TokenEvidence:
    return verify_timestamp_token(
        tree.record, claim, reference, spec=tree.spec, records=tree.records
    )


@pytest.mark.parametrize(
    ("reference", "message"),
    [
        (None, "timestamp token bundle reference is not an object"),
        ([], "timestamp token bundle reference is not an object"),
        ("records/trust/tsa-anchors-v1.json", "timestamp token bundle reference is not an object"),
        ({}, "timestamp token bundle reference lacks path"),
        ({"path": BUNDLE_LOGICAL}, "timestamp token bundle reference lacks bundleId"),
        (
            {"path": BUNDLE_LOGICAL, "bundleId": "tsa-anchors-v1"},
            "timestamp token bundle reference lacks sha256",
        ),
    ],
)
def test_a_malformed_bundle_reference_is_refused(
    tree: WitnessTree,
    local_anchors: tuple[LocalAnchor, ...],
    reference: Any,
    message: str,
) -> None:
    with pytest.raises(TsaError) as refused:
        verify_token(tree, token_claim(tree, local_anchors[0]), reference)
    assert str(refused.value) == message


def test_a_bundle_reference_path_too_large_to_compare_is_refused(
    tree: WitnessTree, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    reference = {**tree.reference, "path": HUGE}
    with pytest.raises(TsaError) as refused:
        verify_token(tree, token_claim(tree, local_anchors[0]), reference)
    assert str(refused.value) == (
        "timestamp token bundle reference path is too large to compare"
    )


@pytest.mark.parametrize("claim", [None, [], "claim"])
def test_a_malformed_claim_is_refused(tree: WitnessTree, claim: Any) -> None:
    with pytest.raises(TsaError) as refused:
        verify_token(tree, claim, tree.reference)
    assert str(refused.value) == "timestamp token claim is not an object"


def test_a_claim_anchor_id_too_large_to_display_is_refused(
    tree: WitnessTree, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    alpha = local_anchors[0]
    claim = {**token_claim(tree, alpha), "tsaAnchorId": HUGE}
    with pytest.raises(TsaError) as refused:
        verify_token(tree, claim, tree.reference)
    assert str(refused.value) == (
        "witness does not select exactly one pinned TSA anchor: "
        f"id=<int too large to display>, endpoint={alpha.endpoint!r}"
    )


def test_a_claim_field_too_large_to_display_is_refused(
    tree: WitnessTree, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    alpha = local_anchors[0]
    claim = {**token_claim(tree, alpha), "tsaPolicyOid": HUGE}
    with pytest.raises(TsaError) as refused:
        verify_token(tree, claim, tree.reference)
    assert str(refused.value) == (
        f"witness tsaPolicyOid mismatch for {tree.record}: expected "
        f"{alpha.tsa.policy_oid}, got <int too large to display>"
    )


def test_the_well_formed_pair_still_verifies(
    tree: WitnessTree, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    """The control: nothing above refuses what a good pair passes."""

    evidence = verify_token(tree, token_claim(tree, local_anchors[0]), tree.reference)
    assert evidence.anchor_id == local_anchors[0].anchor_id


HUGE_VERSION_PATH = "records/trust/tsa-anchors-v" + "9" * 5000 + ".json"


def test_bundle_versions_order_numerically_at_any_length() -> None:
    """``int()`` of a 5,000-digit version raised ValueError (#90)."""

    def reference(path: str) -> dict[str, Any]:
        return {"path": path, "bundleId": path}

    two = "records/trust/tsa-anchors-v2.json"
    ten = "records/trust/tsa-anchors-v10.json"
    active = {path: reference(path) for path in (ten, HUGE_VERSION_PATH, two)}
    assert preferred_active_trust_bundle(active)["path"] == HUGE_VERSION_PATH
    assert preferred_active_trust_bundle(
        {path: reference(path) for path in (two, ten)}
    )["path"] == ten
    keys = sorted(
        (reference(path) for path in (ten, "not-a-bundle", HUGE_VERSION_PATH, two)),
        key=tsa_module._pending_bundle_version,
    )
    assert [entry["path"] for entry in keys] == [
        "not-a-bundle",
        two,
        ten,
        HUGE_VERSION_PATH,
    ]


def test_trusted_bundles_with_a_huge_version_are_refused(tree: WitnessTree) -> None:
    trusted = {
        BUNDLE_LOGICAL: tree.reference,
        HUGE_VERSION_PATH: {**tree.reference, "path": HUGE_VERSION_PATH},
    }
    with pytest.raises(TsaError):
        verify_tree(tree, trusted_bundles=trusted)


@pytest.mark.parametrize("update", [None, [], "x", {}])
def test_a_malformed_prior_pending_update_is_refused(
    tree: WitnessTree, update: Any
) -> None:
    with pytest.raises(TsaError):
        verify_step(
            tree.record,
            spec=tree.spec,
            records=tree.records,
            prior_pending_updates=[update],
        )


def test_a_trusted_bundle_without_a_path_keeps_mains_refusal(tree: WitnessTree) -> None:
    """Review of #92, P2: an active bundle's ``path`` was read with ``.get``.

    On main a second ``trusted_bundles`` entry without ``path`` reached
    ``_load_trust_bundle`` and refused there. The #90 shape check must not
    answer first with its own words.
    """

    trusted = {BUNDLE_LOGICAL: tree.reference, "records/trust/extra": {"bundleId": "x"}}
    with pytest.raises(TsaError) as refused:
        verify_tree(tree, trusted_bundles=trusted)
    assert str(refused.value) == "TSA trust bundle path is not immutable/versioned: None"


def test_a_sole_trusted_bundle_without_a_path_is_a_named_refusal(
    tree: WitnessTree,
) -> None:
    """The sole entry is the newest active bundle, whose ``path`` main read by
    subscript: ``KeyError: 'path'``. It is now a ``TsaError`` naming the key."""

    reference = {key: value for key, value in tree.reference.items() if key != "path"}
    with pytest.raises(TsaError) as refused:
        verify_tree(tree, trusted_bundles={BUNDLE_LOGICAL: reference})
    assert str(refused.value) == "newest active TSA trust bundle reference lacks path"


def test_an_active_bundle_refusal_still_answers_before_a_pending_shape_refusal(
    tree: WitnessTree,
) -> None:
    """Main loaded every active bundle before it read any pending update, so
    an active bundle that refuses keeps its text when a pending update beside
    it is malformed as well."""

    extra = {**tree.reference, "path": "records/trust/extra"}
    trusted = {BUNDLE_LOGICAL: tree.reference, "records/trust/extra": extra}
    for malformed in (None, {"bundleId": "x"}):
        with pytest.raises(TsaError) as refused:
            verify_step(
                tree.record,
                spec=tree.spec,
                records=tree.records,
                trusted_bundles=trusted,
                prior_pending_updates=[malformed],
            )
        # 7561ee01 checked the pending updates first and answered
        # "pending TSA bundle update is not a bundle reference" here.
        assert str(refused.value) == (
            "TSA trust bundle path is not immutable/versioned: 'records/trust/extra'"
        )
    with pytest.raises(TsaError) as pending:
        verify_step(
            tree.record,
            spec=tree.spec,
            records=tree.records,
            prior_pending_updates=[{"bundleId": "x"}],
        )
    assert str(pending.value) == (
        "pending TSA bundle update is not a bundle reference: {'bundleId': 'x'}"
    )


def without_path(reference: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in reference.items() if key != "path"}


def test_an_earlier_pending_update_refusal_answers_before_a_later_missing_path(
    tree: WitnessTree,
) -> None:
    """Delta review of #92: main walked the sorted pending updates one at a
    time, loading each before it read the next one's ``path``. Both of these
    sort to the same key, so input order holds, and main refused the first in
    ``_load_trust_bundle``. 042cfcb checked every update's ``path`` before
    the walk and answered with the second one's shape refusal instead."""

    with pytest.raises(TsaError) as refused:
        verify_step(
            tree.record,
            spec=tree.spec,
            records=tree.records,
            prior_pending_updates=[{**tree.reference, "path": ""}, without_path(tree.reference)],
        )
    assert str(refused.value) == "TSA trust bundle path is not immutable/versioned: ''"


def test_a_pending_update_without_a_path_is_refused_where_main_raised_key_error(
    tree: WitnessTree,
) -> None:
    """The reversed order raised ``KeyError: 'path'`` on main, at the first
    update; it is now the named refusal, at that same update."""

    update = without_path(tree.reference)
    with pytest.raises(TsaError) as refused:
        verify_step(
            tree.record,
            spec=tree.spec,
            records=tree.records,
            prior_pending_updates=[update, {**tree.reference, "path": ""}],
        )
    assert str(refused.value) == (
        f"pending TSA bundle update is not a bundle reference: {update!r}"
    )


@pytest.mark.parametrize("reverse", [False, True], ids=["empty-path-first", "pathless-first"])
def test_the_same_transition_updates_keep_mains_stale_refusal(
    tree: WitnessTree, reverse: bool
) -> None:
    """``transition_bundle_updates`` must equal the updates the record
    carries before any of them is walked, so on main and here this record,
    which carries none, refuses the first supplied entry as stale."""

    updates = [{**tree.reference, "path": ""}, without_path(tree.reference)]
    if reverse:
        updates.reverse()
    with pytest.raises(TsaError) as refused:
        verify_tree(tree, transition_bundle_updates=updates)
    first = updates[0].get("path", updates[0])
    assert str(refused.value) == (
        f"stale transition bundle update supplied for {tree.record}: {first!r}"
    )


def test_a_pending_update_with_a_huge_version_is_refused(tree: WitnessTree) -> None:
    update = {**tree.reference, "path": HUGE_VERSION_PATH}
    with pytest.raises(TsaError):
        verify_step(
            tree.record,
            spec=tree.spec,
            records=tree.records,
            prior_pending_updates=[update],
        )


# ---------------------------------------------------------------------------
# #90: the totality property over JSON-shaped caller arguments.

scalars = (
    st.none()
    | st.booleans()
    | st.integers(-(2**64), 2**64)
    | st.integers(0, 3).map(lambda offset: HUGE + offset)
    | st.text(max_size=12)
    | st.sampled_from([BUNDLE_LOGICAL, HUGE_VERSION_PATH, "tsa-anchors-v1"])
)
json_values = st.recursive(
    scalars,
    lambda children: st.lists(children, max_size=3)
    | st.dictionaries(st.text(max_size=8), children, max_size=3),
    max_leaves=6,
)
REFERENCE_KEYS = ("path", "bundleId", "sha256", "size", "canonicalJsonSha256")
CLAIM_KEYS = (
    "tsaAnchorId",
    "tsa",
    "trustBundleId",
    "trustBundlePath",
    "trustBundleSha256",
    "tokenPath",
    "tokenSha256",
    "tsaPolicyOid",
    "tsaImprintAlgorithmOid",
    "tsaSignerCertificateSha256",
    "tsaSignerSpkiSha256",
)


def mutated(base: dict[str, Any], keys: tuple[str, ...]) -> st.SearchStrategy[Any]:
    """``base`` with some fields replaced or dropped, or any JSON value."""

    edits = st.dictionaries(
        st.sampled_from(keys), st.none() | json_values | st.just("<drop>"), max_size=3
    )

    def apply(changes: dict[str, Any]) -> dict[str, Any]:
        result = dict(base)
        for key, value in changes.items():
            if value == "<drop>":
                result.pop(key, None)
            else:
                result[key] = value
        return result

    return json_values | edits.map(apply)


def refuses_or_returns(call: Any, kind: type) -> None:
    try:
        result = call()
    except TsaError:
        return
    assert isinstance(result, kind)


def test_verify_timestamp_token_is_total_over_its_arguments(
    tree: WitnessTree, local_anchors: tuple[LocalAnchor, ...]
) -> None:
    claim = token_claim(tree, local_anchors[0])

    @PROPERTY
    @given(
        mutated(claim, CLAIM_KEYS),
        mutated(dict(tree.reference), REFERENCE_KEYS),
    )
    def check(claim_arg: Any, reference_arg: Any) -> None:
        refuses_or_returns(
            lambda: verify_token(tree, claim_arg, reference_arg), TokenEvidence
        )

    check()


def test_verify_witness_is_total_over_trusted_bundles(tree: WitnessTree) -> None:
    references = mutated(dict(tree.reference), REFERENCE_KEYS)
    paths = st.sampled_from([BUNDLE_LOGICAL, HUGE_VERSION_PATH]) | st.text(max_size=12)

    @PROPERTY
    @given(st.dictionaries(paths, references, max_size=3))
    def check(trusted: Any) -> None:
        refuses_or_returns(
            lambda: verify_tree(tree, trusted_bundles=trusted), WitnessEvidence
        )

    check()


def test_verify_witness_step_is_total_over_prior_pending_updates(
    tree: WitnessTree,
) -> None:
    references = mutated(dict(tree.reference), REFERENCE_KEYS)

    @PROPERTY
    @given(st.lists(references, max_size=3))
    def check(prior: Any) -> None:
        refuses_or_returns(
            lambda: verify_step(
                tree.record,
                spec=tree.spec,
                records=tree.records,
                prior_pending_updates=prior,
            ),
            WitnessEvidence,
        )

    check()


def test_verify_witness_is_total_over_transition_bundle_updates(
    tree: WitnessTree,
) -> None:
    """The stale-update refusal formatted a caller's value with ``!r``, so a
    huge int in ``transition_bundle_updates`` raised ValueError on main and at
    7561ee01; the main-against-head differential on the review found it."""

    references = mutated(dict(tree.reference), REFERENCE_KEYS)

    @PROPERTY
    @given(st.lists(references, max_size=3))
    def check(supplied: Any) -> None:
        refuses_or_returns(
            lambda: verify_tree(tree, transition_bundle_updates=supplied),
            WitnessEvidence,
        )

    check()


def test_a_stale_transition_update_too_large_to_display_is_refused(
    tree: WitnessTree,
) -> None:
    with pytest.raises(TsaError) as refused:
        verify_tree(tree, transition_bundle_updates=[HUGE])
    assert str(refused.value) == (
        f"stale transition bundle update supplied for {tree.record}: "
        "<int too large to display>"
    )


# ---------------------------------------------------------------------------
# #90: -attime is the floor of genTime in whole seconds, at both range edges.


@pytest.mark.parametrize(
    ("gen_time", "seconds"),
    [
        # The lower edge of the representable range.
        ("00010101000000Z", -62135596800),
        ("00010101000000.5Z", -62135596800),
        # Either side of the epoch: int() truncated -0.5 s to 0.
        ("19691231235959.5Z", -1),
        ("19700101000000Z", 0),
        ("19700101000000.5Z", 0),
        # The upper edge: float rounding named the next second.
        ("99991231235958.999999Z", 253402300798),
        ("99991231235959.999999Z", 253402300799),
    ],
)
def test_attime_is_the_floor_of_gen_time(gen_time: str, seconds: int) -> None:
    parsed = tsa_module._parse_generalized_time(gen_time)
    assert tsa_module._attime(parsed) == str(seconds)


@PROPERTY
@given(
    st.datetimes(
        min_value=datetime(1, 1, 1),
        max_value=datetime(9999, 12, 31, 23, 59, 59, 999999),
    )
)
def test_attime_floors_every_representable_instant(value: datetime) -> None:
    aware = value.replace(tzinfo=UTC)
    seconds = int(tsa_module._attime(aware))
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    assert epoch + timedelta(seconds=seconds) <= aware
    assert aware < epoch + timedelta(seconds=seconds + 1)


def test_both_verifiers_pass_the_floored_attime_to_openssl(
    tree: WitnessTree,
    local_anchors: tuple[LocalAnchor, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every ``-attime`` the TSA verifier hands OpenSSL comes from ``_attime``,
    and the release-chain verifier calls the same function."""

    seen: list[str] = []
    real_run = tsa_module._run_openssl

    def recording(arguments: list[str], *rest: Any, **keywords: Any) -> Any:
        if "-attime" in arguments:
            seen.append(arguments[arguments.index("-attime") + 1])
        return real_run(arguments, *rest, **keywords)

    monkeypatch.setattr(tsa_module, "_run_openssl", recording)
    evidence = verify_token(tree, token_claim(tree, local_anchors[0]), tree.reference)
    gen_time = datetime.fromisoformat(evidence.gen_time.replace("Z", "+00:00"))
    assert seen == [tsa_module._attime(gen_time)] * 2
    source = pathlib.Path(release_chain.__file__).read_text()
    assert source.count("_tsa._attime(gen_time)") == 2
    assert "gen_time.timestamp()" not in source


# ---------------------------------------------------------------------------
# #89: the memoised symlink walk answers exactly as the released one did.


def components_below_as_released(
    root: pathlib.Path, path: pathlib.Path, *, named_root: pathlib.Path | None = None
) -> tuple[pathlib.Path, ...]:
    """``tsa._components_below`` as main had it before #89, verbatim."""

    chain: list[pathlib.Path] = []
    probe = path
    while True:
        chain.append(probe)
        parent = probe.parent
        if parent == probe:
            return ()
        if (
            parent == root
            or parent == named_root
            or (not parent.is_symlink() and parent.resolve() == root)
            or (
                parent.is_symlink()
                and parent.resolve() == root
                and not any(
                    ancestor.resolve() == root for ancestor in parent.parents
                )
            )
        ):
            chain.reverse()
            return tuple(chain)
        probe = parent


NAMES = ("a", "b", "l", "m")
LINK_TARGETS = (".", "..", "../..", "a", "b", "missing", "l", "m", "<root>", "<outer>")
entries = st.lists(
    st.tuples(
        st.integers(0, 3),  # parent: an earlier directory, or the root
        st.sampled_from(NAMES),
        st.sampled_from(["dir", "file", *(f"link:{target}" for target in LINK_TARGETS)]),
    ),
    max_size=8,
)
spellings = st.lists(st.sampled_from([*NAMES, "..", "x"]), min_size=1, max_size=6)


@PROPERTY
@given(entries, spellings, st.sampled_from(["resolved", "named-link", "none"]))
# A link to the root, reached past a missing component and a lexical "..".
# Each @example is the falsifying case Hypothesis found for one mutation of
# _PrefixResolutions._step that the committed 120 derandomized examples did
# not reach (review of #92, P3): dropping the symlink fallback, and looking
# up the spelled prefix instead of its parent's resolution.
@example(layout=[(0, "a", "link:.")], spelling=["b", "..", "a", "a"], naming="resolved")
@example(layout=[(0, "l", "link:.")], spelling=["a", "..", "l", "a"], naming="resolved")
def test_the_symlink_walk_matches_the_released_walk(
    layout: list[tuple[int, str, str]], spelling: list[str], naming: str
) -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as temporary:
        outer = pathlib.Path(temporary).resolve() / "outer"
        root = outer / "records"
        root.mkdir(parents=True)
        directories = [root]
        for parent_index, name, kind in layout:
            parent = directories[min(parent_index, len(directories) - 1)]
            target = parent / name
            if os.path.lexists(target) or not parent.is_dir() or parent.is_symlink():
                continue
            if kind == "dir":
                target.mkdir()
                directories.append(target)
            elif kind == "file":
                target.write_bytes(b"")
            else:
                link = kind.removeprefix("link:")
                link = {"<root>": str(root), "<outer>": str(outer)}.get(link, link)
                target.symlink_to(link)
        named_root: pathlib.Path | None = None
        start = root
        if naming == "named-link":
            named_root = outer / "alias"
            named_root.symlink_to("records")
            start = named_root
        elif naming == "resolved":
            named_root = root
        path = start.joinpath(*spelling)
        try:
            expected: Any = components_below_as_released(
                root, path, named_root=named_root
            )
        except (OSError, RuntimeError):
            # Only a symlink loop raises here, and every caller's whole-path
            # is_file() check refuses such a path before it walks.
            assert not os.path.isfile(path)
            return
        assert tsa_module._components_below(root, path, named_root=named_root) == expected
