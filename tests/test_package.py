"""Package-level invariants: honest status and verbatim provenance."""

import hashlib
import json
import pathlib

import pytest

import receipt
from receipt.canonical import canonical_bytes

# canonical.py is a byte-identical copy of the pinned source file; this hash
# is scripts/canonical_json.py at PolicyEngine/ledger commit 0798427850
# (receipts/ledger-pin-source-hashes.txt).
CANONICAL_SOURCE_SHA256 = (
    "562bf267b7686bce8cb71f3c13f34825c21cd4ef0aba1c0c46aff16962a6cadd"
)


def test_version() -> None:
    assert receipt.__version__ == "0.6.2"


def test_docstring_names_landed_and_pending_extraction() -> None:
    # The package must not claim capability it does not have: the docstring
    # names exactly what has landed and what is still pending.
    assert "Pending extraction" in receipt.__doc__
    assert "release-chain verifier" in receipt.__doc__


def test_canonical_module_is_byte_identical_to_pinned_source() -> None:
    module_path = pathlib.Path(receipt.__file__).parent / "canonical.py"
    digest = hashlib.sha256(module_path.read_bytes()).hexdigest()
    assert digest == CANONICAL_SOURCE_SHA256


def test_readme_states_what_the_canonical_promise_covers() -> None:
    """0.6.2 review, L5 findings 6-8: "one byte stream per value" overstated.

    A subclass whose ``__str__``/``__iter__``/``__repr__`` chooses the bytes,
    an explicit surrogate pair (two keys ``json.loads`` would merge), and
    nesting past the recursion limit each break the unqualified promise.
    ``canonical.py`` stays byte-identical to the pinned upstream serializer
    (the test above), so the README states the promise's scope instead.
    """

    readme = (
        pathlib.Path(__file__).resolve().parents[1] / "README.md"
    ).read_text(encoding="utf-8")
    line = next(
        item for item in readme.splitlines() if item.startswith("- `receipt.canonical`")
    )
    assert "one byte stream per JSON value" in line
    assert "values as `json.loads` returns them" in line
    assert "no explicit surrogate pair" in line
    assert "byte-identical copy of the pinned upstream serializer" in line
    assert "`RecursionError`" in line


@pytest.mark.parametrize(
    "source", ["1e400", "-1e400", "1" + "0" * 400],
    ids=["positive-float-overflow", "negative-float-overflow", "integer-overflow"],
)
def test_readme_qualifies_decoded_numbers_outside_canonical_range(source: str) -> None:
    """Decoding JSON does not guarantee its number can be serialized."""

    value = json.loads(source)
    assert type(value) in (int, float)
    with pytest.raises(ValueError, match="non-finite number|exceeds Number range"):
        canonical_bytes(value)
    readme = (pathlib.Path(__file__).resolve().parents[1] / "README.md").read_text(
        encoding="utf-8"
    )
    promise = next(
        line for line in readme.splitlines() if line.startswith("- `receipt.canonical`")
    )
    assert "finite floats" in promise
    assert "integers that convert to finite ECMAScript Numbers" in promise
