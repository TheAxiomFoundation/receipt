"""Verification snapshots detach values from callbacks on caller-owned inputs.

Frame and garbage-collector reflection deliberately falls outside that promise;
the final documentation test retains the review's reflection probe as an example.
"""

from __future__ import annotations

import gc
import sys
from collections.abc import Iterator, Mapping

import pytest
from hypothesis import example, given, settings, strategies as st

from receipt.sign import (
    KeySpec,
    KeyringSpec,
    SignError,
    generate_signing_keypair,
    sign_payload,
    spki_sha256,
    verify_any_generation,
    verify_threshold,
)


class _LyingPin(str):
    __hash__ = str.__hash__

    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False


class _MutableID(str):
    def __new__(cls, value: str):
        instance = super().__new__(cls, value)
        instance.current = value
        return instance

    def __hash__(self) -> int:
        return hash(self.current)

    def __eq__(self, other: object) -> bool:
        return self.current == other

    def __ne__(self, other: object) -> bool:
        return self.current != other

    def __lt__(self, other: object) -> bool:
        return self.current < other


def _swap_on_read(key: KeySpec, field: str, replacement: str, swap_after: int) -> None:
    """An attribute-name equality callback swaps only caller-owned fields."""

    namespace = vars(key)
    seen = 0
    armed = False

    class Name(str):
        __hash__ = str.__hash__

        def __eq__(self, other: object) -> bool:
            nonlocal seen
            if armed and type(other) is str and str.__eq__(other, field):
                seen += 1
                if seen >= swap_after:
                    namespace[self] = replacement
            return str.__eq__(self, other)

    value = namespace.pop(field)
    namespace[Name(field)] = value
    armed = True


@pytest.mark.parametrize("verifier", ["threshold", "any_generation"])
@pytest.mark.parametrize("swap_after", range(1, 12))
def test_fingerprint_swapped_during_the_snapshot_read_is_refused(
    verifier: str, swap_after: int,
) -> None:
    victim, attacker = generate_signing_keypair(), generate_signing_keypair()
    payload, domain = b"r9 toctou", b"receipt/r9\0"
    signature = sign_payload(attacker[0], payload, domain=domain)
    key = KeySpec("a", spki_sha256(victim[1]), "spki-sha256")
    ring = KeyringSpec((key,), 1)
    _swap_on_read(key, "fingerprint", _LyingPin(spki_sha256(victim[1])), swap_after)
    with pytest.raises(SignError):
        if verifier == "threshold":
            verify_threshold(payload, {"a": signature}, {"a": attacker[1]}, ring,
                             domain=domain, label="toctou", allow_legacy=False)
        else:
            verify_any_generation(payload, signature, {"a": attacker[1]}, ring,
                                  domain=domain, label="toctou", allow_legacy=False)


@pytest.mark.parametrize("swap_after", range(1, 12))
def test_key_id_swapped_during_the_snapshot_read_cannot_count_twice(swap_after: int) -> None:
    first, second = generate_signing_keypair(), generate_signing_keypair()
    payload, domain = b"r9 toctou count", b"receipt/r9\0"
    signature = sign_payload(first[0], payload, domain=domain)
    a = KeySpec("a", spki_sha256(first[1]), "spki-sha256")
    b = KeySpec("b", spki_sha256(second[1]), "spki-sha256")
    ring = KeyringSpec((a, b), 2)
    identity = _MutableID("b")
    _swap_on_read(b, "key_id", identity, swap_after)

    class CallbackKeys(dict[str, bytes]):
        def __getitem__(self, key: str) -> bytes:
            # Value reads follow the ring snapshot even with one id traversal.
            identity.current = "a"
            return super().__getitem__(key)

    with pytest.raises(SignError):
        verify_threshold(payload, {"a": signature}, CallbackKeys(a=first[1]), ring,
                         domain=domain, label="toctou", allow_legacy=False)


@pytest.mark.parametrize("verifier", ["threshold", "any_generation"])
@settings(max_examples=15, deadline=None)
@given(key_id=st.text(max_size=12))
def test_keyring_field_snapshot_reads_each_caller_field_once(verifier: str, key_id: str) -> None:
    """Validation and the verdict use each field's one captured value."""

    pair = generate_signing_keypair()
    payload, domain = b"r9 key field snapshot", b"receipt/r9\0"
    signature = sign_payload(pair[0], payload, domain=domain)
    key = KeySpec(key_id, spki_sha256(pair[1]), "spki-sha256")
    ring = KeyringSpec((key,), 1)
    namespace = vars(key)
    reads = {field: 0 for field in ("key_id", "fingerprint", "scheme")}
    armed = False

    class Name(str):
        __hash__ = str.__hash__

        def __eq__(self, other: object) -> bool:
            if armed and type(other) is str and str.__eq__(self, other):
                reads[other] += 1
                assert reads[other] == 1, "caller field reread after its snapshot"
            return str.__eq__(self, other)

    for field in reads:
        value = namespace.pop(field)
        namespace[Name(field)] = value
    armed = True
    if verifier == "threshold":
        result = verify_threshold(payload, {key_id: signature}, {key_id: pair[1]}, ring,
                                  domain=domain, label="fields-once", allow_legacy=False)
        assert result.satisfied == (key_id,)
    else:
        assert verify_any_generation(payload, signature, {key_id: pair[1]}, ring,
                                     domain=domain, label="fields-once", allow_legacy=False) == key_id
    assert reads == {field: 1 for field in reads}


def test_presented_legacy_key_cannot_fill_a_current_slot() -> None:
    """The review's fourth-iteration routing key must never supply current 'a'."""

    current, old = generate_signing_keypair(), generate_signing_keypair()
    payload, domain = b"r9 presented routing", b"receipt/r9\0"
    ring = KeyringSpec((KeySpec("a", spki_sha256(current[1]), "spki-sha256"),), 1,
                       legacy_keys=(KeySpec("old", spki_sha256(old[1]), "spki-sha256"),))
    identity = _MutableID("a")

    class PublicKeys(dict):
        iterations = 0

        def __iter__(self):
            self.iterations += 1
            if self.iterations < 4:
                return iter(["a"])
            identity.current = "old"
            return iter([identity])

        def __getitem__(self, key):
            identity.current = "a"
            return old[1]

        def __contains__(self, key):
            return key == "a"

        def __len__(self):
            return 1

    with pytest.raises(SignError):
        verify_threshold(payload, {"a": sign_payload(old[0], payload, domain=domain)},
                         PublicKeys(), ring, domain=domain, label="routing", allow_legacy=False)


@pytest.mark.parametrize("verifier", ["threshold", "any_generation"])
@settings(max_examples=15, deadline=None)
@example(key_id="")
@example(key_id="ключé")
@given(key_id=st.text(max_size=12))
def test_presented_mappings_are_read_once(verifier: str, key_id: str) -> None:
    """Each id and value belongs to one traversal, including arbitrary exact ids."""

    pair = generate_signing_keypair()
    payload, domain = b"r9 mapping snapshot", b"receipt/r9\0"
    signature = sign_payload(pair[0], payload, domain=domain)
    ring = KeyringSpec((KeySpec(key_id, spki_sha256(pair[1]), "spki-sha256"),), 1)

    class ReadOnce(Mapping[str, bytes]):
        def __init__(self, value: bytes):
            self.value = value
            self.iterations = 0
            self.lookups = 0

        def __iter__(self) -> Iterator[str]:
            self.iterations += 1
            assert self.iterations == 1, "caller mapping iterated after its snapshot"
            return iter([key_id])

        def __getitem__(self, key: str) -> bytes:
            assert key == key_id
            self.lookups += 1
            assert self.lookups == 1, "caller value read after its snapshot"
            return self.value

        def __len__(self) -> int:
            return 1

    signatures, public_keys = ReadOnce(signature), ReadOnce(pair[1])
    if verifier == "threshold":
        result = verify_threshold(payload, signatures, public_keys, ring,
                                  domain=domain, label="once", allow_legacy=False)
        assert result.satisfied == (key_id,)
        assert (signatures.iterations, signatures.lookups) == (1, 1)
    else:
        assert verify_any_generation(payload, signature, public_keys, ring,
                                     domain=domain, label="once", allow_legacy=False) == key_id
    assert (public_keys.iterations, public_keys.lookups) == (1, 1)


@pytest.mark.parametrize(("verifier", "what"), [
    ("threshold", "key_id"), ("threshold", "public_key"), ("threshold", "signature"),
    ("any_generation", "key_id"), ("any_generation", "public_key"),
])
@settings(max_examples=8, deadline=None)
@given(kind=st.sampled_from(["subclass", "bytearray", "mapping", "none", "int"]))
def test_nonexact_presented_values_cannot_satisfy_the_snapshot(
    verifier: str, what: str, kind: str,
) -> None:
    pair = generate_signing_keypair()
    payload, domain = b"r9 mapping types", b"receipt/r9\0"
    signature = sign_payload(pair[0], payload, domain=domain)
    ring = KeyringSpec((KeySpec("a", spki_sha256(pair[1]), "spki-sha256"),), 1)

    class BytesSubclass(bytes):
        pass

    class StringSubclass(str):
        pass

    original = "a" if what == "key_id" else pair[1] if what == "public_key" else signature
    if kind == "subclass":
        invalid = StringSubclass(original) if what == "key_id" else BytesSubclass(original)
    elif kind == "bytearray":
        invalid = bytearray(original.encode() if what == "key_id" else original)
    elif kind == "mapping":
        invalid = {"value": original}
    elif kind == "none":
        invalid = None
    else:
        invalid = 7

    class Presented(Mapping):
        def __iter__(self):
            return iter([invalid if what == "key_id" else "a"])

        def __getitem__(self, key):
            return invalid if what == "public_key" else pair[1]

        def __len__(self):
            return 1

    public_keys = Presented()
    signatures = {"a": invalid if what == "signature" else signature}
    with pytest.raises(SignError):
        if verifier == "threshold":
            verify_threshold(payload, signatures, public_keys, ring,
                             domain=domain, label="types", allow_legacy=False)
        else:
            verify_any_generation(payload, signature, public_keys, ring,
                                  domain=domain, label="types", allow_legacy=False)


@pytest.mark.parametrize("verifier", ["threshold", "any_generation"])
@pytest.mark.parametrize("field", ["key_id", "fingerprint", "scheme"])
@settings(max_examples=8, deadline=None)
@given(suffix=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", max_size=8))
def test_refused_type_name_cannot_format_through_caller_code(
    verifier: str, field: str, suffix: str,
) -> None:
    calls: list[str] = []

    class Name(str):
        def __format__(self, spec: str) -> str:
            calls.append("format")
            return "renamed-by-callback"

    class Field(str):
        pass

    expected_name = "Field" + suffix
    Field.__name__ = Name(expected_name)
    key = KeySpec("a", "a" * 64, "spki-sha256")
    ring = KeyringSpec((key,), 1)
    object.__setattr__(key, field, Field(getattr(key, field)))
    with pytest.raises(SignError) as caught:
        if verifier == "threshold":
            verify_threshold(b"p", {}, {}, ring, domain=b"d", label="name", allow_legacy=False)
        else:
            verify_any_generation(b"p", b"s" * 64, {}, ring,
                                  domain=b"d", label="name", allow_legacy=False)
    assert str(caught.value) == f"keyring {field} must be a str; found={expected_name}"
    assert calls == []


@pytest.mark.parametrize("how", ["gc", "frame"])
def test_reflection_probe_is_documented_outside_the_guarantee(how: str) -> None:
    """Retain reflection_probe.py as a scope example, not a security assertion.

    An inspecting callback may accept or refuse after private implementation
    changes. Either outcome lies outside the guarantee; both public docstrings
    must explicitly say so. No ordinary caller-input callback uses reflection.
    """

    first, second = generate_signing_keypair(), generate_signing_keypair()
    ring = KeyringSpec((KeySpec("a", spki_sha256(first[1]), "spki-sha256"),
                        KeySpec("b", spki_sha256(second[1]), "spki-sha256")), 2)

    # Control: the exact same material cannot meet two signatures with none.
    with pytest.raises(SignError):
        verify_threshold(b"reflect", {}, {"a": first[1], "b": second[1]}, ring,
                         domain=b"receipt/r9\0", label="reflect", allow_legacy=False)

    class ReflectingPublicKeys(dict):
        def __getitem__(self, key):
            if how == "gc":
                snapshots = [o for o in gc.get_objects() if type(o) is KeyringSpec and o is not ring]
            else:
                snapshots = []
                frame = sys._getframe(1)
                while frame is not None:
                    if frame.f_code.co_name == "verify_threshold":
                        candidate = frame.f_locals.get("keyring")
                        if type(candidate) is KeyringSpec and candidate is not ring:
                            snapshots.append(candidate)
                    frame = frame.f_back
            for snapshot in snapshots:
                object.__setattr__(snapshot, "threshold", 0)
            return super().__getitem__(key)

    try:
        verify_threshold(b"reflect", {}, ReflectingPublicKeys(a=first[1], b=second[1]), ring,
                         domain=b"receipt/r9\0", label="reflect", allow_legacy=False)
    except SignError:
        pass
    for verifier in (verify_threshold, verify_any_generation):
        doc = verifier.__doc__ or ""
        assert "frames" in doc and "garbage collector" in doc
        assert "outside" in doc
