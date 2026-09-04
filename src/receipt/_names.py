"""Tree-entry name policy shared by commit-addressed verifiers.

Git tree names are byte strings. This module keeps that fact visible: an
object-only ``posix-bytes`` comparison can retain a non-UTF-8 component with
``surrogateescape`` until text is needed. Both repertoires require strict UTF-8
wherever a verdict quotes or folds a name.

The ``portable`` repertoire is deliberately narrower.  A component contains
only ASCII letters, digits, ``.``, ``_`` and ``-``; it does not end in a
period; and its basename is not a Win32 device name.  Materialization applies
this portable screen regardless of the declared repertoire.  That extra
screen is a property of writing into an unknown host filesystem, not a wider
claim about ``posix-bytes`` trees.

Every repertoire rejects an empty component, ``.`` and ``..``, and a component
containing NUL or ``/``.  Sibling collision checks fold ASCII letters and
nothing else.  In particular, this module does not normalize Unicode or use
Python's Unicode ``casefold``: the frozen contract names only ASCII folding.

Where the contract is silent, the implementation fails closed.  Unsupported
repertoire names, values other than exact ``bytes`` or ``str`` instances, and
text that cannot round-trip through UTF-8 plus ``surrogateescape`` are refused
instead of being coerced.
"""

from __future__ import annotations

import re
from collections.abc import Iterable


PORTABLE_REPERTOIRE = "portable"
POSIX_BYTES_REPERTOIRE = "posix-bytes"
NAME_REPERTOIRES = frozenset({PORTABLE_REPERTOIRE, POSIX_BYTES_REPERTOIRE})

# A portable component may begin with a period because consumers conventionally
# keep state below ``.axiom``.  Empty, ``.`` and ``..`` are rejected separately.
PORTABLE_NAME_RE = re.compile(r"[A-Za-z0-9._-]+\Z")

# Win32 reserves these basenames in every directory, including when an
# extension follows.  COM0 and LPT0 are ordinary names; Microsoft's table and
# the native matcher both reserve only 1 through 9.  The superscript spellings
# are included for completeness even though the ASCII portable repertoire
# already refuses them.  CONIN$ and CONOUT$ come from the native matcher and
# are likewise outside the portable character set.
WIN32_RESERVED_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{digit}" for digit in range(1, 10)}
    | {f"LPT{digit}" for digit in range(1, 10)}
    | {f"COM{superscript}" for superscript in "\u00b9\u00b2\u00b3"}
    | {f"LPT{superscript}" for superscript in "\u00b9\u00b2\u00b3"}
    | {"CONIN$", "CONOUT$"}
)

_ASCII_LOWER = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz"
)


class NamePolicyError(ValueError):
    """A tree name cannot be interpreted under the selected name policy."""


def validate_repertoire(repertoire: str) -> str:
    """Return a supported repertoire name, refusing coercion or unknown names."""

    if type(repertoire) is not str or repertoire not in NAME_REPERTOIRES:
        raise NamePolicyError(
            "name repertoire must be 'portable' or 'posix-bytes': "
            f"{repertoire!r}"
        )
    return repertoire


def _ascii_upper(text: str) -> str:
    """Uppercase ASCII letters without applying a Unicode case mapping."""

    return "".join(
        chr(ord(character) - 32) if "a" <= character <= "z" else character
        for character in text
    )


def _win32_device_basename(component: str) -> str:
    """Return the portion Win32 compares with its reserved-device table.

    The native rule truncates at the first period or colon and then removes
    trailing spaces from what remains.  Portable names cannot contain a colon
    or a space, but keeping the complete operation here makes the table check
    correct when tested independently and prevents a future caller from
    accidentally broadening it with Unicode uppercasing.
    """

    head = component
    for index, character in enumerate(component):
        if character in ".:":
            head = component[:index]
            break
    return _ascii_upper(head.rstrip(" "))


def _portable_failure(value: object, label: str, repertoire: str | None) -> None:
    context = "" if repertoire is None else f" under name repertoire {repertoire!r}"
    raise NamePolicyError(
        f"{label} is not a portable name (ASCII letters, digits, '.', '_' and "
        "'-', not ending in '.', not a Win32 device name)"
        f"{context}: {value!r}"
    )


def assert_portable_name(value: str, label: str) -> str:
    """Screen every component of a relative POSIX path as portable.

    This path-level helper retains the existing portable-name operation for
    later consumers.  Tree parsing and materialization should use
    :func:`validate_component_text` or :func:`decode_component`, which also
    enforce the raw component grammar.
    """

    if type(value) is not str:
        _portable_failure(value, label, None)
    for component in value.split("/"):
        if (
            PORTABLE_NAME_RE.fullmatch(component) is None
            or component.endswith(".")
            or _win32_device_basename(component) in WIN32_RESERVED_DEVICE_NAMES
        ):
            _portable_failure(value, label, None)
    return value


# The frozen plan and the existing corpus implementation use this spelling.
_assert_portable_name = assert_portable_name


def _text_as_tree_bytes(value: str, label: str) -> bytes:
    """Encode decoded tree text without losing surrogateescaped bytes."""

    try:
        return value.encode("utf-8", errors="surrogateescape")
    except UnicodeEncodeError as exc:
        raise NamePolicyError(
            f"{label} cannot be represented as Git tree-name bytes: {value!r}"
        ) from exc


def validate_component_bytes(value: bytes, *, label: str = "tree entry name") -> bytes:
    """Validate the repository-independent grammar of one raw tree component."""

    if type(value) is not bytes:
        raise NamePolicyError(f"{label} must be bytes: {value!r}")
    if not value:
        raise NamePolicyError(f"{label} is empty")
    if value in {b".", b".."}:
        raise NamePolicyError(f"{label} is a dot component: {value!r}")
    if b"\x00" in value:
        raise NamePolicyError(f"{label} contains NUL: {value!r}")
    if b"/" in value:
        raise NamePolicyError(f"{label} contains '/': {value!r}")
    return value


def decode_component(
    value: bytes,
    *,
    repertoire: str,
    materializing: bool = False,
    label: str = "tree entry name",
) -> str:
    """Validate and decode one raw Git tree component.

    Object-only ``posix-bytes`` reads use ``surrogateescape`` so every byte can
    be retained and compared exactly.  Portable use, including every host
    materialization, requires strict UTF-8 before the portable ASCII screen.
    """

    selected = validate_repertoire(repertoire)
    raw = validate_component_bytes(value, label=label)
    portable_required = materializing or selected == PORTABLE_REPERTOIRE
    if portable_required:
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise NamePolicyError(
                f"{label} is not valid UTF-8 under name repertoire "
                f"{selected!r}: {raw!r}"
            ) from exc
        if (
            PORTABLE_NAME_RE.fullmatch(text) is None
            or text.endswith(".")
            or _win32_device_basename(text) in WIN32_RESERVED_DEVICE_NAMES
        ):
            _portable_failure(text, label, selected)
        return text
    return raw.decode("utf-8", errors="surrogateescape")


def validate_component_text(
    value: str,
    *,
    repertoire: str,
    materializing: bool = False,
    label: str = "tree entry name",
) -> str:
    """Validate text obtained from a tree component and preserve its bytes."""

    if type(value) is not str:
        raise NamePolicyError(f"{label} must be text: {value!r}")
    raw = _text_as_tree_bytes(value, label)
    decoded = decode_component(
        raw,
        repertoire=repertoire,
        materializing=materializing,
        label=label,
    )
    if decoded != value:
        # A non-canonical text representation must not be silently replaced by
        # the round-tripped spelling that would become a host path.
        raise NamePolicyError(
            f"{label} does not round-trip through Git tree-name bytes: {value!r}"
        )
    return value


def ascii_fold_bytes(value: bytes) -> bytes:
    """Fold ASCII case in a canonical raw component and preserve every other byte."""

    raw = validate_component_bytes(value)
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise NamePolicyError("tree entry name is not valid UTF-8 for folding") from exc
    return raw.translate(_ASCII_LOWER)


def ascii_fold_text(value: str) -> str:
    """Fold ASCII case in decoded tree text without Unicode normalization."""

    if type(value) is not str:
        raise NamePolicyError(f"tree entry name must be text: {value!r}")
    raw = _text_as_tree_bytes(value, "tree entry name")
    validate_component_bytes(raw)
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise NamePolicyError("tree entry name is not valid UTF-8 for folding") from exc
    return raw.translate(_ASCII_LOWER).decode("utf-8", errors="surrogateescape")


def assert_no_merging_entries(
    names: Iterable[bytes | str],
    *,
    repertoire: str,
    materializing: bool = False,
    label: str = "tree directory",
) -> None:
    """Refuse siblings whose raw names agree after ASCII case folding.

    ``names`` is one directory's immediate children, not full paths.  Each
    component is validated before it enters the fold index.  Passing
    ``materializing=True`` applies the portable screen to every component
    before the caller may create any host path.
    """

    selected = validate_repertoire(repertoire)
    seen: dict[bytes, tuple[bytes, str]] = {}
    for value in names:
        if type(value) is bytes:
            raw = validate_component_bytes(value, label="tree entry name")
            text = decode_component(
                raw,
                repertoire=selected,
                materializing=materializing,
                label="tree entry name",
            )
            try:
                raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise NamePolicyError(
                    "tree entry name is not valid UTF-8 for folding"
                ) from exc
        elif type(value) is str:
            text = validate_component_text(
                value,
                repertoire=selected,
                materializing=materializing,
                label="tree entry name",
            )
            raw = _text_as_tree_bytes(text, "tree entry name")
            try:
                raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise NamePolicyError(
                    "tree entry name is not valid UTF-8 for folding"
                ) from exc
        else:
            raise NamePolicyError(
                f"tree entry name must be bytes or text: {value!r}"
            )

        folded = raw.translate(_ASCII_LOWER)
        previous = seen.get(folded)
        if previous is not None:
            previous_raw, previous_text = previous
            if previous_raw == raw:
                raise NamePolicyError(
                    f"{label} contains a duplicate entry name: {text!r}"
                )
            raise NamePolicyError(
                f"{label} contains names that merge under ASCII case folding: "
                f"{previous_text!r} and {text!r}"
            )
        seen[folded] = (raw, text)


# The plan uses this internal spelling when it describes the materialization
# screen.  Keep it as an alias rather than making callers copy the operation.
_assert_no_merging_entries = assert_no_merging_entries


__all__ = [
    "NAME_REPERTOIRES",
    "PORTABLE_NAME_RE",
    "PORTABLE_REPERTOIRE",
    "POSIX_BYTES_REPERTOIRE",
    "WIN32_RESERVED_DEVICE_NAMES",
    "NamePolicyError",
    "ascii_fold_bytes",
    "ascii_fold_text",
    "assert_no_merging_entries",
    "assert_portable_name",
    "decode_component",
    "validate_component_bytes",
    "validate_component_text",
    "validate_repertoire",
]
