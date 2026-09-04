"""Name-policy tests for the immutable tree reader.

Git tree components remain bytes until the reader must quote, fold, or write
them. These tests keep that boundary separate from the optional portable
repertoire, whose deliberately small alphabet is a checkout guarantee.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
from collections.abc import Iterable

import pytest

from receipt._names import (
    NAME_REPERTOIRES,
    WIN32_RESERVED_DEVICE_NAMES,
    NamePolicyError,
    _win32_device_basename,
    ascii_fold_bytes,
    ascii_fold_text,
    assert_no_merging_entries,
    assert_portable_name,
    decode_component,
    validate_component_bytes,
    validate_component_text,
    validate_repertoire,
)
from receipt.snapshot import SnapshotError, TreeSnapshot, _parse_raw_tree


def _git(
    root: pathlib.Path,
    *arguments: str,
    input_bytes: bytes | None = None,
) -> bytes:
    completed = subprocess.run(
        ["git", "-C", os.fspath(root), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        raise AssertionError(
            f"git {' '.join(arguments)} failed: "
            f"{completed.stderr.decode(errors='replace')}"
        )
    return completed.stdout


def _hash_object(root: pathlib.Path, object_type: str, payload: bytes) -> str:
    return _git(
        root,
        "hash-object",
        "--literally",
        "-t",
        object_type,
        "-w",
        "--stdin",
        input_bytes=payload,
    ).decode("ascii").strip()


def _commit_with_contents(
    root: pathlib.Path, contents: dict[bytes, bytes]
) -> tuple[str, dict[bytes, str]]:
    root.mkdir()
    _git(root, "init", "-q")
    blobs = {
        name: _hash_object(root, "blob", payload)
        for name, payload in contents.items()
    }
    records = sorted(
        (
            b"100644 " + name + b"\0" + bytes.fromhex(object_id)
            for name, object_id in blobs.items()
        ),
        key=lambda record: record.split(b" ", 1)[1].split(b"\0", 1)[0],
    )
    tree = _hash_object(root, "tree", b"".join(records))
    commit = _hash_object(
        root,
        "commit",
        (
            f"tree {tree}\n".encode("ascii")
            + b"author Name Test <names@example.test> 0 +0000\n"
            + b"committer Name Test <names@example.test> 0 +0000\n\n"
            + b"fixture\n"
        ),
    )
    return commit, blobs


def _commit_with_names(
    root: pathlib.Path, names: Iterable[bytes]
) -> tuple[str, dict[bytes, str]]:
    return _commit_with_contents(root, {name: name + b"\n" for name in names})


def test_repertoire_names_are_an_exact_closed_set() -> None:
    assert NAME_REPERTOIRES == frozenset({"portable", "posix-bytes"})
    assert validate_repertoire("portable") == "portable"
    assert validate_repertoire("posix-bytes") == "posix-bytes"
    for value in ("Portable", "posix", "", None, b"portable"):
        with pytest.raises(NamePolicyError, match="name repertoire must be"):
            validate_repertoire(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "name",
    (
        "a",
        "Z",
        "0",
        "_",
        "-",
        ".axiom",
        "a.b",
        "A_9-z",
        "many.periods.are.fine",
        ".leading.period",
    ),
)
def test_portable_repertoire_accepts_its_exact_alphabet(name: str) -> None:
    assert assert_portable_name(name, "fixture") == name
    assert decode_component(name.encode("ascii"), repertoire="portable") == name


def test_portable_screen_accepts_each_component_of_a_relative_path() -> None:
    path = ".axiom/releases/v1.0/A_name-2"
    assert assert_portable_name(path, "fixture path") == path


@pytest.mark.parametrize(
    "name",
    (
        "has space",
        "colon:name",
        "back\\slash",
        "tilde~name",
        "dollar$name",
        "café",
        "tab\tname",
        "line\nname",
        "good/bad name",
    ),
)
def test_portable_repertoire_refuses_every_character_outside_its_alphabet(
    name: str,
) -> None:
    with pytest.raises(NamePolicyError, match="is not a portable name"):
        assert_portable_name(name, "fixture")


@pytest.mark.parametrize(
    "name", ("", ".", "..", "name.", "...", "good/bad.")
)
def test_portable_repertoire_refuses_empty_dot_and_trailing_dot_names(
    name: str,
) -> None:
    with pytest.raises(NamePolicyError, match="is not a portable name"):
        assert_portable_name(name, "fixture")


@pytest.mark.parametrize(
    "name",
    (
        "CON",
        "con",
        "Con.txt",
        "PRN.archive.tar",
        "aux._",
        "Nul.data",
        "COM1",
        "cOm9.log",
        "LPT1",
        "LpT9.any.extension",
    ),
)
def test_portable_repertoire_refuses_win32_devices_case_insensitively(
    name: str,
) -> None:
    with pytest.raises(NamePolicyError, match="Win32 device name"):
        assert_portable_name(name, "fixture")


@pytest.mark.parametrize(
    "name", ("COM0", "LPT0", "COM10", "LPT10", "CONSOLE", "AUX_", ".CON")
)
def test_similar_non_device_names_remain_portable(name: str) -> None:
    assert assert_portable_name(name, "fixture") == name


def test_win32_device_table_and_basename_operation_are_frozen() -> None:
    expected = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{digit}" for digit in range(1, 10)),
        *(f"LPT{digit}" for digit in range(1, 10)),
        *(f"COM{digit}" for digit in "¹²³"),
        *(f"LPT{digit}" for digit in "¹²³"),
        "CONIN$",
        "CONOUT$",
    }
    assert WIN32_RESERVED_DEVICE_NAMES == frozenset(expected)
    assert _win32_device_basename("coM¹.report") == "COM¹"
    assert _win32_device_basename("conout$:stream") == "CONOUT$"
    assert _win32_device_basename("NUL   .txt") == "NUL"
    assert _win32_device_basename(" COM1.txt") == " COM1"


def test_posix_bytes_preserves_every_non_structural_byte_exactly() -> None:
    raw = b"name \\ : ~ \x80\xfe \xc3\xa9"
    decoded = decode_component(raw, repertoire="posix-bytes")
    assert decoded.encode("utf-8", errors="surrogateescape") == raw
    assert validate_component_text(decoded, repertoire="posix-bytes") == decoded


def test_raw_tree_parser_preserves_non_utf8_name_until_text_is_needed() -> None:
    raw_name = b"raw-\xff-name"
    object_id = "12" * 20
    parsed = _parse_raw_tree(
        "34" * 20,
        b"100644 " + raw_name + b"\0" + bytes.fromhex(object_id),
        object_format="sha1",
    )
    assert len(parsed) == 1
    assert parsed[0].name == raw_name
    assert parsed[0].oid == object_id


def test_invalid_utf8_refuses_only_when_portable_text_is_required() -> None:
    raw = b"invalid-\xff"
    decoded = decode_component(raw, repertoire="posix-bytes")
    assert decoded.encode("utf-8", errors="surrogateescape") == raw

    with pytest.raises(NamePolicyError, match="not valid UTF-8"):
        decode_component(raw, repertoire="portable")
    with pytest.raises(NamePolicyError, match="not valid UTF-8"):
        decode_component(raw, repertoire="posix-bytes", materializing=True)


def test_invalid_utf8_refuses_at_every_ascii_fold_boundary() -> None:
    raw = b"invalid-\xff"
    decoded = raw.decode("utf-8", errors="surrogateescape")
    with pytest.raises(NamePolicyError, match="not valid UTF-8 for folding"):
        ascii_fold_bytes(raw)
    with pytest.raises(NamePolicyError, match="not valid UTF-8 for folding"):
        ascii_fold_text(decoded)
    with pytest.raises(NamePolicyError, match="not valid UTF-8 for folding"):
        assert_no_merging_entries((raw,), repertoire="posix-bytes")


def test_snapshot_exact_byte_lookup_retains_a_lossless_object_only_spelling(
    tmp_path: pathlib.Path,
) -> None:
    root = tmp_path / "repository"
    raw_name = b"raw-\xff-name"
    commit, blobs = _commit_with_names(root, (raw_name,))

    with TreeSnapshot.select(root, commit) as snapshot:
        entry = snapshot.entry(raw_name)
        assert os.fsencode(entry.path) == raw_name
        assert entry.object_id == blobs[raw_name]
        assert snapshot.blob(entry, limit=100) == raw_name + b"\n"

        listing = snapshot.entries("")
        assert tuple(os.fsencode(name) for name in listing.children) == (raw_name,)


def test_materialization_refuses_invalid_utf8_before_creating_a_host_path(
    tmp_path: pathlib.Path,
) -> None:
    root = tmp_path / "repository"
    destination = tmp_path / "materializations"
    destination.mkdir()
    raw_name = b"written-\xff"
    commit, _blobs = _commit_with_names(root, (raw_name,))

    with TreeSnapshot.select(root, commit) as snapshot:
        pending = snapshot.materialize(
            (b"",), destination, repertoire="posix-bytes"
        )
        with pytest.raises(SnapshotError, match="not valid UTF-8 for folding"):
            with pending:
                raise AssertionError("materialization unexpectedly started")
    assert tuple(destination.iterdir()) == ()


def test_attribute_verdict_refuses_invalid_utf8_before_quoting_its_path(
    tmp_path: pathlib.Path,
) -> None:
    root = tmp_path / "repository"
    raw_name = b"protected-\xff"
    commit, _blobs = _commit_with_contents(
        root,
        {
            b".gitattributes": b"* filter=hostile\n",
            raw_name: b"content\n",
        },
    )

    with TreeSnapshot.select(root, commit) as snapshot:
        with pytest.raises(SnapshotError, match="not valid UTF-8"):
            snapshot.refuse_transforming_attributes((raw_name,))


def test_ascii_fold_changes_ascii_letters_and_no_other_code_points() -> None:
    assert ascii_fold_bytes("AZ-Äß".encode()) == "az-Äß".encode()
    assert ascii_fold_text("AZ-Äß") == "az-Äß"


def test_ascii_fold_collisions_and_exact_duplicates_are_distinct_refusals() -> None:
    with pytest.raises(NamePolicyError, match="merge under ASCII case folding"):
        assert_no_merging_entries(
            (b"ReadMe", b"README"), repertoire="posix-bytes"
        )
    with pytest.raises(NamePolicyError, match="duplicate entry name"):
        assert_no_merging_entries((b"same", b"same"), repertoire="posix-bytes")


@pytest.mark.parametrize(
    "names",
    (
        ("Ä", "ä"),
        ("é", "e\N{COMBINING ACUTE ACCENT}"),
        ("Σ", "σ"),
    ),
)
def test_ascii_fold_does_not_add_unicode_case_or_normalization(
    names: tuple[str, str],
) -> None:
    assert_no_merging_entries(names, repertoire="posix-bytes")


@pytest.mark.parametrize(
    ("component", "message"),
    (
        (b"", "is empty"),
        (b".", "is a dot component"),
        (b"..", "is a dot component"),
        (b"nul\0byte", "contains NUL"),
        (b"two/components", "contains '/'")
    ),
)
def test_raw_component_grammar_refuses_structural_names(
    component: bytes, message: str
) -> None:
    with pytest.raises(NamePolicyError, match=message):
        validate_component_bytes(component)


@pytest.mark.parametrize("name", (b"", b".", b"..", b"two/components"))
def test_raw_tree_parser_applies_component_refusals_before_indexing(name: bytes) -> None:
    payload = b"100644 " + name + b"\0" + (b"\x01" * 20)
    with pytest.raises(SnapshotError, match="invalid entry name"):
        _parse_raw_tree("02" * 20, payload, object_format="sha1")
