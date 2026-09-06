"""D1–D12 are disagreements to preserve, not decisions to unify in PR1."""
from __future__ import annotations

import dataclasses
import pathlib
import shutil

import pytest

from receipt import append_gate, release_chain, snapshot
from corpus_fixture import CONTENT, JOURNAL_RELATIVE, PREFIX_RELATIVE
from m1_fixture import signed_repo, raw_repo, outcome, assert_golden


def matrix(repo, tmp_path, label, entries=(), *, remove=(), empty=(), repertoire="portable", yml=False):
    commit = repo.commit(entries, remove=remove, empty=empty)
    # Verify actual raw topology, including empty trees, before any policy.
    with repo.snapshot(commit) as snap:
        listing = snap.entries("").as_dict(include_trees=True)
        for path, mode, *_ in entries:
            assert listing[path].mode == mode
        for path in empty:
            assert listing[path].mode == "040000"
    actual = repo.matrix(commit, tmp_path, repertoire=repertoire, yml=yml)
    manifest = next((repo.root / repo.chain.manifest_relative).glob("*.json")).stem
    assert_golden("disagreement/" + label, actual, ((manifest, "<MANIFEST>"),))
    return commit


@pytest.mark.parametrize("region", ("releases", "rules", "unused", "root", "empty_tree"))
def test_d01_sibling_scopes_and_renderers(signed_repo, tmp_path, region):
    # record: D1; census release_chain.py 2238-2333, corpus.py 1520-1548, snapshot.py 3194-3249
    if region == "empty_tree":
        matrix(signed_repo, tmp_path, "empty_sibling", (("releases/extra", "100644"),), empty=("releases/EXTRA",))
    else:
        paths = ("AA.txt", "aa.txt") if region == "root" else (region + "/Pair.txt", region + "/pair.txt")
        matrix(signed_repo, tmp_path, "fold_" + region, tuple((path, "100644") for path in paths))


@pytest.mark.parametrize("case", ("pinned_alias", "empty_pinned_alias", "state_alias", "content_root_alias"))
def test_d02_configured_aliases_and_actual_siblings(signed_repo, tmp_path, case):
    # record: D2; census release_chain.py 2272-2295, corpus.py 1565-1587, snapshot.py 3194-3249
    paths = {"pinned_alias": "Releases/other.txt", "state_alias": "receipt/Corpus-journal.jsonl",
             "content_root_alias": "Rules/unbound.txt"}
    matrix(signed_repo, tmp_path, case, () if case == "empty_pinned_alias" else ((paths[case], "100644"),),
           empty=("Releases",) if case == "empty_pinned_alias" else (),
           remove=tuple(CONTENT) if case == "content_root_alias" else ())


@pytest.mark.parametrize("region", ("releases", "rules", "unused"))
@pytest.mark.parametrize("repertoire", ("portable", "posix-bytes"))
def test_d03_repertoire_is_distinct_from_export(signed_repo, tmp_path, region, repertoire):
    # record: D3; census _names.py 236-268, verify.py 702-709, append_gate.py 1105-1117
    matrix(signed_repo, tmp_path, f"name_{region}_{repertoire}", ((region + "/bad?.txt", "100644"),), repertoire=repertoire)


def test_d03_gate_only_posix_export(signed_repo, tmp_path):
    commit = matrix(signed_repo, tmp_path, "gate_posix_export", (("releases/policy/bad?.txt", "100644"),), repertoire="posix-bytes")
    # record: D3 gate_posix_export; census append_gate.py 1105-1117 accepting early return
    assert_golden("disagreement/gate_posix_append", outcome(lambda: append_gate.verify_append_gate(
        signed_repo.root, spec=signed_repo.gate("posix-bytes", policy_surface=True), commit=commit, base_ref=signed_repo.base)))


@pytest.mark.parametrize("case", ("raw_unused", "unicode"))
def test_d04_foldability_scope_and_no_unicode_normalization(signed_repo, tmp_path, case):
    # record: D4; census release_chain.py 2276 eager alias_paths fold, corpus.py 1495-1518
    paths = ("unused/bad\udcff",) if case == "raw_unused" else ("unused/é.txt", "unused/é.txt")
    matrix(signed_repo, tmp_path, case, tuple((path, "100644") for path in paths), repertoire="posix-bytes")


@pytest.mark.parametrize("region", ("releases", "rules", "unused"))
@pytest.mark.parametrize("mode", ("120000", "160000"))
def test_d05_mode_obligations_depend_on_use(signed_repo, tmp_path, region, mode):
    # record: D5; census corpus.py 1608-1642, snapshot.py 3227-3232, 2690-2703, 1735-1759
    matrix(signed_repo, tmp_path, f"mode_{region}_{mode}", ((region + ("/link.txt" if mode == "120000" else "/module"), mode),))


@pytest.mark.parametrize("path", ("rules/tax/rate.yaml", ".axiom/toolchain.toml"))
def test_d05_selected_content_and_attested_links(signed_repo, tmp_path, path):
    # record: D5 symlink_content/symlink_attested; census corpus.py 1633-1642, 1666-1682
    matrix(signed_repo, tmp_path, "selected_link_" + path, ((path, "120000"),))


@pytest.mark.parametrize("case", ("state_symlink", "state_gitlink", "state_ancestor_symlink", "state_ancestor_blob", "content_root_blob"))
def test_d06_state_ancestors_and_root_modes(signed_repo, tmp_path, case):
    # record: D6; census verify.py 675-691; snapshot.py 2619-2687, 2931-2950; corpus.py 1595-1606
    entries = {"state_symlink": ((JOURNAL_RELATIVE, "120000"),),
        "state_gitlink": ((JOURNAL_RELATIVE, "160000"),), "state_ancestor_symlink": (("receipt", "120000"),),
        "state_ancestor_blob": (("receipt", "100644"),), "content_root_blob": (("rules", "100644"),)}[case]
    remove = ((JOURNAL_RELATIVE, PREFIX_RELATIVE) if "ancestor" in case else
              tuple(CONTENT) if case == "content_root_blob" else ())
    matrix(signed_repo, tmp_path, case, entries, remove=remove)


@pytest.mark.parametrize("region,mode", (("releases", "100644"), ("rules", "100644"), ("rules", "120000"), ("rules", "040000")))
@pytest.mark.parametrize("repertoire", ("portable", "posix-bytes"))
def test_d07_short_suffix_scope_and_wording(signed_repo, tmp_path, region, mode, repertoire):
    # record: D7; census release_chain.py 2318-2331, corpus.py 1618-1631 including trees/symlinks
    path = region + ("/hidden.sigx" if region == "releases" else "/hidden.ymlx")
    matrix(signed_repo, tmp_path, f"suffix_{region}_{mode}_{repertoire}", () if mode == "040000" else ((path, mode),),
           empty=(path,) if mode == "040000" else (), repertoire=repertoire, yml=region == "rules")


@pytest.mark.parametrize("target", ("releases/anchors/producer-ed25519.pub", "rules/tax/rate.yaml", ".axiom/toolchain.toml", "unused/file.txt"))
def test_d08_attribute_target_scope(signed_repo, tmp_path, target):
    # record: D8; census verify.py 707-709, release_chain.py 2376, append_gate.py 854-874
    matrix(signed_repo, tmp_path, "attributes_" + target,
           ((".gitattributes", "100644", (target + " filter=probe\n").encode()), ("unused/file.txt", "100644")))


@pytest.mark.parametrize("case", ("macro", "root_link", "content_link"))
def test_d08_attribute_sources_are_scoped(signed_repo, tmp_path, case):
    # record: D8 attrs_bad_content/attrs_mode_root/attrs_mode_content; census snapshot.py 950-1120, 2964-2967
    entries = {"macro": (("rules/.gitattributes", "100644", b"[attr]custom filter=probe\n"),),
               "root_link": ((".gitattributes", "120000"),),
               "content_link": (("rules/.gitattributes", "120000"),)}[case]
    matrix(signed_repo, tmp_path, "attribute_source_" + case, entries)


@pytest.mark.parametrize("fault", ("symlink", "alias", "unfoldable"))
def test_d09_caller_anchors_are_a_separate_subject(signed_repo, tmp_path, fault):
    spec = dataclasses.replace(signed_repo.chain, anchor_relative=pathlib.PurePosixPath("separate-anchors"))
    anchors = signed_repo.root / signed_repo.chain.anchor_relative
    entries = tuple(("separate-anchors/" + path.name, "100644", path.read_bytes()) for path in anchors.iterdir())
    extra = {"symlink": (("separate-anchors/unused-symlink", "120000"),),
             "alias": (("separate-anchors/EXTRA", "100644"), ("separate-anchors/extra", "100644")),
             "unfoldable": (("separate-anchors/bad\udcff", "100644"),)}[fault]
    commit = signed_repo.commit(entries + extra, remove=tuple("releases/anchors/" + path.name for path in anchors.iterdir()))
    def verify(anchor_dir):
        with signed_repo.snapshot(commit) as snap:
            value = release_chain.verify_base_release_chain(spec, base=snap, anchor_dir=anchor_dir)
            assert value.head.raw == next((signed_repo.root / signed_repo.chain.manifest_relative).glob("*.json")).read_bytes()
            return {"releases": len(value.releases), "anchor_set_sha256": value.anchor_set_sha256,
                    "anchor_file_sha256s": value.anchor_file_sha256s}
    # record: D9; census release_chain.py 2352-2376 disjoint caller-anchor exclusion
    assert_golden("disagreement/caller_anchors_" + fault, {"tree": outcome(lambda: verify(None)), "caller": outcome(lambda: verify(anchors))})


def test_d10_name_mode_precedence(signed_repo, tmp_path):
    # record: D10 name_and_mode; census release_chain.py 2238-2333 versus snapshot.py 3227-3249
    matrix(signed_repo, tmp_path, "name_and_mode", (("releases/bad?.txt", "100644"), ("releases/a-link", "120000")))


@pytest.mark.parametrize("case", ("fold", "attributes", "state"))
def test_d11_direct_directory_contract(signed_repo, tmp_path, case):
    root = tmp_path / "directory"
    shutil.copytree(signed_repo.root, root, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    if case == "fold":
        entries = (("releases/Pair.txt", "100644"), ("releases/pair.txt", "100644"))
        # Physical copy is a separate direct-reader input: on a folding host
        # these ordinary extras may occupy one inode. Neither is chain schema.
        for path, _ in entries:
            (root / path).write_bytes(b"probe\n")
    elif case == "attributes":
        entries = ((".gitattributes", "100644", b"releases/** filter=probe\n"),)
        (root / ".gitattributes").write_bytes(entries[0][2])
    else:
        entries = ((JOURNAL_RELATIVE, "120000"),)
        (root / JOURNAL_RELATIVE).unlink()
        (root / JOURNAL_RELATIVE).symlink_to("missing")
    matrix(signed_repo, tmp_path, "directory_" + case, entries)
    def call():
        value = release_chain.verify_release_chain(root, spec=signed_repo.chain, require_chain=True,
                    verify_state=True, enforce_production_pins=True)
        assert value.head.raw == next((root / signed_repo.chain.manifest_relative).glob("*.json")).read_bytes()
        return {"releases": len(value.releases), "anchor_set_sha256": value.anchor_set_sha256,
                "anchor_file_sha256s": value.anchor_file_sha256s}
    assert not (root / ".git").exists()
    # record: D11 and D6 directory_state; census release_chain.py 1936-2015, 1553-1635
    assert_golden("disagreement/direct_directory_" + case, outcome(call), ((root, "<ROOT>"),))


@pytest.mark.parametrize("ceiling", (67108864, 40))
def test_d12_repeated_admission_and_exact_stopping_step(raw_repo, monkeypatch, ceiling):
    commit = raw_repo.commit((("protected.txt", "100644"), (".gitattributes", "100644", b"protected.txt -filter\n")))
    monkeypatch.setattr(snapshot, "MAX_ATTRIBUTE_MATCH_WORK", ceiling)
    calls = []
    with raw_repo.snapshot(commit) as snap:
        for _ in range(2):
            result = outcome(lambda: snap.refuse_transforming_attributes(("protected.txt",)))
            calls.append({"result": result, **{name: getattr(snap.work, name) for name in (
                "path_bytes", "attribute_bytes", "attribute_rules", "attribute_match_work")}})
    # record: D12; census snapshot.py 2271-2282, 3003-3012, 3078-3087; refused step is NOT charged
    assert_golden("disagreement/repeat_" + str(ceiling), calls)
