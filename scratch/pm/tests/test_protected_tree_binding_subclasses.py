"""Accepted binding readers retain legacy decisions without policy authority."""
from collections import Counter
from dataclasses import asdict, replace

import pytest

from receipt import corpus, protected_tree, snapshot
from corpus_fixture import CONTENT, journal_rows, render_journal
from m1_fixture import outcome, signed_repo
from protected_tree_consumer_fixture import consumer_leg, work_observation
from test_protected_tree_consumers_work import SCOPES


class AuditReader(snapshot.TreeSnapshot):
    pass


@pytest.fixture
def authority_calls(monkeypatch):
    """Count construction without replacing the classes or their type guards."""
    calls = Counter()
    subjects = []
    for cls in (protected_tree.TreePolicy, protected_tree.ProtectedTreeView,
                protected_tree.ProtectedSelection):
        original = cls.__init__

        def init(self, *args, _original=original, _name=cls.__name__, **kwargs):
            calls[_name] += 1
            if _name == 'TreePolicy':
                subjects.append(args[0] if args else kwargs['snapshot'])
            _original(self, *args, **kwargs)

        monkeypatch.setattr(cls, '__init__', init)
    return calls, subjects


def compare_binding(repo, monkeypatch, authority_calls, reader, commit, *,
                    spec=None, journal=None, reaches_policy=None):
    results = []
    calls, policy_subjects = authority_calls
    for old in (True, False):
        calls.clear()
        policy_subjects.clear()
        with consumer_leg(monkeypatch, corpus, old=old) as (counts, events, subjects):
            with reader.select(repo.root, commit) as selected:
                result = outcome(lambda: asdict(corpus.verify_corpus_binding(
                    selected, repo.journal if journal is None else journal,
                    spec=repo.corpus if spec is None else spec)))
                assert counts['verify_corpus_binding'] == 1
                results.append((result, asdict(selected.work),
                                work_observation(events, subjects)))
                if old or reader is AuditReader:
                    assert not calls
                else:
                    assert all(subject is selected for subject in policy_subjects)
                    assert calls['TreePolicy'] <= 1
                    if reaches_policy is not None:
                        assert calls['TreePolicy'] == int(reaches_policy)
                    if 'value' in result:
                        assert calls['TreePolicy'] == 1
                        assert calls['ProtectedTreeView'] > 0
                        assert calls['ProtectedSelection'] > 0
    # Includes exact exception class/text, the full result, all public work
    # fields, and ordered attempted reads (including failed admission).
    assert results[0] == results[1]
    return results[1]


@pytest.mark.parametrize('reader', (AuditReader, snapshot.TreeSnapshot))
@pytest.mark.parametrize('case,entries,remove,empty,repertoire', SCOPES,
                         ids=[case[0] for case in SCOPES])
def test_subclass_d1_to_d11_binding(signed_repo, monkeypatch, authority_calls,
                                   reader, case, entries, remove, empty, repertoire):
    # Reuse the frozen D1–D11 inputs, including accepting scope differences.
    commit = signed_repo.commit(entries, remove=remove, empty=empty)
    spec = replace(signed_repo.corpus, name_repertoire=repertoire,
                   content_suffixes=('.yaml', '.yml') if case.startswith('D7-rules')
                   else signed_repo.corpus.content_suffixes)
    result, work, _ = compare_binding(
        signed_repo, monkeypatch, authority_calls, reader, commit,
        spec=spec, reaches_policy=True)
    if case == 'clean':
        assert 'value' in result
        assert work['content_bytes'] == 104
        assert work['path_bytes'] == 576


BARRIERS = (
    'malformed', 'declared-whole', 'declared-prefix', 'names-before-siblings',
    'root-alias-before-missing', 'root-missing', 'gitlink-before-symlink',
    'closed-extra', 'closed-absent', 'tombstone', 'tombstone-alias',
    'required-attested', 'attested-missing', 'attested-ancestor',
    'content-digest', 'attested-digest',
)


@pytest.mark.parametrize('reader', (AuditReader, snapshot.TreeSnapshot))
@pytest.mark.parametrize('fault', BARRIERS)
def test_subclass_binding_barrier_order(signed_repo, monkeypatch, authority_calls,
                                       reader, fault):
    extras = {
        'names-before-siblings': (('unused/A', '100644'), ('unused/a', '100644'),
                                  ('zz/bad?.txt', '100644')),
        'root-alias-before-missing': (('Rules/extra', '100644'),),
        'gitlink-before-symlink': (('rules/AAA-module', '160000'),
                                  ('rules/tax/rate.yaml', '120000')),
        'closed-extra': (('rules/extra.yaml', '100644'),),
        'tombstone': (('retired/item.json', '100644'),),
        'tombstone-alias': (('retired/ITEM.JSON', '100644'),),
        'attested-ancestor': (('.axiom', '120000'),),
        'content-digest': (('rules/tax/rate.yaml', '100644', b'changed\n'),),
        'attested-digest': (('.axiom/toolchain.toml', '100644', b'changed\n'),),
    }.get(fault, ())
    remove = (tuple(CONTENT) if fault in {'root-missing', 'root-alias-before-missing'}
              else ('rules/tax/rate.yaml',) if fault == 'closed-absent'
              else ('.axiom/toolchain.toml',) if fault in {'attested-missing', 'attested-ancestor'}
              else ())
    rows = journal_rows()
    if fault in {'declared-whole', 'declared-prefix'}:
        paths = (('rules/CASE/item.yaml', 'rules/case/item.yaml') if fault == 'declared-whole'
                 else ('rules/CASE/x.yaml', 'rules/case/y.yaml'))
        for path in paths:
            rows.append(dict(rows[0], path=path, entryIndex=len(rows)))
    if fault.startswith('tombstone'):
        for state in ('present', 'removed'):
            rows.append(dict(rows[3], path='retired/item.json', state=state, entryIndex=len(rows)))
    if fault == 'required-attested':
        rows = [dict(row, entryIndex=index) for index, row in enumerate(
            row for row in rows if row['kind'] != 'attested')]
    journal = b'not-json\n' if fault == 'malformed' else render_journal(rows)
    commit = signed_repo.commit(extras, remove=remove)
    result, _, _ = compare_binding(
        signed_repo, monkeypatch, authority_calls, reader, commit, journal=journal,
        reaches_policy=fault not in {'malformed', 'declared-whole', 'declared-prefix'})
    assert result['exception'] == 'receipt.corpus.CorpusError'


@pytest.mark.parametrize('reader', (AuditReader, snapshot.TreeSnapshot))
@pytest.mark.parametrize('fault', ('empty', '100644', '100755', '120000', '160000',
                                  '040000', 'missing', 'ancestor'))
def test_subclass_attested_facade(signed_repo, monkeypatch, authority_calls, reader, fault):
    path = '.axiom/toolchain.toml'
    entries = (('.axiom', '120000'),) if fault == 'ancestor' else (
        (path, fault),) if fault in {'100644', '100755', '120000', '160000'} else ()
    commit = signed_repo.commit(entries,
        remove=(path,) if fault in {'040000', 'missing', 'ancestor'} else (),
        empty=(path,) if fault == '040000' else ())
    results = []
    calls, policy_subjects = authority_calls
    for old in (True, False):
        calls.clear()
        policy_subjects.clear()
        with consumer_leg(monkeypatch, corpus, old=old) as (counts, events, subjects):
            with reader.select(signed_repo.root, commit) as selected:
                def call():
                    entries = corpus._attested_entries_from_snapshot(
                        selected, {} if fault == 'empty' else {path: None})
                    return {name: (entry.path, entry.mode, entry.object_type, entry.object_id)
                            for name, entry in entries.items()}
                result = outcome(call)
                assert counts['_attested_entries_from_snapshot'] == 1
                results.append((result, asdict(selected.work), work_observation(events, subjects)))
                if old or reader is AuditReader or fault in {'empty', 'missing', 'ancestor'}:
                    assert not calls
                else:
                    assert policy_subjects == [selected]
                    assert calls['TreePolicy'] == calls['ProtectedTreeView'] == 1
                    assert calls['ProtectedSelection'] == int(fault in {'100644', '100755'})
    assert results[0] == results[1]
    assert ('value' in results[1][0]) == (fault in {'empty', '100644', '100755'})


@pytest.mark.parametrize('lifecycle', ('unentered', 'closed'))
@pytest.mark.parametrize('facade', (False, True))
def test_subclass_lifecycle_keeps_reader_refusals(signed_repo, monkeypatch, authority_calls,
                                                lifecycle, facade):
    results = []
    for old in (True, False):
        with consumer_leg(monkeypatch, corpus, old=old) as (_, events, subjects):
            selected = AuditReader.select(signed_repo.root, signed_repo.base)
            if lifecycle == 'closed':
                with selected:
                    pass
            result = outcome(lambda: corpus._attested_entries_from_snapshot(
                selected, {'.axiom/toolchain.toml': None}) if facade else
                corpus.verify_corpus_binding(selected, signed_repo.journal, spec=signed_repo.corpus))
            results.append((result, asdict(selected.work), work_observation(events, subjects)))
    assert results[0] == results[1]
    assert results[1][0]['exception'] == 'receipt.corpus.CorpusError'
    assert not authority_calls[0]


def test_binding_acceptance_does_not_authorize_a_subclass_policy(signed_repo):
    with AuditReader.select(signed_repo.root, signed_repo.base) as selected:
        corpus.verify_corpus_binding(selected, signed_repo.journal, spec=signed_repo.corpus)
        with pytest.raises(protected_tree.PolicyUseError, match='^policy subject/work mismatch$'):
            protected_tree.TreePolicy(selected, policy_version=protected_tree.POLICY_VERSION,
                                      work=selected.work)
