"""PR5 scope and admission comparisons; every leg proves its body was reached."""
from __future__ import annotations

import hashlib
import inspect
import json
import pathlib
import textwrap
from dataclasses import asdict, replace

import pytest

from receipt import append_gate, corpus, snapshot, verify
from corpus_fixture import CONTENT, JOURNAL_RELATIVE, PREFIX_RELATIVE, journal_rows, render_journal
from m1_append_fixture import append_repo, GATE_SPEC
from m1_fixture import raw_repo, signed_repo, outcome
from protected_tree_consumer_fixture import consumer_leg, work_observation, deterministic_exports
import protected_tree_legacy as legacy


# Every D1–D11 tree-scope mechanism is presented to both real consumers. The
# direct-directory and caller-anchor controls remain pinned independently by PR1.
SCOPES = [('clean', (), (), (), 'portable')]
for region in ('releases', 'rules', 'unused'):
    SCOPES.append((f'D1-{region}', ((region+'/Pair.txt','100644'), (region+'/pair.txt','100644')), (), (), 'portable'))
    for repertoire in ('portable', 'posix-bytes'):
        SCOPES.append((f'D3-{region}-{repertoire}', ((region+'/bad?.txt','100644'),), (), (), repertoire))
    for mode in ('120000','160000'):
        SCOPES.append((f'D5-{region}-{mode}', ((region+'/link.txt',mode),), (), (), 'portable'))
SCOPES += [
    ('D1-root', (('AA.txt','100644'),('aa.txt','100644')), (), (), 'portable'),
    ('D1-empty', (('releases/extra','100644'),), (), ('releases/EXTRA',), 'portable'),
    ('D2-pinned', (('Releases/other.txt','100644'),), (), (), 'portable'),
    ('D2-empty', (), (), ('Releases',), 'portable'),
    ('D2-state', (('receipt/Corpus-journal.jsonl','100644'),), (), (), 'portable'),
    ('D2-content', (('Rules/unbound.txt','100644'),), tuple(CONTENT), (), 'portable'),
    ('D4-raw', (('unused/bad\udcff','100644'),), (), (), 'posix-bytes'),
    ('D4-unicode', (('unused/é.txt','100644'),('unused/é.txt','100644')), (), (), 'posix-bytes'),
    ('D5-content', (('rules/tax/rate.yaml','120000'),), (), (), 'portable'),
    ('D5-attested', (('.axiom/toolchain.toml','120000'),), (), (), 'portable'),
    ('D6-state-link', ((JOURNAL_RELATIVE,'120000'),), (), (), 'portable'),
    ('D6-state-gitlink', ((JOURNAL_RELATIVE,'160000'),), (), (), 'portable'),
    ('D6-ancestor-link', (('receipt','120000'),), (JOURNAL_RELATIVE,PREFIX_RELATIVE), (), 'portable'),
    ('D6-ancestor-blob', (('receipt','100644'),), (JOURNAL_RELATIVE,PREFIX_RELATIVE), (), 'portable'),
    ('D6-content-root', (('rules','100644'),), tuple(CONTENT), (), 'portable'),
    ('D10-names-mode', (('releases/bad?.txt','100644'),('releases/a-link','120000')), (), (), 'portable'),
    ('D10-state-alias', ((JOURNAL_RELATIVE,'120000'),('Releases/other.txt','100644')), (), (), 'portable'),
    ('D10-mode-attributes', (('releases/link','120000'),('.gitattributes','100644',b'releases/** filter=probe\n')), (), (), 'portable'),
    ('D11-directory-fold', (('releases/Pair.txt','100644'),('releases/pair.txt','100644')), (), (), 'portable'),
    ('D11-directory-state', ((JOURNAL_RELATIVE,'120000'),), (), (), 'portable'),
    ('D11-directory-attributes', (('.gitattributes','100644',b'releases/** filter=probe\n'),), (), (), 'portable'),
]
for repertoire in ('portable','posix-bytes'):
    for region, mode in (('releases','100644'),('rules','100644'),('rules','120000'),('rules','040000')):
        path = region + ('/hidden.sigx' if region == 'releases' else '/hidden.ymlx')
        SCOPES.append((f'D7-{region}-{mode}-{repertoire}', () if mode == '040000' else ((path,mode),), (),
                       (path,) if mode == '040000' else (), repertoire))
for target in ('releases/anchors/producer-ed25519.pub','rules/tax/rate.yaml','.axiom/toolchain.toml','unused/file.txt'):
    SCOPES.append(('D8-'+target, (('.gitattributes','100644',(target+' filter=probe\n').encode()),
                                ('unused/file.txt','100644')), (), (), 'portable'))
for path,mode,payload in (('rules/.gitattributes','100644',b'[attr]custom filter=probe\n'),
                          ('.gitattributes','120000',b'probe'),('rules/.gitattributes','120000',b'probe')):
    SCOPES.append((f'D8-source-{path}-{mode}', ((path,mode,payload),), (), (), 'portable'))
for fault, entries in (
    ('link', (('separate-anchors/link','120000'),)),
    ('fold', (('separate-anchors/EXTRA','100644'),('separate-anchors/extra','100644'))),
    ('raw', (('separate-anchors/bad\udcff','100644'),)),
):
    SCOPES.append(('D9-'+fault, entries, (), (), 'posix-bytes'))


def test_pr5_verbatim_body_sha256():
    for group_name, hashes in legacy.PR5_BODY_SHA256.items():
        for name, expected in hashes.items():
            body = textwrap.dedent(inspect.getsource(getattr(getattr(legacy, group_name), name)))
            assert hashlib.sha256(body.encode()).hexdigest() == expected, (group_name, name)


@pytest.mark.parametrize('case,entries,remove,empty,repertoire', SCOPES, ids=[c[0] for c in SCOPES])
@pytest.mark.parametrize('consumer', ('append','binding'))
def test_d1_to_d11_consumer_work(signed_repo, monkeypatch, consumer, case, entries, remove, empty, repertoire):
    commit = signed_repo.commit(entries, remove=remove, empty=empty)
    module = append_gate if consumer == 'append' else corpus
    results = []
    for old in (True, False):
        with consumer_leg(monkeypatch, module, old=old) as (counts, events, subjects):
            with signed_repo.snapshot(commit) as snap:
                if consumer == 'append':
                    candidate = signed_repo.candidate(snap, repertoire)
                    if case.startswith('D9'):
                        candidate = replace(candidate, spec=replace(candidate.spec, chain=replace(candidate.spec.chain,
                            anchor_relative=pathlib.PurePosixPath('separate-anchors'))))
                    def call():
                        listing = append_gate._screen_candidate_tree_aliases(candidate)
                        return snap.refuse_transforming_attributes(append_gate._attribute_entries(candidate, listing))
                    result = outcome(call)
                    assert counts['_screen_candidate_tree_aliases'] == 1
                else:
                    spec = replace(signed_repo.corpus, name_repertoire=repertoire,
                                   content_suffixes=('.yaml','.yml') if case.startswith('D7-rules') else signed_repo.corpus.content_suffixes)
                    result = outcome(lambda: asdict(corpus.verify_corpus_binding(snap, signed_repo.journal, spec=spec)))
                    assert counts['verify_corpus_binding'] == 1
                results.append((result, work_observation(events, subjects)))
                if not old:
                    assert sum(n for key,n in counts.items() if key.startswith('policy:')) > 0
    assert results[0] == results[1]


@pytest.mark.parametrize('branch', ('gate','data','push'))
@pytest.mark.parametrize('fault', ('clean','name','state','alias','attributes','release-link','manifest-file','manifest-empty','manifest-tree'))
def test_full_append_branches_and_counters(append_repo, monkeypatch, branch, fault):
    extras = {
        'clean': (), 'name': (('releases/policy/bad?.txt','100644'),),
        'state': ((GATE_SPEC.chain.state_relative.as_posix(),'120000'),),
        'alias': (('Releases/other','100644'),),
        'attributes': (('.gitattributes','100644',b'releases/** filter=probe\n'),),
        'release-link': (('releases/link','120000'),),
        'manifest-file': (('releases/manifests/0000-0123456789abcdef.json','100644'),),
        'manifest-empty': (), 'manifest-tree': (('releases/manifests/0000-0123456789abcdef.json/child','100644'),),
    }[fault]
    if branch == 'gate':
        extras += (('verification/policy.py','100644'),)
    commit = append_repo.commit(extras, empty=('releases/manifests/0000-0123456789abcdef.json',) if fault == 'manifest-empty' else ())
    spec = replace(GATE_SPEC, chain=replace(GATE_SPEC.chain,name_repertoire='posix-bytes'),
                   gate_surface=GATE_SPEC.gate_surface | {'verification/**','releases/policy/**'})
    results=[]
    for old in (True, False):
        with deterministic_exports(monkeypatch, append_repo.root.parent / 'exports'), \
                consumer_leg(monkeypatch, append_gate, old=old) as (counts, events, subjects):
            result=outcome(lambda: append_gate.verify_append_gate(append_repo.root,spec=spec,commit=commit,
                          base_ref=None if branch=='push' else append_repo.base))
            assert counts['_verify_selected_tree']==1 and counts['_state_entry']>=1
            if fault=='clean':
                assert counts['check_release_chain_without_base' if branch=='push' else 'check_release_proposal']==(branch!='gate')
                assert counts['_screen_candidate_materialization']==(branch!='gate')
            results.append((result,work_observation(events,subjects)))
    assert results[0]==results[1]


@pytest.mark.parametrize('budget,ceiling', (('MAX_PATH_BYTES_TOTAL',80),('MAX_PATH_BYTES_TOTAL',300),
    ('MAX_PATH_BYTES_TOTAL',1000),('MAX_ATTRIBUTE_MATCH_WORK',5),('MAX_MATERIALIZED_BYTES',1),
    ('MAX_TREE_ENTRIES',6)))
@pytest.mark.parametrize('branch',('data','push'))
def test_append_refusal_steps_at_reduced_limits(append_repo,monkeypatch,budget,ceiling,branch):
    commit=append_repo.commit((('.gitattributes','100644',b'releases/** -filter\n'),))
    monkeypatch.setattr(snapshot,budget,ceiling)
    results=[]
    for old in (True,False):
        with consumer_leg(monkeypatch,append_gate,old=old) as (counts,events,subjects):
            result=outcome(lambda: append_gate.verify_append_gate(append_repo.root,spec=GATE_SPEC,commit=commit,
                          base_ref=append_repo.base if branch=='data' else None))
            assert counts['_verify_selected_tree']==1
            assert ('exception' in result) == ((budget,ceiling) not in {('MAX_PATH_BYTES_TOTAL',1000),('MAX_TREE_ENTRIES',6)})
            results.append((result,work_observation(events,subjects)))
    assert results[0]==results[1]


@pytest.mark.parametrize('paths', (
    ('rules/A/x.yaml','rules/a/y.yaml','rules/Z/z.yaml','rules/z/z.yaml'),
    ('rules/A/x.yaml','rules/a/y.yaml'),
    ('rules/a/x.yaml','rules/a/y.yaml'),
    ('é/x.yaml','é/y.yaml'),
))
@pytest.mark.parametrize('ceiling', (0,5,18,19,1000))
def test_declaration_work_alias_precedence_and_live_limits(monkeypatch,paths,ceiling):
    monkeypatch.setattr(corpus,'MAX_PATH_COMPONENTS_TOTAL',ceiling)
    results=[]
    for old in (True,False):
        with consumer_leg(monkeypatch,corpus,old=old) as (counts,events,subjects):
            work=corpus._PathPrefixWork()
            result=outcome(lambda: corpus._reject_aliasing_paths(list(paths),work=work))
            assert counts['_reject_aliasing_paths']==1
            results.append((result,work.work))
    assert results[0]==results[1]


@pytest.mark.parametrize('fault', ('clean','missing','link','gitlink','ancestor','tombstone','tombstone-alias','malformed'))
def test_supplied_journal_and_attested_refusal_work(signed_repo,monkeypatch,fault):
    paths={
        'clean':(), 'missing':(), 'link':(('.axiom/toolchain.toml','120000'),),
        'gitlink':(('.axiom/toolchain.toml','160000'),), 'ancestor':(('.axiom','120000'),),
        'tombstone':(('retired/item.json','100644'),), 'tombstone-alias':(('retired/ITEM.JSON','100644'),),
        'malformed':(('unused/A','100644'),('unused/a','100644')),
    }[fault]
    remove=('.axiom/toolchain.toml',) if fault in {'missing','ancestor'} else ()
    commit=signed_repo.commit(paths+((JOURNAL_RELATIVE,'120000'),),remove=remove)
    rows=journal_rows()
    if fault.startswith('tombstone'):
        for state in ('present','removed'):
            rows.append(dict(rows[3],path='retired/item.json',state=state,entryIndex=len(rows)))
    journal=b'not-json\n' if fault=='malformed' else render_journal(rows)
    results=[]
    for old in (True,False):
        with consumer_leg(monkeypatch,corpus,old=old) as (counts,events,subjects):
            with signed_repo.snapshot(commit) as snap:
                result=outcome(lambda: asdict(corpus.verify_corpus_binding(snap,journal,spec=signed_repo.corpus)))
                assert counts['verify_corpus_binding']==1
                assert all(event[:2]!=('entry',JOURNAL_RELATIVE) for event in events)
                if fault=='clean':
                    assert 'value' in result
                results.append((result,work_observation(events,subjects)))
    assert results[0]==results[1]


@pytest.mark.parametrize('lifecycle',('unentered','closed'))
@pytest.mark.parametrize('fault',('whole','prefix','budget','clean'))
def test_declarations_precede_snapshot_lifecycle_admission(raw_repo,monkeypatch,lifecycle,fault):
    from corpus_fixture import corpus_spec
    rows=journal_rows()
    paths={'whole':('rules/Z/z.yaml','rules/z/z.yaml'),
           'prefix':('rules/A/x.yaml','rules/a/y.yaml'),'budget':(),'clean':()}[fault]
    for path in paths:
        rows.append(dict(rows[0],path=path,entryIndex=len(rows)))
    if fault=='budget':
        monkeypatch.setattr(corpus,'MAX_PATH_COMPONENTS_TOTAL',0)
    results=[]
    for old in (True,False):
        with consumer_leg(monkeypatch,corpus,old=old) as (counts,events,subjects):
            snap=raw_repo.snapshot()
            if lifecycle=='closed':
                with snap:
                    pass
            result=outcome(lambda:corpus.verify_corpus_binding(snap,render_journal(rows),spec=corpus_spec()))
            assert counts['verify_corpus_binding']==1 and counts['_reject_aliasing_paths']==1
            assert result['exception']=='receipt.corpus.CorpusError'
            results.append((result,work_observation(events,subjects)))
    assert results[0]==results[1]


@pytest.mark.parametrize('lifecycle',('unentered','closed'))
@pytest.mark.parametrize('paths',((),('.axiom/toolchain.toml',)))
def test_attested_facade_keeps_empty_and_masked_lifecycle_contract(raw_repo,monkeypatch,lifecycle,paths):
    results=[]
    for old in (True,False):
        with consumer_leg(monkeypatch,corpus,old=old) as (counts,events,subjects):
            snap=raw_repo.snapshot()
            if lifecycle=='closed':
                with snap:
                    pass
            result=outcome(lambda:corpus._attested_entries_from_snapshot(snap,dict.fromkeys(paths)))
            assert counts['_attested_entries_from_snapshot']==1
            results.append((result,work_observation(events,subjects)))
    assert results[0]==results[1]
    assert results[0][0]==({'exception':'receipt.corpus.CorpusError',
        'message':'bound file is missing or not a regular file: .axiom/toolchain.toml'} if paths else {'value':{}})


@pytest.mark.parametrize('branch',('actual-data-append','gate-with-unparsed-state'))
def test_changed_data_and_gate_only_payload_barriers(append_repo,monkeypatch,branch):
    from test_append_gate import observation_row,jsonl_line
    state=GATE_SPEC.chain.state_relative.as_posix()
    base=append_repo.base
    if branch=='actual-data-append':
        with append_repo.snapshot() as snap:
            ledger=snap.blob(snap.entry(state),limit=1<<20)
        commit=append_repo.commit(((state,'100644',ledger+(jsonl_line(observation_row(3))+'\n').encode()),))
        spec=GATE_SPEC
    else:
        base=append_repo.commit(((state,'100644',b'not a journal\n'),))
        commit=append_repo.commit((('verification/policy.py','100644'),),base=base)
        spec=replace(GATE_SPEC,gate_surface=GATE_SPEC.gate_surface|{'verification/**'})
    results=[]
    for old in (True,False):
        with consumer_leg(monkeypatch,append_gate,old=old) as (counts,events,subjects):
            result=outcome(lambda:append_gate.verify_append_gate(append_repo.root,spec=spec,commit=commit,base_ref=base))
            assert counts['_verify_selected_tree']==1 and 'value' in result
            assert counts['_read_state_blob']==(2 if branch=='actual-data-append' else 0)
            assert counts['_screen_candidate_materialization']==(1 if branch=='actual-data-append' else 0)
            assert ('+1 appended' if branch=='actual-data-append' else 'gate-only proposal') in result['value']
            results.append((result,work_observation(events,subjects)))
    assert results[0]==results[1]


@pytest.mark.parametrize('empty',(False,True))
def test_attribute_target_facade_remains_metadata_only(append_repo,monkeypatch,empty):
    with append_repo.snapshot() as source:
        entries={} if empty else source.entries('').as_dict(include_trees=True)
    results=[]
    for old in (True,False):
        with consumer_leg(monkeypatch,append_gate,old=old) as (counts,events,subjects):
            unentered=append_repo.snapshot()
            candidate=append_gate._CandidateTree(unentered,GATE_SPEC,str(GATE_SPEC.chain.state_relative),
                                                str(GATE_SPEC.chain.prefix_relative))
            result=outcome(lambda:tuple(entry.path for entry in append_gate._attribute_entries(candidate,entries)))
            assert counts['_attribute_entries']==1 and 'value' in result
            assert '_policy' not in candidate.__dict__
            results.append((result,work_observation(events,subjects)))
    assert results[0]==results[1]
