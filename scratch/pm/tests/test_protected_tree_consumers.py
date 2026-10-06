"""PR5 selections, compatibility facades and complete composed command bytes."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, replace
from pathlib import Path, PurePosixPath

import pytest

from receipt import _names, append_gate, corpus, protected_tree as policy, snapshot, verify
from corpus_fixture import CONTENT, JOURNAL_RELATIVE, PREFIX_RELATIVE
from m1_fixture import raw_repo, signed_repo, outcome, stable, _goldens
from m1_append_fixture import append_repo, GATE_SPEC
from protected_tree_consumer_fixture import consumer_leg, work_observation
import test_m1_compat_golden as pr1


def encoded(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode()


@pytest.mark.parametrize('relative', (JOURNAL_RELATIVE, PREFIX_RELATIVE))
@pytest.mark.parametrize('mode', ('missing','100644','100755','120000','160000','040000'))
def test_complete_state_command_observation_bytes(signed_repo, tmp_path, monkeypatch, relative, mode):
    original = signed_repo.cli
    calls=[]
    def cli(*args, **kwargs):
        actual=original(*args, **kwargs)
        expected=_goldens()[f'state/{relative}/{mode}']['cli']
        assert encoded(actual)==encoded(expected)
        calls.append(actual)
        return actual
    monkeypatch.setattr(signed_repo,'cli',cli)
    pr1.test_state_shape_and_composed_goldens(signed_repo,tmp_path,relative,mode)
    assert len(calls)==1
    assert signed_repo.git('config','core.precomposeUnicode')==b'false'
    assert signed_repo.git('config','core.ignoreCase')==os.environ.get('RECEIPT_M1_IGNORECASE','false').encode()


@pytest.mark.parametrize('case', ('delete','mode','bytes','symlink','gitlink','base_mode','accept'))
def test_complete_history_command_observation_bytes(signed_repo,tmp_path,monkeypatch,case):
    original=signed_repo.cli
    calls=[]
    def cli(*args,**kwargs):
        actual=original(*args,**kwargs)
        normalized=stable(actual,((kwargs['base'],'<BASE>'),))
        assert encoded(normalized)==encoded(_goldens()['history/'+case]['cli'])
        calls.append(actual)
        return actual
    monkeypatch.setattr(signed_repo,'cli',cli)
    pr1.test_history_goldens(signed_repo,tmp_path,case)
    assert len(calls)==1


@pytest.mark.parametrize('fault', ('clean','rules-fold','unused-fold','content-link','attested-link'))
def test_composed_binding_reaches_each_body_and_preserves_all_phase_details(signed_repo,monkeypatch,fault):
    extras={
        'clean':(), 'rules-fold':(('rules/Pair.txt','100644'),('rules/pair.txt','100644')),
        'unused-fold':(('unused/Pair.txt','100644'),('unused/pair.txt','100644')),
        'content-link':(('rules/tax/rate.yaml','120000'),),
        'attested-link':(('.axiom/toolchain.toml','120000'),),
    }[fault]
    commit=signed_repo.commit(extras)
    results=[]
    for old in (True,False):
        with consumer_leg(monkeypatch,corpus,old=old) as (counts,events,subjects):
            result=verify.run_verification(signed_repo.root,signed_repo.loaded,commit=commit)
            assert counts['composed-binding']==1 and counts['shared-custody']==1
            assert counts['verify_corpus_binding']==int(old)
            if not old:
                assert counts['policy:binding:siblings']==1
            assert result.passes[0].name=='custody' and result.passes[0].ok
            phases=[asdict(item) for item in result.passes]
            results.append((encoded({'ok':result.ok,'passes':phases}),work_observation(events,subjects)))
    assert results[0]==results[1]


FACADES=('_screen_tree_listing','_entries_by_directory','_assert_content_root_spellings',
         '_content_entries_from_listing','_attested_entries_from_snapshot','_assert_tombstones_absent_from_listing')


def metadata(value):
    if isinstance(value,snapshot.GitEntry):
        return [value.path,value.mode,value.object_type,value.object_id]
    if isinstance(value,dict):
        return {key:metadata(item) for key,item in value.items()}
    return value


@pytest.mark.parametrize('facade',FACADES)
@pytest.mark.parametrize('fault',('clean','fold','content-link','root-alias','raw','attested-link','attested-ancestor','tombstone'))
def test_every_mapping_and_attested_facade_reaches_its_old_and_new_body(signed_repo,monkeypatch,facade,fault):
    extras={
        'clean':(), 'fold':(('unused/A','100644'),('unused/a','100644')),
        'content-link':(('rules/tax/rate.yaml','120000'),),
        'root-alias':(('Rules/unbound.txt','100644'),), 'raw':(('unused/bad\udcff','100644'),),
        'attested-link':(('.axiom/toolchain.toml','120000'),),
        'attested-ancestor':(('.axiom','120000'),), 'tombstone':(('retired/ITEM.JSON','100644'),),
    }[fault]
    remove=('.axiom/toolchain.toml',) if fault=='attested-ancestor' else ()
    commit=signed_repo.commit(extras,remove=remove)
    results=[]
    for old in (True,False):
        with consumer_leg(monkeypatch,corpus,old=old) as (counts,events,subjects):
            with signed_repo.snapshot(commit) as snap:
                entries=snap.entries('').as_dict(include_trees=True)
                children=corpus._entries_by_directory(entries)
                before=counts[facade]
                def call():
                    if facade=='_screen_tree_listing':
                        return corpus._screen_tree_listing(entries,children,repertoire='portable')
                    if facade=='_entries_by_directory':
                        return metadata(corpus._entries_by_directory(entries))
                    if facade=='_assert_content_root_spellings':
                        return corpus._assert_content_root_spellings(entries,children,signed_repo.corpus)
                    if facade=='_content_entries_from_listing':
                        return metadata(corpus._content_entries_from_listing(entries,signed_repo.corpus))
                    if facade=='_attested_entries_from_snapshot':
                        return metadata(corpus._attested_entries_from_snapshot(snap,{'.axiom/toolchain.toml':None}))
                    return corpus._assert_tombstones_absent_from_listing(entries,('retired/item.json',))
                result=outcome(call)
                assert counts[facade]-before==1
                results.append((result,work_observation(events,subjects)))
    assert results[0]==results[1]


def test_binding_selection_is_partial_until_content_and_bound_to_subject(raw_repo):
    commit=raw_repo.commit((('rules/file.yaml','100644'),('rules/suffixless','120000'),('unused/module','160000')),
                           empty=('rules/empty',))
    with raw_repo.snapshot(commit) as snap:
        evaluator=policy.TreePolicy(snap,policy_version=policy.POLICY_VERSION,work=snap.work)
        plan=policy.ProtectionPlan(phase='binding',use='binding',whole_tree_name_scope=True,
            content_roots=('rules',),content_suffixes=('.yaml',),
            obligations=('names','siblings','content-roots','content'))
        names=evaluator.evaluate(plan,stage='siblings')
        assert names.finding_for(plan.use) is None
        with pytest.raises(policy.PolicyUseError,match='unevaluated'):
            names.require(plan.use,render=corpus._binding_error)
        content=evaluator.evaluate(plan,stage='content',previous=names)
        assert content.listings['rules/empty']=={}
        selection=content.require(plan.use,render=corpus._binding_error)
        assert tuple(selection.entries_for(snap,use=plan.use,plan=plan))==('rules/file.yaml',)
        work=(evaluator.name_work,evaluator.shape_work,asdict(snap.work))
        repeated=evaluator.evaluate(plan,stage='content',previous=content)
        assert (evaluator.name_work,evaluator.shape_work,asdict(snap.work))==work
        with pytest.raises(policy.PolicyUseError,match='incompatible plan'):
            evaluator.evaluate(replace(plan,content_suffixes=('.json',)),stage='content',previous=content)
        with raw_repo.snapshot(commit) as other:
            with pytest.raises(policy.PolicyUseError,match='subject/purpose'):
                selection.entries_for(other,use=plan.use)
        assert repeated.completed==content.completed
    with pytest.raises(snapshot.SnapshotError):
        selection.entries_for(snap,use=plan.use)


def test_composition_reuses_custody_facts_without_reusing_its_verdict(signed_repo,monkeypatch):
    seen=[]
    original=policy.TreePolicy.evaluate
    def evaluate(subject,plan,**kwargs):
        seen.append((subject,plan.use,kwargs['stage']))
        return original(subject,plan,**kwargs)
    monkeypatch.setattr(policy.TreePolicy,'evaluate',evaluate)
    commit=signed_repo.commit((('rules/Pair.txt','100644'),('rules/pair.txt','100644')))
    result=verify.run_verification(signed_repo.root,signed_repo.loaded,commit=commit)
    assert [(p.name,p.ok) for p in result.passes]==[('custody',True),('binding',False),('declaration',False)]
    custody=next(p for p,use,stage in seen if use=='custody')
    binding=next(p for p,use,stage in seen if use=='binding')
    assert custody is binding
    assert result.passes[1].failure==("directory holds two entries a case-insensitive filesystem "
        "would merge: 'rules/Pair.txt' and 'rules/pair.txt'")


def test_append_consumes_one_evaluator_and_keeps_export_conditional(append_repo,monkeypatch):
    seen=[]
    original=policy.TreePolicy.evaluate
    def evaluate(subject,plan,**kwargs):
        seen.append((subject,plan,kwargs['stage']))
        return original(subject,plan,**kwargs)
    monkeypatch.setattr(policy.TreePolicy,'evaluate',evaluate)
    with append_repo.snapshot() as snap:
        candidate=append_gate._CandidateTree(snap,GATE_SPEC,str(GATE_SPEC.chain.state_relative),str(GATE_SPEC.chain.prefix_relative))
        result=append_gate._verify_selected_tree(candidate,base=None,trusted_code_root=append_repo.root,release_anchor_dir=None)
        assert 'append check OK' in result
        assert {id(p) for p,_,_ in seen}=={id(candidate._policy)}
        stages=[stage for _,_,stage in seen]
        assert stages.index('attributes')<stages.index('export-names')
        assert candidate._plan.fold_whole_alias_paths
        assert candidate._plan.anchor_origin=='caller'
        assert candidate._plan.configured_alias_targets==append_gate._protected_paths(candidate)
        assert all(plan.export_prefixes==candidate._plan.export_prefixes for _,plan,_ in seen)


def test_declaration_index_reuses_folds_but_replays_every_prefix_charge(monkeypatch):
    facts=policy._NameFacts()
    work=corpus._PathPrefixWork()
    obligations=policy.DeclarationObligations(('rules/a/x.yaml','rules/a/y.yaml'),100)
    calls=[]
    original=_names.ascii_fold_text
    def fold(value):
        calls.append(value)
        return original(value)
    monkeypatch.setattr(_names,'ascii_fold_text',fold)
    first=policy.evaluate_declarations(obligations,work=work,render=corpus._binding_error,facts=facts)
    charges=work.work
    folds=len(calls)
    second=policy.evaluate_declarations(obligations,work=work,render=corpus._binding_error,facts=facts)
    assert first==second==4 and work.work==2*charges==20
    assert len(calls)==folds==4


@pytest.mark.parametrize('limit',(3,4,5))
def test_declaration_alias_index_exact_limit(monkeypatch,limit):
    monkeypatch.setattr(corpus,'MAX_ALIAS_INDEX_NODES',limit)
    results=[]
    for old in (True,False):
        with consumer_leg(monkeypatch,corpus,old=old) as (counts,_,__):
            work=corpus._PathPrefixWork()
            result=outcome(lambda: corpus._reject_aliasing_paths(['rules/a/x.yaml','rules/a/y.yaml'],work=work))
            assert counts['_reject_aliasing_paths']==1
            results.append((result,work.work))
    assert results[0]==results[1]
    assert ('exception' in results[0][0])==(limit<4)


def test_composed_binding_hook_remains_observable_with_a_real_reader(signed_repo,monkeypatch):
    calls=[]
    def binding(subject,journal,*,spec):
        calls.append((subject,journal,spec))
        raise corpus.CorpusError('substituted binding reader')
    monkeypatch.setattr(verify,'verify_corpus_binding',binding)
    result=verify.run_verification(signed_repo.root,signed_repo.loaded,commit=signed_repo.base)
    assert len(calls)==1 and calls[0][1]==signed_repo.journal
    assert result.passes[0].ok and result.passes[1].failure=='substituted binding reader'


@pytest.mark.parametrize('repertoire',('portable','posix-bytes'))
@pytest.mark.parametrize('paths',(
    ('unused/A','unused/a','zz/bad?.txt'),
    ('A/bad?.txt','Z/bad\udcff'),
    ('A/bad\udcff','Z/bad?.txt'),
    ('unused/A','unused/a','zz/bad\udcff'),
))
def test_binding_names_precede_siblings_with_repertoire_substep_order(signed_repo,monkeypatch,repertoire,paths):
    commit=signed_repo.commit(tuple((path,'100644') for path in paths))
    results=[]
    for old in (True,False):
        with consumer_leg(monkeypatch,corpus,old=old) as (counts,events,subjects):
            with signed_repo.snapshot(commit) as snap:
                result=outcome(lambda: corpus.verify_corpus_binding(snap,signed_repo.journal,
                               spec=replace(signed_repo.corpus,name_repertoire=repertoire)))
                assert counts['verify_corpus_binding']==1 and 'exception' in result
                results.append((result,work_observation(events,subjects)))
    assert results[0]==results[1]


def test_binding_truncates_long_tree_labels_at_the_retained_renderer(raw_repo,monkeypatch):
    path='a'*200+'/'+'b'*100+'/bad?.txt'
    commit=raw_repo.commit(((path,'100644'),))
    results=[]
    for old in (True,False):
        with consumer_leg(monkeypatch,corpus,old=old) as (counts,_,__):
            with raw_repo.snapshot(commit) as snap:
                entries=snap.entries('').as_dict(include_trees=True)
                result=outcome(lambda: corpus._screen_tree_listing(entries,corpus._entries_by_directory(entries),repertoire='portable'))
                assert counts['_screen_tree_listing']==1
                results.append(result)
    assert results[0]==results[1]
    assert 'more characters]' in results[0]['message']
    assert corpus._quoted(path) in results[0]['message']
