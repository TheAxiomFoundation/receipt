"""Independent PR5 bodies and reached-hook counters for consumer comparisons."""
from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict
from types import FunctionType
import tempfile
from pathlib import Path

from receipt import append_gate, corpus, protected_tree
import protected_tree_legacy as legacy
from test_protected_tree_work import trace_reads


@contextmanager
def consumer_leg(monkeypatch, module, *, old):
    """Install whole legacy bodies, with independent globals and counted entry."""
    group = legacy.PR5Append if module is append_gate else legacy.PR5Corpus
    names = legacy.PR5_BODY_SHA256[group.__name__]
    namespace = dict(module.__dict__)
    counts = Counter()
    with monkeypatch.context() as patch:
        functions = {}
        for name in names:
            source = getattr(group, name) if old else getattr(module, name)
            if old:
                body = FunctionType(source.__code__, namespace, name, source.__defaults__)
                body.__kwdefaults__ = source.__kwdefaults__
                assert body.__code__ is getattr(group, name).__code__
            else:
                body = source
                assert body.__code__ is not getattr(group, name).__code__
            def counted(*args, _body=body, _name=name, **kwargs):
                counts[_name] += 1
                return _body(*args, **kwargs)
            functions[name] = counted
        namespace.update(functions)
        for name, function in functions.items():
            patch.setattr(module, name, function)
        if module is corpus:
            original = corpus._verify_corpus_binding
            def composed(*args, **kwargs):
                counts['composed-binding'] += 1
                if old:
                    kwargs.pop('policy', None)
                    return functions['verify_corpus_binding'](*args, **kwargs)
                return original(*args, **kwargs)
            patch.setattr(corpus, '_verify_corpus_binding', composed)
        original_evaluate = protected_tree.TreePolicy.evaluate
        def evaluate(subject, plan, **kwargs):
            counts['policy:' + plan.use + ':' + kwargs['stage']] += 1
            return original_evaluate(subject, plan, **kwargs)
        patch.setattr(protected_tree.TreePolicy, 'evaluate', evaluate)
        with trace_reads(patch) as (events, subjects):
            yield counts, events, subjects


def work_observation(events, subjects):
    return events, [asdict(subject.work) for subject in subjects]


@contextmanager
def deterministic_exports(monkeypatch, root):
    """Use equal physical export paths so full refusal strings need no scrubbing."""
    original = tempfile.mkdtemp
    root = Path(root)
    root.mkdir(exist_ok=True)
    ordinals = Counter()
    def mkdir(suffix=None, prefix=None, dir=None):
        if prefix == 'receipt-append-candidate-' or (dir and Path(dir).parent == root):
            ordinals[prefix] += 1
            path = Path(dir or root) / (prefix + str(ordinals[prefix]))
            path.mkdir(mode=0o700)
            return str(path)
        return original(suffix=suffix, prefix=prefix, dir=dir)
    with monkeypatch.context() as patch:
        patch.setattr(tempfile, 'mkdtemp', mkdir)
        yield
