"""PR6 comparisons retain independent v0.6.1 bodies and reached-call evidence."""
from __future__ import annotations

import hashlib
import inspect
import textwrap

import protected_tree_legacy as legacy


def test_pr6_verbatim_v061_body_sha256():
    for group, functions in legacy.PR6_BODY_SHA256.items():
        for name, expected in functions.items():
            source = textwrap.dedent(inspect.getsource(getattr(getattr(legacy, group), name)))
            assert hashlib.sha256(source.encode()).hexdigest() == expected, (group, name)
