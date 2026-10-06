# Receipt 0.6 Lane G — Round 1 fold

Both findings are fixed and committed locally on `fix/0.6-pretag-corrections`,
directly above reviewed head `fbd2654d609ce6ce1ca935f799e15ae3168741ee`.

- **R1:** `b842f4148ade1bad0648891f70f8eabde7355d15` — Refuse lone aliases of configured protected prefixes. The shared listing screen compares configured spellings at every prefix depth, over files and trees including empty trees, before materialization/OpenSSL. Base/composed raise the existing append diagnostic through `ReleaseChainError`; append retains the same text, path priority and wider configured surfaces. The caller-anchor exclusion is preserved.
- **R2:** `a2228e40fc0bb2d8e525cae61b91ea495eec4112` — Reject Unicode host aliases and padded GitHub origins. Both authority patterns use ASCII case matching. A dedicated byte capture removes only Git's single framing LF, allowing the existing whitespace/control guard to see configured bytes. `git_output` and refusal words remain unchanged; CHANGELOG is corrected.

Each commit records the reproduced behavior, named tests and
`Co-Authored-By: GPT-6 Astra <noreply@openai.com>`.

R1's signed baseline verified one release and passed all composed stages under
both repertoires while append refused. The committed-head probe now refuses in
the base helper and composed custody with:

```text
index carries an alias of a protected path: CUSTODY (for custody at custody)
```

Binding is `not reached`. R2's real-repository baseline accepted all six Unicode
host forms and three whitespace-padded origins; the head probe refuses all nine,
while `https://GITHUB.COM/O/R.git` still yields `O/R`.

Tests added:

- `test_lone_configured_prefix_alias_refuses_before_materialization`: 24 cases, covering leaf/ancestor × empty/nonempty/blob × both repertoires × base/composed, with pinned composed verification and materialization/OpenSSL tripwires.
- `test_configured_prefix_comparison_preserves_caller_anchor_exclusion`: two cases, with a lone anchor alias, sibling aliases and invalid UTF-8 in an unused anchor subtree; caller trust accepts and tree trust refuses through the shared error path.
- `test_repository_slug_refuses_unicode_case_aliases`: six cases.
- `test_repository_slug_refuses_boundary_whitespace`: three cases.

All 35 new cases fail against exported fbd2654 source (pytest pythonpath explicitly
overridden) and pass after. The two exclusion controls pass their caller-trust
assertion on fbd2654 but fail their tree-trust `ReleaseChainError` assertion.
Existing 16 sibling cases and external-anchor tests still pass.

Validation used the specified pinned venv and ledger/Brier extraction paths:

| Check | Result |
| --- | --- |
| Required four modules | 378 passed, zero skips; 65.09 s |
| Full offline suite | 1,466 passed, 108 deselected, zero skips; 277.62 s |
| All four pinned harnesses | 108 passed, zero skips; 222.88 s |
| `git diff fbd2654 --check` | Passed |
| Existing exception templates | All 192 unchanged |

The offline count is 1,431 + 35 additions. No harness pin or file changed.
Only six authorized tracked files changed. `PROGRESS.md` and `OUTPUT.md` remain
untracked as required. `PROGRESS.md` contains the verbatim baseline and head
reproductions; the original R1 acceptance-asserting probe stops at the required
refusal, and an observation-only adaptation records both entry points.

Publication is incomplete. `git push origin fix/0.6-pretag-corrections` failed:

```text
fatal: unable to access 'https://github.com/TheAxiomFoundation/receipt.git/': Could not resolve host: github.com
```

The GitHub connector blocked the PR body update with
`MCP tool call requires approval, but approval policy is never`.
[PR #59](https://github.com/TheAxiomFoundation/receipt/pull/59) remains draft at
fbd2654 with its body unchanged. The prepared complete body, including the short
“Round 1 fold” section naming both commits and tests, is saved at
`/tmp/receipt-r1fold-pr-body.md`. Push from an environment with working DNS, then
append that section, updating its pending-push paragraph to the confirmed head.

Logs: `/tmp/receipt-r1fold-focused.log`, `/tmp/receipt-r1fold-offline.log`,
`/tmp/receipt-r1fold-harnesses.log`, `/tmp/receipt-r1fold-final-tests-baseline-confirmed.log`,
`/tmp/receipt-r1fold-r1-committed-head.log`, `/tmp/receipt-r1fold-r2-committed-head.log`.

Head OID: a2228e40fc0bb2d8e525cae61b91ea495eec4112
Suite totals: focused 378 passed; offline 1466 passed / 108 deselected; harnesses 108 passed; zero skips.
R1 (high): b842f4148ade1bad0648891f70f8eabde7355d15
R2 (medium): a2228e40fc0bb2d8e525cae61b91ea495eec4112
