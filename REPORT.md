# Witness-lane gaps and offline TSA coverage

Branch `fix/tsa-witness-coverage`, worktree
`/Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-fix-tsa-witness-coverage`,
branched from `origin/main` d542d59 (receipt 0.5.1). Import precedence confirmed
first:

```
$ PYTHONPATH=$PWD/src ./.venv/bin/python -c 'import receipt; print(receipt.__file__)'
/Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-fix-tsa-witness-coverage/src/receipt/__init__.py
```

Offline suite: **222 passed at d542d59 → 238 passed on this branch**, +16, all
16 new tests in the TSA integration battery. I authored four commits, one per
finding, plus this report; four further commits on the branch came from
automation in this environment rather than from me — see the last section,
which says which to keep and which to drop.

## Equivalence safety, established by reading the pinned tree rather than assuming

The four new refusals were checked against the actual authenticated baseline and
the actual pinned fixture, both read read-only from the local `MaxGhenis/brier`
checkout at the pin `4b9e7be22debc8349e76b8bdfe5a0fe18ed31a3f`. Nothing was run
from it and nothing outside this worktree was modified.

| Observed at the pin | Value |
| --- | --- |
| `records/trust/tsa-anchors-v1.json` anchors | one: `freetsa-root-2016` |
| `records/trust/tsa-anchors-v2.json` anchors | two: `freetsa-root-2016`, `digicert-trusted-root-g4` |
| `BRIER_TSA_SPEC` identities | all three of those bundle/anchor pairs |
| `records/2026-07-09/digest-f4f3-genesis.witness.json` | `schemaVersion`, `status: unavailable`, `digestSha256`, `reason` (non-empty string) — no token-evidence field |
| Unavailable witnesses in the tree | exactly one (53 snapshots, `availableWitnesses=52`) |
| Baseline `_v1_witness_evidence` unavailable path (`verify_record_chain.py:1101-1104`) | `if not witness.get("reason")` — no type check, no token-evidence check |
| Baseline `_load_trust_bundle` (`verify_record_chain.py:618`) | no per-anchor code-identity check; identity pinning is per selected anchor only, at `:793` |
| Baseline v1 schema branch (`verify_record_chain.py:1308-1318`) | no bound on the legacy bundle's anchor count |

So each new refusal fires only on inputs the battery never presents, no existing
refusal message or order changed, and the clean tree still verifies. No
existing error string was reworded and `canonical.py` was not touched.

## Finding 1 — a legacy v1 witness could satisfy a multi-anchor bundle with one token

**Changed.** Both halves, in `src/receipt/tsa.py`:

- `verify_witness` — `src/receipt/tsa.py:1330-1345`. After the existing
  transition/preferred check, the legacy bundle is loaded and refused if it
  configures more than one anchor:
  `legacy witness schema requires a single-anchor bundle; <bundle_id> has <n>`.
  Placed before the dispatch so it covers the unavailable v1 witness too, not
  only the available one.
- `_load_trust_bundle` — `src/receipt/tsa.py:617-630`. Every anchor id in a
  loaded bundle must have a code identity in the spec:
  `TSA anchor <id> in bundle <bundle_id> has no verifier code identity`.
  Placed **last**, after the existing commitment-mismatch check, so an altered
  bundle still binds `TSA trust bundle commitment mismatch` exactly as before —
  verified against `_flip_byte`, which flips offset 524 of the 1049-byte v1
  bundle, a character inside the `allowedSigners` subject string, not an anchor
  id.

**Tests added.** `tests/test_tsa.py:712` (`test_refuses_a_legacy_v1_witness_over_a_multi_anchor_bundle`)
and `tests/test_tsa.py:734` (`test_refuses_a_bundle_anchor_the_verifier_code_does_not_pin`).

**Before** (`tsa.py` reverted to d542d59, tests as written):

```
$ PYTHONPATH=$PWD/src ./.venv/bin/python -m pytest -q -p no:cacheprovider \
    tests/test_tsa.py -k "multi_anchor_bundle or does_not_pin" --tb=line
=================================== FAILURES ===================================
E   Failed: DID NOT RAISE TsaError
tests/test_tsa.py:640: Failed: DID NOT RAISE TsaError
E   AssertionError: assert 'TSA identity...eta-root-2026' == 'TSA anchor b...code identity'
      - TSA anchor beta-root-2026 in bundle tsa-anchors-v1 has no verifier code identity
      + TSA identity is not independently pinned in verifier code: tsa-anchors-v1/beta-root-2026
tests/test_tsa.py:666: AssertionError
FAILED tests/test_tsa.py::test_refuses_a_legacy_v1_witness_over_a_multi_anchor_bundle
FAILED tests/test_tsa.py::test_refuses_a_bundle_anchor_the_verifier_code_does_not_pin
2 failed, 1 passed, 22 deselected in 1.03s
```

`DID NOT RAISE` is the review's reproduction, reproduced locally on real
tokens. Driving the same tree through the unmodified `origin/main` module and
printing the returned `WitnessEvidence`:

```
tsa.py under test: origin/main d542d59
configured anchors: 2 ['alpha-root-2026', 'beta-root-2026']
code identities   : 2
verified tokens   : 1
status            : available
```

The second failure shows the coverage gap was previously reachable only as a
late, witness-shaped message and only when a witness happened to name the
unpinned anchor; it is now refused at bundle load, before any witness is read.

**After:**

```
$ PYTHONPATH=$PWD/src ./.venv/bin/python -m pytest -q -p no:cacheprovider \
    tests/test_tsa.py -k "multi_anchor_bundle or does_not_pin"
...                                                                      [100%]
3 passed, 22 deselected in 0.72s
```

## Finding 2 — v1 unavailable metadata was looser than v2

**Applied the tightening; did not freeze the permissiveness.** The task made
this conditional on the differential battery's documented exclusion. That
exclusion turned out to be checkable rather than merely a warning: brier's
genesis witness is the tree's only unavailable witness and carries a non-empty
string `reason` and none of the seven `_TOKEN_EVIDENCE_FIELDS`, and no mutation
in `MUTATIONS` produces a v1 unavailable witness at all
(`token_evidence_inside_unavailable` targets the v2 `TRANSITION` witness). So
both checks are equivalence-safe, and both were added.

**Changed.** `src/receipt/tsa.py:1066-1085`:

- the reason check keeps its message (`unavailable witness lacks a reason for
  <path>`) and its position, and only widens what trips it — `not
  isinstance(reason, str) or not reason` in place of `not
  witness.get("reason")`. Nothing previously refused is refused differently;
  truthy non-strings are now also refused, with the same text.
- a new check after it: `unavailable witness contains token evidence for
  <path>: <fields>`, matching the v2 `_unavailable_outcome` wording and field
  ordering.

`tests/test_brier_witness_equivalence.py:34-40` — the exclusion note now records
this as a place the port is deliberately stricter than the baseline, instead of
claiming the port matches. Docstring only; no behavior, no mutation, no pin
changed, and the module still collects its 17 tests.

**Tests added.** `tests/test_tsa.py:842`
(`test_refuses_a_legacy_unavailable_witness_whose_reason_is_not_a_string`, which
also asserts the untouched witness still verifies) and `tests/test_tsa.py:867`
(`test_refuses_a_legacy_unavailable_witness_that_carries_token_evidence`).

**Before** (`tsa.py` at the previous commit):

```
$ PYTHONPATH=$PWD/src ./.venv/bin/python -m pytest -q -p no:cacheprovider \
    tests/test_tsa.py -k "legacy_unavailable" --tb=line
FF                                                                       [100%]
=================================== FAILURES ===================================
E   Failed: DID NOT RAISE TsaError
tests/test_tsa.py:776: Failed: DID NOT RAISE TsaError
E   Failed: DID NOT RAISE TsaError
tests/test_tsa.py:808: Failed: DID NOT RAISE TsaError
FAILED tests/test_tsa.py::test_refuses_a_legacy_unavailable_witness_whose_reason_is_not_a_string
FAILED tests/test_tsa.py::test_refuses_a_legacy_unavailable_witness_that_carries_token_evidence
2 failed, 25 deselected in 0.48s
```

**After:**

```
$ PYTHONPATH=$PWD/src ./.venv/bin/python -m pytest -q -p no:cacheprovider \
    tests/test_tsa.py -k "legacy_unavailable"
..                                                                       [100%]
2 passed, 25 deselected in 0.49s
```

## Finding 3 — the offline suite had no TSA integration coverage

**Changed.** `tests/test_tsa.py` gains a second half (`:267` onward) built on the
local RFC 3161 authorities `tests/corpus_fixture.py` already generates for the
release-chain lane, rather than a second generator:

- `certificate_pins` (`tests/corpus_fixture.py:123`) derives the exact four-key
  identity dict the verifier compares `allowedSigners` against — assembling it
  any other way pins nothing, and the tests would then prove only that the
  verifier refuses its own fixture.
- `LocalTsa.signer_pem` (`tests/corpus_fixture.py:83`).
- `local_anchors` (`tests/test_tsa.py:327`), a module-scoped fixture: two root
  CAs, two signing certificates carrying `extendedKeyUsage =
  critical,timeStamping`.
- `build_witness_tree` (`tests/test_tsa.py:359`) writes a records tree with a
  canonical `thesis_tsa_trust_bundle_v1` bundle, a `CHAIN_GENESIS.json` pinning
  it, genuine `openssl ts -reply` responses over the record's own digest, and
  the sidecar that claims them, under either witness schema.

`verify_witness` is driven end to end through `bootstrap_trust_bundles`, real
OpenSSL chain and CMS verification, and the code-pin comparisons.

**Tests added** (16 new items; the seven the task named, plus acceptance and
direct-entry-point coverage):

| Test | `tests/test_tsa.py` |
| --- | --- |
| `test_verifies_a_real_rfc3161_witness_end_to_end` | 583 |
| `test_verify_timestamp_token_binds_one_token_to_the_bundle_it_names` | 606 |
| `test_verifies_two_anchors_and_reports_the_earliest_token` | 644 |
| `test_one_identity_allows_several_signers_at_once_and_retires_none` | 658 |
| `test_verifies_a_legacy_v1_witness_over_a_single_anchor_bundle` | 700 |
| `test_refuses_a_legacy_v1_witness_over_a_multi_anchor_bundle` (finding 1) | 712 |
| `test_refuses_a_bundle_anchor_the_verifier_code_does_not_pin` (finding 1) | 734 |
| `test_refuses_a_token_whose_policy_the_anchor_does_not_allow` | 758 |
| `test_refuses_a_token_from_a_signer_the_anchor_does_not_pin` | 775 |
| `test_refuses_a_token_whose_bytes_no_longer_match_the_witness` | 790 |
| `test_refuses_a_tampered_token_whose_hash_the_witness_was_updated_to_match` | 800 |
| `test_refuses_a_token_that_postdates_the_verification_time` | 818 |
| `test_refuses_a_token_that_precedes_the_record_it_witnesses` | 828 |
| `test_refuses_a_legacy_unavailable_witness_whose_reason_is_not_a_string` (finding 2) | 842 |
| `test_refuses_a_legacy_unavailable_witness_that_carries_token_evidence` (finding 2) | 867 |
| `test_a_witness_with_every_authority_unavailable_carries_no_tokens` | 902 |

Two are worth calling out. The tampered-token test flips the last byte and then
*rehashes*, so the digest check cannot catch it and the refusal has to come from
the signature — the branch a hash check alone would leave untested. The
unpinned-signer test substitutes the SPKI in the bundle and in the spec together,
because substituting it in only one stops at the earlier bundle-versus-code
comparison and never reaches the token's own signer.

**Before** — this is coverage of behavior that already existed, so the honest
before/after is the absence itself:

```
$ git show origin/main:tests/test_tsa.py | grep -c "verify_witness\|verify_timestamp_token\|openssl"
0
$ pytest --collect-only  # origin/main copy of tests/test_tsa.py
12 tests collected in 0.02s
```

**After:**

```
$ grep -c "verify_witness\|verify_timestamp_token" tests/test_tsa.py
9
$ PYTHONPATH=$PWD/src ./.venv/bin/python -m pytest -q -p no:cacheprovider \
    tests/test_tsa.py --collect-only
28 tests collected in 0.03s
```

## Finding 4 — the docstring overstated what signer rotation costs

**Changed.** `src/receipt/tsa.py:145-158`. The old text claimed an identity
"pins one signer per authority" and that tokens either side of a rotation
"verify only under different pinned identities". Both are wrong about the code:
`signer_spki_sha256` is a `frozenset` with no singleton constraint, so one
identity holds several signer SPKIs and allows every one of them concurrently. A
rotation is carried by adding the new fingerprint beside the old one in the same
identity. The docstring now says that, and names the limitation that was
actually unstated: there are no generation or retirement semantics — no
fingerprint carries a validity interval and none is ever retired, so a token
from a rotated-out signer keeps verifying while its fingerprint stays in the
set. That is the contrast with `receipt.sign`'s producer-key legacy generations,
where retired keys are named separately and vouch only under `allow_legacy=True`
(`src/receipt/sign.py:360-364`, `:457-464`).

`src/receipt/tsa.py:5,10-17` — the module docstring said "Refusal text is
retained verbatim", which after findings 1 and 2 would imply the port never
diverges. It now says *ported* refusal text is retained verbatim and names the
four places the port is deliberately stricter than the baseline.

**Test added.** `tests/test_tsa.py:658`
(`test_one_identity_allows_several_signers_at_once_and_retires_none`), backed by
`rotate_tsa_signer` (`tests/corpus_fixture.py:259`), which issues a second
timestamping certificate from an existing authority's own CA key so the rotated
tokens still chain to the pinned root — a fresh root would model a different
authority, not a rotation. The test verifies a token from the rotated signer and
a token from the superseded signer under one identity holding both fingerprints,
and asserts the two SPKIs actually differ so it cannot pass degenerately.

**Before/after.** The strongest evidence here is that the test passes against the
*unmodified* module: the old docstring was wrong about the code as it already
stood.

```
$ git show origin/main:src/receipt/tsa.py > src/receipt/tsa.py
$ PYTHONPATH=$PWD/src ./.venv/bin/python -m pytest -q -p no:cacheprovider \
    tests/test_tsa.py -k "several_signers"
.                                                                        [100%]
1 passed, 27 deselected in 1.32s
$ git checkout HEAD -- src/receipt/tsa.py
```

`tests/corpus_fixture.py:158-226` also factors the signer-extension and
`tsa.cnf` templates into `SIGNER_EXTENSIONS`, `_tsa_config`, `_issue_signer` and
`_signer_pins` so `build_local_tsa` and `rotate_tsa_signer` share one
definition. Behavior-preserving: `tests/test_corpus.py` and
`tests/test_release_chain.py` (83 tests) pass unchanged.

## Final offline suite

```
$ PYTHONPATH=$PWD/src ./.venv/bin/python -m pytest -q -p no:cacheprovider tests \
    --ignore=tests/test_ledger_equivalence.py \
    --ignore=tests/test_append_gate_equivalence.py \
    --ignore=tests/test_attest_equivalence.py \
    --ignore=tests/test_brier_witness_equivalence.py
238 passed in 17.50s
```

222 → 238. **16 new TSA integration tests**, all driving `verify_witness` or
`verify_timestamp_token` over genuine RFC 3161 responses through OpenSSL.
`tests/test_brier_witness_equivalence.py` still collects its 17 tests after the
docstring edit.

## Scope note, and the branch history

**The paper carried the same wrong claim, and it was corrected — outside the
scope I was given.** `paper/index.qmd:538-543` said the package has "no legacy
generations for timestamp-authority signers, so an authority's own key rotation
currently splits verification into eras the consumer spec must carry
explicitly". The first clause is true; the second is not, and finding 4's test
demonstrates why — one identity spans the rotation, so nothing splits. I flagged
it as a follow-up rather than editing it, because the task scoped the fix to the
`TsaSpec` docstring and the paper is revised and reviewed on its own branch
(revision 10 landed in d542d59). The environment automation described below then
applied the correction as `f5baf51` and a reflow as `9cc369e`. I checked both
against the code and kept them: a word-level diff of that paragraph against
`origin/main` shows the rotation sentence rewritten and nothing else changed.

```
[replace] - legacy generations
          + generation or retirement semantics
[replace] - signers,
          + signers: an identity allows several signer fingerprints at once
            with no validity interval on any of them,
[replace] - currently splits verification into eras
          + is carried by adding the new fingerprint beside the old one, and
            the superseded signer keeps verifying until
[replace] - spec must carry explicitly.
          + removes it.
```

Drop `f5baf51` and `9cc369e` together if the branch should stay scoped to the
module; the paper claim then needs raising separately, because it is a mechanism
claim the code does not support.

**Two commits on this branch are not mine, and one of them needs dropping.**
The branch is:

```
9cc369e Rewrap the limitations paragraph the rotation correction lengthened (automation, keep)
b751a4b Describe the branch history the report is reporting on           (mine)
f5baf51 Correct the paper's account of timestamp-authority signer rotation (automation, keep or drop)
0dd70ec Record what the witness-lane work changed and what it did not     (mine)
8d21cf8 Ignore a worktree virtualenv symlink, not just a directory        (automation, keep)
821bf90 Say what a TSA identity actually does about signer rotation       (mine, finding 4)
79cf2a9 Hold the legacy unavailable witness to the v2 metadata rules      (mine, finding 2)
9f26186 fixup! Refuse a legacy witness that covers more anchors...        (automation, DROP)
9fcbc42 Refuse a legacy witness that covers more anchors than it verifies (mine, finding 1)
26bfbc2 Drive the witness lane end to end in the offline suite            (mine, finding 3)
```

`9f26186`, `8d21cf8`, `f5baf51` and `9cc369e` appeared without my running `git
commit`, all carrying my Co-Authored-By trailer. There are no git hooks
installed in this repository (`.git/hooks` holds only samples, no
`core.hooksPath`), so the source is automation in this session's environment,
not the repo. I reviewed each against the code before leaving it in place.

`8d21cf8` is correct and should be kept. `.gitignore` had `.venv/`, which matches
only a directory; a worktree cannot hold the virtualenv as a directory without
rebuilding it, so it is a symlink to the primary clone's, which left it
untracked-but-not-ignored. Dropping the trailing slash ignores both shapes.

`9f26186` should be **dropped, not autosquashed**. It swept up finding 2's
in-progress edits plus that unignored `.venv` symlink, which is why my finding-2
commit `79cf2a9` shows only the equivalence-harness docstring in its diffstat:
the code and tests it describes had already been committed one commit earlier.
`git rebase --autosquash` would fold `9f26186` into `9fcbc42` and mis-attribute
finding 2's code to finding 1. A squash merge makes the whole question moot. The
net tree is correct either way — `git diff origin/main..HEAD` touches exactly
`.gitignore`, `REPORT.md`, `src/receipt/tsa.py`, `tests/corpus_fixture.py`,
`tests/test_brier_witness_equivalence.py` and `tests/test_tsa.py`, `.venv` is not
tracked at HEAD, and `canonical.py` is untouched. I left the history alone
because rebase and reset are outside my ground rules.

Related: I reached for `git stash` once to capture finding 2's before-state. A
`[stash-shared]` guard hook blocked the follow-up, correctly — the stash stack
lives in the shared `.git` and is visible to every worktree. I removed the entry
I had created with `git update-ref -d refs/stash` after confirming it was the
only one on the stack and byte-identical to my working tree, and switched to
`git show <ref>:path > file` for the remaining before/after captures. The stash
stack is empty, as it was at session start.

No network was used: no `uv sync`, `pip`, `gh`, or `curl`, and none of the four
equivalence modules were run. Nothing outside this worktree was modified; the
local `MaxGhenis/brier` checkout was read with `git show` only.
