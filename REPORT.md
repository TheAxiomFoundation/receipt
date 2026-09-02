# Spec validation, the fail-closed boundary, receipt handling, and verdict evidence

Branch `fix/spec-validation-and-verdict`, worktree
`_worktrees/receipt-fix-spec-validation-and-verdict`, branched from `d542d59`
(receipt 0.5.1). All twelve findings are implemented. Nothing was left out.

Import precedence confirmed before and after:

```
$ PYTHONPATH=$PWD/src ./.venv/bin/python -c 'import receipt; print(receipt.__file__)'
/Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-fix-spec-validation-and-verdict/src/receipt/__init__.py
```

**Final offline suite: 346 passed.** Baseline was 222; the 124 added tests are
listed per finding below. `pyproject.toml` and `src/receipt/canonical.py` are
byte-identical to `d542d59` (`git diff --stat d542d59 -- pyproject.toml
src/receipt/canonical.py` is empty).

Line references are to the branch head unless marked "was".

---

## 1. `ChainSpec` and `AnchorSpec` had no `__post_init__`

**Changed.** `src/receipt/release_chain.py:80` (`OID_RE`), `:83`
(`_spec_relative_path`), `:116` (`AnchorSpec.__post_init__`), `:165`
(`ChainSpec.__post_init__`).

`AnchorSpec` validates `pem_sha256`, `signer_certificate_sha256` and
`signer_spki_sha256` through the module's existing `_sha256` (64 lowercase hex),
and `policy_oid` against a dotted-decimal OID with no leading-zero arcs — a spec
pinning `1.02` would compare against a spelling no RFC 3161 receipt reports.
`ChainSpec` validates the five relative paths (must be `PurePosixPath`, relative,
at least one component, no `..`), `producer_spki_sha256` as 64 lowercase hex, and
`anchors` as a non-empty `Mapping[str, AnchorSpec]` with non-empty string keys.
Every refusal is a `ReleaseChainError`. The fixtures in `tests/corpus_fixture.py`
and the generated consumer spec module construct unchanged.

**Tests.** `tests/test_spec_validation.py` (new, 199 lines): construction-refusal
coverage for every field — the producer pin (8 values), the anchor map
(empty/non-mapping/bad key/bad value), each anchor digest field × 6 values, the
policy OID (11 rejected spellings, 3 accepted real OIDs), and each of the five
path fields × 4 wrong types × 5 escaping spellings. Plus
`tests/test_cli.py::test_a_chain_resigned_under_a_substituted_key_refuses_by_spki_pin`,
the `verify_release_chain`-level regression.

**Before / after.** A script that builds the fixture corpus, replaces
`producer_spki_sha256` with `None`, substitutes a freshly generated producer key,
and re-signs every manifest under it:

```
$ PYTHONPATH=<d542d59 src> ./.venv/bin/python f1_demo.py <repo>
construction accepted a spec with no producer pin
VERIFIED a chain re-signed under a SUBSTITUTED producer key

$ PYTHONPATH=$PWD/src ./.venv/bin/python f1_demo.py <repo>
CONSTRUCTION REFUSED: ChainSpec producer_spki_sha256 must be exactly 64 lowercase hexadecimal characters
```

With the pin present but the key substituted, the refusal now names the pin:

```
$ ./.venv/bin/python -m pytest tests/test_cli.py -k resigned_under_a_substituted_key
1 passed
```

(the test asserts `match="producer public-key SPKI is not code-pinned"`).

## 2. Empty anchor map

**Changed.** `src/receipt/cli.py:177-196`. Item 1 makes `ChainSpec(anchors={})`
impossible; this is the defensive half of the renderer. With zero witnesses the
sentence closes on what the signature alone proves and the absence is stated —
`This verdict makes no witnessed timing claim` — instead of rendering
`the 0 pinned RFC 3161 authorities ()` and attaching a timing claim to it. The
timing clause is now built once and punctuated by whether a base ref was
verified, so the two branches cannot drift.

**Tests.** `tests/test_cli.py::test_a_verdict_with_no_witnesses_states_no_timing_claim`
(monkeypatches `VerifyResult.witness_times` to `{}`);
`tests/test_spec_validation.py::test_a_spec_with_no_anchors_refuses_at_construction`.

**Before / after.**

```
before: E            0 pinned RFC 3161 authorities ()
        E             witnessed that each recorded prefix existed no later than those times.
        FAILED tests/test_cli.py::test_a_verdict_with_no_witnesses_states_no_timing_claim
        1 failed

after:  2 passed   (with test_pass_verdict_derives_the_witness_clause, unchanged)
```

## 3. `raise SystemExit(0)` inside a spec escaped the fail-closed boundary

**Changed.** `src/receipt/verify.py:78` (`_exception_detail`), `:280` (the `exec`
boundary), `:445`, `:477`, `:510`, `:526` (the four pass boundaries);
`src/receipt/cli.py:300`, `:313`, `:333`, `:349`, `:363` (the five CLI wrappers).
Every one catches `BaseException` and re-raises `KeyboardInterrupt` alone — an
operator's interrupt is not a verdict about the corpus. `SystemExit` and
`GeneratorExit` become a refused spec or a failed pass. `str(SystemExit(0))` is
the bare string `"0"`, so `_exception_detail` names the type rather than quoting
an exit code as if it were a message. Docstrings updated: `verify.py:27-31`
(the fail-closed paragraph now covers `SystemExit`) and `cli.py:18-21`.

**Tests.** `tests/test_cli.py`:
`test_a_spec_that_exits_the_interpreter_is_refused_not_obeyed`
(parametrized over `SystemExit(0)` and `GeneratorExit()` — asserts `EXIT_USAGE`
= 2, a JSON verdict with `stage == "spec"`, `passesCompleted == []`, and no
`"PASS"` anywhere in stdout), `test_a_pass_that_exits_the_interpreter_is_a_fail_verdict`,
`test_a_run_that_exits_the_interpreter_is_a_fail_verdict`.

**Before / after.**

```
before: E       SystemExit: 0
        tests/test_cli.py:705: SystemExit
        FAILED ...[SystemExit(0)]  FAILED ...[GeneratorExit()]
        FAILED test_a_pass_that_exits_the_interpreter_is_a_fail_verdict
        FAILED test_a_run_that_exits_the_interpreter_is_a_fail_verdict
        4 failed

after:  4 passed
```

## 4. Receipt file reopened by three OpenSSL calls with no snapshot

**Changed.** `src/receipt/release_chain.py:801` (`_receipt_bytes`), `:1008-1009`
(the snapshot write inside the existing `TemporaryDirectory`), `:1019`, `:1058`,
`:1085` (the three OpenSSL invocations), `:865` (`_verify_production_signer`'s new
keyword-only `source`).

`_receipt_bytes` lstats the path, requires a regular file, opens once with
`O_RDONLY | O_NOFOLLOW` where the platform has it, `fstat`s the descriptor and
requires a regular file with matching `(st_dev, st_ino)`, then reads the bytes
through that descriptor. Those bytes are written to `receipt-<tsa>.tsr` inside
the run's own temporary directory and passed to the `-text` inspection, the
`-verify`, and the token extraction under `_verify_production_signer`.

**Existing messages preserved.** Every label and refusal still names the original
receipt path: `_verify_production_signer` keeps `receipt` for
`f"token extraction for {receipt.name}"` and the two signer-pin refusals, and
`verify_receipt` keeps it for `cannot inspect RFC 3161 receipt {receipt}`,
`RFC 3161 genTime ... for {receipt.name}` and
`RFC 3161 verification failed for {receipt.name}`. Only the `-in` arguments moved.

**Equivalence check on the OpenSSL diagnostics.** The ledger differential harness
compares refusal text byte for byte and embeds OpenSSL's ASN.1 output verbatim,
and two of its mutations (`flip_freetsa_receipt`, `flip_digicert_receipt`) corrupt
a receipt. I probed whether OpenSSL names its input file in those diagnostics —
flipping bytes at four offsets of a real fixture receipt, under both
`ts -reply -text` and `ts -verify`:

```
801EE2F401000000:error:068000A8:asn1 encoding routines:asn1_check_tlen:wrong tag:...
   PATH IN DIAGNOSTIC: False          (all 8 probes)
```

OpenSSL embeds the path only when it cannot open the file
(`BIO_new_file:...:calling fopen(/nonexistent/x.tsr, rb)`), which is unreachable
here: the receipt is checked for regular-file-ness and read successfully before
any OpenSSL call, and the snapshot is written by this process into its own
directory. So no reachable refusal can print the snapshot path.

**Tests.** `tests/test_release_chain.py`:
`test_a_receipt_swapped_mid_verification_cannot_mix_two_tokens` (monkeypatches
`receipt.release_chain.subprocess.run` to overwrite the alpha receipt with the
beta receipt the instant the `-text` call returns; asserts the swap landed, that
the file on disk really changed, and that the returned genTime equals the
pristine run's), plus
`test_a_receipt_that_is_not_a_regular_file_refuses_before_opening` (a fifo — the
lstat has to run before the open, because opening a fifo for reading blocks) and
`test_a_receipt_replaced_between_the_lstat_and_the_open_refuses` (the
`(device, inode)` guard).

**Before / after.** The pre-change verifier saw two different files:

```
before: E  receipt.release_chain.ReleaseChainError: RFC 3161 verification failed for
           0000-d08b1a688184c6eb.alpha.tsr (exit 1): ... ts_verify_cert:certificate
           verify error ... self-signed certificate in certificate chain
        FAILED test_a_receipt_swapped_mid_verification_cannot_mix_two_tokens
        1 failed

after:  3 passed
```

A refusal was a sound outcome for that swap; the point is that the two calls
could see different files at all, which is what a mixed genTime is made of. With
the snapshot the swap is inert.

## 5. Fractional genTime rounded down

**Changed.** `src/receipt/release_chain.py:614-632` (`_parse_receipt_text` refuses
more than six fractional digits with a `ReleaseChainError`);
`src/receipt/verify.py:305` (`_witness_time`), `:325` (text custody line), `:598`
(JSON witness map). The `-attime` integer conversion is untouched.

The refusal exists because truncation moves the parsed time strictly earlier than
the instant the authority signed, and that time is not merely reported: it is
compared against `createdAtUtc`, compared against the previous release's
witnesses, and it selects the `-attime` the signer certificate is validated at.
`_witness_time` prints microseconds when there are any and omits them when there
are none, so whole-second receipts still render exactly as before.

**Tests.** `tests/test_release_chain.py::test_a_fractional_genTime_keeps_every_digit_it_can_represent`
(parametrized `""`→0, `".1"`→100000, `".123456"`→123456, over real
`openssl ts -reply -text` output with only the fraction rewritten),
`::test_a_genTime_finer_than_a_microsecond_refuses` (`".1234567"`).
`tests/test_cli.py::test_a_witnessed_time_with_no_fraction_is_rendered_whole`
(regex-asserts no spurious `.000000`) and
`::test_a_fractional_witnessed_time_is_quoted_in_full` (parametrized over
microseconds 1, 750000, 999999 — 999999 is the rollover check: the second must
not advance — asserting both the JSON map and the text verdict).

**Before / after.**

```
before: FAILED test_a_fractional_witnessed_time_is_quoted_in_full[1]
        FAILED test_a_fractional_witnessed_time_is_quoted_in_full[750000]
        FAILED test_a_fractional_witnessed_time_is_quoted_in_full[999999]
        FAILED test_a_genTime_finer_than_a_microsecond_refuses
        4 failed, 4 passed

after:  8 passed
```

## 6. A base-ref verdict named the ref spelling, not the resolved commit

**Changed.** `src/receipt/verify.py:163` (`VerifyResult.base_commit`), `:389`,
`:405`, `:436-441` (capture and pass detail), `:581-585` (`history.baseCommit`).

`verify_release_history_immutable` (`release_chain.py:1732`, resolving at `:1738`) already resolved
`base_ref` exactly once via `resolve_base_commit` and returned the commit, and it
already threads that `commit` through every comparison and refusal below it — so
no change was needed there. I verified this by reading the function and by
grepping every caller (`verify.py`, `append_gate.py:605`, the ledger equivalence
harness): none re-resolves. `run_verification` now captures that return value
instead of discarding it.

**Tests.** `tests/test_cli.py::test_the_history_verdict_names_the_resolved_commit_not_the_ref`
(asserts `payload["history"]["baseCommit"]` equals `git rev-parse HEAD`, matched
against `[0-9a-f]{40}`; asserts `present at HEAD (<oid>)` in the pass detail; and
asserts the OID appears in text-mode output) and
`::test_a_verdict_without_a_base_ref_carries_no_history_block`.

**Before / after.**

```
before: >       assert payload["history"]["baseCommit"] == expected
        E       KeyError: 'history'
        1 failed, 1 passed

after:  2 passed
```

Rendered:

```
  [ok  ] history
         every release object present at HEAD (28cfd54f1a751ab4a7eda09b1277d97c847dd4de) is byte- and mode-identical in this tree
```

## 7. `load_spec`'s symlink guard was dead code

**Changed.** `src/receipt/verify.py:262-266`. The check now runs on the path as
supplied, before `resolve()`. The pre-existing post-resolve check and its message
are untouched. Docstring updated at `:239-241`.

**Tests.** `tests/test_cli.py::test_refuses_a_symlinked_spec` — asserts
`VerifySpecError` matching `spec is a symlink` from `load_spec`, and `EXIT_USAGE`
with a JSON verdict whose failure contains `supply the regular file's path`.

**Before / after.**

```
before: E       Failed: DID NOT RAISE VerifySpecError
        1 failed

after:  1 passed
```

## 8. Text verdict printed only the 16-hex head prefix

**Changed.** `src/receipt/verify.py:339` — `head {head.sha256}` as its own
labelled segment, beside (not instead of) the filename. The producer SPKI prefix
is deliberately left as it was: it is pinned in the spec the verdict already
names in full. The head digest is not pinned anywhere, and it is the value the
verdict's own closing paragraph tells an auditor to compare out of band.

**Tests.** `tests/test_cli.py::test_the_text_verdict_carries_every_quotable_digest_in_full`
(renamed from `..._the_full_anchor_set_digest`) — asserts all three quotable
digests appear in text mode at full length: `sha256 <spec>`, `head <64 hex>`,
`anchor set <64 hex>`.

**Before / after.**

```
before: E  AssertionError: assert 'head c599f1d93a20d3a4eb76e8d19dba3e8d103ee547dad93c1fe097b819fdd9cb11' in '...'
        1 failed

after:  1 passed
```

## 9. `VerifyResult.ok` was a vacuous `all()`

**Changed.** `src/receipt/verify.py:96` (`REQUIRED_PASSES = ("custody",
"binding", "declaration")`), `:166-180` (`ok` requires every recorded pass to be
ok *and* the three required passes to have completed).

**Tests.** `tests/test_release_chain.py::test_verify_result_accessors_before_custody`
extended with `assert result.ok is False` for an empty pass tuple, and
`::test_a_verdict_needs_all_three_of_its_passes` — each two-of-three subset is
not ok, the full set is, and a recorded failure still overrides a complete set.

**Before / after.**

```
before: E       ImportError: cannot import name 'REQUIRED_PASSES' from 'receipt.verify'
        FAILED test_verify_result_accessors_before_custody
        FAILED test_a_verdict_needs_all_three_of_its_passes
        2 failed

after:  2 passed
```

(The `ImportError` masks the substantive failure in the second test; the first
fails on `result.ok is False` against the old `all()`.)

## 10. No CLI-level declaration refusal test, no `passesCompleted` assertion

**Changed.** Tests only. `tests/test_cli.py::test_refuses_a_journal_that_omits_a_spec_required_gate`
builds a witnessed corpus whose journal declares `oracle/licensed-parity` but not
the spec-required `rulespec/compile`; custody and binding both pass, and the
command exits `EXIT_FAIL` with
`the witnessed journal does not declare a gate the pinned spec requires:
'rulespec/compile'` on the declaration pass, `passesCompleted == ["custody",
"binding"]`, and nothing on stdout beyond the JSON. And
`::test_json_output_marks_gates_as_not_re_run` now asserts
`payload["passesCompleted"] == ["custody", "binding", "declaration"]`.

**Before / after.** These are coverage additions, not fixes — they pass on
`d542d59` too, which I verified by running them against an unmodified checkout of
that commit's `src`:

```
$ git archive d542d59 src | tar -x -C <scratch>
$ PYTHONPATH=<scratch>/src ./.venv/bin/python -c 'import receipt; print(receipt.__file__)'
<scratch>/src/receipt/__init__.py
$ PYTHONPATH=<scratch>/src ./.venv/bin/python -m pytest tests/test_cli.py \
      -k "omits_a_spec_required_gate or marks_gates_as_not_re_run"
2 passed
```

They are removal detectors for regressions the suite could not previously see.

## 11. CLI hard-coded outcome literals

**Changed.** `src/receipt/cli.py:34` (imports `NOT_RUN, PASS, WAIVED` from
`receipt.corpus`), `:138`, `:151`, `:154`.

**Tests.** `tests/test_cli.py::test_every_non_passing_outcome_is_marked_in_the_verdict`
— builds a corpus carrying one gate of *every* outcome in `GATE_OUTCOMES`, asserts
its own evidence table covers the whole vocabulary (so a fourth outcome fails the
test rather than slipping past it), and asserts each non-passing gate renders with
a bracketed marker while the passing one renders bare.

**Before / after.** A pure decoupling: the strings are identical, so the test
passes before and after. It is a removal detector for the coupling, in the same
class as finding 10.

## 12. Append-gate library leaked git stderr

**Changed.** `src/receipt/append_gate.py:469-475` (`check_append_only`) and
`:498-504` (`_manifest_at_ref`) — the only two lines touched in that file, as
asked. Both pipe stderr and fold a bounded (`[-1000:]`, matching the module
family's existing convention) diagnostic in *after* the existing message, which is
unchanged as the prefix.

The leak was also a violation of the module's own stated contract ("The library
owns no stdout or stderr", `append_gate.py:761`) which the differential harness
asserts via `_assert_port_silent`. Neither branch is reachable from that harness:
all 15 of its mutations leave both files present at the base ref, so `git show`
never fails there.

**Tests.** `tests/test_append_gate_diagnostics.py` (new) — a deliberately new,
narrowly named file so as not to collide with the append-gate lane working in
confinement. Parametrized over both call sites, against a plain git repository
whose base commit holds neither file.

**Before / after.**

```
before: E  AssertionError: the library wrote git's diagnostic to stderr
        E  assert "fatal: path ...t in 'HEAD'\n" == ''
        E    + fatal: path 'ledger/immutable_prefix.json' does not exist in 'HEAD'
        2 failed

after:  2 passed
```

---

## Docstrings updated where a claim changed

- `verify.py:27-31` — the fail-closed paragraph now names `SystemExit` and the
  `KeyboardInterrupt` exemption.
- `verify.py:239-241` — `load_spec` states the symlink requirement and why it is
  checked as supplied.
- `cli.py:18-21` — the `--json` contract paragraph names the `BaseException`
  boundary.
- `release_chain.py:19-26` — the module's claim that post-extraction additions
  "run beside the extracted checks without altering any of their refusals" was no
  longer complete: this round adds two refusals of its own. It now names them and
  states the narrower guarantee that is true — no extracted refusal was reworded
  or moved in the order they fire, and the new refusals cover inputs the upstream
  battery never presents.
- `release_chain.py:947-952` — `verify_receipt` states the single-descriptor read.

## Equivalence safety

- No existing refusal message was reworded. The append-gate change appends to one;
  that branch is unreachable from its differential battery (all 15 mutations leave
  both base files present).
- No existing refusal moved in the order it fires. The receipt snapshot is written
  after the TSA anchor pin and observer checks, so anchor refusals still precede
  receipt refusals; `_receipt_bytes` runs before the first OpenSSL call, so a
  corrupt-but-readable receipt still refuses at the same place with the same text.
- Nothing previously refused is now accepted. Everything new is a refusal.
- The new refusals cover inputs the upstream batteries never present: a spec that
  pins nothing, a receipt swapped or replaced mid-run, and a genTime finer than a
  microsecond.
- OpenSSL diagnostics for a corrupt receipt were probed empirically (finding 4)
  and do not contain the input path, so the snapshot cannot leak into a refusal
  the harness compares.
- `canonical.py` untouched; `pyproject.toml` untouched.

## Commits, in order

```
0e7b82e Refuse a spec that pins nothing                            (finding 1)
15d8a12 Never render a witness clause for zero witnesses           (finding 2)
936d456 Hold the fail-closed boundary against SystemExit           (finding 3)
00406a3 Read each RFC 3161 receipt once, not three times           (finding 4)
270b114 Refuse a genTime finer than a microsecond, and quote the fraction  (5)
a1b74e7 Name the commit a base-ref verdict compared against        (finding 6)
7e286fe Refuse a symlinked spec, before resolving it               (finding 7)
073f2f4 Print the head digest in full, not as a filename prefix    (finding 8)
5053d1c Require the three passes a verdict is made of              (finding 9)
76c1b7d Cover the declaration refusal from the command, and name the passes (10)
80e703c Take the gate outcome vocabulary from receipt.corpus       (finding 11)
e8c19db Fold git's diagnostic into the append gate's refusal       (finding 12)
9f9c8aa Describe the additions the module actually carries now     (docstring)
b018a16 Explain the outcome constants where they are compared      (comment)
6c82621 Normalize the blank lines around the new release-chain tests
```

Every commit ends with the required `Co-Authored-By: Claude Opus 5
<noreply@anthropic.com>` trailer.

## Things worth flagging

**Two commits on this branch are not mine.** `23a003b` ("fixup! Read each RFC
3161 receipt once, not three times") tracked the worktree's `.venv` symlink, and
`a7f314e` added the matching `.gitignore` entries. They were produced by an
auto-commit hook in this environment between my own commits, not by me. The net
state is correct — `.venv` is absent from `HEAD`'s tree (`git cat-file -p
HEAD^{tree} | grep -i venv` is empty), untracked, and ignored, and the
`.gitignore` addition is right (a worktree's `.venv` is a symlink, which the
existing `.venv/` pattern does not match). I did not rewrite history to squash
them, per the ground rules forbidding rebase.

**Not done, and why.** Nothing in the task was skipped. Two related things I
deliberately did not do:

- `verify_release_history_immutable` needed no change for finding 6 — it already
  resolves `base_ref` exactly once and threads the resolved commit through. Stated
  here rather than manufacturing a diff.
- `receipt_source.write_bytes(...)` can raise a bare `OSError` (disk full) rather
  than a `ReleaseChainError`. I left it, because the enclosing
  `tempfile.TemporaryDirectory` already behaves that way for the same class of
  failure, and because `run_verification`'s boundary now converts it to a FAIL
  verdict regardless. A library caller using `verify_receipt` directly would see
  the `OSError`.

**Not run, per the ground rules.** The four network-cloning equivalence modules
(`test_ledger_equivalence.py`, `test_append_gate_equivalence.py`,
`test_attest_equivalence.py`, `test_brier_witness_equivalence.py`). The
equivalence-safety reasoning above is what stands in for them until the
orchestrator runs them.

## Final suite

```
$ PYTHONPATH=$PWD/src ./.venv/bin/python -m pytest -q -p no:cacheprovider tests \
    --ignore=tests/test_ledger_equivalence.py \
    --ignore=tests/test_append_gate_equivalence.py \
    --ignore=tests/test_attest_equivalence.py \
    --ignore=tests/test_brier_witness_equivalence.py
346 passed in 122.62s (0:02:02)
```
