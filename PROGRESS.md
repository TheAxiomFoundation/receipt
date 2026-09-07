# M3 round-1 design fold

## State

Fold complete and validated. Design record only; no production or test changes, installation, network, push, or subagents.

## Done

- Read all 179 lines of `docs/design/REVIEW-r1-m3.md` and the supplied packed-store driver.
- Confirmed starting HEAD `0f014d5` includes the committed review beside the record at `4e97711`.
- Identified the driver as pack removal, with replacement and other permutations requiring separate evidence.
- Ran the supplied driver unchanged with `.venv/bin/python` (Python 3.14.4, Git 2.53.0), exit 0:

  ```json
  {"different_pids": true, "independent_entered_cold_transport": {"exception": "receipt.snapshot.SnapshotError", "message": "object c2981a9931b383b5eb128dc5e3505654ab5269b6 is unavailable"}, "removed_pack_files": 3, "warm_transport_cold_python_headers": {"value": "payload\n"}}
  ```

- Ran 48 additional raw-index cases: loose-only, packed-only, packed-plus-loose; unchanged, removal, replacement retaining/omitting the target; both cold, A warm, B warm, both warm. Cleared Python headers for both readers before observation. Packed-only removal and replacement omitting the target return payload only from warmed readers; loose removal refuses from both; unchanged/retained-target/redundant-loose controls return payload from both. All 48 pairs had different PIDs. Temporary repositories were cleaned up.
- Verified `src`/`tests` equal both `9dc1f85` and offline `origin/main` (`f797f72`, #72); v0.6.0 differs in 54 files. This branch includes M1 through #71; #72 changes the changelog only.
- Located PR3b's correction in merged commit `28f5014` (#68), PR5's callable correction in `041e88b` and subclass preservation in `bcfa49a`/`0f87f7d` (#70). The committed M1 design reviews cover the earlier design gates, not these later implementation findings.
- Folded F1: retained one shared child, named context-scoped availability as a separate deliberate correction (A7), and required approval before PR2/PR3a plus implementation validation. Recorded possible PASS/refusal, phase and counter differences; preserved authentication, admission, D1 and independent legacy owners.
- Added exact driver output and 48-case matrix method/results to the design record. Expanded D7/PR1/PR3a/risk 7 to include Git state, packed/loose objects, warmth, replacement, tamper and controls.
- Corrected risks: 7 critical until approved/validated; 10 memory-only medium; new 12 physical/read-once high; 11 consumer bytes high; 5 requires the full new-finalizer post-pass fault matrix.
- Folded F2 and scope: removed session/output narration, used factual contract wording, recorded the post-M1 baseline once at the top, supplied current full M1 record/review paths and exact merged correction locators, attributed maintainer reads to issue #62's Method, and made D16's test range precise. Kept proposals and historical execution/collection evidence distinct.
- Validated 148 explicit locator groups in 39 current files; all referenced source/test bytes and 19 golden JSON files match `9dc1f85`. Verified the cited correction commits belong to the stated merges.
- Compiled both embedded Python examples and reran the second directly from the record, exit 0. D1, D3/D9/D11, D6 and D12 reproduced; the fixture-dependent initial tree-byte count was 375.
- `.venv/bin/pytest --collect-only -q`: 3,297 collected, exit 0 (0.20 s); no full-suite execution claim. `git diff --check` passed.

## Next

- No fold work remains. Future implementation requires separate D1/A7 approval and the recorded compatibility, consumer and finalizer gates.

## Fold report

- **F1:** reproduced the supplied driver unchanged before rewriting. Python 3.14.4 / Git 2.53.0, exit 0:

  ```json
  {"different_pids": true, "independent_entered_cold_transport": {"exception": "receipt.snapshot.SnapshotError", "message": "object c2981a9931b383b5eb128dc5e3505654ab5269b6 is unavailable"}, "removed_pack_files": 3, "warm_transport_cold_python_headers": {"value": "payload\n"}}
  ```

- **Transport:** chose one shared child with **context-scoped availability**, a deliberate correction gated separately as A7 before PR2/PR3a. It admits authenticated payload and possible continued PASS where today's independently entered cold process refuses after pack removal/replacement; downstream phase/work differences must be recorded. Authentication, per-account admission, D1 and the legacy independent-owner boundary remain required. The 48-case extension reproduced pack replacement omitting the target and both asymmetric warmth permutations; loose removal refused from both readers, while retained-target and duplicate-loose controls succeeded.
- **F2 and scope:** removed session/output narration, made contract wording factual, added exact historical review/merged-commit locators and D16's full test range, corrected the maintainer-read attribution, and documented this checkout's post-M1 code baseline (#64–#72), not v0.6.0. Proposals, collected counts and executed results remain distinct.
- **Risks:** 7 is critical pending approval/validation; 10 retains memory at medium; physical/read-once bypass is separate high risk 12; consumer-byte risk 11 is high; risk 5 requires the full post-pass finalizer fault matrix.
- **Validation:** 148 locator groups checked; 19 goldens unchanged; embedded probes reproduced; 3,297 tests collected only. Production/tests unchanged, review retained committed beside the folded record, and no push. This is the output-file fallback because no `-o` path was supplied.
