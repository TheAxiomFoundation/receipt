# M3 round-1 design fold

## State

Review read in full; F1 reproduced before rewriting. Design record only; no production or test changes, installation, network, push, or subagents.

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

## Next

- Fold F1 using one shared child with explicitly named context-scoped availability, a separate deliberate-correction gate, and unchanged independent-owner compatibility.
- Fold F2, scope, precision, and risk corrections without weakening confirmed requirements.
- Validate the documentation and unchanged code tree; commit each coherent step.
- Write the final report here under `## Fold report` because no `-o` pathname is visible.
