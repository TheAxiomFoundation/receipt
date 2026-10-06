# 0.7: shared tree policy and typed evidence

Scope for the release after 0.6.0, named by the whole-package review that preceded the 0.6.0 tag (GPT-6 Astra, 2026-09-05, verdict on #58) and adopted by the maintainer. This issue records the scope; it does not schedule it.

## What 0.7 changes

1. **One protected-tree policy.** Names (both repertoires), modes, ancestor aliases and attributes are applied once, by one module, producing a protected view that every verifier consumes. Today `verify.py`, `release_chain.py` and `append_gate.py` each assemble their own screens; the 0.6.0 pre-tag finding where the base-chain helper accepted an empty-tree alias the composed command refused later is the cost of that shape.
2. **Attribute semantics as a fixed, versioned policy.** Both readings (exact and ASCII-folded) evaluated, a transform under either refused; no repository setting is an input. Landed as a pre-tag correction; 0.7 moves it into the shared policy.
3. **One repository context.** The frozen process environment, the batch child, the object cache and the work budget belong to one context; candidate and base are immutable selected views over it, instead of two snapshots sharing mutable budget linkage.
4. **A deterministic journal parser** separated from append orchestration: observation-schema validation as immutable policy, generic byte-prefix and history comparison as orchestration.
5. **An immutable evidence core.** Custody, binding, declaration and append results as frozen typed records; the entry-comparison helper renamed and typed as metadata evidence so it cannot be mistaken for a payload audit.
6. **Historical commentary moved to design records.** The forensic review history now carried in docstrings (about 4,100 lines) goes to the receipts directory; docstrings state the contract.

## What 0.7 keeps exactly

Every public refusal text (PolicyEngine/chronicle's shim matches on it), the 108 differential harness cases with their two legs and zero-skip rule, the executable spec and its pin ladder, the direct directory adapter and its guards, the OpenSSL counting and PEM handling, the CLI's emission machinery, and the measured floors (Python 3.11, git 2.36 and 2.50 with SHA1_DC for the store check, OpenSSL 3.0, POSIX with `O_NOFOLLOW`).

## Not in 0.7

A declarative spec, closed typed refusal codes, a smaller public API and reported evaluation time are a 1.0 conversation, and it starts with migrating Chronicle's text matching. Replacing the executable spec is a trust decision, not a cleanup.

## Method

Each step lands with a consumer import and call-site census, all compatibility suites green, and the review every receipt PR gets (a maintainer read plus an independent model round). The review's estimate for the whole of 0.7 is two to four engineering weeks plus one to two weeks of overlapping review and consumer validation for one implementation lane and one peer; an estimate, not a commitment.
