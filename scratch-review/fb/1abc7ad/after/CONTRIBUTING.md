# Contributing

receipt verifies the custody of agent-produced records. Its whole value is
that a skeptic can trust a green verdict, so contributions are held to a
verification-first standard: every behavior change ships with a test, and the
refusal battery is the heart of the suite — each way a published corpus can be
wrong has a test that proves the package refuses it.

## Development

Requires Python 3.11+, `git`, and `openssl`.

```bash
uv venv && uv pip install -e ".[dev]"
uv run pytest
```

The differential harnesses (`tests/test_*_equivalence.py`) pin their upstream
source files by SHA-256 and run the unmodified upstream verifier as an oracle;
they are the evidence that extracted verifiers still match the systems they came
from. Do not weaken a normalization or skip a case to make one pass — if the
behavior genuinely diverged, that is the finding.

## Reporting a problem

Open an issue at
[github.com/TheAxiomFoundation/receipt/issues](https://github.com/TheAxiomFoundation/receipt/issues).
A verification bug that lets a wrong corpus pass, or a correct corpus refuse, is
the highest-priority class — include the spec, the journal, and the tree layout
that reproduces it.

## Pull requests

- One coherent change per PR, with the test that fails before it and passes
  after.
- Run the full suite (`uv run pytest`) before opening.
- Security-relevant changes to the verification path get an independent review
  before merge.

## License

By contributing you agree your contributions are licensed under Apache-2.0, the
license of this repository.
