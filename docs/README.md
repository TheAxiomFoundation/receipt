# API reference build

The reference is rendered by pdoc from the module docstrings — the
docstrings are the documentation; nothing here duplicates them. The
README at the repository root remains the front door.

`pdoc-template/` restyles pdoc's default template with the design
tokens from axiom-foundation.org, where the reference is served at
[axiom-foundation.org/receipt/api](https://axiom-foundation.org/receipt/api/)
(a rewrite of this repository's GitHub Pages deployment).

Build locally:

```bash
uv venv && uv pip install . pdoc
uv run pdoc receipt --docformat restructuredtext -t docs/pdoc-template \
    --favicon https://axiom-foundation.org/favicon.svg \
    -e "receipt=https://github.com/TheAxiomFoundation/receipt/blob/main/src/receipt/" \
    -o _site
```

`.github/workflows/docs.yml` runs the same build on pushes to main and
deploys it to GitHub Pages. No version numbers appear in the rendered
pages or this file: the reference always describes the commit it was
built from.
