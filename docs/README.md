# API reference build

The reference is rendered by pdoc from the module docstrings — the
docstrings are the documentation; nothing here duplicates them. The
README at the repository root remains the front door.

`pdoc-template/` restyles pdoc's default template with the design
tokens from axiom-foundation.org, where the reference is served at
[axiom-foundation.org/receipt/api](https://axiom-foundation.org/receipt/api/)
(a rewrite of this repository's GitHub Pages deployment).

Build locally (the same pinned invocation CI runs):

```bash
uv run --no-dev --with pdoc==16.0.0 python docs/build.py _site
```

`build.py` wraps pdoc's API: it rebinds absolute-path values —
parameter defaults to their source constant's name, module constants to
`...` — so no generated asset embeds a build machine's filesystem
layout, and it fails the build if an absolute build path leaks into any
rendered page or the search index.

`.github/workflows/docs.yml` runs the same build on pushes to main and
deploys it to GitHub Pages. No receipt version number appears in the
rendered pages or this file: the reference always describes the commit
it was built from.
