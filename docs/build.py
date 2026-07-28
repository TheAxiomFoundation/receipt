#!/usr/bin/env python3
"""Build the API reference into _site/ (or a given output directory).

Wraps pdoc's API for one build-time adjustment plus a fail-closed check,
so machine trivia never reaches the rendered pages:

- Function parameter defaults that are absolute filesystem paths
  (resolved at import time, like ``append_gate.CODE_ROOT``) are rebound,
  in the documentation process only, to a symbol that renders as the
  module constant's own name. Signatures keep the parameter's
  optionality visible (``trusted_code_root: pathlib.Path = CODE_ROOT``)
  instead of embedding the build machine's filesystem layout. The
  installed package is untouched.
- After rendering, every page is swept for the repository root and for
  absolute-path reprs; any hit fails the build. (Module-level variables
  get the same protection from the ``default_value`` macro override in
  ``pdoc-template/module.html.jinja2``; this sweep is the backstop for
  both.)

Run from the repository root:

    uv run --no-dev --with pdoc==16.0.0 python docs/build.py
"""

from __future__ import annotations

import html
import importlib
import pathlib
import pkgutil
import sys
import types

import pdoc
import pdoc.render

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE_DIR = pathlib.Path(__file__).resolve().parent / "pdoc-template"


class _SourceName:
    """Stands in for a default value; renders as the source constant's name."""

    def __init__(self, name: str) -> None:
        self._name = name

    def __repr__(self) -> str:
        return self._name


def _symbol_for(module: types.ModuleType, value: object) -> _SourceName:
    for name, attr in vars(module).items():
        if not name.startswith("_") and attr is value:
            return _SourceName(name)
    return _SourceName("...")


def _rebind_absolute_path_defaults(module: types.ModuleType) -> None:
    for fn in vars(module).values():
        if not isinstance(fn, types.FunctionType) or fn.__module__ != module.__name__:
            continue
        if fn.__defaults__:
            fn.__defaults__ = tuple(
                _symbol_for(module, d)
                if isinstance(d, pathlib.PurePath) and d.is_absolute()
                else d
                for d in fn.__defaults__
            )
        if fn.__kwdefaults__:
            fn.__kwdefaults__ = {
                k: _symbol_for(module, d)
                if isinstance(d, pathlib.PurePath) and d.is_absolute()
                else d
                for k, d in fn.__kwdefaults__.items()
            }


def main() -> None:
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "_site")

    import receipt

    modules = [receipt] + [
        importlib.import_module(f"receipt.{m.name}")
        for m in pkgutil.iter_modules(receipt.__path__)
        if not m.name.startswith("_")
    ]
    for module in modules:
        _rebind_absolute_path_defaults(module)

    pdoc.render.configure(
        docformat="restructuredtext",
        template_directory=TEMPLATE_DIR,
        favicon="https://axiom-foundation.org/favicon.svg",
        edit_url_map={
            "receipt": "https://github.com/TheAxiomFoundation/receipt/blob/main/src/receipt/"
        },
    )
    pdoc.pdoc("receipt", output_directory=out)

    leaks = []
    needles = [str(REPO_ROOT), html.escape(str(REPO_ROOT))] + [
        f"PosixPath({quote}/" for quote in ("&#39;", "&#x27;", "'")
    ]
    for page in sorted(out.rglob("*.html")):
        text = page.read_text()
        for needle in needles:
            if needle in text:
                leaks.append(f"{page}: {needle!r}")
    if leaks:
        sys.exit(
            "absolute build paths leaked into the rendered pages:\n" + "\n".join(leaks)
        )


if __name__ == "__main__":
    main()
