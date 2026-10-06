#!/bin/bash
# Build before (parent src + commit tests) and after (commit src + tests) trees
# for one commit, and list the test functions that commit adds.
set -e
R=/Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-crash-refusal-review
C=$1
D=$R/scratch-review/fb/$C
rm -rf "$D"; mkdir -p "$D/before" "$D/after"
cd "$R"
git archive "$C^" | tar -x -C "$D/before"
rm -rf "$D/before/tests"
git archive "$C" tests | tar -x -C "$D/before"
git archive "$C" | tar -x -C "$D/after"
git diff "$C^" "$C" --name-only -- tests/ | grep '^tests/test_' > "$D/files.txt" || true
git diff "$C^" "$C" -- tests/ | grep -E '^\+(async )?def test_' | sed -E 's/^\+(async )?def (test_[A-Za-z0-9_]+).*/\2/' | sort -u > "$D/names.txt"
echo "$C: $(wc -l < "$D/names.txt") new tests in $(tr '\n' ' ' < "$D/files.txt")"
