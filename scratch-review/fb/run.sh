#!/bin/bash
# Run the commit's new tests in the before and after trees.
R=/Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-crash-refusal-review
C=$1
D=$R/scratch-review/fb/$C
K=$(paste -sd'|' "$D/names.txt" | sed 's/|/ or /g')
FILES=$(cat "$D/files.txt" | tr '\n' ' ')
for side in before after; do
  ( cd "$D/$side" && timeout ${FB_TIMEOUT:-900} "$R/.venv/bin/python" -m pytest -q -p no:cacheprovider -p no:warnings --tb=line -k "$K" $FILES > "$D/$side.out" 2>&1; echo "rc=$?" >> "$D/$side.out" )
  echo "$C $side: $(grep -E ' passed| failed| error' "$D/$side.out" | tail -1) $(tail -1 "$D/$side.out")"
done
