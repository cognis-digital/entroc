#!/usr/bin/env bash
# run_all.sh - run every demo; exit non-zero if any demo fails.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
fail=0
for demo in "$HERE"/0*.sh; do
  echo "############################################################"
  echo "# $(basename "$demo")"
  echo "############################################################"
  if bash "$demo"; then :; else echo "DEMO FAILED: $demo"; fail=1; fi
  echo
done
[ "$fail" -eq 0 ] && echo "ALL DEMOS OK" || { echo "SOME DEMOS FAILED"; exit 1; }
