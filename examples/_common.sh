#!/usr/bin/env bash
# _common.sh - locate/build the entroc binary for demos. Sourced by demos.
set -u
EX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
ROOT="$(cd "$EX_DIR/.." && pwd)"
ENTROC="${ENTROC_BIN:-$ROOT/entroc}"
if [ ! -x "$ENTROC" ]; then
  # try to build (respects $CC)
  "${CC:-gcc}" -O2 -std=c99 -Wall -Wextra -o "$ROOT/entroc" "$ROOT/entroc.c" -lm \
    || { echo "cannot build entroc"; exit 1; }
  ENTROC="$ROOT/entroc"
fi
run() { echo "\$ entroc $*"; "$ENTROC" "$@"; }
