#!/usr/bin/env bash
# bench.sh - measure entroc throughput on generated files of known sizes.
# Prints real MB/s. Label the machine yourself when copying numbers into docs.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CC="${CC:-gcc}"
BIN="$ROOT/entroc"

"$CC" -O2 -std=c99 -Wall -Wextra -o "$BIN" "$ROOT/entroc.c" -lm || { echo "build failed"; exit 1; }

echo "entroc benchmark"
echo "cc:     $("$CC" --version | head -1)"
echo "uname:  $(uname -a 2>/dev/null || echo 'n/a')"
echo "date:   $(date -u 2>/dev/null)"
echo

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

bench_one() {
  local mb="$1" win="$2"
  local f="$TMP/data_${mb}mb.bin"
  head -c $((mb*1024*1024)) /dev/urandom > "$f"
  # time 3 runs, take best
  local best=""
  for _ in 1 2 3; do
    local start end el
    start=$(date +%s.%N)
    "$BIN" "$f" --window "$win" --step "$win" >/dev/null 2>&1
    end=$(date +%s.%N)
    el=$(awk "BEGIN{print $end-$start}")
    if [ -z "$best" ] || awk "BEGIN{exit !($el < $best)}"; then best="$el"; fi
  done
  awk -v mb="$mb" -v t="$best" 'BEGIN{ printf "%6d MB  win=%s  %7.3f s  %8.1f MB/s\n", mb, "'"$win"'", t, mb/t }'
}

echo "size      window      time        throughput"
bench_one 8   256
bench_one 32  256
bench_one 64  256
bench_one 64  4096
echo
echo "Note: throughput scales with window/step (smaller windows = more passes)."
