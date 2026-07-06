#!/usr/bin/env bash
# Demo 1: scan a high-entropy random blob. entroc flags it (exit 2), but this
# demo wraps it so the demo itself exits 0.
. "$(dirname "$0")/_common.sh"

TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
head -c 8192 /dev/urandom > "$TMP"

echo "# A random blob is high-entropy -> flagged as one merged region."
run "$TMP" --window 256 --format text
code=$?
echo
echo "entroc exit code: $code (2 = flagged, as expected for random data)"
[ "$code" = "2" ] || { echo "unexpected"; exit 1; }
echo "DEMO OK"
