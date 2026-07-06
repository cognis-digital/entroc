#!/usr/bin/env bash
# Demo 4: entropy profile + ASCII sparkline on a file whose entropy varies
# across its length (readable header then a packed/random tail).
. "$(dirname "$0")/_common.sh"

TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
{
  printf 'MZ header: readable strings and metadata section.......................\n'
  head -c 4096 /dev/urandom
} > "$TMP"

echo "# Per-window entropy profile (CSV) + sparkline to stderr."
echo "# Watch entropy climb from the text header into the random tail."
run "$TMP" --window 128 --step 128 --profile --sparkline --format csv | head -20
echo
echo "DEMO OK"
