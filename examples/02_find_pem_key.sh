#!/usr/bin/env bash
# Demo 2: find a PEM private key embedded in an otherwise-benign config file.
. "$(dirname "$0")/_common.sh"

echo "# Config file with an embedded EC PRIVATE KEY. entroc finds the PEM block"
echo "# and the base64 key material -- previews are REDACTED."
run "$EX_DIR/config_with_key.txt" --format text
code=$?
echo
echo "entroc exit code: $code"
[ "$code" = "2" ] || { echo "expected a finding"; exit 1; }
echo "DEMO OK"
