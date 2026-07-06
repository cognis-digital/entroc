#!/usr/bin/env bash
# Demo 3: hunt for leaked credentials in a .env file (AWS key, JWT, hash).
. "$(dirname "$0")/_common.sh"

echo "# .env file scan. entroc identifies AWS access-key id, a JWT, and a"
echo "# 32-hex token -- all previews redacted so the scan output is safe to log."
run "$EX_DIR/secrets_leak.env" --format csv
code=$?
echo
echo "entroc exit code: $code"
[ "$code" = "2" ] || { echo "expected findings"; exit 1; }
echo "DEMO OK"
