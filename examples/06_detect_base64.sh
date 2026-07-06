#!/usr/bin/env bash
# Demo 6: content-class detection -- label a base64 payload vs a hex string.
. "$(dirname "$0")/_common.sh"

echo "# base64 payload -> classified 'base64'"
run "$EX_DIR/base64_payload.txt" --window 116 --profile --format csv
echo
echo "# stdin also works: pipe hex and see it classified 'hex'"
printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
  | run - --window 64 --profile --format csv
echo
echo "DEMO OK"
