#!/usr/bin/env bash
# Demo 5: emit SARIF 2.1.0 so entroc findings can be uploaded to GitHub code
# scanning or any SARIF-consuming dashboard.
. "$(dirname "$0")/_common.sh"

echo "# SARIF 2.1.0 output for the leaked-secrets sample."
"$ENTROC" "$EX_DIR/secrets_leak.env" --format sarif > /tmp/entroc.sarif
echo "wrote /tmp/entroc.sarif ($(wc -c < /tmp/entroc.sarif) bytes)"
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import sys,json; d=json.load(open("/tmp/entroc.sarif")); print("valid SARIF, version", d["version"], "-", len(d["runs"][0]["results"]), "results")'
else
  head -c 200 /tmp/entroc.sarif; echo
fi
echo "DEMO OK"
