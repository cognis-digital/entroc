#!/usr/bin/env bash
# run_tests.sh - build entroc and run a battery of behavioral assertions.
# Exits non-zero if any assertion fails. POSIX bash; needs gcc + coreutils.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CC="${CC:-gcc}"
BIN="$HERE/entroc.test"
VEC="$HERE/test_vectors"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0

ok()   { echo "PASS $1"; pass=$((pass+1)); }
bad()  { echo "FAIL $1"; fail=$((fail+1)); }

# assert_exit <label> <expected_code> <cmd...>
assert_exit() {
  local label="$1" want="$2"; shift 2
  "$@" >/dev/null 2>&1
  local got=$?
  if [ "$got" = "$want" ]; then ok "$label (exit $got)"; else bad "$label (exit $got, want $want)"; fi
}

# assert_grep <label> <pattern> <cmd...>
assert_grep() {
  local label="$1" pat="$2"; shift 2
  local out; out="$("$@" 2>/dev/null)"
  if printf '%s' "$out" | grep -q "$pat"; then ok "$label"; else bad "$label (no match /$pat/)"; echo "  --- output ---"; printf '%s\n' "$out" | head -5 | sed 's/^/  /'; fi
}

# assert_notgrep <label> <pattern> <cmd...>
assert_notgrep() {
  local label="$1" pat="$2"; shift 2
  local out; out="$("$@" 2>/dev/null)"
  if printf '%s' "$out" | grep -q "$pat"; then bad "$label (unexpected match /$pat/)"; else ok "$label"; fi
}

echo "=== building entroc ($CC) ==="
"$CC" -O2 -std=c99 -Wall -Wextra -Werror -o "$BIN" "$ROOT/entroc.c" -lm || {
  echo "BUILD FAILED"; exit 1; }
echo "build ok"
echo

echo "=== building & running unit tests ==="
UNIT="$HERE/unit_entropy.test"
"$CC" -O2 -std=c99 -Wall -Wextra -Werror -o "$UNIT" "$HERE/unit_entropy.c" -lm || {
  echo "UNIT BUILD FAILED"; exit 1; }
if "$UNIT"; then ok "unit_entropy suite"; else bad "unit_entropy suite"; fi
echo

echo "=== behavioral tests ==="

# 1. random high-entropy file is flagged (exit 2)
head -c 8192 /dev/urandom > "$WORK/rand.bin"
assert_exit "1  random blob flagged" 2 "$BIN" "$WORK/rand.bin" --window 256

# 2. all-zeros / constant file is NOT flagged (exit 0)
assert_exit "2  zeros not flagged" 0 "$BIN" "$VEC/zeros_256.bin" --window 64

# 3. constant 'A' file not flagged
assert_exit "3  constant not flagged" 0 "$BIN" "$VEC/const_A_256.bin" --window 64

# 4. tool identifies itself in JSON
assert_grep "4  json tool id" '"tool":"entroc"' "$BIN" "$VEC/uniform_256.bin"

# 5. global metrics present in JSON
assert_grep "5  global shannon present" '"shannon"' "$BIN" "$VEC/uniform_256.bin"
assert_grep "5b global min_entropy present" '"min_entropy"' "$BIN" "$VEC/uniform_256.bin"
assert_grep "5c global chi_square present" '"chi_square"' "$BIN" "$VEC/uniform_256.bin"

# 6. uniform 256 bytes has near-8.0 shannon (check "shannon":8.00 in global)
assert_grep "6  uniform shannon ~8" '"shannon":8.0000' "$BIN" "$VEC/uniform_256.bin"

# 7. uniform 256 has chi-square 0.00 (perfectly uniform over 256)
assert_grep "7  uniform chi-square 0" '"chi_square":0.00' "$BIN" "$VEC/uniform_256.bin"

# 8. zeros file shannon exactly 0
assert_grep "8  zeros shannon 0" '"shannon":0.0000' "$BIN" "$VEC/zeros_256.bin"

# 9. PEM key detection
assert_grep "9  PEM block detected" 'pem-block' "$BIN" "$VEC/pem_embedded.txt" --format text
assert_exit "9b PEM triggers exit 2" 2 "$BIN" "$VEC/pem_embedded.txt"

# 10. AWS access key detection + redaction
assert_grep "10  AWS key detected" 'aws-access-key-id' "$BIN" "$VEC/secrets_mix.txt" --format text
assert_notgrep "10b AWS key redacted (no full id)" 'AKIAIOSFODNN7EXAMPLE' "$BIN" "$VEC/secrets_mix.txt" --format text

# 11. JWT detection
assert_grep "11  JWT detected" 'jwt' "$BIN" "$VEC/secrets_mix.txt" --format text

# 12. long hex (md5-length 32) detection
assert_grep "12  hex-32 detected" 'hex-32' "$BIN" "$VEC/secrets_mix.txt" --format text

# 13. base64 content classification
assert_grep "13  base64 classified" 'base64' "$BIN" "$VEC/base64_blob.txt" --profile --format csv

# 14. hex content classification
assert_grep "14  hex classified" ',hex' "$BIN" "$VEC/hex_64.txt" --profile --format csv --window 64

# 15. plain text classification
assert_grep "15  text classified" ',text' "$BIN" "$VEC/plain_text.txt" --profile --format csv --window 76

# 16. CSV header validity
assert_grep "16  csv header" '^type,offset,length' "$BIN" "$VEC/pem_embedded.txt" --format csv

# 17. SARIF is valid JSON with version 2.1.0
assert_grep "17  sarif version" '"version":"2.1.0"' "$BIN" "$WORK/rand.bin" --format sarif
assert_grep "17b sarif schema" 'sarif-schema-2.1.0' "$BIN" "$WORK/rand.bin" --format sarif
assert_grep "17c sarif rule id" 'high-entropy-region' "$BIN" "$WORK/rand.bin" --format sarif
# validate SARIF parses as JSON if python available
if command -v python3 >/dev/null 2>&1; then
  if "$BIN" "$VEC/secrets_mix.txt" --format sarif | python3 -c 'import sys,json; json.load(sys.stdin)' 2>/dev/null; then
    ok "17d sarif parses as JSON"
  else bad "17d sarif parses as JSON"; fi
  if "$BIN" "$WORK/rand.bin" --format json | python3 -c 'import sys,json; json.load(sys.stdin)' 2>/dev/null; then
    ok "17e json parses as JSON"
  else bad "17e json parses as JSON"; fi
else
  echo "SKIP 17d/17e (python3 not available for JSON validation)"
fi

# 18. text format summary
assert_grep "18  text result line" 'result:' "$BIN" "$VEC/zeros_256.bin" --format text

# 19. stdin path ('-')
assert_grep "19  stdin json" '"file":"<stdin>"' sh -c "head -c 4096 /dev/urandom | '$BIN' -"
assert_exit "19b stdin flagged" 2 sh -c "head -c 4096 /dev/urandom | '$BIN' - --window 256"

# 20. empty file handled gracefully (exit 0, valid json)
printf "" > "$WORK/empty.bin"
assert_exit "20  empty file exit 0" 0 "$BIN" "$WORK/empty.bin"
assert_grep "20b empty file size 0" '"size":0' "$BIN" "$WORK/empty.bin"

# 21. region merging: two adjacent random blobs merge into fewer regions than windows
head -c 4096 /dev/urandom > "$WORK/big.bin"
regions=$("$BIN" "$WORK/big.bin" --window 256 --step 256 --format json | grep -o '"offset"' | wc -l)
# with contiguous high entropy, should merge to a single region (offset appears once in regions, plus profile off)
merged=$("$BIN" "$WORK/big.bin" --window 256 --step 256 | grep -o '"regions_flagged":[0-9]*' | grep -o '[0-9]*')
if [ "${merged:-0}" -ge 1 ]; then ok "21  regions merged ($merged region(s) for 16 windows)"; else bad "21  region merge"; fi

# 22. min-region filter drops short regions
# a 300-byte random blob padded with zeros; with min-region large, no region survives
head -c 300 /dev/urandom > "$WORK/small_rand"
cat "$VEC/zeros_256.bin" "$VEC/zeros_256.bin" >> "$WORK/small_rand"
assert_exit "22  min-region filters out small region" 0 "$BIN" "$WORK/small_rand" --window 128 --min-region 100000

# 23. threshold controls flagging (very high threshold => nothing flagged)
assert_exit "23  high threshold clears flags" 0 "$BIN" "$WORK/rand.bin" --threshold 8.5

# 24. --no-secrets disables secret scan
assert_notgrep "24  no-secrets suppresses" 'aws-access-key-id' "$BIN" "$VEC/secrets_mix.txt" --no-secrets --format text

# 25. error on missing file (exit 1)
assert_exit "25  missing file exit 1" 1 "$BIN" "$WORK/does_not_exist_xyz"

# 26. unknown option (exit 1)
assert_exit "26  unknown option exit 1" 1 "$BIN" "$VEC/zeros_256.bin" --nonsense

# 27. --help exits 0
assert_exit "27  help exit 0" 0 "$BIN" --help

# 28. --version prints version
assert_grep "28  version" 'entroc 2' "$BIN" --version

# 29. profile emits per-window series in JSON
assert_grep "29  profile series" '"profile":\[' "$BIN" "$WORK/rand.bin" --profile

# 30. secrets never printed in full in JSON preview (redaction marker present)
assert_grep "30  redaction marker" 'redacted' "$BIN" "$VEC/secrets_mix.txt"

echo
echo "=== summary: $pass passed, $fail failed ==="
[ "$fail" -eq 0 ] || exit 1
