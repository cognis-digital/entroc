#!/usr/bin/env sh
# install.sh - build entroc and copy it to $PREFIX/bin (default /usr/local).
# POSIX sh. Needs a C compiler (cc/gcc/clang) and libm.
set -eu

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
HERE="$(cd "$(dirname "$0")" && pwd)"

CC="${CC:-}"
if [ -z "$CC" ]; then
  for c in cc gcc clang; do
    if command -v "$c" >/dev/null 2>&1; then CC="$c"; break; fi
  done
fi
[ -n "$CC" ] || { echo "install.sh: no C compiler found (set CC=)"; exit 1; }

echo "building entroc with $CC ..."
"$CC" -O2 -std=c99 -Wall -Wextra -o "$HERE/entroc" "$HERE/entroc.c" -lm

echo "installing to $BINDIR ..."
mkdir -p "$BINDIR"
if [ -w "$BINDIR" ]; then
  cp "$HERE/entroc" "$BINDIR/entroc"
else
  echo "note: $BINDIR not writable; retrying with sudo"
  sudo cp "$HERE/entroc" "$BINDIR/entroc"
fi
echo "done: $BINDIR/entroc"
"$BINDIR/entroc" --version
