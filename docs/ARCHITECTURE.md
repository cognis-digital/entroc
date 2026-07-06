# entroc architecture

`entroc` is a single translation unit (`entroc.c`, C99, stdlib + libm). No
threads, no third-party code, no dynamic plugins. It reads bytes, computes
statistics over sliding windows, classifies and merges, scans for secret
shapes, and serializes results.

## Pipeline

```
input (file or stdin)
   -> read_stream()            whole input into a growable buffer
   -> global metrics           shannon / min-entropy / chi-square over all bytes
   -> window scan              for each window at `off` (step apart):
        entroc_shannon()         Shannon entropy   (0..8 bits/byte)
        entroc_min_entropy()     min-entropy H_inf = -log2(max p_i)
        entroc_chi_square()      Pearson chi-square vs uniform-over-256
        entroc_classify()        content class (text/base64/hex/high-entropy/packed/binary)
        flagged = shannon >= threshold
   -> region merge             adjacent flagged windows -> contiguous [start,end)
        drop regions shorter than --min-region
   -> entroc_scan_secrets()    whole-buffer secret shapes (PEM/AWS/JWT/hex/base64)
   -> serialize                json | csv | text | sarif   (+ optional profile/sparkline)
   -> exit                     2 if any region or secret flagged, else 0; 1 on error
```

## Entropy metrics

For a window of `n` bytes with byte-value counts `f[b]` and `p_b = f[b]/n`:

- **Shannon** `H = -sum p_b log2 p_b`. Range `0` (constant) to `8` (every byte
  value equally likely). This is the classic "how compressible / how random"
  measure. Compressed and encrypted data sit near 8; plain English text is
  ~4-4.5; a constant run is 0.
- **Min-entropy** `H_inf = -log2(max_b p_b)`. Bounds the *most predictable*
  symbol; always `<= Shannon`. Useful because a distribution can have high
  Shannon entropy yet still have one dominant byte (a weak-randomness tell).
- **Chi-square** vs uniform: expected count per bucket is `n/256`,
  `chi = sum (f[b] - n/256)^2 / (n/256)`. Near 0 means very uniform; large
  means skewed. A goodness-of-fit sanity check on "is this really random".

All three are exact frequency-table computations, not sampled estimates.

## Content classification

`entroc_classify()` combines character-class ratios (base64-alphabet, hex,
printable, alphanumeric) with the window's Shannon entropy. Ordering matters:
hex is the most specific test, then base64, then printable text, then the
non-text tiers split by entropy (`>=7.5` high-entropy, `>=6.5` packed, else
binary). Thresholds are conservative to keep false positives low.

## Secret detection

`entroc_scan_secrets()` runs over the whole buffer (not per window, so a secret
straddling a window boundary is still caught):

- **PEM blocks** - literal `-----BEGIN ` ... `-----END ...-----` scan.
- **AWS access-key ids** - `AKIA`/`ASIA` + 16 uppercase-alnum, with boundary
  checks.
- **JWT** - `eyJ` followed by three base64url segments split by `.`.
- **Long hex runs** - `>= 32` hex chars with entropy `>= 3.0` (labels 32/40/64
  as md5/sha1/sha256 lengths).
- **Base64 key material** - `>= 40` base64 chars with entropy `>= 4.5`.

Every finding gets a **redacted preview**: at most the first 4 visible bytes
followed by `...[redacted]`. The tool never prints a full secret.

## Complexity & memory model

- Time: window scan is `O(N/step * window)` in the worst case because each
  window recomputes its frequency table from scratch (`O(window)` per window).
  For the default `step == window`, that is `O(N)`. Secret scanning is a single
  `O(N)` pass with bounded lookahead. Global metrics are one `O(N)` pass.
- Memory: the whole input is held in RAM (one growable buffer, doubling
  growth), plus `O(#windows)` for the window array and `O(#regions + #secrets)`
  for findings. There is no per-byte allocation.
- The frequency tables are fixed 256-entry stack arrays; no heap churn in the
  hot loop.

## Portability

Strictly C99 stdlib + `libm` (`log2`). The only platform-specific code is a
guarded `_setmode(_fileno(stdin), _O_BINARY)` under `#ifdef _WIN32` so stdin is
read in binary mode on Windows. Everything else - `fopen`/`fread`, `malloc`,
`printf` with `%zu` - is standard. See `docs/USAGE.md` for the portability audit.
