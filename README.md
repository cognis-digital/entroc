# entroc

**Windowed entropy scanner & blob/secret triage** — C99, stdlib + libm only, zero dependencies.

[![ci](https://github.com/cognis-digital/entroc/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/entroc/actions/workflows/ci.yml)
![lang](https://img.shields.io/badge/lang-C99-informational)
![deps](https://img.shields.io/badge/deps-none-2ea043)
![license](https://img.shields.io/badge/license-COCL%201.0-2ea043)

`entroc` slides a window across a file (or stdin), computes **three** entropy
metrics per window, labels each window's likely content class, merges the
flagged windows into contiguous regions, and scans the whole buffer for
**embedded secrets** — then emits JSON, CSV, human text, or **SARIF 2.1.0**.
It exits non-zero when it finds something, so it drops straight into a pipeline.

Scope is **defensive / triage / OSINT**. Secret previews are always redacted;
`entroc` never prints a full key.

## Why windowed entropy

A single file-wide entropy number hides everything interesting. Real triage
questions are *local*:

- **Malware / RE triage** — where inside this binary is the packed or encrypted
  payload? Whole-file entropy of a mostly-benign PE is unremarkable; a 4 KB
  window over the packed section spikes to ~8.0. Windowing localizes it.
- **Secret hunting** — a leaked private key or API token is a small
  high-entropy island in an ocean of readable config. entropy + shape
  detection finds it and hands you the byte offset.
- **Blob classification** — is that opaque field base64, hex, compressed, or
  raw ciphertext? Character-class ratios plus entropy answer it per window.

## Features

- **Three entropy metrics**, per-window and file-global:
  - Shannon entropy (0..8 bits/byte)
  - min-entropy `H_inf = -log2(max p_i)`
  - Pearson chi-square vs a uniform byte distribution
- **Content classification** per window: `text` / `base64` / `hex` /
  `high-entropy` (compressed/encrypted) / `packed-binary` / `binary`.
- **Embedded-secret detection**: PEM blocks (`-----BEGIN … KEY/CERTIFICATE-----`),
  AWS access-key ids (`AKIA…`/`ASIA…`), JWTs (`eyJ…`), long hex runs
  (md5/sha1/sha256 lengths), base64 key material — reported with offset and a
  **redacted** preview.
- **Region merging**: adjacent flagged windows collapse into contiguous
  `[start, end)` regions; `--min-region` drops the noise.
- **Entropy profile** (`--profile`) — per-window series you can graph — plus an
  optional ASCII **sparkline** to stderr.
- **Four output formats**: JSON (default), CSV, human text, and **SARIF 2.1.0**
  for GitHub code scanning and other dashboards.
- **Robust I/O**: reads files or **stdin** (`-`), handles empty and large files,
  binary-safe on Windows.
- **Exit-code contract**: `0` clean, `2` flagged, `1` error.

## Build / run

```bash
cc -O2 -std=c99 -Wall -Wextra -o entroc entroc.c -lm
./entroc suspicious.bin --format text
```

or with the Makefile:

```bash
make            # build
make test       # build + run unit/behavioral tests + demos
make bench      # throughput benchmark
sudo make install
```

## Usage

```
entroc <file|-> [options]      ('-' reads stdin)

  --window N       window size in bytes            (default 256)
  --step N         advance between windows          (default = window)
  --threshold F    min Shannon bits/byte to flag    (default 7.0)
  --min-region N   drop merged regions shorter than N bytes (default 0)
  --format FMT     json (default) | csv | text | sarif
  --profile        include per-window entropy series
  --sparkline      draw an ASCII entropy sparkline to stderr
  --no-secrets     disable embedded-secret scanning
  --version        print version
  -h, --help       help
```

Full reference: [`docs/USAGE.md`](docs/USAGE.md). Design and complexity:
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

### Examples

```bash
# triage an unknown binary, human summary
entroc sample.bin --format text

# find a private key embedded in a config file
entroc config.yml --format text

# hunt leaked credentials in a .env, machine-readable
entroc .env --format csv

# localize a small high-entropy region with an overlapping scan
entroc firmware.bin --window 512 --step 128 --min-region 512

# read from a pipe
xxd -r dump.hex | entroc - --window 256

# emit SARIF for CI code scanning
entroc build/artifact.bin --format sarif > entroc.sarif
```

Runnable demos live in [`examples/`](examples/) — `bash examples/run_all.sh`.

## Output

JSON (default) example shape:

```json
{
  "tool": "entroc",
  "version": "2.0.0",
  "file": "sample.bin",
  "size": 8192,
  "window": 256,
  "step": 256,
  "threshold": 7.00,
  "global": { "shannon": 7.98, "min_entropy": 7.30, "chi_square": 224.62 },
  "max_entropy": 7.31,
  "regions": [ { "offset": 0, "length": 8192, "entropy": 7.31, "class": "high-entropy" } ],
  "regions_flagged": 1,
  "secrets": [ { "offset": 512, "length": 20, "kind": "aws-access-key-id", "preview": "AKIA...[redacted]" } ],
  "secrets_flagged": 1
}
```

## Exit codes

| Code | Meaning |
|------|---------|
| **0** | Nothing flagged (clean). |
| **2** | At least one region or secret flagged. |
| **1** | Error (bad option, unreadable file). |

Gate CI on the exit code: `entroc artifact.bin && echo clean`.

## Benchmark (honest, reproducible)

Run it yourself: `bash bench/bench.sh` (times 3 runs, reports best MB/s and the
machine label). Throughput scales with `window`/`step` because a smaller step
means more windows and more passes.

Measured on **gcc 13.4.0, x86_64 Linux (WSL2), Docker `gcc:13`**, entropy over
random data:

| Input | window/step | throughput |
|-------|-------------|------------|
| 8 MB  | 256 / 256   | ~30 MB/s   |
| 32 MB | 256 / 256   | ~37 MB/s   |
| 64 MB | 256 / 256   | ~33 MB/s   |
| 64 MB | 4096 / 4096 | ~52 MB/s   |

These are real numbers from this machine; yours will differ. The per-window
recomputation of three metrics dominates; larger windows amortize it.

## Tests

`bash tests/run_tests.sh` builds with `-Wall -Wextra -Werror`, runs a C unit
suite (`tests/unit_entropy.c`, 22 checks against known entropy/min-entropy/
chi-square/secret values) and 30+ behavioral assertions against committed test
vectors (`tests/test_vectors/`) — 60+ assertions total, all green in CI on
ubuntu + macos, with a Windows build+smoke job.

## Install

- **Linux/macOS**: `sudo ./install.sh` (or `make install`). Needs `cc`/`gcc`/`clang` + libm.
- **Windows**: `powershell -ExecutionPolicy Bypass -File install.ps1` (uses gcc/clang, falls back to MSVC `cl`).
- **Docker**: `docker build -t entroc . && docker run --rm -i entroc - < file.bin` (multi-stage; tiny runtime image).

## License

COCL 1.0 — see [LICENSE](LICENSE). Commercial use → licensing@cognis.digital

Part of the [Cognis Neural Suite](https://github.com/cognis-digital).
