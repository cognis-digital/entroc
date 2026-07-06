# entroc usage

```
entroc <file|-> [options]      ('-' reads stdin)
```

## Options

| Option           | Default | Meaning                                                    |
|------------------|---------|------------------------------------------------------------|
| `--window N`     | 256     | Window size in bytes.                                      |
| `--step N`       | =window | Advance between windows. `< window` for overlapping scans. |
| `--threshold F`  | 7.0     | Min Shannon bits/byte for a window to be flagged.          |
| `--min-region N` | 0       | Drop merged regions shorter than N bytes.                  |
| `--format FMT`   | json    | `json` \| `csv` \| `text` \| `sarif`.                      |
| `--profile`      | off     | Include the per-window entropy series in the output.       |
| `--sparkline`    | off     | Draw an ASCII entropy sparkline to **stderr**.             |
| `--no-secrets`   | off     | Disable embedded-secret scanning.                          |
| `--version`      |         | Print version and exit 0.                                  |
| `-h`, `--help`   |         | Print help and exit 0.                                     |

## Metrics

Reported per window (with `--profile`) and file-global (`global` object / text
header): **Shannon** entropy (0..8 bits/byte), **min-entropy** `H_inf`, and the
**chi-square** statistic vs a uniform byte distribution.

## Detectors

- **Content class** per window: `text`, `base64`, `hex`, `high-entropy`,
  `packed-binary`, `binary`.
- **Embedded secrets**: PEM blocks, AWS access-key ids, JWTs, long hex runs
  (md5/sha1/sha256 lengths), and base64 key material. Previews are redacted.

## Output formats

- **json** (default): one object with `global`, `regions`, `secrets`, and
  (with `--profile`) `profile`.
- **csv**: `type,offset,length,...` rows for regions/secrets (and windows with
  `--profile`). Easy to pipe into a spreadsheet or `awk`.
- **text**: human summary with a final `result: FLAGGED|clean` line.
- **sarif**: SARIF 2.1.0 for GitHub code scanning / any SARIF dashboard.

## Exit codes

| Code | Meaning                              |
|------|--------------------------------------|
| 0    | Nothing flagged.                     |
| 2    | At least one region or secret found. |
| 1    | Error (bad option, unreadable file). |

## Examples

```bash
# triage an unknown binary
entroc sample.bin --format text

# hunt secrets in a repo file, machine-readable
entroc .env --format csv

# overlapping scan to localize a small high-entropy region
entroc firmware.bin --window 512 --step 128 --min-region 512

# pipe from another tool
xxd -r suspicious.hex | entroc - --window 256

# emit SARIF for CI code scanning
entroc build/artifact.bin --format sarif > entroc.sarif
```

## Portability audit

Strictly portable (C99 stdlib + libm), builds unchanged on Linux/macOS/Windows:

- `fopen`/`fread`/`fclose`, `malloc`/`realloc`/`free`, `printf`/`fprintf`/`fputs`
- `%zu` for `size_t` (C99), `log2` from `<math.h>` (`-lm` on Unix)
- all buffers explicitly sized; no VLAs, no GNU extensions

Platform-specific (guarded):

- `_setmode(_fileno(stdin), _O_BINARY)` under `#ifdef _WIN32` (`<io.h>`,
  `<fcntl.h>`) so piped stdin is read as raw bytes on Windows. No effect and not
  compiled on other platforms.

Not used anywhere: POSIX-only calls (`mmap`, `open`/`read`, `getopt`), threads,
sockets, or any third-party library.
